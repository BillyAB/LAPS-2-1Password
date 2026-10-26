#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets up Sync-LapsTo1Password.ps1 to run as a scheduled task under a gMSA or a standard
    service account.

.DESCRIPTION
    Run this once, elevated, on the server that will run the sync. It:

      1. Checks the gMSA can be used on this server (gMSA only).
      2. Grants the account Modify on C:\ProgramData\LapsTo1Password, where the token, state file
         and logs are kept.
      3. Prompts for the 1Password service account token and writes it to a staging file that only
         the account, SYSTEM and Administrators can read.
      4. Runs a one-off scheduled task as the account that calls
         Sync-LapsTo1Password.ps1 -SaveToken -TokenFile, so the token is encrypted with DPAPI for
         that account. This is needed because a gMSA cannot log on interactively to run -SaveToken.
      5. Deletes the one-off task and the staging file, then checks the token file exists.
      6. Registers (or updates) the recurring sync task to run as the account.

    Run it again with -SkipToken to change the task's settings without re-entering the token, or
    with -TokenOnly to rotate the token without changing the task.

    The account also needs these rights, which this script does not grant:
      - Log on as a batch job on this server
      - LAPS read permission on the OUs in scope (Set-LapsADReadPasswordPermission)
      - Membership of the LAPS authorized password decryptor group, for encrypted passwords

.PARAMETER ServiceAccount
    The account the task runs as, in DOMAIN\name form. A name ending in $ is treated as a gMSA.

.PARAMETER Credential
    The password for a standard (non-gMSA) service account. You are prompted for it if it is not
    given. Not used for a gMSA.

.PARAMETER VaultName
    The 1Password vault to sync into. Passed to Sync-LapsTo1Password.ps1.

.PARAMETER SearchBase
    One or more OUs to search. Passed to Sync-LapsTo1Password.ps1.

.PARAMETER Server
    Domain controller to use. Passed to Sync-LapsTo1Password.ps1.

.PARAMETER ArchiveOrphans
    Passed to Sync-LapsTo1Password.ps1.

.PARAMETER ExtraArguments
    Any other Sync-LapsTo1Password.ps1 parameters, added to the task's command as written, for
    example "-MaxHistory 100 -Tag 'LAPS-Servers'".

.PARAMETER IntervalMinutes
    How often the sync task runs.

.PARAMETER ScriptPath
    Full path to Sync-LapsTo1Password.ps1. Defaults to the copy next to this script. Put it
    somewhere only administrators can write to, because it runs with the account's rights.

.PARAMETER TaskName
    Name of the recurring sync task.

.PARAMETER SkipToken
    Do not set up the token; only register or update the sync task.

.PARAMETER TokenOnly
    Only save the token; do not register or update the sync task.

.PARAMETER StartTask
    Start the sync task once it is registered.

.EXAMPLE
    .\Install-LapsTo1Password.ps1 -ServiceAccount 'CORP\gmsa-laps1p$' -VaultName 'LAPS - Servers' -SearchBase 'OU=Servers,DC=corp,DC=example,DC=com' -ArchiveOrphans

.EXAMPLE
    .\Install-LapsTo1Password.ps1 -ServiceAccount 'CORP\gmsa-laps1p$' -TokenOnly

    Rotates the saved token.

.EXAMPLE
    .\Install-LapsTo1Password.ps1 -ServiceAccount 'CORP\svc-laps1p' -VaultName 'LAPS - Servers' -ExtraArguments '-WhatIf' -StartTask

    Sets up a standard service account and starts a dry run.
#>
[CmdletBinding(DefaultParameterSetName = 'Full')]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[^\\]+\\[^\\]+$')]
    [string]$ServiceAccount,

    [pscredential]$Credential,

    [Parameter(Mandatory, ParameterSetName = 'Full')]
    [Parameter(Mandatory, ParameterSetName = 'SkipToken')]
    [string]$VaultName,

    [Parameter(ParameterSetName = 'Full')]
    [Parameter(ParameterSetName = 'SkipToken')]
    [string[]]$SearchBase,

    [Parameter(ParameterSetName = 'Full')]
    [Parameter(ParameterSetName = 'SkipToken')]
    [string]$Server,

    [Parameter(ParameterSetName = 'Full')]
    [Parameter(ParameterSetName = 'SkipToken')]
    [switch]$ArchiveOrphans,

    [Parameter(ParameterSetName = 'Full')]
    [Parameter(ParameterSetName = 'SkipToken')]
    [string]$ExtraArguments,

    [Parameter(ParameterSetName = 'Full')]
    [Parameter(ParameterSetName = 'SkipToken')]
    [ValidateRange(5, 1440)]
    [int]$IntervalMinutes = 30,

    [string]$ScriptPath = (Join-Path $PSScriptRoot 'Sync-LapsTo1Password.ps1'),

    [Parameter(ParameterSetName = 'Full')]
    [Parameter(ParameterSetName = 'SkipToken')]
    [string]$TaskName = 'Sync LAPS to 1Password',

    [Parameter(Mandatory, ParameterSetName = 'SkipToken')]
    [switch]$SkipToken,

    [Parameter(Mandatory, ParameterSetName = 'TokenOnly')]
    [switch]$TokenOnly,

    [Parameter(ParameterSetName = 'Full')]
    [Parameter(ParameterSetName = 'SkipToken')]
    [switch]$StartTask
)

$ErrorActionPreference = 'Stop'

$DataDirectory = Join-Path $env:ProgramData 'LapsTo1Password'
$TokenPath = Join-Path $DataDirectory 'op-token.xml'
$IsGmsa = $ServiceAccount.EndsWith('$')

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Invoke-Icacls {
    param([Parameter(Mandatory)][string[]]$Arguments)
    $output = & icacls.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "icacls $($Arguments -join ' ') failed: $output" }
}

# Wraps a value in single quotes for a PowerShell -Command string.
function ConvertTo-QuotedArgument {
    param([Parameter(Mandatory)][string]$Value)
    "'" + $Value.Replace("'", "''") + "'"
}

function Register-AccountTask {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)]$Action,
        $Trigger,
        $Settings
    )
    $taskParameters = @{ TaskName = $Name; Action = $Action; Force = $true }
    if ($Trigger) { $taskParameters.Trigger = $Trigger }
    if ($Settings) { $taskParameters.Settings = $Settings }
    if ($IsGmsa) {
        # With LogonType Password, Task Scheduler fetches the gMSA's password from AD itself.
        $taskParameters.Principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType Password -RunLevel Limited
    }
    else {
        $taskParameters.User = $Credential.UserName
        $taskParameters.Password = $Credential.GetNetworkCredential().Password
        $taskParameters.RunLevel = 'Limited'
    }
    Register-ScheduledTask @taskParameters | Out-Null
}

function Get-TaskResultHint {
    param([long]$Result)
    switch ($Result) {
        0x41301 { 'The task is still running.' }
        0x41303 { 'The task has not run. Task Scheduler could not start it, usually because the account cannot log on. See the events below.' }
        0x80070569L { "$ServiceAccount does not have 'Log on as a batch job' on this server." }
        0x8007052EL { "Logon failure for $ServiceAccount. For a gMSA, check Test-ADServiceAccount and that $env:COMPUTERNAME may retrieve its password." }
        0x80070005L { "Access denied. Check $ServiceAccount can read '$ScriptPath' and its folder." }
        default { '' }
    }
}

# Returns Task Scheduler's events for the task since it was started. The Operational log must be
# enabled ("Enable All Tasks History" in Task Scheduler) for these to exist.
function Get-TaskEvents {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][datetime]$StartedAfter)
    $filter = @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; StartTime = $StartedAfter }
    Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like "*$Name*" } |
        Sort-Object TimeCreated |
        ForEach-Object { '  {0:HH:mm:ss} [{1}] {2}' -f $_.TimeCreated, $_.Id, ($_.Message -replace '\s+', ' ') }
}

# Waits for the one-off task to write the token file. Success is judged by the file rather than
# the task's LastRunTime, which is not updated when the task fails to launch.
function Wait-TokenSaved {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][datetime]$StartedAfter,
        [datetime]$PreviousWriteTime = [datetime]::MinValue,
        [int]$TimeoutSeconds = 300
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 2
        if ((Test-Path -LiteralPath $TokenPath) -and (Get-Item -LiteralPath $TokenPath).LastWriteTime -gt $PreviousWriteTime) {
            # Let the task exit before the caller unregisters it.
            $stopBy = (Get-Date).AddSeconds(30)
            while ((Get-ScheduledTask -TaskName $Name).State -eq 'Running' -and (Get-Date) -lt $stopBy) { Start-Sleep -Seconds 1 }
            return
        }
        $state = (Get-ScheduledTask -TaskName $Name).State
        $info = Get-ScheduledTaskInfo -TaskName $Name
        $finished = $state -ne 'Running' -and $info.LastRunTime -ge $StartedAfter -and $info.LastTaskResult -notin 0x41301, 0x41303
    } until ($finished -or (Get-Date) -ge $deadline)

    $reason = if ($finished) { 'finished without saving the token' } else { "did not save the token within $TimeoutSeconds seconds" }
    $details = @(
        "The one-off task $reason."
        ('  State: {0}; last run: {1}; last result: 0x{2:X8} {3}' -f $state, $info.LastRunTime, $info.LastTaskResult, (Get-TaskResultHint $info.LastTaskResult))
    )
    $events = @(Get-TaskEvents -Name $Name -StartedAfter $StartedAfter)
    if ($events) { $details += '  Task Scheduler events:'; $details += $events }
    else { $details += '  No Task Scheduler events found. Enable "All Tasks History" in Task Scheduler to capture them.' }
    throw ($details -join [Environment]::NewLine)
}

#region Checks

if (-not (Test-Path -LiteralPath $ScriptPath)) { throw "Sync script not found at '$ScriptPath'. Pass -ScriptPath." }
$ScriptPath = (Resolve-Path -LiteralPath $ScriptPath).Path

if (-not (Get-Command op.exe -ErrorAction SilentlyContinue) -and
    -not (Test-Path (Join-Path $env:ProgramFiles '1Password CLI\op.exe'))) {
    Write-Warning 'op.exe (1Password CLI) was not found on PATH. Install it for all users before the sync task runs, or add -OpPath to -ExtraArguments.'
}

if ($IsGmsa) {
    Write-Step "Checking gMSA $ServiceAccount can be used on $env:COMPUTERNAME"
    if (Get-Command Test-ADServiceAccount -ErrorAction SilentlyContinue) {
        $gmsaName = ($ServiceAccount -split '\\')[-1].TrimEnd('$')
        if (-not (Test-ADServiceAccount -Identity $gmsaName)) {
            throw "Test-ADServiceAccount returned False for '$gmsaName'. Add $env:COMPUTERNAME to the gMSA's PrincipalsAllowedToRetrieveManagedPassword, run 'klist -li 0x3e7 purge' or reboot, then run Install-ADServiceAccount -Identity $gmsaName."
        }
    }
    else {
        Write-Warning 'The ActiveDirectory module is not installed, so the gMSA could not be checked. Continuing.'
    }
}
elseif (-not $Credential) {
    $Credential = Get-Credential -UserName $ServiceAccount -Message "Password for $ServiceAccount (used to register the scheduled tasks)"
}

#endregion

#region Data directory

Write-Step "Granting $ServiceAccount Modify on $DataDirectory"
New-Item -ItemType Directory -Path $DataDirectory -Force | Out-Null
Invoke-Icacls @($DataDirectory, '/grant', "${ServiceAccount}:(OI)(CI)M")

#endregion

#region Token

if (-not $SkipToken) {
    $stagingDirectory = Join-Path $DataDirectory ('staging-' + [guid]::NewGuid().ToString('N'))
    $stagingToken = Join-Path $stagingDirectory 'token.txt'
    $saveTaskName = 'LapsTo1Password - Save token (one-off)'

    try {
        Write-Step 'Writing the token to a staging file readable only by the account, SYSTEM and Administrators'
        New-Item -ItemType Directory -Path $stagingDirectory -Force | Out-Null
        Invoke-Icacls @($stagingDirectory, '/inheritance:r', '/grant:r',
            "${ServiceAccount}:(OI)(CI)R", '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')

        $secureToken = Read-Host -AsSecureString -Prompt 'Paste the 1Password service account token'
        if ($secureToken.Length -eq 0) { throw 'No token entered.' }
        [System.IO.File]::WriteAllText($stagingToken, (New-Object System.Net.NetworkCredential('', $secureToken)).Password)

        Write-Step "Saving the token as $ServiceAccount with a one-off scheduled task"
        $saveCommand = '& {0} -SaveToken -TokenFile {1} -TokenPath {2}; exit $LASTEXITCODE' -f
            (ConvertTo-QuotedArgument $ScriptPath), (ConvertTo-QuotedArgument $stagingToken), (ConvertTo-QuotedArgument $TokenPath)
        $saveAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$saveCommand`""
        Register-AccountTask -Name $saveTaskName -Action $saveAction

        $previousWriteTime = if (Test-Path -LiteralPath $TokenPath) { (Get-Item -LiteralPath $TokenPath).LastWriteTime } else { [datetime]::MinValue }
        $startedAt = (Get-Date).AddSeconds(-2)
        Start-ScheduledTask -TaskName $saveTaskName
        Wait-TokenSaved -Name $saveTaskName -StartedAfter $startedAt -PreviousWriteTime $previousWriteTime
        Write-Host "Token saved to $TokenPath (decryptable only by $ServiceAccount on $env:COMPUTERNAME)." -ForegroundColor Green
    }
    finally {
        if (Get-ScheduledTask -TaskName $saveTaskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $saveTaskName -Confirm:$false
        }
        if (Test-Path -LiteralPath $stagingToken) {
            # Best effort: overwrite the plaintext token before deleting the file.
            $length = (Get-Item -LiteralPath $stagingToken).Length
            [System.IO.File]::WriteAllBytes($stagingToken, (New-Object byte[] ([math]::Max($length, 1))))
        }
        if (Test-Path -LiteralPath $stagingDirectory) { Remove-Item -LiteralPath $stagingDirectory -Recurse -Force }
    }
}

if ($TokenOnly) {
    Write-Step 'Done. The sync task was not changed.'
    return
}

#endregion

#region Sync task

Write-Step "Registering scheduled task '$TaskName' to run as $ServiceAccount every $IntervalMinutes minutes"

$syncArguments = @('-VaultName', (ConvertTo-QuotedArgument $VaultName))
if ($SearchBase) { $syncArguments += '-SearchBase', (($SearchBase | ForEach-Object { ConvertTo-QuotedArgument $_ }) -join ',') }
if ($Server) { $syncArguments += '-Server', (ConvertTo-QuotedArgument $Server) }
if ($ArchiveOrphans) { $syncArguments += '-ArchiveOrphans' }
if ($ExtraArguments) { $syncArguments += $ExtraArguments }

# -Command rather than -File so that multiple -SearchBase values arrive as an array.
$syncCommand = '& {0} {1}; exit $LASTEXITCODE' -f (ConvertTo-QuotedArgument $ScriptPath), ($syncArguments -join ' ')
if ($syncCommand.Contains('"')) { throw 'Use single quotes, not double quotes, inside -ExtraArguments.' }

$syncAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"$syncCommand`""
$syncTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
$syncSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -StartWhenAvailable

Register-AccountTask -Name $TaskName -Action $syncAction -Trigger $syncTrigger -Settings $syncSettings
Write-Host "Task command: powershell.exe $($syncAction.Arguments)" -ForegroundColor DarkGray

if ($StartTask) {
    Write-Step "Starting '$TaskName'"
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Started. Follow progress in $(Join-Path $DataDirectory 'Logs')." -ForegroundColor Green
}
else {
    Write-Host "Done. The first run starts within $IntervalMinutes minutes; logs are in $(Join-Path $DataDirectory 'Logs')." -ForegroundColor Green
}

#endregion
