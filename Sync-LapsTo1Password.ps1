#Requires -Version 5.1
#Requires -Modules LAPS
<#
.SYNOPSIS
    Syncs Windows LAPS passwords, and their history, from Active Directory to a 1Password vault.

.DESCRIPTION
    Finds every computer in Active Directory that has a LAPS password, reads the current password
    and its history with Get-LapsADPassword, and writes one 1Password Login item per computer.

    Each item holds:
      - the current managed account and password (1Password's built-in password history also
        records every value the sync replaces)
      - a "LAPS details" section: hostname, DN, object GUID, OS, LAPS source, when the password
        was set, when it expires
      - a "LAPS password history" section: one concealed field per earlier password. The section
        is merged on every sync, so it keeps passwords that AD has already rotated out of
        msLAPS-EncryptedPasswordHistory (up to -MaxHistory).

    The script authenticates to 1Password with a service account token through the 1Password CLI
    (op.exe). Passwords are passed to op.exe on stdin and never appear on a command line or on disk.

    To keep within service account rate limits, a local state file records which LAPS password
    version has already been synced for each computer. A computer whose LAPS password has not
    changed costs no 1Password API calls.

    Supports Windows LAPS (encrypted and cleartext) and legacy Microsoft LAPS, as far as
    Get-LapsADPassword can read them. Legacy LAPS keeps no history in AD, so its history builds up
    in 1Password from the first sync onwards.

.PARAMETER VaultName
    Name or ID of the 1Password vault to sync into. The service account needs read and write
    access to it.

.PARAMETER SearchBase
    One or more DNs to search for computers. Defaults to the whole domain.

.PARAMETER Server
    Domain controller to use for both the computer search and the LAPS password reads.

.PARAMETER LdapFilter
    LDAP filter for the computer search. The default finds computers with a Windows LAPS or legacy
    LAPS expiration time, which are readable without decryption rights.

.PARAMETER Tag
    Tag put on every item the script manages. Only items with this tag are matched or archived.

.PARAMETER MaxHistory
    The most history entries to keep per item. 0 keeps none.

.PARAMETER DefaultAccountName
    Username used when LAPS does not report the managed account (legacy LAPS).

.PARAMETER ArchiveOrphans
    Archive tagged items whose computer is no longer returned by the AD search.

.PARAMETER Force
    Re-sync every computer even if the state file says it is up to date. With -ArchiveOrphans,
    also allows archiving more than 25% of the vault's tagged items in one run.

.PARAMETER SaveToken
    Prompt for the 1Password service account token and save it, encrypted with DPAPI, to
    -TokenPath. Run this once, as the account that will run the scheduled task.

.EXAMPLE
    .\Sync-LapsTo1Password.ps1 -SaveToken

.EXAMPLE
    .\Sync-LapsTo1Password.ps1 -VaultName 'LAPS - Servers' -SearchBase 'OU=Servers,DC=corp,DC=example,DC=com' -WhatIf

.EXAMPLE
    .\Sync-LapsTo1Password.ps1 -VaultName 'LAPS - Servers' -SearchBase 'OU=Servers,DC=corp,DC=example,DC=com' -ArchiveOrphans
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Sync')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Sync')]
    [string]$VaultName,

    [Parameter(ParameterSetName = 'Sync')]
    [string[]]$SearchBase,

    [Parameter(ParameterSetName = 'Sync')]
    [string]$Server,

    [Parameter(ParameterSetName = 'Sync')]
    [string]$LdapFilter = '(&(objectCategory=computer)(|(msLAPS-PasswordExpirationTime=*)(ms-Mcs-AdmPwdExpirationTime=*)))',

    [Parameter(ParameterSetName = 'Sync')]
    [string]$Tag = 'LAPS',

    [Parameter(ParameterSetName = 'Sync')]
    [ValidateRange(0, 500)]
    [int]$MaxHistory = 50,

    [Parameter(ParameterSetName = 'Sync')]
    [string]$DefaultAccountName = 'Administrator',

    [Parameter(ParameterSetName = 'Sync')]
    [switch]$ArchiveOrphans,

    [Parameter(ParameterSetName = 'Sync')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'Sync')]
    [string]$OpPath,

    [Parameter(ParameterSetName = 'Sync')]
    [string]$StatePath = (Join-Path $env:ProgramData 'LapsTo1Password\state.json'),

    [Parameter(ParameterSetName = 'Sync')]
    [string]$LogDirectory = (Join-Path $env:ProgramData 'LapsTo1Password\Logs'),

    [Parameter(ParameterSetName = 'Sync')]
    [int]$LogRetentionDays = 30,

    [string]$TokenPath = (Join-Path $env:ProgramData 'LapsTo1Password\op-token.xml'),

    [Parameter(Mandatory, ParameterSetName = 'SaveToken')]
    [switch]$SaveToken
)

$ErrorActionPreference = 'Stop'

$DetailsSectionId = 'laps'
$HistorySectionId = 'laps_history'
$TimeFormat = 'yyyy-MM-dd HH:mm:ss'

#region Helpers

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')][string]$Level = 'INFO'
    )
    if ($Level -eq 'DEBUG' -and $VerbosePreference -eq 'SilentlyContinue') { return }
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString($TimeFormat), $Level, $Message
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 }
    $colour = @{ INFO = 'Gray'; WARN = 'Yellow'; ERROR = 'Red'; DEBUG = 'DarkGray' }[$Level]
    Write-Host $line -ForegroundColor $colour
}

# Replaces a file's ACL with full control for the current user, SYSTEM and Administrators only.
function Set-RestrictedAcl {
    param([Parameter(Mandatory)][string]$Path)
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $principals = @(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-18'
        New-Object System.Security.Principal.SecurityIdentifier 'S-1-5-32-544'
    )
    foreach ($principal in $principals) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
    }
    [System.IO.File]::SetAccessControl($Path, $acl)
}

function ConvertTo-ProcessArgument {
    param([string]$Value)
    if ($Value -notmatch '[\s"]') { return $Value }
    '"' + (($Value -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
}

# Runs op.exe with the service account token in its environment only. When -InputJson is given it
# is written to op's stdin as UTF-8, so secrets never appear on the command line.
function Invoke-Op {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$InputJson,
        [int]$MaxAttempts = 4
    )
    for ($attempt = 1; ; $attempt++) {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $script:Op
        $psi.Arguments = ($Arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }) -join ' '
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.RedirectStandardInput = [bool]$InputJson
        $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
        $psi.StandardErrorEncoding = [System.Text.Encoding]::UTF8
        $psi.EnvironmentVariables['OP_SERVICE_ACCOUNT_TOKEN'] = $script:OpToken

        $process = [System.Diagnostics.Process]::Start($psi)
        try {
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            if ($InputJson) {
                $bytes = (New-Object System.Text.UTF8Encoding $false).GetBytes($InputJson)
                $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
                $process.StandardInput.Close()
            }
            $process.WaitForExit()
            $exitCode = $process.ExitCode
        }
        finally {
            $process.Dispose()
        }

        if ($exitCode -eq 0) { return $stdout.Result }

        $message = $stderr.Result.Trim()
        if ($attempt -lt $MaxAttempts -and $message -match 'rate limit|too many requests|429|timeout|temporarily unavailable') {
            $delay = [math]::Pow(2, $attempt) * 5
            Write-Log "op $($Arguments[0]) $($Arguments[1]) was throttled or timed out; retrying in $delay s: $message" -Level WARN
            Start-Sleep -Seconds $delay
            continue
        }
        throw "op $($Arguments[0]) $($Arguments[1]) failed (exit code $exitCode): $message"
    }
}

function Get-OpToken {
    if ($env:OP_SERVICE_ACCOUNT_TOKEN) { return $env:OP_SERVICE_ACCOUNT_TOKEN }
    if (-not (Test-Path -LiteralPath $TokenPath)) {
        throw "No 1Password service account token found at '$TokenPath'. Run this script with -SaveToken as the account that runs the scheduled task."
    }
    try {
        (Import-Clixml -LiteralPath $TokenPath).GetNetworkCredential().Password
    }
    catch {
        throw "Could not decrypt '$TokenPath' as $env:USERDOMAIN\$env:USERNAME. The token can only be read by the account that saved it, on the computer it was saved on. Run -SaveToken again as this account. ($_)"
    }
}

function Resolve-OpPath {
    if ($OpPath) { return $OpPath }
    $command = Get-Command op.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command) { return $command.Source }
    $candidates = @(
        (Join-Path $env:ProgramFiles '1Password CLI\op.exe')
        (Join-Path $env:LOCALAPPDATA 'Microsoft\WinGet\Links\op.exe')
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    throw 'op.exe (1Password CLI) was not found. Install it or pass -OpPath.'
}

function Format-Utc {
    param([Parameter(Mandatory)][datetime]$Time)
    $Time.ToUniversalTime().ToString($TimeFormat, [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-UtcString {
    param([string]$Value)
    $parsed = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]'AssumeUniversal, AdjustToUniversal'
    if ([datetime]::TryParseExact($Value, $TimeFormat, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed
    }
    $null
}

# History field IDs sort in time order, so the newest entry can be kept first.
function Get-HistoryFieldId {
    param([Parameter(Mandatory)][datetime]$Time)
    'h' + $Time.ToUniversalTime().ToString('yyyyMMddHHmmss', [System.Globalization.CultureInfo]::InvariantCulture)
}

function Get-DomainFromDn {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    (($DistinguishedName -split '(?<!\\),') | Where-Object { $_ -like 'DC=*' } | ForEach-Object { $_.Substring(3) }) -join '.'
}

function Read-State {
    $state = @{}
    if (-not (Test-Path -LiteralPath $StatePath)) { return $state }
    try {
        $json = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($property in $json.PSObject.Properties) {
            $state[$property.Name] = @{ ItemId = $property.Value.ItemId; Version = $property.Value.Version; Title = $property.Value.Title }
        }
    }
    catch {
        Write-Log "State file '$StatePath' could not be read and will be rebuilt: $_" -Level WARN
    }
    $state
}

function Save-State {
    param([Parameter(Mandatory)][hashtable]$State)
    $directory = Split-Path -Parent $StatePath
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    $temp = "$StatePath.tmp"
    [System.IO.File]::WriteAllText($temp, ($State | ConvertTo-Json -Depth 4), (New-Object System.Text.UTF8Encoding $false))
    Move-Item -LiteralPath $temp -Destination $StatePath -Force
}

#endregion

#region Active Directory

function Get-LapsComputer {
    $ldapPrefix = if ($Server) { "LDAP://$Server/" } else { 'LDAP://' }
    $roots = $SearchBase
    if (-not $roots) {
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry("${ldapPrefix}RootDSE")
        $roots = @([string]$rootDse.Properties['defaultNamingContext'][0])
    }

    $attributes = [string[]]@('distinguishedName', 'name', 'dNSHostName', 'objectGUID', 'operatingSystem')
    foreach ($root in $roots) {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher(
            (New-Object System.DirectoryServices.DirectoryEntry("$ldapPrefix$root")), $LdapFilter, $attributes)
        $searcher.PageSize = 1000
        $results = $searcher.FindAll()
        try {
            foreach ($result in $results) {
                $properties = $result.Properties
                $dnsHostName = if ($properties['dnshostname'].Count) { [string]$properties['dnshostname'][0] } else { $null }
                $operatingSystem = if ($properties['operatingsystem'].Count) { [string]$properties['operatingsystem'][0] } else { '' }
                [pscustomobject]@{
                    DistinguishedName = [string]$properties['distinguishedname'][0]
                    Name              = [string]$properties['name'][0]
                    DnsHostName       = $dnsHostName
                    ObjectGuid        = (New-Object guid -ArgumentList (, [byte[]]$properties['objectguid'][0])).ToString()
                    OperatingSystem   = $operatingSystem
                    Title             = if ($dnsHostName) { $dnsHostName.ToLowerInvariant() } else { ([string]$properties['name'][0]).ToLowerInvariant() }
                }
            }
        }
        finally {
            $results.Dispose()
            $searcher.Dispose()
        }
    }
}

function Get-LapsPassword {
    param([Parameter(Mandatory)]$Computer)
    $lapsParameters = @{
        Identity       = $Computer.DistinguishedName
        AsPlainText    = $true
        IncludeHistory = $true
    }
    if ($Server) { $lapsParameters.DomainController = $Server }
    else { $lapsParameters.Domain = Get-DomainFromDn $Computer.DistinguishedName }

    $entries = @(Get-LapsADPassword @lapsParameters)
    [pscustomobject]@{
        Current = $entries | Where-Object { [string]$_.Source -notmatch 'History' } | Select-Object -First 1
        History = @($entries | Where-Object { [string]$_.Source -match 'History' -and $_.Password -and $_.PasswordUpdateTime })
    }
}

#endregion

#region 1Password item

function New-Field {
    param([string]$Id, [string]$Label, [string]$Value, [string]$Type = 'STRING', [string]$Section = $DetailsSectionId)
    @{ id = $Id; type = $Type; label = $Label; value = $Value; section = @{ id = $Section } }
}

# Merges the history already stored in 1Password with the history in AD, plus the password being
# replaced, and returns the newest -MaxHistory entries (excluding the current password).
function Merge-History {
    param($ExistingItem, $Laps, [string]$CurrentId)
    $history = @{}

    if ($ExistingItem) {
        foreach ($field in $ExistingItem.fields) {
            if ($field.section -and $field.section.id -eq $HistorySectionId -and $field.value) {
                $history[$field.id] = @{ Id = $field.id; Label = $field.label; Value = $field.value }
            }
        }

        $previousPassword = ($ExistingItem.fields | Where-Object { $_.id -eq 'password' } | Select-Object -First 1).value
        if ($previousPassword -and $previousPassword -ne $Laps.Current.Password) {
            $previousSet = ConvertFrom-UtcString ($ExistingItem.fields | Where-Object { $_.id -eq 'laps_updated' } | Select-Object -First 1).value
            if (-not $previousSet) { $previousSet = ([datetime]$ExistingItem.updated_at).ToUniversalTime() }
            $id = Get-HistoryFieldId $previousSet
            $history[$id] = @{ Id = $id; Label = Format-Utc $previousSet; Value = $previousPassword }
        }
    }

    foreach ($entry in $Laps.History) {
        $id = Get-HistoryFieldId $entry.PasswordUpdateTime
        $history[$id] = @{ Id = $id; Label = Format-Utc $entry.PasswordUpdateTime; Value = [string]$entry.Password }
    }

    $history.Remove($CurrentId)
    @($history.Values | Where-Object { $_.Value -ne $Laps.Current.Password } | Sort-Object { $_.Id } -Descending | Select-Object -First $MaxHistory)
}

function New-ItemJson {
    param($Computer, $Laps, [datetime]$PasswordSet, [object[]]$History)
    $current = $Laps.Current
    $account = if ($current.Account) { [string]$current.Account } else { $DefaultAccountName }
    $expires = if ($current.ExpirationTimestamp) { Format-Utc $current.ExpirationTimestamp } else { '' }

    $fields = @(
        @{ id = 'username'; type = 'STRING'; purpose = 'USERNAME'; label = 'username'; value = $account }
        @{ id = 'password'; type = 'CONCEALED'; purpose = 'PASSWORD'; label = 'password'; value = [string]$current.Password }
        @{ id = 'notesPlain'; type = 'STRING'; purpose = 'NOTES'; label = 'notesPlain'; value = 'Managed by Sync-LapsTo1Password.ps1. Changes made here are overwritten by the next sync.' }
        New-Field 'laps_hostname' 'Hostname' $Computer.Title
        New-Field 'laps_dn' 'Distinguished name' $Computer.DistinguishedName
        New-Field 'laps_guid' 'Computer object GUID' $Computer.ObjectGuid
        New-Field 'laps_os' 'Operating system' $Computer.OperatingSystem
        New-Field 'laps_source' 'LAPS source' ([string]$current.Source)
        New-Field 'laps_updated' 'Password set (UTC)' (Format-Utc $PasswordSet)
        New-Field 'laps_expires' 'Password expires (UTC)' $expires
        New-Field 'laps_synced' 'Last synced (UTC)' (Format-Utc (Get-Date))
    )
    foreach ($entry in $History) {
        $fields += New-Field $entry.Id $entry.Label $entry.Value 'CONCEALED' $HistorySectionId
    }

    $item = @{
        title    = $Computer.Title
        category = 'LOGIN'
        tags     = @($Tag)
        sections = @(
            @{ id = $DetailsSectionId; label = 'LAPS details' }
            @{ id = $HistorySectionId; label = 'LAPS password history' }
        )
        fields   = $fields
    }
    $item | ConvertTo-Json -Depth 6 -Compress
}

#endregion

#region Save token

if ($SaveToken) {
    $secure = Read-Host -AsSecureString -Prompt 'Paste the 1Password service account token'
    if ($secure.Length -eq 0) { throw 'No token entered.' }
    $directory = Split-Path -Parent $TokenPath
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    New-Object System.Management.Automation.PSCredential('op-service-account', $secure) | Export-Clixml -LiteralPath $TokenPath -Force
    Set-RestrictedAcl -Path $TokenPath
    Write-Host "Token saved to $TokenPath. Only $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME can decrypt it."
    return
}

#endregion

#region Sync

if (-not (Test-Path -LiteralPath $LogDirectory)) { New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null }
$script:LogFile = Join-Path $LogDirectory ('LapsTo1Password_{0}.log' -f (Get-Date -Format 'yyyy-MM-dd'))
Get-ChildItem -LiteralPath $LogDirectory -Filter 'LapsTo1Password_*.log' |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$LogRetentionDays) } |
    Remove-Item -Force

$stats = @{ Computers = 0; Created = 0; Updated = 0; Unchanged = 0; Skipped = 0; Failed = 0; Archived = 0 }

try {
    Write-Log "Starting LAPS to 1Password sync as $env:USERDOMAIN\$env:USERNAME$(if ($WhatIfPreference) { ' (WhatIf)' })"

    $script:Op = Resolve-OpPath
    $script:OpToken = Get-OpToken

    $opVersion = (Invoke-Op @('--version')).Trim()
    if ([version]($opVersion -replace '[^\d.].*$') -lt [version]'2.25.0') {
        throw "1Password CLI $opVersion is too old; 2.25.0 or later is required."
    }
    $vault = Invoke-Op @('vault', 'get', $VaultName, '--format', 'json') | ConvertFrom-Json
    Write-Log "Using 1Password CLI $opVersion, vault '$($vault.name)' ($($vault.id))"

    $computers = @(Get-LapsComputer)
    $stats.Computers = $computers.Count
    if ($computers.Count -eq 0) { throw 'The AD search returned no computers. Check -SearchBase, -LdapFilter and the account''s permissions.' }
    Write-Log "Found $($computers.Count) LAPS-managed computers in AD"

    $listJson = Invoke-Op @('item', 'list', '--vault', $vault.id, '--tags', $Tag, '--format', 'json')
    $items = @(if ($listJson.Trim()) { $listJson | ConvertFrom-Json })
    $itemsById = @{}
    $itemsByTitle = @{}
    foreach ($item in $items) {
        $itemsById[$item.id] = $item
        $titleKey = $item.title.ToLowerInvariant()
        if ($itemsByTitle.ContainsKey($titleKey)) { $itemsByTitle[$titleKey] = $null } else { $itemsByTitle[$titleKey] = $item }
    }
    Write-Log "Found $($items.Count) items tagged '$Tag' in the vault"

    $state = Read-State
    $matchedItemIds = @{}

    foreach ($computer in $computers) {
        try {
            $cached = $state[$computer.ObjectGuid]
            $itemId = $null
            if ($cached -and $itemsById.ContainsKey($cached.ItemId)) {
                $itemId = $cached.ItemId
            }
            elseif ($itemsByTitle.ContainsKey($computer.Title)) {
                if (-not $itemsByTitle[$computer.Title]) {
                    throw "More than one item in the vault is titled '$($computer.Title)'. Remove the duplicates."
                }
                $itemId = $itemsByTitle[$computer.Title].id
            }
            if ($itemId) { $matchedItemIds[$itemId] = $true }

            $laps = Get-LapsPassword $computer
            if (-not $laps.Current -or [string]::IsNullOrEmpty([string]$laps.Current.Password)) {
                $status = if ($laps.Current) { $laps.Current.DecryptionStatus } else { 'no password returned' }
                Write-Log "$($computer.Title): could not read the LAPS password ($status)" -Level WARN
                $stats.Skipped++
                continue
            }

            # Legacy LAPS has no update time, so its expiry time stands in for the password version.
            if ($laps.Current.PasswordUpdateTime) {
                $passwordSet = $laps.Current.PasswordUpdateTime.ToUniversalTime()
                $version = Format-Utc $passwordSet
            }
            else {
                $passwordSet = (Get-Date).ToUniversalTime()
                $version = 'expires:' + $(if ($laps.Current.ExpirationTimestamp) { Format-Utc $laps.Current.ExpirationTimestamp } else { 'unknown' })
            }

            if (-not $Force -and $itemId -and $cached -and $cached.ItemId -eq $itemId -and $cached.Version -eq $version) {
                Write-Log "$($computer.Title): unchanged" -Level DEBUG
                $stats.Unchanged++
                continue
            }

            $existingItem = $null
            if ($itemId) {
                $existingItem = Invoke-Op @('item', 'get', $itemId, '--vault', $vault.id, '--reveal', '--format', 'json') | ConvertFrom-Json
                if (-not $laps.Current.PasswordUpdateTime) {
                    # Keep the first-seen time for a legacy LAPS password that has not changed.
                    $existingPassword = ($existingItem.fields | Where-Object { $_.id -eq 'password' } | Select-Object -First 1).value
                    $existingSet = ConvertFrom-UtcString ($existingItem.fields | Where-Object { $_.id -eq 'laps_updated' } | Select-Object -First 1).value
                    if ($existingPassword -eq $laps.Current.Password -and $existingSet) { $passwordSet = $existingSet }
                }
            }

            $history = Merge-History -ExistingItem $existingItem -Laps $laps -CurrentId (Get-HistoryFieldId $passwordSet)
            $itemJson = New-ItemJson -Computer $computer -Laps $laps -PasswordSet $passwordSet -History $history

            if ($itemId) {
                if ($PSCmdlet.ShouldProcess($computer.Title, "Update 1Password item $itemId ($($history.Count) history entries)")) {
                    Invoke-Op @('item', 'edit', $itemId, '--vault', $vault.id, '--format', 'json') -InputJson $itemJson | Out-Null
                    Write-Log "$($computer.Title): updated item $itemId ($($history.Count) history entries)"
                    $stats.Updated++
                }
            }
            else {
                if ($PSCmdlet.ShouldProcess($computer.Title, "Create 1Password item ($($history.Count) history entries)")) {
                    $created = Invoke-Op @('item', 'create', '--vault', $vault.id, '--format', 'json', '-') -InputJson $itemJson | ConvertFrom-Json
                    $itemId = $created.id
                    $matchedItemIds[$itemId] = $true
                    Write-Log "$($computer.Title): created item $itemId ($($history.Count) history entries)"
                    $stats.Created++
                }
            }

            if (-not $WhatIfPreference) {
                $state[$computer.ObjectGuid] = @{ ItemId = $itemId; Version = $version; Title = $computer.Title }
            }
        }
        catch {
            Write-Log "$($computer.Title): $_" -Level ERROR
            $stats.Failed++
        }
    }

    if (-not $WhatIfPreference) { Save-State $state }

    if ($ArchiveOrphans) {
        $orphans = @($items | Where-Object { -not $matchedItemIds.ContainsKey($_.id) })
        if ($orphans.Count -and $items.Count -and -not $Force -and ($orphans.Count / $items.Count) -gt 0.25) {
            Write-Log "Not archiving $($orphans.Count) of $($items.Count) items: more than 25% of items would be archived. Check the AD search, or run with -Force." -Level ERROR
            $stats.Failed++
        }
        else {
            foreach ($orphan in $orphans) {
                try {
                    if ($PSCmdlet.ShouldProcess($orphan.title, "Archive 1Password item $($orphan.id) (computer no longer found in AD)")) {
                        Invoke-Op @('item', 'delete', $orphan.id, '--vault', $vault.id, '--archive') | Out-Null
                        Write-Log "$($orphan.title): archived item $($orphan.id); its computer is no longer in the AD search"
                        $stats.Archived++
                    }
                }
                catch {
                    Write-Log "$($orphan.title): could not archive: $_" -Level ERROR
                    $stats.Failed++
                }
            }
        }
    }

    Write-Log ('Finished. Computers={0} Created={1} Updated={2} Unchanged={3} Skipped={4} Archived={5} Failed={6}' -f
        $stats.Computers, $stats.Created, $stats.Updated, $stats.Unchanged, $stats.Skipped, $stats.Archived, $stats.Failed)
    if ($stats.Failed) { exit 1 }
    exit 0
}
catch {
    Write-Log "Sync aborted: $_" -Level ERROR
    exit 2
}

#endregion
