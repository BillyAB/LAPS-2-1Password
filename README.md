# Sync-LapsTo1Password

A PowerShell script that copies Windows LAPS passwords and their history from Active Directory into a 1Password vault. It signs in to 1Password with a service account and is meant to run as a Windows scheduled task.

It is based on [marioneubert/laps2onepassword](https://github.com/marioneubert/laps2onepassword) (Go), with these differences:

| | laps2onepassword | This script |
|---|---|---|
| LAPS version | Legacy only (`ms-Mcs-AdmPwd`) | Windows LAPS (encrypted and cleartext) and legacy LAPS, through `Get-LapsADPassword` |
| Password history | None | AD history plus 1Password history that is kept after AD rotates it out |
| 1Password auth | Connect server | Service account token through `op.exe` (no Connect server needed) |
| AD auth | Bind DN and password in `.env` | The identity running the task (Kerberos) |

## What a synced item looks like

There is one **Login** item per computer. Its title is the computer's DNS hostname in lower case, and it is tagged `LAPS`.

- **username / password**: the LAPS-managed account and its current password. 1Password's built-in password history also records every value the sync replaces.
- **LAPS details**: hostname, DN, object GUID, OS, LAPS source, when the password was set, when it expires, and when it was last synced.
- **LAPS password history**: one concealed field per earlier password, labelled with the UTC time it was set, newest first. Each run merges the entries from AD's `msLAPS-EncryptedPasswordHistory` with the entries already stored in 1Password and with the password being replaced. The section therefore holds up to `-MaxHistory` entries (default 50), more than AD's limit of 12.

The script manages these items completely, so any manual edit to one is overwritten the next time that computer's password changes.

## Prerequisites

1. **A Windows Server to run it on** with the inbox `LAPS` PowerShell module (Server 2019 or later with the April 2023 update, or Server 2022/2025) and Windows PowerShell 5.1.
2. **The 1Password CLI**, version 2.25 or later, installed for all users, for example `winget install AgileBits.1Password.CLI --scope machine`. If `op.exe` is not on `PATH`, pass `-OpPath`.
3. **A 1Password service account** (in 1Password: Developer > Service Accounts) with **read and write** access to the target vault. Service accounts cannot use Personal, Private or Employee vaults.
4. **A domain account to run the task**, with the following rights:
   - Permission to read the LAPS password attributes on the OUs in scope. Grant it with `Set-LapsADReadPasswordPermission -Identity 'OU=Servers,DC=corp,DC=example,DC=com' -AllowedPrincipals 'CORP\svc-laps1p'`.
   - For encrypted Windows LAPS passwords, membership of the group named in the **Configure authorized password decryptors** (`ADPasswordEncryptionPrincipal`) policy. The default decryptor group is Domain Admins, so a dedicated group is better.
   - Legacy LAPS only: read on `ms-Mcs-AdmPwd`, granted with `Set-AdmPwdReadPasswordPermission`.
   - **Log on as a batch job** on the server that runs the task.

   Password history exists in AD only when password encryption is enabled. That is a Windows LAPS limitation.

## Automated setup (gMSA or service account)

`Install-LapsTo1Password.ps1` sets everything up in one go. Run it elevated on the sync server, with `Sync-LapsTo1Password.ps1` in the same folder:

```powershell
.\Install-LapsTo1Password.ps1 -ServiceAccount 'CORP\gmsa-laps1p$' -VaultName 'LAPS - Servers' `
    -SearchBase 'OU=Servers,DC=corp,DC=example,DC=com' -ArchiveOrphans
```

It does the following:

1. Checks the gMSA is usable on this server, using `Test-ADServiceAccount`.
2. Grants the account Modify on `C:\ProgramData\LapsTo1Password`.
3. Prompts for the 1Password token and writes it to a staging file that only the account, SYSTEM and Administrators can read.
4. Runs a one-off task as the account that calls `Sync-LapsTo1Password.ps1 -SaveToken -TokenFile`, so the token is DPAPI-encrypted for that account.
5. Deletes the one-off task and the staging file.
6. Registers or updates the recurring sync task, every 30 minutes by default (`-IntervalMinutes`).

An account name ending in `$` is treated as a gMSA. For any other name you are prompted for the account's password.

Other ways to run it:
- `-ExtraArguments '-WhatIf' -StartTask`: a dry run. Run it again without them to go live.
- `-TokenOnly`: rotate the token without changing the task.
- `-SkipToken`: change the task's settings without re-entering the token.

The script does not grant the AD and LAPS rights listed under [Prerequisites](#prerequisites), or **Log on as a batch job**.

## Manual setup

### 1. Save the service account token

The token is stored encrypted with DPAPI, so only the account that saved it can decrypt it, and only on the same server. Save it **as the account that will run the task**:

```powershell
runas /user:CORP\svc-laps1p powershell.exe
# in the new window:
C:\Scripts\LapsTo1Password\Sync-LapsTo1Password.ps1 -SaveToken
```

This writes `C:\ProgramData\LapsTo1Password\op-token.xml` and restricts its ACL to that account, SYSTEM and Administrators. To rotate the token, run `-SaveToken` again.

The script also uses `OP_SERVICE_ACCOUNT_TOKEN` if that environment variable is already set, for example when the token comes from a secrets store.

> **gMSA note:** a gMSA cannot sign in interactively to run `-SaveToken`. Use `Install-LapsTo1Password.ps1` instead (see [Automated setup](#automated-setup-gmsa-or-service-account)), which saves the token through a one-off scheduled task that runs as the gMSA.

### 2. Do a dry run

From the same `runas` window:

```powershell
.\Sync-LapsTo1Password.ps1 -VaultName 'LAPS - Servers' -SearchBase 'OU=Servers,DC=corp,DC=example,DC=com' -WhatIf -Verbose
```

`-WhatIf` reads AD and 1Password but writes nothing, including the state file. After that, run the same command without `-WhatIf` and check a few items in 1Password.

### 3. Register the scheduled task

Run this in an elevated session:

```powershell
$script = 'C:\Scripts\LapsTo1Password\Sync-LapsTo1Password.ps1'
$arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`" " +
             "-VaultName `"LAPS - Servers`" -SearchBase `"OU=Servers,DC=corp,DC=example,DC=com`" -ArchiveOrphans"

$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Minutes 30)
$settings  = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2) -StartWhenAvailable

Register-ScheduledTask -TaskName 'Sync LAPS to 1Password' -Action $action -Trigger $trigger -Settings $settings `
    -User 'CORP\svc-laps1p' -Password (Read-Host 'Service account password') -RunLevel Limited
```

For a gMSA, use `New-ScheduledTaskPrincipal -UserId 'CORP\gmsa-laps1p$' -LogonType Password` and `-Principal` instead of `-User`/`-Password`.

Use a sync interval shorter than your shortest LAPS password age. That way a password that is rotated and then rotated again before a sync still reaches 1Password, through the AD history.

## Parameters

Full help for either script is available with `Get-Help .\<script>.ps1 -Full`.

### Sync-LapsTo1Password.ps1

| Parameter | Default | Purpose |
|---|---|---|
| `-VaultName` | (required) | Vault name or ID |
| `-SearchBase` | Domain root | One or more OUs to search |
| `-Server` | Auto | Domain controller to use |
| `-LdapFilter` | Computers with a Windows or legacy LAPS expiry | Narrows which computers are synced |
| `-Tag` | `LAPS` | Tag on managed items. Only tagged items are matched or archived |
| `-MaxHistory` | `50` | History entries kept per item (0 to 500) |
| `-DefaultAccountName` | `Administrator` | Username for legacy LAPS, which does not report the account |
| `-ArchiveOrphans` | Off | Archive tagged items whose computer is no longer in the AD search |
| `-Force` | Off | Re-sync every computer, and allow archiving more than 25% of items in one run |
| `-OpPath` | Auto | Path to `op.exe`. Searched for on `PATH`, then in `C:\Program Files\1Password CLI`, then in the WinGet links folder |
| `-StatePath` | `C:\ProgramData\LapsTo1Password\state.json` | Which password version was last synced per computer. Holds item IDs and timestamps only |
| `-LogDirectory` | `C:\ProgramData\LapsTo1Password\Logs` | Folder for daily log files |
| `-LogRetentionDays` | `30` | Daily log files older than this are deleted |
| `-TokenPath` | `C:\ProgramData\LapsTo1Password\op-token.xml` | DPAPI-encrypted service account token. Ignored when `OP_SERVICE_ACCOUNT_TOKEN` is set |
| `-SaveToken` | Off | Prompt for the token and save it to `-TokenPath` instead of syncing |
| `-TokenFile` | None | With `-SaveToken`, read the token from this file instead of prompting (used by the install script) |

It also supports `-WhatIf` (read everything, write nothing) and `-Verbose` (log unchanged computers too).

Exit codes: `0` success, `1` some computers failed (see the log), `2` the run aborted.

### Install-LapsTo1Password.ps1

| Parameter | Default | Purpose |
|---|---|---|
| `-ServiceAccount` | (required) | Account the task runs as, as `DOMAIN\name`. A name ending in `$` is treated as a gMSA |
| `-Credential` | Prompted | Password for a standard service account. Not used for a gMSA |
| `-VaultName` | (required, except with `-TokenOnly`) | Passed to the sync script |
| `-SearchBase` | Domain root | Passed to the sync script |
| `-Server` | Auto | Passed to the sync script |
| `-ArchiveOrphans` | Off | Passed to the sync script |
| `-ExtraArguments` | None | Any other sync script parameters, added to the task's command as written. Use single quotes inside it |
| `-IntervalMinutes` | `30` | How often the sync task runs (5 to 1440) |
| `-ScriptPath` | `Sync-LapsTo1Password.ps1` next to the install script | Sync script the task runs. Keep it in a folder only administrators can write to |
| `-TaskName` | `Sync LAPS to 1Password` | Name of the recurring sync task |
| `-SkipToken` | Off | Only register or update the sync task |
| `-TokenOnly` | Off | Only save the token. Use it to rotate the token |
| `-StartTask` | Off | Start the sync task once it is registered |

## How it works and how it stays within rate limits

1. It checks `op.exe` and resolves the vault (2 reads).
2. It searches AD for computers with a LAPS expiry attribute. This search needs no decryption rights.
3. It lists the vault's tagged items (1 read).
4. For each computer it calls `Get-LapsADPassword -IncludeHistory`. This only talks to AD.
5. It compares the password's set time with `state.json`. If the time is unchanged and the item still exists, no 1Password calls are made.
6. Otherwise it fetches the existing item (1 read), merges the history, and creates or replaces the item (1 write).

A steady-state run therefore makes about 3 reads, plus 2 calls per rotated password, which keeps it within service account [rate limits](https://developer.1password.com/docs/service-accounts/rate-limits/) even for large estates. The first run does 1 to 2 calls per computer, so on a very large estate you may need to spread it out with `-SearchBase`.

`state.json` contains only item IDs and timestamps, not passwords. If you delete it, the next run does a full re-sync, which is safe.

## Security notes

- Passwords are sent to `op.exe` on stdin. They never appear in command lines (and so are not captured by process auditing such as event 4688), in temporary files, or in the log.
- The token is passed only in `op.exe`'s environment, never in the script's own process environment.
- Anyone with access to the vault can see every synced password and its history, so scope the vault and the service account tightly.
- Anyone who can read the token file and act as the task account can write to the vault. Protect the server accordingly (it is effectively tier 0 if it syncs domain controllers' DSRM passwords).
