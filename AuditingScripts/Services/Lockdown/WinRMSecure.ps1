<#
.SYNOPSIS
    IRSeC 2026 Fully Verified WinRM Hardening Script for Windows 11 (teamradio)
.DESCRIPTION
    Hardens WinRM WSMan parameters, audits administrative group memberships against
    the competition packet baseline, enables PowerShell ScriptBlock/Module logging,
    and enables WinRM audit logs.
.NOTES
    - Rule 6 Compliant: Preserves 'whiteteam' account access.
    - Rule 14.b.v Compliant: Protects DataDog out-of-scope accounts (ddagentuser / dd-agent).
    - Rule 15 Compliant: Avoids subnet/firewall network blocking.
    - Packet Compliant: Protects all legitimate packet accounts from disablement/deletion.
#>

# Requires Elevated Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[!] Must be run from an Elevated PowerShell Session (Run as Administrator)." -ErrorAction Stop
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  IRSeC WinRM Hardening & Audit Script (teamradio)" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# ----------------------------------------------------------------------
# Competition Packet User Baselines
# ----------------------------------------------------------------------
$BaselineAdmins = @(
    "whiteteam",      # MANDATORY Rule 6
    "scrutineer",     # Local Admin
    "techdirector",   # Local Admin
    "crewchief",      # Local Admin
    "firecrew",       # Local Admin
    "principal",      # Domain Admin
    "sportingdir",    # Domain Admin
    "chiefeng",       # Domain Admin
    "strategist",     # Domain Admin
    "Domain Admins",  # Built-in Domain Admin Group
    "Administrator",  # Built-in Local Admin (Compsole Safety)
    "ddagentuser",    # DataDog User (Rule 14.b.v - Out of Scope)
    "dd-agent"        # DataDog User/Group (Rule 14.b.v - Out of Scope)
)

$BaselineRegularUsers = @(
    # Local Regular Users
    "jackcrew", "garagecrew", "celebrity", "pitlaner", "reserve", "gunners",
    # Domain Regular Users
    "pitcrew", "mechanic", "analyst", "driver", "tireman", "fuelman"
)

# ----------------------------------------------------------------------
# Helper Function: Packet-Aware User Processing
# ----------------------------------------------------------------------
function Confirm-And-ProcessUser {
    param (
        [string]$AccountName,
        [string]$SourceGroup
    )
    
    $cleanName = ($AccountName -split "\\")[-1]

    # Rule 6 Safeguard
    if ($cleanName -ieq "whiteteam") {
        Write-Host "    [*] SAFEGUARD: Skipping 'whiteteam' user (Rule 6 Protection)." -ForegroundColor Cyan
        return
    }

    # Rule 14.b.v Safeguard (DataDog Out of Scope)
    if ($cleanName -ieq "ddagentuser" -or $cleanName -ieq "dd-agent") {
        Write-Host "    [*] SAFEGUARD: Skipping DataDog account '$cleanName' (Rule 14.b.v Protection)." -ForegroundColor Cyan
        return
    }

    # Case 1: Legitimate Regular Packet User elevated to Admin/WinRM group
    if ($cleanName -in $BaselineRegularUsers) {
        Write-Host "`n    [!] UNAUTHORIZED ELEVATION: Regular packet user '$AccountName' found in '$SourceGroup'." -ForegroundColor Yellow
        try {
            Remove-LocalGroupMember -Group $SourceGroup -Member $AccountName -ErrorAction Stop
            Write-Host "        [+] SUCCESS: Stripped unauthorized '$SourceGroup' rights from '$cleanName'." -ForegroundColor Green
            Write-Host "        [*] PACKET SAFEGUARD: User account '$cleanName' kept ENABLED." -ForegroundColor Cyan
        } catch {
            Write-Host "        [!] ERROR: Failed to remove '$AccountName' from '$SourceGroup': $_" -ForegroundColor Red
        }
        return
    }

    # Case 2: Unrecognized / Rogue Account (Not in Packet)
    Write-Host "`n    [!] ROGUE ACCOUNT DETECTED: '$AccountName' in group '$SourceGroup' (Not in Packet)." -ForegroundColor Red
    $response = Read-Host "        Do you want to REMOVE this rogue account from '$SourceGroup' and DISABLE it? (Y/N)"
    
    if ($response -match "^[Yy]") {
        # Step 1: Remove from Group (Works for Domain accounts, Local accounts, Groups, and SIDs)
        try {
            Remove-LocalGroupMember -Group $SourceGroup -Member $AccountName -ErrorAction Stop
            Write-Host "        [+] SUCCESS: '$AccountName' removed from group '$SourceGroup'." -ForegroundColor Green
        } catch {
            Write-Host "        [!] ERROR: Failed to remove '$AccountName' from '$SourceGroup': $_" -ForegroundColor Red
        }

        # Step 2: Disable local account if SAM local user
        try {
            $localUser = Get-LocalUser -Name $cleanName -ErrorAction SilentlyContinue
            if ($localUser) {
                Disable-LocalUser -Name $cleanName -ErrorAction Stop
                Write-Host "        [+] SUCCESS: Rogue local account '$cleanName' disabled." -ForegroundColor Green
            } else {
                Write-Host "        [*] '$AccountName' is a Domain account, Group, or SID. Local disable skipped." -ForegroundColor Gray
            }
        } catch {
            Write-Host "        [!] ERROR: Failed to disable local account '$cleanName': $_" -ForegroundColor Red
        }
    } else {
        Write-Host "        [-] Skipped action for '$AccountName'." -ForegroundColor Gray
    }
}

# ----------------------------------------------------------------------
# 1. WSMan Configuration Hardening
# ----------------------------------------------------------------------
Write-Host "`n[+] Configuring WSMan & Service Parameters..." -ForegroundColor Yellow

Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM -ErrorAction SilentlyContinue

# Force Encryption (Disallow Plaintext Traffic)
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false -Force

# Enforce Limits on WSMan Service and Shell
Set-Item -Path WSMan:\localhost\Service\MaxConcurrentOperationsPerUser -Value 15 -Force
Set-Item -Path WSMan:\localhost\Shell\IdleTimeout -Value 1800000 -Force # 30 minutes in ms

# Disable Insecure Service Auth Methods (Basic, CredSSP)
# Note: If Hermes scoring checks fail, toggle Basic back to $true.
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false -Force
Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $false -Force
Set-Item -Path WSMan:\localhost\Service\Auth\Kerberos -Value $true -Force
Set-Item -Path WSMan:\localhost\Service\Auth\Negotiate -Value $true -Force

Write-Host "    -> WSMan Service Hardened (AllowUnencrypted=False, Basic=False, CredSSP=False)" -ForegroundColor Green

# ----------------------------------------------------------------------
# 2. Interactive Audit & Account Processing
# ----------------------------------------------------------------------
Write-Host "`n[+] Auditing Local Administrative & Remote Management Groups..." -ForegroundColor Yellow

# Audit 'Remote Management Users' Group
$RMUsers = Get-LocalGroupMember -Group "Remote Management Users" -ErrorAction SilentlyContinue
foreach ($member in $RMUsers) {
    $targetIdentifier = if ([string]::IsNullOrWhiteSpace($member.Name)) { if ($member.SID) { $member.SID.Value } else { $null } } else { $member.Name }
    if ([string]::IsNullOrWhiteSpace($targetIdentifier)) { continue }
    
    $cleanName = ($targetIdentifier -split "\\")[-1]

    if ($cleanName -notin $BaselineAdmins) {
        Confirm-And-ProcessUser -AccountName $targetIdentifier -SourceGroup "Remote Management Users"
    }
}

# Audit 'Administrators' Group
$CurrentAdmins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
foreach ($admin in $CurrentAdmins) {
    $targetIdentifier = if ([string]::IsNullOrWhiteSpace($admin.Name)) { if ($admin.SID) { $admin.SID.Value } else { $null } } else { $admin.Name }
    if ([string]::IsNullOrWhiteSpace($targetIdentifier)) { continue }

    $cleanName = ($targetIdentifier -split "\\")[-1]

    if ($cleanName -notin $BaselineAdmins) {
        Confirm-And-ProcessUser -AccountName $targetIdentifier -SourceGroup "Administrators"
    }
}

# ----------------------------------------------------------------------
# 3. Endpoint Security & PSRemoting Verification
# ----------------------------------------------------------------------
Write-Host "`n[+] Verifying PSSession Configurations..." -ForegroundColor Yellow

# SkipNetworkProfileCheck prevents failures on Windows 11 Public interfaces
Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction SilentlyContinue
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

# ----------------------------------------------------------------------
# 4. Enable PowerShell & WinRM Audit Logging
# ----------------------------------------------------------------------
Write-Host "`n[+] Enabling PowerShell Script Block & Module Logging..." -ForegroundColor Yellow

# ScriptBlock Logging (Event ID 4104)
$SBLPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (!(Test-Path $SBLPath)) { New-Item -Path $SBLPath -Force | Out-Null }
New-ItemProperty -Path $SBLPath -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $SBLPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -PropertyType DWord -Force | Out-Null

# Module Logging
$MLPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (!(Test-Path $MLPath)) { New-Item -Path $MLPath -Force | Out-Null }
New-ItemProperty -Path $MLPath -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force | Out-Null

$ModuleNamesPath = "$MLPath\ModuleNames"
if (!(Test-Path $ModuleNamesPath)) { New-Item -Path $ModuleNamesPath -Force | Out-Null }
New-ItemProperty -Path $ModuleNamesPath -Name "*" -Value "*" -PropertyType String -Force | Out-Null

# Enable WinRM Operational Log Channel via native Windows EventLog tool
wevtutil.exe set-log "Microsoft-Windows-WinRM/Operational" /e:true

Write-Host "    -> Script Block Logging (ID 4104) and WinRM Operational Logs Activated." -ForegroundColor Green

# ----------------------------------------------------------------------
# 5. Reset WinRM Service
# ----------------------------------------------------------------------
Write-Host "`n[+] Flushing Active WSMan Remoting Connections..." -ForegroundColor Yellow
Write-Host "    [!] NOTICE: If running via remote WinRM, your session will temporarily disconnect." -ForegroundColor Cyan

Restart-Service -Name WinRM -Force

Write-Host "    -> WinRM Service Restarted." -ForegroundColor Green

# ----------------------------------------------------------------------
# 6. Verification Checklist
# ----------------------------------------------------------------------
Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host "  HARDENING COMPLETE - IMMEDIATE ACTIONS:" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "1. Check Hermes Scoring Dashboard (scoring.irsec.club)."
Write-Host "   -> If WinRM scoring turns RED, run:"
Write-Host "      Set-Item WSMan:\localhost\Service\Auth\Basic -Value `$true" -ForegroundColor Yellow
Write-Host "2. Verify 'whiteteam' user access remains active (Rule 6)."