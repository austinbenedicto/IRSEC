# Requires Administrator Privileges
# ==============================================================================
# IRSeC Telnet Hardening & Remediation Script (Windows / safetycar)
# ==============================================================================

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator!"
    exit
}

Write-Host "[+] Starting Telnet Service Hardening..." -ForegroundColor Green

# 1. Verify Telnet Feature Presence on Windows 10
$telnetFeature = Get-WindowsOptionalFeature -Online -FeatureName "TelnetServer" -ErrorAction SilentlyContinue
if ($telnetFeature -and $telnetFeature.State -ne "Enabled") {
    Write-Host "[!] TelnetServer feature is disabled/missing. Enabling feature..." -ForegroundColor Yellow
    Enable-WindowsOptionalFeature -Online -FeatureName "TelnetServer" -NoRestart | Out-Null
}

# 2. Fix Service Binary Path
$svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TlntSvr"
if (Test-Path $svcPath) {
    Set-ItemProperty -Path $svcPath -Name "ImagePath" -Value "C:\Windows\System32\tlntsvr.exe" -Type ExpandString
    Set-Service -Name "TlntSvr" -StartupType Automatic
    Write-Host "[+] Service binary path verified: C:\Windows\System32\tlntsvr.exe" -ForegroundColor Green
} else {
    Write-Host "[-] Telnet service registry path missing!" -ForegroundColor Red
}

# 3. Clean Telnet Registry Defaults
$telnetRegPath = "HKLM:\SOFTWARE\Microsoft\TelnetServer\1.0"
if (-not (Test-Path $telnetRegPath)) {
    New-Item -Path $telnetRegPath -Force | Out-Null
}

New-ItemProperty -Path $telnetRegPath -Name "DefaultShell" -Value "C:\Windows\System32\cmd.exe" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $telnetRegPath -Name "TelnetSysport" -Value 23 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $telnetRegPath -Name "DefaultDomain" -Value "." -PropertyType String -Force | Out-Null

Write-Host "[+] Telnet registry defaults (DefaultShell, TelnetSysport=23, DefaultDomain=.) enforced." -ForegroundColor Green

# 4. Apply Configuration Limits via tlntadmn
Write-Host "[+] Applying runtime configuration limits..." -ForegroundColor Yellow

& tlntadmn config maxfail=10 | Out-Null
& tlntadmn config timeoutactive=yes | Out-Null
& tlntadmn config timeout=00:05:00 | Out-Null
& tlntadmn config maxconn=20 | Out-Null
& tlntadmn config mode=console | Out-Null
& tlntadmn config sec = +passwd | Out-Null

# 5. Evict Active Telnet Sessions
Write-Host "[+] Terminating existing active Telnet sessions..." -ForegroundColor Yellow
try { & tlntadmn -k all 2>$null | Out-Null } catch {}

# 6. Optimized Firewall Audit (Rule 15 Compliant)
Write-Host "[+] Auditing Windows Firewall rules on Port 23..." -ForegroundColor Yellow

# Query port filters directly for fast, error-free filtering
$port23Filters = Get-NetFirewallPortFilter -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq "23" -or $_.LocalPort -contains "23" }
$blockingRules = @()

if ($port23Filters) {
    foreach ($filter in $port23Filters) {
        $rule = $filter | Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Direction -eq "Inbound" -and $_.Action -eq "Block" -and $_.Enabled -eq "True" }
        if ($rule) { $blockingRules += $rule }
    }
}

if ($blockingRules.Count -gt 0) {
    Write-Host "`n[!] WARNING: Found active blocking firewall rule(s) targeting Port 23:" -ForegroundColor Red
    $blockingRules | Select-Object Name, DisplayName, Enabled, Profile, Action | Format-Table -AutoSize

    $userPrompt = Read-Host "Do you want to delete these blocking firewall rule(s)? (Y/N)"
    if ($userPrompt -eq 'Y' -or $userPrompt -eq 'y') {
        $blockingRules | Remove-NetFirewallRule
        Write-Host "[+] Blocking firewall rule(s) removed." -ForegroundColor Green
    } else {
        Write-Host "[-] Skipped blocking rule removal. (Block rules take precedence over Allow rules)." -ForegroundColor Yellow
    }
} else {
    Write-Host "[+] No active blocking firewall rules found on Port 23." -ForegroundColor Green
}


# 7. Start / Restart Telnet Service Safely
Write-Host "[+] Restarting TlntSvr service..." -ForegroundColor Yellow
Start-Sleep -Seconds 1

$svc = Get-Service -Name "TlntSvr" -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Running') {
        Start-Service -Name "TlntSvr"
        Write-Host "[+] TlntSvr service started." -ForegroundColor Green
    } else {
        Restart-Service -Name "TlntSvr" -Force
        Write-Host "[+] TlntSvr service restarted." -ForegroundColor Green
    }
} else {
    Write-Host "[-] TlntSvr service is not installed on this system." -ForegroundColor Red
}

# 8. Verification Summary
Write-Host "`n================ HARDENING SUMMARY ================" -ForegroundColor Cyan
Get-Service -Name "TlntSvr" | Select-Object Name, Status, StartType | Format-Table -AutoSize
& tlntadmn
Write-Host "===================================================" -ForegroundColor Cyan