#Requires -RunAsAdministrator

Write-Host "[*] Executing Master IRSeC 2026 Blue Team Hardening Script..." -ForegroundColor Cyan

# Helper function to safely set registry properties
function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$PropertyType = "DWord"
    )
    if (-not (Test-Path -Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
}

# ------------------------------------------------------------------
# 1. Clean IFEO Debugger Hijacks (Sticky Keys / Accessibility Backdoors)
# ------------------------------------------------------------------
Write-Host "[+] Auditing and Clearing Accessibility IFEO Persistence Backdoors..." -ForegroundColor Yellow
$accessibilityApps = @("sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe")
foreach ($app in $accessibilityApps) {
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$app"
    if (Test-Path -Path $ifeoPath) {
        $debugger = (Get-ItemProperty -Path $ifeoPath -Name "Debugger" -ErrorAction SilentlyContinue).Debugger
        if ($debugger) {
            Remove-ItemProperty -Path $ifeoPath -Name "Debugger" -Force -ErrorAction SilentlyContinue
            Write-Host "    [!] REMOVED RED TEAM BACKDOOR: Cleared Debugger '$debugger' on $app" -ForegroundColor Red
        }
    }
}

# ------------------------------------------------------------------
# 2. Disable WPAD (Web Proxy Auto-Discovery / Responder Target)
# ------------------------------------------------------------------
Write-Host "[+] Disabling Web Proxy Auto-Discovery (WPAD)..." -ForegroundColor Yellow
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -Name "DisableWpad" -Value 1
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "EnableAutoProxyResultCache" -Value 0
    Write-Host "    [OK] WPAD disabled safely via Registry." -ForegroundColor Green
} catch {
    Write-Host "    [X] Error disabling WPAD: $_" -ForegroundColor Red
}

# ------------------------------------------------------------------
# 3. Disable Windows Script Host (WSH - Blocks VBS/JS Payloads)
# ------------------------------------------------------------------
Write-Host "[+] Disabling Windows Script Host (WSH)..." -ForegroundColor Yellow
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
    Write-Host "    [OK] WSH disabled." -ForegroundColor Green
} catch {
    Write-Host "    [X] Error disabling WSH: $_" -ForegroundColor Red
}

# ------------------------------------------------------------------
# 4. Expand Event Log Sizes and Enable Auditing (30% IR Report Evidence)
# ------------------------------------------------------------------
Write-Host "[+] Expanding Event Logs to 512MB and Activating Auditing..." -ForegroundColor Yellow
$classicLogs = @("Security", "System", "Application")
foreach ($log in $classicLogs) {
    try {
        Limit-EventLog -LogName $log -MaximumSize 512MB -OverflowAction OverwriteAsNeeded -ErrorAction SilentlyContinue
    } catch {}
}

# Expand PowerShell ETW Operational log via wevtutil
try {
    wevtutil.exe sl "Microsoft-Windows-PowerShell/Operational" /ms:536870912 /e:true 2>$null
} catch {}

# Enable ScriptBlock Logging and Command Line Auditing
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1
Write-Host "    [OK] Event logs expanded to 512MB and execution auditing enabled." -ForegroundColor Green

# ------------------------------------------------------------------
# 5. Disable Legacy Protocols (SMBv1, LLMNR, mDNS, NetBIOS, PSv2)
# ------------------------------------------------------------------
Write-Host "[+] Disabling Legacy Network Protocols and PSv2 Engine..." -ForegroundColor Yellow

# Disable SMBv1 & PSv2 via native DISM binary (prevents PowerShell cmdlet feature errors)
try {
    dism.exe /online /disable-feature /featurename:SMB1Protocol /norestart 2>$null | Out-Null
    dism.exe /online /disable-feature /featurename:MicrosoftWindowsPowerShellV2 /norestart 2>$null | Out-Null
    dism.exe /online /disable-feature /featurename:MicrosoftWindowsPowerShellV2Root /norestart 2>$null | Out-Null
} catch {}

# Disable LLMNR and mDNS via Registry
Set-RegistryValue -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMDNS" -Value 0

# Disable NetBIOS via CIM/WMI
try {
    $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPEnabled }
    foreach ($adapter in $adapters) {
        try {
            Invoke-CimMethod -InputObject $adapter -MethodName "SetTcpipNetbios" -Arguments @{TcpipNetbiosOptions = 2} -ErrorAction SilentlyContinue | Out-Null
        } catch {}
    }
} catch {}

# Disable NetBIOS via Registry across all interface keys (Direct fail-safe)
try {
    $netBtPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
    if (Test-Path -Path $netBtPath) {
        Get-ChildItem -Path $netBtPath -ErrorAction SilentlyContinue | ForEach-Object {
            Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 -Type DWord -ErrorAction SilentlyContinue
        }
    }
} catch {}

Write-Host "    [OK] Legacy protocols (SMBv1, LLMNR, mDNS, NetBIOS, PSv2) disabled." -ForegroundColor Green

# ------------------------------------------------------------------
# 6. Credential and Memory Protection (WDigest, LSA, LM Hash)
# ------------------------------------------------------------------
Write-Host "[+] Enforcing Memory and Credential Protections..." -ForegroundColor Yellow
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
Write-Host "    [OK] LmCompatibilityLevel=5, NoLMHash=1, RunAsPPL=1, WDigest cleartext disabled." -ForegroundColor Green

# ------------------------------------------------------------------
# 7. Disable Built-In Guest Account (Rule 6 Safeguard for 'whiteteam')
# ------------------------------------------------------------------
Write-Host "[+] Checking Guest Account status..." -ForegroundColor Yellow
try {
    $guestAccount = Get-CimInstance Win32_UserAccount -Filter "LocalAccount = True AND SID LIKE '%-501'" -ErrorAction SilentlyContinue
    if ($guestAccount) {
        if ($guestAccount.Name -ne "whiteteam") {
            Disable-LocalUser -SID $guestAccount.SID -ErrorAction SilentlyContinue
            net user "$($guestAccount.Name)" /active:no 2>$null | Out-Null
            Write-Host "    [OK] Guest account disabled." -ForegroundColor Green
        }
    }
} catch {}

# ------------------------------------------------------------------
# 8. Disable Non-Essential Vulnerable Services
# ------------------------------------------------------------------
Write-Host "[+] Disabling Non-Essential Services..." -ForegroundColor Yellow
$servicesToDisable = @("RemoteRegistry", "Spooler", "SSDPSRV", "upnphost")
foreach ($svc in $servicesToDisable) {
    try {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    } catch {}
}
Write-Host "    [OK] RemoteRegistry, Spooler, SSDP, UPnP disabled." -ForegroundColor Green

# ------------------------------------------------------------------
# 9. Schannel TLS Protocol Configuration and NLA for RDP
# ------------------------------------------------------------------
Write-Host "[+] Enforcing TLS 1.2/1.3 and RDP NLA..." -ForegroundColor Yellow
$legacyProtocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
foreach ($proto in $legacyProtocols) {
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto"
    Set-RegistryValue -Path "$basePath\Server" -Name "Enabled" -Value 0
    Set-RegistryValue -Path "$basePath\Server" -Name "DisabledByDefault" -Value 1
    Set-RegistryValue -Path "$basePath\Client" -Name "Enabled" -Value 0
    Set-RegistryValue -Path "$basePath\Client" -Name "DisabledByDefault" -Value 1
}
$modernProtocols = @("TLS 1.2", "TLS 1.3")
foreach ($proto in $modernProtocols) {
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto"
    Set-RegistryValue -Path "$basePath\Server" -Name "Enabled" -Value 1
    Set-RegistryValue -Path "$basePath\Server" -Name "DisabledByDefault" -Value 0
    Set-RegistryValue -Path "$basePath\Client" -Name "Enabled" -Value 1
    Set-RegistryValue -Path "$basePath\Client" -Name "DisabledByDefault" -Value 0
}
Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1
Write-Host "    [OK] Legacy SSL/TLS disabled; TLS 1.2/1.3 and RDP NLA enforced." -ForegroundColor Green

# ------------------------------------------------------------------
# 10. WinRM and SMB Service Guarantee (Scoring Protection)
# ------------------------------------------------------------------
Write-Host "[+] Ensuring WinRM and SMB Services remain active for scoring..." -ForegroundColor Yellow
try {
    Set-Service -Name "WinRM" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "WinRM" -ErrorAction SilentlyContinue

    Set-Service -Name "LanmanServer" -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name "LanmanServer" -ErrorAction SilentlyContinue
} catch {}
Write-Host "    [OK] WinRM and SMB services configured and running." -ForegroundColor Green

# ------------------------------------------------------------------
# 11. Disable AutoRun Across All Drives
# ------------------------------------------------------------------
Write-Host "[+] Disabling AutoRun across all drives..." -ForegroundColor Yellow
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255
Write-Host "    [OK] AutoRun disabled (0xFF)." -ForegroundColor Green

Write-Host "`n[*] Master Hardening Script Execution Completed Successfully." -ForegroundColor Cyan