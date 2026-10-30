<#
.SYNOPSIS
    WinRM Blue Team Security & Configuration Audit Script (V2)
    Target OS: Windows 11 / Windows Server (IRSec Competition)
#>

# Ensure running with Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script from an elevated PowerShell terminal (Run as Administrator)."
    exit
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   IRSec WinRM Security & Integrity Audit Tool    " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "Machine:   $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host ""

# --------------------------------------------------
# 1. WINRM SERVICE STATUS & STARTUP TYPE
# --------------------------------------------------
Write-Host "[1] Checking WinRM Service Status..." -ForegroundColor Yellow
$winrmSvc = Get-Service -Name WinRM -ErrorAction SilentlyContinue

if ($winrmSvc) {
    $statusColor = if ($winrmSvc.Status -eq 'Running') { "Green" } else { "Red" }
    Write-Host "  Service Status: " -NoNewline
    Write-Host "$($winrmSvc.Status)" -ForegroundColor $statusColor
    
    $startColor = if ($winrmSvc.StartType -eq 'Automatic') { "Green" } else { "Yellow" }
    Write-Host "  Start Type:     " -NoNewline
    Write-Host "$($winrmSvc.StartType)" -ForegroundColor $startColor
    
    if ($winrmSvc.StartType -ne 'Automatic') {
        Write-Host "  [!] RECOMMENDATION: Set startup to Automatic to ensure scored uptime across reboots." -ForegroundColor Yellow
        Write-Host "      Command: Set-Service -Name WinRM -StartupType Automatic" -ForegroundColor Gray
    }
} else {
    Write-Host "  [!] WinRM Service is NOT installed!" -ForegroundColor Red
}
Write-Host ""

# --------------------------------------------------
# 2. WINRM LISTENERS
# --------------------------------------------------
Write-Host "[2] Auditing WinRM Listeners..." -ForegroundColor Yellow
try {
    $listeners = Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop
    if ($listeners) {
        foreach ($l in $listeners) {
            $transport = $l.Keys[0] # HTTP or HTTPS
            $address   = $l.Keys[1]
            $port      = (Get-Item "WSMan:\localhost\Listener\$($l.Name)\Port").Value
            $enabled   = (Get-Item "WSMan:\localhost\Listener\$($l.Name)\Enabled").Value
            
            Write-Host "  - Listener Name: $($l.Name)" -ForegroundColor Cyan
            Write-Host "    Transport:     $transport"
            Write-Host "    Address:       $address"
            Write-Host "    Port:          $port"
            Write-Host "    Enabled:       $enabled"
            
            if ($transport -eq 'HTTPS') {
                $cert = (Get-Item "WSMan:\localhost\Listener\$($l.Name)\CertificateThumbprint").Value
                Write-Host "    CertThumb:     $cert"
            }
            Write-Host ""
        }
    } else {
        Write-Host "  [!] No active WinRM listeners configured!" -ForegroundColor Red
    }
} catch {
    Write-Host "  [!] Failed to query WSMan drive listeners: $_" -ForegroundColor Red
}

# --------------------------------------------------
# 3. WSMAN CONFIGURATION & SECURITY AUDIT
# --------------------------------------------------
Write-Host "[3] Auditing WinRM Security Settings..." -ForegroundColor Yellow

$serviceConfig = Get-Item WSMan:\localhost\Service -ErrorAction SilentlyContinue

if ($serviceConfig) {
    $allowUnencrypted = (Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction SilentlyContinue).Value
    $basicAuth        = (Get-Item WSMan:\localhost\Service\Auth\Basic -ErrorAction SilentlyContinue).Value
    $trustedHosts     = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction SilentlyContinue).Value

    Write-Host "  AllowUnencrypted: " -NoNewline
    if ($allowUnencrypted -eq $true -or $allowUnencrypted -eq "true") {
        Write-Host "$allowUnencrypted (RISK: Traffic sent in plaintext)" -ForegroundColor Red
    } else {
        Write-Host "$allowUnencrypted (Secure)" -ForegroundColor Green
    }

    Write-Host "  Basic Auth:       " -NoNewline
    if ($basicAuth -eq $true -or $basicAuth -eq "true") {
        Write-Host "$basicAuth (WARNING: Basic Auth enabled)" -ForegroundColor Yellow
    } else {
        Write-Host "$basicAuth (Secure)" -ForegroundColor Green
    }

    Write-Host "  TrustedHosts:     " -NoNewline
    if ($trustedHosts -eq "*") {
        Write-Host "'*' (RISK: Accepts connections from ANY host)" -ForegroundColor Red
    } elseif ([string]::IsNullOrWhiteSpace($trustedHosts)) {
        Write-Host "[None Configured] (Default)" -ForegroundColor Green
    } else {
        Write-Host "$trustedHosts" -ForegroundColor Yellow
    }
}
Write-Host ""

# --------------------------------------------------
# 4. PSSESSION CONFIGURATIONS (PERSISTENCE CHECK)
# --------------------------------------------------
Write-Host "[4] Checking PSSession Endpoints (Red Team Backdoor Check)..." -ForegroundColor Yellow
$endpoints = Get-PSSessionConfiguration -ErrorAction SilentlyContinue
$standardEndpoints = @("microsoft.powershell", "microsoft.powershell32", "microsoft.powershell.workflow")

foreach ($ep in $endpoints) {
    $isStandard = $standardEndpoints -contains $ep.Name.ToLower()
    
    if (-not $isStandard) {
        Write-Host "  [!] CUSTOM ENDPOINT DETECTED (Possible Persistence): $($ep.Name)" -ForegroundColor Red
        Write-Host "      RunspaceType: $($ep.RunspaceType)" -ForegroundColor Red
        Write-Host "      Permission:   $($ep.SecurityDescriptorSddl)" -ForegroundColor Red
    } else {
        Write-Host "  - Standard Endpoint: $($ep.Name) [State: $($ep.State)]" -ForegroundColor Green
    }
}
Write-Host ""

# --------------------------------------------------
# 5. ACTIVE WINRM CONNECTIONS
# --------------------------------------------------
Write-Host "[5] Active Network Connections on WinRM Ports (5985 / 5986)..." -ForegroundColor Yellow
$activeConns = Get-NetTCPConnection -LocalPort 5985, 5986 -ErrorAction SilentlyContinue | Where-Object State -eq 'Established'

if ($activeConns) {
    foreach ($conn in $activeConns) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        Write-Host "  [!] ACTIVE CONNECTION:" -ForegroundColor Red
        Write-Host "      Remote IP:   $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor Yellow
        Write-Host "      Local Port:  $($conn.LocalPort)"
        Write-Host "      Process:     $($proc.Name) (PID: $($conn.OwningProcess))"
    }
} else {
    Write-Host "  No active established connections on 5985 or 5986 at this moment." -ForegroundColor Green
}
Write-Host ""

# --------------------------------------------------
# 6. RECENT WINRM LOGON & CONNECTION LOGS
# --------------------------------------------------
Write-Host "[6] Recent WinRM Operational Events (Last 15 Events)..." -ForegroundColor Yellow
$winrmLog = "Microsoft-Windows-WinRM/Operational"

if (Get-WinEvent -ListLog $winrmLog -ErrorAction SilentlyContinue) {
    $events = Get-WinEvent -LogName $winrmLog -MaxEvents 15 -ErrorAction SilentlyContinue
    
    if ($events) {
        foreach ($evt in $events) {
            $time = $evt.TimeCreated.ToString("HH:mm:ss")
            $id   = $evt.Id
            $msg  = ($evt.Message -split "`r?`n")[0]
            Write-Host "  [$time] Event ID ${id}: $msg" -ForegroundColor Cyan
        }
    } else {
        Write-Host "  No recent events found in $winrmLog." -ForegroundColor Green
    }
} else {
    Write-Host "  [!] WinRM Operational Log is disabled or unavailable." -ForegroundColor Red
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "               Audit Complete                     " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan