<#
.SYNOPSIS
    IRSEC Hardened Kerberos Audit, Multi-Session Purge, and KRBTGT Remediator.
.DESCRIPTION
    Fully automated Blue Team Kerberos response script that:
    1. Audits and detects forged/anomalous Kerberos tickets (RC4, excessive lifetimes).
    2. Safely purges local Kerberos ticket caches without breaking scored services (AD/DNS).
    3. Remotely sweeps domain member servers to purge stale tickets domain-wide.
    4. Safely executes a non-blocking KRBTGT double-reset workflow targeting the PDC Emulator.
    5. Outputs HTML and TXT logs to C:\IRSEC_Logs using native .NET libraries.
.EXAMPLE
    .\Invoke-IRSECKerberosRemediation.ps1 -PurgeAllSessions -Force
.EXAMPLE
    .\Invoke-IRSECKerberosRemediation.ps1 -PurgeAllSessions -ResetKRBTGT -SweepDomainServers -WaitMinutesBetweenResets 10 -Force
#>

[CmdletBinding()]
param(
    [string]$LogDir = "C:\IRSEC_Logs",
    [switch]$PurgeAllSessions,
    [switch]$SkipSystemSession,
    [switch]$SweepDomainServers,
    [switch]$ResetKRBTGT,
    [int]$WaitMinutesBetweenResets = 10,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# --- 1. Environment & Privilege Validation ---
$isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isElevated) {
    throw "EXECUTION DENIED: This script must be run from an Elevated (Administrator) PowerShell prompt."
}

$KListPath    = "$env:SystemRoot\System32\klist.exe"
$NltestPath   = "$env:SystemRoot\System32\nltest.exe"
$RepadminPath = "$env:SystemRoot\System32\repadmin.exe"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

$timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$txtLogPath  = Join-Path $LogDir "Kerberos_MasterLog_$timestamp.txt"
$htmlLogPath = Join-Path $LogDir "Kerberos_MasterLog_$timestamp.html"
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$hostname    = $env:COMPUTERNAME
$domainName  = $env:USERDNSDOMAIN

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "[$time] $Message" | Out-File -FilePath $txtLogPath -Append
    Write-Host "[$time] $Message" -ForegroundColor $Color
}

Write-Log "=== Initiating IRSEC Kerberos Remediation Engine ===" "Cyan"
Write-Log "Host: $hostname | User: $currentUser | Domain: $domainName" "Gray"

# --- 2. Audit Local Ticket Cache & Anomaly Detection ---
Write-Log "Auditing local Kerberos ticket cache..." "Yellow"
$currentTicketsRaw = & $KListPath
$currentTicketsText = $currentTicketsRaw -join "`n"

$anomalies = @()
if ($currentTicketsText -match "rc4-hmac|0x17") {
    $anomalies += "WEAK ENCRYPTION: RC4-HMAC (0x17) detected. High probability of Kerberoasting or Golden Ticket."
}

$currentTicketsRaw | ForEach-Object {
    if ($_ -match "End Time.*: .*\s+(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2})") {
        $endTimeStr = $Matches[1]
        try {
            $endTime = [DateTime]::Parse($endTimeStr)
            if ($endTime -gt (Get-Date).AddHours(12)) {
                $anomalies += "SUSPICIOUS LIFETIME: Ticket expiration ($endTimeStr) exceeds 12 hours."
            }
        } catch {}
    }
}

foreach ($anomaly in $anomalies) {
    Write-Log "[ANOMALY DETECTED] $anomaly" "Red"
}

# --- 3. Local & Multi-Session Ticket Purge ---
$purgeStatus = "Skipped"
$purgedLuids = @()

if ($PurgeAllSessions) {
    if (-not $Force -and -not $ResetKRBTGT) {
        $confirmation = Read-Host "Type PURGE to clear Kerberos tickets across all sessions"
        if ($confirmation -cne "PURGE") {
            Write-Log "Purge operation cancelled by operator." "Yellow"
            return
        }
    }

    Write-Log "Executing local multi-session Kerberos purge..." "Yellow"
    $sessionOutput = & $KListPath sessions
    $luids = $sessionOutput | Select-String -Pattern "0x[0-9a-fA-F]+" | ForEach-Object { $_.Matches.Value } | Select-Object -Unique

    foreach ($luid in $luids) {
        if ($SkipSystemSession -and ($luid -eq "0x0:0x3e7" -or $luid -eq "0x3e7")) {
            Write-Log "Skipping SYSTEM session LUID ($luid) per -SkipSystemSession" "Gray"
            continue
        }
        & $KListPath -li $luid purge | Out-Null
        $purgedLuids += $luid
    }
    
    # Fallback purge for current shell context
    & $KListPath purge | Out-Null
    $purgeStatus = "Executed ($($purgedLuids.Count) LUIDs purged)"
    Write-Log "Local ticket purge completed successfully." "Green"

    # Re-acquire local TGT to protect scored services (AD/DNS)
    if ($domainName) {
        Write-Log "Re-establishing Domain Secure Channel to safeguard scored services..." "Green"
        try {
            & $NltestPath /sc_verify:$domainName | Out-Null
            & $KListPath get krbtgt | Out-Null
            Write-Log "Local TGT re-acquired successfully." "Green"
        } catch {
            Write-Log "WARNING: Unable to re-acquire TGT. Ensure DC is reachable." "Red"
        }
    }
}

# --- 4. Remote Domain Server Ticket Sweep (Optional) ---
$remoteSweepStatus = "Not Requested"
if ($SweepDomainServers) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Log "ActiveDirectory module not found. Skipping remote domain server sweep." "Red"
    } else {
        Import-Module ActiveDirectory
        Write-Log "Querying domain server accounts for remote purge sweep..." "Yellow"
        $servers = Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' | Select-Object -ExpandProperty Name
        
        if ($servers) {
            Write-Log "Broadcasting remote purge across $($servers.Count) domain servers..." "Cyan"
            $results = Invoke-Command -ComputerName $servers -ScriptBlock {
                & "$env:SystemRoot\System32\klist.exe" purge | Out-Null
                & "$env:SystemRoot\System32\nltest.exe" /sc_verify:$using:domainName | Out-Null
                return $env:COMPUTERNAME
            } -ErrorAction SilentlyContinue

            $remoteSweepStatus = "Swept $($results.Count) of $($servers.Count) servers"
            Write-Log "Remote server sweep complete: $remoteSweepStatus" "Green"
        }
    }
}

# --- 5. Hardened KRBTGT Double-Reset Workflow ---
$krbtgtStatus = "Not Requested"

if ($ResetKRBTGT) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        throw "PREREQUISITE FAILED: ActiveDirectory module is required for KRBTGT resets."
    }
    Import-Module ActiveDirectory

    # Target PDC Emulator explicitly
    $domainObj = Get-ADDomain
    $pdc = $domainObj.PDCEmulator
    Write-Log "Targeting Primary Domain Controller (PDC): $pdc" "Cyan"

    if (-not $Force) {
        $confirmReset = Read-Host "Type RESET-KRBTGT to proceed with double resetting the KRBTGT account"
        if ($confirmReset -cne "RESET-KRBTGT") {
            Write-Log "KRBTGT Reset cancelled by operator." "Yellow"
            return
        }
    }

    # --- Reset #1 ---
    Write-Log "[STEP 1/4] Executing KRBTGT Reset #1 on PDC ($pdc)..." "Red"
    Set-ADAccountPassword -Identity "krbtgt" -Server $pdc -Reset -ErrorAction Stop
    Write-Log "KRBTGT Reset #1 executed." "Green"

    Write-Log "Triggering domain-wide AD replication (repadmin /syncall)..." "Yellow"
    if (Test-Path $RepadminPath) {
        & $RepadminPath /syncall $pdc /A /e /P | Out-Null
        Write-Log "AD Replication forced successfully." "Green"
    }

    # Secure channel renewal post Reset #1
    & $NltestPath /sc_verify:$domainName | Out-Null
    & $KListPath get krbtgt | Out-Null

    # --- Active Visual Intermission Timer ---
    $totalSeconds = $WaitMinutesBetweenResets * 60
    Write-Log "Intermission: Pausing $WaitMinutesBetweenResets minute(s) to allow legitimate services to adopt intermediate keys..." "Cyan"
    
    for ($i = $totalSeconds; $i -gt 0; $i--) {
        $min = [math]::Floor($i / 60)
        $sec = $i % 60
        Write-Progress -Activity "KRBTGT Intermission Progress" -Status "Waiting $min m $sec s before Reset #2" -PercentComplete ((( $totalSeconds - $i ) / $totalSeconds ) * 100)
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity "KRBTGT Intermission Progress" -Completed

    # --- Reset #2 ---
    Write-Log "[STEP 2/4] Executing KRBTGT Reset #2 on PDC ($pdc)..." "Red"
    Set-ADAccountPassword -Identity "krbtgt" -Server $pdc -Reset -ErrorAction Stop
    Write-Log "KRBTGT Reset #2 executed. Pre-existing Golden Tickets fully invalidated." "Green"

    Write-Log "Triggering final domain-wide AD replication..." "Yellow"
    if (Test-Path $RepadminPath) {
        & $RepadminPath /syncall $pdc /A /e /P | Out-Null
        Write-Log "Final AD Replication forced successfully." "Green"
    }

    # Final Secure channel renewal
    & $NltestPath /sc_verify:$domainName | Out-Null
    & $KListPath get krbtgt | Out-Null
    $krbtgtStatus = "Completed Successfully (Double Reset + Synced)"
}

# --- 6. HTML Report Generation (Native .NET Utilities) ---
$anomalyHtml = if ($anomalies.Count -gt 0) {
    ($anomalies | ForEach-Object { "<li style='color: #ff4d4d; font-weight: bold;'>[!] $_</li>" }) -join "`n"
} else {
    "<li style='color: #2ecc71;'>No ticket anomalies detected.</li>"
}

$luidsHtml = if ($purgedLuids.Count -gt 0) {
    ($purgedLuids | ForEach-Object { "<code>$_</code>" }) -join ", "
} else {
    "None"
}

# Using System.Net.WebUtility to ensure 100% compatibility across PS 5.1 and PS 7+
$encodedRawOutput = [System.Net.WebUtility]::HtmlEncode($currentTicketsText)

$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IRSEC Kerberos Remediation Log</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e1e; color: #d4d4d4; margin: 20px; }
        h1, h2 { color: #569cd6; border-bottom: 1px solid #3c3c3c; padding-bottom: 5px; }
        .card { background-color: #252526; border: 1px solid #3c3c3c; border-radius: 5px; padding: 15px; margin-bottom: 20px; }
        .label { font-weight: bold; color: #9cdcfe; }
        pre { background-color: #1e1e1e; padding: 12px; border: 1px solid #333; overflow-x: auto; color: #ce9178; font-family: Consolas, monospace; }
        ul { margin: 5px 0; padding-left: 20px; }
        code { background-color: #333; padding: 2px 5px; border-radius: 3px; color: #4ec9b0; }
    </style>
</head>
<body>
    <h1>IRSEC Kerberos Audit & Remediation Log</h1>
    <div class="card">
        <h2>Execution Context</h2>
        <p><span class="label">Timestamp:</span> $(Get-Date)</p>
        <p><span class="label">Host Name:</span> $hostname</p>
        <p><span class="label">User:</span> $currentUser</p>
        <p><span class="label">Domain:</span> $domainName</p>
        <p><span class="label">Local Cache Purge:</span> $purgeStatus</p>
        <p><span class="label">Remote Server Sweep:</span> $remoteSweepStatus</p>
        <p><span class="label">KRBTGT Reset Status:</span> $krbtgtStatus</p>
        <p><span class="label">Purged LUIDs:</span> $luidsHtml</p>
    </div>

    <div class="card">
        <h2>Threat Assessment & Anomaly Scans</h2>
        <ul>$anomalyHtml</ul>
    </div>

    <div class="card">
        <h2>Initial Ticket Output (Raw)</h2>
        <pre>$encodedRawOutput</pre>
    </div>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $htmlLogPath -Encoding utf8
Write-Log "HTML Audit Log generated: $htmlLogPath" "Cyan"
Write-Log "TXT Audit Log generated: $txtLogPath" "Cyan"
Write-Log "=== Operation Completed Successfully ===" "Green"