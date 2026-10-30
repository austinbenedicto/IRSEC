# Audit-TelnetService.ps1
# IRSeC Blue Team Telnet Audit & Monitoring Script for safetycar (10.x.1.3)

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "          TELNET SERVICE & PORT AUDIT             " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Telnet Service Status Check
Write-Host "`n[*] Checking Telnet Service Status..." -ForegroundColor Yellow
$telnetServices = Get-Service | Where-Object { $_.Name -match "TlntSvr|Telnet" -or $_.DisplayName -match "Telnet" }

if ($telnetServices) {
    $telnetServices | Select-Object Name, DisplayName, Status, StartType | Format-Table -AutoSize
} else {
    Write-Host "[!] Default 'TlntSvr' service not found. Checking active port 23 processes..." -ForegroundColor Red
}

# 2. Port 23 Listening Status & Active Connections
Write-Host "[*] Auditing TCP Port 23 Listener & Active Connections..." -ForegroundColor Yellow
$connections = Get-NetTCPConnection -LocalPort 23 -ErrorAction SilentlyContinue

if ($connections) {
    $connections | ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = $_.State
            PID           = $_.OwningProcess
            ProcessName   = $proc.ProcessName
            Executable    = $proc.Path
        }
    } | Format-Table -AutoSize
} else {
    Write-Host "[!] No active process is currently listening on TCP Port 23!" -ForegroundColor Red
}

# 3. Windows Firewall Rules for Port 23
Write-Host "`n[*] Checking Windows Firewall Rules for Port 23..." -ForegroundColor Yellow
$fwPorts = Get-NetFirewallPortFilter | Where-Object { $_.LocalPort -eq 23 } -ErrorAction SilentlyContinue
if ($fwPorts) {
    foreach ($port in $fwPorts) {
        Get-NetFirewallRule -AssociatedFilter $port | Select-Object Name, DisplayName, Enabled, Action, Direction | Format-Table -AutoSize
    }
} else {
    Write-Host "[!] No specific firewall rule found for Port 23." -ForegroundColor Red
}

# 4. Recent Interactive & Telnet Authentication Events (Security Log ID 4624 / 4625)
Write-Host "`n[*] Auditing Recent Authentication Events (Event IDs 4624 / 4625)..." -ForegroundColor Yellow
try {
    $logonEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = 4624, 4625
    } -MaxEvents 30 -ErrorAction Stop

    $auditResults = foreach ($event in $logonEvents) {
        $xml = [xml]$event.ToXml()
        $eventData = $xml.Event.EventData.Data
        $user  = ($eventData | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
        $ip    = ($eventData | Where-Object { $_.Name -eq 'IpAddress' }).'#text'
        $type  = ($eventData | Where-Object { $_.Name -eq 'LogonType' }).'#text'
        $status = if ($event.Id -eq 4624) { "SUCCESS" } else { "FAILED" }

        # LogonType 10 = RemoteInteractive (Telnet/RDP), LogonType 2 = Interactive
        if ($ip -and $ip -ne "-" -and $ip -ne "127.0.0.1" -and $ip -ne "::1") {
            [PSCustomObject]@{
                Timestamp   = $event.TimeCreated
                Status      = $status
                User        = $user
                LogonType   = $type
                SourceIP    = $ip
            }
        }
    }

    if ($auditResults) {
        $auditResults | Format-Table -AutoSize
    } else {
        Write-Host "[+] No suspicious remote network logins recorded in recent logs." -ForegroundColor Green
    }
} catch {
    Write-Host "[!] Security log access restricted or no matching events." -ForegroundColor Red
}

# 5. Active Admin Group Audit (Competition Compliance Check)
Write-Host "`n[*] Auditing Local Administrators Group..." -ForegroundColor Yellow
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource, ObjectClass | Format-Table -AutoSize