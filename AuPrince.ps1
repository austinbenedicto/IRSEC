$allowedPorts = @(514, 53, 88, 135, 389, 445, 636, 3268, 3269, 9389, 22, 443, 8443, 10516, 123, 8042, 5002, 8126, 8125, 5012, 5000, 5001, 6062, 6162)

Write-Host -ForegroundColor "Red" "$env:COMPUTERNAME - IF THIS DOES NOT MATCH A COMPETITION BOX, IT WILL FLAG PRETTY MUCH EVERYTHING. IF IT DOES MATCH, TYPE 'Y' "
$choices = Read-Host
if (-not ($choices -ieq "Y")) {
    exit
}

switch -Exact ($env:COMPUTERNAME) {
    "pitwall" {
        # Active Directory / DNS Server (Server 2025)
        $allowedPorts += 853, "49152-65535"
        $allowedPorts += 5353, 5355 
    }
    "teamradio" {
        # WinRM Management (Windows 11)
        $allowedPorts += 5985, 5986
    }
    "safetycar" {
        # Scored Telnet (Windows 10)
        $allowedPorts += 23
    }
    "transporters" {
        # Scored SMB (Server 2022)
        $allowedPorts += 5445, 5985, 5986, 445, 3389, 22
    }
    "stewards" {
        # Scored IIS Web Server (Windows 10)
        $allowedPorts += 80, 443, 8080, 8172, 5985, 5986, 3389
    }
}

$seenTCP = [System.Collections.Generic.HashSet[string]]::new()
$seenUDP = [System.Collections.Generic.HashSet[string]]::new()

function Get-LocalIPs {
    $ips = @("127.0.0.1", "::1", "0.0.0.0", "[::]")
    try {
        $adapters = Get-NetIPAddress -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress
        if ($adapters) { $ips += $adapters }
    } catch {}
    return $ips
}

$localIPs = Get-LocalIPs

Write-Host "Baseline" -ForegroundColor Cyan

$tcpConnections = Get-NetTCPConnection -ErrorAction SilentlyContinue
foreach ($conn in $tcpConnections) {
    $key = "$($conn.LocalAddress):$($conn.LocalPort)-$($conn.RemoteAddress):$($conn.RemotePort)-$($conn.State)"
    [void]$seenTCP.Add($key)

    if ($localIPs -contains $conn.RemoteAddress -and $localIPs -contains $conn.LocalAddress) { continue }

    $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Write-Host "[BASELINE] TCP | Local: $($conn.LocalAddress):$($conn.LocalPort) -> Remote: $($conn.RemoteAddress):$($conn.RemotePort) | State: $($conn.State) | PID: $($conn.OwningProcess) ($procName)" -ForegroundColor DarkCyan
}

$udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
foreach ($endpoint in $udpEndpoints) {
    $key = "$($endpoint.LocalAddress):$($endpoint.LocalPort)"
    [void]$seenUDP.Add($key)

    $procName = (Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Write-Host "[BASELINE] UDP | Local: $($endpoint.LocalAddress):$($endpoint.LocalPort) | PID: $($endpoint.OwningProcess) ($procName)" -ForegroundColor DarkCyan
}

Write-Host "`nBaseline established. Now listening for NEW external/incoming connections..." -ForegroundColor Green
Write-Host "Press Ctrl+C at any time to stop.`n" -ForegroundColor DarkGray

# Helper function to check if a port matches our allowed list (supports ranges like "49152-65535")
function Test-PortAllowed {
    param($port, $allowedList)
    foreach ($item in $allowedList) {
        if ($item -is [int] -and $port -eq $item) {
            return $true
        }
        if ($item -is [string] -and $item -match '^\d+-\d+$') {
            $range = $item -split '-'
            if ($port -ge [int]$range[0] -and $port -le [int]$range[1]) {
                return $true
            }
        }
    }
    return $false
}

while ($true) {
    Start-Sleep -Seconds 2 

    $currentTCP = Get-NetTCPConnection -ErrorAction SilentlyContinue
    foreach ($conn in $currentTCP) {
        $key = "$($conn.LocalAddress):$($conn.LocalPort)-$($conn.RemoteAddress):$($conn.RemotePort)-$($conn.State)"
        
        if (-not $seenTCP.Contains($key)) {
            [void]$seenTCP.Add($key)

            if ($localIPs -contains $conn.RemoteAddress -and $localIPs -contains $conn.LocalAddress) { continue }

            $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            $isAllowed = Test-PortAllowed -port $conn.LocalPort -allowedList $allowedPorts

            if (-not $isAllowed) {
                Write-Host "[NEW & FLAGGED] Unexpected TCP Connection!" -ForegroundColor Red
            } else {
                Write-Host "[NEW] TCP Connection Opened" -ForegroundColor Cyan
            }
            Write-Host "  Local:   $($conn.LocalAddress):$($conn.LocalPort)"
            Write-Host "  Remote:  $($conn.RemoteAddress):$($conn.RemotePort)"
            Write-Host "  State:   $($conn.State)"
            Write-Host "  Process: $procName (PID: $($conn.OwningProcess))`n"
        }
    }

    $currentUDP = Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    foreach ($endpoint in $currentUDP) {
        $key = "$($endpoint.LocalAddress):$($endpoint.LocalPort)"
        
        if (-not $seenUDP.Contains($key)) {
            [void]$seenUDP.Add($key)

            $procName = (Get-Process -Id $endpoint.OwningProcess -ErrorAction SilentlyContinue).ProcessName
            $isAllowed = Test-PortAllowed -port $endpoint.LocalPort -allowedList $allowedPorts

            if (-not $isAllowed) {
                Write-Host "[NEW & FLAGGED] Unexpected UDP Endpoint!" -ForegroundColor Red
            } else {
                Write-Host "[NEW] UDP Endpoint Opened" -ForegroundColor Cyan
            }
            Write-Host "  Local:   $($endpoint.LocalAddress):$($endpoint.LocalPort)"
            Write-Host "  Process: $procName (PID: $($endpoint.OwningProcess))`n"
        }
    }
}