#requires -Version 5.1
#requires -RunAsAdministrator
<#
NOT a full system image or Active Directory system state backup
Comprehensive Incident Response (IR) & Incident Triage Configuration Snapshot
#>

[CmdletBinding()]
param(
    [string]$Root = 'C:\TrollwareIR\Backups',
    [int]$RetentionHours = 72,
    [switch]$CompressArchive
)

$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$hostName = $env:COMPUTERNAME
$run = Join-Path (Join-Path $Root $hostName) $stamp
$null = New-Item -ItemType Directory -Path $run -Force
$log = Join-Path $run 'backup.log'

function Log {
    param([string]$Message)
    Add-Content -LiteralPath $log -Value "$(Get-Date -Format o) $Message"
}

function Export-CsvSafe {
    param([string]$Name, [scriptblock]$Command)
    try {
        @(& $Command) |
            Export-Csv -LiteralPath (Join-Path $run $Name) -NoTypeInformation
        Log "Exported $Name"
    } catch {
        Log "FAILED $Name : $_"
    }
}

Log "Starting comprehensive IR triage snapshot on $hostName"

# Check if current host is an Active Directory Domain Controller
$domainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
$isDC = $domainRole -ge 4

# --- 1. SYSTEM METADATA ---
Export-CsvSafe 'operating-system.csv' {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object CSName, Caption, Version, BuildNumber,
                      LastBootUpTime, OSArchitecture
}

Export-CsvSafe 'computer-system.csv' {
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Name, Domain, PartOfDomain, DomainRole,
                      Manufacturer, Model, TotalPhysicalMemory
}

# --- 2. INSTALLED SOFTWARE ---
$uninstallPaths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$apps = foreach ($path in $uninstallPaths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Where-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, Publisher,
                      InstallDate, InstallLocation
}
$apps | Sort-Object DisplayName -Unique |
    Export-Csv (Join-Path $run 'installed-apps.csv') -NoTypeInformation

# --- 3. SERVICES & DRIVERS ---
Export-CsvSafe 'services.csv' {
    Get-CimInstance Win32_Service |
        Select-Object Name, DisplayName, State, StartMode,
                      StartName, PathName
}

Export-CsvSafe 'drivers.csv' {
    Get-CimInstance Win32_SystemDriver |
        Select-Object Name, DisplayName, State, StartMode, PathName
}

# --- 4. RUNNING PROCESSES & BINARY HASHING ---
Export-CsvSafe 'processes.csv' {
    Get-CimInstance Win32_Process |
        Select-Object ProcessId, ParentProcessId, Name,
                      ExecutablePath, CommandLine
}

Export-CsvSafe 'process-hashes.csv' {
    Get-CimInstance Win32_Process |
        Where-Object ExecutablePath |
        Select-Object -ExpandProperty ExecutablePath -Unique |
        ForEach-Object {
            $path = $_
            $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
            $hash = Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Path   = $path
                SHA256 = $hash.Hash
                Status = $sig.Status
                Signer = $sig.SignerCertificate.Subject
            }
        }
}

# --- 5. PERSISTENCE MECHANISMS ---
# Scheduled Tasks
Export-CsvSafe 'scheduled-tasks.csv' {
    Get-ScheduledTask | ForEach-Object {
        $t = $_
        [pscustomobject]@{
            TaskPath  = $t.TaskPath
            TaskName  = $t.TaskName
            State     = $t.State
            Actions   = ($t.Actions | ForEach-Object {
                "$($_.Execute) $($_.Arguments)"
            }) -join ' ; '
            Principal = $t.Principal.UserId
        }
    }
}

$taskDir = Join-Path $run 'TaskXML'
$null = New-Item -ItemType Directory -Path $taskDir -Force
try {
    foreach ($task in Get-ScheduledTask) {
        try {
            $xml = Export-ScheduledTask -TaskName $task.TaskName `
                -TaskPath $task.TaskPath -ErrorAction Stop
            $safeName = (($task.TaskPath + $task.TaskName) -replace '[\\/:*?"<>|]', '_')
            Set-Content -LiteralPath (Join-Path $taskDir "$safeName.xml") `
                -Value $xml -Encoding Unicode
        } catch {
            Log "Task XML export failed for $($task.TaskPath)$($task.TaskName)"
        }
    }
} catch {
    Log "Task export failed: $_"
}

# WMI Event Persistence
Export-CsvSafe 'wmi-persistence.csv' {
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Select-Object Consumer, Filter
}

# Startup Folders
Export-CsvSafe 'startup-folder-items.csv' {
    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*",
        "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
    )
    Get-Item $startupPaths -ErrorAction SilentlyContinue |
        Select-Object Name, FullName, Length, CreationTime, LastWriteTime
}

# Registry Persistence Exports
$registryKeys = @(
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM\SYSTEM\CurrentControlSet\Services'
)
foreach ($key in $registryKeys) {
    $safeName = $key -replace '[\\/:*?"<>|]', '_'
    $destination = Join-Path $run "$safeName.reg"
    & reg.exe export $key $destination /y 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Log "Exported registry key $key"
    } else {
        Log "Registry key not exported (may not exist or access denied): $key"
    }
}

# --- 6. USER ACCOUNTS & COMMAND HISTORY ---
Export-CsvSafe 'local-admins.csv' {
    if (-not $isDC) {
        Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue |
            Select-Object Name, ObjectClass, PrincipalSource, SID
    } else {
        Log "Skipped local-admins export: Host is a Domain Controller"
    }
}

Export-CsvSafe 'local-users.csv' {
    if (-not $isDC) {
        Get-LocalUser -ErrorAction SilentlyContinue |
            Select-Object Name, Enabled, LastLogon, SID
    } else {
        Log "Skipped local-users export: Host is a Domain Controller"
    }
}

# PowerShell History
$historyDir = Join-Path $run 'PSHistory'
$null = New-Item -ItemType Directory -Path $historyDir -Force
Get-ChildItem -Path 'C:\Users\' -Filter 'ConsoleHost_history.txt' -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        try {
            $user = $_.FullName.Split('\')[2]
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $historyDir "${user}_ConsoleHost_history.txt") -Force
            Log "Copied PowerShell history for $user"
        } catch {
            Log "Failed to copy PowerShell history: $_"
        }
    }

# --- 7. NETWORK & INTER-PROCESS COMMUNICATION ---
Export-CsvSafe 'firewall-profiles.csv' {
    Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction,
                      DefaultOutboundAction, LogBlocked
}

Export-CsvSafe 'network-connections.csv' {
    Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
}

Export-CsvSafe 'udp-listeners.csv' {
    Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, OwningProcess
}

Export-CsvSafe 'dns-cache.csv' {
    Get-DnsClientCache -ErrorAction SilentlyContinue |
        Select-Object Entry, Data, Type, Status, TTL
}

Export-CsvSafe 'arp-table.csv' {
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias
}

Export-CsvSafe 'shares.csv' {
    Get-SmbShare |
        Select-Object Name, Path, Description, Special, EncryptData
}

Export-CsvSafe 'named-pipes.csv' {
    [System.IO.Directory]::GetFiles("\\.\pipe\") | ForEach-Object {
        [pscustomobject]@{ PipeName = $_ }
    }
}

if (Test-Path 'C:\Windows\System32\drivers\etc\hosts') {
    try {
        Copy-Item 'C:\Windows\System32\drivers\etc\hosts' -Destination (Join-Path $run 'hosts.txt') -Force
        Log "Copied hosts file"
    } catch {
        Log "Failed to copy hosts file: $_"
    }
}

# --- 8. RECENT HIGH-VALUE EVENT LOGS ---
Export-CsvSafe 'recent-service-installs.csv' {
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddHours(-$RetentionHours)} -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, Message
}

# --- 9. DIFFERENTIAL ANALYSIS ---
$hostRoot = Split-Path $run -Parent
$previous = Get-ChildItem -LiteralPath $hostRoot -Directory |
    Where-Object FullName -ne $run |
    Sort-Object Name -Descending |
    Select-Object -First 1

if ($previous -and (Test-Path (Join-Path $previous.FullName 'services.csv'))) {
    try {
        $old = Import-Csv (Join-Path $previous.FullName 'services.csv')
        $new = Import-Csv (Join-Path $run 'services.csv')
        $diff = Compare-Object $old $new -Property Name, State, StartMode, PathName
        $diff | Export-Csv (Join-Path $run 'service-changes.csv') -NoTypeInformation
        Log "Compared services with snapshot $($previous.Name)"
    } catch {
        Log "Service comparison failed: $_"
    }
}

# --- 10. RETENTION CLEANUP ---
try {
    Get-ChildItem -LiteralPath $hostRoot -Directory |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-$RetentionHours) } |
        ForEach-Object {
            Log "Removing expired snapshot directory $($_.FullName)"
            Remove-Item -LiteralPath $_.FullName -Recurse -Force
        }
} catch {
    Log "Retention cleanup failed: $_"
}

Log "Snapshot finished: $run"

# --- 11. CRYPTOGRAPHIC MANIFEST GENERATION ---
# Generated strictly after all files and log entries are finalized
$manifest = Get-ChildItem -LiteralPath $run -File -Recurse |
    Where-Object Name -ne 'manifest.csv' |
    ForEach-Object {
        try {
            $h = Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256
            [pscustomobject]@{
                RelativePath = $_.FullName.Substring($run.Length).TrimStart('\')
                Length       = $_.Length
                SHA256       = $h.Hash
            }
        } catch {
            Log "Could not hash $($_.FullName)"
        }
    }
$manifest | Export-Csv (Join-Path $run 'manifest.csv') -NoTypeInformation

# Optional zip archive bundling
if ($CompressArchive) {
    try {
        $zipPath = "$run.zip"
        Compress-Archive -Path "$run\*" -DestinationPath $zipPath -Force
        Write-Host "Snapshot archived to $zipPath"
    } catch {
        Write-Warning "Archive creation failed: $_"
    }
}

Write-Host "Snapshot saved to $run"