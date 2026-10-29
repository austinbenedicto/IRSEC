#requires -Version 5.1
<#
Summary & HTML Report Generator for IR Triage Snapshots
#>

[CmdletBinding()]
param(
    [string]$SnapshotPath,
    [string]$Root = 'C:\TrollwareIR\Backups'
)

# Auto-detect latest snapshot if no path is specified
if (-not $SnapshotPath) {
    if (Test-Path $Root) {
        $latest = Get-ChildItem -Path $Root -Recurse -Directory |
            Where-Object { Test-Path (Join-Path $_.FullName 'manifest.csv') } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        
        if ($latest) {
            $SnapshotPath = $latest.FullName
        } else {
            Write-Error "No valid snapshot folders found in $Root"
            return
        }
    } else {
        Write-Error "Root path $Root does not exist."
        return
    }
}

Write-Host "Generating HTML report for: $SnapshotPath" -ForegroundColor Cyan

# Helper to safely load CSV data into HTML tables
function Get-CsvTableHtml {
    param([string]$FileName, [string]$Title)
    $path = Join-Path $SnapshotPath $FileName
    if (Test-Path $path) {
        $data = Import-Csv -LiteralPath $path
        if ($data) {
            $table = $data | ConvertTo-Html -Fragment
            return "<h2>$Title</h2>$table"
        } else {
            return "<h2>$Title</h2><p class='empty'>No records found (file empty).</p>"
        }
    }
    return "<h2>$Title</h2><p class='empty'>Artifact file not present ($FileName).</p>"
}

# Read system metadata
$osPath = Join-Path $SnapshotPath 'operating-system.csv'
$csPath = Join-Path $SnapshotPath 'computer-system.csv'
$hostInfo = if (Test-Path $csPath) { Import-Csv $csPath } else { $null }
$osInfo   = if (Test-Path $osPath) { Import-Csv $osPath } else { $null }

# Unsigned / Unknown Process Binaries
$hashPath = Join-Path $SnapshotPath 'process-hashes.csv'
$unsignedProcesses = if (Test-Path $hashPath) {
    Import-Csv $hashPath | Where-Object { $_.Status -ne 'Valid' }
} else { $null }

# HTML & CSS Template
$css = @"
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1e1e2e; color: #cdd6f4; margin: 0; padding: 20px; }
    h1 { color: #89b4fa; border-bottom: 2px solid #45475a; padding-bottom: 10px; }
    h2 { color: #f38ba8; margin-top: 30px; border-bottom: 1px solid #313244; padding-bottom: 5px; }
    .card { background-color: #181825; border-radius: 8px; padding: 15px; margin-bottom: 20px; border: 1px solid #313244; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; background-color: #11111b; }
    th { background-color: #313244; color: #a6adc8; text-align: left; padding: 8px; border: 1px solid #45475a; }
    td { padding: 8px; border: 1px solid #313244; word-break: break-all; }
    tr:nth-child(even) { background-color: #181825; }
    tr:hover { background-color: #45475a; }
    .alert { background-color: #f38ba8; color: #11111b; font-weight: bold; padding: 2px 6px; border-radius: 4px; }
    .empty { color: #a6adc8; font-style: italic; }
    .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
    .meta-item { background: #313244; padding: 10px; border-radius: 5px; }
    .meta-label { font-size: 11px; color: #a6adc8; text-transform: uppercase; }
    .meta-value { font-size: 14px; font-weight: bold; color: #89b4fa; margin-top: 4px; }
</style>
"@

$htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>IR Triage Report - $($hostInfo.Name)</title>
    $css
</head>
<body>
    <h1>Incident Response Triage Snapshot</h1>
    <div class='card'>
        <div class='meta-grid'>
            <div class='meta-item'><div class='meta-label'>Host Name</div><div class='meta-value'>$($hostInfo.Name)</div></div>
            <div class='meta-item'><div class='meta-label'>OS Version</div><div class='meta-value'>$($osInfo.Caption) ($($osInfo.Version))</div></div>
            <div class='meta-item'><div class='meta-label'>Domain</div><div class='meta-value'>$($hostInfo.Domain)</div></div>
            <div class='meta-item'><div class='meta-label'>Last Boot Time</div><div class='meta-value'>$($osInfo.LastBootUpTime)</div></div>
            <div class='meta-item'><div class='meta-label'>Snapshot Path</div><div class='meta-value' style='font-size:11px;'>$SnapshotPath</div></div>
        </div>
    </div>
"@

# High Priority Sections
$secServiceChanges = Get-CsvTableHtml 'service-changes.csv' '1. Service Changes (vs Previous Baseline)'
$secNewServices     = Get-CsvTableHtml 'recent-service-installs.csv' '2. Recently Installed Services (Event ID 7045)'

# Format Unsigned Processes Section
$secUnsigned = "<h2>3. Unsigned or Invalid Code Signatures (Process Executables)</h2>"
if ($unsignedProcesses) {
    $secUnsigned += ($unsignedProcesses | ConvertTo-Html -Fragment)
} else {
    $secUnsigned += "<p class='empty'>All running process executables have valid digital signatures.</p>"
}

# Persistence & Network
$secWMIPersist     = Get-CsvTableHtml 'wmi-persistence.csv' '4. WMI Event Subscriptions (Fileless Persistence)'
$secStartup        = Get-CsvTableHtml 'startup-folder-items.csv' '5. Startup Folder Items'
$secAdmins         = Get-CsvTableHtml 'local-admins.csv' '6. Local Administrators Group'
$secConnections    = Get-CsvTableHtml 'network-connections.csv' '7. Active Network Connections'
$secDNS            = Get-CsvTableHtml 'dns-cache.csv' '8. DNS Cache'

$htmlFooter = "</body></html>"

# Assemble & Save HTML
$reportPath = Join-Path $SnapshotPath 'report.html'
$htmlHeader + $secServiceChanges + $secNewServices + $secUnsigned + $secWMIPersist + $secStartup + $secAdmins + $secConnections + $secDNS + $htmlFooter | Out-File -FilePath $reportPath -Encoding utf8

Write-Host "Report successfully generated: $reportPath" -ForegroundColor Green

# Open in default web browser
Start-Process $reportPath