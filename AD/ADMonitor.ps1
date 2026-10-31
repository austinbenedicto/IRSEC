#requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive Active Directory & Windows Security Log Auditor for Blue Team (IRSEC / CCDC).
.DESCRIPTION
    Polls Security and System logs using server-side XPath filtering to eliminate RPC bottlenecks.
    Monitors for DCSync, Shadow Credentials, Delegation tampering, Kerberoasting, AS-REP Roasting,
    Universal Group changes, DSRM password resets, and Domain Trust modifications.
.EXAMPLE
    .\ADMonitor.ps1 -ComputerName DC01,DC02 -IncludeInformational
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [int]$PollSeconds = 5,
    [string]$OutputRoot = ".\ADMonitor",
    [int]$FirstRunLookbackMinutes = 15,
    [switch]$IncludeInformational,
    [switch]$IncludeMachineAccounts,
    [switch]$ConfigureLocalAuditPolicy
)

$ErrorActionPreference = "Stop"

if ($PollSeconds -lt 2) { throw "PollSeconds must be at least 2." }

$root = [System.IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Path $root -Force | Out-Null

$checkpointPath = Join-Path $root "checkpoints.json"
$alertPath      = Join-Path $root "alerts.csv"
$monitorLogPath  = Join-Path $root "monitor.log"

# --- Local Audit Policy Enforcer ---
if ($ConfigureLocalAuditPolicy) {
    Write-Host "[+] Applying high-visibility local audit policies via auditpol..." -ForegroundColor Green
    $auditCategories = @(
        'Logon', 'User Account Management', 'Security Group Management',
        'Process Creation', 'Audit Policy Change', 'Kerberos Service Ticket Operations',
        'Kerberos Authentication Service', 'Directory Service Access',
        'Directory Service Changes'
    )
    foreach ($cat in $auditCategories) {
        auditpol /set /subcategory:"$cat" /success:enable /failure:enable | Out-Null
    }
}

# --- AD Event Catalog ---
$eventCatalog = @{
    # Defenses & Audit changes
    1102 = @{ Log="Security"; Severity="High";   Title="Security Log Cleared"; Meaning="Log cleared."; Investigate="URGENT: Defense evasion in progress." }
    4719 = @{ Log="Security"; Severity="High";   Title="Audit Policy Changed"; Meaning="System audit policy modified."; Investigate="Verify if logging subcategories were disabled." }

    # login and move
    4624 = @{ Log="Security"; Severity="Info";   Title="Successful Logon"; Meaning="Logon session established."; Investigate="Inspect LogonType (3=Net, 10=RDP) and source IP." }
    4625 = @{ Log="Security"; Severity="Medium"; Title="Failed Logon"; Meaning="Logon authentication failed."; Investigate="Check for brute-force or password spraying." }
    4648 = @{ Log="Security"; Severity="Medium"; Title="Explicit Credentials Used"; Meaning="Process ran under alternate credentials."; Investigate="Check process path and target account." }
    4776 = @{ Log="Security"; Severity="Medium"; Title="NTLM Credential Validation"; Meaning="DC validated NTLM auth."; Investigate="Check for NTLM spraying or Pass-the-Hash." }
    5140 = @{ Log="Security"; Severity="Medium"; Title="Network Share Object Accessed"; Meaning="SMB Share accessed."; Investigate="Look for access to C$, ADMIN$, or IPC$." }
    5145 = @{ Log="Security"; Severity="High";   Title="Network Share File/Pipe Checked"; Meaning="Detailed SMB access."; Investigate="Check for PsExec execution or remote tool drops." }

    # Redteam sneaky shenanigans
    4662 = @{ Log="Security"; Severity="High";   Title="Directory Service Operation"; Meaning="DS Object accessed."; Investigate="Inspected for DCSync replication GUIDs." }
    5136 = @{ Log="Security"; Severity="High";   Title="AD Object Attribute Modified"; Meaning="AD Object modified."; Investigate="Check AttributeLDAPDisplayName for KeyCredentialLink, Delegation, or SPNs." }
    4768 = @{ Log="Security"; Severity="High";   Title="Kerberos TGT Requested"; Meaning="AS-REQ ticket requested."; Investigate="Check for AS-REP Roasting (TicketEncryption: 0x17/RC4)." }
    4769 = @{ Log="Security"; Severity="High";   Title="Kerberos Service Ticket Requested"; Meaning="TGS-REQ ticket requested."; Investigate="Check for Kerberoasting (TicketEncryption: 0x17/RC4)." }

    # Group Membership stuff
    4728 = @{ Log="Security"; Severity="High";   Title="Added to Global Group"; Meaning="User added to group."; Investigate="Check if added to Domain Admins." }
    4732 = @{ Log="Security"; Severity="High";   Title="Added to Local Group"; Meaning="User added to group."; Investigate="Check if added to Local Administrators." }
    4756 = @{ Log="Security"; Severity="High";   Title="Added to Universal Group"; Meaning="User added to group."; Investigate="Check if added to Enterprise Admins." }

    # accounts and backdoors, AKA redteam shenanigans part 2
    4720 = @{ Log="Security"; Severity="High";   Title="User Account Created"; Meaning="New user account added."; Investigate="Verify authorization and creator identity." }
    4724 = @{ Log="Security"; Severity="High";   Title="Password Reset Attempted"; Meaning="Account password reset."; Investigate="Verify who reset administrative passwords." }
    4738 = @{ Log="Security"; Severity="Medium"; Title="User Account Modified"; Meaning="Account attributes altered."; Investigate="Check if DontRequirePreAuth set or SPN added." }
    4794 = @{ Log="Security"; Severity="High";   Title="DSRM Password Reset Attempt"; Meaning="DSRM Administrator password reset."; Investigate="CRITICAL: Attacker setting up persistence via DSRM mode." }
    4706 = @{ Log="Security"; Severity="High";   Title="Domain Trust Created"; Meaning="New trust relationship formed."; Investigate="Verify unauthorized external or rogue domain trusts." }

    # persist and run
    4688 = @{ Log="Security"; Severity="Info";   Title="Process Created"; Meaning="New process executed."; Investigate="Review full command-line and parent process." }
    4697 = @{ Log="Security"; Severity="High";   Title="Service Installed (Security Log)"; Meaning="New service registered."; Investigate="Check binary path and service startup type." }
    7045 = @{ Log="System";   Severity="High";   Title="Service Installed (System Log)"; Meaning="New service registered."; Investigate="Check binary path and service name." }
    4698 = @{ Log="Security"; Severity="High";   Title="Scheduled Task Created"; Meaning="Task created."; Investigate="Inspect task actions, triggers, and binary path." }
}

function Write-MonitorLog {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -LiteralPath $monitorLogPath -Value $line -Encoding UTF8
}

function Get-EventXmlData {
    param([System.Diagnostics.Eventing.Reader.EventLogRecord]$Event)

    $result = @{}
    try {
        [xml]$xml = $Event.ToXml()
        
        # event data parsing
        if ($xml.Event.EventData.Data) {
            foreach ($item in $xml.Event.EventData.Data) {
                if ($item.Name) { 
                    $result[[string]$item.Name] = [string]$item.'#text' 
                }
            }
        }
        # structures
        if ($xml.Event.UserData) {
            foreach ($node in $xml.Event.UserData.ChildNodes.ChildNodes) {
                if ($node.Name -and -not $result.ContainsKey($node.Name)) {
                    $result[[string]$node.Name] = [string]$node.InnerText
                }
            }
        }
    } catch {}
    return $result
}

function Get-FirstValue {
    param([hashtable]$Data, [string[]]$Names)
    foreach ($name in $Names) {
        if ($Data.ContainsKey($name) -and -not [string]::IsNullOrWhiteSpace($Data[$name])) {
            return [string]$Data[$name]
        }
    }
    return ""
}

function Process-SecurityEvent {
    param(
        [string]$HostName,
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event
    )

    $id   = [int]$Event.Id
    $info = $eventCatalog[$id]
    if (-not $info) { return }

    if ($info.Severity -eq "Info" -and -not $IncludeInformational) {
        return
    }

    $data   = Get-EventXmlData -Event $Event
    $target = Get-FirstValue $data @("TargetUserName", "AccountName", "MemberName", "ServiceName", "ObjectName", "TaskName", "ObjectDN")
    $actor  = Get-FirstValue $data @("SubjectUserName", "CallerUserName", "WorkstationName")
    $source = Get-FirstValue $data @("IpAddress", "ClientAddress", "Workstation", "CallerComputerName")

    # noise removal
    if (-not $IncludeMachineAccounts) {
        if ($target.EndsWith("$") -or $actor.EndsWith("$")) { return }
    }

    $extraContext = ""

    # --- 1. DCSync Filtering (Event 4662) ---
    if ($id -eq 4662) {
        $properties = Get-FirstValue $data @("Properties", "AccessMask")
        $dcSyncGuids = @(
            "1131f6aa-9c0e-11d1-bf38-00c04fa938ee", # DS-Replication-Get-Changes
            "1131f6ad-9c0e-11d1-bf38-00c04fa938ee"  # DS-Replication-Get-Changes-All
        )
        
        $isDCSync = $false
        foreach ($guid in $dcSyncGuids) {
            if ($properties -like "*$guid*") { $isDCSync = $true; break }
        }

        # Suppress non-DCSync 4662 events to prevent log flooding
        if (-not $isDCSync) { return }
        $extraContext = " [CRITICAL: DCSync Replication Requested]"
    }

    # --- 2. Kerberos RC4 Encryption Checks (4768 / 4769) ---
    if ($id -in @(4768, 4769)) {
        $encType = Get-FirstValue $data @("TicketEncryptionType")
        if ($encType -eq "0x17") { 
            $extraContext = " [CRITICAL: RC4 Encryption (0x17) Used - High Probability of Kerberoasting / AS-REP Roasting]" 
        }
    }

    # --- 3. AD Object Modification Attribute Parsing (5136) ---
    if ($id -eq 5136) {
        $attrName  = Get-FirstValue $data @("AttributeLDAPDisplayName")
        $attrValue = Get-FirstValue $data @("AttributeValue")

        switch -Wildcard ($attrName) {
            "msDS-KeyCredentialLink" {
                $extraContext = " [CRITICAL: Shadow Credentials Added ($attrName)]"
            }
            "msDS-AllowedToDelegateTo" {
                $extraContext = " [CRITICAL: Kerberos Delegation Modified ($attrName)]"
            }
            "servicePrincipalName" {
                $extraContext = " [WARNING: SPN Modified ($attrName = $attrValue)]"
            }
            "adminCount" {
                $extraContext = " [WARNING: AdminSDHolder Protection Flag Set ($attrName)]"
            }
            default {
                $extraContext = " [Attribute: $attrName = $attrValue]"
            }
        }
    }

    $record = [pscustomobject]@{
        TimeCreated         = $Event.TimeCreated
        Computer            = $HostName
        LogName             = $Event.LogName
        EventId             = $id
        Severity            = $info.Severity
        Title               = $info.Title + $extraContext
        AccountOrTarget     = $target
        Actor               = $actor
        SourceAddressOrHost = $source
        RecordId            = $Event.RecordId
        Meaning             = $info.Meaning
        RecommendedTriage   = $info.Investigate
    }

    $color = switch ($info.Severity) {
        "High"   { "Red" }
        "Medium" { "Yellow" }
        default  { "Cyan" }
    }

    Write-Host "`n[$($info.Severity)] [$HostName] $($info.Title)$extraContext - Event $id" -ForegroundColor $color
    Write-Host "Time: $($Event.TimeCreated) | RecordID: $($Event.RecordId) | Log: $($Event.LogName)"
    if ($target) { Write-Host "Target: $target" }
    if ($actor)  { Write-Host "Actor:  $actor" }
    if ($source) { Write-Host "Source: $source" }
    Write-Host "Triage: $($info.Investigate)"

    return $record
}

# --- State Initialization ---
$checkpoints = @{}
if (Test-Path -LiteralPath $checkpointPath) {
    try {
        $saved = Get-Content -LiteralPath $checkpointPath -Raw | ConvertFrom-Json
        foreach ($prop in $saved.PSObject.Properties) {
            $checkpoints[$prop.Name] = [long]$prop.Value
        }
    } catch {
        Write-Warning "Failed to load checkpoints file. Initializing clean state."
    }
}

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "  COMPREHENSIVE AD SECURITY MONITOR (IRSEC / CCDC)" -ForegroundColor Cyan
Write-Host "  Target Hosts: $($ComputerName -join ', ')" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$monitoredLogs = @("Security", "System")

foreach ($hostName in $ComputerName) {
    foreach ($log in $monitoredLogs) {
        $key = "${hostName}_${log}"
        if (-not $checkpoints.ContainsKey($key)) {
            try {
                $latest = Get-WinEvent -ComputerName $hostName -LogName $log -MaxEvents 1 -ErrorAction Stop
                $checkpoints[$key] = [long]$latest.RecordId
                
                if ($FirstRunLookbackMinutes -gt 0) {
                    $sinceISO = (Get-Date).AddMinutes(-$FirstRunLookbackMinutes).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                    $xpath = "*[System[TimeCreated[@SystemTime>='$sinceISO']]]"
                    
                    $initEvents = Get-WinEvent -ComputerName $hostName -LogName $log -FilterXPath $xpath -ErrorAction SilentlyContinue |
                                  Sort-Object RecordId
                    
                    $alertsToExport = @()
                    foreach ($ev in $initEvents) {
                        $processed = Process-SecurityEvent -HostName $hostName -Event $ev
                        if ($processed) { $alertsToExport += $processed }
                    }
                    if ($alertsToExport.Count -gt 0) {
                        $alertsToExport | Export-Csv -LiteralPath $alertPath -NoTypeInformation -Encoding UTF8 -Append
                    }
                }
                Write-Host "[+] Initialized $key at RecordID $($checkpoints[$key])" -ForegroundColor Green
            } catch {
                Write-Warning "Could not initialize log '$log' on $hostName : $_"
            }
        }
    }
}

$checkpoints | ConvertTo-Json | Set-Content -LiteralPath $checkpointPath -Encoding UTF8

# --- Monitoring! ---
while ($true) {
    $batchAlerts = @()

    foreach ($hostName in $ComputerName) {
        foreach ($log in $monitoredLogs) {
            $key = "${hostName}_${log}"
            if (-not $checkpoints.ContainsKey($key)) { continue }

            $lastId = [long]$checkpoints[$key]
            
            # Server-Side XPath Filter
            $xpath = "*[System[EventRecordID > $lastId]]"

            try {
                $newEvents = Get-WinEvent -ComputerName $hostName -LogName $log -FilterXPath $xpath -ErrorAction SilentlyContinue |
                             Sort-Object RecordId

                foreach ($ev in $newEvents) {
                    $processed = Process-SecurityEvent -HostName $hostName -Event $ev
                    if ($processed) { $batchAlerts += $processed }

                    if ([long]$ev.RecordId -gt $lastId) {
                        $lastId = [long]$ev.RecordId
                    }
                }
                $checkpoints[$key] = $lastId
            } catch {
                Write-Warning "Error polling $log on ${hostName}: $_"
            }
        }
    }

# Write alerts safely
if ($batchAlerts.Count -gt 0) {
    try {
        $exportParams = @{
            LiteralPath       = $alertPath
            NoTypeInformation = $true
            Encoding          = "UTF8"
            Append            = (Test-Path -LiteralPath $alertPath)
        }
        $batchAlerts | Export-Csv @exportParams -ErrorAction Stop
    } catch {
        Write-Warning "alerts.csv locked by external process (Datadog). Retrying next cycle..."
    }
}

# Save state
try {
    $checkpoints | ConvertTo-Json | Set-Content -LiteralPath $checkpointPath -Encoding UTF8 -ErrorAction Stop
} catch {
    Write-Warning "checkpoints.json locked. Retrying next cycle..."
}
    Start-Sleep -Seconds $PollSeconds
}