<#
.SYNOPSIS
    Comprehensive Active Directory, Windows Security, and Infrastructure Health Audit.
.DESCRIPTION
    Performs fast, multi-threaded diagnostic checks on Active Directory domains, Domain Controllers, 
    local security configurations, network services, and active threat indicators.
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot = ".\Competition-Health",

    [string[]]$DomainControllers = @(),

    [ValidateRange(1, 720)]
    [int]$EventLookbackHours = 24,

    [int[]]$RequiredPorts = @(53, 88, 389, 636, 3268, 9389),

    [int[]]$SecurityEventIds = @(1102, 4719, 4720, 4722, 4724, 4726, 4728, 4732, 4740, 4756, 5136),

    [ValidateRange(100, 5000)]
    [int]$PortTimeoutMs = 750,

    [switch]$IncludeDism,

    [switch]$GenerateHtmlReport = $true
)

$ErrorActionPreference = "Continue"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutputRoot $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$results = [System.Collections.Generic.List[object]]::new()

# Helper: Log check results with real-time color-coded terminal feedback
function Add-Check {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Details,
        [string]$Recommendation = ""
    )

    $color = switch ($Status) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        "INFO" { "Cyan" }
        default { "Gray" }
    }

    Write-Host ("[{0,-4}] {1,-40} | {2}" -f $Status, $Name, $Details) -ForegroundColor $color

    $results.Add([pscustomobject]@{
        Time           = Get-Date
        Check          = $Name
        Status         = $Status
        Details        = [string]$Details
        Recommendation = [string]$Recommendation
    })
}

# Helper: Check if a command/executable is in PATH
function Test-CommandAvailable {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# Helper: High-performance TCP socket test replacing slow Test-NetConnection
function Test-PortFast {
    param(
        [string]$ComputerName,
        [int]$Port,
        [int]$TimeoutMs = 750
    )
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            $client.EndConnect($async)
            $client.Close()
            return $true
        }
        $client.Close()
        return $false
    } catch {
        return $false
    }
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " ACTIVE DIRECTORY & INFRASTRUCTURE HEALTH CHECK   " -ForegroundColor Cyan
Write-Host " Output Directory: $outDir" -ForegroundColor Gray
Write-Host "==================================================`n" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Active Directory & Domain Controller Discovery
# ---------------------------------------------------------------------------
$domain = $null
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    Add-Check "AD Domain Discovery" "PASS" "Domain: $($domain.DNSRoot)"

    if ($DomainControllers.Count -eq 0) {
        $DomainControllers = @(
            Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
        )
    }
    Add-Check "Domain Controller Discovery" "INFO" "Discovered $($DomainControllers.Count) DC(s): $($DomainControllers -join ', ')"
} catch {
    Add-Check "AD Domain Discovery" "FAIL" $_.Exception.Message "Install RSAT AD tools and verify domain connectivity."
    $DomainControllers = @()
}

# ---------------------------------------------------------------------------
# 2. Local System Integrity & Security Controls
# ---------------------------------------------------------------------------
# Pending Reboot Detection
$rebootPending = $false
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") { $rebootPending = $true }
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") { $rebootPending = $true }

if ($rebootPending) {
    Add-Check "Pending System Reboot" "WARN" "Host has a pending system reboot." "Schedule host reboot during maintenance window."
} else {
    Add-Check "Pending System Reboot" "PASS" "No pending reboot flags detected."
}

# Windows Defender Operational Status
if (Test-CommandAvailable "Get-MpComputerStatus") {
    try {
        $mp = Get-MpComputerStatus
        if ($mp.AntivirusEnabled -and $mp.RealTimeProtectionEnabled) {
            Add-Check "Antivirus Protection" "PASS" "Real-time protection enabled. Signatures: $($mp.AntivirusSignatureLastUpdated)"
        } else {
            Add-Check "Antivirus Protection" "WARN" "Antivirus or Real-time protection disabled." "Enable Microsoft Defender or operational AV."
        }
    } catch {
        Add-Check "Antivirus Protection" "INFO" $_.Exception.Message
    }
}

# DNS Resolver Configuration
try {
    $dns = Get-DnsClientServerAddress -AddressFamily IPv4 |
        Where-Object { $_.ServerAddresses.Count -gt 0 } |
        Select-Object InterfaceAlias, ServerAddresses

    $dns | Export-Csv (Join-Path $outDir "dns-client.csv") -NoTypeInformation

    $dnsSummary = ($dns | ForEach-Object { "$($_.InterfaceAlias): $($_.ServerAddresses -join ',')" }) -join "; "
    Add-Check "DNS Client Configuration" "INFO" $dnsSummary "Confirm endpoints use internal domain DNS resolvers."
} catch {
    Add-Check "DNS Client Configuration" "WARN" $_.Exception.Message
}

# Time Synchronization Status
try {
    $timeOutput = & w32tm.exe /query /status 2>&1
    $timeExit = $LASTEXITCODE
    $timeOutput | Set-Content (Join-Path $outDir "time-status.txt")

    if ($timeExit -eq 0) {
        Add-Check "Time Synchronization" "PASS" "w32tm status collected successfully." "Ensure clock skew < 5 minutes for Kerberos."
    } else {
        Add-Check "Time Synchronization" "WARN" "w32tm exited with code $timeExit" "Investigate Windows Time Service status."
    }
} catch {
    Add-Check "Time Synchronization" "WARN" $_.Exception.Message
}

# ---------------------------------------------------------------------------
# 3. Domain Controller Connectivity & Service Health
# ---------------------------------------------------------------------------
# Fast Multi-Port Connectivity Checks
foreach ($dc in $DomainControllers) {
    foreach ($port in $RequiredPorts) {
        $isOpen = Test-PortFast -ComputerName $dc -Port $port -TimeoutMs $PortTimeoutMs
        if ($isOpen) {
            Add-Check "Port Check ($($dc):$port)" "PASS" "TCP Port $port open."
        } else {
            Add-Check "Port Check ($($dc):$port)" "WARN" "TCP Port $port filtered or closed." "Check firewalls and service states on $dc."
        }
    }
}

# Remote DC Core Services Assessment (CIM / WinRM)
foreach ($dc in $DomainControllers) {
    try {
        $cimOptions = New-CimSessionOption -Protocol Wsman -ConnectTimeoutMs 2000
        $session = New-CimSession -ComputerName $dc -SessionOption $cimOptions -ErrorAction Stop
        
        $adServices = Get-CimInstance -CimSession $session -ClassName Win32_Service -Filter "Name='NTDS' OR Name='DNS' OR Name='KDC' OR Name='Netlogon' OR Name='W32Time' OR Name='DFSR' OR Name='Dnscache' OR Name='ADWS'" -ErrorAction Stop
        
        foreach ($svc in $adServices) {
            $svcStatus = if ($svc.State -eq 'Running') { "PASS" } else { "WARN" }
            Add-Check "DC Service ($($dc): $($svc.Name))" $svcStatus "State=$($svc.State)"
        }
        Remove-CimSession $session -ErrorAction SilentlyContinue
    } catch {
        try {
            $adServices = Invoke-Command -ComputerName $dc -ScriptBlock {
                Get-Service -Name "NTDS", "DNS", "KDC", "Netlogon", "W32Time", "DFSR", "Dnscache", "ADWS" -ErrorAction SilentlyContinue
            } -ErrorAction Stop

            foreach ($svc in $adServices) {
                $svcStatus = if ($svc.Status -eq 'Running') { "PASS" } else { "WARN" }
                Add-Check "DC Service ($($dc): $($svc.Name))" $svcStatus "Status=$($svc.Status)"
            }
        } catch {
            Add-Check "DC Service Check ($dc)" "WARN" "Failed to query services via CIM/WinRM: $($_.Exception.Message)" "Verify WinRM / RPC access."
        }
    }
}

# Domain SMB Shares (SYSVOL / NETLOGON)
if ($domain) {
    foreach ($share in @("SYSVOL", "NETLOGON")) {
        $path = "\\$($domain.PDCEmulator)\$share"
        if (Test-Path $path) {
            Add-Check "$share Share Access" "PASS" "Accessible at $path"
        } else {
            Add-Check "$share Share Access" "WARN" "Inaccessible at $path" "Check SMB connectivity, DNS, and DFS-R status."
        }
    }
}

# ICMP Reachability
foreach ($dc in $DomainControllers) {
    if (Test-Connection -ComputerName $dc -Count 1 -Quiet) {
        Add-Check "DC ICMP Reachability ($dc)" "PASS" "Host replied to ICMP echo."
    } else {
        Add-Check "DC ICMP Reachability ($dc)" "WARN" "No ICMP response." "Host may be offline or blocking ICMP."
    }
}

# FSMO Roles Reachability
if ($domain) {
    try {
        $forest = Get-ADForest -ErrorAction Stop
        $fsmoRoles = @{
            "PDC Emulator"         = $domain.PDCEmulator
            "RID Master"            = $domain.RIDMaster
            "Infrastructure Master" = $domain.InfrastructureMaster
            "Schema Master"         = $forest.SchemaMaster
            "Domain Naming Master"  = $forest.DomainNamingMaster
        }

        foreach ($role in $fsmoRoles.Keys) {
            $holder = $fsmoRoles[$role]
            if (Test-PortFast -ComputerName $holder -Port 389 -TimeoutMs $PortTimeoutMs) {
                Add-Check "FSMO Role: $role" "PASS" "Owner ($holder) LDAP port reachable."
            } else {
                Add-Check "FSMO Role: $role" "WARN" "Owner ($holder) unreachable via LDAP." "Verify host status and connectivity."
            }
        }
    } catch {
        Add-Check "FSMO Role Check" "WARN" $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------
# 4. AD Replication & Diagnostics Tools
# ---------------------------------------------------------------------------
# AD Replication Summary
if (Test-CommandAvailable "repadmin.exe") {
    $repOutput = & repadmin.exe /replsummary 2>&1
    $repExit = $LASTEXITCODE
    $repOutput | Set-Content (Join-Path $outDir "replication-summary.txt")

    if ($repExit -eq 0) {
        Add-Check "AD Replication Summary" "PASS" "Replication status collected successfully."
    } else {
        Add-Check "AD Replication Summary" "WARN" "Replication errors detected. Check replication-summary.txt" "Review partner status in repadmin logs."
    }
} else {
    Add-Check "AD Replication Summary" "SKIP" "repadmin.exe not found on local host."
}

# DCDIAG Diagnostics
if (Test-CommandAvailable "dcdiag.exe") {
    foreach ($dc in $DomainControllers) {
        $safeName = $dc -replace '[^a-zA-Z0-9_.-]', '_'
        $log = Join-Path $outDir "dcdiag-$safeName.txt"
        $output = & dcdiag.exe "/s:$($dc)" /test:Advertising /test:Services /test:SysVolCheck /test:NetLogons 2>&1
        $exit = $LASTEXITCODE
        $output | Set-Content $log

        $status = if ($exit -eq 0) { "PASS" } else { "WARN" }
        Add-Check "DCDIAG Assessment ($dc)" $status "Exit code $exit. Details logged to dcdiag-$safeName.txt"
    }
} else {
    Add-Check "DCDIAG Assessment" "SKIP" "dcdiag.exe not found."
}

# ---------------------------------------------------------------------------
# 5. Active Directory Attack Surface & Security Auditing
# ---------------------------------------------------------------------------
if ($domain) {
    # AS-REP Roasting Vulnerability Scan
    try {
        $asrepUsers = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } -Properties DoesNotRequirePreAuth
        if ($asrepUsers.Count -gt 0) {
            $userList = ($asrepUsers | Select-Object -ExpandProperty SamAccountName) -join ", "
            Add-Check "AS-REP Roasting Scan" "WARN" "Found $($asrepUsers.Count) user(s) with Pre-Auth Not Required: $userList" "Enable Kerberos Pre-Authentication on these accounts."
        } else {
            Add-Check "AS-REP Roasting Scan" "PASS" "No enabled accounts with Pre-Auth Disabled."
        }
    } catch {
        Add-Check "AS-REP Roasting Scan" "WARN" $_.Exception.Message
    }

    # Kerberoasting Vulnerability Scan
    try {
        $kerberoastUsers = Get-ADUser -Filter { ServicePrincipalName -ne "$null" -and Enabled -eq $true } -Properties ServicePrincipalName |
            Where-Object { $_.SamAccountName -notlike "krbtgt" -and $_.SamAccountName -notlike "*$" }
        
        if ($kerberoastUsers.Count -gt 0) {
            $userList = ($kerberoastUsers | Select-Object -ExpandProperty SamAccountName) -join ", "
            Add-Check "Kerberoasting Exposure" "WARN" "Found $($kerberoastUsers.Count) user account(s) with SPNs set: $userList" "Ensure strong 25+ char passwords or migrate to gMSA."
        } else {
            Add-Check "Kerberoasting Exposure" "PASS" "No user accounts exposed to Kerberoasting."
        }
    } catch {
        Add-Check "Kerberoasting Exposure" "WARN" $_.Exception.Message
    }

    # Unconstrained Delegation Check
    try {
        $unconstrained = Get-ADObject -Filter { TrustedForDelegation -eq $true -and Enabled -eq $true } -Properties TrustedForDelegation |
            Where-Object { $_.ObjectClass -ne "domainDNS" -and $_.Name -notlike "*$" }
        
        if ($unconstrained.Count -gt 0) {
            $names = ($unconstrained | Select-Object -ExpandProperty Name) -join ", "
            Add-Check "Unconstrained Delegation" "WARN" "Found $($unconstrained.Count) non-DC object(s) with Unconstrained Delegation: $names" "Migrate to Constrained or Resource-Based Constrained Delegation."
        } else {
            Add-Check "Unconstrained Delegation" "PASS" "No non-DC objects configured with Unconstrained Delegation."
        }
    } catch {
        Add-Check "Unconstrained Delegation" "WARN" $_.Exception.Message
    }

    # Privileged Group Membership Audit
    $privGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
    foreach ($grp in $privGroups) {
        try {
            $members = Get-ADGroupMember -Identity $grp -ErrorAction SilentlyContinue
            if ($members) {
                Add-Check "Privileged Group ($grp)" "INFO" "Contains $($members.Count) member(s): $(($members.Name) -join ', ')" "Audit for unauthorized accounts."
            }
        } catch {
            Add-Check "Privileged Group ($grp)" "WARN" $_.Exception.Message
        }
    }

    # Domain Password Policy Audit
    try {
        $policy = Get-ADDefaultDomainPasswordPolicy
        $policy | Select-Object ComplexityEnabled, ReversibleEncryptionEnabled, MinPasswordLength, PasswordHistoryCount, MaxPasswordAge, LockoutThreshold, LockoutDuration |
            Export-Csv (Join-Path $outDir "password-policy.csv") -NoTypeInformation

        if ($policy.ReversibleEncryptionEnabled) {
            Add-Check "Reversible Encryption" "FAIL" "Reversible password encryption is ENABLED." "Disable reversible encryption immediately in GPO."
        } else {
            Add-Check "Reversible Encryption" "PASS" "Reversible password encryption is disabled."
        }

        if ($policy.MinPasswordLength -lt 14) {
            Add-Check "Password Minimum Length" "WARN" "Minimum password length is $($policy.MinPasswordLength) characters." "Increase minimum password length to at least 14+ characters."
        } else {
            Add-Check "Password Minimum Length" "PASS" "Minimum password length is $($policy.MinPasswordLength) characters."
        }
    } catch {
        Add-Check "Domain Password Policy" "WARN" $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------
# 6. Windows Event Logs & OS Servicing
# ---------------------------------------------------------------------------
# High-Value Security Event Extraction
try {
    $since = (Get-Date).AddHours(-$EventLookbackHours)
    $events = @(
        Get-WinEvent -FilterHashtable @{
            LogName   = "Security"
            Id        = $SecurityEventIds
            StartTime = $since
        } -MaxEvents 300 -ErrorAction SilentlyContinue
    )

    $events | Select-Object TimeCreated, Id, MachineName, RecordId, Message |
        Export-Csv (Join-Path $outDir "security-events.csv") -NoTypeInformation

    Add-Check "Security Log Analysis" "INFO" "Extracted $($events.Count) high-value security events in last $EventLookbackHours hours." "Review security-events.csv for active threats."
} catch {
    Add-Check "Security Log Analysis" "WARN" $_.Exception.Message "Verify administrator privileges to read Security logs."
}

# Optional DISM Servicing Store Check
if ($IncludeDism) {
    try {
        $dismResult = & dism.exe /Online /Cleanup-Image /CheckHealth 2>&1
        if ($LASTEXITCODE -eq 0 -and ($dismResult -match "No component store corruption detected")) {
            Add-Check "OS Servicing Store (DISM)" "PASS" "Component store healthy."
        } else {
            Add-Check "OS Servicing Store (DISM)" "WARN" "Component store corruption detected." "Run: Dism /Online /Cleanup-Image /RestoreHealth"
        }
    } catch {
        Add-Check "OS Servicing Store (DISM)" "WARN" $_.Exception.Message
    }
} else {
    Add-Check "OS Servicing Store (DISM)" "SKIP" "DISM check skipped. Use -IncludeDism parameter to enable."
}

# ---------------------------------------------------------------------------
# 7. Output Generation & Dashboarding
# ---------------------------------------------------------------------------
# Export CSV
$results | Export-Csv (Join-Path $outDir "health-checks.csv") -NoTypeInformation

# Export Plain Text Summary
$results | Sort-Object Status, Check |
    Format-Table Status, Check, Details -Wrap |
    Out-String -Width 240 |
    Set-Content (Join-Path $outDir "summary.txt")

# Generate HTML Dashboard Report
if ($GenerateHtmlReport) {
    $htmlPath = Join-Path $outDir "report.html"
    $htmlHeader = @"
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; margin: 20px; }
    h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    th { background-color: #34495e; color: white; text-align: left; padding: 12px; }
    td { padding: 10px; border-bottom: 1px solid #ddd; font-size: 14px; }
    tr:hover { background-color: #f1f1f1; }
    .PASS { background-color: #2ecc71; color: white; font-weight: bold; text-align: center; border-radius: 4px; padding: 4px 8px; }
    .WARN { background-color: #f1c40f; color: black; font-weight: bold; text-align: center; border-radius: 4px; padding: 4px 8px; }
    .FAIL { background-color: #e74c3c; color: white; font-weight: bold; text-align: center; border-radius: 4px; padding: 4px 8px; }
    .INFO { background-color: #3498db; color: white; font-weight: bold; text-align: center; border-radius: 4px; padding: 4px 8px; }
    .SKIP { background-color: #95a5a6; color: white; font-weight: bold; text-align: center; border-radius: 4px; padding: 4px 8px; }
</style>
<h2>Active Directory Environment Assessment Report</h2>
<p><b>Generated:</b> $(Get-Date) | <b>Output Path:</b> $outDir</p>
"@

    $htmlRows = foreach ($r in $results) {
        "<tr>
            <td style='width: 80px;'><span class='$($r.Status)'>$($r.Status)</span></td>
            <td><b>$($r.Check)</b></td>
            <td>$([System.Net.WebUtility]::HtmlEncode($r.Details))</td>
            <td>$([System.Net.WebUtility]::HtmlEncode($r.Recommendation))</td>
         </tr>"
    }

    $htmlBody = "<table><tr><th>Status</th><th>Check</th><th>Details</th><th>Recommendation</th></tr>" + ($htmlRows -join "") + "</table>"
    $htmlHeader + $htmlBody | Set-Content $htmlPath
}

# Console Final Summary
Write-Host "`n==================================================" -ForegroundColor Cyan
Write-Host " ASSESSMENT SUMMARY                               " -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
$results | Group-Object Status | ForEach-Object {
    $cntColor = switch ($_.Name) {
        "PASS" { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        default { "Cyan" }
    }
    Write-Host (" {0,-6} : {1}" -f $_.Name, $_.Count) -ForegroundColor $cntColor
}

Write-Host "`nReport artifacts generated:" -ForegroundColor Green
Write-Host " - Full Summary : $outDir\summary.txt"
Write-Host " - HTML Report  : $outDir\report.html"
Write-Host " - Structured CSV: $outDir\health-checks.csv"