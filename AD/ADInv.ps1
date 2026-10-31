[CmdletBinding()]
param(
    [string]$OutputRoot = "C:\AD_Audit",
    [int]$StaleDays = 90
)

# ----------------------------------------------------------------------
# 1. Environment & Dependency Checks
# ----------------------------------------------------------------------
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "Active Directory module not found. Attempting RSAT installation..." -ForegroundColor Yellow
    try {
        Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction Stop
    } catch {
        Write-Error "Failed to install Active Directory RSAT tools. Run as Administrator or install manually."
        exit
    }
}

if (-not (Get-Module -ListAvailable -Name DnsServer)) {
    Write-Host "DnsServer module not found. Script will fall back to WMI/CIM where necessary..." -ForegroundColor Yellow
}

Import-Module ActiveDirectory -ErrorAction Stop

# ----------------------------------------------------------------------
# 2. Domain Discovery & Output Setup
# ----------------------------------------------------------------------
try {
    $domain = Get-ADDomain -ErrorAction Stop
} catch {
    Write-Warning "Default ADWS discovery failed: $_"
    $dcTarget = Read-Host "Enter the FQDN or IP of a target Domain Controller (e.g. dc01.domain.com)"
    $domain = Get-ADDomain -Server $dcTarget -ErrorAction Stop
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path -Path $OutputRoot -ChildPath $stamp
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$findings = [System.Collections.Generic.List[object]]::new()
$cutoff = (Get-Date).AddDays(-$StaleDays)

Write-Host "Collecting inventory for domain: $($domain.DNSRoot)..." -ForegroundColor Cyan

# ----------------------------------------------------------------------
# 3. Domain Controllers
# ----------------------------------------------------------------------
$dcs = Get-ADDomainController -Filter * |
    Select-Object HostName, IPv4Address, Site, IsGlobalCatalog,
        IsReadOnly, OperatingSystem, OperationMasterRoles

$dcs | Export-Csv "$outDir\DomainControllers.csv" -NoTypeInformation

# ----------------------------------------------------------------------
# 4. User Accounts & Security Risk Checks
# ----------------------------------------------------------------------
$users = Get-ADUser -Filter * -Properties Enabled, LastLogonDate,
    PasswordLastSet, PasswordNeverExpires, PasswordNotRequired,
    AdminCount, ServicePrincipalNames, DoesNotRequirePreAuth,
    TrustedForDelegation, whenCreated |
    Select-Object Name, SamAccountName, Enabled, LastLogonDate,
        PasswordLastSet, PasswordNeverExpires, PasswordNotRequired,
        AdminCount, ServicePrincipalNames, DoesNotRequirePreAuth,
        TrustedForDelegation, whenCreated, DistinguishedName

$users | Export-Csv "$outDir\Users.csv" -NoTypeInformation

foreach ($u in $users) {
    if ($u.Enabled -and $u.PasswordNotRequired) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = $u.SamAccountName
            Issue    = "Enabled account has PasswordNotRequired set"
            Evidence = "PasswordNotRequired = True"
        })
    }

    if ($u.Enabled -and $u.DoesNotRequirePreAuth) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = $u.SamAccountName
            Issue    = "AS-REP Roastable Account"
            Evidence = "DoesNotRequirePreAuth = True"
        })
    }

    if ($u.Enabled -and $u.ServicePrincipalNames -and $u.ServicePrincipalNames.Count -gt 0) {
        $findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object   = $u.SamAccountName
            Issue    = "Kerberoastable User Account"
            Evidence = "SPNs: $($u.ServicePrincipalNames -join ', ')"
        })
    }

    if ($u.Enabled -and $u.TrustedForDelegation) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = $u.SamAccountName
            Issue    = "User configured for Unconstrained Delegation"
            Evidence = "TrustedForDelegation = True"
        })
    }

    if ($u.Enabled -and $u.PasswordNeverExpires) {
        $findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object   = $u.SamAccountName
            Issue    = "Password never expires"
            Evidence = "PasswordNeverExpires = True"
        })
    }

    if ($u.Enabled -and $u.LastLogonDate -and $u.LastLogonDate -lt $cutoff) {
        $findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object   = $u.SamAccountName
            Issue    = "Potentially stale enabled user"
            Evidence = "LastLogonDate = $($u.LastLogonDate)"
        })
    }
}

# ----------------------------------------------------------------------
# 5. KRBTGT Account Password Check
# ----------------------------------------------------------------------
$krbtgt = Get-ADUser -Filter "SamAccountName -eq 'krbtgt'" -Properties PasswordLastSet
if ($krbtgt -and $krbtgt.PasswordLastSet -and $krbtgt.PasswordLastSet -lt (Get-Date).AddDays(-180)) {
    $findings.Add([pscustomobject]@{
        Severity = "High"
        Object   = "krbtgt"
        Issue    = "KRBTGT password is over 180 days old"
        Evidence = "PasswordLastSet = $($krbtgt.PasswordLastSet) (Risk of persistent Golden Ticket abuse)"
    })
}

# ----------------------------------------------------------------------
# 6. Computer Accounts & Unconstrained Delegation Checks
# ----------------------------------------------------------------------
$computers = Get-ADComputer -Filter * -Properties Enabled,
    LastLogonDate, OperatingSystem, OperatingSystemVersion,
    PasswordLastSet, TrustedForDelegation |
    Select-Object Name, Enabled, LastLogonDate, OperatingSystem,
        OperatingSystemVersion, PasswordLastSet, TrustedForDelegation, DistinguishedName

$computers | Export-Csv "$outDir\Computers.csv" -NoTypeInformation

foreach ($c in $computers) {
    if ($c.Enabled -and $c.LastLogonDate -and $c.LastLogonDate -lt $cutoff) {
        $findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object   = $c.Name
            Issue    = "Potentially stale enabled computer"
            Evidence = "LastLogonDate = $($c.LastLogonDate)"
        })
    }

    if ($c.Enabled -and $c.TrustedForDelegation) {
        $findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object   = $c.Name
            Issue    = "Unconstrained Delegation Enabled"
            Evidence = "TrustedForDelegation = True"
        })
    }
}

# ----------------------------------------------------------------------
# 7. Groups & Privileged Membership
# ----------------------------------------------------------------------
$groups = Get-ADGroup -Filter * -Properties GroupCategory,
    GroupScope, AdminCount, whenCreated |
    Select-Object Name, SamAccountName, SID, GroupCategory,
        GroupScope, AdminCount, whenCreated, DistinguishedName

$groups | Export-Csv "$outDir\Groups.csv" -NoTypeInformation

$privilegedGroupNames = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators"
)

$privileged = foreach ($name in $privilegedGroupNames) {
    try {
        $group = Get-ADGroup -Identity $name -ErrorAction Stop
        Get-ADGroupMember -Identity $group -Recursive |
            Select-Object @{N="PrivilegedGroup";E={$name}},
                Name, SamAccountName, ObjectClass, SID
    } catch {
        Write-Warning "Could not query group '$name': $_"
    }
}

$privileged | Export-Csv "$outDir\PrivilegedMembers.csv" -NoTypeInformation

# ----------------------------------------------------------------------
# 8. Password Policy
# ----------------------------------------------------------------------
try {
    Get-ADDefaultDomainPasswordPolicy |
        Select-Object ComplexityEnabled, MinPasswordLength,
            PasswordHistoryCount, MaxPasswordAge, LockoutThreshold,
            LockoutDuration, LockoutObservationWindow |
        Export-Csv "$outDir\PasswordPolicy.csv" -NoTypeInformation
} catch {
    Write-Warning "Password policy query failed: $_"
}

# ----------------------------------------------------------------------
# 9. DNS Configuration & Record Triage
# ----------------------------------------------------------------------
Write-Host "Querying DNS configuration..." -ForegroundColor Cyan

try {
    $dnsZones = Get-DnsServerZone -ErrorAction Stop | 
        Select-Object ZoneName, ZoneType, DynamicUpdate, IsDsIntegrated, IsReverseLookupZone
} catch {
    $dnsZones = Get-CimInstance -Namespace "root\MicrosoftDNS" -ClassName "MicrosoftDNS_Zone" -ErrorAction SilentlyContinue |
        Select-Object @{N="ZoneName";E={$_.Name}}, ZoneType, @{N="DynamicUpdate";E={$_.AllowUpdate}}, @{N="IsDsIntegrated";E={$_.DsIntegrated}}, @{N="IsReverseLookupZone";E={$_.Reverse}}
}

if ($dnsZones) {
    $dnsZones | Export-Csv "$outDir\DNS_Zones.csv" -NoTypeInformation

    foreach ($zone in $dnsZones) {
        if ($zone.DynamicUpdate -eq "NonsecureAndSecure" -or $zone.DynamicUpdate -eq 1) {
            $findings.Add([pscustomobject]@{
                Severity = "High"
                Object   = $zone.ZoneName
                Issue    = "DNS Zone allows non-secure dynamic updates"
                Evidence = "DynamicUpdate = $($zone.DynamicUpdate) (Allows unauthenticated DNS poisoning)"
            })
        }
    }

    $dnsRecords = foreach ($zone in $dnsZones) {
        $zName = $zone.ZoneName
        try {
            Get-DnsServerResourceRecord -ZoneName $zName -ErrorAction Stop | ForEach-Object {
                $recordDataStr = switch ($_.RecordType) {
                    "A"     { $_.RecordData.IPv4Address.IPAddressToString }
                    "AAAA"  { $_.RecordData.IPv6Address.IPAddressToString }
                    "CNAME" { $_.RecordData.HostNameAlias }
                    "TXT"   { $_.RecordData.DescriptiveText -join " " }
                    Default { $_.RecordData.ToString() }
                }

                [pscustomobject]@{
                    ZoneName   = $zName
                    HostName   = $_.HostName
                    RecordType = $_.RecordType
                    RecordData = $recordDataStr
                    TimeToLive = $_.TimeToLive.TotalSeconds
                    Timestamp  = $_.TimeStamp
                }
            }
        } catch {
            Get-CimInstance -Namespace "root\MicrosoftDNS" -ClassName "MicrosoftDNS_ResourceRecord" -Filter "ContainerName='$zName'" -ErrorAction SilentlyContinue |
                Select-Object @{N="ZoneName";E={$_.ContainerName}}, @{N="HostName";E={$_.OwnerName}}, @{N="RecordType";E={$_.RecordClass}}, @{N="RecordData";E={$_.TextRepresentation}}, TimeToLive, Timestamp
        }
    }

    if ($dnsRecords) {
        $dnsRecords | Export-Csv "$outDir\DNS_ResourceRecords.csv" -NoTypeInformation

        foreach ($rec in $dnsRecords) {
            if ($rec.HostName -in @("wpad", "isatap") -and -not $rec.Timestamp) {
                $findings.Add([pscustomobject]@{
                    Severity = "High"
                    Object   = "$($rec.HostName).$($rec.ZoneName)"
                    Issue    = "Static WPAD/ISATAP record detected"
                    Evidence = "Points to $($rec.RecordData). High risk of MitM hijacking."
                })
            }

            if ($rec.RecordType -in @("A", "AAAA") -and -not $rec.Timestamp -and $rec.HostName -ne "@") {
                $findings.Add([pscustomobject]@{
                    Severity = "Low"
                    Object   = "$($rec.HostName).$($rec.ZoneName)"
                    Issue    = "Static A/AAAA record (No timestamp)"
                    Evidence = "Target IP: $($rec.RecordData)"
                })
            }

            if ($rec.RecordType -eq "TXT") {
                $findings.Add([pscustomobject]@{
                    Severity = "Medium"
                    Object   = "$($rec.HostName).$($rec.ZoneName)"
                    Issue    = "DNS TXT record found"
                    Evidence = "Data: $($rec.RecordData)"
                })
            }
        }
    }
}

try {
    $globalBlocklist = Get-DnsServerGlobalQueryBlockList -ErrorAction Stop
    if (-not $globalBlocklist.Enable) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = "DNS Server Configuration"
            Issue    = "DNS Global Query BlockList is disabled"
            Evidence = "Enable = False (Allows WPAD/ISATAP resolution)"
        })
    }
} catch {
    # Non-DNS DC workstation context
}

# Export findings to CSV
$findings | Export-Csv "$outDir\Findings.csv" -NoTypeInformation

# ----------------------------------------------------------------------
# 10. Generate HTML Report
# ----------------------------------------------------------------------
$highCount   = @($findings | Where-Object Severity -eq "High").Count
$mediumCount = @($findings | Where-Object Severity -eq "Medium").Count
$lowCount    = @($findings | Where-Object Severity -eq "Low").Count

$rows = foreach ($f in $findings) {
    $severity = [System.Net.WebUtility]::HtmlEncode($f.Severity)
    $obj      = [System.Net.WebUtility]::HtmlEncode($f.Object)
    $issue    = [System.Net.WebUtility]::HtmlEncode($f.Issue)
    $evidence = [System.Net.WebUtility]::HtmlEncode($f.Evidence)

    $badgeColor = switch ($f.Severity) {
        "High"   { "#d9534f" }
        "Medium" { "#f0ad4e" }
        "Low"    { "#5bc0de" }
        Default  { "#777777" }
    }

    "<tr><td><span style='background-color: $badgeColor; color: white; padding: 3px 8px; border-radius: 3px; font-weight: bold;'>$severity</span></td><td>$obj</td><td>$issue</td><td>$evidence</td></tr>"
}

$html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>AD Security Audit & Inventory Report</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 30px; background-color: #f8f9fa; color: #333; }
.container { background: #ffffff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
h1 { color: #0056b3; border-bottom: 2px solid #0056b3; padding-bottom: 8px; }
table { border-collapse: collapse; width: 100%; margin-top: 15px; }
th, td { border: 1px solid #dee2e6; padding: 10px; text-align: left; }
th { background: #e9ecef; }
tr:nth-child(even) { background-color: #f2f2f2; }
.summary-box { background: #e8f4f8; padding: 12px; border-left: 4px solid #17a2b8; margin-bottom: 20px; }
</style>
</head>
<body>
<div class="container">
<h1>Active Directory Security & Triage Inventory</h1>
<div class="summary-box">
    <p><strong>Domain:</strong> $($domain.DNSRoot)</p>
    <p><strong>Generated:</strong> $(Get-Date)</p>
    <p><strong>Summary:</strong> Users: $(@($users).Count) | Computers: $(@($computers).Count) | Groups: $(@($groups).Count) | DNS Zones: $(@($dnsZones).Count)</p>
    <p><strong>Findings Severity Breakdown:</strong> <span style='color: #d9534f; font-weight: bold;'>High: $highCount</span> | <span style='color: #f0ad4e; font-weight: bold;'>Medium: $mediumCount</span> | <span style='color: #5bc0de; font-weight: bold;'>Low: $lowCount</span></p>
</div>

<h2>Triage Findings</h2>
<p><em>Findings represent vectors for potential exploitation or persistence. Validate findings before taking remediations.</em></p>
<table>
<tr><th>Severity</th><th>Object</th><th>Issue</th><th>Evidence</th></tr>
$($rows -join "`n")
</table>
</div>
</body>
</html>
"@

$html | Set-Content "$outDir\Report.html" -Encoding UTF8

Write-Host "`nInventory complete!" -ForegroundColor Green
Write-Host "Report generated at: $outDir\Report.html"
Write-Host "CSV exports located at: $outDir"