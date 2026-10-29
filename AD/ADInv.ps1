<#
.SYNOPSIS
    Active Directory & DNS IRSEC Security Audit, Persistence Detection, and Inventory Script.
.DESCRIPTION
    Performs baseline inventory, scans for common AD/DNS security vulnerabilities,
    detects Red Team persistence mechanisms (Shadow Credentials, RBCD, GPO backdoors),
    and generates CSV reports, an HTML summary, and an automated remediation script.
#>

[CmdletBinding()]
param(
    [int]$StaleDays = 30,
    [string]$OutputRoot = $PSScriptRoot
)

#Requires -RunAsAdministrator

# ----------------------------------------------------------------------
# 0. Environment Setup & Module Checks
# ----------------------------------------------------------------------
Write-Host "[+] Verifying required modules..." -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "Active Directory module not found. Installing RSAT..." -ForegroundColor Yellow
    try {
        Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -ErrorAction Stop
    } catch {
        Write-Error "Failed to install AD RSAT tools automatically. Please install manually." -ErrorAction Stop
    }
}

if (-not (Get-Module -ListAvailable -Name DnsServer)) {
    Write-Host "DnsServer module not found. Falling back to CIM/WMI queries where applicable." -ForegroundColor Yellow
}

Import-Module ActiveDirectory -ErrorAction Stop

# ----------------------------------------------------------------------
# 1. Domain Discovery & Output Directory Setup
# ----------------------------------------------------------------------
try {
    $domain = Get-ADDomain -ErrorAction Stop
} catch {
    Write-Warning "Default Active Directory Web Services (ADWS) discovery failed: $_"
    $dcTarget = Read-Host "Enter the FQDN or IP of a target Domain Controller (e.g. dc01.domain.com)"
    $domain = Get-ADDomain -Server $dcTarget -ErrorAction Stop
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path -Path $OutputRoot -ChildPath "AD_IRSEC_Audit_$stamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$findings = [System.Collections.Generic.List[object]]::new()
$remediationCmds = [System.Collections.Generic.List[string]]::new()
$remediationCmds.Add("# Auto-generated IRSEC Remediation Script - Review commands before running!")
$remediationCmds.Add("# Generated: $(Get-Date)")
$remediationCmds.Add("")

$cutoff = (Get-Date).AddDays(-$StaleDays)

Write-Host "[+] Collecting inventory and performing security audit for domain: $($domain.DNSRoot)" -ForegroundColor Cyan

# ----------------------------------------------------------------------
# 2. Domain Controllers & Core Infrastructure
# ----------------------------------------------------------------------
Write-Host " -> Auditing Domain Controllers..." -ForegroundColor Gray
try {
    $dcs = Get-ADDomainController -Filter * |
        Select-Object HostName, IPv4Address, Site, IsGlobalCatalog,
            IsReadOnly, OperatingSystem, OperationMasterRoles

    $dcs | Export-Csv "$outDir\DomainControllers.csv" -NoTypeInformation
} catch {
    Write-Warning "Failed to query Domain Controllers: $_"
}

# ----------------------------------------------------------------------
# 3. User Accounts & Credential Security
# ----------------------------------------------------------------------
Write-Host " -> Auditing User Accounts..." -ForegroundColor Gray
$users = Get-ADUser -Filter * -Properties Enabled, LastLogonDate,
    PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, DONT_REQ_PREAUTH,
    AdminCount, ServicePrincipalNames, whenCreated, "msDS-KeyCredentialLink" |
    Select-Object Name, SamAccountName, Enabled, LastLogonDate,
        PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, DONT_REQ_PREAUTH,
        AdminCount, ServicePrincipalNames, whenCreated, DistinguishedName, "msDS-KeyCredentialLink"

$users | Export-Csv "$outDir\Users.csv" -NoTypeInformation

foreach ($u in $users) {
    if ($u.Enabled -and $u.PasswordNotRequired) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = $u.SamAccountName
            Issue    = "Enabled account has PasswordNotRequired set"
            Evidence = "PasswordNotRequired=True"
        })
        $remediationCmds.Add("Set-ADUser -Identity '$($u.SamAccountName)' -PasswordNotRequired `$false")
    }

    if ($u.Enabled -and $u.DONT_REQ_PREAUTH) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = $u.SamAccountName
            Issue    = "AS-REP Roasting Target (Pre-authentication Disabled)"
            Evidence = "DONT_REQ_PREAUTH=True"
        })
        $remediationCmds.Add("Set-ADUser -Identity '$($u.SamAccountName)' -DoesNotRequirePreAuth `$false")
    }

    if ($u.Enabled -and $u.ServicePrincipalNames -and $u.AdminCount -ne 1) {
        $findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object   = $u.SamAccountName
            Issue    = "Kerberoastable User Account (SPN Set on Non-Admin)"
            Evidence = "SPNs: $($u.ServicePrincipalNames -join '; ')"
        })
    }

    if ($u.Enabled -and $u.PasswordNeverExpires) {
        $findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object   = $u.SamAccountName
            Issue    = "Password Never Expires"
            Evidence = "PasswordNeverExpires=True"
        })
        $remediationCmds.Add("Set-ADUser -Identity '$($u.SamAccountName)' -PasswordNeverExpires `$false")
    }

    if ($u.Enabled -and $u.LastLogonDate -and $u.LastLogonDate -lt $cutoff) {
        $findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object   = $u.SamAccountName
            Issue    = "Potentially Stale Enabled User"
            Evidence = "LastLogonDate=$($u.LastLogonDate)"
        })
        $remediationCmds.Add("# Disable-ADAccount -Identity '$($u.SamAccountName)'")
    }

    # Shadow Credentials Check (pyWhisker / Whisker Persistence)
    if ($u."msDS-KeyCredentialLink") {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = $u.SamAccountName
            Issue    = "Shadow Credentials Detected (Possible Whisker/PKINIT Persistence)"
            Evidence = "msDS-KeyCredentialLink property is populated"
        })
        $remediationCmds.Add("Set-ADUser -Identity '$($u.SamAccountName)' -Clear 'msDS-KeyCredentialLink'")
    }
}

# krbtgt Account Audit (Golden Ticket Check)
try {
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet -ErrorAction SilentlyContinue
    if ($krbtgt -and $krbtgt.PasswordLastSet -and $krbtgt.PasswordLastSet -lt (Get-Date).AddDays(-180)) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = "krbtgt"
            Issue    = "krbtgt password is older than 180 days (Golden Ticket Risk)"
            Evidence = "PasswordLastSet = $($krbtgt.PasswordLastSet). Reset twice to invalidate old TGTs."
        })
    }
} catch {}

# ----------------------------------------------------------------------
# 4. Computer Objects & Delegation Attacks
# ----------------------------------------------------------------------
Write-Host " -> Auditing Computer Objects & Delegation..." -ForegroundColor Gray
$computers = Get-ADComputer -Filter * -Properties Enabled,
    LastLogonDate, OperatingSystem, OperatingSystemVersion,
    PasswordLastSet, TrustedForDelegation, "msDS-AllowedToActOnBehalfOfOtherIdentity" |
    Select-Object Name, Enabled, LastLogonDate, OperatingSystem,
        OperatingSystemVersion, PasswordLastSet, TrustedForDelegation,
        "msDS-AllowedToActOnBehalfOfOtherIdentity", DistinguishedName

$computers | Export-Csv "$outDir\Computers.csv" -NoTypeInformation

foreach ($c in $computers) {
    if ($c.Enabled -and $c.LastLogonDate -and $c.LastLogonDate -lt $cutoff) {
        $findings.Add([pscustomobject]@{
            Severity = "Medium"
            Object   = $c.Name
            Issue    = "Potentially Stale Enabled Computer"
            Evidence = "LastLogonDate=$($c.LastLogonDate)"
        })
    }

    if ($c.Enabled -and $c.TrustedForDelegation) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = $c.Name
            Issue    = "Unconstrained Delegation Enabled"
            Evidence = "TrustedForDelegation=True"
        })
        $remediationCmds.Add("Set-ADAccountControl -Identity '$($c.Name)' -TrustedForDelegation `$false")
    }

    # RBCD Check (Resource-Based Constrained Delegation Persistence)
    if ($c."msDS-AllowedToActOnBehalfOfOtherIdentity") {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = $c.Name
            Issue    = "Resource-Based Constrained Delegation (RBCD) Configured"
            Evidence = "msDS-AllowedToActOnBehalfOfOtherIdentity is populated"
        })
        $remediationCmds.Add("Set-ADComputer -Identity '$($c.Name)' -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'")
    }
}

# ----------------------------------------------------------------------
# 5. Groups & Privileged Access Management
# ----------------------------------------------------------------------
Write-Host " -> Auditing Groups and Privileged Members..." -ForegroundColor Gray
$groups = Get-ADGroup -Filter * -Properties GroupCategory,
    GroupScope, AdminCount, whenCreated |
    Select-Object Name, SamAccountName, SID, GroupCategory,
        GroupScope, AdminCount, whenCreated, DistinguishedName

$groups | Export-Csv "$outDir\Groups.csv" -NoTypeInformation

$privilegedGroupNames = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
$privileged = foreach ($name in $privilegedGroupNames) {
    try {
        $group = Get-ADGroup -Identity $name -ErrorAction Stop
        Get-ADGroupMember -Identity $group |
            Select-Object @{N="PrivilegedGroup";E={$name}}, Name, SamAccountName, ObjectClass, SID
    } catch {
        Write-Warning "Could not query group '$name': $_"
    }
}

$privileged | Export-Csv "$outDir\PrivilegedMembers.csv" -NoTypeInformation

# ----------------------------------------------------------------------
# 6. Group Policy & Domain Trusts Audit
# ----------------------------------------------------------------------
Write-Host " -> Auditing Group Policy Objects & Trusts..." -ForegroundColor Gray
if (Get-Module -ListAvailable -Name GroupPolicy) {
    try {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        $recentGPOs = Get-GPO -All | Where-Object { $_.ModificationTime -gt (Get-Date).AddHours(-24) }
        foreach ($gpo in $recentGPOs) {
            $findings.Add([pscustomobject]@{
                Severity = "Medium"
                Object   = $gpo.DisplayName
                Issue    = "GPO Modified in Last 24 Hours (Review for Malicious Backdoors)"
                Evidence = "Modified: $($gpo.ModificationTime) | Owner: $($gpo.Owner)"
            })
        }
    } catch {
        Write-Warning "Failed to query Group Policy Objects: $_"
    }
}

try {
    $domainTrusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
    if ($domainTrusts) {
        $domainTrusts | Export-Csv "$outDir\DomainTrusts.csv" -NoTypeInformation
        foreach ($t in $domainTrusts) {
            $findings.Add([pscustomobject]@{
                Severity = "Medium"
                Object   = $t.Name
                Issue    = "Domain Trust Configured"
                Evidence = "Direction = $($t.TrustDirection); Type = $($t.TrustType)"
            })
        }
    }
} catch {}

# ----------------------------------------------------------------------
# 7. Password Policies
# ----------------------------------------------------------------------
Write-Host " -> Auditing Password Policies..." -ForegroundColor Gray
try {
    Get-ADDefaultDomainPasswordPolicy |
        Select-Object ComplexityEnabled, MinPasswordLength,
            PasswordHistoryCount, MaxPasswordAge, LockoutThreshold,
            LockoutDuration, LockoutObservationWindow |
        Export-Csv "$outDir\PasswordPolicy.csv" -NoTypeInformation
} catch {
    Write-Warning "Default Password policy query failed: $_"
}

try {
    $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
    if ($fgpp) {
        $fgpp | Export-Csv "$outDir\FineGrainedPasswordPolicies.csv" -NoTypeInformation
    }
} catch {}

# ----------------------------------------------------------------------
# 8. DNS Configuration & Vulnerability Audit
# ----------------------------------------------------------------------
Write-Host " -> Auditing DNS Infrastructure & Records..." -ForegroundColor Gray

try {
    $dnsZones = Get-DnsServerZone -ErrorAction Stop | Select-Object ZoneName, ZoneType, DynamicUpdate, IsDsIntegrated, IsReverseLookupZone
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
                Issue    = "DNS Zone Allows Unauthenticated Dynamic Updates"
                Evidence = "DynamicUpdate=$($zone.DynamicUpdate) (Allows arbitrary DNS poisoning)"
            })
            $remediationCmds.Add("Set-DnsServerPrimaryZone -Name '$($zone.ZoneName)' -DynamicUpdate Secure")
        }
    }

    $dnsRecords = foreach ($zone in $dnsZones) {
        $zName = $zone.ZoneName
        try {
            Get-DnsServerResourceRecord -ZoneName $zName -ErrorAction Stop | ForEach-Object {
                $rData = switch ($_.RecordType) {
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
                    RecordData = $rData
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
            $shortHost = $rec.HostName.Split('.')[0].ToLower()

            if ($shortHost -in @("wpad", "isatap") -and -not $rec.Timestamp) {
                $findings.Add([pscustomobject]@{
                    Severity = "High"
                    Object   = "$($rec.HostName).$($rec.ZoneName)"
                    Issue    = "Static WPAD/ISATAP Record Detected"
                    Evidence = "Points to '$($rec.RecordData)'. High risk of MiTM hijacking."
                })
                $remediationCmds.Add("Remove-DnsServerResourceRecord -ZoneName '$($rec.ZoneName)' -Name '$($rec.HostName)' -RRType '$($rec.RecordType)' -Force")
            }

            if ($rec.RecordType -in @("A", "AAAA") -and -not $rec.Timestamp -and $shortHost -ne "@") {
                $findings.Add([pscustomobject]@{
                    Severity = "Low"
                    Object   = "$($rec.HostName).$($rec.ZoneName)"
                    Issue    = "Static A/AAAA Record (No Timestamp)"
                    Evidence = "Target IP: $($rec.RecordData)"
                })
            }

            if ($rec.RecordType -eq "TXT") {
                $findings.Add([pscustomobject]@{
                    Severity = "Medium"
                    Object   = "$($rec.HostName).$($rec.ZoneName)"
                    Issue    = "DNS TXT Record Found"
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
            Issue    = "DNS Global Query BlockList is Disabled"
            Evidence = "Enable = False (Allows WPAD/ISATAP resolution)"
        })
        $remediationCmds.Add("Set-DnsServerGlobalQueryBlockList -Enable `$true")
    }
} catch {}

# ----------------------------------------------------------------------
# 9. Output Generation (CSV, Remediation Script & HTML Dashboard)
# ----------------------------------------------------------------------
Write-Host "[+] Exporting findings and generating reports..." -ForegroundColor Cyan

$findings | Export-Csv "$outDir\Findings.csv" -NoTypeInformation

$remediationPath = Join-Path $outDir "Remediate_Findings.ps1"
$remediationCmds | Set-Content $remediationPath -Encoding UTF8

$high = @($findings | Where-Object Severity -eq "High").Count
$medium = @($findings | Where-Object Severity -eq "Medium").Count
$low = @($findings | Where-Object Severity -eq "Low").Count

$rows = foreach ($f in $findings) {
    $severity = [System.Net.WebUtility]::HtmlEncode($f.Severity)
    $obj      = [System.Net.WebUtility]::HtmlEncode($f.Object)
    $issue    = [System.Net.WebUtility]::HtmlEncode($f.Issue)
    $evidence = [System.Net.WebUtility]::HtmlEncode($f.Evidence)

    $color = switch ($f.Severity) {
        "High"   { "#f8d7da" }
        "Medium" { "#fff3cd" }
        Default  { "#ffffff" }
    }

    "<tr style='background-color: $color;'><td><b>$severity</b></td><td>$obj</td><td>$issue</td><td>$evidence</td></tr>"
}

$html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>IRSEC AD & DNS Audit Dashboard</title>
<style>
body { font-family: Segoe UI, Tahoma, Geneva, Verdana, sans-serif; margin: 30px; background-color: #f4f6f9; color: #333; }
h1 { color: #003366; }
.card { background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
table { border-collapse: collapse; width: 100%; margin-top: 10px; }
th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
th { background: #003366; color: white; }
.badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; }
.high { background: #dc3545; color: white; }
.medium { background: #ffc107; color: #212529; }
.low { background: #17a2b8; color: white; }
</style>
</head>
<body>
<div class="card">
    <h1>Active Directory IRSEC Audit Dashboard</h1>
    <p><b>Domain:</b> $($domain.DNSRoot) | <b>Generated:</b> $(Get-Date)</p>
    <p><b>Inventory Summary:</b> Users: $(@($users).Count) | Computers: $(@($computers).Count) | Groups: $(@($groups).Count) | DNS Zones: $(@($dnsZones).Count)</p>
    <p><b>Severity Triage:</b> 
        <span class="badge high">High: $high</span> 
        <span class="badge medium">Medium: $medium</span> 
        <span class="badge low">Low: $low</span>
    </p>
</div>

<div class="card">
    <h2>Detected Security Findings & Persistence Leads</h2>
    <p><i>Review accounts and dependencies before taking automated remediation actions.</i></p>
    <table>
    <tr><th>Severity</th><th>Object / System</th><th>Issue Description</th><th>Evidence / Configuration</th></tr>
    $($rows -join "`n")
    </table>
</div>
</body>
</html>
"@

$html | Set-Content "$outDir\Report.html" -Encoding UTF8

Write-Host "`n[✔] Audit complete!" -ForegroundColor Green
Write-Host " -> HTML Summary:      $outDir\Report.html"
Write-Host " -> Findings CSV:      $outDir\Findings.csv"
Write-Host " -> Remediation Plan:  $outDir\Remediate_Findings.ps1"
Write-Host " -> Raw CSV Exports:   $outDir"