# =====================================================================
# IRSEC Active Directory & DNS Security Audit Script
# Compatible with Windows Server 2012 R2 through 2025
# =====================================================================

#Requires -RunAsAdministrator

# 1. Create Output Folder
$OutputFolder = "C:\AD_IRSEC_Audit_" + (Get-Date -Format "yyyyMMdd-HHmmss")
New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null

Write-Host "[+] Starting AD Audit. Output directory: $OutputFolder" -ForegroundColor Cyan

# 2. Verify Module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "Active Directory module missing. Installing RSAT..." -ForegroundColor Yellow
    try {
        Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ErrorAction Stop
    } catch {
        Write-Error "Cannot install AD RSAT module automatically. Please install RSAT manually."
        return
    }
}

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# 3. Discover Domain
try {
    $domain = Get-ADDomain -ErrorAction Stop
    $domainName = $domain.DNSRoot
} catch {
    Write-Host "Could not automatically discover domain. Prompting for Domain Controller..." -ForegroundColor Yellow
    $dcTarget = Read-Host "Enter Domain Controller IP or Hostname"
    $domain = Get-ADDomain -Server $dcTarget -ErrorAction Stop
    $domainName = $domain.DNSRoot
}

$findings = [System.Collections.Generic.List[object]]::new()
$remediationCmds = [System.Collections.Generic.List[string]]::new()
$remediationCmds.Add("# Auto-generated Remediation Script")
$remediationCmds.Add("# Generated: " + (Get-Date))
$remediationCmds.Add("")

$staleCutoff = (Get-Date).AddDays(-30)

# 4. Domain Controllers
Write-Host "[+] Auditing Domain Controllers..." -ForegroundColor Gray
try {
    $dcs = Get-ADDomainController -Filter * | Select-Object HostName, IPv4Address, Site, IsGlobalCatalog, IsReadOnly, OperatingSystem
    $dcs | Export-Csv -Path "$OutputFolder\DomainControllers.csv" -NoTypeInformation
} catch {
    Write-Warning "DC Query failed: $_"
}

# 5. User Account Audit
Write-Host "[+] Auditing User Accounts..." -ForegroundColor Gray
try {
    $userProps = @('Enabled', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires', 'PasswordNotRequired', 'DoesNotRequirePreAuth', 'AdminCount', 'ServicePrincipalNames', 'whenCreated')
    $users = Get-ADUser -Filter * -Properties $userProps -ErrorAction Stop
    
    $users | Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, DoesNotRequirePreAuth, AdminCount, whenCreated, DistinguishedName | Export-Csv -Path "$OutputFolder\Users.csv" -NoTypeInformation

    foreach ($u in $users) {
        # Check PasswordNotRequired
        if ($u.Enabled -and $u.PasswordNotRequired) {
            $findings.Add([pscustomobject]@{
                Severity = "High"
                Object   = $u.SamAccountName
                Issue    = "PasswordNotRequired Set"
                Evidence = "PasswordNotRequired = True"
            })
            $remediationCmds.Add("Set-ADUser -Identity '$($u.SamAccountName)' -PasswordNotRequired `$false")
        }

        # Check Pre-Auth Disabled (AS-REP Roasting Target)
        if ($u.Enabled -and $u.DoesNotRequirePreAuth) {
            $findings.Add([pscustomobject]@{
                Severity = "High"
                Object   = $u.SamAccountName
                Issue    = "AS-REP Roastable (Pre-Auth Disabled)"
                Evidence = "DoesNotRequirePreAuth = True"
            })
            $remediationCmds.Add("Set-ADUser -Identity '$($u.SamAccountName)' -DoesNotRequirePreAuth `$false")
        }

        # Check Kerberoastable User
        if ($u.Enabled -and $u.ServicePrincipalNames -and $u.AdminCount -ne 1) {
            $spnList = ($u.ServicePrincipalNames) -join "; "
            $findings.Add([pscustomobject]@{
                Severity = "Medium"
                Object   = $u.SamAccountName
                Issue    = "Kerberoastable Account (SPN Set on Non-Admin)"
                Evidence = "SPNs: $spnList"
            })
        }

        # Check PasswordNeverExpires
        if ($u.Enabled -and $u.PasswordNeverExpires) {
            $findings.Add([pscustomobject]@{
                Severity = "Medium"
                Object   = $u.SamAccountName
                Issue    = "Password Never Expires"
                Evidence = "PasswordNeverExpires = True"
            })
            $remediationCmds.Add("Set-ADUser -Identity '$($u.SamAccountName)' -PasswordNeverExpires `$false")
        }

        # Stale User Check
        if ($u.Enabled -and $u.LastLogonDate -and $u.LastLogonDate -lt $staleCutoff) {
            $findings.Add([pscustomobject]@{
                Severity = "Medium"
                Object   = $u.SamAccountName
                Issue    = "Stale Enabled User (Inactive > 30 Days)"
                Evidence = "LastLogonDate = $($u.LastLogonDate)"
            })
            $remediationCmds.Add("# Disable-ADAccount -Identity '$($u.SamAccountName)'")
        }
    }
} catch {
    Write-Warning "User Query failed: $_"
}

# 6. Safe Check for Shadow Credentials
try {
    $shadowUsers = Get-ADUser -Filter 'msDS-KeyCredentialLink -like "*"' -Properties "msDS-KeyCredentialLink" -ErrorAction SilentlyContinue
    foreach ($su in $shadowUsers) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = $su.SamAccountName
            Issue    = "Shadow Credentials Persistence Detected"
            Evidence = "msDS-KeyCredentialLink attribute populated"
        })
        $remediationCmds.Add("Set-ADUser -Identity '$($su.SamAccountName)' -Clear 'msDS-KeyCredentialLink'")
    }
} catch {}

# 7. krbtgt Password Age Check
try {
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet -ErrorAction SilentlyContinue
    if ($krbtgt -and $krbtgt.PasswordLastSet -and $krbtgt.PasswordLastSet -lt (Get-Date).AddDays(-180)) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = "krbtgt"
            Issue    = "krbtgt Password Older Than 180 Days (Golden Ticket Risk)"
            Evidence = "PasswordLastSet = $($krbtgt.PasswordLastSet)"
        })
    }
} catch {}

# 8. Computer Audit & Delegation
Write-Host "[+] Auditing Computer Objects..." -ForegroundColor Gray
try {
    $compProps = @('Enabled', 'LastLogonDate', 'OperatingSystem', 'OperatingSystemVersion', 'PasswordLastSet', 'TrustedForDelegation')
    $computers = Get-ADComputer -Filter * -Properties $compProps -ErrorAction Stop
    $computers | Select-Object Name, Enabled, LastLogonDate, OperatingSystem, OperatingSystemVersion, PasswordLastSet, TrustedForDelegation, DistinguishedName | Export-Csv -Path "$OutputFolder\Computers.csv" -NoTypeInformation

    foreach ($c in $computers) {
        if ($c.Enabled -and $c.LastLogonDate -and $c.LastLogonDate -lt $staleCutoff) {
            $findings.Add([pscustomobject]@{
                Severity = "Medium"
                Object   = $c.Name
                Issue    = "Stale Enabled Computer"
                Evidence = "LastLogonDate = $($c.LastLogonDate)"
            })
        }

        if ($c.Enabled -and $c.TrustedForDelegation) {
            $findings.Add([pscustomobject]@{
                Severity = "High"
                Object   = $c.Name
                Issue    = "Unconstrained Delegation Enabled"
                Evidence = "TrustedForDelegation = True"
            })
            $remediationCmds.Add("Set-ADAccountControl -Identity '$($c.Name)' -TrustedForDelegation `$false")
        }
    }
} catch {
    Write-Warning "Computer Query failed: $_"
}

# 9. Safe Check for Resource-Based Constrained Delegation (RBCD)
try {
    $rbcdComps = Get-ADComputer -Filter 'msDS-AllowedToActOnBehalfOfOtherIdentity -like "*"' -Properties "msDS-AllowedToActOnBehalfOfOtherIdentity" -ErrorAction SilentlyContinue
    foreach ($rc in $rbcdComps) {
        $findings.Add([pscustomobject]@{
            Severity = "High"
            Object   = $rc.Name
            Issue    = "RBCD Persistence Detected"
            Evidence = "msDS-AllowedToActOnBehalfOfOtherIdentity populated"
        })
        $remediationCmds.Add("Set-ADComputer -Identity '$($rc.Name)' -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'")
    }
} catch {}

# 10. Groups & Privileged Access Audit
Write-Host "[+] Auditing Groups & Privileged Members..." -ForegroundColor Gray
try {
    $groups = Get-ADGroup -Filter * -Properties GroupCategory, GroupScope, AdminCount, whenCreated
    $groups | Select-Object Name, SamAccountName, SID, GroupCategory, GroupScope, AdminCount, whenCreated, DistinguishedName | Export-Csv -Path "$OutputFolder\Groups.csv" -NoTypeInformation

    $privGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    $privMembers = foreach ($pg in $privGroups) {
        try {
            Get-ADGroupMember -Identity $pg -ErrorAction SilentlyContinue | Select-Object @{N="PrivilegedGroup";E={$pg}}, Name, SamAccountName, ObjectClass, SID
        } catch {}
    }
    $privMembers | Export-Csv -Path "$OutputFolder\PrivilegedMembers.csv" -NoTypeInformation
} catch {
    Write-Warning "Group Query failed: $_"
}

# 11. DNS Audit
Write-Host "[+] Auditing DNS Settings & Records..." -ForegroundColor Gray
try {
    $dnsZones = Get-DnsServerZone -ErrorAction Stop | Select-Object ZoneName, ZoneType, DynamicUpdate, IsDsIntegrated
    $dnsZones | Export-Csv -Path "$OutputFolder\DNS_Zones.csv" -NoTypeInformation

    foreach ($z in $dnsZones) {
        if ($z.DynamicUpdate -eq "NonsecureAndSecure" -or $z.DynamicUpdate -eq 1) {
            $findings.Add([pscustomobject]@{
                Severity = "High"
                Object   = $z.ZoneName
                Issue    = "Unauthenticated DNS Dynamic Updates Allowed"
                Evidence = "DynamicUpdate = $($z.DynamicUpdate)"
            })
            $remediationCmds.Add("Set-DnsServerPrimaryZone -Name '$($z.ZoneName)' -DynamicUpdate Secure")
        }

        try {
            $records = Get-DnsServerResourceRecord -ZoneName $z.ZoneName -ErrorAction SilentlyContinue
            foreach ($r in $records) {
                $hostName = $r.HostName.ToLower()
                if (($hostName -eq "wpad" -or $hostName -eq "isatap") -and -not $r.Timestamp) {
                    $findings.Add([pscustomobject]@{
                        Severity = "High"
                        Object   = "$($r.HostName).$($z.ZoneName)"
                        Issue    = "Static WPAD/ISATAP DNS Record Found"
                        Evidence = "RecordType = $($r.RecordType)"
                    })
                    $remediationCmds.Add("Remove-DnsServerResourceRecord -ZoneName '$($z.ZoneName)' -Name '$($r.HostName)' -RRType '$($r.RecordType)' -Force")
                }
            }
        } catch {}
    }
} catch {
    Write-Warning "DNS Query skipped or unavailable: $_"
}

# 12. Save Results & Build Reports
$findings | Export-Csv -Path "$OutputFolder\Findings.csv" -NoTypeInformation
$remediationCmds | Set-Content -Path "$OutputFolder\Remediate.ps1" -Encoding UTF8

$highCount = ($findings | Where-Object Severity -eq "High").Count
$medCount = ($findings | Where-Object Severity -eq "Medium").Count

$htmlRows = foreach ($f in $findings) {
    $bg = if ($f.Severity -eq "High") { "#f8d7da" } else { "#fff3cd" }
    "<tr style='background:$bg;'><td><b>$($f.Severity)</b></td><td>$($f.Object)</td><td>$($f.Issue)</td><td>$($f.Evidence)</td></tr>"
}
$htmlRowString = $htmlRows -join "`n"

$htmlText = @"
<!DOCTYPE html>
<html>
<head>
<title>AD Security Report</title>
<style>
body { font-family: sans-serif; margin: 20px; background: #f8f9fa; }
table { border-collapse: collapse; width: 100%; margin-top: 15px; background: #fff; }
th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
th { background: #343a40; color: #fff; }
</style>
</head>
<body>
<h2>Active Directory & DNS Audit Dashboard</h2>
<p>Domain: $domainName | Date: $(Get-Date)</p>
<p><b>Total High Severity:</b> $highCount | <b>Total Medium Severity:</b> $medCount</p>
<table>
<tr><th>Severity</th><th>Target Object</th><th>Issue</th><th>Evidence</th></tr>
$htmlRowString
</table>
</body>
</html>
"@

$htmlText | Set-Content -Path "$OutputFolder\Report.html" -Encoding UTF8

Write-Host "`n[✔] SUCCESS! Audit Complete." -ForegroundColor Green
Write-Host "Output Folder: $OutputFolder"
Write-Host "Report File:   $OutputFolder\Report.html"