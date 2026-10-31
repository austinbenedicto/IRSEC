Import-Module WebAdministration

$mainSite = Get-Website | Select-Object -First 1
$rawPath = if ($mainSite -and $mainSite.physicalPath) {$mainSite.physicalPath } else { "C:\inetpub\wwwroot" }

$webRoot  = [System.Environment]::ExpandEnvironmentVariables($rawPath)

$iusrSid     = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WinIUserSid, $null)
$iisIusrsSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WinBuiltinIUsersSid, $null)
$adminsSid   = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
$systemSid   = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
$everyoneSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
$usersSid    = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)


$inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$allow       = [System.Security.AccessControl.AccessControlType]::Allow


Backup-WebConfiguration -Name "PreHardeningBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
$BR = "C:\BU\wwwroot"
$folders = @("images", "uploads", "assets", "css", "js")
Write-Host -foreground "Green" "Further removing shenanigan abilities"

Set-WebConfigurationProperty -filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxUrl" -Value 2048
Set-WebConfigurationProperty -filter "system.webServer/security/requestFiltering/requestLimits" -Name "maxQueryString" -Value 1024

$dangerousVerbs = @("TRACE", "TRACK", "DEBUG", "SEARCH")
foreach ($verb in $dangerousVerbs) {
    try {
        Add-WebConfigurationProperty -Filter "system.webServer/security/requestFiltering/verbs" -Name "verbs" -Value @{allowed=$false; verb=$verb} -ErrorAction Stop
    } catch {
        # Silently continue if verb is already blocked or rule exists
    }
}

foreach ($site in Get-Website) {
    if ($site -and $site.physicalPath) {
        foreach ($folder in $folders) {
            $sitePath = [System.Environment]::ExpandEnvironmentVariables($site.physicalPath)
            $fullPath = Join-Path $sitePath $folder
            if (Test-Path $fullPath) {
                $location = "$($site.Name)/$folder"
                Set-WebConfigurationProperty -Filter "system.webServer/handlers" -Location $location -Name "accessPolicy" -Value "Read"
                Write-Host "Disabled script execution on $location" -ForegroundColor Green
            }
        }
    }
}


Write-Host -foreground "Green" "removed verbs"


Write-Host -foreground "Green" "creating ideally useless file"

if(-not (Test-Path $BR)){
	New-Item -ItemType Directory -Force -Path $BR | Out-Null
}

Copy-Item -Path "$webRoot\*" -Destination $BR -Force -Recurse

Write-Host -foreground "Green" "Doing shenanigans involving fire"

$acl = Get-Acl -Path $webRoot

$acl.SetAccessRuleProtection($true, $true)

$acl.PurgeAccessRules($everyoneSid)
$acl.PurgeAccessRules($usersSid)

$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, "FullControl", $inheritance, $propagation, $allow)))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adminsSid, "FullControl", $inheritance, $propagation, $allow)))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($iusrSid, "ReadAndExecute, ListFolderContents, Read", $inheritance, $propagation, $allow)))
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($iisIusrsSid, "ReadAndExecute, ListFolderContents, Read", $inheritance, $propagation, $allow)))
Set-Acl -Path $webRoot -AclObject $acl

foreach ($site in Get-Website) {
    if ($site -and $site.physicalPath) {
        $sitePath = [System.Environment]::ExpandEnvironmentVariables($site.physicalPath)
        $uploadPath = Join-Path $sitePath "uploads"
        if (Test-Path $uploadPath) {
            $uAcl = Get-Acl -Path $uploadPath
            $uAcl.SetAccessRuleProtection($false, $false)
            $uAcl.PurgeAccessRules($everyoneSid)
            $uAcl.PurgeAccessRules($usersSid)
            $writeRule = New-Object System.Security.AccessControl.FileSystemAccessRule($iisIusrsSid, "Modify", $inheritance, $propagation, $allow)
            $uAcl.AddAccessRule($writeRule)
            Set-Acl -Path $uploadPath -AclObject $uAcl
            Write-Host "Reset permissions and granted Modify access to $uploadPath" -ForegroundColor Green
        }
    }
}
Write-Host -foreground "green" "shenanigans complete"


