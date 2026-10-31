# Audit-LocalUsers.ps1

$AdminList = @("scrutineer", "techdirector", "crewchief", "firecrew")
$UserList  = @("jackcrew", "garagecrew", "celebrity", "pitlaner", "reserve", "gunners")

# Protected system accounts that must never be disabled (Rules 6 & 14)
$ProtectedAccounts = @("whiteteam", "ddagentuser", "dd-agent")

$allUsers = Get-LocalUser

foreach ($user in $allUsers) {
    $username = $user.Name

    if ($ProtectedAccounts -contains $username) {
        continue
    }

    if ($user.Enabled) {
        if ($AdminList -notcontains $username -and $UserList -notcontains $username) {
            $input = Read-Host "Disable unauthorized user '$username'? (y/n)"
            if ($input -eq "y" -or $input -eq "Y") {
                Disable-LocalUser -Name $username
                Write-Host " [-] Disabled $username" -ForegroundColor Red
            }
        }
    } 
    # Audit Disabled Users: Prompt to enable if they are approved competition accounts
    else {
        if ($AdminList -contains $username -or $UserList -contains $username) {
            $input = Read-Host "Enable approved user '$username'? (y/n)"
            if ($input -eq "y" -or $input -eq "Y") {
                Enable-LocalUser -Name $username
                Write-Host " [+] Enabled $username" -ForegroundColor Green
            }
        }
    }
}