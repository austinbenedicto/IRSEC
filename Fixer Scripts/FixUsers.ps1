#ADD DATADOG STUFF

$EnabledUsers = Get-LocalUser | Where-Object {$_.Enabled -eq $true}

$AdminList       = @("scrutineer", "techdirector", "crewchief", "firecrew", "whiteteam")
$UserList        = @("jackcrew", "garagecrew", "celebrity", "pitlaner", "reserve", "gunners", "whiteteam")
$DomainAdminList = @("principal", "sportingdir", "chiefeng", "strategist", "whiteteam")
$DomainUserList  = @("pitcrew", "mechanic", "analyst", "driver", "tireman", "fuelman", "whiteteam")

$result = @()

$groups = Get-LocalGroup
$checked = @()
foreach ($group in $groups) {
	$members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | Where-Object {$_.PrincipalSource -eq 'Local'}
		foreach($member in $members){
			$member = (($member.Name -split "\\")[-1]).ToString().Trim()
			if($checked -notcontains $member){
				$memberEnabled = (Get-LocalUser -Name $member).Enabled
				if($memberEnabled){
					if($AdminList -notcontains $member -and $UserList -notcontains $member){
						Write-Host Disable $member"?"
						$input = Read-Host
						if($input -eq "y" -or $input -eq "Y"){
							Disable-LocalUser -Name $member	
							Write-Host "Disabled $member"
						}
					}
				}
				else{
					if($AdminList -contains $member -or $UserList -contains $member){
						Write-Host Enable $member"?"
						$input = Read-Host
						if($input -eq "y" -or $input -eq "Y"){
							Enable-LocalUser -Name $member	
							Write-Host "Enabled $member"
						}

					}
				}
	
				Get-LocalGroup | ForEach-Object {
    					$GroupVal = $_
    					if (Get-LocalGroupMember -Group $GroupVal.Name -Member $member -ErrorAction SilentlyContinue) {
        					#Write-Host "$member is a member of local group: $($GroupVal.Name)"
    					}
				}
			}
			


			
		}
		$checked += $member
}


$result
