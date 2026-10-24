	
function Header{
	Write-Host "----------------------------------------------------------------------------"
	Write-Host "|                         Gathering Information                            |"
	Write-Host "----------------------------------------------------------------------------"
}


function Storage{
	$Storage = Get-CimInstance -ClassName CIM_DiskDrive | Select-Object Size
	$Storage = (($Storage -split "`n")[0])
	$Storage = $Storage[7..($storage.length-2)] 
	$StorageSize = ""
	foreach($num in $Storage){
		$StorageSize = $StorageSize + $num
	}
	$StorageSizeOutput = "Total Storage:    " + $StorageSize
	Write-Host -Foreground "White" $StorageSizeOutput
}

function RAM{
	$RAM = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
	$RAMOutput = "RAM:              "+$RAM
	Write-Host -ForeGround "White" $RAMOutput
}
function OS{
	$Version = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Version
	$SerialNumber = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object SerialNumber
	$Version = (($Version -split "`n")[0])
	$SerialNumber = (($SerialNumber -split "`n")[0])
	$Version = $Version[10..($Version.length-2)]
	$SerialNumber = $SerialNumber[15..($SerialNumber.length-2)]
	$VersionTemp = ""
	foreach($num in $Version){
		$VersionTemp += $num
	}
	$SerialTemp = ""
	foreach($temp in $SerialNumber){
		$SerialTemp += $temp
	}
	$VersionOutput = "Version:          " + $VersionTemp
	$SerialOutput = "Serial Number:    " + $SerialTemp
	Write-Host -ForeGround "White" $VersionOutput
	Write-Host -ForeGround "White" $SerialOutput
}

function IP{
Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | Format-Table ServiceName, MACAddress, IPAddress, IPSubnet, DefaultIPGateway


	$four = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Wi-Fi        
	$six =  Get-NetIPAddress -InterfaceAlias "Wi-Fi" -AddressFamily IPv6 -AddressState Preferred | Select-Object IPAddress, PrefixOrigin, SuffixOrigin, ValidLifetime    

	$four = ($four -split "`n")[0]
	$temp = ((($six -split "`n")[0]) -split "%")
	$nic = (($temp[1])-split ";")[0]
	$six = ((($six)-split " ")[4])[12..(((($six)-split " ")[4]).length-2)]
	$sixOut = ""
	foreach($twelve in $six){
		$sixOut += $twelve
	}
	$fourOutput = "IPv4:             " + $four
	$sixOutput = "IPv6:             " + $SixOut
	$NICOutput = "NIC:              " + $nic

	Write-Host -ForeGround "White" $fourOutput
	Write-Host -ForeGround "White" $sixOutput
	Write-Host -ForeGround "White" $NICOutput
}

#This ones a bit beyond my current powershell scripting abilities. Made with help from AI
function Ports {
    # 1. Gather all active listening endpoints (TCP and UDP)
    $Endpoints = @()
    if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
        $Endpoints += Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    }
    if (Get-Command Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        $Endpoints += Get-NetUDPEndpoint -ErrorAction SilentlyContinue
    }

    # 2. Process every single endpoint without dropping anything
    $Endpoints | ForEach-Object {
        # CHANGED: Using $OwnerPid instead of the reserved $Pid system variable
        $OwnerPid = $_.OwningProcess
        $Port = $_.LocalPort
        $Protocol = if ($_.GetType().Name -like "*TCP*") { "TCP" } else { "UDP" }
        
        # Check if a Windows Service is attached to this process ID
        $Services = Get-CimInstance -ClassName Win32_Service -Filter "ProcessId = $OwnerPid" -ErrorAction SilentlyContinue
        
        if ($Services) {
            foreach ($Service in $Services) {
                [PSCustomObject]@{
                    "Port"     = $Port
                    "Protocol" = $Protocol
                    "Owner"    = $Service.Name
                    "Type"     = "Windows Service"
                }
            }
        } else {
            # If no service, identify the process or kernel component
            $Process = Get-Process -Id $OwnerPid -ErrorAction SilentlyContinue
            $OwnerName = if ($OwnerPid -eq 4) { "Windows Kernel (System)" } elseif ($Process) { $Process.Name } else { "Unknown" }
            
            [PSCustomObject]@{
                "Port"     = $Port
                "Protocol" = $Protocol
                "Owner"    = $OwnerName
                "Type"     = if ($OwnerPid -eq 4) { "Kernel" } else { "Application" }
            }
        }
    } | Sort-Object Port, Protocol -Unique
}

function Groups{
	$result = @()
	$all = net localgroup
	foreach($item in $all){
		if($item -match "\*"){
			$item = ($item -split "\*")[1]
			$members = net localgroup $item
			$sub = $item.Substring(0, $item.Length-1)
			
			if($members -match $sub){

				$temp = ($members -split "-------------------------------------------------------------------------------") | Select-Object -Skip 7
				$temp = $temp -split "`n"
				
				foreach($tempitem in $temp){	
					if(!($tempitem -match "successful")){
						#$item
						#$temp
						#$tempitem
						if ($tempitem -match '[a-z]') {
							$result += (($item + " - " + $tempitem))
						}
					}
				}
				
			}
			
		}
	}
	
	Write-Host -ForeGround "White" "Groups - Users"
	foreach($val in $result){
		Write-Host -ForeGround "White" $val
	} 
	

}


function Main{
	Header
	Storage
	RAM
	OS
	IP
	Ports
	Groups
}


Main