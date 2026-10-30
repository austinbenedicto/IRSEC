function global:Header{
	Write-Host "----------------------------------------------------------------------------"
	Write-Host "|                                Auditing!                                 |"
	Write-Host "----------------------------------------------------------------------------"


}

function global:Decode{
	process{
		$status = ($_ -split ":")[0]
		$info = ($_ -split ":")[1]
		switch ($status) {
    		"🟥" { Write-Host -ForeGround "Red" "`[FAIL`] " -NoNewLine;Write-Host -Foreground "White" $info}
    		"🟪" { Write-Host -ForeGround "Magenta" "`[BAD?`] " -NoNewLine;Write-Host -Foreground "White" $info}
		"🟨" { Write-Host -ForeGround "Yellow" "`[WARN`] " -NoNewLine;Write-Host -Foreground "White" $info}
		"🟩" { Write-Host -ForeGround "Green" "`[PASS`] " -NoNewLine;Write-Host -Foreground "White" $info}
       		Default   { "Unknown status." }
		}
	}

}
function global:Output{
	Header
	foreach($value in $results){
		$square = $value -split ":"
		$info = $square[1..($square.Count-1)]
		$square = $square[0]
		$character = ""
		if($square -eq "🟨"){
			$color = "Yellow"
			$character = "WARN"
		}
		elseif($square -eq "🟪"){
			$color = "Magenta"
			$character = "BAD?"
		}
		elseif($square -eq "🟩"){
			$color = "Green"
			$character = "PASS"
		}
		elseif($square -eq "🟥"){
			$color = "Red"
			$character = "FAIL"
		}
		Write-Host -ForeGround $color "[$character] " -NoNewLine 
		Write-Host -Foreground "White" $info
	}

}

function global:ExecutionPolicy(){
	$ExecPol = Get-ExecutionPolicy
	$result = @() 
	if($ExecPol -eq "RemoteSigned"){
		$result += "🟨:Execution Policy Remote Signed"
	}
	elseif($ExecPol -eq "Restricted"){
		$result += "🟩:Execution Policy Restricted"
	}
	elseif($ExecPol -eq "AllSigned"){
		$result += "🟨:Execution Policy All Signed"
	}
	elseif($ExecPol -eq "Unrestricted"){
		$result += "🟥:Execution Policy Unrestricted"
	}
	elseif($ExecPol -eq "Bypass"){
		$result += "🟥:Execution Policy Bypass"
	}
	elseif($ExecPol -eq "Undefined"){
		$result += "🟥:Execution Policy Undefined"
	}
	else{
		$result += "🟪:Execution Policy Default"
	}

	return $result
}

function global:UserAccountControl{
	$result = @()
	$temp = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop
	$lua = ((($temp -split "=")[1]) -split ";")[0]
	$behavior = ((($temp -split "=")[2]) -split ";")[0]
	$secure = ((((($temp -split "=")[3]) -split ";")[0])-split "}")[0]
	if($lua-eq1-and$behavior-ne5-and$behavior-ne0-and$secure-eq1){
		$result+="🟩:UAC Secure"
	}
	elseif($lua-eq1-and$behavior-eq5-and$secure-eq1){
		$result+="🟨:UAC Windows Default"
	}
	else{
		$result+="🟥:UAC Insecure"
	}


	return $result
}

function global:LocalSecurityPolicy{
	$result = @()
	
	
	return $result
}

function global:GroupPolicy{
	$result = @()


	return $result

}

function global:LegacyProtocolsFeatures{
	$result = @()
	$smb1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" | Select-Object FeatureName, State
	$ntlm2 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue | Select-Object LmCompatibilityLevel
	$guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount = True AND SID LIKE '%-501'" | Select-Object Name, Disabled
	$autorun = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue | Select-Object NoDriveTypeAutoRun
	

	$llmnr = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue).EnableMulticast
	$netbios = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled} | Select-Object Description, TcpipNetbiosOptions
	$powershell2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2"
	$wdigest = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
	$remoteregistry = (Get-Service -Name "RemoteRegistry" -ErrorAction SilentlyContinue).StartType
	
	$Protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")

	

	$SchannelStatus = foreach ($Proto in $Protocols) {
		$Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Proto\Server"
    
		$Enabled = Get-ItemProperty -Path $Path -Name "Enabled" -ErrorAction SilentlyContinue
    
    		[PSCustomObject]@{
        		Protocol        = $Proto
        		ConfiguredState = if ($Enabled) { if ($Enabled.Enabled -eq 0) { "Explicitly Disabled" } else { "Explicitly Enabled" } } else { "Default (Not set in registry)" }
    		}
}


#$SchannelStatus

#$
#$llmnr
$powershell2
#$wdigest
#$remoteregistry
#$autorun
#$protocols

	foreach ($item in $netbios){
		$system = ((($item -split "=")[1]) -split ";")[0]
		$value = ((($item -split "=")[2]) -split "}")[0]
		if($value-eq2){
			$result += ("🟩:NetBIOS - "+$system+" - Disabled")
		}
		elseif($value-eq1){
			$result += ("🟥:NetBIOS - "+$system+" - Enabled")
		}
		else{
			$result += ("🟨:NetBIOS - "+$system+" - Unconfigured")
		}

	}
$smb1 = (($smb1 -split "State=")[1] -split "}")[0]


	if($smb1-eq"Disabled"){
		$result += "🟩:SMBv1 Disabled"
	}
	elseif($smb1-eq"Enabled"){
		$result += "🟥:SMBv1 Enabled"
	}

$ntlm2 = ((($ntlm2 -split "Enabled=")[1]) -split "}")[0]
	
	if($ntlm2-eq5){
		$result += "🟩:NTLM 5, Good Hashing"
	}
	else{
		$result += "🟥:NTLM not 5, Weak Hashing or No Hashing... NTLMv1 Allowed"
	}

$guest = (($guest -split "Disabled=")[1] -split "}")[0]
	
	if($guest-eq"True"){
		$result += "🟩:Guest Account Disabled"
	}
	else{
		$result += "🟥:Guest Account Enabled"
	}



	return $result

}


function global:WindowsOptionalFeatures{
	$result = @()


	return $result
}

function global:Groups{
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
							$result += ("🟪:"+ ($item + " - " + $tempitem))
						}
					}
				}
				
			}
			
		}
	}
	
	return $result

}

function global:Users{
	$result = @()
	$allowed = "JW, Guest, Administrator, DefaultAccount, WDAGUtilityAccount"
	$allowed = $allowed -split ", "
	$current = (net user)[4 .. ((net user).Length - 2)] -split '\s+' | Where-Object { $_ -ne '' }
	$current = $current -split "`n"
	$current = $current[0..($current.Length -5)]

	foreach($value in $current){
		if($value -match '[A-z]'){
			if($value -In $allowed){
				$result += ("🟩:User - " +$value)
			}	
			else{
				$result += ("🟥:Invalid User - "+$value)
			}
		}
	}	

	return $result

}

function global:Firewall{
	$result = @()


	return $result

}

function global:Scheduler{
	$result = @()


	return $result

}

function global:Audits{
	$result = @()


	return $result

}

function global:Registry{
	$result = @()


	return $result

}

function global:Processes{
	$result = @()


	return $result
}

function global:Services{
	$result = @()
	$Services = Get-Service | Select-Object -ExpandProperty DisplayName
	$ServiceList = "
Function Discovery Provider Host
Function Discovery Resource Publication
ZTDNS Helper service
Agent Activation Runtime_33272b
Aggregated Data Platform Service
Application Layer Gateway Service
Application Identity
Application Information
Application Management
App Readiness
Microsoft App-V Client
AppX Deployment Service (AppXSVC)
Windows Virtual Audio Device Proxy Service
AssignedAccessManager Service
Windows Audio Endpoint Builder
Windows Audio
Cellular Time
ActiveX Installer (AxInstSV)
GameDVR and Broadcast User Service_33272b
BitLocker Drive Encryption Service
Base Filtering Engine
Background Intelligent Transfer Service
Bluetooth User Support Service_33272b
Background Tasks Infrastructure Service
Bluetooth Audio Gateway Service
AVCTP service
Bluetooth Support Service
Capability Access Manager Service
CaptureService_33272b
Clipboard User Service_33272b
Connected Devices Platform Service
Connected Devices Platform User Service_33272b
Certificate Propagation
Microsoft Office Click-to-Run Service
Client License Service (ClipSVC)
Cloud Backup and Restore Service_33272b
Microsoft Cloud Identity Service
COM+ System Application
ConsentUX User Service_33272b
CoreMessaging
CredentialEnrollmentManagerUserSvc_33272b
Cryptographic Services
Offline Files
DCOM Server Process Launcher
Declared Configuration(DC) service
Optimize drives
Dell Client Management Service
Dell TechHub
Dell Trusted Device
DeviceAssociationBroker_33272b
Device Association Service
Device Install Service
DevicePicker_33272b
DevicesFlow_33272b
DevQuery Background Discovery Broker
DHCP Client
Diagnostic Execution Service
Connected User Experiences and Telemetry
DialogBlockingService
Display Policy Service
Display Enhancement Service
Device Management Enrollment Service
Device Management Wireless Application Protocol (WAP) Push message Routing Service
DNS Client
Delivery Optimization
Wired AutoConfig
Diagnostic Policy Service
Intel(R) Dynamic Tuning Technology Telemetry Service
Device Setup Manager
Data Sharing Service
Data Usage
EABackgroundService
Extensible Authentication Protocol
Microsoft Edge Update Service (edgeupdate)
Microsoft Edge Update Service (edgeupdatem)
Encrypting File System (EFS)
Embedded Mode
Enterprise App Management Service
Windows Event Log
COM+ Event System
function global:Discovery Provider Host
function global:Discovery Resource Publication
File History Service
Windows Font Cache Service
Windows Camera Frame Server
Windows Camera Frame Server Monitor
GameInput Redist Service
GameInput Service
Gaming Services
Gaming Services
Group Policy Client
GraphicsPerfSvc
Human Interface Device Service
Credential Vault Host Storage
Hotpatch Monitoring Service
HV Host Service
Windows Mobile Hotspot Service
intelliGo Audio Service
IKE and AuthIP IPsec Keying Modules
Microsoft Store Install Service
Intel(R) Audio Service
Intel(R) Graphics Display Service
Intel® Graphics Software
Intel(R) Trace Agent Service
Inventory and Compatibility Appraisal service
Intel(R) Innovation Platform Framework Service
IP Helper
IP Translation Configuration Service
IsolationSession
IsoSessionCore
CNG Key Isolation
KtmRm for Distributed Transaction Coordinator
Server
Workstation
Geolocation Service
Windows License Manager Service
Link-Layer Topology Discovery Mapper
TCP/IP NetBIOS Helper
Kerberos Local Key Distribution Center
Local Session Manager
Language Experience Service
Downloaded Maps Manager
Mobile Connectivity Management Service
McpManagementService
Microsoft Defender Core Service
MessagingService_33272b
Microsoft Edge Elevation Service (MicrosoftEdgeElevationService)
Windows MIDI Service
Mozilla Maintenance Service
Windows Defender Firewall
Distributed Transaction Coordinator
Microsoft iSCSI Initiator Service
Windows Installer
Microsoft Keyboard Filter
Natural Authentication
Network Connectivity Assistant
Network Connection Broker
Network Connected Devices Auto-Setup
Netlogon
Network Connections
Network List Service
Network Setup Service
Net.Tcp Port Sharing Service
Microsoft Passport Container
Microsoft Passport
Network Location Awareness
Now Playing Session Manager Service_33272b
Network Store Interface Service
Sync Host_33272b
P9RdrService_33272b
Program Compatibility Assistant Service
BranchCache
PenService_33272b
Performance Counter DLL Host
Phone Service
Contact Data_33272b
Performance Logs & Alerts
Plug and Play
IPsec Policy Agent
Power
Print Device Configuration Service
Printer Extensions and Notifications
PrintScanBrokerService
PrintWorkflow_33272b
User Profile Service
Windows PushToInstall Service
Quality Windows Audio Video Experience
Remote Access Auto Connection Manager
Remote Access Connection Manager
ReFS Dedup Service
Routing and Remote Access
Remote Registry
Retail Demo Service
Radio Management Service
RPC Endpoint Mapper
Remote Procedure Call (RPC) Locator
Remote Procedure Call (RPC)
Intel(R) Storage Middleware Service
Realtek Audio Universal Service
Security Accounts Manager
Smart Card
Smart Card Device Enumeration Service
Task Scheduler
Smart Card Removal Policy
Windows Backup
Secondary Logon
Windows Security Service
Payments and NFC/SE Manager
System Event Notification Service
Windows Defender Advanced Threat Protection Service
Sensor Data Service
Sensor Service
Sensor Monitoring Service
Remote Desktop Configuration
Session Detection
Internet Connection Sharing (ICS)
Shell Hardware Detection
Shared PC Account Manager
Microsoft Storage Spaces SMP
Microsoft Windows SMS Router Service.
SNMP Trap
Print Spooler
Software Protection
SSDP Discovery
OpenSSH Authentication Agent
Secure Socket Tunneling Protocol Service
State Repository Service
Windows Image Acquisition (WIA)
Storage Service
Spot Verifier
Microsoft Software Shadow Copy Provider
SysMain
System Events Broker
Telephony
Thunderbolt(TM) Peer to Peer Shortcut
Remote Desktop Services
Text Input Management Service
Themes
Storage Tiers Management
Time Broker
Web Account Manager
Distributed Link Tracking Client
Recommended Troubleshooting Service
Windows Modules Installer
Auto Time Zone Updater
Udk User Service_33272b
User Experience Virtualization Service
Remote Desktop Services UserMode Port Redirector
User Data Storage_33272b
UPnP Device Host
User Data Access_33272b
User Manager
Credential Vault Upgrade Service
Update Orchestrator Service
Credential Manager
VirtualBox system service
Virtual Disk
VMware Authorization Service
Hyper-V Guest Service Interface
Hyper-V Heartbeat Service
Hyper-V Data Exchange Service
Hyper-V Remote Desktop Virtualization Service
Hyper-V Guest Shutdown Service
Hyper-V Time Synchronization Service
Hyper-V PowerShell Direct Service
Hyper-V Volume Shadow Copy Requestor
VMware DHCP Service
VMware USB Arbitration Service
VMware NAT Service
VMware Autostart Service
Volume Shadow Copy
Windows Time
WaaSMedicSvc
WalletService
Warp JIT Service
Waves Audio Services
Block Level Backup Engine Service
Windows Biometric Service
Windows Connection Manager
Windows Connect Now - Config Registrar
Diagnostic Service Host
Diagnostic System Host
Microsoft Defender Antivirus Network Inspection Service
WebClient
Web Threat Defense Service
Web Threat Defense User Service_33272b
Windows Event Collector
Windows Encryption Provider Host Service
Problem Reports Control Panel Support
Windows Error Reporting Service
Wi-Fi Direct Services Connection Manager Service
Windows Health and Optimized Experiences
Still Image Acquisition Events
Microsoft Defender Antivirus Service
WinHTTP Web Proxy Auto-Discovery Service
Windows Management Instrumentation
Windows Remote Management (WS-Management)
WireGuard Manager
WireGuard Tunnel: team2-peer4
Windows Insider Service
WLAN AutoConfig
Microsoft Account Sign-in Assistant
Local Profile Assistant Service
Windows Management Service
WMI Performance Adapter
Intel(R) Management Engine WMI Provider Registration
Windows Media Player Network Sharing Service
Work Folders
Parental Controls
Portable Device Enumerator Service
Windows Push Notifications System Service
Windows Push Notifications User Service_33272b
Windows AI Components Host
Security Center
Windows Search
Windows Update
Microsoft Usage and Quality Insights
WWAN AutoConfig
Xbox Live Auth Manager
Xbox Live Game Save
Xbox Accessory Management Service
Xbox Live Networking Service"
$ServiceList = $ServiceList -split '\r?\n'
foreach($Service in $Services){	
	if($Service -notin $ServiceList){
		$result += "🟨:Potential Service Issue - "+$Service
	}
}
	return $result
}

function global:NetworkShares{
	$result = @()


	return $result
}

function global:StartUp{
	$result = @()


	return $result
}

function global:Updates{
	$result = @()


	return $result
}

function global:Programs{
	$result = @()


	return $result
}

function global:Remote{
	$result = @()


	return $result
}

function global:EventLogs{
	$result = @()


	return $result
}

#function global:Ports{
	#param(
	#	[boolean]$Exhaust
	#)
	
	
	#$result = @()
	

	#$TCP = Get-NetTCPConnection
	#$UDP = Get-NetUDPEndpoint
	#foreach($Connection in $TCP){
	#	if($Connection.State-eq""){
	#		
	#	}
	#}

	#return $result
#}

function global:DNS{
	$result = @()


	return $result
}

function global:SessionAndCredentialProtection{
	$result = @()


	return $result
}


function global:HostsFileIntegrity{
	$result = @()


	return $result
}

function global:CheckPSAliasing{


}


function global:Main{
	$results=@()
	$results += ExecutionPolicy #Done
	$results += UserAccountControl #Done
	$results += LocalSecurityPolicy
	$results += GroupPolicy
	$results += LegacyProtocolsFeatures #Work in Progress
	$results += Groups
	$results += Users
	$results += Scheduler #sysinternals?
	$results += Audits
	$results += Registry #PrivEsc
	$results += Processes #sysinternals?
	$results += Services #done
	$results += NetworkShares
	$results += StartUp #sysinternals?
	$results += Updates
	$results += Programs #autoruns
	$results += Remote
	$results += EventLogs
	$results += Ports #sysinternals
	$results += DNS 
	$results += SessionAndCredentialProtection
	$results += HostsFileIntegrity
	$results += Firewall
	$results += WindowsOptionalFeatures
 

	Output	
}

Main
