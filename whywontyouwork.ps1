#really hoping the file name isn't accurate... i wrote it before creating the script

$MyIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254*" }).IPAddress | Select-Object -First 1
$Sadness = "10.64.1.0/24"
$LockDown = $true
Write-Host "Enter the scoring box IP"
$ScoreCheck = Read-Host 
$DataDogPorts = @(443, 8443, 10516, 123, 8042, 5002, 8126, 8125, 5012, 5000, 5001, 6062, 6162)

$DataDogIPs = @("34.149.66.128/26", "34.160.125.158/32", "35.190.51.116/32", "34.149.119.85/32", "34.149.203.90/32", "34.110.187.75/32", "34.117.129.254/32", "34.149.54.227/32", "34.160.7.29/32", "34.160.40.115/32", "34.160.41.148/32", "34.160.150.109/32", "35.244.255.175/32", "13.244.85.86/32", "13.244.188.203/32", "13.245.194.43/32", "13.245.200.254/32", "13.246.172.210/32", "13.247.164.9/32", "18.99.147.8/29", "3.45.0.40/29", "16.162.136.62/32", "16.163.153.45/32", "18.163.21.55/32", "18.163.59.106/32", "18.166.19.255/32", "43.198.123.228/32", "5.60.130.112/29", "13.114.211.96/32", "13.115.46.213/32", "52.192.175.207/32", "3.35.66.96/32", "3.36.177.119/32", "13.209.118.42/32", "13.209.230.111/32", "15.165.240.116/32", "18.98.131.24/29", "43.203.72.233/32", "13.208.126.217/32", "13.208.133.55/32", "13.208.142.17/32", "13.208.255.200/32", "15.152.238.192/32", "15.168.188.85/32", "18.96.16.112/29", "13.126.169.175/32", "13.234.54.8/32", "18.96.227.72/29", "35.154.93.182/32", "3.1.36.99/32", "3.1.219.207/32", "18.99.34.208/29", "18.139.52.173/32", "13.54.169.48/32", "13.236.246.161/32", "13.238.14.57/32", "18.98.196.216/29", "18.98.96.240/29", "43.218.5.202/32", "108.137.133.223/32", "108.137.188.57/32", "3.96.7.126/32", "18.99.4.112/29", "52.60.189.53/32", "99.79.87.237/32", "3.40.2.64/29", "3.120.223.25/32", "3.121.24.234/32", "18.195.155.52/32", "13.48.150.244/32", "13.48.239.118/32", "13.48.254.37/32", "18.99.99.232/29", "15.161.86.71/32", "18.99.209.96/29", "18.102.80.189/32", "35.152.76.8/32", "3.40.134.72/29", "18.200.120.237/32", "63.34.100.178/32", "63.35.33.198/32", "3.41.0.88/29", "18.130.113.168/32", "35.176.195.46/32", "35.177.43.250/32", "15.188.202.64/32", "15.188.240.172/32", "15.188.243.248/32", "18.98.67.176/29", "18.99.224.56/29", "3.44.192.120/29", "18.229.28.50/32", "18.229.36.120/32", "52.67.95.251/32", "3.41.176.48/29", "3.92.150.182/32", "52.55.56.26/32", "107.21.25.247/32", "3.18.172.189/32", "3.18.188.104/32", "3.18.197.0/32", "18.97.147.8/29", "18.96.130.96/29", "52.9.13.199/32", "52.9.139.134/32", "54.177.155.33/32", "3.42.136.80/29", "34.208.32.189/32", "52.35.61.232/32", "52.89.221.151/32", "20.62.248.141/32", "20.83.144.189/32", "40.76.107.170/32", "52.186.167.216/29", "34.146.154.144/29", "34.159.50.128/29", "34.48.76.208/29", "34.174.98.16/29", "34.145.82.128/29", "34.94.234.88/29", "8.234.4.128/25", "34.0.225.0/24", "34.69.237.0/24", "34.121.119.136/32", "35.184.241.87/32", "35.223.11.90/32", "209.162.159.0/26")


$Port = @(514, 53, 88, 135, 389, 445, 636, 3268, 3269, 9389) + $DataDogPorts
$IPV4 = @("10.5.1.1", "10.5.1.254", "192.168.5.4", "192.168.5.4") + $DataDogIPs + $MyIp + $ScoreCheck

#LAN, Server2025, AD/DNS
if($env:COMPUTERNAME -eq "pitwall"){
	$IPV4 += "10.5.1.2", "10.5.1.3", "192.168.5.1", "192.168.5.2"
	$Port += 853, 5353, 5355
}
if ($env:COMPUTERNAME -eq "pitwall") {
	Remove-NetFirewallRule -Name "IRSEC_RPC_Dynamic" -ErrorAction SilentlyContinue
	New-NetFirewallRule -Name "IRSEC_RPC_Dynamic" -DisplayName "Allow RPC Dynamic" -Direction Inbound -Protocol TCP -LocalPort "49152-65535" -RemoteAddress $IPV4 -Action Allow
}

#LAN, Windows11, WinRM
if($env:COMPUTERNAME -eq "teamradio"){
	$IPV4 += "10.5.1.2"
	$Port += 5985, 5986
}

#LAN, Windows10, ICMP/TelNet
if($env:COMPUTERNAME -eq "safetycar"){
	$IPV4 += "10.5.1.3"
	$Port += 23
	$LockDown = $false
}

#WAN, Server2022, SMB
if($env:COMPUTERNAME -eq "transporters"){
	$IPV4 += "192.168.5.1", "10.5.1.4"
	$Port += 5445
}

#WAN, Windows10, IIS
if($env:COMPUTERNAME -eq "stewards"){
	$IPV4 += "192.168.5.2", "10.5.1.6"
	$Port += 80, 443, 8172, 8080
}



$DataDogTCP = @(443, 8443, 10516, 8042, 5002, 8126, 5012, 5000, 5001, 6062, 6162)

$DataDogUDP = @(123, 8125)


$PortTCP = @(53, 88, 135, 389, 445, 636, 3268, 3269, 9389, 464, 3389) + $DataDogTCP

$PortUDP = @(53, 88, 123, 389, 514, 464) + $DataDogUDP

switch -Exact ($env:COMPUTERNAME) {
    "pitwall" {
        # Active Directory / DNS Server (Server 2025)
        $PortTCP += 853        
        $PortUDP += 5353, 5355 
    }
    "teamradio" {
        # WinRM Management (Windows 11)
        $PortTCP += 5985, 5986 
    }
    "safetycar" {
        # Scored Telnet (Windows 10)
        $PortTCP += 23
    }
    "transporters" {
        # Scored SMB (Server 2022)
        $PortTCP += 5445
    }
    "stewards" {
        # Scored IIS Web Server (Windows 10)
        $PortTCP += 80, 443, 8080, 8172 
    }
}

Remove-NetFirewallRule -Name "IRSECASPs_TCP" -ErrorAction SilentlyContinue
Remove-NetFirewallRule -Name "IRSECASPs_UDP" -ErrorAction SilentlyContinue

New-NetFirewallRule -Name "IRSECASPs_TCP" `
    -DisplayName "IRSECRPA_TCP" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort $PortTCP `
    -RemoteAddress $IPV4 `
    -Action Allow

New-NetFirewallRule -Name "IRSECASPs_UDP" `
    -DisplayName "IRSECRPA_UDP" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort $PortUDP `
    -RemoteAddress $IPV4 `
    -Action Allow
if($LockDown){
	Write-Host -ForeGround "Cyan" "Disable Write Permissions to Registry Firewall stuff"
}
else{
	Write-Host -ForeGround "Cyan" "Don't forget to run ICMPain+Suffering script"
}

$ManagementIP = "172.16.1.0/24"
New-NetFirewallRule -Name "AllowManagementNetworkTCP" `
    -DisplayName "Management_TCP" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort * `
    -RemoteAddress  $ManagementIP`
    -Action Allow

New-NetFirewallRule -Name "AllowManagementNetworkUDP" `
    -DisplayName "Management_UDP" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort * `
    -RemoteAddress $ManagementIP `
    -Action Allow


Set-NetFirewallProfile -Profile Domain, Private, Public -DefaultInboundAction Block
