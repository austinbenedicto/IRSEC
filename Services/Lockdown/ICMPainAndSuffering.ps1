$ScoreIP = ""

$RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"

Write-Host -ForeGround "Yellow" "This Command Requires the IP Address of the Scoring Box: "
$ScoreIP = Read-Host
Remove-NetFirewallRule -Name "ICMP_Allow"

New-NetFirewallRule -Name "ICMP_Allow" -DisplayName "SEC - Allow ICMP Inbound from Scoring Engine" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -RemoteAddress $ScoreIP -Action Allow


Write-Host -ForeGround "Green" "Success!"
Get-NetFirewallRule -Name "ICMP_Allow" | Select-Object Name, DisplayName, Enabled, Action, Direction


Write-Host -ForeGround "Cyan" "Now Lock permissions to write to the registry firewall rules folder. Make sure you have run the firewall configuration script first!"

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" -Name "LastKey" -Value "Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"


Start-Process regedit.exe