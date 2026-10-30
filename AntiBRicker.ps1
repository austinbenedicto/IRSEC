#Note this is the UNBRicker...
Write-Host -ForeGround "Cyan" "Enter the value... you know what value..."
$value = Read-Host

Write-Host -ForeGround "Cyan" "Any x in a Storm"
$p = Read-Host

New-NetFirewallRule -Name "UNBRicker$value" `
	-DisplayName "UNBRicker - $value" `
	-Direction Inbound `
	-Action Allow `
	-RemoteAddress $value `
	-LocalPort $p `
	-Enabled True
