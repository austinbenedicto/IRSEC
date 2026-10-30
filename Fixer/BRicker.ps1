#Note this is the BRicker...
Write-Host -ForeGround "Cyan" "Enter the value... you know what value..."
$value = Read-Host

New-NetFirewallRule -Name "BRicker$value" `
    -DisplayName "BRicker - $value" `
    -Direction Inbound `
    -Action Block `
    -RemoteAddress $value `
    -Enabled True