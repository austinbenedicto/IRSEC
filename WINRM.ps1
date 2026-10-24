
if((Get-Service -Name WinRM).Status -ne "Running"){
		Start-Service WinRM
		Write-Host -ForeGround "Green" "WinRM Started"
}
WinRM quickconfig -q


while($true){
	#5985, 5986
	if((Get-Service -Name WinRM).Status -ne "Running"){
		Set-Service -Name WinRM -StartupType Automatic -ErrorAction SilentlyContinue
		Start-Service WinRM
		Write-Host -ForeGround "Green" "WinRM Started"
	}
	try {
		$dump = Test-WSMan -ComputerName "127.0.0.1" -ErrorAction Stop
		Write-Host "Success: WinRM is fully responsive." -ForegroundColor Green
	} 
	catch [System.InvalidOperationException] {
		$errorMessage = $_.Exception.Message
		switch -Wildcard ($errorMessage) {
			"*The client cannot connect to the destination specified*" {
				Write-Host "ERROR: Connection refused. Check if a firewall is blocking port 5985/5986, or run 'winrm quickconfig' on the target." -ForegroundColor Red
				Write-Host -ForeGround "Yellow" "Attempt Auto-Remediation? y/n: " -NoNewLine
				Write-Host -ForeGround "Red" "I have no idea what im doing ☹️. fix this manually"
        		}
        	"*The WinRM client cannot process the request*computer in the TrustedHosts list*" {
			Write-Host "ERROR: Authentication failed. You must add this computer to your TrustedHosts list." -ForegroundColor Yellow
			$IPVal = 0.0.0.0/## #Replace with scoring box or network IP when able
			# Set-Item WSMan:\localhost\Client\TrustedHosts -Value "$IPVal"
        		}

        	"*Access is denied*" {
			Write-Host "ERROR: Access Denied. Your current account doesn't have administrative privileges on the target machine." -ForegroundColor Red
        		}

        	"*The network location profile*Public*" {
			Write-Host "ERROR: Network profile is set to Public. WinRM requires Private or Domain." -ForegroundColor Red
        		}

        	Default {
			Write-Host "An unhandled WinRM error occurred:" -ForegroundColor DarkRed
            		Write-Host $errorMessage -ForegroundColor Red
        		}
		}
	}
	catch {
		Write-Host "General Network or DNS Error: $($_.Exception.Message)" -ForegroundColor Red
	}
	Start-Sleep 5
}