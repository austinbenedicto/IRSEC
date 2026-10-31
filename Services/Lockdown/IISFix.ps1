Import-Module WebAdministration -ErrorAction SilentlyContinue

$mainSite   = Get-Website | Select-Object -First 1
$rawPath    = if ($mainSite -and $mainSite.physicalPath) { $mainSite.physicalPath } else { "C:\inetpub\wwwroot" }
$webRoot    = [System.Environment]::ExpandEnvironmentVariables($rawPath)
$backupRoot = "C:\BU\wwwroot"

if (-not (Test-Path $backupRoot)) {
    Write-Host "Backup directory $backupRoot does not exist!" -ForegroundColor Red
    return
}

try {
    
    Get-ChildItem -Path "IIS:\AppPools" -ErrorAction SilentlyContinue | Restart-WebAppPool -ErrorAction SilentlyContinue
    Get-Process -Name "w3wp" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1

    
    robocopy.exe $backupRoot $webRoot /MIR /R:1 /W:1 /NFL /NDL | Out-Null
    if ($LASTEXITCODE -lt 8) {
        Write-Host "Site restored" -ForegroundColor Green
    } else {
        throw "Robocopy failed with exit code $LASTEXITCODE"
    }
}
catch {
    Write-Host "failed: $_" -ForegroundColor Red
}
finally {
    Get-ChildItem -Path "IIS:\AppPools" -ErrorAction SilentlyContinue | ForEach-Object {
        $poolState = (Get-WebAppPoolState -Name $_.Name -ErrorAction SilentlyContinue).Value
        if ($poolState -eq "Stopped") {
            Start-WebAppPool -Name $_.Name -ErrorAction SilentlyContinue
        }
    }
}