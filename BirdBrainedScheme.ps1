$birds = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

$a=add-type -member '[DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr a, int x, int y, int cx, int cy, uint f);' -name W -passthru; Get-Process | Where-Object {$_.MainWindowTitle} | ForEach-Object {$a::SetWindowPos($_.MainWindowHandle, [IntPtr]-2, 0, 0, 0, 0, 0x0013)}

$currentShell = Get-ItemPropertyValue -Path $birds -Name "Shell" -ErrorAction SilentlyContinue
if ($currentShell -ne "explorer.exe") {
	if (-not (Get-Process -Name "cmd" -ErrorAction SilentlyContinue)) {
            Start-Process cmd.exe -ErrorAction SilentlyContinue
        }
        powershell -Command "Start-Process powershell -ArgumentList '-NoExit' -WindowStyle Maximized; Start-Sleep -m 500; $w=Add-Type -MemberDefinition '[DllImport(\"user32.dll\")] public static extern bool SetForegroundWindow(IntPtr h);' -Name F -PassThru; $p=Get-Process -Name powershell | Sort-Object StartTime -Descending | Select-Object -First 1; $w::SetForegroundWindow($p.MainWindowHandle)" -ErrorAction SilentlyContinue
	 if (-not (Get-Process -Name "taskmgr" -ErrorAction SilentlyContinue)) {
            Start-Process Taskmgr.exe -ErrorAction SilentlyContinue
        }
        Set-ItemProperty -Path $birds -Name "Shell" -Value "explorer.exe" -ErrorAction SilentlyContinue
    }

while($true){
    $birds = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    try {
        $Identity = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        
        $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        
        $Acl = $RegKey.GetAccessControl()
        
        $Acl.SetOwner($Identity)
        $RegKey.SetAccessControl($Acl)
        $RegKey.Close()
        
        $RegKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        $Acl = $RegKey.GetAccessControl()
        $Rule = New-Object System.Security.AccessControl.RegistryAccessRule($Identity, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $Acl.ResetAccessRule($Rule)
        $RegKey.SetAccessControl($Acl)
        $RegKey.Close()
    } catch {
        # please work?
    }


    $currentShell = Get-ItemPropertyValue -Path $birds -Name "Shell" -ErrorAction SilentlyContinue

    Set-ItemProperty -Path $birds -Name "Shell" -Value "explorer.exe" -ErrorAction SilentlyContinue

    
	Start-Sleep 5
}
