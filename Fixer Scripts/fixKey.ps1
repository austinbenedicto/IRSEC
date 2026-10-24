$ShortcutFile = [Environment]::GetFolderPath("Programs") + "\InlineScriptTask.lnk"

$WShellObject = New-Object -ComObject WScript.Shell
$ShortcutItem = $WShellObject.CreateShortcut($ShortcutFile)

$ShortcutItem.TargetPath  = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$ShortcutItem.Arguments   = '-WindowStyle Hidden -NoProfile -NonInteractive -Command "function GoatWare {
#need to put all of this on same line before running


}; GoatWare"'





$ShortcutItem.Hotkey      = "Ctrl+Alt+N"
$ShortcutItem.Description = "Runs embedded PowerShell code silently"

$ShortcutItem.Save()
