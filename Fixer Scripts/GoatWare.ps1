function global:Fix-Mouse{
# Check if class exists in current session to prevent TYPE_ALREADY_EXISTS error
if (-not ("MouseFixer" -as [type])) {
    $code = @"
using System;
using System.Runtime.InteropServices;

public class MouseFixer {
    [DllImport("user32.dll")]
    public static extern bool SwapMouseButton(bool fSwap);
}
"@
    Add-Type -TypeDefinition $code
}

# 1. Apply primary left button immediately
[MouseFixer]::SwapMouseButton($false) | Out-Null

# 2. Update registry so Left remains primary after reboot
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SwapMouseButtons" -Value "0"
}

function global:Fix-Keyboard {
    # Force language list to English (US) QWERTY
    $LangList = New-WinUserLanguageList -Language "en-US"
    Set-WinUserLanguageList -LanguageList $LangList -Force
}
function global:Fix-Keys {
    $code = @"
using System; using System.Runtime.InteropServices;
public class Keys {
    [DllImport("user32.dll")] public static extern bool SystemParametersInfo(uint a, uint b, int[] c, uint d);
    public static void Off() {
        SystemParametersInfo(0x003B, 8, new int[]{8, 508}, 3); // StickyKeys OFF
        SystemParametersInfo(0x0033, 24, new int[]{24, 126, 0, 0, 0, 0}, 3); // FilterKeys OFF
        SystemParametersInfo(0x0035, 8, new int[]{8, 62}, 3); // ToggleKeys OFF
    }
}
"@
    if (-not ("Keys" -as [type])) { Add-Type -TypeDefinition $code }
    [Keys]::Off()
}

function global:Fix-All{
Fix-Mouse
Fix-Keyboard
Fix-Keys
}



Fix-All
