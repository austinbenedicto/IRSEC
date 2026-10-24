rule IRSEC_PHP_Webshell_Indicators
{
    meta:
        description = "PHP request input combined with command execution"
        severity = "high"
        category = "webshell"

    strings:
        $php = "<?php" nocase

        $input1 = "$_GET[" ascii
        $input2 = "$_POST[" ascii
        $input3 = "$_REQUEST[" ascii

        $exec1 = "shell_exec(" ascii
        $exec2 = "system(" ascii
        $exec3 = "passthru(" ascii
        $exec4 = "exec(" ascii

    condition:
        filesize < 1MB and
        $php and
        any of ($input*) and
        any of ($exec*)
}