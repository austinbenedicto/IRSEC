
rule IRSEC_Bash_Reverse_Shell
{
    meta:
        description = "Suspicious Bash network shell patterns"
        severity = "high"
        category = "reverse_shell"

    strings:
        $shebang1 = "#!/bin/bash" ascii
        $shebang2 = "#!/usr/bin/env bash" ascii

        $network1 = "/dev/tcp/" ascii
        $network2 = "/dev/udp/" ascii

        $redirect1 = "0>&1" ascii
        $redirect2 = ">& /dev/tcp/" ascii

        $shell1 = "bash -i" ascii
        $shell2 = "/bin/sh -i" ascii

    condition:
        filesize < 1MB and
        (
            (any of ($shebang*) and
             any of ($network*) and
             any of ($shell*))
            or
            ($network1 and $redirect1 and $shell1)
            or
            $redirect2
        )
}
