
rule IRSEC_ELF_Suspicious_Indicators
{
    meta:
        description = "ELF binary with suspicious execution indicators"
        severity = "medium"
        category = "linux_binary"

    strings:
        $exec1 = "/bin/sh" ascii
        $exec2 = "/bin/bash" ascii

        $net1 = "connect" ascii
        $net2 = "socket" ascii

        $persistence1 = "/etc/cron.d/" ascii
        $persistence2 = "/etc/systemd/system/" ascii

    condition:
        filesize < 10MB and
        uint32(0) == 0x464c457f and
        any of ($exec*) and
        any of ($net*) and
        any of ($persistence*)
}
