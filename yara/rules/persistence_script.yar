
rule IRSEC_Suspicious_Persistence_Script
{
    meta:
        description = "Possible Linux persistence setup script"
        severity = "high"
        category = "persistence"

    strings:
        $persist1 = "/etc/cron.d/" ascii
        $persist2 = "/etc/systemd/system/" ascii
        $persist3 = "crontab -" ascii
        $persist4 = "authorized_keys" ascii

        $remote1 = "curl " ascii
        $remote2 = "wget " ascii
        $remote3 = "/dev/tcp/" ascii

        $exec1 = "bash -c" ascii
        $exec2 = "sh -c" ascii
        $exec3 = "chmod +x" ascii

    condition:
        filesize < 1MB and
        any of ($persist*) and
        any of ($remote*) and
        any of ($exec*)
}
