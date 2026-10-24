
rule IRSEC_Credential_Access_Script
{
    meta:
        description = "Possible credential collection script"
        severity = "high"
        category = "credential_access"

    strings:
        $credential1 = "/etc/shadow" ascii
        $credential2 = "/root/.ssh/id_rsa" ascii
        $credential3 = "/root/.ssh/id_ed25519" ascii
        $credential4 = ".bash_history" ascii

        $archive1 = "tar -czf" ascii
        $archive2 = "tar czf" ascii
        $archive3 = "zip -r" ascii

        $transfer1 = "curl -F" ascii
        $transfer2 = "scp " ascii
        $transfer3 = "nc " ascii

    condition:
        filesize < 1MB and
        any of ($credential*) and
        (
            any of ($archive*) or
            any of ($transfer*)
        )
}
