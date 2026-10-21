
rule IRSEC_Suspicious_Downloader
{
    meta:
        description = "Download-and-execute command patterns"
        severity = "medium"
        category = "downloader"

    strings:
        $download1 = "curl " ascii
        $download2 = "wget " ascii

        $pipe1 = "| bash" ascii
        $pipe2 = "| sh" ascii
        $pipe3 = "|bash" ascii
        $pipe4 = "|sh" ascii

    condition:
        filesize < 1MB and
        any of ($download*) and
        any of ($pipe*)
}
