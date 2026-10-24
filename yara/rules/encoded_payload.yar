
rule IRSEC_Encoded_Shell_Payload
{
    meta:
        description = "Encoded shell payload execution patterns"
        severity = "medium"
        category = "obfuscation"

    strings:
        $decode1 = "base64 -d" ascii
        $decode2 = "base64 --decode" ascii
        $decode3 = "base64 -di" ascii

        $execute1 = "| bash" ascii
        $execute2 = "| sh" ascii
        $execute3 = "|bash" ascii
        $execute4 = "|sh" ascii

        $other1 = "eval $(" ascii
        $other2 = "eval$(" ascii

    condition:
        filesize < 1MB and
        any of ($decode*) and
        (
            any of ($execute*) or
            any of ($other*)
        )
}
