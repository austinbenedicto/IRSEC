
rule IRSEC_JSP_Webshell_Indicators
{
    meta:
        description = "Suspicious JSP command execution"
        severity = "high"
        category = "webshell"

    strings:
        $jsp = "<%@" ascii
        $request = "request.getParameter(" ascii
        $exec1 = "Runtime.getRuntime().exec(" ascii
        $exec2 = "ProcessBuilder(" ascii

    condition:
        filesize < 1MB and
        $jsp and
        $request and
        any of ($exec*)
}

rule IRSEC_ASPX_Webshell_Indicators
{
    meta:
        description = "Suspicious ASPX process execution"
        severity = "high"
        category = "webshell"

    strings:
        $page = "<%@ Page" ascii nocase
        $input1 = "Request.Form[" ascii
        $input2 = "Request.QueryString[" ascii
        $exec1 = "Process.Start(" ascii
        $exec2 = "ProcessStartInfo(" ascii

    condition:
        filesize < 1MB and
        $page and
        any of ($input*) and
        any of ($exec*)
}
