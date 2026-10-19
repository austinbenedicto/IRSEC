
rule IRSEC_Python_Reverse_Shell
{
    meta:
        description = "Python socket-based reverse shell indicators"
        severity = "high"
        category = "reverse_shell"

    strings:
        $socket1 = "socket.socket(" ascii
        $socket2 = "from socket import" ascii

        $connect1 = ".connect((" ascii
        $connect2 = ".connect_ex(" ascii

        $shell1 = "subprocess.Popen(" ascii
        $shell2 = "os.system(" ascii
        $shell3 = "pty.spawn(" ascii

        $redirect1 = "os.dup2(" ascii
        $redirect2 = "stdin=subprocess.PIPE" ascii

    condition:
        filesize < 1MB and
        any of ($socket*) and
        any of ($connect*) and
        any of ($shell*) and
        any of ($redirect*)
}
