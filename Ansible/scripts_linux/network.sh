#!/usr/bin/bash

# ============================================================
# IRSeC Linux Blue Team - network.sh
#
# Purpose:
#   Investigate network activity on a Linux system.
#
# READ ONLY - This script does not modify firewall rules,
# processes, interfaces, or connections.
# ============================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] network.sh must be run as root"
    echo "    sudo ./network.sh"
    exit 1
fi


# ============================================================
# PAUSE
# ============================================================

pause() {
    echo
    read -rp "Press ENTER to continue..."
}


# ============================================================
# LISTENING PORTS
# ============================================================

listening_ports() {

    clear

    echo "============================================================"
    echo "                    LISTENING PORTS"
    echo "============================================================"
    echo

    ss -lntup

    pause
}


# ============================================================
# ESTABLISHED CONNECTIONS
# ============================================================

established_connections() {

    clear

    echo "============================================================"
    echo "                ESTABLISHED CONNECTIONS"
    echo "============================================================"
    echo

    ss -tnp state established

    pause
}


# ============================================================
# ALL NETWORK CONNECTIONS
# ============================================================

all_connections() {

    clear

    echo "============================================================"
    echo "                  ALL NETWORK SOCKETS"
    echo "============================================================"
    echo

    ss -tunap

    pause
}


# ============================================================
# ROUTING TABLE
# ============================================================

routing_table() {

    clear

    echo "============================================================"
    echo "                     ROUTING TABLE"
    echo "============================================================"
    echo

    ip route

    pause
}


# ============================================================
# ARP / NEIGHBOR TABLE
# ============================================================

neighbor_table() {

    clear

    echo "============================================================"
    echo "                  ARP / NEIGHBOR TABLE"
    echo "============================================================"
    echo

    ip neigh

    pause
}


# ============================================================
# NETWORK INTERFACES
# ============================================================

interfaces() {

    clear

    echo "============================================================"
    echo "                  NETWORK INTERFACES"
    echo "============================================================"
    echo

    ip -brief addr

    pause
}


# ============================================================
# DNS CONFIGURATION
# ============================================================

dns_config() {

    clear

    echo "============================================================"
    echo "                    DNS CONFIGURATION"
    echo "============================================================"
    echo

    echo "--- /etc/resolv.conf ---"
    echo

    cat /etc/resolv.conf 2>/dev/null

    echo

    if command -v resolvectl >/dev/null 2>&1; then

        echo "--- systemd-resolved ---"
        echo

        resolvectl status 2>/dev/null

    fi

    pause
}


# ============================================================
# FIREWALL
# ============================================================

firewall() {

    clear

    echo "============================================================"
    echo "                     FIREWALL RULES"
    echo "============================================================"
    echo

    if command -v nft >/dev/null 2>&1; then

        echo "================ NFTABLES ================"
        echo

        nft list ruleset 2>/dev/null

        echo

    fi


    if command -v iptables >/dev/null 2>&1; then

        echo "================ IPTABLES ================"
        echo

        iptables -L -n -v 2>/dev/null

        echo

    fi


    if command -v ufw >/dev/null 2>&1; then

        echo "================ UFW ================"
        echo

        ufw status verbose 2>/dev/null

    fi

    pause
}


# ============================================================
# INVESTIGATE PORT
# ============================================================

investigate_port() {

    clear

    echo "============================================================"
    echo "                   INVESTIGATE PORT"
    echo "============================================================"
    echo

    read -rp "Enter port number: " PORT

    # Make sure input is numeric
    if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
        echo
        echo "[!] Invalid port."
        pause
        return
    fi

    # Make sure valid TCP/UDP port
    if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        echo
        echo "[!] Port must be between 1 and 65535."
        pause
        return
    fi


    echo
    echo "================ SOCKET INFORMATION ================"
    echo

    SOCKET_INFO=$(ss -tunap 2>/dev/null | \
        awk -v port="$PORT" '
        $5 ~ ":" port "$" || $6 ~ ":" port "$"
        ')

    if [ -z "$SOCKET_INFO" ]; then

        echo "[-] No current socket found using port $PORT."

        pause
        return

    fi

    echo "$SOCKET_INFO"


    # ========================================================
    # Extract PIDs
    # ========================================================

    PIDS=$(echo "$SOCKET_INFO" | \
        grep -oE 'pid=[0-9]+' | \
        cut -d= -f2 | \
        sort -u)


    if [ -z "$PIDS" ]; then

        echo
        echo "[-] No PID information available."

        pause
        return

    fi


    # ========================================================
    # Investigate every PID associated with port
    # ========================================================

    for PID in $PIDS; do

        echo
        echo "============================================================"
        echo "                    PROCESS PID $PID"
        echo "============================================================"


        echo
        echo "--- Process ---"
        ps -fp "$PID"


        echo
        echo "--- Command Line ---"

        if [ -r "/proc/$PID/cmdline" ]; then

            tr '\0' ' ' < "/proc/$PID/cmdline"
            echo

        else

            echo "Unable to read command line."

        fi


        echo
        echo "--- Executable ---"

        if [ -e "/proc/$PID/exe" ]; then

            readlink -f "/proc/$PID/exe"

        else

            echo "Executable unavailable."

        fi


        echo
        echo "--- Working Directory ---"

        if [ -e "/proc/$PID/cwd" ]; then

            readlink -f "/proc/$PID/cwd"

        else

            echo "Working directory unavailable."

        fi


        echo
        echo "--- Parent Process ---"

        PPID_VALUE=$(ps -o ppid= -p "$PID" | tr -d ' ')

        if [ -n "$PPID_VALUE" ]; then
            ps -fp "$PPID_VALUE"
        fi


        echo
        echo "--- Process Tree ---"

        if command -v pstree >/dev/null 2>&1; then
            pstree -sp "$PID"
        else
            echo "pstree not installed."
        fi


        echo
        echo "--- Network Connections ---"

        ss -tunap 2>/dev/null | \
            grep -E "pid=$PID([,)]|$)"


        # ====================================================
        # Open Files
        # ====================================================

        echo
        echo "--- Open Files ---"

        if command -v lsof >/dev/null 2>&1; then

            lsof -p "$PID" 2>/dev/null | head -30

        else

            echo "lsof not installed."

        fi


        # ====================================================
        # Executable hash
        # ====================================================

        echo
        echo "--- Executable SHA256 ---"

        EXE=$(readlink -f "/proc/$PID/exe" 2>/dev/null)

        if [ -n "$EXE" ] && [ -f "$EXE" ]; then

            sha256sum "$EXE"

        else

            echo "Unable to hash executable."

        fi


        # ====================================================
        # Process start time
        # ====================================================

        echo
        echo "--- Process Start Time ---"

        ps -p "$PID" \
            -o lstart= \
            2>/dev/null


        # ====================================================
        # Process owner
        # ====================================================

        echo
        echo "--- Process Owner ---"

        ps -p "$PID" \
            -o user= \
            2>/dev/null


    done

    pause
}


# ============================================================
# INVESTIGATE PID
# ============================================================

investigate_pid() {

    clear

    echo "============================================================"
    echo "                    INVESTIGATE PID"
    echo "============================================================"
    echo

    read -rp "Enter PID: " PID

    if ! [[ "$PID" =~ ^[0-9]+$ ]]; then

        echo
        echo "[!] Invalid PID."

        pause
        return

    fi


    if [ ! -d "/proc/$PID" ]; then

        echo
        echo "[!] PID $PID does not exist."

        pause
        return

    fi


    echo
    echo "================ PROCESS ================="
    echo

    ps -fp "$PID"


    echo
    echo "================ COMMAND ================="
    echo

    tr '\0' ' ' < "/proc/$PID/cmdline"
    echo


    echo
    echo "================ EXECUTABLE ================="
    echo

    readlink -f "/proc/$PID/exe"


    echo
    echo "================ WORKING DIRECTORY ================="
    echo

    readlink -f "/proc/$PID/cwd"


    echo
    echo "================ NETWORK ================="
    echo

    ss -tunap 2>/dev/null | \
        grep -E "pid=$PID([,)]|$)"


    echo
    echo "================ PROCESS TREE ================="
    echo

    if command -v pstree >/dev/null 2>&1; then
        pstree -sp "$PID"
    else
        echo "pstree not installed."
    fi


    echo
    echo "================ HASH ================="
    echo

    EXE=$(readlink -f "/proc/$PID/exe" 2>/dev/null)

    if [ -n "$EXE" ] && [ -f "$EXE" ]; then
        sha256sum "$EXE"
    else
        echo "Unable to hash executable."
    fi


    pause
}


# ============================================================
# CONNECTION SUMMARY
# ============================================================

connection_summary() {

    clear

    echo "============================================================"
    echo "                   NETWORK SUMMARY"
    echo "============================================================"
    echo


    echo "Listening TCP sockets:"
    ss -lntH 2>/dev/null | wc -l


    echo "Listening UDP sockets:"
    ss -lnuH 2>/dev/null | wc -l


    echo "Established TCP connections:"
    ss -tnH state established 2>/dev/null | wc -l


    echo
    echo "================ LISTENING PORTS ================"
    echo

    ss -lntup


    echo
    echo "================ ESTABLISHED CONNECTIONS ================"
    echo

    ss -tnp state established


    pause
}


# ============================================================
# MAIN MENU
# ============================================================

while true; do

    clear

    echo "============================================================"
    echo "            IRSeC NETWORK INVESTIGATION"
    echo "============================================================"
    echo
    echo "  1) Network Summary"
    echo "  2) Listening Ports"
    echo "  3) Established Connections"
    echo "  4) All Network Sockets"
    echo
    echo "  5) Investigate Port"
    echo "  6) Investigate PID"
    echo
    echo "  7) Network Interfaces"
    echo "  8) Routing Table"
    echo "  9) ARP / Neighbor Table"
    echo " 10) DNS Configuration"
    echo " 11) Firewall Rules"
    echo
    echo "  0) Exit"
    echo
    echo "============================================================"
    echo

    read -rp "Select option: " CHOICE

    case "$CHOICE" in

        1)
            connection_summary
            ;;

        2)
            listening_ports
            ;;

        3)
            established_connections
            ;;

        4)
            all_connections
            ;;

        5)
            investigate_port
            ;;

        6)
            investigate_pid
            ;;

        7)
            interfaces
            ;;

        8)
            routing_table
            ;;

        9)
            neighbor_table
            ;;

        10)
            dns_config
            ;;

        11)
            firewall
            ;;

        0)
            clear
            echo "[+] Exiting network investigation."
            exit 0
            ;;

        *)
            echo
            echo "[!] Invalid selection."
            sleep 1
            ;;

    esac

done