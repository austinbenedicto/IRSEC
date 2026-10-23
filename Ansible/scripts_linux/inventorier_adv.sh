#!/usr/bin/bash

# ============================================================
# IRSeC Linux Blue Team - inventorier.sh
#
# 1. Displays useful system inventory information
# 2. Creates baseline files for watch.sh
# 3. Creates persistence baselines for persistence.sh
#
# IMPORTANT:
# The baseline represents the state of the machine when this
# script was run. It does NOT mean everything is trusted.
# ============================================================


# ============================================================
# ROOT CHECK
# ============================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] inventory.sh must be run as root"
    echo "    sudo ./inventorier.sh"
    exit 1
fi


# ============================================================
# BASELINE LOCATION
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASELINE="$SCRIPT_DIR/baseline"

mkdir -p "$BASELINE"


echo "============================================================"
echo "                  SYSTEM INVENTORY"
echo "============================================================"


# ============================================================
# OS / VERSION / HOSTNAME
# ============================================================

echo
echo -n "OS: "
grep '^NAME=' /etc/os-release | cut -d= -f2 | tr -d '"'

echo -n "Version: "
grep '^VERSION=' /etc/os-release | cut -d= -f2 | tr -d '"'

echo -n "Hostname: "
hostname


# ============================================================
# IP / MAC
# ============================================================

echo
echo "Network Information"

echo -n "IP Address: "

ip -4 -brief addr show scope global \
    | awk '{print $3}' \
    | cut -d/ -f1 \
    | tr '\n' ' '

echo

echo -n "MAC Address: "

ip -brief link \
    | awk '{print $3}' \
    | grep -v "00:00:00:00:00:00" \
    | tr '\n' ' '

echo


# ============================================================
# ADMIN USERS
# ============================================================

echo
echo -n "Admin Users: "

for group in sudo admin wheel; do

    if getent group "$group" > /dev/null; then

        getent group "$group" \
            | cut -d: -f4 \
            | tr ',' ' '

    fi

done

echo


# ============================================================
# LOGIN USERS
# ============================================================

echo
echo "All Users with Login Shell:"

while IFS=':' read -r username pass uid gid gecos homedir loginshell; do

    if { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } \
        && [ "$username" != "nobody" ] \
        && [[ ! "$loginshell" =~ (nologin|false)$ ]]; then

        echo "  - $username"

    fi

done < /etc/passwd


# ============================================================
# OPEN PORTS
# ============================================================

echo
echo "Open Ports:"

ss -lntupH 2>/dev/null \
    | awk '{print $5}' \
    | grep -oE '[0-9]+$' \
    | sort -nu \
    | while read -r port; do

        echo "  - Port: $port"

    done


# ============================================================
#
#                CREATE BASELINE
#
# ============================================================

echo
echo "============================================================"
echo "                 CREATING BASELINE"
echo "============================================================"


# ============================================================
# BASELINE METADATA
# ============================================================

{
    echo "Hostname: $(hostname)"
    echo "Created: $(date)"
    echo "Kernel: $(uname -r)"

} > "$BASELINE/info.txt"


# ============================================================
# USERS
# Used by watch.sh
# ============================================================

cut -d: -f1 /etc/passwd \
    | sort \
    > "$BASELINE/users.txt"

echo "[+] users.txt"


# ============================================================
# ADMIN GROUPS
# ============================================================

{
    getent group sudo 2>/dev/null
    getent group wheel 2>/dev/null
    getent group admin 2>/dev/null

} | sort > "$BASELINE/admins.txt"

echo "[+] admins.txt"


# ============================================================
# LISTENING PORTS
# Used by watch.sh
# ============================================================

ss -lntupH 2>/dev/null \
    | sort \
    > "$BASELINE/ports.txt"

echo "[+] ports.txt"


# ============================================================
# RUNNING SERVICES
# Used by watch.sh
# ============================================================

systemctl list-units \
    --type=service \
    --state=running \
    --no-legend \
    --no-pager \
    2>/dev/null \
    | awk '{print $1}' \
    | sort \
    > "$BASELINE/services.txt"

echo "[+] services.txt"


# ============================================================
# IMPORTANT ACCOUNT FILE HASHES
# Used by persistence.sh
# ============================================================

sha256sum /etc/passwd \
    | awk '{print $1}' \
    > "$BASELINE/passwd.sha256"

sha256sum /etc/group \
    | awk '{print $1}' \
    > "$BASELINE/group.sha256"

if [ -f /etc/sudoers ]; then

    sha256sum /etc/sudoers \
        | awk '{print $1}' \
        > "$BASELINE/sudoers.sha256"

fi

echo "[+] account hashes"


# ============================================================
# SUDOERS.D
# ============================================================

find /etc/sudoers.d \
    -type f \
    -exec sha256sum {} \; \
    2>/dev/null \
    | sort \
    > "$BASELINE/sudoers_d.txt"

echo "[+] sudoers_d.txt"


# ============================================================
# SSH AUTHORIZED KEYS
# Used by persistence.sh
# ============================================================

find /root /home \
    -type f \
    -name "authorized_keys" \
    -exec sha256sum {} \; \
    2>/dev/null \
    | sort \
    > "$BASELINE/ssh_keys.txt"

echo "[+] ssh_keys.txt"


# ============================================================
# SYSTEMD SERVICE FILES
# Used by persistence.sh
# ============================================================

find /etc/systemd/system \
    \( -type f -o -type l \) \
    -exec sha256sum {} \; \
    2>/dev/null \
    | sort \
    > "$BASELINE/systemd.txt"

echo "[+] systemd.txt"


# ============================================================
# SYSTEMD TIMERS
# ============================================================

systemctl list-timers \
    --all \
    --no-legend \
    --no-pager \
    2>/dev/null \
    | awk '{print $NF}' \
    | sort \
    > "$BASELINE/timers.txt"

echo "[+] timers.txt"


# ============================================================
# SYSTEM CRON
# ============================================================

{
    if [ -f /etc/crontab ]; then
        sha256sum /etc/crontab
    fi

    find \
        /etc/cron.d \
        /etc/cron.hourly \
        /etc/cron.daily \
        /etc/cron.weekly \
        /etc/cron.monthly \
        -type f \
        -exec sha256sum {} \; \
        2>/dev/null

} | sort > "$BASELINE/cron.txt"

echo "[+] cron.txt"


# ============================================================
# USER CRONTABS
# ============================================================

> "$BASELINE/user_cron.txt"

while IFS=: read -r username _ uid _; do

    if [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; then

        USER_CRON=$(crontab -u "$username" -l 2>/dev/null)

        if [ -n "$USER_CRON" ]; then

            echo "### USER: $username" \
                >> "$BASELINE/user_cron.txt"

            echo "$USER_CRON" \
                >> "$BASELINE/user_cron.txt"

        fi

    fi

done < /etc/passwd

echo "[+] user_cron.txt"


# ============================================================
# SUID / SGID FILES
# ============================================================

echo "[*] Scanning SUID/SGID files..."

find / \
    -xdev \
    -type f \
    \( -perm -4000 -o -perm -2000 \) \
    2>/dev/null \
    | sort \
    > "$BASELINE/suid.txt"

echo "[+] suid.txt"


# ============================================================
# SHELL STARTUP FILES
# ============================================================

{
    for file in \
        /etc/profile \
        /etc/bash.bashrc \
        /etc/bashrc \
        /root/.bashrc \
        /root/.profile
    do

        if [ -f "$file" ]; then
            sha256sum "$file"
        fi

    done


    find /home \
        -maxdepth 2 \
        -type f \
        \( -name ".bashrc" \
        -o -name ".profile" \
        -o -name ".bash_profile" \) \
        -exec sha256sum {} \; \
        2>/dev/null

} | sort > "$BASELINE/startup.txt"

echo "[+] startup.txt"


# ============================================================
# PROFILE.D
# ============================================================

find /etc/profile.d \
    -type f \
    -exec sha256sum {} \; \
    2>/dev/null \
    | sort \
    > "$BASELINE/profile_d.txt"

echo "[+] profile_d.txt"


# ============================================================
# LD.SO.PRELOAD
# ============================================================

if [ -f /etc/ld.so.preload ]; then

    sha256sum /etc/ld.so.preload \
        | awk '{print $1}' \
        > "$BASELINE/ld_preload.sha256"

fi

echo "[+] ld.so.preload baseline"


# ============================================================
# APACHE CONFIGURATION
# ============================================================

if [ -d /etc/apache2 ]; then

    find /etc/apache2 \
        -type f \
        -exec sha256sum {} \; \
        2>/dev/null \
        | sort \
        > "$BASELINE/apache.txt"

    echo "[+] apache.txt"

fi


# ============================================================
# NGINX CONFIGURATION
# ============================================================

if [ -d /etc/nginx ]; then

    find /etc/nginx \
        -type f \
        -exec sha256sum {} \; \
        2>/dev/null \
        | sort \
        > "$BASELINE/nginx.txt"

    echo "[+] nginx.txt"

fi


# ============================================================
# WEB ROOT
# ============================================================

if [ -d /var/www ]; then

    find /var/www \
        -type f \
        -exec sha256sum {} \; \
        2>/dev/null \
        | sort \
        > "$BASELINE/web.txt"

    echo "[+] web.txt"

fi


# ============================================================
# COMPLETE
# ============================================================

echo
echo "============================================================"
echo "                 BASELINE COMPLETE"
echo "============================================================"

echo
echo "Baseline directory:"
echo "    $BASELINE"

echo
echo "IMPORTANT:"
echo "This baseline represents the machine as it exists NOW."
echo "It does NOT guarantee that the current system is clean."

echo
echo "You can now run:"
echo "    sudo ./watch.sh"
echo "    sudo ./persistence.sh"

echo