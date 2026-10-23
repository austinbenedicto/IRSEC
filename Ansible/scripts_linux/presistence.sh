#!/usr/bin/bash

# ============================================================
# IRSeC Linux Blue Team - persistence.sh
#
# Compares current persistence mechanisms against the
# baseline created by inventorier.sh.
#
# READ ONLY - Does not modify the system.
# ============================================================

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] persistence.sh must be run as root"
    echo "    sudo ./persistence.sh"
    exit 1
fi

BASELINE="./baseline"
TEMP="/tmp/irsec_persistence"

FINDINGS=0

mkdir -p "$TEMP"

# Make sure baseline exists
if [ ! -d "$BASELINE" ]; then
    echo "[!] Baseline directory not found."
    echo "    Run inventorier.sh first."
    exit 1
fi


# ============================================================
# ALERT FUNCTION
# ============================================================

alert() {
    echo
    echo "[!] $1"
    FINDINGS=$((FINDINGS + 1))
}


# ============================================================
# HEADER
# ============================================================

echo "============================================================"
echo "          IRSeC LINUX PERSISTENCE SCANNER"
echo "============================================================"
echo "Host: $(hostname)"
echo "Time: $(date)"
echo


# ============================================================
# 1. ACCOUNT FILES
# ============================================================

echo -n "[*] Checking accounts.................... "

ACCOUNT_ALERT=0

for file in passwd group sudoers; do

    CURRENT_FILE="/etc/$file"
    BASE_FILE="$BASELINE/$file.sha256"

    if [ -f "$BASE_FILE" ] && [ -f "$CURRENT_FILE" ]; then

        CURRENT_HASH=$(sha256sum "$CURRENT_FILE" | awk '{print $1}')
        BASE_HASH=$(cat "$BASE_FILE")

        if [ "$CURRENT_HASH" != "$BASE_HASH" ]; then

            if [ "$ACCOUNT_ALERT" -eq 0 ]; then
                echo "ALERT"
                ACCOUNT_ALERT=1
            fi

            alert "$CURRENT_FILE CHANGED"

        fi

    fi

done

if [ "$ACCOUNT_ALERT" -eq 0 ]; then
    echo "OK"
fi


# ============================================================
# 2. SSH AUTHORIZED KEYS
# ============================================================

echo -n "[*] Checking SSH keys.................... "

find /root /home \
    -type f \
    -name "authorized_keys" \
    -exec sha256sum {} \; \
    2>/dev/null \
    | sort > "$TEMP/ssh_keys.txt"

if [ -f "$BASELINE/ssh_keys.txt" ]; then

    SSH_DIFF=$(diff "$BASELINE/ssh_keys.txt" \
                    "$TEMP/ssh_keys.txt")

    if [ -n "$SSH_DIFF" ]; then

        echo "ALERT"

        alert "SSH AUTHORIZED_KEYS CHANGED"

        echo "$SSH_DIFF"

    else

        echo "OK"

    fi

else
    echo "NO BASELINE"
fi


# ============================================================
# 3. SYSTEMD SERVICE FILES
# ============================================================

echo -n "[*] Checking systemd services............ "

find /etc/systemd/system \
    \( -type f -o -type l \) \
    -exec sha256sum {} \; \
    2>/dev/null \
    | sort > "$TEMP/systemd.txt"

if [ -f "$BASELINE/systemd.txt" ]; then

    SYSTEMD_DIFF=$(diff "$BASELINE/systemd.txt" \
                        "$TEMP/systemd.txt")

    if [ -n "$SYSTEMD_DIFF" ]; then

        echo "ALERT"

        alert "SYSTEMD CONFIGURATION CHANGED"

        echo "$SYSTEMD_DIFF"

    else

        echo "OK"

    fi

else
    echo "NO BASELINE"
fi


# ============================================================
# 4. SYSTEMD TIMERS
# ============================================================

echo -n "[*] Checking systemd timers.............. "

systemctl list-timers \
    --all \
    --no-legend \
    --no-pager \
    2>/dev/null \
    | awk '{print $NF}' \
    | sort > "$TEMP/timers.txt"

if [ -f "$BASELINE/timers.txt" ]; then

    NEW_TIMERS=$(comm -13 \
        "$BASELINE/timers.txt" \
        "$TEMP/timers.txt")

    if [ -n "$NEW_TIMERS" ]; then

        echo "ALERT"

        alert "NEW SYSTEMD TIMER"

        echo "$NEW_TIMERS"

    else

        echo "OK"

    fi

else
    echo "NO BASELINE"
fi


# ============================================================
# 5. SYSTEM CRON
# ============================================================

echo -n "[*] Checking system cron................. "

{
    [ -f /etc/crontab ] && sha256sum /etc/crontab

    find \
        /etc/cron.d \
        /etc/cron.hourly \
        /etc/cron.daily \
        /etc/cron.weekly \
        /etc/cron.monthly \
        -type f \
        -exec sha256sum {} \; \
        2>/dev/null

} | sort > "$TEMP/cron.txt"


if [ -f "$BASELINE/cron.txt" ]; then

    CRON_DIFF=$(diff \
        "$BASELINE/cron.txt" \
        "$TEMP/cron.txt")

    if [ -n "$CRON_DIFF" ]; then

        echo "ALERT"

        alert "SYSTEM CRON CHANGED"

        echo "$CRON_DIFF"

    else

        echo "OK"

    fi

else
    echo "NO BASELINE"
fi


# ============================================================
# 6. USER CRONTABS
# ============================================================

echo -n "[*] Checking user crontabs............... "

> "$TEMP/user_cron.txt"

while IFS=: read -r username _ uid _; do

    if [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; then

        CRON=$(crontab -u "$username" -l 2>/dev/null)

        if [ -n "$CRON" ]; then

            echo "### USER: $username" \
                >> "$TEMP/user_cron.txt"

            echo "$CRON" \
                >> "$TEMP/user_cron.txt"

        fi

    fi

done < /etc/passwd


if [ -f "$BASELINE/user_cron.txt" ]; then

    CRON_DIFF=$(diff \
        "$BASELINE/user_cron.txt" \
        "$TEMP/user_cron.txt")

    if [ -n "$CRON_DIFF" ]; then

        echo "ALERT"

        alert "USER CRONTAB CHANGED"

        echo "$CRON_DIFF"

    else

        echo "OK"

    fi

else
    echo "NO BASELINE"
fi


# ============================================================
# 7. SUID / SGID FILES
# ============================================================

echo -n "[*] Checking SUID/SGID files............. "

find / \
    -xdev \
    -type f \
    \( -perm -4000 -o -perm -2000 \) \
    2>/dev/null \
    | sort > "$TEMP/suid.txt"


if [ -f "$BASELINE/suid.txt" ]; then

    NEW_SUID=$(comm -13 \
        "$BASELINE/suid.txt" \
        "$TEMP/suid.txt")

    if [ -n "$NEW_SUID" ]; then

        echo "ALERT"

        alert "NEW SUID/SGID FILE"

        echo "$NEW_SUID"

    else

        echo "OK"

    fi

else
    echo "NO BASELINE"
fi


# ============================================================
# 8. SHELL STARTUP FILES
# ============================================================

echo -n "[*] Checking shell startup files......... "

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

} | sort > "$TEMP/startup.txt"


if [ -f "$BASELINE/startup.txt" ]; then

    STARTUP_DIFF=$(diff \
        "$BASELINE/startup.txt" \
        "$TEMP/startup.txt")

    if [ -n "$STARTUP_DIFF" ]; then

        echo "ALERT"

        alert "SHELL STARTUP FILE CHANGED"

        echo "$STARTUP_DIFF"

    else

        echo "OK"

    fi

else
    echo "NO BASELINE"
fi


# ============================================================
# 9. PROFILE.D
# ============================================================

echo -n "[*] Checking /etc/profile.d.............. "

find /etc/profile.d \
    -type f \
    -exec sha256sum {} \; \
    2>/dev/null \
    | sort > "$TEMP/profile_d.txt"


if [ -f "$BASELINE/profile_d.txt" ]; then

    PROFILE_DIFF=$(diff \
        "$BASELINE/profile_d.txt" \
        "$TEMP/profile_d.txt")

    if [ -n "$PROFILE_DIFF" ]; then

        echo "ALERT"

        alert "/etc/profile.d CHANGED"

        echo "$PROFILE_DIFF"

    else

        echo "OK"

    fi

else
    echo "NO BASELINE"
fi


# ============================================================
# 10. LD.SO.PRELOAD
# ============================================================

echo -n "[*] Checking ld.so.preload............... "

if [ -f /etc/ld.so.preload ]; then

    CURRENT_HASH=$(sha256sum /etc/ld.so.preload \
        | awk '{print $1}')

    if [ -f "$BASELINE/ld_preload.sha256" ]; then

        BASE_HASH=$(cat "$BASELINE/ld_preload.sha256")

        if [ "$CURRENT_HASH" != "$BASE_HASH" ]; then

            echo "ALERT"

            alert "/etc/ld.so.preload CHANGED"

            echo "Contents:"
            cat /etc/ld.so.preload

        else

            echo "OK"

        fi

    else

        echo "ALERT"

        alert "/etc/ld.so.preload NOW EXISTS"

        echo "Contents:"
        cat /etc/ld.so.preload

    fi

else

    if [ -f "$BASELINE/ld_preload.sha256" ]; then
        echo "ALERT"
        alert "/etc/ld.so.preload REMOVED"
    else
        echo "OK"
    fi

fi


# ============================================================
# SUMMARY
# ============================================================

echo
echo "============================================================"

if [ "$FINDINGS" -eq 0 ]; then

    echo "[+] No persistence changes detected."

else

    echo "[!] $FINDINGS potential persistence change(s) detected."
    echo "[!] Investigate before removing anything."

fi

echo "============================================================"

rm -rf "$TEMP"