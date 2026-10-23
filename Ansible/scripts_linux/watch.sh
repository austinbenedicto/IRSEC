#!/usr/bin/bash

# ==========================================
# IRSeC Linux Blue Team - watch.sh
#
# Takes a baseline when started and only
# alerts when something NEW appears.
# ==========================================

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run with sudo"
    exit 1
fi

INTERVAL=5
BASELINE="/tmp/irsec_watch"

mkdir -p "$BASELINE"

echo "[*] Creating initial baseline..."

# -------------------------------
# Baseline: Users
# -------------------------------

cut -d: -f1 /etc/passwd | sort > "$BASELINE/users"

# -------------------------------
# Baseline: Listening Ports
# -------------------------------

ss -lntupH 2>/dev/null | sort > "$BASELINE/ports"

# -------------------------------
# Baseline: Services
# -------------------------------

systemctl list-units \
    --type=service \
    --state=running \
    --no-legend \
    --no-pager 2>/dev/null \
    | awk '{print $1}' \
    | sort > "$BASELINE/services"

echo "[+] Baseline complete."
echo "[*] Watching system every ${INTERVAL} seconds..."
echo "[*] You will only see output when something NEW appears."
echo ""

while true; do

    # ==========================================
    # USERS
    # ==========================================

    cut -d: -f1 /etc/passwd | sort > "$BASELINE/users.current"

    NEW_USERS=$(comm -13 \
        "$BASELINE/users" \
        "$BASELINE/users.current")

    if [[ -n "$NEW_USERS" ]]; then

        echo "========================================"
        echo "[!] NEW USER DETECTED - $(date)"
        echo "========================================"

        while read -r user; do
            [[ -z "$user" ]] && continue

            echo ""
            echo "User: $user"

            getent passwd "$user"

            echo "Groups:"
            groups "$user" 2>/dev/null

        done <<< "$NEW_USERS"

        echo ""

        cp "$BASELINE/users.current" "$BASELINE/users"
    fi


    # ==========================================
    # LISTENING PORTS
    # ==========================================

    ss -lntupH 2>/dev/null \
        | sort > "$BASELINE/ports.current"

    NEW_PORTS=$(comm -13 \
        "$BASELINE/ports" \
        "$BASELINE/ports.current")

    if [[ -n "$NEW_PORTS" ]]; then

        echo "========================================"
        echo "[!] NEW LISTENING PORT - $(date)"
        echo "========================================"

        echo "$NEW_PORTS"

        echo ""

        cp "$BASELINE/ports.current" "$BASELINE/ports"
    fi


    # ==========================================
    # SERVICES
    # ==========================================

    systemctl list-units \
        --type=service \
        --state=running \
        --no-legend \
        --no-pager 2>/dev/null \
        | awk '{print $1}' \
        | sort > "$BASELINE/services.current"

    NEW_SERVICES=$(comm -13 \
        "$BASELINE/services" \
        "$BASELINE/services.current")

    if [[ -n "$NEW_SERVICES" ]]; then

        echo "========================================"
        echo "[!] NEW RUNNING SERVICE - $(date)"
        echo "========================================"

        while read -r service; do
            [[ -z "$service" ]] && continue

            echo ""
            echo "Service: $service"

            systemctl status "$service" \
                --no-pager \
                --lines=3 2>/dev/null

        done <<< "$NEW_SERVICES"

        echo ""

        cp "$BASELINE/services.current" "$BASELINE/services"
    fi


    sleep "$INTERVAL"

done