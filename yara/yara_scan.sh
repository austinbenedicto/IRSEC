
#!/usr/bin/env bash

:'
Scan a specified directory using every .yar rule.

Display matching rule names and filenames.

Apply a per-rule scan timeout.

Continue through other rules if one scan fails.

Return a nonzero exit code if a scan fails.
'

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RULE_DIR="$SCRIPT_DIR/../yara/rules"
TARGET="${1:-/var/www}"
TIMEOUT_SECONDS=120

if ! command -v yara >/dev/null 2>&1; then
    echo "[ERROR] YARA is not installed."
    exit 1
fi

if [[ ! -d "$RULE_DIR" ]]; then
    echo "[ERROR] Rules directory missing: $RULE_DIR"
    exit 1
fi

if [[ ! -d "$TARGET" ]]; then
    echo "[ERROR] Target directory missing: $TARGET"
    exit 1
fi

shopt -s nullglob
rules=()
declare -A seen_rules=()
for candidate in "$RULE_DIR"/*.yar "$RULE_DIR"/*,yar; do
    [[ -e "$candidate" ]] || continue
    if [[ -z "${seen_rules[$candidate]+x}" ]]; then
        seen_rules["$candidate"]=1
        rules+=("$candidate")
    fi
done

if (( ${#rules[@]} == 0 )); then
    echo "[ERROR] No YARA rules found."
    exit 1
fi

echo "===================================="
echo " IRSEC BLUE TEAM - YARA SCANNER"
echo "===================================="
echo "Host: $(hostname)"
echo "Target: $TARGET"
echo "Rules: ${#rules[@]}"
echo "Time: $(date -u +%FT%TZ)"
echo

failed=0

for rule in "${rules[@]}"; do
    echo "[INFO] Running $(basename "$rule")"

    if yara -r -t "$TIMEOUT_SECONDS" \
        "$rule" "$TARGET"; then
        echo "[INFO] Rule scan completed"
    else
        echo "[ERROR] Scan failed or timed out"
        failed=1
    fi
done

echo
echo "[INFO] All rule scans attempted"
exit "$failed"
