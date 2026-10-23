
#!/usr/bin/env bash

set -euo pipefail

BACKUP_DIR="/var/backups/irsec"
TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)

usage() {
    echo "IRSEC Blue Team - Backup Utility"
    echo
    echo "Usage:"
    echo "  $0 backup <file_or_directory>"
    echo "  $0 list"
    echo "  $0 verify <backup_name>"
    echo "  $0 restore <backup_name> <destination>"
    exit 1
}

init_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
}

backup_file() {
    local source="$1"
    local name archive

    if [[ ! -e "$source" ]]; then
        echo "[ERROR] Source does not exist: $source"
        exit 1
    fi

    init_backup_dir

    name=$(basename "$source")
    archive="${name}_${TIMESTAMP}_$$.tar.gz"

    echo "[INFO] Backing up: $source"

    tar -czpf "$BACKUP_DIR/$archive" \
        -C "$(dirname "$source")" \
        "$(basename "$source")"

    sha256sum "$BACKUP_DIR/$archive" \
        > "$BACKUP_DIR/$archive.sha256"

    chmod 600 "$BACKUP_DIR/$archive" \
        "$BACKUP_DIR/$archive.sha256"

    echo "[PASS] Backup created:"
    echo "$BACKUP_DIR/$archive"
}

list_backups() {
    init_backup_dir
    echo "[INFO] Available backups:"
    find "$BACKUP_DIR" -maxdepth 1 \
        -type f -name '*.tar.gz' -print
}

verify_backup() {
    local archive="$1"
    local filename

    filename=$(basename "$archive")

    if [[ ! -f "$BACKUP_DIR/$filename.sha256" ]]; then
        echo "[ERROR] Checksum file missing"
        exit 1
    fi

    (
        cd "$BACKUP_DIR"
        sha256sum -c "$filename.sha256"
    )

    tar -tzf "$BACKUP_DIR/$filename" > /dev/null

    echo "[PASS] Backup verified"
}

restore_backup() {
    local archive="$1"
    local destination="$2"
    local filename

    filename=$(basename "$archive")

    verify_backup "$filename"

    if [[ ! -d "$destination" ]]; then
        echo "[ERROR] Destination must be an existing directory"
        exit 1
    fi

    echo "[WARN] Restore may overwrite existing files"
    echo "Archive: $filename"
    echo "Destination: $destination"

    read -r -p "Type RESTORE to continue: " confirm

    if [[ "$confirm" != "RESTORE" ]]; then
        echo "[INFO] Restore cancelled"
        exit 0
    fi

    tar -xzpf "$BACKUP_DIR/$filename" \
        -C "$destination" \
        --no-same-owner

    echo "[PASS] Restore completed"
}

if [[ $# -lt 1 ]]; then
    usage
fi

case "$1" in
    backup)
        [[ $# -eq 2 ]] || usage
        backup_file "$2"
        ;;
    list)
        [[ $# -eq 1 ]] || usage
        list_backups
        ;;
    verify)
        [[ $# -eq 2 ]] || usage
        verify_backup "$2"
        ;;
    restore)
        [[ $# -eq 3 ]] || usage
        restore_backup "$2" "$3"
        ;;
    *)
        usage
        ;;
esac
