#!/usr/bin/env bash
# IRSEC SCRIPT LAUNCHER
# ---------------------
# Displays Bash scripts in a numbered terminal menu and lets an operator
# choose which one to run locally. Scripts are NOT executed automatically.
#
# Usage:
#   bash script-menu.sh                    # Search the launcher's directory
#   bash script-menu.sh /path/to/scripts   # Search a specified directory
#
# The menu looks only for .sh files immediately inside the chosen directory.
# It does not search subdirectories or run scripts on remote hosts.

# Treat references to unset variables as errors, helping catch typos.
set -u

# Find the directory containing this launcher, even when started elsewhere.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# Use the first command-line argument as the scripts directory, if provided.
# Otherwise, default to the directory containing this launcher.
TARGET_DIR="${1:-$SCRIPT_DIR}"

# Stop early if the selected scripts directory does not exist.
if [[ ! -d "$TARGET_DIR" ]]; then
  printf 'Directory not found: %s\n' "$TARGET_DIR" >&2
  exit 1
fi

# Convert the directory to an absolute path for reliable execution.
TARGET_DIR="$(cd -- "$TARGET_DIR" && pwd -P)"

# Keep displaying the menu until the operator chooses to quit.
while true; do
  # Rebuild the list each time so newly added/removed scripts are reflected.
  scripts=()

  # Read filenames safely, including those containing spaces.
  # find searches only the chosen directory, and sort makes numbering stable.
  while IFS= read -r -d '' file; do
    # Exclude this launcher itself to avoid launching another menu.
    [[ "$(realpath -- "$file")" == "$(realpath -- "${BASH_SOURCE[0]}")" ]] && continue
    scripts+=("$file")
  done < <(find "$TARGET_DIR" -maxdepth 1 -type f -name '*.sh' -print0 | sort -z)

  # Display the available scripts with zero-based menu numbers.
  printf '\n========== IRSEC SCRIPT LAUNCHER ==========\n'
  if ((${#scripts[@]} == 0)); then
    printf 'No .sh scripts found in %s\n' "$TARGET_DIR"
    exit 0
  fi
  for i in "${!scripts[@]}"; do
    printf '  [%d] %s\n' "$i" "${scripts[$i]##*/}"
  done
  printf '\n  [q] Quit\n\n'

  # Read a menu selection; EOF (Ctrl+D) exits cleanly.
  read -r -p 'Select script: ' choice || exit 0
  [[ "$choice" == q || "$choice" == Q ]] && exit 0

  # Accept only a number that corresponds to an available script.
  # The 10# prefix ensures leading zeros are treated as decimal, not octal.
  if [[ ! "$choice" =~ ^[0-9]+$ ]] || ((10#$choice >= ${#scripts[@]})); then
    printf 'Invalid selection.\n' >&2
    continue
  fi

  # Translate the selected number into the matching script path.
  selected="${scripts[10#$choice]}"
  printf '\nSelected: %s\n' "$selected"

  # Require explicit confirmation to prevent accidental execution.
  read -r -p 'Run this script with bash? [y/N]: ' confirm || exit 0
  if [[ "$confirm" != y && "$confirm" != Y ]]; then
    printf 'Cancelled.\n'
    continue
  fi

  # Execute the selected script on THIS machine with the current user's
  # permissions. Changing into TARGET_DIR helps scripts using relative paths.
  printf '\n--- Running %s ---\n' "${selected##*/}"
  (cd -- "$TARGET_DIR" && bash -- "$selected")

  # Show the script's exit code: 0 typically means success; nonzero means
  # the script reported an error. Then return to the menu after Enter.
  status=$?
  printf '\n--- Exit status: %d ---\n' "$status"
  read -r -p 'Press Enter to return to menu...' _ || exit 0
done
