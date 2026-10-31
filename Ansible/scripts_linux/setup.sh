#!/usr/bin/env bash
# F1.sh - interactive password-based Ansible deployment, run from Ansible/.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
export ANSIBLE_CONFIG="$PWD/ansible.cfg"
umask 077
secret_file=""
cleanup() { unset F1SH_PASSWORD || true; [[ -z "$secret_file" ]] || rm -f "$secret_file"; }
trap cleanup EXIT
[[ -f inventory.ini && -f install-scripts.yml && -d scripts_linux && -d ../AuditingScripts ]] || {
  echo 'ERROR: Expected complete IRSEC repository (Ansible and AuditingScripts folders).'; exit 1;
}
echo 'F1.sh - deployment-only controller setup'
read -r -p 'Are you on an authorized controller during permitted activity? Type YES: ' approval
[[ "$approval" == YES ]] || exit 1
if ! command -v ansible-playbook >/dev/null || ! command -v sshpass >/dev/null || ! python3 -c 'import winrm' 2>/dev/null; then
  read -r -p 'Install Ansible/SSH/WinRM controller dependencies with apt? (y/N): ' install
  [[ "$install" == y ]] || { echo 'Install prerequisites first.'; exit 1; }
  sudo apt-get update
  sudo apt-get install -y ansible sshpass python3-winrm openssh-client
fi
if ! ansible-galaxy collection list ansible.windows 2>/dev/null | grep -q 'ansible.windows'; then
  ansible-galaxy collection install ansible.windows
fi
read -r -p 'Linux SSH username: ' linux_user
read -r -p 'Windows WinRM username (DOMAIN\\user if necessary): ' windows_user
[[ -n "$linux_user" && -n "$windows_user" ]] || { echo 'Usernames required.'; exit 1; }
read -r -s -p 'Shared default password: ' F1SH_PASSWORD; echo
[[ -n "$F1SH_PASSWORD" ]] || { echo 'Password required.'; exit 1; }
export F1SH_PASSWORD
secret_file=$(mktemp "${TMPDIR:-/tmp}/f1sh-ansible-XXXXXXXX.json")
python3 - "$secret_file" "$linux_user" "$windows_user" <<'PY'
import json, os, sys
path, linux, windows = sys.argv[1:]
with open(path, 'w') as f:
    json.dump({'ansible_password': os.environ['F1SH_PASSWORD'],
               'f1sh_linux_user': linux, 'f1sh_windows_user': windows}, f)
os.chmod(path, 0o600)
PY
printf '\nDeployment targets: 1=pitlane  2=Linux  3=Windows  4=All  5=One host\n'
read -r -p 'Choose 1-5: ' choice
case "$choice" in
  1) limit=pitlane;; 2) limit=linux;; 3) limit=windows;; 4) limit='linux:windows';;
  5) read -r -p 'Hostname from inventory: ' limit
     case "$limit" in pitlane|garage|grandstand|scrutineering|pitwall|teamradio|safetycar|transporters|stewards) ;; *) echo 'Not an approved deployment host'; exit 1;; esac;;
  *) echo 'Invalid choice'; exit 1;;
esac
echo 'Connection tests (review failures):'
if [[ "$choice" == 2 || "$choice" == 4 || "$limit" =~ ^(pitlane|garage|grandstand|scrutineering)$ ]]; then
  ansible linux -m raw -a hostname -e "@$secret_file" --limit "$limit" || true
fi
if [[ "$choice" == 3 || "$choice" == 4 || "$limit" =~ ^(pitwall|teamradio|safetycar|transporters|stewards)$ ]]; then
  ansible windows -m ansible.windows.win_ping -e "@$secret_file" --limit "$limit" || true
fi
echo 'Files will be COPIED, not executed. Check failed connections above.'
read -r -p "Type DEPLOY to continue to $limit: " confirm
[[ "$confirm" == DEPLOY ]] || { echo 'Cancelled'; exit 0; }
ansible-playbook install-scripts.yml -e "@$secret_file" --limit "$limit"
