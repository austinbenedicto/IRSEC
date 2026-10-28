#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ $(id -u) -eq 0 ]]; then echo 'Run as a normal user with sudo access, not root.' >&2; exit 1; fi
for path in inventory.ini install-scripts.yml scripts_linux ../yara/rules '../Auditing Scripts' '../Fixer Scripts'; do
  [[ -e "$path" ]] || { echo "Missing repo path: $path" >&2; exit 1; }
done
if ! command -v apt-get >/dev/null; then echo 'This bootstrap currently supports Debian/Ubuntu controllers only.' >&2; exit 1; fi
printf 'This will install Ansible and dependencies ON THIS CONTROLLER, then copy tools to authorized hosts.\n'
read -r -p 'Continue? [y/N] ' proceed
[[ "$proceed" =~ ^[Yy]$ ]] || exit 0
sudo apt-get update
sudo apt-get install -y ansible rsync sshpass python3 python3-winrm
ansible-galaxy collection install ansible.posix ansible.windows
read -r -p 'Shared Linux SSH administrator username: ' linux_user
read -r -p 'Shared Windows administrator username (e.g. .\Administrator): ' windows_user
[[ -n "$linux_user" && -n "$windows_user" ]] || { echo 'Both usernames required.' >&2; exit 1; }
read -r -s -p 'Shared password (not stored in Git): ' shared_password; printf '\n'
[[ -n "$shared_password" ]] || { echo 'Password required.' >&2; exit 1; }
# YAML supports JSON syntax; write values safely without shell interpolation.
creds=$(mktemp /tmp/irsec-ansible-credentials.XXXXXX.json)
chmod 600 "$creds"
cleanup() { rm -f -- "$creds"; unset shared_password; }
trap cleanup EXIT
export IRSEC_LINUX_USER="$linux_user" IRSEC_WINDOWS_USER="$windows_user" IRSEC_PASSWORD="$shared_password"
python3 - "$creds" <<'PYINNER'
import json,os,sys
with open(sys.argv[1], 'w') as f:
 json.dump({'linux_user':os.environ['IRSEC_LINUX_USER'], 'windows_user':os.environ['IRSEC_WINDOWS_USER'], 'shared_password':os.environ['IRSEC_PASSWORD']},f)
PYINNER
unset IRSEC_PASSWORD shared_password
# Pass per-group usernames and passwords via inventory variables, loaded at runtime.
# No password is written to the repo. Runtime file removed on exit.
# Generate separate group vars in the temporary extra-vars file.
python3 - "$creds" <<'PYINNER'
import json,sys
p=sys.argv[1]
d=json.load(open(p))
# Per-host credentials from group membership, without secrets in repository.
# Ansible group vars can be selected using group_names in play context.
d.update({'ansible_user': "{{ linux_user if 'linux' in group_names else windows_user }}",'ansible_password':'{{ shared_password }}'})
with open(p,'w') as f: json.dump(d,f)
PYINNER
printf '\nChecking syntax...\n'
ansible-playbook install-scripts.yml --syntax-check
printf '\nChoose targets: 1) one Linux host (pitlane) 2) all Linux 3) all Windows 4) all supported (Linux + Windows)\n'
read -r -p 'Choice [1]: ' choice
case "${choice:-1}" in
  1) limit='pitlane' ;;
  2) limit='linux' ;;
  3) limit='windows' ;;
  4) limit='linux:windows' ;;
  *) echo 'Invalid choice.' >&2; exit 1 ;;
esac
printf 'Deploying to %s. Files will be COPIED, not executed.\n' "$limit"
ansible-playbook install-scripts.yml --limit "$limit" --extra-vars "@$creds"
