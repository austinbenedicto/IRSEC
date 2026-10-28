# IRSEC Team 5 — deployment-only Ansible

## Repo paths
Replace `Ansible/install-scripts.yml`. Add `Ansible/inventory.ini`, `Ansible/ansible.cfg`, and `Ansible/setup.sh`. Existing `Ansible/scripts_linux/`, `yara/rules/`, `Auditing Scripts/`, and `Fixer Scripts/` remain unchanged. No Windows scripts are executed.

## Use
On an approved in-scope Debian/Ubuntu Linux controller, place/clone the entire IRSEC repo locally, then run:

```bash
cd IRSEC/Ansible
bash setup.sh
```

The setup script asks for the shared password and separate Linux/Windows usernames. It never saves the password to the repo. Windows hosts must have WinRM enabled, an authorized account, and a reachable port; `teamradio` is the only host whose scored service is WinRM. Do **not** enable WinRM or change services solely to make deployment work without permission. Windows Ansible modules use PowerShell internally. SSH/rsync is required for Linux, without remote Python. `timing` (Wazuh) and `barrier` (pfSense) are excluded.

## Before competition
Test on your own lab VMs, not RITSEC infrastructure. Confirm each SSH host key. Verify WinRM availability. Avoid putting personal account credentials into competition infrastructure. Use only during Hands On periods. Check rules with White Team.

## Known limitations
- Cloud hosts must be reachable from the chosen LAN controller; routing and firewall rules may prevent this.
- Ansible `synchronize` needs rsync on the targets and may need SSH key authentication depending on target configuration. If password-based rsync fails, establish authorized SSH keys or use another approved deployment method.
- This script installs packages on the controller, not the targets; apt availability may be affected by the competition environment.
- The Windows tool folders currently contain PowerShell scripts. They are copied, not run.
- Target destination `/tmp/irsec-tools` is temporary; it may disappear after reboot.
- WinRM must be correctly configured for authenticated, encrypted message transport. Do not open new scored services without approval.
