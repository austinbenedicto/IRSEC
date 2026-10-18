# IRSEC
This is the repo we will use for IRSEC and maybe ccdc mini comp

Whenever you want to add something plz make a branch and have the naming convetion of it be
initails: what_you_are_doing

[HOW TO USE BRANCHES (click me)](git-workflow-guide.md)

## Ansible script installation

Use the playbook at [Ansible/install-scripts.yml](Ansible/install-scripts.yml) to install scripts onto target hosts.

Place scripts in:
- `Ansible/linux-scripts/` for Linux targets
- `Ansible/windows-scripts/` for Windows targets

See [Ansible/how-to-add-scripts.txt](Ansible/how-to-add-scripts.txt) for quick setup instructions.

Example:

```bash
ansible-playbook -i <inventory> Ansible/install-scripts.yml
```

Defaults:
- Linux install directory on hosts: `/opt/irsec/scripts`
- Windows install directory on hosts: `C:\IRSEC\scripts`
