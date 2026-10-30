# F1.sh Wazuh FIM Pack — IRSeC

## Contents
- `f1sh_linux_agent.conf` — centralized Linux FIM settings
- `f1sh_windows_agent.conf` — centralized Windows FIM + registry monitoring
- `f1sh_fim_rules.xml` — optional manager-side priority rules (100100–100103)

## Before deployment
- Agents are already installed: **do not install new agents**.
- Have shell/sudo access to the **Wazuh manager**. Dashboard-only access is not sufficient for these file-copy steps.
- Inspect and back up existing group configs and custom rules; do not overwrite organizers' settings.
- These are starter profiles; remove nonexistent paths and reduce noisy paths if necessary.
- Rule IDs 100100–100103 must not conflict with existing custom rule IDs.
- The XML is syntax-checked, but live Wazuh rule matching has **not** been tested against your competition version. Test it first.

## Step-by-step on the manager

### 1. Inspect agents and existing groups
```bash
sudo /var/ossec/bin/agent_control -l
sudo /var/ossec/bin/agent_groups -l
sudo ls -l /var/ossec/etc/shared/
sudo ls -l /var/ossec/etc/rules/
```

### 2. Create groups (if absent)
```bash
sudo /var/ossec/bin/agent_groups -a -g f1sh-linux
sudo /var/ossec/bin/agent_groups -a -g f1sh-windows
```
If a group already exists, do not recreate it.

### 3. Back up any existing group files and check for rule-ID conflicts
```bash
sudo cp -a /var/ossec/etc/shared/f1sh-linux/agent.conf /var/ossec/etc/shared/f1sh-linux/agent.conf.bak 2>/dev/null || true
sudo cp -a /var/ossec/etc/shared/f1sh-windows/agent.conf /var/ossec/etc/shared/f1sh-windows/agent.conf.bak 2>/dev/null || true
sudo grep -R -n -E 'id="10010[0-3]"' /var/ossec/etc/rules/ || true
```
If `agent.conf` already exists, **merge the `<syscheck>` contents** into the existing config instead of replacing it. Avoid duplicate/conflicting syscheck blocks.

### 4. Copy configs from the directory where you uploaded/extracted the pack
```bash
# ONLY when the group agent.conf files are empty/new; otherwise merge manually:
sudo cp f1sh_linux_agent.conf /var/ossec/etc/shared/f1sh-linux/agent.conf
sudo cp f1sh_windows_agent.conf /var/ossec/etc/shared/f1sh-windows/agent.conf

# Custom rule file on the MANAGER, not on agents:
sudo cp f1sh_fim_rules.xml /var/ossec/etc/rules/f1sh_fim_rules.xml
sudo chown root:wazuh /var/ossec/etc/rules/f1sh_fim_rules.xml
sudo chmod 640 /var/ossec/etc/rules/f1sh_fim_rules.xml
```
If your manager uses different ownership conventions, match the permissions of neighboring custom rule files. Ensure agent group configs are readable by Wazuh.

### 5. Assign existing agents to groups
```bash
sudo /var/ossec/bin/agent_control -l
sudo /var/ossec/bin/agent_groups -h
# Replace 001 with a real Linux agent ID:
sudo /var/ossec/bin/agent_groups -a -i 001 -g f1sh-linux
# Replace 002 with a real Windows agent ID:
sudo /var/ossec/bin/agent_groups -a -i 002 -g f1sh-windows
```
**Important:** Depending on your Wazuh version, group assignment may replace or append existing memberships. Review `agent_groups -h` and preserve the existing groups (often using `-q` to avoid replacing memberships); do not remove organizers' groups inadvertently.

### 6. Validate and apply
```bash
# Inspect logs if rule loading fails:
sudo /var/ossec/bin/wazuh-logtest
# Exit the interactive tester with Ctrl+C, then restart manager:
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
sudo tail -n 80 /var/ossec/logs/ossec.log
```
`wazuh-logtest` is interactive and useful for testing a *real captured event*. Simply opening it does not verify all rules. For actual event matching, copy a real JSON FIM event from the dashboard and test with the appropriate log format/version. Watch manager logs for rule parsing errors after restart.

### 7. Verify on endpoints and dashboard
- Confirm Linux and Windows agents remain connected and assigned correctly.
- Check agent configuration sync in the dashboard; group configs can be distributed automatically without manually editing agents.
- To test safely, uncomment the optional test directory in the appropriate agent config and create that directory **before** deploying; then create/modify/delete a harmless file there. Built-in FIM alerts should appear.
- For custom high-priority rules, make a reversible, authorized test modification in a monitored location or replay a captured FIM event; confirm expected rule ID/severity in the FIM/Threat Hunting events.
- Verify Windows registry events actually use the path format your custom rules expect; adjust regex if your installed version emits a different format.

## Notes
- FIM is not a process monitor or an antivirus replacement.
- Windows registry monitoring is scan-based in this profile; real-time settings apply to selected directories.
- `/etc/passwd` and related identity files are scanned on the configured interval; real-time is reserved for directories.
- Very broad Windows Services registry monitoring can be noisy. Remove it if it overwhelms alerts.
- If the manager already centrally manages FIM, merge rather than override it.
