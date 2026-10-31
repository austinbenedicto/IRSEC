#!/usr/bin/env bash
# IRSEC - Interactive IPv4 blocker (LOCAL Linux host only)
# Usage: bash block-ip.sh [IPv4]
# Adds temporary inbound and outbound DROP rules using iptables.
# Does not save rules across reboots and does not modify pfSense.
# Only use for authorized defensive response; blocking a scored service,
# White Team, logging, or management traffic can violate competition rules.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo 'Run with sudo: sudo bash block-ip.sh [IPv4]' >&2
  exit 1
fi
if ! command -v iptables >/dev/null 2>&1; then
  echo 'iptables is not installed. No firewall changes made.' >&2
  exit 1
fi

ip=${1:-}
if [[ -z $ip ]]; then
  read -r -p 'IPv4 address to block: ' ip
fi

# Require exactly four decimal octets in the range 0-255.
if [[ ! $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo 'Invalid IPv4 address.' >&2; exit 1
fi
IFS=. read -r a b c d <<< "$ip"
for octet in "$a" "$b" "$c" "$d"; do
  if (( 10#$octet > 255 )); then
    echo 'Invalid IPv4 address.' >&2; exit 1
  fi
done
# Canonicalize to prevent leading-zero ambiguity.
ip="$((10#$a)).$((10#$b)).$((10#$c)).$((10#$d))"

# Do not block localhost, multicast, broadcast, unspecified, or reserved
# addresses. Protect competition management, firewall, and logging networks.
if (( a == 0 || a == 127 || a >= 224 )) ||
   [[ $ip == 255.255.255.255 ]] ||
   [[ $ip == 10.5.1.254 || $ip == 192.168.5.4 ]] ||
   [[ $ip == 172.16.1.* ]]; then
  echo 'Refusing to block a reserved or protected address.' >&2; exit 1
fi

# Protect every local IPv4 address assigned to this host.
if command -v ip >/dev/null 2>&1; then
  if ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | grep -Fxq -- "$ip"; then
    echo 'Refusing to block a local interface address.' >&2; exit 1
  fi
  # Protect the current default gateway(s), if present.
  if ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | grep -Fxq -- "$ip"; then
    echo 'Refusing to block the default gateway.' >&2; exit 1
  fi
fi

printf '\nTarget: %s\nAction: DROP inbound traffic FROM and outbound traffic TO this IPv4 address.\n' "$ip"
printf 'Host: %s\n' "$(hostname)"
read -r -p 'Apply both firewall rules? Type BLOCK to confirm: ' answer
if [[ $answer != BLOCK ]]; then
  echo 'Cancelled. No firewall changes made.'; exit 0
fi

# Use -C to avoid duplicate rules; insert at the top so existing ACCEPT
# rules do not bypass them. These rules apply only on this Linux machine.
if ! iptables -C INPUT -s "$ip" -j DROP 2>/dev/null; then
  iptables -I INPUT 1 -s "$ip" -j DROP
fi
if ! iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null; then
  iptables -I OUTPUT 1 -d "$ip" -j DROP
fi
printf '\nBlocked %s on this host. Rules are not persisted across reboot.\n' "$ip"
printf 'To undo later (as root):\n'
printf '  iptables -D INPUT -s %s -j DROP\n' "$ip"
printf '  iptables -D OUTPUT -d %s -j DROP\n' "$ip"
