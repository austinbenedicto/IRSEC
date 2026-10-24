#!/usr/bin/bash

if [ "$(id -u)" -ne 0 ]; then
    echo "inventory.sh run fail"
    exit 1
fi

# This does the OS, Version and hostname of the system
echo -n "OS: "
grep -Eo 'NAME="[^"]+"' /etc/os-release | head -n 1 | sed 's/^NAME="//; s/"$//'
echo -n "Version: "
grep -Eo 'VERSION="[^"]+"' /etc/os-release | head -n 1 | sed 's/^VERSION="//; s/"$//'
echo -n "Hostname: "
hostname

# This does IP and MAC address
echo -n "IP Address: "
ip a 2>/dev/null | grep -Eo 'inet ([0-9]{1,3}\.){3}[0-9]{1,3}' | awk '{print $2}' | grep -vE '^127\.0\.0\.1$'
echo -n "MAC Address: "
ip -brief link 2>/dev/null | grep -Eo '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | grep -vE '^00:00:00:00:00:00$'

# Admin users
echo -n "Admin Users: "
getent group sudo | cut -d: -f4 | while read -r username; do
    echo -n "$username "
done
getent group admin | cut -d: -f4 | while read -r username; do
    echo -n "$username "
done
getent group wheel | cut -d: -f4 | while read -r username; do
    echo -n "$username "
done

echo

# Other Users
echo -n "All Users with Login Shell: "
while IFS=':' read -r username _ uid _ _ _ loginshell; do
    if [ -n "$uid" ] && [ "$uid" -ge 1000 ] && [ "$username" != "nobody" ] && [[ "$loginshell" != *nologin* ]]; then
        echo -n ". $username "
    fi
done < /etc/passwd

echo

# Open Ports
echo "Open Ports"
ss -tulpn 2>/dev/null | grep -v '127.0.0.*' | tr -s ' ' | cut -d ' ' -f5 | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | while read -r port; do
    echo "Port: $port"
done
