#!/usr/bin/bash

if ["$(id - u)" -ne 0]; then
    echo "inventory.sh run fail"
    exit 1
fi

# This does the OS, Version and hostname of the system
echo -n "OS: " 
cat /etc/os-release | grep "NAME" | grep -o "\"[a-zA-Z]*\"" | grep -o "[a-zA-Z]*"
echo -n "Version " 
cat /etc/os-release | grep "VERSION=" | grep -o "\".*\"" | grep -o "[^\"]*"
echo -n "Hostname: "
hostname



#This does IP and MAC address
echo -n "IP Address: "
ip a | grep -o "inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | grep -o "[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*" | grep -v "127.0.0.1"
echo -n "MAC Address: "
ip -brief link | grep -o "[0-9a-fA-F]*:[0-9a-fA-F]*:[0-9a-fA-F]*:[0-9a-fA-F]*:[0-9a-fA-F]*:[0-9a-fA-F]*" | grep -v "00:00:00:00:00:00"






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






#Other Users
echo -n "All Users with Login Shell: "

while IFS=':' read -r username pass uid gid gecos homedir loginshell; do
    if [ -z "$uid" ] || [ "$uid" -ge 1000 ] && [ "$username" != "nobody" ] && [[ ! "$loginshell" =~ "nologin" ]]; then
        echo ". $username "
    fi
done < /etc/passwd






# Open Ports
echo "Open Ports"
ss -tulpn | grep -v "127.0.0.*" | tr -s ' ' | cut -d ' ' -f5 | grep -oE ":[0-9]+" | grep -oE "[0-9]+" | while read -r port; do
    echo "•Port: $port"
done