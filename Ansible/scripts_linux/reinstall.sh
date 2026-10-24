#!/usr/bin/bash

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "reinstall.sh run fail"
    exit 1
fi

echo "****CLEARING APT****"
apt clean
apt update

echo -e "\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"
echo "****REMOVING CURL****"
apt purge curl -y
echo -e "\n\n****REINSTALLING CURL****"
apt install curl

echo -e "\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"
echo "****REMOVING GIT****"
apt purge git -y
echo -e "\n\n****REINSTALLING GIT****"
apt install git

echo -e "\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n"
curl -fsSL https://yazi-rs.github.io/builds/yazi-keyring.gpg | tee /usr/share/keyrings/yazi-keyring.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/yazi-keyring.gpg] https://yazi-rs.github.io/builds/ stable main' | tee /etc/apt/sources.list.d/yazi.list >/dev/null
echo -e "\n\n****INSTALLING YAZI****"
apt install yazi



#add any additional packages to reinstall below