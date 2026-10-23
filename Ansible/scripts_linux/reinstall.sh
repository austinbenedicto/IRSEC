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


#add any additional packages to reinstall below