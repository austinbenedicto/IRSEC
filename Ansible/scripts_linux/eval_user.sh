#!/usr/bin/bash

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "eval_users.sh run fail"
    exit 1
fi

# Allowed user list
user_list=(
  "student"
)

# reads each line in the /etc/passwd file and labels each variable
while IFS=':' read -r username pass uid gid gecos homedir loginshell; do
    echo "~~~~~"
    username=$(echo "$username" | tr -d '[:space:]')

    # notify that user should be system account
    if [ -z "$uid" ] || [ "$uid" -lt 1000 ]; then
        echo "UID:$uid indicates '$username' is a system account."
    else
        echo "$username"
    fi

    echo "User login shell: $loginshell"

    # notify that user account has no login shell
    if [ "$loginshell" == "/usr/sbin/nologin" ] || [ "$loginshell" == "/sbin/nologin" ]; then
        echo "User has no login shell."
    fi

    # ask whether to approve account
    while true; do
        if printf "%s\n" "${user_list[@]}" | grep -qxF "$username"; then
            accappr='y'
        else
            read -p "Approve this account? y/n: " accappr </dev/tty
        fi

        case $accappr in
            # if account is approved, change password if the user has login capabilities
            [Yy] )
                if [ "$loginshell" == "/usr/sbin/nologin" ] || [ "$loginshell" == "/sbin/nologin" ]; then
                    echo "User '$username' is approved. No login password to change."
                else
                    echo "User '$username' is approved. Please change the password."
                    read -s -p "Enter new password for '$username': " new_pass </dev/tty
                    if [ -z "$new_pass" ]; then
                        echo "Skipping password change."
                        break
                    fi
                    echo "${username}:${new_pass}" | chpasswd
                    if [ $? -eq 0 ]; then
                        echo "Password updated for ${username}."
                    else
                        echo "Password update FAILED for ${username}."
                    fi
                fi
                break
                ;;

            # if the account is not approved, ask whether to brick (for accounts where removing causes problems) or delete
            [Nn] )
                while true; do
                    read -p "Brick or delete '$username'? B/D: " usrstatus </dev/tty

                    case $usrstatus in
                        [Bb] )
                            echo "Bricking account '$username'..."
                            # remove login capability
                            usermod -L -s /sbin/nologin $username
                            if [ $? -eq 0 ]; then
                                echo "User '$username' has been locked."
                            else
                                echo "Error locking user '$username'."
                            fi
                            # set account expiration to the minimum date, Jan 1 1970
                            chage -E 0 $username
                            if [ $? -eq 0 ]; then
                                echo "User '$username' set to expired."
                            else
                                echo "Error expiring user '$username'."
                            fi
                            break
                            ;;
                        [Dd] )
                            echo "Deleting user '$username'..."
                            # list all files owned by user before deletion in a txt file to reference later
                            touch files_from_$username.txt
                            find / -user $username -ls -type f > files_from_$username.txt
                            # remove user and their home directory
                            deluser --remove-home $username
                            if [ $? -eq 0 ]; then
                                echo "User '$username' removed."
                            else
                                echo "Error removing user '$username'."
                            fi
                            break
                            ;;
                        * )
                            echo "Invalid response. Please try again"
                            ;;
                    esac
                done
                break
                ;;
            * )
                echo "Invalid response. Please try again"
                ;;
        esac
    done
done < /etc/passwd