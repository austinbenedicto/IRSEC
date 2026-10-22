#!/bin/bash
daemon -f sh -c 'while true; do /root/ssh_watchdog.php; sleep 10; done'