#!/bin/sh
set -eu

echo "=== Container identity ==="
echo "Hostname: $(hostname)"
echo
echo "IP addresses:"
ip -4 addr show | awk '/inet / {print $2}'
echo
echo "MAC addresses:"
ip link show | awk '/link\/ether/ {print $2}'
echo "=========================="
echo

cp inquisitor.py inquisitor
chmod +x inquisitor

exec /usr/sbin/vsftpd /etc/vsftpd.conf