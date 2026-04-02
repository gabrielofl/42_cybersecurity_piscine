#!/bin/sh
set -eu

echo "=========================="
echo "Hostname: $(hostname)"
echo "Container role: ${CONTAINER_ROLE:-unknown}"
echo
echo "IP addresses:"
ip -4 addr show | awk '/inet / {print $2}'
echo
echo "MAC addresses:"
ip link show | awk '/link\/ether/ {print $2}'
echo "=========================="
echo

case "${CONTAINER_ROLE:-}" in
    ftp-server)
        echo "FTP server"

        if ! id ftpuser >/dev/null 2>&1; then
            adduser --disabled-password --gecos "" ftpuser
            echo "ftpuser:${FTP_PASSWORD:-ftppass}" | chpasswd
        fi

        chown -R ftpuser:ftpuser /home/vsftpd/ftpuser || true
        chmod 755 /home/vsftpd/ftpuser

        exec /usr/sbin/vsftpd /etc/vsftpd.conf
        ;;

    attacker)
        echo "Starting Attacker"
        cd /app
		exec tail -f /dev/null
        ;;

    ftp-client)
        echo "FTP client"
        mkdir -p /shared
        chmod 755 /shared
        exec tail -f /dev/null
        ;;

    *)
        exit 1
        ;;
esac