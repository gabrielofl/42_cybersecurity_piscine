FROM debian:bookworm-20240211-slim

RUN apt-get update && apt-get install -y \
    vsftpd \
	ftp \
	iproute2 \
    net-tools \
    procps \
	python3 \
	python3-pip \
    libpcap-dev \
    python3-scapy \
	&& rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /home/ftpuser -s /bin/bash ftpuser \
    && echo "ftpuser:ftppass" | chpasswd \
    && mkdir -p /home/ftpuser/files \
    && chown -R ftpuser:ftpuser /home/ftpuser \
    && mkdir -p /var/run/vsftpd/empty \
    && chmod 755 /var/run/vsftpd/empty

COPY vsftpd.conf /etc/vsftpd.conf
COPY entrypoint.sh /entrypoint.sh
COPY inquisitor.py /inquisitor.py

RUN chmod +x /entrypoint.sh

EXPOSE 21

ENTRYPOINT ["/entrypoint.sh"]