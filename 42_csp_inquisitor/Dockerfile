FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    vsftpd \
    tcpdump \
    net-tools \
    iproute2 \
    ftp \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/vsftpd/empty /home/vsftpd

RUN pip install --no-cache-dir scapy

COPY inquisitor.py /app/inquisitor.py
COPY entrypoint.sh /entrypoint.sh
COPY vsftpd.conf /etc/vsftpd.conf

RUN chmod +x /entrypoint.sh

WORKDIR /app

EXPOSE 21

ENTRYPOINT ["/entrypoint.sh"]