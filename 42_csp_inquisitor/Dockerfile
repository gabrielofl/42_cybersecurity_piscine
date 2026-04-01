FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    vsftpd \
	ftp \
	iproute2 \
    net-tools \
    procps \
	python3 \
	python3-pip \
	&& rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /home/ftpuser -s /bin/bash ftpuser \
    && echo "ftpuser:ftppass" | chpasswd \
    && mkdir -p /home/ftpuser/files \
    && chown -R ftpuser:ftpuser /home/ftpuser

COPY vsftpd.conf /etc/vsftpd.conf
COPY entrypoint.sh /entrypoint.sh
COPY inquisitor.py /inquisitor.py

RUN chmod +x /entrypoint.sh

EXPOSE 21

CMD ["/entrypoint.sh"]