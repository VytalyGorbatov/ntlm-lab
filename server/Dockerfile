FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    samba \
    smbclient \
    tcpdump \
    iproute2 \
    net-tools \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY configs/smb.conf /etc/samba/smb.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 445/tcp 139/tcp 135/tcp 137/udp 138/udp

WORKDIR /srv/samba

ENTRYPOINT ["/entrypoint.sh"]
