#!/bin/bash
set -e

echo "[+] Initializing NTLM-Lab Samba Server..."

# Ensure directories exist
mkdir -p /srv/samba/public /srv/samba/secured /opt/shared/pcaps /var/log/samba
chmod 777 /srv/samba/public
chmod 770 /srv/samba/secured

# Create sample file in public share
echo "Welcome to NTLM-Lab Public Share" > /srv/samba/public/welcome.txt
echo "Confidential NTLM-Lab Data" > /srv/samba/secured/secret.txt

# Create standard test users in Linux and Samba
USERS=(
    "admin:AdminPassword123!"
    "testuser:TestPassword123!"
    "user1:User1Password!"
    "user2:User2Password!"
    "user3:User3Password!"
    "user4:User4Password!"
    "user5:User5Password!"
)

for entry in "${USERS[@]}"; do
    IFS=":" read -r username password <<< "$entry"
    if ! id -u "$username" >/dev/null 2>&1; then
        useradd -M -s /usr/sbin/nologin "$username" || true
    fi
    (echo "$password"; echo "$password") | smbpasswd -s -a "$username"
    smbpasswd -e "$username"
    echo "  [+] Configured user: $username"
done

# Assign secured directory ownership to admin
chown -R admin:admin /srv/samba/secured

# Start network packet capture if requested
if [ "${ENABLE_CAPTURE}" = "true" ]; then
    PCAP_FILE="/opt/shared/pcaps/server_$(date +%Y%m%d_%H%M%S).pcap"
    echo "[+] Starting background packet capture to: $PCAP_FILE"
    tcpdump -i any -s 0 -w "$PCAP_FILE" "port 445 or port 139 or port 135 or port 389" -U &
    TCPDUMP_PID=$!
    trap "kill $TCPDUMP_PID 2>/dev/null || true" EXIT
fi

# Start NetBIOS daemon in background
echo "[+] Starting nmbd..."
nmbd -D

# Start SMB daemon in foreground
echo "[+] Starting smbd in foreground..."
exec smbd -F --no-process-group --debug-stdout < /dev/null
