#!/bin/bash
# Stop tcpdump cleanly inside ntlm_server container
set -e

echo "[+] Stopping packet capture in ntlm_server..."
docker exec ntlm_server pkill -2 tcpdump 2>/dev/null || true
sleep 1

# Check latest captured pcap if argument given
PCAP_NAME="${1}"
if [ -n "${PCAP_NAME}" ]; then
    PCAP_PATH="shared/pcaps/${PCAP_NAME}"
    if [ -f "${PCAP_PATH}" ]; then
        SIZE=$(ls -lh "${PCAP_PATH}" | awk '{print $5}')
        echo "[+] Capture saved: ${PCAP_PATH} (${SIZE})"
    fi
fi
