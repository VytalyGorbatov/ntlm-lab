#!/bin/bash
# Start tcpdump inside the server container or on the bridge interface
set -e

PCAP_NAME="${1:-capture_$(date +%Y%m%d_%H%M%S).pcap}"
PCAP_PATH="/opt/shared/pcaps/${PCAP_NAME}"

echo "[+] Starting packet capture inside ntlm_server container..."
echo "[+] Destination: ${PCAP_PATH}"

docker exec -d ntlm_server tcpdump -i eth0 -s 0 -w "${PCAP_PATH}" "port 445 or port 139 or port 135 or port 389" -U
sleep 0.5

echo "[+] Capture running in background. To stop, run:"
echo "    ./scripts/stop_capture.sh ${PCAP_NAME}"
