#!/bin/bash
# Runner script for benign generator with server health check
set -e

SERVER_IP="${SERVER_IP:-172.24.0.10}"
SERVER_PORT="${SERVER_PORT:-445}"
COUNT="${COUNT:-50}"

echo "[+] Checking connectivity to Samba server at ${SERVER_IP}:${SERVER_PORT}..."
timeout 15 bash -c "until nc -z ${SERVER_IP} ${SERVER_PORT}; do sleep 0.5; done"
echo "[+] Samba server is online."

echo "[+] Starting benign traffic generation: ${COUNT} sessions..."
python3 /opt/client/benign_generator.py \
    --server "${SERVER_IP}" \
    --port "${SERVER_PORT}" \
    --count "${COUNT}" \
    "$@"
