#!/bin/bash
# Master pipeline to capture and process NTLMSSP datasets through Snort 3
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${LAB_DIR}"

BENIGN_COUNT="${1:-5000}"
ATTACK_COUNT="${2:-5000}"
WORKERS="${3:-8}"
DELAY_MAX="${4:-0.01}"

echo "=========================================================="
echo " SMBv1/NetBIOS Dataset Generation & Snort Processing Pipeline"
echo " Benign Sessions: ${BENIGN_COUNT}"
echo " Attack Sessions: ${ATTACK_COUNT}"
echo " Workers:         ${WORKERS}"
echo "=========================================================="

mkdir -p shared/pcaps shared/datasets
rm -f shared/pcaps/benign_basic.pcap shared/pcaps/attack_basic.pcap

# 1. Capture Benign Traffic
echo ""
echo "[*] Phase 1: Capturing Benign Traffic..."
./scripts/start_capture.sh benign_basic.pcap
sleep 1
docker exec ntlm_client /opt/client/run_benign.sh --count "${BENIGN_COUNT}" --workers "${WORKERS}" --delay-min 0.0 --delay-max "${DELAY_MAX}"
sleep 1
./scripts/stop_capture.sh benign_basic.pcap

# 2. Capture Attack Traffic
echo ""
echo "[*] Phase 2: Capturing Attack Traffic..."
./scripts/start_capture.sh attack_basic.pcap
sleep 1
docker exec ntlm_attacker /opt/client/run_attack.sh --count "${ATTACK_COUNT}" --scenario mixed --fn-ratio 0.65 --workers "${WORKERS}" --delay-min 0.0 --delay-max "${DELAY_MAX}"
sleep 1
./scripts/stop_capture.sh attack_basic.pcap

# 3. Process Benign PCAP with Snort alert_json and buffer dump
echo ""
echo "[*] Phase 3: Processing Benign PCAP with Snort 3 (alert_json + buffers)..."
python3 scripts/process_ntlm_dataset.py \
    -i shared/pcaps/benign_basic.pcap \
    -o shared/datasets/benign_basic.json

# 4. Process Attack PCAP with Snort alert_json and buffer dump
echo ""
echo "[*] Phase 4: Processing Attack PCAP with Snort 3 (alert_json + buffers)..."
python3 scripts/process_ntlm_dataset.py \
    -i shared/pcaps/attack_basic.pcap \
    -o shared/datasets/attack_basic.json \
    --is-attack

# 5. Combine and Generate Dissertation 2x2 Matrix Report
echo ""
echo "[*] Phase 5: Combining Cohorts & Building Dissertation Matrix..."
python3 scripts/combine_datasets.py \
    --benign shared/datasets/benign_basic.json \
    --attack shared/datasets/attack_basic.json \
    -o shared/datasets/combined_basic.json \
    --report shared/datasets/dataset_report.md

# 6. Generate Leakage-Resistant Splits
echo ""
echo "[*] Phase 6: Generating Skeleton-Holdout and Stratified Splits..."
python3 scripts/create_splits.py \
    -i shared/datasets/combined_basic.json \
    -o shared/datasets/splits

echo "[+] Pipeline completed successfully!"
echo "[+] Combined Dataset: ${LAB_DIR}/shared/datasets/combined_basic.json"
echo "[+] Summary Report:   ${LAB_DIR}/shared/datasets/dataset_report.md"
