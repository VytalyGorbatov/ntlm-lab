#!/bin/bash
# Evaluates a generated PCAP with Snort 3 and ntlmssp.rules
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PCAP_FILE="${1}"
if [ -z "${PCAP_FILE}" ] || [ ! -f "${PCAP_FILE}" ]; then
    echo "Usage: $0 <path_to_pcap>"
    echo "Available PCAPs in shared:"
    ls -l "${WORKSPACE_ROOT}/ntlm-lab/shared/pcaps"/*.pcap 2>/dev/null || echo "  (no pcaps found yet)"
    exit 1
fi

RULES_FILE="${WORKSPACE_ROOT}/PhD_Artifacts/FP_Groups_testing/ntlmssp.rules"
SNORT_CONF="${WORKSPACE_ROOT}/IDS/snort3/lua/snort.lua"

echo "=========================================================="
echo " Running Snort 3 Evaluation against NTLMSSP FastPattern"
echo " PCAP:  ${PCAP_FILE}"
echo " Rules: ${RULES_FILE}"
echo "=========================================================="

echo "[*] Snort alert_fast output:"
snort -c "${SNORT_CONF}" -R "${RULES_FILE}" -r "${PCAP_FILE}" -k none -A alert_fast -q

echo ""
echo "[*] Alert Breakdown:"
TOTAL_ALERTS=$(snort -c "${SNORT_CONF}" -R "${RULES_FILE}" -r "${PCAP_FILE}" -k none -A alert_fast -q 2>/dev/null | wc -l)
ANCHOR_ALERTS=$(snort -c "${SNORT_CONF}" -R "${RULES_FILE}" -r "${PCAP_FILE}" -k none -A alert_fast -q 2>/dev/null | grep '\[1:1:0\]' | wc -l)
ATTACK_ALERTS=$(( TOTAL_ALERTS - ANCHOR_ALERTS ))

echo "  Total Packets Alerted:       ${TOTAL_ALERTS}"
echo "  NTLMSSP FP Anchor (SID: 1):  ${ANCHOR_ALERTS} (Candidate pool)"
echo "  Attack Rules Triggered:      ${ATTACK_ALERTS}"
echo "=========================================================="
