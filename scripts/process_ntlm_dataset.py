#!/usr/bin/env python3
"""Process PCAPs through Snort 3 with alert_json and SMB buffer dumps for CVE-2008-4834/4835.

Extracts SMBv1 FastPattern candidate packets matching Anchor SID 1, checks Snort attack alerts
across the 16 target CVE-2008-4834 / CVE-2008-4835 SIDs, decodes and formats payload buffers
into the standard schema compatible with sip-dataset and nids_ml:
  - buffers: smb_header + "\\x1E" + smb_payload + "\\x1E"
  - buffer_names: "smb_header\\x1esmb_payload\\x1e"
  - metadata: flowstart_time, src_ap, dst_ap, alerted, is_attack, attack_rules, meta
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("process_smb_dataset")

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DEFAULT_RULES = PROJECT_ROOT / "rules" / "cve_2008_4834.rules"
DEFAULT_CONFIG = Path("/home/vhorbato/Academy/IDS/snort3/lua/snort.lua")

# Anchor rules used to define the FastPattern candidate pool (SMBv1 Session Message)
ANCHOR_SIDS = {
    "1", "2", "3",
    "1:1", "1:2", "1:3",
    "1:1:1", "1:2:1", "1:3:1",
    "1:1:2", "1:2:2", "1:3:2",
    "1:1:0", "1:2:0", "1:3:0",
}

# Target Attack SIDs for CVE-2008-4834 and CVE-2008-4835
TARGET_SIDS = {
    "15196", "15199", "15200", "15203",
    "15205", "15206", "15209", "15210",
    "15213", "15214", "15217", "15218",
    "15220", "15221", "15224", "15225",
}


def run_snort_alert_json(
    snort_bin: str,
    snort_conf: Path,
    rules_file: Path,
    pcap_path: Path,
) -> List[Dict[str, Any]]:
    """Execute Snort 3 with alert_json and return parsed alert events."""
    fields = (
        "timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap "
        "rule action flowstart_time seconds client_bytes client_pkts "
        "server_bytes server_pkts b64_data"
    )
    lua_config = f"alert_json = {{ file = false, buffers = 'both', fields = '{fields}' }}"

    cmd = [
        snort_bin,
        "-c",
        str(snort_conf),
        "-R",
        str(rules_file),
        "-r",
        str(pcap_path),
        "-k",
        "none",
        "--lua",
        lua_config,
        "-A",
        "alert_json",
        "-q",
    ]

    logger.info("Executing Snort 3 over PCAP: %s (Rules: %s)", pcap_path, rules_file)
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if res.returncode != 0:
        logger.warning("Snort exited with non-zero code %d. Stderr: %s", res.returncode, res.stderr)

    events: List[Dict[str, Any]] = []
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as e:
            logger.debug("Failed parsing JSON line: %s (%s)", line, e)

    logger.info("Parsed %d raw alert events from Snort", len(events))
    return events


def parse_smb_metadata(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse structural SMB header fields from raw packet payload (sanitized of session IDs)."""
    idx = raw_bytes.find(b"\xffSMB")
    if idx == -1:
        return {}

    meta: Dict[str, Any] = {
        "smb_offset": idx,
    }

    hdr = raw_bytes[idx:]
    if len(hdr) < 32:
        return meta

    try:
        cmd = hdr[4]
        status = struct.unpack("<I", hdr[5:9])[0]
        flags = hdr[9]
        flags2 = struct.unpack("<H", hdr[10:12])[0]

        meta.update({
            "command": hex(cmd),
            "status": hex(status),
            "flags": hex(flags),
            "flags2": hex(flags2),
            "is_unicode": bool(flags2 & 0x8000),
        })

        # Detailed structural subcommand parsing (without leaking oracle counts or session IDs)
        if len(hdr) > 36:
            if cmd == 0xA0 and len(hdr) >= 75:  # NT_TRANSACT
                func = struct.unpack("<H", hdr[69:71])[0]
                meta["function"] = hex(func)
            elif cmd == 0x32 and len(hdr) >= 67:  # TRANSACTION2
                subcmd = struct.unpack("<H", hdr[61:63])[0]
                meta["subcommand"] = hex(subcmd)
            elif cmd in (0x75, 0x73, 0x2e, 0xa2, 0x2f, 0x2d, 0x24, 0x74):
                # Chained AndX secondary commands
                sec_cmd = None
                sec_offset = None
                if len(hdr) > 33 and hdr[33] in (0xA0, 0xA1, 0x32, 0x33):
                    sec_cmd = hdr[33]
                    sec_offset = 33
                elif len(hdr) > 35 and hdr[35] in (0xA0, 0xA1, 0x32, 0x33):
                    sec_cmd = hdr[35]
                    sec_offset = 35

                if sec_cmd is not None:
                    meta["secondary_command"] = hex(sec_cmd)
                    meta["andx_offset"] = sec_offset + 4  # offset from TCP payload (37 or 39)
                    if sec_offset == 35 and len(hdr) >= 38:
                        jump_pad = struct.unpack("<H", hdr[36:38])[0]
                        base = 38 + jump_pad
                    elif sec_offset == 33 and len(hdr) >= 37:
                        andx_off = struct.unpack("<H", hdr[35:37])[0]
                        jump_pad = max(0, andx_off - 40)
                        base = 38 + jump_pad
                    else:
                        base = 38

                    if sec_cmd == 0xA0 and len(hdr) >= base + 39:
                        func = struct.unpack("<H", hdr[base + 37 : base + 39])[0]
                        meta["function"] = hex(func)
                    elif sec_cmd == 0x32 and len(hdr) >= base + 31:
                        subcmd = struct.unpack("<H", hdr[base + 29 : base + 31])[0]
                        meta["subcommand"] = hex(subcmd)

    except Exception as e:
        logger.debug("Error parsing SMB metadata: %s", e)

    return meta


def is_transaction_packet(raw_payload: bytes) -> bool:
    """Check if raw payload contains an SMB transaction command or chained transaction."""
    idx = raw_payload.find(b"\xffSMB")
    if idx == -1 or len(raw_payload) < idx + 36:
        return False
    hdr = raw_payload[idx:]
    cmd = hdr[4]
    # Standalone transaction commands:
    # 0xA0 (NT Transact), 0xA1 (NT Transact Secondary),
    # 0x32 (Trans2), 0x33 (Trans2 Secondary)
    if cmd in (0xA0, 0xA1, 0x32, 0x33):
        return True

    # Chained AndX: must have a secondary transaction command in the AndX header
    # hdr[32] is WordCount
    # Offset 37 from TCP (offset 33 in hdr) or offset 39 from TCP (offset 35 in hdr)
    if cmd in (0x75, 0x73, 0x2e, 0xa2, 0x2f, 0x2d, 0x24, 0x74):
        if len(hdr) > 33 and hdr[33] in (0xA0, 0xA1, 0x32, 0x33):
            return True
        if len(hdr) > 35 and hdr[35] in (0xA0, 0xA1, 0x32, 0x33):
            return True

    return False


def process_alerts_to_dataset(
    events: List[Dict[str, Any]],
    is_attack: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """Aggregate per-packet alerts, extract buffers, and construct standard dataset records."""
    packets: Dict[Any, List[Dict[str, Any]]] = {}
    for ev in events:
        pkt_key = ev.get("pkt_num") or (
            ev.get("timestamp"),
            ev.get("src_ap"),
            ev.get("dst_ap"),
        )
        packets.setdefault(pkt_key, []).append(ev)

    records: List[Dict[str, Any]] = []
    stats = {
        "total_packets_alerted": len(packets),
        "fp_candidates": 0,
        "alerted_1": 0,
        "alerted_0": 0,
        "snort_fn": 0,
        "benign_fp": 0,
    }

    for pkt_key, pkt_events in packets.items():
        rules_triggered = [e.get("rule", "") for e in pkt_events]

        # Check if any target attack rule triggered
        attack_rules = [
            r for r in rules_triggered
            if any(f":{sid}:" in r for sid in TARGET_SIDS)
        ]

        # Candidate check: packet must match Anchor SID 1, 2, or 3, or trigger a Target SID
        is_candidate = (
            len(attack_rules) > 0
            or any(
                any(
                    r in ANCHOR_SIDS or f":{s}:" in r or r.startswith(f"1:{s}:")
                    for s in ("1", "2", "3")
                )
                for r in rules_triggered
            )
        )
        if not is_candidate:
            continue

        base_ev = pkt_events[0]

        # Decode raw packet payload
        b64_data = base_ev.get("b64_data", "")
        raw_payload = base64.b64decode(b64_data) if b64_data else b""

        # Filter candidate records: must be a genuine SMB transaction packet (or chained transaction)
        if not is_transaction_packet(raw_payload):
            continue

        stats["fp_candidates"] += 1
        alerted = 1 if len(attack_rules) > 0 else 0

        if alerted:
            stats["alerted_1"] += 1
            if is_attack == 0:
                stats["benign_fp"] += 1
        else:
            stats["alerted_0"] += 1
            if is_attack == 1:
                stats["snort_fn"] += 1

        # Extract SMB metadata
        meta = parse_smb_metadata(raw_payload)

        # Split into two buffers: smb_header and smb_payload separated by 0x1E
        idx = raw_payload.find(b"\xffSMB")
        if idx != -1:
            smb_header_bytes = raw_payload[idx : idx + 32]
            smb_payload_bytes = raw_payload[idx + 32 :]
        else:
            smb_header_bytes = raw_payload[:32]
            smb_payload_bytes = raw_payload[32:]

        # Zero out bytes 24..31 (TID, PID, UID, MID) in smb_header_bytes to eliminate session leakage
        if len(smb_header_bytes) >= 32:
            smb_header_bytes = smb_header_bytes[:24] + b"\x00" * 8
        elif len(smb_header_bytes) > 24:
            smb_header_bytes = smb_header_bytes[:24] + b"\x00" * (len(smb_header_bytes) - 24)

        # Scrub any internal 0x1E (30) bytes in smb_header_bytes and smb_payload_bytes
        if 0x1E in smb_header_bytes:
            smb_header_bytes = bytes(0x1F if b == 0x1E else b for b in smb_header_bytes)
        if 0x1E in smb_payload_bytes:
            smb_payload_bytes = bytes(0x1F if b == 0x1E else b for b in smb_payload_bytes)

        header_str = smb_header_bytes.decode("latin1", errors="replace")
        payload_str = smb_payload_bytes.decode("latin1", errors="replace")
        buffers = f"{header_str}\x1e{payload_str}\x1e"
        buffer_names = "smb_header\x1esmb_payload\x1e"

        record = {
            "flowstart_time": base_ev.get("flowstart_time", 0),
            "seconds": base_ev.get("seconds", 0),
            "proto": base_ev.get("proto", "TCP"),
            "pkt_gen": base_ev.get("pkt_gen", "stream_tcp"),
            "pkt_len": base_ev.get("pkt_len", len(raw_payload)),
            "dir": base_ev.get("dir", "C2S"),
            "src_ap": base_ev.get("src_ap", ""),
            "dst_ap": base_ev.get("dst_ap", ""),
            "client_bytes": base_ev.get("client_bytes", 0),
            "client_pkts": base_ev.get("client_pkts", 0),
            "server_bytes": base_ev.get("server_bytes", 0),
            "server_pkts": base_ev.get("server_pkts", 0),
            "buffers": buffers,
            "buffer_names": buffer_names,
            "alerted": alerted,
            "is_attack": is_attack,
            "attack_rules": attack_rules,
            "all_rules": rules_triggered,
            "meta": meta,
        }
        records.append(record)

    return records, stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Process PCAPs through Snort 3 with alert_json and SMB buffer dumps")
    parser.add_argument("-i", "--input", required=True, type=Path, help="Path to input PCAP file")
    parser.add_argument("-o", "--output", required=True, type=Path, help="Output JSON dataset path")
    parser.add_argument("--is-attack", action="store_true", help="Label as attack (is_attack=1)")
    parser.add_argument(
        "--rules",
        type=Path,
        default=DEFAULT_RULES,
        help="Snort rules file (default: ntlm-lab/rules/cve_2008_4834.rules)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG,
        help="Snort config lua file",
    )
    parser.add_argument(
        "--snort-bin",
        default="snort",
        help="Path to Snort binary",
    )
    args = parser.parse_args()

    if not args.input.exists():
        logger.error("Input PCAP does not exist: %s", args.input)
        sys.exit(1)

    is_attack_val = 1 if args.is_attack else 0
    events = run_snort_alert_json(args.snort_bin, args.config, args.rules, args.input)

    # Save raw alerts jsonl dump
    alerts_dump_path = args.output.with_suffix(".alerts.jsonl")
    alerts_dump_path.parent.mkdir(parents=True, exist_ok=True)
    with alerts_dump_path.open("w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    logger.info("Saved raw alert stream to: %s", alerts_dump_path)

    # Convert to structured dataset
    records, stats = process_alerts_to_dataset(events, is_attack_val)

    # Save structured dataset JSON
    dataset_obj = {
        "dataset": records,
        "metadata": {
            "source_pcap": str(args.input),
            "pcap_size_bytes": args.input.stat().st_size,
            "is_attack": is_attack_val,
            "total_records": len(records),
            "statistics": stats,
        },
    }

    with args.output.open("w", encoding="utf-8") as f:
        json.dump(dataset_obj, f, indent=2)

    logger.info("Saved processed dataset with SMB buffer dumps to: %s", args.output)

    # Summary report
    print("\n" + "=" * 65)
    print(" SMBv1 CVE-2008-4834/4835 DATASET PROCESSING SUMMARY")
    print(f" Source PCAP:    {args.input}")
    print(f" Output Dataset: {args.output}")
    print(f" Class:          {'Attack (is_attack=1)' if is_attack_val else 'Benign (is_attack=0)'}")
    print("-" * 65)
    print(f"  Total Packets Alerted:         {stats['total_packets_alerted']}")
    print(f"  FastPattern Candidates (SID 1): {stats['fp_candidates']}")
    print(f"  Snort Alerted (alerted=1):     {stats['alerted_1']}")
    print(f"  Snort Non-Alerted (alerted=0):   {stats['alerted_0']}")
    if is_attack_val:
        print(f"  [*] Snort False Negatives:     {stats['snort_fn']}")
    else:
        print(f"  [*] Added Benign FP:           {stats['benign_fp']}")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
