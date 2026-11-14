#!/usr/bin/env python3
"""Comprehensive Repair for all generator collision underflow defects in SMBv1 dataset splits.

Remediates all remaining benign records with:
1. Chained TRANS2 TotalParameterCount < ParameterCount
2. Standalone NT_TRANSACT TotalParameterCount < ParameterCount
3. Standalone TRANS2 TotalParameterCount < ParameterCount
4. NT_TRANSACT_SECONDARY ParameterCount + ParameterDisplacement > TotalParameterCount
5. TRANS2_SECONDARY ParameterCount + ParameterDisplacement > TotalParameterCount
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import random
import struct
import sys


def sanitize_id_val(val: int) -> int:
    """Ensure a 16-bit integer field contains no 0x1E (30) byte."""
    low = val & 0xFF
    high = (val >> 8) & 0xFF
    if low == 0x1E:
        low = 0x1F
    if high == 0x1E:
        high = 0x1F
    return (high << 8) | low


def sanitize_int32(val: int) -> int:
    """Ensure a 32-bit integer field contains no 0x1E (30) byte."""
    b0 = val & 0xFF
    b1 = (val >> 8) & 0xFF
    b2 = (val >> 16) & 0xFF
    b3 = (val >> 24) & 0xFF
    if b0 == 0x1E:
        b0 = 0x1F
    if b1 == 0x1E:
        b1 = 0x1F
    if b2 == 0x1E:
        b2 = 0x1F
    if b3 == 0x1E:
        b3 = 0x1F
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)


def find_all_defective_benign_records(records: list[dict]) -> list[dict]:
    """Locate all benign records with any underflow/chunk overflow defect."""
    defective = []
    for idx, r in enumerate(records):
        if r.get("is_attack", 0) == 1:
            continue
        raw = r["buffers"].encode("latin1")
        parts = raw.split(b"\x1e")
        if len(parts) < 2:
            continue
        hdr = parts[0]
        pld = parts[1]
        if len(hdr) < 5:
            continue
        cmd = hdr[4]
        skel = r.get("meta", {}).get("skeleton_id", "")

        # 1. Chained TRANS2
        if "chained_trans2" in skel and len(pld) >= 6:
            andx_target = r.get("meta", {}).get("andx_offset")
            if andx_target == 39:
                jp = pld[4] | (pld[5] << 8)
                base = 6 + jp
            else:
                andx_off = pld[3] | (pld[4] << 8)
                jp = andx_off + 4 - 44
                base = 6 + jp
            if len(pld) >= base + 21:
                tot = pld[base + 1] | (pld[base + 2] << 8)
                param = pld[base + 19] | (pld[base + 20] << 8)
                if tot < param:
                    defective.append({
                        "idx": idx, "kind": "chained_trans2", "base": base,
                        "tot": tot, "target_min": param, "width": 2, "offset": base + 1
                    })
                    continue

        # 2. Standalone NT_TRANSACT (0xA0)
        if cmd == 0xA0 and len(pld) >= 24:
            tot = struct.unpack("<I", pld[4:8])[0]
            param = struct.unpack("<I", pld[20:24])[0]
            if tot < param:
                defective.append({
                    "idx": idx, "kind": "nt_transact", "base": 0,
                    "tot": tot, "target_min": param, "width": 4, "offset": 4
                })
                continue

        # 3. Standalone TRANS2 (0x32)
        elif cmd == 0x32 and len(pld) >= 21:
            tot = struct.unpack("<H", pld[1:3])[0]
            param = struct.unpack("<H", pld[19:21])[0]
            if tot < param:
                defective.append({
                    "idx": idx, "kind": "standalone_trans2", "base": 0,
                    "tot": tot, "target_min": param, "width": 2, "offset": 1
                })
                continue

        # 4. NT_TRANSACT_SECONDARY (0xA1)
        elif cmd == 0xA1 and len(pld) >= 24:
            tot = struct.unpack("<I", pld[4:8])[0]
            param = struct.unpack("<I", pld[12:16])[0]
            disp = struct.unpack("<I", pld[20:24])[0]
            if param + disp > tot:
                defective.append({
                    "idx": idx, "kind": "nt_secondary", "base": 0,
                    "tot": tot, "target_min": param + disp, "width": 4, "offset": 4
                })
                continue

        # 5. TRANS2_SECONDARY (0x33)
        elif cmd == 0x33 and len(pld) >= 11:
            tot = struct.unpack("<H", pld[1:3])[0]
            param = struct.unpack("<H", pld[5:7])[0]
            disp = struct.unpack("<H", pld[9:11])[0]
            if param + disp > tot:
                defective.append({
                    "idx": idx, "kind": "trans2_secondary", "base": 0,
                    "tot": tot, "target_min": param + disp, "width": 2, "offset": 1
                })
                continue

    return defective


def repair_split(file_path: Path, seed: int = 42) -> int:
    print(f"Processing {file_path}...")
    bak_path = file_path.with_suffix(".json.bak")
    if not bak_path.exists():
        raise RuntimeError(f"Backup file {bak_path} does not exist! Aborting.")

    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    records = data["dataset"]
    rng = random.Random(seed)

    # 1. Snapshot attack records
    attack_hashes_before = []
    attack_count = 0
    for idx, r in enumerate(records):
        if r.get("is_attack", 0) == 1:
            attack_count += 1
            attack_hashes_before.append((idx, hashlib.sha256(r["buffers"].encode("latin1")).hexdigest()))

    # 2. Find defective benign records
    defective = find_all_defective_benign_records(records)
    print(f"  Found {len(defective)} defective benign records in {file_path.name}")

    # 3. Repair records
    repaired_indices = set()
    for item in defective:
        idx = item["idx"]
        offset = item["offset"]
        width = item["width"]
        target_min = item["target_min"]

        r = records[idx]
        raw = r["buffers"].encode("latin1")
        parts = raw.split(b"\x1e")
        assert len(parts) == 3, f"Unexpected parts len {len(parts)} at idx {idx}"
        assert parts[2] == b"", f"Unexpected parts[2] {parts[2]} at idx {idx}"

        pld = bytearray(parts[1])
        delta = rng.choice([0, 1, 2, 4])
        new_tot = target_min + delta

        if width == 2:
            new_tot_sanitized = sanitize_id_val(new_tot)
            if new_tot_sanitized < target_min:
                new_tot_sanitized = target_min + 1
                new_tot_sanitized = sanitize_id_val(new_tot_sanitized)
            new_bytes = struct.pack("<H", new_tot_sanitized)
        else:
            new_tot_sanitized = sanitize_int32(new_tot)
            if new_tot_sanitized < target_min:
                new_tot_sanitized = target_min + 1
                new_tot_sanitized = sanitize_int32(new_tot_sanitized)
            new_bytes = struct.pack("<I", new_tot_sanitized)

        assert b"\x1e" not in new_bytes, f"0x1E in new_bytes for {item}"

        for b_i in range(width):
            pld[offset + b_i] = new_bytes[b_i]

        new_raw = parts[0] + b"\x1e" + bytes(pld) + b"\x1e"
        assert new_raw.count(b"\x1e") == 2, f"Sanitization violated at idx {idx}: count={new_raw.count(b'\x1e')}"

        r["buffers"] = new_raw.decode("latin1")
        repaired_indices.add(idx)

    print(f"  Repaired {len(repaired_indices)} records.")

    # 4. Verify post-repair integrity
    defective_after = find_all_defective_benign_records(records)
    assert len(defective_after) == 0, f"Remaining defective records: {len(defective_after)}"
    print(f"  Post-repair benign underflow count: {len(defective_after)} (EXACTLY ZERO)")

    # Verify attack records unchanged
    attack_hashes_after = []
    for idx, r in enumerate(records):
        if r.get("is_attack", 0) == 1:
            attack_hashes_after.append((idx, hashlib.sha256(r["buffers"].encode("latin1")).hexdigest()))

    assert attack_hashes_before == attack_hashes_after, "Attack records were altered!"
    print(f"  All {attack_count} attack records verified 100% unaltered.")

    # 5. Write repaired split
    with file_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=True)
    print(f"  Successfully wrote repaired {file_path}")

    return len(repaired_indices)


def main():
    splits_dir = Path("ntlm-lab/shared/datasets/splits/skeleton_holdout")
    repaired_counts = {}
    for split_name in ["train", "val", "test"]:
        split_path = splits_dir / f"{split_name}.json"
        count = repair_split(split_path)
        repaired_counts[split_name] = count

    # Update manifest.json
    manifest_path = splits_dir / "manifest.json"
    if manifest_path.exists():
        with manifest_path.open("r", encoding="utf-8") as f:
            manifest = json.load(f)

        manifest["defect_remediation"] = {
            "status": "fully_remediated",
            "description": "Repaired all generator collision underflow and chunk overflow defects across chained and standalone transactions",
            "repaired_records": repaired_counts,
            "post_repair_benign_underflow_records": {s: 0 for s in repaired_counts},
            "attack_records_preserved_unaltered": True,
        }

        with manifest_path.open("w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=True)
        print(f"Successfully updated {manifest_path} with comprehensive verification metrics.")

    print("\nSummary of repaired records:")
    for split, count in repaired_counts.items():
        print(f"  {split}: {count} records repaired")


if __name__ == "__main__":
    main()
