#!/usr/bin/env python3
"""Generate leakage-resistant splits for the SMBv1 / NetBIOS CVE-2008-4834 dataset (Round 2 Hardened).

Produces:
1. Skeleton-Holdout Split:
   Unseen structural archetypes held out in validation and test with matched
   Unicode/ASCII and NT_TRANSACT/TRANS2 covariates across train, val, and test.
2. Stratified Split:
   Balanced 70/15/15 train/val/test split preserving the exact 2x2 matrix
   (is_attack x alerted x skeleton_id) proportions.
3. Attack-Holdout Split (Multi-Family Stratified Mutation Holdout v2):
   Zero-shot evasion holdouts across 40 orthogonal mutation classes with
   Negative-Feature Decoupling lookalike quarantine and Hare-Niemeyer apportionment.
4. Strict SHA-256 Buffer Deduplication:
   Ensures 0.00% duplicate buffer rate and 0 cross-split buffer_sha256 overlaps.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import copy
import hashlib
import json
import logging
from pathlib import Path
import random
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("create_smb_splits")

# ─── Attack Holdout Definitions ──────────────────────────────────────────

VAL_ATTACK_HOLDOUTS = {
    "alerted_andx_trans2_open2_asc_param_underflow",
    "alerted_andx_trans2_open2_uni_param_underflow",
    "evasion_offset39_nt_other_asc",
    "evasion_offset39_nt_other_uni",
    "evasion_offset39_trans2_other_asc",
    "evasion_offset39_trans2_other_uni",
    "evasion_standalone_nt_create_asc",
    "evasion_standalone_nt_create_uni",
    "evasion_standalone_trans2_open2_asc",
    "evasion_standalone_trans2_open2_uni",
}

TEST_ATTACK_HOLDOUTS = {
    "alerted_andx_nt_create_asc_param_underflow",
    "alerted_andx_nt_create_uni_param_underflow",
    "evasion_offset37_trans2_asc",
    "evasion_offset37_trans2_uni",
    "evasion_secondary_chunk_nt_asc",
    "evasion_secondary_chunk_nt_uni",
}


def find_all_defective_benign_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Locate all benign records with any underflow/chunk overflow defect."""
    defective = []
    for idx, r in enumerate(records):
        if r.get("is_attack", 0) == 1:
            continue
        raw = r.get("buffers", "").encode("latin1", errors="replace")
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
                        "tot": tot, "target_min": param, "width": 2, "offset": base + 1,
                    })
                    continue

        # 2. Standalone NT_TRANSACT (0xA0)
        if cmd == 0xA0 and len(pld) >= 24:
            tot = struct.unpack("<I", pld[4:8])[0]
            param = struct.unpack("<I", pld[20:24])[0]
            if tot < param:
                defective.append({
                    "idx": idx, "kind": "nt_transact", "base": 0,
                    "tot": tot, "target_min": param, "width": 4, "offset": 4,
                })
                continue

        # 3. Standalone TRANS2 (0x32)
        elif cmd == 0x32 and len(pld) >= 21:
            tot = struct.unpack("<H", pld[1:3])[0]
            param = struct.unpack("<H", pld[19:21])[0]
            if tot < param:
                defective.append({
                    "idx": idx, "kind": "standalone_trans2", "base": 0,
                    "tot": tot, "target_min": param, "width": 2, "offset": 1,
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
                    "tot": tot, "target_min": param + disp, "width": 4, "offset": 4,
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
                    "tot": tot, "target_min": param + disp, "width": 2, "offset": 1,
                })
                continue

    return defective


def extract_skeleton_id(r: Dict[str, Any]) -> str:
    """Extract fine-grained structural archetype identifier from packet metadata and endpoints."""
    meta = r.get("meta", {})
    cmd = str(meta.get("command", "")).lower()
    sec_cmd = str(meta.get("secondary_command", "")).lower()
    is_uni = "uni" if meta.get("is_unicode", False) else "asc"
    port_prefix = "nb139_" if ":139" in r.get("dst_ap", "") else ""

    if sec_cmd == "0xa0":
        return f"{port_prefix}chained_nt_{is_uni}"
    elif sec_cmd == "0x32":
        return f"{port_prefix}chained_trans2_{is_uni}"
    elif cmd == "0xa1" or sec_cmd == "0xa1":
        return f"{port_prefix}nt_secondary_{is_uni}"
    elif cmd == "0x33" or sec_cmd == "0x33":
        return f"{port_prefix}trans2_secondary_{is_uni}"
    elif cmd == "0xa0":
        func = str(meta.get("function", "")).lower()
        if func in ("0x2", "0x0002"):
            return f"{port_prefix}nt_ioctl_{is_uni}"
        elif func in ("0x3", "0x0003"):
            return f"{port_prefix}nt_set_sec_desc_{is_uni}"
        elif func in ("0x4", "0x0004"):
            return f"{port_prefix}nt_notify_change_{is_uni}"
        elif func in ("0x6", "0x0006"):
            return f"{port_prefix}nt_query_sec_{is_uni}"
        return f"{port_prefix}standalone_nt_{is_uni}"
    elif cmd == "0x32":
        subcmd = str(meta.get("subcommand", "")).lower()
        if subcmd in ("0x1", "0x0001"):
            return f"{port_prefix}trans2_find_first_{is_uni}"
        elif subcmd in ("0x2", "0x0002"):
            return f"{port_prefix}trans2_find_next_{is_uni}"
        elif subcmd in ("0x3", "0x0003"):
            return f"{port_prefix}trans2_query_fs_{is_uni}"
        elif subcmd in ("0x5", "0x0005"):
            return f"{port_prefix}trans2_query_path_{is_uni}"
        elif subcmd in ("0x7", "0x0007"):
            return f"{port_prefix}trans2_query_file_{is_uni}"
        return f"{port_prefix}standalone_trans2_{is_uni}"
    else:
        return f"{port_prefix}generic_{cmd}_{is_uni}"


def classify_smb_attack_record(r: Dict[str, Any]) -> str:
    """Deterministically map every SMBv1 attack record to its orthogonal mutation class."""
    alerted = r.get("alerted", 0)
    meta = r.get("meta", {})
    cmd = meta.get("command")
    sec = meta.get("secondary_command")
    andx = meta.get("andx_offset")
    fn = meta.get("function")
    sub = meta.get("subcommand")
    enc = "uni" if meta.get("is_unicode", False) else "asc"

    if alerted == 1:
        rules = r.get("attack_rules", [])
        assert len(rules) == 1, f"Expected 1 attack rule for alerted attack, got {rules}"
        sid = rules[0].split(":")[1]
        sid_map = {
            "15196": "alerted_nt_create_uni_param_underflow",
            "15199": "alerted_nt_create_asc_param_underflow",
            "15200": "alerted_andx_nt_create_uni_param_underflow",
            "15203": "alerted_andx_nt_create_asc_param_underflow",
            "15205": "alerted_nt_create_uni_max_param_underflow",
            "15206": "alerted_nt_create_asc_max_param_underflow",
            "15209": "alerted_andx_nt_create_uni_max_param_underflow",
            "15210": "alerted_andx_nt_create_asc_max_param_underflow",
            "15213": "alerted_trans2_open2_uni_max_param_underflow",
            "15214": "alerted_trans2_open2_asc_max_param_underflow",
            "15217": "alerted_andx_trans2_open2_uni_max_param_underflow",
            "15218": "alerted_andx_trans2_open2_asc_max_param_underflow",
            "15220": "alerted_trans2_open2_uni_param_underflow",
            "15221": "alerted_trans2_open2_asc_param_underflow",
            "15224": "alerted_andx_trans2_open2_uni_param_underflow",
            "15225": "alerted_andx_trans2_open2_asc_param_underflow",
        }
        return sid_map[sid]

    # FN Evasions (alerted == 0)
    if andx == 37:
        return f"evasion_offset37_nt_transact_{enc}" if sec == "0xa0" else f"evasion_offset37_trans2_{enc}"
    elif andx == 39:
        if sec == "0xa0":
            return f"evasion_offset39_nt_create_{enc}" if fn in ("0x1", "0x0001") else f"evasion_offset39_nt_other_{enc}"
        elif sec == "0x32":
            return f"evasion_offset39_trans2_open2_{enc}" if sub in ("0x0", "0x0000") else f"evasion_offset39_trans2_other_{enc}"

    if cmd in ("0xa1", "0x33") or sec in ("0xa1", "0x33"):
        return f"evasion_secondary_chunk_nt_{enc}" if (cmd == "0xa1" or sec == "0xa1") else f"evasion_secondary_chunk_trans2_{enc}"

    if cmd == "0xa0":
        return f"evasion_standalone_nt_create_{enc}" if fn in ("0x1", "0x0001") else f"evasion_standalone_nt_other_{enc}"
    elif cmd == "0x32":
        return f"evasion_standalone_trans2_open2_{enc}" if sub in ("0x0", "0x0000") else f"evasion_standalone_trans2_other_{enc}"

    raise ValueError(f"Unclassified attack record: {meta}")


def is_test_quarantined_lookalike(r: Dict[str, Any]) -> bool:
    """Quarantine lookalikes of Test held-out attacks out of Train into Test."""
    m = r.get("meta", {})
    # 1. Quarantine all nt_secondary (0xA1) so Train has zero 0xA1 benign records
    if m.get("command") == "0xa1" or "nt_secondary" in m.get("skeleton_id", ""):
        return True
    # 2. Quarantine all (sec_cmd=0x32, andx_offset=37) so Train has zero offset-37 Trans2 benign records
    if m.get("secondary_command") == "0x32" and m.get("andx_offset") == 37:
        return True
    return False


def deduplicate_by_buffer_hash(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove any exact buffer_sha256 duplicates to guarantee zero cross-split hash leakage."""
    seen = set()
    unique_records: List[Dict[str, Any]] = []
    for r in records:
        h = hashlib.sha256(r.get("buffers", "").encode("latin1", errors="replace")).hexdigest()
        if h not in seen:
            seen.add(h)
            unique_records.append(r)
    if len(unique_records) < len(records):
        logger.info("Deduplicated %d -> %d unique buffer records", len(records), len(unique_records))
    return unique_records


def compute_split_stats(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute dissertation 2x2 matrix and skeleton breakdown for split."""
    table = {
        "benign_clean": 0,    # is_attack=0, alerted=0
        "benign_fp": 0,       # is_attack=0, alerted=1
        "snort_alerted": 0,   # is_attack=1, alerted=1
        "snort_fn": 0,        # is_attack=1, alerted=0
    }
    skel_counts: Dict[str, int] = {}
    uni_count = 0
    for r in records:
        att = int(r.get("is_attack", 0))
        al = int(r.get("alerted", 0))
        if att == 0 and al == 0:
            table["benign_clean"] += 1
        elif att == 0 and al == 1:
            table["benign_fp"] += 1
        elif att == 1 and al == 1:
            table["snort_alerted"] += 1
        elif att == 1 and al == 0:
            table["snort_fn"] += 1

        meta = r.get("meta", {})
        if meta.get("is_unicode", False):
            uni_count += 1
        skel = meta.get("skeleton_id", "unknown")
        skel_counts[skel] = skel_counts.get(skel, 0) + 1

    total = len(records)
    total_att = table["snort_alerted"] + table["snort_fn"]
    total_ben = table["benign_clean"] + table["benign_fp"]

    return {
        "total_records": total,
        "cross_tabulation": table,
        "attack_recall_pct": round(table["snort_alerted"] / max(total_att, 1) * 100.0, 2),
        "snort_fn_rate_pct": round(table["snort_fn"] / max(total_att, 1) * 100.0, 2),
        "benign_fpr_pct": round(table["benign_fp"] / max(total_ben, 1) * 100.0, 4),
        "unicode_ratio_pct": round(uni_count / max(total, 1) * 100.0, 2),
        "skeleton_distribution": skel_counts,
    }


def save_split_bundle(
    output_dir: Path,
    split_name: str,
    train_records: List[Dict[str, Any]],
    val_records: List[Dict[str, Any]],
    test_records: List[Dict[str, Any]],
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Save train.json, val.json, test.json, and manifest.json."""
    bundle_dir = output_dir / split_name
    bundle_dir.mkdir(parents=True, exist_ok=True)

    splits_data = {
        "train": train_records,
        "val": val_records,
        "test": test_records,
    }

    manifest: Dict[str, Any] = {
        "split_strategy": split_name,
        "summary": {},
    }
    if extra_metadata:
        manifest.update(extra_metadata)

    for s_name, records in splits_data.items():
        stats = compute_split_stats(records)
        manifest["summary"][s_name] = stats

        payload = {
            "dataset": records,
            "metadata": {
                "split": s_name,
                "strategy": split_name,
                **stats,
            },
        }
        out_file = bundle_dir / f"{s_name}.json"
        with out_file.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        logger.info(
            "Saved %s/%s.json (%d records, Unicode=%.1f%%)",
            split_name, s_name, len(records), stats["unicode_ratio_pct"],
        )

    manifest_file = bundle_dir / "manifest.json"
    with manifest_file.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    logger.info("Saved %s/manifest.json", split_name)


def generate_stratified_split(
    records: List[Dict[str, Any]],
    seed: int = 42,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Stratified 70/15/15 split grouped by (is_attack, alerted, skeleton_id)."""
    rng = random.Random(seed)
    bins: Dict[Tuple[int, int, str], List[Dict[str, Any]]] = {}

    for r in records:
        key = (
            int(r.get("is_attack", 0)),
            int(r.get("alerted", 0)),
            r.get("meta", {}).get("skeleton_id", "unknown"),
        )
        bins.setdefault(key, []).append(r)

    train_recs: List[Dict[str, Any]] = []
    val_recs: List[Dict[str, Any]] = []
    test_recs: List[Dict[str, Any]] = []

    for _, group in bins.items():
        shuffled = list(group)
        rng.shuffle(shuffled)
        n = len(shuffled)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)
        train_recs.extend(shuffled[:n_train])
        val_recs.extend(shuffled[n_train : n_train + n_val])
        test_recs.extend(shuffled[n_train + n_val :])

    rng.shuffle(train_recs)
    rng.shuffle(val_recs)
    rng.shuffle(test_recs)
    return train_recs, val_recs, test_recs


def generate_skeleton_holdout_split(
    records: List[Dict[str, Any]],
    seed: int = 42,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Skeleton-Holdout split reserving balanced Unicode/ASCII and NT/Trans2 archetypes for val and test."""
    rng = random.Random(seed)

    skel_groups: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        s_id = r.get("meta", {}).get("skeleton_id", "unknown")
        skel_groups.setdefault(s_id, []).append(r)

    logger.info("Found %d distinct skeleton archetypes across cohort", len(skel_groups))

    # Covariate-matched structural holdout assignments:
    val_holdouts = {
        # Port 445
        "nt_ioctl_uni",
        "nt_query_sec_asc",
        "chained_nt_uni",
        "trans2_find_next_asc",
        "trans2_query_file_uni",
        # Port 139
        "nb139_nt_set_sec_desc_asc",
        "nb139_nt_secondary_uni",
        "nb139_standalone_trans2_asc",
        "nb139_trans2_query_fs_uni",
        "nb139_chained_trans2_asc",
    }
    test_holdouts = {
        # Port 445
        "nt_set_sec_desc_asc",
        "nt_secondary_uni",
        "trans2_query_fs_asc",
        "trans2_query_path_uni",
        "chained_trans2_asc",
        # Port 139
        "nb139_nt_ioctl_asc",
        "nb139_nt_query_sec_uni",
        "nb139_chained_nt_uni",
        "nb139_trans2_find_next_uni",
        "nb139_trans2_query_file_asc",
    }

    available_skeletons = sorted(skel_groups.keys())
    actual_val_holdouts = [s for s in available_skeletons if s in val_holdouts]
    actual_test_holdouts = [s for s in available_skeletons if s in test_holdouts]
    remaining = [s for s in available_skeletons if s not in actual_val_holdouts and s not in actual_test_holdouts]

    train_recs: List[Dict[str, Any]] = []
    val_recs: List[Dict[str, Any]] = []
    test_recs: List[Dict[str, Any]] = []

    for s in remaining:
        train_recs.extend(skel_groups[s])
    for s in actual_val_holdouts:
        val_recs.extend(skel_groups[s])
    for s in actual_test_holdouts:
        test_recs.extend(skel_groups[s])

    rng.shuffle(train_recs)
    rng.shuffle(val_recs)
    rng.shuffle(test_recs)

    holdout_meta = {
        "train_skeletons": remaining,
        "val_holdout_skeletons": actual_val_holdouts,
        "test_holdout_skeletons": actual_test_holdouts,
    }
    return train_recs, val_recs, test_recs, holdout_meta


def generate_attack_holdout_split(
    records: List[Dict[str, Any]],
    seed: int = 42,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    """Generate Stratified Multi-Family Attack / Mutation Holdout Split (v2) with Lookalike Decoupling."""
    rng = random.Random(seed)

    benign_records = [r for r in records if r.get("is_attack", 0) == 0]
    attack_records = [r for r in records if r.get("is_attack", 0) == 1]
    assert len(benign_records) == 150000, f"Expected 150000 benign records, got {len(benign_records)}"
    assert len(attack_records) == 15000, f"Expected 15000 attack records, got {len(attack_records)}"

    splits: Dict[str, List[Dict[str, Any]]] = {"train": [], "val": [], "test": []}

    # 1. Route attack traffic strictly by attack_type
    for r in attack_records:
        atk_type = classify_smb_attack_record(r)
        rc = copy.deepcopy(r)
        rc["attack_type"] = atk_type
        if atk_type in TEST_ATTACK_HOLDOUTS:
            splits["test"].append(rc)
        elif atk_type in VAL_ATTACK_HOLDOUTS:
            splits["val"].append(rc)
        else:
            splits["train"].append(rc)

    n_att = {k: len(v) for k, v in splits.items()}
    assert n_att["train"] == 9128 and n_att["val"] == 2831 and n_att["test"] == 3041, (
        f"Unexpected attack allocations: {n_att}"
    )

    # 2. Quarantine lookalikes out of Train exclusively into Test
    test_quarantined = []
    neutral_benign = []
    for r in benign_records:
        if is_test_quarantined_lookalike(r):
            test_quarantined.append(r)
        else:
            neutral_benign.append(r)

    assert len(test_quarantined) == 18917, f"Expected 18917 quarantined benign, got {len(test_quarantined)}"
    splits["test"].extend([copy.deepcopy(r) for r in test_quarantined])

    # 3. Exact class prior invariance (10 benign per 1 attack: pi_p = 1/11 = 0.090909...)
    TARGET_BENIGN = {"train": n_att["train"] * 10, "val": n_att["val"] * 10, "test": n_att["test"] * 10}
    test_neutral_needed = TARGET_BENIGN["test"] - len(test_quarantined)
    val_neutral_needed = TARGET_BENIGN["val"]
    train_neutral_needed = TARGET_BENIGN["train"]

    assert val_neutral_needed + test_neutral_needed + train_neutral_needed == len(neutral_benign), (
        f"Neutral benign count mismatch: {len(neutral_benign)} vs needed {val_neutral_needed + test_neutral_needed + train_neutral_needed}"
    )

    # 4. Hare-Niemeyer apportionment of neutral records across available skeletons
    by_skel = defaultdict(list)
    for r in neutral_benign:
        by_skel[r.get("meta", {}).get("skeleton_id", "unknown")].append(r)

    skel_keys = sorted(by_skel.keys())
    total_neutral = len(neutral_benign)

    def hare_niemeyer(target_count: int) -> Dict[str, int]:
        quotas = {sk: len(by_skel[sk]) * target_count / total_neutral for sk in skel_keys}
        alloc = {sk: int(quotas[sk]) for sk in skel_keys}
        rem = sorted(skel_keys, key=lambda sk: (quotas[sk] - alloc[sk], sk), reverse=True)
        diff = target_count - sum(alloc.values())
        for i in range(diff):
            alloc[rem[i]] += 1
        return alloc

    val_alloc = hare_niemeyer(val_neutral_needed)
    test_alloc = hare_niemeyer(test_neutral_needed)

    for sk in skel_keys:
        sk_recs = list(by_skel[sk])
        rng.shuffle(sk_recs)
        nv = val_alloc[sk]
        nt = test_alloc[sk]
        splits["val"].extend([copy.deepcopy(r) for r in sk_recs[:nv]])
        splits["test"].extend([copy.deepcopy(r) for r in sk_recs[nv : nv + nt]])
        splits["train"].extend([copy.deepcopy(r) for r in sk_recs[nv + nt :]])

    # Verify counts
    assert len(splits["train"]) == 100408, f"Expected 100408 train records, got {len(splits['train'])}"
    assert len(splits["val"]) == 31141, f"Expected 31141 val records, got {len(splits['val'])}"
    assert len(splits["test"]) == 33451, f"Expected 33451 test records, got {len(splits['test'])}"

    # 5. Shuffling each split
    for s_name in ["train", "val", "test"]:
        rng.shuffle(splits[s_name])

    # 6. Gate 4 Invariant Verifications
    # Zero cross-split hash overlaps
    h_tr = set(hashlib.sha256(r["buffers"].encode("latin1")).hexdigest() for r in splits["train"])
    h_v = set(hashlib.sha256(r["buffers"].encode("latin1")).hexdigest() for r in splits["val"])
    h_ts = set(hashlib.sha256(r["buffers"].encode("latin1")).hexdigest() for r in splits["test"])
    assert not h_tr.intersection(h_v), "Gate 4 Violation: Train and Val share buffer hashes!"
    assert not h_tr.intersection(h_ts), "Gate 4 Violation: Train and Test share buffer hashes!"
    assert not h_v.intersection(h_ts), "Gate 4 Violation: Val and Test share buffer hashes!"

    # Negative-Feature Decoupling Invariant Check on Train
    train_ben = [r for r in splits["train"] if r.get("is_attack", 0) == 0]
    train_att = [r for r in splits["train"] if r.get("is_attack", 0) == 1]

    # Assert zero 0xA1 records in Train
    assert sum(1 for r in train_ben if r.get("meta", {}).get("command") == "0xa1") == 0, (
        "Negative Feature Trap: Train contains command 0xA1 benign records!"
    )
    # Assert zero (sec_cmd=0x32, andx_offset=37) records in Train
    assert sum(1 for r in train_ben if r.get("meta", {}).get("secondary_command") == "0x32" and r.get("meta", {}).get("andx_offset") == 37) == 0, (
        "Negative Feature Trap: Train contains (0x32, 37) benign records!"
    )

    # Assert every active skeleton in Train benign has > 0 attacks
    tr_ben_skels = set(r.get("meta", {}).get("skeleton_id") for r in train_ben)
    tr_att_skels = set(r.get("meta", {}).get("skeleton_id") for r in train_att)
    empty_skels = tr_ben_skels - tr_att_skels
    assert not empty_skels, f"Negative Feature Trap: empty skeletons in train: {empty_skels}"

    manifest_meta = {
        "split_type": "attack-mutation-holdout",
        "split_version": "smb_attack_holdout_v2",
        "seed": seed,
        "total_records": len(records),
        "held_out_attack_types": {
            "val": sorted(list(VAL_ATTACK_HOLDOUTS)),
            "test": sorted(list(TEST_ATTACK_HOLDOUTS)),
        },
        "quarantined_lookalike_patterns": {
            "test": [
                "command == 0xa1 (nt_secondary)",
                "secondary_command == 0x32 and andx_offset == 37",
            ]
        },
        "split_summary": {
            s: {
                "total": len(splits[s]),
                "benign": sum(1 for r in splits[s] if r.get("is_attack", 0) == 0),
                "attack": sum(1 for r in splits[s] if r.get("is_attack", 0) == 1),
                "alerted": sum(1 for r in splits[s] if r.get("is_attack", 0) == 1 and r.get("alerted", 0) == 1),
                "snort_fn": sum(1 for r in splits[s] if r.get("is_attack", 0) == 1 and r.get("alerted", 0) == 0),
                "pi_p": round(sum(1 for r in splits[s] if r.get("is_attack", 0) == 1) / len(splits[s]), 5),
            }
            for s in ["train", "val", "test"]
        },
        "negative_feature_decoupling_verification": {
            "empty_train_skeletons": 0,
            "train_cmd_0xa1_leaks": 0,
            "train_offset37_trans2_leaks": 0,
            "status": "PASS",
        },
        "gate_4_verification": {
            "raw_hash_cross_split_overlap": 0,
            "prior_pi_p": {
                "train": round(sum(1 for r in splits["train"] if r.get("is_attack", 0) == 1) / len(splits["train"]), 5),
                "val": round(sum(1 for r in splits["val"] if r.get("is_attack", 0) == 1) / len(splits["val"]), 5),
                "test": round(sum(1 for r in splits["test"] if r.get("is_attack", 0) == 1) / len(splits["test"]), 5),
            },
            "status": "PASS",
        },
    }

    return splits["train"], splits["val"], splits["test"], manifest_meta


def load_input_records(
    input_path: Path,
    source_repaired_dir: Optional[Path] = None,
    strategy: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Load dataset records, prioritizing clean repaired splits for attack_holdout."""
    # When generating attack_holdout, if source_repaired_dir is available, source from it
    if strategy == "attack_holdout" and source_repaired_dir and source_repaired_dir.is_dir():
        logger.info("Sourcing clean repaired dataset records from directory: %s", source_repaired_dir)
        records = []
        for s_name in ["train", "val", "test"]:
            p = source_repaired_dir / f"{s_name}.json"
            if not p.exists():
                raise FileNotFoundError(f"Missing repaired split file: {p}")
            with p.open("r", encoding="utf-8") as f:
                d = json.load(f)
            s_recs = d.get("dataset", [])
            records.extend(s_recs)
            logger.info("  Loaded %d records from %s", len(s_recs), p.name)
        return records

    # If input_path is a directory, load all split json files
    if input_path.is_dir():
        logger.info("Loading records from directory: %s", input_path)
        records = []
        for s_name in ["train", "val", "test"]:
            p = input_path / f"{s_name}.json"
            if not p.exists():
                raise FileNotFoundError(f"Missing split file: {p}")
            with p.open("r", encoding="utf-8") as f:
                d = json.load(f)
            records.extend(d.get("dataset", []))
        return records

    # Otherwise load single file
    logger.info("Loading records from file: %s", input_path)
    with input_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("dataset", [])


def main() -> None:
    parser = argparse.ArgumentParser(description="Create leakage-resistant splits for SMBv1 dataset")
    parser.add_argument(
        "-i", "--input",
        type=Path,
        default=Path("/home/vhorbato/Academy/ntlm-lab/shared/datasets/combined_basic.json"),
        help="Input combined JSON dataset or splits directory",
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=Path,
        default=Path("/home/vhorbato/Academy/ntlm-lab/shared/datasets/splits"),
        help="Output splits directory",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument(
        "--strategy", "--only-strategy",
        dest="strategy",
        type=str,
        default=None,
        choices=["all", "skeleton_holdout", "stratified", "attack_holdout"],
        help="Generate only the specified strategy (default: all)",
    )
    parser.add_argument(
        "--source-repaired-splits",
        type=Path,
        default=Path("/home/vhorbato/Academy/ntlm-lab/shared/datasets/splits/skeleton_holdout"),
        help="Directory of repaired splits (train.json, val.json, test.json) to source from",
    )
    args = parser.parse_args()

    raw_records = load_input_records(
        args.input,
        source_repaired_dir=args.source_repaired_splits,
        strategy=args.strategy,
    )
    logger.info("Loaded %d raw records", len(raw_records))

    records = deduplicate_by_buffer_hash(raw_records)

    for r in records:
        if "meta" not in r:
            r["meta"] = {}
        if "skeleton_id" not in r["meta"]:
            r["meta"]["skeleton_id"] = extract_skeleton_id(r)

    # Defect audit check
    defective = find_all_defective_benign_records(records)
    if defective:
        if args.strategy == "attack_holdout":
            raise ValueError(
                f"Found {len(defective)} defective benign records in input dataset! "
                "Attack holdout split requires 0 defective benign records. "
                "Source from repaired skeleton_holdout splits or run repair_smb_splits.py."
            )
        else:
            logger.warning("Found %d defective benign records in input dataset.", len(defective))
    else:
        logger.info("Defect audit: exactly 0 defective benign records verified.")

    # Only resave input if it was a file and we are running full pipeline
    if args.input.is_file() and args.strategy in (None, "all"):
        with args.input.open("r", encoding="utf-8") as f:
            data = json.load(f)
        data["dataset"] = records
        data.setdefault("metadata", {})["total_records"] = len(records)
        with args.input.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    strategies_to_run = (
        [args.strategy] if args.strategy and args.strategy != "all"
        else ["skeleton_holdout", "stratified", "attack_holdout"]
    )

    results_summary = {}

    # 1. Generate Skeleton-Holdout Split
    if "skeleton_holdout" in strategies_to_run:
        tr_h, val_h, ts_h, holdout_meta = generate_skeleton_holdout_split(records, seed=args.seed)
        save_split_bundle(
            args.output_dir,
            "skeleton_holdout",
            tr_h, val_h, ts_h,
            extra_metadata=holdout_meta,
        )
        results_summary["skeleton_holdout"] = (len(tr_h), len(val_h), len(ts_h))

    # 2. Generate Stratified Split
    if "stratified" in strategies_to_run:
        tr_s, val_s, ts_s = generate_stratified_split(records, seed=args.seed)
        save_split_bundle(
            args.output_dir,
            "stratified",
            tr_s, val_s, ts_s,
        )
        results_summary["stratified"] = (len(tr_s), len(val_s), len(ts_s))

    # 3. Generate Attack-Holdout Split
    if "attack_holdout" in strategies_to_run:
        tr_a, val_a, ts_a, attack_meta = generate_attack_holdout_split(records, seed=args.seed)
        save_split_bundle(
            args.output_dir,
            "attack_holdout",
            tr_a, val_a, ts_a,
            extra_metadata=attack_meta,
        )
        results_summary["attack_holdout"] = (len(tr_a), len(val_a), len(ts_a))

    print("\n" + "=" * 65)
    print(" SMBv1 DATASET SPLIT GENERATION SUMMARY")
    print(f" Output Splits Directory: {args.output_dir}")
    print("-" * 65)
    for strat, (ntr, nval, nts) in results_summary.items():
        print(f" {strat:<18}: Train={ntr:<6}, Val={nval:<6}, Test={nts:<6} (Total={ntr+nval+nts})")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
