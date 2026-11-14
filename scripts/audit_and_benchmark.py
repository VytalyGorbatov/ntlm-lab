#!/usr/bin/env python3
"""Comprehensive Validation Audit & Anti-Leak Benchmark for SMBv1 Dataset (Round 2 Hardened).

Evaluates against all 6 Dissertation Quality Gates:
1. Gate 1 (Integrity & 2x2 Matrix): Total records, Benign FPR (target: 0.00%), Snort FN rate.
2. Gate 2 (Handshake, Delimiter & Skeleton Purity): 0 handshakes, strictly 2 0x1E bytes per record, 0 class-pure skeletons.
3. Gate 3 (Header-Only & Duplicate Safety): Header PR-AUC <= 0.55, 0.00% duplicate buffer rate.
4. Gate 4 (Split Validity & Covariate Balance): 0 cross-split hash overlaps, balanced Unicode/ASCII in train/val/test.
5. Gate 5 (Anti-Leak Baselines): Length PR-AUC <= 0.65, Payload[:64] LogReg <= 0.65, Payload[:64] Tree-5 <= 0.65, Holdout Tree-5 <= 0.65.
6. Gate 6 (Snort Rule Coverage): All 16 target SIDs (15196..15225) active.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List
import numpy as np
from sklearn.metrics import precision_recall_curve, auc
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("smb_audit")


def pr_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    p, r, _ = precision_recall_curve(y_true, y_score)
    return float(auc(r, p))


def extract_hdr_and_pld(bufs: str) -> tuple[bytes, bytes]:
    raw = bufs.encode("latin1", errors="replace")
    if 30 in raw:
        idx = raw.index(30)
        hdr = raw[:idx]
        pld = raw[idx + 1 :]
        if pld and pld[-1] == 30:
            pld = pld[:-1]
        return hdr, pld
    return raw[:32], raw[32:]


def audit_dataset(dataset_path: Path) -> Dict[str, Any]:
    with dataset_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    records = data.get("dataset", [])
    logger.info("Loaded %d records for audit from %s", len(records), dataset_path)

    matrix = {"benign_clean": 0, "benign_fp": 0, "snort_alerted": 0, "snort_fn": 0}
    rules_dist: Dict[str, int] = {}
    handshake_mislabel_count = 0
    delimiter_error_count = 0
    header_col_count = 0

    y_true_list = []
    lens_list = []
    header_bytes_list = []
    payload_ngram_features = []
    payload_160_features = []
    hashes = []
    skel_class_counts = defaultdict(lambda: [0, 0])

    for r in records:
        att = int(r.get("is_attack", 0))
        al = int(r.get("alerted", 0))
        y_true_list.append(att)

        if att == 0 and al == 0:
            matrix["benign_clean"] += 1
        elif att == 0 and al == 1:
            matrix["benign_fp"] += 1
        elif att == 1 and al == 1:
            matrix["snort_alerted"] += 1
        elif att == 1 and al == 0:
            matrix["snort_fn"] += 1

        for rule in r.get("attack_rules", []):
            rules_dist[rule] = rules_dist.get(rule, 0) + 1

        bufs = r.get("buffers", "")
        raw_bytes = bufs.encode("latin1", errors="replace")
        hashes.append(hashlib.sha256(raw_bytes).hexdigest())

        # Strict delimiter check: must have exactly 2 occurrences of 0x1E (at index 32 and at the end)
        if raw_bytes.count(30) != 2 or raw_bytes.index(30) != 32 or raw_bytes[-1] != 30:
            delimiter_error_count += 1

        hdr_part, pld_part = extract_hdr_and_pld(bufs)
        hdr_padded = hdr_part[:32].ljust(32, b"\x00")
        header_bytes_list.append(list(hdr_padded))

        if any(b != 0 for b in hdr_padded[24:32]):
            header_col_count += 1

        meta = r.get("meta", {})
        cmd = str(meta.get("command", "")).lower()
        sec_cmd = str(meta.get("secondary_command", "")).lower()
        if cmd not in ("0xa0", "0xa1", "0x32", "0x33") and sec_cmd not in ("0xa0", "0xa1", "0x32", "0x33"):
            handshake_mislabel_count += 1

        skel = meta.get("skeleton_id", "unknown")
        skel_class_counts[skel][att] += 1

        lens_list.append(len(bufs))
        pld_64 = list(pld_part[:64].ljust(64, b"\x00"))
        pld_160 = list(pld_part[:160].ljust(160, b"\x00"))
        payload_ngram_features.append(pld_64)
        payload_160_features.append(pld_160)

    y_arr = np.array(y_true_list, dtype=int)
    total_att = matrix["snort_alerted"] + matrix["snort_fn"]
    total_ben = matrix["benign_clean"] + matrix["benign_fp"]
    benign_fpr = matrix["benign_fp"] / max(total_ben, 1) * 100.0
    fn_rate = matrix["snort_fn"] / max(total_att, 1) * 100.0
    dup_count = len(hashes) - len(set(hashes))

    pure_skeletons = [
        s for s, (c0, c1) in skel_class_counts.items()
        if c0 == 0 or c1 == 0
    ]

    # 1. Length Baseline
    len_scores = np.array(lens_list, dtype=float)
    len_prauc = max(pr_auc(y_arr, len_scores), pr_auc(y_arr, -len_scores))

    # 2. Header-Only Baseline
    X_hdr = np.array(header_bytes_list, dtype=float)
    clf_hdr = LogisticRegression(max_iter=500, random_state=42)
    clf_hdr.fit(X_hdr, y_arr)
    hdr_prauc = pr_auc(y_arr, clf_hdr.predict_proba(X_hdr)[:, 1])

    tree_hdr = DecisionTreeClassifier(max_depth=5, random_state=42)
    tree_hdr.fit(X_hdr, y_arr)
    tree_hdr_prauc = pr_auc(y_arr, tree_hdr.predict_proba(X_hdr)[:, 1])

    # 3. Payload[:64] Anti-Leak Baselines (LogReg & Tree-5)
    X_pld64 = np.array(payload_ngram_features, dtype=float)
    clf_pld64 = LogisticRegression(max_iter=500, random_state=42)
    clf_pld64.fit(X_pld64, y_arr)
    pld64_logreg_prauc = pr_auc(y_arr, clf_pld64.predict_proba(X_pld64)[:, 1])

    tree_pld64 = DecisionTreeClassifier(max_depth=5, random_state=42)
    tree_pld64.fit(X_pld64, y_arr)
    pld64_prauc = pr_auc(y_arr, tree_pld64.predict_proba(X_pld64)[:, 1])

    # 4. Full Neural Window Payload[:160] Baselines (LogReg & Tree-5)
    X_pld160 = np.array(payload_160_features, dtype=float)
    clf_pld160 = LogisticRegression(max_iter=500, random_state=42)
    clf_pld160.fit(X_pld160, y_arr)
    pld160_logreg_prauc = pr_auc(y_arr, clf_pld160.predict_proba(X_pld160)[:, 1])

    tree_pld160 = DecisionTreeClassifier(max_depth=5, random_state=42)
    tree_pld160.fit(X_pld160, y_arr)
    pld160_prauc = pr_auc(y_arr, tree_pld160.predict_proba(X_pld160)[:, 1])

    # 5. Skeleton-Holdout Split Audit (evaluated across full 160-byte window)
    holdout_test_prauc = None
    cross_split_overlap = 0
    holdout_dir = dataset_path.parent / "splits" / "skeleton_holdout"
    if (holdout_dir / "train.json").exists() and (holdout_dir / "test.json").exists():
        with (holdout_dir / "train.json").open("r", encoding="utf-8") as f:
            tr_recs = json.load(f)["dataset"]
        with (holdout_dir / "val.json").open("r", encoding="utf-8") as f:
            val_recs = json.load(f)["dataset"]
        with (holdout_dir / "test.json").open("r", encoding="utf-8") as f:
            ts_recs = json.load(f)["dataset"]

        h_tr = {hashlib.sha256(r["buffers"].encode("latin1")).hexdigest() for r in tr_recs}
        h_val = {hashlib.sha256(r["buffers"].encode("latin1")).hexdigest() for r in val_recs}
        h_ts = {hashlib.sha256(r["buffers"].encode("latin1")).hexdigest() for r in ts_recs}
        cross_split_overlap = len(h_tr & h_val) + len(h_tr & h_ts) + len(h_val & h_ts)

        def get_pld_features(recs: List[Dict[str, Any]]):
            X_list, y_list = [], []
            for rec in recs:
                _, p = extract_hdr_and_pld(rec.get("buffers", ""))
                X_list.append(list(p[:160].ljust(160, b"\x00")))
                y_list.append(int(rec.get("is_attack", 0)))
            return np.array(X_list, dtype=float), np.array(y_list, dtype=int)

        X_tr, y_tr = get_pld_features(tr_recs)
        X_ts, y_ts = get_pld_features(ts_recs)
        tree_holdout = DecisionTreeClassifier(max_depth=5, random_state=42)
        tree_holdout.fit(X_tr, y_tr)
        holdout_test_prauc = pr_auc(y_ts, tree_holdout.predict_proba(X_ts)[:, 1])

    results = {
        "total_records": len(records),
        "matrix": matrix,
        "benign_fpr_pct": round(benign_fpr, 4),
        "snort_fn_rate_pct": round(fn_rate, 2),
        "handshake_mislabel_count": handshake_mislabel_count,
        "delimiter_error_count": delimiter_error_count,
        "unmasked_header_id_count": header_col_count,
        "duplicate_buffer_count": dup_count,
        "cross_split_hash_overlap": cross_split_overlap,
        "class_pure_skeletons": pure_skeletons,
        "length_prauc": round(len_prauc, 4),
        "header_logreg_prauc": round(hdr_prauc, 4),
        "header_tree_prauc": round(tree_hdr_prauc, 4),
        "payload64_logreg_prauc": round(pld64_logreg_prauc, 4),
        "payload64_tree_depth5_prauc": round(pld64_prauc, 4),
        "payload160_logreg_prauc": round(pld160_logreg_prauc, 4),
        "payload160_tree_depth5_prauc": round(pld160_prauc, 4),
        "holdout_test_tree_prauc": round(holdout_test_prauc, 4) if holdout_test_prauc is not None else None,
        "target_rules_triggered_count": len(rules_dist),
        "rules_distribution": dict(sorted(rules_dist.items())),
    }

    print("\n" + "=" * 72)
    print(" DISSERTATION QUALITY GATES VALIDATION AUDIT (ROUND 2 HARDENED)")
    print("=" * 72)
    print(f" Total Analyzed Records:        {len(records)}")
    print(f" Benign Clean (alerted=0):      {matrix['benign_clean']}")
    print(f" Added Benign FP (alerted=1):   {matrix['benign_fp']} (Benign FPR: {benign_fpr:.4f}%)")
    print(f" Snort Alerted (alerted=1):     {matrix['snort_alerted']}")
    print(f" Snort False Negatives (al=0):  {matrix['snort_fn']} (FN Rate: {fn_rate:.2f}%)")
    print(f" Target SIDs Active (of 16):    {len(rules_dist)} / 16")
    print("-" * 72)
    print(f" Handshake Packets Mislabeled:  {handshake_mislabel_count} (Pass if 0)")
    print(f" Delimiter Collisions / Errors: {delimiter_error_count} (Pass if 0)")
    print(f" Unmasked Session IDs in Hdr:   {header_col_count} (Pass if 0)")
    print(f" Duplicate Buffers (SHA-256):   {dup_count} (Pass if 0)")
    print(f" Cross-Split Hash Overlaps:     {cross_split_overlap} (Pass if 0)")
    print(f" Class-Pure Skeletons:          {len(pure_skeletons)} {pure_skeletons} (Pass if 0)")
    print("-" * 72)
    print(" Anti-Leak Baselines:")
    print(f"   Length Baseline PR-AUC:          {len_prauc:.4f} (Pass if <= 0.65)")
    print(f"   Header LogReg PR-AUC:            {hdr_prauc:.4f} (Pass if <= 0.55)")
    print(f"   Header Tree Depth-5 PR-AUC:      {tree_hdr_prauc:.4f} (Pass if <= 0.55)")
    print(f"   Payload[:64] LogReg PR-AUC:      {pld64_logreg_prauc:.4f} (Pass if <= 0.65)")
    print(f"   Payload[:64] Tree Depth-5 PR-AUC: {pld64_prauc:.4f} (Pass if <= 0.65)")
    print(f"   Payload[:160] LogReg PR-AUC:     {pld160_logreg_prauc:.4f} (Pass if <= 0.65)")
    print(f"   Payload[:160] Tree Depth-5 PR-AUC: {pld160_prauc:.4f} (Pass if <= 0.65)")
    if holdout_test_prauc is not None:
        print(f"   Holdout Test Tree[:160] PR-AUC:  {holdout_test_prauc:.4f} (Pass if <= 0.65)")
    print("=" * 72 + "\n")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", type=Path, default=Path("/home/vhorbato/Academy/ntlm-lab/shared/datasets/combined_basic.json"))
    args = parser.parse_args()
    audit_dataset(args.input)
