#!/usr/bin/env python3
"""Gate 5 (Anti-Leak Baselines & Hardness Verification) Evaluation Script
for SMBv1 / NTLM Attack Holdout Split (train.json, val.json, test.json).
"""
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import auc, precision_recall_curve, roc_auc_score
from sklearn.tree import DecisionTreeClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("gate5_benchmarker")

SPLITS_DIR = Path("/home/vhorbato/Academy/ntlm-lab/shared/datasets/splits/attack_holdout")


def pr_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    p, r, _ = precision_recall_curve(y_true, y_score)
    return float(auc(r, p))


def roc_auc(y_true: np.ndarray, y_score: np.ndarray) -> float:
    try:
        return float(roc_auc_score(y_true, y_score))
    except Exception:
        return 0.5


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


def load_dataset(split_name: str) -> List[Dict[str, Any]]:
    p = SPLITS_DIR / f"{split_name}.json"
    logger.info("Loading %s from %s ...", split_name, p)
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    recs = data.get("dataset", [])
    logger.info("Loaded %s: %d records.", split_name, len(recs))
    return recs


def main():
    splits_data = {s: load_dataset(s) for s in ["train", "val", "test"]}
    y_true = {s: np.array([int(r.get("is_attack", 0)) for r in splits_data[s]], dtype=int) for s in splits_data}

    for s in ["train", "val", "test"]:
        prior = float(np.mean(y_true[s]))
        logger.info("%s set: N=%d, attacks=%d, prior pi_p=%.6f", s, len(y_true[s]), np.sum(y_true[s]), prior)

    results = {}

    # =========================================================================
    # Baseline 1: Packet Length Baseline
    # =========================================================================
    logger.info("Evaluating Baseline 1: Packet Length Baseline ...")
    # Features: total buffer length, payload length, header length
    def extract_len_features(recs: List[Dict[str, Any]]) -> np.ndarray:
        feats = []
        for r in recs:
            bufs = r.get("buffers", "")
            hdr, pld = extract_hdr_and_pld(bufs)
            tot_len = len(bufs)
            pld_len = len(pld)
            hdr_len = len(hdr)
            feats.append([tot_len, pld_len, hdr_len])
        return np.array(feats, dtype=float)

    X_len_tr = extract_len_features(splits_data["train"])
    X_len_val = extract_len_features(splits_data["val"])
    X_len_ts = extract_len_features(splits_data["test"])

    # Logistic Regression on [total_len, payload_len, hdr_len]
    clf_len = LogisticRegression(max_iter=1000, random_state=42)
    clf_len.fit(X_len_tr, y_true["train"])
    prob_len_tr = clf_len.predict_proba(X_len_tr)[:, 1]
    prob_len_val = clf_len.predict_proba(X_len_val)[:, 1]
    prob_len_ts = clf_len.predict_proba(X_len_ts)[:, 1]

    # Also single total_len direction check
    raw_len_val = X_len_val[:, 0]
    raw_len_ts = X_len_ts[:, 0]
    raw_len_val_prauc = max(pr_auc(y_true["val"], raw_len_val), pr_auc(y_true["val"], -raw_len_val))
    raw_len_ts_prauc = max(pr_auc(y_true["test"], raw_len_ts), pr_auc(y_true["test"], -raw_len_ts))

    results["Packet Length (LogReg: total, pld, hdr)"] = {
        "train_pr": pr_auc(y_true["train"], prob_len_tr),
        "train_roc": roc_auc(y_true["train"], prob_len_tr),
        "val_pr": pr_auc(y_true["val"], prob_len_val),
        "val_roc": roc_auc(y_true["val"], prob_len_val),
        "test_pr": pr_auc(y_true["test"], prob_len_ts),
        "test_roc": roc_auc(y_true["test"], prob_len_ts),
    }
    results["Packet Length (Univariate raw direction)"] = {
        "train_pr": max(pr_auc(y_true["train"], X_len_tr[:, 0]), pr_auc(y_true["train"], -X_len_tr[:, 0])),
        "train_roc": max(roc_auc(y_true["train"], X_len_tr[:, 0]), 1.0 - roc_auc(y_true["train"], X_len_tr[:, 0])),
        "val_pr": raw_len_val_prauc,
        "val_roc": max(roc_auc(y_true["val"], raw_len_val), 1.0 - roc_auc(y_true["val"], raw_len_val)),
        "test_pr": raw_len_ts_prauc,
        "test_roc": max(roc_auc(y_true["test"], raw_len_ts), 1.0 - roc_auc(y_true["test"], raw_len_ts)),
    }

    # =========================================================================
    # Baseline 2: Skeleton Archetype / Structural Meta Baseline
    # =========================================================================
    logger.info("Evaluating Baseline 2: Skeleton Archetype / Structural Meta Baseline ...")
    # Features: skeleton_id, command, secondary_command, is_unicode, port 139/445
    def extract_skel_meta_dict(recs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        dicts = []
        for r in recs:
            meta = r.get("meta", {})
            dst_ap = str(r.get("dst_ap", ""))
            port = "139" if ":139" in dst_ap else "445"
            d = {
                "skeleton_id": str(meta.get("skeleton_id", "unknown")),
                "command": str(meta.get("command", "none")),
                "secondary_command": str(meta.get("secondary_command", "none")),
                "is_unicode": str(bool(meta.get("is_unicode", False))),
                "port": port,
            }
            dicts.append(d)
        return dicts

    dicts_tr = extract_skel_meta_dict(splits_data["train"])
    dicts_val = extract_skel_meta_dict(splits_data["val"])
    dicts_ts = extract_skel_meta_dict(splits_data["test"])

    vec_skel = DictVectorizer(sparse=True)
    X_skel_tr = vec_skel.fit_transform(dicts_tr)
    X_skel_val = vec_skel.transform(dicts_val)
    X_skel_ts = vec_skel.transform(dicts_ts)

    logger.info("Skeleton feature dimension: %d", X_skel_tr.shape[1])

    clf_skel = LogisticRegression(max_iter=1000, random_state=42)
    clf_skel.fit(X_skel_tr, y_true["train"])
    prob_skel_tr = clf_skel.predict_proba(X_skel_tr)[:, 1]
    prob_skel_val = clf_skel.predict_proba(X_skel_val)[:, 1]
    prob_skel_ts = clf_skel.predict_proba(X_skel_ts)[:, 1]

    results["Skeleton Meta (skeleton_id, cmd, sec_cmd, is_uni, port)"] = {
        "train_pr": pr_auc(y_true["train"], prob_skel_tr),
        "train_roc": roc_auc(y_true["train"], prob_skel_tr),
        "val_pr": pr_auc(y_true["val"], prob_skel_val),
        "val_roc": roc_auc(y_true["val"], prob_skel_val),
        "test_pr": pr_auc(y_true["test"], prob_skel_ts),
        "test_roc": roc_auc(y_true["test"], prob_skel_ts),
    }

    # Verify probability distribution on Test to check for negative-conditioning inversion
    logger.info("Skel test prob stats: min=%.4f, mean=%.4f, max=%.4f, median=%.4f",
                np.min(prob_skel_ts), np.mean(prob_skel_ts), np.max(prob_skel_ts), np.median(prob_skel_ts))
    logger.info("Skel test prob for attack samples: mean=%.4f", np.mean(prob_skel_ts[y_true["test"] == 1]))
    logger.info("Skel test prob for benign samples: mean=%.4f", np.mean(prob_skel_ts[y_true["test"] == 0]))

    # =========================================================================
    # Baseline 3: Header-Only LogReg / Linear Baseline (smb_header bytes 0..32)
    # =========================================================================
    logger.info("Evaluating Baseline 3: Header-Only Linear Baseline ...")
    def extract_hdr_bytes(recs: List[Dict[str, Any]]) -> np.ndarray:
        feats = []
        for r in recs:
            hdr, _ = extract_hdr_and_pld(r.get("buffers", ""))
            hdr_padded = list(hdr[:32].ljust(32, b"\x00"))
            feats.append(hdr_padded)
        return np.array(feats, dtype=float)

    X_hdr_tr = extract_hdr_bytes(splits_data["train"])
    X_hdr_val = extract_hdr_bytes(splits_data["val"])
    X_hdr_ts = extract_hdr_bytes(splits_data["test"])

    clf_hdr = LogisticRegression(max_iter=1000, random_state=42)
    clf_hdr.fit(X_hdr_tr, y_true["train"])
    prob_hdr_tr = clf_hdr.predict_proba(X_hdr_tr)[:, 1]
    prob_hdr_val = clf_hdr.predict_proba(X_hdr_val)[:, 1]
    prob_hdr_ts = clf_hdr.predict_proba(X_hdr_ts)[:, 1]

    results["Header-Only LogReg (smb_header 0..32)"] = {
        "train_pr": pr_auc(y_true["train"], prob_hdr_tr),
        "train_roc": roc_auc(y_true["train"], prob_hdr_tr),
        "val_pr": pr_auc(y_true["val"], prob_hdr_val),
        "val_roc": roc_auc(y_true["val"], prob_hdr_val),
        "test_pr": pr_auc(y_true["test"], prob_hdr_ts),
        "test_roc": roc_auc(y_true["test"], prob_hdr_ts),
    }

    # =========================================================================
    # Baseline 4: Payload[:64] Tree-5 & LogReg Baseline
    # =========================================================================
    logger.info("Evaluating Baseline 4: Payload[:64] Tree-5 and LogReg Baseline ...")
    def extract_pld64_bytes(recs: List[Dict[str, Any]]) -> np.ndarray:
        feats = []
        for r in recs:
            _, pld = extract_hdr_and_pld(r.get("buffers", ""))
            pld_padded = list(pld[:64].ljust(64, b"\x00"))
            feats.append(pld_padded)
        return np.array(feats, dtype=float)

    X_pld64_tr = extract_pld64_bytes(splits_data["train"])
    X_pld64_val = extract_pld64_bytes(splits_data["val"])
    X_pld64_ts = extract_pld64_bytes(splits_data["test"])

    # Model A: LogReg
    clf_pld_lr = LogisticRegression(max_iter=1000, random_state=42)
    clf_pld_lr.fit(X_pld64_tr, y_true["train"])
    prob_pld_lr_tr = clf_pld_lr.predict_proba(X_pld64_tr)[:, 1]
    prob_pld_lr_val = clf_pld_lr.predict_proba(X_pld64_val)[:, 1]
    prob_pld_lr_ts = clf_pld_lr.predict_proba(X_pld64_ts)[:, 1]

    results["Payload[:64] LogReg"] = {
        "train_pr": pr_auc(y_true["train"], prob_pld_lr_tr),
        "train_roc": roc_auc(y_true["train"], prob_pld_lr_tr),
        "val_pr": pr_auc(y_true["val"], prob_pld_lr_val),
        "val_roc": roc_auc(y_true["val"], prob_pld_lr_val),
        "test_pr": pr_auc(y_true["test"], prob_pld_lr_ts),
        "test_roc": roc_auc(y_true["test"], prob_pld_lr_ts),
    }

    # Model B: Shallow Decision Tree (depth=5)
    tree_pld = DecisionTreeClassifier(max_depth=5, random_state=42)
    tree_pld.fit(X_pld64_tr, y_true["train"])
    prob_tree_tr = tree_pld.predict_proba(X_pld64_tr)[:, 1]
    prob_tree_val = tree_pld.predict_proba(X_pld64_val)[:, 1]
    prob_tree_ts = tree_pld.predict_proba(X_pld64_ts)[:, 1]

    results["Payload[:64] Shallow Tree (depth=5)"] = {
        "train_pr": pr_auc(y_true["train"], prob_tree_tr),
        "train_roc": roc_auc(y_true["train"], prob_tree_tr),
        "val_pr": pr_auc(y_true["val"], prob_tree_val),
        "val_roc": roc_auc(y_true["val"], prob_tree_val),
        "test_pr": pr_auc(y_true["test"], prob_tree_ts),
        "test_roc": roc_auc(y_true["test"], prob_tree_ts),
    }

    # =========================================================================
    # Baseline 5: Source/Telemetry Baseline (ports, src_ap, dst_ap, proto, pkt_gen)
    # =========================================================================
    logger.info("Evaluating Baseline 5: Source / Telemetry Baseline ...")
    def extract_telemetry_dict(recs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        dicts = []
        for r in recs:
            src_ap = str(r.get("src_ap", ""))
            dst_ap = str(r.get("dst_ap", ""))
            src_port = src_ap.split(":")[-1] if ":" in src_ap else "0"
            dst_port = dst_ap.split(":")[-1] if ":" in dst_ap else "0"
            src_ip = src_ap.split(":")[0] if ":" in src_ap else ""
            dst_ip = dst_ap.split(":")[0] if ":" in dst_ap else ""
            proto = str(r.get("proto", "TCP"))
            pkt_gen = str(r.get("pkt_gen", "stream_tcp"))
            dir_str = str(r.get("dir", "C2S"))
            
            d = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "proto": proto,
                "pkt_gen": pkt_gen,
                "dir": dir_str,
                "client_bytes": float(r.get("client_bytes", 0)),
                "client_pkts": float(r.get("client_pkts", 0)),
                "server_bytes": float(r.get("server_bytes", 0)),
                "server_pkts": float(r.get("server_pkts", 0)),
                "pkt_len": float(r.get("pkt_len", 0)),
            }
            dicts.append(d)
        return dicts

    dicts_telem_tr = extract_telemetry_dict(splits_data["train"])
    dicts_telem_val = extract_telemetry_dict(splits_data["val"])
    dicts_telem_ts = extract_telemetry_dict(splits_data["test"])

    vec_telem = DictVectorizer(sparse=True)
    X_telem_tr = vec_telem.fit_transform(dicts_telem_tr)
    X_telem_val = vec_telem.transform(dicts_telem_val)
    X_telem_ts = vec_telem.transform(dicts_telem_ts)

    logger.info("Telemetry feature dimension: %d", X_telem_tr.shape[1])

    clf_telem = LogisticRegression(max_iter=1000, random_state=42)
    clf_telem.fit(X_telem_tr, y_true["train"])
    prob_telem_tr = clf_telem.predict_proba(X_telem_tr)[:, 1]
    prob_telem_val = clf_telem.predict_proba(X_telem_val)[:, 1]
    prob_telem_ts = clf_telem.predict_proba(X_telem_ts)[:, 1]

    results["Source/Telemetry (ports, src/dst_ap, proto, pkt_gen) LogReg"] = {
        "train_pr": pr_auc(y_true["train"], prob_telem_tr),
        "train_roc": roc_auc(y_true["train"], prob_telem_tr),
        "val_pr": pr_auc(y_true["val"], prob_telem_val),
        "val_roc": roc_auc(y_true["val"], prob_telem_val),
        "test_pr": pr_auc(y_true["test"], prob_telem_ts),
        "test_roc": roc_auc(y_true["test"], prob_telem_ts),
    }

    # Also a shallow decision tree on telemetry
    tree_telem = DecisionTreeClassifier(max_depth=5, random_state=42)
    tree_telem.fit(X_telem_tr, y_true["train"])
    prob_tree_telem_tr = tree_telem.predict_proba(X_telem_tr)[:, 1]
    prob_tree_telem_val = tree_telem.predict_proba(X_telem_val)[:, 1]
    prob_tree_telem_ts = tree_telem.predict_proba(X_telem_ts)[:, 1]

    results["Source/Telemetry Shallow Tree (depth=5)"] = {
        "train_pr": pr_auc(y_true["train"], prob_tree_telem_tr),
        "train_roc": roc_auc(y_true["train"], prob_tree_telem_tr),
        "val_pr": pr_auc(y_true["val"], prob_tree_telem_val),
        "val_roc": roc_auc(y_true["val"], prob_tree_telem_val),
        "test_pr": pr_auc(y_true["test"], prob_tree_telem_ts),
        "test_roc": roc_auc(y_true["test"], prob_tree_telem_ts),
    }

    # =========================================================================
    # SUMMARY TABLE & GATE 5 DECISION
    # =========================================================================
    print("\n" + "=" * 105)
    print(" GATE 5 (ANTI-LEAK BASELINES & HARDNESS VERIFICATION) BENCHMARK RESULTS")
    print(f" Splits Directory: {SPLITS_DIR}")
    print(f" Positive Attack Prior (pi_p): Train={np.mean(y_true['train']):.4f}, Val={np.mean(y_true['val']):.4f}, Test={np.mean(y_true['test']):.4f}")
    print(f" Gate 5 Hardness Ceiling Target: PR-AUC <= 0.65 (All baselines must pass)")
    print("-" * 105)
    header = f"{'Baseline':<48} | {'Val PR':<7} | {'Val ROC':<7} | {'Test PR':<7} | {'Test ROC':<8} | {'Ceiling <= 0.65':<15}"
    print(header)
    print("-" * 105)

    all_passed = True
    for name, m in results.items():
        v_pr = m["val_pr"]
        v_roc = m["val_roc"]
        t_pr = m["test_pr"]
        t_roc = m["test_roc"]
        passed = (v_pr <= 0.65) and (t_pr <= 0.65)
        if not passed:
            all_passed = False
        status = "PASS" if passed else "FAIL"
        print(f"{name:<48} | {v_pr:.4f}  | {v_roc:.4f}  | {t_pr:.4f}  | {t_roc:.4f}   | {status:<15}")

    print("=" * 105)
    print(f" Overall Gate 5 Hardness Decision: {'PASSED (APPROVED)' if all_passed else 'FAILED (REJECTED)'}")
    print("=" * 105 + "\n")


if __name__ == "__main__":
    main()
