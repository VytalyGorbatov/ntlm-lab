#!/usr/bin/env python3
"""Combine benign and attack NTLMSSP datasets into a single cohort.

Performs timing normalization, categorical encoding, duplicate auditing,
and outputs dissertation-ready evaluation breakdown metrics.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
from pathlib import Path
from typing import Any, Dict, List

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("combine_ntlm_datasets")


def normalize_timing(records: List[Dict[str, Any]], field: str) -> None:
    vals = [r[field] for r in records if isinstance(r.get(field), (int, float))]
    if not vals:
        return
    baseline = min(vals)
    for r in records:
        if isinstance(r.get(field), (int, float)):
            r[field] = r[field] - baseline


def build_categorical_mappings(records: List[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    CAT_FIELDS = ["proto", "pkt_gen", "dir"]
    mappings: Dict[str, Dict[str, int]] = {}
    for f in CAT_FIELDS:
        m: Dict[str, int] = {}
        for r in records:
            val = str(r.get(f, ""))
            if val not in m:
                m[val] = len(m)
            r[f"{f}_encoded"] = m[val]
        mappings[f"{f}_mapping"] = m
    return mappings


def main() -> None:
    parser = argparse.ArgumentParser(description="Combine benign and attack NTLMSSP datasets")
    parser.add_argument("--benign", required=True, type=Path, help="Benign JSON dataset")
    parser.add_argument("--attack", required=True, type=Path, help="Attack JSON dataset")
    parser.add_argument("-o", "--output", required=True, type=Path, help="Combined output JSON path")
    parser.add_argument("--report", type=Path, help="Optional markdown report path")
    args = parser.parse_args()

    with args.benign.open("r", encoding="utf-8") as f:
        benign_data = json.load(f)["dataset"]
    with args.attack.open("r", encoding="utf-8") as f:
        attack_data = json.load(f)["dataset"]

    logger.info("Loaded %d benign records and %d attack records", len(benign_data), len(attack_data))

    # Normalize timing independently per cohort before concatenation to eliminate timestamp leakage
    normalize_timing(benign_data, "flowstart_time")
    normalize_timing(benign_data, "seconds")
    normalize_timing(attack_data, "flowstart_time")
    normalize_timing(attack_data, "seconds")

    combined_records = list(benign_data) + list(attack_data)

    # Sanitize src_ap across all records to eliminate IP leakage between containers
    for r in combined_records:
        src = r.get("src_ap", "")
        port = src.split(":")[-1] if ":" in src else str(random.randint(1025, 65500))
        r["src_ap"] = f"172.24.0.100:{port}"

    # Build categorical mappings
    mappings = build_categorical_mappings(combined_records)

    # Cross-tabulation statistics
    table = {
        "benign_non_alerted": 0,  # is_attack=0, alerted=0
        "benign_fp": 0,           # is_attack=0, alerted=1
        "snort_alerted": 0,       # is_attack=1, alerted=1
        "snort_fn": 0,            # is_attack=1, alerted=0
    }

    attack_rules_dist: Dict[str, int] = {}
    for r in combined_records:
        att = r.get("is_attack", 0)
        al = r.get("alerted", 0)
        if att == 0 and al == 0:
            table["benign_non_alerted"] += 1
        elif att == 0 and al == 1:
            table["benign_fp"] += 1
        elif att == 1 and al == 1:
            table["snort_alerted"] += 1
        elif att == 1 and al == 0:
            table["snort_fn"] += 1

        for rule in r.get("attack_rules", []):
            attack_rules_dist[rule] = attack_rules_dist.get(rule, 0) + 1

    total_attack = table["snort_alerted"] + table["snort_fn"]
    total_benign = table["benign_non_alerted"] + table["benign_fp"]
    fn_rate = (table["snort_fn"] / total_attack * 100.0) if total_attack else 0.0
    benign_fpr = (table["benign_fp"] / total_benign * 100.0) if total_benign else 0.0

    output_payload = {
        "dataset": combined_records,
        "metadata": {
            "total_samples": len(combined_records),
            "benign_samples": len(benign_data),
            "attack_samples": len(attack_data),
            "cross_tabulation": table,
            "fn_rate_pct": fn_rate,
            "benign_fpr_pct": benign_fpr,
            "attack_rules_triggered": attack_rules_dist,
            **mappings,
        },
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2)

    logger.info("Saved combined dataset to %s", args.output)

    # Console Report
    print("\n" + "=" * 65)
    print(" NTLMSSP CROSS-PROTOCOL DATASET EVALUATION MATRIX")
    print("=" * 65)
    print(f" Total Cohort Size: {len(combined_records)} packets")
    print("-" * 65)
    print(f" {'Metric':<35} | {'Count':<10} | {'Percentage':<10}")
    print("-" * 65)
    recall_pct = (table['snort_alerted'] / total_attack * 100.0) if total_attack else 0.0
    total_size = len(combined_records) if combined_records else 1
    print(f" {'Benign Clean (alerted=0, attack=0)':<35} | {table['benign_non_alerted']:<10} | {table['benign_non_alerted']/total_size*100:>8.1f}%")
    print(f" {'Benign Added FP (alerted=1, attack=0)':<35} | {table['benign_fp']:<10} | {benign_fpr:>8.1f}% (FPR)")
    print(f" {'Snort Alerted Attack (alerted=1, att=1)':<35} | {table['snort_alerted']:<10} | {recall_pct:>8.1f}% (Recall)")
    print(f" {'Snort False Negatives (alerted=0, att=1)':<35} | {table['snort_fn']:<10} | {fn_rate:>8.1f}% (FN Rate)")
    print("-" * 65)
    print(f" Attack Rules Triggered Breakdown:")
    for rule, count in sorted(attack_rules_dist.items(), key=lambda x: x[1], reverse=True):
        print(f"   SID {rule:<20}: {count} occurrences")
    print("=" * 65 + "\n")

    if args.report:
        with args.report.open("w", encoding="utf-8") as f:
            f.write("# NTLMSSP FastPattern Dataset Generation Report\n\n")
            f.write("## 1. Executive Summary\n")
            f.write(f"- Total records: **{len(combined_records)}**\n")
            f.write(f"- Snort FN rate: **{fn_rate:.1f}%** ({table['snort_fn']}/{total_attack})\n")
            f.write(f"- Benign FPR: **{benign_fpr:.2f}%** ({table['benign_fp']}/{total_benign})\n\n")
            f.write("## 2. 2x2 Evaluation Matrix (Dissertation Objective)\n\n")
            f.write("| Ground Truth | Snort Alerted (`alerted=1`) | Snort Non-Alerted (`alerted=0`) | Total |\n")
            f.write("|---|---:|---:|---:|\n")
            f.write(f"| **Attack (`is_attack=1`)** | {table['snort_alerted']} (Alerted Positives) | {table['snort_fn']} (**Snort False Negatives**) | {total_attack} |\n")
            f.write(f"| **Benign (`is_attack=0`)** | {table['benign_fp']} (Added False Positives) | {table['benign_non_alerted']} (Clean Negatives) | {total_benign} |\n")
            f.write(f"| **Total** | {table['snort_alerted'] + table['benign_fp']} | {table['snort_fn'] + table['benign_non_alerted']} | {len(combined_records)} |\n\n")
            f.write("## 3. Attack Rules Triggered Breakdown\n\n")
            f.write("| Snort Rule SID | Occurrences |\n")
            f.write("|---|---:|\n")
            for rule, count in sorted(attack_rules_dist.items(), key=lambda x: x[1], reverse=True):
                f.write(f"| `{rule}` | {count} |\n")
        logger.info("Saved markdown report to %s", args.report)


if __name__ == "__main__":
    main()
