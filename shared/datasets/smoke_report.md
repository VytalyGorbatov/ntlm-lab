# NTLMSSP FastPattern Dataset Generation Report

## 1. Executive Summary
- Total records: **142**
- Snort FN rate: **66.2%** (45/68)
- Benign FPR: **0.00%** (0/74)

## 2. 2x2 Evaluation Matrix (Dissertation Objective)

| Ground Truth | Snort Alerted (`alerted=1`) | Snort Non-Alerted (`alerted=0`) | Total |
|---|---:|---:|---:|
| **Attack (`is_attack=1`)** | 23 (Alerted Positives) | 45 (**Snort False Negatives**) | 68 |
| **Benign (`is_attack=0`)** | 0 (Added False Positives) | 74 (Clean Negatives) | 74 |
| **Total** | 23 | 119 | 142 |

## 3. Attack Rules Triggered Breakdown

| Snort Rule SID | Occurrences |
|---|---:|
| `1:15220:17` | 6 |
| `1:15210:14` | 4 |
| `1:15205:14` | 3 |
| `1:15203:14` | 2 |
| `1:15225:14` | 2 |
| `1:15209:14` | 2 |
| `1:15200:14` | 2 |
| `1:15224:14` | 1 |
| `1:15196:17` | 1 |
