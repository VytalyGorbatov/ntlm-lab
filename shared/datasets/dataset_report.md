# NTLMSSP FastPattern Dataset Generation Report

## 1. Executive Summary
- Total records: **165000**
- Snort FN rate: **65.3%** (9795/15000)
- Benign FPR: **0.00%** (0/150000)

## 2. 2x2 Evaluation Matrix (Dissertation Objective)

| Ground Truth | Snort Alerted (`alerted=1`) | Snort Non-Alerted (`alerted=0`) | Total |
|---|---:|---:|---:|
| **Attack (`is_attack=1`)** | 5205 (Alerted Positives) | 9795 (**Snort False Negatives**) | 15000 |
| **Benign (`is_attack=0`)** | 0 (Added False Positives) | 150000 (Clean Negatives) | 150000 |
| **Total** | 5205 | 159795 | 165000 |

## 3. Attack Rules Triggered Breakdown

| Snort Rule SID | Occurrences |
|---|---:|
| `1:15225:14` | 501 |
| `1:15200:14` | 490 |
| `1:15218:14` | 476 |
| `1:15209:14` | 473 |
| `1:15203:14` | 470 |
| `1:15210:14` | 458 |
| `1:15224:14` | 455 |
| `1:15217:14` | 436 |
| `1:15196:17` | 208 |
| `1:15205:14` | 189 |
| `1:15213:14` | 185 |
| `1:15199:14` | 182 |
| `1:15206:14` | 176 |
| `1:15214:14` | 171 |
| `1:15221:14` | 168 |
| `1:15220:17` | 167 |
