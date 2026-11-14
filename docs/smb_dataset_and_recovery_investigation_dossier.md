# Technical Dossier: SMBv1 / NetBIOS 165k Dataset & Neural Risk Scorer Recovery Discrepancy

**Workspace Paths**: `/home/vhorbato/Academy/ntlm-lab` & `/home/vhorbato/Academy/nids_ml`  
**Target Vulnerabilities**: `CVE-2008-4834` & `CVE-2008-4835` (MS09-001, NetBIOS Session Service / SMBv1 Underflow)  
**Target Snort Rules**: 16 Rules (SIDs 15196–15225) + Anchor SID 1 (`FASTPATTERN ANCHOR`)  
**Dissertation North-Star Objective**: Recover Snort False Negatives (`is_attack=1 AND alerted=0`) at controlled benign false-positive budgets ($\text{FPR} \le 1\%, 5\%, 10\%$).

---

## 1. Dataset Provenance & Structural Design

The dataset was generated in `ntlm-lab` using stateful containerized interactions between client/attacker containers and live Samba 4.15 on `ntlm_server` (IP: `172.24.0.10`), followed by full packet capture and Snort 3 stream reassembly processing.

### 1.1 Structural Topology: 60 Archetypes Matrix
To prevent shortcut learning and single-token memorization, the dataset spans 15 structural transaction patterns $\times$ 2 encodings $\times$ 2 transport modes:
- **Transport Modes**: Port 445 (Direct TCP) and Port 139 (NetBIOS Session Request RFC 1001/1002).
- **Encodings**: Unicode (`Flags2 & 0x8000`) and ASCII.
- **Resource Targets**: Symmetrically balanced between Disk Shares (`\public`, `\secured` $\sim 82\%$) and Named Pipes (`\srvsvc`, `\samr`, `\lsarpc`, `\spoolss`, `\wkssvc`, `\browser` $\sim 18\%$) in both Benign and Attack cohorts.
- **Subcommands & Trans2 Functions**:
  - `0xA0` (NT Transact): `0x0001` (Create), `0x0002` (IOCTL), `0x0003` (Set Security Descriptor), `0x0004` (Notify Change), `0x0006` (Query Security Descriptor).
  - `0x32` (Transaction2): `0x0000` (Open2), `0x0001` (Find First2), `0x0002` (Find Next2), `0x0003` (Query FS Info), `0x0005` (Query Path Info), `0x0007` (Query File Info).
  - Compound / Chained AndX (`0x75`, `0x73`, `0x2E`, `0x2F`, `0x24`, `0x2D`, `0xA2`) with offsets 37 and 39.
  - Multi-chunk Secondary transactions: `0xA1` (NT Transact Secondary) and `0x33` (Trans2 Secondary).

### 1.2 Data Schema & Representation
Each record in the dataset follows the multi-protocol unified schema:
- `buffers`: Latin-1 string containing SMB Header (32 bytes) + `0x1E` + Transaction Payload/Parameters + `0x1E` (exactly 2 `0x1E` bytes per buffer).
- `buffer_names`: `"smb_header\x1esmb_payload\x1e"`.
- `fixed_len`: 192 bytes (`header_len`: 32, `body_len`: 160, `sep_byte`: 30).
- `alerted`: Weak IDS supervisory label (`1` if triggered any of the 16 target SIDs, `0` otherwise).
- `is_attack`: Ground truth label used **strictly** for evaluation, diagnostics, and Oracle upper bound.

---

## 2. Six Dissertation Quality Gates Audit (165,000 Records)

The 165,000-record dataset at `/home/vhorbato/Academy/ntlm-lab/shared/datasets/combined_basic.json` passed all 6 dissertation quality gates:

```text
========================================================================================
             SMBv1 / NetBIOS DISSERTATION QUALITY GATES (165,000-RECORD COHORT)
========================================================================================
 Gate 1: Dataset Integrity & 2x2 Matrix .................. [PASS] 0.00% Benign FPR
 Gate 2: Handshake, Delimiter & Skeleton Purity ........... [PASS] 0 Class-Pure Archetypes
 Gate 3: High-Entropy Identifier Sanitization ............ [PASS] 0 Leaked IDs
 Gate 4: Leakage-Resistant Split Integrity ............... [PASS] 0 Cross-Split Overlaps
 Gate 5: Anti-Leak Baselines & Dataset Hardness .......... [PASS] All Baselines <= 0.191
 Gate 6: Snort Coverage & False Negative Realism ......... [PASS] 16/16 SIDs Active
========================================================================================
```

### Detailed Invariants & Verification:
- **Gate 1 (Benign Safety)**: `0 / 150,000` Added Benign FPs on Snort 3 (**0.0000% Benign FPR**). Snort FN rate = **`65.30%`** (9,795 missed attacks / 15,000 total attacks).
- **Gate 2 (Protocol Purity)**: 0 handshake packets mislabeled; 100% of records have strictly two `0x1E` separators; 0 class-pure skeleton archetypes.
- **Gate 3 (Sanitization)**: All session identifiers (TID, PID, UID, MID) zeroed in buffer extraction; Header LogReg PR-AUC = `0.1174` (random baseline $\sim 0.091$).
- **Gate 4 (Deduplication)**: 0 duplicate buffers (165,000 unique SHA-256 hashes); zero cross-split hash leaks between Train, Val, and Test.
- **Gate 5 (Anti-Leak Hardness)**:
  - Packet Length Baseline PR-AUC: **`0.0950`**
  - Payload[:64] Tree Depth-5 PR-AUC: **`0.1906`** ($\le 0.65$ limit)
  - Holdout Test Tree[:160] PR-AUC: **`0.1248`** ($\le 0.65$ limit)
- **Gate 6 (Snort Rule Coverage)**: All 16 target SIDs triggered (167 to 501 occurrences each).

---

## 3. Split Allocations & File Locations

All splits are stored in `/home/vhorbato/Academy/ntlm-lab/shared/datasets/splits/`:

### 3.1 Primary Experimental Split: `skeleton_holdout/`
Held out 10 structural archetypes in Validation and 10 structural archetypes in Test:

| Split File Path | Total Records | Clean Benign (`is_attack=0, alerted=0`) | Added Benign FP (`alerted=1`) | Snort Alerted (`alerted=1, att=1`) | Snort FNs (`alerted=0, att=1`) | Attack Prior ($\pi_p$) | Alert Rate ($c$) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `.../skeleton_holdout/train.json` | **105,867** | 96,470 | 0 (0.00%) | 3,177 (33.81%) | 6,220 (66.19%) | **`0.0888`** | **`0.0300`** |
| `.../skeleton_holdout/val.json` | **29,923** | 27,097 | 0 (0.00%) | 1,041 (36.84%) | 1,785 (63.16%) | **`0.0944`** | **`0.0348`** |
| `.../skeleton_holdout/test.json` | **29,210** | 26,433 | 0 (0.00%) | 987 (35.54%) | 1,790 (64.46%) | **`0.0951`** | **`0.0338`** |
| **Combined Total** | **165,000** | **150,000** | **0 (0.00%)** | **5,205 (34.70%)** | **9,795 (65.30%)** | **`0.0909`** | **`0.0315`** |

Manifest: `/home/vhorbato/Academy/ntlm-lab/shared/datasets/splits/skeleton_holdout/manifest.json`.

---

## 4. Empirical Baseline Findings

### 4.1 Supervised Neural Oracle Benchmark (`smb_tcn_2way_oracle_165k`)
- **Config**: `/home/vhorbato/Academy/nids_ml/smb_tcn_2way_oracle_165k.conf` (3 pretrain + 5 supervised epochs, batch size 256, lr 5e-4).
- **Checkpoint & Predictions**: `/home/vhorbato/Academy/artifacts/smb_tcn_2way_oracle_165k/`
- **Test Metrics**:
  - Calibrated Test PR-AUC: **`0.5853`** (vs random baseline `0.0951`).
  - Precision at Threshold 0.5: **`93.88%`** (Precision at best F1 = 85.40%, Recall = 46.13%).
  - Snort FN Recovery at validation-selected thresholds:
    - $\text{FPR} \le 1\%$ ($T=0.2168$): **601 FNs recovered** (33.58% recovery rate, total attack recall: 57.18%, 602 added benign FPs).
    - $\text{FPR} \le 5\%$ ($T=0.1588$): **794 FNs recovered** (44.36% recovery rate, total attack recall: 64.13%).
    - $\text{FPR} \le 10\%$ ($T=0.1146$): **1,105 FNs recovered** (61.73% recovery rate, total attack recall: 75.33%).

### 4.2 Weakly Supervised PU Learning Baseline (`smb_tcn_2way_pu_165k`)
- **Config**: `/home/vhorbato/Academy/nids_ml/smb_tcn_2way_pu_165k.conf` (3 pretrain + 10 `nnPU` epochs, batch size 256, lr 2e-4, $\pi_p=0.0888, w_{\text{ssl}}=1.5, w_{\text{alert}}=0.2, w_{\text{pu}}=1.0$).
- **Checkpoint & Predictions**: `/home/vhorbato/Academy/artifacts/smb_tcn_2way_pu_165k/`
- **Test Metrics**:
  - Calibrated Test PR-AUC: **`0.1105`** (only slightly above random baseline `0.0951`).
  - Calibration: Platt scaling reduced ECE from 0.0148 to **`0.0038`** (3.9x improvement).
  - Snort FN Recovery at validation-selected thresholds:
    - $\text{FPR} \le 1\%$ ($T=0.1131$): **22 FNs recovered** (1.23% recovery rate, 287 added benign FPs / 1.09% FPR).
    - $\text{FPR} \le 5\%$ ($T=0.1085$): **92 FNs recovered** (5.14% recovery rate, 1,335 added benign FPs / 5.05% FPR).
    - $\text{FPR} \le 10\%$ ($T=0.1059$): **173 FNs recovered** (9.66% recovery rate, 2,563 added benign FPs / 9.70% FPR).

---

## 5. Comparative Error Decomposition Table ($is\_attack \times alerted \times nn$)

Evaluated on the 29,210 unseen skeleton holdout test set:

| Traffic Cohort / Operational Meaning | Snort Baseline | Weak PU ($T_{\text{fpr1\%}}$) | Weak PU ($T_{\text{fpr5\%}}$) | Weak PU ($T_{\text{fpr10\%}}$) | Supervised Oracle ($T_{\text{fpr1\%}}$) | Supervised Oracle ($T=0.5$) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `is_attack=1, alerted=1, nn=1` (Snort TP confirmed by NN) | 987 | 31 | 91 | 169 | 753 | 661 |
| `is_attack=1, alerted=1, nn=0` (Snort TP missed by NN) | 0 | 956 | 896 | 818 | 234 | 326 |
| `is_attack=1, alerted=0, nn=1` (**Snort FN recovered by NN**) | **0** | **22** | **92** | **173** | **601** | **520** |
| `is_attack=1, alerted=0, nn=0` (Snort FN still missed) | 1,790 | 1,768 | 1,698 | 1,617 | 1,189 | 1,270 |
| `is_attack=0, alerted=0, nn=1` (**Added Benign FP**) | **0** | **287** | **1,335** | **2,563** | **602** | **77** |
| `is_attack=0, alerted=0, nn=0` (Benign Clean TN) | 26,433 | 26,146 | 25,098 | 23,870 | 25,831 | 26,356 |
| **Total Test Cohort** | **29,210** | **29,210** | **29,210** | **29,210** | **29,210** | **29,210** |

---

## 6. The Core Problem Statement & Diagnostic Hypotheses

### The Core Discrepancy
Why does the Supervised Oracle achieve **PR-AUC = 0.5853** and recover **601 Snort FNs** with **93.88% precision**, while the Weakly Supervised `nnPU` model achieves only **PR-AUC = 0.1105** and recovers only **22 to 92 Snort FNs**?

The Oracle proves that the byte-level representation contains sufficient inductive signal to detect attacks across unseen holdout archetypes. Therefore, the deficit lies in **how the weakly supervised PU objective learns from `alerted=1` vs `alerted=0` under extreme class imbalance**.

### Key Hypotheses for the Next Agent Session:

1. **Positive Set Exposure Bottleneck (`steps_per_epoch`)**:
   - In `TwoWayTrainer.train_pu`, `steps_per_epoch` defaults to `len(loader_p) = 3,177 / 256 = 13` steps per epoch.
   - Across 10 epochs, the network only executed 130 gradient updates, seeing only $\sim 33,280$ unlabeled samples ($\sim 32\%$ of $U=102,690$). The vast majority of unlabeled data was never presented to the network!
   - In contrast, the Oracle ran for 414 steps per epoch (2,070 steps total) over 100% of the data.
   - *Investigation needed*: Decouple `steps_per_epoch` to cycle through the full unlabeled pool ($414$ steps per epoch) with positive oversampling or dynamic sampling.

2. **PU Risk Weighting & Loss Landscape**:
   - The current loss balance is $w_{\text{ssl}} = 1.5, w_{\text{alert}} = 0.2, w_{\text{pu}} = 1.0$.
   - Does auxiliary SSL contrastive loss dominate gradient updates when the positive set is small?
   - In `nnPU`, when $\pi_p \approx 0.0888$ is small, the negative risk estimator $\hat{R}_u^-(g) - \pi_p \hat{R}_p^-(g)$ frequently clips to zero if the decision boundary is premature.

3. **Two-Way Protocol Buffer Geometry & Receptive Field**:
   - Current slicing: `fixed_len: 192`, `header_len: 32`, `body_len: 160`.
   - In SMBv1, MS09-001 underflows occur in parameter blocks (`TotalParameterCount`, `ParameterCount`, `MaxParameterCount`) and transaction data chunks (`FEAList`, `FILE_FULL_EA_INFORMATION`).
   - Does 160 bytes truncate critical displacement bytes in multi-chunk secondary transactions?
   - Does `tcn_2way` with `kernel=3, dilations=[1, 2, 4]` have a sufficiently wide receptive field (effective receptive field: $\approx 15$ bytes) to correlate byte 32 (command) with byte 69 (function) and byte 85 (counts)?

4. **Calibration & Operating Threshold Policy**:
   - With an empirical test prior of $\sim 9.5\%$, uncalibrated logits skew heavily negative.
   - Platt scaling fitted $a=0.2501, b=-1.6701$, squashing the score distribution into a narrow band $[0.08, 0.16]$.
   - Isotonic calibration or Beta calibration on the validation set may offer better dynamic range for fine-grained ranking.
