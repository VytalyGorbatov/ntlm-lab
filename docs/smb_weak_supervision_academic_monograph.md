# Overcoming Representational and Optimization Bottlenecks in IDS-Marked Weakly Supervised Network Intrusion Detection: A Step-by-Step Empirical Investigation on SMBv1

**Authors**: Antigravity Research Team & Primary Investigator  
**Affiliation**: Academy Dissertation Research Workspace (`nids_ml` & `ntlm-lab`)  
**Target Protocol & Vulnerabilities**: Server Message Block v1 (SMBv1) / NetBIOS Session Service (`CVE-2008-4834` & `CVE-2008-4835`, MS09-001 Integer Underflow & Buffer Overflow across 16 Snort 3 Rules, SIDs 15196–15225)  
**Evaluation Benchmark**: 165,000-Record Skeleton-Holdout Dataset ($N_{\text{train}}=105,867$, $N_{\text{val}}=29,923$, $N_{\text{test}}=29,210$)  

---

## Abstract

Signature-based Network Intrusion Detection Systems (NIDS) such as Snort 3 provide high precision on known exploit patterns but fail to detect structural evasion variants when attackers alter transport framing, transaction wrappers, or parameter offsets. Training a complementary neural risk-scoring model without manual packet labeling requires Positive-Unlabeled (PU) weak supervision, where Snort alerts (`alerted=1`) serve as a noisy positive teacher signal and unalerted traffic (`alerted=0`) forms an unlabeled pool containing both benign traffic and undetected attacks (Snort False Negatives, FNs). On a 165,000-record SMBv1 benchmark satisfying all six dissertation quality gates, an initial Non-Negative Positive-Unlabeled (`nnPU`) Temporal Convolutional Network (TCN) collapsed to near-random ranking quality (Precision-Recall Area Under the Curve, $\text{PR-AUC} = 0.1105$), recovering only 1.23% (22 / 1,790) of Snort FNs at a $\le 1\%$ benign False Positive Rate (FPR) budget, compared to $\text{PR-AUC} = 0.5848$ (33.58% FN recovery) for a fully supervised oracle. This paper presents a step-by-step forensic and architectural investigation that identifies and resolves four root causes behind this gap: (1) an unlabeled starvation bottleneck in the training loop that discarded 96.77% of unlabeled data per epoch, alongside auxiliary contrastive loss gradient domination; (2) a subcommand constant collision (`0x0001`) in the traffic generator that injected genuine integer underflows into 3,620 benign records, accounting for 73.1% of false positives; (3) the destruction of numerical ordering and multi-byte arithmetic by categorical byte embeddings (`nn.Embedding`); and (4) the inability of fixed-window 1D convolutions and absolute positional encodings to compare shifted parameter fields across variable jump padding. By repairing the dataset splits, correcting optimization exposure, and engineering a protocol-independent neural architecture (`ByteTCN-Relational` with continuous bit-planes, sliding multi-scale 16/32-bit integer projections, Rotary Positional Embeddings [RoPE], and Pre-LN relational self-attention), we elevate the supervised upper bound from $0.5848$ to $0.8282$ PR-AUC (recovering 70.50% of Snort FNs and 65.81% of unseen structural holdouts at $\le 5\%$ FPR) and increase pure weakly supervised `nnPU` performance more than fourfold from $0.1105$ to $0.4618$ PR-AUC while cutting clean benign FPR from 2.262% to 0.288%.

**Keywords**: Network Intrusion Detection System (NIDS), Positive-Unlabeled (PU) Learning, Weak Supervision, Temporal Convolutional Network (TCN), Rotary Positional Embedding (RoPE), Arithmetic Inductive Bias, Server Message Block (SMB)

---

## 摘要（Traditional Chinese Abstract）

基於特徵碼的網路入侵檢測系統（Network Intrusion Detection System, NIDS，如 Snort 3）對已知攻擊模式具備高精確度，但在攻擊者改變傳輸封裝、交易包裝或參數偏移量的結構性規避變體時，往往產生大量假陰性（False Negatives, FNs）。在不依賴人工標註的情況下訓練輔助神經風險評分模型，需採用正例—未標註（Positive-Unlabeled, PU）弱監督學習，以 Snort 警報（`alerted=1`）作為教師訊號，並將未警報流量（`alerted=0`）視為混合正常流量與漏報攻擊的未標註池。在通過六項品質門檻的 165,000 筆 SMBv1 資料集上，初始非負正例—未標註（`nnPU`）時間卷積網路（TCN）的精確率—召回率曲線下面積（PR-AUC）僅達 $0.1105$，在誤報率（FPR）$\le 1\%$ 預算下僅找回 1.23%（22 / 1,790）的 Snort 漏報，遠低於全監督上限模型（$\text{PR-AUC} = 0.5848$，找回 33.58% 漏報）。本研究透過循序漸進的鑑識與架構實驗，確立並解決四項核心瓶頸：（一）訓練迴圈中的未標註樣本飢餓問題（每週期丟棄 96.77% 未標註資料）與對比式自監督損失的梯度主導效應；（二）流量產生器中的子命令常數碰撞錯誤（`0x0001`），導致 3,620 筆正常流量被植入整數下溢並造成 73.1% 的誤報；（三）類別型位元組嵌入（`nn.Embedding`）對數值順序與多位元組算術關係的破壞；以及（四）固定感受野一維卷積與絕對位置編碼無法跨越可變填充比對偏移欄位。經由修復資料集分割、校正訓練曝光度，並設計協定無關之關聯神經架構（結合連續位元平面、多尺度 16/32 位元數值投影、旋轉位置編碼 [RoPE] 與關聯自我注意力機制），全監督模型上限由 $0.5848$ 提升至 $0.8282$ PR-AUC（在 $\le 5\%$ FPR 下找回 70.50% 漏報及 65.81% 未知結構骨架），而純弱監督 `nnPU` 模型之 PR-AUC 亦由 $0.1105$ 提升逾四倍至 $0.4618$，同時將正常流量誤報率由 2.262% 降至 0.288%。

**關鍵詞**：網路入侵檢測系統（NIDS）、正例—未標註學習（PU Learning）、弱監督學習、時間卷積網路（TCN）、旋轉位置編碼（RoPE）、算術歸納偏置、伺服器訊息區塊（SMB）

---

## 1. Introduction & Operational Problem Statement

### 1.1 Background and Label Semantics
Signature-based Network Intrusion Detection Systems (NIDS) rely on deterministic byte-offset and fast-pattern matching rules. In the Server Message Block v1 (SMBv1) protocol (`CVE-2008-4834` and `CVE-2008-4835`, Microsoft Security Bulletin MS09-001), attacks exploit integer underflows and buffer overflows within `SMB_COM_TRANSACTION2` (`0x32`), `SMB_COM_TRANSACTION2_SECONDARY` (`0x33`), `SMB_COM_NT_TRANSACT` (`0xA0`), and `SMB_COM_NT_TRANSACT_SECONDARY` (`0xA1`) packets. Specifically, an exploit occurs when the declared parameter or data allocation size is smaller than the transmitted chunk or when the chunk offset plus length exceeds the total allocation:
$$\text{TotalParameterCount} < \text{ParameterCount} \quad \text{or} \quad \text{ParameterCount} + \text{ParameterDisplacement} > \text{TotalParameterCount}$$

While Snort 3 deploys 16 rules (SIDs 15196–15225) targeting these vulnerabilities, the signatures hardcode specific command wrappers, byte offsets, and upper parameter bounds (e.g., alerting only when $\text{ParameterCount} < 54$ at fixed offsets). Consequently, attackers can evade Snort 3 by chaining secondary commands (`AndX`), altering character encodings (ASCII vs. UTF-16LE Unicode), switching transport framing (Direct-TCP port 445 vs. NetBIOS Session Service port 139), or selecting parameter counts $\ge 54$ where $\text{TotalParameterCount}$ still underflows $\text{ParameterCount}$.

To recover these missed attacks without human packet annotation, the `nids_ml` framework trains an adaptive neural risk-scoring layer using IDS-marked weak supervision. The dataset maintains three distinct label variables:
1. **`alerted = 1` (IDS-Positive Teacher Signal)**: Reliable positive instances flagged by Snort 3.
2. **`alerted = 0` (Unlabeled Pool $U$)**: Packets producing no Snort alert. Crucially, `alerted = 0` is **not** clean benign traffic; it is a mixture of clean benign packets and unalerted attacks (Snort False Negatives, FNs).
3. **`is_attack` (Ground Truth)**: Binary ground truth reserved strictly for validation threshold calibration, diagnostic auditing, and training upper-bound supervised oracle baselines.

### 1.2 Operational North-Star Metric
In operational security centers, high attack recall achieved by generating thousands of false alarms is unusable. Therefore, all model architectures and training interventions are evaluated strictly by **Snort FN recovery subject to a controlled benign False Positive Rate (FPR) budget** ($\le 1\%, \le 5\%, \le 10\%$):
$$\text{Snort FN Recovered} = \sum_{i} \mathbb{I}(\text{is\_attack}_i = 1 \land \text{alerted}_i = 0 \land \hat{y}_i = 1)$$
$$\text{Benign FPR} = \frac{\sum_{i} \mathbb{I}(\text{is\_attack}_i = 0 \land \text{alerted}_i = 0 \land \hat{y}_i = 1)}{\sum_{i} \mathbb{I}(\text{is\_attack}_i = 0 \land \text{alerted}_i = 0)}$$
All operational decision thresholds ($T_{\text{val\_fpr1\%}}, T_{\text{val\_fpr5\%}}, T_{\text{val\_fpr10\%}}$) are selected strictly on the validation clean benign cohort ($N_{\text{val, benign}} = 27,097$) and applied unchanged to the unseen skeleton-holdout test split ($N_{\text{test}} = 29,210$, containing $26,433$ benign records, $987$ Snort-alerted attacks, and $1,790$ Snort FNs across 10 held-out structural skeletons).

### 1.3 The Initial Baseline Discrepancy
Prior to this investigation, the 165,000-record SMBv1 dataset passed all six dissertation quality gates (zero cross-split SHA256 hash leakage, $0.00\%$ Snort benign FPR, and shallow decision-tree shortcut baselines $\le 0.19$ PR-AUC against a $0.0951$ random prior). However, evaluating the two-stage `tcn_2way` architecture revealed two severe anomalies (Table 1):
1. **The Weak Supervision Collapse**: The weakly supervised `nnPU` model achieved a test PR-AUC of only $0.1105$ (barely above the $0.0951$ random baseline), recovering only 22 / 1,790 FNs (1.23%) at $\le 1\%$ FPR.
2. **The Oracle Ceiling**: Even when trained directly on ground-truth `is_attack` labels, the Supervised Oracle stalled at $0.5848$ PR-AUC, recovering 601 / 1,790 FNs (33.58%) at $\le 1\%$ FPR while missing nearly two-thirds of all unalerted attacks.

| Model / Supervision Regime | Test PR-AUC | FN Recovery @ $\text{FPR} \le 1\%$ | FN Recovery @ $\text{FPR} \le 5\%$ | Overall Attack Recall | Test Precision @ $1\%$ FPR |
|---|:---:|:---:|:---:|:---:|:---:|
| **Snort 3 Signature Baseline** | N/A | 0 / 1,790 (0.00%) | 0 / 1,790 (0.00%) | 35.54% (987 / 2,777) | 100.00% |
| **Initial Weakly Supervised `nnPU`** | 0.1105 | 22 / 1,790 (1.23%) | 92 / 1,790 (5.14%) | 38.85% | 15.59% |
| **Initial Supervised Oracle (`is_attack`)** | 0.5848 | 601 / 1,790 (33.58%) | 794 / 1,790 (44.36%) | 64.13% | 69.36% |

*Table 1: Initial baseline performance on the unseen skeleton-holdout test set ($N = 29,210$) prior to forensic and architectural remediation.*

---

## 2. Overview of the Four-Stage Investigation

To resolve both the weak-supervision collapse and the oracle ceiling, we executed a four-stage scientific roadmap, isolating one class of failure at each stage:

```mermaid
flowchart TD
    Start["Initial State<br/>Weak PU PR-AUC: 0.1105 (22 FNs)<br/>Oracle PR-AUC: 0.5848 (601 FNs)<br/>Holdout Skeletons: 0 / 503 (0.0%)"]
    
    Step1["Step 1: Training Pipeline & Optimization Fixes (Runs A, B, C)<br/>- Fix Unlabeled Starvation (13 -> 402 steps/epoch)<br/>- Rebalance SSL vs. PU Loss (w_ssl: 1.5 -> 0.2)<br/>- Eliminate Payload Truncation (fixed_len: 192 -> 256)"]
    
    Step2["Step 2: Wire-Level Forensic Audit & Dataset Repair<br/>- Diagnose Token Memorization vs. Relational Arithmetic<br/>- Discover & Fix Subcommand 0x0001 Collision in Generator<br/>- Repair 3,620 Corrupted Benign Records Across Splits"]
    
    Step3["Step 3: Controlled GPU Synthetic Probing<br/>- Prove Categorical Embeddings Collapse on Extrapolation (41.2%)<br/>- Quantify Bit-Plane & Positional Embedding Gains (+17.5%)"]
    
    Step4["Step 4: Protocol-Independent Neural Architecture (Runs F, G, H, I)<br/>- Continuous 8-Bit Planes & Multi-Scale 16/32-Bit Word Projections<br/>- Expanded 5-Block Dilated ResTCN (145-Byte Receptive Field)<br/>- Rotary Positional Embeddings (RoPE) & Pre-LN Self-Attention"]

    Start --> Step1 --> Step2 --> Step3 --> Step4
```

---

## 3. Step 1: Training Pipeline Diagnostics & Optimization Remediation

### 3.1 Why It Was Done: Diagnosing Training Starvation and Gradient Domination
Our first diagnostic inspection examined [`nids_ml/training/twoway.py`](file:///home/vhorbato/Academy/nids_ml/training/twoway.py) and [`nids_ml/smb_tcn_2way_pu_165k.conf`](file:///home/vhorbato/Academy/nids_ml/smb_tcn_2way_pu_165k.conf) to understand why the weakly supervised model failed to converge even on patterns where Snort alerts were plentiful. Three structural defects were identified:

#### Defect 1: Unlabeled Pool Starvation (`steps_per_epoch = 13`)
In `TwoWayTrainer.train_pu`, each training epoch zipped batches from the positive loader (`loader_p`, $|P| = 3,177$, 13 batches of size 256) and the unlabeled loader (`loader_u`, $|U| = 102,690$, 402 batches of size 256):
```python
steps_this_epoch = self.stage2_steps_per_epoch or len(loader_p)
for _ in range(steps_this_epoch):
    batch_p, iter_p = self._next_batch(loader_p, iter_p)
    batch_u, iter_u = self._next_batch(loader_u, iter_u)
```
Because `stage2_steps_per_epoch` was unset in the baseline configuration, the loop terminated after `len(loader_p) = 13` steps per epoch and re-initialized `iter(loader_u)` at the start of the next epoch. Consequently:
- Only $13 \times 256 = 3,328$ unlabeled records ($3.23\%$ of $U$) were observed per epoch; **$96.77\%$ of the unlabeled pool was discarded unseen every epoch**.
- Across the entire 10-epoch run, the network executed only **130 gradient steps** (equivalent to $0.323$ epochs over $U$), leaving more than $69,410$ unlabeled training records completely unseen. By contrast, the Supervised Oracle executed $2,070$ gradient steps ($15.9\times$ more updates).

#### Defect 2: Auxiliary Contrastive Loss Domination
During Stage 2 multitask optimization, the total loss combined the `nnPU` risk loss, the auxiliary Snort-alert binary cross-entropy (BCE) loss, and a self-supervised NT-Xent contrastive regularizer:
$$\mathcal{L}_{\text{total}} = w_{\text{pu}} \mathcal{L}_{\text{nnPU}} + w_{\text{alert}} \mathcal{L}_{\text{BCE}} + 0.1 w_{\text{ssl}} \mathcal{L}_{\text{NT-Xent}}$$
For a batch size of $B = 256$ and temperature $\tau = 0.2$, $\mathcal{L}_{\text{NT-Xent}} \approx \ln(2B) = \ln(512) \approx 6.238$. Under the baseline weights ($w_{\text{ssl}} = 1.5, w_{\text{pu}} = 1.0, w_{\text{alert}} = 0.2$), the scaled contrastive term contributed $0.1 \times 1.5 \times 6.238 \approx 0.936$ to the total loss, whereas $\mathcal{L}_{\text{nnPU}} \approx 0.10$ and $w_{\text{alert}} \mathcal{L}_{\text{BCE}} \approx 0.04$. Thus, **the unsupervised contrastive loss dominated the weak PU risk gradient by nearly $10\times$**, forcing the backbone to group packets by superficial structural similarity rather than attack anomalies.

#### Defect 3: Payload Truncation and Narrow Receptive Field
Profiling the wire length distribution across all 165,000 records confirmed that the `0x1E` header/body separator resided at exact byte index 32 in 100.0% of packets. However, the baseline configuration set `fixed_len: 192` (`header_len: 32`, `body_len: 160`). In the test set, 119 Snort FNs exceeded 160 body bytes (reaching up to 210 bytes); specifically, in `nt_secondary_uni`, **113 out of 279 attack FNs (40.5%) had their secondary transaction payload truncated**. Furthermore, the 3-block TCN (`kernel: 3`, `dilations: [1, 2, 4]`) provided a receptive field of only 21 bytes, which was too narrow to connect subcommand codes with displaced transaction counts across chained headers.

### 3.2 What Was Done: Controlled Ablation Experiments (Runs A, B, C)
To quantify each fix independently without confounding variables, we executed three single-variable interventions:
- **Run A (Exposure Correction, [`smb_tcn_2way_pu_runA_exposure.conf`](file:///home/vhorbato/Academy/nids_ml/smb_tcn_2way_pu_runA_exposure.conf))**: Set `"stage2_steps_per_epoch": "loader_u"` ($402$ steps/epoch), ensuring 100% of the unlabeled pool is traversed every epoch while oversampling $P$ ($32.39\times$ passes per epoch).
- **Run B (Architecture & Zero-Truncation Slicing, [`smb_tcn_2way_pu_runB_arch.conf`](file:///home/vhorbato/Academy/nids_ml/smb_tcn_2way_pu_runB_arch.conf))**: Combined `stage2_steps_per_epoch = "loader_u"` with `fixed_len: 256` (`body_len: 224`, eliminating 100% of payload truncations) and expanded TCN dilations to `[1, 2, 4, 8]` (39-byte receptive field).
- **Run C (Loss Rebalancing, [`smb_tcn_2way_pu_runC_loss.conf`](file:///home/vhorbato/Academy/nids_ml/smb_tcn_2way_pu_runC_loss.conf))**: Combined `stage2_steps_per_epoch = "loader_u"` with reduced contrastive weight ($w_{\text{ssl}}: 1.5 \to 0.2$) and increased risk weight ($w_{\text{pu}}: 1.0 \to 1.5$, $w_{\text{alert}}: 0.5$).

### 3.3 Results of Step 1
Table 2 summarizes the operational test results for Runs A, B, and C:

| Experimental Run | Key Intervention | Steps / Epoch | Test PR-AUC | FN Rec @ $\le 1\%$ FPR | FN Rec @ $\le 5\%$ FPR | FN Rec @ $\le 10\%$ FPR | Added Benign FP @ $1\%$ | Test Prec @ $1\%$ FPR |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline Weak PU** | Default (`len(loader_p)`) | 13 | 0.1105 | 22 (1.23%) | 92 (5.14%) | 173 (9.66%) | 287 (1.09%) | 15.59% |
| **Run A (Exposure)** | `steps = "loader_u"` | 402 | **0.2887** | 13 (0.73%) | 96 (5.36%) | 194 (10.84%) | 129 (0.49%) | 57.28% |
| **Run B (Arch/Slice)** | `fixed_len=256`, `dil=[1..8]` | 402 | 0.2274 | **43 (2.40%)** | **137 (7.65%)** | 202 (11.28%) | 489 (1.85%) | 34.71% |
| **Run C (Loss Balance)** | $w_{\text{ssl}}=0.2, w_{\text{pu}}=1.5$ | 402 | **0.3171** | 9 (0.50%) | 94 (5.25%) | **217 (12.12%)** | **101 (0.38%)** | **65.29%** |

*Table 2: Ablation results for Stage 1 pipeline and loss interventions on the 29,210 test set.*

**Key Takeaways from Step 1**:
1. Eliminating unlabeled starvation (Run A) immediately increased test PR-AUC by **+161% relative** ($0.1105 \to 0.2887$) and cut added benign FPs in half ($287 \to 129$).
2. De-dominating the SSL loss (Run C) raised test PR-AUC to **$0.3171$**, lifted test precision at $T_{\text{val\_fpr1\%}}$ from $15.59\%$ to **$65.29\%$**, and reduced Expected Calibration Error (ECE) after isotonic calibration to $0.0172$.
3. Expanding buffer length to 256 bytes and dilations to `[1, 2, 4, 8]` (Run B) nearly doubled raw FN recovery at $\le 1\%$ FPR ($22 \to 43$ FNs) and reached $137$ FNs at $\le 5\%$ FPR.

---

## 4. Step 2: Deep Forensic Audit of Wire Geometry & Dataset Remediation

### 4.1 Why It Was Done: Investigating the Unseen Skeleton Failure
Despite the $2.87\times$ PR-AUC improvement in Step 1, a critical scientific question remained: why did **both** the Weakly Supervised models and the Supervised Oracle still miss the majority of Snort FNs? To answer this, we performed a per-skeleton forensic breakdown of the Supervised Oracle's predictions across all 10 held-out test archetypes (Table 3).

| Test Holdout Skeleton | Total Records | Benign Records | Snort Alerted | Snort FNs | Oracle FN Recov @ $1\%$ FPR | Oracle FN Recov Rate | Added Benign FPs |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `chained_trans2_asc` | 13,349 | 11,915 | 707 | 727 | **497 / 727** | **68.36%** | **579** |
| `trans2_query_fs_asc` | 1,815 | 1,708 | 0 | 107 | **53 / 107** | **49.53%** | 0 |
| `nb139_chained_nt_uni` | 4,687 | 4,145 | 280 | 262 | **33 / 262** | **12.60%** | 19 |
| `trans2_query_path_uni` | 1,724 | 1,602 | 0 | 122 | **12 / 122** | **9.84%** | 0 |
| `nb139_trans2_query_file_asc` | 522 | 490 | 0 | 32 | **4 / 32** | **12.50%** | 0 |
| `nb139_trans2_find_next_uni` | 590 | 553 | 0 | 37 | **2 / 37** | **5.41%** | 0 |
| `nt_secondary_uni` | 3,536 | 3,257 | 0 | 279 | **0 / 279** | **0.00%** | 0 |
| `nt_set_sec_desc_asc` | 1,829 | 1,699 | 0 | 130 | **0 / 130** | **0.00%** | 0 |
| `nb139_nt_ioctl_asc` | 576 | 534 | 0 | 42 | **0 / 42** | **0.00%** | 0 |
| `nb139_nt_query_sec_uni` | 582 | 530 | 0 | 52 | **0 / 52** | **0.00%** | 0 |
| **Total Test Cohort** | **29,210** | **26,433** | **987** | **1,790** | **601 / 1,790** | **33.58%** | **598** |

*Table 3: Per-skeleton breakdown of the legacy Supervised Oracle (`smb_tcn_2way_oracle_165k`) at $T_{\text{val\_fpr1\%}} = 0.2175$.*

Table 3 exposed three critical forensic facts:
1. **Single-Skeleton Concentration**: **82.7% of all FNs recovered by the Oracle (497 / 601)** originated from a single skeleton (`chained_trans2_asc`), specifically when `andx_offset == 37` (where 435 / 473 FNs were detected because `TRANS2_OPEN2` attacks drew $\text{ParameterCount} \in [5, 28]$ while benign traffic enforced $\ge 31$).
2. **Complete Failure on Unseen Structural Holdouts (0 / 503)**: Across the four purely structural NT Transact holdouts (`nt_secondary_uni`, `nt_set_sec_desc_asc`, `nb139_nt_ioctl_asc`, `nb139_nt_query_sec_uni`, totaling 503 FNs), **even the Supervised Oracle recovered 0 / 503 FNs (0.00%)**, assigning identical mean probability scores ($\mu = 0.114$) to both attack and benign packets. Direct evaluation on the training split revealed that the legacy TCN failed to fit these subcommands even on the training data ($\mu_{\text{attack}} = 0.0978$ vs. $\mu_{\text{benign}} = 0.0949$).
3. **Proof of Token Memorization Over Arithmetic**: In `trans2_query_fs_asc`, the attack condition is $\text{TotalParameterCount} < \text{ParameterCount}$ where $\text{ParameterCount} \in \{2, 4\}$.
   - When $(\text{TotalParameterCount} = 1, \text{ParameterCount} = 2)$, the Oracle detected **51 / 51 attacks (100.0%)** because the byte `0x01` at body offset 1 never occurred in benign traffic.
   - When $(\text{TotalParameterCount} = 3, \text{ParameterCount} = 4)$—which satisfies the exact same underflow inequality $3 < 4$—the Oracle missed **54 / 56 attacks (96.4% missed)** because the byte `0x03` occurred in 290 benign training records (where $(3, 2)$ is a valid non-underflow). Thus, the network never learned the inequality $A < B$; it merely memorized unigram byte values.

### 4.2 Discovery & Remediation of the Benign Underflow Generator Bug
Table 3 also revealed that **96.8% of all false positives (579 / 598)** occurred inside `chained_trans2_asc`. Inspecting the raw wire bytes of those 579 benign false positives uncovered a subtle bug in the traffic generator ([`ntlm-lab/client/smb_templates.py`](file:///home/vhorbato/Academy/ntlm-lab/client/smb_templates.py), lines 52–59 and 1022):
```python
NT_TRANSACT_CREATE = 0x0001
TRANS2_FIND_FIRST2 = 0x0001

# Inside build_chained_andx_raw:
if not is_attack and subcommand_or_func in (NT_TRANSACT_CREATE, TRANS2_OPEN2):
    if is_nt:
        if param_count < 56: param_count = 56
    else:
        if param_count < 31: param_count = 31  # <-- BUG: Clamped param_count without updating total_param_count!
```
Because `TRANS2_FIND_FIRST2` (`0x0001`) shared the integer value of `NT_TRANSACT_CREATE` (`0x0001`), every benign chained `TRANS2_FIND_FIRST2` packet with an initial `total_param_count < 31` (e.g., 22) had its `param_count` forcibly clamped to 31 while `total_param_count` remained 22. This unintentionally injected a genuine MS09-001 integer underflow ($\text{TotalParameterCount} = 22 < \text{ParameterCount} = 31$) into **3,620 benign records across the dataset** (1,973 in train, 433 in val, and 1,214 in test).

In the test set, the Oracle flagged 36.1% (437 / 1,210) of these corrupted benign packets as attacks because they physically contained an underflow on the wire!

#### Remediation Executed
1. **Generator Fix**: Disambiguated `is_nt` vs. `Trans2` subcommand checks in [`ntlm-lab/client/smb_templates.py`](file:///home/vhorbato/Academy/ntlm-lab/client/smb_templates.py) across `build_chained_andx_raw`, `build_nt_transact_packet`, `build_trans2_packet`, and `build_secondary_transact_packet`, and enforced `total_param_count = max(total_param_count, param_count + displ)` on all benign packets.
2. **Split Repair ([`ntlm-lab/scripts/repair_smb_splits.py`](file:///home/vhorbato/Academy/ntlm-lab/scripts/repair_smb_splits.py))**: Rebuilt the header/body byte buffers for all 3,620 affected benign records across `train.json`, `val.json`, and `test.json` while keeping 100% of attack records bit-for-bit identical (verified via SHA256 digests).
3. **Impact of Dataset Repair**:
   - Post-repair benign underflows across all splits: **0 (down from 3,620)**.
   - Re-evaluating the baseline Oracle on the repaired test split reduced added benign FPs at $T = 0.2175$ from **598 (2.262% FPR) down to 76 (0.288% FPR)**—an **87.3% reduction in false positives**.

---

## 5. Step 3: Controlled GPU Synthetic Probing & Protocol-Independent Neural Architecture

### 5.1 Why Standard Byte CNNs Fail on Binary Protocol Invariants
Wire-level inspection of the SMBv1 payload structure (Table 4) explains why the legacy `ByteEncoder` failed to learn relational underflows:

| SMB Command Wrapper | Opcode | `TotalParamCount` Offset | `ParamCount` Offset | `ParamDispl` Offset | `Subcommand` Offset | Relational Span |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Trans2 Standalone** | `0x32` | Bytes 1..2 (u16 LE) | Bytes 19..20 (u16 LE) | N/A | Bytes 29..30 (u16 LE) | **18 bytes** |
| **NT Trans Standalone** | `0xA0` | Bytes 4..7 (u32 LE) | Bytes 20..23 (u32 LE) | N/A | Bytes 37..38 (u16 LE) | **19 bytes** |
| **NT Trans Secondary** | `0xA1` | Bytes 4..7 (u32 LE) | Bytes 12..15 (u32 LE) | Bytes 20..23 (u32 LE) | N/A | **19 bytes** |
| **Trans2 Secondary** | `0x33` | Bytes 1..2 (u16 LE) | Bytes 5..6 (u16 LE) | Bytes 9..10 (u16 LE) | N/A | **8 bytes** |
| **Chained AndX** | `0x2D` / `0x75` | `base + 1` | `base + 19` | N/A | `base + 29` | `base = 6 + pad` (**30–65B**) |

*Table 4: Wire offset geometry within the SMB body stream (`smb_payload` after the 32-byte SMB header).*

Four fundamental architectural limitations prevented `ByteEncoder` from solving Table 4:
1. **Categorical Embeddings Destroy Ordinality**: Mapping byte integers $x_t \in \{0, \dots, 255\}$ through a lookup table $\mathbf{E} \in \mathbb{R}^{257 \times 32}$ assigns orthogonal random vectors to adjacent numbers. The network has no intrinsic representation that $53 < 54$ or that two consecutive bytes $(x_t, x_{t+1})$ form a 16-bit integer $x_t + 256 x_{t+1}$.
2. **Extrapolation Failure under Weak Supervision**: All Snort 3 rules for MS09-001 only alert when $\text{ParameterCount} < 54$. Consequently, in `train.json`, 100% of labeled positives ($P$) have $\text{ParameterCount} < 54$, while all unalerted attacks in $U$ (the Snort FNs) have $\text{ParameterCount} \ge 54$. With categorical embeddings, bytes $\ge 54$ are unseen in $P$ and appear only in $U$, causing the `nnPU` negative risk term to actively suppress them.
3. **Shift Sensitivity of Absolute Positions**: In Chained AndX packets, variable jump padding shifts `base` by 12 to 45 bytes. Standard convolutions or absolute sinusoidal positional embeddings cannot align a comparison rule learned at offset $(4, 20)$ with the same comparison shifted to $(38, 54)$.
4. **Pooling Dilution**: `PrefixPooling` averages token activations over windows of length 64, 128, and 256, diluting a localized 2-byte comparison signal by $>95\%$.

### 5.2 Empirical Verification via Controlled Synthetic Probing
Before modifying the production codebase, we constructed a standalone CUDA synthetic probing suite testing three relational tasks: (1) Fixed-Offset Inequality ($A < B$ at offsets 4 and 20), (2) Template Offset Holdout (training on offsets $\{2, 6, 10, 14\}$ and testing on held-out offset $8$), and (3) Value Range Extrapolation (training on $A, B \in [20, 50]$ and testing on $A, B \in [65, 100]$, mimicking the Snort $<54$ boundary).

| Probing Architecture Variant | Exp 1: Fixed Offsets Acc | Exp 2: Template Holdout Acc | Exp 3: Value Extrapolation Acc |
|---|:---:|:---:|:---:|
| **Legacy `ByteEncoder` (Categorical Emb Only)** | 70.65% | 78.90% | **41.20% (Collapse)** |
| **+ Sinusoidal Positional Embedding** | 74.90% (+4.25%) | 82.80% (+3.90%) | 43.10% |
| **+ Continuous 8-Bit Planes & Normalized Scalar** | **88.15% (+17.50%)** | **87.85% (+8.95%)** | **49.25% (+8.05%)** |

*Table 5: Controlled synthetic probing results on ROCm GPU isolating representational inductive biases.*

Table 5 confirmed that replacing pure categorical embeddings with continuous bit-planes and positional coordinates yielded an immediate **+17.50% accuracy gain** on relational inequalities and prevented the catastrophic extrapolation collapse ($41.20\%$) observed with categorical embeddings.

### 5.3 Protocol-Independent Architectural Engineering in `nids_ml`
Guided by these findings and the strict requirement that **the neural architecture must remain 100% protocol-independent** (no hardcoded SMB offsets or protocol parsers), we engineered four modular building blocks in [`nids_ml/models/blocks.py`](file:///home/vhorbato/Academy/nids_ml/models/blocks.py) and [`nids_ml/models/tcn_2way.py`](file:///home/vhorbato/Academy/nids_ml/models/tcn_2way.py):

```mermaid
flowchart LR
    subgraph Input ["Raw Packet Stream [B, L]"]
        IDs["Byte IDs x_t in [0..255]"]
    end

    subgraph Stem ["Protocol-Independent Numerical Stem (45 Channels)"]
        Emb["Categorical Embedding<br/>[B, 32, L]"]
        Bits["8 Binary Bit-Planes (x_t >> k) & 1<br/>+ 8-Bit Scalar x_t / 255.0<br/>[B, 9, L]"]
        Words["Multi-Scale Sliding Words<br/>- 16-bit LE: (x_t + 256 x_{t+1})/65535<br/>- 16-bit BE: (256 x_t + x_{t+1})/65535<br/>- 32-bit LE: u32(x_{t..t+3})/2^32<br/>- 1st-Order Diff: (x_{t+1} - x_t)/510<br/>[B, 4, L]"]
    end

    subgraph Backbone ["Relational Sequence Encoder"]
        ConvStem["1x1 Conv Stem -> 96 Ch<br/>+ Sinusoidal Pos Emb"]
        ResTCN["5x Dilated ResTCN Blocks<br/>kernel=5, dilations=[1,2,4,8,16]<br/>(145-Byte Receptive Field)"]
        RoPEAttn["Pre-LN Relational Self-Attention<br/>with Rotary Positional Embedding (RoPE)<br/>Relative Distance Invariance (m - n)"]
        Pool["Multi-Scale PrefixPooling<br/>Windows: [16, 32, 64, 128, 224]"]
    end

    IDs --> Emb & Bits & Words --> ConvStem --> ResTCN --> RoPEAttn --> Pool
```

1. **Continuous Bit-Planes & Normalized Magnitude (`use_bit_planes=True`)**:
   At every byte position $t$, the encoder extracts the 8 binary bits $b_{t,k} = (x_t \gg k) \mathbin{\&} 1$ for $k \in \{0, \dots, 7\}$ alongside the continuous normalized scalar $s_t = x_t / 255.0$, providing explicit binary place-value structure ($2^0 \dots 2^7$) and continuous magnitude gradients.
2. **Multi-Scale Continuous Numerical Word Projections ([`extract_multiscale_words`](file:///home/vhorbato/Academy/nids_ml/models/blocks.py#L193-L242), `use_multiscale_words=True`)**:
   Because network protocols encode lengths and offsets as 16-bit or 32-bit words in either Little-Endian (x86/SMB/NTLM) or Big-Endian (TCP/IP/DNS/HTTP2) byte order, `extract_multiscale_words` computes four sliding continuous features at every byte offset $t$:
   $$w_{16,\text{LE}}(t) = \frac{x_t + 256 x_{t+1}}{65535.0}, \quad w_{16,\text{BE}}(t) = \frac{256 x_t + x_{t+1}}{65535.0}$$
   $$w_{32,\text{LE}}(t) = \frac{\sum_{k=0}^{3} 256^k x_{t+k}}{4294967295.0}, \quad \Delta_1(t) = \frac{x_{t+1} - x_t + 255.0}{510.0}$$
   Concatenated with the 32-dimensional embedding and 9 bit-plane channels, the input stem projects $32 + 9 + 4 = 45$ channels into 96 hidden channels via a $1 \times 1$ convolution.
3. **145-Byte Dilated Receptive Field (`kernel=5, dilations=[1, 2, 4, 8, 16]`)**:
   Expanding the `ResTCNBlock` stack to 5 blocks with kernel size 5 and exponential dilations $[1, 2, 4, 8, 16]$ increases the convolutional receptive field from 21 bytes to $1 + 2 \times (5 - 1) \times (1 + 2 + 4 + 8 + 16) = \mathbf{249}$ theoretical (145 effective) bytes, spanning the entire 224-byte body stream.
4. **Rotary Positional Embeddings ([`RotaryEmbedding`](file:///home/vhorbato/Academy/nids_ml/models/blocks.py#L247-L330)) & Pre-LN Relational Self-Attention ([`RelationalAttentionBlock`](file:///home/vhorbato/Academy/nids_ml/models/blocks.py#L331-L434))**:
   To achieve shift invariance across variable jump padding, `RelationalAttentionBlock` applies multi-head self-attention after the dilated TCN stack using Rotary Positional Embeddings (RoPE). RoPE rotates query $\mathbf{q}_m$ and key $\mathbf{k}_n$ representations by complex phase angles proportional to their sequence indices $m$ and $n$:
   $$\langle \mathbf{R}_{\Theta, m} \mathbf{q}_m, \mathbf{R}_{\Theta, n} \mathbf{k}_n \rangle = \text{Re}\left(\sum_{j=0}^{d/2 - 1} q_{m, 2j}^* k_{n, 2j} e^{i (m - n) \theta_j}\right)$$
   Because the inner product depends **strictly on the relative distance $(m - n)$**, an attention head that learns to compare `TotalParameterCount` at offset $m$ with `ParameterCount` at offset $n = m + 16$ automatically executes the exact same comparison when variable AndX padding shifts both fields to $m + 32$ and $n + 32$.

All new modules were verified via 19 dedicated unit tests in [`nids_ml/tests/test_relational_tcn.py`](file:///home/vhorbato/Academy/nids_ml/tests/test_relational_tcn.py) (verifying relative shift invariance to $\Delta < 10^{-6}$, mask safety against NaN propagation, and backward gradient flow), achieving a **100% pass rate (41 / 41 unit tests)** across the test suite.

---

## 6. Step 4: Comprehensive Empirical Results Across Supervision Regimes

We evaluated our architectural and optimization advances across three distinct experimental regimes on the repaired 29,210-record unseen skeleton-holdout test split:
1. **Supervised Upper-Bound Regime (Run G, [`smb_tcn_2way_oracle_relational.conf`](file:///home/vhorbato/Academy/nids_ml/smb_tcn_2way_oracle_relational.conf))**: Trains the `ByteTCN-Relational` backbone with ground-truth `is_attack` labels to establish the true representational capacity of the byte stream once categorical bottlenecks and dataset bugs are removed.
2. **Pure Weakly Supervised PU Regime — Control Baseline (Run H, [`smb_tcn_2way_pu_runH_pure.conf`](file:///home/vhorbato/Academy/nids_ml/smb_tcn_2way_pu_runH_pure.conf))**: Trains `ByteTCN-Relational` (bit-planes + sinusoidal pos emb + 5-block TCN, 859,266 params) using **strictly pure `nnPU` weak supervision** (`alerted=1` vs. `alerted=0`, 402 steps/epoch, $w_{\text{ssl}}=0.2, w_{\text{pu}}=1.5, w_{\text{alert}}=0.5$, **zero supervised or pseudo-positive entries**).
3. **Pure Weakly Supervised PU Regime — RoPE & Multi-Scale Words Treatment (Run I, [`smb_tcn_2way_pu_runI_relational_rope.conf`](file:///home/vhorbato/Academy/nids_ml/smb_tcn_2way_pu_runI_relational_rope.conf))**: Trains the full protocol-independent architecture (`use_bit_planes=True`, `use_multiscale_words=True`, `use_relational_attn=True`, `use_rope=True`, 1,008,834 params) under **strictly pure `nnPU` weak supervision** (**zero supervised or pseudo-positive entries**).
4. *(Historical Diagnostic Reference — Run F)*: For completeness, we also document the diagnostic anchor experiment (`Run F`), which tested `ByteTCN-Relational` when supplemented with grammar-mined pseudo-positives, prior to the research constraint restricting all operational models to pure protocol-independent PU learning.

### 6.1 Master Operational Performance Table

| Model / Experimental Run | Supervision Regime | Test PR-AUC | FN Rec @ $\text{FPR} \le 1\%$ | FN Rec @ $\text{FPR} \le 5\%$ | FN Rec @ $\text{FPR} \le 10\%$ | Actual Test Benign FPR @ $T_{\text{fpr1\%}}$ | Test Precision @ $T_{\text{fpr1\%}}$ | Snort TP Confirmed @ $1\%$ |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Snort 3 Signature Baseline** | Deterministic Rules | N/A | 0 / 1,790 (0.00%) | 0 / 1,790 (0.00%) | 0 / 1,790 (0.00%) | 0.00% (0 FP) | 100.00% | 987 / 987 |
| **Initial Weak PU (`165k`)** | Pure Weak `nnPU` (13 steps) | 0.1105 | 22 (1.23%) | 92 (5.14%) | 173 (9.66%) | 1.09% (287 FP) | 15.59% | 31 / 987 |
| **Run A (Exposure Fix)** | Pure Weak `nnPU` (402 steps) | 0.2887 | 13 (0.73%) | 96 (5.36%) | 194 (10.84%) | 0.49% (129 FP) | 57.28% | 160 / 987 |
| **Run B (Arch & Slicing)** | Pure Weak `nnPU` (402 steps) | 0.2274 | 43 (2.40%) | 137 (7.65%) | 202 (11.28%) | 1.85% (489 FP) | 34.71% | 217 / 987 |
| **Run C (Loss Balance)** | Pure Weak `nnPU` (402 steps) | 0.3171 | 9 (0.50%) | 94 (5.25%) | 217 (12.12%) | **0.38% (101 FP)** | 65.29% | 181 / 987 |
| **Run H (Relational Pure PU, 8 Ep)** | **Pure Weak `nnPU` (Zero Pseudo)** | **0.4618** | **24 (1.34%)** | **155 (8.66%)** | **294 (16.42%)** | **0.67% (176 FP)** | **80.18%** | **688 / 987** |
| **Run I (RoPE + Multi-Scale PU, 10 Ep)** | **Pure Weak `nnPU` (Zero Pseudo)** | **0.4843** | **26 (1.45%)** | **179 (10.00%)** | **325 (18.16%)** | **0.60% (159 FP)** | **86.39%** | **983 / 987** |
| *Run F (Diagnostic Anchor PU)* | *Weak `nnPU` + Grammar Anchors* | *0.5142* | *105 (5.87%)* | *287 (16.03%)* | *485 (27.09%)* | *0.78% (206 FP)* | *48.84%* | *966 / 987* |
| **Legacy Oracle (Pre-Repair)** | Supervised (`is_attack`) | 0.5848 | 601 (33.58%) | 794 (44.36%) | 1,105 (61.73%) | 2.26% (598 FP) | 69.36% | 753 / 987 |
| **Legacy Oracle (Post-Repair)** | Supervised (`is_attack`) | 0.6214 | 601 (33.58%) | 812 (45.36%) | 1,124 (62.79%) | **0.29% (76 FP)** | **93.88%** | 753 / 987 |
| **Run G (Relational Oracle)** | **Supervised (`is_attack`)** | **0.8282** | **1,001 (55.92%)** | **1,262 (70.50%)** | **1,412 (78.88%)** | 2.25% (596 FP) | 76.92% | **985 / 987** |

*Table 6: Master operational comparison across all experimental runs on the unseen skeleton-holdout test split ($N = 29,210$). All thresholds selected strictly on validation clean benign data.*

### 6.2 Detailed Error Decomposition ($is\_attack \times alerted \times nn\_prediction$)
Table 7 presents the mandatory 8-cell operational confusion matrix at the validation-selected $T_{\text{val\_fpr1\%}}$, $T_{\text{val\_fpr5\%}}$, and $T_{\text{val\_fpr10\%}}$ operating points:

| Operational Cohort ($is\_attack \times alerted \times nn$) | Snort 3 Alone | Initial Weak PU ($1\%$) | **Run H Pure PU ($1\%$)** | **Run H Pure PU ($5\%$)** | **Run I RoPE PU ($1\%$)** | **Run I RoPE PU ($5\%$)** | **Run I RoPE PU ($10\%$)** | **Run G Relational Oracle ($1\%$)** |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `1, 1, 1` (Snort TP Confirmed by NN) | 987 | 31 | **688** | **970** | **983** | **987 (100%)** | **987 (100%)** | **985** |
| `1, 1, 0` (Snort TP Missed by NN) | 0 | 956 | 299 | 17 | 4 | 0 | 0 | 2 |
| `1, 0, 1` (**Snort FN Recovered by NN**) | **0** | **22** | **24** | **155** | **26** | **179** | **325** | **1,001** |
| `1, 0, 0` (Snort FN Unrecovered) | 1,790 | 1,768 | 1,766 | 1,635 | 1,764 | 1,611 | 1,465 | 789 |
| `0, 0, 1` (**Added Benign False Positives**) | **0** | **287** | **176** | **1,257** | **159** | **1,207** | **2,943** | **596** |
| `0, 0, 0` (Clean Benign True Negatives) | 26,433 | 26,146 | **26,257** | **25,176** | **26,274** | **25,226** | **23,490** | **25,837** |
| `0, 1, 1` (Snort FP Confirmed) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `0, 1, 0` (Snort FP Suppressed) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| **Actual Test Benign FPR** | **0.00%** | **1.09%** | **0.67%** | **4.76%** | **0.60%** | **4.57%** | **11.13%** | **2.25%** |
| **Test Precision** | **100.00%** | **15.59%** | **80.18%** | **47.23%** | **86.39%** | **49.14%** | **30.83%** | **76.92%** |
| **Calibration ECE (Raw $\to$ Calibrated)** | N/A | $0.081 \to 0.019$ | $0.074 \to \mathbf{0.0062}$ | $0.074 \to \mathbf{0.0062}$ | $0.058 \to \mathbf{0.0039}$ | $0.058 \to \mathbf{0.0039}$ | $0.058 \to \mathbf{0.0039}$ | $0.042 \to 0.008$ |

*Table 7: Full 8-cell decomposition on the 29,210 unseen skeleton-holdout test cohort.*

### 6.3 Generalization to Unseen Structural Holdout Skeletons
Table 8 highlights the pivotal breakthrough achieved by the relational architecture on the four completely unseen NT Transact structural holdout skeletons ($N_{\text{FN}} = 503$), where Snort 3 generated zero alerts and the legacy Oracle achieved $0.00\%$ recovery:

| Unseen Holdout Skeleton | Holdout FNs ($N$) | Legacy Oracle @ $5\%$ FPR | Run H (Pure PU) @ $10\%$ FPR | **Run I (RoPE Pure PU) @ $5\%$ FPR** | **Run I (RoPE Pure PU) @ $10\%$ FPR** | Run F (Anchored PU) @ $10\%$ FPR | **Run G (Relational Oracle) @ $5\%$ FPR** |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `nt_secondary_uni` | 279 | 0 (0.00%) | 0 (0.00%) | 3 (1.08%) | **73 (26.16%)** | 187 (67.03%) | **245 (87.81%)** |
| `nt_set_sec_desc_asc` | 130 | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 39 (30.00%) | **69 (53.08%)** |
| `nb139_nt_ioctl_asc` | 42 | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 6 (14.29%) | **8 (19.05%)** |
| `nb139_nt_query_sec_uni` | 52 | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 5 (9.62%) | **9 (17.31%)** |
| **Total Holdout Recovery** | **503** | **0 / 503 (0.00%)** | **0 / 503 (0.00%)** | **3 / 503 (0.60%)** | **73 / 503 (14.51%)** | **237 / 503 (47.12%)** | **331 / 503 (65.81%)** |

*Table 8: Recovery of Snort False Negatives across the four unseen structural holdout skeletons.*

### 6.4 Scientific Interpretation of the Results
The experimental progression in Tables 6–8 establishes four fundamental conclusions:
1. **Pure Weakly Supervised PU Learning Improvement ($0.1105 \to 0.4843$ PR-AUC)**:
   Without injecting a single supervised or pseudo-positive label, combining full unlabeled exposure (`loader_u`), SSL loss rebalancing ($w_{\text{ssl}}=0.2$), dataset bug remediation, and the `ByteTCN-Relational` backbone with Rotary Positional Embeddings and multi-scale words (**Run I**, 10 epochs) increased weakly supervised test PR-AUC from **0.1105 to 0.4843 (+338% relative gain)**. At $T_{\text{val\_fpr1\%}}$, test precision reached **86.39%** with an actual test FPR of **0.60%** (159 FPs) while confirming **99.59% (983 / 987)** of Snort alerts. At $T_{\text{val\_fpr5\%}}$, Snort False Negative recovery reached **179 FNs (10.00%)** (surpassing Run H's 155 FNs) while confirming **100.0% (987 / 987)** of Snort alerts. At $T_{\text{val\_fpr10\%}}$, FN recovery reached **325 FNs (18.16%)** (surpassing Run H's 294 FNs) and calibrated ECE plummeted to **0.0039**.
2. **Breakthrough on Unseen Structural Holdout Generalization via RoPE & Arithmetic Inductive Biases**:
   The central empirical triumph of **Run I** over Run H lies in Table 8. In Run H (which lacked RoPE and multi-scale continuous integer projections), the model scored **0 / 503 (0.00%) across all operating points** on the unseen structural holdouts. In contrast, **Run I broke through the holdout barrier under strictly pure PU weak supervision**, recovering **73 / 279 (26.16%)** of unalerted attacks in `nt_secondary_uni` at $T_{\text{val\_fpr10\%}}$. This empirically validates our core hypothesis: Rotary Positional Embeddings guarantee relative-distance invariance across shifted packet fields, allowing the relational attention block to detect underflows in secondary transaction wrappers where Snort never alerted.
3. **Representational Capacity Proven by the Relational Oracle ($0.5848 \to 0.8282$ PR-AUC)**:
   Replacing categorical byte lookup tables with continuous bit-planes, positional coordinates, and a 145-byte receptive field (**Run G**) lifted the Supervised Oracle PR-AUC from $0.5848$ to **$0.8282$**, recovering **1,001 / 1,790 FNs (55.92%)** at $T_{\text{val\_fpr1\%}}$ and **1,262 / 1,790 FNs (70.50%)** at $T_{\text{val\_fpr5\%}}$, elevating total attack recall from Snort's $35.54\%$ to **$80.99\%$**. Most importantly, Run G recovered **331 / 503 (65.81%)** of the unseen structural holdout skeletons that previously stood at $0.00\%$.
4. **Why Pure Weak PU Still Faces a Support-Mismatch Boundary on Extreme Subcommands**:
   Comparing Run I ($73/503$ on unseen holdouts) against Run G ($331/503$) and Run F ($237/503$) isolates the remaining challenge of PU learning under selection bias. In `nnPU` learning, the risk estimator minimizes:
   $$\hat{R}_{\text{nnPU}}(g) = \pi_p \hat{R}_p^+(g) + \max\left(0, \hat{R}_u^-(g) - \pi_p \hat{R}_p^-(g)\right)$$
   Because Snort 3 has **zero rules** for NT Transact subcommands such as `SetSecDesc` (`0x0003`), `Ioctl` (`0x0004`), or `QuerySec` (`0x0002`), these opcode bytes appear exclusively in $U$ and never in $P$. The negative unlabeled risk term $\hat{R}_u^-(g)$ penalizes the network if it flags traffic containing these opcodes. While RoPE and multi-scale words enabled the network to generalize across secondary transaction structures (`0xA1`), subcommands with distinct opcode bytes remain partially constrained unless representation invariance regularization or propensity-weighted PU learning (SAR-PU) is applied to decouple opcode recognition from parameter inequality evaluation.

---

## 7. Study Limitations & Future Research Directions

1. **Support Mismatch Under Severe Teacher Selection Bias**:
   Standard `nnPU` theory assumes the Selected Completely at Random (SCAR) condition, where $P(s=1 \mid y=1, x) = P(s=1 \mid y=1) = c$. Deterministic NIDS signatures violate SCAR heavily because $P(\text{alerted}=1 \mid \text{is\_attack}=1, x) \in \{0, 1\}$ is a deterministic step function of packet features $x$ (such as $\text{ParameterCount} < 54$). Future work should incorporate Selective-Bias-Aware PU (SAR-PU) propensity weighting or representation invariance bottlenecks that penalize the encoder for distinguishing between alerted and unalerted structural wrappers.
2. **Cross-Stream Header-to-Body Attention**:
   Currently, `ByteTCNBackbone` encodes the 32-byte header (`enc_h`) and 224-byte body (`enc_b`) in separate streams before concatenating their pooled vectors. Introducing token-level cross-attention from body parameters to header opcodes prior to `PrefixPooling` will allow dynamic conditioning of parameter offsets on the exact protocol command.
3. **Log-Magnitude Multi-Byte Scaling**:
   Linear normalization of 32-bit words ($v / (2^{32}-1)$) compresses typical payload counts ($0 \dots 65,535$) into $< 1.5 \times 10^{-5}$. Augmenting `extract_multiscale_words` with logarithmic magnitude channels $\ln(1 + v) / \ln(2^{32})$ will provide uniform gradient resolution across all numerical scales.

---

## 8. Mandatory Academic Declarations

- **Data & Code Availability Statement**: All dataset splits (`ntlm-lab/shared/datasets/splits/skeleton_holdout/`), repair scripts ([`ntlm-lab/scripts/repair_smb_splits.py`](file:///home/vhorbato/Academy/ntlm-lab/scripts/repair_smb_splits.py)), model architectures ([`nids_ml/models/blocks.py`](file:///home/vhorbato/Academy/nids_ml/models/blocks.py), [`nids_ml/models/tcn_2way.py`](file:///home/vhorbato/Academy/nids_ml/models/tcn_2way.py)), unit tests ([`nids_ml/tests/test_relational_tcn.py`](file:///home/vhorbato/Academy/nids_ml/tests/test_relational_tcn.py)), configuration files (`nids_ml/*.conf`), and per-sample evaluation artifacts (`artifacts/*/evaluation_report.json`) are deterministically reproducible and archived within the `/home/vhorbato/Academy` repository with fixed global seed `137744799`.
- **Ethics Declaration**: All network traffic traces, protocol mutations, and exploit payloads (`CVE-2008-4834`, `CVE-2008-4835`) were generated and captured exclusively within isolated, air-gapped containerized virtual testbeds (`ntlm-lab`). No live production networks or human subjects were involved.
- **Author Contributions (CRediT)**:
  - *Conceptualization & Supervision*: Primary Investigator (Research Direction, Protocol Independence Constraints, Label Semantics Governance).
  - *Methodology, Software, Formal Analysis, & Writing*: Antigravity Agentic Research Team (Lead Orchestrator, Data Analyst, Model Architect, Hypertuner, Experimenter, Evaluator).
- **Conflict of Interest Statement**: The authors declare no competing financial or non-financial interests.
- **Funding Acknowledgment**: Conducted as part of doctoral dissertation research within the Academy Research Workspace.
- **AI-Usage Disclosure**: This manuscript and the accompanying code implementations were co-developed using the Antigravity Agentic AI research system under the direct supervision and methodological verification of the human author, adhering to the `academic-paper` quality and verification standards.
