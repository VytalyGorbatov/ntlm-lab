# NTLM Lab & Dataset Pipeline: NTLMSSP FastPattern Evaluation Environment

This environment provides a reproducible, containerized testbed for generating, capturing, and processing NTLM authentication traffic across SMB dialects. It is designed to evaluate cross-protocol transfer of the **Per Fast Pattern neural risk-scoring layer** developed in `nids_ml`, targeting the primary FastPattern group:

$$\text{FastPattern: } \texttt{NTLMSSP|00 03 00 00 00|}$$

---

## 1. Dissertation North-Star Objective

All traffic generation, mutations, and evaluations adhere to the dissertation objective:

> **Recover Snort False Negatives at a controlled benign false-positive budget.**

```text
Snort FN          = is_attack=1 AND alerted=0
Added Benign FP   = is_attack=0 AND alerted=0 AND nn_prediction=1
Benign FPR        = Added Benign FP / count(is_attack=0 AND alerted=0)
```

### Label Semantics:
- `alerted=1`: Snort teacher signal / reliable IDS positive.
- `alerted=0`: Unlabeled from IDS perspective (contains both clean benign and Snort False Negatives).
- `is_attack`: Ground truth label used **only** for evaluation, diagnostics, and oracle upper bounds.

---

## 2. Architecture & Network Topology

Isolated Docker bridge network `ntlmnet` (`172.24.0.0/16`):

```text
                   +----------------------------------+
                   |    ntlm_server (172.24.0.10)     |
                   |   - Ubuntu 22.04 + Samba 4.15    |
                   |   - Ports: 445, 139, 135         |
                   |   - Shares: [public], [secured]  |
                   +----------------+-----------------+
                                    |
            +-----------------------+-----------------------+
            |                                               |
+-----------+---------------------+   +---------------------+-----------+
|    ntlm_client (172.24.0.20)    |   |   ntlm_attacker (172.24.0.30)   |
|  - Legitimate SMB sessions      |   |  - Attack generator (Impacket)  |
|  - Standard Windows signing     |   |  - CVE-2019-1040, bursts, FNs   |
+---------------------------------+   +---------------------------------+
```

---

## 3. Directory Layout

```text
ntlm-lab/
├── docker-compose.yml          # 3-node container orchestration
├── README.md                   # This documentation
├── client/
│   ├── Dockerfile              # Python 3.11 with Impacket & Scapy
│   ├── benign_generator.py     # High-entropy legitimate NTLM session generator
│   ├── attack_generator.py     # Multi-scenario attack & evasion generator
│   ├── run_benign.sh           # Benign runner with connection check
│   ├── run_attack.sh           # Attack runner with connection check
│   └── requirements.txt        # Python dependencies
├── server/
│   ├── Dockerfile              # Samba 4.15 server
│   ├── entrypoint.sh           # Account provisioning & smbd starter
│   └── configs/smb.conf        # Dialect & NTLM authentication configuration
├── scripts/
│   ├── start_capture.sh        # Background tcpdump on eth0
│   ├── stop_capture.sh         # Clean capture termination & flush
│   ├── run_snort_eval.sh       # Snort 3 fast alert summary
│   ├── process_ntlm_dataset.py # Snort alert_json + buffer dumps processor
│   ├── combine_datasets.py     # Cohort merger & 2x2 matrix evaluator
│   └── run_dataset_pipeline.sh # Master one-touch generation & processing script
└── shared/
    ├── configs/                # Users, credentials, domains, workstations
    ├── pcaps/                  # Captured raw network PCAPs
    └── datasets/               # JSON datasets and alert_json dumps with buffer extracts
```

---

## 4. Attack Scenarios & Ground Truth Breakdown

The attack generator ([`attack_generator.py`](file:///home/vhorbato/Academy/ntlm-lab/client/attack_generator.py)) produces both Snort-alerted attacks and Snort False Negatives:

| Scenario Name | Type | Target SID | Wire Behavior / Mutation |
|---|---|---|---|
| `cve_2019_1040_smbv2` | Alerted | SID 59653 | Drop-the-MIC attack on SMBv2 (clearing `0x42008010` in flags, stripping MIC) |
| `cve_2019_1040_smbv1` | Alerted | SID 50633 | Drop-the-MIC attack on SMBv1 |
| `smbv1_brute_burst` | Alerted | SID 50633 / 44651 | Rapid burst of SMBv1 auth requests ($\ge 5$ req/s) |
| `cve_2019_1040_evasion` | Snort FN | Anchor SID 1 only | MIC stripped, but flags retain `0x40000010` to evade Snort rule bitmask |
| `mic_tampering` | Snort FN | Anchor SID 1 only | Random byte corruption of 16-byte MIC in NTLMSSP Type 3 |
| `password_spraying` | Snort FN | Anchor SID 1 only | Low-rate password spraying (< 2 req/s) evading detection filter rate |
| `credential_stuffing` | Snort FN | Anchor SID 1 only | Targeted credential stuffing with forged `ntlm` responses |
| `null_session_smbv2` | Snort FN | Anchor SID 1 only | Anonymous null session over SMBv2 (evades SMBv1-only SID 33825) |
| `malformed_offsets` | Snort FN | Anchor SID 1 only | Corrupted offset/length headers in NTLMSSP Type 3 |

---

## 5. Usage & Master Pipeline

### 5.1 One-Touch Dataset Generation & Snort Processing
To run the full end-to-end pipeline (captures benign, captures attack, runs Snort 3 with `alert_json` and buffer extraction, and generates the dissertation evaluation matrix):

```bash
./scripts/run_dataset_pipeline.sh 50 50
```

### 5.2 Manual Step Execution
1. **Start capture**:
   ```bash
   ./scripts/start_capture.sh my_capture.pcap
   ```
2. **Generate traffic**:
   - Benign:
     ```bash
     docker exec ntlm_client /opt/client/run_benign.sh --count 50
     ```
   - Attack:
     ```bash
     docker exec ntlm_attacker /opt/client/run_attack.sh --count 50 --scenario mixed --fn-ratio 0.6
     ```
3. **Stop capture**:
   ```bash
   ./scripts/stop_capture.sh my_capture.pcap
   ```
4. **Run Snort with `alert_json` and buffer dumps**:
   ```bash
   python3 scripts/process_ntlm_dataset.py \
       -i shared/pcaps/my_capture.pcap \
       -o shared/datasets/my_dataset.json \
       [--is-attack]
   ```
5. **Combine datasets**:
   ```bash
   python3 scripts/combine_datasets.py \
       --benign shared/datasets/benign_basic.json \
       --attack shared/datasets/attack_basic.json \
       -o shared/datasets/combined_basic.json \
       --report shared/datasets/dataset_report.md
   ```

---

## 6. Output Dataset Schema

Each record in `shared/datasets/combined_basic.json` strictly adheres to the format required by `nids_ml`:

```json
{
  "flowstart_time": 0,
  "seconds": 0,
  "proto": "TCP",
  "pkt_gen": "stream_tcp",
  "pkt_len": 456,
  "dir": "C2S",
  "src_ap": "172.24.0.20:59484",
  "dst_ap": "172.24.0.10:445",
  "client_bytes": 1333,
  "client_pkts": 7,
  "server_bytes": 1258,
  "server_pkts": 6,
  "buffers": "...",
  "buffer_names": "ntlmssp_auth\u001e",
  "alerted": 0,
  "is_attack": 0,
  "attack_rules": [],
  "all_rules": ["1:1:0"],
  "meta": {
    "domain": "WORKGROUP",
    "username": "user1",
    "workstation": "WS-DEV-99",
    "negotiate_flags": "0xe0888235",
    "ntlm_offset": 108,
    "payload_len": 456
  }
}
```
The `buffers` field is transport-encoded in latin-1 string format, perfectly compatible with `decode_buffers_field` in `nids_ml/data/common.py`.
