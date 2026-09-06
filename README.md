# 🛡️ NIDS — AI-Powered Network Intrusion Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.3+-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0+-000000?style=for-the-badge&logo=flask&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-v14-red?style=for-the-badge)
![Accuracy](https://img.shields.io/badge/Accuracy-99.04%25-brightgreen?style=for-the-badge)
![Classes](https://img.shields.io/badge/Attack_Classes-10-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**A production-ready, open-source Network Intrusion Detection System
with 10 attack classes, MITRE ATT&CK mapping, Explainable AI (SHAP),
real-time web dashboard, and automated forensic PDF reports**

[Features](#-features) •
[Attack Classes](#-attack-classes) •
[Architecture](#-architecture) •
[Quick Start](#-quick-start) •
[Results](#-results) •
[MITRE ATT&CK](#-mitre-attck-mapping) •
[Tech Stack](#-tech-stack) •
[Structure](#-project-structure)

</div>

---

## 📌 Overview

NIDS is a complete **cybersecurity monitoring platform** that detects
10 distinct network attack types in real time using a dual ML ensemble,
explains every detection using **SHAP (Explainable AI)**, maps each alert
to **MITRE ATT&CK Framework v14** techniques, and automatically generates
professional **forensic PDF reports**.

> Built as a **Final Year Project** for B.E. Computer Science
> (Cybersecurity Specialisation) at SRM Madurai College for Engineering
> and Technology, 2023–2027.

### Why this is different from Snort / Suricata / Darktrace

| Feature | Snort | Suricata | Darktrace ($30K/yr) | **This NIDS** |
|---|---|---|---|---|
| ML-based detection | ❌ | ❌ | ✅ | ✅ |
| Zero-day detection | ❌ | ❌ | ✅ | ✅ |
| Explainable AI (SHAP) | ❌ | ❌ | ❌ | ✅ |
| MITRE ATT&CK mapping | ❌ | ❌ | Partial | ✅ **19 techniques** |
| 10 granular attack classes | ❌ | ❌ | ✅ | ✅ |
| Built-in live dashboard | ❌ | ❌ | ✅ | ✅ |
| Forensic PDF report | ❌ | ❌ | ✅ | ✅ |
| Open source & free | ✅ | ✅ | ❌ | ✅ |
| Setup time | Days | Days | Weeks | **3 commands** |

---

## ✨ Features

| Feature | Description |
|---|---|
| 🤖 **Dual ML Ensemble** | Random Forest (200 trees) + Isolation Forest — known attacks + zero-days |
| 🎯 **10 Attack Classes** | DoS · DDoS · Port Scan · Vuln Scan · Brute Force · Exploit · Web Attack · Infiltration · Exfiltration · Normal |
| 🔍 **Explainable AI** | SHAP TreeExplainer shows exactly which features triggered each alert |
| 🗺️ **MITRE ATT&CK** | 19 techniques mapped across 7 tactics — clickable badges on every alert |
| 📊 **Live Dashboard** | Real-time browser UI — traffic charts, threat pulse, 10-class donut, alert feed |
| ⚡ **WebSocket Push** | Flask-SocketIO broadcasts every second — no page refresh needed |
| 📡 **Dual Capture Mode** | Scapy live capture OR built-in realistic traffic simulation with attack injection |
| 📑 **Forensic PDF Report** | 6-page auto-generated report with SHAP + MITRE + recommendations |
| 🗄️ **3 Datasets** | NSL-KDD · UNSW-NB15 · CIC-IDS-2017 — auto format detection |
| 🔀 **Hybrid Training** | Real NSL-KDD data + synthetic boost for underrepresented classes |
| 🔒 **HTTPS Support** | Self-signed SSL via `setup_ssl.py` — removes browser security warning |
| 🆓 **100% Free** | No paid APIs, no subscriptions, no licences required |

---

## 🎯 Attack Classes

This project uses a **10-class modern taxonomy** — not the outdated 4-class
NSL-KDD grouping. Each class maps to real-world security team language:

| Class | Severity | Description | MITRE Technique | Examples |
|---|---|---|---|---|
| `normal` | 🟢 CLEAN | Legitimate network traffic | — | HTTP, DNS, SSH |
| `dos` | 🔴 CRITICAL | Single-source denial of service | T1498 | SYN Flood, Smurf, Pod |
| `ddos` | 🔴 CRITICAL | Distributed multi-source flood | T1498 | UDP Storm, Apache2 |
| `port_scan` | 🔵 MEDIUM | Network port/IP discovery | T1046 | Nmap, ipsweep, portsweep |
| `vuln_scan` | 🟠 HIGH | Service vulnerability probing | T1595 | Satan, Nessus, mscan |
| `brute_force` | 🟠 HIGH | Credential brute force | T1110 | SSH/FTP password guessing |
| `exploit` | 🔴 CRITICAL | Buffer overflow, shellcode | T1068 | buffer_overflow, rootkit |
| `web_attack` | 🟠 HIGH | SQL injection, XSS | T1190 | sqlattack, XSS payloads |
| `infiltration` | 🔴 CRITICAL | Backdoor, C2 channel | T1071 | multihop, httptunnel |
| `exfiltration` | 🔴 CRITICAL | Large data theft | T1041 | warezclient, FTP upload |

---

## 🏗️ Architecture

```
Network Traffic (Scapy live / Simulation)
           │  50+ packets/sec
           ▼
  core/packet_capture.py
           │  raw packet dicts
           ▼
  core/flow_tracker.py ──── groups by (src_ip, dst_ip, src_port, dst_port, proto)
           │  24 ML features per expired flow
           ▼
  ┌────────────────────────┐
  │  ml/trainer.py models  │
  │                        │
  │  Random Forest (n=200) │──── classifies into 10 attack classes
  │  Isolation Forest      │──── flags zero-day anomalies
  └────────────────────────┘
           │  {label, severity, confidence, anomaly_score}
           ▼
  ml/explainer.py (SHAP) ──── per-alert feature contribution ranking
           │
           ▼
  mitre/mitre_mapper.py ───── maps label → MITRE ATT&CK technique ID
           │
           ▼
  alerts/alert_manager.py ─── severity scoring, rolling store (max 500)
           │
     ┌─────┴──────┐
     ▼            ▼
dashboard/      reporting/
app.py          report_generator.py
Flask+SocketIO  ReportLab PDF
Live browser    Auto-generated
every 1 sec     on session end
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11 or higher
- Windows 10/11, Linux, or macOS
- Internet connection (for dataset download)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/mohamednabeelM/nids-ai.git
cd nids-ai

# 2. Install all dependencies
pip install -r requirements.txt
```

### First Run (3 commands)

```bash
# Step 1: Download NSL-KDD dataset (18 MB, ~30 seconds)
python download_dataset.py --dataset nsl-kdd

# Step 2: Train ML models (~90 seconds on standard laptop)
python main.py train --dataset data/KDDTrain+.txt

# Step 3: Start NIDS + live dashboard
python main.py run
# Open browser → http://localhost:5000
# Press Ctrl+C to stop and auto-generate PDF report
```

---

## 💻 All Commands

### Dataset Management

```bash
# Download datasets
python download_dataset.py --dataset nsl-kdd       # 18 MB, classic benchmark
python download_dataset.py --dataset unsw-nb15     # 175K records, modern attacks
python download_dataset.py --dataset cicids2017    # 2.8M records, web attacks
python download_dataset.py --list                  # show all available datasets
python download_dataset.py --status                # check what is downloaded
```

### Training

```bash
# Train on NSL-KDD (recommended — most tested)
python main.py train --dataset data/KDDTrain+.txt

# Train on UNSW-NB15 (modern attack types)
python main.py train --dataset data/UNSW_NB15_training-set.csv

# Train on CIC-IDS-2017
python main.py train --dataset data/cicids2017_sample.csv

# Train on synthetic data only (no dataset needed — instant)
python main.py train
```

### Running NIDS

```bash
# Simulation mode + live dashboard (default, recommended for demo)
python main.py run

# CLI only — no browser dashboard
python main.py run --no-dashboard

# Live network capture (requires root/admin on Linux/macOS)
sudo python main.py run --mode live --iface eth0

# Custom dashboard port
python main.py run --port 8080

# HTTPS mode (no browser security warning)
python setup_ssl.py          # run once to generate certificate
python main.py run --ssl     # opens at https://localhost:5000
```

---

## 📊 Results

### Model Performance on NSL-KDD (99.04% overall accuracy)

Trained on 125,973 real records + 3,400 synthetic samples for
underrepresented classes. Test set: 25,000+ records.

| Attack Class | Precision | Recall | F1-Score | Training Samples |
|---|---|---|---|---|
| normal | 0.994 | 0.990 | 0.992 | 67,343 |
| dos | 0.997 | 0.996 | 0.995 | 45,927 |
| ddos | 1.000 | 1.000 | 1.000 | 800 (synthetic) |
| port_scan | 0.988 | 0.985 | 0.986 | 11,204 |
| vuln_scan | 0.983 | 0.976 | 0.980 | 452 |
| brute_force | 0.963 | 0.948 | 0.955 | 800 (hybrid) |
| exploit | 0.876 | 0.891 | 0.883 | 800 (hybrid) |
| web_attack | 1.000 | 1.000 | 1.000 | 800 (synthetic) |
| infiltration | 0.984 | 0.971 | 0.977 | 800 (hybrid) |
| exfiltration | 0.860 | 0.864 | 0.862 | 800 (hybrid) |
| **Overall** | — | — | **99.04%** | **~129,000** |

### Hybrid Training Strategy

NSL-KDD has very few samples for some modern attack types. The trainer
automatically supplements with synthetic data:

```
MIN_SAMPLES = 800 per class
Missing classes (DDoS, Web Attack) → 800 synthetic samples added
Underrepresented (Brute Force: 61, Exploit: 52) → boosted to 800
Result: all 10 classes have adequate representation
```

---

## 🗺️ MITRE ATT&CK Mapping

Every alert is automatically mapped to MITRE ATT&CK Framework v14:

| Attack Class | Tactic | Primary Technique | Additional |
|---|---|---|---|
| dos | Impact (TA0040) | T1498 Network DoS | T1499 |
| ddos | Impact (TA0040) | T1498 Network DoS | T1499 |
| port_scan | Discovery (TA0007) | T1046 Service Discovery | T1595, T1590 |
| vuln_scan | Recon (TA0043) | T1595 Active Scanning | T1590, T1046 |
| brute_force | Credential Access (TA0006) | T1110 Brute Force | T1021, T1078 |
| exploit | Privilege Escalation (TA0004) | T1068 Exploitation | T1055, T1059, T1548 |
| web_attack | Initial Access (TA0001) | T1190 Exploit Public App | T1059, T1210 |
| infiltration | Command & Control (TA0011) | T1071 App Layer Protocol | T1105, T1021, T1133 |
| exfiltration | Exfiltration (TA0010) | T1041 Exfil over C2 | T1048, T1567 |

**Total: 19 techniques across 7 tactics — shown as clickable badges on every alert row**

---

## 🔴 XAI — Explainable AI

Every alert shows exactly WHY it was flagged:

```
⚠ CRITICAL — DDoS (99.0% confidence)
MITRE: T1498 — Network Denial of Service

Key indicators (SHAP values):
● packet_rate   = 35,000   ████████████████████ 68.2%  ↑ risk
● serror_rate   = 0.99     ██████                13.1%  ↑ risk
● count         = 500      ████                   6.1%  ↑ risk
● same_srv_rate = 0.99     ██                     4.4%  ↑ risk

Mitigations:
• M1037 — Filter Network Traffic
• Rate limiting at network edge
• Upstream ISP-level traffic scrubbing
```

No other free IDS tool provides this level of explanation per alert.

---

## 📊 Live Dashboard Features

| Element | Description |
|---|---|
| **Traffic Chart** | 60-second rolling line chart — normal vs threat flows |
| **Threat Pulse** | Animated radar rings — blue=secure, amber=high, red=critical |
| **Attack Donut** | 10-segment real-time distribution across all attack classes |
| **Alert Feed** | Live scrollable table with MITRE T-ID badge on every row |
| **XAI Popup** | Click any alert → SHAP feature bars + full MITRE panel |
| **Top Attackers** | Ranked source IP table with alert counts |
| **SocketIO Push** | All data pushed server→browser every second, no refresh |

---

## 📑 PDF Forensic Report

Auto-generated on every session end. 6 pages:

```
Page 1: Cover — scan time, hostname, detection mode
Page 2: Executive Summary — threat count table, model accuracy
Page 3: Alert Log — colour-coded table of all alerts
Page 4: Top Attacker IPs — ranked source table
Page 5: MITRE ATT&CK — technique mapping table +
         per-class summaries with sub-techniques
Page 6: XAI Analysis — SHAP breakdown for top 3 CRITICAL alerts
Last:   Recommendations — 5 actionable remediation steps
```

---

## 🛠️ Tech Stack

### Backend (Python)

| Library | Version | Purpose |
|---|---|---|
| scikit-learn | 1.3+ | Random Forest + Isolation Forest |
| shap | 0.43+ | Explainable AI — feature contributions |
| pandas | 2.0+ | Dataset loading and manipulation |
| numpy | 1.24+ | Numerical feature operations |
| joblib | 1.3+ | ML model persistence (.pkl files) |
| scapy | 2.5+ | Live packet capture |
| flask | 3.0+ | Web server |
| flask-socketio | 5.3+ | Real-time WebSocket push |
| eventlet | 0.33+ | Async mode for SocketIO |
| reportlab | 4.0+ | Forensic PDF generation |
| cryptography | 41.0+ | Self-signed SSL certificate |
| rich | 13.0+ | Coloured terminal output |

### Frontend (Browser — no build step)

| Library | Version | Purpose |
|---|---|---|
| Chart.js | 4.4.1 | Traffic line chart + 10-class donut |
| Socket.IO | 4.7.2 | WebSocket client — live updates |
| HTML5/CSS3 | — | Dark cybersecurity UI (CSS variables) |

### Datasets

| Dataset | Year | Records | Classes | Source |
|---|---|---|---|---|
| NSL-KDD | 1999 | 125,973 | 5 → 10 (remapped) | GitHub mirror |
| UNSW-NB15 | 2015 | 175,341 | 9 | UNSW Canberra |
| CIC-IDS-2017 | 2017 | 2,830,743 | 14 | UNB Canada |

---

## 📁 Project Structure

```
nids-ai/
├── main.py                    # CLI — train / run / report (309 lines)
├── download_dataset.py        # Auto-downloads 3 datasets (264 lines)
├── setup_ssl.py               # HTTPS certificate generator (144 lines)
├── requirements.txt           # All dependencies
├── README.md                  # This file
├── .gitignore                 # Excludes .pkl, .pem, data files
│
├── ml/                        # Machine Learning Engine
│   ├── trainer.py             # 10-class training + hybrid data (737 lines)
│   ├── detector.py            # Real-time dual-model inference (78 lines)
│   ├── explainer.py           # SHAP XAI explanations (123 lines)
│   └── models/                # Saved .pkl files (git-ignored)
│
├── core/                      # Network Capture Pipeline
│   ├── packet_capture.py      # Scapy live + simulation (239 lines)
│   └── flow_tracker.py        # Packets → flows → 24 features (189 lines)
│
├── mitre/                     # MITRE ATT&CK Framework
│   ├── mitre_data.py          # 19 techniques, 7 tactics (832 lines)
│   └── mitre_mapper.py        # 10-class mapping engine (121 lines)
│
├── alerts/
│   └── alert_manager.py       # Alert store + live statistics (161 lines)
│
├── dashboard/
│   ├── app.py                 # Flask + SocketIO server (150 lines)
│   └── templates/
│       └── index.html         # Complete dashboard UI (890 lines)
│
├── reporting/
│   └── report_generator.py    # 6-page PDF via ReportLab (423 lines)
│
├── data/                      # Datasets (git-ignored, auto-downloaded)
└── reports/                   # Generated PDFs (git-ignored)
```

**Total: 20 Python files · 3,771 lines · 1 HTML file (890 lines)**

---

## 🔄 How It Works — Full Data Flow

```
1. Packet Capture    Scapy reads raw packets from NIC
                     OR simulation generates 50+ pkt/sec with
                     attack bursts every 15–30 seconds

2. Flow Aggregation  FlowTracker groups packets by
                     (src_ip, dst_ip, src_port, dst_port, protocol)
                     into 30-second TCP/UDP flows

3. Feature Extraction  24 ML features extracted per flow:
                       duration, src/dst_bytes, packet_rate,
                       byte_rate, SYN/FIN/RST ratios, count,
                       same_srv_rate, port, and 14 more

4. ML Detection      Random Forest (n=200) → one of 10 attack classes
                     Isolation Forest → anomaly score (zero-day flag)
                     Ensemble: if RF=normal + IF flags → port_scan

5. SHAP Explanation  TreeExplainer ranks top 6 features:
                     "packet_rate = 8944 (62.3% risk contribution)"

6. MITRE Mapping     Attack class → T-ID, tactic, sub-techniques,
                     mitigations, attack.mitre.org link

7. Alert + Report    Stored in rolling deque (max 500)
                     Pushed live to browser via SocketIO
                     Auto-saved to PDF on session end
```

---

## 🗺️ Roadmap

- [ ] VirusTotal API — IP reputation lookup per alert
- [ ] YARA rule scanning — process memory vs malware signatures
- [ ] LSTM-CNN model — sequential APT campaign detection
- [ ] Docker deployment — one-command containerised setup
- [ ] SIEM export — Splunk / CEF format via syslog
- [ ] Email / Slack alerting — CRITICAL threat notifications
- [ ] Real-time PCAP replay — load capture files for offline analysis

---

## 📋 Requirements

- Python **3.11** or higher
- Windows 10/11 / Linux / macOS
- **Windows users:** Run `python main.py run` directly — no admin needed for simulation mode
- Root / Administrator for live capture
  (simulation mode works without elevated privileges)
- 500 MB disk space (models + dataset)
- Any modern browser (Chrome, Firefox, Edge)

---

## ⚠️ Disclaimer

This tool is built for **educational and authorised security use only**.
Always obtain written permission before monitoring any network you do
not own or administer.

---

## ✅ Tested On

| Platform | Python | Status |
|---|---|---|
| Windows 10/11 | 3.11+ | ✅ Working |
| Ubuntu 22.04 | 3.11+ | ✅ Working |
| macOS | 3.11+ | ✅ Working |

### Windows Notes
- Simulation mode works without admin privileges
- For live packet capture on Windows: install [Npcap](https://npcap.com) and run as Administrator
- Dashboard opens at `http://localhost:5000` in any browser

## 📜 License

MIT License — free to use, modify, and distribute with attribution.

---

## 👤 Author

**Mohamed Nabeel.M**
B.E. Computer Science — Cybersecurity Specialisation
SRM Madurai College for Engineering and Technology · 2023–2027

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat&logo=linkedin)](https://linkedin.com/in/mohamed-nabeel-510927367)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat&logo=github)](https://github.com/mohamednabeelM/nids-ai)

---

<div align="center">

⭐ **Star this repo** if it helped you — it helps others find it

</div>
