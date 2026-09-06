"""
 NIDS — AI-Powered Network Intrusion Detection System
# Author  : Mohamed Nabeel.M
# Degree  : B.E. Computer Science (Cybersecurity), 2023–2027
# GitHub  : https://github.com/mohamednabeelM/nids-ai
# License : MIT License (see LICENSE.txt)
============================================================

ml/trainer.py — Trains the NIDS ML pipeline on NSL-KDD dataset
or synthetic data when the dataset is unavailable.

Models trained:
  1. Random Forest   — supervised, multi-class attack classification
  2. Isolation Forest — unsupervised, zero-day anomaly detection
"""

import os
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix
)

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

FEATURE_NAMES = [
    "duration", "protocol_type", "src_bytes", "dst_bytes",
    "wrong_fragment", "urgent", "count", "srv_count",
    "serror_rate", "rerror_rate", "same_srv_rate", "diff_srv_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_serror_rate",
    "packet_rate", "byte_rate",
    "flag_syn_ratio", "flag_fin_ratio", "flag_rst_ratio",
    "port_number", "is_well_known_port",
]

# ─── Expanded 10-Class Attack Taxonomy (2026) ────────────────────────────────
ATTACK_CLASSES = [
    "normal",       # Legitimate network traffic
    "dos",          # Denial of Service — single source flood
    "ddos",         # Distributed DoS — multi-source coordinated
    "port_scan",    # Port/IP scanning (Nmap, ipsweep, portsweep)
    "vuln_scan",    # Vulnerability enumeration (satan, mscan)
    "brute_force",  # Credential brute force (SSH, FTP, HTTP)
    "exploit",      # Buffer overflow, shellcode, privilege escalation
    "web_attack",   # SQL injection, XSS, HTTP exploitation
    "infiltration", # Backdoor, unauthorized remote access, C2
    "exfiltration", # Data theft — large outbound transfers
]

SEVERITY_MAP = {
    "normal":      "CLEAN",
    "dos":         "CRITICAL",
    "ddos":        "CRITICAL",
    "port_scan":   "MEDIUM",
    "vuln_scan":   "HIGH",
    "brute_force": "HIGH",
    "exploit":     "CRITICAL",
    "web_attack":  "HIGH",
    "infiltration":"CRITICAL",
    "exfiltration":"CRITICAL",
}

# Human-readable display names
CLASS_DISPLAY = {
    "normal":      "Normal Traffic",
    "dos":         "DoS — Denial of Service",
    "ddos":        "DDoS — Distributed DoS",
    "port_scan":   "Port Scan",
    "vuln_scan":   "Vulnerability Scan",
    "brute_force": "Brute Force Attack",
    "exploit":     "Exploit / Injection",
    "web_attack":  "Web Attack (XSS/SQLi)",
    "infiltration":"Infiltration / Backdoor",
    "exfiltration":"Data Exfiltration",
}

# ─── Synthetic Data Generator ─────────────────────────────────────────────────

def _rng(seed):
    return __import__('numpy').random.default_rng(seed)

def _make_normal(n):
    r = _rng(0)
    return {
        "duration":r.exponential(30,n),"protocol_type":r.choice([0,1,2],n,p=[0.6,0.35,0.05]),
        "src_bytes":r.lognormal(8,2,n),"dst_bytes":r.lognormal(9,2,n),
        "wrong_fragment":__import__('numpy').zeros(n),"urgent":__import__('numpy').zeros(n),
        "count":r.integers(1,50,n),"srv_count":r.integers(1,30,n),
        "serror_rate":r.uniform(0,0.1,n),"rerror_rate":r.uniform(0,0.1,n),
        "same_srv_rate":r.uniform(0.7,1.0,n),"diff_srv_rate":r.uniform(0,0.3,n),
        "dst_host_count":r.integers(1,255,n),"dst_host_srv_count":r.integers(1,100,n),
        "dst_host_same_srv_rate":r.uniform(0.5,1.0,n),"dst_host_diff_srv_rate":r.uniform(0,0.2,n),
        "dst_host_serror_rate":r.uniform(0,0.1,n),"packet_rate":r.uniform(1,100,n),
        "byte_rate":r.uniform(100,10000,n),"flag_syn_ratio":r.uniform(0,0.3,n),
        "flag_fin_ratio":r.uniform(0,0.3,n),"flag_rst_ratio":r.uniform(0,0.1,n),
        "port_number":r.choice([80,443,22,25,53,8080],n),"is_well_known_port":__import__('numpy').ones(n),
    }

def _make_dos(n):
    r = _rng(1)
    return {
        "duration":r.exponential(1,n),"protocol_type":r.choice([0,2],n,p=[0.7,0.3]),
        "src_bytes":r.lognormal(5,1,n),"dst_bytes":r.lognormal(4,1,n),
        "wrong_fragment":r.integers(0,5,n).astype(float),"urgent":__import__('numpy').zeros(n),
        "count":r.integers(200,512,n),"srv_count":r.integers(200,512,n),
        "serror_rate":r.uniform(0.85,1.0,n),"rerror_rate":r.uniform(0,0.1,n),
        "same_srv_rate":r.uniform(0.9,1.0,n),"diff_srv_rate":r.uniform(0,0.05,n),
        "dst_host_count":r.integers(240,255,n),"dst_host_srv_count":r.integers(230,255,n),
        "dst_host_same_srv_rate":r.uniform(0.95,1.0,n),"dst_host_diff_srv_rate":r.uniform(0,0.05,n),
        "dst_host_serror_rate":r.uniform(0.85,1.0,n),"packet_rate":r.uniform(2000,15000,n),
        "byte_rate":r.uniform(50000,200000,n),"flag_syn_ratio":r.uniform(0.8,1.0,n),
        "flag_fin_ratio":r.uniform(0,0.05,n),"flag_rst_ratio":r.uniform(0.1,0.4,n),
        "port_number":r.integers(1,1024,n),"is_well_known_port":__import__('numpy').ones(n),
    }

def _make_ddos(n):
    """DDoS: multi-source, even higher volume, amplification patterns."""
    r = _rng(2)
    return {
        "duration":r.exponential(0.5,n),"protocol_type":r.choice([0,1,2],n,p=[0.4,0.4,0.2]),
        "src_bytes":r.lognormal(4,1,n),"dst_bytes":r.lognormal(3,1,n),
        "wrong_fragment":r.integers(0,8,n).astype(float),"urgent":__import__('numpy').zeros(n),
        "count":r.integers(400,512,n),"srv_count":r.integers(350,512,n),
        "serror_rate":r.uniform(0.9,1.0,n),"rerror_rate":r.uniform(0,0.05,n),
        "same_srv_rate":r.uniform(0.95,1.0,n),"diff_srv_rate":r.uniform(0,0.03,n),
        "dst_host_count":r.integers(250,255,n),"dst_host_srv_count":r.integers(245,255,n),
        "dst_host_same_srv_rate":r.uniform(0.98,1.0,n),"dst_host_diff_srv_rate":r.uniform(0,0.02,n),
        "dst_host_serror_rate":r.uniform(0.9,1.0,n),"packet_rate":r.uniform(10000,50000,n),
        "byte_rate":r.uniform(200000,1000000,n),"flag_syn_ratio":r.uniform(0.85,1.0,n),
        "flag_fin_ratio":r.uniform(0,0.03,n),"flag_rst_ratio":r.uniform(0.05,0.3,n),
        "port_number":r.choice([80,443,53,123],n),"is_well_known_port":__import__('numpy').ones(n),
    }

def _make_port_scan(n):
    """Port Scan: Nmap/ipsweep — sequential ports, low bytes, high RST."""
    r = _rng(3)
    return {
        "duration":r.exponential(0.5,n),"protocol_type":r.choice([0,1],n,p=[0.6,0.4]),
        "src_bytes":r.lognormal(3,1,n),"dst_bytes":r.lognormal(2,1,n),
        "wrong_fragment":__import__('numpy').zeros(n),"urgent":__import__('numpy').zeros(n),
        "count":r.integers(1,30,n),"srv_count":r.integers(1,15,n),
        "serror_rate":r.uniform(0.2,0.7,n),"rerror_rate":r.uniform(0.4,0.9,n),
        "same_srv_rate":r.uniform(0,0.15,n),"diff_srv_rate":r.uniform(0.85,1.0,n),
        "dst_host_count":r.integers(1,10,n),"dst_host_srv_count":r.integers(1,255,n),
        "dst_host_same_srv_rate":r.uniform(0,0.1,n),"dst_host_diff_srv_rate":r.uniform(0.9,1.0,n),
        "dst_host_serror_rate":r.uniform(0.3,0.8,n),"packet_rate":r.uniform(50,800,n),
        "byte_rate":r.uniform(50,3000,n),"flag_syn_ratio":r.uniform(0.6,1.0,n),
        "flag_fin_ratio":r.uniform(0,0.1,n),"flag_rst_ratio":r.uniform(0.5,0.95,n),
        "port_number":r.integers(1,65535,n),"is_well_known_port":r.choice([0,1],n,p=[0.6,0.4]),
    }

def _make_vuln_scan(n):
    """Vuln Scan: targeted service probing — slower, smarter than port scan."""
    r = _rng(4)
    return {
        "duration":r.exponential(2,n),"protocol_type":__import__('numpy').zeros(n),  # TCP
        "src_bytes":r.lognormal(5,1,n),"dst_bytes":r.lognormal(5,1,n),
        "wrong_fragment":__import__('numpy').zeros(n),"urgent":__import__('numpy').zeros(n),
        "count":r.integers(5,60,n),"srv_count":r.integers(3,30,n),
        "serror_rate":r.uniform(0.1,0.5,n),"rerror_rate":r.uniform(0.2,0.6,n),
        "same_srv_rate":r.uniform(0.1,0.4,n),"diff_srv_rate":r.uniform(0.6,0.9,n),
        "dst_host_count":r.integers(1,30,n),"dst_host_srv_count":r.integers(5,80,n),
        "dst_host_same_srv_rate":r.uniform(0.1,0.4,n),"dst_host_diff_srv_rate":r.uniform(0.6,0.9,n),
        "dst_host_serror_rate":r.uniform(0.1,0.5,n),"packet_rate":r.uniform(10,200,n),
        "byte_rate":r.uniform(500,8000,n),"flag_syn_ratio":r.uniform(0.3,0.7,n),
        "flag_fin_ratio":r.uniform(0.1,0.4,n),"flag_rst_ratio":r.uniform(0.2,0.6,n),
        "port_number":r.choice([21,22,23,25,80,110,443,445,3306,8080],n),
        "is_well_known_port":__import__('numpy').ones(n),
    }

def _make_brute_force(n):
    """Brute Force: repeated auth attempts to SSH/FTP/HTTP — same service, many tries."""
    r = _rng(5)
    return {
        "duration":r.exponential(60,n),"protocol_type":__import__('numpy').zeros(n),
        "src_bytes":r.lognormal(6,1,n),"dst_bytes":r.lognormal(8,1,n),
        "wrong_fragment":__import__('numpy').zeros(n),"urgent":__import__('numpy').zeros(n),
        "count":r.integers(50,300,n),"srv_count":r.integers(50,300,n),
        "serror_rate":r.uniform(0,0.2,n),"rerror_rate":r.uniform(0.3,0.8,n),
        "same_srv_rate":r.uniform(0.85,1.0,n),"diff_srv_rate":r.uniform(0,0.1,n),
        "dst_host_count":r.integers(1,5,n),"dst_host_srv_count":r.integers(50,300,n),
        "dst_host_same_srv_rate":r.uniform(0.9,1.0,n),"dst_host_diff_srv_rate":r.uniform(0,0.05,n),
        "dst_host_serror_rate":r.uniform(0,0.2,n),"packet_rate":r.uniform(5,80,n),
        "byte_rate":r.uniform(1000,15000,n),"flag_syn_ratio":r.uniform(0.1,0.4,n),
        "flag_fin_ratio":r.uniform(0.2,0.6,n),"flag_rst_ratio":r.uniform(0.1,0.4,n),
        "port_number":r.choice([21,22,80,110,443,3306],n),
        "is_well_known_port":__import__('numpy').ones(n),
    }

def _make_exploit(n):
    """Exploit: buffer overflow/shellcode — large payload, single connection."""
    r = _rng(6)
    return {
        "duration":r.exponential(150,n),"protocol_type":__import__('numpy').zeros(n),
        "src_bytes":r.lognormal(11,1,n),"dst_bytes":r.lognormal(9,1,n),
        "wrong_fragment":__import__('numpy').zeros(n),"urgent":r.integers(0,6,n).astype(float),
        "count":r.integers(1,8,n),"srv_count":r.integers(1,5,n),
        "serror_rate":r.uniform(0,0.1,n),"rerror_rate":r.uniform(0,0.1,n),
        "same_srv_rate":r.uniform(0.5,1.0,n),"diff_srv_rate":r.uniform(0,0.2,n),
        "dst_host_count":r.integers(1,15,n),"dst_host_srv_count":r.integers(1,8,n),
        "dst_host_same_srv_rate":r.uniform(0.5,1.0,n),"dst_host_diff_srv_rate":r.uniform(0,0.2,n),
        "dst_host_serror_rate":r.uniform(0,0.1,n),"packet_rate":r.uniform(1,25,n),
        "byte_rate":r.uniform(5000,500000,n),"flag_syn_ratio":r.uniform(0,0.2,n),
        "flag_fin_ratio":r.uniform(0.5,1.0,n),"flag_rst_ratio":r.uniform(0,0.15,n),
        "port_number":r.choice([22,23,513,514,80,8080],n),
        "is_well_known_port":r.choice([0,1],n,p=[0.3,0.7]),
    }

def _make_web_attack(n):
    """Web Attack: SQLi/XSS — port 80/443, crafted payloads in HTTP."""
    r = _rng(7)
    return {
        "duration":r.exponential(5,n),"protocol_type":__import__('numpy').zeros(n),
        "src_bytes":r.lognormal(7,1,n),"dst_bytes":r.lognormal(8,1,n),
        "wrong_fragment":__import__('numpy').zeros(n),"urgent":__import__('numpy').zeros(n),
        "count":r.integers(10,100,n),"srv_count":r.integers(10,100,n),
        "serror_rate":r.uniform(0,0.15,n),"rerror_rate":r.uniform(0.1,0.4,n),
        "same_srv_rate":r.uniform(0.7,1.0,n),"diff_srv_rate":r.uniform(0,0.2,n),
        "dst_host_count":r.integers(1,10,n),"dst_host_srv_count":r.integers(10,100,n),
        "dst_host_same_srv_rate":r.uniform(0.8,1.0,n),"dst_host_diff_srv_rate":r.uniform(0,0.1,n),
        "dst_host_serror_rate":r.uniform(0,0.15,n),"packet_rate":r.uniform(2,50,n),
        "byte_rate":r.uniform(2000,30000,n),"flag_syn_ratio":r.uniform(0.05,0.25,n),
        "flag_fin_ratio":r.uniform(0.3,0.7,n),"flag_rst_ratio":r.uniform(0.05,0.2,n),
        "port_number":r.choice([80,443,8080,8443],n),"is_well_known_port":__import__('numpy').ones(n),
    }

def _make_infiltration(n):
    """Infiltration/Backdoor: persistent low-traffic covert channel."""
    r = _rng(8)
    return {
        "duration":r.exponential(300,n),"protocol_type":__import__('numpy').zeros(n),
        "src_bytes":r.lognormal(7,1,n),"dst_bytes":r.lognormal(6,1,n),
        "wrong_fragment":__import__('numpy').zeros(n),"urgent":r.integers(0,2,n).astype(float),
        "count":r.integers(1,10,n),"srv_count":r.integers(1,5,n),
        "serror_rate":r.uniform(0,0.05,n),"rerror_rate":r.uniform(0,0.05,n),
        "same_srv_rate":r.uniform(0.6,1.0,n),"diff_srv_rate":r.uniform(0,0.15,n),
        "dst_host_count":r.integers(1,5,n),"dst_host_srv_count":r.integers(1,5,n),
        "dst_host_same_srv_rate":r.uniform(0.7,1.0,n),"dst_host_diff_srv_rate":r.uniform(0,0.1,n),
        "dst_host_serror_rate":r.uniform(0,0.05,n),"packet_rate":r.uniform(0.5,10,n),
        "byte_rate":r.uniform(500,20000,n),"flag_syn_ratio":r.uniform(0,0.15,n),
        "flag_fin_ratio":r.uniform(0.4,0.8,n),"flag_rst_ratio":r.uniform(0,0.1,n),
        "port_number":r.choice([4444,5555,6666,31337,8888,9999,1337],n),
        "is_well_known_port":__import__('numpy').zeros(n),  # Non-standard ports
    }

def _make_exfiltration(n):
    """Exfiltration: large outbound data transfers — high byte_rate, big dst_bytes."""
    r = _rng(9)
    return {
        "duration":r.exponential(120,n),"protocol_type":__import__('numpy').zeros(n),
        "src_bytes":r.lognormal(7,1,n),"dst_bytes":r.lognormal(14,1,n),  # Very high
        "wrong_fragment":__import__('numpy').zeros(n),"urgent":__import__('numpy').zeros(n),
        "count":r.integers(1,20,n),"srv_count":r.integers(1,10,n),
        "serror_rate":r.uniform(0,0.1,n),"rerror_rate":r.uniform(0,0.1,n),
        "same_srv_rate":r.uniform(0.5,1.0,n),"diff_srv_rate":r.uniform(0,0.3,n),
        "dst_host_count":r.integers(1,10,n),"dst_host_srv_count":r.integers(1,10,n),
        "dst_host_same_srv_rate":r.uniform(0.5,1.0,n),"dst_host_diff_srv_rate":r.uniform(0,0.2,n),
        "dst_host_serror_rate":r.uniform(0,0.1,n),"packet_rate":r.uniform(1,30,n),
        "byte_rate":r.uniform(100000,10000000,n),"flag_syn_ratio":r.uniform(0,0.15,n),
        "flag_fin_ratio":r.uniform(0.5,0.9,n),"flag_rst_ratio":r.uniform(0,0.1,n),
        "port_number":r.choice([21,80,443,8080,25,465],n),
        "is_well_known_port":__import__('numpy').ones(n),
    }


def generate_synthetic_dataset(n_per_class: int = 2000) -> tuple:
    """Generate synthetic network flow data for all 10 attack classes."""
    import numpy as np, pandas as pd
    builders = {
        "normal":      _make_normal,
        "dos":         _make_dos,
        "ddos":        _make_ddos,
        "port_scan":   _make_port_scan,
        "vuln_scan":   _make_vuln_scan,
        "brute_force": _make_brute_force,
        "exploit":     _make_exploit,
        "web_attack":  _make_web_attack,
        "infiltration":_make_infiltration,
        "exfiltration":_make_exfiltration,
    }
    dfs, labels = [], []
    for cls, builder in builders.items():
        d   = builder(n_per_class)
        df  = pd.DataFrame(d, columns=FEATURE_NAMES)
        # Add small Gaussian noise
        for col in FEATURE_NAMES[:-2]:
            std = df[col].std()
            if std > 0:
                df[col] += np.random.normal(0, std * 0.02, n_per_class)
        df = df.clip(lower=0)
        dfs.append(df)
        labels.extend([cls] * n_per_class)
    return pd.concat(dfs, ignore_index=True), pd.Series(labels)



# ─── Trainer Class ────────────────────────────────────────────────────────────

class NIDSTrainer:
    def __init__(self, model_dir: str = MODEL_DIR):
        self.model_dir    = model_dir
        self.rf_model     = None
        self.iso_model    = None
        self.scaler       = None
        self.label_enc    = None
        os.makedirs(model_dir, exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def train(self, dataset_path: str | None = None,
              n_per_class: int = 2000) -> dict:
        """Train RF + Isolation Forest. Returns metrics dict."""
        X, y = self._load_data(dataset_path, n_per_class)

        # Encode + scale
        self.label_enc = LabelEncoder()
        y_enc = self.label_enc.fit_transform(y)
        self.scaler = StandardScaler()
        X_sc = self.scaler.fit_transform(X)

        X_tr, X_te, y_tr, y_te = train_test_split(
            X_sc, y_enc, test_size=0.2,
            random_state=42, stratify=y_enc,
        )

        # Random Forest
        self.rf_model = RandomForestClassifier(
            n_estimators=150, max_depth=20,
            min_samples_split=4, random_state=42,
            class_weight="balanced", n_jobs=-1,
        )
        self.rf_model.fit(X_tr, y_tr)
        y_pred  = self.rf_model.predict(X_te)
        acc     = accuracy_score(y_te, y_pred)
        report  = classification_report(
            y_te, y_pred,
            target_names=self.label_enc.classes_,
            output_dict=True,
        )

        # Isolation Forest — train only on normal traffic
        normal_mask = (y == "normal").values
        self.iso_model = IsolationForest(
            n_estimators=150, contamination=0.05,
            random_state=42, n_jobs=-1,
        )
        self.iso_model.fit(X_sc[normal_mask])

        self._save()
        return {"accuracy": acc, "report": report}

    def load(self) -> bool:
        """Load persisted models. Returns False if not found."""
        try:
            self.rf_model  = joblib.load(f"{self.model_dir}/rf.pkl")
            self.iso_model = joblib.load(f"{self.model_dir}/iso.pkl")
            self.scaler    = joblib.load(f"{self.model_dir}/scaler.pkl")
            self.label_enc = joblib.load(f"{self.model_dir}/label_enc.pkl")
            return True
        except FileNotFoundError:
            return False

    def models_exist(self) -> bool:
        return all(
            os.path.exists(f"{self.model_dir}/{f}")
            for f in ["rf.pkl","iso.pkl","scaler.pkl","label_enc.pkl"]
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load_data(self, path, n_per_class):
        if path and os.path.exists(path):
            # Expects NSL-KDD KDDTrain+.txt format
            cols = FEATURE_NAMES + ["label", "difficulty"]
            df = pd.read_csv(path, names=cols)
            X  = df[FEATURE_NAMES]
            y  = df["label"].map(self._nsl_label_map()).fillna("normal")
            return X, y
        return generate_synthetic_dataset(n_per_class)

    @staticmethod
    def _nsl_label_map() -> dict:
        """
        Granular NSL-KDD sub-label → 10-class mapping.
        Each original sub-label is mapped to the most semantically
        accurate modern attack class.
        """
        return {
            # ── Normal ──────────────────────────────────────────────
            "normal":          "normal",

            # ── DoS (single-source floods) ───────────────────────────
            "neptune":         "dos",      # SYN flood
            "smurf":           "dos",      # ICMP amplification
            "pod":             "dos",      # Ping of death
            "teardrop":        "dos",      # IP fragmentation
            "back":            "dos",      # Apache DoS
            "land":            "dos",      # Same src/dst IP
            "worm":            "dos",      # Worm-based disruption

            # ── DDoS (high-volume / distributed-like) ───────────────
            "apache2":         "ddos",     # HTTP flood from many
            "udpstorm":        "ddos",     # UDP amplification storm
            "processtable":    "ddos",     # Process table exhaustion

            # ── Port Scan (host/port discovery) ─────────────────────
            "ipsweep":         "port_scan", # IP sweep
            "nmap":            "port_scan", # Nmap port scan
            "portsweep":       "port_scan", # Port sweep
            "mscan":           "port_scan", # Mini-scan
            "saint":           "port_scan", # Security scanner

            # ── Vulnerability Scan (service enumeration) ────────────
            "satan":           "vuln_scan", # Security admin tool

            # ── Brute Force (credential attacks) ────────────────────
            "guess_passwd":    "brute_force",  # Password guessing
            "ftp_write":       "brute_force",  # FTP write exploit
            "xlock":           "brute_force",  # X11 lock brute force
            "xsnoop":          "brute_force",  # X11 snooping
            "snmpguess":       "brute_force",  # SNMP community guess
            "snmpgetattack":   "brute_force",  # SNMP GET attack

            # ── Infiltration (unauthorized remote access) ────────────
            "imap":            "infiltration", # IMAP buffer overflow
            "multihop":        "infiltration", # Multi-hop backdoor
            "phf":             "infiltration", # PHF CGI exploit
            "spy":             "infiltration", # Spy software
            "named":           "infiltration", # DNS named exploit
            "sendmail":        "infiltration", # Sendmail exploit

            # ── Exfiltration (data theft) ────────────────────────────
            "warezclient":     "exfiltration", # Warez download
            "warezmaster":     "exfiltration", # Warez server
            "httptunnel":      "exfiltration", # HTTP tunnel covert

            # ── Exploit (privilege escalation / shellcode) ───────────
            "buffer_overflow": "exploit",  # Buffer overflow
            "loadmodule":      "exploit",  # Kernel module load
            "perl":            "exploit",  # Perl exploit
            "rootkit":         "exploit",  # Rootkit installation
            "xterm":           "exploit",  # Xterm shell exploit
            "ps":              "exploit",  # Process manipulation

            # ── Web Attack (injection) ────────────────────────────────
            "sqlattack":       "web_attack",   # SQL injection
        }

    def _save(self):
        joblib.dump(self.rf_model,  f"{self.model_dir}/rf.pkl")
        joblib.dump(self.iso_model, f"{self.model_dir}/iso.pkl")
        joblib.dump(self.scaler,    f"{self.model_dir}/scaler.pkl")
        joblib.dump(self.label_enc, f"{self.model_dir}/label_enc.pkl")


# ─── Multi-Dataset Loader (added) ────────────────────────────────────────────

    def _train_from_xy(self, X, y) -> dict:
        """
        Train from pre-loaded X, y.
        Automatically supplements underrepresented classes with synthetic
        data so every class has at least MIN_SAMPLES training samples.
        This is critical when NSL-KDD has <100 samples for some classes.
        """
        import numpy as np
        import pandas as pd
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score, classification_report

        MIN_SAMPLES = 800    # minimum samples per class after supplementing
        SYN_CLASSES = {      # classes NSL-KDD lacks entirely
            "ddos":      _make_ddos,
            "web_attack":_make_web_attack,
        }
        BOOST_CLASSES = {    # classes NSL-KDD has but with too few samples
            "brute_force": _make_brute_force,
            "exploit":     _make_exploit,
            "infiltration":_make_infiltration,
            "exfiltration":_make_exfiltration,
        }

        print(f"[*] Real data: {len(X)} samples, {y.nunique()} classes")

        # ── Add entirely missing classes ─────────────────────────────────
        syn_dfs, syn_labels = [], []
        for cls, builder in SYN_CLASSES.items():
            if cls not in y.values:
                df = pd.DataFrame(builder(MIN_SAMPLES), columns=FEATURE_NAMES)
                syn_dfs.append(df.clip(lower=0))
                syn_labels.extend([cls] * MIN_SAMPLES)
                print(f"[*] Added {MIN_SAMPLES} synthetic {cls} samples")

        # ── Boost underrepresented classes ───────────────────────────────
        class_counts = y.value_counts()
        for cls, builder in BOOST_CLASSES.items():
            current = class_counts.get(cls, 0)
            needed  = max(0, MIN_SAMPLES - current)
            if needed > 0:
                df = pd.DataFrame(builder(needed), columns=FEATURE_NAMES)
                syn_dfs.append(df.clip(lower=0))
                syn_labels.extend([cls] * needed)
                print(f"[*] Boosted {cls}: {current} → {current+needed} samples")

        # ── Combine real + synthetic ─────────────────────────────────────
        if syn_dfs:
            X_syn  = pd.concat(syn_dfs, ignore_index=True)
            y_syn  = pd.Series(syn_labels)
            X_combined = pd.concat([X.reset_index(drop=True), X_syn],
                                   ignore_index=True)
            y_combined = pd.concat([y.reset_index(drop=True), y_syn],
                                   ignore_index=True)
        else:
            X_combined, y_combined = X, y

        print(f"[*] Combined: {len(X_combined)} samples, "
              f"{y_combined.nunique()} classes")

        # ── Encode + scale ───────────────────────────────────────────────
        self.label_enc = LabelEncoder()
        y_enc = self.label_enc.fit_transform(y_combined)
        self.scaler = StandardScaler()
        X_sc = self.scaler.fit_transform(X_combined)

        X_tr, X_te, y_tr, y_te = train_test_split(
            X_sc, y_enc, test_size=0.2, random_state=42, stratify=y_enc
        )

        # ── Train Random Forest ──────────────────────────────────────────
        self.rf_model = RandomForestClassifier(
            n_estimators=200,     # more trees for 10 classes
            max_depth=25,
            min_samples_split=3,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1,
        )
        self.rf_model.fit(X_tr, y_tr)
        y_pred = self.rf_model.predict(X_te)
        acc    = accuracy_score(y_te, y_pred)
        report = classification_report(
            y_te, y_pred,
            target_names=self.label_enc.classes_,
            output_dict=True,
        )

        # ── Train Isolation Forest on normal traffic only ────────────────
        normal_mask = (y_combined == "normal").values
        X_normal = X_sc[normal_mask] if normal_mask.sum() > 0 else X_sc
        self.iso_model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
            n_jobs=-1,
        )
        self.iso_model.fit(X_normal)
        self._save()
        return {"accuracy": acc, "report": report}


def load_unsw_nb15(path: str) -> tuple:
    """
    Load UNSW-NB15 dataset CSV and map to our 5-class schema.
    Columns expected: ..., label (0=normal,1=attack), attack_cat
    """
    import pandas as pd
    df = pd.read_csv(path, low_memory=False)

    # UNSW-NB15 to our schema mapping
    attack_map = {
        "":               "normal",
        "normal":         "normal",
        "dos":            "dos",
        "generic":        "ddos",       # High-volume generic floods
        "exploits":       "exploit",    # Exploitation attempts
        "fuzzers":        "web_attack", # Fuzzing = application-layer attack
        "reconnaissance": "port_scan",  # Network recon
        "analysis":       "vuln_scan",  # Targeted analysis/scanning
        "shellcode":      "exploit",    # Shellcode injection
        "backdoor":       "infiltration", # Backdoor access
        "worms":          "dos",        # Worm-based disruption
    }

    # Common UNSW-NB15 feature names → our feature names
    col_map = {
        "dur":         "duration",
        "proto":       "protocol_type",
        "sbytes":      "src_bytes",
        "dbytes":      "dst_bytes",
        "wrong_fragment": "wrong_fragment",
        "urgent":      "urgent",
        "ct_dst_ltm":  "count",
        "ct_src_ltm":  "srv_count",
        "rate":        "packet_rate",
        "sload":       "byte_rate",
        "dport":       "port_number",
    }

    # Rename available columns
    df = df.rename(columns=col_map)

    # Fill missing features with 0
    for feat in FEATURE_NAMES:
        if feat not in df.columns:
            df[feat] = 0.0

    # Encode protocol — use is_string_dtype() which works for both legacy
    # 'object' dtype (pandas <2) and new StringDtype (pandas 2+).
    proto_map = {"tcp": 0, "udp": 1, "icmp": 2}
    if pd.api.types.is_string_dtype(df["protocol_type"]):
        df["protocol_type"] = df["protocol_type"].str.lower().map(proto_map).fillna(0).astype(float)

    # Derive rate features
    if "serror_rate" not in df.columns:
        df["serror_rate"] = 0.0
    if "rerror_rate" not in df.columns:
        df["rerror_rate"] = 0.0
    df["same_srv_rate"]          = df.get("ct_srv_src", pd.Series(0, index=df.index)) / 100
    df["diff_srv_rate"]          = 1 - df["same_srv_rate"]
    df["dst_host_count"]         = df.get("ct_dst_sport_ltm", pd.Series(1, index=df.index))
    df["dst_host_srv_count"]     = df.get("ct_dst_src_ltm",   pd.Series(1, index=df.index))
    df["dst_host_same_srv_rate"] = df.get("ct_srv_dst",       pd.Series(1, index=df.index)) / 100
    df["dst_host_diff_srv_rate"] = 0.0
    df["dst_host_serror_rate"]   = 0.0
    df["flag_syn_ratio"]         = 0.0
    df["flag_fin_ratio"]         = 0.0
    df["flag_rst_ratio"]         = 0.0
    df["is_well_known_port"]     = (pd.to_numeric(df["port_number"], errors="coerce").fillna(0) < 1024).astype(float)

    # Coerce all feature columns to numeric (handles any residual strings)
    feat_df = df[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce").fillna(0)
    X = feat_df.clip(lower=0)

    # Labels
    if "attack_cat" in df.columns:
        y = df["attack_cat"].str.strip().str.lower().map(attack_map).fillna("normal")
    elif "label" in df.columns:
        y = df["label"].map({0: "normal", 1: "dos"})
    else:
        y = pd.Series(["normal"] * len(df))

    return X, y


def load_cicids2017(path: str) -> tuple:
    """
    Load CIC-IDS-2017 CSV.
    Label column is ' Label' (with leading space).
    """
    import pandas as pd
    df = pd.read_csv(path, low_memory=False)
    df.columns = df.columns.str.strip()

    cicids_map = {
        "BENIGN":                      "normal",
        "DDoS":                        "ddos",
        "DoS Hulk":                    "dos",
        "DoS GoldenEye":               "dos",
        "DoS slowloris":               "dos",
        "DoS Slowhttptest":            "dos",
        "Heartbleed":                  "exploit",
        "PortScan":                    "port_scan",
        "Infiltration":                "infiltration",
        "FTP-Patator":                 "brute_force",
        "SSH-Patator":                 "brute_force",
        "Bot":                         "infiltration",  # Botnet C2 = infiltration
        "Web Attack – Brute Force":"brute_force",
        "Web Attack – XSS":       "web_attack",
        "Web Attack – Sql Injection":"web_attack",
        # Handle both dash styles
        "Web Attack - Brute Force":    "brute_force",
        "Web Attack - XSS":            "web_attack",
        "Web Attack - Sql Injection":  "web_attack",
    }

    col_map = {
        "Flow Duration":           "duration",
        "Protocol":                "protocol_type",
        "Total Fwd Packets":       "count",
        "Total Backward Packets":  "srv_count",
        "Total Length of Fwd Packets": "src_bytes",
        "Total Length of Bwd Packets": "dst_bytes",
        "Flow Packets/s":          "packet_rate",
        "Flow Bytes/s":            "byte_rate",
        "Destination Port":        "port_number",
        "SYN Flag Count":          "flag_syn_ratio",
        "FIN Flag Count":          "flag_fin_ratio",
        "RST Flag Count":          "flag_rst_ratio",
        "URG Flag Count":          "urgent",
    }
    df = df.rename(columns=col_map)
    for feat in FEATURE_NAMES:
        if feat not in df.columns:
            df[feat] = 0.0

    df["is_well_known_port"] = (pd.to_numeric(df["port_number"], errors="coerce").fillna(0) < 1024).astype(float)
    df = df.replace([float("inf"), float("-inf")], 0).fillna(0)
    # Coerce all feature columns to numeric (handles any residual strings)
    feat_df = df[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce").fillna(0)
    X = feat_df.clip(lower=0)

    label_col = "Label" if "Label" in df.columns else "label"
    y = df[label_col].map(cicids_map).fillna("normal")
    return X, y


def auto_load_dataset(path: str) -> tuple:
    """
    Automatically detect dataset format from filename and load it.
    Supports: NSL-KDD, UNSW-NB15, CIC-IDS-2017, generic CSV.
    """
    import pandas as pd
    name = os.path.basename(path).lower()

    if "kdd" in name or "nsl" in name:
        print(f"[*] Detected: NSL-KDD format")
        cols = FEATURE_NAMES + ["label", "difficulty"]
        df = pd.read_csv(path, names=cols, low_memory=False)
        X  = df[FEATURE_NAMES].fillna(0).clip(lower=0)
        from ml.trainer import NIDSTrainer
        y  = df["label"].map(NIDSTrainer._nsl_label_map()).fillna("normal")
        return X, y

    elif "unsw" in name or "nb15" in name:
        print(f"[*] Detected: UNSW-NB15 format")
        return load_unsw_nb15(path)

    elif "cicids" in name or "cic" in name or "ids2017" in name:
        print(f"[*] Detected: CIC-IDS-2017 format")
        return load_cicids2017(path)

    else:
        # Try NSL-KDD format first (most common)
        print(f"[*] Unknown format — trying NSL-KDD parser")
        try:
            cols = FEATURE_NAMES + ["label", "difficulty"]
            df = pd.read_csv(path, names=cols, low_memory=False)
            X  = df[FEATURE_NAMES].fillna(0).clip(lower=0)
            from ml.trainer import NIDSTrainer
            y  = df["label"].map(NIDSTrainer._nsl_label_map()).fillna("normal")
            return X, y
        except Exception:
            print(f"[!] Could not parse {path} — using synthetic data")
            return generate_synthetic_dataset()

