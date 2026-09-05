"""
ml/modern_detector.py — Standalone Modern Threat Detector
Detects: ransomware · encrypted_c2 · dga
Uses:    8 new behavioural features ONLY
Models:  Random Forest (200 trees, 4 classes)

This module is COMPLETELY SEPARATE from the classic 24-feature model.
It runs in parallel and only overrides when confidence >= 0.75.
"""

import os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# ─── Feature Definitions ─────────────────────────────────────────────────────
MODERN_FEATURES = [
    "beacon_score",           # Regularity of connection timing (LOW=C2 beaconing)
    "dns_query_entropy",      # DNS domain name entropy (HIGH=DGA)
    "dns_nxdomain_rate",      # DNS failure rate (HIGH=DGA scanning)
    "dns_query_rate",         # DNS queries per second (HIGH=DNS tunneling)
    "tls_cert_validity_days", # TLS cert lifetime (SHORT=malware-generated)
    "tls_is_self_signed",     # 1=self-signed cert (malware characteristic)
    "smb_lateral_score",      # SMB spread score (HIGH=ransomware lateral movement)
    "payload_entropy",        # Byte entropy (HIGH=encrypted/ransomware payload)
]

MODERN_CLASSES   = ["normal", "ransomware", "encrypted_c2", "dga"]
MODERN_SEVERITY  = {
    "normal":       "CLEAN",
    "ransomware":   "CRITICAL",
    "encrypted_c2": "CRITICAL",
    "dga":          "HIGH",
}
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

# ─── Key Separators (non-overlapping by design) ───────────────────────────────
# smb_lateral_score > 0.70  → ONLY ransomware
# beacon_score      < 0.08  → ONLY encrypted_c2
# dns_nxdomain_rate > 0.70  → ONLY dga
# dns_query_rate    > 30    → ONLY dga
# payload_entropy   > 0.93  → encrypted_c2 or ransomware (smb distinguishes)

# ─── Synthetic Data Profiles ─────────────────────────────────────────────────
#              beacon  dns_ent  nxd_rt  dns_qr   tls_d    self_sg  smb_lat payload
_PROFILES = {
    "normal":       (2.20,  2.10, 0.04,  0.40,  300.0,  0.00, 0.00, 0.30),
    "ransomware":   (0.14,  1.80, 0.09,  0.45,   14.0,  0.65, 0.88, 0.95),
    "encrypted_c2": (0.04,  2.30, 0.04,  0.08,    6.0,  0.72, 0.00, 0.97),
    "dga":          (0.40,  4.20, 0.93, 85.00,    0.0,  0.00, 0.00, 0.52),
}
_STD = {
    "normal":       (0.30,  0.25, 0.03,  0.20,  50.0, 0.00, 0.00, 0.07),
    "ransomware":   (0.03,  0.30, 0.04,  0.15,   4.0, 0.10, 0.05, 0.02),
    "encrypted_c2": (0.015, 0.25, 0.025, 0.04,   2.0, 0.10, 0.00, 0.015),
    "dga":          (0.08,  0.25, 0.035,12.00,   0.0, 0.00, 0.00, 0.06),
}


def _generate_data(n_per_class: int = 3000):
    """Generate synthetic training data for all 4 classes."""
    import pandas as pd
    rng = np.random.default_rng(42)
    dfs, labels = [], []
    for cls in MODERN_CLASSES:
        means = _PROFILES[cls]
        stds  = _STD[cls]
        data  = {}
        for feat, mean, std in zip(MODERN_FEATURES, means, stds):
            if std == 0:
                data[feat] = np.full(n_per_class, mean)
            else:
                data[feat] = rng.normal(mean, std, n_per_class)
        df = pd.DataFrame(data, columns=MODERN_FEATURES).clip(lower=0)
        dfs.append(df)
        labels.extend([cls] * n_per_class)
    return pd.concat(dfs, ignore_index=True), pd.Series(labels)


# ─── ModernThreatDetector Class ───────────────────────────────────────────────

class ModernThreatDetector:
    CONFIDENCE_THRESHOLD = 0.75

    def __init__(self):
        self.rf_model  = None
        self.scaler    = None
        self.label_enc = None

    # ── Public API ────────────────────────────────────────────────────────────

    def train(self, n_per_class: int = 3000) -> dict:
        """Train on 8 modern features × 4 classes. Returns accuracy dict."""
        import pandas as pd
        X, y = _generate_data(n_per_class)

        self.label_enc = LabelEncoder()
        y_enc = self.label_enc.fit_transform(y)
        self.scaler = StandardScaler()
        X_sc = self.scaler.fit_transform(X)

        X_tr, X_te, y_tr, y_te = train_test_split(
            X_sc, y_enc, test_size=0.2, random_state=42, stratify=y_enc
        )
        self.rf_model = RandomForestClassifier(
            n_estimators=200, max_depth=20,
            class_weight="balanced", random_state=42, n_jobs=-1,
        )
        self.rf_model.fit(X_tr, y_tr)
        acc = accuracy_score(y_te, self.rf_model.predict(X_te))
        report = classification_report(
            y_te, self.rf_model.predict(X_te),
            target_names=self.label_enc.classes_, output_dict=True
        )
        print(f"[✓] Modern Threat Detector accuracy: {acc*100:.2f}%")
        self._save()
        return {"accuracy": acc, "report": report}

    def predict(self, features: dict) -> dict | None:
        """
        Predict using only the 8 modern features.
        Returns None if: class is 'normal' OR confidence < threshold.
        Returns full result dict if ransomware/C2/DGA detected.
        """
        if self.rf_model is None:
            return None

        import pandas as pd
        row  = {f: float(features.get(f, 0.0)) for f in MODERN_FEATURES}
        X    = pd.DataFrame([row], columns=MODERN_FEATURES)
        X_sc = self.scaler.transform(X)

        proba = self.rf_model.predict_proba(X_sc)[0]
        idx   = int(np.argmax(proba))
        label = self.label_enc.inverse_transform([idx])[0]
        conf  = float(proba[idx])

        # Only override classic model when detecting a real modern threat
        if label == "normal" or conf < self.CONFIDENCE_THRESHOLD:
            return None

        return {
            "label":      label,
            "severity":   MODERN_SEVERITY.get(label, "CRITICAL"),
            "confidence": round(conf, 4),
            "anomaly":    True,
            "anomaly_score": -0.6,
            "probabilities": {
                cls: round(float(p), 4)
                for cls, p in zip(self.label_enc.classes_, proba)
            },
            "source": "modern_threat_detector",
        }

    def load(self) -> bool:
        """Load saved models. Returns True if successful."""
        try:
            self.rf_model  = joblib.load(f"{MODEL_DIR}/modern_rf.pkl")
            self.scaler    = joblib.load(f"{MODEL_DIR}/modern_scaler.pkl")
            self.label_enc = joblib.load(f"{MODEL_DIR}/modern_label_enc.pkl")
            return True
        except FileNotFoundError:
            return False

    def models_exist(self) -> bool:
        return all(
            os.path.exists(f"{MODEL_DIR}/{f}")
            for f in ["modern_rf.pkl", "modern_scaler.pkl", "modern_label_enc.pkl"]
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _save(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.rf_model,  f"{MODEL_DIR}/modern_rf.pkl")
        joblib.dump(self.scaler,    f"{MODEL_DIR}/modern_scaler.pkl")
        joblib.dump(self.label_enc, f"{MODEL_DIR}/modern_label_enc.pkl")
        print(f"[✓] Modern models saved to ml/models/")
