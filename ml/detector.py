"""
ml/detector.py — Two-model cascade inference engine.

Stage 1 → Classic RF (24 features, 10 classes)  — 99.04% accuracy
Stage 2 → Modern Threat Detector (8 features, 4 classes) — 100% accuracy

The modern detector ONLY overrides the classic result when:
  • It detects ransomware / encrypted_c2 / dga  (not normal)
  • Confidence >= 0.75
  • Classic result is not already CRITICAL with high confidence
"""

import numpy as np
import pandas as pd
from .trainer import NIDSTrainer, FEATURE_NAMES, SEVERITY_MAP

try:
    from .modern_detector import ModernThreatDetector, MODERN_FEATURES
    _MODERN_AVAILABLE = True
except ImportError:
    _MODERN_AVAILABLE = False


class NIDSDetector:
    def __init__(self, trainer: NIDSTrainer,
                 modern=None):
        self.trainer   = trainer
        self.rf        = trainer.rf_model
        self.iso       = trainer.iso_model
        self.scaler    = trainer.scaler
        self.label_enc = trainer.label_enc
        self.modern    = modern   # ModernThreatDetector instance or None

    # ── Public API ────────────────────────────────────────────────────────────

    def predict(self, features: dict) -> dict:
        """Run full cascade. Returns detection result dict."""

        # Stage 1: Classic 24-feature model
        result = self._classic(features)

        # Stage 2: Modern 8-feature detector
        if self.modern is not None:
            modern_result = self.modern.predict(features)
            if modern_result is not None:
                # Don't downgrade a high-confidence CRITICAL classic result
                classic_is_certain = (
                    result["severity"] == "CRITICAL" and
                    result["confidence"] >= 0.85
                )
                if not classic_is_certain:
                    modern_result["anomaly"]       = result.get("anomaly", False)
                    modern_result["anomaly_score"] = result.get("anomaly_score", 0.0)
                    return modern_result

        return result

    def predict_batch(self, df: pd.DataFrame) -> list:
        return [self.predict(row.to_dict()) for _, row in df.iterrows()]

    # ── Classic 24-feature model ──────────────────────────────────────────────

    def _classic(self, features: dict) -> dict:
        # Use only the first 24 classic features
        classic_24 = FEATURE_NAMES[:24]
        row  = [float(features.get(f, 0.0)) for f in classic_24]
        X    = np.array(row).reshape(1, -1)
        X_sc = self.scaler.transform(X)

        proba  = self.rf.predict_proba(X_sc)[0]
        idx    = int(np.argmax(proba))
        label  = self.label_enc.inverse_transform([idx])[0]
        conf   = float(proba[idx])
        probs  = {
            cls: round(float(p), 4)
            for cls, p in zip(self.label_enc.classes_, proba)
        }

        iso_score  = float(self.iso.decision_function(X_sc)[0])
        is_anomaly = bool(self.iso.predict(X_sc)[0] == -1)

        if label == "normal" and is_anomaly and iso_score < -0.15:
            label    = "port_scan"
            conf     = max(conf, 0.55)
            severity = "MEDIUM"
        elif label == "normal" and conf < 0.60:
            severity = "LOW"
        else:
            severity = SEVERITY_MAP.get(label, "CLEAN")

        return {
            "label":         label,
            "severity":      severity,
            "confidence":    round(conf, 4),
            "anomaly":       is_anomaly,
            "anomaly_score": round(iso_score, 4),
            "probabilities": probs,
            "source":        "classic_model",
        }
