"""
ml/explainer.py — SHAP-based Explainable AI layer.
Answers: "WHY was this flow flagged as an attack?"
"""

import numpy as np
import pandas as pd

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

from .trainer import NIDSTrainer, FEATURE_NAMES


class NIDSExplainer:
    def __init__(self, trainer: NIDSTrainer, max_background: int = 200):
        self.trainer        = trainer
        self._explainer     = None
        self.max_background = max_background

    # ─── Public API ───────────────────────────────────────────────────────────

    def build(self, X_background: np.ndarray | None = None) -> bool:
        """
        Build SHAP TreeExplainer from background data.
        Call once after model is loaded / trained.
        Returns True if SHAP is available.
        """
        if not SHAP_AVAILABLE:
            return False

        if X_background is None:
            from .trainer import generate_synthetic_dataset
            df, _ = generate_synthetic_dataset(n_per_class=50)
            X_background = self.trainer.scaler.transform(df[FEATURE_NAMES].values)

        bg = X_background[:self.max_background]
        self._explainer = shap.TreeExplainer(
            self.trainer.rf_model,
            data=bg,
            feature_perturbation="interventional",
        )
        return True

    def explain(self, features: dict, top_n: int = 6) -> dict:
        """
        Explain one prediction.
        Returns a dict with:
          top_features: list of {name, value, shap_value, direction}
          summary     : plain-English explanation string
        """
        if not SHAP_AVAILABLE or self._explainer is None:
            return self._fallback_explain(features, top_n)

        row   = np.array([[float(features.get(f, 0.0)) for f in FEATURE_NAMES]])
        row_s = self.trainer.scaler.transform(row)

        shap_vals = self._explainer.shap_values(row_s)
        proba     = self.trainer.rf_model.predict_proba(row_s)[0]
        cls_idx   = int(np.argmax(proba))

        sv = np.array(shap_vals)
        if sv.ndim == 3:
            cls_idx = min(cls_idx, sv.shape[0] - 1)
            vals = sv[cls_idx][0]
        elif sv.ndim == 2:
            vals = sv[0]
        else:
            vals = sv.flatten()
        top  = np.argsort(np.abs(vals))[::-1][:top_n]

        top_features = []
        for i in top:
            top_features.append({
                "name":       FEATURE_NAMES[i],
                "value":      round(float(features.get(FEATURE_NAMES[i], 0.0)), 4),
                "shap_value": round(float(vals[i]), 4),
                "direction":  "↑ increases risk" if vals[i] > 0 else "↓ decreases risk",
                "pct":        round(abs(float(vals[i])) / (np.sum(np.abs(vals)) + 1e-9) * 100, 1),
            })

        return {
            "top_features": top_features,
            "summary":      self._build_summary(top_features),
            "method":       "SHAP TreeExplainer",
        }

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _fallback_explain(self, features: dict, top_n: int) -> dict:
        """Feature-importance-based fallback when SHAP is unavailable."""
        importances = self.trainer.rf_model.feature_importances_
        top = np.argsort(importances)[::-1][:top_n]
        top_features = []
        for i in top:
            fname = FEATURE_NAMES[i]
            fval  = features.get(fname, 0.0)
            top_features.append({
                "name":       fname,
                "value":      round(float(fval), 4),
                "shap_value": round(float(importances[i]), 4),
                "direction":  "↑ increases risk",
                "pct":        round(float(importances[i]) * 100, 1),
            })
        return {
            "top_features": top_features,
            "summary":      self._build_summary(top_features),
            "method":       "Feature Importance (SHAP unavailable)",
        }

    @staticmethod
    def _build_summary(top_features: list[dict]) -> str:
        if not top_features:
            return "No explanation available."
        lines = []
        for f in top_features[:3]:
            lines.append(
                f"• {f['name']} = {f['value']}  ({f['pct']}% contribution, {f['direction']})"
            )
        return "Key indicators:\n" + "\n".join(lines)
