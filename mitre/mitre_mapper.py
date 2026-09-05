"""
mitre/mitre_mapper.py — Maps NIDS detection results to MITRE ATT&CK
Framework v14 techniques. Enriches every alert with actionable
threat intelligence context.
"""

from .mitre_data import ATTACK_CLASS_MAP, TECHNIQUES, TACTICS


class MITREMapper:
    """
    Enriches a detection result with MITRE ATT&CK context.
    Called once per alert, after detector.predict().
    """

    def __init__(self):
        self.techniques = TECHNIQUES
        self.tactics    = TACTICS
        self.class_map  = ATTACK_CLASS_MAP

    # ─── Public API ───────────────────────────────────────────────────────────

    def map(self, attack_label: str) -> dict:
        """
        Map a detected attack class to its MITRE ATT&CK techniques.

        Args:
            attack_label: One of 'dos', 'probe', 'r2l', 'u2r', 'normal'

        Returns:
            dict with full MITRE context ready for dashboard + PDF
        """
        label  = attack_label.lower().strip()
        entry  = self.class_map.get(label, self.class_map["normal"])

        # Build full technique objects for primary and secondary
        primary   = self._get_technique(entry["primary_technique"])
        secondary = self._get_technique(entry["secondary_technique"])
        all_techs = [
            self._get_technique(tid)
            for tid in entry["technique_ids"]
            if self._get_technique(tid) is not None
        ]

        return {
            "attack_class":     label,
            "tactic":           entry["tactic"],
            "kill_chain_phase": entry["kill_chain_phase"],
            "severity":         entry["severity"],
            "summary":          entry["summary"],
            "primary_technique": primary,
            "secondary_technique": secondary,
            "all_techniques":   all_techs,
            "technique_ids":    entry["technique_ids"],
            "has_mapping":      len(entry["technique_ids"]) > 0,
        }

    def get_technique(self, technique_id: str) -> dict | None:
        """Public accessor for a single technique by ID."""
        return self._get_technique(technique_id)

    def all_mappings_summary(self) -> list[dict]:
        """
        Returns a flat summary of all attack→technique mappings.
        Used by report_generator for the MITRE section table.
        """
        rows = []
        for cls, entry in self.class_map.items():
            if cls == "normal":
                continue
            for tid in entry["technique_ids"]:
                tech = self._get_technique(tid)
                if tech:
                    rows.append({
                        "attack_class":  cls.upper(),
                        "tactic":        tech["tactic"],
                        "technique_id":  tech["id"],
                        "technique_name":tech["name"],
                        "severity":      entry["severity"],
                        "url":           tech["url"],
                    })
        return rows

    def format_badge(self, attack_label: str) -> dict:
        """
        Lightweight version for dashboard — just the badge data.
        Returns primary technique ID, name, tactic, and colour.
        """
        mapping = self.map(attack_label)
        primary = mapping.get("primary_technique")

        if not primary:
            return {
                "technique_id":   "N/A",
                "technique_name": "Normal Traffic",
                "tactic":         "N/A",
                "colour":         "#10b981",
                "url":            "https://attack.mitre.org",
            }

        colour_map = {
            "CRITICAL": "#ef4444",
            "HIGH":     "#f59e0b",
            "MEDIUM":   "#3b82f6",
            "CLEAN":    "#10b981",
        }

        return {
            "technique_id":   primary["id"],
            "technique_name": primary["name"],
            "tactic":         primary["tactic"],
            "colour":         colour_map.get(mapping["severity"], "#64748b"),
            "url":            primary["url"],
        }

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _get_technique(self, tid: str | None) -> dict | None:
        if not tid:
            return None
        return self.techniques.get(tid)
