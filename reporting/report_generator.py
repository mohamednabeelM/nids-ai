"""
reporting/report_generator.py — Generates a professional forensic
PDF report from NIDS scan session data using ReportLab.
"""

import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak,
)

# ─── Palette ─────────────────────────────────────────────────────────────────
CLR_DARK     = colors.HexColor("#040d1a")
CLR_ACCENT   = colors.HexColor("#0ea5e9")
CLR_RED      = colors.HexColor("#ef4444")
CLR_AMBER    = colors.HexColor("#f59e0b")
CLR_GREEN    = colors.HexColor("#10b981")
CLR_BLUE     = colors.HexColor("#3b82f6")
CLR_MUTED    = colors.HexColor("#64748b")
CLR_LIGHT    = colors.HexColor("#f1f5f9")
CLR_CARD     = colors.HexColor("#e8f4fd")
CLR_HEADER   = colors.HexColor("#1a2940")   # Dark navy for table headers

SEV_CLR = {
    "CRITICAL": CLR_RED,
    "HIGH":     CLR_AMBER,
    "MEDIUM":   CLR_BLUE,
    "LOW":      CLR_GREEN,
    "CLEAN":    CLR_MUTED,
}

MARGIN = 16 * mm


def _styles():
    base = getSampleStyleSheet()
    return {
        "Title": ParagraphStyle("NIDSTitle", parent=base["Title"],
            fontSize=22, textColor=CLR_DARK, alignment=TA_CENTER,
            spaceAfter=4),
        "Sub": ParagraphStyle("NIDSSub", parent=base["Normal"],
            fontSize=10, textColor=CLR_MUTED, alignment=TA_CENTER,
            spaceAfter=16),
        "Section": ParagraphStyle("NIDSSection", parent=base["Heading2"],
            fontSize=13, textColor=CLR_DARK, spaceBefore=14, spaceAfter=6),
        "Body": ParagraphStyle("NIDSBody", parent=base["Normal"],
            fontSize=9, leading=13, textColor=CLR_DARK),
        "Mono": ParagraphStyle("NIDSMono", parent=base["Code"],
            fontSize=8, leading=11, backColor=CLR_LIGHT, borderPad=3),
        "Tag": ParagraphStyle("NIDSTag", parent=base["Normal"],
            fontSize=8, leading=10, textColor=CLR_MUTED),
    }


class NIDSReportGenerator:
    def __init__(self, session_data: dict, output_dir: str = "."):
        self.data       = session_data
        self.output_dir = output_dir
        self.ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(output_dir, exist_ok=True)

    # ─── Public API ───────────────────────────────────────────────────────────

    def generate(self) -> str:
        path = os.path.join(self.output_dir, f"nids_report_{self.ts}.pdf")
        s    = _styles()

        doc = SimpleDocTemplate(
            path, pagesize=A4,
            leftMargin=MARGIN, rightMargin=MARGIN,
            topMargin=MARGIN, bottomMargin=MARGIN,
            title="NIDS Forensic Report",
        )

        story = (
            self._cover(s)
            + self._summary(s)
            + self._alert_table(s)
            + self._top_attackers(s)
            + self._mitre_section(s)
            + self._xai_section(s)
            + self._recommendations(s)
        )

        doc.build(story,
                  onFirstPage=self._decorate,
                  onLaterPages=self._decorate)
        return path

    # ─── Page Decorations ─────────────────────────────────────────────────────

    @staticmethod
    def _decorate(canvas, doc):
        w, h = A4
        canvas.saveState()
        canvas.setStrokeColor(CLR_ACCENT)
        canvas.setLineWidth(2)
        canvas.line(MARGIN, h - 12*mm, w - MARGIN, h - 12*mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(CLR_MUTED)
        canvas.drawCentredString(w/2, 8*mm,
            f"Page {doc.page}  ·  NIDS AI Forensic Report  ·  Confidential")
        canvas.restoreState()

    # ─── Sections ─────────────────────────────────────────────────────────────

    def _cover(self, s):
        meta = self.data.get("meta", {})
        return [
            Spacer(1, 16*mm),
            Paragraph("🛡️ NIDS — AI Network Intrusion Detection", s["Title"]),
            Paragraph("Forensic Analysis Report", s["Title"]),
            Spacer(1, 4*mm),
            Paragraph(
                f"Session: {meta.get('session_start','N/A')} — {meta.get('session_end','N/A')}"
                f"  |  Host: {meta.get('hostname','N/A')}"
                f"  |  Mode: {meta.get('mode','Simulation')}",
                s["Sub"]),
            HRFlowable(width="100%", thickness=1,
                       color=CLR_ACCENT, spaceAfter=20),
            PageBreak(),
        ]

    def _summary(self, s):
        stats = self.data.get("stats", {})
        alerts = self.data.get("alerts", [])
        
        # Dynamically calculate accurate flow counts from alerts list if available
        if alerts:
            total_flows = len(alerts)
            clean_flows = sum(1 for a in alerts if a.get("label", "").lower() == "normal" or a.get("severity", "").upper() == "LOW")
            crit = sum(1 for a in alerts if a.get("severity", "").upper() == "CRITICAL")
            high = sum(1 for a in alerts if a.get("severity", "").upper() == "HIGH")
            medium = sum(1 for a in alerts if a.get("severity", "").upper() == "MEDIUM")
            low = sum(1 for a in alerts if a.get("severity", "").upper() == "LOW")
            
            clean_pct = (clean_flows / total_flows * 100) if total_flows > 0 else 0.0
            threat_pct = 100.0 - clean_pct
        else:
            total_flows = stats.get("total_flows", 0)
            clean_flows = stats.get("clean", 0)
            crit = stats.get("critical", 0)
            high = stats.get("high", 0)
            medium = stats.get("medium", 0)
            low = stats.get("low", 0)
            clean_pct = stats.get("clean_pct", 0)
            threat_pct = stats.get("threat_pct", 0)

        story = [Paragraph("Executive Summary", s["Section"])]

        verdict = (
            "⚠️  THREATS DETECTED — Immediate investigation required."
            if (crit + high) > 0
            else "✅  No critical threats detected during this session."
        )
        story.append(Paragraph(verdict, s["Body"]))
        story.append(Spacer(1, 6))

        rows = [
            ["Metric", "Value"],
            ["Total Flows Analysed",    str(total_flows)],
            ["Clean Flows",             str(clean_flows)],
            ["🔴 Critical Threats",     str(crit)],
            ["🟠 High Threats",         str(high)],
            ["🔵 Medium Threats",       str(medium)],
            ["🟢 Low Threats",          str(low)],
            ["Clean Traffic %",         f"{clean_pct:.1f}%"],
            ["Threat Traffic %",        f"{threat_pct:.1f}%"],
            ["Session Duration",        stats.get("uptime","N/A")],
            ["ML Model Accuracy",       stats.get("model_accuracy","N/A")],
        ]
        tbl = Table(rows, colWidths=[100*mm, 60*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0,0),(-1,0), CLR_DARK),
            ("TEXTCOLOR",   (0,0),(-1,0), colors.white),
            ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0),(-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[CLR_LIGHT,colors.white]),
            ("GRID",        (0,0),(-1,-1), 0.3, colors.lightgrey),
            ("ALIGN",       (1,0),(1,-1), "CENTER"),
        ]))
        story += [tbl, Spacer(1,8), PageBreak()]
        return story

    def _alert_table(self, s):
        alerts = self.data.get("alerts", [])[:100]
        story  = [Paragraph(f"Alert Log ({len(alerts)} entries)", s["Section"])]

        if not alerts:
            story.append(Paragraph("No alerts recorded in this session.", s["Body"]))
            return story

        header = ["Time","Severity","Source","Destination","Attack","Confidence"]
        rows   = [header]
        for a in alerts:
            rows.append([
                a.get("timestamp",""),
                a.get("severity",""),
                a.get("src",""),
                a.get("dst",""),
                a.get("label",""),
                a.get("confidence",""),
            ])

        tbl = Table(rows, colWidths=[18*mm,20*mm,38*mm,38*mm,28*mm,18*mm])
        style = [
            ("BACKGROUND",  (0,0),(-1,0), CLR_DARK),
            ("TEXTCOLOR",   (0,0),(-1,0), colors.white),
            ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0),(-1,-1), 7),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[CLR_LIGHT,colors.white]),
            ("GRID",        (0,0),(-1,-1), 0.2, colors.lightgrey),
        ]
        for i, a in enumerate(alerts, 1):
            sev = a.get("severity","CLEAN")
            clr = SEV_CLR.get(sev, CLR_MUTED)
            style.append(("TEXTCOLOR", (1,i),(1,i), clr))
            style.append(("FONTNAME",  (1,i),(1,i), "Helvetica-Bold"))
        tbl.setStyle(TableStyle(style))
        story += [tbl, Spacer(1,6), PageBreak()]
        return story

    def _top_attackers(self, s):
        sources = self.data.get("top_sources", [])
        story   = [Paragraph("Top Attacker IPs", s["Section"])]
        if not sources:
            story.append(Paragraph("No attack sources recorded.", s["Body"]))
            return story

        rows = [["Rank","IP Address","Alert Count","Threat Level"]]
        for i, src in enumerate(sources[:10], 1):
            cnt = src.get("count",0)
            lvl = "CRITICAL" if cnt > 20 else "HIGH" if cnt > 5 else "MEDIUM"
            rows.append([str(i), src.get("ip",""), str(cnt), lvl])

        tbl = Table(rows, colWidths=[15*mm,60*mm,40*mm,45*mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0,0),(-1,0), CLR_DARK),
            ("TEXTCOLOR",   (0,0),(-1,0), colors.white),
            ("FONTNAME",    (0,0),(-1,0), "Helvetica-Bold"),
            ("FONTSIZE",    (0,0),(-1,-1), 9),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[CLR_LIGHT,colors.white]),
            ("GRID",        (0,0),(-1,-1), 0.3, colors.lightgrey),
            ("ALIGN",       (0,0),(-1,-1), "CENTER"),
        ]))
        story += [tbl, Spacer(1,6)]
        return story

    def _xai_section(self, s):
        alerts = self.data.get("alerts", [])
        story  = [Paragraph("AI Explanation Samples (Top 3 Alerts)", s["Section"])]
        critical = [a for a in alerts if a.get("severity") == "CRITICAL"][:3]
        if not critical:
            story.append(Paragraph("No critical alerts to explain.", s["Body"]))
            return story

        for a in critical:
            exp  = a.get("explanation", {})
            feats = exp.get("top_features", [])
            story.append(Paragraph(
                f'<b>Alert:</b> {a.get("label","")} from {a.get("src","")} '
                f'— Confidence: {a.get("confidence","")}', s["Body"]))
            if feats:
                feat_rows = [["Feature","Value","Contribution","Direction"]]
                for f in feats[:5]:
                    feat_rows.append([f["name"], str(f["value"]),
                                      f"{f['pct']}%", f["direction"]])
                ft = Table(feat_rows, colWidths=[45*mm,30*mm,30*mm,55*mm])
                ft.setStyle(TableStyle([
                    ("BACKGROUND",(0,0),(-1,0),CLR_ACCENT),
                    ("TEXTCOLOR", (0,0),(-1,0),colors.white),
                    ("FONTSIZE",  (0,0),(-1,-1),8),
                    ("ROWBACKGROUNDS",(0,1),(-1,-1),[CLR_CARD,colors.white]),
                    ("GRID",(0,0),(-1,-1),0.2,colors.lightgrey),
                ]))
                story.append(ft)
            story.append(Spacer(1,8))
        return story

    def _mitre_section(self, s: dict) -> list:
        """MITRE ATT&CK mapping table — one row per technique."""
        story = [
            PageBreak(),
            Paragraph("MITRE ATT&CK Framework Mapping", s["Section"]),
        ]
        story.append(Paragraph(
            "Each detected attack class is mapped to its corresponding MITRE ATT&CK "
            "Tactics and Techniques (Framework v14). This enables security teams to "
            "correlate NIDS detections with the broader threat intelligence ecosystem.",
            s["Body"],
        ))
        story.append(Spacer(1, 8))

        try:
            import sys, os
            sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
            from mitre.mitre_mapper import MITREMapper
            mapper = MITREMapper()
            rows   = mapper.all_mappings_summary()
        except Exception as e:
            story.append(Paragraph(f"MITRE mapping unavailable: {e}", s["Body"]))
            return story

        if not rows:
            story.append(Paragraph("No techniques mapped.", s["Body"]))
            return story

        # ── Technique table ───────────────────────────────────────────────
        sev_clr_map = {
            "CRITICAL": CLR_RED,
            "HIGH":     CLR_AMBER,
            "MEDIUM":   CLR_BLUE,
            "LOW":      CLR_GREEN,
        }

        header = ["Attack Class", "Tactic", "Technique ID",
                  "Technique Name", "Severity"]
        table_data = [header]
        for row in rows:
            table_data.append([
                row["attack_class"],
                row["tactic"],
                row["technique_id"],
                row["technique_name"],
                row["severity"],
            ])

        col_w = [25*mm, 50*mm, 25*mm, 52*mm, 22*mm]
        tbl = Table(table_data, colWidths=col_w)

        tbl_style = [
            ("BACKGROUND",  (0, 0), (-1, 0), CLR_HEADER),
            ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [CLR_LIGHT, colors.white]),
            ("GRID",        (0, 0), (-1, -1), 0.3, colors.lightgrey),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for i, row in enumerate(rows, 1):
            clr = sev_clr_map.get(row["severity"], CLR_MUTED)
            tbl_style.append(("TEXTCOLOR", (4, i), (4, i), clr))
            tbl_style.append(("FONTNAME",  (4, i), (4, i), "Helvetica-Bold"))
            tbl_style.append(("TEXTCOLOR", (2, i), (2, i), CLR_ACCENT))
            tbl_style.append(("FONTNAME",  (2, i), (2, i), "Courier-Bold"))

        tbl.setStyle(TableStyle(tbl_style))
        story += [tbl, Spacer(1, 8)]
        story.append(Paragraph(
            "Full details at: https://attack.mitre.org", s["Tag"]
        ))
        story.append(Spacer(1, 10))

        # ── Per-attack-class summary boxes ───────────────────────────────
        story.append(Paragraph("Attack Class Summaries", s["Section"]))
        try:
            from mitre.mitre_data import ATTACK_CLASS_MAP, TECHNIQUES
        except ImportError:
            return story

        cls_colours = {
            "dos":   CLR_RED,
            "probe": CLR_AMBER,
            "r2l":   CLR_BLUE,
            "u2r":   CLR_MUTED,
        }

        for cls, entry in ATTACK_CLASS_MAP.items():
            if cls == "normal":
                continue

            clr = cls_colours.get(cls, CLR_MUTED)

            # Class header
            story.append(Paragraph(
                f'<font color="{clr.hexval()}"><b>{cls.upper()}</b></font>'
                f'  —  {entry["tactic"]}',
                s["Body"],
            ))
            story.append(Paragraph(entry["summary"], s["Tag"]))
            story.append(Spacer(1, 3))

            # Technique mini-table for this class
            tech_ids = entry["technique_ids"]
            if tech_ids:
                tech_rows = [["ID", "Technique", "Description (excerpt)"]]
                for tid in tech_ids:
                    tech = TECHNIQUES.get(tid)
                    if tech:
                        desc = tech["desc"][:90] + "…" if len(tech["desc"]) > 90 else tech["desc"]
                        tech_rows.append([tid, tech["name"], desc])

                t = Table(tech_rows, colWidths=[20*mm, 48*mm, 106*mm])
                t.setStyle(TableStyle([
                    ("BACKGROUND",  (0, 0), (-1, 0), clr),
                    ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
                    ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE",    (0, 0), (-1, -1), 7.5),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [CLR_LIGHT, colors.white]),
                    ("GRID",        (0, 0), (-1, -1), 0.2, colors.lightgrey),
                    ("TOPPADDING",    (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ("FONTNAME",    (0, 1), (0, -1), "Courier-Bold"),
                    ("TEXTCOLOR",   (0, 1), (0, -1), CLR_ACCENT),
                ]))
                story += [t, Spacer(1, 8)]

        return story

    def _recommendations(self, s):
        recs = [
            ("Block attacker IPs",
             "Use firewall rules to block the top source IPs identified in the alert log."),
            ("Investigate DoS flows",
             "High packet-rate flows from single sources should be traced to origin. "
             "Consider rate limiting at the network edge."),
            ("Review probe targets",
             "Port scan targets indicate which services are being enumerated. "
             "Disable unused services and apply strict firewall ingress rules."),
            ("Patch R2L vulnerabilities",
             "Remote-to-Local attack attempts suggest exposed services (SSH, FTP, SMTP). "
             "Enforce key-based auth and disable password login."),
            ("Enable continuous monitoring",
             "Deploy NIDS in persistent mode with SIEM integration and automated alerting "
             "for 24/7 coverage."),
        ]
        story = [PageBreak(), Paragraph("Recommendations", s["Section"])]
        for i, (title, detail) in enumerate(recs, 1):
            story.append(Paragraph(f"<b>{i}. {title}</b>", s["Body"]))
            story.append(Paragraph(detail, s["Body"]))
            story.append(Spacer(1, 4))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            "Generated by <b>NIDS — AI Network Intrusion Detection System</b>. "
            "For authorised security use only.",
            s["Tag"]))
        return story
