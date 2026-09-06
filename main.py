#!/usr/bin/env python3
"""
main.py — NIDS: AI-Powered Network Intrusion Detection System
Author  :  Mohamed Nabeel.M
Degree  :  B.E. Computer Science (Cybersecurity), 2023–2027
GitHub  : https://github.com/mohamednabeelM/nids-ai
============================================================
Usage:
  python main.py train                     # Train ML models
  python main.py run                       # Simulate + dashboard (default)
  python main.py run --mode live           # Live capture (requires root)
  python main.py run --iface eth0          # Choose interface
  python main.py report                    # Generate PDF report from last session
  python main.py run --port 8080           # Custom dashboard port
"""

import argparse
import os
import sys
import time
import socket
import platform
import threading
from datetime import datetime

# ── Rich terminal output ───────────────────────────────────────────────────────
from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.live    import Live
from rich         import box
from rich.text    import Text

console = Console()

BANNER = """
[bold cyan] ███╗   ██╗██╗██████╗ ███████╗[/bold cyan]
[bold cyan] ████╗  ██║██║██╔══██╗██╔════╝[/bold cyan]
[bold cyan] ██╔██╗ ██║██║██║  ██║███████╗[/bold cyan]
[bold cyan] ██║╚██╗██║██║██║  ██║╚════██║[/bold cyan]
[bold cyan] ██║ ╚████║██║██████╔╝███████║[/bold cyan]
[bold cyan] ╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝[/bold cyan]
[dim]  AI-Powered Network Intrusion Detection System[/dim]
"""


# ─── CLI Args ─────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="NIDS — AI Network Intrusion Detection System",
    )
    sub = p.add_subparsers(dest="command", help="Command to run")

    # train
    tr = sub.add_parser("train", help="Train ML models")
    tr.add_argument("--dataset", default=None,
                    help="Path to NSL-KDD KDDTrain+.txt (optional)")
    tr.add_argument("--samples", type=int, default=2000,
                    help="Samples per class for synthetic training")

    # run
    ru = sub.add_parser("run", help="Start NIDS detection + dashboard")
    ru.add_argument("--mode", choices=["simulate","live"],
                    default="simulate", help="Traffic source")
    ru.add_argument("--iface", default="eth0",
                    help="Network interface for live mode")
    ru.add_argument("--port", type=int, default=5000,
                    help="Dashboard port (default 5000)")
    ru.add_argument("--no-dashboard", action="store_true",
                    help="CLI-only mode (no web dashboard)")
    ru.add_argument("--ssl", action="store_true",
                    help="Enable HTTPS (uses cert.pem + key.pem in project root)")

    # report
    rp = sub.add_parser("report", help="Generate PDF from saved session")
    rp.add_argument("--output", default="./reports",
                    help="Output directory for PDF")

    return p.parse_args()


# ─── Training ──────────────────────────────────────────────────────────────────

def cmd_train(args):
    from ml.trainer import NIDSTrainer, auto_load_dataset

    console.print(BANNER)
    console.rule("[bold]Training ML Models[/bold]")

    dataset_path = getattr(args, "dataset", None)
    n_per_class  = getattr(args, "samples", 2000)

    # Show dataset info
    if dataset_path:
        console.print(f"[cyan]Dataset:[/cyan] {dataset_path}")
        if not os.path.exists(dataset_path):
            console.print(f"[red]❌  File not found: {dataset_path}[/red]")
            console.print("[yellow]Run: python download_dataset.py  to download a dataset[/yellow]")
            console.print("[dim]Or continuing with synthetic training data…[/dim]\n")
            dataset_path = None
    else:
        console.print("[yellow]No dataset specified — using synthetic training data[/yellow]")
        console.print("[dim]Tip: python download_dataset.py --dataset nsl-kdd[/dim]\n")

    trainer = NIDSTrainer()
    with console.status("[cyan]Training Random Forest + Isolation Forest…"):
        if dataset_path:
            # Use auto_load_dataset to detect format (NSL-KDD / UNSW-NB15 / CIC-IDS)
            console.print(f"[cyan]Auto-detecting dataset format…[/cyan]")
            X, y = auto_load_dataset(dataset_path)
            console.print(f"[green]✅  Loaded {len(X)} samples, {len(y.unique())} classes[/green]")
            import pandas as pd
            metrics = trainer._train_from_xy(X, y)
        else:
            metrics = trainer.train(dataset_path=None, n_per_class=n_per_class)

    acc = metrics["accuracy"]
    console.print(f"\n[bold green]✅  Classic model complete![/bold green]")
    console.print(f"   Random Forest accuracy : [bold cyan]{acc*100:.2f}%[/bold cyan]")
    console.print(f"   10 attack classes detected")

    # Train Modern Threat Detector
    console.print("\n[cyan]Training Modern Threat Detector...[/cyan]")
    console.print("[dim]  Targets: ransomware · encrypted_c2 · dga[/dim]")
    console.print("[dim]  Features: beacon_score · dns_entropy · tls · smb · payload_entropy[/dim]")
    try:
        from ml.modern_detector import ModernThreatDetector
        mtd = ModernThreatDetector()
        with console.status("[cyan]Training on 8 modern behavioural features..."):
            m = mtd.train(n_per_class=3000)
        console.print(
            f"[bold green]✅  Modern Threat Detector complete![/bold green]  "
            f"accuracy: [bold cyan]{m['accuracy']*100:.2f}%[/bold cyan]"
        )
    except Exception as e:
        console.print(f"[yellow]Modern detector training failed: {e}[/yellow]")
    console.print(f"\n[dim]All models saved to ml/models/[/dim]")

    # Per-class table
    report = metrics["report"]
    tbl = Table(box=box.SIMPLE, show_header=True)
    tbl.add_column("Class",    style="bold")
    tbl.add_column("Precision")
    tbl.add_column("Recall")
    tbl.add_column("F1-Score")
    tbl.add_column("Support")
    for cls, v in report.items():
        if cls in ("accuracy","macro avg","weighted avg"):
            continue
        tbl.add_row(
            cls.upper(),
            f"{v['precision']:.3f}",
            f"{v['recall']:.3f}",
            f"{v['f1-score']:.3f}",
            str(int(v['support'])),
        )
    console.print(tbl)
    console.print(f"\n[dim]Run 'python main.py run' to start detection.[/dim]")


# ─── Run (Detection + Dashboard) ──────────────────────────────────────────────

def cmd_run(args):
    from ml.trainer       import NIDSTrainer
    from ml.detector      import NIDSDetector
    from ml.explainer     import NIDSExplainer
    from core.packet_capture import PacketCapture
    from core.flow_tracker   import FlowTracker
    from alerts.alert_manager import AlertManager
    import dashboard.app as dash_app

    console.print(BANNER)
    console.rule("[bold]Starting NIDS[/bold]")

    # ── Load / train models ──────────────────────────────────────────────────
    trainer = NIDSTrainer()
    if not trainer.models_exist():
        console.print("[yellow]No trained models found — training now…[/yellow]")
        trainer.train(n_per_class=1500)
    else:
        console.print("[cyan]Loading classic model (24 features · 10 classes)…[/cyan]")
        trainer.load()

    # Load Modern Threat Detector
    modern = None
    try:
        from ml.modern_detector import ModernThreatDetector
        mtd = ModernThreatDetector()
        if mtd.models_exist():
            mtd.load()
            modern = mtd
            console.print("[cyan]Loading Modern Threat Detector (ransomware · C2 · DGA)…[/cyan]")
        else:
            console.print("[yellow]Modern detector not found — training now…[/yellow]")
            mtd.train(n_per_class=2000)
            modern = mtd
    except Exception as e:
        console.print(f"[yellow]Modern detector unavailable: {e}[/yellow]")

    detector  = NIDSDetector(trainer, modern)
    explainer = NIDSExplainer(trainer)

    with console.status("[cyan]Building XAI explainer…"):
        explainer.build()

    alert_mgr  = AlertManager()
    flow_track = FlowTracker()

    # ── Packet callback ──────────────────────────────────────────────────────
    def on_packet(pkt_info: dict):
        alert_mgr.record_packet()
        flow_track.process_packet(pkt_info)

        for flow, features in flow_track.collect_expired():
            detection   = detector.predict(features)
            explanation = explainer.explain(features)
            alert       = alert_mgr.add(flow, detection, explanation)
            if alert and alert.severity in ("CRITICAL","HIGH"):
                console.print(
                    f"  [{_sev_clr(alert.severity)}]{alert.severity}[/]  "
                    f"{alert.label:10s}  {alert.src_ip} → {alert.dst_ip}"
                )

    # ── Capture ──────────────────────────────────────────────────────────────
    mode    = getattr(args, "mode",  "simulate")
    iface   = getattr(args, "iface", "eth0")
    port    = getattr(args, "port",  5000)
    no_dash = getattr(args, "no_dashboard", False)

    capture = PacketCapture(mode=mode, interface=iface, callback=on_packet)

    # ── Dashboard ─────────────────────────────────────────────────────────────
    if not no_dash:
        dash_app.init_dashboard(alert_mgr, detector, capture, trainer)
        use_ssl = getattr(args, "ssl", False)
        dash_thread = threading.Thread(
            target=dash_app.run,
            kwargs={"host":"0.0.0.0","port":port,
                    "debug":False},
            daemon=True,
        )
        dash_thread.start()
        proto = "https" if getattr(args, "ssl", False) else "http"
        console.print(f"\n[bold green]Dashboard:[/bold green] {proto}://localhost:{port}")

    # ── Start capture ─────────────────────────────────────────────────────────
    console.print(
        f"[bold green]Detection started[/bold green]  "
        f"mode=[cyan]{mode}[/cyan]  "
        + (f"iface=[cyan]{iface}[/cyan]" if mode=="live" else "")
    )
    console.print("[dim]Press Ctrl+C to stop and generate report.[/dim]\n")

    capture.start()
    start_time = time.time()

    try:
        while True:
            time.sleep(5)
            s = alert_mgr.dashboard_stats()
            console.print(
                f"  [dim]{_uptime(start_time)}[/dim]  "
                f"flows=[cyan]{s['total_flows']}[/cyan]  "
                f"[red]crit={s['critical']}[/red]  "
                f"[yellow]high={s['high']}[/yellow]  "
                f"[green]clean={s['clean']}[/green]  "
                f"pkt/s=[dim]{s['packets_per_sec']}[/dim]"
            )
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping capture…[/yellow]")
        capture.stop()

    # ── Auto-generate report ──────────────────────────────────────────────────
    console.print("[cyan]Generating PDF report…[/cyan]")
    _generate_report(alert_mgr, trainer, mode, start_time)


# ─── Report ────────────────────────────────────────────────────────────────────

def cmd_report(args):
    console.print("[yellow]No live session data. Run 'python main.py run' first.[/yellow]")


def _generate_report(alert_mgr, trainer, mode, start_time):
    from reporting.report_generator import NIDSReportGenerator

    stats = alert_mgr.dashboard_stats()
    stats["uptime"]         = _uptime(start_time)
    stats["model_accuracy"] = "Trained (see ml/models/)"

    session_data = {
        "meta": {
            "session_start": datetime.fromtimestamp(start_time)
                             .strftime("%Y-%m-%d %H:%M:%S"),
            "session_end":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname":      socket.gethostname(),
            "mode":          mode.capitalize(),
        },
        "stats":       stats,
        "alerts":      alert_mgr.all_alerts_for_report(),
        "top_sources": stats.get("top_sources", []),
    }

    reporter = NIDSReportGenerator(session_data, output_dir="./reports")
    path     = reporter.generate()
    console.print(f"[bold green]✅  Report saved:[/bold green] [cyan]{path}[/cyan]")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _uptime(start: float) -> str:
    s = int(time.time() - start)
    return f"{s//3600:02d}:{(s%3600)//60:02d}:{s%60:02d}"

def _sev_clr(sev: str) -> str:
    return {"CRITICAL":"bold red","HIGH":"bold yellow",
            "MEDIUM":"bold blue","LOW":"bold green"}.get(sev,"dim")


# ─── Entry ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    if args.command == "train":
        cmd_train(args)
    elif args.command == "run":
        cmd_run(args)
    elif args.command == "report":
        cmd_report(args)
    else:
        # Default: run in simulate mode
        class DefaultArgs:
            command      = "run"
            mode         = "simulate"
            iface        = "eth0"
            port         = 5000
            no_dashboard = False
        cmd_run(DefaultArgs())


if __name__ == "__main__":
    try:
       main()
    except KeyboardInterrupt:
       pass
