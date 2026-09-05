"""
dashboard/app.py — Flask + SocketIO real-time web dashboard.
Pushes live alerts and stats to the browser every second.
"""

import threading
import time
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit


app     = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*",
                    async_mode="threading")

# Global references — set by main.py before app.run()
_alert_manager = None
_detector_ref  = None
_capture_ref   = None
_trainer_ref   = None
_start_time    = time.time()


def init_dashboard(alert_manager, detector=None,
                   capture=None, trainer=None):
    """Called by main.py to inject live references."""
    global _alert_manager, _detector_ref, _capture_ref, _trainer_ref, _start_time
    _alert_manager = alert_manager
    _detector_ref  = detector
    _capture_ref   = capture
    _trainer_ref   = trainer
    _start_time    = time.time()


# ─── HTTP Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    if _alert_manager is None:
        return jsonify({"error": "not initialised"})
    stats = _alert_manager.dashboard_stats()
    stats["uptime"] = _fmt_uptime(time.time() - _start_time)
    return jsonify(stats)


@app.route("/api/alerts")
def api_alerts():
    n = int(request.args.get("n", 50))
    if _alert_manager is None:
        return jsonify([])
    return jsonify(_alert_manager.recent_alerts(n))


@app.route("/api/explain/<alert_id>")
def api_explain(alert_id):
    """Return explanation for a specific alert by ID."""
    if _alert_manager is None:
        return jsonify({})
    for a in _alert_manager.recent_alerts(500):
        if a["id"] == alert_id:
            return jsonify(a.get("explanation", {}))
    return jsonify({"error": "alert not found"}), 404


@app.route("/api/model_info")
def api_model_info():
    if _trainer_ref is None:
        return jsonify({"status": "no model"})
    return jsonify({
        "status":   "loaded",
        "classes":  list(_trainer_ref.label_enc.classes_)
                    if _trainer_ref.label_enc else [],
        "features": 24,
        "models":   ["Random Forest (n=150)", "Isolation Forest (n=150)"],
    })


# ─── SocketIO Events ──────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    emit("connected", {"msg": "NIDS dashboard connected"})
    _push_full_state()


@socketio.on("request_state")
def on_request_state():
    _push_full_state()


def _push_full_state():
    if _alert_manager is None:
        return
    stats  = _alert_manager.dashboard_stats()
    stats["uptime"] = _fmt_uptime(time.time() - _start_time)
    emit("stats_update",  stats)
    emit("alerts_update", _alert_manager.recent_alerts(50))


# ─── Background Broadcaster ───────────────────────────────────────────────────

def _broadcast_loop():
    """Push live updates to all connected clients every second."""
    while True:
        time.sleep(1)
        if _alert_manager is None:
            continue
        try:
            stats = _alert_manager.dashboard_stats()
            stats["uptime"] = _fmt_uptime(time.time() - _start_time)
            socketio.emit("stats_update",  stats)
            socketio.emit("alerts_update", _alert_manager.recent_alerts(50))
        except Exception:
            pass


def start_broadcaster():
    t = threading.Thread(target=_broadcast_loop, daemon=True)
    t.start()


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _fmt_uptime(seconds: float) -> str:
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def run(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
    start_broadcaster()
    socketio.run(app, host=host, port=port,
                 debug=debug, use_reloader=False, log_output=False)
