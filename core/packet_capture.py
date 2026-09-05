"""
core/packet_capture.py — Packet capture with two modes:
  LIVE      : Scapy sniff on real interface (requires root/admin)
  SIMULATE  : Realistic synthetic traffic generator (works everywhere)
"""

import random
import threading
import time
from typing import Callable

# ─── Simulation Config ────────────────────────────────────────────────────────
NORMAL_HOSTS = [f"192.168.1.{i}" for i in range(2, 30)]
ATTACK_HOSTS = [f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"
                for _ in range(10)]
SERVER_IP    = "192.168.1.1"
SERVICES     = {80: "HTTP", 443: "HTTPS", 22: "SSH",
                25: "SMTP", 53: "DNS",  3306: "MySQL"}

ATTACK_TEMPLATES = {
    "dos": {
        "description": "SYN Flood / DoS Attack",
        "pkt_rate":    800,
        "size_range":  (40, 80),
        "flags":       {"SYN": True},
        "dst_port":    80,
    },
    "probe": {
        "description": "Port Scan",
        "pkt_rate":    200,
        "size_range":  (40, 60),
        "flags":       {"SYN": True, "RST": False},
        "dst_port":    None,   # random
    },
    "r2l": {
        "description": "Remote-to-Local (Credential Brute Force)",
        "pkt_rate":    30,
        "size_range":  (200, 500),
        "flags":       {"SYN": False, "ACK": True},
        "dst_port":    22,
    },
    "u2r": {
        "description": "Privilege Escalation",
        "pkt_rate":    5,
        "size_range":  (1000, 4000),
        "flags":       {"FIN": True},
        "dst_port":    23,
    },
}


class PacketCapture:
    """Unified interface for live capture and traffic simulation."""

    def __init__(self, mode: str = "simulate",
                 interface: str = "eth0",
                 callback: Callable | None = None):
        self.mode       = mode          # "live" | "simulate"
        self.interface  = interface
        self.callback   = callback      # fn(pkt_info: dict)
        self._running   = False
        self._thread    = None
        self.stats      = {"total": 0, "attacks_injected": 0}

    # ─── Public API ───────────────────────────────────────────────────────────

    def start(self):
        self._running = True
        if self.mode == "live":
            self._thread = threading.Thread(
                target=self._live_capture, daemon=True)
        else:
            self._thread = threading.Thread(
                target=self._simulate, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def set_callback(self, fn: Callable):
        self.callback = fn

    # ─── Live Capture (Scapy) ─────────────────────────────────────────────────

    def _live_capture(self):
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
        except ImportError:
            print("[!] Scapy not installed — falling back to simulation.")
            self._simulate()
            return

        def _process(pkt):
            if not self._running:
                return
            info = self._parse_scapy_pkt(pkt)
            if info:
                self.stats["total"] += 1
                if self.callback:
                    self.callback(info)

        try:
            sniff(iface=self.interface, prn=_process,
                  store=False, stop_filter=lambda _: not self._running)
        except PermissionError:
            print("[!] Root/admin required for live capture — using simulation.")
            self._simulate()
        except Exception as e:
            print(f"[!] Capture error: {e} — using simulation.")
            self._simulate()

    @staticmethod
    def _parse_scapy_pkt(pkt) -> dict | None:
        from scapy.all import IP, TCP, UDP, ICMP
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        proto_map = {"tcp": 0, "udp": 1, "icmp": 2}
        proto = 0

        flags = {}
        sport, dport = 0, 0

        if pkt.haslayer(TCP):
            proto  = 0
            tcp    = pkt[TCP]
            sport  = tcp.sport
            dport  = tcp.dport
            f      = tcp.flags
            flags  = {
                "SYN": bool(f & 0x02),
                "ACK": bool(f & 0x10),
                "FIN": bool(f & 0x01),
                "RST": bool(f & 0x04),
                "URG": bool(f & 0x20),
            }
        elif pkt.haslayer(UDP):
            proto = 1
            udp   = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
        elif pkt.haslayer(ICMP):
            proto = 2

        return {
            "src_ip":   ip.src,
            "dst_ip":   ip.dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
            "size":     len(pkt),
            "flags":    flags,
            "ts":       time.time(),
        }

    # ─── Traffic Simulation ───────────────────────────────────────────────────

    def _simulate(self):
        """
        Generates a realistic mix of normal + attack traffic.
        Attack bursts are injected every 15–30 seconds.
        """
        next_attack = time.time() + random.uniform(10, 20)

        while self._running:
            now = time.time()

            # Inject attack burst?
            if now >= next_attack:
                attack_type = random.choice(list(ATTACK_TEMPLATES.keys()))
                self._inject_attack(attack_type, duration=random.uniform(3, 8))
                next_attack = now + random.uniform(15, 35)

            # Normal packet
            pkt = self._make_normal_pkt()
            self.stats["total"] += 1
            if self.callback:
                self.callback(pkt)
            time.sleep(random.expovariate(50))   # ~50 pkts/sec normal rate

    def _inject_attack(self, attack_type: str, duration: float):
        tmpl      = ATTACK_TEMPLATES[attack_type]
        attacker  = random.choice(ATTACK_HOSTS)
        end_time  = time.time() + duration
        rate      = tmpl["pkt_rate"]
        sleep_t   = 1.0 / rate

        def _burst():
            while self._running and time.time() < end_time:
                pkt = self._make_attack_pkt(attacker, tmpl)
                self.stats["total"]           += 1
                self.stats["attacks_injected"] += 1
                if self.callback:
                    self.callback(pkt)
                time.sleep(sleep_t)

        t = threading.Thread(target=_burst, daemon=True)
        t.start()

    @staticmethod
    def _make_normal_pkt() -> dict:
        src  = random.choice(NORMAL_HOSTS)
        dst  = SERVER_IP
        port = random.choice(list(SERVICES.keys()))
        proto = random.choices([0, 1, 2], weights=[60, 35, 5])[0]
        return {
            "src_ip":   src,
            "dst_ip":   dst,
            "src_port": random.randint(1024, 65535),
            "dst_port": port,
            "protocol": proto,
            "size":     random.randint(40, 1500),
            "flags":    {
                "SYN": random.random() < 0.1,
                "ACK": random.random() < 0.7,
                "FIN": random.random() < 0.05,
                "RST": random.random() < 0.02,
                "URG": False,
            },
            "ts": time.time(),
        }

    @staticmethod
    def _make_attack_pkt(attacker: str, tmpl: dict) -> dict:
        lo, hi = tmpl["size_range"]
        port   = tmpl["dst_port"] or random.randint(1, 65535)
        return {
            "src_ip":   attacker,
            "dst_ip":   SERVER_IP,
            "src_port": random.randint(1024, 65535),
            "dst_port": port,
            "protocol": 0,
            "size":     random.randint(lo, hi),
            "flags":    tmpl["flags"].copy(),
            "ts":       time.time(),
            "_attack":  True,
        }
