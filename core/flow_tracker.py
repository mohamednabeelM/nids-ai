"""
core/flow_tracker.py — Aggregates raw packet events into network flows
and extracts ML-ready features from each completed flow.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field

FLOW_TIMEOUT = 30.0   # seconds of inactivity before flow is finalised


@dataclass
class Flow:
    src_ip:    str
    dst_ip:    str
    src_port:  int
    dst_port:  int
    protocol:  int      # 0=TCP 1=UDP 2=ICMP

    # Counters updated as packets arrive
    start_time:    float = field(default_factory=time.time)
    last_seen:     float = field(default_factory=time.time)
    pkt_count:     int   = 0
    src_bytes:     int   = 0
    dst_bytes:     int   = 0
    syn_count:     int   = 0
    fin_count:     int   = 0
    rst_count:     int   = 0
    urg_count:     int   = 0
    wrong_frags:   int   = 0
    same_srv:      int   = 0
    diff_srv:      int   = 0

    def update(self, pkt_size: int, is_src: bool, flags: dict):
        self.pkt_count  += 1
        self.last_seen   = time.time()
        if is_src:
            self.src_bytes += pkt_size
        else:
            self.dst_bytes += pkt_size
        self.syn_count  += int(flags.get("SYN", False))
        self.fin_count  += int(flags.get("FIN", False))
        self.rst_count  += int(flags.get("RST", False))
        self.urg_count  += int(flags.get("URG", False))

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time

    def is_expired(self) -> bool:
        return (time.time() - self.last_seen) > FLOW_TIMEOUT

    def to_features(self, global_stats: dict) -> dict:
        """Convert flow into an ML feature vector."""
        duration    = max(self.duration, 0.001)
        pkt_rate    = self.pkt_count / duration
        byte_rate   = (self.src_bytes + self.dst_bytes) / duration
        pkt_cnt     = max(self.pkt_count, 1)

        return {
            "duration":               duration,
            "protocol_type":          self.protocol,
            "src_bytes":              float(self.src_bytes),
            "dst_bytes":              float(self.dst_bytes),
            "wrong_fragment":         float(self.wrong_frags),
            "urgent":                 float(self.urg_count),
            "count":                  float(global_stats.get("conn_2s", 1)),
            "srv_count":              float(global_stats.get("srv_2s", 1)),
            "serror_rate":            self.syn_count / pkt_cnt,
            "rerror_rate":            self.rst_count / pkt_cnt,
            "same_srv_rate":          self.same_srv / max(self.same_srv + self.diff_srv, 1),
            "diff_srv_rate":          self.diff_srv / max(self.same_srv + self.diff_srv, 1),
            "dst_host_count":         float(global_stats.get("dst_host_count", 1)),
            "dst_host_srv_count":     float(global_stats.get("dst_host_srv_count", 1)),
            "dst_host_same_srv_rate": float(global_stats.get("dst_host_same_srv_rate", 1.0)),
            "dst_host_diff_srv_rate": float(global_stats.get("dst_host_diff_srv_rate", 0.0)),
            "dst_host_serror_rate":   float(global_stats.get("dst_host_serror_rate", 0.0)),
            "packet_rate":            pkt_rate,
            "byte_rate":              byte_rate,
            "flag_syn_ratio":         self.syn_count / pkt_cnt,
            "flag_fin_ratio":         self.fin_count / pkt_cnt,
            "flag_rst_ratio":         self.rst_count / pkt_cnt,
            "port_number":            float(self.dst_port),
            "is_well_known_port":     float(self.dst_port < 1024),
        }


class FlowTracker:
    """Tracks all active network flows and emits completed flows."""

    def __init__(self):
        self._flows:  dict[tuple, Flow] = {}
        self._history: list[dict]       = []   # recent completed flows
        self._conn_window: list[float]  = []   # timestamps for 2-sec window
        self._dst_host_log: dict        = defaultdict(set)

    # ─── Public API ───────────────────────────────────────────────────────────

    def process_packet(self, pkt_info: dict) -> Flow | None:
        """
        Feed one packet. Returns a completed Flow if one just expired,
        else None.
        """
        key     = self._flow_key(pkt_info)
        rev_key = self._flow_key(pkt_info, reverse=True)

        now = time.time()
        self._conn_window = [t for t in self._conn_window if now - t < 2.0]
        self._conn_window.append(now)

        # Look up existing flow
        if key in self._flows:
            flow = self._flows[key]
            is_src = True
        elif rev_key in self._flows:
            flow   = self._flows[rev_key]
            key    = rev_key
            is_src = False
        else:
            # New flow
            flow = Flow(
                src_ip   = pkt_info.get("src_ip",   "0.0.0.0"),
                dst_ip   = pkt_info.get("dst_ip",   "0.0.0.0"),
                src_port = pkt_info.get("src_port", 0),
                dst_port = pkt_info.get("dst_port", 0),
                protocol = pkt_info.get("protocol", 0),
            )
            self._flows[key] = flow
            is_src = True

        flow.update(
            pkt_size = pkt_info.get("size", 0),
            is_src   = is_src,
            flags    = pkt_info.get("flags", {}),
        )

        # Track destination host statistics
        dst = pkt_info.get("dst_ip", "")
        self._dst_host_log[dst].add(pkt_info.get("dst_port", 0))

        # Check for expired flows
        return self._expire_flow(key)

    def collect_expired(self) -> list[tuple[Flow, dict]]:
        """Return and remove all expired flows as (flow, features) pairs."""
        expired_keys = [k for k, f in list(self._flows.items()) if f.is_expired()]
        results = []
        for key in expired_keys:
            flow = self._flows.pop(key)
            stats = self._global_stats(flow)
            results.append((flow, flow.to_features(stats)))
        return results

    def active_count(self) -> int:
        return len(self._flows)

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _expire_flow(self, key: tuple) -> Flow | None:
        flow = self._flows.get(key)
        if flow and flow.is_expired() and flow.pkt_count > 0:
            return self._flows.pop(key)
        return None

    def _global_stats(self, flow: Flow) -> dict:
        dst = flow.dst_ip
        dst_ports = self._dst_host_log.get(dst, set())
        total_dst  = max(len(dst_ports), 1)
        same_srv   = sum(1 for p in dst_ports if p == flow.dst_port)
        return {
            "conn_2s":               len(self._conn_window),
            "srv_2s":                max(len(self._conn_window) // 2, 1),
            "dst_host_count":        len(self._dst_host_log),
            "dst_host_srv_count":    total_dst,
            "dst_host_same_srv_rate": same_srv / total_dst,
            "dst_host_diff_srv_rate": (total_dst - same_srv) / total_dst,
            "dst_host_serror_rate":  0.0,   # approximation
        }

    @staticmethod
    def _flow_key(pkt: dict, reverse: bool = False) -> tuple:
        if reverse:
            return (pkt.get("dst_ip"), pkt.get("src_ip"),
                    pkt.get("dst_port"), pkt.get("src_port"),
                    pkt.get("protocol"))
        return (pkt.get("src_ip"), pkt.get("dst_ip"),
                pkt.get("src_port"), pkt.get("dst_port"),
                pkt.get("protocol"))
