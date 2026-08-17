"""
network_scanner.py — Packet capture + ARP network scanner for the ZeroDay-Edge Node.

Two responsibilities:
  1. Packet Sniffer (background thread)
     - Sniffs all IP packets on the default interface using Scapy
     - Accumulates per-flow (5-tuple, bidirectional) CIC-IDS-2017-style
       statistics in a 5-second window — see _FlowStats
     - drain_flows() returns flow dicts, keyed by the trained models'
       actual feature names, ready for ML classification

  2. ARP Scanner
     - Broadcasts ARP requests to enumerate all devices on the LAN
     - Fallback: reads /proc/net/arp if Scapy is unavailable
     - Results cached in memory, refreshed periodically
"""

import logging
import re
import shutil
import socket
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Scapy availability check ──────────────────────────────────────────────
SCAPY_AVAILABLE = False
try:
    from scapy.all import ARP, Ether, IP, TCP, UDP, srp, sniff  # type: ignore
    SCAPY_AVAILABLE = True
    logger.info("Scapy available — live packet capture enabled")
except ImportError:
    logger.warning("Scapy not installed — live capture disabled (manual ingest only)")

# ── nmcli availability check (Evil Twin / Beacon Flood detection) ─────────
# Uses a normal station-mode WiFi scan — no monitor mode needed, unlike
# deauth detection.
NMCLI_AVAILABLE = shutil.which("nmcli") is not None
if NMCLI_AVAILABLE:
    logger.info("nmcli available — WiFi SSID scan (Evil Twin/Beacon Flood) enabled")
else:
    logger.warning("nmcli not found — Evil Twin/Beacon Flood detection disabled")


def _parse_nmcli_terse(line: str) -> list[str]:
    """
    Split one line of `nmcli -t` output on unescaped colons — nmcli escapes
    literal colons inside field values (e.g. a BSSID's own colons) with a
    backslash specifically so they don't collide with the field separator.
    """
    fields = re.split(r"(?<!\\):", line)
    return [f.replace("\\:", ":").replace("\\\\", "\\") for f in fields]


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LOCAL_IP = _get_local_ip()


class _RunningStats:
    """
    Streaming mean/std/min/max via Welford's algorithm — O(1) memory per
    flow regardless of packet count, instead of storing every packet length
    or inter-arrival time. A flood can mint thousands of samples inside one
    5s window; a 4GB Pi 4 doesn't have the headroom to buffer all of them
    the way an 8GB Pi 5 might get away with.
    """

    __slots__ = ("n", "mean", "m2", "min", "max")

    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.m2 = 0.0
        self.min = 0.0
        self.max = 0.0

    def add(self, x: float):
        self.n += 1
        if self.n == 1:
            self.min = self.max = x
        else:
            if x < self.min: self.min = x
            if x > self.max: self.max = x
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    @property
    def std(self) -> float:
        return (self.m2 / self.n) ** 0.5 if self.n > 1 else 0.0

    @property
    def total(self) -> float:
        return self.mean * self.n


class _FlowStats:
    """
    Accumulates CIC-IDS-2017-style bidirectional flow statistics from raw
    packets, keyed by 5-tuple by the caller. "Forward" = whichever endpoint
    sent the first packet of the flow, "backward" = the other side —
    matches CICFlowMeter's convention, which is what feature_columns.joblib
    and the trained models expect. Field names in to_feature_dict() are
    written to match those trained column names exactly.
    """

    __slots__ = (
        "start_time", "last_time", "initiator", "peer_ip",
        "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
        "fwd_len", "bwd_len", "pkt_len",
        "flow_iat", "fwd_iat", "bwd_iat", "last_fwd_time", "last_bwd_time",
        "fwd_header_bytes", "bwd_header_bytes", "min_fwd_header_bytes",
        "syn_cnt", "ack_cnt", "fin_cnt", "rst_cnt", "psh_cnt", "urg_cnt",
        "fwd_psh_cnt", "bwd_psh_cnt", "fwd_urg_cnt", "bwd_urg_cnt",
        "init_fwd_win", "init_bwd_win", "fwd_data_pkts",
    )

    def __init__(self, now: float):
        self.start_time = now
        self.last_time = now
        self.initiator = None
        self.peer_ip = None
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0
        self.fwd_len = _RunningStats()
        self.bwd_len = _RunningStats()
        self.pkt_len = _RunningStats()
        self.flow_iat = _RunningStats()
        self.fwd_iat = _RunningStats()
        self.bwd_iat = _RunningStats()
        self.last_fwd_time = None
        self.last_bwd_time = None
        self.fwd_header_bytes = 0
        self.bwd_header_bytes = 0
        self.min_fwd_header_bytes = None
        self.syn_cnt = 0
        self.ack_cnt = 0
        self.fin_cnt = 0
        self.rst_cnt = 0
        self.psh_cnt = 0
        self.urg_cnt = 0
        self.fwd_psh_cnt = 0
        self.bwd_psh_cnt = 0
        self.fwd_urg_cnt = 0
        self.bwd_urg_cnt = 0
        self.init_fwd_win = None
        self.init_bwd_win = None
        self.fwd_data_pkts = 0

    def add_packet(self, src: str, sport: int, dst: str, pkt_len: int,
                    header_len: int, payload_len: int, tcp_layer, now: float):
        if self.initiator is None:
            self.initiator = (src, sport)
            self.peer_ip = dst
        is_fwd = (src, sport) == self.initiator

        if now > self.last_time:
            self.flow_iat.add((now - self.last_time) * 1e6)  # microseconds
        self.last_time = now
        self.pkt_len.add(pkt_len)

        if is_fwd:
            self.fwd_pkts += 1
            self.fwd_bytes += pkt_len
            self.fwd_len.add(pkt_len)
            self.fwd_header_bytes += header_len
            self.min_fwd_header_bytes = (
                header_len if self.min_fwd_header_bytes is None
                else min(self.min_fwd_header_bytes, header_len)
            )
            if payload_len > 0:
                self.fwd_data_pkts += 1
            if self.last_fwd_time is not None and now > self.last_fwd_time:
                self.fwd_iat.add((now - self.last_fwd_time) * 1e6)
            self.last_fwd_time = now
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += pkt_len
            self.bwd_len.add(pkt_len)
            self.bwd_header_bytes += header_len
            if self.last_bwd_time is not None and now > self.last_bwd_time:
                self.bwd_iat.add((now - self.last_bwd_time) * 1e6)
            self.last_bwd_time = now

        if tcp_layer is not None:
            flags = tcp_layer.flags
            if flags.S: self.syn_cnt += 1
            if flags.A: self.ack_cnt += 1
            if flags.F: self.fin_cnt += 1
            if flags.R: self.rst_cnt += 1
            if flags.P:
                self.psh_cnt += 1
                if is_fwd: self.fwd_psh_cnt += 1
                else: self.bwd_psh_cnt += 1
            if flags.U:
                self.urg_cnt += 1
                if is_fwd: self.fwd_urg_cnt += 1
                else: self.bwd_urg_cnt += 1
            if is_fwd and self.init_fwd_win is None:
                self.init_fwd_win = tcp_layer.window
            elif not is_fwd and self.init_bwd_win is None:
                self.init_bwd_win = tcp_layer.window

    def to_feature_dict(self, now: float, sensor_node_id: str) -> dict:
        duration_s = max(now - self.start_time, 1e-6)
        total_pkts = self.fwd_pkts + self.bwd_pkts
        total_bytes = self.fwd_bytes + self.bwd_bytes
        src_ip = self.initiator[0] if self.initiator else "0.0.0.0"
        dst_ip = self.peer_ip or "0.0.0.0"

        return {
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            # snake_case shortcuts — kept for db.insert_flow()/app.py compatibility
            "flow_duration": duration_s * 1e6,
            "total_fwd_packets": self.fwd_pkts,
            "total_bwd_packets": self.bwd_pkts,
            "flow_bytes_per_sec": total_bytes / duration_s,
            "sensor_node_id": sensor_node_id,
            # Native CIC-IDS-2017 column names — picked up directly by
            # ml_engine.py's _prepare_features() fallback (flow_data.get(col,
            # 0.0)), no changes needed there.
            "Flow Duration": duration_s * 1e6,
            "Tot Fwd Pkts": self.fwd_pkts,
            "Tot Bwd Pkts": self.bwd_pkts,
            "TotLen Fwd Pkts": self.fwd_bytes,
            "TotLen Bwd Pkts": self.bwd_bytes,
            "Fwd Pkt Len Max": self.fwd_len.max,
            "Fwd Pkt Len Min": self.fwd_len.min,
            "Fwd Pkt Len Mean": self.fwd_len.mean,
            "Fwd Pkt Len Std": self.fwd_len.std,
            "Bwd Pkt Len Max": self.bwd_len.max,
            "Bwd Pkt Len Min": self.bwd_len.min,
            "Bwd Pkt Len Mean": self.bwd_len.mean,
            "Bwd Pkt Len Std": self.bwd_len.std,
            "Flow Byts/s": total_bytes / duration_s,
            "Flow Pkts/s": total_pkts / duration_s,
            "Flow IAT Mean": self.flow_iat.mean,
            "Flow IAT Std": self.flow_iat.std,
            "Flow IAT Max": self.flow_iat.max,
            "Flow IAT Min": self.flow_iat.min,
            "Fwd IAT Tot": self.fwd_iat.total,
            "Fwd IAT Mean": self.fwd_iat.mean,
            "Fwd IAT Std": self.fwd_iat.std,
            "Fwd IAT Max": self.fwd_iat.max,
            "Fwd IAT Min": self.fwd_iat.min,
            "Bwd IAT Tot": self.bwd_iat.total,
            "Bwd IAT Mean": self.bwd_iat.mean,
            "Bwd IAT Std": self.bwd_iat.std,
            "Bwd IAT Max": self.bwd_iat.max,
            "Bwd IAT Min": self.bwd_iat.min,
            "Fwd PSH Flags": self.fwd_psh_cnt,
            "Bwd PSH Flags": self.bwd_psh_cnt,
            "Fwd URG Flags": self.fwd_urg_cnt,
            "Bwd URG Flags": self.bwd_urg_cnt,
            "Fwd Header Len": self.fwd_header_bytes,
            "Bwd Header Len": self.bwd_header_bytes,
            "Fwd Pkts/s": self.fwd_pkts / duration_s,
            "Bwd Pkts/s": self.bwd_pkts / duration_s,
            "Pkt Len Min": self.pkt_len.min,
            "Pkt Len Max": self.pkt_len.max,
            "Pkt Len Mean": self.pkt_len.mean,
            "Pkt Len Std": self.pkt_len.std,
            "Pkt Len Var": self.pkt_len.std ** 2,
            "FIN Flag Cnt": self.fin_cnt,
            "SYN Flag Cnt": self.syn_cnt,
            "RST Flag Cnt": self.rst_cnt,
            "PSH Flag Cnt": self.psh_cnt,
            "ACK Flag Cnt": self.ack_cnt,
            "URG Flag Cnt": self.urg_cnt,
            "Down/Up Ratio": (self.bwd_pkts / self.fwd_pkts) if self.fwd_pkts else 0.0,
            "Pkt Size Avg": (total_bytes / total_pkts) if total_pkts else 0.0,
            "Fwd Seg Size Avg": self.fwd_len.mean,
            "Bwd Seg Size Avg": self.bwd_len.mean,
            "Subflow Fwd Pkts": self.fwd_pkts,
            "Subflow Fwd Byts": self.fwd_bytes,
            "Subflow Bwd Pkts": self.bwd_pkts,
            "Subflow Bwd Byts": self.bwd_bytes,
            "Init Fwd Win Byts": self.init_fwd_win if self.init_fwd_win is not None else -1,
            "Init Bwd Win Byts": self.init_bwd_win if self.init_bwd_win is not None else -1,
            "Fwd Act Data Pkts": self.fwd_data_pkts,
            "Fwd Seg Size Min": self.min_fwd_header_bytes or 0,
        }


# ── Flow accumulator (shared state) ──────────────────────────────────────
# Key: 5-tuple (lower (ip,port) pair first, for consistent bidirectional
# matching regardless of which packet direction arrives first)
_flow_table: dict = defaultdict(lambda: _FlowStats(time.time()))
_flow_lock  = threading.Lock()

# Caps distinct flows tracked between drains. A port scan / DDoS can
# otherwise mint unbounded new keys in the 5s window; on a 4GB Pi 4 that
# memory isn't there to spare the way it is on an 8GB Pi 5.
_MAX_FLOW_TABLE_ENTRIES = 4000

# ── Burst tracker: port scans AND DDoS/floods (separate from _flow_table) ──
# A scan touching N ports, or a flood sending N packets, on one target looks
# in proper 5-tuple flows like many small separate flows — not one big flow
# — so neither shows the "many packets in one flow" shape the tree ensemble
# was verified against. Track volume/diversity per (src, dst) pair directly
# instead of hoping the ML models happen to recognize that shattered
# representation.
# Key: (src_ip, dst_ip) — Value: {"ports": set(), "pkts": int, "bytes": int, "start": float}
_scan_table: dict = defaultdict(lambda: {"ports": set(), "pkts": 0, "bytes": 0, "start": time.time()})
_SCAN_PORT_THRESHOLD = 15     # distinct dst ports from one src to one dst within a window = scan
_SCAN_MAX_AVG_PKTS_PER_PORT = 5  # below this density, high port count = scan, not flood
_FLOOD_PACKET_THRESHOLD = 300  # packets from one src to one dst within a window = flood/DDoS

# ── Brute-force tracker ────────────────────────────────────────────────────
# Repeated login/connection attempts at ONE port look like the scan case —
# many small separate flows (each attempt gets its own ephemeral source
# port) — but concentrated on a single destination port instead of spread
# across many. Counts fresh SYNs (SYN without ACK = a new connection
# attempt, not a response) per (src, dst, dst_port).
_bruteforce_table: dict = defaultdict(lambda: {"attempts": 0, "start": time.time()})
_BRUTEFORCE_ATTEMPT_THRESHOLD = 10  # connection attempts to the same dst:port within a window

# ARP scan results cache
_devices_cache: list[dict] = []
_devices_lock  = threading.Lock()

# ── WiFi SSID scan state (Evil Twin / Beacon Flood) ────────────────────────
# First-seen-trusted, same philosophy as db.py's iot_devices Zero Trust
# registry: the first BSSID seen for an SSID becomes the baseline; a second,
# different BSSID for the same SSID is the classic Evil Twin signature.
_known_ssid_bssids: dict = defaultdict(set)
_wifi_scan_lock = threading.Lock()
_last_evil_twin_alert: dict = {}
_last_beacon_flood_alert: dict = {"t": 0.0}
_BEACON_FLOOD_SSID_THRESHOLD = 25  # distinct SSIDs in one scan pass = flood
_ALERT_COOLDOWN_SECONDS = 30       # don't re-alert the same condition more often than this


class NetworkScanner:
    """
    Manages packet capture (Scapy) and ARP scanning.
    Designed to run its blocking operations in daemon threads.
    """

    def __init__(self, interface: str | None = None):
        """
        Args:
            interface: Network interface to sniff on (e.g. "eth0", "wlan0").
                       None = Scapy auto-detect.
        """
        self.interface = interface
        self._sniff_running = False

    # ── Packet Capture ────────────────────────────────────────────────────

    def start_capture(self):
        """
        Start blocking Scapy packet sniff. Call from a daemon thread.
        Silently no-ops if Scapy is unavailable.
        """
        if not SCAPY_AVAILABLE:
            logger.info("Capture disabled — running in passive/manual-ingest mode")
            return

        self._sniff_running = True
        logger.info("Starting packet capture (interface=%s)…", self.interface or "auto")

        kwargs: dict = {
            "prn":    self._handle_packet,
            "store":  False,
            "filter": "ip",          # only IPv4
        }
        if self.interface:
            kwargs["iface"] = self.interface

        try:
            sniff(**kwargs)  # blocks forever
        except PermissionError:
            logger.error(
                "Packet capture requires root privileges. "
                "Run with: sudo python app.py"
            )
        except Exception as e:
            logger.error("Capture error: %s", e)

    def _handle_packet(self, pkt):
        """Scapy callback — accumulate per-flow CIC-IDS-2017-style stats from each IP packet."""
        try:
            if not pkt.haslayer(IP):
                return

            ip = pkt[IP]
            src, dst = ip.src, ip.dst

            # Skip loopback and our own management traffic to Flask port
            if src.startswith("127.") or dst.startswith("127."):
                return
            if src == LOCAL_IP and dst == LOCAL_IP:
                return

            tcp_layer = pkt[TCP] if pkt.haslayer(TCP) else None
            udp_layer = pkt[UDP] if pkt.haslayer(UDP) else None

            if tcp_layer is not None:
                sport, dport = tcp_layer.sport, tcp_layer.dport
                header_len = ip.ihl * 4 + tcp_layer.dataofs * 4
                payload_len = len(tcp_layer.payload)
            elif udp_layer is not None:
                sport, dport = udp_layer.sport, udp_layer.dport
                header_len = ip.ihl * 4 + 8
                payload_len = len(udp_layer.payload)
            else:
                sport, dport = 0, 0
                header_len = ip.ihl * 4
                payload_len = len(ip.payload)

            pkt_len = len(pkt)
            now = time.time()

            a, b = (src, sport), (dst, dport)
            key = (src, sport, dst, dport) if a <= b else (dst, dport, src, sport)

            with _flow_lock:
                if key not in _flow_table and len(_flow_table) >= _MAX_FLOW_TABLE_ENTRIES:
                    return  # table full — this flow's stats resume next drain window
                _flow_table[key].add_packet(src, sport, dst, pkt_len, header_len, payload_len, tcp_layer, now)

                scan_entry = _scan_table[(src, dst)]
                scan_entry["ports"].add(dport)
                scan_entry["pkts"] += 1
                scan_entry["bytes"] += pkt_len

                if tcp_layer is not None and tcp_layer.flags.S and not tcp_layer.flags.A:
                    _bruteforce_table[(src, dst, dport)]["attempts"] += 1

        except Exception:
            pass  # never crash the capture thread

    def drain_flows(self) -> list[dict]:
        """
        Snapshot and clear the current flow table.
        Returns a list of flow dicts ready for ML classification.
        """
        with _flow_lock:
            snapshot = dict(_flow_table)
            _flow_table.clear()

        now = time.time()
        sensor_node_id = f"rpi4-{self.interface or 'eth0'}"
        return [stats.to_feature_dict(now, sensor_node_id) for stats in snapshot.values()]

    def drain_burst_alerts(self) -> list[dict]:
        """
        Snapshot and clear the burst tracker. Returns pre-formed alert dicts
        (same shape as MLEngine.classify()'s output) for any (src, dst) pair
        that crossed the flood or scan threshold in the window — bypasses
        the ML pipeline entirely, see _scan_table comment.

        Scan vs flood is told apart by packets-PER-PORT, not raw packet
        count: a scan spreads ~1 packet across each of many ports (low
        density), a flood concentrates hundreds of packets on one or two
        ports (high density). Raw packet count alone was wrong — a normal
        1000-port nmap scan easily exceeds a "300 packets in 5s" flood
        threshold on total volume, which mislabeled real scans as floods.
        """
        with _flow_lock:
            snapshot = dict(_scan_table)
            _scan_table.clear()

        now = time.time()
        alerts = []
        for (src, dst), data in snapshot.items():
            n_ports = len(data["ports"])
            n_pkts = data["pkts"]
            window_s = round(now - data["start"], 1)
            avg_pkts_per_port = n_pkts / max(n_ports, 1)

            if n_ports >= _SCAN_PORT_THRESHOLD and avg_pkts_per_port < _SCAN_MAX_AVG_PKTS_PER_PORT:
                confidence = min(n_ports / (_SCAN_PORT_THRESHOLD * 4), 1.0)
                alerts.append({
                    "source_ip": src,
                    "dest_ip": dst,
                    "threat_class": "PortScan",
                    "confidence": confidence,
                    "detected_by": "Port Scan Heuristic",
                    "is_blocked": confidence >= 0.85,
                    "xai_features": [
                        {"name": "distinct_ports_scanned", "raw_value": n_ports, "impact": 1.0},
                        {"name": "packets_in_window", "raw_value": n_pkts, "impact": 0.6},
                        {"name": "window_seconds", "raw_value": window_s, "impact": 0.0},
                    ],
                    "timestamp": datetime.utcnow().isoformat(),
                })
            elif n_pkts >= _FLOOD_PACKET_THRESHOLD:
                confidence = min(n_pkts / (_FLOOD_PACKET_THRESHOLD * 4), 1.0)
                alerts.append({
                    "source_ip": src,
                    "dest_ip": dst,
                    "threat_class": "DDoS / Flood",
                    "confidence": confidence,
                    "detected_by": "Flood Heuristic",
                    "is_blocked": confidence >= 0.85,
                    "xai_features": [
                        {"name": "packets_in_window", "raw_value": n_pkts, "impact": 1.0},
                        {"name": "bytes_in_window", "raw_value": data["bytes"], "impact": 0.7},
                        {"name": "window_seconds", "raw_value": window_s, "impact": 0.0},
                    ],
                    "timestamp": datetime.utcnow().isoformat(),
                })
        return alerts

    def drain_bruteforce_alerts(self) -> list[dict]:
        """
        Snapshot and clear the brute-force tracker. Returns pre-formed alert
        dicts for any (src, dst, dst_port) that crossed
        _BRUTEFORCE_ATTEMPT_THRESHOLD fresh connection attempts in the window.
        """
        with _flow_lock:
            snapshot = dict(_bruteforce_table)
            _bruteforce_table.clear()

        now = time.time()
        alerts = []
        for (src, dst, port), data in snapshot.items():
            attempts = data["attempts"]
            if attempts < _BRUTEFORCE_ATTEMPT_THRESHOLD:
                continue
            confidence = min(attempts / (_BRUTEFORCE_ATTEMPT_THRESHOLD * 4), 1.0)
            alerts.append({
                "source_ip": src,
                "dest_ip": dst,
                "threat_class": "Brute Force Attempt",
                "confidence": confidence,
                "detected_by": "Brute Force Heuristic",
                "is_blocked": confidence >= 0.85,
                "xai_features": [
                    {"name": "connection_attempts", "raw_value": attempts, "impact": 1.0},
                    {"name": "target_port", "raw_value": port, "impact": 0.3},
                    {"name": "window_seconds", "raw_value": round(now - data["start"], 1), "impact": 0.0},
                ],
                "timestamp": datetime.utcnow().isoformat(),
            })
        return alerts

    # ── ARP Scan ──────────────────────────────────────────────────────────

    def arp_scan(self, subnet: str | None = None) -> list[dict]:
        """
        Discover all devices on the LAN via ARP broadcast.

        Falls back to /proc/net/arp if Scapy is unavailable or fails.
        Updates the internal device cache.
        """
        if subnet is None:
            parts = LOCAL_IP.split(".")
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

        logger.info("ARP scanning %s…", subnet)
        devices: list[dict] = []

        if SCAPY_AVAILABLE:
            try:
                arp_pkt   = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
                answered, _ = srp(arp_pkt, timeout=2, verbose=False)

                for _, received in answered:
                    ip  = received.psrc
                    mac = received.hwsrc
                    devices.append({
                        "ip":           ip,
                        "mac":          mac,
                        "hostname":     self._resolve(ip),
                        "is_suspicious": self._is_suspicious(ip),
                        "last_seen":    datetime.utcnow().isoformat(),
                    })
            except Exception as e:
                logger.warning("ARP scan failed: %s — falling back to ARP table", e)
                devices = self._read_arp_table()
        else:
            devices = self._read_arp_table()

        with _devices_lock:
            _devices_cache.clear()
            _devices_cache.extend(devices)

        # Register every discovered device in the Zero Trust registry
        for d in devices:
            try:
                from db import register_device
                is_new = register_device(
                    mac=d["mac"],
                    ip=d["ip"],
                    hostname=d.get("hostname", "unknown"),
                )
                if is_new:
                    logger.warning(
                        "Zero Trust: UNVERIFIED device joined — %s @ %s",
                        d["mac"], d["ip"],
                    )
            except Exception as e:
                logger.debug("register_device error: %s", e)

        logger.info("ARP scan found %d devices", len(devices))
        return devices

    def _read_arp_table(self) -> list[dict]:
        """Read /proc/net/arp — Linux-only fallback that doesn't need root."""
        devices = []
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]  # skip header line
            for line in lines:
                parts = line.split()
                # Columns: IP Addr | HW type | Flags | HW addr | Mask | Device
                if len(parts) >= 4 and parts[2] not in ("0x0", "0x00"):
                    ip  = parts[0]
                    mac = parts[3]
                    devices.append({
                        "ip":            ip,
                        "mac":           mac,
                        "hostname":      self._resolve(ip),
                        "is_suspicious": self._is_suspicious(ip),
                        "last_seen":     datetime.utcnow().isoformat(),
                    })
        except FileNotFoundError:
            logger.warning("/proc/net/arp not found — not on Linux?")
        except Exception as e:
            logger.warning("ARP table read error: %s", e)
        return devices

    def get_network_devices(self) -> list[dict]:
        """Return cached ARP scan results (non-blocking)."""
        with _devices_lock:
            return list(_devices_cache)

    # ── WiFi SSID Scan: Evil Twin / Beacon Flood detection ─────────────────

    def wifi_ssid_scan(self):
        """
        Scan visible WiFi networks (normal station-mode scan via nmcli, no
        monitor mode) and flag:
          - Evil Twin: a known SSID suddenly broadcast from a second,
            different BSSID.
          - Beacon Flood: an abnormal number of distinct SSIDs visible in
            one scan pass.
        """
        if not NMCLI_AVAILABLE:
            return

        try:
            out = subprocess.run(
                ["nmcli", "-t", "-f", "SSID,BSSID", "dev", "wifi", "list", "--rescan", "yes"],
                capture_output=True, text=True, timeout=15,
            ).stdout
        except Exception as e:
            logger.warning("WiFi SSID scan failed: %s", e)
            return

        now = time.time()
        seen_ssids: set = set()

        for line in out.splitlines():
            fields = _parse_nmcli_terse(line)
            if len(fields) != 2:
                continue
            ssid, bssid = fields
            if not ssid or not bssid:
                continue
            seen_ssids.add(ssid)

            with _wifi_scan_lock:
                known = _known_ssid_bssids[ssid]
                is_new_bssid = bssid not in known
                known.add(bssid)
                has_other_bssid = len(known) > 1

            if is_new_bssid and has_other_bssid:
                self._alert_evil_twin(ssid, bssid, now)

        if len(seen_ssids) >= _BEACON_FLOOD_SSID_THRESHOLD:
            self._alert_beacon_flood(len(seen_ssids), now)

    @staticmethod
    def _alert_evil_twin(ssid: str, bssid: str, now: float):
        key = (ssid, bssid)
        with _wifi_scan_lock:
            last = _last_evil_twin_alert.get(key, 0.0)
            if now - last < _ALERT_COOLDOWN_SECONDS:
                return
            _last_evil_twin_alert[key] = now
            known_count = len(_known_ssid_bssids.get(ssid, ()))

        try:
            from db import insert_alert
            insert_alert({
                "source_ip": bssid,
                "dest_ip": ssid,
                "threat_class": "Evil Twin / Rogue AP",
                "confidence": 0.9,
                "detected_by": "WiFi Scan Heuristic",
                "is_blocked": False,  # can't iptables-block a rogue AP's radio
                "xai_features": [
                    {"name": "ssid", "raw_value": ssid, "impact": 1.0},
                    {"name": "new_bssid", "raw_value": bssid, "impact": 1.0},
                    {"name": "known_bssid_count", "raw_value": known_count, "impact": 0.5},
                ],
                "timestamp": datetime.utcnow().isoformat(),
            })
            logger.warning("Evil Twin suspected: SSID '%s' now also seen from %s", ssid, bssid)
        except Exception as e:
            logger.debug("insert_alert (evil twin) error: %s", e)

    @staticmethod
    def _alert_beacon_flood(ssid_count: int, now: float):
        with _wifi_scan_lock:
            last = _last_beacon_flood_alert["t"]
            if now - last < _ALERT_COOLDOWN_SECONDS:
                return
            _last_beacon_flood_alert["t"] = now

        try:
            from db import insert_alert
            insert_alert({
                "source_ip": "airwaves",
                "dest_ip": LOCAL_IP,
                "threat_class": "Beacon Flood",
                "confidence": min(ssid_count / (_BEACON_FLOOD_SSID_THRESHOLD * 2), 1.0),
                "detected_by": "WiFi Scan Heuristic",
                "is_blocked": False,
                "xai_features": [
                    {"name": "distinct_ssids_seen", "raw_value": ssid_count, "impact": 1.0},
                    {"name": "threshold", "raw_value": _BEACON_FLOOD_SSID_THRESHOLD, "impact": 0.0},
                ],
                "timestamp": datetime.utcnow().isoformat(),
            })
            logger.warning("Beacon flood suspected: %d distinct SSIDs in one scan", ssid_count)
        except Exception as e:
            logger.debug("insert_alert (beacon flood) error: %s", e)

    def start_periodic_scan(self, interval: int = 60):
        """Launch a daemon thread that refreshes ARP + WiFi SSID scan data every `interval` seconds."""
        def _loop():
            # Run initial scans immediately
            try:
                self.arp_scan()
            except Exception as e:
                logger.error("Initial ARP scan failed: %s", e)
            try:
                self.wifi_ssid_scan()
            except Exception as e:
                logger.error("Initial WiFi SSID scan failed: %s", e)

            while True:
                time.sleep(interval)
                try:
                    self.arp_scan()
                except Exception as e:
                    logger.error("Periodic ARP scan failed: %s", e)
                try:
                    self.wifi_ssid_scan()
                except Exception as e:
                    logger.error("Periodic WiFi SSID scan failed: %s", e)

        t = threading.Thread(target=_loop, daemon=True, name="arp-scanner")
        t.start()
        logger.info("Periodic ARP + WiFi SSID scan started (interval=%ds)", interval)

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _resolve(ip: str) -> str:
        """Reverse-DNS lookup with 0.5s timeout. Returns 'unknown' on failure."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "unknown"

    @staticmethod
    def _is_suspicious(ip: str) -> bool:
        """Cross-check against blocked IPs database."""
        try:
            from db import is_ip_blocked
            return is_ip_blocked(ip)
        except Exception:
            return False
