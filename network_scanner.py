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
import platform
import shutil
import socket
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)

IS_WINDOWS = platform.system() == "Windows"

# ── Scapy availability check ──────────────────────────────────────────────
SCAPY_AVAILABLE = False
try:
    from scapy.all import ARP, Ether, IP, TCP, UDP, srp, sniff  # type: ignore
    SCAPY_AVAILABLE = True
    logger.info("Scapy available — live packet capture enabled")
except ImportError:
    logger.warning("Scapy not installed — live capture disabled (manual ingest only)")

# ── WiFi SSID scan availability check (Evil Twin / Beacon Flood) ─────────
# On Windows: uses native `netsh wlan show networks mode=bssid`
# On Linux:   uses station-mode `nmcli`
WIFI_SCAN_AVAILABLE = IS_WINDOWS or (shutil.which("nmcli") is not None)
if WIFI_SCAN_AVAILABLE:
    backend = "Windows netsh" if IS_WINDOWS else "Linux nmcli"
    logger.info("WiFi SSID scan enabled (%s) — Evil Twin/Beacon Flood active", backend)
else:
    logger.warning("Neither netsh nor nmcli found — Evil Twin/Beacon Flood detection disabled")


def _parse_nmcli_terse(line: str) -> list[str]:
    """
    Split one line of `nmcli -t` output on unescaped colons.
    """
    fields = re.split(r"(?<!\\):", line)
    return [f.replace("\\:", ":").replace("\\\\", "\\") for f in fields]


def _trigger_windows_wlan_scan():
    """Trigger an active hardware probe scan on Windows using WlanScan API."""
    try:
        import ctypes
        from ctypes import wintypes
        wlan = ctypes.windll.wlanapi
        handle = wintypes.HANDLE()
        neg_ver = wintypes.DWORD()
        if wlan.WlanOpenHandle(2, None, ctypes.byref(neg_ver), ctypes.byref(handle)) == 0:
            class WLAN_INTERFACE_INFO(ctypes.Structure):
                _fields_ = [('InterfaceGuid', ctypes.c_ubyte * 16), ('strInterfaceDescription', ctypes.c_wchar * 256), ('isState', ctypes.c_uint)]
            class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
                _fields_ = [('dwNumberOfItems', wintypes.DWORD), ('dwIndex', wintypes.DWORD), ('InterfaceInfo', WLAN_INTERFACE_INFO * 1)]
            pList = ctypes.c_void_p()
            if wlan.WlanEnumInterfaces(handle, None, ctypes.byref(pList)) == 0 and pList:
                info_list = ctypes.cast(pList, ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)).contents
                for i in range(info_list.dwNumberOfItems):
                    wlan.WlanScan(handle, ctypes.byref(info_list.InterfaceInfo[i].InterfaceGuid), None, None, None)
            wlan.WlanCloseHandle(handle, None)
    except Exception:
        pass


def _get_connected_wifi() -> tuple[str | None, str | None]:
    """Get currently connected SSID and AP BSSID on Windows."""
    try:
        res = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=5)
        ssid, bssid = None, None
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("SSID") and not line.startswith("BSSID"):
                p = line.split(":", 1)
                if len(p) == 2:
                    ssid = p[1].strip()
            elif "BSSID" in line:
                m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
                if m and not bssid:
                    bssid = m.group(1).lower()
        return ssid, bssid
    except Exception:
        return None, None


def _scan_wifi_windows() -> list[dict]:
    """Scan WiFi networks on Windows using active hardware probe + netsh."""
    _trigger_windows_wlan_scan()
    # Allow driver a brief moment to update WLAN cache with probe responses
    time.sleep(1.2)
    try:
        res = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=8
        )
        out = res.stdout
    except Exception as e:
        logger.debug("Windows WiFi netsh scan error: %s", e)
        return []

    networks = []
    cur_ssid = None
    cur_auth = ""
    cur_enc = ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("SSID"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                cur_ssid = parts[1].strip()
                cur_auth = ""
                cur_enc = ""
        elif line.startswith("Authentication"):
            p = line.split(":", 1)
            if len(p) == 2:
                cur_auth = p[1].strip()
        elif line.startswith("Encryption"):
            p = line.split(":", 1)
            if len(p) == 2:
                cur_enc = p[1].strip()
        elif line.startswith("BSSID") and cur_ssid:
            m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
            if m:
                networks.append({
                    "ssid": cur_ssid,
                    "bssid": m.group(1).lower(),
                    "auth": cur_auth,
                    "encryption": cur_enc,
                })
    return networks


def _scan_wifi_linux() -> list[tuple[str, str]]:
    """Scan WiFi networks on Linux using nmcli."""
    if not shutil.which("nmcli"):
        return []
    try:
        out = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID", "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, timeout=12,
        ).stdout
    except Exception as e:
        logger.warning("Linux WiFi nmcli scan failed: %s", e)
        return []

    networks = []
    for line in out.splitlines():
        fields = _parse_nmcli_terse(line)
        if len(fields) == 2 and fields[0] and fields[1]:
            networks.append((fields[0], fields[1].lower()))
    return networks


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
# ── Port scan & burst tracker ──────────────────────────────────────────────
# Common benign LAN infrastructure ports (DNS, DHCP, NTP, NetBIOS, SSDP, mDNS, LLMNR)
# that normal OS networking queries every few seconds — excluded from port scan counts.
_BENIGN_LAN_PORTS = {53, 67, 68, 123, 137, 138, 1900, 5351, 5353, 5355}

# Key: (src_ip, dst_ip) — Value: {"ports": set(), "syn_ports": set(), "pkts": int, "bytes": int, "start": float, "last_alert": float}
_scan_table: dict = defaultdict(lambda: {"ports": set(), "syn_ports": set(), "pkts": 0, "bytes": 0, "start": time.time(), "last_alert": 0.0})
_SCAN_SYN_PORT_THRESHOLD = 6      # 6 or more distinct destination ports probed with SYN packets
_SCAN_GENERIC_PORT_THRESHOLD = 8  # 8 or more distinct non-benign ports
_FLOOD_PACKET_THRESHOLD = 400     # 400 packets burst
_FLOOD_MIN_RATE = 40.0            # AND >= 40 packets per second (burst flood rate)

# ── Brute-force tracker ────────────────────────────────────────────────────
# Key: (src_ip, dst_ip, dst_port) — Value: {"attempts": 0, "start": float, "last_alert": float}
_bruteforce_table: dict = defaultdict(lambda: {"attempts": 0, "start": time.time(), "last_alert": 0.0})
_BRUTEFORCE_ATTEMPT_THRESHOLD = 8  # 8 connection attempts to same auth port = brute force

# ARP scan results cache
_devices_cache: list[dict] = []
_devices_lock  = threading.Lock()

# ── WiFi SSID scan state (Evil Twin / Beacon Flood) ────────────────────────
_known_ssid_bssids: dict = defaultdict(set)
_wifi_scan_lock = threading.Lock()
_last_evil_twin_alert: dict = {}
_last_beacon_flood_alert: dict = {"t": 0.0}
_BEACON_FLOOD_SSID_THRESHOLD = 15  # 15 distinct SSIDs in one scan pass = flood
_ALERT_COOLDOWN_SECONDS = 15       # alert cooldown

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

        # On Windows: also sniff the Npcap Loopback Adapter if present.
        # This allows local tools like Nmap scanning 192.168.0.202 or localhost
        # to be detected simultaneously with external network traffic on the WiFi/Ethernet adapter.
        if IS_WINDOWS:
            try:
                from scapy.all import conf
                for iface_name, iface_obj in conf.ifaces.items():
                    desc = getattr(iface_obj, "description", "").lower()
                    name = getattr(iface_obj, "name", "").lower()
                    if "loopback" in desc or "loopback" in name:
                        logger.info("Starting secondary loopback sniffer on: %s (%s)", name, iface_name)
                        threading.Thread(
                            target=self._sniff_worker,
                            args=(iface_name,),
                            daemon=True,
                            name="scapy-loopback-sniff",
                        ).start()
                        break
            except Exception as e:
                logger.debug("Loopback sniff setup error: %s", e)

        self._sniff_worker(self.interface)

    def _sniff_worker(self, iface: str | None):
        kwargs: dict = {
            "prn":    self._handle_packet,
            "store":  False,
            "filter": "ip",          # only IPv4
        }
        if iface:
            kwargs["iface"] = iface

        try:
            sniff(**kwargs)  # blocks forever
        except PermissionError:
            logger.error(
                "Packet capture requires root privileges. "
                "Run with: sudo python app.py"
            )
        except Exception as e:
            logger.error("Capture error (%s): %s", iface or "auto", e)

    def _handle_packet(self, pkt):
        """Scapy callback — accumulate per-flow CIC-IDS-2017-style stats from each IP packet."""
        try:
            if not pkt.haslayer(IP):
                return

            ip = pkt[IP]
            src, dst = ip.src, ip.dst

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

            # Ignore management traffic to Flask dashboard (port 5000)
            if sport == 5000 or dport == 5000:
                return

            # Ignore basic infrastructure services (DNS, DHCP, NTP, DoT) and LAN multicast/broadcast
            # These are datagram/infrastructure utilities, not session flows, and produce false ML triggers.
            if sport in (53, 67, 68, 123, 853) or dport in (53, 67, 68, 123, 853):
                return
            if dst.startswith("224.") or dst.startswith("239.") or dst == "255.255.255.255" or dst.endswith(".255"):
                return
            # Ignore internal localhost loopback IPC (Chrome, IDE, Windows local services)
            if src.startswith("127.") and dst.startswith("127."):
                return
            # Public DNS resolvers (Cloudflare, Google, Quad9)
            if dst in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9") or src in ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"):
                return

            pkt_len = len(pkt)
            now = time.time()

            a, b = (src, sport), (dst, dport)
            key = (src, sport, dst, dport) if a <= b else (dst, dport, src, sport)

            with _flow_lock:
                if key not in _flow_table and len(_flow_table) >= _MAX_FLOW_TABLE_ENTRIES:
                    return  # table full — this flow's stats resume next drain window
                _flow_table[key].add_packet(src, sport, dst, pkt_len, header_len, payload_len, tcp_layer, now)

                scan_entry = _scan_table[(src, dst)]
                if dport > 0:
                    scan_entry["ports"].add(dport)
                scan_entry["pkts"] += 1
                scan_entry["bytes"] += pkt_len

                if tcp_layer is not None:
                    # Fresh SYN connection attempt (e.g. brute-force / connect scan)
                    if tcp_layer.flags.S and not tcp_layer.flags.A:
                        scan_entry["syn_ports"].add(dport)
                        # Only track brute-force attempts on known authentication/management services
                        if dport in (21, 22, 23, 445, 1433, 3306, 3389, 5432):
                            _bruteforce_table[(src, dst, dport)]["attempts"] += 1
                    # Port scan flag anomalies (NULL scan, Xmas scan, SYN-FIN scan)
                    flags = tcp_layer.flags
                    if int(flags) == 0 or (flags.F and flags.P and flags.U) or (flags.S and flags.F):
                        scan_entry["syn_ports"].add(dport)
                        scan_entry["ports"].add(dport)

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
        Evaluate the burst tracker. Returns pre-formed alert dicts
        for any (src, dst) pair that crossed the flood or scan threshold.
        Maintains rolling history so probes are never lost across drain cycles.
        """
        with _flow_lock:
            snapshot = list(_scan_table.items())

        now = time.time()
        alerts = []
        to_delete = []

        for (src, dst), data in snapshot:
            n_pkts = data["pkts"]
            window_s = max(round(now - data["start"], 1), 0.1)

            # Filter out benign LAN infrastructure ports (DNS, DHCP, SSDP, mDNS, etc.)
            non_infra_ports = data["ports"] - _BENIGN_LAN_PORTS
            syn_ports = data["syn_ports"] - _BENIGN_LAN_PORTS

            # Guard router gateway from normal OS service queries
            is_gateway = (dst == "192.168.0.1" or dst.endswith(".1"))
            syn_thresh = 8 if is_gateway else _SCAN_SYN_PORT_THRESHOLD

            # Evict stale entries with no activity for 30s
            if now - data["start"] > 30 and len(syn_ports) < syn_thresh and n_pkts < _FLOOD_PACKET_THRESHOLD:
                to_delete.append((src, dst))
                continue

            # 1. Port scan detection (requires distinct destination ports probed with SYN packets)
            is_port_scan = (len(syn_ports) >= syn_thresh)
            if is_port_scan:
                if now - data.get("last_alert", 0.0) >= 3.0:
                    port_count = len(syn_ports)
                    confidence = min(0.85 + (port_count / 20.0) * 0.14, 0.99)
                    alerts.append({
                        "source_ip": src,
                        "dest_ip": dst,
                        "threat_class": "PortScan",
                        "confidence": round(confidence, 2),
                        "detected_by": "Port Scan Heuristic",
                        "is_blocked": confidence >= 0.85,
                        "xai_features": [
                            {"name": "distinct_ports_scanned", "raw_value": port_count, "impact": 1.0},
                            {"name": "syn_probes", "raw_value": port_count, "impact": 0.8},
                            {"name": "window_seconds", "raw_value": window_s, "impact": 0.0},
                        ],
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                    data["last_alert"] = now
                    data["ports"] = set()
                    data["syn_ports"] = set()
                    data["pkts"] = 0
                    data["bytes"] = 0
                    data["start"] = now

            # 2. Flood / DDoS detection
            # True flood attacks consist of rapid small packets (< 300 bytes, e.g. SYN flood, UDP flood)
            # at high packet rates, rather than normal bulk MTU data downloads (> 1000 bytes/pkt).
            avg_pkt_sz = data["bytes"] / max(n_pkts, 1)
            is_flood = (
                n_pkts >= 800 and
                (n_pkts / window_s) >= 80.0 and
                avg_pkt_sz < 300 and
                src != LOCAL_IP
            )
            if is_flood:
                if now - data.get("last_alert", 0.0) >= 3.0:
                    confidence = min(0.80 + (n_pkts / 2000.0) * 0.19, 0.99)
                    alerts.append({
                        "source_ip": src,
                        "dest_ip": dst,
                        "threat_class": "DDoS / Flood",
                        "confidence": round(confidence, 2),
                        "detected_by": "Flood Heuristic",
                        "is_blocked": confidence >= 0.85,
                        "xai_features": [
                            {"name": "packets_in_window", "raw_value": n_pkts, "impact": 1.0},
                            {"name": "packets_per_second", "raw_value": round(n_pkts / window_s, 1), "impact": 0.8},
                            {"name": "avg_packet_bytes", "raw_value": round(avg_pkt_sz, 1), "impact": 0.5},
                        ],
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                    data["last_alert"] = now
                    data["pkts"] = 0
                    data["bytes"] = 0
                    data["start"] = now

        with _flow_lock:
            for k in to_delete:
                _scan_table.pop(k, None)

        return alerts

    def drain_bruteforce_alerts(self) -> list[dict]:
        """
        Evaluate the brute-force tracker for repeated connection attempts to the same port.
        """
        with _flow_lock:
            snapshot = list(_bruteforce_table.items())

        now = time.time()
        alerts = []
        to_delete = []

        for (src, dst, port), data in snapshot:
            attempts = data["attempts"]
            if now - data["start"] > 30 and attempts < _BRUTEFORCE_ATTEMPT_THRESHOLD:
                to_delete.append((src, dst, port))
                continue

            if attempts >= _BRUTEFORCE_ATTEMPT_THRESHOLD:
                if now - data.get("last_alert", 0.0) >= 3.0:
                    confidence = min(0.75 + (attempts / 20.0) * 0.25, 0.99)
                    alerts.append({
                        "source_ip": src,
                        "dest_ip": dst,
                        "threat_class": "Brute Force Attempt",
                        "confidence": round(confidence, 2),
                        "detected_by": "Brute Force Heuristic",
                        "is_blocked": confidence >= 0.85,
                        "xai_features": [
                            {"name": "connection_attempts", "raw_value": attempts, "impact": 1.0},
                            {"name": "target_port", "raw_value": port, "impact": 0.8},
                            {"name": "window_seconds", "raw_value": round(now - data["start"], 1), "impact": 0.0},
                        ],
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                    data["last_alert"] = now
                    data["attempts"] = 0
                    data["start"] = now

        with _flow_lock:
            for k in to_delete:
                _bruteforce_table.pop(k, None)

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
            import platform
            if platform.system() == "Windows":
                try:
                    res = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
                    for line in res.stdout.splitlines():
                        match = re.search(r"^\s*([\d\.]+)\s+([0-9a-fA-F\-]{17})\s+(\w+)", line)
                        if match:
                            ip = match.group(1)
                            mac = match.group(2).replace("-", ":").lower()
                            # skip broadcast and multicast
                            if not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                                devices.append({
                                    "ip":            ip,
                                    "mac":           mac,
                                    "hostname":      self._resolve(ip),
                                    "is_suspicious": self._is_suspicious(ip),
                                    "last_seen":     datetime.utcnow().isoformat(),
                                })
                except Exception as e:
                    logger.warning("Windows arp -a fallback error: %s", e)
            else:
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
        Scan visible WiFi networks (Windows netsh or Linux nmcli) and flag:
          - Evil Twin / Rogue AP: a known SSID suddenly broadcast from a second,
            different BSSID.
          - Beacon Flood: an abnormal number of distinct SSIDs visible in
            one scan pass.
        """
        if not WIFI_SCAN_AVAILABLE:
            return

        networks = _scan_wifi_windows() if IS_WINDOWS else _scan_wifi_linux()
        if not networks:
            return

        now = time.time()
        seen_ssids: set = set()
        connected_ssid, connected_bssid = _get_connected_wifi() if IS_WINDOWS else (None, None)

        for net in networks:
            if isinstance(net, dict):
                ssid = net.get("ssid")
                bssid = net.get("bssid")
                auth = net.get("auth", "")
                enc = net.get("encryption", "")
            else:
                ssid, bssid = net
                auth, enc = "", ""

            if not ssid or not bssid:
                continue
            seen_ssids.add(ssid)

            # 1. Evil Twin impersonating the currently connected Wi-Fi network
            if connected_ssid and connected_bssid:
                is_exact = (ssid.lower() == connected_ssid.lower())
                s_clean = re.sub(r"[^a-zA-Z0-9]", "", ssid.lower())
                c_clean = re.sub(r"[^a-zA-Z0-9]", "", connected_ssid.lower())
                is_clone = False
                if not is_exact and len(s_clean) >= 4 and len(c_clean) >= 4:
                    if s_clean in c_clean or c_clean in s_clean:
                        is_clone = True

                if (is_exact and bssid.lower() != connected_bssid.lower()) or is_clone:
                    self._alert_evil_twin(
                        ssid=ssid,
                        bssid=bssid,
                        reason=f"Impersonating legitimate network '{connected_ssid}' (Legitimate BSSID: {connected_bssid})",
                        confidence=0.98,
                        now=now,
                    )
                    continue

            # 2. Multi-BSSID Evil Twin (same SSID broadcast from multiple MAC addresses)
            with _wifi_scan_lock:
                known = _known_ssid_bssids[ssid]
                known.add(bssid)
                has_other_bssid = len(known) > 1

            if has_other_bssid:
                self._alert_evil_twin(
                    ssid=ssid,
                    bssid=bssid,
                    reason=f"SSID '{ssid}' broadcast from multiple BSSIDs ({len(known)} distinct MACs)",
                    confidence=0.95,
                    now=now,
                )
                continue

            # 3. Rogue Open AP / Honeypot detection (e.g. Free Wifi, unencrypted rogue hotspot)
            is_open = (auth.lower() in ("open", "none") or enc.lower() in ("none", "open"))
            is_suspicious_name = any(w in ssid.lower() for w in ("free", "rogue", "evil", "fake", "honeypot", "public", "hack", "pine", "flipper"))
            if is_open or is_suspicious_name:
                self._alert_rogue_ap(
                    ssid=ssid,
                    bssid=bssid,
                    auth=auth,
                    enc=enc,
                    now=now,
                )

        if len(seen_ssids) >= _BEACON_FLOOD_SSID_THRESHOLD:
            self._alert_beacon_flood(len(seen_ssids), now)

    @staticmethod
    def _alert_evil_twin(ssid: str, bssid: str, reason: str, confidence: float, now: float):
        key = (ssid, bssid)
        with _wifi_scan_lock:
            last = _last_evil_twin_alert.get(key, 0.0)
            if now - last < _ALERT_COOLDOWN_SECONDS:
                return
            _last_evil_twin_alert[key] = now

        try:
            from db import insert_alert
            insert_alert({
                "source_ip": bssid,
                "dest_ip": ssid,
                "threat_class": "Evil Twin / Rogue AP",
                "confidence": confidence,
                "detected_by": "WiFi Scan Heuristic",
                "is_blocked": False,  # can't iptables-block a rogue AP's radio
                "xai_features": [
                    {"name": "ssid", "raw_value": ssid, "impact": 1.0},
                    {"name": "rogue_bssid", "raw_value": bssid, "impact": 1.0},
                    {"name": "detection_reason", "raw_value": reason, "impact": 0.8},
                ],
                "timestamp": datetime.utcnow().isoformat(),
            })
            logger.warning("Evil Twin detected! SSID '%s' (BSSID %s): %s", ssid, bssid, reason)
        except Exception as e:
            logger.debug("insert_alert (evil twin) error: %s", e)

    @staticmethod
    def _alert_rogue_ap(ssid: str, bssid: str, auth: str, enc: str, now: float):
        key = (ssid, bssid, "rogue_ap")
        with _wifi_scan_lock:
            last = _last_evil_twin_alert.get(key, 0.0)
            if now - last < _ALERT_COOLDOWN_SECONDS:
                return
            _last_evil_twin_alert[key] = now

        try:
            from db import insert_alert
            insert_alert({
                "source_ip": bssid,
                "dest_ip": ssid,
                "threat_class": "Evil Twin / Rogue AP",
                "confidence": 0.95,
                "detected_by": "WiFi Scan Heuristic",
                "is_blocked": False,
                "xai_features": [
                    {"name": "ssid", "raw_value": ssid, "impact": 1.0},
                    {"name": "rogue_bssid", "raw_value": bssid, "impact": 1.0},
                    {"name": "security", "raw_value": f"{auth or 'Open'}/{enc or 'None'}", "impact": 0.9},
                ],
                "timestamp": datetime.utcnow().isoformat(),
            })
            logger.warning("Rogue AP detected! SSID '%s' (BSSID %s) security: %s/%s", ssid, bssid, auth, enc)
        except Exception as e:
            logger.debug("insert_alert (rogue ap) error: %s", e)

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

    def start_periodic_scan(self, interval: int = 30):
        """Launch daemon threads that refresh ARP and WiFi SSID scan data."""
        def _arp_loop():
            while True:
                try:
                    self.arp_scan()
                except Exception as e:
                    logger.error("Periodic ARP scan failed: %s", e)
                time.sleep(interval)

        def _wifi_loop():
            while True:
                try:
                    self.wifi_ssid_scan()
                except Exception as e:
                    logger.debug("Periodic WiFi scan failed: %s", e)
                time.sleep(6)  # Rapid 6s polling for Rogue AP / Evil Twin detection

        t_arp = threading.Thread(target=_arp_loop, daemon=True, name="arp-scanner")
        t_arp.start()
        t_wifi = threading.Thread(target=_wifi_loop, daemon=True, name="wifi-scanner")
        t_wifi.start()
        logger.info("Periodic ARP scan (interval=%ds) & Rogue AP scan (interval=6s) started", interval)

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
