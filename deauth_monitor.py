"""
deauth_monitor.py — 802.11 deauthentication/disassociation flood detector.

Runs independently of app.py / ml_engine.py. Deauth attacks are Layer 2
802.11 management frames — invisible to any capture that only sees IP
traffic (which is all app.py's Scapy sniff ever looks at), and unrelated
to the CIC-IDS-2017 flow features the tree/deep models were trained on.
Detection here is a plain rate check, not an ML classification.

Requires the interface to already be in monitor mode (nexmon on the Pi 4's
onboard BCM43455c0, or a monitor-mode-capable USB adapter) before this
script starts — it does not manage interface mode itself.

Writes alerts into the same threat_alerts table app.py's dashboard reads
from (source_ip/dest_ip columns hold MAC addresses here, not IPs — same
TEXT columns, no schema change needed). SQLite's WAL mode (see db.py)
allows this separate process to write alerts safely alongside app.py.

Usage:
    python deauth_monitor.py --iface wlan0
    sudo .venv/bin/python deauth_monitor.py --iface wlan0 --threshold 8 --window 5
"""

import argparse
import logging
import time
from collections import defaultdict, deque

from scapy.all import sniff
from scapy.layers.dot11 import Dot11

import db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("deauth-monitor")

_MGMT_TYPE = 0
_SUBTYPE_DISASSOC = 10
_SUBTYPE_DEAUTH = 12


class DeauthMonitor:
    """Tracks deauth/disassoc frame rate per transmitter MAC; alerts on flood."""

    def __init__(self, window_s: float, threshold: int, cooldown_s: float):
        self.window_s = window_s
        self.threshold = threshold
        self.cooldown_s = cooldown_s
        self._frame_times: dict = defaultdict(deque)
        self._last_alert: dict = {}

    def handle_frame(self, pkt):
        if not pkt.haslayer(Dot11):
            return
        dot11 = pkt[Dot11]
        if dot11.type != _MGMT_TYPE or dot11.subtype not in (_SUBTYPE_DISASSOC, _SUBTYPE_DEAUTH):
            return

        src = dot11.addr2 or "unknown"
        dst = dot11.addr1 or "ff:ff:ff:ff:ff:ff"
        bssid = dot11.addr3 or src
        now = time.time()

        times = self._frame_times[src]
        times.append(now)
        while times and now - times[0] > self.window_s:
            times.popleft()

        if len(times) < self.threshold:
            return

        last = self._last_alert.get(src, 0.0)
        if now - last < self.cooldown_s:
            return  # already alerted for this source recently — avoid spamming the DB
        self._last_alert[src] = now

        kind = "Disassociation" if dot11.subtype == _SUBTYPE_DISASSOC else "Deauthentication"
        confidence = min(len(times) / (self.threshold * 4), 1.0)

        result = {
            "source_ip": src,
            "dest_ip": dst,
            "threat_class": f"WiFi {kind} Flood",
            "confidence": confidence,
            "detected_by": "802.11 Deauth Monitor",
            "is_blocked": False,  # spoofed L2 frames aren't iptables-blockable
            "xai_features": [
                {"name": "frames_in_window", "raw_value": len(times), "impact": 1.0},
                {"name": "window_seconds", "raw_value": self.window_s, "impact": 0.0},
                {"name": "bssid", "raw_value": bssid, "impact": 0.0},
            ],
        }
        db.insert_alert(result)
        logger.warning(
            "%s FLOOD — %d frames/%.0fs from %s (bssid=%s) targeting %s",
            kind, len(times), self.window_s, src, bssid, dst,
        )


def main():
    parser = argparse.ArgumentParser(description="802.11 deauth/disassoc flood detector")
    parser.add_argument("--iface", required=True, help="Monitor-mode interface, e.g. wlan0")
    parser.add_argument("--window", type=float, default=5.0, help="Sliding window in seconds")
    parser.add_argument("--threshold", type=int, default=5, help="Frames in window to trigger an alert")
    parser.add_argument("--cooldown", type=float, default=30.0, help="Seconds before re-alerting the same source")
    args = parser.parse_args()

    db.init_db()
    monitor = DeauthMonitor(window_s=args.window, threshold=args.threshold, cooldown_s=args.cooldown)

    logger.info(
        "Starting deauth monitor on %s (window=%.1fs, threshold=%d frames, cooldown=%.0fs)",
        args.iface, args.window, args.threshold, args.cooldown,
    )
    sniff(iface=args.iface, prn=monitor.handle_frame, store=False)


if __name__ == "__main__":
    main()
