"""
behavior.py — Adaptive per-device behaviour baseline (unsupervised, online).

The supervised models only know attack patterns from CIC-IDS-2017, and the
heuristics only know fixed thresholds. This module learns what is NORMAL for
each individual device on THIS network and flags sudden deviations — so a
device that suddenly talks to 40 hosts, or pushes 50x its usual bytes, is
caught even when the traffic matches no known attack signature (zero-day,
compromised IoT device, data exfiltration, lateral movement).

How it works
  - Every flow-drain window, flows are grouped per source IP into a small
    feature vector: flows, packets, bytes, distinct dest IPs, distinct dest
    ports, SYN count.
  - Each feature keeps a running mean/variance (Welford) per device.
  - Learning phase: the first LEARN_WINDOWS windows only train the baseline.
  - After that, a window is scored with a robust z-score per feature
    (std floored so tiny/quiet baselines don't make noise "anomalous").
    A device is flagged when its worst z-score stays >= Z_THRESHOLD for
    CONSECUTIVE windows (one blip is not an anomaly).
  - Anomalous windows are NOT folded into the baseline (no poisoning), and
    normal windows keep adapting it (slow drift is learned).

Pure Python, O(1) memory per device — fine on a Pi 4.
"""

import json
import logging
import math
import os
import threading
import time
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

FEATURES = ("flows", "packets", "bytes", "dest_ips", "dest_ports", "syns")

LEARN_WINDOWS = int(os.environ.get("EDGE_BASELINE_LEARN", "30"))   # ~1 min at a 2 s drain
Z_THRESHOLD = float(os.environ.get("EDGE_BASELINE_Z", "6.0"))
CONSECUTIVE = int(os.environ.get("EDGE_BASELINE_CONSEC", "2"))
ALERT_COOLDOWN_S = 30
# Absolute floors on the std so a device that is usually silent doesn't alert on
# trivial activity: a feature must also move by at least this much.
_MIN_STD = {"flows": 3.0, "packets": 20.0, "bytes": 5000.0, "dest_ips": 2.0, "dest_ports": 3.0, "syns": 3.0}
_MIN_DELTA = {"flows": 15, "packets": 150, "bytes": 50_000, "dest_ips": 8, "dest_ports": 10, "syns": 15}

_NICE = {
    "flows": "new connections", "packets": "packet volume", "bytes": "data volume",
    "dest_ips": "distinct hosts contacted", "dest_ports": "distinct ports contacted",
    "syns": "connection attempts (SYN)",
}

STATE_FILE = Path(__file__).parent / "behavior_baseline.json"


class _Stat:
    __slots__ = ("n", "mean", "m2")

    def __init__(self):
        self.n, self.mean, self.m2 = 0, 0.0, 0.0

    def add(self, x: float):
        self.n += 1
        d = x - self.mean
        self.mean += d / self.n
        self.m2 += d * (x - self.mean)

    @property
    def std(self) -> float:
        return math.sqrt(self.m2 / self.n) if self.n > 1 else 0.0


class _Device:
    __slots__ = ("stats", "windows", "strikes", "last_alert")

    def __init__(self):
        self.stats = {f: _Stat() for f in FEATURES}
        self.windows = 0
        self.strikes = 0
        self.last_alert = 0.0


class BehaviorModel:
    def __init__(self):
        self._devices: dict[str, _Device] = {}
        self._lock = threading.Lock()
        self._load()

    # ── public ───────────────────────────────────────────────────────────

    def observe(self, flows: list[dict]) -> list[dict]:
        """Feed one drain window of flows; returns alert dicts for anomalous devices."""
        per_dev = self._aggregate(flows)
        alerts = []
        now = time.time()
        with self._lock:
            for ip, vec in per_dev.items():
                dev = self._devices.setdefault(ip, _Device())
                alert = self._score(ip, dev, vec, now)
                if alert:
                    alerts.append(alert)
            if len(self._devices) > 2000:  # bound memory: drop the least-trained devices
                for ip in sorted(self._devices, key=lambda i: self._devices[i].windows)[:500]:
                    del self._devices[ip]
        return alerts

    def status(self) -> dict:
        with self._lock:
            learned = sum(1 for d in self._devices.values() if d.windows >= LEARN_WINDOWS)
            return {
                "devices_tracked": len(self._devices),
                "devices_baselined": learned,
                "learn_windows": LEARN_WINDOWS,
                "z_threshold": Z_THRESHOLD,
            }

    def save(self):
        try:
            with self._lock:
                data = {
                    ip: {"windows": d.windows,
                         "stats": {f: [s.n, s.mean, s.m2] for f, s in d.stats.items()}}
                    for ip, d in self._devices.items() if d.windows >= LEARN_WINDOWS
                }
            STATE_FILE.write_text(json.dumps(data))
        except Exception as e:
            logger.debug("baseline save failed: %s", e)

    # ── internals ────────────────────────────────────────────────────────

    @staticmethod
    def _aggregate(flows: list[dict]) -> dict:
        acc: dict[str, dict] = {}
        for f in flows:
            ip = f.get("source_ip")
            if not ip:
                continue
            a = acc.setdefault(ip, {"flows": 0, "packets": 0, "bytes": 0, "ips": set(), "ports": set(), "syns": 0})
            a["flows"] += 1
            a["packets"] += int(f.get("Tot Fwd Pkts", 0)) + int(f.get("Tot Bwd Pkts", 0))
            a["bytes"] += int(f.get("TotLen Fwd Pkts", 0)) + int(f.get("TotLen Bwd Pkts", 0))
            a["ips"].add(f.get("destination_ip"))
            a["ports"].add(f.get("destination_port", 0))
            a["syns"] += int(f.get("SYN Flag Cnt", 0))
        return {
            ip: {"flows": a["flows"], "packets": a["packets"], "bytes": a["bytes"],
                 "dest_ips": len(a["ips"]), "dest_ports": len(a["ports"]), "syns": a["syns"]}
            for ip, a in acc.items()
        }

    def _score(self, ip: str, dev: _Device, vec: dict, now: float):
        # Learning phase: just train
        if dev.windows < LEARN_WINDOWS:
            for f in FEATURES:
                dev.stats[f].add(vec[f])
            dev.windows += 1
            return None

        zs = {}
        for f in FEATURES:
            st = dev.stats[f]
            std = max(st.std, _MIN_STD[f], 0.25 * st.mean)
            delta = vec[f] - st.mean
            if delta >= _MIN_DELTA[f]:          # only upward deviations matter, and only meaningful ones
                zs[f] = delta / std
        worst = max(zs.values(), default=0.0)

        if worst >= Z_THRESHOLD:
            dev.strikes += 1          # anomalous window: do NOT learn from it
        else:
            dev.strikes = 0
            for f in FEATURES:        # normal window: keep adapting
                dev.stats[f].add(vec[f])
            dev.windows += 1
            return None

        if dev.strikes < CONSECUTIVE or now - dev.last_alert < ALERT_COOLDOWN_S:
            return None
        dev.last_alert = now

        top = sorted(zs.items(), key=lambda kv: -kv[1])[:5]
        zmax = top[0][1]
        confidence = round(min(0.60 + 0.40 * min((zmax - Z_THRESHOLD) / (3 * Z_THRESHOLD), 1.0), 1.0), 4)
        return {
            "source_ip": ip,
            "dest_ip": "multiple",
            "threat_class": "Behavioral Anomaly",
            "confidence": confidence,
            "detected_by": "Adaptive Baseline AI",
            "is_blocked": False,   # advisory: statistical, so never auto-blocks on its own
            "xai_features": [
                {
                    "name": f"{_NICE[f]} (normal ≈ {dev.stats[f].mean:.0f})",
                    "raw_value": vec[f],
                    "impact": round(z / zmax, 3),
                }
                for f, z in top
            ],
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _load(self):
        try:
            if STATE_FILE.exists():
                data = json.loads(STATE_FILE.read_text())
                for ip, d in data.items():
                    dev = _Device()
                    dev.windows = d["windows"]
                    for f, (n, mean, m2) in d["stats"].items():
                        if f in dev.stats:
                            s = dev.stats[f]
                            s.n, s.mean, s.m2 = n, mean, m2
                    self._devices[ip] = dev
                logger.info("Behaviour baseline: restored %d device profile(s)", len(self._devices))
        except Exception as e:
            logger.warning("Could not restore baseline: %s", e)
