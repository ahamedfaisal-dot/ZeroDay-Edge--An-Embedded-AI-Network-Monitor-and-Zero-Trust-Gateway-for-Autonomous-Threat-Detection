"""
campaign.py — Attack-campaign correlation + predictive kill-chain AI.

Individual alerts say "something bad happened". Real attacks are sequences:
recon -> credential attack -> exploitation -> impact. This module links the
alerts from one source into a CAMPAIGN, places it on a kill chain, and:

  1. Predicts the attacker's NEXT stage with a first-order Markov model.
     The transition matrix starts from kill-chain prior knowledge and keeps
     LEARNING online from every attack sequence this node observes, so the
     prediction adapts to the threats actually seen on this network.
  2. Scores each campaign 0-100 (how far along the kill chain, how persistent,
     how confident the detectors were, how recent) — risk fades as an
     attacker goes quiet.
  3. Fuses active campaigns into one network-wide AI Threat Level
     (noisy-OR: independent attackers compound), shown on the dashboard.

Pure Python, no extra dependencies; O(1) work per alert.
"""

import json
import logging
import math
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

STAGES = ["Recon", "Credential Access", "Exploitation", "Impact"]
N = len(STAGES)

_CAMPAIGN_GAP_S = 900        # silence longer than this ends a campaign
_ACTIVE_S = 1800             # campaigns older than this stop counting toward the threat level
_HALF_LIFE_S = 600           # risk decays with this e-folding time
PREEMPT_RISK = float(os.environ.get("EDGE_PREEMPT_RISK", "80"))

STATE_FILE = Path(__file__).parent / "campaign_model.json"

# Kill-chain prior as pseudo-counts: rows = current stage, cols = next stage.
# Attackers mostly persist or advance; regressing is rare.
_PRIOR = [
    # Recon  Cred  Exploit Impact
    [2.0,   3.0,  2.0,    1.0],   # from Recon
    [0.5,   2.0,  3.0,    1.0],   # from Credential Access
    [0.3,   0.5,  2.0,    3.0],   # from Exploitation
    [0.5,   0.3,  1.0,    3.0],   # from Impact
]


def stage_of(threat_class: str) -> int:
    t = (threat_class or "").lower().replace(" ", "")
    if "honeypot" in t:                       # credential capture = credential attack, bare probe = recon
        return 1 if "credential" in t else 0
    if "ddos" in t or "flood" in t:          # incl. Beacon Flood, "PortScan / DDoS"
        return 3
    if "portscan" in t or "recon" in t:
        return 0
    if "brute" in t or "evil" in t or "rogue" in t:
        return 1
    return 2                                  # malicious / behavioural / unknown payload activity


def _ts(iso: str) -> float:
    try:
        return datetime.fromisoformat(iso).replace(tzinfo=timezone.utc).timestamp()
    except Exception:
        return time.time()


class _Campaign:
    __slots__ = ("ip", "events", "last_ts", "first_ts", "last_stage", "last_class", "preempted")

    def __init__(self, ip: str, ts: float):
        self.ip = ip
        self.events = deque(maxlen=60)      # (ts, stage, confidence)
        self.first_ts = ts
        self.last_ts = ts
        self.last_stage = None
        self.last_class = ""
        self.preempted = False


class CampaignEngine:
    def __init__(self):
        self._lock = threading.Lock()
        self._campaigns: dict[str, _Campaign] = {}
        self._counts = [row[:] for row in _PRIOR]
        self._load()

    # ── ingestion ────────────────────────────────────────────────────────

    def record(self, ip: str, threat_class: str, confidence: float, timestamp_iso: str | None = None) -> dict:
        ts = _ts(timestamp_iso) if timestamp_iso else time.time()
        stage = stage_of(threat_class)
        with self._lock:
            c = self._campaigns.get(ip)
            if c is None or ts - c.last_ts > _CAMPAIGN_GAP_S:
                c = self._campaigns[ip] = _Campaign(ip, ts)
            if c.last_stage is not None:
                self._counts[c.last_stage][stage] += 1.0   # online learning of attacker behaviour
            c.events.append((ts, stage, float(confidence or 0)))
            c.last_ts = max(c.last_ts, ts)
            c.last_stage = stage
            c.last_class = threat_class
            if len(self._campaigns) > 500:
                for k in sorted(self._campaigns, key=lambda k: self._campaigns[k].last_ts)[:100]:
                    del self._campaigns[k]
            return self._summarise(c, time.time())

    # ── queries ──────────────────────────────────────────────────────────

    def snapshot(self, limit: int = 5) -> dict:
        now = time.time()
        with self._lock:
            active = [c for c in self._campaigns.values() if now - c.last_ts < _ACTIVE_S]
            summaries = sorted((self._summarise(c, now) for c in active), key=lambda s: -s["risk"])
        survive = 1.0
        for s in summaries:
            if s["age_s"] < _CAMPAIGN_GAP_S:
                survive *= 1.0 - s["risk"] / 100.0
        level = round(100 * (1 - survive))
        return {
            "threat_level": level,
            "label": "SEVERE" if level >= 70 else "HIGH" if level >= 45 else "ELEVATED" if level >= 20 else "CALM",
            "active_campaigns": sum(1 for s in summaries if s["risk"] >= 5),
            "campaigns": summaries[:limit],
        }

    def for_ip(self, ip: str) -> dict | None:
        with self._lock:
            c = self._campaigns.get(ip)
            return self._summarise(c, time.time()) if c else None

    def mark_preempted(self, ip: str):
        with self._lock:
            if ip in self._campaigns:
                self._campaigns[ip].preempted = True

    # ── model ────────────────────────────────────────────────────────────

    def _distribution(self, stage: int) -> list[float]:
        row = self._counts[stage]
        total = sum(row)
        return [v / total for v in row]

    def _summarise(self, c: _Campaign, now: float) -> dict:
        evs = list(c.events)
        # Each stage once, in kill-chain order, with how many alerts hit it
        # ("Recon x12 > Credential Access x11"), instead of a flip-flopping
        # sequence that grows with every alert.
        stage_counts = {}
        for _, st, _ in evs:
            stage_counts[st] = stage_counts.get(st, 0) + 1
        stages_seen = sorted(stage_counts)
        max_stage = max(st for _, st, _ in evs)
        mean_conf = sum(cf for *_, cf in evs) / len(evs)
        distinct = len(set(st for _, st, _ in evs))

        raw = (20.0 * max_stage                       # how deep in the kill chain
               + 5.0 * math.log2(1 + len(evs))        # persistence
               + 20.0 * mean_conf                     # detector certainty
               + 5.0 * (distinct - 1) + 5.0)          # breadth of techniques
        age = max(now - c.last_ts, 0.0)
        risk = max(0.0, min(100.0, raw * math.exp(-age / _HALF_LIFE_S)))

        dist = self._distribution(c.last_stage)
        top = max(range(N), key=lambda i: dist[i])
        return {
            "ip": c.ip,
            "risk": round(risk),
            "stage": c.last_stage,
            "stage_name": STAGES[c.last_stage],
            "kill_chain": [STAGES[st] + (f" ×{stage_counts[st]}" if stage_counts[st] > 1 else "") for st in stages_seen],
            "events": len(evs),
            "last_class": c.last_class,
            "age_s": round(age),
            "duration_s": round(c.last_ts - c.first_ts),
            "predicted_next": {"stage": STAGES[top], "probability": round(dist[top], 2)},
            "distribution": [{"stage": STAGES[i], "probability": round(dist[i], 2)} for i in range(N)],
            "preempt_recommended": risk >= PREEMPT_RISK and distinct >= 2 and not c.preempted,
        }

    # ── persistence of the learned transition matrix ─────────────────────

    def save(self):
        try:
            with self._lock:
                STATE_FILE.write_text(json.dumps(self._counts))
        except Exception as e:
            logger.debug("campaign model save failed: %s", e)

    def _load(self):
        try:
            if STATE_FILE.exists():
                m = json.loads(STATE_FILE.read_text())
                if len(m) == N and all(len(r) == N for r in m):
                    self._counts = m
                    logger.info("Campaign model: restored learned kill-chain transitions")
        except Exception as e:
            logger.warning("Could not restore campaign model: %s", e)
