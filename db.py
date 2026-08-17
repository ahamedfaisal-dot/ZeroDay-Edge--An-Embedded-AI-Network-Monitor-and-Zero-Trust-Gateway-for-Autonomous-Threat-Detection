"""
db.py — SQLite database layer for the ZeroDay-Edge RPi5 Node.

No ORM, no Django — raw sqlite3 for minimum overhead.
Tables:
  threat_alerts  — ML-classified threat detections
  blocked_ips    — Currently blocked IP addresses
  network_flows  — Ingested / captured network flows
"""

import sqlite3
import json
import socket
import time
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "rpi_shield.db"

# Captured at module load — marks when the Flask process started
_PROCESS_START = time.time()


# ── Connection ────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # better concurrent reads/writes
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


# ── Schema Init ───────────────────────────────────────────────────────────

def init_db():
    """Create tables if they don't exist. Safe to call multiple times."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS threat_alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip    TEXT    NOT NULL,
            dest_ip      TEXT    NOT NULL,
            threat_class TEXT    NOT NULL DEFAULT 'Benign',
            confidence   REAL    NOT NULL DEFAULT 0.0,
            detected_by  TEXT             DEFAULT 'None',
            xai_data     TEXT,
            is_blocked   INTEGER          DEFAULT 0,
            timestamp    TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ip           TEXT    UNIQUE NOT NULL,
            reason       TEXT             DEFAULT 'auto',
            auto_blocked INTEGER          DEFAULT 1,
            blocked_at   TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS network_flows (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip     TEXT,
            dest_ip       TEXT,
            flow_duration REAL    DEFAULT 0,
            fwd_pkts      INTEGER DEFAULT 0,
            bwd_pkts      INTEGER DEFAULT 0,
            bytes_per_sec REAL    DEFAULT 0,
            created_at    TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_alerts_ts    ON threat_alerts(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_class ON threat_alerts(threat_class);
        CREATE INDEX IF NOT EXISTS idx_alerts_src   ON threat_alerts(source_ip);

        CREATE TABLE IF NOT EXISTS iot_devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mac         TEXT    UNIQUE NOT NULL,
            ip          TEXT,
            hostname    TEXT    DEFAULT 'unknown',
            status      TEXT    DEFAULT 'unverified',
            alert_count INTEGER DEFAULT 0,
            trust_score REAL    DEFAULT 100.0,
            first_seen  TEXT    NOT NULL,
            last_seen   TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_iot_ip  ON iot_devices(ip);
        CREATE INDEX IF NOT EXISTS idx_iot_mac ON iot_devices(mac);
    """)
    conn.commit()
    conn.close()
    logger.info("Database initialised at %s", DB_PATH)


# ── threat_alerts ─────────────────────────────────────────────────────────

def insert_alert(result: dict) -> int | None:
    """Insert a classification result into threat_alerts. Returns row id."""
    if not result:
        return None
    conn = _get_conn()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO threat_alerts
            (source_ip, dest_ip, threat_class, confidence, detected_by,
             xai_data, is_blocked, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        result.get("source_ip", "0.0.0.0"),
        result.get("dest_ip", result.get("destination_ip", "0.0.0.0")),
        result.get("threat_class", "Benign"),
        float(result.get("confidence", 0.0)),
        result.get("detected_by", "None"),
        json.dumps(result.get("xai_features", [])),
        1 if result.get("is_blocked") else 0,
        result.get("timestamp", datetime.utcnow().isoformat()),
    ))
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id


def get_recent_alerts(limit: int = 20, threats_only: bool = False) -> list[dict]:
    conn = _get_conn()
    c = conn.cursor()
    if threats_only:
        c.execute("""
            SELECT * FROM threat_alerts
            WHERE LOWER(threat_class) NOT IN ('benign', 'normal')
            ORDER BY timestamp DESC LIMIT ?
        """, (limit,))
    else:
        c.execute(
            "SELECT * FROM threat_alerts ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
    rows = [dict(r) for r in c.fetchall()]
    conn.close()

    # Hydrate xai_data JSON into a proper list
    for r in rows:
        raw = r.pop("xai_data", None)
        try:
            r["xai_features"] = json.loads(raw) if raw else []
        except Exception:
            r["xai_features"] = []

    return rows


def get_alert_by_id(alert_id: int) -> dict | None:
    conn = _get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM threat_alerts WHERE id = ?", (alert_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    r = dict(row)
    raw = r.pop("xai_data", None)
    try:
        r["xai_features"] = json.loads(raw) if raw else []
    except Exception:
        r["xai_features"] = []
    return r


# ── blocked_ips ───────────────────────────────────────────────────────────

def add_blocked_ip(ip: str, reason: str = "auto", auto: bool = True):
    conn = _get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO blocked_ips (ip, reason, auto_blocked, blocked_at)
        VALUES (?, ?, ?, ?)
    """, (ip, reason, 1 if auto else 0, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


def remove_blocked_ip(ip: str):
    conn = _get_conn()
    conn.execute("DELETE FROM blocked_ips WHERE ip = ?", (ip,))
    conn.commit()
    conn.close()


def get_blocked_ips() -> list[dict]:
    conn = _get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def is_ip_blocked(ip: str) -> bool:
    conn = _get_conn()
    c = conn.cursor()
    c.execute("SELECT 1 FROM blocked_ips WHERE ip = ?", (ip,))
    result = c.fetchone() is not None
    conn.close()
    return result


def clear_all() -> list[str]:
    """
    Wipe all tables — used by the dashboard's "Clear Data" button to reset
    to a clean state (e.g. before a demo run-through).

    Returns the IPs that were blocked, so the caller can also remove the
    matching iptables rules (this function only touches the DB).
    """
    conn = _get_conn()
    c = conn.cursor()
    c.execute("SELECT ip FROM blocked_ips")
    blocked_ips = [r["ip"] for r in c.fetchall()]

    conn.executescript("""
        DELETE FROM threat_alerts;
        DELETE FROM blocked_ips;
        DELETE FROM network_flows;
        DELETE FROM iot_devices;
    """)
    conn.commit()
    conn.close()
    logger.info("Database cleared (all tables wiped)")
    return blocked_ips


# ── network_flows ─────────────────────────────────────────────────────────

def prune_old_data(max_flows: int = 5000, max_alerts: int = 2000):
    """
    Delete the oldest rows beyond the retention cap.

    network_flows/threat_alerts grow unbounded otherwise — fine with 8GB RAM
    to cache pages and headroom for the SD card, tight on a 4GB Pi 4 where
    the DB competes with ML models and Chromium for the page cache. Call
    periodically from a background thread, not on every insert.
    """
    conn = _get_conn()
    conn.execute("""
        DELETE FROM network_flows WHERE id NOT IN (
            SELECT id FROM network_flows ORDER BY id DESC LIMIT ?
        )
    """, (max_flows,))
    conn.execute("""
        DELETE FROM threat_alerts WHERE id NOT IN (
            SELECT id FROM threat_alerts ORDER BY id DESC LIMIT ?
        )
    """, (max_alerts,))
    conn.commit()
    conn.close()


def insert_flow(flow: dict):
    conn = _get_conn()
    conn.execute("""
        INSERT INTO network_flows
            (source_ip, dest_ip, flow_duration, fwd_pkts, bwd_pkts, bytes_per_sec, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        flow.get("source_ip", "0.0.0.0"),
        flow.get("destination_ip", flow.get("dest_ip", "0.0.0.0")),
        float(flow.get("flow_duration", 0)),
        int(flow.get("total_fwd_packets", 0)),
        int(flow.get("total_bwd_packets", 0)),
        float(flow.get("flow_bytes_per_sec", 0.0)),
        datetime.utcnow().isoformat(),
    ))
    conn.commit()
    conn.close()


# ── Stats & System ────────────────────────────────────────────────────────

def _get_local_ip() -> str:
    """Reliably get the outbound network IP of this device."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_stats() -> dict:
    """Aggregate KPI stats for the dashboard."""
    conn = _get_conn()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM network_flows")
    total_flows = c.fetchone()[0]

    c.execute("""
        SELECT COUNT(*) FROM threat_alerts
        WHERE LOWER(threat_class) NOT IN ('benign', 'normal')
    """)
    total_threats = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM blocked_ips")
    total_blocked = c.fetchone()[0]

    c.execute("""
        SELECT AVG(confidence) FROM threat_alerts
        WHERE LOWER(threat_class) NOT IN ('benign', 'normal')
          AND confidence > 0
    """)
    avg_row = c.fetchone()[0]
    avg_confidence = round(float(avg_row or 0.0), 4)

    c.execute("""
        SELECT source_ip, dest_ip, threat_class, confidence, detected_by, is_blocked, timestamp
        FROM threat_alerts
        WHERE LOWER(threat_class) NOT IN ('benign', 'normal')
        ORDER BY timestamp DESC
        LIMIT 1
    """)
    last_row = c.fetchone()
    last_alert = dict(last_row) if last_row else None

    conn.close()

    uptime_s = int(time.time() - _PROCESS_START)
    hours, rem = divmod(uptime_s, 3600)
    minutes, seconds = divmod(rem, 60)

    return {
        "total_flows": total_flows,
        "total_threats": total_threats,
        "threats_blocked": total_blocked,
        "avg_confidence": avg_confidence,
        "last_alert": last_alert,
        "rpi_ip": _get_local_ip(),
        "uptime_seconds": uptime_s,
        "uptime_human": f"{hours:02d}:{minutes:02d}:{seconds:02d}",
        "monitoring": True,
    }

# ── iot_devices (Zero Trust device registry) ─────────────────────────────

def register_device(mac: str, ip: str, hostname: str = "unknown") -> bool:
    """
    Register or refresh a device discovered by ARP scan.
    Returns True if this is a brand-new device (first discovery).
    """
    conn = _get_conn()
    now  = datetime.utcnow().isoformat()
    c    = conn.cursor()

    c.execute("SELECT id FROM iot_devices WHERE mac = ?", (mac,))
    existing = c.fetchone()

    if existing:
        conn.execute(
            "UPDATE iot_devices SET ip = ?, hostname = ?, last_seen = ? WHERE mac = ?",
            (ip, hostname, now, mac),
        )
        conn.commit()
        conn.close()
        return False  # device already known
    else:
        conn.execute(
            """
            INSERT INTO iot_devices
                (mac, ip, hostname, status, alert_count, trust_score, first_seen, last_seen)
            VALUES (?, ?, ?, 'unverified', 0, 100.0, ?, ?)
            """,
            (mac, ip, hostname, now, now),
        )
        conn.commit()
        conn.close()
        logger.info("Zero Trust: new device registered — %s (%s, %s)", mac, ip, hostname)
        return True  # brand-new — operator should verify


def get_iot_devices() -> list[dict]:
    """Return all tracked devices ordered by most recently seen."""
    conn = _get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM iot_devices ORDER BY last_seen DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_device_by_ip(ip: str) -> dict | None:
    """Look up a device by its current IP address."""
    conn = _get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM iot_devices WHERE ip = ?", (ip,))
    row = c.fetchone()
    conn.close()
    return dict(row) if row else None


def update_device_status(mac: str, status: str):
    """
    Manually set a device status.
    status: 'unverified' | 'trusted' | 'blocked'
    """
    conn = _get_conn()
    conn.execute("UPDATE iot_devices SET status = ? WHERE mac = ?", (status, mac))
    conn.commit()
    conn.close()


def penalise_device(ip: str, confidence: float) -> float | None:
    """
    Degrade a device's trust score when a threat is detected from its IP.

    Penalty = confidence × 25  (so a 0.99-confidence hit = ~25 point drop).
    A device starting at 100 needs 4 high-confidence hits to reach 0.
    When trust_score reaches 0 the device is auto-blocked.

    Returns the new trust_score, or None if no device is registered for this IP.
    """
    conn  = _get_conn()
    c     = conn.cursor()
    c.execute(
        "SELECT mac, trust_score, status FROM iot_devices WHERE ip = ?", (ip,)
    )
    row = c.fetchone()

    if not row:
        conn.close()
        return None

    mac       = row["mac"]
    penalty   = confidence * 25.0
    new_score = max(row["trust_score"] - penalty, 0.0)
    # Trusted devices are still penalised — zero trust means no permanent immunity
    new_status = "blocked" if new_score <= 0 else row["status"]

    conn.execute(
        """
        UPDATE iot_devices
        SET trust_score = ?, alert_count = alert_count + 1, status = ?,
            last_seen = ?
        WHERE mac = ?
        """,
        (new_score, new_status, datetime.utcnow().isoformat(), mac),
    )
    conn.commit()
    conn.close()

    logger.info(
        "Zero Trust: %s trust %.1f → %.1f (status: %s)",
        ip, row["trust_score"], new_score, new_status,
    )
    return new_score
