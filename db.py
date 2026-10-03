"""
db.py — SQLite database layer for the ZeroDay-Edge RPi5 Node.

No ORM, no Django — raw sqlite3 for minimum overhead.
Tables:
  threat_alerts  — ML-classified threat detections
  blocked_ips    — Currently blocked IP addresses
  network_flows  — Ingested / captured network flows
"""

import sqlite3
import sys
import json
import socket
import threading
import time
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent / "rpi_shield.db"

# Captured at module load — marks when the Flask process started
_PROCESS_START = time.time()


# ── Connections ───────────────────────────────────────────────────────────
# ONE shared SQLite connection for the whole process, serialised by a Python
# lock. All our threads (Flask workers, sniffer drain, heuristics, ARP scan)
# live in one process, so SQLite's own file locking was pure overhead — and on
# a Pi it surfaced as "database is locked" 500s that hung ~30 s then failed.
# With the lock, a thread that has to wait waits in Python (never errors), and
# any call holding the DB for >2 s is logged with its name so a stall is easy
# to attribute.
#
# Callers keep the same pattern as before: `conn = _get_conn() ... conn.close()`.
# _get_conn() takes the lock; close() (or garbage collection of the handle, if
# a code path forgets) releases it and rolls back any uncommitted leftovers.

_db_lock = threading.RLock()
_shared_conn: sqlite3.Connection | None = None
_depth = 0                # RLock nesting depth (only the outermost close() may rollback)
_LOCK_WAIT_S = 20
_SLOW_HOLD_S = 2.0


def _open_shared() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        logger.info("SQLite journal_mode=%s", mode)
    except sqlite3.OperationalError as e:
        logger.warning("Could not enable WAL (%s) - continuing in default mode", e)
    conn.execute("PRAGMA synchronous=NORMAL")  # fsync on checkpoint only - faster on SD card
    conn.execute("PRAGMA temp_store=MEMORY")   # temp tables in RAM, not on SD card
    return conn


class _Handle:
    """Lock-holding proxy to the shared connection; close() releases the lock."""

    def __init__(self, caller: str):
        global _shared_conn, _depth
        if not _db_lock.acquire(timeout=_LOCK_WAIT_S):
            raise RuntimeError(f"DB busy: lock not acquired in {_LOCK_WAIT_S}s (caller={caller})")
        _depth += 1
        self._held = True
        self._caller = caller
        self._t0 = time.time()
        if _shared_conn is None:
            _shared_conn = _open_shared()
        self._c = _shared_conn

    def __getattr__(self, name):
        return getattr(self._c, name)

    def close(self):
        global _depth
        if not self._held:
            return
        self._held = False
        try:
            if _depth == 1 and self._c.in_transaction:
                self._c.rollback()  # discard anything a code path forgot to commit
        finally:
            _depth -= 1
            held = time.time() - self._t0
            _db_lock.release()
            if held > _SLOW_HOLD_S:
                logger.warning("DB held %.1fs by %s (thread %s)", held, self._caller,
                               threading.current_thread().name)

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _get_conn() -> "_Handle":
    return _Handle(sys._getframe(1).f_code.co_name)


def _enable_wal():
    """Kept for callers/tests; the shared connection enables WAL when it opens."""
    _get_conn().close()


# ── Schema Init ───────────────────────────────────────────────────────────

def init_db():
    """Create tables if they don't exist. Safe to call multiple times."""
    _enable_wal()
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
        CREATE INDEX IF NOT EXISTS idx_alerts_id    ON threat_alerts(id DESC);

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
            ORDER BY id DESC LIMIT ?
        """, (limit,))
    else:
        c.execute(
            "SELECT * FROM threat_alerts ORDER BY id DESC LIMIT ?",
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


def get_honeypot_summary(limit: int = 40) -> dict:
    """Counters + recent visitors of the deception honeypot (from stored alerts)."""
    conn = _get_conn()
    try:
        det = "Deception Honeypot"
        total = conn.execute("SELECT COUNT(*) FROM threat_alerts WHERE detected_by = ?", (det,)).fetchone()[0]
        creds = conn.execute(
            "SELECT COUNT(*) FROM threat_alerts WHERE detected_by = ? AND threat_class LIKE '%Credential%'", (det,)
        ).fetchone()[0]
        attackers = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM threat_alerts WHERE detected_by = ?", (det,)
        ).fetchone()[0]
        rows = conn.execute(
            """SELECT id, source_ip, dest_ip, threat_class, confidence, is_blocked, xai_data, timestamp
               FROM threat_alerts WHERE detected_by = ? ORDER BY id DESC LIMIT ?""", (det, limit)
        ).fetchall()
        events = []
        for r in rows:
            d = dict(r)
            try:
                feats = json.loads(d.pop("xai_data") or "[]")
            except Exception:
                feats = []
            svc = next((f["raw_value"] for f in feats if f.get("name") == "decoy_service"), "")
            tried = [str(f["raw_value"]) for f in feats if f.get("name") == "credentials_tried"]
            req = next((str(f["raw_value"]) for f in feats if f.get("name") == "request"), "")
            events.append({**d, "service": svc, "credentials": tried, "request": req})
        return {"total_hits": total, "credential_captures": creds, "unique_attackers": attackers, "events": events}
    finally:
        conn.close()


def max_alert_id() -> int:
    conn = _get_conn()
    try:
        return conn.execute("SELECT COALESCE(MAX(id), 0) FROM threat_alerts").fetchone()[0]
    finally:
        conn.close()


def get_alerts_since(last_id: int, limit: int = 500) -> list[dict]:
    """Alerts with id > last_id, oldest first (feeds the campaign correlator)."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            """SELECT id, source_ip, threat_class, confidence, timestamp
               FROM threat_alerts WHERE id > ? ORDER BY id ASC LIMIT ?""",
            (last_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


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
    c.execute("""
        SELECT b.*,
               (SELECT threat_class FROM threat_alerts a WHERE a.source_ip = b.ip
                  AND LOWER(a.threat_class) NOT IN ('benign','normal') ORDER BY a.id DESC LIMIT 1) AS threat_class,
               (SELECT confidence FROM threat_alerts a WHERE a.source_ip = b.ip
                  AND LOWER(a.threat_class) NOT IN ('benign','normal') ORDER BY a.id DESC LIMIT 1) AS confidence,
               (SELECT detected_by FROM threat_alerts a WHERE a.source_ip = b.ip
                  AND LOWER(a.threat_class) NOT IN ('benign','normal') ORDER BY a.id DESC LIMIT 1) AS detected_by
        FROM blocked_ips b ORDER BY b.id DESC
    """)
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


def insert_flows(flows: list[dict]):
    """Insert many flows in one transaction (one connection, one commit)."""
    if not flows:
        return
    now = datetime.utcnow().isoformat()
    rows = [(
        f.get("source_ip", "0.0.0.0"),
        f.get("destination_ip", f.get("dest_ip", "0.0.0.0")),
        float(f.get("flow_duration", 0)),
        int(f.get("total_fwd_packets", 0)),
        int(f.get("total_bwd_packets", 0)),
        float(f.get("flow_bytes_per_sec", 0.0)),
        now,
    ) for f in flows]
    conn = _get_conn()
    conn.executemany("""
        INSERT INTO network_flows
            (source_ip, dest_ip, flow_duration, fwd_pkts, bwd_pkts, bytes_per_sec, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, rows)
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


_LOCAL_IP = _get_local_ip()


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
        ORDER BY id DESC
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
        "rpi_ip": _LOCAL_IP,
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
