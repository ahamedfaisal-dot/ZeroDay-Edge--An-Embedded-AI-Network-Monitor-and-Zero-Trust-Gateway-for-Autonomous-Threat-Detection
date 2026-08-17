"""
app.py — Flask backend for the ZeroDay-Edge RPi5 Node.

Serves:
  GET  /                     → static/index.html (TFT frontend)
  GET  /api/stats            → dashboard KPI aggregate
  GET  /api/alerts           → threat alert list (recent 20)
  GET  /api/network          → cached ARP device list
  GET  /api/blocked          → currently blocked IPs
  POST /api/ingest           → manual flow ingestion (from external sensors)
  POST /api/block/<ip>       → manually block an IP via iptables
  POST /api/unblock/<ip>     → remove iptables block + DB record
  GET  /api/xai/<alert_id>   → SHAP / reconstruction XAI for an alert

Background threads:
  - Scapy packet sniffer (daemon)
  - Flow drain + ML classification every 5 s (daemon)
  - Periodic ARP scan every 60 s (daemon)
"""

import logging
import os
import subprocess
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

import db
from ml_engine import MLEngine
from network_scanner import NetworkScanner

# ── Logging ───────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cybershield")

# ── App Setup ─────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

# ── Service Initialisation ────────────────────────────────────────────────
db.init_db()

ml = MLEngine()
scanner = NetworkScanner()

# Pre-load all ML models in a background thread so the server starts instantly
threading.Thread(target=ml.load, daemon=True, name="ml-loader").start()


# ── iptables Helpers ──────────────────────────────────────────────────────

def _iptables(action: str, ip: str) -> bool:
    """
    Add or remove an iptables INPUT DROP rule for `ip`.

    action: '-A' (append) | '-D' (delete)
    Returns True on success, False on failure.
    """
    try:
        subprocess.run(
            ["sudo", "iptables", action, "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True,
            timeout=5,
        )
        return True
    except FileNotFoundError:
        logger.warning("iptables not found — block/unblock is DB-only (simulation mode)")
        return False
    except subprocess.CalledProcessError as e:
        logger.warning("iptables %s %s failed: %s", action, ip, e.stderr.decode())
        return False
    except Exception as e:
        logger.error("iptables error: %s", e)
        return False


def _block_ip(ip: str, reason: str = "auto", auto: bool = True):
    _iptables("-A", ip)
    db.add_blocked_ip(ip, reason=reason, auto=auto)
    logger.info("Blocked %s (%s)", ip, reason)


def _unblock_ip(ip: str):
    _iptables("-D", ip)
    db.remove_blocked_ip(ip)
    logger.info("Unblocked %s", ip)


# ── Classification Helper ─────────────────────────────────────────────────

def _classify_and_store(flow_data: dict) -> dict:
    """Run ML pipeline, persist flow + alert, auto-block if needed."""
    result = ml.classify(flow_data)

    # Always store the raw flow
    db.insert_flow(flow_data)

    # Only store alerts for genuine threats (not Benign)
    is_threat = result.get("threat_class", "Benign").lower() not in ("benign", "normal")
    if is_threat:
        db.insert_alert(result)
        if result.get("is_blocked") and not db.is_ip_blocked(result["source_ip"]):
            _block_ip(result["source_ip"], reason="auto", auto=True)

        # Zero Trust: degrade this device's trust score
        new_score = db.penalise_device(
            ip=result["source_ip"],
            confidence=float(result.get("confidence", 0.5)),
        )
        # If score just hit 0 the device is now auto-blocked in DB;
        # also enforce the iptables rule if not already present
        if new_score is not None and new_score <= 0:
            if not db.is_ip_blocked(result["source_ip"]):
                _block_ip(result["source_ip"], reason="zero-trust-score", auto=True)

    return result


# ── Background Flow Processor ─────────────────────────────────────────────

# Tunable via env — on a 4GB Pi 4, widening these spacings trades detection
# latency for lower average CPU/IO load, since the same core budget is now
# also shared with Chromium kiosk if it's running on-device.
_FLOW_DRAIN_INTERVAL = int(os.environ.get("EDGE_FLOW_INTERVAL", "5"))
_ARP_SCAN_INTERVAL   = int(os.environ.get("EDGE_ARP_INTERVAL", "60"))
_DB_PRUNE_INTERVAL   = int(os.environ.get("EDGE_DB_PRUNE_INTERVAL", "1800"))  # 30 min


def _flow_drain_loop():
    """Drain captured flows from the sniffer every _FLOW_DRAIN_INTERVAL seconds, classify each."""
    while True:
        time.sleep(_FLOW_DRAIN_INTERVAL)
        try:
            flows = scanner.drain_flows()
            for flow in flows:
                _classify_and_store(flow)

            # Port scans, DDoS/floods, brute-force: detected by deterministic
            # heuristics, not the ML pipeline (see network_scanner.py's
            # tracker docstrings) — these arrive pre-formed, just persist +
            # auto-block them.
            for result in scanner.drain_burst_alerts() + scanner.drain_bruteforce_alerts():
                db.insert_alert(result)
                if result.get("is_blocked") and not db.is_ip_blocked(result["source_ip"]):
                    _block_ip(result["source_ip"], reason="heuristic:" + result["detected_by"], auto=True)
        except Exception as e:
            logger.error("Flow drain error: %s", e)


def _db_prune_loop():
    """Periodically cap network_flows/threat_alerts row counts (see db.prune_old_data)."""
    while True:
        time.sleep(_DB_PRUNE_INTERVAL)
        try:
            db.prune_old_data()
        except Exception as e:
            logger.error("DB prune error: %s", e)


def _start_background_threads():
    # 1. Packet capture (blocking — must be its own thread)
    threading.Thread(
        target=scanner.start_capture,
        daemon=True,
        name="pkt-capture",
    ).start()

    # 2. Flow drain + classification
    threading.Thread(
        target=_flow_drain_loop,
        daemon=True,
        name="flow-drain",
    ).start()

    # 3. Periodic ARP scan
    scanner.start_periodic_scan(interval=_ARP_SCAN_INTERVAL)

    # 4. Periodic DB pruning — keeps SQLite (and the SD card's page cache
    #    footprint) bounded over long uptimes
    threading.Thread(
        target=_db_prune_loop,
        daemon=True,
        name="db-prune",
    ).start()


_start_background_threads()


# ── Routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the TFT frontend SPA."""
    return send_from_directory("static", "index.html")


@app.route("/api/stats")
def api_stats():
    """Aggregate KPI numbers for the dashboard."""
    return jsonify(db.get_stats())


@app.route("/api/alerts")
def api_alerts():
    """
    Query params:
      limit       (int, default 20)
      threats_only (bool, default false)
    """
    limit = request.args.get("limit", 20, type=int)
    threats_only = request.args.get("threats_only", "false").lower() == "true"
    return jsonify(db.get_recent_alerts(limit=limit, threats_only=threats_only))


@app.route("/api/network")
def api_network():
    """Return cached ARP-scanned devices (non-blocking)."""
    return jsonify(scanner.get_network_devices())


@app.route("/api/blocked")
def api_blocked():
    """Return all currently blocked IPs."""
    return jsonify(db.get_blocked_ips())


@app.route("/api/clear", methods=["POST"])
def api_clear():
    """Wipe all alerts/flows/blocked IPs/device registry — dashboard 'Clear Data' button."""
    blocked_ips = db.clear_all()
    for ip in blocked_ips:
        _iptables("-D", ip)
    logger.info("Dashboard: data cleared (%d iptables rules removed)", len(blocked_ips))
    return jsonify({
        "status": "cleared",
        "unblocked_ips": len(blocked_ips),
        "timestamp": datetime.utcnow().isoformat(),
    })


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    """
    Accept a flow from an external sensor and run the ML pipeline.

    Required JSON fields: source_ip, destination_ip
    Optional: flow_duration, total_fwd_packets, total_bwd_packets,
              flow_bytes_per_sec, sensor_node_id
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Expected JSON body"}), 400

    for field in ("source_ip", "destination_ip"):
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    # Apply safe defaults
    data.setdefault("flow_duration", 0.0)
    data.setdefault("total_fwd_packets", 0)
    data.setdefault("total_bwd_packets", 0)
    data.setdefault("flow_bytes_per_sec", 0.0)
    data.setdefault("sensor_node_id", "manual-ingest")

    result = _classify_and_store(data)
    return jsonify(result), 202


@app.route("/api/block/<ip>", methods=["POST"])
def api_block(ip: str):
    """Manually block an IP."""
    if db.is_ip_blocked(ip):
        return jsonify({"status": "already_blocked", "ip": ip}), 200
    _block_ip(ip, reason="manual", auto=False)
    return jsonify({
        "status":    "blocked",
        "ip":        ip,
        "timestamp": datetime.utcnow().isoformat(),
    })


@app.route("/api/unblock/<ip>", methods=["POST"])
def api_unblock(ip: str):
    """Manually unblock an IP."""
    _unblock_ip(ip)
    return jsonify({
        "status":    "unblocked",
        "ip":        ip,
        "timestamp": datetime.utcnow().isoformat(),
    })


@app.route("/api/xai/<int:alert_id>")
def api_xai(alert_id: int):
    """Return stored SHAP/XAI data for a specific alert."""
    alert = db.get_alert_by_id(alert_id)
    if not alert:
        return jsonify({"error": f"Alert {alert_id} not found"}), 404

    return jsonify({
        "alert_id":    alert_id,
        "source_ip":   alert.get("source_ip"),
        "dest_ip":     alert.get("dest_ip"),
        "threat_class": alert.get("threat_class"),
        "confidence":  alert.get("confidence"),
        "detected_by": alert.get("detected_by"),
        "is_blocked":  bool(alert.get("is_blocked")),
        "timestamp":   alert.get("timestamp"),
        "xai_features": alert.get("xai_features", []),
    })


@app.route("/api/iot")
def api_iot():
    """
    Return all Zero Trust device registry entries.
    Each entry has: mac, ip, hostname, status, trust_score, alert_count, last_seen.
    """
    return jsonify(db.get_iot_devices())


@app.route("/api/iot/<mac>/trust", methods=["POST"])
def api_iot_trust(mac: str):
    """
    Manually mark a device as trusted.
    This does NOT reset the trust score — it only changes the status label
    so the operator acknowledges the device.
    """
    db.update_device_status(mac, "trusted")
    logger.info("Zero Trust: operator marked %s as TRUSTED", mac)
    return jsonify({
        "status": "trusted",
        "mac": mac,
        "timestamp": datetime.utcnow().isoformat(),
    })


@app.route("/api/iot/<mac>/block", methods=["POST"])
def api_iot_block(mac: str):
    """
    Manually block a device by MAC address.
    Looks up the device’s current IP and adds an iptables DROP rule.
    """
    device = db.get_device_by_ip.__module__  # verify db is reachable
    devices = db.get_iot_devices()
    target  = next((d for d in devices if d["mac"] == mac), None)

    if not target:
        return jsonify({"error": f"Device {mac} not found"}), 404

    db.update_device_status(mac, "blocked")
    ip = target.get("ip")
    if ip and not db.is_ip_blocked(ip):
        _block_ip(ip, reason="manual-zt", auto=False)

    logger.info("Zero Trust: operator BLOCKED device %s (%s)", mac, ip)
    return jsonify({
        "status":    "blocked",
        "mac":       mac,
        "ip":        ip,
        "timestamp": datetime.utcnow().isoformat(),
    })


# ── Entry Point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info(" ZeroDay-Edge — Embedded AI Network Monitor")
    logger.info(" Zero Trust Gateway | Autonomous Threat Detection")
    logger.info(" http://0.0.0.0:5000")
    logger.info("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
