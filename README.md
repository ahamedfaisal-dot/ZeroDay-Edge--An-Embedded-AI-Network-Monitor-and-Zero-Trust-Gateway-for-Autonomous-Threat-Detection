# ZeroDay-Edge
### An Embedded AI Network Monitor and Zero Trust Gateway for Autonomous Threat Detection

> **Runs on:** Raspberry Pi 4 Model B (4 GB) · **Display:** 3.5″ TFT / small LCD, Chromium kiosk · **Stack:** Flask · Scapy · XGBoost · Random Forest · TFLite (Autoencoder + BiLSTM) · SQLite

Originally designed for a Raspberry Pi 5 (8 GB). This build has been re-architected to run comfortably on a **Pi 4 Model B with 4 GB RAM** — every design decision below that mentions memory, threads, or "why not just use X" exists because of that constraint.

---

## Table of Contents

1. [Overview](#overview)
2. [Why There Are Two Detection Systems](#why-there-are-two-detection-systems)
3. [System Architecture](#system-architecture)
4. [The ML Pipeline (3-Stage Cascade)](#the-ml-pipeline-3-stage-cascade)
5. [Flow Feature Extraction](#flow-feature-extraction)
6. [Heuristic Detectors](#heuristic-detectors)
7. [XAI — Explainable AI](#xai--explainable-ai)
8. [Zero Trust Device Registry](#zero-trust-device-registry)
9. [Pi 4 (4GB) Optimizations](#pi-4-4gb-optimizations)
10. [File Structure](#file-structure)
11. [Hardware](#hardware)
12. [Installation](#installation)
13. [Running the Server](#running-the-server)
14. [Frontend — Kiosk Dashboard](#frontend--kiosk-dashboard)
15. [REST API Reference](#rest-api-reference)
16. [Attack Simulation Tools](#attack-simulation-tools)
17. [Configuration & Tuning](#configuration--tuning)
18. [Known Limitations](#known-limitations)

---

## Overview

**ZeroDay-Edge** is a self-contained network security appliance. It runs entirely on the Pi — no cloud dependency — watching traffic on the local network and flagging threats in real time on its own screen.

**What it actually does:**

- **Captures live traffic** via a Scapy packet sniffer, reconstructing proper bidirectional network flows (not just raw packets).
- **Classifies each flow** through a 3-stage ML cascade (tree ensemble → autoencoder → BiLSTM), trained on CIC-IDS-2017-style features.
- **Also runs deterministic heuristic detectors** alongside the ML pipeline, for attack shapes the ML models don't reliably see in live traffic (see [below](#why-there-are-two-detection-systems)) — port scans, floods, brute-force, WiFi Evil Twin, beacon flooding.
- **Explains every ML decision** with real per-feature contribution values (TreeSHAP via XGBoost's own C++ core, no external `shap` package).
- **Tracks every device** on the LAN under a Zero Trust model — unverified by default, trust degrades on bad behavior, auto-blocked at zero.
- **Auto-blocks** malicious sources at the kernel level via `iptables`.
- **Displays everything** on a small screen in Chromium kiosk mode — no keyboard or mouse needed at the device.

---

## Why There Are Two Detection Systems

This is the single most important architectural fact about this project, and it wasn't the original design — it was discovered the hard way while testing against *real* attack traffic (nmap scans, TCP floods, brute-force attempts) instead of synthetic test vectors.

**The problem:** the ML models were trained on CIC-IDS-2017, where each row is one fully-featured network flow (packet counts, timing statistics, TCP flags, window sizes — ~76 columns). But a real port scan touching 1000 ports doesn't produce *one* flow with 1000 packets — it produces **1000 separate tiny 1–2 packet flows**, one per port, because each port probe is technically its own connection (its own 5-tuple: source IP, source port, dest IP, dest port, protocol). Individually, none of those tiny flows look anything like the rich, feature-complete "PortScan" examples the model was trained on. The same fragmentation problem applies to WiFi-layer attacks (deauth floods, evil twins) — those aren't IP flows at all, they're 802.11 management frames that never reach the flow-classification layer in the first place.

**The fix:** rather than trying to force every attack shape through the ML cascade, `network_scanner.py` runs **two parallel detection paths** on the same captured traffic:

| Path | What it catches | How |
|---|---|---|
| **ML Pipeline** (`ml_engine.py`) | Attacks that *do* present as a single, feature-rich malicious flow — the classic CIC-IDS-2017 attack shapes | XGBoost + Random Forest consensus → Autoencoder anomaly → BiLSTM temporal |
| **Heuristic Detectors** (`network_scanner.py`) | Attacks that fragment across many small flows or never become IP flows at all — port scans, floods, brute-force, WiFi-layer attacks | Deterministic rate/diversity thresholds on raw packet/frame counts, independent of the ML models |

Both paths write into the same `threat_alerts` table and render identically on the dashboard — the operator never needs to know which one fired. `detected_by` tells you which: `"Tree Ensemble"` / `"Autoencoder Zero-Day"` / `"BiLSTM Temporal"` for the ML path, or `"Port Scan Heuristic"` / `"Flood Heuristic"` / `"Brute Force Heuristic"` / `"WiFi Scan Heuristic"` / `"802.11 Deauth Monitor"` for the heuristic path.

---

## System Architecture

```
+--------------------------------------------------------------------------+
|                    Raspberry Pi 4 Model B (4 GB)                         |
|                                                                          |
|  +--------------+     +------------------------------------------+      |
|  |  Small LCD   |     |         Flask Web Server                  |      |
|  |  Chromium    |<----|         app.py : 5000                     |      |
|  |  Kiosk Mode  |     +----------+-------------------+------------+      |
|  +--------------+                |                   |                  |
|                          +-------+--------+   +-------+-------+         |
|                          |  ML Engine     |   |  SQLite DB    |         |
|                          |  ml_engine.py  |   |  db.py (WAL)  |         |
|                          |                |   |               |         |
|                          |  Stage 1: XGB  |   | threat_alerts |         |
|                          |    + RF        |   | blocked_ips   |         |
|                          |  Stage 2: AE   |   | network_flows |         |
|                          |    (tflite)    |   | iot_devices   |         |
|                          |  Stage 3: LSTM |   +-------+-------+         |
|                          |    (tflite)    |           |                 |
|                          |  XGBoost XAI   |           |                 |
|                          +-------+--------+           |                 |
|                                  |                     |                 |
|                          +-------+---------------------+------+         |
|                          |   network_scanner.py                |         |
|                          |                                     |         |
|                          |  Scapy packet sniffer                |         |
|                          |    -> bidirectional 5-tuple flows    |         |
|                          |    -> ~50 real CIC-IDS-2017 features |         |
|                          |  ARP LAN scanner (every 60s)         |         |
|                          |  WiFi SSID scanner (nmcli, every 60s)|         |
|                          |  Heuristic detectors:                |         |
|                          |    Port Scan / Flood / Brute Force   |         |
|                          |    Evil Twin / Beacon Flood          |         |
|                          +---------------------------------------+        |
|                                                                          |
|  +----------------------------------------------------------------------+|
|  |                          iptables                                    ||
|  |         DROP rules for auto/manual-blocked IPs                      ||
|  +----------------------------------------------------------------------+|
|                                                                          |
|  +----------------------------------------------------------------------+|
|  |   deauth_monitor.py  (separate systemd process, optional)           ||
|  |   Requires WiFi monitor mode (nexmon patch or a monitor-mode-       ||
|  |   capable USB adapter) — sees raw 802.11 deauth/disassoc frames     ||
|  |   the main capture path never receives, writes into the same DB    ||
|  +----------------------------------------------------------------------+|
+--------------------------------------------------------------------------+
         |                                  ^
         | eth0 / wlan0                     | ARP + WiFi scan
         v                                  |
+--------------------------------------------------------------------------+
|                  Local Network (192.168.x.x/24)                          |
|   [Laptop]  [Phone]  [IoT device]  [ESP8266 attack-test device]         |
+--------------------------------------------------------------------------+
```

### Background Threads (inside `app.py`)

| Thread | Interval | What it does |
|---|---|---|
| `pkt-capture` | Continuous | Scapy sniffs IP packets, builds bidirectional flow statistics + feeds the heuristic burst/brute-force/scan trackers |
| `flow-drain` | Every 5 s (`EDGE_FLOW_INTERVAL`) | Drains the flow table through `ml.classify()`, drains the heuristic trackers, persists results |
| `arp-scanner` | Every 60 s (`EDGE_ARP_INTERVAL`) | ARP scan (device discovery) + WiFi SSID scan (Evil Twin/Beacon Flood) in the same loop |
| `db-prune` | Every 30 min (`EDGE_DB_PRUNE_INTERVAL`) | Caps `network_flows`/`threat_alerts` row counts so the SQLite file doesn't grow unbounded over long uptimes |

Plus, optionally, `deauth_monitor.py` as its **own separate process** (not a thread inside `app.py`) — see [Attack Simulation Tools](#attack-simulation-tools).

---

## The ML Pipeline (3-Stage Cascade)

A cascade classifier — each stage only runs if the previous one didn't already flag the flow as malicious.

```
Flow Data (~76 CIC-IDS-2017-style features)
         |
         v
+---------------------------------------------------+
|  STAGE 1 — Tree Ensemble                          |
|                                                    |
|  XGBoost  --+                                      |
|             +-- Consensus (BOTH must predict 1)    |
|  Random     |                                      |
|  Forest  ---+                                      |
|                                                    |
|  Confidence: fixed 0.99 when triggered             |
+------------------+---------------------------------+
                   |  BENIGN only passes through
                   v
+---------------------------------------------------+
|  STAGE 2 — Deep Autoencoder (Zero-Day)             |
|                                                    |
|  Reconstructs the flow vector; high reconstruction |
|  error = never seen anything like this before.     |
|                                                    |
|  Threshold: MSE > 50.0                             |
|  Runtime: tflite-runtime (see Pi 4 Optimizations)  |
+------------------+---------------------------------+
                   |  BENIGN only passes through
                   v
+---------------------------------------------------+
|  STAGE 3 — BiLSTM (Temporal)                       |
|                                                    |
|  Catches attacks that only show up through timing  |
|  patterns rather than raw volume.                  |
|                                                    |
|  Threshold: probability > 0.98                     |
|  Runtime: tflite-runtime                           |
+------------------+---------------------------------+
                   |
                   v
            Classification Result
       {threat_class, confidence, detected_by,
        is_blocked, xai_features}
```

### Threat-class heuristics (Stage 2 only)

When the Autoencoder flags a flow, a secondary rule labels the *kind* of threat, based on volume:

| Condition | Threat Class |
|---|---|
| `total_fwd_packets > 1000` AND `avg_packet_size > 1000 bytes` | `Command Injection / RCE` |
| `total_fwd_packets > 100` OR `flow_bytes_per_sec > 2000` | `PortScan / DDoS` |
| Everything else | `Malicious` |

### Auto-block threshold

```python
# ml_engine.py
_AUTO_BLOCK_THRESHOLD = 0.85   # confidence >= this -> is_blocked = True
```

### `EDGE_LITE_MODE`

Set `EDGE_LITE_MODE=1` to skip Stage 2/3 entirely and run tree-ensemble-only classification. Useful when RAM is genuinely tight (e.g. Chromium kiosk running on the same 4GB device).

---

## Flow Feature Extraction

This is the part that changed the most from the original Pi 5 design, and it's the reason the heuristic detectors exist at all.

`network_scanner.py`'s packet handler builds **proper bidirectional flows**, keyed by the full 5-tuple `(src_ip, src_port, dst_ip, dst_port, protocol)` — "forward" is whichever side sent the first packet, "backward" is the other side, matching the convention `feature_columns.joblib` was trained on. Per flow, it computes (via a streaming Welford's-algorithm accumulator, `_RunningStats` — O(1) memory per flow regardless of packet count, which matters when a flood can mint thousands of packets in one 5-second window on a memory-constrained device):

- Packet-length min/max/mean/std, forward and backward separately, plus combined
- Inter-arrival-time min/max/mean/std, forward/backward/combined
- TCP flag counts (SYN/ACK/FIN/RST/PSH/URG), forward and backward
- Header lengths, init window sizes, forward "data packet" count
- Byte/packet rates, down/up ratio, average packet size

That's roughly 50 of the model's ~76 trained columns computed from **real captured packets** — a large improvement over the original design, which only ever populated 4 basic aggregate fields (`flow_duration`, `total_fwd_packets`, `total_bwd_packets`, `flow_bytes_per_sec`) and zero-padded everything else. Native CIC-IDS-2017 column names (e.g. `"Fwd Pkt Len Max"`, `"SYN Flag Cnt"`) are emitted directly in the flow dict, so `ml_engine.py`'s `_prepare_features()` picks them up automatically through its existing fallback (`flow_data.get(col, 0.0)`) — no model-side changes needed.

The in-memory flow table is capped at 4000 concurrent entries (`_MAX_FLOW_TABLE_ENTRIES`) so a flood/scan can't grow it unbounded before the next drain.

---

## Heuristic Detectors

All of these run inside `network_scanner.py`, alongside packet capture, and bypass the ML pipeline entirely — see [Why There Are Two Detection Systems](#why-there-are-two-detection-systems) for the reasoning.

### Port Scan vs. DDoS/Flood

Both are tracked from the same per-`(src_ip, dst_ip)` aggregate (`_scan_table`): distinct destination ports touched, total packets, total bytes. They're told apart by **packets-per-port density**, not raw volume — a scan spreads ~1 packet across many ports; a flood concentrates hundreds of packets on one or two ports. (Raw packet count alone was tried first and was wrong: a normal 1000-port nmap scan easily exceeds a flat "300 packets in 5s" flood threshold on total volume, which mislabeled real scans as floods.)

```python
_SCAN_PORT_THRESHOLD = 15          # distinct ports touched = scan candidate
_SCAN_MAX_AVG_PKTS_PER_PORT = 5    # below this density with many ports -> PortScan
_FLOOD_PACKET_THRESHOLD = 300      # packets in one window, concentrated -> DDoS/Flood
```

### Brute Force

Tracked per `(src_ip, dst_ip, dst_port)` — counts fresh SYN packets (SYN without ACK = a new connection attempt, not a response) at a *single* port. Same underlying shape as a scan (many small attempts), but concentrated on one port instead of spread across many — the signature of repeated login attempts.

```python
_BRUTEFORCE_ATTEMPT_THRESHOLD = 10  # connection attempts to one dst:port in one window
```

### Evil Twin / Rogue AP & Beacon Flood

Uses a normal station-mode WiFi scan (`nmcli -t -f SSID,BSSID dev wifi list`) — **no monitor mode required**, unlike deauth detection. First-seen-trusted, same philosophy as the Zero Trust device registry: the first BSSID seen for an SSID becomes the baseline.

- **Evil Twin**: a known SSID suddenly broadcasting from a *second, different* BSSID — the classic impersonation signature.
- **Beacon Flood**: an abnormal number of distinct SSIDs visible in one scan pass.

```python
_BEACON_FLOOD_SSID_THRESHOLD = 25   # distinct SSIDs in one scan = flood
_ALERT_COOLDOWN_SECONDS = 30        # don't re-alert the same condition constantly
```

A brand-new, never-seen-before SSID does **not** alert on its own — new networks legitimately appear all the time. Only a *collision* (same name, new BSSID) is suspicious.

### WiFi Deauthentication Flood (separate process — see below)

Not run inside `network_scanner.py`, because it needs the WiFi radio in **monitor mode**, which is mutually exclusive with normal station-mode networking on a single radio. See [Attack Simulation Tools](#attack-simulation-tools) for `deauth_monitor.py`.

---

## XAI — Explainable AI

Every threat detection includes a ranked list of features that contributed most, answering *"why did this get flagged?"*

### Stage 1 (Tree Ensemble) — XGBoost native TreeSHAP

Uses XGBoost's own `pred_contribs=True` (exact SHAP values, computed inside its C++ core) — **not** the separate `shap` Python package. This matters specifically because `shap` depends on `numba` → `llvmlite`, which has no prebuilt wheel on 32-bit ARM (`armv7l`) and fails trying to compile LLVM from source. XGBoost's built-in contributions sidestep that entirely, with zero extra dependencies.

```json
{ "name": "Init Bwd Win Byts", "raw_value": -1.0, "impact": 2.217 }
```

### Stage 2 (Autoencoder) — reconstruction error attribution

Per-feature squared reconstruction error `(original - reconstructed)^2` — the features the autoencoder found most "unexpected."

### Stage 3 (BiLSTM) — scaled feature magnitude

Absolute scaled feature value, normalized 0–1, as a proxy for influence on the LSTM's hidden state.

### Heuristic detectors — plain-English reasons

Since there's no model involved, the heuristics populate `xai_features` with the actual numbers that tripped the threshold instead — e.g. `distinct_ports_scanned`, `packets_in_window`, `connection_attempts`, `new_bssid`. Same rendering path on the dashboard, just human-derived rather than model-derived.

---

## Zero Trust Device Registry

> *"Never trust, always verify."*

Every device discovered by the ARP scanner starts at `status = unverified`, `trust_score = 100`.

```
penalty = confidence × 25.0
```

A single high-confidence detection (0.99) removes ~25 points; 4 such detections zero out the score. At `trust_score <= 0`, the device is marked `blocked` in `iot_devices` and dropped via `iptables`. Manually marking a device `trusted` does **not** grant immunity — it's still penalized on further detections, matching genuine Zero Trust ("no permanent trust").

---

## Pi 4 (4GB) Optimizations

This section exists because the project's biggest engineering effort, after the flow-extraction rewrite, was fitting comfortably into 4GB of RAM. Every one of these is a direct response to something that broke or was too slow on the actual hardware.

| Optimization | Why |
|---|---|
| **`tflite-runtime` instead of full TensorFlow** | Full TF's ~400MB+ RSS and slow import were fine on an 8GB Pi 5, not on 4GB. `convert_to_tflite.py` (run once, off-device) produces quantized `.tflite` models; `ml_engine.py` loads those via `tflite_runtime.Interpreter` if present, falling back to full TF/`.h5` only if they're missing. |
| **Dropped `shap`** | Failed to build on 32-bit ARM (`numba`/`llvmlite` have no wheel there). Replaced with XGBoost's own native contribution computation — see [XAI](#xai--explainable-ai). |
| **Dropped `pandas`** | Was a listed dependency but never actually imported anywhere in the code. |
| **Thread-capped ML models** | `EDGE_ML_THREADS` (default 2) caps XGBoost/RF/tflite internal thread pools so they don't oversubscribe the Pi 4's 4 cores against Flask + Scapy + (optionally) Chromium. |
| **Streaming flow statistics** | `_RunningStats` (Welford's algorithm) instead of storing every packet length/IAT — O(1) memory per flow regardless of how many packets a flood sends. |
| **Capped flow/scan tables** | `_MAX_FLOW_TABLE_ENTRIES = 4000` — a port scan/flood can't mint unbounded tracking entries between drains. |
| **Periodic DB pruning** | `db.prune_old_data()` caps `network_flows`/`threat_alerts` row counts (default 5000/2000) — unbounded growth on an SD card is a real problem over long uptimes. |
| **1GB swap + systemd memory limits** | `install.sh` provisions swap as an OOM safety net, and the systemd unit sets `MemoryMax=1600M`/`MemoryHigh=1300M` so the ML service can't crowd out Chromium, which shares the same 4GB continuously in kiosk mode. |
| **Memory-trimmed Chromium kiosk flags** | `--disable-gpu --disable-dev-shm-usage --disk-cache-size=1` — the kiosk autostart avoids GPU-compositing/shared-memory assumptions the 4GB Pi 4 can't spare. |
| **`EDGE_LITE_MODE`** | Full opt-out of Stage 2/3 + their tflite runtime overhead, tree-ensemble-only, for the tightest possible memory footprint. |

---

## File Structure

```
EDGE_SERVER/
|
+-- app.py                     Flask app — routes + background threads (flow-drain, ARP/WiFi scan, DB prune)
+-- ml_engine.py                3-stage ML cascade + XGBoost-native XAI (thread-safe singleton)
+-- network_scanner.py          Packet capture, bidirectional flow features, ARP scan, WiFi scan,
|                                heuristic detectors (scan/flood/brute-force/evil-twin/beacon-flood)
+-- db.py                       SQLite layer (WAL mode, no ORM)
+-- deauth_monitor.py           Standalone 802.11 deauth/disassoc flood detector (needs monitor mode)
+-- convert_to_tflite.py        One-time Keras -> TFLite model converter (run off-device)
+-- demo_flows.py                Known-good ML-pipeline test payloads (benign + malicious)
+-- test_ml.py                   Smoke tests for the ML pipeline + DB
+-- requirements.txt             Python dependencies (Pi 4 / 32-bit-ARM aware)
+-- install.sh                   One-shot Pi 4 setup: packages, swap, venv, ml_models, systemd, kiosk
+-- start.sh                     Manual launch script
+-- esp8266_attack_device.ino    ESP8266 firmware: port scan / flood / brute-force test device
+-- deauth_test_device.ino       ESP8266 firmware: serial-controlled deauth test device
+-- README.md                    This file
|
+-- ml_models/                   Trained model files
|   +-- xgboost_model.joblib
|   +-- rf_model.joblib
|   +-- scaler.joblib
|   +-- feature_columns.joblib   (76 columns)
|   +-- autoencoder.h5 / autoencoder.tflite   (tflite preferred, see Pi 4 Optimizations)
|   +-- bilstm.h5 / bilstm.tflite
|
+-- static/                      Frontend SPA (served by Flask)
|   +-- index.html               5-page single-page app (Dashboard/Alerts/Network/Blocked/Explain)
|   +-- style.css
|   +-- app.js
|
+-- rpi_shield.db                SQLite database (auto-created on first run)
```

---

## Hardware

| Component | Specification |
|---|---|
| **Board** | Raspberry Pi 4 Model B, **4 GB RAM** |
| **OS** | Raspberry Pi OS (32-bit `armhf` or 64-bit `aarch64` — both supported; see `requirements.txt`) |
| **Display** | Small LCD/TFT (SPI or HDMI), Chromium kiosk mode |
| **Network** | Ethernet or WiFi for normal operation |
| **Storage** | microSD, 16GB+ |
| **Power** | Official Pi 4 USB-C PSU |

**Optional — for WiFi deauth detection specifically:** the Pi 4's onboard WiFi chip (Broadcom BCM43455c0) does not support monitor mode out of the box. Two options:
- A patched firmware via [nexmon](https://github.com/seemoo-lab/nexmon) — works, but is genuinely fragile: version-locked to specific kernel/firmware combinations, and the bundled toolchain predates modern Debian (expect `libisl`/`libmpfr` compatibility symlinking).
- A cheap external USB WiFi adapter with a monitor-mode-capable chipset (Atheros AR9271, e.g. Alfa AWUS036NHA) — no patching needed, `iw dev wlan1 set type monitor` just works with the mainline driver.

**Optional — for live attack testing:** an ESP8266 (Wemos D1 Mini) + SSD1306/SH1106 OLED + buttons, running `esp8266_attack_device.ino` and/or `deauth_test_device.ino` — see [Attack Simulation Tools](#attack-simulation-tools).

---

## Installation

```bash
scp -r EDGE_SERVER/ pi@<rpi-ip>:~/
ssh pi@<rpi-ip>
cd ~/EDGE_SERVER
sudo bash install.sh
```

`install.sh` does, in order:

1. **System packages** — `python3`, `libpcap-dev`, `libopenblas-dev` (numpy's BLAS dependency, easy to miss), `dphys-swapfile`, and (unless `LITE_KIOSK=1`) `chromium-browser`/`unclutter`
2. **Swap** — ensures 1GB via `dphys-swapfile`
3. **Python venv + requirements** — `tflite-runtime` on `aarch64`/`armv7l`, everything else standard
4. **ML model copy** — from a sibling `../backend/ml_models/` if present, else copy manually into `ml_models/`
5. **systemd service** — `cybershield-edge.service`, with `MemoryMax`/`MemoryHigh`/`CPUWeight` set, `EDGE_LITE_MODE` passed through from the environment
6. **Chromium kiosk autostart** — memory-trimmed flags, unless `LITE_KIOSK=1`

**Before deploying**, run the tflite conversion **once**, off-device (needs full TensorFlow, which you do *not* want installed on the Pi itself):

```bash
pip install tensorflow
python convert_to_tflite.py
# copy the resulting ml_models/*.tflite to the Pi
```

Without this step, `ml_engine.py` falls back to loading `.h5` directly, which needs full TensorFlow on-device — avoid this on a 4GB Pi 4 if at all possible.

### Env overrides

```bash
sudo LITE_KIOSK=1 bash install.sh        # headless, no Chromium kiosk
sudo EDGE_LITE_MODE=1 bash install.sh    # tree-ensemble-only, lowest memory footprint
```

---

## Running the Server

```bash
sudo systemctl start cybershield-edge      # start
sudo systemctl stop cybershield-edge       # stop
sudo systemctl restart cybershield-edge    # restart (after any code change)
sudo systemctl status cybershield-edge     # is it running?
sudo journalctl -fu cybershield-edge       # live logs
```

Auto-starts on boot by default (`install.sh` enables it). `sudo systemctl disable cybershield-edge` turns that off without stopping it right now.

Manual/dev launch:
```bash
sudo bash start.sh
# or:
sudo .venv/bin/python app.py
```

Dashboard: `http://<rpi-ip>:5000` from any device on the LAN, or `http://localhost:5000` in the kiosk itself.

---

## Frontend — Kiosk Dashboard

Five pages, bottom tab navigation, no scrolling — designed for a small touch/non-touch display in kiosk mode.

| Page | Contents |
|---|---|
| **Home** | KPI row (flows/threats/blocked), last-threat panel, AI confidence bar, recent-threats mini-feed |
| **Alerts** | Full threat list — threat class, `detected_by`, source→dest, blocked status, timestamp |
| **Network** | Zero Trust device list (Trust/Block per device), **Scan** button (manual ARP refresh), **Clear** button (wipes all alerts/flows/blocked-IPs/device-registry — confirms before running, also removes the matching `iptables` rules; useful for resetting before a demo run-through) |
| **Blocked** | Currently blocked IPs with one-tap unblock |
| **Explain** | Alert selector + XAI feature-contribution bar chart (works for both ML and heuristic detections) |

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the dashboard SPA |
| `GET` | `/api/stats` | Dashboard KPIs (flows, threats, blocked, avg confidence, uptime, last alert) |
| `GET` | `/api/alerts?limit=20&threats_only=false` | Recent alerts |
| `GET` | `/api/xai/<alert_id>` | XAI feature contributions for one alert |
| `GET` | `/api/network` | Cached ARP-discovered devices |
| `GET` | `/api/blocked` | Currently blocked IPs |
| `POST` | `/api/clear` | Wipe all alerts/flows/blocked-IPs/device-registry (also unblocks matching `iptables` rules) |
| `POST` | `/api/ingest` | Submit a flow dict directly for ML classification (external sensors, or manual testing — see `demo_flows.py`) |
| `POST` | `/api/block/<ip>` | Manually block an IP |
| `POST` | `/api/unblock/<ip>` | Remove a block |
| `GET` | `/api/iot` | Zero Trust device registry |
| `POST` | `/api/iot/<mac>/trust` | Mark a device trusted (does not grant immunity — see Zero Trust section) |
| `POST` | `/api/iot/<mac>/block` | Block a device by MAC |

**`/api/ingest` request/response example:**
```json
// POST body
{
  "source_ip": "10.0.0.5",
  "destination_ip": "192.168.1.1",
  "flow_duration": 50000.0,
  "total_fwd_packets": 5000,
  "total_bwd_packets": 4500,
  "flow_bytes_per_sec": 99999.0
}
```
```json
// 202 response
{
  "source_ip": "10.0.0.5",
  "dest_ip": "192.168.1.1",
  "threat_class": "Malicious",
  "confidence": 0.99,
  "detected_by": "Tree Ensemble",
  "is_blocked": true,
  "xai_features": [
    { "name": "Init Bwd Win Byts", "raw_value": -1.0, "impact": 2.217 }
  ],
  "timestamp": "2026-08-17T12:00:00"
}
```

---

## Attack Simulation Tools

Tools used to validate every detector actually fires against real attack traffic, not just synthetic vectors.

### `demo_flows.py` — ML pipeline test payloads

Since real captured traffic only populates ~50 of 76 features (see [Flow Feature Extraction](#flow-feature-extraction)), and even that can fragment across many small flows, this script sends hand-crafted, realistically-shaped payloads (SYN-flood pattern) straight to the ML pipeline — useful for confirming Stage 1 fires and XAI populates correctly, independent of live traffic conditions.

```bash
.venv/bin/python demo_flows.py --check          # classify locally, no Flask needed
.venv/bin/python demo_flows.py --send            # POST the malicious flow to a running server
.venv/bin/python demo_flows.py --send --benign   # POST the benign flow instead
```

### `esp8266_attack_device.ino` — port scan / flood / brute-force

Standalone ESP8266 hardware, connects to the network as a normal WiFi station (no monitor mode), OLED menu (Up/Down/Confirm/Back) to select and run each attack against a configured target IP — exercises the exact same heuristic detectors real attack tools would trip.

### `deauth_test_device.ino` + `deauth_monitor.py` — WiFi deauth

- `deauth_test_device.ino`: serial-controlled ESP8266 firmware, sends raw 802.11 deauth frames at a target AP's broadcast address (`scan` to list nearby APs, `attack <bssid> <channel>` to start, `stop` to end).
- `deauth_monitor.py`: a **separate process** from `app.py` (run it as its own systemd service), because it needs the WiFi radio in monitor mode, which can't coexist with normal station-mode networking on one radio. Counts deauth/disassoc frames per transmitter MAC in a sliding window; alerts on a flood, with a per-source cooldown to avoid spamming the DB.

```bash
sudo .venv/bin/python deauth_monitor.py --iface wlan0 --window 5 --threshold 5 --cooldown 30
```

Writes directly into the same `threat_alerts` table the dashboard reads from — SQLite's WAL mode handles the separate-process writer safely.

**Test everything only against a network and devices you own or have explicit permission to test.**

---

## Configuration & Tuning

### Environment variables

| Variable | Default | Where | Effect |
|---|---|---|---|
| `EDGE_LITE_MODE` | `0` | `ml_engine.py` | `1` = skip Stage 2/3 + reduce to tree-ensemble-only |
| `EDGE_ML_THREADS` | `2` | `ml_engine.py` | Thread cap for XGBoost/RF/tflite |
| `EDGE_FLOW_INTERVAL` | `5` | `app.py` | Seconds between flow-drain/classify passes |
| `EDGE_ARP_INTERVAL` | `60` | `app.py` | Seconds between ARP + WiFi SSID scans |
| `EDGE_DB_PRUNE_INTERVAL` | `1800` | `app.py` | Seconds between DB row-count pruning passes |
| `LITE_KIOSK` | `0` | `install.sh` (install-time only) | `1` = skip Chromium kiosk, headless deploy |

### Detection thresholds

```python
# ml_engine.py
_AUTO_BLOCK_THRESHOLD      = 0.85
_AUTOENCODER_MSE_THRESHOLD = 50.0
_BILSTM_PROB_THRESHOLD     = 0.98

# network_scanner.py
_SCAN_PORT_THRESHOLD          = 15
_SCAN_MAX_AVG_PKTS_PER_PORT   = 5
_FLOOD_PACKET_THRESHOLD       = 300
_BRUTEFORCE_ATTEMPT_THRESHOLD = 10
_BEACON_FLOOD_SSID_THRESHOLD  = 25
_ALERT_COOLDOWN_SECONDS       = 30
_MAX_FLOW_TABLE_ENTRIES       = 4000

# db.py — trust score penalty
penalty = confidence * 25.0   # in penalise_device()

# deauth_monitor.py (CLI flags, not constants)
--window 5 --threshold 5 --cooldown 30
```

---

## Known Limitations

- **Not all 76 trained features are computed from live traffic.** Bulk-transfer-rate features (`Fwd/Bwd Byts/b Avg`, `Blk Rate Avg`) and active/idle burst segmentation (`Active/Idle Mean/Std/Max/Min`) default to zero — reasonable approximations for most flows, but a real gap if an attack specifically depends on those columns.
- **`nmcli`-based WiFi scanning is first-seen-trusted.** If an Evil Twin is already broadcasting before the Pi's very first scan, whichever BSSID appears first in that scan becomes the "trusted" baseline — same tradeoff as the Zero Trust device registry, not unique to this feature.
- **Deauth detection requires monitor mode**, which is not reliably available on the Pi 4's onboard WiFi chip without either a fragile firmware patch (nexmon) or extra hardware (a monitor-mode-capable USB adapter). It's genuinely the least turnkey part of this project.
- **`sklearn`/`xgboost` version drift.** Models are trained in one environment and may be loaded by a newer `scikit-learn`/`xgboost` on the Pi (piwheels serves current versions, not necessarily the training version) — watch for `InconsistentVersionWarning` in the logs; predictions can shift subtly across versions even without an error.
