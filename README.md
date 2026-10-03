# ZeroDay-Edge
### An Embedded AI Network Monitor and Zero Trust Gateway for Autonomous Threat Detection

> **Runs on:** Raspberry Pi 4 Model B (4 GB) · **Display:** 3.5″ TFT / small LCD, Chromium kiosk · **Stack:** Flask · Scapy · XGBoost · Random Forest · TFLite (Autoencoder + BiLSTM) · online-learning baseline & Markov kill-chain models · deception honeypot · nftables/iptables · SQLite

Originally designed for a Raspberry Pi 5 (8 GB). This build has been re-architected to run comfortably on a **Pi 4 Model B with 4 GB RAM** — every design decision below that mentions memory, threads, or "why not just use X" exists because of that constraint.

---

## Table of Contents

1. [Overview](#overview)
2. [Why There Are Two Detection Systems](#why-there-are-two-detection-systems)
3. [System Architecture](#system-architecture)
4. [The ML Pipeline (3-Stage Cascade)](#the-ml-pipeline-3-stage-cascade)
5. [Flow Feature Extraction](#flow-feature-extraction)
6. [Heuristic Detectors](#heuristic-detectors)
7. [Adaptive Behavior Baseline (Unsupervised AI)](#adaptive-behavior-baseline-unsupervised-ai)
8. [Attack Campaign Correlation & Predictive Kill-Chain](#attack-campaign-correlation--predictive-kill-chain)
9. [Deception Honeypot](#deception-honeypot)
10. [XAI — Explainable AI & Incident Briefs](#xai--explainable-ai--incident-briefs)
11. [Zero Trust Device Registry](#zero-trust-device-registry)
12. [Firewall Enforcement (Block / Unblock)](#firewall-enforcement-block--unblock)
13. [Pi 4 (4GB) Optimizations](#pi-4-4gb-optimizations)
14. [File Structure](#file-structure)
15. [Hardware](#hardware)
16. [Installation](#installation)
17. [Running the Server & Kiosk Mode](#running-the-server--kiosk-mode)
18. [Frontend — Kiosk Dashboard](#frontend--kiosk-dashboard)
19. [REST API Reference](#rest-api-reference)
20. [Testing & Attack Simulation](#testing--attack-simulation)
21. [Configuration & Tuning](#configuration--tuning)
22. [Known Limitations](#known-limitations)

---

## Overview

**ZeroDay-Edge** is a self-contained network security appliance. It runs entirely on the Pi — no cloud dependency — watching traffic on the local network and flagging threats in real time on its own screen.

**What it actually does:**

- **Captures live traffic** via a Scapy packet sniffer, reconstructing proper bidirectional network flows (not just raw packets).
- **Classifies each flow** through a 3-stage ML cascade (tree ensemble → autoencoder → BiLSTM), trained on CIC-IDS-2017-style features. Flows are scored in batches, and the tree ensemble reports its real probability as confidence.
- **Runs deterministic heuristic detectors** alongside the ML pipeline, for attack shapes the ML models don't reliably see in live traffic (see [below](#why-there-are-two-detection-systems)) — port scans, floods, brute-force, WiFi Evil Twin, beacon flooding — on a 1-second sliding window so attacks surface almost immediately.
- **Learns what is normal for every device** (adaptive behavior baseline) and flags sudden deviations no signature knows — zero-day behaviour, compromised IoT devices, data exfiltration.
- **Correlates alerts into attack campaigns**, places them on a kill chain (Recon → Credential Access → Exploitation → Impact), **predicts the attacker's next move** with an online-learning Markov model, and shows a network-wide **AI Threat Level**.
- **Runs a deception honeypot** — fake Telnet / FTP / router-admin services. Anyone who touches them is hostile; their login attempts are captured and shown live.
- **Explains every decision** — real per-feature contribution values (TreeSHAP via XGBoost's own C++ core, no external `shap` package) plus a plain-English incident brief with severity and recommended action.
- **Tracks every device** on the LAN under a Zero Trust model — unverified by default, trust degrades on bad behavior, auto-blocked at zero.
- **Auto-blocks** malicious sources at the kernel level (`iptables` **or** `nftables`, auto-detected), with safeguards so the operator can never lock themselves out.
- **Displays everything** on a small screen in Chromium kiosk mode — and launches that kiosk by itself when you start the server from a terminal.

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

### The full detection stack

```
                         live packets (Scapy)
                                  |
          +-----------------------+------------------------+
          |                       |                        |
   per-flow features        burst trackers           decoy services
   (CIC-IDS-2017 style)     (src,dst) / dst-port     Telnet / FTP / web admin
          |                       |                        |
   ML cascade                Heuristics              Honeypot (deception)
   XGB+RF -> AE -> BiLSTM    scan / flood / brute    any visitor = hostile
          |                       |                        |
          +-----------+-----------+-----------+------------+
                      |                       |
          Adaptive Behavior Baseline    threat_alerts (SQLite)
          (per-device, unsupervised)            |
                      +-----------+-------------+
                                  |
                  Campaign correlator + kill-chain predictor
                  -> campaign risk, AI Threat Level, next-stage forecast
                                  |
            +---------------------+----------------------+
            |                     |                      |
     Zero Trust scoring    Firewall (nft/iptables)   Dashboard + incident briefs
```

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
|  |                 nftables set  /  iptables DROP rules                 ||
|  |   blocked IPs dropped; dashboard (5000) + SSH (22) safeguarded      ||
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
| `pkt-capture` | Continuous | Scapy sniffs IP packets (auto-picks the default-route interface, restarts itself if it dies), builds bidirectional flow statistics + feeds the heuristic trackers |
| `heuristics` | Every 1 s (`EDGE_HEURISTIC_INTERVAL`) | Checks the scan / flood / brute-force trackers over an 8 s sliding window, persists + blocks + penalises |
| `flow-drain` | Every 2 s (`EDGE_FLOW_INTERVAL`) | Drains the flow table, classifies the whole batch in one ML call, feeds the behavior baseline, persists results |
| `campaigns` | Every 1.5 s | Feeds every stored alert into the campaign correlator (kill-chain, risk, prediction); optional pre-emptive blocking |
| `honeypot-<port>` | Continuous | One listener thread per decoy port; bounded concurrent sessions |
| `arp-scanner` | Every 60 s (`EDGE_ARP_INTERVAL`) | ARP scan (device discovery) |
| `wifi-scanner` | Every 60 s | WiFi SSID scan (Evil Twin / Beacon Flood) — own thread so its ~15 s rescan never delays ARP |
| `baseline-save` | Every 5 min | Persists the behavior baseline and the learned kill-chain transition matrix |
| `health-log` | Every 15 s | Logs capture liveness; warns if no packets arrived (wrong interface?) |
| `db-prune` | Every 30 min (`EDGE_DB_PRUNE_INTERVAL`) | Caps `network_flows`/`threat_alerts` row counts so the SQLite file doesn't grow unbounded |

Plus, optionally, `deauth_monitor.py` as its **own separate process** (not a thread inside `app.py`) — see [Attack Simulation Tools](#testing--attack-simulation).

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
|             +-- Soft vote on P(malicious)          |
|  Random     |   mean >= 0.6 and neither < 0.3      |
|  Forest  ---+                                      |
|                                                    |
|  Confidence: the real mean probability             |
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

### Batch scoring and real confidence

All flows drained in one window go through **one** `predict_proba` call per tree model (per-call overhead dominates for single rows on a Pi); the deep stages then run per flow only on flows the trees called benign. Stage 1 no longer reports a hard-coded 0.99: the confidence is the mean of the two models' probabilities, and the vote is *soft* — strict "both above 0.5" missed floods where XGBoost said 0.99 but the Random Forest sat at 0.58. Tune with `EDGE_TREE_THRESHOLD` (default `0.6`).

Flows with fewer than 2 packets, traffic the Pi itself initiates, and multicast/broadcast traffic (mDNS, SSDP, DHCP) are ignored before classification.

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
_SCAN_PORT_THRESHOLD = 10          # distinct ports touched = scan candidate
_SCAN_MAX_AVG_PKTS_PER_PORT = 5    # below this density with many ports -> PortScan
_FLOOD_PACKET_THRESHOLD = 100      # packets in one window, concentrated -> DDoS/Flood
_TRACKER_WINDOW_SECONDS = 8        # sliding window (an nmap / nping run takes 3–6 s)
_HEURISTIC_COOLDOWN_SECONDS = 2    # per (type, src, dst) re-alert cooldown
```

The trackers are checked **every second** over a sliding window, so an attack is flagged the moment it crosses a threshold rather than when a fixed window ends; an alerted entry restarts its window so one attack isn't counted forever. Confidence is calibrated as `min(0.80 + (count / (threshold × 2)) × 0.20, 1.0)`, so crossing a threshold immediately yields ≥ 0.85 — the auto-block bar. Traffic originating from the Pi itself is never counted.

### Brute Force

Tracked per `(src_ip, dst_ip, dst_port)` — counts fresh SYN packets (SYN without ACK = a new connection attempt, not a response) at a *single* port. Same underlying shape as a scan (many small attempts), but concentrated on one port instead of spread across many — the signature of repeated login attempts.

```python
_BRUTEFORCE_ATTEMPT_THRESHOLD = 6   # connection attempts to one dst:port in the window
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

Not run inside `network_scanner.py`, because it needs the WiFi radio in **monitor mode**, which is mutually exclusive with normal station-mode networking on a single radio. See [Attack Simulation Tools](#testing--attack-simulation) for `deauth_monitor.py`.

---

## Adaptive Behavior Baseline (Unsupervised AI)

`behavior.py` — the supervised models only know attacks from CIC-IDS-2017, and the heuristics only know fixed thresholds. This module learns what is **normal for each individual device on this network** and flags sudden deviations, so a device that suddenly talks to 40 hosts or pushes 50× its usual bytes is caught even when the traffic matches no known signature.

- Every flow-drain window, flows are grouped per source IP into a feature vector: **flows, packets, bytes, distinct destination IPs, distinct destination ports, SYN count**.
- Each feature keeps a running mean/variance (Welford) per device — O(1) memory.
- **Learning phase:** the first `EDGE_BASELINE_LEARN` windows (default 30, ~1 min) only train the baseline.
- **Scoring:** a robust z-score per feature, with the std floored (`max(std, absolute floor, 25 % of mean)`) and a minimum absolute change required, so quiet devices don't produce noise. Only *upward* deviations count.
- A device is flagged when its worst z-score stays ≥ `EDGE_BASELINE_Z` (default 6) for `EDGE_BASELINE_CONSEC` (default 2) consecutive windows, with a 30 s cooldown.
- **No poisoning:** anomalous windows are *not* folded into the baseline; normal windows keep adapting it, so slow drift is learned without alerting.
- Alerts are **advisory** (`threat_class = "Behavioral Anomaly"`, `detected_by = "Adaptive Baseline AI"`, never auto-blocks on its own — it is statistical) but still lower the device's Zero Trust score. The XAI list names the deviating features with the device's normal value, e.g. *"distinct hosts contacted (normal ≈ 2)"*.
- Baselines persist to `behavior_baseline.json` every 5 minutes, so a reboot doesn't reset the learning.

---

## Attack Campaign Correlation & Predictive Kill-Chain

`campaign.py` — individual alerts say "something bad happened"; real attacks are *sequences*. Every stored alert (heuristic, ML, WiFi, honeypot, behavioral, manual ingest) is fed to the correlator, which groups a source's alerts into a **campaign** (a gap of more than 15 minutes starts a new one).

**Kill chain stages:**

| Stage | Examples |
|---|---|
| 0 · Recon | Port Scan, honeypot probe |
| 1 · Credential Access | Brute Force, honeypot login attempt, Evil Twin |
| 2 · Exploitation | ML "Malicious", Behavioral Anomaly |
| 3 · Impact | DDoS / Flood, Beacon Flood |

**Three AI outputs:**

1. **Next-stage prediction** — a first-order Markov model over the four stages. The transition matrix starts from kill-chain prior knowledge and **keeps learning online** from every attack sequence this node observes, so predictions adapt to the threats actually seen on *this* network (e.g. after 40 observed scan→flood attacks, a new scanner's predicted next stage moves from Credential Access 38 % to Impact 85 %). Persisted to `campaign_model.json`; delete that file to reset what it learned.
2. **Campaign risk (0–100)** — kill-chain depth, persistence, mean detector confidence, breadth of techniques, with an exponential decay so risk fades when an attacker goes quiet.
3. **AI Threat Level (0–100)** — all active campaigns fused by noisy-OR (independent attackers compound), labelled `CALM` / `ELEVATED` / `HIGH` / `SEVERE`.

The Home screen shows the Threat Level bar and, under the last threat, the kill chain (`Recon ×12 ▸ Credential Access ×11 · risk 71 · next: Impact 62 %`). The Explain tab shows the same for any alert.

**Optional pre-emptive blocking:** set `EDGE_PREEMPTIVE=1` and an attacker whose campaign passes `EDGE_PREEMPT_RISK` (default 80) across at least two techniques is blocked before it finishes. Off by default; protected IPs are never blocked.

---

## Deception Honeypot

`honeypot.py` — the Pi opens **decoy services on ports no legitimate device uses** (default: Telnet `:23`, FTP `:21`, a router-style web-admin login `:8080`). Detection is trivial and almost free of false positives: *any* connection is hostile reconnaissance or a login attempt. Unlike the statistical detectors it needs no baseline and fires on the first packet.

- **Captures what the attacker tried** — usernames/passwords (Telnet, FTP, web form) and the HTTP request line + `User-Agent` (e.g. `sqlmap/1.7`). Credentials are kept even if the attacker hangs up mid-login.
- **Graduated response:** a lone probe raises a high-confidence alert (`Honeypot Probe`, 92 %) but does **not** block — a LAN device could wander onto `:8080` by accident. A **credential attempt** or touching **2+ distinct decoys within a minute** raises `Honeypot Credential Capture` / 99 % and blocks the source.
- Protected addresses (the Pi, its gateway, `EDGE_WHITELIST`) are alerted but never blocked.
- **Safe by construction:** decoys only speak a few lines of protocol — no commands executed, no filesystem access, input capped at 4 KB, 8 s timeout, at most 40 concurrent sessions (a 200-connection flood peaked at 44 threads and fully drained).
- Feeds the campaign kill-chain and the incident brief ("Deception trigger (high-fidelity)").
- Shown live on the dedicated **Decoy** tab. `EDGE_HONEYPOT=0` disables it; `EDGE_HONEYPOT_PORTS="2323:telnet,2121:ftp,8081:http"` changes the ports. A port already in use is skipped with a warning.

---

## XAI — Explainable AI & Incident Briefs

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

### Plain-English incident briefs

`explain.py` turns an alert and its evidence into a short brief on the **Explain** tab: a **severity** badge (`LOW` → `CRITICAL`), a category, *what happened*, the *key evidence*, a **recommended action**, and — when available — the attacker's kill chain, campaign risk and predicted next stage. It covers port scans, floods, brute force, behavioral anomalies, rogue access points, beacon floods, honeypot triggers and generic ML detections. It is template-based on purpose: deterministic, instant, no network or LLM on a Pi 4, and it can only describe evidence that is actually stored in the alert.

---

## Zero Trust Device Registry

> *"Never trust, always verify."*

Every device discovered by the ARP scanner starts at `status = unverified`, `trust_score = 100`.

```
penalty = confidence × 25.0
```

A single high-confidence detection (0.99) removes ~25 points; 4 such detections zero out the score. At `trust_score <= 0`, the device is marked `blocked` in `iot_devices` and dropped at the firewall. Every detector — ML, heuristics, behavioral anomaly, honeypot — applies the penalty. Manually marking a device `trusted` does **not** grant immunity — it's still penalized on further detections, matching genuine Zero Trust ("no permanent trust").

---

## Firewall Enforcement (Block / Unblock)

`firewall.py` enforces blocks and reports honestly whether they took effect.

- **Backend auto-detection:** `iptables` if present, else `nft`, else DB-only simulation (logged loudly). It searches `/usr/sbin` and `/sbin` explicitly — on Debian/Raspberry Pi OS a normal user's `PATH` lacks them, and a root process started via `sudo -E` inherits that `PATH`, which silently degraded blocking to DB-only in early versions.
- **`iptables` mode:** a rule is checked with `-C` before `-A`, so repeated attacks never stack duplicates; unblock removes **every** copy (`-D` deletes only one per call).
- **`nft` mode:** one `inet cybershield` table with a `blocked` set; adding/removing an element is naturally idempotent.
- **Operator safeguard:** the dashboard port (5000) and SSH (22) are ACCEPTed ahead of any block, so a test attack from your own PC can't cut your session. Attack traffic to every other port is dropped (a blocked scanner sees `999 filtered ports` and only `22/tcp open`).
- **Strict mode** (`EDGE_STRICT_BLOCK=1`): the block rule is placed *before* the management accepts, so a blocked IP is dropped on **every** port including 22 and 5000. Unblock from the Pi's own screen (kiosk) or a whitelisted IP.
- **Protected IPs** (never auto-blocked): the Pi itself, its default gateway, loopback, multicast/broadcast, and anything in `EDGE_WHITELIST` (comma-separated).
- **Persistence:** blocks recorded in the database are re-applied at startup — firewall rules don't survive a reboot.
- Unblock is available from the Blocked tab, from a button on the Home screen's Last Threat card, and via `POST`/`GET /api/unblock/<ip>`; the response says whether the firewall was actually cleared.

---

## Pi 4 (4GB) Optimizations

This section exists because the project's biggest engineering effort, after the flow-extraction rewrite, was fitting comfortably into 4GB of RAM. Every one of these is a direct response to something that broke or was too slow on the actual hardware.

| Optimization | Why |
|---|---|
| **`tflite-runtime` instead of full TensorFlow** | Full TF's ~400MB+ RSS and slow import were fine on an 8GB Pi 5, not on 4GB. `convert_to_tflite.py` (run once, off-device) produces quantized `.tflite` models; `ml_engine.py` loads those via `tflite_runtime.Interpreter` if present, falling back to full TF/`.h5` only if they're missing. |
| **Dropped `shap`** | Failed to build on 32-bit ARM (`numba`/`llvmlite` have no wheel there). Replaced with XGBoost's own native contribution computation — see [XAI](#xai--explainable-ai--incident-briefs). |
| **Dropped `pandas`** | Was a listed dependency but never actually imported anywhere in the code. |
| **Thread-capped ML models** | `EDGE_ML_THREADS` (default 2) caps XGBoost/RF/tflite internal thread pools so they don't oversubscribe the Pi 4's 4 cores against Flask + Scapy + (optionally) Chromium. |
| **Streaming flow statistics** | `_RunningStats` (Welford's algorithm) instead of storing every packet length/IAT — O(1) memory per flow regardless of how many packets a flood sends. |
| **Capped flow/scan tables** | `_MAX_FLOW_TABLE_ENTRIES = 4000` — a port scan/flood can't mint unbounded tracking entries between drains. |
| **Periodic DB pruning** | `db.prune_old_data()` caps `network_flows`/`threat_alerts` row counts (default 5000/2000) — unbounded growth on an SD card is a real problem over long uptimes. |
| **1GB swap + systemd memory limits** | `install.sh` provisions swap as an OOM safety net, and the systemd unit sets `MemoryMax=1600M`/`MemoryHigh=1300M` so the ML service can't crowd out Chromium, which shares the same 4GB continuously in kiosk mode. |
| **Memory-trimmed Chromium kiosk flags** | `--disable-gpu --disable-dev-shm-usage --disk-cache-size=1` — the kiosk autostart avoids GPU-compositing/shared-memory assumptions the 4GB Pi 4 can't spare. |
| **Batch ML scoring** | One `predict_proba` call per tree model per drain window instead of one per flow. |
| **Single shared SQLite connection** | One connection serialised by a Python lock — the whole app is one process, so SQLite file-locking was pure overhead and surfaced as "database is locked" 500s. WAL is enabled once; calls holding the DB > 2 s are logged by name. |
| **Kiosk profile in `/tmp`** | Chromium's profile/cache live in RAM — a kiosk needs no persistence, it spares the SD card, and it keeps working even if the home folder has filesystem errors. |
| **`EDGE_LITE_MODE`** | Full opt-out of Stage 2/3 + their tflite runtime overhead, tree-ensemble-only, for the tightest possible memory footprint. |

---

## File Structure

```
EDGE_SERVER/
|
+-- app.py                     Flask app — routes + background threads, ties every layer together, auto-elevates to root
+-- ml_engine.py                3-stage ML cascade (batch scoring, soft-vote confidence) + XGBoost-native XAI
+-- network_scanner.py          Packet capture, bidirectional flow features, ARP scan, WiFi scan,
|                                heuristic detectors (scan/flood/brute-force/evil-twin/beacon-flood), protected IPs
+-- behavior.py                 Adaptive per-device behavior baseline (online, unsupervised anomaly detection)
+-- campaign.py                 Attack-campaign correlator + Markov kill-chain predictor + AI Threat Level
+-- honeypot.py                 Deception honeypot: decoy Telnet / FTP / web-admin services
+-- explain.py                  Plain-English incident briefs (severity, evidence, recommended action)
+-- firewall.py                 iptables / nftables block + unblock enforcement, management-port safeguards
+-- db.py                       SQLite layer (single shared connection, WAL, no ORM)
+-- deauth_monitor.py           Standalone 802.11 deauth/disassoc flood detector (needs monitor mode)
+-- kiosk_launch.sh             Opens the dashboard in Chromium kiosk on the Pi's screen (called by app.py)
+-- convert_to_tflite.py        One-time Keras -> TFLite model converter (run off-device)
+-- demo_flows.py                Known-good ML-pipeline test payloads (benign + malicious)
+-- selftest.py                  End-to-end detection check — replays scan/flood/brute-force traffic, no root needed
+-- test_ml.py                   Smoke tests for the ML pipeline + DB
+-- test_heuristic.py / test_e2e.py   Additional heuristic / end-to-end tests
+-- generate_metrics.py / plot_metrics.py   Model evaluation report + plots  ->  metrics/
+-- requirements.txt             Python dependencies (Pi 4 / 32-bit-ARM aware)
+-- install.sh                   One-shot Pi 4 setup: packages, swap, venv, ml_models, systemd service
+-- start.sh                     Launch script (auto-elevates with sudo, opens the kiosk)
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
+-- metrics/                     Evaluation report (accuracy, ROC/PR curves, confusion matrix, feature importance …)
|
+-- static/                      Frontend SPA (served by Flask)
|   +-- index.html               6-page single-page app (Home/Alerts/Network/Blocked/Decoy/Explain)
|   +-- style.css
|   +-- app.js
|
+-- rpi_shield.db                SQLite database (auto-created on first run)
+-- behavior_baseline.json       Learned per-device baselines (auto-created)
+-- campaign_model.json          Learned kill-chain transition matrix (auto-created)
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

**Optional — for live attack testing:** an ESP8266 (Wemos D1 Mini) + SSD1306/SH1106 OLED + buttons, running `esp8266_attack_device.ino` and/or `deauth_test_device.ino` — see [Attack Simulation Tools](#testing--attack-simulation).

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

> **Note:** the kiosk is now also launched by the server itself whenever you run `bash start.sh` or `python app.py` (see [Running the Server & Kiosk Mode](#running-the-server--kiosk-mode)). Step 6 only sets up the older LXDE-style autostart; on current Raspberry Pi OS (Wayland/labwc) rely on `kiosk_launch.sh` instead.

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

## Running the Server & Kiosk Mode

### From a terminal (recommended for development and demos)

```bash
cd ~/EDGE_SERVER
bash start.sh
```

`start.sh` finds the virtualenv (`venv/` or `.venv/`), **re-launches itself under `sudo`** (packet capture and the firewall need root; the password comes from `EDGE_SUDO_PASSWORD`, default `pi`, so there is no prompt), starts the server, and **opens the dashboard in Chromium kiosk mode on the Pi's own screen**.

Examples:

```bash
EDGE_WHITELIST=192.168.0.200 bash start.sh        # never auto-block your admin PC
EDGE_STRICT_BLOCK=1 bash start.sh                 # blocked IPs dropped on ALL ports, incl. SSH/dashboard
EDGE_PREEMPTIVE=1 bash start.sh                   # block attackers predicted to escalate
EDGE_KIOSK=0 bash start.sh                        # server only, no Chromium
EDGE_IFACE=wlan0 bash start.sh                    # force the capture interface
```

### How the kiosk launches

The server runs as root, but Chromium must run as the logged-in **desktop user**. `kiosk_launch.sh` waits for the server, finds that user's graphical session (Wayland `wayland-0` or X11 `:0`) and starts Chromium inside it with `--kiosk`, a throw-away profile in `/tmp`, and `--password-store=basic` (so there is **no keyring-unlock password prompt**). It confirms Chromium is still alive after a few seconds and prints `[kiosk] …` messages (also in `/tmp/zeroday-kiosk.log`) explaining any failure.

**One requirement:** the Pi must be on its desktop, not a text login. Enable once:

```bash
sudo raspi-config nonint do_boot_behaviour B4     # desktop autologin
```

Leave kiosk mode with **Alt+F4** on a keyboard.

### As a boot-time service

```bash
sudo systemctl start cybershield-edge      # start
sudo systemctl stop cybershield-edge       # stop
sudo systemctl restart cybershield-edge    # restart (after any code change)
sudo systemctl status cybershield-edge     # is it running?
sudo journalctl -fu cybershield-edge       # live logs
```

`install.sh` enables the service at boot. Don't run the service and `start.sh` at the same time (both want port 5000).

Dashboard: `http://<rpi-ip>:5000` from any device on the LAN, or `http://localhost:5000` on the Pi.

### Diagnostics

```bash
curl http://localhost:5000/api/health       # capture liveness, packets seen, firewall backend, ML stages, behavior/campaign/honeypot status
sudo nft list ruleset | grep -A8 cybershield   # what the firewall is actually enforcing
```

---

## Frontend — Kiosk Dashboard

Six pages with bottom tab navigation, designed for a small touch/non-touch display in kiosk mode. Lists scroll when they outgrow the screen; the dashboard polls every 1–2 s, skips a poll if the previous one is still in flight, and never serves a stale cached bundle.

| Page | Contents |
|---|---|
| **Home** | KPI row (flows/threats/blocked), last-threat panel with **Unblock** button and kill-chain line, **AI Threat Level** bar, AI confidence bar, recent-threats feed (page scrolls) |
| **Alerts** | Full threat list — threat class, `detected_by`, source→dest, blocked status, timestamp |
| **Network** | Zero Trust device list (Trust/Block per device), **Scan** button (manual ARP refresh), **Clear** button (wipes all alerts/flows/blocked-IPs/device-registry — confirms first, also removes the firewall blocks; useful before a demo run-through) |
| **Blocked** | Every blocked IP with its threat class, confidence, detector and a one-tap **Unblock** |
| **Decoy** | Honeypot status (LIVE + listening ports), counters (hits / logins tried / attackers) and a live feed of every visitor with the **credentials they tried** |
| **Explain** | Alert selector, **AI incident brief** (severity, summary, evidence, action, kill chain + predicted next stage) and the XAI feature-contribution bars |

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the dashboard SPA |
| `GET` | `/api/health` | Capture liveness (packets seen, interface, errors), firewall backend, ML stages loaded, behavior-baseline / campaign / honeypot status |
| `GET` | `/api/stats` | Dashboard KPIs (flows, threats, blocked, avg confidence, uptime, last alert) plus `ai`: threat level, label and top active campaigns (kill chain, risk, predicted next stage) |
| `GET` | `/api/honeypot` | Decoy status, ports, counters and recent visitors with captured credentials |
| `GET` | `/api/alerts?limit=20&threats_only=false` | Recent alerts |
| `GET` | `/api/xai/<alert_id>` | XAI feature contributions, plus the plain-English `explanation` and the source's `campaign` (kill chain, risk, prediction) |
| `GET` | `/api/network` | Cached ARP-discovered devices |
| `GET` | `/api/blocked` | Currently blocked IPs |
| `POST` | `/api/clear` | Wipe all alerts/flows/blocked-IPs/device-registry (also removes the matching firewall blocks) |
| `POST` | `/api/ingest` | Submit a flow dict directly for ML classification (external sensors, or manual testing — see `demo_flows.py`) |
| `POST` | `/api/block/<ip>` | Manually block an IP; response reports whether the firewall `enforced` it |
| `POST`/`GET` | `/api/unblock/<ip>` | Remove a block (every firewall rule copy); response reports `firewall_cleared` |
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

## Testing & Attack Simulation

### `selftest.py` — end-to-end detection check (no root, no network)

Builds synthetic Scapy packets (port scan, SYN flood, SSH brute force, a DoS-like flow, normal browsing), pushes them through the **real** sniffer callback, then runs the same drain + classify path `app.py` uses. Proves the whole pipeline works independent of live traffic — and that normal browsing does *not* alert.

```bash
./venv/bin/python selftest.py        # ends with: RESULT: ALL PASS
./venv/bin/python test_ml.py         # ML pipeline + DB smoke tests
```

### Live attacks from another machine

```bash
nmap -sS -p 1-1000 <pi-ip>                              # Port Scan heuristic
nping --tcp -p 80 --flags syn -c 500 <pi-ip>            # DDoS / Flood heuristic
nmap -sS -p 21,23,8080 <pi-ip>                          # Honeypot probes
nmap -Pn -T4 -p 1-1000 <pi-ip>                          # verify a block: expect "filtered" (ARP host-discovery can't be firewalled)
```

Run a scan, then a password guess, then a flood and watch the **AI Threat Level** climb and the kill chain grow on the Home screen. Tip: whitelist your PC (`EDGE_WHITELIST`) if you don't want the test to block it.

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
| `EDGE_LITE_MODE` | `0` | `ml_engine.py` | `1` = skip Stage 2/3, tree-ensemble-only |
| `EDGE_ML_THREADS` | `2` | `ml_engine.py` | Thread cap for XGBoost/RF/tflite |
| `EDGE_TREE_THRESHOLD` | `0.6` | `ml_engine.py` | Mean P(malicious) the tree ensemble needs to flag a flow |
| `EDGE_FLOW_INTERVAL` | `2` | `app.py` | Seconds between flow-drain/classify passes |
| `EDGE_HEURISTIC_INTERVAL` | `1` | `app.py` | Seconds between scan/flood/brute-force checks |
| `EDGE_ARP_INTERVAL` | `60` | `app.py` | Seconds between ARP + WiFi SSID scans |
| `EDGE_DB_PRUNE_INTERVAL` | `1800` | `app.py` | Seconds between DB row-count pruning passes |
| `EDGE_IFACE` | auto (default route) | `app.py` | Network interface to sniff, e.g. `wlan0` / `eth0` |
| `EDGE_WHITELIST` | — | `network_scanner.py` | Comma-separated IPs that are never auto-blocked (your admin PC) |
| `EDGE_STRICT_BLOCK` | `0` | `firewall.py` | `1` = blocked IPs are dropped on every port, including 22 and 5000 |
| `EDGE_PREEMPTIVE` | `0` | `app.py` | `1` = block attackers whose campaign is predicted to escalate |
| `EDGE_PREEMPT_RISK` | `80` | `campaign.py` | Campaign risk that triggers pre-emptive blocking |
| `EDGE_BASELINE_LEARN` | `30` | `behavior.py` | Windows used to learn a device's baseline before scoring |
| `EDGE_BASELINE_Z` | `6.0` | `behavior.py` | z-score needed to call a window anomalous |
| `EDGE_BASELINE_CONSEC` | `2` | `behavior.py` | Consecutive anomalous windows required before alerting |
| `EDGE_HONEYPOT` | `1` | `app.py` | `0` = disable the decoy services |
| `EDGE_HONEYPOT_PORTS` | `23:telnet,21:ftp,8080:http` | `honeypot.py` | Decoy ports and the protocol each speaks |
| `EDGE_KIOSK` | `1` | `app.py` / `kiosk_launch.sh` | `0` = don't open Chromium on the Pi's screen |
| `EDGE_KIOSK_USER` | the user who ran `sudo` | `kiosk_launch.sh` | Desktop user Chromium runs as |
| `EDGE_PORT` | `5000` | `firewall.py` / `kiosk_launch.sh` | Dashboard port used for the safeguard rule and kiosk URL |
| `EDGE_SUDO_PASSWORD` | `pi` | `start.sh` / `app.py` | Password fed to `sudo -S` when auto-elevating |
| `EDGE_NO_SUDO` | — | `app.py` | `1` = don't auto-elevate (already root, e.g. under systemd) |
| `LITE_KIOSK` | `0` | `install.sh` (install-time only) | `1` = skip installing the Chromium kiosk, headless deploy |

### Detection thresholds

```python
# ml_engine.py
_AUTO_BLOCK_THRESHOLD      = 0.85
_AUTOENCODER_MSE_THRESHOLD = 50.0
_BILSTM_PROB_THRESHOLD     = 0.98

# network_scanner.py
_SCAN_PORT_THRESHOLD          = 10
_SCAN_MAX_AVG_PKTS_PER_PORT   = 5
_FLOOD_PACKET_THRESHOLD       = 100
_BRUTEFORCE_ATTEMPT_THRESHOLD = 6
_TRACKER_WINDOW_SECONDS       = 8
_HEURISTIC_COOLDOWN_SECONDS   = 2
_BEACON_FLOOD_SSID_THRESHOLD  = 25
_ALERT_COOLDOWN_SECONDS       = 30
_MAX_FLOW_TABLE_ENTRIES       = 4000

# behavior.py — see the baseline section
LEARN_WINDOWS = 30; Z_THRESHOLD = 6.0; CONSECUTIVE = 2

# campaign.py
_CAMPAIGN_GAP_S = 900; _ACTIVE_S = 1800; _HALF_LIFE_S = 600; PREEMPT_RISK = 80

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
- **`sudo` password is a convention, not a secret.** `start.sh` / `app.py` default `EDGE_SUDO_PASSWORD` to `pi` so the device runs with no prompts. Change it (or run the systemd service, which needs no password) on anything that isn't a lab device.
- **Management ports are always reachable by default.** Dashboard (5000) and SSH (22) are accepted ahead of any block so an operator can't be locked out, which means a blocked attacker can still *reach* those two ports unless `EDGE_STRICT_BLOCK=1`. The honeypot and heuristics still alert on attacks aimed at them.
- **ARP host discovery can't be firewalled.** On the same subnet, nmap finds the Pi via ARP regardless of IP-level blocks; use `-Pn` when verifying a block.
- **Behavior baseline and campaign model are statistical.** The baseline needs ~1 minute of a device's traffic before it can alert, only sees devices that generate traffic through the Pi, and its alerts never auto-block. The campaign model learns from *your* traffic — many repeated demo attacks will skew its predictions (delete `campaign_model.json` to reset).
- **The honeypot only protects the Pi's own address.** It sees what reaches the Pi; it is not a network-wide sensor, and a lone probe deliberately doesn't block (to avoid blocking a LAN device that wandered onto a decoy port).
- **A failing SD card breaks things in confusing ways.** "Structure needs cleaning" (`EUCLEAN`) from the filesystem means corruption on the card; run `fsck` and replace the card if `dmesg` shows repeated `mmc`/`I/O error` lines. The kiosk keeps its profile in `/tmp` to stay independent of it.
