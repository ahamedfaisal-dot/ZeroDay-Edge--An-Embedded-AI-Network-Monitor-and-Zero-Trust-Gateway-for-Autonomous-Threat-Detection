"""
selftest.py — end-to-end detection check, no root / network needed.

Builds synthetic Scapy packets (port scan, SYN flood, brute force, DoS-like
flow, normal browsing), pushes them through the REAL sniffer callback, then
runs the same drain + classify path app.py uses. Run on the Pi to prove the
pipeline works independent of live traffic:

    ./venv/bin/python selftest.py
"""
import logging
import random
import sys
import time

logging.disable(logging.CRITICAL)

import network_scanner as ns
from ml_engine import MLEngine

from scapy.all import IP, TCP, UDP, Raw  # noqa: E402

sc = ns.NetworkScanner()
ml = MLEngine()
ml.load()

ATK, VIC, USER = "192.168.77.5", "192.168.77.1", "192.168.77.20"
ok = True


def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {detail}")


def send(src, dst, sport, dport, flags="S", payload=b"", n=1):
    for _ in range(n):
        sc._handle_packet(IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / Raw(payload))


def reset():
    with ns._flow_lock:
        ns._flow_table.clear(); ns._scan_table.clear(); ns._bruteforce_table.clear()
    ns._heuristic_last_alert.clear()


print("1. Port scan (SYN to 100 ports)")
reset()
for p in range(1, 101):
    send(ATK, VIC, 40000, p, "S")
a = sc.drain_burst_alerts()
check("PortScan alert", any(x["threat_class"] == "PortScan" for x in a), f"-> {[x['threat_class'] for x in a]}")

print("2. SYN/UDP flood (1500 pkts to one port)")
reset()
send(ATK, VIC, 5555, 80, "S", n=1500)
a = sc.drain_burst_alerts()
check("DDoS/Flood alert", any(x["threat_class"] == "DDoS / Flood" for x in a), f"-> {[x['threat_class'] for x in a]}")

print("3. SSH brute force (40 fresh SYNs to :22, different source ports)")
reset()
for i in range(40):
    send(ATK, VIC, 50000 + i, 22, "S")
a = sc.drain_bruteforce_alerts()
check("Brute Force alert", any(x["threat_class"] == "Brute Force Attempt" for x in a), f"-> {[x['threat_class'] for x in a]}")

print("4. Normal browsing must NOT alert")
reset()
send(USER, VIC, 51000, 443, "S"); send(VIC, USER, 443, 51000, "SA")
for _ in range(20):
    send(USER, VIC, 51000, 443, "PA", b"x" * 300); send(VIC, USER, 443, 51000, "A", b"y" * 1400)
check("no burst alerts", not sc.drain_burst_alerts() and not sc.drain_bruteforce_alerts())
flows = sc.drain_flows()
res = ml.classify_batch(flows)
check("flow classified Benign", flows and all(r["threat_class"] == "Benign" for r in res),
      f"-> {[(r['threat_class'], r['confidence']) for r in res]}")

print("5. DoS-like flow through ML (many fwd packets, tiny IAT, no replies)")
reset()
for i in range(400):
    send(ATK, VIC, 60000, 80, "PA", b"GET / HTTP/1.1\r\n" * 4)
flows = sc.drain_flows()
res = ml.classify_batch(flows)
print("     ", [(r["threat_class"], r["confidence"]) for r in res])
check("ML produced a verdict for the flow", len(res) == 1)

print("\nRESULT:", "ALL PASS" if ok else "FAILURES — see above")
sys.exit(0 if ok else 1)
