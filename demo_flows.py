"""
demo_flows.py — known-good demo payloads for showing the ML pipeline detect
a threat live, without depending on real captured traffic or hoping a
synthetic 4-field flow happens to cross the model's decision boundary.

Background: /api/ingest normally only gets 4 populated features from real
captured traffic (see network_scanner.py's drain_flows()), which is often
NOT enough for the tree ensemble to fire (confirmed empirically — see the
project conversation this came from). But ml_engine.py's _prepare_features
falls back to flow_data.get(col, 0.0) for ANY column name in the payload
that matches a trained feature name exactly, not just the 4 shortcut keys.
So a demo payload with realistic values across most/all 76 features has a
much better chance of actually landing on the "malicious" side of the
model's decision boundary, the way a real captured attack flow would.

Usage:
    python demo_flows.py --check          # classify locally, print result (no Flask needed)
    python demo_flows.py --send           # POST to a running local Flask server
    python demo_flows.py --send --benign  # send the benign flow instead
"""

import argparse
import json

import requests

BENIGN_FLOW = {
    "source_ip": "192.168.1.50",
    "destination_ip": "192.168.1.1",
    "Flow Duration": 1200000,
    "Tot Fwd Pkts": 8,
    "Tot Bwd Pkts": 7,
    "TotLen Fwd Pkts": 960,
    "TotLen Bwd Pkts": 4200,
    "Fwd Pkt Len Max": 200,
    "Fwd Pkt Len Min": 60,
    "Fwd Pkt Len Mean": 120,
    "Fwd Pkt Len Std": 45,
    "Bwd Pkt Len Max": 1400,
    "Bwd Pkt Len Min": 200,
    "Bwd Pkt Len Mean": 600,
    "Bwd Pkt Len Std": 300,
    "Flow Byts/s": 4300,
    "Flow Pkts/s": 12,
    "Flow IAT Mean": 85000,
    "Flow IAT Std": 40000,
    "Flow IAT Max": 200000,
    "Flow IAT Min": 5000,
    "Fwd PSH Flags": 1,
    "Fwd Header Len": 160,
    "Bwd Header Len": 140,
    "Pkt Len Min": 60,
    "Pkt Len Max": 1400,
    "Pkt Len Mean": 340,
    "SYN Flag Cnt": 1,
    "ACK Flag Cnt": 14,
    "FIN Flag Cnt": 1,
    "Init Fwd Win Byts": 29200,
    "Init Bwd Win Byts": 28960,
    "Fwd Seg Size Min": 20,
}

# Shaped like a SYN-flood / DDoS flow: huge packet count, tiny uniform
# packets, almost no backward traffic (target never responds), near-zero
# timing between packets, all SYN / no ACK.
MALICIOUS_FLOOD_FLOW = {
    "source_ip": "10.0.0.66",
    "destination_ip": "192.168.1.1",
    "Flow Duration": 250000,
    "Tot Fwd Pkts": 8000,
    "Tot Bwd Pkts": 2,
    "TotLen Fwd Pkts": 320000,
    "TotLen Bwd Pkts": 0,
    "Fwd Pkt Len Max": 60,
    "Fwd Pkt Len Min": 40,
    "Fwd Pkt Len Mean": 40,
    "Fwd Pkt Len Std": 2,
    "Bwd Pkt Len Max": 0,
    "Bwd Pkt Len Min": 0,
    "Bwd Pkt Len Mean": 0,
    "Bwd Pkt Len Std": 0,
    "Flow Byts/s": 1280000,
    "Flow Pkts/s": 32000,
    "Flow IAT Mean": 30,
    "Flow IAT Std": 5,
    "Flow IAT Max": 100,
    "Flow IAT Min": 1,
    "Fwd IAT Tot": 240000,
    "Fwd IAT Mean": 30,
    "Fwd IAT Std": 5,
    "Fwd IAT Max": 100,
    "Fwd IAT Min": 1,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Len": 160000,
    "Bwd Header Len": 40,
    "Fwd Pkts/s": 32000,
    "Bwd Pkts/s": 8,
    "Pkt Len Min": 0,
    "Pkt Len Max": 60,
    "Pkt Len Mean": 39,
    "Pkt Len Std": 3,
    "Pkt Len Var": 9,
    "FIN Flag Cnt": 0,
    "SYN Flag Cnt": 8000,
    "RST Flag Cnt": 0,
    "PSH Flag Cnt": 0,
    "ACK Flag Cnt": 2,
    "URG Flag Cnt": 0,
    "CWE Flag Count": 0,
    "ECE Flag Cnt": 0,
    "Down/Up Ratio": 0,
    "Pkt Size Avg": 39,
    "Fwd Seg Size Avg": 40,
    "Bwd Seg Size Avg": 0,
    "Subflow Fwd Pkts": 8000,
    "Subflow Fwd Byts": 320000,
    "Subflow Bwd Pkts": 2,
    "Subflow Bwd Byts": 0,
    "Init Fwd Win Byts": 29200,
    "Init Bwd Win Byts": -1,
    "Fwd Act Data Pkts": 0,
    "Fwd Seg Size Min": 20,
    "Active Mean": 250000,
    "Active Std": 0,
    "Active Max": 250000,
    "Active Min": 250000,
    "Idle Mean": 0,
    "Idle Std": 0,
    "Idle Max": 0,
    "Idle Min": 0,
}


def check_locally(flow: dict):
    from ml_engine import MLEngine
    engine = MLEngine()
    engine.load()
    result = engine.classify(flow)
    print(json.dumps(result, indent=2, default=str))
    return result


def send(flow: dict, url: str):
    resp = requests.post(url, json=flow, timeout=10)
    print(resp.status_code)
    print(json.dumps(resp.json(), indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Classify locally, no Flask server needed")
    parser.add_argument("--send", action="store_true", help="POST to a running Flask server's /api/ingest")
    parser.add_argument("--benign", action="store_true", help="Use the benign flow instead of the malicious one")
    parser.add_argument("--url", default="http://localhost:5000/api/ingest")
    args = parser.parse_args()

    flow = BENIGN_FLOW if args.benign else MALICIOUS_FLOOD_FLOW

    if args.check:
        check_locally(flow)
    elif args.send:
        send(flow, args.url)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
