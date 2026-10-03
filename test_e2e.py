"""
test_e2e.py — End-to-end test: simulate network_scanner producing a flow
and passing it through MLEngine, verifying no false positives on typical Pi traffic.
"""
import sys, time
sys.path.insert(0, '.')
from network_scanner import _FlowStats
from ml_engine import MLEngine

def make_http_flow():
    """Typical HTTP/HTTPS web browsing: 8 fwd + 6 bwd packets."""
    now = time.time()
    stats = _FlowStats(now - 2.0)
    for i in range(8):
        t = now - 2.0 + i * 0.25
        stats.add_packet('192.168.0.50', 54321, '1.2.3.4', 200, 52, 148, None, t)
    for i in range(6):
        t = now - 2.0 + i * 0.33 + 0.01
        stats.add_packet('1.2.3.4', 443, '192.168.0.50', 1400, 52, 1348, None, t)
    return stats.to_feature_dict(now, 'rpi-eth0')

def make_ssh_flow():
    """Typical SSH session: bidirectional ~250 byte packets."""
    now = time.time()
    stats = _FlowStats(now - 5.0)
    for i in range(50):
        t = now - 5.0 + i * 0.1
        stats.add_packet('192.168.0.200', 51234, '192.168.0.100', 250, 52, 198, None, t)
        stats.add_packet('192.168.0.100', 22, '192.168.0.200', 250, 52, 198, None, t + 0.01)
    return stats.to_feature_dict(now, 'rpi-eth0')

def make_flood_flow():
    """DDoS flood: 1000 small packets from one source in 5 seconds."""
    now = time.time()
    stats = _FlowStats(now - 5.0)
    for i in range(500):
        t = now - 5.0 + i * 0.01
        stats.add_packet('10.0.0.5', 1234, '192.168.0.100', 64, 20, 44, None, t)
    return stats.to_feature_dict(now, 'rpi-eth0')

engine = MLEngine()
engine.load()

print("\n=== End-to-End Flow Tests ===\n")

tests = [
    ("HTTP/HTTPS Browsing (benign)", make_http_flow(), "Benign"),
    ("SSH Session (benign)", make_ssh_flow(), "Benign"),
    ("DDoS Flood (malicious)", make_flood_flow(), None),
]

passed = 0
failed = 0
for name, flow, expected_class in tests:
    result = engine.classify(flow)
    tc = result['threat_class']
    conf = result['confidence']
    db = result['detected_by']
    ok = (expected_class is None) or (tc == expected_class)
    status = "PASS" if ok else "FAIL"
    if ok:
        passed += 1
    else:
        failed += 1
    exp_str = f"(expected={expected_class})" if expected_class else "(no expectation)"
    print(f"  {status}  {name}")
    print(f"         -> {tc}, confidence={conf:.4f}, by={db} {exp_str}")

print(f"\n  Results: {passed} passed, {failed} failed\n")
sys.exit(0 if failed == 0 else 1)
