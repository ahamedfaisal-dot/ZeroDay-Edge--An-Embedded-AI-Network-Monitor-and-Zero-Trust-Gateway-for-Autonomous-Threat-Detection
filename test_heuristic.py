"""Quick test of heuristic burst alerts."""
import sys, time
sys.path.insert(0, '.')
from network_scanner import _scan_table, _flow_lock, NetworkScanner

scanner = NetworkScanner(interface='eth0')
now = time.time()

# Simulate port scan: 500 distinct ports
with _flow_lock:
    entry = _scan_table[('10.0.0.5', '192.168.0.100')]
    entry['ports'] = set(range(500))
    entry['pkts'] = 500
    entry['bytes'] = 32000
    entry['start'] = now - 4.0

alerts = scanner.drain_burst_alerts()
print(f'Port scan heuristic alerts: {len(alerts)}')
for a in alerts:
    tc = a['threat_class']
    src = a['source_ip']
    conf = a['confidence']
    blocked = a['is_blocked']
    print(f'  {tc} from {src} conf={conf:.2f} blocked={blocked}')

# Simulate flood: 1000 packets on port 80
with _flow_lock:
    entry2 = _scan_table[('10.0.0.9', '192.168.0.100')]
    entry2['ports'] = {80}
    entry2['pkts'] = 1000
    entry2['bytes'] = 64000
    entry2['start'] = now - 4.0

alerts2 = scanner.drain_burst_alerts()
print(f'Flood heuristic alerts: {len(alerts2)}')
for a in alerts2:
    tc = a['threat_class']
    src = a['source_ip']
    conf = a['confidence']
    blocked = a['is_blocked']
    print(f'  {tc} from {src} conf={conf:.2f} blocked={blocked}')
