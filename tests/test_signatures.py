from datetime import datetime, timedelta
from sentinel.sniffer.protocol import PacketEvent
from sentinel.rules.signatures import ThreatDetector


def test_port_scan_detection():
    detector = ThreatDetector(port_scan_threshold=5, port_scan_window_secs=10)
    now = datetime.now()
    src = "192.168.1.50"
    dst = "10.0.0.1"

    alerts = []
    # Send packets to 6 distinct ports
    for p in range(1, 7):
        pkt = PacketEvent(
            timestamp=now + timedelta(milliseconds=p * 100),
            protocol="TCP",
            src_ip=src,
            dst_ip=dst,
            src_port=50000,
            dst_port=p,
            length=64,
            flags="S"
        )
        new_alerts = detector.process_packet(pkt)
        alerts.extend(new_alerts)

    assert len(alerts) >= 1
    assert alerts[0].rule_name == "Horizontal/Vertical Port Scan"
    assert alerts[0].source_ip == src
    assert alerts[0].target_ip == dst
    assert alerts[0].severity == "HIGH"


def test_syn_flood_detection():
    detector = ThreatDetector(syn_flood_threshold=5, syn_flood_window_secs=5)
    now = datetime.now()
    dst = "10.0.0.1"

    alerts = []
    for i in range(6):
        pkt = PacketEvent(
            timestamp=now + timedelta(milliseconds=i * 50),
            protocol="TCP",
            src_ip=f"192.168.1.{i+10}",
            dst_ip=dst,
            src_port=40000 + i,
            dst_port=80,
            length=54,
            flags="S"
        )
        new_alerts = detector.process_packet(pkt)
        alerts.extend(new_alerts)

    assert len(alerts) >= 1
    assert alerts[0].rule_name == "TCP SYN Flood (DoS)"
    assert alerts[0].severity == "CRITICAL"


def test_brute_force_detection():
    detector = ThreatDetector(brute_force_threshold=5, brute_force_window_secs=30)
    now = datetime.now()
    attacker = "203.0.113.10"

    alert = None
    for i in range(5):
        alert = detector.process_auth_failure(
            src_ip=attacker,
            target_user="admin",
            timestamp=now + timedelta(seconds=i * 2)
        )

    assert alert is not None
    assert alert.rule_name == "Authentication Brute Force"
    assert alert.source_ip == attacker
    assert alert.severity == "CRITICAL"
