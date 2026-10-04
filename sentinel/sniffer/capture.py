import random
import time
from datetime import datetime
from typing import Callable, Optional, Generator
import sys
from sentinel.sniffer.protocol import PacketEvent

# Attempt to import scapy; if Npcap is missing or user lacks permissions, fallback gracefully
try:
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)
    logging.getLogger("scapy.loading").setLevel(logging.CRITICAL)
    import io, os
    # Temporarily redirect stderr to silence 'No libpcap provider' banner on Windows
    _orig_stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
        conf.verb = 0
    finally:
        sys.stderr = _orig_stderr
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


def parse_scapy_packet(pkt) -> Optional[PacketEvent]:
    """Converts a raw Scapy packet into a normalized PacketEvent."""
    if not pkt.haslayer(IP):
        return None

    ip_layer = pkt[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    length = len(pkt)
    proto_name = "OTHER"
    src_port = None
    dst_port = None
    flags = ""

    if pkt.haslayer(TCP):
        proto_name = "TCP"
        tcp_layer = pkt[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        flags = str(tcp_layer.flags)
    elif pkt.haslayer(UDP):
        proto_name = "UDP"
        udp_layer = pkt[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
    elif pkt.haslayer(ICMP):
        proto_name = "ICMP"

    payload_len = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0

    return PacketEvent(
        timestamp=datetime.now(),
        protocol=proto_name,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        flags=flags,
        raw_payload_len=payload_len,
    )


def start_live_capture(
    interface: Optional[str] = None,
    filter_expr: Optional[str] = None,
    packet_callback: Optional[Callable[[PacketEvent], None]] = None,
    count: int = 0
):
    """Starts live packet capture using Scapy."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not properly configured. Ensure Npcap/WinPcap is installed for live capture.")

    def _internal_cb(pkt):
        event = parse_scapy_packet(pkt)
        if event and packet_callback:
            packet_callback(event)

    sniff(iface=interface, filter=filter_expr, prn=_internal_cb, count=count, store=False)


def generate_synthetic_traffic(
    count: int = 50,
    interval: float = 0.05,
    attack_simulation: Optional[str] = None
) -> Generator[PacketEvent, None, None]:
    """
    Generates synthetic network traffic for testing, education, and simulation.
    Can inject simulated attacks such as 'port_scan' or 'syn_flood'.
    """
    normal_ips = ["192.168.1.10", "192.168.1.25", "192.168.1.50", "192.168.1.100"]
    servers = ["10.0.0.5", "172.217.16.206", "1.1.1.1", "142.250.190.46"]
    common_ports = [80, 443, 22, 53, 8080, 3306]

    attacker_ip = "192.168.1.250"
    victim_ip = "10.0.0.5"

    for i in range(count):
        if attack_simulation == "port_scan" and i >= 10 and i <= 35:
            # Simulated horizontal/vertical port scan
            target_port = 20 + (i - 10) * 3
            event = PacketEvent(
                timestamp=datetime.now(),
                protocol="TCP",
                src_ip=attacker_ip,
                dst_ip=victim_ip,
                src_port=random.randint(40000, 60000),
                dst_port=target_port,
                length=64,
                flags="S",
                raw_payload_len=0
            )
        elif attack_simulation == "syn_flood" and i >= 10 and i <= 40:
            # Simulated SYN flood
            event = PacketEvent(
                timestamp=datetime.now(),
                protocol="TCP",
                src_ip=f"192.168.1.{random.randint(100, 240)}",
                dst_ip=victim_ip,
                src_port=random.randint(40000, 65000),
                dst_port=80,
                length=54,
                flags="S",
                raw_payload_len=0
            )
        else:
            proto = random.choice(["TCP", "UDP", "ICMP"])
            src = random.choice(normal_ips)
            dst = random.choice(servers)
            sport = random.randint(30000, 65000) if proto != "ICMP" else None
            dport = random.choice(common_ports) if proto != "ICMP" else None
            flags = "PA" if proto == "TCP" else ""

            event = PacketEvent(
                timestamp=datetime.now(),
                protocol=proto,
                src_ip=src,
                dst_ip=dst,
                src_port=sport,
                dst_port=dport,
                length=random.randint(64, 1500),
                flags=flags,
                raw_payload_len=random.randint(0, 1400)
            )

        yield event
        time.sleep(interval)
