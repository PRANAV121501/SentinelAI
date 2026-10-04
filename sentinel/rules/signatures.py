from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional
from sentinel.sniffer.protocol import PacketEvent, SecurityAlert


class ThreatDetector:
    """
    Stateful signature and heuristic-based threat detection engine.
    Maintains rolling time windows to detect port scans, floods, and brute force patterns.
    """

    def __init__(
        self,
        port_scan_threshold: int = 10,
        port_scan_window_secs: int = 15,
        syn_flood_threshold: int = 20,
        syn_flood_window_secs: int = 5,
        brute_force_threshold: int = 5,
        brute_force_window_secs: int = 60
    ):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = timedelta(seconds=port_scan_window_secs)

        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_window = timedelta(seconds=syn_flood_window_secs)

        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = timedelta(seconds=brute_force_window_secs)

        # State tracking:
        # (src_ip, dst_ip) -> list of (timestamp, dst_port)
        self._port_attempts: Dict[tuple, List[tuple]] = defaultdict(list)

        # dst_ip -> list of (timestamp, src_ip) for SYN packets
        self._syn_packets: Dict[str, List[tuple]] = defaultdict(list)

        # src_ip -> list of timestamp for failed auth events
        self._failed_auth: Dict[str, List[datetime]] = defaultdict(list)

        # To prevent alert spamming for the same ongoing incident
        self._alert_cooldown: Dict[str, datetime] = {}

    def _is_cooling_down(self, alert_key: str, now: datetime, cooldown_secs: int = 30) -> bool:
        if alert_key in self._alert_cooldown:
            if (now - self._alert_cooldown[alert_key]).total_seconds() < cooldown_secs:
                return True
        self._alert_cooldown[alert_key] = now
        return False

    def process_packet(self, packet: PacketEvent) -> List[SecurityAlert]:
        """Inspects a packet event and returns any security alerts triggered."""
        alerts: List[SecurityAlert] = []
        now = packet.timestamp

        # 1. Port Scan Detection (TCP SYN or UDP probes to multiple distinct ports)
        if packet.dst_port is not None and packet.src_ip and packet.dst_ip:
            key = (packet.src_ip, packet.dst_ip)
            # Prune older entries outside the window
            self._port_attempts[key] = [
                (ts, p) for ts, p in self._port_attempts[key]
                if now - ts <= self.port_scan_window
            ]
            self._port_attempts[key].append((now, packet.dst_port))

            unique_ports: Set[int] = {p for _, p in self._port_attempts[key]}
            if len(unique_ports) >= self.port_scan_threshold:
                alert_key = f"PORTSCAN:{packet.src_ip}->{packet.dst_ip}"
                if not self._is_cooling_down(alert_key, now):
                    alerts.append(SecurityAlert(
                        timestamp=now,
                        rule_name="Horizontal/Vertical Port Scan",
                        severity="HIGH",
                        source_ip=packet.src_ip,
                        target_ip=packet.dst_ip,
                        description=(
                            f"Host {packet.src_ip} probed {len(unique_ports)} distinct ports "
                            f"on {packet.dst_ip} within {self.port_scan_window.total_seconds()}s"
                        ),
                        evidence={"scanned_ports": sorted(list(unique_ports))[:20], "total_probes": len(self._port_attempts[key])},
                        mitre_technique="T1046 (Network Service Discovery)"
                    ))

        # 2. SYN Flood Detection (High rate of TCP SYN packets to a destination)
        if packet.protocol == "TCP" and "S" in packet.flags and packet.dst_ip:
            self._syn_packets[packet.dst_ip] = [
                (ts, src) for ts, src in self._syn_packets[packet.dst_ip]
                if now - ts <= self.syn_flood_window
            ]
            self._syn_packets[packet.dst_ip].append((now, packet.src_ip))

            if len(self._syn_packets[packet.dst_ip]) >= self.syn_flood_threshold:
                alert_key = f"SYNFLOOD:{packet.dst_ip}"
                if not self._is_cooling_down(alert_key, now):
                    alerts.append(SecurityAlert(
                        timestamp=now,
                        rule_name="TCP SYN Flood (DoS)",
                        severity="CRITICAL",
                        source_ip=packet.src_ip,
                        target_ip=packet.dst_ip,
                        description=(
                            f"Target {packet.dst_ip} received {len(self._syn_packets[packet.dst_ip])} SYN packets "
                            f"in {self.syn_flood_window.total_seconds()}s"
                        ),
                        evidence={"syn_packet_count": len(self._syn_packets[packet.dst_ip])},
                        mitre_technique="T1498.001 (Direct Network Flood)"
                    ))

        return alerts

    def process_auth_failure(self, src_ip: str, target_user: str, timestamp: Optional[datetime] = None) -> Optional[SecurityAlert]:
        """Tracks failed authentication attempts and alerts on brute force patterns."""
        now = timestamp or datetime.now()
        self._failed_auth[src_ip] = [
            ts for ts in self._failed_auth[src_ip]
            if now - ts <= self.brute_force_window
        ]
        self._failed_auth[src_ip].append(now)

        if len(self._failed_auth[src_ip]) >= self.brute_force_threshold:
            alert_key = f"BRUTEFORCE:{src_ip}"
            if not self._is_cooling_down(alert_key, now):
                return SecurityAlert(
                    timestamp=now,
                    rule_name="Authentication Brute Force",
                    severity="CRITICAL",
                    source_ip=src_ip,
                    target_ip="Localhost / Auth Gateway",
                    description=(
                        f"IP {src_ip} exceeded failure threshold with {len(self._failed_auth[src_ip])} "
                        f"failed login attempts targeting user '{target_user}'"
                    ),
                    evidence={"attempts": len(self._failed_auth[src_ip]), "targeted_user": target_user},
                    mitre_technique="T1110.001 (Password Guessing)"
                )
        return None
