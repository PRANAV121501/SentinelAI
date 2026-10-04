from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any


@dataclass
class PacketEvent:
    """Normalized network packet event for analysis."""
    timestamp: datetime
    protocol: str              # TCP, UDP, ICMP, ARP, etc.
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int = 0
    flags: str = ""            # e.g., 'SYN', 'ACK', 'FIN'
    raw_payload_len: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        sport = f":{self.src_port}" if self.src_port else ""
        dport = f":{self.dst_port}" if self.dst_port else ""
        flag_str = f" [{self.flags}]" if self.flags else ""
        return f"{self.protocol:4s} {self.src_ip}{sport} -> {self.dst_ip}{dport}{flag_str} ({self.length} bytes)"


@dataclass
class SecurityAlert:
    """Security alert raised by detection rules or AI models."""
    timestamp: datetime
    rule_name: str
    severity: str              # CRITICAL, HIGH, MEDIUM, LOW, INFO
    source_ip: str
    target_ip: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_technique: Optional[str] = None
