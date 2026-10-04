import re
from datetime import datetime
from typing import List, Generator, Tuple
from aegis.rules.signatures import ThreatDetector
from aegis.sniffer.protocol import SecurityAlert

# Matches standard Linux sshd failed password messages:
# "Failed password for invalid user admin from 192.168.1.100 port 45122 ssh2"
# "Failed password for root from 10.0.0.15 port 51234 ssh2"
FAILED_SSH_REGEX = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
)


def parse_auth_line(line: str) -> Tuple[bool, str, str]:
    """Parses a single auth log line. Returns (is_failure, ip, user)."""
    match = FAILED_SSH_REGEX.search(line)
    if match:
        return True, match.group("ip"), match.group("user")
    return False, "", ""


def analyze_log_file(file_path: str, detector: ThreatDetector) -> List[SecurityAlert]:
    """Reads an authentication log file and returns any detected brute force alerts."""
    alerts: List[SecurityAlert] = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            is_fail, ip, user = parse_auth_line(line)
            if is_fail:
                alert = detector.process_auth_failure(src_ip=ip, target_user=user)
                if alert:
                    alerts.append(alert)
    return alerts
