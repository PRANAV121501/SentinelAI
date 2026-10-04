import sys
import json
from datetime import datetime
from typing import List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from sentinel.sniffer.protocol import PacketEvent, SecurityAlert

# Ensure UTF-8 output on Windows terminals
if sys.platform.startswith("win") and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(highlight=False)


def print_banner():
    banner = Text(
        r"""
  ____  _____ _   _ _____ ___ _   _ _____ _        _    ___ 
 / ___|| ____| \ | |_   _|_ _| \ | | ____| |      / \  |_ _|
 \___ \|  _| |  \| | | |  | ||  \| |  _| | |     / _ \  | | 
  ___) | |___| |\  | | |  | || |\  | |___| |___ / ___ \ | | 
 |____/|_____|_| \_| |_| |___|_| \_|_____|_____/_/   \_\___|
        Autonomous Threat Detection Platform (v0.1.0)
        """,
        style="bold cyan"
    )
    console.print(banner)
    console.print("[dim]Year 1 Engine: Packet Inspector & Threat Correlator[/dim]\n")


def display_packet(packet: PacketEvent):
    """Displays a single packet with color-coded protocol."""
    proto_colors = {
        "TCP": "green",
        "UDP": "blue",
        "ICMP": "yellow",
        "OTHER": "magenta"
    }
    color = proto_colors.get(packet.protocol, "white")
    sport = f":{packet.src_port}" if packet.src_port else ""
    dport = f":{packet.dst_port}" if packet.dst_port else ""
    flags = f" [cyan]{packet.flags}[/cyan]" if packet.flags else ""

    console.print(
        f"[dim]{packet.timestamp.strftime('%H:%M:%S.%f')[:-3]}[/dim] "
        f"[{color}]{packet.protocol:4s}[/{color}] "
        f"[bold]{packet.src_ip}{sport}[/bold] -> [bold]{packet.dst_ip}{dport}[/bold]"
        f"{flags} ({packet.length} B)"
    )


def display_alert(alert: SecurityAlert):
    """Renders a high-visibility terminal alert panel."""
    severity_styles = {
        "CRITICAL": "bold white on red",
        "HIGH": "bold red",
        "MEDIUM": "bold yellow",
        "LOW": "bold green",
        "INFO": "dim cyan"
    }
    style = severity_styles.get(alert.severity, "bold red")

    content = (
        f"[bold]Incident:[/bold] {alert.rule_name}\n"
        f"[bold]Attacker IP:[/bold] [red]{alert.source_ip}[/red]\n"
        f"[bold]Target:[/bold] [yellow]{alert.target_ip}[/yellow]\n"
        f"[bold]Description:[/bold] {alert.description}\n"
        f"[bold]MITRE Technique:[/bold] [magenta]{alert.mitre_technique or 'N/A'}[/magenta]\n"
        f"[dim]Timestamp: {alert.timestamp.isoformat()}[/dim]"
    )

    console.print()
    console.print(Panel(content, title=f"[*] [{style}] SECURITY ALERT: {alert.severity} [/{style}] [*]", border_style="red"))
    console.print()


def export_alerts_to_json(alerts: List[SecurityAlert], output_file: str):
    """Exports a list of alerts to a standard JSON file."""
    data = []
    for a in alerts:
        data.append({
            "timestamp": a.timestamp.isoformat(),
            "rule_name": a.rule_name,
            "severity": a.severity,
            "source_ip": a.source_ip,
            "target_ip": a.target_ip,
            "description": a.description,
            "evidence": a.evidence,
            "mitre_technique": a.mitre_technique
        })

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]Successfully exported {len(alerts)} alert(s) to [bold]{output_file}[/bold][/green]")
