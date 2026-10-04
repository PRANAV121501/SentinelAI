import sys
import click

if sys.platform.startswith("win") and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
from aegis import __version__
from aegis.storage.reporter import (
    print_banner,
    display_packet,
    display_alert,
    export_alerts_to_json,
    console
)
from aegis.sniffer.protocol import PacketEvent
from aegis.sniffer.capture import start_live_capture, generate_synthetic_traffic, SCAPY_AVAILABLE
from aegis.rules.signatures import ThreatDetector
from aegis.parsers.auth_log import analyze_log_file


@click.group()
def cli():
    """AegisNet: Autonomous Threat Detection & Incident Response Platform."""
    pass


@cli.command()
def version():
    """Display platform version and security engine status."""
    print_banner()
    console.print(f"[bold green]AegisNet Version:[/bold green] {__version__}")
    console.print(f"[bold cyan]Scapy Sniffer Status:[/bold cyan] {'Available' if SCAPY_AVAILABLE else 'Npcap/RawSocket not configured'}")
    console.print("[dim]Phase: Year 1 Foundations (Packet Analyzer & Heuristic Rule Engine)[/dim]\n")


@cli.command()
@click.option("--interface", "-i", default=None, help="Network interface name (e.g. eth0 or Wi-Fi).")
@click.option("--filter", "-f", "bpf_filter", default=None, help="BPF packet filter expression (e.g. 'tcp or udp').")
@click.option("--count", "-c", default=0, help="Number of packets to capture (0 = infinite).")
def sniff(interface, bpf_filter, count):
    """Start live network sniffing and real-time threat detection."""
    print_banner()
    console.print(f"[bold green]Starting live packet sniffing on interface:[/bold green] {interface or 'Default'}")
    if bpf_filter:
        console.print(f"[bold cyan]Filter:[/bold cyan] {bpf_filter}")
    console.print("[yellow]Press Ctrl+C to terminate.[/yellow]\n")

    detector = ThreatDetector()

    def on_packet(packet: PacketEvent):
        display_packet(packet)
        alerts = detector.process_packet(packet)
        for alert in alerts:
            display_alert(alert)

    try:
        start_live_capture(interface=interface, filter_expr=bpf_filter, packet_callback=on_packet, count=count)
    except KeyboardInterrupt:
        console.print("\n[bold red]Sniffing stopped by user.[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]Capture error:[/bold red] {e}")
        console.print("[yellow]Tip: Live raw packet capture often requires Administrator/root privileges or Npcap installed on Windows.[/yellow]")
        console.print("[cyan]You can run 'python -m aegis.cli simulate-attack' to test the detection engine with synthetic traffic.[/cyan]")


@cli.command()
@click.option("--type", "attack_type", type=click.Choice(["port_scan", "syn_flood", "normal"]), default="port_scan", help="Type of traffic/attack to simulate.")
@click.option("--count", "-n", default=50, help="Number of packets to simulate.")
@click.option("--interval", "-t", default=0.05, help="Delay between packets in seconds.")
@click.option("--export", "-o", default=None, help="Optional output JSON file to save triggered alerts.")
def simulate_attack(attack_type, count, interval, export):
    """Simulate network traffic and test real-time threat detection."""
    print_banner()
    console.print(f"[bold yellow]Simulating Network Scenario:[/bold yellow] [bold red]{attack_type.upper()}[/bold red]")
    console.print(f"[dim]Streaming {count} packets at {interval}s intervals...[/dim]\n")

    detector = ThreatDetector(port_scan_threshold=8, syn_flood_threshold=15)
    captured_alerts = []

    traffic = generate_synthetic_traffic(
        count=count,
        interval=interval,
        attack_simulation=None if attack_type == "normal" else attack_type
    )

    for packet in traffic:
        display_packet(packet)
        alerts = detector.process_packet(packet)
        for alert in alerts:
            display_alert(alert)
            captured_alerts.append(alert)

    console.print(f"\n[bold green]Simulation completed.[/bold green] Total Alerts Triggered: [bold red]{len(captured_alerts)}[/bold red]")
    if export and captured_alerts:
        export_alerts_to_json(captured_alerts, export)


@cli.command()
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--export", "-o", default=None, help="Optional output JSON file to save triggered alerts.")
def parse_logs(logfile, export):
    """Analyze authentication and system logs for brute force attacks."""
    print_banner()
    console.print(f"[bold green]Analyzing log file:[/bold green] {logfile}\n")

    detector = ThreatDetector(brute_force_threshold=5)
    alerts = analyze_log_file(logfile, detector)

    for alert in alerts:
        display_alert(alert)

    console.print(f"[bold green]Log analysis finished.[/bold green] Detected [bold red]{len(alerts)}[/bold red] threat incident(s).")
    if export and alerts:
        export_alerts_to_json(alerts, export)


def main():
    cli()


if __name__ == "__main__":
    main()
