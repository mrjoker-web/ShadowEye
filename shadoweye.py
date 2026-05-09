#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════╗
# ║              ShadowEye — Network Monitor v1.0               ║
# ║         Part of Shadow Suite by Mr Joker / mrjoker-web      ║
# ║   For educational purposes and authorized networks only.    ║
# ╚══════════════════════════════════════════════════════════════╝

import argparse
import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime
from threading import Thread, Lock

# ── Dependency check ──────────────────────────────────────────
MISSING = []
try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
except ImportError:
    MISSING.append("scapy")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.text import Text
    from rich import box
    from rich.style import Style
except ImportError:
    MISSING.append("rich")

if MISSING:
    print(f"[!] Missing dependencies: {', '.join(MISSING)}")
    print(f"    Install: pip install {' '.join(MISSING)}")
    sys.exit(1)

console = Console()

# ── Constants ─────────────────────────────────────────────────
VERSION  = "1.0.0"
BANNER   = r"""
[bold green]
 ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗    ███████╗██╗   ██╗███████╗
 ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║    ██╔════╝╚██╗ ██╔╝██╔════╝
 ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║    █████╗   ╚████╔╝ █████╗  
 ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║    ██╔══╝    ╚██╔╝  ██╔══╝  
 ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝    ███████╗   ██║   ███████╗
 ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝    ╚══════╝   ╚═╝   ╚══════╝
[/bold green][dim]                Network Monitor v{VERSION} — Shadow Suite by Mr Joker[/dim]
""".format(VERSION=VERSION)

# ── MAC OUI vendor lookup (offline, top vendors) ──────────────
OUI_TABLE = {
    "00:50:56": "VMware",          "00:0C:29": "VMware",
    "00:1A:11": "Google",          "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",    "E4:5F:01": "Raspberry Pi",
    "00:1B:63": "Apple",           "A4:C3:F0": "Apple",
    "F8:FF:C2": "Apple",           "3C:22:FB": "Apple",
    "00:11:22": "Cisc0",           "00:1E:13": "Cisco",
    "00:25:9C": "Cisco",           "18:B4:30": "Nest Labs",
    "00:17:88": "Philips Hue",     "EC:FA:BC": "Xiaomi",
    "28:6C:07": "Xiaomi",          "50:EC:50": "Huawei",
    "00:E0:FC": "Huawei",          "B4:0F:3B": "Samsung",
    "8C:71:F8": "Samsung",         "00:1D:A1": "Sony",
    "00:13:A9": "Sony",            "00:23:12": "TP-Link",
    "54:C9:DF": "TP-Link",         "14:CC:20": "TP-Link",
    "00:1F:90": "D-Link",          "1C:BD:B9": "D-Link",
    "00:26:5A": "Netgear",         "A0:21:B7": "Netgear",
    "00:18:E7": "Netgear",         "00:1C:10": "Asus",
    "04:D4:C4": "Asus",            "00:50:BA": "D-Link",
    "00:04:96": "Extreme Network", "00:00:0C": "Cisco",
    "00:24:E4": "Withings",        "00:0F:60": "Motorola",
    "40:49:0F": "Motorola",        "00:17:F2": "Apple",
}

def get_vendor(mac: str) -> str:
    mac_upper = mac.upper()
    prefix6 = mac_upper[:8]
    prefix8 = mac_upper[:11]
    for prefix, vendor in OUI_TABLE.items():
        if mac_upper.startswith(prefix.upper()):
            return vendor
    # Fallback: try system arp table or return Unknown
    return "Unknown"

# ── Utility functions ─────────────────────────────────────────
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_gateway() -> str:
    try:
        result = subprocess.check_output(
            "ip route | grep default | awk '{print $3}'",
            shell=True, text=True
        ).strip()
        return result or "N/A"
    except Exception:
        return "N/A"

def get_network_cidr(local_ip: str) -> str:
    try:
        result = subprocess.check_output(
            f"ip -o -f inet addr show | grep {local_ip}",
            shell=True, text=True
        ).strip()
        cidr = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', result)
        if cidr:
            net = ipaddress.ip_network(cidr.group(1), strict=False)
            return str(net)
    except Exception:
        pass
    # Fallback: assume /24
    parts = local_ip.rsplit('.', 1)
    return f"{parts[0]}.0/24"

def resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0]
        return name
    except Exception:
        return "—"

def ping_latency(ip: str) -> str:
    try:
        result = subprocess.check_output(
            f"ping -c 1 -W 1 {ip}",
            shell=True, text=True, stderr=subprocess.DEVNULL
        )
        match = re.search(r'time=([\d.]+)', result)
        return f"{match.group(1)} ms" if match else "—"
    except Exception:
        return "—"

def ttl_os_guess(ip: str) -> str:
    try:
        result = subprocess.check_output(
            f"ping -c 1 -W 1 {ip}",
            shell=True, text=True, stderr=subprocess.DEVNULL
        )
        match = re.search(r'ttl=(\d+)', result, re.IGNORECASE)
        if match:
            ttl = int(match.group(1))
            if ttl <= 64:
                return "Linux/Android"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Network Device"
    except Exception:
        pass
    return "—"

def quick_port_scan(ip: str, ports=(21,22,23,25,53,80,443,445,3389,8080,8443)) -> str:
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(str(port))
            s.close()
        except Exception:
            pass
    return ", ".join(open_ports) if open_ports else "—"

# ── ARP Scan ──────────────────────────────────────────────────
def arp_scan(network: str) -> list[dict]:
    devices = []
    try:
        arp  = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered, _ = srp(packet, timeout=2, retry=1)
        for sent, received in answered:
            devices.append({
                "ip":  received.psrc,
                "mac": received.hwsrc.upper(),
            })
    except Exception as e:
        console.print(f"[red][!] ARP scan error: {e}[/red]")
    return devices

# ── Enrich device info ────────────────────────────────────────
def enrich_device(dev: dict, local_ip: str, gateway: str, port_scan: bool) -> dict:
    ip  = dev["ip"]
    mac = dev["mac"]
    dev["vendor"]   = get_vendor(mac)
    dev["hostname"] = resolve_hostname(ip)
    dev["latency"]  = ping_latency(ip)
    dev["os_guess"] = ttl_os_guess(ip)
    dev["ports"]    = quick_port_scan(ip) if port_scan else "—"
    dev["role"]     = ("🏠 This Device" if ip == local_ip else
                       "🌐 Gateway"     if ip == gateway  else
                       "📱 Device")
    dev["first_seen"] = datetime.now().strftime("%H:%M:%S")
    return dev

# ── Rich Table builder ────────────────────────────────────────
def build_table(devices: list[dict], show_ports: bool) -> Table:
    t = Table(
        box=box.SIMPLE_HEAVY,
        border_style="green",
        header_style="bold green",
        show_lines=True,
        expand=True,
        title="[bold green]ShadowEye[/bold green] [dim]— Active Devices[/dim]",
        title_style="bold"
    )
    t.add_column("#",         style="dim",          width=3,  justify="right")
    t.add_column("IP Address", style="bold cyan",   min_width=15)
    t.add_column("MAC Address", style="yellow",     min_width=17)
    t.add_column("Vendor",     style="magenta",     min_width=14)
    t.add_column("Hostname",   style="white",       min_width=16)
    t.add_column("OS Guess",   style="blue",        min_width=14)
    t.add_column("Latency",    style="green",       min_width=9,  justify="right")
    if show_ports:
        t.add_column("Open Ports", style="red",     min_width=18)
    t.add_column("Role",       style="bold white",  min_width=14)
    t.add_column("Seen",       style="dim",         min_width=8)

    for i, d in enumerate(devices, 1):
        row = [
            str(i),
            d.get("ip", "—"),
            d.get("mac", "—"),
            d.get("vendor", "—"),
            d.get("hostname", "—"),
            d.get("os_guess", "—"),
            d.get("latency", "—"),
        ]
        if show_ports:
            row.append(d.get("ports", "—"))
        row += [d.get("role", "—"), d.get("first_seen", "—")]
        t.add_row(*row)
    return t

# ── Export ────────────────────────────────────────────────────
def export_results(devices: list[dict], fmt: str, path: str):
    try:
        if fmt == "json":
            with open(path, "w") as f:
                json.dump(devices, f, indent=2)
        elif fmt == "txt":
            with open(path, "w") as f:
                f.write(f"ShadowEye Report — {datetime.now()}\n")
                f.write("=" * 60 + "\n")
                for d in devices:
                    for k, v in d.items():
                        f.write(f"  {k:12}: {v}\n")
                    f.write("-" * 60 + "\n")
        console.print(f"[green][✔] Exported to {path}[/green]")
    except Exception as e:
        console.print(f"[red][!] Export error: {e}[/red]")

# ── Watch mode ────────────────────────────────────────────────
def watch_mode(network: str, local_ip: str, gateway: str,
               interval: int, port_scan: bool):
    known_macs: dict[str, dict] = {}
    lock = Lock()

    console.print(Panel(
        f"[bold green]WATCH MODE[/bold green] — Scanning [cyan]{network}[/cyan] every [yellow]{interval}s[/yellow]\n"
        "[dim]Press Ctrl+C to stop[/dim]",
        border_style="green"
    ))

    try:
        while True:
            raw = arp_scan(network)
            current_macs = {d["mac"]: d for d in raw}

            with lock:
                # New devices
                for mac, dev in current_macs.items():
                    if mac not in known_macs:
                        dev = enrich_device(dev, local_ip, gateway, port_scan)
                        known_macs[mac] = dev
                        console.print(
                            f"\n[bold red]⚠ NEW DEVICE DETECTED[/bold red] "
                            f"[cyan]{dev['ip']}[/cyan]  "
                            f"[yellow]{mac}[/yellow]  "
                            f"[magenta]{dev['vendor']}[/magenta]  "
                            f"[dim]{dev['first_seen']}[/dim]"
                        )
                    else:
                        known_macs[mac]["latency"] = ping_latency(dev["ip"])

                # Gone devices
                gone = [m for m in known_macs if m not in current_macs]
                for mac in gone:
                    d = known_macs.pop(mac)
                    console.print(
                        f"\n[dim]↩ DEVICE LEFT[/dim] "
                        f"[cyan]{d['ip']}[/cyan]  "
                        f"[yellow]{mac}[/yellow]  "
                        f"[magenta]{d['vendor']}[/magenta]"
                    )

                devices = list(known_macs.values())

            # Redraw table
            console.clear()
            console.print(BANNER)
            console.print(build_table(devices, port_scan))
            console.print(
                f"[dim]  Network: [cyan]{network}[/cyan]  |  "
                f"Devices: [green]{len(devices)}[/green]  |  "
                f"Next scan in [yellow]{interval}s[/yellow]  |  "
                f"{datetime.now().strftime('%H:%M:%S')}[/dim]\n"
            )
            time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Watch mode stopped.[/yellow]")

# ── Main scan ─────────────────────────────────────────────────
def run_scan(args):
    console.print(BANNER)

    local_ip = get_local_ip()
    gateway  = get_gateway()
    network  = args.network or get_network_cidr(local_ip)

    console.print(Panel(
        f"[bold]Local IP :[/bold]  [cyan]{local_ip}[/cyan]\n"
        f"[bold]Gateway  :[/bold]  [cyan]{gateway}[/cyan]\n"
        f"[bold]Network  :[/bold]  [cyan]{network}[/cyan]\n"
        f"[bold]Port Scan:[/bold]  [yellow]{'Yes' if args.ports else 'No'}[/yellow]",
        title="[bold green]ShadowEye Config[/bold green]",
        border_style="green"
    ))

    if args.watch:
        watch_mode(network, local_ip, gateway, args.interval, args.ports)
        return

    with console.status("[bold green]Scanning network via ARP...[/bold green]", spinner="dots"):
        raw_devices = arp_scan(network)

    if not raw_devices:
        console.print("[red][!] No devices found. Run as root/sudo.[/red]")
        return

    console.print(f"[green][✔] Found {len(raw_devices)} device(s). Enriching data...[/green]\n")

    devices = []
    for dev in raw_devices:
        with console.status(f"[dim]Enriching {dev['ip']}...[/dim]"):
            devices.append(enrich_device(dev, local_ip, gateway, args.ports))

    console.print(build_table(devices, args.ports))
    console.print(f"\n[dim]  Scan completed at {datetime.now().strftime('%H:%M:%S')} — {len(devices)} device(s) found[/dim]\n")

    if args.export:
        fmt = "json" if args.export.endswith(".json") else "txt"
        export_results(devices, fmt, args.export)

# ── CLI ───────────────────────────────────────────────────────
def main():
    if os.geteuid() != 0:
        print("[!] ShadowEye requires root privileges for ARP scanning.")
        print("    Run with: sudo python3 shadoweye.py")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        prog="shadoweye",
        description="ShadowEye — Network Device Monitor | Shadow Suite",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  sudo python3 shadoweye.py                        # auto-detect network
  sudo python3 shadoweye.py -n 192.168.1.0/24      # specific network
  sudo python3 shadoweye.py -p                     # include port scan
  sudo python3 shadoweye.py -w                     # watch mode (live)
  sudo python3 shadoweye.py -w -i 15               # watch every 15s
  sudo python3 shadoweye.py -e report.json         # export to JSON
  sudo python3 shadoweye.py -e report.txt          # export to TXT
        """
    )
    parser.add_argument("-n", "--network",  metavar="CIDR",
                        help="Target network (e.g. 192.168.1.0/24). Auto-detected if omitted.")
    parser.add_argument("-p", "--ports",    action="store_true",
                        help="Enable quick port scan per device (slower).")
    parser.add_argument("-w", "--watch",    action="store_true",
                        help="Watch mode: continuous monitoring with new device alerts.")
    parser.add_argument("-i", "--interval", type=int, default=30, metavar="SEC",
                        help="Watch mode scan interval in seconds (default: 30).")
    parser.add_argument("-e", "--export",   metavar="FILE",
                        help="Export results to file (.json or .txt).")
    parser.add_argument("-v", "--version",  action="version",
                        version=f"ShadowEye v{VERSION}")

    args = parser.parse_args()
    run_scan(args)

if __name__ == "__main__":
    main()
