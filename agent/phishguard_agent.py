#!/usr/bin/env python3
"""
PhishGuard Local Security Agent
================================
Runs on a user's local machine, scans the LAN, and sends results to
the PhishGuard backend API so the dashboard can display them.

Architecture:
    User Machine
        │
        └─► PhishGuard Local Agent  (this file)
                │
                └─► PhishGuard Backend API  (POST /api/v1/agent/network-report)
                        │
                        └─► PhishGuard Dashboard  (Next.js)

Usage:
    python phishguard_agent.py --backend https://your-api.railway.app
    python phishguard_agent.py --backend http://localhost:8000 --interval 60
    python phishguard_agent.py --backend https://your-api --token YOUR_JWT_TOKEN

Requirements:
    pip install psutil requests

Optional (for ARP scanning):
    pip install scapy
    Run with: sudo python phishguard_agent.py ...
"""

import argparse
import hashlib
import json
import logging
import platform
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Optional

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PhishGuard Agent] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("phishguard_agent")

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    import psutil
except ImportError:
    logger.error("psutil is required. Install with: pip install psutil")
    sys.exit(1)

try:
    import requests
except ImportError:
    logger.error("requests is required. Install with: pip install requests")
    sys.exit(1)

# Optional: scapy for ARP scanning
try:
    from scapy.all import ARP, Ether, srp  # type: ignore
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# OUI vendor table (same as backend)
# ─────────────────────────────────────────────────────────────────────────────
_OUI: dict[str, str] = {
    "ACBC32": "Apple", "3C0754": "Apple", "7CF05F": "Apple",
    "001A2F": "Cisco", "0023EB": "Cisco", "606BBD": "Cisco",
    "F4F26D": "TP-Link", "50C7BF": "TP-Link", "B0487A": "TP-Link",
    "A021B7": "Netgear", "20E52A": "Netgear",
    "002339": "Samsung", "84A466": "Samsung",
    "001372": "Dell", "D4AE52": "Dell",
    "001083": "HP", "3C4A92": "HP",
    "8C8D28": "Intel", "F8B156": "Intel",
    "B827EB": "Raspberry Pi", "DC2B61": "Raspberry Pi",
    "049226": "ASUS", "2C56DC": "ASUS",
    "00156D": "Ubiquiti", "245A4C": "Ubiquiti",
    "44650D": "Amazon", "34D270": "Amazon",
    "54607E": "Google", "F4F5E8": "Google",
    "001CF0": "D-Link", "14D64D": "D-Link",
    "000569": "VMware", "000C29": "VMware",
    "080027": "VirtualBox",
}

def _vendor(mac: str) -> str:
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    return _OUI.get(oui, "Unknown Vendor")


# ─────────────────────────────────────────────────────────────────────────────
# Device ID — stable per machine
# ─────────────────────────────────────────────────────────────────────────────
def _get_device_id() -> str:
    """Generate a stable device ID based on hostname + MAC address."""
    try:
        mac = hex(uuid.getnode()).replace("0x", "").upper()
        raw = f"{socket.gethostname()}-{mac}-{platform.node()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    except Exception:
        return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:16]


# ─────────────────────────────────────────────────────────────────────────────
# Network utilities
# ─────────────────────────────────────────────────────────────────────────────
def _default_gateway() -> Optional[str]:
    """Get default gateway IP."""
    try:
        # Linux
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                cols = line.split()
                if len(cols) >= 3 and cols[1] == "00000000":
                    return socket.inet_ntoa(struct.pack("<I", int(cols[2], 16)))
    except Exception:
        pass
    try:
        # macOS / fallback
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            if "gateway:" in line:
                return line.split("gateway:")[-1].strip()
    except Exception:
        pass
    try:
        # Windows
        result = subprocess.run(
            ["route", "print", "0.0.0.0"],
            capture_output=True, text=True, timeout=3
        )
        for line in result.stdout.splitlines():
            if "0.0.0.0" in line:
                parts = line.split()
                if len(parts) >= 3:
                    return parts[2]
    except Exception:
        pass
    return None


def _get_local_interfaces() -> list[dict]:
    """Get all local IPv4 interfaces with their subnets."""
    interfaces = []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for iface, addr_list in addrs.items():
            if iface in ("lo", "lo0"):
                continue
            st = stats.get(iface)
            if not st or not st.isup:
                continue
            for a in addr_list:
                if a.family == socket.AF_INET and a.address:
                    try:
                        import ipaddress
                        net = ipaddress.IPv4Network(f"{a.address}/{a.netmask}", strict=False)
                        if not net.is_private or net.prefixlen >= 31:
                            continue
                        # Get MAC
                        mac = None
                        for b in addr_list:
                            if b.family == psutil.AF_LINK:
                                mac = b.address
                                break
                        interfaces.append({
                            "name": iface,
                            "ip": a.address,
                            "netmask": a.netmask,
                            "network": str(net),
                            "mac": mac,
                        })
                    except Exception:
                        pass
    except Exception as e:
        logger.warning(f"Interface enumeration error: {e}")
    return interfaces


def _resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    """Reverse DNS lookup with timeout."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip
    finally:
        socket.setdefaulttimeout(old)


def _classify_device(hostname: str, vendor: str, open_ports: list, is_gateway: bool) -> str:
    h, v = hostname.lower(), vendor.lower()
    if is_gateway: return "Router / Gateway"
    if any(k in h for k in ["router", "gateway", "rt-", "-ap"]): return "Router / Gateway"
    if any(k in h for k in ["macbook", "imac", "mac-"]): return "Mac Computer"
    if any(k in h for k in ["iphone", "ipad"]): return "iPhone / iPad"
    if any(k in h for k in ["android", "galaxy", "pixel"]): return "Android Device"
    if any(k in h for k in ["printer", "canon", "epson", "brother"]): return "Printer"
    if any(k in h for k in ["server", "srv", "nas", "synology"]): return "Server / NAS"
    if any(k in h for k in ["cam", "camera", "nvr", "dvr"]): return "IP Camera"
    if any(k in h for k in ["tv", "smart-tv", "roku"]): return "Smart TV"
    if any(k in h for k in ["raspberry", "raspi"]): return "Raspberry Pi"
    if any(k in h for k in ["laptop", "thinkpad", "surface"]): return "Laptop"
    if "apple" in v: return "Apple Device"
    if any(k in v for k in ["cisco", "netgear", "tp-link", "asus", "ubiquiti"]): return "Network Device"
    if "raspberry" in v: return "Raspberry Pi"
    if any(k in v for k in ["samsung", "amazon", "google"]): return "Smart Device"
    if any(k in v for k in ["vmware", "virtualbox"]): return "Virtual Machine"
    if 3389 in open_ports: return "Windows PC"
    if 22 in open_ports and 80 in open_ports: return "Server / NAS"
    if 445 in open_ports: return "Windows PC"
    return "Computer / Device"


# ─────────────────────────────────────────────────────────────────────────────
# Scanning strategies
# ─────────────────────────────────────────────────────────────────────────────

def _scapy_arp_scan(network: str, iface: str) -> dict[str, str]:
    """ARP scan using scapy (requires root + scapy installed)."""
    if not _SCAPY_AVAILABLE:
        raise RuntimeError("scapy not available")
    logger.info(f"Scapy ARP scan: {network}")
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(packet, iface=iface, timeout=2, verbose=False)
    result = {}
    for _, rcv in answered:
        result[rcv.psrc] = rcv.hwsrc
    return result


def _arp_cache_scan() -> dict[str, str]:
    """Read OS ARP cache — zero privilege required."""
    result = {}
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                cols = line.split()
                if len(cols) >= 4 and cols[2] != "0x0" and cols[3] != "00:00:00:00:00:00":
                    result[cols[0]] = cols[3]
    except Exception:
        pass
    # Windows / macOS fallback via arp -a
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                ip = parts[0].strip("()")
                mac = parts[1] if ":" in parts[1] or "-" in parts[1] else (parts[2] if len(parts) > 2 else "")
                if mac and "ff:ff:ff:ff:ff:ff" not in mac.lower():
                    try:
                        socket.inet_aton(ip)
                        result[ip] = mac
                    except Exception:
                        pass
    except Exception:
        pass
    return result


_PROBE_PORTS = [80, 443, 22, 8080, 445, 3389, 5900, 21, 23, 8443]

def _tcp_probe(ip: str, timeout: float = 0.4) -> list[int]:
    open_ports = []
    for port in _PROBE_PORTS[:6]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports


def _tcp_probe_subnet(network_str: str, max_hosts: int = 256) -> dict[str, list[int]]:
    """TCP probe all hosts in subnet. Returns {ip: [open_ports]}."""
    import ipaddress
    net = ipaddress.IPv4Network(network_str)
    hosts = [str(h) for h in net.hosts()][:max_hosts]
    found: dict[str, list[int]] = {}
    lock = threading.Lock()

    def probe(ip):
        ports = _tcp_probe(ip)
        if ports:
            with lock:
                found[ip] = ports

    with ThreadPoolExecutor(max_workers=64) as ex:
        list(ex.map(probe, hosts))
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Main scan function
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScannedDevice:
    ip: str
    mac: str
    hostname: str
    vendor: str
    device_type: str
    is_gateway: bool
    is_this_machine: bool
    open_ports: list = field(default_factory=list)
    scan_method: str = "arp"
    status: str = "active"


def scan_network() -> dict:
    """
    Scan the local network and return a report dict.
    Tries scapy ARP → ARP cache → TCP probe → self-only.
    """
    t0 = time.monotonic()
    ts = datetime.utcnow().isoformat() + "Z"

    interfaces = _get_local_interfaces()
    gw = _default_gateway()
    my_hostname = socket.gethostname()

    if not interfaces:
        logger.warning("No local interfaces found")
        return {
            "devices": [], "total": 0, "scan_mode": "no_interfaces",
            "scanned_subnet": None, "duration_seconds": round(time.monotonic()-t0, 2),
            "scanned_at": ts, "gateway": gw,
        }

    primary = interfaces[0]
    subnet = primary["network"]
    iface_name = primary["name"]
    my_ip = primary["ip"]
    my_mac = primary.get("mac", "N/A")

    logger.info(f"Scanning {subnet} via {iface_name} (this machine: {my_ip})")

    # ── Strategy 1: Scapy ARP ──────────────────────────────────────────────
    scan_mode = "tcp_probe"
    ip_mac: dict[str, str] = {}

    try:
        ip_mac = _scapy_arp_scan(subnet, iface_name)
        if ip_mac:
            scan_mode = "arp_scapy"
            logger.info(f"Scapy ARP found {len(ip_mac)} hosts")
    except Exception as e:
        logger.debug(f"Scapy ARP failed: {e}")

    # ── Strategy 2: ARP cache supplement ──────────────────────────────────
    cache = _arp_cache_scan()
    for ip, mac in cache.items():
        if ip not in ip_mac:
            ip_mac[ip] = mac
    if ip_mac and scan_mode == "tcp_probe":
        scan_mode = "arp_cache"
        logger.info(f"ARP cache found {len(ip_mac)} hosts")

    # Always include self
    if my_ip not in ip_mac:
        ip_mac[my_ip] = my_mac or "N/A"

    # ── Strategy 3: TCP probe if ARP found nothing ─────────────────────────
    tcp_data: dict[str, list[int]] = {}
    if scan_mode == "tcp_probe" or len(ip_mac) <= 1:
        logger.info("Running TCP probe scan...")
        tcp_data = _tcp_probe_subnet(subnet, max_hosts=256)
        for ip in tcp_data:
            if ip not in ip_mac:
                ip_mac[ip] = "N/A (TCP)"
        if len(ip_mac) > 1:
            scan_mode = "tcp_probe"
            logger.info(f"TCP probe found {len(ip_mac)-1} additional hosts")

    # ── Build device list ──────────────────────────────────────────────────
    devices: list[ScannedDevice] = []
    lock = threading.Lock()

    def enrich(ip: str, mac: str):
        vendor = _vendor(mac) if mac not in ("N/A", "N/A (TCP)") else "Unknown"
        hostname = _resolve_hostname(ip)
        is_gw = ip == gw
        is_me = ip == my_ip
        ports = tcp_data.get(ip, [])
        device_type = _classify_device(hostname, vendor, ports, is_gw)
        method = "scapy_arp" if scan_mode == "arp_scapy" else scan_mode
        if is_me:
            device_type = f"This Machine ({my_hostname})"
            method = "interface"
        with lock:
            devices.append(ScannedDevice(
                ip=ip, mac=mac, hostname=hostname, vendor=vendor,
                device_type=device_type, is_gateway=is_gw,
                is_this_machine=is_me, open_ports=ports, scan_method=method,
            ))

    with ThreadPoolExecutor(max_workers=32) as ex:
        list(ex.map(lambda kv: enrich(*kv), ip_mac.items()))

    devices.sort(key=lambda d: tuple(int(x) for x in d.ip.split(".")))

    duration = round(time.monotonic() - t0, 2)
    logger.info(f"Scan complete: {len(devices)} devices in {duration}s ({scan_mode})")

    return {
        "devices": [asdict(d) for d in devices],
        "total": len(devices),
        "scan_mode": scan_mode,
        "scanned_subnet": subnet,
        "interface": iface_name,
        "gateway": gw,
        "duration_seconds": duration,
        "scanned_at": ts,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Backend communication
# ─────────────────────────────────────────────────────────────────────────────

def send_report(backend_url: str, report: dict, device_id: str, token: Optional[str] = None) -> bool:
    """POST scan results to the backend agent endpoint."""
    url = f"{backend_url.rstrip('/')}/api/v1/agent/network-report"
    payload = {"device_id": device_id, **report}

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=30)
        if resp.status_code == 200:
            logger.info(f"✅ Report accepted by backend ({resp.status_code})")
            return True
        else:
            logger.error(f"❌ Backend rejected report: {resp.status_code} — {resp.text[:200]}")
            return False
    except requests.ConnectionError:
        logger.error(f"❌ Cannot reach backend at {backend_url}")
        return False
    except Exception as e:
        logger.error(f"❌ Failed to send report: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PhishGuard Local Security Agent — scans your LAN and reports to the dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishguard_agent.py --backend https://your-api.railway.app
  python phishguard_agent.py --backend http://localhost:8000 --interval 60
  python phishguard_agent.py --backend https://your-api --token YOUR_JWT_TOKEN
  sudo python phishguard_agent.py --backend https://your-api  # Full ARP scan

Requirements:
  pip install psutil requests
  pip install scapy  # optional, for ARP scanning (requires sudo)
        """,
    )
    parser.add_argument(
        "--backend", required=True,
        help="PhishGuard backend URL (e.g. https://phishguard-api.railway.app)"
    )
    parser.add_argument(
        "--token", default=None,
        help="JWT token for authentication (optional)"
    )
    parser.add_argument(
        "--interval", type=int, default=0,
        help="Repeat scan every N seconds (0 = run once and exit)"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run one scan and exit (same as --interval 0)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Scan and print results without sending to backend"
    )
    args = parser.parse_args()

    device_id = _get_device_id()
    logger.info(f"PhishGuard Local Agent starting")
    logger.info(f"  Device ID : {device_id}")
    logger.info(f"  Backend   : {args.backend}")
    logger.info(f"  Interval  : {'once' if args.interval == 0 else f'{args.interval}s'}")
    logger.info(f"  ARP (scapy): {'available' if _SCAPY_AVAILABLE else 'not available (TCP mode)'}")
    logger.info("-" * 50)

    def run_once():
        logger.info("Starting network scan...")
        report = scan_network()
        logger.info(f"Found {report['total']} devices via {report['scan_mode']}")
        if args.dry_run:
            print(json.dumps(report, indent=2))
        else:
            send_report(args.backend, report, device_id, args.token)

    run_once()

    if args.interval > 0 and not args.once:
        logger.info(f"Scheduling next scan in {args.interval}s (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(args.interval)
                logger.info(f"Running scheduled scan...")
                run_once()
        except KeyboardInterrupt:
            logger.info("Agent stopped.")


if __name__ == "__main__":
    main()
