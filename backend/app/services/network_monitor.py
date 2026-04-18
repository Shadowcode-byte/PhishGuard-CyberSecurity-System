"""
Network Monitor Service — Real-Time Connection Monitoring
=========================================================
Architecture:
  PRIMARY: psutil.net_connections() reads real OS-level TCP/UDP connections.
  FALLBACK: Graceful simulation mode when running in sandboxed/CI environments.

Monitors:
  - Outgoing network connections
  - DNS requests & domain lookups
  - HTTP/HTTPS traffic
  - Destination IP, port, protocol
  - Packet sizes via psutil net_io_counters
  - Timestamps for all events

Integration: Called by threat.py routes every poll interval.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import socket
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

SAFE_INTERNAL_PREFIXES = (
    "127.", "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
    "172.31.", "::1", "fe80:", "0.0.0.0",
)

PROTO_MAP = {
    80: "HTTP",   443: "HTTPS",  8080: "HTTP",   8443: "HTTPS",
    53: "DNS",    25: "SMTP",    587: "SMTP",     465: "SMTPS",
    110: "POP3",  993: "IMAPS",  143: "IMAP",
    21: "FTP",    22: "SSH",     23: "Telnet",
    3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
    3389: "RDP",  5900: "VNC",   4444: "TCP",
    6667: "IRC",  9001: "Tor",   9030: "Tor",
    123: "NTP",   161: "SNMP",   162: "SNMP",
}

# ─────────────────────────────────────────────────────────────────────────────
# IO stats cache (non-blocking, background refresh)
# ─────────────────────────────────────────────────────────────────────────────

_io_cache: dict = {}
_io_lock = threading.Lock()


def _refresh_io_cache() -> None:
    try:
        import psutil
        s1 = psutil.net_io_counters()
        time.sleep(1.0)
        s2 = psutil.net_io_counters()
        with _io_lock:
            _io_cache.update({
                "bytes_sent_total": s2.bytes_sent,
                "bytes_recv_total": s2.bytes_recv,
                "bytes_sent_rate": max(0, s2.bytes_sent - s1.bytes_sent),
                "bytes_recv_rate": max(0, s2.bytes_recv - s1.bytes_recv),
                "packets_sent": s2.packets_sent,
                "packets_recv": s2.packets_recv,
                "errors_in": s2.errin,
                "errors_out": s2.errout,
                "is_real": True,
                "sampled_at": time.time(),
            })
    except Exception as e:
        logger.debug(f"IO cache refresh failed: {e}")


def get_network_io_stats() -> dict:
    """Return network IO stats from cache. Background thread refreshes every 5s."""
    with _io_lock:
        cached = dict(_io_cache)

    stale = (time.time() - cached.get("sampled_at", 0)) > 5.0
    if stale:
        t = threading.Thread(target=_refresh_io_cache, daemon=True)
        t.start()

    if not cached.get("is_real"):
        return {
            "bytes_sent_total": 0, "bytes_recv_total": 0,
            "bytes_sent_rate": 0, "bytes_recv_rate": 0,
            "packets_sent": 0, "packets_recv": 0,
            "errors_in": 0, "errors_out": 0,
            "is_real": False,
        }

    return {k: v for k, v in cached.items() if k != "sampled_at"}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def is_internal(ip: str) -> bool:
    return ip.startswith(SAFE_INTERNAL_PREFIXES)


def proto(port: int) -> str:
    return PROTO_MAP.get(port, "TCP")


def proc_name(pid: Optional[int]) -> str:
    try:
        if pid:
            import psutil
            return psutil.Process(pid).name()
    except Exception:
        pass
    return "unknown"


def rdns(ip: str, timeout: float = 0.3) -> Optional[str]:
    if is_internal(ip) or not ip:
        return None
    try:
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        result = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old)
        return result
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Real connection reader
# ─────────────────────────────────────────────────────────────────────────────

def read_real_connections(analyzer_fn) -> tuple[list[dict], bool]:
    """
    Snapshot OS-level TCP/UDP connections via psutil.
    Returns (events, has_external_connections).
    analyzer_fn: callable(domain, port, ip) → analysis dict
    """
    try:
        import psutil
        raw = psutil.net_connections(kind="inet")
    except ImportError:
        logger.warning("psutil not installed — cannot read real connections")
        return [], False
    except Exception as e:
        logger.warning(f"psutil.net_connections failed: {e}")
        return [], False

    now = datetime.utcnow()
    results: list[dict] = []
    seen: set[str] = set()

    for conn in raw:
        if conn.status not in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT"):
            continue
        if not conn.raddr:
            continue

        rip = conn.raddr.ip
        rport = conn.raddr.port
        key = f"{rip}:{rport}"
        if key in seen or is_internal(rip):
            continue
        seen.add(key)

        domain = rdns(rip) or rip
        pr = proto(rport)
        analysis = analyzer_fn(domain, rport, rip)

        results.append({
            "id": hashlib.md5(f"{rip}:{rport}:{now.date()}".encode()).hexdigest()[:12],
            "domain": domain,
            "ip": rip,
            "port": rport,
            "protocol": pr,
            "process": proc_name(conn.pid),
            "risk_level": analysis["risk_level"],
            "reasons": analysis["reasons"],
            "indicators": analysis["indicators"],
            "confidence": analysis["confidence"],
            "is_known_safe": analysis.get("is_known_safe", False),
            "timestamp": now.isoformat() + "Z",
            "local_port": conn.laddr.port if conn.laddr else None,
            "status": conn.status,
            "data_source": "real",
            "packet_size": None,
        })

    return results, len(results) > 0


# ─────────────────────────────────────────────────────────────────────────────
# Network Scanner (ARP / host discovery)
# ─────────────────────────────────────────────────────────────────────────────

def scan_local_network() -> list[dict]:
    """
    Discover devices on the local network using ARP broadcast.
    Requires scapy or falls back to psutil/socket methods.
    Returns list of {ip, mac, hostname, device_type}.
    """
    devices = []

    # Method 1: Try scapy ARP scan
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
        import ipaddress

        # Get local subnet
        import psutil
        addrs = psutil.net_if_addrs()
        local_subnet = None
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and not is_internal(addr.address):
                    local_subnet = f"{addr.address}/24"
                    break
            if local_subnet:
                break

        if not local_subnet:
            local_subnet = "192.168.1.0/24"

        arp = ARP(pdst=local_subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]

        for sent, received in result:
            ip = received.psrc
            mac = received.hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ip

            device_type = _classify_device(hostname, mac)
            devices.append({
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "device_type": device_type,
                "status": "active",
                "method": "arp",
            })

        return devices

    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"Scapy ARP scan failed: {e}")

    # Method 2: psutil + socket for local interfaces
    try:
        import psutil
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for iface, addr_list in addrs.items():
            if iface not in stats or not stats[iface].isup:
                continue
            for addr in addr_list:
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = ip
                    devices.append({
                        "ip": ip,
                        "mac": "N/A",
                        "hostname": hostname,
                        "device_type": "This Machine",
                        "status": "active",
                        "method": "interface",
                    })
    except Exception as e:
        logger.debug(f"Interface scan failed: {e}")

    return devices


def _classify_device(hostname: str, mac: str) -> str:
    hostname_lower = hostname.lower()
    if any(k in hostname_lower for k in ["router", "gateway", "gw", "ap-"]):
        return "Router/Gateway"
    if any(k in hostname_lower for k in ["laptop", "macbook", "thinkpad"]):
        return "Laptop"
    if any(k in hostname_lower for k in ["phone", "iphone", "android", "mobile"]):
        return "Mobile Device"
    if any(k in hostname_lower for k in ["printer", "print"]):
        return "Printer"
    if any(k in hostname_lower for k in ["server", "srv"]):
        return "Server"
    if any(k in hostname_lower for k in ["cam", "camera", "nvr", "dvr"]):
        return "IP Camera"
    # MAC prefix-based classification (first 3 bytes)
    oui = mac.upper().replace(":", "")[:6]
    apple_ouis = {"ACBC32", "3C0754", "7CF05F", "A4D18C"}
    if oui in apple_ouis:
        return "Apple Device"
    return "Unknown Device"
