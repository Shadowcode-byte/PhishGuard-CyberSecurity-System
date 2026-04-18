"""
network_scanner.py — Cloud-Safe Local Network Device Discovery
==============================================================

Architecture
------------
This module is intentionally passive on cloud/container deployments.
Real network scanning is delegated to the PhishGuard Local Agent
(agent/phishguard_agent.py) which runs on the user's machine and POSTs
results to POST /api/v1/agent/network-report.

psutil is OPTIONAL — if missing, the backend starts normally and
scan() returns a graceful 'agent_required' result instead of crashing.
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ── Optional psutil import ────────────────────────────────────────────────────
try:
    import psutil
    _PSUTIL_AVAILABLE = True
    logger.info("[network_scanner] psutil available — local scanning enabled")
except ImportError:
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False
    logger.warning(
        "[network_scanner] psutil not installed — network scanning disabled. "
        "Use the PhishGuard Local Agent for network discovery."
    )

# ── Optional raw-socket / ipaddress imports (Linux only) ─────────────────────
try:
    import fcntl
    import ipaddress
    _RAW_SOCKET_SUPPORT = True
except ImportError:
    _RAW_SOCKET_SUPPORT = False

# ─────────────────────────────────────────────────────────────────────────────
# OUI vendor table
# ─────────────────────────────────────────────────────────────────────────────
_OUI: dict[str, str] = {
    "ACBC32": "Apple", "3C0754": "Apple", "7CF05F": "Apple",
    "A4D18C": "Apple", "F0DBF8": "Apple", "DC2B2A": "Apple",
    "001A2F": "Cisco", "0023EB": "Cisco", "606BBD": "Cisco",
    "F4F26D": "TP-Link", "50C7BF": "TP-Link", "B0487A": "TP-Link",
    "A021B7": "Netgear", "20E52A": "Netgear", "744D28": "Netgear",
    "002339": "Samsung", "84A466": "Samsung", "CC07AB": "Samsung",
    "001372": "Dell",   "0019B9": "Dell",   "D4AE52": "Dell",
    "001083": "HP",     "3C4A92": "HP",     "9CB654": "HP",
    "8C8D28": "Intel",  "F8B156": "Intel",  "3417EB": "Intel",
    "B827EB": "Raspberry Pi", "DC2B61": "Raspberry Pi",
    "049226": "ASUS",   "1062EB": "ASUS",   "2C56DC": "ASUS",
    "00156D": "Ubiquiti", "0418D6": "Ubiquiti", "245A4C": "Ubiquiti",
    "44650D": "Amazon", "34D270": "Amazon", "A002DC": "Amazon",
    "54607E": "Google", "F4F5E8": "Google", "3C5AB4": "Google",
    "001CF0": "D-Link", "00265A": "D-Link", "14D64D": "D-Link",
    "000569": "VMware", "001C14": "VMware", "000C29": "VMware",
    "080027": "VirtualBox",
}

def _vendor(mac: str) -> str:
    oui = mac.upper().replace(":", "").replace("-", "")[:6]
    return _OUI.get(oui, "Unknown Vendor")


# ─────────────────────────────────────────────────────────────────────────────
# Interface helpers
# ─────────────────────────────────────────────────────────────────────────────
_SIOCGIFFLAGS = 0x8913
_IFF_BROADCAST = 0x0002

def _iface_flags(iface: str) -> int:
    if not _RAW_SOCKET_SUPPORT:
        return 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack("16sh", iface.encode()[:15], 0)
        res = fcntl.ioctl(s.fileno(), _SIOCGIFFLAGS, ifreq)
        s.close()
        return struct.unpack_from("H", res, 16)[0]
    except Exception:
        return 0

def _has_broadcast(iface: str) -> bool:
    return bool(_iface_flags(iface) & _IFF_BROADCAST)

def _mac_for_iface(iface: str) -> Optional[str]:
    if not _PSUTIL_AVAILABLE:
        return None
    for a in psutil.net_if_addrs().get(iface, []):
        if a.family == psutil.AF_LINK and a.address not in (None, "", "00:00:00:00:00:00"):
            return a.address.lower()
    return None

def _default_gateway() -> Optional[str]:
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                cols = line.split()
                if len(cols) >= 3 and cols[1] == "00000000":
                    return socket.inet_ntoa(struct.pack("<I", int(cols[2], 16)))
    except Exception:
        pass
    return None


@dataclass
class _Iface:
    name: str; ip: str; netmask: str; mac: Optional[str]
    network: str; prefix_len: int; num_hosts: int
    broadcast_capable: bool; is_private: bool

    @property
    def scannable(self) -> bool:
        return self.broadcast_capable and self.is_private and self.prefix_len < 31

    @property
    def is_container_link(self) -> bool:
        return self.prefix_len >= 31 or not self.broadcast_capable


def _list_interfaces() -> list[_Iface]:
    if not _PSUTIL_AVAILABLE or not _RAW_SOCKET_SUPPORT:
        return []
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        result: list[_Iface] = []
        for iface, addr_list in addrs.items():
            if iface == "lo":
                continue
            st = stats.get(iface)
            if not st or not st.isup:
                continue
            mac = _mac_for_iface(iface)
            bc = _has_broadcast(iface)
            for a in addr_list:
                if a.family != socket.AF_INET:
                    continue
                try:
                    net = ipaddress.IPv4Network(f"{a.address}/{a.netmask}", strict=False)
                    result.append(_Iface(
                        name=iface, ip=a.address, netmask=a.netmask, mac=mac,
                        network=str(net), prefix_len=net.prefixlen,
                        num_hosts=net.num_addresses, broadcast_capable=bc,
                        is_private=net.is_private,
                    ))
                except Exception:
                    pass
        return result
    except Exception as e:
        logger.warning(f"[network_scanner] _list_interfaces error: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 1 — Raw ARP
# ─────────────────────────────────────────────────────────────────────────────
def _build_arp_request(src_mac: bytes, src_ip: str, tgt_ip: str) -> bytes:
    ether = b"\xff\xff\xff\xff\xff\xff" + src_mac + b"\x08\x06"
    arp = struct.pack("!HHbbH", 1, 0x0800, 6, 4, 1) + src_mac + socket.inet_aton(src_ip) + b"\x00"*6 + socket.inet_aton(tgt_ip)
    return ether + arp

def _parse_arp_reply(frame: bytes):
    if len(frame) < 42: return None
    if struct.unpack("!H", frame[12:14])[0] != 0x0806: return None
    if struct.unpack("!H", frame[20:22])[0] != 2: return None
    return socket.inet_ntoa(frame[28:32]), ":".join(f"{b:02x}" for b in frame[22:28])

def _arp_scan(ifc: _Iface, timeout: float = 2.5) -> dict[str, str]:
    if not _RAW_SOCKET_SUPPORT:
        raise RuntimeError("Raw socket support not available")
    if not ifc.mac:
        raise RuntimeError(f"No MAC on {ifc.name}")
    src_mac = bytes.fromhex(ifc.mac.replace(":", ""))
    network = ipaddress.IPv4Network(ifc.network)
    hosts = [str(h) for h in network.hosts()]
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
        sock.bind((ifc.name, 0)); sock.settimeout(0.05)
    except PermissionError:
        raise PermissionError("Root/admin privileges required for raw ARP")
    except OSError as e:
        raise RuntimeError(f"Cannot open AF_PACKET on {ifc.name}: {e}")
    for ip in hosts:
        try: sock.send(_build_arp_request(src_mac, ifc.ip, ip))
        except Exception: pass
    replies: dict[str, str] = {}
    net_set = set(str(h) for h in network.hosts())
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data, _ = sock.recvfrom(65535)
            parsed = _parse_arp_reply(data)
            if parsed:
                ip, mac = parsed
                if ip in net_set and ip not in replies:
                    replies[ip] = mac
        except (socket.timeout, BlockingIOError):
            time.sleep(0.025)
        except Exception:
            break
    sock.close()
    return replies


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 2 — Kernel ARP cache
# ─────────────────────────────────────────────────────────────────────────────
def _read_arp_cache() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                cols = line.split()
                if len(cols) < 4: continue
                if cols[2] == "0x0" or cols[3] == "00:00:00:00:00:00": continue
                out[cols[0]] = cols[3]
    except Exception:
        pass
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Strategy 3 — TCP probe
# ─────────────────────────────────────────────────────────────────────────────
_PROBE_PORTS = [80, 443, 22, 8080, 445, 3389, 5900, 8443, 21, 23]

def _tcp_alive(ip: str, ports: list, timeout: float) -> list:
    open_ports = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, p)) == 0: open_ports.append(p)
            s.close()
        except Exception: pass
    return open_ports

def _tcp_probe_subnet(network, max_hosts=512, concurrency=96, timeout=0.35) -> dict:
    hosts = [str(h) for h in network.hosts()][:max_hosts]
    found: dict = {}; lock = threading.Lock()
    def probe(ip):
        ports = _tcp_alive(ip, _PROBE_PORTS[:6], timeout)
        if ports:
            with lock: found[ip] = ports
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        list(ex.map(probe, hosts))
    return found


# ─────────────────────────────────────────────────────────────────────────────
# Device classification
# ─────────────────────────────────────────────────────────────────────────────
def _resolve(ip: str, timeout: float = 0.4) -> str:
    old = socket.getdefaulttimeout(); socket.setdefaulttimeout(timeout)
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return ip
    finally: socket.setdefaulttimeout(old)

def _classify(hostname: str, vendor: str, open_ports: list, is_gateway: bool) -> str:
    h, v = hostname.lower(), vendor.lower()
    if is_gateway: return "Router / Gateway"
    if any(k in h for k in ["router","gateway","rt-","-ap"]): return "Router / Gateway"
    if any(k in h for k in ["macbook","imac","mac-"]): return "Mac Computer"
    if any(k in h for k in ["iphone","ipad"]): return "iPhone / iPad"
    if any(k in h for k in ["android","galaxy","pixel"]): return "Android Device"
    if any(k in h for k in ["printer","canon","epson","brother"]): return "Printer"
    if any(k in h for k in ["server","srv","nas","synology","qnap"]): return "Server / NAS"
    if any(k in h for k in ["cam","camera","nvr","dvr"]): return "IP Camera"
    if any(k in h for k in ["tv","smart-tv","roku","firetv","chromecast"]): return "Smart TV"
    if any(k in h for k in ["raspberry","raspi"]): return "Raspberry Pi"
    if any(k in h for k in ["laptop","thinkpad","surface","lenovo"]): return "Laptop"
    if "apple" in v: return "Apple Device"
    if any(k in v for k in ["cisco","linksys","netgear","tp-link","d-link","asus","ubiquiti"]): return "Network Device"
    if "raspberry" in v: return "Raspberry Pi"
    if any(k in v for k in ["samsung","amazon","google"]): return "Smart Device"
    if any(k in v for k in ["vmware","virtualbox"]): return "Virtual Machine"
    if 22 in open_ports and 80 in open_ports: return "Server / NAS"
    if 3389 in open_ports: return "Windows PC"
    if 5900 in open_ports: return "Remote Desktop Host"
    if 445 in open_ports: return "Windows PC"
    return "Computer / Device"


@dataclass
class Device:
    ip: str; mac: str; hostname: str; vendor: str; device_type: str
    is_gateway: bool; is_this_machine: bool; status: str = "active"
    scan_method: str = "arp"; open_ports: list = field(default_factory=list)

def _enrich(ip_mac: dict, ifc: _Iface, gw, method="arp") -> list:
    devices = []; lock = threading.Lock()
    def build(ip, mac):
        v = _vendor(mac); h = _resolve(ip); gw_f = ip==gw; sf = ip==ifc.ip
        with lock:
            devices.append(Device(ip=ip,mac=mac,hostname=h,vendor=v,
                device_type=_classify(h,v,[],gw_f),is_gateway=gw_f,
                is_this_machine=sf,scan_method=method))
    with ThreadPoolExecutor(max_workers=32) as ex:
        list(ex.map(lambda kv: build(*kv), ip_mac.items()))
    devices.sort(key=lambda d: tuple(int(x) for x in d.ip.split(".")))
    return devices

def _self_device(ifc: _Iface, gw) -> Device:
    mac = ifc.mac or "N/A"; v = _vendor(mac) if ifc.mac else "Unknown Vendor"
    return Device(ip=ifc.ip, mac=mac, hostname=_resolve(ifc.ip,0.3), vendor=v,
        device_type="This Machine (Backend Host)", is_gateway=(ifc.ip==gw),
        is_this_machine=True, scan_method="interface")


# ─────────────────────────────────────────────────────────────────────────────
# Response builder
# ─────────────────────────────────────────────────────────────────────────────
def _result(devices, scan_mode, error_type, subnet, interface, hosts_probed, t0, ts, permission_required, instructions=None) -> dict:
    return {
        "devices": [{"ip":d.ip,"mac":d.mac,"hostname":d.hostname,"vendor":d.vendor,
            "device_type":d.device_type,"is_gateway":d.is_gateway,
            "is_this_machine":d.is_this_machine,"status":d.status,
            "scan_method":d.scan_method,"open_ports":d.open_ports} for d in devices],
        "total": len(devices), "scan_mode": scan_mode, "error_type": error_type,
        "scanned_subnet": subnet, "interface": interface,
        "total_hosts_probed": hosts_probed,
        "duration_seconds": round(time.monotonic()-t0, 2),
        "scanned_at": ts, "permission_required": permission_required,
        "instructions": instructions,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point — never raises
# ─────────────────────────────────────────────────────────────────────────────
def scan() -> dict:
    """
    Run the network scan pipeline. Always returns a valid dict, never raises.

    In cloud/container environments or when psutil is unavailable,
    returns a 'agent_required' result with clear setup instructions.
    """
    t0 = time.monotonic()
    ts = datetime.utcnow().isoformat() + "Z"

    if not _PSUTIL_AVAILABLE:
        logger.warning("[network_scanner] Scan skipped — psutil not available")
        return _result([], "agent_required", "psutil_missing", None, None, 0, t0, ts,
            permission_required=False,
            instructions=(
                "Network scanning requires the PhishGuard Local Agent.\n\n"
                "The backend is running in a cloud environment where direct "
                "network interface access is not possible.\n\n"
                "To scan your local network:\n\n"
                "  1. Download phishguard_agent.py\n"
                "  2. Run it on your machine:\n\n"
                "     python phishguard_agent.py --backend https://your-backend-url\n\n"
                "  3. Results will appear here automatically."
            ))

    try:
        gw = _default_gateway()
        ifs = _list_interfaces()
    except Exception as e:
        logger.error(f"[network_scanner] Interface enumeration failed: {e}")
        return _result([], "error", "interface_error", None, None, 0, t0, ts, False,
            "Failed to enumerate network interfaces. Use the Local Agent instead.")

    if not ifs:
        return _result([], "agent_required", "no_interfaces", None, None, 0, t0, ts,
            permission_required=False,
            instructions=(
                "No active network interfaces detected.\n\n"
                "This is expected in cloud deployments (Railway, Render, Docker).\n\n"
                "Use the PhishGuard Local Agent:\n\n"
                "  python phishguard_agent.py --backend https://your-backend-url"
            ))

    scannable = [i for i in ifs if i.scannable]
    is_container = not scannable and all(i.is_container_link for i in ifs)

    if is_container:
        logger.info("[network_scanner] Container environment — directing to agent")
        devs = [_self_device(ifs[0], gw)]
        return _result(devs, "agent_required", "container_env",
            ifs[0].network, ifs[0].name, len(devs), t0, ts,
            permission_required=False,
            instructions=(
                "Backend is running inside a container — no LAN broadcast domain.\n\n"
                "Use the PhishGuard Local Agent to scan your real LAN:\n\n"
                "  python phishguard_agent.py --backend https://your-backend-url\n\n"
                "The agent runs on your machine and sends results to the dashboard."
            ))

    ifc = scannable[0]
    try:
        net = ipaddress.IPv4Network(ifc.network)
    except Exception:
        return _result([], "error", "invalid_network", None, None, 0, t0, ts, False)

    # Strategy 1: Raw ARP
    arp_error = None
    try:
        logger.info(f"[network_scanner] ARP scan: {ifc.network} via {ifc.name}")
        arp_hits = _arp_scan(ifc, timeout=2.5)
        for ip, mac in _read_arp_cache().items():
            try:
                if ip not in arp_hits and ipaddress.IPv4Address(ip) in net:
                    arp_hits[ip] = mac
            except Exception: pass
        if ifc.ip not in arp_hits and ifc.mac:
            arp_hits[ifc.ip] = ifc.mac
        devs = _enrich(arp_hits, ifc, gw, "arp")
        return _result(devs, "arp_full", None, ifc.network, ifc.name, net.num_addresses, t0, ts, False)
    except PermissionError as e:
        arp_error = "permission_denied"
        logger.warning(f"[network_scanner] ARP needs root: {e}")
    except (RuntimeError, Exception) as e:
        arp_error = "arp_unsupported"
        logger.warning(f"[network_scanner] ARP failed: {e}")

    # Strategy 2: Kernel ARP cache
    try:
        cache = _read_arp_cache()
        cache_in_subnet = {ip: mac for ip, mac in cache.items()
            if ipaddress.IPv4Address(ip) in net}
        if cache_in_subnet:
            if ifc.ip not in cache_in_subnet and ifc.mac:
                cache_in_subnet[ifc.ip] = ifc.mac
            devs = _enrich(cache_in_subnet, ifc, gw, "arp_cache")
            return _result(devs, "arp_kernel", arp_error, ifc.network, ifc.name,
                len(cache_in_subnet), t0, ts, permission_required=True,
                instructions="Showing ARP cache only. Use the Local Agent or run with sudo for full scan.")
    except Exception as e:
        logger.warning(f"[network_scanner] ARP cache error: {e}")

    # Strategy 3: TCP probe
    try:
        tcp_hits = _tcp_probe_subnet(net, max_hosts=512, concurrency=96)
        if ifc.ip not in tcp_hits:
            tcp_hits[ifc.ip] = []
        if tcp_hits:
            devs = []
            for ip, ports in tcp_hits.items():
                h = _resolve(ip, 0.4); gf = ip==gw; sf = ip==ifc.ip
                devs.append(Device(ip=ip, mac="N/A (TCP scan)", hostname=h,
                    vendor="Unknown (no ARP)", device_type=_classify(h,"",ports,gf),
                    is_gateway=gf, is_this_machine=sf, open_ports=ports, scan_method="tcp"))
            devs.sort(key=lambda d: tuple(int(x) for x in d.ip.split(".")))
            return _result(devs, "tcp_probe", arp_error, ifc.network, ifc.name,
                min(net.num_addresses, 512), t0, ts, permission_required=True,
                instructions="TCP probe mode — MACs unavailable. Use the Local Agent for full discovery.")
    except Exception as e:
        logger.warning(f"[network_scanner] TCP probe error: {e}")

    # Strategy 4: Self-only
    devs = [_self_device(ifc, gw)]
    return _result(devs, "self_only", arp_error or "no_hosts_found",
        ifc.network, ifc.name, net.num_addresses, t0, ts, permission_required=True,
        instructions="No other devices responded. Use the PhishGuard Local Agent for reliable LAN discovery.")
