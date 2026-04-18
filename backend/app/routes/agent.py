"""
Agent Route — /api/v1/agent
============================
Receives network scan reports from the PhishGuard Local Agent,
stores them in memory, and exposes the latest data for the dashboard.

Endpoints:
    POST /agent/network-report   — receive a scan report from the local agent
    GET  /agent/network-report   — retrieve the latest stored report
    GET  /agent/status           — agent connection status
"""

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.models.models import User
from app.security.auth import require_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/agent", tags=["Local Agent"])

# ── In-memory store (one report per device_id) ────────────────────────────────
# For production you could replace this with a database table.
_latest_reports: dict[str, dict] = {}
_last_seen: dict[str, str] = {}  # device_id → ISO timestamp


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class DeviceInfo(BaseModel):
    ip: str
    mac: str = "N/A"
    hostname: str = ""
    vendor: str = "Unknown"
    device_type: str = "Computer / Device"
    is_gateway: bool = False
    is_this_machine: bool = False
    open_ports: list[int] = Field(default_factory=list)
    scan_method: str = "agent"
    status: str = "active"


class NetworkReport(BaseModel):
    device_id: str
    devices: list[DeviceInfo]
    total: int = 0
    scan_mode: str = "agent"
    scanned_subnet: Optional[str] = None
    interface: Optional[str] = None
    gateway: Optional[str] = None
    duration_seconds: float = 0.0
    scanned_at: Optional[str] = None


# ── Helper ────────────────────────────────────────────────────────────────────

def _inject_user(
    request: Request,
    current_user: User = Depends(require_user),
) -> User:
    return current_user


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/network-report")
async def receive_network_report(
    report: NetworkReport,
    current_user: User = Depends(_inject_user),
):
    """
    Receive a scan report from the PhishGuard Local Agent.
    Stores the latest report per device_id in memory.

    Example payload:
    {
      "device_id": "abc123",
      "devices": [
        {
          "ip": "192.168.1.1",
          "mac": "aa:bb:cc:dd:ee:ff",
          "hostname": "router",
          "open_ports": [80, 443]
        }
      ]
    }
    """
    device_id = report.device_id.strip()
    if not device_id:
        raise HTTPException(status_code=400, detail="device_id is required")

    now = datetime.utcnow().isoformat() + "Z"
    report_dict = report.model_dump()

    # Ensure total is correct
    report_dict["total"] = len(report_dict["devices"])
    report_dict["received_at"] = now
    report_dict["reported_by_user"] = current_user.email

    _latest_reports[device_id] = report_dict
    _last_seen[device_id] = now

    logger.info(
        f"[agent] Received report from device={device_id} "
        f"user={current_user.email} devices={report_dict['total']} "
        f"subnet={report.scanned_subnet}"
    )

    return {
        "status": "accepted",
        "device_id": device_id,
        "devices_received": report_dict["total"],
        "received_at": now,
    }


@router.get("/network-report")
async def get_network_report(
    current_user: User = Depends(_inject_user),
):
    """
    Return the latest network scan report from the Local Agent.

    If no agent has reported yet, returns an 'agent_required' response
    with setup instructions for the dashboard to display.
    """
    if not _latest_reports:
        return {
            "devices": [],
            "total": 0,
            "scan_mode": "agent_required",
            "error_type": "no_agent_report",
            "scanned_subnet": None,
            "interface": None,
            "total_hosts_probed": 0,
            "duration_seconds": 0.0,
            "scanned_at": None,
            "permission_required": False,
            "instructions": (
                "No scan data received yet. Set up the PhishGuard Local Agent on your machine:\n\n"
                "  1. Download phishguard_agent.py from the dashboard\n"
                "  2. Install dependencies:\n\n"
                "     pip install psutil requests\n\n"
                "  3. Run the agent:\n\n"
                "     python phishguard_agent.py --backend https://your-backend-url\n\n"
                "  Optional: Install scapy for ARP scanning (requires sudo):\n\n"
                "     pip install scapy\n"
                "     sudo python phishguard_agent.py --backend https://your-backend-url"
            ),
        }

    # Return the most recent report across all known devices
    # (sorted by received_at, newest first)
    all_reports = list(_latest_reports.values())
    all_reports.sort(
        key=lambda r: r.get("received_at", ""),
        reverse=True,
    )
    latest = all_reports[0]

    # Add fields the frontend expects
    return {
        **latest,
        "scan_mode": latest.get("scan_mode", "agent"),
        "error_type": None,
        "total_hosts_probed": latest.get("total", 0),
        "permission_required": False,
        "instructions": None,
    }


@router.get("/status")
async def agent_status(
    current_user: User = Depends(_inject_user),
):
    """Return status of all connected agents."""
    agents = [
        {
            "device_id": device_id,
            "last_seen": _last_seen.get(device_id),
            "devices_reported": len(_latest_reports[device_id].get("devices", [])),
            "subnet": _latest_reports[device_id].get("scanned_subnet"),
        }
        for device_id in _latest_reports
    ]
    return {
        "connected_agents": len(agents),
        "agents": agents,
        "has_data": len(_latest_reports) > 0,
    }
