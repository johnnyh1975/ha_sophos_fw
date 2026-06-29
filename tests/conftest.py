"""Shared pytest fixtures for Sophos Firewall integration tests.

All mock data uses deepcopy in fixtures to prevent test isolation issues
(module-level dicts would otherwise be mutated between tests).
"""
from __future__ import annotations

import copy
from typing import Any
from unittest.mock import AsyncMock, MagicMock
import pytest

from custom_components.sophos_firewall.const import (
    DATA_ADMIN,
    DATA_BACKUP,
    DATA_DHCP_SERVERS,
    DATA_FIREWALL_RULES,
    DATA_INTERFACES,
    DATA_SNMP_DEVICE,
    DATA_SNMP_HA,
    DATA_SNMP_HEALTH,
    DATA_SNMP_LICENSES,
    DATA_SNMP_SERVICES,
    DATA_SNMP_STATS,
    DATA_SNMP_TUNNELS,
    DATA_WEB_FILTER_POLICIES,
    DATA_ZONES,
)

# ── XML API stubs ─────────────────────────────────────────────────────────────

MOCK_INTERFACE = {
    "Name": "PortA",
    "InterfaceStatus": "ON",
    "NetworkZone": "LAN",
    "IPv4Assignment": "Static",
    "InterfaceSpeed": "Auto Negotiate",
    "MTU": "1500",
}

MOCK_FIREWALL_RULE = {
    "Name": "Allow LAN to IoT",
    "Status": "Enable",
    "Action": "Accept",
    "PolicyType": "Network",
    "IPFamily": "IPv4",
}

MOCK_WEB_FILTER_POLICY = {
    "Name": "DefaultPolicy",
    "DefaultAction": "Allow",
}

MOCK_DHCP_SERVER = {
    "Name": "Main_DHCP",
    "Status": "1",
    "Interface": "PortA",
}

MOCK_BACKUP = {
    "ScheduleBackup": {
        "BackupMode": "Mail",
        "BackupFrequency": "Monthly",
    }
}

MOCK_ADMIN = {
    "HostnameSettings": {"HostName": "5HeyneXG"},
}

# ── SNMP stubs ────────────────────────────────────────────────────────────────

OID_DEVICE_NAME    = "1.3.6.1.4.1.2604.5.1.1.1.0"
OID_DEVICE_TYPE    = "1.3.6.1.4.1.2604.5.1.1.2.0"
OID_DEVICE_FW      = "1.3.6.1.4.1.2604.5.1.1.3.0"
OID_DEVICE_SERIAL  = "1.3.6.1.4.1.2604.5.1.1.4.0"

MOCK_SNMP_DEVICE = {
    OID_DEVICE_NAME:   "5HeyneXG",
    OID_DEVICE_TYPE:   "SFVH_KV01_SFOS",
    OID_DEVICE_FW:     "22.0.0 GA-Build411",
    OID_DEVICE_SERIAL: "C01001D2MQT76C4",
}

MOCK_SNMP_STATS = {
    "memory_percent":     33,
    "memory_capacity_mb": 72383,
    "disk_percent":       27,
    "disk_capacity_mb":   11969,
    "swap_percent":       23,
    "swap_capacity_mb":   4095,
    "uptime_seconds":     6502743,
    "http_hits":          21355078,
    "ftp_hits":           0,
    "smtp_hits":          19,
    "imap_hits":          47,
    "pop3_hits":          12,
    "live_users":         1,
    "current_date":       "Thu May 15 17:00:00 2026",
}

MOCK_SNMP_SERVICES = {
    "pop3":      3,  # running
    "imap":      3,
    "smtp":      3,
    "ftp":       3,
    "http":      3,
    "av":        3,
    "antispam":  1,  # stopped
    "dns":       3,
    "ha_svc":    1,  # stopped
    "ips":       3,
    "apache":    3,
    "ntp":       3,
    "tomcat":    3,
    "ssl_vpn":   3,
    "ipsec_vpn": 3,
    "database":  3,
    "network":   3,
    "garner":    3,
    "drouting":  3,
    "sshd":      3,
    "dgd":       3,
}

MOCK_SNMP_LICENSES = {
    "base_fw":     {"name": "Basis-Firewall",     "status_code": 1, "expiry_date": "Dec 31 2999"},
    "net_protect": {"name": "Network Protection", "status_code": 1, "expiry_date": "Dec 31 2999"},
    "enh_plus":    {"name": "Enhanced Plus",      "status_code": 2, "expiry_date": "unknown"},
}

MOCK_SNMP_TUNNELS = [
    {"index": "1", "name": "Azure-VPN",  "conn_status": 1, "activated": 1},
    {"index": "2", "name": "Branch-VPN", "conn_status": 0, "activated": 1},
]

MOCK_SNMP_HEALTH = {
    "cpu_temperature_c": None,   # VM — not available
    "npu_temperature_c": None,
    "fans": {},
    "psus": {},
}

MOCK_SNMP_HA = {
    "ha_enabled":    False,
    "current_state": 2,
}

# ── Combined coordinator data ─────────────────────────────────────────────────

_COORDINATOR_DATA: dict[str, Any] = {
    DATA_INTERFACES:          [MOCK_INTERFACE],
    DATA_ZONES:               [{"Name": "LAN", "Type": "LAN"}],
    DATA_FIREWALL_RULES:      [MOCK_FIREWALL_RULE],
    DATA_WEB_FILTER_POLICIES: [MOCK_WEB_FILTER_POLICY],
    DATA_DHCP_SERVERS:        [MOCK_DHCP_SERVER],
    DATA_BACKUP:              MOCK_BACKUP,
    DATA_ADMIN:               MOCK_ADMIN,
    DATA_SNMP_DEVICE:         MOCK_SNMP_DEVICE,
    DATA_SNMP_STATS:          MOCK_SNMP_STATS,
    DATA_SNMP_SERVICES:       MOCK_SNMP_SERVICES,
    DATA_SNMP_LICENSES:       MOCK_SNMP_LICENSES,
    DATA_SNMP_TUNNELS:        MOCK_SNMP_TUNNELS,
    DATA_SNMP_HEALTH:         MOCK_SNMP_HEALTH,
    DATA_SNMP_HA:             MOCK_SNMP_HA,
}

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def coordinator_data() -> dict[str, Any]:
    """Return a fresh deepcopy of coordinator data for each test."""
    return copy.deepcopy(_COORDINATOR_DATA)


@pytest.fixture
def mock_entry() -> MagicMock:
    """Minimal ConfigEntry mock."""
    entry = MagicMock()
    entry.entry_id = "test_entry_id"
    entry.data = {
        "host":           "10.10.0.1",
        "port":           4444,
        "username":       "admin",
        "password":       "secret",
        "verify_ssl":     False,
        "snmp_enabled":   True,
        "snmp_community": "public",
        "snmp_version":   "2c",
        "write_access":   True,
        # polling toggles (all on by default)
        "poll_xml_interfaces": True,
        "poll_xml_fw_rules":   True,
        "poll_xml_dhcp":       True,
        "poll_xml_webfilter":  True,
        "poll_xml_backup":     True,
        "poll_xml_zones":      True,
        "poll_xml_admin":      True,
        "poll_snmp_stats":     True,
        "poll_snmp_services":  True,
        "poll_snmp_tunnels":   True,
        "poll_snmp_ha":        True,
        "poll_snmp_health":    True,
        "poll_snmp_licenses":  True,
        "poll_snmp_device":    True,
        # intervals
        "interval_realtime":  30,
        "interval_fast":      120,
        "interval_operative": 600,
        "interval_static":    1800,
    }
    entry.options = {}
    return entry


@pytest.fixture
def mock_coordinator(mock_entry, coordinator_data) -> MagicMock:
    """Coordinator mock pre-loaded with full test data."""
    coord = MagicMock()
    coord.data = coordinator_data
    coord.config_entry = mock_entry
    coord.async_request_refresh = AsyncMock()
    # Public xml_client with write methods
    coord.xml_client = MagicMock()
    coord.xml_client._username = "admin"
    coord.xml_client._password = "secret"
    coord.xml_client.set_firewall_rule_status     = AsyncMock()
    coord.xml_client.set_web_filter_default_action = AsyncMock()
    coord.xml_client.close = AsyncMock()
    return coord

# Backward-compatible aliases used by test_entities.py
MOCK_COORDINATOR_DATA = _COORDINATOR_DATA
MOCK_SNMP_LICENSES    = MOCK_SNMP_LICENSES
MOCK_SNMP_TUNNELS     = MOCK_SNMP_TUNNELS
