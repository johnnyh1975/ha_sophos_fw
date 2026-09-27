"""Typed data contract between the API clients, coordinators and entities.

The clients parse raw XML / SNMP responses into these frozen dataclasses, so
entities never see XML tag names or OID strings. Every value that the
firewall may omit is ``| None``: *missing* is represented as None, never as a
fabricated 0 — a fabricated 0 is indistinguishable from a real measurement
and corrupts long-term statistics (TOTAL_INCREASING counters would record a
reset).

Collections are dicts keyed by the object's stable name (XML) or row index
(SNMP tables), preserving the firewall's order.

The ``XmlData`` / ``SnmpData`` containers hold one field per coordinator
endpoint. ``None`` there means "never fetched successfully in this session".
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

# ── XML API ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Interface:
    """A network interface as reported by the XML API."""

    name: str
    is_up: bool | None
    zone: str | None = None
    ipv4_assignment: str | None = None
    speed: str | None = None
    mtu: str | None = None
    # The fixed device name (PortA, PortA.30), which SNMP ifName reports;
    # ``name`` can be changed by the user.
    hardware: str | None = None


@dataclass(frozen=True, slots=True)
class FirewallRule:
    """A firewall rule."""

    name: str
    enabled: bool | None
    action: str | None = None
    policy_type: str | None = None
    ip_family: str | None = None


@dataclass(frozen=True, slots=True)
class WebFilterPolicy:
    """A web filter policy."""

    name: str
    default_action: str | None

    @property
    def allows(self) -> bool | None:
        """Return True when the default action is Allow, None if unknown."""
        if self.default_action is None:
            return None
        return self.default_action.lower() == "allow"


@dataclass(frozen=True, slots=True)
class DhcpServer:
    """A DHCP server instance with its static leases."""

    name: str
    running: bool | None
    interface: str | None = None
    lease_time: str | None = None
    static_leases: tuple[Mapping[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class BackupSettings:
    """Scheduled backup configuration."""

    mode: str | None
    frequency: str | None


@dataclass(frozen=True, slots=True)
class AdminSettings:
    """Administration settings (only the hostname is used)."""

    hostname: str | None


@dataclass(frozen=True, slots=True)
class XmlData:
    """Data owned by the XML coordinator — one field per endpoint."""

    interfaces: dict[str, Interface] | None = None
    firewall_rules: dict[str, FirewallRule] | None = None
    web_filter_policies: dict[str, WebFilterPolicy] | None = None
    dhcp_servers: dict[str, DhcpServer] | None = None
    backup: BackupSettings | None = None
    admin: AdminSettings | None = None


# ── SNMP ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """Static appliance information (sfosXGDeviceInfo)."""

    name: str | None = None
    model: str | None = None
    firmware: str | None = None
    serial: str | None = None
    webcat_version: str | None = None
    ips_version: str | None = None


@dataclass(frozen=True, slots=True)
class SystemStats:
    """Resource usage and protocol hit counters (sfosXGDeviceStats)."""

    current_date: str | None = None
    uptime_seconds: int | None = None
    disk_capacity_mb: int | None = None
    disk_percent: int | None = None
    memory_capacity_mb: int | None = None
    memory_percent: int | None = None
    swap_capacity_mb: int | None = None
    swap_percent: int | None = None
    live_users: int | None = None
    http_hits: int | None = None
    ftp_hits: int | None = None
    smtp_hits: int | None = None
    imap_hits: int | None = None
    pop3_hits: int | None = None


@dataclass(frozen=True, slots=True)
class License:
    """One subscription module."""

    key: str
    name: str
    status_code: int | None
    expiry_date: str | None


@dataclass(frozen=True, slots=True)
class VpnTunnel:
    """One row of sfosIPSecVpnTunnelTable."""

    index: str
    name: str
    conn_status: int | None = None
    activated: int | None = None
    tunnels_configured: int | None = None


@dataclass(frozen=True, slots=True)
class SystemHealth:
    """Hardware health — empty/None on virtual appliances."""

    cpu_temperature_c: float | None = None
    npu_temperature_c: float | None = None
    fans: dict[str, int | None] = field(default_factory=dict)
    psus: dict[str, bool | None] = field(default_factory=dict)

    @property
    def has_hardware_sensors(self) -> bool:
        """Return True if the appliance reports any hardware sensor."""
        return (
            self.cpu_temperature_c is not None
            or self.npu_temperature_c is not None
            or bool(self.fans)
            or bool(self.psus)
        )


@dataclass(frozen=True, slots=True)
class HaStatus:
    """High-availability cluster state (sfosXGHAStats)."""

    enabled: bool | None
    current_state: int | None
    peer_state: int | None


@dataclass(frozen=True, slots=True)
class InterfaceCounters:
    """Octet counters of one interface (IF-MIB ifHCIn/OutOctets)."""

    in_octets: int | None
    out_octets: int | None


@dataclass(frozen=True, slots=True)
class TrafficSample:
    """All interface counters of one walk and when the walk finished.

    ``sampled_at`` is time.monotonic() — the time base the coordinator
    computes rates from (the actual time between two walks, not the nominal
    poll interval, which drifts and is skipped when a walk fails).
    """

    sampled_at: float
    counters: dict[str, InterfaceCounters]


@dataclass(frozen=True, slots=True)
class InterfaceTraffic:
    """Counters and rates (bit/s) of one interface; a rate is None until two
    consecutive samples exist, and after a counter reset."""

    in_octets: int | None
    out_octets: int | None
    in_bps: float | None = None
    out_bps: float | None = None


@dataclass(frozen=True, slots=True)
class SnmpData:
    """Data owned by the SNMP coordinator — one field per endpoint."""

    device: DeviceInfo | None = None
    stats: SystemStats | None = None
    services: dict[str, int | None] | None = None
    licenses: dict[str, License] | None = None
    tunnels: dict[str, VpnTunnel] | None = None
    health: SystemHealth | None = None
    ha: HaStatus | None = None
    cpu: dict[str, int | None] | None = None  # core number ("1", "2", …) → load %
    traffic: dict[str, InterfaceTraffic] | None = None  # ifName → counters and rates
