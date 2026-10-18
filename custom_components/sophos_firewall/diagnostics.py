"""Diagnostics for the Sophos Firewall integration.

Credentials, the SNMP community, the appliance serial number, all
DHCP lease details (MAC, IP, hostname), wireless SSIDs (findable on public
Wi-Fi maps) and access-point IP addresses are redacted. For the static leases
only their number and field names are kept: without them a parser that
read every mapping as one empty lease (#29) looked like any redacted list.
"""
from __future__ import annotations

import time
from dataclasses import asdict
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from . import SophosConfigEntry
from .const import CONF_SNMP_COMMUNITY
from .coordinator import SophosCoordinator

TO_REDACT = {
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_SNMP_COMMUNITY,
    CONF_HOST,
    "serial",
    "ssid",
    "ip_address",
}


def _lease_shape(data: dict[str, Any]) -> None:
    """Replace each DHCP server's static leases by their count and field names."""
    for server in (data.get("dhcp_servers") or {}).values():
        leases = server.get("static_leases") or ()
        server["static_leases"] = {
            "count": len(leases),
            "fields": sorted({key for lease in leases for key in lease}),
        }


def _coordinator_diagnostics(coordinator: SophosCoordinator[Any, Any]) -> dict[str, Any]:
    now = time.monotonic()
    endpoints = {}
    for endpoint in coordinator.endpoints:
        fetched = coordinator.fetched_at(endpoint.key)
        endpoints[endpoint.key] = {
            "tier": endpoint.tier.value,
            "enabled": coordinator.endpoint_enabled(endpoint.key),
            "available": coordinator.endpoint_available(endpoint.key),
            "seconds_since_fetch": None if fetched is None else round(now - fetched, 1),
        }
    return {
        "last_update_success": coordinator.last_update_success,
        "last_exception": repr(coordinator.last_exception) if coordinator.last_exception else None,
        "update_interval": str(coordinator.update_interval),
        "endpoints": endpoints,
        "data": _data(coordinator),
    }


def _data(coordinator: SophosCoordinator[Any, Any]) -> dict[str, Any] | None:
    if coordinator.data is None:
        return None
    data: dict[str, Any] = asdict(coordinator.data)
    if "dhcp_servers" in data:
        _lease_shape(data)
    return data


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: SophosConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    runtime = entry.runtime_data
    snmp: dict[str, Any] | None = None
    if runtime.snmp is not None:
        snmp = {
            **_coordinator_diagnostics(runtime.snmp),
            "is_virtual": runtime.snmp.is_virtual,
        }
    return async_redact_data(
        {
            "entry": {
                "version": entry.version,
                "minor_version": entry.minor_version,
                "data": dict(entry.data),
                "options": dict(entry.options),
            },
            "xml": _coordinator_diagnostics(runtime.xml),
            "snmp": snmp,
        },
        TO_REDACT,
    )
