"""Diagnostics for the Sophos Firewall integration.

Credentials, the SNMP community, the appliance serial number and all
DHCP lease details (MAC, IP, hostname) are redacted.
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
    "static_leases",
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
        "data": asdict(coordinator.data) if coordinator.data is not None else None,
    }


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
