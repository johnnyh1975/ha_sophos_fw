"""Diagnostics support for Sophos Firewall.

Provides a sanitised data dump for debugging without exposing credentials
or sensitive network topology details.
"""
from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_SNMP_COMMUNITY
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

TO_REDACT = {CONF_PASSWORD, CONF_USERNAME, CONF_SNMP_COMMUNITY, "AppKey", "serial_number"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator = entry.runtime_data
    return {
        "entry_data": async_redact_data(dict(entry.data), TO_REDACT),
        "coordinator_data": async_redact_data(coordinator.data or {}, TO_REDACT),
    }
