"""Repair issues (Settings → Repairs) for problems only the user can fix.

Raised for conditions that persist until the user changes something on the
firewall — never for transient outages, which only make entities
unavailable and are logged once:

* ``api_access_denied`` — the firewall answered with status 532/534: the API
  is disabled or Home Assistant's IP address is not on the API allow list.
* ``snmp_unreachable`` — the SNMP agent has not answered once since the
  entry was set up, for at least 10 minutes (agent disabled, SNMP not
  allowed in the zone, or a wrong community; an SNMPv2c agent silently
  ignores a wrong community). A warning, not an error: SNMP is optional.

Each issue is cleared as soon as the source works again. The module is not
called ``repairs.py``: Home Assistant loads a module of that name as a
repair-flow platform.
"""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir

from .const import DOMAIN

ISSUE_API_ACCESS_DENIED = "api_access_denied"
ISSUE_SNMP_UNREACHABLE = "snmp_unreachable"
ISSUES = (ISSUE_API_ACCESS_DENIED, ISSUE_SNMP_UNREACHABLE)


def issue_id(kind: str, entry: ConfigEntry) -> str:
    """Return the issue id of this kind for one config entry."""
    return f"{kind}_{entry.entry_id}"


@callback
def async_raise_issue(
    hass: HomeAssistant, entry: ConfigEntry, kind: str, **placeholders: str
) -> None:
    """Create (or update) the issue of this kind for the entry."""
    severity = (
        ir.IssueSeverity.WARNING if kind == ISSUE_SNMP_UNREACHABLE else ir.IssueSeverity.ERROR
    )
    ir.async_create_issue(
        hass,
        DOMAIN,
        issue_id(kind, entry),
        is_fixable=False,
        severity=severity,
        translation_key=kind,
        translation_placeholders={
            "title": entry.title,
            "host": entry.data.get(CONF_HOST, ""),
            **placeholders,
        },
    )


@callback
def async_clear_issue(hass: HomeAssistant, entry: ConfigEntry, kind: str) -> None:
    """Delete the issue of this kind for the entry (no-op if there is none)."""
    ir.async_delete_issue(hass, DOMAIN, issue_id(kind, entry))


@callback
def async_clear_all_issues(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Delete every issue of the entry (when it is disabled or removed)."""
    for kind in ISSUES:
        async_clear_issue(hass, entry, kind)
