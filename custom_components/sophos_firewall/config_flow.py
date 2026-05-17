"""Config flow for the Sophos Firewall integration.

Three-step setup:
  Step 1 — Connection: host, port, credentials, SSL
  Step 2 — SNMP (optional): community string, version
  Step 3 — Write access (optional): enable switch entities with warning

An OptionsFlow allows changing intervals, SNMP config, and write-access
after initial setup without removing and re-adding the integration.
"""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigEntry, ConfigFlow, OptionsFlow
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult, section

from .const import (
    CONF_SNMP_COMMUNITY,
    CONF_SNMP_ENABLED,
    CONF_SNMP_INTERVAL,
    CONF_SNMP_VERSION,
    CONF_VERIFY_SSL,
    CONF_WRITE_ACCESS,
    CONF_XML_INTERVAL,
    # Polling tier intervals
    CONF_INTERVAL_REALTIME, CONF_INTERVAL_FAST,
    CONF_INTERVAL_OPERATIVE, CONF_INTERVAL_STATIC,
    # Polling source toggles — XML
    CONF_POLL_XML_INTERFACES, CONF_POLL_XML_FW_RULES, CONF_POLL_XML_DHCP,
    CONF_POLL_XML_WEBFILTER, CONF_POLL_XML_ZONES, CONF_POLL_XML_BACKUP,
    CONF_POLL_XML_ADMIN,
    # Polling source toggles — SNMP
    CONF_POLL_SNMP_STATS, CONF_POLL_SNMP_SERVICES, CONF_POLL_SNMP_TUNNELS,
    CONF_POLL_SNMP_HEALTH, CONF_POLL_SNMP_HA, CONF_POLL_SNMP_LICENSES,
    CONF_POLL_SNMP_DEVICE,
    # Defaults
    DEFAULT_PORT,
    DEFAULT_SNMP_COMMUNITY,
    DEFAULT_SNMP_INTERVAL,
    DEFAULT_SNMP_VERSION,
    DEFAULT_XML_INTERVAL,
    DEFAULT_INTERVAL_REALTIME, DEFAULT_INTERVAL_FAST,
    DEFAULT_INTERVAL_OPERATIVE, DEFAULT_INTERVAL_STATIC,
    DEFAULT_POLL_XML_INTERFACES, DEFAULT_POLL_XML_FW_RULES, DEFAULT_POLL_XML_DHCP,
    DEFAULT_POLL_XML_WEBFILTER, DEFAULT_POLL_XML_ZONES, DEFAULT_POLL_XML_BACKUP,
    DEFAULT_POLL_XML_ADMIN,
    DEFAULT_POLL_SNMP_STATS, DEFAULT_POLL_SNMP_SERVICES, DEFAULT_POLL_SNMP_TUNNELS,
    DEFAULT_POLL_SNMP_HEALTH, DEFAULT_POLL_SNMP_HA, DEFAULT_POLL_SNMP_LICENSES,
    DEFAULT_POLL_SNMP_DEVICE,
    DOMAIN,
)
from .snmp_client import SNMPClient
from .sophos_client import SophosAuthError, SophosAPIError, SophosClient

_LOGGER = logging.getLogger(__name__)


def _flatten_sections(data: dict[str, Any]) -> dict[str, Any]:
    """Flatten nested section data into a flat dict.

    When sections are used, HA returns user_input as:
        {"realtime": {"interval_realtime": 30, "poll_xml_interfaces": True}, ...}

    This flattens it to:
        {"interval_realtime": 30, "poll_xml_interfaces": True, ...}
    """
    flat: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            flat.update(value)
        else:
            flat[key] = value
    return flat


def _polling_schema(snmp_enabled: bool, cur: Any) -> vol.Schema:
    """Build the polling configuration schema using HA Sections API.

    Sections provide visual grouping with titles in the HA UI (HA 2024.9+).
    Each section is collapsed=False so all options are visible by default.

    "Einmalig beim Start" fields (admin, device_info) are always enabled.
    Zones (CONF_POLL_XML_ZONES) default to False — the data is fetched but
    no entities are created yet. Activating it is only useful for future
    zone-based automations; a UI hint in translations makes this clear.

    Args:
        snmp_enabled: Whether to include SNMP source toggles.
        cur: Callable(key, default) → current value, or {} for first-time.
    """
    def _get(key: str, default: Any) -> Any:
        if callable(cur):
            return cur(key, default)
        return default

    # ── ⚡ Echtzeit ──────────────────────────────────────────────────────────
    realtime_fields: dict = {
        vol.Optional(CONF_INTERVAL_REALTIME,
            default=_get(CONF_INTERVAL_REALTIME, DEFAULT_INTERVAL_REALTIME)):
            vol.All(int, vol.Range(min=10, max=300)),
        vol.Optional(CONF_POLL_XML_INTERFACES,
            default=_get(CONF_POLL_XML_INTERFACES, DEFAULT_POLL_XML_INTERFACES)): bool,
    }
    if snmp_enabled:
        realtime_fields[vol.Optional(CONF_POLL_SNMP_STATS,
            default=_get(CONF_POLL_SNMP_STATS, DEFAULT_POLL_SNMP_STATS))] = bool
        realtime_fields[vol.Optional(CONF_POLL_SNMP_SERVICES,
            default=_get(CONF_POLL_SNMP_SERVICES, DEFAULT_POLL_SNMP_SERVICES))] = bool

    # ── 🔄 Schnell ───────────────────────────────────────────────────────────
    fast_fields: dict = {
        vol.Optional(CONF_INTERVAL_FAST,
            default=_get(CONF_INTERVAL_FAST, DEFAULT_INTERVAL_FAST)):
            vol.All(int, vol.Range(min=60, max=600)),
    }
    if snmp_enabled:
        fast_fields[vol.Optional(CONF_POLL_SNMP_TUNNELS,
            default=_get(CONF_POLL_SNMP_TUNNELS, DEFAULT_POLL_SNMP_TUNNELS))] = bool
        fast_fields[vol.Optional(CONF_POLL_SNMP_HA,
            default=_get(CONF_POLL_SNMP_HA, DEFAULT_POLL_SNMP_HA))] = bool

    # ── 🔧 Operativ ──────────────────────────────────────────────────────────
    operative_fields: dict = {
        vol.Optional(CONF_INTERVAL_OPERATIVE,
            default=_get(CONF_INTERVAL_OPERATIVE, DEFAULT_INTERVAL_OPERATIVE)):
            vol.All(int, vol.Range(min=60, max=3600)),
        vol.Optional(CONF_POLL_XML_FW_RULES,
            default=_get(CONF_POLL_XML_FW_RULES, DEFAULT_POLL_XML_FW_RULES)): bool,
    }
    if snmp_enabled:
        operative_fields[vol.Optional(CONF_POLL_SNMP_HEALTH,
            default=_get(CONF_POLL_SNMP_HEALTH, DEFAULT_POLL_SNMP_HEALTH))] = bool

    # ── 🗄 Statisch ──────────────────────────────────────────────────────────
    static_fields: dict = {
        vol.Optional(CONF_INTERVAL_STATIC,
            default=_get(CONF_INTERVAL_STATIC, DEFAULT_INTERVAL_STATIC)):
            vol.All(int, vol.Range(min=300, max=86400)),
        vol.Optional(CONF_POLL_XML_DHCP,
            default=_get(CONF_POLL_XML_DHCP, DEFAULT_POLL_XML_DHCP)): bool,
        vol.Optional(CONF_POLL_XML_WEBFILTER,
            default=_get(CONF_POLL_XML_WEBFILTER, DEFAULT_POLL_XML_WEBFILTER)): bool,
        vol.Optional(CONF_POLL_XML_BACKUP,
            default=_get(CONF_POLL_XML_BACKUP, DEFAULT_POLL_XML_BACKUP)): bool,
    }
    if snmp_enabled:
        static_fields[vol.Optional(CONF_POLL_SNMP_LICENSES,
            default=_get(CONF_POLL_SNMP_LICENSES, DEFAULT_POLL_SNMP_LICENSES))] = bool

    # Sections as plain string keys (not vol.Optional) — HA requirement
    return vol.Schema({
        "realtime": section(vol.Schema(realtime_fields),  {"collapsed": False}),
        "fast":     section(vol.Schema(fast_fields),      {"collapsed": False}),
        "operative":section(vol.Schema(operative_fields), {"collapsed": False}),
        "static":   section(vol.Schema(static_fields),    {"collapsed": False}),
    })


def _polling_placeholders() -> dict[str, str]:
    """Return description_placeholders for the polling step."""
    return {
        "realtime_default":  str(DEFAULT_INTERVAL_REALTIME),
        "fast_default":      str(DEFAULT_INTERVAL_FAST),
        "operative_default": str(DEFAULT_INTERVAL_OPERATIVE),
        "static_default":    str(DEFAULT_INTERVAL_STATIC),
    }


STEP_CONNECTION_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Required(CONF_PORT, default=DEFAULT_PORT): int,
        vol.Required(CONF_USERNAME, default="admin"): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Required(CONF_VERIFY_SSL, default=False): bool,
    }
)

STEP_SNMP_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_SNMP_ENABLED, default=False): bool,
        vol.Optional(CONF_SNMP_COMMUNITY, default=DEFAULT_SNMP_COMMUNITY): str,
        vol.Optional(CONF_SNMP_VERSION, default=DEFAULT_SNMP_VERSION): vol.In(["1", "2c"]),
    }
)

STEP_WRITE_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_WRITE_ACCESS, default=False): bool,
    }
)


class SophosFirewallConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle the initial setup of the Sophos Firewall integration."""

    VERSION = 1
    _data: dict[str, Any]  # accumulates data across steps

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 1: Collect and validate connection parameters."""
        errors: dict[str, str] = {}
        self._data = {}

        if user_input is not None:
            # Prevent duplicate entries for the same host
            await self.async_set_unique_id(
                f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}"
            )
            self._abort_if_unique_id_configured()

            # Test connectivity
            errors = await self._test_xml_connection(user_input)
            if not errors:
                self._data.update(user_input)
                return await self.async_step_snmp()

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_CONNECTION_SCHEMA,
            errors=errors,
            description_placeholders={"default_port": str(DEFAULT_PORT)},
        )

    async def async_step_snmp(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 2: Optional SNMP configuration."""
        errors: dict[str, str] = {}

        if user_input is not None:
            if user_input.get(CONF_SNMP_ENABLED):
                # Merge step-1 data (contains CONF_HOST) with step-2 input
                merged = {**self._data, **user_input}
                errors = await self._test_snmp_connection(merged)
            if not errors:
                self._data.update(user_input)
                return await self.async_step_write_access()

        return self.async_show_form(
            step_id="snmp",
            data_schema=STEP_SNMP_SCHEMA,
            errors=errors,
        )

    async def async_step_write_access(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 3: Optional write-access (enables switch entities)."""
        if user_input is not None:
            self._data.update(user_input)
            return await self.async_step_polling()

        return self.async_show_form(
            step_id="write_access",
            data_schema=STEP_WRITE_SCHEMA,
            description_placeholders={},
        )

    async def async_step_polling(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 4: Polling intervals and data sources — grouped by frequency."""
        snmp_enabled = self._data.get(CONF_SNMP_ENABLED, False)

        if user_input is not None:
            # Flatten sections before storing
            flat = _flatten_sections(user_input)
            self._data.update(flat)
            # Always enable once-only fields
            self._data[CONF_POLL_XML_ZONES]   = True
            self._data[CONF_POLL_XML_ADMIN]   = True
            self._data[CONF_POLL_SNMP_DEVICE] = True
            return self.async_create_entry(
                title=self._data[CONF_HOST],
                data=self._data,
            )

        schema = _polling_schema(snmp_enabled, {})
        return self.async_show_form(
            step_id="polling",
            data_schema=schema,
            description_placeholders=_polling_placeholders(),
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Allow the user to change host/port/credentials without deleting the entry."""
        reconfigure_entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}

        if user_input is not None:
            errors = await self._test_xml_connection(user_input)
            if not errors:
                return self.async_update_reload_and_abort(
                    reconfigure_entry,
                    data_updates=user_input,
                )

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_HOST,
                        default=reconfigure_entry.data.get(CONF_HOST, ""),
                    ): str,
                    vol.Required(
                        CONF_PORT,
                        default=reconfigure_entry.data.get(CONF_PORT, DEFAULT_PORT),
                    ): int,
                    vol.Required(
                        CONF_USERNAME,
                        default=reconfigure_entry.data.get(CONF_USERNAME, "admin"),
                    ): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Required(
                        CONF_VERIFY_SSL,
                        default=reconfigure_entry.data.get(CONF_VERIFY_SSL, False),
                    ): bool,
                }
            ),
            errors=errors,
            description_placeholders={
                "host": reconfigure_entry.data.get(CONF_HOST, ""),
            },
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    async def _test_xml_connection(data: dict[str, Any]) -> dict[str, str]:
        """Return error dict (empty = success)."""
        client = SophosClient(
            host=data[CONF_HOST],
            port=data[CONF_PORT],
            username=data[CONF_USERNAME],
            password=data[CONF_PASSWORD],
            verify_ssl=data.get(CONF_VERIFY_SSL, False),
        )
        try:
            async with client:
                await client.test_connection()
        except SophosAuthError:
            return {"base": "invalid_auth"}
        except SophosAPIError:
            return {"base": "cannot_connect"}
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Unexpected error during XML connection test")
            return {"base": "unknown"}
        return {}

    @staticmethod
    async def _test_snmp_connection(data: dict[str, Any]) -> dict[str, str]:
        """Return error dict (empty = success)."""
        # Check puresnmp availability without blocking the event loop.
        # The import is deferred to an executor thread.
        import asyncio
        import concurrent.futures

        def _check_import() -> bool:
            try:
                import puresnmp  # noqa: F401
                return True
            except ImportError:
                return False

        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            available = await loop.run_in_executor(pool, _check_import)

        if not available:
            _LOGGER.warning(
                "puresnmp not yet installed — it will be installed on HA restart. "
                "Skip SNMP for now and enable it later via Options."
            )
            return {"base": "snmp_not_available"}

        client = SNMPClient(
            host=data[CONF_HOST],
            community=data.get(CONF_SNMP_COMMUNITY, DEFAULT_SNMP_COMMUNITY),
            version=data.get(CONF_SNMP_VERSION, DEFAULT_SNMP_VERSION),
        )
        try:
            reachable = await client.test_connection()
        except Exception:  # noqa: BLE001
            _LOGGER.exception("Unexpected error during SNMP connection test")
            return {"base": "snmp_cannot_connect"}
        if not reachable:
            return {"base": "snmp_cannot_connect"}
        return {}

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> "SophosOptionsFlow":
        """Return the options flow handler."""
        return SophosOptionsFlow(config_entry)


class SophosOptionsFlow(OptionsFlow):
    """Options flow: single step combining intervals, SNMP and polling sources."""

    def __init__(self, config_entry: ConfigEntry) -> None:
        self._entry = config_entry

    def _cur(self, key: str, default: Any) -> Any:
        opts = self._entry.options
        data = self._entry.data
        return opts.get(key, data.get(key, default))

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Single step: SNMP credentials + polling intervals + sources."""
        errors: dict[str, str] = {}

        snmp_enabled = (
            user_input.get(CONF_SNMP_ENABLED, False)
            if user_input is not None
            else self._cur(CONF_SNMP_ENABLED, False)
        )

        if user_input is not None:
            if user_input.get(CONF_SNMP_ENABLED):
                merged = {**self._entry.data, **user_input}
                errors = await SophosFirewallConfigFlow._test_snmp_connection(merged)

            if not errors:
                # Sections return nested dicts — flatten for storage
                flat = _flatten_sections(user_input)

                new_data = {
                    **self._entry.data,
                    CONF_SNMP_ENABLED:   flat.get(CONF_SNMP_ENABLED, False),
                    CONF_SNMP_COMMUNITY: flat.get(CONF_SNMP_COMMUNITY, DEFAULT_SNMP_COMMUNITY),
                    CONF_SNMP_VERSION:   flat.get(CONF_SNMP_VERSION, DEFAULT_SNMP_VERSION),
                    CONF_WRITE_ACCESS:   flat.get(CONF_WRITE_ACCESS, False),
                    # Hardcode once-only fields — always True
                    CONF_POLL_XML_ZONES:  True,
                    CONF_POLL_XML_ADMIN:  True,
                    CONF_POLL_SNMP_DEVICE: True,
                }
                self.hass.config_entries.async_update_entry(self._entry, data=new_data)
                return self.async_create_entry(title="", data=flat)

        snmp_cred_fields = {
            vol.Optional(CONF_SNMP_ENABLED,
                default=self._cur(CONF_SNMP_ENABLED, False)): bool,
            vol.Optional(CONF_SNMP_COMMUNITY,
                default=self._cur(CONF_SNMP_COMMUNITY, DEFAULT_SNMP_COMMUNITY)): str,
            vol.Optional(CONF_SNMP_VERSION,
                default=self._cur(CONF_SNMP_VERSION, DEFAULT_SNMP_VERSION)): vol.In(["1", "2c"]),
            vol.Optional(CONF_WRITE_ACCESS,
                default=self._cur(CONF_WRITE_ACCESS, False)): bool,
        }
        polling = _polling_schema(snmp_enabled, self._cur)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({**snmp_cred_fields, **polling.schema}),
            errors=errors,
            description_placeholders=_polling_placeholders(),
        )

