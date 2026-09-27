"""Config flow for the Sophos Firewall integration.

Setup (user flow)
    1. connection   host, port, credentials, certificate check  → entry.data
    2. snmp         optional SNMP (community string, v2c)         → entry.options
    3. write_access optional switches for rules / web filter      → entry.options
    4. polling      intervals and data sources, grouped by tier   → entry.options

Only the connection settings live in entry.data; they are changed with the
reconfigure flow (or the reauth flow for the password). Everything else is an
option and changed with the options flow.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    SOURCE_REAUTH,
    ConfigEntry,
    ConfigEntryState,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.data_entry_flow import section

from .const import (
    CONF_INTERVAL_FAST,
    CONF_INTERVAL_OPERATIVE,
    CONF_INTERVAL_REALTIME,
    CONF_INTERVAL_STATIC,
    CONF_POLL_SNMP_HA,
    CONF_POLL_SNMP_HEALTH,
    CONF_POLL_SNMP_LICENSES,
    CONF_POLL_SNMP_SERVICES,
    CONF_POLL_SNMP_STATS,
    CONF_POLL_SNMP_TRAFFIC,
    CONF_POLL_SNMP_TUNNELS,
    CONF_POLL_XML_BACKUP,
    CONF_POLL_XML_DHCP,
    CONF_POLL_XML_FW_RULES,
    CONF_POLL_XML_INTERFACES,
    CONF_POLL_XML_WEBFILTER,
    CONF_SNMP_COMMUNITY,
    CONF_SNMP_ENABLED,
    CONF_VERIFY_SSL,
    CONF_WRITE_ACCESS,
    CONFIG_ENTRY_VERSION,
    DEFAULT_INTERVAL_FAST,
    DEFAULT_INTERVAL_OPERATIVE,
    DEFAULT_INTERVAL_REALTIME,
    DEFAULT_INTERVAL_STATIC,
    DEFAULT_POLL_SNMP_HA,
    DEFAULT_POLL_SNMP_HEALTH,
    DEFAULT_POLL_SNMP_LICENSES,
    DEFAULT_POLL_SNMP_SERVICES,
    DEFAULT_POLL_SNMP_STATS,
    DEFAULT_POLL_SNMP_TRAFFIC,
    DEFAULT_POLL_SNMP_TUNNELS,
    DEFAULT_POLL_XML_BACKUP,
    DEFAULT_POLL_XML_DHCP,
    DEFAULT_POLL_XML_FW_RULES,
    DEFAULT_POLL_XML_INTERFACES,
    DEFAULT_POLL_XML_WEBFILTER,
    DEFAULT_PORT,
    DEFAULT_SNMP_COMMUNITY,
    DEFAULT_USERNAME,
    DOMAIN,
)
from . import session as xml_session
from .snmp_client import SNMPClient, SophosSNMPError
from .sophos_client import (
    SophosAccessError,
    SophosAuthError,
    SophosClient,
    SophosError,
)

_LOGGER = logging.getLogger(__name__)

type Getter = Callable[[str, Any], Any]


def _defaults(_key: str, default: Any) -> Any:
    return default


# ── Schemas ───────────────────────────────────────────────────────────────────


def _connection_schema(get: Getter = _defaults) -> vol.Schema:
    host_default = get(CONF_HOST, None)
    host_key = (
        vol.Required(CONF_HOST) if host_default is None
        else vol.Required(CONF_HOST, default=host_default)
    )
    return vol.Schema(
        {
            host_key: str,
            vol.Required(CONF_PORT, default=get(CONF_PORT, DEFAULT_PORT)): vol.All(
                vol.Coerce(int), vol.Range(min=1, max=65535)
            ),
            vol.Required(CONF_USERNAME, default=get(CONF_USERNAME, DEFAULT_USERNAME)): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Required(CONF_VERIFY_SSL, default=get(CONF_VERIFY_SSL, False)): bool,
        }
    )


def _snmp_fields(get: Getter = _defaults) -> dict[vol.Marker, Any]:
    return {
        vol.Required(CONF_SNMP_ENABLED, default=get(CONF_SNMP_ENABLED, False)): bool,
        vol.Required(
            CONF_SNMP_COMMUNITY, default=get(CONF_SNMP_COMMUNITY, DEFAULT_SNMP_COMMUNITY)
        ): str,
    }


def _write_fields(get: Getter = _defaults) -> dict[vol.Marker, Any]:
    return {vol.Required(CONF_WRITE_ACCESS, default=get(CONF_WRITE_ACCESS, False)): bool}


def _polling_sections(snmp_enabled: bool, get: Getter = _defaults) -> dict[str, Any]:
    """Polling intervals and data sources, one section per tier.

    SNMP sources are only shown when SNMP is enabled.
    """

    def interval(key: str, default: int, low: int, high: int) -> dict[vol.Marker, Any]:
        return {
            vol.Required(key, default=get(key, default)): vol.All(
                vol.Coerce(int), vol.Range(min=low, max=high)
            )
        }

    def toggles(*items: tuple[str, bool, bool]) -> dict[vol.Marker, Any]:
        return {
            vol.Required(key, default=get(key, default)): bool
            for key, default, needs_snmp in items
            if snmp_enabled or not needs_snmp
        }

    tiers = {
        "realtime": {
            **interval(CONF_INTERVAL_REALTIME, DEFAULT_INTERVAL_REALTIME, 10, 300),
            **toggles(
                (CONF_POLL_XML_INTERFACES, DEFAULT_POLL_XML_INTERFACES, False),
                (CONF_POLL_SNMP_STATS, DEFAULT_POLL_SNMP_STATS, True),
                (CONF_POLL_SNMP_SERVICES, DEFAULT_POLL_SNMP_SERVICES, True),
                (CONF_POLL_SNMP_TRAFFIC, DEFAULT_POLL_SNMP_TRAFFIC, True),
            ),
        },
        "fast": {
            **interval(CONF_INTERVAL_FAST, DEFAULT_INTERVAL_FAST, 60, 600),
            **toggles(
                (CONF_POLL_SNMP_TUNNELS, DEFAULT_POLL_SNMP_TUNNELS, True),
                (CONF_POLL_SNMP_HA, DEFAULT_POLL_SNMP_HA, True),
            ),
        },
        "operative": {
            **interval(CONF_INTERVAL_OPERATIVE, DEFAULT_INTERVAL_OPERATIVE, 60, 3600),
            **toggles(
                (CONF_POLL_XML_FW_RULES, DEFAULT_POLL_XML_FW_RULES, False),
                (CONF_POLL_SNMP_HEALTH, DEFAULT_POLL_SNMP_HEALTH, True),
            ),
        },
        "static": {
            **interval(CONF_INTERVAL_STATIC, DEFAULT_INTERVAL_STATIC, 300, 86400),
            **toggles(
                (CONF_POLL_XML_DHCP, DEFAULT_POLL_XML_DHCP, False),
                (CONF_POLL_XML_WEBFILTER, DEFAULT_POLL_XML_WEBFILTER, False),
                (CONF_POLL_XML_BACKUP, DEFAULT_POLL_XML_BACKUP, False),
                (CONF_POLL_SNMP_LICENSES, DEFAULT_POLL_SNMP_LICENSES, True),
            ),
        },
    }
    return {
        name: section(vol.Schema(fields), {"collapsed": False})
        for name, fields in tiers.items()
    }


def _flatten(user_input: Mapping[str, Any]) -> dict[str, Any]:
    """Flatten section input ({"realtime": {...}, ...}) into one dict."""
    flat: dict[str, Any] = {}
    for key, value in user_input.items():
        if isinstance(value, Mapping):
            flat.update(value)
        else:
            flat[key] = value
    return flat


# ── Connection tests ──────────────────────────────────────────────────────────


async def async_test_xml_connection(
    hass: HomeAssistant, data: Mapping[str, Any]
) -> dict[str, str]:
    """Try the XML API with the given settings; return an error dict."""
    session = xml_session.create_xml_session(data.get(CONF_VERIFY_SSL, False))
    client = SophosClient(
        session,
        host=data[CONF_HOST],
        port=data[CONF_PORT],
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
    )
    try:
        await client.test_connection()
    except SophosAuthError:
        return {"base": "invalid_auth"}
    except SophosAccessError:
        return {"base": "api_access_denied"}
    except SophosError:
        return {"base": "cannot_connect"}
    except Exception:
        _LOGGER.exception("Unexpected error during XML connection test")
        return {"base": "unknown"}
    finally:
        await session.close()
    return {}


async def async_test_snmp_connection(
    hass: HomeAssistant, host: str, community: str
) -> dict[str, str]:
    """Try SNMP with the given settings; return an error dict."""
    client = SNMPClient(host, community=community)
    try:
        await client.preload(hass)
        await client.test_connection()
    except SophosSNMPError:
        return {"base": "snmp_cannot_connect"}
    except Exception:
        _LOGGER.exception("Unexpected error during SNMP connection test")
        return {"base": "unknown"}
    return {}


# ── Config flow ───────────────────────────────────────────────────────────────


class SophosFirewallConfigFlow(ConfigFlow, domain=DOMAIN):
    """Set up a Sophos Firewall."""

    VERSION = CONFIG_ENTRY_VERSION

    def __init__(self) -> None:
        self._connection: dict[str, Any] = {}
        self._options: dict[str, Any] = {}

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 1: connection settings."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._async_abort_entries_match(
                {CONF_HOST: user_input[CONF_HOST], CONF_PORT: user_input[CONF_PORT]}
            )
            errors = await async_test_xml_connection(self.hass, user_input)
            if not errors:
                await self.async_set_unique_id(
                    f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}"
                )
                self._abort_if_unique_id_configured()
                self._connection = user_input
                return await self.async_step_snmp()

        return self.async_show_form(
            step_id="user",
            data_schema=self.add_suggested_values_to_schema(
                _connection_schema(), _without_password(user_input)
            ),
            errors=errors,
        )

    async def async_step_snmp(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 2: optional SNMP."""
        errors: dict[str, str] = {}
        if user_input is not None:
            if user_input[CONF_SNMP_ENABLED]:
                errors = await async_test_snmp_connection(
                    self.hass, self._connection[CONF_HOST], user_input[CONF_SNMP_COMMUNITY]
                )
            if not errors:
                self._options.update(user_input)
                return await self.async_step_write_access()

        return self.async_show_form(
            step_id="snmp",
            data_schema=self.add_suggested_values_to_schema(
                vol.Schema(_snmp_fields()), user_input
            ),
            errors=errors,
        )

    async def async_step_write_access(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 3: optional write access."""
        if user_input is not None:
            self._options.update(user_input)
            return await self.async_step_polling()
        return self.async_show_form(step_id="write_access", data_schema=vol.Schema(_write_fields()))

    async def async_step_polling(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Step 4: polling intervals and data sources."""
        if user_input is not None:
            self._options.update(_flatten(user_input))
            return self.async_create_entry(
                title=self._connection[CONF_HOST],
                data=self._connection,
                options=self._options,
            )
        return self.async_show_form(
            step_id="polling",
            data_schema=vol.Schema(_polling_sections(self._options[CONF_SNMP_ENABLED])),
        )

    async def async_step_reauth(self, entry_data: Mapping[str, Any]) -> ConfigFlowResult:
        """Start re-authentication after the firewall rejected the credentials."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask for the new password."""
        errors: dict[str, str] = {}
        entry = self._get_reauth_entry()
        if user_input is not None:
            errors = await async_test_xml_connection(
                self.hass, {**entry.data, CONF_PASSWORD: user_input[CONF_PASSWORD]}
            )
            if not errors:
                return self._async_update_and_finish(
                    entry, data={**entry.data, CONF_PASSWORD: user_input[CONF_PASSWORD]}
                )
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
            description_placeholders={
                "host": entry.data[CONF_HOST],
                "username": entry.data[CONF_USERNAME],
            },
            errors=errors,
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Change the connection settings of an existing entry.

        Entity unique_ids do not contain host or port (since v1.1.0), so a new
        address keeps every entity and its history.
        """
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            host, port = user_input[CONF_HOST], user_input[CONF_PORT]
            for other in self._async_current_entries(include_ignore=False):
                if other.entry_id != entry.entry_id and (
                    (other.data.get(CONF_HOST), other.data.get(CONF_PORT)) == (host, port)
                    or other.unique_id == f"{host}:{port}"
                ):
                    return self.async_abort(reason="already_configured")
            errors = await async_test_xml_connection(self.hass, user_input)
            if not errors:
                return self._async_update_and_finish(
                    entry,
                    unique_id=f"{host}:{port}",
                    title=host if entry.title == entry.data[CONF_HOST] else entry.title,
                    data={**entry.data, **user_input},
                )
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_connection_schema(lambda key, default: entry.data.get(key, default)),
            description_placeholders={"host": entry.data[CONF_HOST]},
            errors=errors,
        )

    def _async_update_and_finish(
        self, entry: ConfigEntry, **changes: Any
    ) -> ConfigFlowResult:
        """Store new connection data and reload the entry exactly once.

        A loaded entry has an update listener that reloads it when its data
        changes (__init__.py); Home Assistant's async_update_reload_and_abort
        would reload it a second time, and warns about exactly that from
        2026.x on. An entry that is not loaded (setup failed) has no listener,
        and unchanged data (the same password entered again) does not make
        the listener reload — both are reloaded here, so polling that stopped
        on rejected credentials always starts again.
        """
        reason = "reauth_successful" if self.source == SOURCE_REAUTH else "reconfigure_successful"
        if entry.state is not ConfigEntryState.LOADED:
            return self.async_update_reload_and_abort(entry, reason=reason, **changes)
        data_changed = changes["data"] != dict(entry.data)
        self.hass.config_entries.async_update_entry(entry, **changes)
        if not data_changed:
            self.hass.config_entries.async_schedule_reload(entry.entry_id)
        return self.async_abort(reason=reason)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> SophosOptionsFlow:
        """Return the options flow handler."""
        return SophosOptionsFlow()


def _without_password(user_input: dict[str, Any] | None) -> dict[str, Any] | None:
    """Pre-fill a re-shown form, but never echo the password back."""
    if user_input is None:
        return None
    return {k: v for k, v in user_input.items() if k != CONF_PASSWORD}


class SophosOptionsFlow(OptionsFlow):
    """Change SNMP, write access and polling — one form."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show and store the options."""
        errors: dict[str, str] = {}
        options = self.config_entry.options
        flat: dict[str, Any] = {}

        def get(key: str, default: Any) -> Any:
            # Entered values first, so a form re-shown after an error keeps
            # them (HA 2025.x does not apply suggested values inside sections).
            return flat.get(key, options.get(key, default))

        if user_input is not None:
            flat = _flatten(user_input)
            snmp_changed = not options.get(CONF_SNMP_ENABLED) or flat[
                CONF_SNMP_COMMUNITY
            ] != options.get(CONF_SNMP_COMMUNITY)
            if flat[CONF_SNMP_ENABLED] and snmp_changed:
                errors = await async_test_snmp_connection(
                    self.hass, self.config_entry.data[CONF_HOST], flat[CONF_SNMP_COMMUNITY]
                )
            if not errors:
                return self.async_create_entry(data={**options, **flat})

        fields: dict[Any, Any] = {
            **_snmp_fields(get),
            **_write_fields(get),
            # All sources are shown, so SNMP sources can be chosen in the
            # same step that enables SNMP. They have no effect without SNMP.
            **_polling_sections(True, get),
        }
        schema = vol.Schema(fields)
        return self.async_show_form(
            step_id="init",
            data_schema=self.add_suggested_values_to_schema(schema, user_input),
            errors=errors,
        )
