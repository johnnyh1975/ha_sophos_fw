"""Sophos Firewall integration for Home Assistant.

Startup strategy
----------------
Phase 1 — connectivity check (~1s, blocking):
    Open the persistent HTTP session and verify credentials with one
    lightweight XML call. Raises ConfigEntryNotReady immediately if the
    firewall is unreachable or credentials are wrong.

Phase 2 — SNMP preload (executor thread, non-blocking):
    The puresnmp MPM plugin is loaded in an executor thread so that
    subsequent SNMP calls never block the event loop.

Phase 3 — background data fetch (fire-and-forget):
    Full coordinator refresh runs as a HA task after setup returns.
    Entities start as ``unavailable`` and populate after the first fetch.
"""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_PORT, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError

from .const import (
    CONF_SNMP_COMMUNITY,
    CONF_SNMP_ENABLED,
    CONF_SNMP_VERSION,
    CONF_VERIFY_SSL,
    DEFAULT_SNMP_COMMUNITY,
    DEFAULT_SNMP_VERSION,
    DOMAIN,
    PLATFORMS,
)
from .coordinator import SophosCoordinator
from .snmp_client import SNMPClient
from .sophos_client import SophosAPIError, SophosAuthError, SophosClient

_LOGGER = logging.getLogger(__name__)

type SophosConfigEntry = ConfigEntry[SophosCoordinator]


async def async_setup_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Set up Sophos Firewall from a config entry."""
    xml_client = SophosClient(
        host=entry.data[CONF_HOST],
        port=entry.data[CONF_PORT],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        verify_ssl=entry.data.get(CONF_VERIFY_SSL, False),
    )

    snmp_client: SNMPClient | None = None
    if entry.data.get(CONF_SNMP_ENABLED):
        snmp_client = SNMPClient(
            host=entry.data[CONF_HOST],
            community=entry.data.get(CONF_SNMP_COMMUNITY, DEFAULT_SNMP_COMMUNITY),
            version=entry.data.get(CONF_SNMP_VERSION, DEFAULT_SNMP_VERSION),
        )

    # ── Phase 1: connectivity check ───────────────────────────────────────────
    await xml_client.open()
    try:
        api_version = await xml_client.test_connection()
        _LOGGER.debug(
            "Sophos Firewall at %s reachable (API %s)",
            entry.data[CONF_HOST], api_version,
        )
    except SophosAuthError as exc:
        await xml_client.close()
        raise ConfigEntryNotReady(
            translation_domain=DOMAIN,
            translation_key="setup_auth_failed",
        ) from exc
    except (SophosAPIError, TimeoutError, OSError) as exc:
        await xml_client.close()
        raise ConfigEntryNotReady(
            translation_domain=DOMAIN,
            translation_key="setup_cannot_connect",
            translation_placeholders={
                "host": entry.data[CONF_HOST],
                "port": str(entry.data[CONF_PORT]),
            },
        ) from exc

    # ── Phase 2: SNMP MPM preload in executor ─────────────────────────────────
    if snmp_client is not None:
        try:
            await snmp_client.preload()
        except Exception as exc:  # noqa: BLE001 — SNMP preload failure is non-fatal
            _LOGGER.warning("SNMP preload failed (SNMP will be disabled): %s", exc)
            snmp_client = None

    # ── Phase 3: initial data fetch ───────────────────────────────────────────
    coordinator = SophosCoordinator(hass, entry, xml_client, snmp_client)

    # async_config_entry_first_refresh raises ConfigEntryNotReady on failure,
    # which causes HA to retry setup with backoff — the standard pattern.
    # Entities are available immediately after setup rather than starting as
    # "unavailable" and populating after the first background poll.
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = coordinator
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    # Setze unique_id falls noch nicht gesetzt (Migration von älteren Versionen)
    if not entry.unique_id:
        hass.config_entries.async_update_entry(
            entry, unique_id=f"{entry.data[CONF_HOST]}:{entry.data.get(CONF_PORT, 4444)}"
        )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    _LOGGER.info(
        "Sophos Firewall loaded — entities populate after first background fetch"
    )
    return True


async def async_migrate_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Migrate config entry to current version.

    Called by HA when entry.version < current integration version.
    Returns True if migration succeeded, False to abort setup.
    """
    _LOGGER.debug(
        "Migrating Sophos Firewall entry from version %s", entry.version
    )
    # Aktuell keine Daten-Migrationen nötig — Struktur ist stabil seit v0.5.
    # Dieser Hook ist vorbereitet für künftige Versionssprünge.
    return True


async def async_unload_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Unload all platforms and close HTTP session."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.async_close()
    return unloaded


async def _async_update_listener(hass: HomeAssistant, entry: SophosConfigEntry) -> None:
    """Reload the integration when options are changed."""
    await hass.config_entries.async_reload(entry.entry_id)
