"""Sophos Firewall integration for Home Assistant.

Setup
-----
1. The XML API client uses a dedicated aiohttp session that never reuses a
   connection (see session.py), closed on unload, on a failed or cancelled
   setup and when Home Assistant stops.
2. Setup waits for one XML request only — the admin settings: it proves
   connectivity, credentials and API access and yields the hostname the
   entity IDs of a new install are built from. On failure setup is retried
   (ConfigEntryNotReady), or the reauth flow starts on rejected credentials
   (ConfigEntryAuthFailed). The firewall answers one request after another,
   ~5 s each; waiting for all of them took 34 s on a real firewall. The
   other endpoints are fetched in the background right after.
3. SNMP is optional. Its coordinator refreshes in the background, so an
   unreachable SNMP agent neither delays nor blocks setup; SNMP entities
   report unavailable until the agent answers.
4. The device registry entry is created before the platforms, and kept up to
   date from both coordinators (hostname, model, firmware, serial).
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    EVENT_HOMEASSISTANT_CLOSE,
)
from homeassistant.core import Event, HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.util.hass_dict import HassKey

from .const import (
    CONF_SNMP_COMMUNITY,
    CONF_SNMP_ENABLED,
    CONF_VERIFY_SSL,
    CONFIG_ENTRY_VERSION,
    DEFAULT_PORT,
    DEFAULT_SNMP_COMMUNITY,
    DOMAIN,
    EP_ADMIN,
    MANUFACTURER,
    OBSOLETE_KEYS,
    PLATFORMS,
)
from . import session as xml_session
from .coordinator import SophosSnmpCoordinator, SophosXmlCoordinator
from .issues import ISSUE_SNMP_UNREACHABLE, async_clear_all_issues, async_clear_issue
from .snmp_client import SNMPClient
from .sophos_client import SophosClient

_LOGGER = logging.getLogger(__name__)

#: Entries whose state is watched to clear their repair issues when disabled.
_WATCHED: HassKey[set[str]] = HassKey(f"{DOMAIN}_watched_entries")


@dataclass(slots=True)
class SophosRuntimeData:
    """Objects owned by one config entry."""

    xml: SophosXmlCoordinator
    snmp: SophosSnmpCoordinator | None
    #: data and options the entry was set up with (see _async_update_listener)
    settings: tuple[dict[str, Any], dict[str, Any]] | None = None
    device_snapshot: tuple[object, ...] | None = None


type SophosConfigEntry = ConfigEntry[SophosRuntimeData]


async def async_setup_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Set up Sophos Firewall from a config entry."""
    started = time.monotonic()
    _async_clear_issues_when_disabled(hass, entry)
    host: str = entry.data[CONF_HOST]
    session = xml_session.create_xml_session(entry.data.get(CONF_VERIFY_SSL, False))
    entry.async_on_unload(session.close)

    async def _close_session(_: Event) -> None:
        # Stopping Home Assistant does not unload config entries.
        await session.close()

    entry.async_on_unload(hass.bus.async_listen(EVENT_HOMEASSISTANT_CLOSE, _close_session))
    client = SophosClient(
        session,
        host=host,
        port=entry.data.get(CONF_PORT, DEFAULT_PORT),
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
    )
    _migrate_unique_ids(hass, entry)
    xml = SophosXmlCoordinator(hass, entry, client)
    try:
        await xml.async_first_refresh_of(EP_ADMIN)
    except BaseException:  # also a setup cancelled because Home Assistant stops
        await session.close()  # setup is retried with a new session
        raise
    xml_done = time.monotonic()

    snmp: SophosSnmpCoordinator | None = None
    if entry.options.get(CONF_SNMP_ENABLED, False):
        snmp_client = SNMPClient(
            host,
            community=entry.options.get(CONF_SNMP_COMMUNITY, DEFAULT_SNMP_COMMUNITY),
        )
        try:
            await snmp_client.preload(hass)
        except Exception:  # SNMP is optional — never let it break setup
            _LOGGER.exception("SNMP could not be initialised for %s; continuing without SNMP", host)
        else:
            snmp = SophosSnmpCoordinator(hass, entry, snmp_client)
    snmp_done = time.monotonic()

    if snmp is None:  # SNMP switched off (or not usable): its issue no longer applies
        async_clear_issue(hass, entry, ISSUE_SNMP_UNREACHABLE)
    entry.runtime_data = SophosRuntimeData(xml=xml, snmp=snmp, settings=_settings(entry))

    _async_update_device(hass, entry)
    entry.async_on_unload(xml.async_add_listener(lambda: _async_update_device(hass, entry)))
    entry.async_create_background_task(
        hass, xml.async_refresh(), f"{DOMAIN} XML initial refresh {host}"
    )
    if snmp is not None:
        entry.async_on_unload(
            snmp.async_add_listener(lambda: _async_update_device(hass, entry))
        )
        entry.async_create_background_task(
            hass, snmp.async_refresh(), f"{DOMAIN} SNMP first refresh {host}"
        )

    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    done = time.monotonic()
    _LOGGER.debug(
        "Setup of %s took %.2f s: XML admin settings %.2f s, SNMP preload %.2f s, "
        "platforms %.2f s",
        host, done - started, xml_done - started, snmp_done - xml_done, done - snmp_done,
    )
    return True


CONNECTION_KEYS = frozenset({CONF_HOST, CONF_PORT, CONF_USERNAME, CONF_PASSWORD, CONF_VERIFY_SSL})
_V1_UNIQUE_ID = re.compile(r"^(?P<host>[^_]+)_(?P<port>\d+)_(?P<suffix>.+)$")


async def async_migrate_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Migrate a config entry from v1.0.x (version 1) to version 2.

    1. Entity unique_ids "{host}_{port}_{suffix}" → "{entry_id}_{suffix}".
       The entity registry entry is updated in place, so entity_ids, names,
       areas, disabled flags and the recorder history are kept. Leftovers
       from an earlier address (the old reconfigure flow orphaned them) are
       migrated too if their slot is free — restoring their customisations —
       and removed otherwise.
    2. Everything except the connection settings moves to entry.options.
    3. Settings without effect are dropped (SNMP version, zones, …).
    """
    if entry.version > CONFIG_ENTRY_VERSION:
        # Newer HA versions refuse downgrades before calling this; 2025.x does not.
        _LOGGER.error(
            "Config entry version %s is newer than this integration supports (%s) — "
            "downgrading is not possible",
            entry.version, CONFIG_ENTRY_VERSION,
        )
        return False
    if entry.version == 1:
        _migrate_unique_ids(hass, entry)
        options: dict[str, Any] = {
            key: value
            for key, value in {**entry.data, **entry.options}.items()
            if key not in CONNECTION_KEYS and key not in OBSOLETE_KEYS
        }
        data = {key: value for key, value in entry.data.items() if key in CONNECTION_KEYS}
        # v1.0.x reconfigure never updated the entry unique_id, so it can still
        # name an old address. Derive it from the current one unless another
        # entry already uses that.
        unique_id = f"{data[CONF_HOST]}:{data.get(CONF_PORT, DEFAULT_PORT)}"
        taken = hass.config_entries.async_entry_for_domain_unique_id(DOMAIN, unique_id)
        if taken is not None and taken.entry_id != entry.entry_id:
            unique_id = entry.unique_id or unique_id
        hass.config_entries.async_update_entry(
            entry,
            data=data,
            options=options,
            unique_id=unique_id,
            version=2,
            minor_version=1,
        )
        _LOGGER.info("Migrated %s to config entry version 2", entry.title)
    return True


def _migrate_unique_ids(hass: HomeAssistant, entry: SophosConfigEntry) -> None:
    """Convert host-based entity unique_ids of this entry (idempotent).

    Also run on every setup: Home Assistant saves the config entry within a
    second but the entity registry only minutes later during startup, so a
    hard stop in between leaves a version-2 entry with old unique_ids.
    """
    registry = er.async_get(hass)
    current = f"{entry.data.get(CONF_HOST)}_{entry.data.get(CONF_PORT, DEFAULT_PORT)}_"
    new_prefix = f"{entry.entry_id}_"
    plan: list[tuple[bool, er.RegistryEntry, str]] = []
    for reg_entry in er.async_entries_for_config_entry(registry, entry.entry_id):
        uid = reg_entry.unique_id
        if uid.startswith(new_prefix):
            continue
        if uid.startswith(current):
            plan.append((True, reg_entry, new_prefix + uid[len(current):]))
        elif match := _V1_UNIQUE_ID.match(uid):
            plan.append((False, reg_entry, new_prefix + match["suffix"]))
        else:
            # A leftover in no known format (e.g. an old host containing "_"):
            # it can never be provided again.
            _LOGGER.debug("Removing unrecognised leftover %s (%s)", reg_entry.entity_id, uid)
            registry.async_remove(reg_entry.entity_id)
    # Entities of the current address first: they win if an orphan collides.
    for is_current, reg_entry, new_uid in sorted(plan, key=lambda item: not item[0]):
        if registry.async_get_entity_id(reg_entry.domain, DOMAIN, new_uid):
            _LOGGER.debug("Removing duplicate %s (%s)", reg_entry.entity_id, reg_entry.unique_id)
            registry.async_remove(reg_entry.entity_id)
            continue
        registry.async_update_entity(reg_entry.entity_id, new_unique_id=new_uid)
        if not is_current:
            _LOGGER.info("Restored orphaned entity %s", reg_entry.entity_id)


async def async_unload_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> bool:
    """Unload a config entry."""
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_entry(hass: HomeAssistant, entry: SophosConfigEntry) -> None:
    """Delete the entry's repair issues when the entry is deleted."""
    async_clear_all_issues(hass, entry)
    hass.data.get(_WATCHED, set()).discard(entry.entry_id)


@callback
def _async_clear_issues_when_disabled(hass: HomeAssistant, entry: SophosConfigEntry) -> None:
    """Delete the entry's repair issues once the user disables the entry.

    A disabled entry no longer retries, so "the integration keeps retrying"
    would stay wrong until the entry is deleted. Watched through the entry's
    state: when disabled while waiting for a retry (setup failed — the usual
    case of "API access denied"), Home Assistant does not call
    async_unload_entry. Registered once per entry: state callbacks survive
    reloads and failed setups.
    """
    watched = hass.data.setdefault(_WATCHED, set())
    if entry.entry_id in watched:
        return
    watched.add(entry.entry_id)

    @callback
    def _state_changed() -> None:
        if entry.disabled_by is not None:
            async_clear_all_issues(hass, entry)

    entry.async_on_state_change(_state_changed)


def _settings(entry: SophosConfigEntry) -> tuple[dict[str, Any], dict[str, Any]]:
    return dict(entry.data), dict(entry.options)


async def _async_update_listener(hass: HomeAssistant, entry: SophosConfigEntry) -> None:
    """Reload the entry when its data or options changed.

    The only reload path while the entry is loaded: the options flow, and the
    reauth and reconfigure flows (config_flow.py), just update the entry.
    Renaming the entry changes neither and does not reload it.
    """
    if _settings(entry) != entry.runtime_data.settings:
        await hass.config_entries.async_reload(entry.entry_id)


@callback
def _async_update_device(hass: HomeAssistant, entry: SophosConfigEntry) -> None:
    """Create or update the firewall's device registry entry.

    Only values that are actually known are written, so a not-yet-answering
    SNMP agent never blanks out a model or firmware version learned earlier,
    and a failed hostname fetch never renames the device to its IP address.
    """
    runtime = entry.runtime_data
    admin = runtime.xml.data.admin if runtime.xml.data else None
    device = runtime.snmp.data.device if runtime.snmp and runtime.snmp.data else None

    host = entry.data[CONF_HOST]
    port = entry.data.get(CONF_PORT, DEFAULT_PORT)
    registry = dr.async_get(hass)
    details: dict[str, str] = {}
    if name := (admin.hostname if admin else None) or (device.name if device else None):
        details["name"] = name
    elif not dr.async_entries_for_config_entry(registry, entry.entry_id):
        details["name"] = host  # brand-new device and no hostname known yet
    if device is not None:
        for field, value in (
            ("model", device.model),
            ("sw_version", device.firmware),
            ("serial_number", device.serial),
        ):
            if value:
                details[field] = value

    snapshot = (host, port, *sorted(details.items()))
    if snapshot == runtime.device_snapshot:
        return
    runtime.device_snapshot = snapshot
    registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, entry.entry_id)},
        manufacturer=MANUFACTURER,
        configuration_url=f"https://{host}:{port}",
        **details,  # type: ignore[arg-type]
    )
