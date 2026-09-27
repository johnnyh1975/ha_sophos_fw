"""Base entity class and dynamic-entity management."""
from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, EMPTY_CONFIRMATIONS
from .coordinator import SophosCoordinator, SophosSnmpCoordinator, SophosXmlCoordinator
from .models import SnmpData, XmlData

_LOGGER = logging.getLogger(__name__)


def _slug(text: str) -> str:
    """Convert text to a safe entity-ID slug (lowercase, underscores)."""
    return re.sub(r"[^a-z0-9]+", "_", str(text).lower()).strip("_")


def build_unique_id(entry: ConfigEntry, unique_suffix: str) -> str:
    """Return the registry unique_id for an entity of this config entry.

    Single source of truth for SophosEntity and async_remove_stale_entities().

    Based on the config entry ID — Home Assistant's documented unique ID of
    last resort: the XML API exposes no serial number, and host/IP are not
    acceptable sources (they change, e.g. via the reconfigure flow). Until
    v1.1.0 this was "{host}_{port}_{suffix}"; async_migrate_entry() converts it.
    """
    return f"{entry.entry_id}_{unique_suffix}"


@callback
def async_remove_stale_entities(
    hass: HomeAssistant,
    entry: ConfigEntry,
    domain: str,
    suffix_prefix: str,
    current_suffixes: Iterable[str],
    *,
    remove_all: bool = False,
) -> set[str]:
    """Remove registry entities that no longer correspond to firewall objects.

    Reads the entity registry itself, so entities created in an earlier HA
    session are found too — the case that matters after an update.

    Safety guard: an empty ``current_suffixes`` removes nothing unless
    ``remove_all`` is set (configuration-driven removal only). Removing a
    registry entry discards the user's customisations, so an empty result
    must never trigger it on its own.

    Returns the set of removed unique_suffixes.
    """
    current = set(current_suffixes)
    if not current and not remove_all:
        return set()

    registry = er.async_get(hass)
    base = build_unique_id(entry, "")
    family = base + suffix_prefix
    removed: set[str] = set()
    for reg_entry in er.async_entries_for_config_entry(registry, entry.entry_id):
        if reg_entry.domain != domain or not reg_entry.unique_id.startswith(family):
            continue
        suffix = reg_entry.unique_id[len(base):]
        if remove_all or suffix not in current:
            _LOGGER.debug("Removing stale entity %s (%s)", reg_entry.entity_id, suffix)
            registry.async_remove(reg_entry.entity_id)
            removed.add(suffix)
    return removed


@callback
def async_remove_entities(
    hass: HomeAssistant, entry: ConfigEntry, domain: str, suffixes: Iterable[str]
) -> None:
    """Remove the registry entries with exactly these unique_suffixes."""
    registry = er.async_get(hass)
    for suffix in suffixes:
        if entity_id := registry.async_get_entity_id(
            domain, DOMAIN, build_unique_id(entry, suffix)
        ):
            _LOGGER.debug("Removing entity %s (source disabled)", entity_id)
            registry.async_remove(entity_id)


def _registered_suffixes(
    hass: HomeAssistant, entry: ConfigEntry, domain: str, suffix_prefix: str
) -> set[str]:
    """Unique_id suffixes of the entry's registry entities in one family."""
    base = build_unique_id(entry, "")
    family = base + suffix_prefix
    return {
        reg_entry.unique_id[len(base):]
        for reg_entry in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
        if reg_entry.domain == domain and reg_entry.unique_id.startswith(family)
    }


class SophosEntity[CoordinatorT: SophosCoordinator[Any, Any]](CoordinatorEntity[CoordinatorT]):
    """Base class for all Sophos Firewall entities.

    * ``unique_id`` — see build_unique_id().
    * ``suggested_object_id`` — the suffix only; Home Assistant prepends the
      device name (has_entity_name), so the hostname is not repeated.
    * ``available`` — the coordinator is up *and* the endpoint that feeds
      this entity was fetched successfully last time (``endpoint=None``:
      coordinator availability only, e.g. for action entities).
    """

    _attr_has_entity_name = True

    def __init__(
        self, coordinator: CoordinatorT, unique_suffix: str, endpoint: str | None
    ) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._unique_suffix = unique_suffix
        self._endpoint = endpoint
        self._attr_unique_id = build_unique_id(entry, unique_suffix)
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry.entry_id)})

    @property
    def endpoint(self) -> str | None:
        """Return the endpoint feeding this entity (None: coordinator only)."""
        return self._endpoint

    @property
    def unique_suffix(self) -> str:
        """Return the unique_id suffix."""
        return self._unique_suffix

    @property
    def suggested_object_id(self) -> str:
        """Return the suffix slug; Home Assistant prepends the device name."""
        return _slug(self._unique_suffix)

    @property
    def available(self) -> bool:
        """Return True if the feeding endpoint delivered data last time."""
        if not super().available:
            return False
        return self._endpoint is None or self.coordinator.endpoint_available(self._endpoint)


class SophosXmlEntity(SophosEntity[SophosXmlCoordinator]):
    """Entity fed by the XML API coordinator."""

    @property
    def xml(self) -> XmlData:
        """Return the current XML data."""
        return self.coordinator.data


class SophosSnmpEntity(SophosEntity[SophosSnmpCoordinator]):
    """Entity fed by the SNMP coordinator."""

    @property
    def snmp(self) -> SnmpData:
        """Return the current SNMP data."""
        return self.coordinator.data


@dataclass(frozen=True, slots=True)
class DynamicFamily[CoordinatorT: SophosCoordinator[Any, Any], ItemT]:
    """A family of entities created per firewall object.

    ``items`` maps each unique_suffix to the object an entity is built from;
    it returns None when the endpoint was never fetched.

    ``remove_stale=False`` for entities that are created once a value shows
    up but must not disappear when a single reading is missing (hardware
    sensors, version strings).

    ``trust_empty=True`` when a successful fetch that returns no objects
    means "there are none" — plausible for SNMP table walks, which are
    all-or-nothing. The table must then stay empty for EMPTY_CONFIRMATIONS
    consecutive successful fetches before the last entities are removed, so
    a transiently empty table (e.g. while the firewall's IPsec service is
    still starting) does not delete customised entities.
    XML families keep the guard: an XML answer can be empty because the API
    profile lacks permission for the object type.

    ``confirm_missing=True`` keeps a single entity whose object is missing
    until it was absent for EMPTY_CONFIRMATIONS consecutive successful
    fetches — for objects the agent derives from runtime state (kernel
    network devices) rather than configuration: a VLAN or bridge can be
    missing briefly while the firewall boots, and removing its registry
    entry loses the user's customisations (HA 2025.5 restores neither the
    name nor the enabled state when the entity is re-created).
    """

    prefix: str
    endpoint: str
    items: Callable[[Any], Mapping[str, ItemT] | None]
    factory: Callable[[CoordinatorT, ItemT], Entity]
    remove_stale: bool = True
    trust_empty: bool = False
    confirm_missing: bool = False


@callback
def async_add_static_entities(
    hass: HomeAssistant,
    entry: ConfigEntry,
    domain: str,
    async_add_entities: AddEntitiesCallback,
    entities: Iterable[SophosEntity[Any]],
) -> None:
    """Add entities whose data source is enabled; remove the others.

    An entity whose endpoint the user switched off in the options would
    otherwise stay "unavailable" forever. Removal is configuration-driven,
    and switching the source back on recreates the entity.
    """
    keep: list[SophosEntity[Any]] = []
    drop: list[str] = []
    for entity in entities:
        if entity.endpoint is None or entity.coordinator.endpoint_configured(entity.endpoint):
            keep.append(entity)
        else:
            drop.append(entity.unique_suffix)
    async_remove_entities(hass, entry, domain, drop)
    async_add_entities(keep)


@callback
def async_setup_dynamic_entities[CoordinatorT: SophosCoordinator[Any, Any]](
    hass: HomeAssistant,
    entry: ConfigEntry,
    coordinator: CoordinatorT,
    domain: str,
    async_add_entities: AddEntitiesCallback,
    families: Iterable[DynamicFamily[CoordinatorT, Any]],
) -> None:
    """Add entities for new firewall objects and remove those that vanished.

    Runs now and after every coordinator update. A family is only touched
    when its endpoint's last fetch succeeded — a failed fetch never adds or
    removes anything. Families whose source the user switched off in the
    options are removed entirely (configuration-driven).
    """
    active: list[DynamicFamily[CoordinatorT, Any]] = []
    for family in families:
        if coordinator.endpoint_configured(family.endpoint):
            active.append(family)
        else:
            async_remove_stale_entities(hass, entry, domain, family.prefix, (), remove_all=True)
    families = tuple(active)
    known: set[str] = set()
    empty_streak: dict[str, int] = {}
    last_fetch: dict[str, float | None] = {}
    missing_streak: dict[str, int] = {}
    last_missing_fetch: dict[str, float | None] = {}

    @callback
    def _still_confirming(
        family: DynamicFamily[CoordinatorT, Any], present: set[str]
    ) -> set[str]:
        """Suffixes missing now but not yet for EMPTY_CONFIRMATIONS fetches."""
        prefix = family.prefix
        fetched = coordinator.fetched_at(family.endpoint)
        new_fetch = fetched != last_missing_fetch.get(prefix)
        last_missing_fetch[prefix] = fetched
        keep: set[str] = set()
        for suffix in _registered_suffixes(hass, entry, domain, prefix) - present:
            if new_fetch:  # count each fetch once
                missing_streak[suffix] = missing_streak.get(suffix, 0) + 1
            if missing_streak.get(suffix, 0) < EMPTY_CONFIRMATIONS:
                keep.add(suffix)
        for suffix in present:
            missing_streak.pop(suffix, None)
        return keep

    @callback
    def _sync() -> None:
        if coordinator.data is None:
            return
        new_entities: list[Entity] = []
        for family in families:
            if not coordinator.endpoint_available(family.endpoint):
                continue
            items = family.items(coordinator.data)
            if items is None:
                continue
            for suffix, item in items.items():
                if suffix not in known:
                    known.add(suffix)
                    new_entities.append(family.factory(coordinator, item))
            if not family.remove_stale:
                continue
            remove_all = False
            if family.trust_empty and not items:
                fetched = coordinator.fetched_at(family.endpoint)
                if fetched != last_fetch.get(family.prefix):  # count each fetch once
                    last_fetch[family.prefix] = fetched
                    empty_streak[family.prefix] = empty_streak.get(family.prefix, 0) + 1
                remove_all = empty_streak[family.prefix] >= EMPTY_CONFIRMATIONS
            else:
                empty_streak.pop(family.prefix, None)
            current = set(items)
            if family.confirm_missing:
                current |= _still_confirming(family, current)
            known.difference_update(
                async_remove_stale_entities(
                    hass, entry, domain, family.prefix, current, remove_all=remove_all
                )
            )
        if new_entities:
            async_add_entities(new_entities)

    _sync()
    entry.async_on_unload(coordinator.async_add_listener(_sync))
