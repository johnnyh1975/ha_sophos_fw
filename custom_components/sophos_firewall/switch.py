"""Switch platform for Sophos Firewall integration.

Switches are only registered when write_access is enabled.
Uses two-phase registration (same pattern as binary_sensor.py) to support
lazy loading — dynamic entities are added via coordinator listener.
"""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import (
    CONF_WRITE_ACCESS,
    DATA_FIREWALL_RULES,
    DATA_WEB_FILTER_POLICIES,
    DOMAIN,
)
from .coordinator import SophosCoordinator
from .entity import SophosEntity, field_str
from .sophos_client import SophosClient, SophosAPIError

_LOGGER = logging.getLogger(__name__)

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up switch entities — only when write_access is enabled."""
    if not entry.data.get(CONF_WRITE_ACCESS, False):
        return

    coordinator: SophosCoordinator = entry.runtime_data
    added_ids: set[str] = set()

    def _add_switches() -> None:
        data = coordinator.data
        if not data:
            return
        reg = er.async_get(coordinator.hass)
        new_entities: list[SwitchEntity] = []

        # ── Firewall rule switches ─────────────────────────────────────────────
        current_rule_names: set[str] = {
            r.get("Name", "") for r in data.get(DATA_FIREWALL_RULES, [])
        }
        for rule in data.get(DATA_FIREWALL_RULES, []):
            uid = f"{entry.entry_id}_switch_fwrule_{rule.get('Name','')}"
            if uid not in added_ids:
                added_ids.add(uid)
                new_entities.append(SophosFirewallRuleSwitch(coordinator, rule))

        for uid in list(added_ids):
            if not uid.startswith(f"{entry.entry_id}_switch_fwrule_"):
                continue
            name = uid[len(f"{entry.entry_id}_switch_fwrule_"):]
            if name not in current_rule_names:
                entity_id = reg.async_get_entity_id("switch", "sophos_firewall", uid)
                if entity_id:
                    reg.async_remove(entity_id)
                added_ids.discard(uid)

        # ── Web filter switches ────────────────────────────────────────────────
        current_policy_names: set[str] = {
            p.get("Name", "") for p in data.get(DATA_WEB_FILTER_POLICIES, [])
        }
        for policy in data.get(DATA_WEB_FILTER_POLICIES, []):
            uid = f"{entry.entry_id}_switch_webfilter_{policy.get('Name','')}"
            if uid not in added_ids:
                added_ids.add(uid)
                new_entities.append(SophosWebFilterSwitch(coordinator, policy))

        for uid in list(added_ids):
            if not uid.startswith(f"{entry.entry_id}_switch_webfilter_"):
                continue
            name = uid[len(f"{entry.entry_id}_switch_webfilter_"):]
            if name not in current_policy_names:
                entity_id = reg.async_get_entity_id("switch", "sophos_firewall", uid)
                if entity_id:
                    reg.async_remove(entity_id)
                added_ids.discard(uid)

        if new_entities:
            _LOGGER.debug("Adding %d switch entities", len(new_entities))
            async_add_entities(new_entities)

    entry.async_on_unload(
        coordinator.async_add_listener(_add_switches)
    )

    if coordinator.data:
        _add_switches()


class SophosFirewallRuleSwitch(SophosEntity, SwitchEntity, RestoreEntity):
    """Switch to enable/disable a Sophos firewall rule.

    EntityCategory.CONFIG — erscheint nur im Konfigurationsbereich der Geräte-Seite.
    RestoreEntity: zeigt letzten bekannten State sofort nach HA-Neustart.
    """

    _attr_translation_key = "firewall_rule"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:shield-outline"

    def __init__(
        self, coordinator: SophosCoordinator, rule: dict[str, Any]
    ) -> None:
        self._rule_name = rule.get("Name", "unknown")
        super().__init__(coordinator, unique_suffix=f"switch_fwrule_{self._rule_name}")
        self._attr_translation_placeholders = {"name": self._rule_name}
        self._restored_is_on: bool | None = None
        self._optimistic: bool | None = None

    async def async_added_to_hass(self) -> None:
        """Restore the last known state on startup."""
        await super().async_added_to_hass()
        last_state = await self.async_get_last_state()
        if last_state is not None and last_state.state in ("on", "off"):
            self._restored_is_on = last_state.state == "on"

    def _handle_coordinator_update(self) -> None:
        """Clear the optimistic override once fresh data has arrived."""
        self._optimistic = None
        super()._handle_coordinator_update()

    @property
    def is_on(self) -> bool | None:
        if self._optimistic is not None:
            return self._optimistic
        if self.coordinator.data is None:
            return self._restored_is_on
        for rule in self.coordinator.data.get(DATA_FIREWALL_RULES, []):
            if rule.get("Name") == self._rule_name:
                return field_str(rule, "Status").lower() == "enable"
        return None

    async def async_turn_on(self, **_: Any) -> None:
        await self._set(enable=True)

    async def async_turn_off(self, **_: Any) -> None:
        await self._set(enable=False)

    async def _set(self, enable: bool) -> None:
        client: SophosClient = self.coordinator.xml_client
        try:
            await client.set_firewall_rule_status(self._rule_name, enable)
        except SophosAPIError as exc:
            _LOGGER.error("Failed to set firewall rule %r: %s", self._rule_name, exc)
            # Write failed — force a refresh so the UI reverts to actual state
            self.coordinator.force_operative_refresh()
            await self.coordinator.async_request_refresh()
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="write_failed",
            ) from exc
        # Optimistic update: reflect the new state immediately rather than
        # showing stale data until the refresh round-trip completes.
        # _handle_coordinator_update() clears this once fresh data arrives.
        self._optimistic = enable
        self.async_write_ha_state()
        self.coordinator.force_operative_refresh()
        await self.coordinator.async_request_refresh()


class SophosWebFilterSwitch(SophosEntity, SwitchEntity, RestoreEntity):
    """Switch to toggle a web filter policy DefaultAction (Allow / Deny).

    ``is_on`` = True when DefaultAction == "Allow".
    EntityCategory.CONFIG — erscheint nur im Konfigurationsbereich der Geräte-Seite.
    RestoreEntity: zeigt letzten bekannten State sofort nach HA-Neustart.
    """

    _attr_translation_key = "web_filter_policy"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:filter-outline"

    def __init__(
        self, coordinator: SophosCoordinator, policy: dict[str, Any]
    ) -> None:
        self._policy_name = policy.get("Name", "unknown")
        super().__init__(
            coordinator, unique_suffix=f"switch_webfilter_{self._policy_name}"
        )
        self._attr_translation_placeholders = {"name": self._policy_name}
        self._restored_is_on: bool | None = None
        self._optimistic: bool | None = None

    async def async_added_to_hass(self) -> None:
        """Restore the last known state on startup."""
        await super().async_added_to_hass()
        last_state = await self.async_get_last_state()
        if last_state is not None and last_state.state in ("on", "off"):
            self._restored_is_on = last_state.state == "on"

    def _handle_coordinator_update(self) -> None:
        """Clear the optimistic override once fresh data has arrived."""
        self._optimistic = None
        super()._handle_coordinator_update()

    @property
    def is_on(self) -> bool | None:
        if self._optimistic is not None:
            return self._optimistic
        if self.coordinator.data is None:
            return self._restored_is_on
        for policy in self.coordinator.data.get(DATA_WEB_FILTER_POLICIES, []):
            if policy.get("Name") == self._policy_name:
                return field_str(policy, "DefaultAction").lower() == "allow"
        return None

    async def async_turn_on(self, **_: Any) -> None:
        await self._set(allow=True)

    async def async_turn_off(self, **_: Any) -> None:
        await self._set(allow=False)

    async def _set(self, allow: bool) -> None:
        client: SophosClient = self.coordinator.xml_client
        try:
            await client.set_web_filter_default_action(self._policy_name, allow)
        except SophosAPIError as exc:
            _LOGGER.error(
                "Failed to set web filter policy %r: %s", self._policy_name, exc
            )
            self.coordinator.force_operative_refresh()
            await self.coordinator.async_request_refresh()
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="write_failed",
            ) from exc
        self._optimistic = allow
        self.async_write_ha_state()
        self.coordinator.force_operative_refresh()
        await self.coordinator.async_request_refresh()
