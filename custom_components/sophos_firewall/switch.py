"""Switch platform for the Sophos Firewall integration.

Switches exist only with write access enabled. After a successful write the
new state is shown optimistically until the written endpoint has actually
been re-read from the firewall.
"""
from __future__ import annotations

import time
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import SophosConfigEntry
from .const import CONF_WRITE_ACCESS, DOMAIN, EP_FIREWALL_RULES, EP_WEB_FILTER
from .coordinator import SophosXmlCoordinator
from .entity import (
    DynamicFamily,
    SophosXmlEntity,
    async_remove_stale_entities,
    async_setup_dynamic_entities,
)
from .models import FirewallRule, WebFilterPolicy, XmlData
from .sophos_client import SophosError

# Writes go to the firewall one at a time.
PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up switches — only when write access is enabled."""
    if not entry.options.get(CONF_WRITE_ACCESS, False):
        # Switches from a period with write access would otherwise linger as
        # unavailable entities. Configuration-driven, so remove_all is safe.
        for family in ("switch_fwrule_", "switch_webfilter_"):
            async_remove_stale_entities(hass, entry, "switch", family, (), remove_all=True)
        return

    async_setup_dynamic_entities(
        hass, entry, entry.runtime_data.xml, "switch", async_add_entities,
        [
            DynamicFamily(
                "switch_fwrule_", EP_FIREWALL_RULES, _rule_items, SophosFirewallRuleSwitch
            ),
            DynamicFamily(
                "switch_webfilter_", EP_WEB_FILTER, _policy_items, SophosWebFilterSwitch
            ),
        ],
    )


def _rule_items(data: XmlData) -> dict[str, FirewallRule] | None:
    if data.firewall_rules is None:
        return None
    return {f"switch_fwrule_{name}": rule for name, rule in data.firewall_rules.items()}


def _policy_items(data: XmlData) -> dict[str, WebFilterPolicy] | None:
    if data.web_filter_policies is None:
        return None
    return {f"switch_webfilter_{n}": p for n, p in data.web_filter_policies.items()}


class _SophosWriteSwitch(SophosXmlEntity, SwitchEntity):
    """Common write/optimistic-state handling."""

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: SophosXmlCoordinator, suffix: str, endpoint: str) -> None:
        super().__init__(coordinator, suffix, endpoint)
        self._optimistic: bool | None = None
        self._written_at: float | None = None

    def _actual(self) -> bool | None:
        raise NotImplementedError

    async def _write(self, on: bool) -> None:
        raise NotImplementedError

    @property
    def is_on(self) -> bool | None:
        if self._optimistic is not None:
            return self._optimistic
        return self._actual()

    @callback
    def _handle_coordinator_update(self) -> None:
        """Drop the optimistic state once the endpoint was re-read after the write."""
        fetched = self.coordinator.fetched_at(self._endpoint or "")
        if self._written_at is not None and fetched is not None and fetched > self._written_at:
            self._optimistic = None
            self._written_at = None
        super()._handle_coordinator_update()

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set(False)

    async def _set(self, on: bool) -> None:
        try:
            await self._write(on)
        except SophosError as exc:
            await self.coordinator.async_refresh_endpoints(self._endpoint or "")
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="write_failed",
                translation_placeholders={"name": self._object_name, "error": str(exc)},
            ) from exc
        self._optimistic = on
        self._written_at = time.monotonic()
        self.async_write_ha_state()
        await self.coordinator.async_refresh_endpoints(self._endpoint or "")

    @property
    def _object_name(self) -> str:
        raise NotImplementedError


class SophosFirewallRuleSwitch(_SophosWriteSwitch):
    """Enable/disable a firewall rule."""

    _attr_translation_key = "firewall_rule"

    def __init__(self, coordinator: SophosXmlCoordinator, rule: FirewallRule) -> None:
        super().__init__(coordinator, f"switch_fwrule_{rule.name}", EP_FIREWALL_RULES)
        self._name = rule.name
        self._attr_translation_placeholders = {"name": rule.name}

    @property
    def _object_name(self) -> str:
        return self._name

    def _actual(self) -> bool | None:
        rule = (self.xml.firewall_rules or {}).get(self._name)
        return rule.enabled if rule else None

    async def _write(self, on: bool) -> None:
        await self.coordinator.client.set_firewall_rule_status(self._name, on)


class SophosWebFilterSwitch(_SophosWriteSwitch):
    """Toggle a web filter policy's DefaultAction (on = Allow)."""

    _attr_translation_key = "web_filter_policy"

    def __init__(self, coordinator: SophosXmlCoordinator, policy: WebFilterPolicy) -> None:
        super().__init__(coordinator, f"switch_webfilter_{policy.name}", EP_WEB_FILTER)
        self._name = policy.name
        self._attr_translation_placeholders = {"name": policy.name}

    @property
    def _object_name(self) -> str:
        return self._name

    def _actual(self) -> bool | None:
        policy = (self.xml.web_filter_policies or {}).get(self._name)
        return policy.allows if policy else None

    async def _write(self, on: bool) -> None:
        await self.coordinator.client.set_web_filter_default_action(self._name, on)
