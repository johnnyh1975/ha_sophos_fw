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
from .const import (
    CONF_WRITE_ACCESS,
    DOMAIN,
    EP_FIREWALL_RULES,
    EP_TUNNELS,
    EP_WEB_FILTER,
    EP_WIRELESS,
    VPN_ACTIVATED,
)
from .coordinator import SophosCoordinator, SophosSnmpCoordinator, SophosXmlCoordinator
from .entity import (
    DynamicFamily,
    SophosEntity,
    async_remove_stale_entities,
    async_setup_dynamic_entities,
)
from .models import FirewallRule, SnmpData, VpnTunnel, WebFilterPolicy, WirelessNetwork, XmlData
from .sophos_client import SophosClient, SophosError

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
        for family in ("switch_fwrule_", "switch_webfilter_", "switch_wlan_", "switch_ipsec_"):
            async_remove_stale_entities(hass, entry, "switch", family, (), remove_all=True)
        return

    runtime = entry.runtime_data
    async_setup_dynamic_entities(
        hass, entry, runtime.xml, "switch", async_add_entities,
        [
            DynamicFamily(
                "switch_fwrule_", EP_FIREWALL_RULES, _rule_items, SophosFirewallRuleSwitch
            ),
            DynamicFamily(
                "switch_webfilter_", EP_WEB_FILTER, _policy_items, SophosWebFilterSwitch
            ),
            DynamicFamily(
                "switch_wlan_", EP_WIRELESS, _wlan_items, SophosWirelessNetworkSwitch
            ),
        ],
    )
    if (snmp := runtime.snmp) is None:
        return
    client = runtime.xml.client
    # IPsec connections: state from the SNMP tunnel table, written through
    # the XML API (untested: no appliance with IPsec available).
    async_setup_dynamic_entities(
        hass, entry, snmp, "switch", async_add_entities,
        [
            DynamicFamily(
                "switch_ipsec_", EP_TUNNELS, _ipsec_items,
                lambda coordinator, tunnel: SophosIpsecSwitch(coordinator, tunnel, client),
                trust_empty=True,
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


def _wlan_items(data: XmlData) -> dict[str, WirelessNetwork] | None:
    if data.wireless_networks is None:
        return None
    return {f"switch_wlan_{hw}": net for hw, net in data.wireless_networks.items()}


def _ipsec_items(data: SnmpData) -> dict[str, VpnTunnel] | None:
    if data.tunnels is None:
        return None
    return {f"switch_ipsec_{t.index}": t for t in data.tunnels.values() if t.name}


class _SophosWriteSwitch[CoordinatorT: SophosCoordinator[Any, Any]](
    SophosEntity[CoordinatorT], SwitchEntity
):
    """Common write/optimistic-state handling."""

    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: CoordinatorT, suffix: str, endpoint: str) -> None:
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


class SophosFirewallRuleSwitch(_SophosWriteSwitch[SophosXmlCoordinator]):
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
        rule = (self.coordinator.data.firewall_rules or {}).get(self._name)
        return rule.enabled if rule else None

    async def _write(self, on: bool) -> None:
        await self.coordinator.client.set_firewall_rule_status(self._name, on)


class SophosWebFilterSwitch(_SophosWriteSwitch[SophosXmlCoordinator]):
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
        policy = (self.coordinator.data.web_filter_policies or {}).get(self._name)
        return policy.allows if policy else None

    async def _write(self, on: bool) -> None:
        await self.coordinator.client.set_web_filter_default_action(self._name, on)


class SophosWirelessNetworkSwitch(_SophosWriteSwitch[SophosXmlCoordinator]):
    """Switch a wireless network on or off (untested: no appliance with APs).

    Written with <WirelessNetworkStatus> and the network's HardwareName.
    """

    _attr_translation_key = "wireless_network"

    def __init__(self, coordinator: SophosXmlCoordinator, network: WirelessNetwork) -> None:
        super().__init__(coordinator, f"switch_wlan_{network.hardware_name}", EP_WIRELESS)
        self._hardware = network.hardware_name
        self._attr_translation_placeholders = {"name": network.name}

    def _network(self) -> WirelessNetwork | None:
        return (self.coordinator.data.wireless_networks or {}).get(self._hardware)

    @property
    def _object_name(self) -> str:
        network = self._network()
        return network.name if network else self._hardware

    def _actual(self) -> bool | None:
        network = self._network()
        return network.enabled if network else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        network = self._network()
        return {} if network is None else {"ssid": network.ssid, "interface": self._hardware}

    async def _write(self, on: bool) -> None:
        await self.coordinator.client.set_wireless_network_status(self._hardware, on)


class SophosIpsecSwitch(_SophosWriteSwitch[SophosSnmpCoordinator]):
    """Activate or deactivate an IPsec connection (untested: no IPsec available).

    State: sfosIPSecVpnActivated from the SNMP tunnel table. Write: XML
    <VPNIPSecConnection><Active|DeActive> with the connection name as SNMP
    reports it; that it equals the name in the XML API is not verified.
    """

    _attr_translation_key = "ipsec_connection"

    def __init__(
        self, coordinator: SophosSnmpCoordinator, tunnel: VpnTunnel, client: SophosClient
    ) -> None:
        super().__init__(coordinator, f"switch_ipsec_{tunnel.index}", EP_TUNNELS)
        self._index = tunnel.index
        self._conn_name = tunnel.name
        self._client = client
        self._attr_translation_placeholders = {"name": tunnel.name}

    def _tunnel(self) -> VpnTunnel | None:
        return (self.coordinator.data.tunnels or {}).get(self._index)

    @property
    def _object_name(self) -> str:
        return self._conn_name

    def _actual(self) -> bool | None:
        tunnel = self._tunnel()
        if tunnel is None or tunnel.activated is None:
            return None
        return tunnel.activated == VPN_ACTIVATED

    async def _write(self, on: bool) -> None:
        await self._client.set_ipsec_connection_active(self._conn_name, on)
