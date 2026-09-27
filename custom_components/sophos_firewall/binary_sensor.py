"""Binary sensor platform for the Sophos Firewall integration."""
from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import SophosConfigEntry
from .const import (
    CONF_SNMP_ENABLED,
    CONF_WRITE_ACCESS,
    EP_FIREWALL_RULES,
    EP_HA,
    EP_HEALTH,
    EP_INTERFACES,
    EP_TUNNELS,
    VPN_ACTIVATED,
    VPN_STATUS_ACTIVE,
    VPN_STATUS_PARTIALLY_ACTIVE,
)
from .coordinator import SophosSnmpCoordinator, SophosXmlCoordinator
from .entity import (
    DynamicFamily,
    SophosSnmpEntity,
    SophosXmlEntity,
    async_add_static_entities,
    async_remove_entities,
    async_remove_stale_entities,
    async_setup_dynamic_entities,
)
from .models import FirewallRule, Interface, SnmpData, VpnTunnel

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up binary sensors."""
    runtime = entry.runtime_data
    write_access: bool = entry.options.get(CONF_WRITE_ACCESS, False)

    xml_families: list[DynamicFamily[SophosXmlCoordinator, Any]] = [
        DynamicFamily(
            "iface_", EP_INTERFACES,
            lambda d: _keyed("iface_", d.interfaces), SophosInterfaceSensor,
        ),
    ]
    if write_access:
        # The switch platform owns firewall rules; drop read-only rule sensors
        # left over from before write access was enabled (configuration-driven,
        # so removing the whole family is safe).
        async_remove_stale_entities(hass, entry, "binary_sensor", "fwrule_", (), remove_all=True)
    else:
        xml_families.append(
            DynamicFamily(
                "fwrule_", EP_FIREWALL_RULES,
                lambda d: _keyed("fwrule_", d.firewall_rules), SophosFirewallRuleSensor,
            )
        )
    async_setup_dynamic_entities(
        hass, entry, runtime.xml, "binary_sensor", async_add_entities, xml_families
    )

    if (snmp := runtime.snmp) is None:
        if not entry.options.get(CONF_SNMP_ENABLED, False):
            # SNMP switched off in the options (configuration-driven, see sensor.py)
            async_remove_entities(hass, entry, "binary_sensor", ["ha_enabled"])
            for prefix in ("vpn_", "psu_"):
                async_remove_stale_entities(hass, entry, "binary_sensor", prefix, (), remove_all=True)
        return
    async_add_static_entities(
        hass, entry, "binary_sensor", async_add_entities, [SophosHAEnabledSensor(snmp)]
    )
    async_setup_dynamic_entities(
        hass, entry, snmp, "binary_sensor", async_add_entities,
        [
            # An empty tunnel table after a successful walk means "no IPsec
            # connections" — this also removes the policy-table leftovers of
            # v1.0.2 (#18) on firewalls without IPsec.
            DynamicFamily(
                "vpn_", EP_TUNNELS, _vpn_items, SophosVPNTunnelSensor, trust_empty=True
            ),
            # A failed PSU may drop out of the table — its entity must stay so
            # alerts can fire, hence no stale removal for hardware.
            DynamicFamily("psu_", EP_HEALTH, _psu_items, SophosPSUSensor, remove_stale=False),
        ],
    )


def _keyed[T](prefix: str, items: dict[str, T] | None) -> dict[str, T] | None:
    return None if items is None else {f"{prefix}{name}": item for name, item in items.items()}


def _vpn_items(data: SnmpData) -> dict[str, VpnTunnel] | None:
    return None if data.tunnels is None else {f"vpn_{i}": t for i, t in data.tunnels.items()}


def _psu_items(data: SnmpData) -> dict[str, str] | None:
    if data.health is None:
        return None
    return {f"psu_{key}": key for key in data.health.psus}


# ── XML entities ──────────────────────────────────────────────────────────────


class SophosInterfaceSensor(SophosXmlEntity, BinarySensorEntity):
    """Network interface up/down."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = "interface_status"

    def __init__(self, coordinator: SophosXmlCoordinator, iface: Interface) -> None:
        super().__init__(coordinator, f"iface_{iface.name}", EP_INTERFACES)
        self._name = iface.name
        self._attr_translation_placeholders = {"name": iface.name}

    def _iface(self) -> Interface | None:
        return (self.xml.interfaces or {}).get(self._name)

    @property
    def is_on(self) -> bool | None:
        iface = self._iface()
        return iface.is_up if iface else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if (iface := self._iface()) is None:
            return {}
        return {
            "zone": iface.zone,
            "ipv4_assignment": iface.ipv4_assignment,
            "speed": iface.speed,
            "mtu": iface.mtu,
        }


class SophosFirewallRuleSensor(SophosXmlEntity, BinarySensorEntity):
    """Firewall rule enabled/disabled (read-only, used without write access)."""

    _attr_translation_key = "firewall_rule_status"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    # One entity per rule — often dozens, rarely all of interest.
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: SophosXmlCoordinator, rule: FirewallRule) -> None:
        super().__init__(coordinator, f"fwrule_{rule.name}", EP_FIREWALL_RULES)
        self._name = rule.name
        self._attr_translation_placeholders = {"name": rule.name}

    def _rule(self) -> FirewallRule | None:
        return (self.xml.firewall_rules or {}).get(self._name)

    @property
    def is_on(self) -> bool | None:
        rule = self._rule()
        return rule.enabled if rule else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if (rule := self._rule()) is None:
            return {}
        return {
            "action": rule.action,
            "policy_type": rule.policy_type,
            "ip_family": rule.ip_family,
        }


# ── SNMP entities ─────────────────────────────────────────────────────────────


class SophosVPNTunnelSensor(SophosSnmpEntity, BinarySensorEntity):
    """IPsec connection up/down.

    partially-active (some but not all SAs up) counts as on: traffic flows
    for at least part of the connection. The degradation stays visible — and
    alertable — via the ``partially_active`` attribute.
    """

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = "vpn_tunnel_status"

    def __init__(self, coordinator: SophosSnmpCoordinator, tunnel: VpnTunnel) -> None:
        super().__init__(coordinator, f"vpn_{tunnel.index}", EP_TUNNELS)
        self._index = tunnel.index
        self._attr_translation_placeholders = {"name": tunnel.name}

    def _tunnel(self) -> VpnTunnel | None:
        return (self.snmp.tunnels or {}).get(self._index)

    @property
    def is_on(self) -> bool | None:
        if (tunnel := self._tunnel()) is None or tunnel.conn_status is None:
            return None
        return tunnel.conn_status in (VPN_STATUS_ACTIVE, VPN_STATUS_PARTIALLY_ACTIVE)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if (tunnel := self._tunnel()) is None:
            return {}
        return {
            "conn_status_code": tunnel.conn_status,
            "partially_active": tunnel.conn_status == VPN_STATUS_PARTIALLY_ACTIVE,
            "activated": tunnel.activated == VPN_ACTIVATED,
            "tunnels_configured": tunnel.tunnels_configured,
        }


class SophosHAEnabledSensor(SophosSnmpEntity, BinarySensorEntity):
    """High-availability cluster enabled."""

    _attr_translation_key = "ha_enabled"
    _attr_device_class = BinarySensorDeviceClass.RUNNING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: SophosSnmpCoordinator) -> None:
        super().__init__(coordinator, "ha_enabled", EP_HA)

    @property
    def is_on(self) -> bool | None:
        return self.snmp.ha.enabled if self.snmp.ha else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        ha = self.snmp.ha
        return {
            "current_state_code": ha.current_state if ha else None,
            "peer_state_code": ha.peer_state if ha else None,
        }


class SophosPSUSensor(SophosSnmpEntity, BinarySensorEntity):
    """Power supply unit up/down (hardware appliances only)."""

    _attr_device_class = BinarySensorDeviceClass.POWER
    _attr_translation_key = "psu_status"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: SophosSnmpCoordinator, psu_key: str) -> None:
        super().__init__(coordinator, f"psu_{psu_key}", EP_HEALTH)
        self._key = psu_key
        self._attr_translation_placeholders = {"psu": psu_key.replace("_", " ")}

    @property
    def is_on(self) -> bool | None:
        return self.snmp.health.psus.get(self._key) if self.snmp.health else None
