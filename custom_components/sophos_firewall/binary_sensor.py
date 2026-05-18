"""Binary sensor platform for Sophos Firewall integration.

Dynamic entities (per interface, per tunnel, per DHCP server) are registered
in two phases to support lazy loading.

Phase 1 (setup):  Nothing — all binary sensors are dynamic.
Phase 2 (update): Entities created from coordinator data on the first
                  successful fetch, via a coordinator listener.

Note: Service and license sensors have been replaced by the aggregate
SophosServicesSummarySensor and SophosLicensesSummarySensor in sensor.py.
"""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.restore_state import RestoreEntity

from .const import (
    CONF_SNMP_ENABLED,
    CONF_WRITE_ACCESS,
    DATA_INTERFACES,
    DATA_FIREWALL_RULES,
    DATA_SNMP_TUNNELS,
)
from .coordinator import SophosCoordinator
from .entity import SophosEntity

_LOGGER = logging.getLogger(__name__)

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up binary sensor entities.

    All binary sensors are dynamic — created from coordinator data on the
    first successful fetch, via a coordinator listener.
    """
    coordinator: SophosCoordinator = entry.runtime_data
    snmp_enabled: bool = entry.data.get(CONF_SNMP_ENABLED, False)
    write_access: bool = entry.data.get(CONF_WRITE_ACCESS, False)
    added_ids: set[str] = set()

    def _add_dynamic_entities() -> None:
        data = coordinator.data
        if not data:
            return

        reg = er.async_get(coordinator.hass)
        new_entities: list[BinarySensorEntity] = []

        # ── Interfaces ────────────────────────────────────────────────────────
        current_iface_names: set[str] = {
            i.get("Name", "") for i in data.get(DATA_INTERFACES, [])
        }
        for iface in data.get(DATA_INTERFACES, []):
            uid = f"{entry.entry_id}_iface_{iface.get('Name','')}"
            if uid not in added_ids:
                added_ids.add(uid)
                new_entities.append(SophosInterfaceSensor(coordinator, iface))

        # Remove stale interface sensors
        for uid in list(added_ids):
            if not uid.startswith(f"{entry.entry_id}_iface_"):
                continue
            name = uid[len(f"{entry.entry_id}_iface_"):]
            if name not in current_iface_names:
                entity_id = reg.async_get_entity_id("binary_sensor", "sophos_firewall", uid)
                if entity_id:
                    reg.async_remove(entity_id)
                added_ids.discard(uid)

        # ── Firewall rules (read-only, no write_access) ───────────────────────
        # Mit write_access: Switch in switch.py übernimmt Zustand + Steuerung.
        # Ohne write_access: binary_sensor als Nur-Lese-Anzeige (EntityCategory.CONFIG).
        if not write_access:
            current_rule_names: set[str] = {
                r.get("Name", "") for r in data.get(DATA_FIREWALL_RULES, [])
            }
            for rule in data.get(DATA_FIREWALL_RULES, []):
                uid = f"{entry.entry_id}_fwrule_{rule.get('Name','')}"
                if uid not in added_ids:
                    added_ids.add(uid)
                    new_entities.append(SophosFirewallRuleSensor(coordinator, rule))

            # Remove stale rule sensors
            for uid in list(added_ids):
                if not uid.startswith(f"{entry.entry_id}_fwrule_"):
                    continue
                name = uid[len(f"{entry.entry_id}_fwrule_"):]
                if name not in current_rule_names:
                    entity_id = reg.async_get_entity_id("binary_sensor", "sophos_firewall", uid)
                    if entity_id:
                        reg.async_remove(entity_id)
                    added_ids.discard(uid)

        # ── VPN tunnels (SNMP) ────────────────────────────────────────────────
        if snmp_enabled:
            current_tunnel_idxs: set[str] = {
                str(t.get("index", "")) for t in data.get(DATA_SNMP_TUNNELS, [])
            }
            for tunnel in data.get(DATA_SNMP_TUNNELS, []):
                uid = f"{entry.entry_id}_vpn_{tunnel.get('index','')}"
                if uid not in added_ids:
                    added_ids.add(uid)
                    new_entities.append(SophosVPNTunnelSensor(coordinator, tunnel))

            # Remove stale VPN sensors
            for uid in list(added_ids):
                if not uid.startswith(f"{entry.entry_id}_vpn_"):
                    continue
                idx = uid[len(f"{entry.entry_id}_vpn_"):]
                if idx not in current_tunnel_idxs:
                    entity_id = reg.async_get_entity_id("binary_sensor", "sophos_firewall", uid)
                    if entity_id:
                        reg.async_remove(entity_id)
                    added_ids.discard(uid)

        if new_entities:
            _LOGGER.debug("Adding %d dynamic binary_sensor entities", len(new_entities))
            async_add_entities(new_entities)

    entry.async_on_unload(
        coordinator.async_add_listener(_add_dynamic_entities)
    )

    if coordinator.data:
        _add_dynamic_entities()


# ── Entity classes ────────────────────────────────────────────────────────────

class SophosInterfaceSensor(SophosEntity, BinarySensorEntity, RestoreEntity):
    """Binary sensor: network interface up/down.

    RestoreEntity: zeigt letzten bekannten State sofort nach HA-Neustart.
    """

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = "interface_status"
    _attr_icon = "mdi:ethernet"

    def __init__(self, coordinator: SophosCoordinator, iface: dict[str, Any]) -> None:
        self._iface_name = iface.get("Name", "unknown")
        super().__init__(coordinator, unique_suffix=f"iface_{self._iface_name}")
        self._attr_translation_placeholders = {"name": self._iface_name}

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        for iface in self.coordinator.data.get(DATA_INTERFACES, []):
            if iface.get("Name") == self._iface_name:
                return iface.get("InterfaceStatus", "").upper() == "ON"
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if self.coordinator.data is None:
            return {}
        for iface in self.coordinator.data.get(DATA_INTERFACES, []):
            if iface.get("Name") == self._iface_name:
                return {
                    "zone":            iface.get("NetworkZone"),
                    "ipv4_assignment": iface.get("IPv4Assignment"),
                    "speed":           iface.get("InterfaceSpeed"),
                    "mtu":             iface.get("MTU"),
                }
        return {}


class SophosFirewallRuleSensor(SophosEntity, BinarySensorEntity):
    """Binary sensor: firewall rule enabled/disabled.

    EntityCategory.CONFIG — erscheint nur im Konfigurationsbereich der Geräte-Seite.
    """

    _attr_translation_key = "firewall_rule_status"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:shield-outline"

    def __init__(self, coordinator: SophosCoordinator, rule: dict[str, Any]) -> None:
        self._rule_name = rule.get("Name", "unknown")
        super().__init__(coordinator, unique_suffix=f"fwrule_{self._rule_name}")
        self._attr_translation_placeholders = {"name": self._rule_name}

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        for rule in self.coordinator.data.get(DATA_FIREWALL_RULES, []):
            if rule.get("Name") == self._rule_name:
                return rule.get("Status", "").lower() == "enable"
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if self.coordinator.data is None:
            return {}
        for rule in self.coordinator.data.get(DATA_FIREWALL_RULES, []):
            if rule.get("Name") == self._rule_name:
                return {
                    "action":      rule.get("Action"),
                    "policy_type": rule.get("PolicyType"),
                    "ip_family":   rule.get("IPFamily"),
                }
        return {}



class SophosVPNTunnelSensor(SophosEntity, BinarySensorEntity, RestoreEntity):
    """Binary sensor: IPSec VPN tunnel active/inactive (SNMP).

    RestoreEntity: zeigt letzten bekannten State sofort nach HA-Neustart.
    """

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = "vpn_tunnel_status"
    _attr_icon = "mdi:vpn"

    def __init__(
        self, coordinator: SophosCoordinator, tunnel: dict[str, Any]
    ) -> None:
        self._tunnel_name = tunnel.get("name", "unknown")
        self._tunnel_idx  = tunnel.get("index", "0")
        super().__init__(coordinator, unique_suffix=f"vpn_{self._tunnel_idx}")
        self._attr_translation_placeholders = {"name": self._tunnel_name}

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        for tunnel in self.coordinator.data.get(DATA_SNMP_TUNNELS, []):
            if tunnel.get("index") == self._tunnel_idx:
                return tunnel.get("conn_status") == 1
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if self.coordinator.data is None:
            return {}
        for tunnel in self.coordinator.data.get(DATA_SNMP_TUNNELS, []):
            if tunnel.get("index") == self._tunnel_idx:
                return {
                    "conn_status_code": tunnel.get("conn_status"),
                    "activated":        tunnel.get("activated") == 1,
                }
        return {}
