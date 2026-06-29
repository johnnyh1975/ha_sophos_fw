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
    DATA_SNMP_HA,
    DATA_SNMP_HEALTH,
    DATA_SNMP_TUNNELS,
)
from .coordinator import SophosCoordinator
from .entity import SophosEntity, field_str

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

    # ── Static SNMP entities (always one per entry when SNMP is enabled) ───────
    if snmp_enabled:
        async_add_entities([SophosHAEnabledSensor(coordinator)])

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

            # ── PSU status sensors (physical appliances only) ──────────────────
            # psus dict is empty on virtual appliances (SFVH) — no entities created.
            health = data.get(DATA_SNMP_HEALTH, {})
            current_psu_keys: set[str] = set(health.get("psus", {}).keys())
            for psu_key in health.get("psus", {}):
                uid = f"{entry.entry_id}_psu_{psu_key}"
                if uid not in added_ids:
                    added_ids.add(uid)
                    new_entities.append(SophosPSUSensor(coordinator, psu_key))

            # Remove stale PSU sensors
            for uid in list(added_ids):
                if not uid.startswith(f"{entry.entry_id}_psu_"):
                    continue
                psu_key = uid[len(f"{entry.entry_id}_psu_"):]
                if psu_key not in current_psu_keys:
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

    RestoreEntity: shows the last known state immediately after an HA restart,
    until the first coordinator fetch populates fresh data.
    """

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = "interface_status"
    _attr_icon = "mdi:ethernet"

    def __init__(self, coordinator: SophosCoordinator, iface: dict[str, Any]) -> None:
        self._iface_name = iface.get("Name", "unknown")
        super().__init__(coordinator, unique_suffix=f"iface_{self._iface_name}")
        self._attr_translation_placeholders = {"name": self._iface_name}
        self._restored_is_on: bool | None = None

    async def async_added_to_hass(self) -> None:
        """Restore the last known state on startup."""
        await super().async_added_to_hass()
        last_state = await self.async_get_last_state()
        if last_state is not None and last_state.state in ("on", "off"):
            self._restored_is_on = last_state.state == "on"

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            # No fresh data yet — fall back to restored state after restart
            return self._restored_is_on
        for iface in self.coordinator.data.get(DATA_INTERFACES, []):
            if iface.get("Name") == self._iface_name:
                return field_str(iface, "InterfaceStatus").upper() == "ON"
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
                return field_str(rule, "Status").lower() == "enable"
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

    RestoreEntity: shows the last known state immediately after an HA restart,
    until the first coordinator fetch populates fresh data.
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
        self._restored_is_on: bool | None = None

    async def async_added_to_hass(self) -> None:
        """Restore the last known state on startup."""
        await super().async_added_to_hass()
        last_state = await self.async_get_last_state()
        if last_state is not None and last_state.state in ("on", "off"):
            self._restored_is_on = last_state.state == "on"

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return self._restored_is_on
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

class SophosHAEnabledSensor(SophosEntity, BinarySensorEntity):
    """Binary sensor: High Availability cluster active or not.

    True  → HA is enabled and the cluster is operational.
    False → HA is disabled (single-node standalone mode).
    None  → SNMP data not yet available.
    """

    _attr_translation_key  = "ha_enabled"
    _attr_icon             = "mdi:server-network"
    _attr_device_class     = BinarySensorDeviceClass.RUNNING

    def __init__(self, coordinator: SophosCoordinator) -> None:
        super().__init__(coordinator, unique_suffix="ha_enabled")

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        ha = self.coordinator.data.get(DATA_SNMP_HA, {})
        if not ha:
            return None
        return bool(ha.get("ha_enabled", False))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        ha = (self.coordinator.data or {}).get(DATA_SNMP_HA, {})
        return {
            "current_state_code": ha.get("current_state"),
            "peer_state_code":    ha.get("peer_state"),
        }


class SophosPSUSensor(SophosEntity, BinarySensorEntity):
    """Binary sensor for a single PSU (power supply unit).

    True  → PSU present and operational.
    False → PSU absent or failed.

    Only created on physical appliances — the psus dict is empty on SFVH
    virtual appliances, so no entities are registered for VMs.
    """

    _attr_device_class = BinarySensorDeviceClass.POWER

    def __init__(self, coordinator: SophosCoordinator, psu_key: str) -> None:
        super().__init__(coordinator, unique_suffix=f"psu_{psu_key}")
        self._psu_key = psu_key
        self._attr_translation_key = "psu_status"
        self._attr_translation_placeholders = {"psu": psu_key.replace("_", " ")}

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        return (
            self.coordinator.data
            .get(DATA_SNMP_HEALTH, {})
            .get("psus", {})
            .get(self._psu_key)
        )
