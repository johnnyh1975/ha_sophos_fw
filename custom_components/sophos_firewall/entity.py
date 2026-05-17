"""Base entity class shared by all Sophos Firewall entities."""
from __future__ import annotations

import re

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DATA_ADMIN,
    DATA_SNMP_DEVICE,
    DOMAIN,
    OID_DEVICE_APP_KEY,
    OID_DEVICE_FW_VERSION,
    OID_DEVICE_TYPE,
)
from .coordinator import SophosCoordinator


def _slug(text: str) -> str:
    """Convert text to a safe HA entity ID slug (lowercase, underscores)."""
    text = str(text).lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    return text.strip("_")


class SophosEntity(CoordinatorEntity[SophosCoordinator]):
    """Base class for all Sophos Firewall entities.

    Multi-firewall naming strategy
    --------------------------------
    Two firewalls in the same HA instance must not collide.

    With has_entity_name=True, HA automatically prefixes the entity_id
    with the device name (hostname). We must NOT include the hostname
    again in suggested_object_id — that causes double-prefix:

        ✗  switch.5heynexg_5heynexg_switch_webfilter_...   ← wrong
        ✓  switch.5heynexg_switch_webfilter_...              ← correct

    Implementation:
    - unique_id           = "{host}_{port}_{suffix}" — stable, survives rename
    - suggested_object_id = "{suffix_slug}" only  — HA prepends device name
    - device_info.name    = hostname              — the prefix HA uses

    Result: entity_id = slugify(device.name) + "_" + slugify(suffix)
            e.g. "5heynexg_switch_fwrule_allow_lan_to_iot"
    """

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: SophosCoordinator,
        unique_suffix: str,
    ) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        host = entry.data.get("host", "sophos")
        port = entry.data.get("port", 4444)

        # Stable unique_id — never changes even if hostname is renamed
        self._attr_unique_id = f"{host}_{port}_{unique_suffix}"

        # Store suffix for the suggested_object_id property
        self._unique_suffix = unique_suffix

    # ── HA naming hooks ───────────────────────────────────────────────────────

    @property
    def suggested_object_id(self) -> str:
        """Return suffix-only slug — HA prepends the device name automatically.

        With has_entity_name=True, HA builds entity_id as:
            slugify(device.name) + "_" + slugify(suggested_object_id)

        So we return only the suffix here — not the hostname — to avoid:
            5heynexg_5heynexg_switch_webfilter_...  ← wrong (double prefix)
        """
        return _slug(self._unique_suffix)

    # ── Device info ───────────────────────────────────────────────────────────

    @property
    def device_info(self) -> DeviceInfo:
        """Return device registry entry.

        Device name = hostname (from XML AdminSettings.HostName).
        In multi-FW setups each firewall appears as a separate device
        under its own hostname.

        With has_entity_name=True, HA builds the friendly_name as:
            "{device.name} {entity.name}"
            e.g. "5HeyneXG Interface PortA"
        """
        coordinator = self.coordinator
        entry = coordinator.config_entry
        data = coordinator.data or {}

        snmp_device: dict = data.get(DATA_SNMP_DEVICE, {})
        admin: dict = data.get(DATA_ADMIN, {})

        name      = admin.get("HostnameSettings", {}).get("HostName") \
                    or entry.data.get("host", "Sophos Firewall")
        model      = snmp_device.get(OID_DEVICE_TYPE)      or "Sophos Firewall"
        sw_version = snmp_device.get(OID_DEVICE_FW_VERSION)
        serial     = snmp_device.get(OID_DEVICE_APP_KEY)

        return DeviceInfo(
            identifiers={(DOMAIN, entry.entry_id)},
            name=name,
            manufacturer="Sophos",
            model=model,
            sw_version=sw_version,
            serial_number=serial,
            configuration_url=(
                f"https://{entry.data['host']}:{entry.data.get('port', 4444)}"
            ),
        )
