"""Button platform for Sophos Firewall integration."""
from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import SophosCoordinator
from .entity import SophosEntity
from .sophos_client import SophosAPIError

_LOGGER = logging.getLogger(__name__)

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up button entities."""
    coordinator: SophosCoordinator = entry.runtime_data
    async_add_entities([SophosBackupButton(coordinator)])


class SophosBackupButton(SophosEntity, ButtonEntity):
    """Button to trigger an immediate backup on the Sophos Firewall.

    Uses the XML API BackupRestore endpoint.  This is a write operation
    but is intentionally not gated by write_access because triggering
    a backup is non-destructive.
    """

    _attr_translation_key = "trigger_backup"
    _attr_icon = "mdi:backup-restore"

    def __init__(self, coordinator: SophosCoordinator) -> None:
        super().__init__(coordinator, unique_suffix="button_backup")

    async def async_press(self) -> None:
        """Trigger an immediate backup via the dedicated client method."""
        try:
            await self.coordinator.xml_client.trigger_backup()
        except SophosAPIError as exc:
            _LOGGER.error("Failed to trigger backup: %s", exc)
