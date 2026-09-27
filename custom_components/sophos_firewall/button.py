"""Button platform for the Sophos Firewall integration."""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import SophosConfigEntry
from .const import DOMAIN
from .coordinator import SophosXmlCoordinator
from .entity import SophosXmlEntity
from .sophos_client import SophosError

PARALLEL_UPDATES = 1


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the backup button."""
    async_add_entities([SophosBackupButton(entry.runtime_data.xml)])


class SophosBackupButton(SophosXmlEntity, ButtonEntity):
    """Trigger an immediate backup.

    Not gated by write access: a backup is non-destructive.
    """

    _attr_translation_key = "trigger_backup"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator: SophosXmlCoordinator) -> None:
        super().__init__(coordinator, "button_backup", None)

    async def async_press(self) -> None:
        """Trigger the backup."""
        try:
            await self.coordinator.client.trigger_backup()
        except SophosError as exc:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="backup_failed",
                translation_placeholders={"error": str(exc)},
            ) from exc
