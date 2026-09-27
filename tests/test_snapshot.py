"""Entity registry snapshot — the compatibility contract with existing installs.

unique_id, entity_id, translation_key, device_class, state_class and unit are
what users' automations, dashboards and long-term statistics depend on. Any
change to this snapshot must be deliberate (and, for unique_id, migrated).

Regenerate after an intended change with:
    SOPHOS_UPDATE_SNAPSHOT=1 pytest tests/test_snapshot.py
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from .conftest import ENTRY_ID, make_entry, setup_entry
from .fake_snmp import FakeSnmpAgent
from .fake_sophos import FakeSophosApi

SNAPSHOT_DIR = Path(__file__).parent / "snapshots"
ALL_SOURCES = {"poll_xml_backup": True, "poll_snmp_ha": True}


def _dump(hass: HomeAssistant) -> dict[str, dict[str, object]]:
    registry = er.async_get(hass)
    result: dict[str, dict[str, object]] = {}
    for entry in sorted(
        er.async_entries_for_config_entry(registry, ENTRY_ID), key=lambda e: e.entity_id
    ):
        # Registry values, not state attributes: entities that are disabled by
        # default have no state, but their contract matters just the same.
        result[entry.entity_id] = {
            "unique_id": entry.unique_id,
            "translation_key": entry.translation_key,
            "entity_category": entry.entity_category,
            "disabled_by_default": entry.disabled_by is er.RegistryEntryDisabler.INTEGRATION,
            "device_class": entry.original_device_class,
            "state_class": (entry.capabilities or {}).get("state_class"),
            "unit": entry.unit_of_measurement,
        }
    return result


@pytest.mark.parametrize("write_access", [False, True])
async def test_entity_registry_snapshot(
    hass: HomeAssistant, xml_api: FakeSophosApi, hardware_agent: FakeSnmpAgent, write_access: bool
) -> None:
    await setup_entry(hass, make_entry(options=ALL_SOURCES, write_access=write_access))
    actual = json.loads(json.dumps(_dump(hass)))
    path = SNAPSHOT_DIR / f"entities_write_access_{str(write_access).lower()}.json"
    if os.environ.get("SOPHOS_UPDATE_SNAPSHOT"):
        path.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    expected = json.loads(path.read_text(encoding="utf-8"))
    assert actual == expected
