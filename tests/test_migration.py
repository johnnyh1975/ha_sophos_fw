"""Config entry migration v1 (≤ v1.0.x) → v2 (v1.1.0)."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from custom_components.sophos_firewall.const import DOMAIN
from pytest_homeassistant_custom_component.common import MockConfigEntry

from .conftest import CONNECTION, ENTRY_ID, setup_entry
from .fake_snmp import FakeSnmpAgent
from .fake_sophos import HOST, PORT, FakeSophosApi

# What v1.0.x stored: everything in data, options only after the options flow.
V1_DATA = {
    **CONNECTION,
    "snmp_enabled": True,
    "snmp_community": "public",
    "snmp_version": "2c",
    "write_access": False,
    "interval_realtime": 30,
    "poll_xml_zones": True,
    "poll_xml_admin": True,
    "poll_snmp_device": True,
}
V1_OPTIONS = {"interval_realtime": 45, "poll_xml_backup": True, "snmp_version": "1"}
OLD = f"{HOST}_{PORT}_"
NEW = f"{ENTRY_ID}_"


def _v1_entry(**kwargs) -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        title=HOST,
        entry_id=ENTRY_ID,
        version=1,
        data=kwargs.pop("data", V1_DATA),
        options=kwargs.pop("options", V1_OPTIONS),
        **kwargs,
    )


def _register(hass: HomeAssistant, entry: MockConfigEntry, domain: str, unique_id: str, **kw) -> str:
    return er.async_get(hass).async_get_or_create(
        domain, DOMAIN, unique_id, config_entry=entry, **kw
    ).entity_id


async def test_migration_keeps_entity_ids_and_customisations(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = _v1_entry(unique_id=f"{HOST}:{PORT}")
    entry.add_to_hass(hass)
    registry = er.async_get(hass)
    memory = _register(hass, entry, "sensor", OLD + "sensor_memory_percent",
                       suggested_object_id="5heynexg_sensor_memory_percent")
    iface = _register(hass, entry, "binary_sensor", OLD + "iface_PortA",
                      suggested_object_id="5heynexg_iface_porta")
    registry.async_update_entity(memory, name="RAM", area_id="server_room")
    registry.async_update_entity(iface, disabled_by=er.RegistryEntryDisabler.USER)

    await setup_entry(hass, entry)

    assert entry.state is ConfigEntryState.LOADED
    assert entry.version == 2
    assert dict(entry.data) == CONNECTION
    assert entry.options == {
        "snmp_enabled": True,
        "snmp_community": "public",
        "write_access": False,
        "interval_realtime": 45,  # options win over data
        "poll_xml_backup": True,
    }
    assert entry.unique_id == f"{HOST}:{PORT}"

    migrated = registry.async_get(memory)
    assert migrated.unique_id == NEW + "sensor_memory_percent"
    assert migrated.name == "RAM"
    assert migrated.area_id == "server_room"
    assert registry.async_get(iface).unique_id == NEW + "iface_PortA"
    assert registry.async_get(iface).disabled_by is er.RegistryEntryDisabler.USER
    assert hass.states.get(memory).state == "33"
    # nothing was created twice
    unique_ids = [e.unique_id for e in er.async_entries_for_config_entry(registry, ENTRY_ID)]
    assert len(unique_ids) == len(set(unique_ids))
    assert not any(uid.startswith(OLD) for uid in unique_ids)


async def test_orphans_from_an_old_address_are_restored_or_removed(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """v1.0.x reconfigure orphaned entities under the previous host."""
    entry = _v1_entry(unique_id=f"{HOST}:{PORT}")
    entry.add_to_hass(hass)
    registry = er.async_get(hass)
    current = _register(hass, entry, "sensor", OLD + "sensor_uptime")
    orphan_twin = _register(hass, entry, "sensor", "10.0.0.9_4444_sensor_uptime")
    orphan_only = _register(hass, entry, "sensor", "10.0.0.9_4444_sensor_disk_percent")

    await setup_entry(hass, entry)

    assert registry.async_get(current).unique_id == NEW + "sensor_uptime"
    assert registry.async_get(orphan_twin) is None  # collided with the current one
    assert registry.async_get(orphan_only).unique_id == NEW + "sensor_disk_percent"


async def test_entry_without_unique_id_gets_one(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    entry = _v1_entry(data={**V1_DATA, "snmp_enabled": False}, options={})
    await setup_entry(hass, entry)
    assert entry.unique_id == f"{HOST}:{PORT}"


async def test_downgrade_is_refused(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    entry = MockConfigEntry(domain=DOMAIN, version=3, data=dict(CONNECTION))
    await setup_entry(hass, entry)
    assert entry.state is ConfigEntryState.MIGRATION_ERROR


async def test_already_migrated_entry_is_untouched(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    from .conftest import make_entry

    entry = make_entry(snmp_enabled=False)
    options = dict(entry.options)
    await setup_entry(hass, entry)
    assert entry.version == 2
    assert dict(entry.options) == options


async def test_stale_entry_unique_id_is_corrected(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """v1.0.x reconfigure kept the unique_id of the previous address."""
    entry = _v1_entry(data={**V1_DATA, "snmp_enabled": False}, options={},
                      unique_id="10.0.0.9:4444")
    await setup_entry(hass, entry)
    assert entry.unique_id == f"{HOST}:{PORT}"


async def test_entry_unique_id_kept_when_address_taken(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    MockConfigEntry(domain=DOMAIN, version=2, data={**CONNECTION, "host": "other"},
                    unique_id=f"{HOST}:{PORT}").add_to_hass(hass)
    entry = _v1_entry(data={**V1_DATA, "snmp_enabled": False}, options={},
                      unique_id="10.0.0.9:4444")
    await setup_entry(hass, entry)
    assert entry.unique_id == "10.0.0.9:4444"


async def test_old_unique_ids_on_a_v2_entry_are_fixed_at_setup(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """Hard stop after the migration saved the entry but not the registry."""
    from .conftest import make_entry

    entry = make_entry(snmp_enabled=False)
    entry.add_to_hass(hass)
    iface = _register(hass, entry, "binary_sensor", OLD + "iface_PortA",
                      suggested_object_id="5heynexg_iface_porta")
    await setup_entry(hass, entry)
    registry = er.async_get(hass)
    assert registry.async_get(iface).unique_id == NEW + "iface_PortA"
    assert hass.states.get(iface).state == "on"


async def test_unrecognised_leftovers_are_removed(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    entry = _v1_entry(data={**V1_DATA, "snmp_enabled": False}, options={})
    entry.add_to_hass(hass)
    leftover = _register(hass, entry, "binary_sensor", "fw_lab.local_4444_iface_PortA")
    await setup_entry(hass, entry)
    assert er.async_get(hass).async_get(leftover) is None
