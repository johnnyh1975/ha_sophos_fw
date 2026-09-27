"""Setup, unload and device registry."""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import EVENT_HOMEASSISTANT_CLOSE
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr

from custom_components.sophos_firewall import async_setup_entry
from custom_components.sophos_firewall import session as session_module
from custom_components.sophos_firewall.const import DOMAIN
from custom_components.sophos_firewall.coordinator import SophosXmlCoordinator

from .conftest import ENTRY_ID, make_entry, setup_entry


def _device(hass: HomeAssistant) -> dr.DeviceEntry:
    devices = dr.async_entries_for_config_entry(dr.async_get(hass), ENTRY_ID)
    assert len(devices) == 1
    return devices[0]
from .fake_snmp import FakeSnmpAgent
from .fake_sophos import FakeSophosApi


async def test_setup_and_unload(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry()
    await setup_entry(hass, entry)
    assert entry.state is ConfigEntryState.LOADED
    assert hass.states.get("binary_sensor.5heynexg_iface_porta").state == "on"
    assert hass.states.get("sensor.5heynexg_sensor_memory_percent").state == "33"

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.NOT_LOADED


async def test_device_registry_combines_xml_and_snmp(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry())
    device = _device(hass)
    assert device.identifiers == {(DOMAIN, ENTRY_ID)}
    assert device.name == "5HeyneXG"
    assert device.manufacturer == "Sophos"
    assert device.model == "SFVH_KV01_SFOS"
    assert device.sw_version == "SFOS 22.0.0 GA-Build411"
    assert device.serial_number == "C01001D2MQT76C4"
    assert device.configuration_url == "https://127.0.0.1:4444"


async def test_setup_without_snmp(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    assert entry.state is ConfigEntryState.LOADED
    assert entry.runtime_data.snmp is None
    assert hass.states.get("sensor.5heynexg_sensor_memory_percent") is None
    device = _device(hass)
    assert device.name == "5HeyneXG"
    assert device.model is None


async def test_unreachable_snmp_does_not_block_setup(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """SNMP is optional: a dead agent leaves SNMP entities unavailable only."""
    snmp_agent.drop_all = True
    entry = make_entry()
    await setup_entry(hass, entry)
    assert entry.state is ConfigEntryState.LOADED
    assert hass.states.get("binary_sensor.5heynexg_iface_porta").state == "on"
    assert hass.states.get("sensor.5heynexg_sensor_memory_percent").state == "unavailable"


async def test_snmp_preload_failure_continues_without_snmp(
    hass: HomeAssistant, xml_api: FakeSophosApi, caplog
) -> None:
    with patch(
        "custom_components.sophos_firewall.snmp_client.SNMPClient.preload",
        side_effect=ImportError("puresnmp broken"),
    ):
        entry = make_entry()
        await setup_entry(hass, entry)
    assert entry.state is ConfigEntryState.LOADED
    assert entry.runtime_data.snmp is None
    assert "continuing without SNMP" in caplog.text


async def test_xml_unreachable_retries_setup(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    xml_api.exc = TimeoutError()
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_RETRY


async def test_rejected_credentials_start_reauth(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """v1.0.x raised ConfigEntryNotReady here and retried forever."""
    xml_api.password = "changed-on-firewall"
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_ERROR
    flows = hass.config_entries.flow.async_progress()
    assert [f["context"]["source"] for f in flows] == ["reauth"]


async def test_options_update_reloads_entry(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    before = entry.runtime_data
    hass.config_entries.async_update_entry(entry, options={**entry.options, "interval_realtime": 60})
    await hass.async_block_till_done()
    assert entry.runtime_data is not before
    assert entry.runtime_data.xml.update_interval.total_seconds() == 60


async def test_failed_hostname_fetch_does_not_rename_device(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """Regression: a missing hostname renamed the device to its IP address."""
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    assert _device(hass).name == "5HeyneXG"

    await hass.config_entries.async_unload(entry.entry_id)
    xml_api.broken_tags.add("AdminSettings")
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert _device(hass).name == "5HeyneXG"


async def test_new_device_without_hostname_is_named_after_host(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    xml_api.broken_tags.add("AdminSettings")
    await setup_entry(hass, make_entry(snmp_enabled=False))
    assert _device(hass).name == "127.0.0.1"


async def test_setup_and_requests_are_timed_in_the_debug_log(
    hass: HomeAssistant, xml_api: FakeSophosApi, caplog
) -> None:
    """Debug timing to find where a slow setup spends its time."""
    import logging

    caplog.set_level(logging.DEBUG, logger="custom_components.sophos_firewall")
    await setup_entry(hass, make_entry(snmp_enabled=False))
    assert "Setup of 127.0.0.1 took" in caplog.text
    assert "XML admin settings" in caplog.text
    for tag in ("Interface", "FirewallRule", "DHCPServer", "WebFilterPolicy", "AdminSettings"):
        assert f"XML Get {tag} on 127.0.0.1: waited" in caplog.text, tag


async def test_failed_request_is_timed_too(
    hass: HomeAssistant, xml_api: FakeSophosApi, caplog
) -> None:
    import logging

    caplog.set_level(logging.DEBUG, logger="custom_components.sophos_firewall")
    xml_api.exc = TimeoutError()
    await setup_entry(hass, make_entry(snmp_enabled=False))
    assert "XML Get AdminSettings on 127.0.0.1: waited" in caplog.text
    assert "(failed)" in caplog.text


async def test_setup_waits_only_for_the_admin_settings(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """A real firewall answers one request after another, ~5 s each: waiting
    for all five took 34 s. Setup needs connectivity, credentials and the
    hostname — the admin settings; the rest follows in the background."""
    xml_api.delay = 0.2
    entry = make_entry(snmp_enabled=False)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.LOADED
    assert xml_api.requests == [("get", "AdminSettings")]
    # async_entries_for_config_entry: async_get_device is deprecated from HA 2026.9
    devices = dr.async_entries_for_config_entry(dr.async_get(hass), ENTRY_ID)
    assert [(d.identifiers, d.name) for d in devices] == [({(DOMAIN, ENTRY_ID)}, "5HeyneXG")]
    assert hass.states.get("binary_sensor.5heynexg_iface_porta") is None  # not yet

    await hass.async_block_till_done(wait_background_tasks=True)
    assert hass.states.get("binary_sensor.5heynexg_iface_porta").state == "on"
    assert sorted(xml_api.requests[1:]) == [
        ("get", tag) for tag in ("DHCPServer", "FirewallRule", "Interface", "WebFilterPolicy")
    ]  # each once — the background refresh does not fetch the admin settings again


async def test_setup_fetches_everything_if_admin_settings_are_refused(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """E.g. an API profile without permission for the admin settings: setup
    must not fail when the other objects can be read (as before 1.1)."""
    xml_api.broken_gets = {"AdminSettings"}
    entry = make_entry(snmp_enabled=False)
    entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.LOADED
    assert ("get", "Interface") in xml_api.requests  # in the same refresh
    from homeassistant.helpers import entity_registry as er

    # no hostname without the admin settings: the device is named after the IP
    entity_id = er.async_get(hass).async_get_entity_id(
        "binary_sensor", DOMAIN, f"{ENTRY_ID}_iface_PortA"
    )
    assert entity_id is not None
    assert hass.states.get(entity_id).state == "on"


async def test_setup_retries_when_firewall_is_unreachable(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    xml_api.exc = TimeoutError()
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_RETRY
    assert xml_api.requests == []  # the transport failed before the fake logged it


async def test_updates_never_overlap(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    """The background refresh after setup and a requested one run one after
    the other — otherwise both would fetch the same objects. HA 2026.x locks
    async_refresh itself; HA 2025.5 (the minimum) does not."""
    import asyncio

    xml_api.delay = 0.1
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    xml = entry.runtime_data.xml
    xml.invalidate("interfaces")
    await asyncio.gather(xml.async_refresh(), xml.async_refresh())
    assert xml_api.count("get", "Interface") == 2  # setup + one of the two refreshes


async def test_xml_session_is_closed_when_home_assistant_stops(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """Review finding: stopping HA does not unload entries, so the dedicated
    session was never closed."""
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    session = entry.runtime_data.xml.client._session
    assert not session.closed
    hass.bus.async_fire(EVENT_HOMEASSISTANT_CLOSE)
    await hass.async_block_till_done()
    assert session.closed


async def test_xml_session_is_closed_when_setup_is_cancelled(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    sessions = []
    create = session_module.create_xml_session  # the fixture's patched factory

    def _capture(verify_ssl: bool):
        sessions.append(create(verify_ssl))
        return sessions[-1]

    entry = make_entry(snmp_enabled=False)
    entry.add_to_hass(hass)
    with (
        patch.object(session_module, "create_xml_session", side_effect=_capture),
        patch.object(
            SophosXmlCoordinator, "async_first_refresh_of", side_effect=asyncio.CancelledError
        ),
        pytest.raises(asyncio.CancelledError),
    ):
        await async_setup_entry(hass, entry)
    assert len(sessions) == 1 and sessions[0].closed
