"""Entity states and attributes, dynamic entities, actions and diagnostics."""
from __future__ import annotations

import asyncio
from unittest.mock import patch
from datetime import timedelta

import pytest
from freezegun.api import FrozenDateTimeFactory
from homeassistant.components.button import DOMAIN as BUTTON_DOMAIN, SERVICE_PRESS
from homeassistant.components.switch import DOMAIN as SWITCH_DOMAIN
from homeassistant.const import (
    ATTR_ENTITY_ID,
    SERVICE_TURN_OFF,
    SERVICE_TURN_ON,
    STATE_OFF,
    STATE_ON,
    STATE_UNAVAILABLE,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import entity_registry as er
from homeassistant.util import dt as dt_util

from custom_components.sophos_firewall.diagnostics import async_get_config_entry_diagnostics
from pytest_homeassistant_custom_component.common import async_fire_time_changed

from .conftest import make_entry, setup_entry
from .fake_snmp import FakeSnmpAgent
from .fake_sophos import FakeSophosApi

P = "5heynexg"


def _attrs(hass: HomeAssistant, entity_id: str) -> dict:
    state = hass.states.get(entity_id)
    assert state is not None, entity_id
    return dict(state.attributes)


def _state(hass: HomeAssistant, entity_id: str) -> str:
    state = hass.states.get(entity_id)
    assert state is not None, entity_id
    return state.state


async def _tick(hass: HomeAssistant, freezer: FrozenDateTimeFactory, seconds: float) -> None:
    freezer.tick(timedelta(seconds=seconds))
    async_fire_time_changed(hass)
    await hass.async_block_till_done(wait_background_tasks=True)


# ── XML entities ──────────────────────────────────────────────────────────────


async def test_interface_sensors(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    assert _state(hass, f"binary_sensor.{P}_iface_porta") == STATE_ON
    assert _state(hass, f"binary_sensor.{P}_iface_portb") == STATE_OFF
    attrs = _attrs(hass, f"binary_sensor.{P}_iface_porta")
    assert attrs["friendly_name"] == "5HeyneXG Interface PortA"
    assert attrs["device_class"] == "connectivity"
    assert {k: attrs[k] for k in ("zone", "ipv4_assignment", "speed", "mtu")} == {
        "zone": "LAN", "ipv4_assignment": "Static", "speed": "Auto Negotiate", "mtu": "1500",
    }


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_firewall_rule_sensors_without_write_access(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    entity_id = f"binary_sensor.{P}_fwrule_allow_lan_to_iot"
    assert _state(hass, entity_id) == STATE_ON
    assert _state(hass, f"binary_sensor.{P}_fwrule_block_guest") == STATE_OFF
    assert _attrs(hass, entity_id)["action"] == "Accept"
    assert hass.states.get(f"switch.{P}_switch_fwrule_allow_lan_to_iot") is None


async def test_dhcp_sensors(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    entity_id = f"sensor.{P}_dhcp_leases_main_dhcp"
    assert _state(hass, entity_id) == "on"
    assert _state(hass, f"sensor.{P}_dhcp_leases_guest_dhcp") == "off"
    attrs = _attrs(hass, entity_id)
    assert attrs["lease_count"] == 2
    assert attrs["interface"] == "PortA"
    assert attrs["leases"][0]["MACAddress"] == "aa:bb:cc:00:11:22"


async def test_web_filter_default_action_prefers_default_policy(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    entity_id = f"sensor.{P}_sensor_web_filter_default_action"
    assert _state(hass, entity_id) == "allow"
    assert _attrs(hass, entity_id)["options"] == ["allow", "deny"]


async def test_web_filter_default_action_deny(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    for policy in xml_api.records["WebFilterPolicy"]:
        policy["DefaultAction"] = "Deny"
    await setup_entry(hass, make_entry(snmp_enabled=False))
    assert _state(hass, f"sensor.{P}_sensor_web_filter_default_action") == "deny"


async def test_unknown_enum_value_is_unknown_and_logged_once(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi, caplog
) -> None:
    """HA rejects ENUM values outside the options; a new SFOS value must not
    break the sensor but be reported."""
    for policy in xml_api.records["WebFilterPolicy"]:
        policy["DefaultAction"] = "Quarantine"
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    entity_id = f"sensor.{P}_sensor_web_filter_default_action"
    assert _state(hass, entity_id) == "unknown"
    entry.runtime_data.xml.invalidate("web_filter_policies")
    await _tick(hass, freezer, 30)
    assert caplog.text.count("Unknown value 'Quarantine' for web_filter_default_action") == 1


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_backup_frequency_needs_its_toggle(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    await setup_entry(hass, make_entry(options={"poll_xml_backup": True}, snmp_enabled=False))
    assert _state(hass, f"sensor.{P}_sensor_backup_frequency") == "monthly"


# ── SNMP entities ─────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_snmp_stats_sensors(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry())
    assert _state(hass, f"sensor.{P}_sensor_memory_percent") == "33"
    assert _state(hass, f"sensor.{P}_sensor_disk_percent") == "27"
    assert _state(hass, f"sensor.{P}_sensor_swap_percent") == "23"
    assert _state(hass, f"sensor.{P}_sensor_http_hits") == "21355078"
    assert _state(hass, f"sensor.{P}_sensor_ftp_hits") == "0"
    assert _state(hass, f"sensor.{P}_sensor_smtp_hits") == "19"
    assert _state(hass, f"sensor.{P}_sensor_imap_hits") == "47"
    assert _state(hass, f"sensor.{P}_sensor_pop3_hits") == "12"
    assert _state(hass, f"sensor.{P}_sensor_live_users") == "1"
    boot = dt_util.parse_datetime(_state(hass, f"sensor.{P}_sensor_uptime"))
    assert boot is not None
    expected = dt_util.utcnow() - timedelta(seconds=6502743)
    assert abs((boot - expected).total_seconds()) < 2
    assert "uptime_seconds" not in _attrs(hass, f"sensor.{P}_sensor_uptime")
    assert _state(hass, f"sensor.{P}_sensor_ips_version") == "22.1.26"
    assert _state(hass, f"sensor.{P}_sensor_webcat_version") == "1.0.1.1207"


async def test_services_summary(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry())
    entity_id = f"sensor.{P}_sensor_services_summary"
    assert _state(hass, entity_id) == "18"
    attrs = _attrs(hass, entity_id)
    assert "unit_of_measurement" not in attrs  # v1.0.x: "/ 21 running"
    assert attrs["total"] == 21
    assert attrs["stopped"] == ["Anti-Spam", "HA-Service", "Tomcat"]
    assert attrs["details"]["Tomcat"] is None


async def test_licenses_summary(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry())
    entity_id = f"sensor.{P}_sensor_licenses_summary"
    assert _state(hass, entity_id) == "4"
    attrs = _attrs(hass, entity_id)
    assert "Base Firewall" in attrs["ok"]
    assert "Email Protection" in attrs["problem"]
    assert attrs["next_expiry"] == "Jan 5 2026"
    assert attrs["total"] == 9
    assert "unit_of_measurement" not in attrs  # v1.0.x: "/ 9 OK"


async def test_vpn_tunnels(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry())
    assert _state(hass, f"binary_sensor.{P}_vpn_1") == STATE_ON
    assert _state(hass, f"binary_sensor.{P}_vpn_2") == STATE_OFF
    # partially-active counts as connected; degradation visible as attribute
    assert _state(hass, f"binary_sensor.{P}_vpn_3") == STATE_ON
    attrs = _attrs(hass, f"binary_sensor.{P}_vpn_3")
    assert attrs["friendly_name"] == "5HeyneXG VPN DR-Site"
    assert attrs["partially_active"] is True
    assert attrs["conn_status_code"] == 2
    assert attrs["activated"] is True
    assert attrs["tunnels_configured"] == 3
    assert hass.states.get(f"binary_sensor.{P}_vpn_7") is None  # policy table not read


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_ha_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry(options={"poll_snmp_ha": True}))
    assert _state(hass, f"binary_sensor.{P}_ha_enabled") == STATE_OFF
    assert _state(hass, f"sensor.{P}_ha_current_state") == "standalone"
    assert _state(hass, f"sensor.{P}_ha_peer_state") == "not_applicable"
    assert _attrs(hass, f"sensor.{P}_ha_current_state")["state_code"] == 2


async def test_no_hardware_entities_on_virtual_appliance(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry())
    assert hass.states.get(f"sensor.{P}_sensor_cpu_temperature") is None
    assert hass.states.get(f"sensor.{P}_sensor_fan_1") is None
    assert hass.states.get(f"binary_sensor.{P}_psu_psu_1") is None


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_hardware_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, hardware_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry())
    assert _state(hass, f"sensor.{P}_sensor_cpu_temperature") == "42.0"
    assert _state(hass, f"sensor.{P}_sensor_npu_temperature") == "65.0"
    assert _state(hass, f"sensor.{P}_sensor_fan_1") == "3000"
    assert _state(hass, f"sensor.{P}_sensor_fan_3") == "2900"
    assert _state(hass, f"binary_sensor.{P}_psu_psu_1") == STATE_ON
    assert _state(hass, f"binary_sensor.{P}_psu_psu_2") == STATE_OFF


# ── Dynamic entities and stale cleanup ────────────────────────────────────────


async def test_new_and_removed_firewall_objects(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    xml_api.records["Interface"].append({"Name": "PortC", "InterfaceStatus": "ON"})
    del xml_api.records["Interface"][1]  # PortB
    await _tick(hass, freezer, 30)
    assert _state(hass, f"binary_sensor.{P}_iface_portc") == STATE_ON
    assert hass.states.get(f"binary_sensor.{P}_iface_portb") is None
    assert er.async_get(hass).async_get(f"binary_sensor.{P}_iface_portb") is None


async def test_orphan_from_previous_session_is_removed(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """Upgrade case: a VPN entity created from the policy table (index 7)."""
    entry = make_entry()
    entry.add_to_hass(hass)
    er.async_get(hass).async_get_or_create(
        "binary_sensor", "sophos_firewall", "sophos_test_entry_vpn_7", config_entry=entry
    )
    await setup_entry(hass, entry)
    unique_ids = {e.unique_id for e in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)}
    assert "sophos_test_entry_vpn_7" not in unique_ids
    assert "sophos_test_entry_vpn_1" in unique_ids


async def test_empty_list_never_removes_entities(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    xml_api.records["Interface"] = []
    await _tick(hass, freezer, 30)
    assert er.async_get(hass).async_get(f"binary_sensor.{P}_iface_porta") is not None


async def test_write_access_toggles_move_rules_between_platforms(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    registry = er.async_get(hass)
    assert registry.async_get(f"binary_sensor.{P}_fwrule_allow_lan_to_iot") is not None

    hass.config_entries.async_update_entry(entry, options={**entry.options, "write_access": True})
    await hass.async_block_till_done(wait_background_tasks=True)
    assert registry.async_get(f"binary_sensor.{P}_fwrule_allow_lan_to_iot") is None
    assert _state(hass, f"switch.{P}_switch_fwrule_allow_lan_to_iot") == STATE_ON

    hass.config_entries.async_update_entry(entry, options={**entry.options, "write_access": False})
    await hass.async_block_till_done()
    assert registry.async_get(f"switch.{P}_switch_fwrule_allow_lan_to_iot") is None


# ── Switches ──────────────────────────────────────────────────────────────────


async def test_firewall_rule_switch(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False, write_access=True))
    entity_id = f"switch.{P}_switch_fwrule_block_guest"
    assert _state(hass, entity_id) == STATE_OFF
    await hass.services.async_call(SWITCH_DOMAIN, SERVICE_TURN_ON, {ATTR_ENTITY_ID: entity_id}, blocking=True)
    await hass.async_block_till_done()
    assert xml_api.records["FirewallRule"][1]["Status"] == "Enable"
    assert _state(hass, entity_id) == STATE_ON


async def test_web_filter_switch_is_reread_after_write(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    """Regression (A4): the switch flipped back — its static-tier endpoint
    was never re-read after the write."""
    await setup_entry(hass, make_entry(snmp_enabled=False, write_access=True))
    entity_id = f"switch.{P}_switch_webfilter_kids"
    before = xml_api.count("get", "WebFilterPolicy")
    await hass.services.async_call(SWITCH_DOMAIN, SERVICE_TURN_ON, {ATTR_ENTITY_ID: entity_id}, blocking=True)
    await hass.async_block_till_done()
    assert xml_api.count("get", "WebFilterPolicy") == before + 1
    await _tick(hass, freezer, 30)
    assert _state(hass, entity_id) == STATE_ON


async def test_switch_written_during_a_running_cycle_keeps_its_new_state(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """Review finding: a cycle that had read the rules before the write was
    stamped "fetched" at its end, after the write — the switch dropped its new
    state and the requested re-read found the rules fresh (up to 10 min old
    state; 30 min for web filters)."""
    await setup_entry(hass, make_entry(snmp_enabled=False, write_access=True))
    entity_id = f"switch.{P}_switch_fwrule_block_guest"
    assert _state(hass, entity_id) == STATE_OFF
    coordinator = hass.config_entries.async_entries("sophos_firewall")[0].runtime_data.xml
    xml_api.delay = 0.2
    coordinator.invalidate("interfaces", "firewall_rules")
    xml_api.auth_failures_left = 1  # this cycle's interfaces GET is rejected once
    cycle = hass.async_create_task(coordinator.async_refresh())
    await asyncio.sleep(0.5)  # rules read (old state); cycle waits to retry the login
    await hass.services.async_call(SWITCH_DOMAIN, SERVICE_TURN_ON, {ATTR_ENTITY_ID: entity_id}, blocking=True)
    await cycle
    await hass.async_block_till_done(wait_background_tasks=True)
    assert xml_api.records["FirewallRule"][1]["Status"] == "Enable"
    assert _state(hass, entity_id) == STATE_ON
    # The re-read requested by the switch waits for the running cycle; from
    # HA 2026.x the request debouncer then holds it for its 10 s cooldown.
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=11))
    await hass.async_block_till_done(wait_background_tasks=True)
    assert xml_api.count("get", "FirewallRule") == 3  # setup, the cycle, the re-read
    assert _state(hass, entity_id) == STATE_ON


async def test_rejected_switch_write_raises_translated_error(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False, write_access=True))
    xml_api.reject_sets.add("FirewallRule")
    entity_id = f"switch.{P}_switch_fwrule_block_guest"
    with pytest.raises(HomeAssistantError) as err:
        await hass.services.async_call(
            SWITCH_DOMAIN, SERVICE_TURN_ON, {ATTR_ENTITY_ID: entity_id}, blocking=True
        )
    assert err.value.translation_key == "write_failed"
    assert _state(hass, entity_id) == STATE_OFF


async def test_switch_write_timeout_is_translated(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """Regression (A8): a timeout escaped as a raw TimeoutError."""
    await setup_entry(hass, make_entry(snmp_enabled=False, write_access=True))
    xml_api.exc = TimeoutError()
    with pytest.raises(HomeAssistantError) as err:
        await hass.services.async_call(
            SWITCH_DOMAIN, SERVICE_TURN_OFF,
            {ATTR_ENTITY_ID: f"switch.{P}_switch_fwrule_allow_lan_to_iot"}, blocking=True,
        )
    assert err.value.translation_key == "write_failed"


# ── Button ────────────────────────────────────────────────────────────────────


async def test_backup_button(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    await hass.services.async_call(
        BUTTON_DOMAIN, SERVICE_PRESS, {ATTR_ENTITY_ID: f"button.{P}_button_backup"}, blocking=True
    )
    assert xml_api.requests[-1] == ("set", "BackupRestore")


async def test_backup_button_failure(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    xml_api.reject_sets.add("BackupRestore")
    with pytest.raises(HomeAssistantError) as err:
        await hass.services.async_call(
            BUTTON_DOMAIN, SERVICE_PRESS, {ATTR_ENTITY_ID: f"button.{P}_button_backup"}, blocking=True
        )
    assert err.value.translation_key == "backup_failed"


async def test_button_unavailable_when_firewall_unreachable(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    xml_api.exc = TimeoutError()
    await _tick(hass, freezer, 30)
    assert _state(hass, f"button.{P}_button_backup") == STATE_UNAVAILABLE


# ── Diagnostics ───────────────────────────────────────────────────────────────


async def test_diagnostics_redacts_secrets(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """Regression (A11): the serial number leaked under its OID key."""
    entry = make_entry()
    await setup_entry(hass, entry)
    diag = await async_get_config_entry_diagnostics(hass, entry)
    text = str(diag)
    for secret in ("secret", "C01001D2MQT76C4", "aa:bb:cc:00:11:22", "10.10.0.50", "127.0.0.1"):
        assert secret not in text, secret
    assert diag["xml"]["endpoints"]["interfaces"]["available"] is True
    assert diag["snmp"]["is_virtual"] is None  # decided after three empty health reads
    assert diag["snmp"]["data"]["stats"]["memory_percent"] == 33


# ── Missing values are unknown, never invented ────────────────────────────────


def test_items_callbacks_return_none_before_the_first_fetch() -> None:
    """DynamicFamily contract: None = never fetched (nothing is added or removed)."""
    from custom_components.sophos_firewall import binary_sensor, sensor, switch
    from custom_components.sophos_firewall.models import SnmpData, XmlData

    xml, snmp = XmlData(), SnmpData()
    assert switch._rule_items(xml) is None  # noqa: SLF001
    assert switch._policy_items(xml) is None  # noqa: SLF001
    assert sensor._dhcp_items(xml) is None  # noqa: SLF001
    assert sensor._fan_items(snmp) is None  # noqa: SLF001
    assert sensor._cpu_usage_items(snmp) is None  # noqa: SLF001
    assert sensor._cpu_core_items(snmp) is None  # noqa: SLF001
    assert sensor._traffic_items("rx_rate", set)(snmp) is None  # noqa: SLF001
    assert binary_sensor._vpn_items(snmp) is None  # noqa: SLF001
    assert binary_sensor._psu_items(snmp) is None  # noqa: SLF001


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_summaries_are_unknown_when_nothing_is_reported(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """No service/license reported a state: "unknown", not "0 running"."""
    from .fake_snmp import SOPHOS

    snmp_agent.remove_prefix(f"{SOPHOS}.3")
    snmp_agent.remove_prefix(f"{SOPHOS}.5")
    snmp_agent.remove_prefix(f"{SOPHOS}.2.2.0")  # uptime
    await setup_entry(hass, make_entry())
    assert _state(hass, f"sensor.{P}_sensor_services_summary") == "unknown"
    assert _state(hass, f"sensor.{P}_sensor_licenses_summary") == "unknown"
    assert _state(hass, f"sensor.{P}_sensor_uptime") == "unknown"
    assert _state(hass, f"sensor.{P}_service_ips") == "unknown"


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_unparseable_license_expiry_is_none(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    from .fake_snmp import SOPHOS, OctetString

    snmp_agent.set(f"{SOPHOS}.5.1.2.0", OctetString(b"never"))  # base firewall
    await setup_entry(hass, make_entry())
    assert _attrs(hass, f"sensor.{P}_license_base_fw")["expiry_date"] is None
    assert _attrs(hass, f"sensor.{P}_sensor_licenses_summary")["next_expiry"] == "Jan 5 2026"


async def test_dhcp_server_without_status(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    del xml_api.records["DHCPServer"][0]["Status"]
    await setup_entry(hass, make_entry(snmp_enabled=False))
    entity_id = f"sensor.{P}_dhcp_leases_main_dhcp"
    assert _state(hass, entity_id) == "unknown"
    assert _attrs(hass, entity_id)["lease_count"] == 2


async def test_web_filter_without_policies_or_default_action(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    xml_api.records["WebFilterPolicy"] = [{"Name": "Kids"}]  # no DefaultAction
    entry = make_entry(snmp_enabled=False, write_access=True)
    await setup_entry(hass, entry)
    assert _state(hass, f"sensor.{P}_sensor_web_filter_default_action") == "unknown"
    assert _state(hass, f"switch.{P}_switch_webfilter_kids") == "unknown"

    xml_api.records["WebFilterPolicy"] = []
    await entry.runtime_data.xml.async_refresh_endpoints("web_filter_policies")
    await hass.async_block_till_done()
    assert _state(hass, f"sensor.{P}_sensor_web_filter_default_action") == "unknown"


async def test_rejected_web_filter_write_names_the_policy(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False, write_access=True))
    xml_api.reject_sets.add("WebFilterPolicy")
    with pytest.raises(HomeAssistantError) as err:
        await hass.services.async_call(
            SWITCH_DOMAIN, SERVICE_TURN_ON,
            {ATTR_ENTITY_ID: f"switch.{P}_switch_webfilter_kids"}, blocking=True,
        )
    assert err.value.translation_key == "write_failed"
    assert err.value.translation_placeholders["name"] == "Kids"


# ── Entities follow the enabled data sources ──────────────────────────────────


async def test_entities_of_disabled_sources_are_not_created(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """Default install: backup and HA polling are off → no forever-unavailable entities."""
    await setup_entry(hass, make_entry())
    for entity_id in (
        f"sensor.{P}_sensor_backup_frequency",
        f"binary_sensor.{P}_ha_enabled",
        f"sensor.{P}_ha_current_state",
        f"sensor.{P}_ha_peer_state",
    ):
        assert hass.states.get(entity_id) is None, entity_id


async def test_switching_a_source_off_removes_its_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry()
    await setup_entry(hass, entry)
    registry = er.async_get(hass)
    assert registry.async_get(f"sensor.{P}_sensor_memory_percent") is not None
    assert registry.async_get(f"binary_sensor.{P}_vpn_1") is not None

    hass.config_entries.async_update_entry(
        entry, options={**entry.options, "poll_snmp_stats": False, "poll_snmp_tunnels": False}
    )
    await hass.async_block_till_done(wait_background_tasks=True)
    assert registry.async_get(f"sensor.{P}_sensor_memory_percent") is None
    assert registry.async_get(f"sensor.{P}_sensor_uptime") is None
    assert registry.async_get(f"binary_sensor.{P}_vpn_1") is None
    assert registry.async_get(f"sensor.{P}_sensor_services_summary") is not None


async def test_switching_snmp_off_removes_exactly_the_snmp_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, hardware_agent: FakeSnmpAgent
) -> None:
    """Review finding: with SNMP switched off, every SNMP entity stayed
    "unavailable". Compared against an XML-only setup of the same firewall,
    so no SNMP entity is left and no XML entity is lost."""
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    registry = er.async_get(hass)

    def _entities() -> set[str]:
        return {e.entity_id for e in er.async_entries_for_config_entry(registry, entry.entry_id)}

    xml_only = _entities()
    hass.config_entries.async_update_entry(entry, options={**entry.options, "snmp_enabled": True, "poll_snmp_ha": True})
    await hass.async_block_till_done(wait_background_tasks=True)
    with_snmp = _entities()
    assert {f"sensor.{P}_sensor_memory_percent", f"sensor.{P}_service_ips",
            f"sensor.{P}_traffic_rx_rate_portb", f"sensor.{P}_sensor_cpu_core_1",
            f"sensor.{P}_sensor_fan_1", f"binary_sensor.{P}_psu_psu_1",
            f"binary_sensor.{P}_vpn_1", f"binary_sensor.{P}_ha_enabled",
            f"sensor.{P}_ha_current_state"} <= with_snmp - xml_only

    hass.config_entries.async_update_entry(entry, options={**entry.options, "snmp_enabled": False})
    await hass.async_block_till_done(wait_background_tasks=True)
    assert _entities() == xml_only


async def test_snmp_that_fails_to_start_keeps_its_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """Only the user's choice removes entities, not an SNMP start error."""
    entry = make_entry()
    await setup_entry(hass, entry)
    registry = er.async_get(hass)
    assert registry.async_get(f"sensor.{P}_sensor_memory_percent") is not None
    with patch(
        "custom_components.sophos_firewall.SNMPClient.preload", side_effect=OSError("boom")
    ):
        await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done(wait_background_tasks=True)
    assert entry.runtime_data.snmp is None
    assert registry.async_get(f"sensor.{P}_sensor_memory_percent") is not None


async def test_hardware_entities_survive_a_missing_row(
    hass: HomeAssistant, xml_api: FakeSophosApi, hardware_agent: FakeSnmpAgent
) -> None:
    """A failed PSU/fan dropping out of the table must keep its entity."""
    from .fake_snmp import FAN_SPEED, PSU_STATUS

    entry = make_entry()
    await setup_entry(hass, entry)
    hardware_agent.remove_prefix(f"{PSU_STATUS}.2")
    hardware_agent.remove_prefix(f"{FAN_SPEED}.3")
    entry.runtime_data.snmp.invalidate("health")
    await entry.runtime_data.snmp.async_refresh()
    await hass.async_block_till_done()
    registry = er.async_get(hass)
    assert registry.async_get(f"binary_sensor.{P}_psu_psu_2") is not None
    assert registry.async_get(f"sensor.{P}_sensor_fan_3") is not None


# ── Switch optimistic state ───────────────────────────────────────────────────


async def test_switch_shows_firewall_truth_after_reread(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """A write the firewall accepts but does not apply reverts after the re-read."""
    await setup_entry(hass, make_entry(snmp_enabled=False, write_access=True))
    entity_id = f"switch.{P}_switch_fwrule_block_guest"
    original = xml_api._answer

    def accept_but_ignore(url, data):
        response = original(url, data)
        xml_api.records["FirewallRule"][1]["Status"] = "Disable"
        return response

    xml_api._answer = accept_but_ignore  # type: ignore[method-assign]
    await hass.services.async_call(SWITCH_DOMAIN, SERVICE_TURN_ON, {ATTR_ENTITY_ID: entity_id}, blocking=True)
    await hass.async_block_till_done()
    assert _state(hass, entity_id) == STATE_OFF


async def test_switch_with_failed_reread_is_unavailable_not_stale(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    """If the re-read after a write fails, the old value must not come back."""
    await setup_entry(hass, make_entry(snmp_enabled=False, write_access=True))
    entity_id = f"switch.{P}_switch_webfilter_kids"
    xml_api.broken_gets.add("WebFilterPolicy")
    await hass.services.async_call(SWITCH_DOMAIN, SERVICE_TURN_ON, {ATTR_ENTITY_ID: entity_id}, blocking=True)
    await hass.async_block_till_done()
    assert _state(hass, entity_id) == STATE_UNAVAILABLE
    xml_api.broken_gets.clear()
    await _tick(hass, freezer, 30)  # failed endpoints are retried on the next run
    assert _state(hass, entity_id) == STATE_ON


async def test_v102_policy_table_leftovers_removed_without_ipsec(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """Field test: no IPsec connections → empty tunnel table after a successful
    walk → the VPN entities v1.0.2 created from the policy table must go."""
    from .fake_snmp import VPN_ENTRY

    snmp_agent.remove_prefix(VPN_ENTRY)
    entry = make_entry()
    entry.add_to_hass(hass)
    registry = er.async_get(hass)
    for index in (1, 4, 9):
        registry.async_get_or_create(
            "binary_sensor", "sophos_firewall", f"sophos_test_entry_vpn_{index}", config_entry=entry
        )
    await setup_entry(hass, entry)

    def vpn_entities() -> list[str]:
        return [
            e.unique_id for e in er.async_entries_for_config_entry(registry, entry.entry_id)
            if "_vpn_" in e.unique_id
        ]

    assert len(vpn_entities()) == 3  # one empty walk is not enough
    for _ in range(2):
        entry.runtime_data.snmp.invalidate("tunnels")
        await entry.runtime_data.snmp.async_refresh()
        await hass.async_block_till_done()
    assert vpn_entities() == []  # third consecutive empty walk


async def test_transiently_empty_tunnel_table_keeps_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """E.g. the IPsec service still starting after a firewall reboot."""
    from .fake_snmp import VPN_ENTRY, sophos_mib

    entry = make_entry()
    await setup_entry(hass, entry)
    snmp = entry.runtime_data.snmp
    registry = er.async_get(hass)
    snmp_agent.remove_prefix(VPN_ENTRY)
    for _ in range(2):
        snmp.invalidate("tunnels")
        await snmp.async_refresh()
        await hass.async_block_till_done()
    for oid, value in sophos_mib().items():  # tunnels are back
        snmp_agent.set(oid, value)
    snmp.invalidate("tunnels")
    await snmp.async_refresh()
    await hass.async_block_till_done()
    snmp_agent.remove_prefix(VPN_ENTRY)
    snmp.invalidate("tunnels")
    await snmp.async_refresh()
    await hass.async_block_till_done()
    assert registry.async_get(f"binary_sensor.{P}_vpn_1") is not None


async def test_failed_walk_never_counts_as_empty(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """The trust in empty tables must not extend to failed walks."""
    entry = make_entry()
    await setup_entry(hass, entry)
    snmp_agent.drop_prefixes = {"1.3.6.1.4.1.2604.5.1.6"}
    entry.runtime_data.snmp.invalidate("tunnels")
    await entry.runtime_data.snmp.async_refresh()
    await hass.async_block_till_done()
    assert er.async_get(hass).async_get(f"binary_sensor.{P}_vpn_1") is not None


# ── Gold: categories, defaults, icons (Phase 3) ───────────────────────────────


async def test_rarely_used_entities_are_created_disabled(
    hass: HomeAssistant, xml_api: FakeSophosApi, hardware_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry(options={"poll_xml_backup": True, "poll_snmp_ha": True}))
    registry = er.async_get(hass)
    disabled = {
        e.entity_id.removeprefix(f"{e.domain}.{P}_")
        for e in er.async_entries_for_config_entry(registry, "sophos_test_entry")
        if e.disabled_by is er.RegistryEntryDisabler.INTEGRATION
    }
    assert disabled == {
        "fwrule_allow_lan_to_iot", "fwrule_block_guest",
        "sensor_swap_percent", "sensor_ftp_hits", "sensor_smtp_hits",
        "sensor_imap_hits", "sensor_pop3_hits",
        "sensor_ips_version", "sensor_webcat_version",
        "sensor_fan_1", "sensor_fan_2", "sensor_fan_3",
        "ha_peer_state", "sensor_backup_frequency",
        # Phase 4: per core, per service, per license
        "sensor_cpu_core_1", "sensor_cpu_core_2", "sensor_cpu_core_3", "sensor_cpu_core_4",
        *(f"service_{key}" for key in (
            "pop3", "imap", "smtp", "ftp", "http", "av", "antispam", "dns", "ha_svc", "ips",
            "apache", "ntp", "tomcat", "ssl_vpn", "ipsec_vpn", "database", "network",
            "garner", "drouting", "sshd", "dgd",
        )),
        *(f"license_{key}" for key in (
            "base_fw", "net_protect", "web_protect", "mail_protect", "web_server",
            "sandstorm", "enh_support", "enh_plus", "central_orch",
        )),
        # byte counters of every interface; rates of interfaces the XML API
        # does not list (VLANs, wireless network)
        *(f"traffic_{kind}_{name}" for kind in ("rx_bytes", "tx_bytes")
          for name in ("porta", "portb", "porta_30", "porta_40", "porta_50", "guestap")),
        *(f"traffic_{kind}_{name}" for kind in ("rx_rate", "tx_rate")
          for name in ("porta_30", "porta_40", "porta_50", "guestap")),
    }
    assert hass.states.get(f"sensor.{P}_sensor_swap_percent") is None


async def test_existing_entities_stay_enabled_and_get_their_category(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """Update from v1.0.x: disabled-by-default only applies to new entities;
    the category of existing ones is updated."""
    entry = make_entry()
    entry.add_to_hass(hass)
    registry = er.async_get(hass)
    for suffix in ("sensor_swap_percent", "sensor_uptime"):
        registry.async_get_or_create(
            "sensor", "sophos_firewall", f"sophos_test_entry_{suffix}",
            config_entry=entry, suggested_object_id=f"{P}_{suffix}",
        )
    await setup_entry(hass, entry)
    swap = registry.async_get(f"sensor.{P}_sensor_swap_percent")
    assert swap is not None and swap.disabled_by is None
    assert _state(hass, f"sensor.{P}_sensor_swap_percent") == "23"
    uptime = registry.async_get(f"sensor.{P}_sensor_uptime")
    assert uptime is not None and uptime.entity_category is er.EntityCategory.DIAGNOSTIC


async def test_icons_come_from_icons_json(
    hass: HomeAssistant, xml_api: FakeSophosApi, hardware_agent: FakeSnmpAgent
) -> None:
    """No hard-coded icons: the icon-translations rule replaces _attr_icon."""
    await setup_entry(
        hass,
        make_entry(write_access=True, options={"poll_xml_backup": True, "poll_snmp_ha": True}),
    )
    entries = er.async_entries_for_config_entry(er.async_get(hass), "sophos_test_entry")
    assert entries
    assert [e.entity_id for e in entries if e.original_icon] == []


async def _refresh_stats(hass: HomeAssistant, entry) -> None:
    snmp = entry.runtime_data.snmp
    snmp.invalidate("stats")
    await snmp.async_refresh()
    await hass.async_block_till_done()


async def test_last_boot_is_stable_and_follows_reboots(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi,
    snmp_agent: FakeSnmpAgent,
) -> None:
    """v1.0.x wrote a new uptime state every poll; the boot time must only
    change on a reboot (or a drift beyond the tolerance)."""
    from .fake_snmp import SOPHOS, TimeTicks

    uptime_oid = f"{SOPHOS}.2.2.0"
    uptime = 650274300  # ticks (1/100 s)
    entry = make_entry()
    await setup_entry(hass, entry)
    entity_id = f"sensor.{P}_sensor_uptime"
    first = hass.states.get(entity_id)
    assert first is not None

    # 30 s later, the agent reports 31 s more (poll timing jitter): unchanged
    freezer.tick(timedelta(seconds=30))
    snmp_agent.set(uptime_oid, TimeTicks(uptime + 3100))
    await _refresh_stats(hass, entry)
    assert hass.states.get(entity_id).state == first.state
    assert hass.states.get(entity_id).last_changed == first.last_changed

    # drift beyond the 60 s tolerance: corrected
    freezer.tick(timedelta(seconds=30))
    snmp_agent.set(uptime_oid, TimeTicks(uptime + 6000 + 9000))
    await _refresh_stats(hass, entry)
    drifted = dt_util.parse_datetime(_state(hass, entity_id))
    assert drifted == dt_util.parse_datetime(first.state) - timedelta(seconds=90)

    # state written again long after the fetch (no new data): the uptime was
    # valid at fetch time, so the boot time must not move by the elapsed time
    before = _state(hass, entity_id)
    freezer.tick(timedelta(seconds=120))
    entity = hass.data["entity_components"]["sensor"].get_entity(entity_id)
    entity.async_write_ha_state()
    assert _state(hass, entity_id) == before

    # reboot: uptime starts again
    freezer.tick(timedelta(seconds=30))
    snmp_agent.set(uptime_oid, TimeTicks(12000))
    await _refresh_stats(hass, entry)
    rebooted = dt_util.parse_datetime(_state(hass, entity_id))
    assert rebooted == (dt_util.utcnow() - timedelta(seconds=120)).replace(microsecond=0)


async def test_version_entity_without_value_is_removed_after_confirmation(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """Field test: SFOS 22 reports "not available" as the web category
    version; the entity left over from v1.0.x stayed "unavailable" forever."""
    from .fake_snmp import SOPHOS, OctetString

    snmp_agent.set(f"{SOPHOS}.1.5.0", OctetString(b"not available"))
    entry = make_entry()
    entry.add_to_hass(hass)
    registry = er.async_get(hass)
    registry.async_get_or_create(
        "sensor", "sophos_firewall", "sophos_test_entry_sensor_webcat_version",
        config_entry=entry, suggested_object_id=f"{P}_sensor_webcat_version",
    )
    await setup_entry(hass, entry)
    webcat = f"sensor.{P}_sensor_webcat_version"
    assert registry.async_get(webcat) is not None  # one answer is not enough

    snmp = entry.runtime_data.snmp
    for _ in range(2):
        snmp.invalidate("device")
        await snmp.async_refresh()
        await hass.async_block_till_done()
    assert registry.async_get(webcat) is None
    assert registry.async_get(f"sensor.{P}_sensor_ips_version") is not None


async def test_version_entity_survives_a_failed_fetch(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """Only successful answers without a value count."""
    from .fake_snmp import SOPHOS, OctetString

    snmp_agent.set(f"{SOPHOS}.1.5.0", OctetString(b"not available"))
    entry = make_entry()
    entry.add_to_hass(hass)
    er.async_get(hass).async_get_or_create(
        "sensor", "sophos_firewall", "sophos_test_entry_sensor_webcat_version",
        config_entry=entry, suggested_object_id=f"{P}_sensor_webcat_version",
    )
    await setup_entry(hass, entry)  # first confirmation
    snmp = entry.runtime_data.snmp
    snmp_agent.drop_all = True
    for _ in range(3):
        snmp.invalidate("device")
        await snmp.async_refresh()
        await hass.async_block_till_done()
    assert er.async_get(hass).async_get(f"sensor.{P}_sensor_webcat_version") is not None


# ── Per-service and per-license sensors (Phase 4) ─────────────────────────────


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_service_sensors(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry())
    assert _state(hass, f"sensor.{P}_service_ips") == "running"
    assert _state(hass, f"sensor.{P}_service_antispam") == "stopped"
    assert _state(hass, f"sensor.{P}_service_tomcat") == "unknown"  # not implemented
    attrs = _attrs(hass, f"sensor.{P}_service_ips")
    assert attrs["friendly_name"] == "5HeyneXG Service IPS"
    assert attrs["state_code"] == 3
    assert attrs["options"][7] == "unregistered"


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_unknown_service_code_is_unknown_and_logged(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent, caplog
) -> None:
    from .fake_snmp import SOPHOS, Integer

    snmp_agent.set(f"{SOPHOS}.3.10.0", Integer(9))  # IPS
    await setup_entry(hass, make_entry())
    assert _state(hass, f"sensor.{P}_service_ips") == "unknown"
    assert _attrs(hass, f"sensor.{P}_service_ips")["state_code"] == 9
    assert "Unknown value '9' for service ips" in caplog.text


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_license_sensors(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry())
    entity_id = f"sensor.{P}_license_base_fw"
    assert _state(hass, entity_id) == "subscribed"
    assert _attrs(hass, entity_id)["expiry_date"] == "2999-12-31"
    assert _attrs(hass, entity_id)["friendly_name"] == "5HeyneXG License Base Firewall"
    assert _state(hass, f"sensor.{P}_license_mail_protect") == "expired"
    assert _state(hass, f"sensor.{P}_license_enh_support") == "none"
    assert _attrs(hass, f"sensor.{P}_license_enh_support")["expiry_date"] is None


async def test_service_and_license_sensors_follow_their_options(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry(options={"poll_snmp_services": False, "poll_snmp_licenses": False})
    await setup_entry(hass, entry)
    ids = [e.entity_id for e in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)]
    assert not [i for i in ids if "_service_" in i or "_license_" in i]
