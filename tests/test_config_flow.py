"""Config, reauth, reconfigure and options flows through Home Assistant's flow manager."""
from __future__ import annotations

from typing import Any

import pytest
from homeassistant.config_entries import SOURCE_USER, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import entity_registry as er

from custom_components.sophos_firewall.const import DOMAIN
from pytest_homeassistant_custom_component.common import MockConfigEntry

from .conftest import CONNECTION, make_entry, setup_entry
from .fake_snmp import FakeSnmpAgent
from .fake_sophos import HOST, PORT, FakeSophosApi

POLLING: dict[str, Any] = {
    "realtime": {"interval_realtime": 30, "poll_xml_interfaces": True},
    "fast": {"interval_fast": 120},
    "operative": {"interval_operative": 600, "poll_xml_fw_rules": True},
    "static": {"interval_static": 1800, "poll_xml_dhcp": True,
               "poll_xml_webfilter": True, "poll_xml_backup": False},
}
SNMP_POLLING: dict[str, Any] = {
    "realtime": {**POLLING["realtime"], "poll_snmp_stats": True, "poll_snmp_services": True,
                 "poll_snmp_traffic": True},
    "fast": {**POLLING["fast"], "poll_snmp_tunnels": True, "poll_snmp_ha": False},
    "operative": {**POLLING["operative"], "poll_snmp_health": True},
    "static": {**POLLING["static"], "poll_snmp_licenses": True},
}


async def _user_step(hass: HomeAssistant, user_input: dict[str, Any] = CONNECTION) -> dict[str, Any]:
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"
    return await hass.config_entries.flow.async_configure(result["flow_id"], user_input)


# ── User flow ─────────────────────────────────────────────────────────────────


async def test_full_flow_without_snmp(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    result = await _user_step(hass)
    assert result["step_id"] == "snmp"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"snmp_enabled": False, "snmp_community": "public"}
    )
    assert result["step_id"] == "write_access"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"write_access": True})
    assert result["step_id"] == "polling"
    schema_sections = set(result["data_schema"].schema)
    assert schema_sections == {"realtime", "fast", "operative", "static"}
    result = await hass.config_entries.flow.async_configure(result["flow_id"], POLLING)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    entry = result["result"]
    assert entry.title == HOST
    assert entry.unique_id == f"{HOST}:{PORT}"
    assert entry.version == 2
    assert dict(entry.data) == CONNECTION  # only connection settings in data
    assert entry.options["write_access"] is True
    assert entry.options["interval_operative"] == 600
    assert "snmp_version" not in entry.options


async def test_full_flow_with_snmp(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    result = await _user_step(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"snmp_enabled": True, "snmp_community": "public"}
    )
    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"write_access": False})
    result = await hass.config_entries.flow.async_configure(result["flow_id"], SNMP_POLLING)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done(wait_background_tasks=True)
    assert result["result"].state is ConfigEntryState.LOADED
    assert hass.states.get("sensor.5heynexg_sensor_memory_percent").state == "33"


async def test_snmp_step_error_and_recovery(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    result = await _user_step(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"snmp_enabled": True, "snmp_community": "wrong"}
    )
    assert result["errors"] == {"base": "snmp_cannot_connect"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"snmp_enabled": True, "snmp_community": "public"}
    )
    assert result["step_id"] == "write_access"


@pytest.mark.parametrize(
    ("setup_fake", "error"),
    [
        (lambda api: setattr(api, "password", "other"), "invalid_auth"),
        (lambda api: setattr(api, "access_code", "534"), "api_access_denied"),
        (lambda api: setattr(api, "exc", TimeoutError()), "cannot_connect"),
        (lambda api: setattr(api, "exc", RuntimeError("bug")), "unknown"),
    ],
)
async def test_user_step_errors_and_recovery(
    hass: HomeAssistant, xml_api: FakeSophosApi, setup_fake, error: str
) -> None:
    setup_fake(xml_api)
    result = await _user_step(hass)
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": error}

    fresh = FakeSophosApi()
    xml_api.password, xml_api.access_code, xml_api.exc = fresh.password, None, None
    result = await hass.config_entries.flow.async_configure(result["flow_id"], CONNECTION)
    assert result["step_id"] == "snmp"


async def test_same_firewall_cannot_be_added_twice(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    make_entry().add_to_hass(hass)
    result = await _user_step(hass)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_duplicate_detected_even_without_entry_unique_id(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    MockConfigEntry(domain=DOMAIN, data=dict(CONNECTION), version=2).add_to_hass(hass)
    result = await _user_step(hass)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


# ── Reauth ────────────────────────────────────────────────────────────────────


async def test_reauth(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    xml_api.password = "new-password"
    result = await entry.start_reauth_flow(hass)
    assert result["step_id"] == "reauth_confirm"
    assert result["description_placeholders"]["host"] == HOST
    assert result["description_placeholders"]["username"] == "admin"

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"password": "wrong"})
    assert result["errors"] == {"base": "invalid_auth"}
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": "new-password"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data["password"] == "new-password"
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED


RELOAD_WARNING = "should use it for scheduling a reload"


async def _admin_gets_after(hass: HomeAssistant, xml_api: FakeSophosApi, before: int) -> int:
    await hass.async_block_till_done(wait_background_tasks=True)
    return xml_api.count("get", "AdminSettings") - before


async def test_reauth_reloads_a_loaded_entry_once(
    hass: HomeAssistant, xml_api: FakeSophosApi, caplog: pytest.LogCaptureFixture
) -> None:
    """Review finding: the update listener and async_update_reload_and_abort
    both reloaded the entry (HA warns: breaks in 2026.12)."""
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    before = xml_api.count("get", "AdminSettings")
    xml_api.password = "new-password"
    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": "new-password"}
    )
    assert result["reason"] == "reauth_successful"
    assert await _admin_gets_after(hass, xml_api, before) == 1  # one setup = one reload
    assert entry.state is ConfigEntryState.LOADED
    assert RELOAD_WARNING not in caplog.text


async def test_reauth_with_the_same_password_still_reloads(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """Polling stops on rejected credentials; confirming the unchanged
    password (e.g. an account that was locked) must start it again."""
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    before = xml_api.count("get", "AdminSettings")
    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": CONNECTION["password"]}
    )
    assert result["reason"] == "reauth_successful"
    assert await _admin_gets_after(hass, xml_api, before) == 1


async def test_reauth_after_failed_setup_reloads(
    hass: HomeAssistant, xml_api: FakeSophosApi, caplog: pytest.LogCaptureFixture
) -> None:
    xml_api.password = "changed-on-firewall"
    entry = make_entry(snmp_enabled=False)
    entry.add_to_hass(hass)
    assert not await hass.config_entries.async_setup(entry.entry_id)
    assert entry.state is ConfigEntryState.SETUP_ERROR
    result = await entry.start_reauth_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"password": "changed-on-firewall"}
    )
    assert result["reason"] == "reauth_successful"
    await hass.async_block_till_done(wait_background_tasks=True)
    assert entry.state is ConfigEntryState.LOADED
    assert RELOAD_WARNING not in caplog.text


async def test_reconfigure_reloads_a_loaded_entry_once(
    hass: HomeAssistant, xml_api: FakeSophosApi, caplog: pytest.LogCaptureFixture
) -> None:
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    before = xml_api.count("get", "AdminSettings")
    xml_api.password = "rotated"
    result = await entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**CONNECTION, "password": "rotated"}
    )
    assert result["reason"] == "reconfigure_successful"
    assert await _admin_gets_after(hass, xml_api, before) == 1
    assert entry.state is ConfigEntryState.LOADED
    assert RELOAD_WARNING not in caplog.text


async def test_renaming_the_entry_does_not_reload_it(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    before = xml_api.count("get", "AdminSettings")
    hass.config_entries.async_update_entry(entry, title="Firewall Keller")
    assert await _admin_gets_after(hass, xml_api, before) == 0


# ── Reconfigure ───────────────────────────────────────────────────────────────


async def test_reconfigure_validates_credentials(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    result = await entry.start_reconfigure_flow(hass)
    assert result["step_id"] == "reconfigure"
    assert result["description_placeholders"]["host"] == HOST
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**CONNECTION, "password": "wrong"}
    )
    assert result["errors"] == {"base": "invalid_auth"}
    xml_api.password = "rotated"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**CONNECTION, "password": "rotated"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert entry.data["password"] == "rotated"
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED


async def test_reconfigure_to_another_host_keeps_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, aioclient_mock
) -> None:
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    registry = er.async_get(hass)
    before = {e.entity_id: e.unique_id for e in er.async_entries_for_config_entry(registry, entry.entry_id)}
    aioclient_mock.post("https://localhost:4444/webconsole/APIController", side_effect=xml_api.handle)

    result = await entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**CONNECTION, "host": "localhost"}
    )
    assert result["reason"] == "reconfigure_successful"
    await hass.async_block_till_done()
    assert entry.data["host"] == "localhost"
    assert entry.unique_id == "localhost:4444"
    assert entry.title == "localhost"
    assert entry.state is ConfigEntryState.LOADED
    after = {e.entity_id: e.unique_id for e in er.async_entries_for_config_entry(registry, entry.entry_id)}
    assert after == before  # regression (A9): v1.0.x orphaned every entity


async def test_reconfigure_to_unique_id_of_another_entry_is_refused(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """An entry whose (stale) unique_id names the target address also blocks it."""
    MockConfigEntry(
        domain=DOMAIN, version=2, data={**CONNECTION, "host": "10.1.1.1"}, unique_id="10.9.9.9:4444"
    ).add_to_hass(hass)
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    result = await entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**CONNECTION, "host": "10.9.9.9"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


async def test_reconfigure_to_an_address_of_another_entry_is_refused(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    other = MockConfigEntry(
        domain=DOMAIN, version=2, data={**CONNECTION, "host": "10.9.9.9"}, unique_id="10.9.9.9:4444"
    )
    other.add_to_hass(hass)
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    result = await entry.start_reconfigure_flow(hass)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {**CONNECTION, "host": "10.9.9.9"}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


# ── Options ───────────────────────────────────────────────────────────────────


async def test_options_flow_writes_options_only(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    """Regression (A12): v1.0.x wrote data and options → two reloads."""
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    data_before = dict(entry.data)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["step_id"] == "init"
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {"snmp_enabled": False, "snmp_community": "public", "write_access": True, **SNMP_POLLING},
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done(wait_background_tasks=True)
    assert dict(entry.data) == data_before
    assert entry.options["write_access"] is True
    assert entry.options["interval_realtime"] == 30
    assert entry.state is ConfigEntryState.LOADED
    assert hass.states.get("switch.5heynexg_switch_fwrule_block_guest") is not None


async def test_options_flow_tests_snmp_when_enabled(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    user_input = {"snmp_enabled": True, "snmp_community": "wrong", "write_access": False, **SNMP_POLLING}
    result = await hass.config_entries.options.async_configure(result["flow_id"], user_input)
    assert result["errors"] == {"base": "snmp_cannot_connect"}
    result = await hass.config_entries.options.async_configure(
        result["flow_id"], {**user_input, "snmp_community": "public"}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done(wait_background_tasks=True)
    assert hass.states.get("sensor.5heynexg_sensor_memory_percent").state == "33"


async def test_options_flow_switches_interface_traffic_off(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry()
    await setup_entry(hass, entry)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    realtime = result["data_schema"].schema["realtime"].schema.schema
    assert "poll_snmp_traffic" in {str(key) for key in realtime}
    polling = {**SNMP_POLLING, "realtime": {**SNMP_POLLING["realtime"], "poll_snmp_traffic": False}}
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {"snmp_enabled": True, "snmp_community": "public", "write_access": False, **polling},
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done(wait_background_tasks=True)
    assert entry.options["poll_snmp_traffic"] is False
    assert not entry.runtime_data.snmp.endpoint_enabled("traffic")


async def test_options_flow_skips_snmp_test_when_unchanged(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry()
    await setup_entry(hass, entry)
    snmp_agent.drop_all = True  # a test would fail now
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {"snmp_enabled": True, "snmp_community": "public", "write_access": False, **SNMP_POLLING},
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY
    await hass.async_block_till_done(wait_background_tasks=True)  # reload with dead agent


async def test_interval_out_of_range_is_rejected(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    from homeassistant.data_entry_flow import InvalidData

    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    bad = {**SNMP_POLLING, "realtime": {**SNMP_POLLING["realtime"], "interval_realtime": 5}}
    with pytest.raises(InvalidData):
        await hass.config_entries.options.async_configure(
            result["flow_id"],
            {"snmp_enabled": False, "snmp_community": "public", "write_access": False, **bad},
        )


async def test_options_form_keeps_entered_values_after_error(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    changed = {**SNMP_POLLING, "realtime": {**SNMP_POLLING["realtime"], "interval_realtime": 77}}
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {"snmp_enabled": True, "snmp_community": "wrong", "write_access": False, **changed},
    )
    assert result["errors"] == {"base": "snmp_cannot_connect"}
    realtime = result["data_schema"].schema["realtime"].schema.schema
    defaults = {str(key): key.default() for key in realtime}
    assert defaults["interval_realtime"] == 77


async def test_unexpected_snmp_error_is_reported_as_unknown(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The flow's safety net for a bug in the SNMP path. Only reachable by
    injecting an unexpected exception: every real transport, protocol and
    decoding error is a SophosSNMPError (snmp_cannot_connect)."""
    from custom_components.sophos_firewall.snmp_client import SNMPClient

    async def _bug(self: SNMPClient) -> None:
        raise RuntimeError("bug")

    monkeypatch.setattr(SNMPClient, "test_connection", _bug)
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {"snmp_enabled": True, "snmp_community": "public", "write_access": False, **SNMP_POLLING},
    )
    assert result["errors"] == {"base": "unknown"}
