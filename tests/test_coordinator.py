"""Coordinators: tier scheduling, per-source and per-endpoint availability."""
from __future__ import annotations

from collections.abc import Generator
from datetime import timedelta
from unittest.mock import patch

import pytest
from freezegun.api import FrozenDateTimeFactory
from homeassistant.config_entries import SOURCE_REAUTH
from homeassistant.const import STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components.sophos_firewall.const import Tier
from custom_components.sophos_firewall.coordinator import TierScheduler

from .conftest import make_entry, setup_entry
from .fake_snmp import SOPHOS, FakeSnmpAgent, Integer, sophos_mib
from .fake_sophos import FakeSophosApi

IFACE = "binary_sensor.5heynexg_iface_porta"
RULE = "binary_sensor.5heynexg_fwrule_allow_lan_to_iot"
MEMORY = "sensor.5heynexg_sensor_memory_percent"
HTTP_HITS = "sensor.5heynexg_sensor_http_hits"
VPN = "binary_sensor.5heynexg_vpn_1"


@pytest.fixture(autouse=True)
def no_auth_retry_delay() -> Generator[None]:
    with patch("custom_components.sophos_firewall.coordinator.AUTH_RETRY_DELAY", 0):
        yield


async def _tick(hass: HomeAssistant, freezer: FrozenDateTimeFactory, seconds: float) -> None:
    from pytest_homeassistant_custom_component.common import async_fire_time_changed

    freezer.tick(timedelta(seconds=seconds))
    async_fire_time_changed(hass)
    await hass.async_block_till_done(wait_background_tasks=True)


async def _refresh_snmp(hass: HomeAssistant, entry, *keys: str) -> None:
    """Re-poll SNMP endpoints now.

    SNMP timeouts are real UDP timeouts on the event loop clock, which the
    freezer would stop — so SNMP failure tests refresh explicitly instead.
    """
    snmp = entry.runtime_data.snmp
    snmp.invalidate(*keys)
    await snmp.async_refresh()
    await hass.async_block_till_done()


def _state(hass: HomeAssistant, entity_id: str) -> str:
    state = hass.states.get(entity_id)
    assert state is not None, entity_id
    return state.state


# ── TierScheduler (pure) ──────────────────────────────────────────────────────


INTERVALS = {Tier.REALTIME: 30, Tier.FAST: 120, Tier.OPERATIVE: 600, Tier.STATIC: 1800}


def test_never_fetched_is_due_even_right_after_host_boot() -> None:
    """Regression (A3): a 0.0 sentinel hid operative/static data after a reboot.

    time.monotonic() counts from host boot; at 180 s uptime v1.0.x computed
    180 - 0.0 < 600 and skipped the firewall rules for ten minutes.
    """
    scheduler = TierScheduler(INTERVALS, 30)
    for tier in Tier:
        assert scheduler.is_due("x", tier, now=180.0)


def test_realtime_is_due_despite_scheduling_jitter() -> None:
    """Regression (A2): HA's scheduling makes the gap a hair under 30 s."""
    scheduler = TierScheduler(INTERVALS, 30)
    scheduler.mark_fetched("iface", 1000.0)
    assert scheduler.is_due("iface", Tier.REALTIME, now=1029.99)


def test_slower_tiers_wait_for_their_interval() -> None:
    scheduler = TierScheduler(INTERVALS, 30)
    scheduler.mark_fetched("rules", 1000.0)
    assert not scheduler.is_due("rules", Tier.OPERATIVE, now=1000 + 570)
    assert scheduler.is_due("rules", Tier.OPERATIVE, now=1000 + 599.9)


def test_invalidate_makes_endpoint_due() -> None:
    scheduler = TierScheduler(INTERVALS, 30)
    scheduler.mark_fetched("rules", 1000.0)
    scheduler.invalidate("rules")
    assert scheduler.is_due("rules", Tier.OPERATIVE, now=1001.0)


# ── Scheduling through the real coordinator ───────────────────────────────────


async def test_tiers_poll_at_their_intervals(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    assert xml_api.count("get", "Interface") == 1
    assert xml_api.count("get", "FirewallRule") == 1

    for _ in range(19):  # 19 × 30 s = 570 s
        await _tick(hass, freezer, 30)
    assert xml_api.count("get", "Interface") == 20  # every run — no skipped cycles
    assert xml_api.count("get", "FirewallRule") == 1

    await _tick(hass, freezer, 30)  # 600 s
    assert xml_api.count("get", "FirewallRule") == 2
    assert xml_api.count("get", "DHCPServer") == 1


async def test_disabled_endpoint_is_not_polled(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(options={"poll_xml_fw_rules": False}, snmp_enabled=False))
    assert xml_api.count("get", "FirewallRule") == 0
    assert xml_api.count("get", "BackupRestore") == 0  # off by default


# ── XML failures ──────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_failing_endpoint_affects_only_its_entities(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi, caplog
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    xml_api.broken_tags.add("Interface")
    await _tick(hass, freezer, 30)
    assert _state(hass, IFACE) == STATE_UNAVAILABLE
    assert _state(hass, RULE) == "on"

    await _tick(hass, freezer, 30)
    assert caplog.text.count("fetching interfaces failed") == 1  # logged once, not per cycle

    xml_api.broken_tags.clear()
    await _tick(hass, freezer, 30)
    assert _state(hass, IFACE) == "on"
    assert "interfaces is available again" in caplog.text


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_unreachable_firewall_makes_xml_entities_unavailable(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry()
    await setup_entry(hass, entry)
    xml_api.exc = TimeoutError()
    await _tick(hass, freezer, 30)
    assert _state(hass, IFACE) == STATE_UNAVAILABLE
    assert _state(hass, RULE) == STATE_UNAVAILABLE
    assert isinstance(entry.runtime_data.xml.last_exception, UpdateFailed)
    # SNMP is a separate source and keeps working
    assert _state(hass, MEMORY) == "33"

    xml_api.exc = None
    await _tick(hass, freezer, 30)
    assert _state(hass, IFACE) == "on"
    assert _state(hass, RULE) == "on"


async def test_transient_auth_failure_is_retried(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    xml_api.auth_failures_left = 1
    await _tick(hass, freezer, 30)
    assert _state(hass, IFACE) == "on"
    assert not hass.config_entries.flow.async_progress()


async def test_rejected_credentials_during_operation_start_reauth(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    xml_api.password = "rotated"
    await _tick(hass, freezer, 30)
    flows = hass.config_entries.flow.async_progress()
    assert [f["context"]["source"] for f in flows] == [SOURCE_REAUTH]


async def test_api_access_denied_is_reported(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    xml_api.access_code = "534"
    await _tick(hass, freezer, 30)
    exc = entry.runtime_data.xml.last_exception
    assert isinstance(exc, UpdateFailed)
    assert exc.translation_key == "api_access_denied"
    assert _state(hass, IFACE) == STATE_UNAVAILABLE


# ── SNMP failures ─────────────────────────────────────────────────────────────


async def test_snmp_outage_shows_unavailable_not_zero(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """Regression (A1): v1.0.x showed 0 % memory and reset the hit counters."""
    entry = make_entry()
    await setup_entry(hass, entry)
    assert _state(hass, HTTP_HITS) == "21355078"

    snmp_agent.drop_all = True
    await _refresh_snmp(hass, entry, "stats", "services")
    assert _state(hass, MEMORY) == STATE_UNAVAILABLE
    assert _state(hass, HTTP_HITS) == STATE_UNAVAILABLE
    assert _state(hass, IFACE) == "on"  # XML unaffected
    assert entry.runtime_data.snmp.data.stats.http_hits == 21355078  # retained, not zeroed

    snmp_agent.drop_all = False
    await _refresh_snmp(hass, entry, "stats")
    assert _state(hass, HTTP_HITS) == "21355078"


async def test_snmp_value_missing_on_agent_is_unknown(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    snmp_agent.remove_prefix(f"{SOPHOS}.2.5.2.0")
    await setup_entry(hass, make_entry())
    assert _state(hass, MEMORY) == "unknown"


async def test_failed_vpn_walk_keeps_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """A failed walk must not remove tunnel entities from the registry."""
    from homeassistant.helpers import entity_registry as er

    entry = make_entry()
    await setup_entry(hass, entry)
    assert _state(hass, VPN) == "on"
    snmp_agent.answer_limit = 0
    await _refresh_snmp(hass, entry, "tunnels")
    assert er.async_get(hass).async_get(VPN) is not None
    assert _state(hass, VPN) == STATE_UNAVAILABLE


# ── Virtual appliance detection ───────────────────────────────────────────────


async def test_virtual_appliance_stops_health_polling(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry()
    await setup_entry(hass, entry)
    snmp = entry.runtime_data.snmp
    for _ in range(2):  # the first two empty answers could be a booting appliance
        assert snmp.is_virtual is None
        assert snmp.endpoint_enabled("health")
        await _refresh_snmp(hass, entry, "health")
    assert snmp.is_virtual is True
    assert not snmp.endpoint_enabled("health")


async def test_booting_hardware_appliance_is_not_marked_virtual(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """Review finding: a hardware appliance that answered once without sensor
    values (still booting) lost its fan/PSU/temperature monitoring until the
    next restart."""
    entry = make_entry()
    await setup_entry(hass, entry)  # the agent reports no hardware sensors yet
    await _refresh_snmp(hass, entry, "health")
    snmp = entry.runtime_data.snmp
    assert snmp.is_virtual is None
    assert snmp.endpoint_enabled("health")

    for oid, value in sophos_mib(hardware=True).items():  # boot finished
        snmp_agent.set(oid, value)
    await _refresh_snmp(hass, entry, "health")
    assert snmp.is_virtual is False
    assert _state(hass, "sensor.5heynexg_sensor_cpu_temperature") == "42.0"


async def test_hardware_appliance_keeps_health_polling(
    hass: HomeAssistant, xml_api: FakeSophosApi, hardware_agent: FakeSnmpAgent
) -> None:
    entry = make_entry()
    await setup_entry(hass, entry)
    assert entry.runtime_data.snmp.is_virtual is False
    assert entry.runtime_data.snmp.endpoint_enabled("health")


async def test_failed_first_health_fetch_does_not_mark_virtual(
    hass: HomeAssistant, xml_api: FakeSophosApi, hardware_agent: FakeSnmpAgent
) -> None:
    """Regression (A1): one timeout at startup disabled health polling for good."""
    hardware_agent.drop_all = True
    entry = make_entry()
    await setup_entry(hass, entry)
    assert entry.runtime_data.snmp.is_virtual is None

    hardware_agent.drop_all = False
    await _refresh_snmp(hass, entry)
    assert entry.runtime_data.snmp.is_virtual is False
    assert _state(hass, "sensor.5heynexg_sensor_cpu_temperature") == "42.0"


async def test_hit_counter_reset_on_agent_is_passed_through(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """A genuine counter reset (firewall reboot) is still reported as such."""
    await setup_entry(hass, make_entry())
    snmp_agent.set(f"{SOPHOS}.2.7.0", Integer(5))
    await _tick(hass, freezer, 30)
    assert _state(hass, HTTP_HITS) == "5"


async def test_outage_recovery_is_not_logged_per_endpoint(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi, caplog
) -> None:
    """A whole-source outage is logged once by HA — not once per endpoint."""
    await setup_entry(hass, make_entry(snmp_enabled=False))
    xml_api.exc = TimeoutError()
    await _tick(hass, freezer, 30)
    xml_api.exc = None
    await _tick(hass, freezer, 30)
    assert "fetching interfaces failed" not in caplog.text
    assert "is available again" not in caplog.text
    assert "Timeout talking to" in caplog.text  # detail in HA's single error line


async def test_realtime_poll_survives_scheduling_jitter(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    """Regression (A2) end-to-end: a run slightly early still fetches realtime data."""
    await setup_entry(hass, make_entry(snmp_enabled=False))
    for _ in range(5):
        await _tick(hass, freezer, 29.99)
    assert xml_api.count("get", "Interface") == 6


async def test_failing_snmp_endpoint_affects_only_its_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry()
    await setup_entry(hass, entry)
    snmp_agent.drop_prefixes = {f"{SOPHOS}.6"}  # VPN table only
    await _refresh_snmp(hass, entry, "tunnels", "stats")
    assert _state(hass, VPN) == STATE_UNAVAILABLE
    assert _state(hass, MEMORY) == "33"
    assert entry.runtime_data.snmp.last_update_success


async def test_first_refresh_without_any_data_retries_setup(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """Every endpoint answering with an API error must not load an empty entry."""
    from homeassistant.config_entries import ConfigEntryState

    xml_api.broken_tags = {"Interface", "FirewallRule", "DHCPServer", "WebFilterPolicy", "AdminSettings"}
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_RETRY
