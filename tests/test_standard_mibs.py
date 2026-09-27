"""CPU load (HOST-RESOURCES-MIB) and interface traffic (IF-MIB)."""
from __future__ import annotations

from datetime import timedelta

import pytest
from freezegun.api import FrozenDateTimeFactory
from homeassistant.const import STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import async_fire_time_changed

from custom_components.sophos_firewall.const import INTERNAL_INTERFACE_RE
from custom_components.sophos_firewall.coordinator import traffic_rates
from custom_components.sophos_firewall.models import InterfaceCounters, TrafficSample

from .conftest import make_entry, setup_entry
from .fake_snmp import (
    HR_PROCESSOR_LOAD,
    IFX_ENTRY,
    Counter64,
    FakeSnmpAgent,
    OctetString,
    sophos_mib,
)
from .fake_sophos import FakeSophosApi

P = "5heynexg"
PORTA_RX = f"sensor.{P}_traffic_rx_rate_porta"
PORTA_TX = f"sensor.{P}_traffic_tx_rate_porta"


def _state(hass: HomeAssistant, entity_id: str) -> str:
    state = hass.states.get(entity_id)
    assert state is not None, entity_id
    return state.state


async def _tick(hass: HomeAssistant, freezer: FrozenDateTimeFactory, seconds: float) -> None:
    freezer.tick(timedelta(seconds=seconds))
    async_fire_time_changed(hass)
    await hass.async_block_till_done(wait_background_tasks=True)


# ── Rate computation ──────────────────────────────────────────────────────────


def _sample(at: float, **counters: tuple[int | None, int | None]) -> TrafficSample:
    return TrafficSample(
        sampled_at=at,
        counters={name: InterfaceCounters(*values) for name, values in counters.items()},
    )


def test_rate_uses_the_measured_time_between_samples() -> None:
    first = _sample(100.0, PortA=(1_000, 5_000))
    second = _sample(145.0, PortA=(1_000 + 562_500_000, 5_000 + 5_625))
    traffic = traffic_rates(first, second)["PortA"]
    assert traffic.in_bps == 100_000_000.0  # 562.5 MB in 45 s = 100 Mbit/s
    assert traffic.out_bps == 1_000.0
    assert (traffic.in_octets, traffic.out_octets) == (562_501_000, 10_625)


def test_no_rate_without_a_previous_sample() -> None:
    traffic = traffic_rates(None, _sample(10.0, PortA=(1, 2)))["PortA"]
    assert (traffic.in_bps, traffic.out_bps) == (None, None)
    assert (traffic.in_octets, traffic.out_octets) == (1, 2)


@pytest.mark.parametrize(
    ("previous", "current", "seconds"),
    [
        ((5_000, 5_000), (10, 10), 30.0),       # counter reset (reboot)
        ((None, None), (10, 10), 30.0),         # counter missing before
        ((10, 10), (None, None), 30.0),         # counter missing now
        ((10, 10), (20, 20), 0.5),              # samples too close together
    ],
)
def test_no_rate_when_not_computable(
    previous: tuple[int | None, int | None], current: tuple[int | None, int | None],
    seconds: float,
) -> None:
    traffic = traffic_rates(_sample(0.0, PortA=previous), _sample(seconds, PortA=current))
    assert (traffic["PortA"].in_bps, traffic["PortA"].out_bps) == (None, None)


def test_new_interface_gets_a_rate_from_its_second_sample() -> None:
    traffic = traffic_rates(_sample(0.0, PortA=(0, 0)), _sample(30.0, PortA=(0, 0), PortC=(5, 5)))
    assert traffic["PortC"].in_bps is None
    assert traffic["PortA"].in_bps == 0.0


# ── Traffic entities ──────────────────────────────────────────────────────────


async def test_traffic_rate_from_the_real_agent(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi,
    snmp_agent: FakeSnmpAgent,
) -> None:
    """Rates in Mbit/s (suggested unit) from two walks 45 s apart — not the
    nominal 30 s interval."""
    await setup_entry(hass, make_entry())
    assert _state(hass, PORTA_RX) == STATE_UNKNOWN  # one sample only
    state = hass.states.get(PORTA_RX)
    assert state.attributes["unit_of_measurement"] == "Mbit/s"
    assert state.attributes["device_class"] == "data_rate"

    # PortA is row 6: 6e9 received, 6e8 sent
    snmp_agent.set(f"{IFX_ENTRY}.6.6", Counter64(6_000_000_000 + 562_500_000))
    snmp_agent.set(f"{IFX_ENTRY}.10.6", Counter64(600_000_000 + 56_250_000))
    await _tick(hass, freezer, 45)
    assert float(_state(hass, PORTA_RX)) == pytest.approx(100.0)
    assert float(_state(hass, PORTA_TX)) == pytest.approx(10.0)


async def test_internal_interfaces_get_no_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """The real interface list of an SFVH: ports and VLANs/wireless get
    entities, the 11 kernel/SFOS helper devices none."""
    entry = make_entry()
    await setup_entry(hass, entry)
    registry = er.async_get(hass)
    rates = {
        e.entity_id.removeprefix(f"sensor.{P}_traffic_rx_rate_"): e.disabled_by
        for e in er.async_entries_for_config_entry(registry, entry.entry_id)
        if "_traffic_rx_rate_" in e.entity_id
    }
    disabled = er.RegistryEntryDisabler.INTEGRATION
    assert rates == {
        "porta": None, "portb": None,  # listed by the XML API
        "porta_30": disabled, "porta_40": disabled, "porta_50": disabled, "guestap": disabled,
    }
    assert set(entry.runtime_data.snmp.data.traffic) == {
        "PortA", "PortB", "PortA.30", "PortA.40", "PortA.50", "GuestAP",
    }


async def test_traffic_entities_wait_for_the_xml_interface_list(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi,
    snmp_agent: FakeSnmpAgent,
) -> None:
    """Enabled-by-default is decided once, at creation: created before the
    XML API listed PortA, its sensors would stay disabled for good."""
    xml_api.broken_tags.add("Interface")
    entry = make_entry()
    await setup_entry(hass, entry)
    registry = er.async_get(hass)
    assert registry.async_get(PORTA_RX) is None

    xml_api.broken_tags.clear()
    await _tick(hass, freezer, 30)  # XML interfaces, then SNMP traffic again
    await _tick(hass, freezer, 30)
    porta = registry.async_get(PORTA_RX)
    assert porta is not None and porta.disabled_by is None


async def test_without_xml_interface_polling_all_traffic_entities_are_disabled(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry(options={"poll_xml_interfaces": False})
    await setup_entry(hass, entry)
    porta = er.async_get(hass).async_get(PORTA_RX)
    assert porta is not None
    assert porta.disabled_by is er.RegistryEntryDisabler.INTEGRATION


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_byte_counters(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry())
    state = hass.states.get(f"sensor.{P}_traffic_rx_bytes_porta")
    assert state is not None
    assert state.attributes["unit_of_measurement"] == "GB"
    assert state.attributes["state_class"] == "total_increasing"
    assert float(state.state) == pytest.approx(6.0)  # 6e9 bytes


async def test_traffic_option_off_creates_and_polls_nothing(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry(options={"poll_snmp_traffic": False})
    await setup_entry(hass, entry)
    ids = [e.entity_id for e in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)]
    assert not [i for i in ids if "_traffic_" in i]
    assert entry.runtime_data.snmp.data.traffic is None  # never walked


async def test_agent_without_ifxtable_creates_no_traffic_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    snmp_agent.remove_prefix(IFX_ENTRY)
    entry = make_entry()
    await setup_entry(hass, entry)
    ids = [e.entity_id for e in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)]
    assert not [i for i in ids if "_traffic_" in i]
    assert entry.runtime_data.snmp.endpoint_available("traffic")  # empty, not failed


# ── CPU ───────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_cpu_usage_and_cores(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    await setup_entry(hass, make_entry())
    assert _state(hass, f"sensor.{P}_sensor_cpu_usage") == "21.0"  # (22+21+23+18) / 4
    loads = [_state(hass, f"sensor.{P}_sensor_cpu_core_{core}") for core in range(1, 5)]
    assert loads == ["22", "21", "23", "18"]
    attrs = hass.states.get(f"sensor.{P}_sensor_cpu_core_4").attributes
    assert attrs["friendly_name"] == "5HeyneXG CPU core 4"
    assert attrs["unit_of_measurement"] == "%"


async def test_agent_without_processor_table_creates_no_cpu_entities(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    snmp_agent.remove_prefix(HR_PROCESSOR_LOAD)
    entry = make_entry()
    await setup_entry(hass, entry)
    ids = [e.entity_id for e in er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)]
    assert not [i for i in ids if "_cpu_core_" in i or i.endswith("_cpu_usage")]
    assert hass.states.get(f"sensor.{P}_sensor_cpu_temperature") is None  # VM anyway


# ── Review findings (Phase 4) ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    ["lo", "dummy0", "dummy1", "ipsec0", "sit0", "ip6tnl0", "gre0", "gretap0", "erspan0",
     "ifb0", "ifb1", "dfq", "spq", "tunl0", "ip_vti0", "ip6_vti0", "ip6gre0", "teql0"],
)
def test_internal_interface_names(name: str) -> None:
    assert INTERNAL_INTERFACE_RE.match(name)


@pytest.mark.parametrize(
    "name",
    ["PortA", "PortA.30", "GuestAP", "xfrm1", "br0", "tun0", "lounge", "dfq_lan", "Port1",
     "ipsec", "loop0"],
)
def test_real_interface_names_are_kept(name: str) -> None:
    assert not INTERNAL_INTERFACE_RE.match(name)


async def test_renamed_port_is_matched_by_its_hardware_name(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """The XML Name is user-defined ("WAN"); SNMP ifName is the device name."""
    xml_api.records["Interface"][1]["Name"] = "WAN"  # Hardware stays "PortB"
    await setup_entry(hass, make_entry())
    portb = er.async_get(hass).async_get(f"sensor.{P}_traffic_rx_rate_portb")
    assert portb is not None and portb.disabled_by is None


async def _refresh_traffic(hass: HomeAssistant, entry) -> None:
    """Explicit refresh: SNMP timeouts run on the loop clock (see test_coordinator)."""
    snmp = entry.runtime_data.snmp
    snmp.invalidate("traffic")
    await snmp.async_refresh()
    await hass.async_block_till_done()


async def test_briefly_missing_interface_keeps_its_customised_entity(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """A VLAN missing from the agent for a walk or two (firewall booting) must
    not lose its registry entry — HA 2025.5 would re-create it disabled and
    without the user's name."""
    entry = make_entry()
    await setup_entry(hass, entry)
    registry = er.async_get(hass)
    vlan = f"sensor.{P}_traffic_rx_rate_porta_30"
    registry.async_update_entity(vlan, disabled_by=None, name="IoT VLAN in")
    mib = sophos_mib()
    row = {oid: mib[oid] for oid in (f"{IFX_ENTRY}.{col}.18" for col in (1, 6, 10))}  # PortA.30

    for oid in row:
        snmp_agent.remove_prefix(oid)
    for _ in range(2):
        await _refresh_traffic(hass, entry)
    kept = registry.async_get(vlan)
    assert kept is not None and kept.name == "IoT VLAN in" and kept.disabled_by is None

    for oid, value in row.items():  # back again: the count starts over
        snmp_agent.set(oid, value)
    await _refresh_traffic(hass, entry)
    for oid in row:
        snmp_agent.remove_prefix(oid)
    for _ in range(2):
        await _refresh_traffic(hass, entry)
    assert registry.async_get(vlan) is not None

    await _refresh_traffic(hass, entry)  # third consecutive walk without it
    assert registry.async_get(vlan) is None


async def test_duplicate_ifname_uses_the_lowest_index(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    snmp_agent.set(f"{IFX_ENTRY}.1.40", OctetString(b"PortA"))
    snmp_agent.set(f"{IFX_ENTRY}.6.40", Counter64(1))
    snmp_agent.set(f"{IFX_ENTRY}.10.40", Counter64(1))
    entry = make_entry()
    await setup_entry(hass, entry)
    assert entry.runtime_data.snmp.data.traffic["PortA"].in_octets == 6_000_000_000


@pytest.mark.usefixtures("entity_registry_enabled_by_default")
async def test_cpu_average_skips_unreadable_cores(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    snmp_agent.set(f"{HR_PROCESSOR_LOAD}.196611", OctetString(b"n/a"))
    await setup_entry(hass, make_entry())
    assert _state(hass, f"sensor.{P}_sensor_cpu_usage") == "22.0"  # (22+21+23) / 3
    assert _state(hass, f"sensor.{P}_sensor_cpu_core_4") == STATE_UNKNOWN


async def test_rate_after_a_failed_walk_spans_the_whole_gap(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """A failed walk keeps the previous sample: the next rate is the average
    over the whole interval, not over the nominal 30 s."""
    entry = make_entry()
    await setup_entry(hass, entry)
    snmp = entry.runtime_data.snmp
    before = snmp._traffic_sample  # noqa: SLF001 — the stored time base
    assert before is not None

    snmp_agent.drop_prefixes = {"1.3.6.1.2.1.31"}
    snmp.invalidate("stats")  # same cycle: stats succeed, only traffic fails
    await _refresh_traffic(hass, entry)
    assert not snmp.endpoint_available("traffic")
    assert snmp.endpoint_available("stats") and snmp.last_update_success
    assert snmp._traffic_sample is before  # noqa: SLF001

    snmp_agent.drop_prefixes = set()
    snmp_agent.set(f"{IFX_ENTRY}.6.6", Counter64(6_000_000_000 + 1_000_000))
    await _refresh_traffic(hass, entry)
    after = snmp._traffic_sample  # noqa: SLF001
    assert after is not None and after is not before
    expected = 1_000_000 * 8 / (after.sampled_at - before.sampled_at)
    assert snmp.data.traffic["PortA"].in_bps == pytest.approx(expected, abs=0.1)
