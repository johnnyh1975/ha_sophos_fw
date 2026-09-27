"""SNMPClient against a real UDP SNMP agent (tests/fake_snmp.py).

Every test drives the real puresnmp stack over a real socket — encoding,
GETBULK walks, timeouts and error mapping are all exercised for real.
"""
from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from homeassistant.core import HomeAssistant

from custom_components.sophos_firewall.models import (
    DeviceInfo,
    HaStatus,
    SystemHealth,
    SystemStats,
    VpnTunnel,
)
from custom_components.sophos_firewall.snmp_client import (
    SNMPClient,
    SophosSNMPError,
    table_column,
    tenths_to_celsius,
    timeticks_to_seconds,
    to_int,
    to_str,
)

from .fake_snmp import (
    FAN_SPEED,
    PSU_STATUS,
    SOPHOS,
    VPN_ENTRY,
    FakeSnmpAgent,
    Gauge,
    Integer,
    OctetString,
)


async def _client(hass: HomeAssistant, community: str = "public") -> SNMPClient:
    client = SNMPClient("127.0.0.1", community=community)
    await client.preload(hass)
    return client


# ── Value helpers ─────────────────────────────────────────────────────────────


def test_value_helpers_keep_missing_as_none() -> None:
    """Missing values must stay None — never become a plausible 0 (v1.0.x bug)."""
    assert to_int(None) is None
    assert to_int("abc") is None
    assert to_int(True) is None
    assert to_int(Integer(7)) == 7
    assert to_int("42 %") == 42
    assert to_str(None) is None
    assert to_str("  ") is None
    assert to_str(b"x") == "x"
    assert timeticks_to_seconds(None) is None
    assert timeticks_to_seconds(timedelta(seconds=90)) == 90
    assert timeticks_to_seconds(12345) == 123
    assert tenths_to_celsius(None) is None
    assert tenths_to_celsius(0) is None
    assert tenths_to_celsius(425) == 42.5


def test_table_column_reads_index_not_column() -> None:
    table = "1.2.3"
    data = {
        "1.2.3.1.2.1": "a",
        ".1.2.3.1.2.2": "b",       # leading dot tolerated
        "1.2.3.1.2": "x",          # no index
        "1.2.3.1.2.4.9": "x",      # two-part index
        "1.2.3.1.3.1": "x",        # other column
        "1.2.3.2.2.1": "x",        # other entry
    }
    assert table_column(data, table, "2") == {"1": "a", "2": "b"}


# ── Setup ─────────────────────────────────────────────────────────────────────


def test_client_requires_preload() -> None:
    with pytest.raises(RuntimeError, match="preload"):
        SNMPClient("127.0.0.1", community="public")._get_client()


async def test_concurrent_preloads_patch_once(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    clients = [SNMPClient("127.0.0.1", community="public") for _ in range(3)]
    await asyncio.gather(*(c.preload(hass) for c in clients))
    from puresnmp.plugins import security

    assert security._sophos_ha_patched is True
    for client in clients:
        assert await client.test_connection() == "5HeyneXG"


# ── Data ──────────────────────────────────────────────────────────────────────


async def test_device_info(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    client = await _client(hass)
    assert await client.get_device_info() == DeviceInfo(
        name="5HeyneXG",
        model="SFVH_KV01_SFOS",
        firmware="SFOS 22.0.0 GA-Build411",
        serial="C01001D2MQT76C4",
        webcat_version="1.0.1.1207",
        ips_version="22.1.26",
    )


async def test_stats(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    client = await _client(hass)
    stats = await client.get_stats()
    assert stats == SystemStats(
        current_date="Sun Sep 27 09:00:00 2026",
        uptime_seconds=6502743,
        disk_capacity_mb=11969, disk_percent=27,
        memory_capacity_mb=72383, memory_percent=33,
        swap_capacity_mb=4095, swap_percent=23,
        live_users=1, http_hits=21355078, ftp_hits=0,
        smtp_hits=19, imap_hits=47, pop3_hits=12,
    )


async def test_unimplemented_oid_is_none_not_zero(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    snmp_agent.remove_prefix(f"{SOPHOS}.2.7.0")  # HTTP hits
    stats = await (await _client(hass)).get_stats()
    assert stats.http_hits is None
    assert stats.memory_percent == 33


async def test_services(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    services = await (await _client(hass)).get_services()
    assert len(services) == 21
    assert services["ips"] == 3
    assert services["antispam"] == 1
    assert services["tomcat"] is None  # not implemented by the agent


async def test_licenses(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    licenses = await (await _client(hass)).get_licenses()
    assert len(licenses) == 9
    assert licenses["base_fw"].status_code == 3
    assert licenses["base_fw"].expiry_date == "Dec 31 2999"
    assert licenses["enh_support"].status_code == 0
    assert licenses["enh_support"].expiry_date is None


async def test_vpn_tunnels_come_from_the_tunnel_table(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    """Regression #18: v1.0.2 walked the IPsec *policy* table."""
    tunnels = await (await _client(hass)).get_vpn_tunnels()
    assert tunnels == {
        "1": VpnTunnel("1", "Azure-VPN", conn_status=1, activated=1, tunnels_configured=1),
        "2": VpnTunnel("2", "Branch-VPN", conn_status=0, activated=1, tunnels_configured=1),
        "3": VpnTunnel("3", "DR-Site", conn_status=2, activated=1, tunnels_configured=3),
    }
    assert "IKEv2-Policy" not in {t.name for t in tunnels.values()}


async def test_vpn_rows_without_name_are_skipped(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    snmp_agent.remove_prefix(f"{VPN_ENTRY}.2.2")
    tunnels = await (await _client(hass)).get_vpn_tunnels()
    assert set(tunnels) == {"1", "3"}


async def test_vpn_walk_uses_getbulk(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    await (await _client(hass)).get_vpn_tunnels()
    assert "getbulk" in snmp_agent.requests
    assert "getnext" not in snmp_agent.requests


async def test_long_tables_are_walked_completely(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    """Tables longer than one GETBULK answer must not be truncated.

    puresnmp 2.0.1 drops rows when several columns are bulk-walked in one
    call; the client walks each column on its own.
    """
    for i in range(4, 80):
        snmp_agent.set(f"{VPN_ENTRY}.2.{i}", OctetString(f"T{i}".encode()))
        snmp_agent.set(f"{VPN_ENTRY}.9.{i}", Integer(1))
    tunnels = await (await _client(hass)).get_vpn_tunnels()
    assert len(tunnels) == 79
    assert all(t.conn_status is not None for t in tunnels.values())


async def test_health_on_virtual_appliance(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    health = await (await _client(hass)).get_system_health()
    assert health == SystemHealth()
    assert not health.has_hardware_sensors


async def test_health_on_hardware_parses_mib_layout(hass: HomeAssistant, hardware_agent: FakeSnmpAgent) -> None:
    """Regression (Befund 2): fan/PSU tables were keyed by column, not row."""
    health = await (await _client(hass)).get_system_health()
    assert health == SystemHealth(
        cpu_temperature_c=42.0,
        npu_temperature_c=65.0,
        fans={"fan_1": 3000, "fan_2": 3150, "fan_3": 2900},
        psus={"psu_1": True, "psu_2": False},
    )


async def test_health_ignores_foreign_columns(hass: HomeAssistant, hardware_agent: FakeSnmpAgent) -> None:
    hardware_agent.set(f"{SOPHOS}.9.3.1.3.1", Gauge(1))       # other column
    hardware_agent.set(f"{FAN_SPEED}.4.9", Gauge(9999))       # two-part index
    hardware_agent.set(f"{PSU_STATUS}.3", Integer(7))         # unknown status → down
    health = await (await _client(hass)).get_system_health()
    assert health.fans == {"fan_1": 3000, "fan_2": 3150, "fan_3": 2900}
    assert health.psus == {"psu_1": True, "psu_2": False, "psu_3": False}


async def test_ha_status(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    assert await (await _client(hass)).get_ha_status() == HaStatus(
        enabled=False, current_state=2, peer_state=0
    )


# ── Failures ──────────────────────────────────────────────────────────────────


async def test_silent_agent_raises_instead_of_zeros(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    """Regression (A1): v1.0.x turned a timeout into 0 % memory, 0 hits, …"""
    client = await _client(hass)
    snmp_agent.drop_all = True
    with pytest.raises(SophosSNMPError):
        await client.get_stats()


async def test_wrong_community_raises(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    client = await _client(hass, community="wrong")
    with pytest.raises(SophosSNMPError):
        await client.test_connection()


async def test_walk_failing_half_way_raises(hass: HomeAssistant, snmp_agent: FakeSnmpAgent) -> None:
    """A partial table would make rows vanish and their entities be deleted."""
    for i in range(4, 60):
        snmp_agent.set(f"{VPN_ENTRY}.2.{i}", Integer(i))
    client = await _client(hass)
    snmp_agent.answer_limit = 1
    with pytest.raises(SophosSNMPError):
        await client.get_vpn_tunnels()


async def test_unexpected_errors_are_not_masked(hass: HomeAssistant, snmp_agent: FakeSnmpAgent, monkeypatch) -> None:
    """Programming errors must surface, not be reported as 'agent unreachable'."""
    client = await _client(hass)

    async def broken(*args, **kwargs):
        raise KeyError("bug")

    monkeypatch.setattr(client._get_client(), "multiget", broken)
    with pytest.raises(KeyError):
        await client.get_stats()


# ── UDP transport (replacement for puresnmp's send_udp) ───────────────────────


async def test_cancelled_request_closes_its_socket(
    hass: HomeAssistant, snmp_agent: FakeSnmpAgent, monkeypatch: pytest.MonkeyPatch
) -> None:
    """puresnmp's own sender leaked the socket when the request was cancelled."""
    from custom_components.sophos_firewall import snmp_client as module

    transports: list[asyncio.DatagramTransport] = []
    original = module._UDPRequest.connection_made

    def track(self, transport):
        transports.append(transport)
        original(self, transport)

    monkeypatch.setattr(module._UDPRequest, "connection_made", track)
    monkeypatch.setattr(module, "SNMP_OPERATION_BUDGET", 0.2)  # cancels mid-attempt
    client = await _client(hass)
    snmp_agent.drop_all = True
    with pytest.raises(SophosSNMPError):
        await client.get_stats()
    assert transports
    assert all(t.is_closing() for t in transports)


async def test_icmp_port_unreachable_fails_fast(
    hass: HomeAssistant, socket_enabled: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A host without SNMP answers with ICMP port-unreachable → immediate error."""
    import socket

    from custom_components.sophos_firewall import snmp_client as module

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    closed_port = sock.getsockname()[1]
    sock.close()
    monkeypatch.setattr(module, "SNMP_TIMEOUT", 5)  # would take 5 s if not fast
    client = SNMPClient("127.0.0.1", community="public", port=closed_port)
    await client.preload(hass)
    loop = asyncio.get_running_loop()
    start = loop.time()
    with pytest.raises(SophosSNMPError):
        await client.get_stats()
    assert loop.time() - start < 1


async def test_lost_packets_are_retried(
    hass: HomeAssistant, snmp_agent: FakeSnmpAgent, monkeypatch: pytest.MonkeyPatch
) -> None:
    from custom_components.sophos_firewall import snmp_client as module

    monkeypatch.setattr(module, "SNMP_RETRIES", 3)
    monkeypatch.setattr(module, "SNMP_OPERATION_BUDGET", 5)
    client = await _client(hass)
    snmp_agent.drop_next = 2  # first two attempts lost, third answered
    assert (await client.get_stats()).memory_percent == 33


async def test_failed_walk_cancels_sibling_walks(
    hass: HomeAssistant, snmp_agent: FakeSnmpAgent
) -> None:
    """One failing column must not leave the other column walks running."""
    for i in range(4, 80):
        snmp_agent.set(f"{VPN_ENTRY}.9.{i}", Integer(1))
    client = await _client(hass)
    snmp_agent.drop_prefixes = {f"{VPN_ENTRY}.2"}  # the name column never answers
    with pytest.raises(SophosSNMPError):
        await client.get_vpn_tunnels()
    pending = [
        t for t in asyncio.all_tasks()
        if getattr(t.get_coro(), "__qualname__", "").endswith("_walk_columns.<locals>._walk")
    ]
    assert not pending


async def test_startup_burst_against_a_serial_agent(
    hass: HomeAssistant, snmp_agent: FakeSnmpAgent, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Field test 1.1 beta: every endpoint at once overloaded the SFOS agent.

    The agent answers one request at a time. Without a concurrency limit the
    tail of the burst waits longer than the per-attempt timeout and fails.
    """
    from custom_components.sophos_firewall import snmp_client as module

    monkeypatch.setattr(module, "SNMP_OPERATION_BUDGET", 10)
    snmp_agent.serial_delay = 0.2

    async def burst() -> list[object]:
        client = await _client(hass)
        return await asyncio.gather(
            client.get_stats(), client.get_services(), client.get_vpn_tunnels(),
            client.get_ha_status(), client.get_system_health(), client.get_licenses(),
            client.get_device_info(), return_exceptions=True,
        )

    monkeypatch.setattr(module, "SNMP_MAX_CONCURRENT", 12)  # first 1.1 beta
    assert any(isinstance(r, SophosSNMPError) for r in await burst())
    await asyncio.sleep(1.5)  # let the agent drain the retransmissions

    monkeypatch.setattr(module, "SNMP_MAX_CONCURRENT", 2)
    results = await burst()
    assert not any(isinstance(r, Exception) for r in results), results


async def test_placeholder_texts_are_missing_values(
    hass: HomeAssistant, snmp_agent: FakeSnmpAgent
) -> None:
    """Field test: SFOS 22.0.2 reports the webcat version as 'Not Available'."""
    snmp_agent.set(f"{SOPHOS}.1.5.0", OctetString(b"Not Available"))
    snmp_agent.set(f"{SOPHOS}.5.8.2.0", OctetString(b"fail"))
    client = await _client(hass)
    assert (await client.get_device_info()).webcat_version is None
    assert (await client.get_licenses())["enh_plus"].expiry_date is None
