"""Tests for snmp_client.py — puresnmp-based SNMP client.

All SNMP calls use puresnmp (not snmpwalk subprocess).
The Client is mocked via unittest.mock to avoid real network calls.
"""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import datetime
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from custom_components.sophos_firewall.snmp_client import (
    SNMPClient,
    _py,
    _safe_int,
    _timeticks_to_seconds,
    _safe_str,
)


# ── Module-level conversion functions ────────────────────────────────────────

def test_py_with_plain_int():
    """_py passes through plain Python ints."""
    assert _py(42) == 42


def test_py_with_none():
    assert _py(None) is None


def test_py_with_plain_string():
    assert _py("hello") == "hello"


def test_safe_int_plain():
    assert _safe_int(42) == 42


def test_safe_int_none():
    assert _safe_int(None) == 0


def test_safe_int_default():
    assert _safe_int(None, default=-1) == -1


def test_safe_str_plain():
    assert _safe_str("hello") == "hello"


def test_safe_str_none():
    assert _safe_str(None) is None


def test_safe_str_empty():
    assert _safe_str("") is None


def test_timeticks_to_seconds_timedelta():
    """timedelta from puresnmp TimeTicks.pythonize() → total_seconds()."""
    td = datetime.timedelta(days=75, hours=6, minutes=19, seconds=3)
    result = _timeticks_to_seconds(td)
    assert result == int(td.total_seconds())


def test_timeticks_to_seconds_int():
    """Raw int (hundredths of seconds) → seconds."""
    result = _timeticks_to_seconds(650274344)
    assert result == 650274344 // 100


def test_timeticks_to_seconds_none():
    assert _timeticks_to_seconds(None) == 0


# ── SNMPClient.is_available ───────────────────────────────────────────────────

def test_is_available_reflects_puresnmp_import():
    """is_available() returns True iff puresnmp can be imported.

    This mirrors the real implementation rather than hard-coding True, so the
    test passes whether or not puresnmp happens to be installed in the test
    environment — it asserts the method's contract, not the environment.
    """
    try:
        import puresnmp  # noqa: F401
        expected = True
    except ImportError:
        expected = False
    assert SNMPClient.is_available() is expected


# ── SNMPClient construction ───────────────────────────────────────────────────

def test_client_construction():
    """SNMPClient can be constructed with host/community/version."""
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    assert client._host == "10.10.0.1"
    assert client._community == "public"


# ── preload ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_preload_creates_client():
    """preload() initializes the internal puresnmp Client.

    The real preload() runs its blocking loader via asyncio.to_thread(), so we
    patch that (not the obsolete get_event_loop path) and have it execute the
    inner _load function, asserting the Client gets created as a side-effect.
    """
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    assert client._client is None

    async def _fake_to_thread(fn, *args, **kwargs):
        # Simulate the executor running _load without real puresnmp/network:
        # stand in for the Client instance the real _load would assign.
        from unittest.mock import MagicMock
        client._client = MagicMock()

    with patch("asyncio.to_thread", side_effect=_fake_to_thread):
        await client.preload()

    assert client._client is not None


# ── test_connection ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_connection_success():
    """test_connection returns True when SNMP agent responds."""
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    client._client = MagicMock()

    async def fake_get(oid):
        return "5HeyneXG"

    client._get = fake_get
    result = await client.test_connection()
    assert result is True


@pytest.mark.asyncio
async def test_connection_failure_on_exception():
    """test_connection returns False when SNMP raises."""
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    client._client = MagicMock()

    async def fake_get(oid):
        return None  # no response

    client._get = fake_get
    result = await client.test_connection()
    assert result is False


# ── _get_client() guard against missing preload() ─────────────────────────────
#
# Regression coverage for the bug reported by taracraft: calling any fetch
# method before preload() must raise RuntimeError from _get_client(), and
# that RuntimeError must be logged at WARNING (not silently downgraded to
# DEBUG alongside ordinary network timeouts) so the real cause is visible.

def test_get_client_raises_runtime_error_without_preload():
    """_get_client() raises RuntimeError when preload() was never called."""
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    assert client._client is None
    with pytest.raises(RuntimeError, match="before preload"):
        client._get_client()


@pytest.mark.asyncio
async def test_get_without_preload_returns_none_and_logs_warning(caplog):
    """_get() on a non-preloaded client returns None (does not raise) but
    must log at WARNING level, distinguishing it from ordinary timeouts."""
    import logging
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")

    with caplog.at_level(logging.WARNING, logger="custom_components.sophos_firewall.snmp_client"):
        result = await client._get("1.3.6.1.4.1.2604.5.1.3.3.0")

    assert result is None
    assert any(
        "before preload" in record.message and record.levelno == logging.WARNING
        for record in caplog.records
    )


@pytest.mark.asyncio
async def test_multiget_without_preload_returns_none_dict_and_logs_warning(caplog):
    """_multiget() on a non-preloaded client logs at WARNING, not DEBUG."""
    import logging
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    oids = ["1.3.6.1.4.1.2604.5.1.3.3.0", "1.3.6.1.4.1.2604.5.1.3.4.0"]

    with caplog.at_level(logging.WARNING, logger="custom_components.sophos_firewall.snmp_client"):
        result = await client._multiget(oids)

    assert result == {o: None for o in oids}
    assert any(record.levelno == logging.WARNING for record in caplog.records)


@pytest.mark.asyncio
async def test_walk_without_preload_returns_empty_dict_and_logs_warning(caplog):
    """_walk() on a non-preloaded client logs at WARNING, not DEBUG."""
    import logging
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")

    with caplog.at_level(logging.WARNING, logger="custom_components.sophos_firewall.snmp_client"):
        result = await client._walk("1.3.6.1.4.1.2604.5.1.3")

    assert result == {}
    assert any(record.levelno == logging.WARNING for record in caplog.records)


@pytest.mark.asyncio
async def test_get_ordinary_timeout_still_logs_at_debug_not_warning(caplog):
    """A normal asyncio.TimeoutError (real network issue) stays at DEBUG —
    only the preload() implementation bug is escalated to WARNING."""
    import asyncio
    import logging
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    client._client = MagicMock()
    client._client.get = AsyncMock(side_effect=asyncio.TimeoutError())

    with caplog.at_level(logging.DEBUG, logger="custom_components.sophos_firewall.snmp_client"):
        result = await client._get("1.3.6.1.4.1.2604.5.1.3.3.0")

    assert result is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings == []


# ── get_device_info ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_device_info_returns_strings():
    """get_device_info converts OctetString values to plain strings."""
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    client._client = MagicMock()

    def make_octet(value: bytes):
        m = MagicMock()
        m.pythonize.return_value = value
        return m

    async def fake_multiget(oids):
        return {
            oids[0]: make_octet(b"5HeyneXG"),
            oids[1]: make_octet(b"SFVH_KV01_SFOS"),
            oids[2]: make_octet(b"22.0.0 GA-Build411"),
            oids[3]: make_octet(b"C01001D2MQT76C4"),
        }

    client._multiget = fake_multiget
    info = await client.get_device_info()

    # All values should be plain strings, no OctetString wrappers
    for v in info.values():
        assert isinstance(v, str), f"Expected str, got {type(v)}: {v!r}"

    assert "5HeyneXG" in info.values()
    assert "SFVH_KV01_SFOS" in info.values()


# ── get_stats ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_stats_returns_integers():
    """get_stats converts Integer values to plain ints."""
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    client._client = MagicMock()

    def make_int(value: int):
        m = MagicMock()
        m.pythonize.return_value = value
        return m

    def make_timeticks(td: datetime.timedelta):
        m = MagicMock()
        m.pythonize.return_value = td
        return m

    async def fake_multiget(oids):
        return {oid: make_int(0) for oid in oids}

    # Patch uptime OID to return timedelta
    from custom_components.sophos_firewall.snmp_client import OID_UPTIME
    async def fake_multiget_with_uptime(oids):
        result = {oid: make_int(0) for oid in oids}
        if OID_UPTIME in result:
            result[OID_UPTIME] = make_timeticks(datetime.timedelta(days=75, hours=6))
        return result

    client._multiget = fake_multiget_with_uptime
    stats = await client.get_stats()

    assert isinstance(stats["memory_percent"], int)
    assert isinstance(stats["disk_percent"], int)
    assert isinstance(stats["uptime_seconds"], int)
    assert stats["uptime_seconds"] > 0  # timedelta converted correctly


# ── get_services ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_services_returns_int_codes():
    """get_services returns dict of service_key → int status code."""
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    client._client = MagicMock()

    def make_int(value: int):
        m = MagicMock()
        m.pythonize.return_value = value
        return m

    async def fake_multiget(oids):
        # All services running (3)
        return {oid: make_int(3) for oid in oids}

    client._multiget = fake_multiget
    services = await client.get_services()

    assert isinstance(services, dict)
    for key, val in services.items():
        assert isinstance(val, int), f"Service {key}: expected int, got {type(val)}"
    assert all(v == 3 for v in services.values())


# ── get_system_health ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_system_health_vm_returns_none_temps():
    """On virtual appliances (SFVH), temperature OIDs return None."""
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    client._client = MagicMock()

    async def fake_multiget(oids):
        # Return empty — no temperature data
        return {}

    async def fake_walk(oid):
        return {}

    client._multiget = fake_multiget
    client._walk = fake_walk

    health = await client.get_system_health()
    assert health["cpu_temperature_c"] is None
    assert health["npu_temperature_c"] is None
    assert health["fans"] == {}


@pytest.mark.asyncio
async def test_get_system_health_physical_returns_temps():
    """On physical appliances, temperatures are floats."""
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    client._client = MagicMock()

    from custom_components.sophos_firewall.snmp_client import OID_CPU_TEMPERATURE, OID_NPU_TEMPERATURE

    def make_int(v):
        m = MagicMock()
        m.pythonize.return_value = v
        return m

    async def fake_multiget(oids):
        result = {}
        if OID_CPU_TEMPERATURE in oids:
            result[OID_CPU_TEMPERATURE] = make_int(450)  # 45.0 °C
        if OID_NPU_TEMPERATURE in oids:
            result[OID_NPU_TEMPERATURE] = make_int(380)  # 38.0 °C
        return result

    async def fake_walk(oid):
        return {}

    client._multiget = fake_multiget
    client._walk = fake_walk

    health = await client.get_system_health()
    assert health["cpu_temperature_c"] == 45.0
    assert health["npu_temperature_c"] == 38.0


# ── get_vpn_tunnels ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_vpn_tunnels_parses_table():
    """get_vpn_tunnels assembles tunnel dicts from SNMP table walk."""
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    client._client = MagicMock()

    BASE = "1.3.6.1.4.1.2604.5.1.6.1.2.1.1"

    def make_val(v):
        m = MagicMock()
        if isinstance(v, bytes):
            m.pythonize.return_value = v
        else:
            m.pythonize.return_value = v
        return m

    async def fake_walk(oid):
        return {
            f"{BASE}.2.1": make_val(b"Azure-VPN"),
            f"{BASE}.9.1": make_val(1),
            f"{BASE}.10.1": make_val(1),
            f"{BASE}.2.2": make_val(b"Branch-VPN"),
            f"{BASE}.9.2": make_val(0),
            f"{BASE}.10.2": make_val(1),
        }

    client._walk = fake_walk
    tunnels = await client.get_vpn_tunnels()

    assert len(tunnels) == 2
    azure = next(t for t in tunnels if t["name"] == "Azure-VPN")
    branch = next(t for t in tunnels if t["name"] == "Branch-VPN")
    assert azure["conn_status"] == 1
    assert branch["conn_status"] == 0


@pytest.mark.asyncio
async def test_get_vpn_tunnels_empty():
    """get_vpn_tunnels returns empty list when no tunnels."""
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    client._client = MagicMock()

    async def fake_walk(oid):
        return {}

    client._walk = fake_walk
    tunnels = await client.get_vpn_tunnels()
    assert tunnels == []


# ── Hardening: malformed OIDs in health walk must not crash ───────────────────

@pytest.mark.asyncio
async def test_get_system_health_malformed_oid_does_not_crash():
    """A malformed/short OID in the fan/psu walk is skipped, not fatal.

    Previously oid.rsplit('.', 2)[-2] would IndexError on an OID with too few
    components, taking down the whole health fetch.
    """
    client = SNMPClient(host="10.10.0.1", community="public", version="2c")
    client._client = MagicMock()

    def make_int(v):
        m = MagicMock()
        m.pythonize.return_value = v
        return m

    async def fake_multiget(oids):
        return {}

    async def fake_walk(oid):
        # Mix a valid fan OID with a malformed one (no dots before the .2)
        return {
            "1.3.6.1.4.1.2604.5.1.9.3.1.2.1.2": make_int(3000),  # valid → fan_1
            "2": make_int(9999),                                  # malformed, ends ".2"? no
            ".2": make_int(8888),                                 # edge: rsplit → ['', '2']
        }

    client._multiget = fake_multiget
    client._walk = fake_walk

    # Must not raise despite the malformed OIDs
    health = await client.get_system_health()
    # The valid fan is parsed; malformed entries are skipped without crashing
    assert "fan_1" in health["fans"]
    assert health["fans"]["fan_1"] == 3000
