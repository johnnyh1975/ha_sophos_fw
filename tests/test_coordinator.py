"""Tests for coordinator.py — tiered polling and data merging."""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import time
from copy import deepcopy
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from custom_components.sophos_firewall.coordinator import SophosCoordinator
from custom_components.sophos_firewall.const import (
    DATA_INTERFACES, DATA_SNMP_STATS, DATA_SNMP_SERVICES,
)
from tests.conftest import _COORDINATOR_DATA


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_coordinator(mock_entry, snmp_enabled=True) -> SophosCoordinator:
    """Build a coordinator with minimal mocked clients."""
    hass = MagicMock()
    hass.loop = MagicMock()

    xml_client = MagicMock()
    xml_client.get_interfaces          = AsyncMock(return_value=[{"Name": "PortA", "InterfaceStatus": "ON"}])
    xml_client.get_zones               = AsyncMock(return_value=[])
    xml_client.get_firewall_rules      = AsyncMock(return_value=[])
    xml_client.get_web_filter_policies = AsyncMock(return_value=[])
    xml_client.get_dhcp_servers        = AsyncMock(return_value=[])
    xml_client.get_backup              = AsyncMock(return_value={})
    xml_client.get_admin_settings      = AsyncMock(return_value={})
    xml_client.close                   = AsyncMock()
    xml_client._session                = None

    snmp_client = None
    if snmp_enabled:
        snmp_client = MagicMock()
        snmp_client.get_device_info  = AsyncMock(return_value=deepcopy(_COORDINATOR_DATA)["snmp_device"])
        snmp_client.get_stats        = AsyncMock(return_value=deepcopy(_COORDINATOR_DATA)["snmp_stats"])
        snmp_client.get_services     = AsyncMock(return_value=deepcopy(_COORDINATOR_DATA)["snmp_services"])
        snmp_client.get_licenses     = AsyncMock(return_value=deepcopy(_COORDINATOR_DATA)["snmp_licenses"])
        snmp_client.get_vpn_tunnels  = AsyncMock(return_value=deepcopy(_COORDINATOR_DATA)["snmp_tunnels"])
        snmp_client.get_system_health= AsyncMock(return_value=deepcopy(_COORDINATOR_DATA)["snmp_health"])
        snmp_client.get_ha_status    = AsyncMock(return_value=deepcopy(_COORDINATOR_DATA)["snmp_ha"])

    mock_entry.data["snmp_enabled"] = snmp_enabled
    return SophosCoordinator(hass, mock_entry, xml_client, snmp_client)


# ── _fetch_xml ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_xml_realtime_returns_interfaces(mock_entry):
    """_fetch_xml with realtime=True fetches interfaces."""
    coord = make_coordinator(mock_entry, snmp_enabled=False)
    data = await coord._fetch_xml(realtime=True, operative=False, static=False, once=False)
    assert DATA_INTERFACES in data
    assert data[DATA_INTERFACES][0]["Name"] == "PortA"


@pytest.mark.asyncio
async def test_fetch_xml_skips_non_due_tiers(mock_entry):
    """_fetch_xml skips tiers that are not due (returns None/empty)."""
    coord = make_coordinator(mock_entry, snmp_enabled=False)
    # No tiers due except once (for zones/admin)
    data = await coord._fetch_xml(realtime=False, operative=False, static=False, once=True)
    # Interfaces not fetched — returns None (no previous data)
    assert data[DATA_INTERFACES] is None or data[DATA_INTERFACES] == []


# ── _fetch_snmp ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_snmp_realtime_returns_stats(mock_entry):
    """_fetch_snmp with realtime=True fetches stats."""
    coord = make_coordinator(mock_entry, snmp_enabled=True)
    data = await coord._fetch_snmp(realtime=True, fast=False, operative=False, static=False, once=False)
    assert DATA_SNMP_STATS in data
    assert data[DATA_SNMP_STATS]["memory_percent"] == 33


@pytest.mark.asyncio
async def test_fetch_snmp_skips_health_on_vm(mock_entry):
    """_fetch_snmp skips health polling when _is_virtual=True."""
    coord = make_coordinator(mock_entry, snmp_enabled=True)
    coord._is_virtual = True
    data = await coord._fetch_snmp(realtime=False, fast=False, operative=True, static=False, once=False)
    # health client method should NOT have been called
    coord._snmp_client.get_system_health.assert_not_called()


# ── VM detection ──────────────────────────────────────────────────────────────

def test_detect_virtual_appliance_sets_flag(mock_entry):
    """_detect_virtual_appliance sets _is_virtual=True when temps are None."""
    coord = make_coordinator(mock_entry, snmp_enabled=True)
    assert coord._is_virtual is None
    snmp_data = {"snmp_health": {"cpu_temperature_c": None, "fans": {}, "psus": {}}}
    coord._detect_virtual_appliance(snmp_data)
    assert coord._is_virtual is True


def test_detect_physical_appliance(mock_entry):
    """_detect_virtual_appliance sets _is_virtual=False when temps are present."""
    coord = make_coordinator(mock_entry, snmp_enabled=True)
    snmp_data = {"snmp_health": {"cpu_temperature_c": 45.0, "fans": {"fan_1": 2000}, "psus": {}}}
    coord._detect_virtual_appliance(snmp_data)
    assert coord._is_virtual is False


def test_detect_virtual_only_runs_once(mock_entry):
    """_detect_virtual_appliance is idempotent after first detection."""
    coord = make_coordinator(mock_entry, snmp_enabled=True)
    coord._is_virtual = True  # already set
    # Even with physical data, should not change
    snmp_data = {"snmp_health": {"cpu_temperature_c": 45.0, "fans": {"fan_1": 2000}, "psus": {}}}
    coord._detect_virtual_appliance(snmp_data)
    assert coord._is_virtual is True  # unchanged


# ── Timing ────────────────────────────────────────────────────────────────────

def test_due_returns_true_when_interval_elapsed(mock_entry):
    """_due() returns True when the interval has elapsed."""
    coord = make_coordinator(mock_entry, snmp_enabled=False)
    old_time = time.monotonic() - 100  # 100s ago
    assert coord._due(old_time, 30) is True


def test_due_returns_false_when_recent(mock_entry):
    """_due() returns False when the interval has not elapsed."""
    coord = make_coordinator(mock_entry, snmp_enabled=False)
    recent = time.monotonic()
    assert coord._due(recent, 30) is False


# ── Error handling ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_snmp_failure_is_non_fatal(mock_entry):
    """SNMP exceptions do not cause UpdateFailed — XML data still returned."""
    coord = make_coordinator(mock_entry, snmp_enabled=True)
    coord._snmp_client.get_stats         = AsyncMock(side_effect=Exception("SNMP timeout"))
    coord._snmp_client.get_services      = AsyncMock(side_effect=Exception("SNMP timeout"))
    coord._snmp_client.get_device_info   = AsyncMock(side_effect=Exception("SNMP timeout"))
    coord._snmp_client.get_licenses      = AsyncMock(side_effect=Exception("SNMP timeout"))
    coord._snmp_client.get_vpn_tunnels   = AsyncMock(side_effect=Exception("SNMP timeout"))
    coord._snmp_client.get_system_health = AsyncMock(side_effect=Exception("SNMP timeout"))
    coord._snmp_client.get_ha_status     = AsyncMock(side_effect=Exception("SNMP timeout"))

    data = await coord._async_update_data()
    assert DATA_INTERFACES in data  # XML data present


@pytest.mark.asyncio
async def test_xml_auth_error_raises(mock_entry):
    """SophosAuthError triggers ConfigEntryAuthFailed."""
    from homeassistant.exceptions import ConfigEntryAuthFailed
    from custom_components.sophos_firewall.sophos_client import SophosAuthError

    coord = make_coordinator(mock_entry, snmp_enabled=False)
    coord.xml_client.get_interfaces = AsyncMock(side_effect=SophosAuthError("bad creds"))

    with pytest.raises(ConfigEntryAuthFailed):
        await coord._async_update_data()


@pytest.mark.asyncio
async def test_xml_api_error_raises_update_failed(mock_entry):
    """SophosAPIError triggers UpdateFailed."""
    from homeassistant.helpers.update_coordinator import UpdateFailed
    from custom_components.sophos_firewall.sophos_client import SophosAPIError

    coord = make_coordinator(mock_entry, snmp_enabled=False)
    coord.xml_client.get_interfaces = AsyncMock(side_effect=SophosAPIError("timeout"))

    with pytest.raises(UpdateFailed):
        await coord._async_update_data()


@pytest.mark.asyncio
async def test_tier_timestamps_reset_after_relogin(mock_entry):
    """After a successful re-login, tiers that did NOT run this cycle are
    reset to 0 so they run unconditionally on the very next cycle.

    The tier that triggered the auth error (realtime, here) is correctly
    left at "now" — it already fetched fresh data on the successful retry,
    so it does not need forcing on the next cycle. Only the *other* tiers,
    which were skipped this cycle, get reset.
    """
    import time as _time
    from custom_components.sophos_firewall.sophos_client import SophosAuthError

    coord = make_coordinator(mock_entry, snmp_enabled=False)

    # realtime must be "due" (timestamp in the past) so _fetch_xml() actually
    # calls get_interfaces() and the simulated SophosAuthError fires.
    coord._last_realtime  = 0.0
    # fast/operative/static are deliberately "just ran" (timestamp == now) —
    # i.e. NOT due this cycle — to prove the reset changes them rather than
    # them coincidentally already being 0 before the update.
    before = _time.monotonic()
    coord._last_fast      = before
    coord._last_operative = before
    coord._last_static    = before
    coord._once_done      = True

    # First call raises auth error; second call (re-login retry) succeeds
    call_count = {"n": 0}
    async def _sometimes_fail():
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise SophosAuthError("session expired")
        return [{"Name": "PortA", "InterfaceStatus": "ON"}]

    coord.xml_client.get_interfaces = _sometimes_fail

    await coord._async_update_data()

    # realtime ran successfully on the retry — correctly stamped with "now",
    # not reset to 0 (it doesn't need forcing, it already has fresh data).
    assert coord._last_realtime  > before
    # fast/operative/static did NOT run this cycle — reset to 0 so they are
    # unconditionally due on the next cycle, regardless of their interval.
    assert coord._last_fast      == 0.0
    assert coord._last_operative == 0.0
    assert coord._last_static    == 0.0
    assert coord._once_done      is False


@pytest.mark.asyncio
async def test_snmp_partial_tier_failure_leaves_other_tiers_intact(mock_entry):
    """A timeout in SNMP realtime does not wipe fast/operative/static data."""
    import asyncio

    coord = make_coordinator(mock_entry, snmp_enabled=True)
    # Realtime fails; other tiers succeed normally
    coord._snmp_client.get_stats    = AsyncMock(side_effect=asyncio.TimeoutError())
    coord._snmp_client.get_services = AsyncMock(side_effect=asyncio.TimeoutError())

    data = await coord._fetch_snmp(
        realtime=True, fast=True, operative=False, static=False, once=True
    )
    # Realtime data absent (or None/empty due to failure)
    assert data.get(DATA_SNMP_STATS) in (None, {})
    # Fast-tier VPN tunnels still fetched successfully
    from custom_components.sophos_firewall.const import DATA_SNMP_TUNNELS
    assert data[DATA_SNMP_TUNNELS] is not None


@pytest.mark.asyncio
async def test_snmp_single_oid_failure_does_not_affect_sibling(mock_entry):
    """Within a tier, one failing OID does not prevent the sibling from being returned."""
    import asyncio
    from custom_components.sophos_firewall.const import DATA_SNMP_SERVICES

    coord = make_coordinator(mock_entry, snmp_enabled=True)
    # stats fails, services succeeds
    coord._snmp_client.get_stats    = AsyncMock(side_effect=asyncio.TimeoutError())
    coord._snmp_client.get_services = AsyncMock(return_value={"dns": 3, "av": 3})

    data = await coord._fetch_snmp(
        realtime=True, fast=False, operative=False, static=False, once=False
    )
    assert data.get(DATA_SNMP_STATS) in (None, {})
    assert data[DATA_SNMP_SERVICES] == {"dns": 3, "av": 3}


# ── Session lifecycle ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_async_close_calls_xml_client(mock_entry):
    """async_close() calls close() on the xml_client."""
    coord = make_coordinator(mock_entry, snmp_enabled=False)
    await coord.async_close()
    coord.xml_client.close.assert_awaited_once()


# ── Hardening: interval clamping prevents busy-loop ───────────────────────────

def test_zero_realtime_interval_is_clamped(mock_entry):
    """A zero realtime interval must be clamped to the default, otherwise
    update_interval=timedelta(0) busy-loops and hammers the firewall."""
    from custom_components.sophos_firewall.const import DEFAULT_INTERVAL_REALTIME
    mock_entry.options = {"interval_realtime": 0}
    coord = make_coordinator(mock_entry, snmp_enabled=False)
    assert coord._iv_realtime == DEFAULT_INTERVAL_REALTIME
    assert coord.update_interval.total_seconds() >= 5


def test_negative_realtime_interval_is_clamped(mock_entry):
    """A negative realtime interval is clamped to the default."""
    from custom_components.sophos_firewall.const import DEFAULT_INTERVAL_REALTIME
    mock_entry.options = {"interval_realtime": -10}
    coord = make_coordinator(mock_entry, snmp_enabled=False)
    assert coord._iv_realtime == DEFAULT_INTERVAL_REALTIME


def test_non_int_realtime_interval_is_clamped(mock_entry):
    """A non-integer realtime interval (corrupt storage) is clamped."""
    from custom_components.sophos_firewall.const import DEFAULT_INTERVAL_REALTIME
    mock_entry.options = {"interval_realtime": "not a number"}
    coord = make_coordinator(mock_entry, snmp_enabled=False)
    assert coord._iv_realtime == DEFAULT_INTERVAL_REALTIME


def test_valid_realtime_interval_is_preserved(mock_entry):
    """A valid realtime interval is used unchanged."""
    mock_entry.options = {"interval_realtime": 45}
    coord = make_coordinator(mock_entry, snmp_enabled=False)
    assert coord._iv_realtime == 45
