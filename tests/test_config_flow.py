"""Tests for config_flow.py — all steps, error paths, reauth, reconfigure.

Mocking strategy
----------------
SophosClient and SNMPClient are patched at the module level so no real
network calls are made.  The _test_xml_connection / _test_snmp_connection
static helpers are also patchable individually for fine-grained control.
"""
from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from custom_components.sophos_firewall.config_flow import SophosFirewallConfigFlow
from custom_components.sophos_firewall.const import (
    CONF_SNMP_ENABLED,
    CONF_SNMP_COMMUNITY,
    CONF_SNMP_VERSION,
    CONF_VERIFY_SSL,
    CONF_WRITE_ACCESS,
    DEFAULT_PORT,
    DEFAULT_SNMP_COMMUNITY,
    DEFAULT_SNMP_VERSION,
    DOMAIN,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

VALID_CONNECTION = {
    "host":       "10.0.0.1",
    "port":       DEFAULT_PORT,
    "username":   "admin",
    "password":   "secret",
    "verify_ssl": False,
}

VALID_SNMP_DISABLED = {
    CONF_SNMP_ENABLED:    False,
    CONF_SNMP_COMMUNITY:  DEFAULT_SNMP_COMMUNITY,
    CONF_SNMP_VERSION:    DEFAULT_SNMP_VERSION,
}

VALID_WRITE_ACCESS_OFF = {CONF_WRITE_ACCESS: False}

VALID_POLLING_INPUT = {
    "realtime": {
        "interval_realtime":   30,
        "poll_xml_interfaces": True,
    },
    "fast": {
        "interval_fast": 120,
    },
    "operative": {
        "interval_operative": 600,
        "poll_xml_fw_rules":  True,
    },
    "static": {
        "interval_static":   1800,
        "poll_xml_dhcp":     True,
        "poll_xml_webfilter": True,
        "poll_xml_backup":   True,
    },
}


def _make_flow(hass=None) -> SophosFirewallConfigFlow:
    """Return a bare flow instance with a minimal hass mock."""
    flow = SophosFirewallConfigFlow()
    flow.hass = hass or MagicMock()
    flow.hass.config_entries = MagicMock()
    flow.hass.config_entries.async_entries = MagicMock(return_value=[])
    flow.context = {"source": "user"}
    flow._data = {}
    return flow


# ── Step: user ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_step_user_shows_form_initially():
    """Without user_input the flow shows the connection form."""
    flow = _make_flow()
    with patch.object(flow, "async_set_unique_id", new=AsyncMock()):
        with patch.object(flow, "_abort_if_unique_id_configured"):
            result = await flow.async_step_user(None)
    assert result["type"] == "form"
    assert result["step_id"] == "user"


@pytest.mark.asyncio
async def test_step_user_valid_credentials_proceeds_to_snmp():
    """Valid credentials advance to the SNMP step."""
    flow = _make_flow()
    with patch.object(SophosFirewallConfigFlow, "_test_xml_connection",
                      new=AsyncMock(return_value={})):
        with patch.object(flow, "async_set_unique_id", new=AsyncMock()):
            with patch.object(flow, "_abort_if_unique_id_configured"):
                result = await flow.async_step_user(VALID_CONNECTION)
    assert result["type"] == "form"
    assert result["step_id"] == "snmp"


@pytest.mark.asyncio
async def test_step_user_invalid_auth_shows_error():
    """Bad credentials show invalid_auth error on the same form."""
    flow = _make_flow()
    with patch.object(SophosFirewallConfigFlow, "_test_xml_connection",
                      new=AsyncMock(return_value={"base": "invalid_auth"})):
        with patch.object(flow, "async_set_unique_id", new=AsyncMock()):
            with patch.object(flow, "_abort_if_unique_id_configured"):
                result = await flow.async_step_user(VALID_CONNECTION)
    assert result["type"] == "form"
    assert result["errors"] == {"base": "invalid_auth"}


@pytest.mark.asyncio
async def test_step_user_cannot_connect_shows_error():
    """Unreachable host shows cannot_connect error."""
    flow = _make_flow()
    with patch.object(SophosFirewallConfigFlow, "_test_xml_connection",
                      new=AsyncMock(return_value={"base": "cannot_connect"})):
        with patch.object(flow, "async_set_unique_id", new=AsyncMock()):
            with patch.object(flow, "_abort_if_unique_id_configured"):
                result = await flow.async_step_user(VALID_CONNECTION)
    assert result["errors"]["base"] == "cannot_connect"


# ── Step: snmp ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_step_snmp_disabled_skips_test():
    """SNMP disabled — no connection test, advances to write_access."""
    flow = _make_flow()
    flow._data = dict(VALID_CONNECTION)
    result = await flow.async_step_snmp(VALID_SNMP_DISABLED)
    assert result["type"] == "form"
    assert result["step_id"] == "write_access"


@pytest.mark.asyncio
async def test_step_snmp_enabled_ok_advances():
    """SNMP enabled and reachable — advances to write_access."""
    flow = _make_flow()
    flow._data = dict(VALID_CONNECTION)
    snmp_input = {
        CONF_SNMP_ENABLED:   True,
        CONF_SNMP_COMMUNITY: "public",
        CONF_SNMP_VERSION:   "2c",
    }
    with patch.object(SophosFirewallConfigFlow, "_test_snmp_connection",
                      new=AsyncMock(return_value={})):
        result = await flow.async_step_snmp(snmp_input)
    assert result["step_id"] == "write_access"


@pytest.mark.asyncio
async def test_step_snmp_enabled_unreachable_shows_error():
    """SNMP enabled but unreachable — error on snmp form."""
    flow = _make_flow()
    flow._data = dict(VALID_CONNECTION)
    snmp_input = {
        CONF_SNMP_ENABLED:   True,
        CONF_SNMP_COMMUNITY: "wrong",
        CONF_SNMP_VERSION:   "2c",
    }
    with patch.object(SophosFirewallConfigFlow, "_test_snmp_connection",
                      new=AsyncMock(return_value={"base": "snmp_cannot_connect"})):
        result = await flow.async_step_snmp(snmp_input)
    assert result["type"] == "form"
    assert result["errors"]["base"] == "snmp_cannot_connect"


# ── Step: write_access ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_step_write_access_advances_to_polling():
    """write_access step advances to polling step."""
    flow = _make_flow()
    flow._data = {**VALID_CONNECTION, **VALID_SNMP_DISABLED}
    result = await flow.async_step_write_access(VALID_WRITE_ACCESS_OFF)
    assert result["type"] == "form"
    assert result["step_id"] == "polling"


# ── Step: polling ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_step_polling_creates_entry():
    """polling step with valid input creates the config entry."""
    flow = _make_flow()
    flow._data = {
        **VALID_CONNECTION,
        **VALID_SNMP_DISABLED,
        **VALID_WRITE_ACCESS_OFF,
    }
    with patch.object(flow, "async_create_entry",
                      return_value={"type": "create_entry", "title": "10.0.0.1", "data": {}}) as mock_create:
        result = await flow.async_step_polling(VALID_POLLING_INPUT)
    assert mock_create.called
    assert result["type"] == "create_entry"


# ── Step: reauth ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_step_reauth_shows_reauth_confirm_form():
    """async_step_reauth() immediately delegates to reauth_confirm form."""
    flow = _make_flow()
    flow.context = {"source": "reauth", "entry_id": "test_entry_id"}

    existing_entry = MagicMock()
    existing_entry.data = dict(VALID_CONNECTION)
    flow.hass.config_entries.async_get_entry = MagicMock(return_value=existing_entry)

    result = await flow.async_step_reauth({})
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_confirm"


@pytest.mark.asyncio
async def test_step_reauth_confirm_success_aborts_with_reload():
    """Correct password → async_update_reload_and_abort called."""
    flow = _make_flow()
    flow.context = {"source": "reauth", "entry_id": "test_entry_id"}

    existing_entry = MagicMock()
    existing_entry.data = dict(VALID_CONNECTION)
    flow.hass.config_entries.async_get_entry = MagicMock(return_value=existing_entry)
    flow._reauth_entry = existing_entry

    with patch.object(SophosFirewallConfigFlow, "_test_xml_connection",
                      new=AsyncMock(return_value={})):
        with patch.object(flow, "async_update_reload_and_abort",
                          return_value={"type": "abort", "reason": "reauth_successful"}) as mock_abort:
            result = await flow.async_step_reauth_confirm({"password": "newpassword"})

    mock_abort.assert_called_once()
    call_kwargs = mock_abort.call_args.kwargs
    assert call_kwargs["data_updates"] == {"password": "newpassword"}
    assert call_kwargs["reason"] == "reauth_successful"


@pytest.mark.asyncio
async def test_step_reauth_confirm_wrong_password_shows_error():
    """Wrong password → invalid_auth error stays on reauth_confirm form."""
    flow = _make_flow()
    flow.context = {"source": "reauth", "entry_id": "test_entry_id"}

    existing_entry = MagicMock()
    existing_entry.data = dict(VALID_CONNECTION)
    flow.hass.config_entries.async_get_entry = MagicMock(return_value=existing_entry)
    flow._reauth_entry = existing_entry

    with patch.object(SophosFirewallConfigFlow, "_test_xml_connection",
                      new=AsyncMock(return_value={"base": "invalid_auth"})):
        result = await flow.async_step_reauth_confirm({"password": "wrong"})

    assert result["type"] == "form"
    assert result["step_id"] == "reauth_confirm"
    assert result["errors"] == {"base": "invalid_auth"}


@pytest.mark.asyncio
async def test_step_reauth_confirm_no_input_shows_form():
    """No input → show the form without errors."""
    flow = _make_flow()
    flow.context = {"source": "reauth", "entry_id": "test_entry_id"}

    existing_entry = MagicMock()
    existing_entry.data = dict(VALID_CONNECTION)
    flow.hass.config_entries.async_get_entry = MagicMock(return_value=existing_entry)
    flow._reauth_entry = existing_entry

    result = await flow.async_step_reauth_confirm(None)
    assert result["type"] == "form"
    assert result["step_id"] == "reauth_confirm"
    assert result["errors"] == {}


# ── Step: reconfigure ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_step_reconfigure_shows_form():
    """reconfigure without input shows the form pre-filled with current data."""
    flow = _make_flow()
    flow.context = {"source": "reconfigure", "entry_id": "test_entry_id"}

    existing_entry = MagicMock()
    existing_entry.data = dict(VALID_CONNECTION)
    flow.hass.config_entries.async_get_entry = MagicMock(return_value=existing_entry)

    with patch.object(flow, "_get_reconfigure_entry", return_value=existing_entry):
        result = await flow.async_step_reconfigure(None)

    assert result["type"] == "form"
    assert result["step_id"] == "reconfigure"


@pytest.mark.asyncio
async def test_step_reconfigure_valid_input_aborts_with_success():
    """Valid reconfigure input → async_update_reload_and_abort."""
    flow = _make_flow()
    flow.context = {"source": "reconfigure", "entry_id": "test_entry_id"}

    existing_entry = MagicMock()
    existing_entry.data = dict(VALID_CONNECTION)

    new_data = {**VALID_CONNECTION, "host": "10.0.0.2"}

    with patch.object(flow, "_get_reconfigure_entry", return_value=existing_entry):
        with patch.object(SophosFirewallConfigFlow, "_test_xml_connection",
                          new=AsyncMock(return_value={})):
            with patch.object(flow, "async_update_reload_and_abort",
                              return_value={"type": "abort", "reason": "reconfigure_successful"}) as mock_abort:
                result = await flow.async_step_reconfigure(new_data)

    mock_abort.assert_called_once()
    assert result["reason"] == "reconfigure_successful"


@pytest.mark.asyncio
async def test_step_reconfigure_invalid_auth_shows_error():
    """Wrong credentials on reconfigure → error on form."""
    flow = _make_flow()
    flow.context = {"source": "reconfigure", "entry_id": "test_entry_id"}

    existing_entry = MagicMock()
    existing_entry.data = dict(VALID_CONNECTION)

    with patch.object(flow, "_get_reconfigure_entry", return_value=existing_entry):
        with patch.object(SophosFirewallConfigFlow, "_test_xml_connection",
                          new=AsyncMock(return_value={"base": "invalid_auth"})):
            result = await flow.async_step_reconfigure(VALID_CONNECTION)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "invalid_auth"
