"""Shared fixtures.

Tests run the integration against two fakes that speak the real protocols:

* ``xml_api``    — FakeSophosApi behind Home Assistant's aiohttp test mocker
* ``snmp_agent`` — FakeSnmpAgent, a UDP SNMP agent on 127.0.0.1

Nothing inside the integration is mocked.
"""
from __future__ import annotations

from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import PropertyMock, patch

import pytest
from homeassistant.core import HomeAssistant

from custom_components.sophos_firewall.const import DOMAIN
from pytest_homeassistant_custom_component.common import MockConfigEntry
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from .fake_snmp import FakeSnmpAgent, sophos_mib
from .fake_sophos import HOST, PASSWORD, PORT, USERNAME, FakeSophosApi

ENTRY_ID = "sophos_test_entry"

SNMP_MODULE = "custom_components.sophos_firewall.snmp_client"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations: None) -> None:
    """Load custom_components/ in every test."""


@pytest.fixture(autouse=True)
def fast_snmp() -> Generator[None]:
    """Shrink SNMP timeouts so timeout tests take about a second."""
    with (
        patch(f"{SNMP_MODULE}.SNMP_TIMEOUT", 1),
        patch(f"{SNMP_MODULE}.SNMP_RETRIES", 1),
        patch(f"{SNMP_MODULE}.SNMP_OPERATION_BUDGET", 1.5),
    ):
        yield


@pytest.fixture(autouse=True)
def reset_unknown_value_log() -> Generator[None]:
    """Unknown ENUM values are logged once per HA process; isolate tests."""
    from custom_components.sophos_firewall import sensor

    sensor._unknown_logged.clear()  # noqa: SLF001
    yield
    sensor._unknown_logged.clear()  # noqa: SLF001


@pytest.fixture
def entity_registry_enabled_by_default() -> Generator[None]:
    """Create entities that are disabled by default as enabled.

    Same fixture as in Home Assistant core's tests/conftest.py (PHCC does not
    ship it). Only for tests that check the *values* of such entities; the
    defaults themselves are checked without it.
    """
    with patch(
        "homeassistant.helpers.entity.Entity.entity_registry_enabled_default",
        return_value=True,
        new_callable=PropertyMock,
    ):
        yield


@pytest.fixture
def xml_api(hass: HomeAssistant, aioclient_mock: AiohttpClientMocker) -> Generator[FakeSophosApi]:
    """A fake XML API answering every request of the integration.

    The integration's dedicated XML session is replaced by one bound to
    Home Assistant's aiohttp test mocker.
    """
    api = FakeSophosApi().register(aioclient_mock)
    with patch(
        "custom_components.sophos_firewall.session.create_xml_session",
        side_effect=lambda verify_ssl: aioclient_mock.create_session(hass.loop),
    ):
        yield api


@pytest.fixture
async def snmp_agent(socket_enabled: None) -> AsyncGenerator[FakeSnmpAgent]:
    """A fake SNMP agent (virtual appliance) on a free local UDP port."""
    agent = await FakeSnmpAgent(sophos_mib()).start()
    with patch(f"{SNMP_MODULE}.DEFAULT_SNMP_PORT", agent.port):
        yield agent
    agent.stop()


@pytest.fixture
async def hardware_agent(snmp_agent: FakeSnmpAgent) -> FakeSnmpAgent:
    """The fake agent, reporting a hardware appliance (temps, fans, PSUs)."""
    snmp_agent.mib.clear()
    for oid, value in sophos_mib(hardware=True).items():
        snmp_agent.set(oid, value)
    return snmp_agent


CONNECTION: dict[str, Any] = {
    "host": HOST,
    "port": PORT,
    "username": USERNAME,
    "password": PASSWORD,
    "verify_ssl": False,
}


def make_entry(options: dict[str, Any] | None = None, **settings: Any) -> MockConfigEntry:
    """Return a (version 2) config entry for the fake firewall.

    Keyword arguments are options (snmp_enabled=False, write_access=True, …);
    ``options`` adds more, e.g. polling toggles.
    """
    return MockConfigEntry(
        domain=DOMAIN,
        title=HOST,
        unique_id=f"{HOST}:{PORT}",
        entry_id=ENTRY_ID,
        version=2,
        data=dict(CONNECTION),
        options={
            "snmp_enabled": True,
            "snmp_community": "public",
            "write_access": False,
            **settings,
            **(options or {}),
        },
    )


async def setup_entry(hass: HomeAssistant, entry: MockConfigEntry) -> None:
    """Add the entry (if needed) and set it up, incl. the background SNMP refresh."""
    if hass.config_entries.async_get_entry(entry.entry_id) is None:
        entry.add_to_hass(hass)
    await hass.config_entries.async_setup(entry.entry_id)
    await hass.async_block_till_done(wait_background_tasks=True)
