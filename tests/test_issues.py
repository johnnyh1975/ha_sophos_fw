"""Repair issues: raised for problems only the user can fix, cleared on recovery."""
from __future__ import annotations

from datetime import timedelta

import pytest
from freezegun.api import FrozenDateTimeFactory
from homeassistant.config_entries import ConfigEntryDisabler, ConfigEntryState
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from pytest_homeassistant_custom_component.common import async_fire_time_changed

from custom_components.sophos_firewall.const import DOMAIN

from .conftest import ENTRY_ID, make_entry, setup_entry
from .fake_snmp import FakeSnmpAgent
from .fake_sophos import HOST, FakeSophosApi

ACCESS = f"api_access_denied_{ENTRY_ID}"
SNMP = f"snmp_unreachable_{ENTRY_ID}"


def _issue(hass: HomeAssistant, issue_id: str) -> ir.IssueEntry | None:
    return ir.async_get(hass).async_get_issue(DOMAIN, issue_id)


async def _tick(hass: HomeAssistant, freezer: FrozenDateTimeFactory, seconds: float) -> None:
    freezer.tick(timedelta(seconds=seconds))
    async_fire_time_changed(hass)
    await hass.async_block_till_done(wait_background_tasks=True)


async def _refresh_snmp(hass: HomeAssistant, entry) -> None:
    """SNMP timeouts run on the loop clock, so no freezer here (see test_coordinator)."""
    snmp = entry.runtime_data.snmp
    snmp.invalidate(*(ep.key for ep in snmp.endpoints))
    await snmp.async_refresh()
    await hass.async_block_till_done()


# ── API access denied (532/534) ───────────────────────────────────────────────


async def test_access_denied_at_setup_raises_issue_until_fixed(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    xml_api.access_code = "534"
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_RETRY
    issue = _issue(hass, ACCESS)
    assert issue is not None
    assert issue.translation_key == "api_access_denied"
    assert issue.severity is ir.IssueSeverity.ERROR
    assert not issue.is_fixable
    assert issue.translation_placeholders == {"title": HOST, "host": HOST, "code": "534"}

    xml_api.access_code = None
    await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert _issue(hass, ACCESS) is None


async def test_access_revoked_while_running(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    assert _issue(hass, ACCESS) is None
    xml_api.access_code = "532"
    await _tick(hass, freezer, 30)
    assert _issue(hass, ACCESS).translation_placeholders["code"] == "532"
    xml_api.access_code = None
    await _tick(hass, freezer, 30)
    assert _issue(hass, ACCESS) is None


async def test_unreachable_firewall_is_no_issue(
    hass: HomeAssistant, freezer: FrozenDateTimeFactory, xml_api: FakeSophosApi
) -> None:
    """A transient outage only makes entities unavailable."""
    await setup_entry(hass, make_entry(snmp_enabled=False))
    xml_api.exc = TimeoutError()
    await _tick(hass, freezer, 30)
    assert ir.async_get(hass).issues == {}


# ── SNMP never answering ──────────────────────────────────────────────────────


@pytest.fixture
def no_snmp_issue_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop the 10-minute condition, leaving only the attempt count.

    SNMP timeouts run on the loop clock, which the freezer would stop, so the
    time cannot be advanced in SNMP failure tests.
    """
    from custom_components.sophos_firewall import coordinator

    monkeypatch.setattr(coordinator, "SNMP_ISSUE_AFTER_SECONDS", 0)


async def test_snmp_issue_waits_for_the_agent_to_boot(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    """After a power outage the agent answers minutes after the XML API:
    failed attempts within the first 10 minutes raise no issue."""
    snmp_agent.drop_all = True
    entry = make_entry()
    await setup_entry(hass, entry)
    for _ in range(3):
        await _refresh_snmp(hass, entry)
    assert _issue(hass, SNMP) is None


@pytest.mark.usefixtures("no_snmp_issue_delay")
async def test_snmp_never_answering_raises_issue_after_three_attempts(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    snmp_agent.drop_all = True
    entry = make_entry()
    await setup_entry(hass, entry)  # attempt 1 (background first refresh)
    await _refresh_snmp(hass, entry)  # attempt 2
    assert _issue(hass, SNMP) is None
    await _refresh_snmp(hass, entry)  # attempt 3
    issue = _issue(hass, SNMP)
    assert issue is not None
    assert issue.translation_key == "snmp_unreachable"
    assert issue.severity is ir.IssueSeverity.WARNING  # SNMP is optional
    assert issue.translation_placeholders == {"title": HOST, "host": HOST}

    snmp_agent.drop_all = False
    await _refresh_snmp(hass, entry)
    assert _issue(hass, SNMP) is None


@pytest.mark.usefixtures("no_snmp_issue_delay")
async def test_snmp_outage_after_success_is_no_issue(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    entry = make_entry()
    await setup_entry(hass, entry)
    snmp_agent.drop_all = True
    for _ in range(3):
        await _refresh_snmp(hass, entry)
    assert _issue(hass, SNMP) is None


@pytest.mark.usefixtures("no_snmp_issue_delay")
async def test_turning_snmp_off_clears_its_issue(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent
) -> None:
    snmp_agent.drop_all = True
    entry = make_entry()
    await setup_entry(hass, entry)
    for _ in range(2):
        await _refresh_snmp(hass, entry)
    assert _issue(hass, SNMP) is not None

    hass.config_entries.async_update_entry(
        entry, options={**entry.options, "snmp_enabled": False}
    )
    await hass.async_block_till_done(wait_background_tasks=True)
    assert entry.state is ConfigEntryState.LOADED
    assert _issue(hass, SNMP) is None


async def test_removing_the_entry_clears_its_issues(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    xml_api.access_code = "534"
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    assert _issue(hass, ACCESS) is not None
    await hass.config_entries.async_remove(entry.entry_id)
    await hass.async_block_till_done()
    assert _issue(hass, ACCESS) is None


async def test_disabling_a_retrying_entry_clears_its_issue(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """Review finding: a disabled entry kept "keeps retrying". Setup failed,
    so Home Assistant never calls async_unload_entry on disable."""
    xml_api.access_code = "534"
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    assert entry.state is ConfigEntryState.SETUP_RETRY
    assert _issue(hass, ACCESS) is not None
    await hass.config_entries.async_reload(entry.entry_id)  # a retry: still one watcher
    await hass.async_block_till_done()

    await hass.config_entries.async_set_disabled_by(
        entry.entry_id, ConfigEntryDisabler.USER
    )
    await hass.async_block_till_done()
    assert _issue(hass, ACCESS) is None


async def test_disabling_a_loaded_entry_clears_its_issues(
    hass: HomeAssistant, xml_api: FakeSophosApi, snmp_agent: FakeSnmpAgent,
    no_snmp_issue_delay: None,
) -> None:
    snmp_agent.drop_all = True
    entry = make_entry()
    await setup_entry(hass, entry)
    for _ in range(2):
        await _refresh_snmp(hass, entry)
    assert _issue(hass, SNMP) is not None
    await hass.config_entries.async_set_disabled_by(
        entry.entry_id, ConfigEntryDisabler.USER
    )
    await hass.async_block_till_done()
    assert _issue(hass, SNMP) is None


async def test_reloading_keeps_the_issue(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    """Only disabling clears: a reload with access still denied keeps it."""
    xml_api.access_code = "534"
    entry = make_entry(snmp_enabled=False)
    await setup_entry(hass, entry)
    await hass.config_entries.async_reload(entry.entry_id)
    await hass.async_block_till_done()
    assert _issue(hass, ACCESS) is not None
