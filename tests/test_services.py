"""Actions: block/unblock a site (URL group) or a device (IP host group)."""
from __future__ import annotations

import copy
from typing import Any

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from custom_components.sophos_firewall.const import DOMAIN

from .conftest import ENTRY_ID, make_entry, setup_entry
from .fake_sophos import FakeSophosApi


async def _call(hass: HomeAssistant, service: str, **data: Any) -> dict[str, Any]:
    response = await hass.services.async_call(
        DOMAIN, service, {"config_entry_id": ENTRY_ID, **data},
        blocking=True, return_response=True,
    )
    assert isinstance(response, dict)
    return response


def _group(xml_api: FakeSophosApi, tag: str, name: str) -> dict[str, Any]:
    return next(r for r in xml_api.records[tag] if r["Name"] == name)


@pytest.fixture
async def writable(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False, write_access=True))


# ── Sites ─────────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("writable")
async def test_block_url_adds_the_domain_and_keeps_the_group(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    before = copy.deepcopy(_group(xml_api, "WebFilterURLGroup", "HA Blocked Sites"))
    response = await _call(
        hass, "block_url", url_group="HA Blocked Sites", url="https://www.Tiktok.com/foryou"
    )
    assert response == {"changed": True}
    group = _group(xml_api, "WebFilterURLGroup", "HA Blocked Sites")
    assert group == {**before, "URLlist": {"URL": ["games.example", "video.example", "www.tiktok.com"]}}
    assert xml_api.set_operations[-1] == "update"


@pytest.mark.usefixtures("writable")
async def test_block_url_twice_writes_once(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    assert (await _call(hass, "block_url", url_group="HA Blocked Sites", url="games.example")) == {
        "changed": False
    }
    assert ("set", "WebFilterURLGroup") not in xml_api.requests


@pytest.mark.usefixtures("writable")
async def test_block_url_in_an_empty_group(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    """An empty group has no URLlist element (Sophos SDK, Ansible)."""
    await _call(hass, "block_url", url_group="Empty Group", url="a.example")
    assert _group(xml_api, "WebFilterURLGroup", "Empty Group")["URLlist"] == {"URL": "a.example"}


@pytest.mark.usefixtures("writable")
async def test_unblock_url(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    assert (await _call(hass, "unblock_url", url_group="HA Blocked Sites", url="GAMES.example")) == {
        "changed": True
    }
    assert _group(xml_api, "WebFilterURLGroup", "HA Blocked Sites")["URLlist"] == {
        "URL": "video.example"
    }
    assert (await _call(hass, "unblock_url", url_group="HA Blocked Sites", url="x.example")) == {
        "changed": False
    }


@pytest.mark.usefixtures("writable")
async def test_built_in_url_group_is_refused(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    with pytest.raises(HomeAssistantError) as err:
        await _call(hass, "block_url", url_group="Built-in Group", url="a.example")
    assert err.value.translation_key == "group_not_editable"
    assert ("set", "WebFilterURLGroup") not in xml_api.requests


@pytest.mark.usefixtures("writable")
async def test_unknown_url_group(hass: HomeAssistant) -> None:
    with pytest.raises(HomeAssistantError) as err:
        await _call(hass, "block_url", url_group="Nope", url="a.example")
    assert err.value.translation_key == "group_not_found"


@pytest.mark.usefixtures("writable")
@pytest.mark.parametrize("url", ["*.example.com", "example", "exa mple.com", "a" * 251 + ".com"])
async def test_invalid_domain_is_rejected(hass: HomeAssistant, url: str) -> None:
    import voluptuous as vol

    with pytest.raises(vol.Invalid):
        await _call(hass, "block_url", url_group="HA Blocked Sites", url=url)


# ── Devices ───────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("writable")
async def test_block_device_creates_the_host_and_joins_the_group(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    response = await _call(
        hass, "block_device", host_group="Empty Devices", ip_address="10.10.0.77",
        host_name="Kids tablet",
    )
    assert response == {"changed": True, "host": "Kids tablet"}
    host = _group(xml_api, "IPHost", "Kids tablet")
    assert host["HostType"] == "IP" and host["IPAddress"] == "10.10.0.77"
    group = _group(xml_api, "IPHostGroup", "Empty Devices")
    assert group == {"Name": "Empty Devices", "Description": "", "HostList": {"Host": "Kids tablet"},
                     "IPFamily": "IPv4"}


@pytest.mark.usefixtures("writable")
async def test_block_device_reuses_an_existing_host(
    hass: HomeAssistant, xml_api: FakeSophosApi
) -> None:
    hosts = len(xml_api.records["IPHost"])
    response = await _call(hass, "block_device", host_group="Empty Devices", ip_address="10.10.0.50")
    assert response == {"changed": True, "host": "nas"}
    assert len(xml_api.records["IPHost"]) == hosts
    # already a member: nothing to write
    assert (await _call(hass, "block_device", host_group="HA Blocked Devices",
                        ip_address="10.10.0.50"))["changed"] is False


@pytest.mark.usefixtures("writable")
async def test_default_host_name(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    response = await _call(hass, "block_device", host_group="Empty Devices", ip_address="10.10.0.9")
    assert response["host"] == "HA 10.10.0.9"


@pytest.mark.usefixtures("writable")
async def test_unblock_device_keeps_the_host(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    before = copy.deepcopy(_group(xml_api, "IPHostGroup", "HA Blocked Devices"))
    response = await _call(
        hass, "unblock_device", host_group="HA Blocked Devices", ip_address="10.10.0.50"
    )
    assert response == {"changed": True, "host": "nas"}
    group = _group(xml_api, "IPHostGroup", "HA Blocked Devices")
    assert group == {k: v for k, v in before.items() if k != "HostList"}  # empty: no HostList
    assert any(h["Name"] == "nas" for h in xml_api.records["IPHost"])
    assert (await _call(hass, "unblock_device", host_group="HA Blocked Devices",
                        ip_address="10.99.0.1")) == {"changed": False}


@pytest.mark.usefixtures("writable")
async def test_ipv6_group_is_refused(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    with pytest.raises(HomeAssistantError) as err:
        await _call(hass, "block_device", host_group="V6 Devices", ip_address="10.10.0.50")
    assert err.value.translation_key == "write_failed"
    assert ("set", "IPHostGroup") not in xml_api.requests


# ── Preconditions ─────────────────────────────────────────────────────────────


async def test_actions_need_write_access(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False))
    with pytest.raises(ServiceValidationError) as err:
        await _call(hass, "block_url", url_group="HA Blocked Sites", url="a.example")
    assert err.value.translation_key == "write_access_disabled"
    assert not [r for r in xml_api.requests if r[0] == "set"]


async def test_unknown_entry(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    await setup_entry(hass, make_entry(snmp_enabled=False, write_access=True))
    with pytest.raises(ServiceValidationError) as err:
        await hass.services.async_call(
            DOMAIN, "block_url",
            {"config_entry_id": "nope", "url_group": "HA Blocked Sites", "url": "a.example"},
            blocking=True, return_response=True,
        )
    assert err.value.translation_key == "entry_not_found"


async def test_entry_not_loaded(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    entry = make_entry(snmp_enabled=False, write_access=True)
    await setup_entry(hass, entry)
    await hass.config_entries.async_unload(entry.entry_id)
    with pytest.raises(ServiceValidationError) as err:
        await _call(hass, "block_url", url_group="HA Blocked Sites", url="a.example")
    assert err.value.translation_key == "entry_not_loaded"


@pytest.mark.usefixtures("writable")
async def test_full_group_is_reported(hass: HomeAssistant, xml_api: FakeSophosApi) -> None:
    xml_api.set_codes["WebFilterURLGroup"] = "523"
    with pytest.raises(HomeAssistantError) as err:
        await _call(hass, "block_url", url_group="HA Blocked Sites", url="a.example")
    assert err.value.translation_key == "group_full"
