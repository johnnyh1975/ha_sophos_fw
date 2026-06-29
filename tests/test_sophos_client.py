"""Tests for sophos_client.py — XML API wrapper.

Uses aioresponses to mock HTTP without a real network connection.
"""
from __future__ import annotations

import pytest
from aioresponses import aioresponses

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from custom_components.sophos_firewall.sophos_client import (
    SophosAuthError,
    SophosAPIError,
    SophosClient,
)

URL = "https://192.168.1.1:4444/webconsole/APIController"

# ── Helpers ───────────────────────────────────────────────────────────────────

def make_client() -> SophosClient:
    return SophosClient(
        host="192.168.1.1",
        port=4444,
        username="admin",
        password="secret",
        verify_ssl=False,
    )


# ── test_connection ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_connection_success():
    """test_connection returns API version on success."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            version = await client.test_connection()
    assert version == "2200.1"


@pytest.mark.asyncio
async def test_connection_auth_failure():
    """test_connection raises SophosAuthError on bad credentials."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Failure</status></Login>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            with pytest.raises(SophosAuthError):
                await client.test_connection()


@pytest.mark.asyncio
async def test_connection_network_error():
    """test_connection raises SophosAPIError on connection error."""
    import aiohttp
    # Use a generic client error rather than ClientConnectorError
    # which requires a real connection_key object
    with aioresponses() as m:
        m.post(URL, exception=aiohttp.ClientError("Connection refused"))
        async with make_client() as client:
            with pytest.raises(SophosAPIError):
                await client.test_connection()


# ── get_interfaces ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_interfaces_single():
    """get_interfaces returns a list with one interface dict."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <Interface transactionid="">
        <Name>PortA</Name>
        <InterfaceStatus>ON</InterfaceStatus>
        <NetworkZone>LAN</NetworkZone>
        <InterfaceSpeed>Auto Negotiate</InterfaceSpeed>
        <MTU>1500</MTU>
      </Interface>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            interfaces = await client.get_interfaces()

    assert len(interfaces) == 1
    assert interfaces[0]["Name"] == "PortA"
    assert interfaces[0]["InterfaceStatus"] == "ON"
    assert interfaces[0]["NetworkZone"] == "LAN"


@pytest.mark.asyncio
async def test_get_interfaces_empty():
    """get_interfaces returns empty list when firewall has no interfaces."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <Interface><Status code="526">No. of records Zero.</Status></Interface>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            interfaces = await client.get_interfaces()

    assert interfaces == []


@pytest.mark.asyncio
async def test_get_interfaces_invalid_xml():
    """get_interfaces raises SophosAPIError on malformed XML."""
    with aioresponses() as m:
        m.post(URL, body="not xml at all", content_type="text/html")
        async with make_client() as client:
            with pytest.raises(SophosAPIError, match="Invalid XML"):
                await client.get_interfaces()


# ── get_firewall_rules ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_firewall_rules():
    """get_firewall_rules returns rules with Status field."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <FirewallRule transactionid="">
        <Name>Allow LAN to WAN</Name>
        <Status>Enable</Status>
        <Action>Accept</Action>
        <PolicyType>Network</PolicyType>
        <IPFamily>IPv4</IPFamily>
      </FirewallRule>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            rules = await client.get_firewall_rules()

    assert len(rules) == 1
    assert rules[0]["Name"] == "Allow LAN to WAN"
    assert rules[0]["Status"] == "Enable"
    assert rules[0]["Action"] == "Accept"


# ── set_firewall_rule_status ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_set_firewall_rule_status_enable():
    """set_firewall_rule_status sends Enable without raising."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <FirewallRule><Status code="200">Configuration applied successfully.</Status></FirewallRule>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            # Should not raise
            await client.set_firewall_rule_status("Allow LAN to WAN", enable=True)


@pytest.mark.asyncio
async def test_set_firewall_rule_status_error():
    """set_firewall_rule_status raises SophosAPIError on non-200 status."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <FirewallRule><Status code="502">Rule not found.</Status></FirewallRule>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            with pytest.raises(SophosAPIError):
                await client.set_firewall_rule_status("NonExistent", enable=True)


# ── get_web_filter_policies ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_web_filter_policies():
    """get_web_filter_policies returns policy with DefaultAction."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <WebFilterPolicy transactionid="">
        <Name>Alle zulassen</Name>
        <DefaultAction>Allow</DefaultAction>
        <EnableReporting>Enable</EnableReporting>
      </WebFilterPolicy>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            policies = await client.get_web_filter_policies()

    assert len(policies) == 1
    assert policies[0]["DefaultAction"] == "Allow"


# ── _elem_to_dict ─────────────────────────────────────────────────────────────

def test_elem_to_dict_nested():
    """_elem_to_dict correctly converts nested XML to dict."""
    from xml.etree import ElementTree as ET
    xml = ET.fromstring("""
    <Root>
      <Child>value1</Child>
      <Child>value2</Child>
      <Nested><Deep>deep_value</Deep></Nested>
    </Root>
    """)
    result = SophosClient._elem_to_dict(xml)
    # Multiple sibling tags should become a list
    assert isinstance(result["Child"], list)
    assert result["Child"] == ["value1", "value2"]
    assert result["Nested"]["Deep"] == "deep_value"


def test_elem_to_dict_single_child():
    """_elem_to_dict single child stays as string, not list."""
    from xml.etree import ElementTree as ET
    xml = ET.fromstring("<Root><Name>PortA</Name></Root>")
    result = SophosClient._elem_to_dict(xml)
    assert result["Name"] == "PortA"
    assert not isinstance(result["Name"], list)


# ── Response-level Status codes (532/534/535) — regression for code review ────

@pytest.mark.asyncio
async def test_post_status_532_api_not_enabled_raises_auth():
    """Response-level Status code 532 (API not enabled) → SophosAuthError."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Status code="532">API access not enabled</Status>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            with pytest.raises(SophosAuthError):
                await client.test_connection()


@pytest.mark.asyncio
async def test_post_status_534_ip_blocked_raises_auth():
    """Response-level Status code 534 (IP not in access list) → SophosAuthError."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Status code="534">IP address not allowed</Status>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            with pytest.raises(SophosAuthError):
                await client.test_connection()


@pytest.mark.asyncio
async def test_post_status_other_error_raises_api_error():
    """A non-2xx response-level Status code → SophosAPIError (not auth)."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Status code="500">Internal error</Status>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            with pytest.raises(SophosAPIError):
                await client.test_connection()


@pytest.mark.asyncio
async def test_post_nested_status_not_treated_as_error():
    """A <Status> nested inside a record element must NOT trigger the
    response-level check — only direct children of <Response> count."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <Interface><Name>PortA</Name><Status code="200"/></Interface>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            result = await client.get_interfaces()
    assert len(result) == 1
    assert result[0]["Name"] == "PortA"


# ── trigger_backup status check — regression for code review B2 ───────────────

@pytest.mark.asyncio
async def test_trigger_backup_success():
    """trigger_backup completes silently when the firewall accepts it."""
    # First call: get_backup() reads current config
    get_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <BackupRestore><ScheduleBackup><BackupMode>Local</BackupMode>
      <BackupFrequency>Daily</BackupFrequency></ScheduleBackup></BackupRestore>
    </Response>"""
    # Second call: the write-back
    set_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <BackupRestore><Status code="200">Configuration applied successfully</Status></BackupRestore>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=get_response, content_type="text/xml")
        m.post(URL, body=set_response, content_type="text/xml")
        async with make_client() as client:
            await client.trigger_backup()  # must not raise


@pytest.mark.asyncio
async def test_trigger_backup_failure_raises():
    """trigger_backup raises when the firewall rejects the backup (no longer
    silently swallowed) — regression for code review finding B2."""
    get_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <BackupRestore><ScheduleBackup><BackupMode>Mail</BackupMode>
      <BackupFrequency>Daily</BackupFrequency></ScheduleBackup></BackupRestore>
    </Response>"""
    set_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <BackupRestore><Status code="502">Mail server not configured</Status></BackupRestore>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=get_response, content_type="text/xml")
        m.post(URL, body=set_response, content_type="text/xml")
        async with make_client() as client:
            with pytest.raises(SophosAPIError):
                await client.trigger_backup()


# ── _get_tag element-skip vs list-discard — regression for code review V4 ─────

@pytest.mark.asyncio
async def test_get_tag_skips_individual_error_element():
    """One element with an error status is skipped; valid siblings are kept
    (previously the whole list was discarded) — regression for V4."""
    xml_response = """<?xml version="1.0"?>
    <Response APIVersion="2200.1">
      <Login><status>Authentication Successful</status></Login>
      <Interface><Name>PortA</Name><InterfaceStatus>ON</InterfaceStatus></Interface>
      <Interface><Status code="526"/></Interface>
      <Interface><Name>PortC</Name><InterfaceStatus>ON</InterfaceStatus></Interface>
    </Response>"""
    with aioresponses() as m:
        m.post(URL, body=xml_response, content_type="text/xml")
        async with make_client() as client:
            result = await client.get_interfaces()
    # Two valid interfaces kept, the error element skipped — not an empty list
    names = {i.get("Name") for i in result}
    assert "PortA" in names
    assert "PortC" in names
