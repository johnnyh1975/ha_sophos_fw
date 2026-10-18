"""A fake Sophos XML API for tests.

Plugs into Home Assistant's aiohttp test mocker (``aioclient_mock``): every
POST to the API endpoint is answered by ``FakeSophosApi.handle``, which
parses the real request XML the client sent and answers like SFOS does.
The integration's real SophosClient, session handling and XML parsing run
unmodified.
"""
from __future__ import annotations

import asyncio
import copy
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from yarl import URL

from pytest_homeassistant_custom_component.test_util.aiohttp import (
    AiohttpClientMocker,
    AiohttpClientMockResponse,
)

HOST = "127.0.0.1"
PORT = 4444
URL_API = f"https://{HOST}:{PORT}/webconsole/APIController"
USERNAME = "admin"
PASSWORD = "secret"

DEFAULT_RECORDS: dict[str, list[dict[str, Any]]] = {
    "Interface": [
        {"Name": "PortA", "Hardware": "PortA", "InterfaceStatus": "ON", "NetworkZone": "LAN",
         "IPv4Assignment": "Static", "InterfaceSpeed": "Auto Negotiate", "MTU": "1500"},
        {"Name": "PortB", "Hardware": "PortB", "InterfaceStatus": "OFF", "NetworkZone": "WAN",
         "IPv4Assignment": "DHCP", "InterfaceSpeed": "Auto Negotiate", "MTU": "1500"},
    ],
    # SFOS 18+ shape: the action sits in the NetworkPolicy block (Sophos
    # SDK updatefwrule.j2 and functional tests, Sophos Migration Utility
    # tmpl/FirewallRule.tmpl). Position, PolicyType and the policy block are
    # part of every rule; an update has to send them back.
    "FirewallRule": [
        {"Name": "Allow LAN to IoT", "Description": "", "IPFamily": "IPv4",
         "Status": "Enable", "Position": "Top", "PolicyType": "Network",
         "NetworkPolicy": {
             "Action": "Accept", "LogTraffic": "Enable", "SkipLocalDestined": "Disable",
             "SourceZones": {"Zone": ["LAN", "VPN"]}, "DestinationZones": {"Zone": "IoT"},
             "Schedule": "All The Time",
         }},
        {"Name": "Block Guest", "Description": "guests stay out", "IPFamily": "IPv4",
         "Status": "Disable", "Position": "After", "PolicyType": "Network",
         "After": {"Name": "Allow LAN to IoT"},
         "NetworkPolicy": {
             "Action": "Drop", "LogTraffic": "Disable", "SkipLocalDestined": "Disable",
             "SourceZones": {"Zone": "Guest"}, "Schedule": "Work hours",
         }},
    ],
    # Fields as in a recorded SFOS response (demisto/content SophosXGFirewall
    # test_data/web_filter_get.xml) plus a RuleList (Sophos SDK template).
    "WebFilterPolicy": [
        {"Name": "Kids", "Description": "", "DefaultAction": "Deny",
         "EnableReporting": "Enable", "DownloadFileSizeRestriction": "50",
         "DownloadFileSizeRestrictionEnabled": "1", "EnforceSafeSearch": "1",
         "RuleList": {"Rule": {
             "CategoryList": {"Category": {"ID": "Games", "type": "WebCategory"}},
             "HTTPAction": "Deny", "HTTPSAction": "Deny", "Schedule": "All The Time",
             "PolicyRuleEnabled": "1",
         }}},
        {"Name": "Default Policy", "Description": "", "DefaultAction": "Allow",
         "EnableReporting": "Enable", "DownloadFileSizeRestriction": "0",
         "DownloadFileSizeRestrictionEnabled": "0", "EnforceSafeSearch": "0"},
    ],
    "DHCPServer": [
        # Shape as SFOS sends it (#29): every static mapping is its own <Lease>
        # inside <StaticLease>; lease times are DefaultLeaseTime/MaxLeaseTime.
        {"Name": "Main_DHCP", "Status": "1", "Interface": "PortA",
         "DefaultLeaseTime": "1440", "MaxLeaseTime": "2880",
         "StaticLease": {"Lease": [
             {"HostName": "nas", "MACAddress": "AA:BB:CC:00:11:22", "IPAddress": "10.10.0.50"},
             {"HostName": "tv", "MACAddress": "AA:BB:CC:00:11:33", "IPAddress": "10.10.0.51"},
         ]}},
        {"Name": "Guest_DHCP", "Status": "0", "Interface": "PortC",
         "DefaultLeaseTime": "60", "MaxLeaseTime": "120", "StaticLease": ""},
    ],
    "BackupRestore": [
        {"ScheduleBackup": {"BackupMode": "Mail", "BackupFrequency": "Monthly"}},
    ],
    "AdminSettings": [
        {"HostnameSettings": {"HostName": "5HeyneXG"}},
    ],
}


# Fields the API documentation marks mandatory for an update (21.0 API
# help: Add/Edit firewall rule; Add/Update web filter policy). An update
# replaces the stored object, so whatever a request leaves out is lost.
MANDATORY: dict[str, tuple[str, ...]] = {
    "FirewallRule": ("Name", "PolicyType", "Position"),
    "WebFilterPolicy": ("Name", "DefaultAction", "DownloadFileSizeRestriction"),
}


def _from_xml(elem: ET.Element) -> Any:
    """Inverse of _to_xml: repeated tags become lists, leaves become str."""
    if not len(elem):
        return (elem.text or "").strip()  # pretty-printing whitespace is no value
    result: dict[str, Any] = {}
    for child in elem:
        value = _from_xml(child)
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(value)
        else:
            result[child.tag] = value
    return result


def _to_xml(tag: str, value: Any) -> str:
    if isinstance(value, list):
        return "".join(_to_xml(tag, item) for item in value)
    if isinstance(value, dict):
        inner = "".join(_to_xml(k, v) for k, v in value.items())
        return f"<{tag}>{inner}</{tag}>"
    return f"<{tag}>{escape(str(value))}</{tag}>"


class FakeSophosApi:
    """Stateful fake of the SFOS XML API."""

    def __init__(self) -> None:
        self.records = copy.deepcopy(DEFAULT_RECORDS)
        self.password = PASSWORD
        self.access_code: str | None = None     # "532" / "534" → access denied
        self.http_status = 200
        self.exc: BaseException | None = None   # raised by the transport
        self.fail_tags: dict[str, str] = {}     # tag → record-level error code
        self.broken_tags: set[str] = set()      # tags answered with a response-level error
        self.broken_gets: set[str] = set()      # like broken_tags, but only for <Get>
        self.break_gets_after_set: set[str] = set()  # → broken_gets once a <Set> succeeded
        self.reject_sets: set[str] = set()      # tags whose <Set> is rejected
        self.set_operations: list[str] = []     # operation attribute of each <Set>
        self.auth_failures_left = 0             # transient auth failures
        self.requests: list[tuple[str, str]] = []  # (operation, tag)
        self.delay = 0.0                        # seconds per request
        self.in_flight = 0
        self.peak_in_flight = 0

    def register(self, aioclient_mock: AiohttpClientMocker) -> FakeSophosApi:
        aioclient_mock.post(URL_API, side_effect=self.handle)
        return self

    def count(self, operation: str, tag: str) -> int:
        return self.requests.count((operation, tag))

    async def handle(self, method: str, url: URL, data: Any) -> AiohttpClientMockResponse:
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            return self._answer(url, data)
        finally:
            self.in_flight -= 1

    def _answer(self, url: URL, data: Any) -> AiohttpClientMockResponse:
        if self.exc is not None:
            raise self.exc
        request = ET.fromstring(data["reqxml"])
        user = request.findtext("Login/Username")
        password = request.findtext("Login/Password")

        operation, tag = "login", ""
        for op in ("Get", "Set"):
            if (elem := request.find(op)) is not None and len(elem):
                operation, tag = op.lower(), elem[0].tag
                break
        self.requests.append((operation, tag))

        def reply(body: str, status: int | None = None) -> AiohttpClientMockResponse:
            return AiohttpClientMockResponse(
                "post", url, status=status or self.http_status,
                text=f'<?xml version="1.0" encoding="UTF-8"?><Response APIVersion="2200.1">{body}</Response>',
            )

        if self.http_status != 200:
            return reply("")
        if self.access_code:
            return reply(f'<Status code="{self.access_code}">API access denied</Status>')
        if self.auth_failures_left > 0 or user != "admin" or password != self.password:
            self.auth_failures_left = max(0, self.auth_failures_left - 1)
            return reply("<Login><status>Authentication Failure</status></Login>")
        login = "<Login><status>Authentication Successful</status></Login>"

        if tag in self.broken_tags or (operation == "get" and tag in self.broken_gets):
            return reply(f'{login}<Status code="500">Internal error</Status>')

        if operation == "get":
            if code := self.fail_tags.get(tag):
                return reply(f'{login}<{tag} transactionid=""><Status code="{code}">failed</Status></{tag}>')
            records = self.records.get(tag, [])
            if not records:  # as SFOS answers (Sophos SDK test fixtures): no code
                return reply(f'{login}<{tag} transactionid=""><Status>Number of records Zero.</Status></{tag}>')
            # as SFOS sends records: transactionid attribute, pretty-printed
            body = "".join(
                _to_xml(tag, rec).replace(f"<{tag}>", f'\n  <{tag} transactionid="">', 1)
                .replace("><", ">\n    <")
                for rec in records
            )
            return reply(login + body + "\n")

        if operation == "set":
            elem = request.find(f"Set/{tag}")
            assert elem is not None
            if tag in self.reject_sets:
                return reply(f'{login}<{tag} transactionid=""><Status code="500">Operation failed</Status></{tag}>')
            set_op = request.find("Set").get("operation", "")  # type: ignore[union-attr]
            self.set_operations.append(set_op)
            new = _from_xml(elem)
            records = self.records.setdefault(tag, [])
            index = next(
                (i for i, rec in enumerate(records) if rec.get("Name") == new.get("Name")), None
            )
            if set_op == "add" and index is not None:
                return reply(f'{login}<{tag} transactionid=""><Status code="502">Operation failed. Entity having same name already exists.</Status></{tag}>')
            if missing := [f for f in MANDATORY.get(tag, ("Name",)) if f not in new]:
                params = "".join(f"<Params>/{tag}/{f}</Params>" for f in missing)
                return reply(f'{login}<{tag} transactionid=""><Status code="501">Configuration parameters validation failed.</Status>{params}</{tag}>')
            if index is None and set_op == "update":
                return reply(f'{login}<{tag} transactionid=""><Status code="500">Operation could not be performed on Entity.</Status></{tag}>')
            if index is None:
                records.append(new)
            else:  # an update replaces the whole object
                records[index] = new
            if tag in self.break_gets_after_set:
                self.broken_gets.add(tag)
            return reply(f'{login}<{tag} transactionid=""><Status code="200">Configuration applied successfully.</Status></{tag}>')

        return reply(login)
