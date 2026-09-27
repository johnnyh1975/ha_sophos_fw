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
    "FirewallRule": [
        {"Name": "Allow LAN to IoT", "Status": "Enable", "Action": "Accept",
         "PolicyType": "Network", "IPFamily": "IPv4"},
        {"Name": "Block Guest", "Status": "Disable", "Action": "Drop",
         "PolicyType": "Network", "IPFamily": "IPv4"},
    ],
    "WebFilterPolicy": [
        {"Name": "Kids", "DefaultAction": "Deny"},
        {"Name": "Default Policy", "DefaultAction": "Allow"},
    ],
    "DHCPServer": [
        {"Name": "Main_DHCP", "Status": "1", "Interface": "PortA", "LeaseTime": "1440",
         "StaticLease": [
             {"MACAddress": "AA:BB:CC:00:11:22", "IPAddress": "10.10.0.50", "HostName": "nas"},
             {"MACAddress": "AA:BB:CC:00:11:33", "IPAddress": "10.10.0.51", "HostName": "tv"},
         ]},
        {"Name": "Guest_DHCP", "Status": "0", "Interface": "PortC", "LeaseTime": "60"},
    ],
    "BackupRestore": [
        {"ScheduleBackup": {"BackupMode": "Mail", "BackupFrequency": "Monthly"}},
    ],
    "AdminSettings": [
        {"HostnameSettings": {"HostName": "5HeyneXG"}},
    ],
}


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
        self.reject_sets: set[str] = set()      # tags whose <Set> is rejected
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
            body = "".join(_to_xml(tag, rec) for rec in self.records.get(tag, []))
            return reply(login + body)

        if operation == "set":
            elem = request.find(f"Set/{tag}")
            assert elem is not None
            if tag in self.reject_sets:
                return reply(f'{login}<{tag} transactionid=""><Status code="500">Operation failed</Status></{tag}>')
            name = elem.findtext("Name")
            for rec in self.records.get(tag, []):
                if name is not None and rec.get("Name") == name:
                    for child in elem:
                        if child.tag != "Name":
                            rec[child.tag] = child.text or ""
            return reply(f'{login}<{tag} transactionid=""><Status code="200">Configuration applied successfully.</Status></{tag}>')

        return reply(login)
