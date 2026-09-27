"""Async client for the Sophos Firewall XML API.

The XML API is a single HTTPS POST endpoint that takes an XML request and
returns an XML response. The client parses responses into the typed models
of ``models.py`` — callers never see raw XML.

Connection strategy
-------------------
The client uses an aiohttp session injected by the caller
(``inject-websession``). Two firewall-specific constraints apply:

* **One request at a time.** The firewall answers XML requests strictly one
  after another (5-10 s each, measured). A second request in flight only
  waits on the firewall while its own timeout runs — that is how requests
  timed out. A semaphore in the client enforces the limit for every caller
  (XML_MAX_CONCURRENT_REQUESTS).
* **No connection reuse.** A request sent on a reused keep-alive connection
  hangs or fails on the firewall. The integration therefore injects a
  session whose connector never pools (see session.py); every request also
  sends ``Connection: close``.

Error model
-----------
``SophosError`` is the base class. Callers distinguish:

* ``SophosConnectionError`` — network failure or timeout (transient).
* ``SophosAuthError``       — credentials rejected (reauth can fix it).
* ``SophosAccessError``     — API disabled or client IP not allowed
                               (codes 532/534; only the firewall admin can fix it).
* ``SophosAPIError``        — any other API-level failure.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Iterable, Mapping
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as _xml_escape

import aiohttp

from .const import (
    DEFAULT_TIMEOUT,
    XML_API_PATH,
    XML_MAX_CONCURRENT_REQUESTS,
    XML_TAG_ADMIN,
    XML_TAG_BACKUP,
    XML_TAG_DHCP_SERVER,
    XML_TAG_FIREWALL_RULE,
    XML_TAG_INTERFACE,
    XML_TAG_WEB_FILTER,
)
from .models import (
    AdminSettings,
    BackupSettings,
    DhcpServer,
    FirewallRule,
    Interface,
    WebFilterPolicy,
)

_LOGGER = logging.getLogger(__name__)

_SUCCESS_CODES = frozenset({"200", "201", "202", ""})
_ACCESS_DENIED_CODES = frozenset({"532", "534"})
_AUTH_FAILED_CODES = frozenset({"535"})


class SophosError(Exception):
    """Base class for all errors raised by the XML client."""


class SophosConnectionError(SophosError):
    """The firewall could not be reached or did not answer in time."""


class SophosAuthError(SophosError):
    """The firewall rejected the credentials."""


class SophosAccessError(SophosError):
    """API access is denied by firewall configuration.

    Code 532: the XML API is not enabled. Code 534: the client IP is not in
    the API access list. HTTP 403 is treated the same way. New credentials
    cannot fix this — the firewall administrator has to change the setting.
    """

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class SophosAPIError(SophosError):
    """Any other API-level failure."""


# ── XML → dict helpers ────────────────────────────────────────────────────────


def _elem_to_dict(element: ET.Element) -> dict[str, Any]:
    """Recursively convert an XML element to a nested dict.

    Repeated sibling tags become lists.
    """
    result: dict[str, Any] = {}
    for child in element:
        value: Any = _elem_to_dict(child) if len(child) else (child.text or "")
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(value)
        else:
            result[child.tag] = value
    return result


def _text(record: Mapping[str, Any], key: str) -> str | None:
    """Return a leaf value as stripped str, or None if missing or not a leaf.

    The XML→dict conversion yields a dict when an element unexpectedly has
    children; such values are treated as missing instead of crashing callers.
    """
    value = record.get(key)
    if isinstance(value, str):
        value = value.strip()
        return value or None
    return None


def _path(record: Mapping[str, Any], *keys: str) -> Mapping[str, Any]:
    """Descend into nested dicts, returning {} for anything unexpected."""
    current: Any = record
    for key in keys:
        current = current.get(key) if isinstance(current, Mapping) else None
    return current if isinstance(current, Mapping) else {}


def _equals(value: str | None, expected: str) -> bool | None:
    """Case-insensitive comparison that keeps 'unknown' as None."""
    if value is None:
        return None
    return value.lower() == expected.lower()


# ── Record parsers ────────────────────────────────────────────────────────────


def parse_interface(record: Mapping[str, Any]) -> Interface | None:
    """Parse one <Interface> record."""
    if (name := _text(record, "Name")) is None:
        return None
    return Interface(
        name=name,
        is_up=_equals(_text(record, "InterfaceStatus"), "on"),
        hardware=_text(record, "Hardware"),
        zone=_text(record, "NetworkZone"),
        ipv4_assignment=_text(record, "IPv4Assignment"),
        speed=_text(record, "InterfaceSpeed"),
        mtu=_text(record, "MTU"),
    )


def parse_firewall_rule(record: Mapping[str, Any]) -> FirewallRule | None:
    """Parse one <FirewallRule> record."""
    if (name := _text(record, "Name")) is None:
        return None
    return FirewallRule(
        name=name,
        enabled=_equals(_text(record, "Status"), "enable"),
        # SFOS 22 nests the action in the policy-type block.
        action=_text(record, "Action")
        or _text(_path(record, "NetworkPolicy"), "Action")
        or _text(_path(record, "UserPolicy"), "Action"),
        policy_type=_text(record, "PolicyType"),
        ip_family=_text(record, "IPFamily"),
    )


def parse_web_filter_policy(record: Mapping[str, Any]) -> WebFilterPolicy | None:
    """Parse one <WebFilterPolicy> record."""
    if (name := _text(record, "Name")) is None:
        return None
    return WebFilterPolicy(name=name, default_action=_text(record, "DefaultAction"))


def parse_dhcp_server(record: Mapping[str, Any]) -> DhcpServer | None:
    """Parse one <DHCPServer> record including its static leases."""
    if (name := _text(record, "Name")) is None:
        return None
    raw = record.get("StaticLease", [])
    raw_leases = [raw] if isinstance(raw, Mapping) else raw if isinstance(raw, list) else []
    leases: list[dict[str, str]] = []
    for lease in raw_leases:
        if not isinstance(lease, Mapping):
            continue
        normalised = {k: v for k, v in lease.items() if isinstance(v, str)}
        if "MACAddress" in normalised:
            normalised["MACAddress"] = normalised["MACAddress"].lower()
        leases.append(normalised)
    status = _text(record, "Status")
    return DhcpServer(
        name=name,
        running=None if status is None else status == "1",
        interface=_text(record, "Interface"),
        lease_time=_text(record, "LeaseTime"),
        static_leases=tuple(leases),
    )


def parse_backup(record: Mapping[str, Any]) -> BackupSettings:
    """Parse the <BackupRestore> record."""
    schedule = _path(record, "ScheduleBackup")
    return BackupSettings(
        mode=_text(schedule, "BackupMode"),
        frequency=_text(schedule, "BackupFrequency"),
    )


def parse_admin(record: Mapping[str, Any]) -> AdminSettings:
    """Parse the <AdminSettings> record."""
    return AdminSettings(hostname=_text(_path(record, "HostnameSettings"), "HostName"))


# ── Client ────────────────────────────────────────────────────────────────────


class SophosClient:
    """Thin async client for the Sophos Firewall XML API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        port: int,
        username: str,
        password: str,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._session = session
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._url = f"https://{host}:{port}{XML_API_PATH}"
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._semaphore = asyncio.Semaphore(XML_MAX_CONCURRENT_REQUESTS)

    # ── Low-level request ─────────────────────────────────────────────────────

    def _login_block(self) -> str:
        """Return the XML Login block with escaped credentials."""
        return (
            "<Login>"
            f"<Username>{_xml_escape(self._username)}</Username>"
            f"<Password>{_xml_escape(self._password)}</Password>"
            "</Login>"
        )

    def _request(self, body: str = "") -> str:
        """Wrap an operation in the standard request envelope."""
        return f"<Request>{self._login_block()}{body}</Request>"

    async def _post(self, xml: str, label: str = "request") -> ET.Element:
        """POST an XML request and return the parsed <Response> element.

        Logs at debug level how long the request waited for its turn
        (XML_MAX_CONCURRENT_REQUESTS) and how long the firewall took.
        """
        queued = time.monotonic()
        started: float | None = None
        outcome = "failed"
        try:
            async with self._semaphore:
                started = time.monotonic()
                async with self._session.post(
                    self._url,
                    data={"reqxml": xml},
                    headers={"Connection": "close"},
                    timeout=self._timeout,
                ) as resp:
                    if resp.status == 403:
                        raise SophosAccessError(
                            f"HTTP 403 from {self._host}: API access forbidden", code="403"
                        )
                    if resp.status not in (200, 201):
                        raise SophosAPIError(
                            f"Unexpected HTTP {resp.status} from {self._host}:{self._port}"
                        )
                    text = await resp.text()
                    outcome = f"{len(text)} bytes"
        except TimeoutError as exc:
            # aiohttp raises the builtin TimeoutError (not a ClientError) when
            # the total timeout expires — it must not escape as a raw exception.
            raise SophosConnectionError(
                f"Timeout talking to {self._host}:{self._port}"
            ) from exc
        except aiohttp.ClientError as exc:
            raise SophosConnectionError(
                f"Cannot talk to {self._host}:{self._port}: {exc}"
            ) from exc
        finally:
            done = time.monotonic()
            _LOGGER.debug(
                "XML %s on %s: waited %.2f s for a slot, request %.2f s (%s)",
                label, self._host, (started or done) - queued,
                done - started if started is not None else 0.0, outcome,
            )

        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise SophosAPIError(f"Invalid XML response: {exc}") from exc

        login_el = root.find("Login/status")
        if login_el is not None:
            status_text = (login_el.text or "").lower()
            if "fail" in status_text or "invalid" in status_text:
                raise SophosAuthError(f"Authentication failed: {login_el.text}")

        # Response-level status (direct child only — nested record-level
        # <Status> elements are handled per record).
        status_el = root.find("Status")
        if status_el is not None:
            code = status_el.get("code", "")
            message = f"(code {code}) {status_el.text or ''}".strip()
            if code in _ACCESS_DENIED_CODES:
                raise SophosAccessError(f"API access denied {message}", code=code)
            if code in _AUTH_FAILED_CODES:
                raise SophosAuthError(f"Authentication failed {message}")
            if code not in _SUCCESS_CODES:
                raise SophosAPIError(f"API request failed {message}")
        return root

    async def _get_records(self, tag: str) -> list[dict[str, Any]]:
        """Fetch all records for an XML tag, skipping per-record errors."""
        root = await self._post(self._request(f"<Get><{tag}/></Get>"), label=f"Get {tag}")
        records: list[dict[str, Any]] = []
        for elem in root.iter(tag):
            status_el = elem.find("Status")
            if status_el is not None and status_el.get("code", "") not in _SUCCESS_CODES:
                _LOGGER.debug(
                    "%s record returned status %s — skipped", tag, status_el.get("code")
                )
                continue
            if record := _elem_to_dict(elem):
                records.append(record)
        return records

    # ── Connection test ───────────────────────────────────────────────────────

    async def test_connection(self) -> str:
        """Verify credentials and connectivity; return the API version."""
        root = await self._post(self._request(), label="login")
        return root.get("APIVersion", "unknown")

    # ── Data fetch methods ────────────────────────────────────────────────────

    async def get_interfaces(self) -> dict[str, Interface]:
        """Return all interfaces keyed by name."""
        return _by_name(parse_interface(r) for r in await self._get_records(XML_TAG_INTERFACE))

    async def get_firewall_rules(self) -> dict[str, FirewallRule]:
        """Return all firewall rules keyed by name."""
        return _by_name(
            parse_firewall_rule(r) for r in await self._get_records(XML_TAG_FIREWALL_RULE)
        )

    async def get_web_filter_policies(self) -> dict[str, WebFilterPolicy]:
        """Return all web filter policies keyed by name."""
        return _by_name(
            parse_web_filter_policy(r) for r in await self._get_records(XML_TAG_WEB_FILTER)
        )

    async def get_dhcp_servers(self) -> dict[str, DhcpServer]:
        """Return all DHCP servers keyed by name."""
        return _by_name(
            parse_dhcp_server(r) for r in await self._get_records(XML_TAG_DHCP_SERVER)
        )

    async def get_backup(self) -> BackupSettings:
        """Return the scheduled-backup configuration."""
        records = await self._get_records(XML_TAG_BACKUP)
        return parse_backup(records[0] if records else {})

    async def get_admin_settings(self) -> AdminSettings:
        """Return administration settings (hostname)."""
        records = await self._get_records(XML_TAG_ADMIN)
        return parse_admin(records[0] if records else {})

    # ── Write methods ─────────────────────────────────────────────────────────

    async def _set(self, tag: str, body: str, *, operation: str = "") -> None:
        """Send a <Set> request and check the record-level status."""
        attr = f' operation="{operation}"' if operation else ""
        root = await self._post(
            self._request(f"<Set{attr}><{tag}>{body}</{tag}></Set>"), label=f"Set {tag}"
        )
        status_el = root.find(f"{tag}/Status")
        if status_el is not None and status_el.get("code", "") not in _SUCCESS_CODES:
            raise SophosAPIError(
                f"Set {tag} failed (code {status_el.get('code')}): {status_el.text or ''}".strip()
            )

    async def set_firewall_rule_status(self, name: str, enable: bool) -> None:
        """Enable or disable a firewall rule by name."""
        status = "Enable" if enable else "Disable"
        await self._set(
            XML_TAG_FIREWALL_RULE,
            f"<Name>{_xml_escape(name)}</Name><Status>{status}</Status>",
        )
        _LOGGER.debug("FirewallRule %r → %s", name, status)

    async def set_web_filter_default_action(self, name: str, allow: bool) -> None:
        """Set the DefaultAction of a web filter policy."""
        action = "Allow" if allow else "Deny"
        await self._set(
            XML_TAG_WEB_FILTER,
            f"<Name>{_xml_escape(name)}</Name><DefaultAction>{action}</DefaultAction>",
        )
        _LOGGER.debug("WebFilterPolicy %r → %s", name, action)

    async def trigger_backup(self) -> None:
        """Trigger an immediate backup without changing the user's settings.

        SFOS has no "run now" endpoint: writing the current BackupRestore
        schedule back unchanged makes the firewall run a backup cycle.
        """
        current = await self.get_backup()
        mode = current.mode or "Mail"
        frequency = current.frequency or "Never"
        await self._set(
            XML_TAG_BACKUP,
            "<ScheduleBackup>"
            f"<BackupMode>{_xml_escape(mode)}</BackupMode>"
            f"<BackupFrequency>{_xml_escape(frequency)}</BackupFrequency>"
            "</ScheduleBackup>",
            operation="add",
        )
        _LOGGER.info("Backup triggered on %s (mode=%s, frequency=%s)", self._host, mode, frequency)


def _by_name[T: (Interface, FirewallRule, WebFilterPolicy, DhcpServer)](
    items: Iterable[T | None],
) -> dict[str, T]:
    """Collect parsed records into a dict keyed by name, dropping None."""
    result: dict[str, T] = {}
    for item in items:
        if item is not None and item.name not in result:
            result[item.name] = item
    return result
