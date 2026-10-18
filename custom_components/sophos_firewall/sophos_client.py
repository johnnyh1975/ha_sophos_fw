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
import contextlib
import logging
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as _xml_escape

import aiohttp

from .const import (
    DEFAULT_TIMEOUT,
    XML_API_PATH,
    XML_MAX_CONCURRENT_REQUESTS,
    XML_TAG_ADMIN,
    XML_TAG_IP_HOST,
    XML_TAG_IP_HOST_GROUP,
    XML_TAG_URL_GROUP,
    XML_TAG_WIRELESS_NETWORKS,
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
    WirelessNetwork,
)

_LOGGER = logging.getLogger(__name__)

# Response-level <Status> codes that are no error. Only for that element:
# a write is confirmed by an explicit 2xx code, see _is_success().
_RESPONSE_OK_CODES = frozenset({"200", "201", "202", ""})
_ACCESS_DENIED_CODES = frozenset({"532", "534"})
_AUTH_FAILED_CODES = frozenset({"535"})


def _is_success(code: str) -> bool:
    """A write succeeded only with an explicit 2xx code (SDK: any 2xx)."""
    return len(code) == 3 and code.isdigit() and code.startswith("2")


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


class SophosNotFoundError(SophosAPIError):
    """The named record does not exist on the firewall."""


class SophosWriteError(SophosAPIError):
    """A write the firewall rejected, with its record-level status code.

    Codes (SFOS API documentation, "Status Code and Description"): 502 same
    name exists, 522-525 maximum limit reached, 526 record does not exist,
    528 default entity not editable, 599 no privilege.
    """

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


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


def _child_ci(elem: ET.Element, tag: str) -> ET.Element | None:
    """Direct child by tag, ignoring case (SFOS spells some tags both ways)."""
    wanted = tag.lower()
    return next((child for child in elem if child.tag.lower() == wanted), None)


def _child_text(elem: ET.Element, tag: str) -> str | None:
    """Stripped text of a direct child, or None."""
    child = elem.find(tag)
    if child is None or child.text is None:
        return None
    return child.text.strip() or None


def _is_status_only(elem: ET.Element) -> bool:
    """True for a record element that carries only a <Status>.

    That is a per-record error (<Status code="529">…) or the empty-result
    marker, which has no code: <Status>Number of records Zero.</Status>
    (Sophos SDK test fixtures). A real record has fields besides Status.
    """
    children = list(elem)
    return len(children) == 1 and children[0].tag == "Status"


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


def _minutes(record: Mapping[str, Any], key: str) -> int | None:
    """Return a whole number of minutes, or None if missing or not a number."""
    value = _text(record, key)
    return int(value) if value is not None and value.isdigit() else None


def parse_dhcp_server(record: Mapping[str, Any]) -> DhcpServer | None:
    """Parse one <DHCPServer> record including its static leases.

    SFOS wraps every static MAC-IP mapping in its own element::

        <StaticLease>
          <Lease><HostName>…</HostName><MACAddress>…</MACAddress><IPAddress>…</IPAddress></Lease>
          <Lease>…</Lease>
        </StaticLease>

    so ``StaticLease`` arrives as ``{"Lease": {...}}`` (one mapping) or
    ``{"Lease": [{...}, ...]}`` (several), and as "" when there are none.
    Up to v1.1.0 the leases were expected directly under ``StaticLease``: all
    mappings of a server then counted as one lease without fields (#29).
    The lease times are DefaultLeaseTime and MaxLeaseTime, in minutes.
    """
    if (name := _text(record, "Name")) is None:
        return None
    container = record.get("StaticLease")
    raw = container.get("Lease", []) if isinstance(container, Mapping) else []
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
        default_lease_time=_minutes(record, "DefaultLeaseTime"),
        max_lease_time=_minutes(record, "MaxLeaseTime"),
        static_leases=tuple(leases),
    )


def parse_backup(record: Mapping[str, Any]) -> BackupSettings:
    """Parse the <BackupRestore> record."""
    schedule = _path(record, "ScheduleBackup")
    return BackupSettings(
        mode=_text(schedule, "BackupMode"),
        frequency=_text(schedule, "BackupFrequency"),
    )


def parse_wireless_network(record: Mapping[str, Any]) -> WirelessNetwork | None:
    """Parse one <WirelessNetworks> record (keyed by HardwareName, e.g. wlnet1)."""
    if (hardware := _text(record, "HardwareName")) is None:
        return None
    return WirelessNetwork(
        hardware_name=hardware,
        name=_text(record, "Name") or hardware,
        ssid=_text(record, "SSID"),
        enabled=_equals(_text(record, "Status"), "enable"),
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

    async def _post(self, xml: str, label: str = "request", *, slot_held: bool = False) -> ET.Element:
        """POST an XML request and return the parsed <Response> element.

        Logs at debug level how long the request waited for its turn
        (XML_MAX_CONCURRENT_REQUESTS) and how long the firewall took.
        ``slot_held``: the caller already holds the request slot (a read and
        the write that depends on it must not let other requests in between).
        """
        queued = time.monotonic()
        started: float | None = None
        outcome = "failed"
        slot: contextlib.AbstractAsyncContextManager[Any] = (
            contextlib.nullcontext() if slot_held else self._semaphore
        )
        try:
            async with slot:
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
            if code not in _RESPONSE_OK_CODES:
                raise SophosAPIError(f"API request failed {message}")
        return root

    async def _get_records(self, tag: str) -> list[dict[str, Any]]:
        """Fetch all records for an XML tag, skipping per-record errors."""
        root = await self._post(self._request(f"<Get><{tag}/></Get>"), label=f"Get {tag}")
        records: list[dict[str, Any]] = []
        for elem in root.iter(tag):
            if _is_status_only(elem):
                continue
            if record := _elem_to_dict(elem):
                records.append(record)
        return records

    async def _get_record_elements(self, tag: str) -> list[ET.Element]:
        """Fetch all records of a tag unparsed (per-record errors skipped)."""
        root = await self._post(self._request(f"<Get><{tag}/></Get>"), label=f"Get {tag}")
        return [elem for elem in root.iter(tag) if not _is_status_only(elem)]

    async def _get_record_element(self, tag: str, name: str) -> ET.Element:
        """Fetch one record as the firewall sent it, unparsed (slot held by caller)."""
        root = await self._post(
            self._request(f"<Get><{tag}/></Get>"), label=f"Get {tag}", slot_held=True
        )
        error: ET.Element | None = None
        for elem in root.iter(tag):
            if _is_status_only(elem):
                status = elem.find("Status")
                if status is not None and status.get("code"):
                    error = status
                continue
            if (elem.findtext("Name") or "").strip() == name:
                return elem
        if error is not None:
            raise SophosAPIError(
                f"Reading {tag} failed (code {error.get('code')}): {error.text or ''}".strip()
            )
        raise SophosNotFoundError(f"{tag} {name!r} not found on the firewall")

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

    def _confirm(self, root: ET.Element, what: str, *paths: str) -> None:
        """Raise unless the answer confirms the write with a 2xx code.

        The status sits under the entity element (Response/<Tag>/Status); a
        few writes answer elsewhere (IPsec actions), hence several paths.
        """
        status_el = next(
            (el for path in paths if (el := root.find(path)) is not None), None
        )
        if status_el is None:
            raise SophosAPIError(f"{what}: the firewall did not confirm the change")
        code = status_el.get("code", "")
        if not _is_success(code):
            params = " ".join(p.text or "" for p in root.iter("Params")).strip()
            detail = f"{status_el.text or ''} {params}".strip()
            raise SophosWriteError(f"{what} failed (code {code or '?'}): {detail}", code=code)

    async def _modify_record(
        self,
        tag: str,
        name: str,
        change: Callable[[ET.Element], bool],
        verify: Callable[[ET.Element], bool] | None = None,
    ) -> None:
        """Read one record unparsed, let ``change`` edit it, write it all back.

        ``change`` returns False when there is nothing to write (e.g. the URL
        is already in the group); then no Set is sent.
        """
        async with self._semaphore:
            await self._modify_record_held(tag, name, change, verify)

    async def _modify_record_held(
        self,
        tag: str,
        name: str,
        change: Callable[[ET.Element], bool],
        verify: Callable[[ET.Element], bool] | None = None,
    ) -> None:
        """``_modify_record`` for a caller that already holds the request slot.

        ``verify`` (group memberships) reads the record again after the
        write and checks that the change is really there: an answer of 200
        alone does not prove that SFOS applied an update the way it was
        sent (e.g. when the last member is removed). If the change is not
        visible the write counts as failed.
        """
        elem = await self._get_record_element(tag, name)
        if not change(elem):
            return
        body = ET.tostring(elem, encoding="unicode")
        root = await self._post(
            self._request(f'<Set operation="update">{body}</Set>'),
            label=f"Set {tag}", slot_held=True,
        )
        self._confirm(root, f"Set {tag} {name!r}", f"{tag}/Status")
        if verify is None:
            return
        try:
            after = await self._get_record_element(tag, name)
        except SophosError as err:
            _LOGGER.warning("Could not read %s %r back after the change: %s", tag, name, err)
            return
        if not verify(after):
            raise SophosWriteError(
                f"{tag} {name!r}: the firewall confirmed the change, "
                "but reading it back shows it was not applied",
                code="not_applied",
            )

    async def _update_field(self, tag: str, name: str, field: str, value: str) -> None:
        """Change one field of a record and write the whole record back.

        SFOS updates replace the object: the API documentation marks fields
        such as a rule's PolicyType and Position or a web filter policy's
        DownloadFileSizeRestriction as mandatory, and Sophos staff and
        partners state that an update must contain every element of the
        object. Up to v1.1.0 only Name and the changed field were sent.
        The record is therefore read unparsed and sent back as the firewall
        delivered it, with nothing but this one field changed — the same
        read-modify-write as Sophos' SDK, without re-building the object
        from a template that knows only some of its fields.
        """
        # One slot for read and write (in _modify_record): a poll queued in
        # between would let an edit made in the web admin meanwhile be
        # overwritten by our copy.
        def change(elem: ET.Element) -> bool:
            target = elem.find(field)
            if target is None:
                raise SophosAPIError(f"{tag} {name!r} has no <{field}> element")
            target.text = value
            return True

        await self._modify_record(tag, name, change)

    async def set_firewall_rule_status(self, name: str, enable: bool) -> None:
        """Enable or disable a firewall rule by name."""
        status = "Enable" if enable else "Disable"
        await self._update_field(XML_TAG_FIREWALL_RULE, name, "Status", status)
        _LOGGER.debug("FirewallRule %r → %s", name, status)

    async def set_web_filter_default_action(self, name: str, allow: bool) -> None:
        """Set the DefaultAction of a web filter policy."""
        action = "Allow" if allow else "Deny"
        await self._update_field(XML_TAG_WEB_FILTER, name, "DefaultAction", action)
        _LOGGER.debug("WebFilterPolicy %r → %s", name, action)

    # ── URL groups: block / unblock a site ────────────────────────────────────

    async def set_url_in_group(self, group: str, url: str, present: bool) -> bool:
        """Add a domain to a web filter URL group, or remove it.

        Real shape (Sophos SDK functional test, Ansible integration tests):
        <WebFilterURLGroup><Name/><Description/><IsDefault>No</IsDefault>
        <URLlist><URL>a.com</URL>…</URLlist></WebFilterURLGroup>; URLlist is
        missing when the group is empty, and its tag case varies
        ("URLlist"/"URLList"), so it is matched case-insensitively and
        written back as read. Returns False if nothing had to change.
        """
        wanted = url.strip().lower()
        changed = True

        def urls(elem: ET.Element) -> list[ET.Element]:
            url_list = _child_ci(elem, "URLlist")
            if url_list is None:
                return []
            return [
                e for e in url_list
                if e.tag.lower() == "url" and (e.text or "").strip().lower() == wanted
            ]

        def change(elem: ET.Element) -> bool:
            nonlocal changed
            if (_child_text(elem, "IsDefault") or "No").lower() != "no":
                raise SophosWriteError(
                    f"URL group {group!r} is a built-in group and cannot be edited", code="528"
                )
            url_list = _child_ci(elem, "URLlist")
            existing = urls(elem)
            if present:
                changed = not existing
                if changed:
                    if url_list is None:
                        url_list = ET.SubElement(elem, "URLlist")
                    ET.SubElement(url_list, "URL").text = wanted
                return changed
            changed = bool(existing) and url_list is not None
            if changed and url_list is not None:
                for entry in existing:
                    url_list.remove(entry)
                if not len(url_list):  # an empty group has no URLlist (SDK, Ansible)
                    elem.remove(url_list)
            return changed

        await self._modify_record(
            XML_TAG_URL_GROUP, group, change, verify=lambda e: bool(urls(e)) == present
        )
        return changed

    # ── IP host groups: block / unblock a device ──────────────────────────────

    async def _ip_hosts_held(self, ip: str) -> list[str]:
        """Names of all IPHosts (HostType IP) with this address (slot held)."""
        root = await self._post(
            self._request(f"<Get><{XML_TAG_IP_HOST}/></Get>"),
            label=f"Get {XML_TAG_IP_HOST}", slot_held=True,
        )
        return [
            name
            for elem in root.iter(XML_TAG_IP_HOST)
            if not _is_status_only(elem)
            and (_child_text(elem, "HostType") or "") == "IP"
            and (_child_text(elem, "IPAddress") or "") == ip
            and (name := _child_text(elem, "Name"))
        ]

    @staticmethod
    def _host_members(elem: ET.Element) -> list[str]:
        host_list = elem.find("HostList")
        if host_list is None:
            return []
        return [(e.text or "").strip() for e in host_list.findall("Host")]

    @staticmethod
    def _check_ipv4_group(elem: ET.Element, group: str) -> None:
        if (_child_text(elem, "IPFamily") or "IPv4") != "IPv4":
            raise SophosWriteError(f"IP host group {group!r} is not an IPv4 group")

    async def block_ip_in_group(self, group: str, ip: str, name: str) -> tuple[bool, str]:
        """Put the device with ``ip`` into an IP host group; return (changed, host).

        An IPHost with that address is reused whatever its name; otherwise
        one named ``name`` is created. Everything runs in one request slot:
        the group is checked first (so a wrong group name leaves no new
        host behind), and two calls for the same address cannot both
        create the host.

        The documented and tested way to change a group (Sophos SDK, Ansible
        integration tests) is to update it with its complete HostList.
        """
        async with self._semaphore:
            group_elem = await self._get_record_element(XML_TAG_IP_HOST_GROUP, group)
            self._check_ipv4_group(group_elem, group)
            hosts = await self._ip_hosts_held(ip)
            members = self._host_members(group_elem)
            if member := next((h for h in hosts if h in members), None):
                return False, member
            host = hosts[0] if hosts else await self._add_ip_host_held(ip, name)

            def change(elem: ET.Element) -> bool:
                self._check_ipv4_group(elem, group)
                if host in self._host_members(elem):
                    return False
                host_list = elem.find("HostList")
                if host_list is None:
                    host_list = ET.Element("HostList")
                    # keep the documented element order: HostList before IPFamily
                    family = elem.find("IPFamily")
                    index = list(elem).index(family) if family is not None else len(elem)
                    elem.insert(index, host_list)
                ET.SubElement(host_list, "Host").text = host
                return True

            await self._modify_record_held(
                XML_TAG_IP_HOST_GROUP, group, change,
                verify=lambda e: host in self._host_members(e),
            )
        return True, host

    async def unblock_ip_in_group(self, group: str, ip: str) -> tuple[bool, list[str]]:
        """Take every IPHost with ``ip`` out of an IP host group.

        Returns (changed, removed host names). The hosts themselves stay:
        they may be used elsewhere. An empty group has no HostList element
        (XSOAR recording of a real firewall).
        """
        removed: list[str] = []
        async with self._semaphore:
            hosts = set(await self._ip_hosts_held(ip))

            def change(elem: ET.Element) -> bool:
                self._check_ipv4_group(elem, group)
                host_list = elem.find("HostList")
                if host_list is None:
                    return False
                for entry in host_list.findall("Host"):
                    if (entry.text or "").strip() in hosts:
                        removed.append((entry.text or "").strip())
                        host_list.remove(entry)
                if not removed:
                    return False
                if not len(host_list):
                    elem.remove(host_list)
                return True

            await self._modify_record_held(
                XML_TAG_IP_HOST_GROUP, group, change,
                verify=lambda e: not hosts.intersection(self._host_members(e)),
            )
        return bool(removed), removed

    async def _add_ip_host_held(self, ip: str, name: str) -> str:
        """Create an IPHost (HostType IP) for ``ip`` named ``name`` (slot held)."""
        root = await self._post(
            self._request(
                '<Set operation="add"><IPHost>'
                f"<Name>{_xml_escape(name)}</Name><IPFamily>IPv4</IPFamily>"
                f"<HostType>IP</HostType><IPAddress>{_xml_escape(ip)}</IPAddress>"
                "<Description>Created by Home Assistant</Description>"
                "</IPHost></Set>"
            ),
            label="Set IPHost", slot_held=True,
        )
        try:
            self._confirm(root, f"Add IP host {name!r}", "IPHost/Status")
        except SophosWriteError as err:
            if err.code == "502":  # "same name exists" — used for another address
                raise SophosWriteError(
                    f"An IP host named {name!r} already exists with another address",
                    code="502",
                ) from err
            raise
        return name

    # ── Wireless networks (untested: no appliance with wireless available) ────

    async def get_wireless_networks(self) -> dict[str, WirelessNetwork]:
        """Return the wireless networks keyed by their HardwareName.

        Fields per the Add/Update Wireless Network page (HardwareName, Name,
        SSID) and a third-party module (Status Enable/Disable on a Get).
        """
        networks: dict[str, WirelessNetwork] = {}
        for record in await self._get_records(XML_TAG_WIRELESS_NETWORKS):
            if network := parse_wireless_network(record):
                networks.setdefault(network.hardware_name, network)
        return networks

    async def set_wireless_network_status(self, hardware_name: str, enable: bool) -> None:
        """Switch a wireless network on or off.

        <WirelessNetworkStatus> with the network's HardwareName (API docs:
        "Enter the name of Interface", max 10 characters; Status "Enable",
        "Disable"). The display name is rejected (526).
        """
        status = "Enable" if enable else "Disable"
        root = await self._post(
            self._request(
                '<Set operation="update"><WirelessNetworkStatus>'
                f"<Name>{_xml_escape(hardware_name)}</Name><Status>{status}</Status>"
                "</WirelessNetworkStatus></Set>"
            ),
            label="Set WirelessNetworkStatus",
        )
        self._confirm(root, f"Wireless network {hardware_name!r}", "WirelessNetworkStatus/Status")

    # ── IPsec (untested: no appliance with IPsec available) ───────────────────

    async def set_ipsec_connection_active(self, name: str, active: bool) -> None:
        """Activate or deactivate an IPsec connection.

        <VPNIPSecConnection><Active|DeActive><Name/></…> needs only the name
        (Sophos support in the Sophos Community, thread 142169; the Sophos
        Ansible collection sends the same elements). Where the answer puts
        its status is not documented, hence the several paths.
        """
        action = "Active" if active else "DeActive"
        root = await self._post(
            self._request(
                f'<Set operation="update"><VPNIPSecConnection><{action}>'
                f"<Name>{_xml_escape(name)}</Name>"
                f"</{action}></VPNIPSecConnection></Set>"
            ),
            label=f"Set VPNIPSecConnection {action}",
        )
        self._confirm(
            root, f"IPsec connection {name!r}",
            f"VPNIPSecConnection/{action}/Status", "VPNIPSecConnection/Status",
            f"{action}/Status", "Configuration/Status",
        )


def _by_name[T: (Interface, FirewallRule, WebFilterPolicy, DhcpServer)](
    items: Iterable[T | None],
) -> dict[str, T]:
    """Collect parsed records into a dict keyed by name, dropping None."""
    result: dict[str, T] = {}
    for item in items:
        if item is not None and item.name not in result:
            result[item.name] = item
    return result
