"""Async wrapper around the Sophos Firewall XML API.

The Sophos XML API is a synchronous HTTP POST endpoint that accepts XML
request payloads and returns XML responses.  We use aiohttp directly
(no third-party SDK dependency) so the event loop is never blocked.

Connection strategy
-------------------
The Sophos XML API cannot handle many simultaneous TCP connections.
Production logs showed consistent ~10s timeouts when 7 requests were fired
in parallel via asyncio.gather() — always a different endpoint, proving it
is a connection-backlog issue on the firewall side, not a slow endpoint.

We address this with two complementary measures:

1. **Persistent TCPConnector** (limit_per_host=2):
   A single aiohttp session with a bounded TCPConnector is created once and
   reused across all poll cycles. ``force_close=True`` closes the connection
   after each request (required because the Sophos firewall drops idle
   connections). Each request therefore pays a new TCP handshake (~5ms on LAN)
   but avoids "Server disconnected" errors from stale Keep-Alive sockets.

2. **Semaphore in the coordinator** (max 2 concurrent):
   Even with Keep-Alive, we never send more than 2 requests simultaneously,
   so the firewall's connection queue is never overwhelmed.

All public methods return plain Python dicts or lists of dicts.
Callers never see raw XML.
"""
from __future__ import annotations

import logging
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as _xml_escape

import aiohttp

from .const import DEFAULT_PORT, DEFAULT_TIMEOUT, XML_TAG_FIREWALL_RULE

_LOGGER = logging.getLogger(__name__)

_API_PATH = "/webconsole/APIController"

# Maximum simultaneous TCP connections to the Sophos firewall.
# With lazy loading the background refresh runs after TLS is established
# (via the connectivity-check request in async_setup_entry). Two concurrent
# Keep-Alive requests on the same socket are reliable; the previous timeouts
# were caused by 7 parallel cold TLS handshakes, not by 2 warm requests.
_MAX_CONNECTIONS = 2


class SophosAuthError(Exception):
    """Raised when the firewall rejects credentials or denies API access.

    Triggered by:
    - Login/status text containing "fail"/"invalid" (wrong credentials)
    - HTTP 403 (API access permission denied)
    - Response-level Status code 532 (API not enabled), 534 (IP not in
      API access list), or 535 (authentication/authorization failure)
    """


class SophosAPIError(Exception):
    """Raised for any non-auth API failure."""


class SophosClient:
    """Thin async client for the Sophos Firewall XML API.

    Maintains a persistent aiohttp session with a bounded TCPConnector so
    that TCP+TLS connections are reused across poll cycles and the number of
    simultaneous connections to the firewall is capped.

    Usage::

        client = SophosClient(host, port, user, password)
        await client.open()
        try:
            interfaces = await client.get_interfaces()
        finally:
            await client.close()

    Or as a context manager::

        async with SophosClient(host, port, user, password) as client:
            interfaces = await client.get_interfaces()
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        verify_ssl: bool = True,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._url = f"https://{host}:{port}{_API_PATH}"
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._ssl: bool | None = None if verify_ssl else False
        self._session: aiohttp.ClientSession | None = None
        self._connector: aiohttp.TCPConnector | None = None

    # ── Session lifecycle ─────────────────────────────────────────────────────

    async def open(self) -> None:
        """Create the persistent session with a bounded connection pool.

        Called once by the coordinator on setup. The session and connector
        are reused across all poll cycles. force_close=True means each
        request uses a new TCP connection — required to avoid stale-socket
        errors from the firewall dropping idle Keep-Alive connections.
        """
        self._connector = aiohttp.TCPConnector(
            limit=_MAX_CONNECTIONS,
            limit_per_host=_MAX_CONNECTIONS,
            # force_close=True: close the connection after each request.
            # The Sophos firewall drops idle Keep-Alive connections after
            # a short timeout (observed: "Server disconnected" errors on the
            # second poll cycle). force_close avoids using stale connections
            # at the cost of a new TCP handshake per request (~5ms on LAN).
            force_close=True,
            enable_cleanup_closed=True,
            ssl=self._ssl,
        )
        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=self._timeout,
            connector_owner=True,  # session owns connector — closed together
        )
        _LOGGER.debug(
            "SophosClient session opened for %s (max %d connections)",
            self._host, _MAX_CONNECTIONS,
        )

    async def close(self) -> None:
        """Close the session and underlying connector, releasing all sockets.

        Tolerant of errors during close — a failure here must never prevent
        the config entry from unloading cleanly. The session reference is
        cleared regardless so a subsequent open() starts fresh.
        """
        if self._session is not None:
            try:
                await self._session.close()
            except Exception as exc:  # noqa: BLE001 — close failures are non-fatal
                _LOGGER.debug("Error closing SophosClient session for %s: %s", self._host, exc)
            finally:
                self._session = None
                self._connector = None
                _LOGGER.debug("SophosClient session closed for %s", self._host)

    async def __aenter__(self) -> "SophosClient":
        await self.open()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    async def _ensure_session(self) -> aiohttp.ClientSession:
        """Return the active session, creating one lazily if needed."""
        if self._session is None:
            await self.open()
        return self._session  # type: ignore[return-value]

    # ── Low-level request ─────────────────────────────────────────────────────

    def _login_block(self) -> str:
        """Return the XML Login block with escaped credentials.

        Centralises credential escaping — all XML payloads use this
        instead of inline f-strings with self._username/_password.
        """
        return (
            f"<Login>"
            f"<Username>{_xml_escape(self._username)}</Username>"
            f"<Password>{_xml_escape(self._password)}</Password>"
            f"</Login>"
        )

    def _build_request(self, operation: str, tag: str, body: str = "") -> str:
        """Wrap an API operation in the standard Sophos XML envelope."""
        return (
            f"<Request>"
            f"{self._login_block()}"
            f"<{operation}><{tag}{body}/></{operation}>"
            f"</Request>"
        )

    async def _post(self, xml: str) -> ET.Element:
        """POST raw XML and return the parsed <Response> element.

        The ssl parameter is configured on the connector, so individual
        requests do not need to pass it again.

        Raises:
            SophosAuthError: On status code 535 (wrong credentials).
            SophosAPIError:  On any other non-success status or network error.
        """
        session = await self._ensure_session()
        try:
            async with session.post(
                self._url,
                data={"reqxml": xml},
            ) as resp:
                if resp.status == 403:
                    raise SophosAuthError(f"HTTP 403 Forbidden from {self._host} — check API access permissions")
                if resp.status not in (200, 201):
                    raise SophosAPIError(
                        f"Unexpected HTTP {resp.status} from {self._host}:{self._port}"
                    )
                text = await resp.text()
        except aiohttp.ClientConnectorError as exc:
            raise SophosAPIError(f"Cannot connect to {self._host}:{self._port}: {exc}") from exc
        except aiohttp.ClientError as exc:
            raise SophosAPIError(f"HTTP error: {exc}") from exc

        try:
            root = ET.fromstring(text)
        except ET.ParseError as exc:
            raise SophosAPIError(f"Invalid XML response: {exc}") from exc

        # Check top-level login status
        login_el = root.find("Login/status")
        if login_el is not None:
            status_text = (login_el.text or "").lower()
            if "fail" in status_text or "invalid" in status_text:
                raise SophosAuthError(f"Authentication failed: {login_el.text}")

        # Check response-level Status element. Sophos reports certain request
        # rejections here (not in Login/status):
        #   532 = API access not enabled on the firewall
        #   534 = client IP not in the API Access List
        #   535 = authentication/authorization failure
        # These otherwise slip through as an empty/zero-record response.
        status_el = root.find("Status")
        if status_el is not None:
            code = status_el.get("code", "")
            if code in ("532", "534", "535"):
                # 535 is auth-class; 532/534 are access-policy errors. Both
                # mean the request will never succeed until the admin fixes
                # firewall config, so surface them as auth errors to trigger
                # the reauth/repair path rather than silent empty data.
                raise SophosAuthError(
                    f"API access denied (code {code}): {status_el.text or ''}".strip()
                )
            if code and code not in ("200", "201"):
                raise SophosAPIError(
                    f"API request failed (code {code}): {status_el.text or ''}".strip()
                )

        return root

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _elem_to_dict(element: ET.Element) -> dict[str, Any]:
        """Recursively convert an XML element to a nested dict."""
        result: dict[str, Any] = {}
        for child in element:
            tag = child.tag
            if len(child):
                value: Any = SophosClient._elem_to_dict(child)
            else:
                value = child.text or ""
            if tag in result:
                # Multiple sibling elements with the same tag → list
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(value)
            else:
                result[tag] = value
        return result

    async def _get_tag(self, tag: str) -> list[dict[str, Any]]:
        """Fetch all records for a given XML tag.

        Returns an empty list when the firewall reports zero records.
        """
        xml = self._build_request("Get", tag)
        root = await self._post(xml)

        records: list[dict[str, Any]] = []
        for elem in root.iter(tag):
            # Skip status-only elements (e.g. <Interface><Status code="529"/></Interface>).
            # A status code other than success on an individual element means
            # that one record is unavailable — skip just that element rather
            # than discarding every record fetched in the same response.
            status_el = elem.find("Status")
            if status_el is not None and status_el.get("code"):
                code = status_el.get("code", "")
                if code not in ("200", "201", ""):
                    _LOGGER.debug(
                        "Tag %s element returned status %s — skipping this record",
                        tag, code,
                    )
                    continue
            d = self._elem_to_dict(elem)
            if d:
                records.append(d)
        return records

    # ── Connection test ───────────────────────────────────────────────────────

    async def test_connection(self) -> str:
        """Verify credentials and connectivity.

        Returns:
            The API version string (e.g. "2200.1").

        Raises:
            SophosAuthError: On authentication failure.
            SophosAPIError:  On connection or parse errors.
        """
        xml = (
            f"<Request>"
            f"{self._login_block()}"
            f"</Request>"
        )
        root = await self._post(xml)
        return root.get("APIVersion", "unknown")

    # ── Data fetch methods ────────────────────────────────────────────────────

    async def get_interfaces(self) -> list[dict[str, Any]]:
        """Return all network interfaces with status, zone, IP, and speed."""
        return await self._get_tag("Interface")

    async def get_zones(self) -> list[dict[str, Any]]:
        """Return all network zones with their enabled services."""
        return await self._get_tag("Zone")

    async def get_firewall_rules(self) -> list[dict[str, Any]]:
        """Return all firewall rules with name, status (Enable/Disable), and action."""
        return await self._get_tag(XML_TAG_FIREWALL_RULE)

    async def get_web_filter_policies(self) -> list[dict[str, Any]]:
        """Return all web filter policies with DefaultAction (Allow/Deny)."""
        return await self._get_tag("WebFilterPolicy")

    async def get_dhcp_servers(self) -> list[dict[str, Any]]:
        """Return all DHCP server instances with status and static leases."""
        return await self._get_tag("DHCPServer")

    async def get_backup(self) -> dict[str, Any]:
        """Return backup schedule configuration."""
        records = await self._get_tag("BackupRestore")
        return records[0] if records else {}

    async def get_admin_settings(self) -> dict[str, Any]:
        """Return administration settings including hostname."""
        records = await self._get_tag("AdminSettings")
        return records[0] if records else {}

    # ── Write methods (require write_access=True in config) ───────────────────

    async def set_firewall_rule_status(self, name: str, enable: bool) -> None:
        """Enable or disable a firewall rule by name.

        Args:
            name:   Exact rule name as returned by get_firewall_rules().
            enable: True to enable, False to disable.

        Raises:
            SophosAPIError: If the update fails.
        """
        status = "Enable" if enable else "Disable"
        xml = (
            f"<Request>"
            f"{self._login_block()}"
            f"<Set>"
            f"<FirewallRule>"
            f"<Name>{_xml_escape(name)}</Name>"
            f"<Status>{_xml_escape(status)}</Status>"
            f"</FirewallRule>"
            f"</Set>"
            f"</Request>"
        )
        root = await self._post(xml)
        status_el = root.find(f"FirewallRule/Status")
        if status_el is not None:
            code = status_el.get("code", "200")
            if code not in ("200", ""):
                raise SophosAPIError(
                    f"set_firewall_rule_status({name!r}) failed: {status_el.text}"
                )
        _LOGGER.debug("FirewallRule %r → %s", name, status)

    async def set_web_filter_default_action(self, name: str, allow: bool) -> None:
        """Toggle the DefaultAction of a web filter policy.

        Args:
            name:  Exact policy name.
            allow: True for Allow, False for Deny.

        Raises:
            SophosAPIError: If the update fails.
        """
        action = "Allow" if allow else "Deny"
        xml = (
            f"<Request>"
            f"{self._login_block()}"
            f"<Set>"
            f"<WebFilterPolicy>"
            f"<Name>{_xml_escape(name)}</Name>"
            f"<DefaultAction>{_xml_escape(action)}</DefaultAction>"
            f"</WebFilterPolicy>"
            f"</Set>"
            f"</Request>"
        )
        root = await self._post(xml)
        status_el = root.find("WebFilterPolicy/Status")
        if status_el is not None:
            code = status_el.get("code", "200")
            if code not in ("200", ""):
                raise SophosAPIError(
                    f"set_web_filter_default_action({name!r}) failed: {status_el.text}"
                )
        _LOGGER.debug("WebFilterPolicy %r → DefaultAction %s", name, action)

    async def trigger_backup(self) -> None:
        """Trigger an immediate backup without overwriting user-configured settings.

        Sophos has no dedicated "run now" endpoint. The trigger mechanism is to
        write the existing BackupRestore config back unchanged — this signals the
        firewall to run a backup cycle immediately without modifying BackupMode,
        BackupFrequency, or any other user setting.

        Raises:
            SophosAPIError: If reading current config or writing back fails.
        """
        # Read current backup configuration
        current = await self.get_backup()
        schedule = current.get("ScheduleBackup", {})
        mode = schedule.get("BackupMode", "Mail")
        frequency = schedule.get("BackupFrequency", "Never")

        # Write the same values back to trigger an immediate backup cycle
        xml = (
            f"<Request>"
            f"{self._login_block()}"
            f"<Set operation=\"add\">"
            f"<BackupRestore>"
            f"<ScheduleBackup>"
            f"<BackupMode>{_xml_escape(mode)}</BackupMode>"
            f"<BackupFrequency>{_xml_escape(frequency)}</BackupFrequency>"
            f"</ScheduleBackup>"
            f"</BackupRestore>"
            f"</Set>"
            f"</Request>"
        )
        root = await self._post(xml)
        # _post() already raises on response-level Status errors (532/534/535
        # and other non-2xx codes). Additionally check the BackupRestore-specific
        # status so a rejected backup (e.g. BackupMode=Mail with no mail server
        # configured) surfaces as an error instead of a silent success.
        status_el = root.find("BackupRestore/Status")
        if status_el is not None:
            code = status_el.get("code", "200")
            if code not in ("200", "201", ""):
                raise SophosAPIError(
                    f"trigger_backup failed (code {code}): {status_el.text or ''}".strip()
                )
        _LOGGER.info("Sophos Firewall backup triggered (mode=%s, frequency=%s)", mode, frequency)

