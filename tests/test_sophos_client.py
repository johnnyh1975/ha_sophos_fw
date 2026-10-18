"""SophosClient against the fake XML API."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

import aiohttp
import pytest
from homeassistant.core import HomeAssistant

from custom_components.sophos_firewall.models import (
    AdminSettings,
    BackupSettings,
    DhcpServer,
    FirewallRule,
    Interface,
    WebFilterPolicy,
)
from custom_components.sophos_firewall.sophos_client import (
    SophosAccessError,
    SophosAPIError,
    SophosAuthError,
    SophosClient,
    SophosConnectionError,
    parse_dhcp_server,
    parse_interface,
)
from pytest_homeassistant_custom_component.test_util.aiohttp import AiohttpClientMocker

from .fake_sophos import HOST, PASSWORD, PORT, USERNAME, FakeSophosApi


@pytest.fixture
async def session(
    hass: HomeAssistant, aioclient_mock: AiohttpClientMocker
) -> AsyncGenerator[aiohttp.ClientSession]:
    session = aioclient_mock.create_session(hass.loop)
    yield session
    await session.close()


@pytest.fixture
def client(session: aiohttp.ClientSession, xml_api: FakeSophosApi) -> SophosClient:
    return SophosClient(session, HOST, PORT, USERNAME, PASSWORD)


async def test_test_connection_returns_api_version(client: SophosClient) -> None:
    assert await client.test_connection() == "2200.1"


async def test_every_request_closes_the_connection(
    client: SophosClient, aioclient_mock: AiohttpClientMocker
) -> None:
    """The firewall drops idle keep-alive sockets — never reuse one."""
    await client.get_interfaces()
    await client.get_firewall_rules()
    assert [call[3] for call in aioclient_mock.mock_calls] == [{"Connection": "close"}] * 2


async def test_one_request_at_a_time(client: SophosClient, xml_api: FakeSophosApi) -> None:
    xml_api.delay = 0.01
    await asyncio.gather(*(client.get_interfaces() for _ in range(6)))
    assert xml_api.peak_in_flight == 1


async def test_queued_requests_do_not_eat_into_their_timeout(
    socket_enabled: None, tmp_path
) -> None:
    """Root cause of the admin-settings timeouts, on a real TLS connection
    (the HTTP mock does not apply aiohttp timeouts): the firewall answers one
    request after another. With two in flight, the second one waited on the
    firewall while its own timeout ran (20.03 s against a 20 s limit on a
    real firewall). Each request must get its full timeout for itself."""
    server = _KeepAliveServer(serial_delay=0.6)  # the firewall's time per request
    await server.start(tmp_path)
    from custom_components.sophos_firewall.session import create_xml_session

    session = create_xml_session(verify_ssl=False)
    try:
        client = SophosClient(session, "127.0.0.1", server.port, USERNAME, PASSWORD, timeout=1.0)
        results = await asyncio.gather(*(client.test_connection() for _ in range(3)))
        assert results == ["2200.1"] * 3
    finally:
        await session.close()
        await server.stop()


async def test_parses_all_record_types(client: SophosClient) -> None:
    assert await client.get_interfaces() == {
        "PortA": Interface("PortA", True, "LAN", "Static", "Auto Negotiate", "1500", "PortA"),
        "PortB": Interface("PortB", False, "WAN", "DHCP", "Auto Negotiate", "1500", "PortB"),
    }
    assert await client.get_firewall_rules() == {
        "Allow LAN to IoT": FirewallRule("Allow LAN to IoT", True, "Accept", "Network", "IPv4"),
        "Block Guest": FirewallRule("Block Guest", False, "Drop", "Network", "IPv4"),
    }
    assert await client.get_web_filter_policies() == {
        "Kids": WebFilterPolicy("Kids", "Deny"),
        "Default Policy": WebFilterPolicy("Default Policy", "Allow"),
    }
    dhcp = await client.get_dhcp_servers()
    assert dhcp["Main_DHCP"].running is True
    assert dhcp["Main_DHCP"].static_leases[0] == {
        "MACAddress": "aa:bb:cc:00:11:22", "IPAddress": "10.10.0.50", "HostName": "nas"
    }
    assert dhcp["Main_DHCP"].default_lease_time == 1440
    assert dhcp["Main_DHCP"].max_lease_time == 2880
    assert dhcp["Guest_DHCP"] == DhcpServer("Guest_DHCP", False, "PortC", 60, 120, ())
    assert await client.get_backup() == BackupSettings("Mail", "Monthly")
    assert await client.get_admin_settings() == AdminSettings("5HeyneXG")


def test_parsers_tolerate_unexpected_shapes() -> None:
    """Nested dicts or missing fields must not crash — they become None."""
    assert parse_interface({}) is None
    iface = parse_interface({"Name": "X", "InterfaceStatus": {"weird": "1"}})
    assert iface == Interface("X", None)
    assert parse_dhcp_server(
        {"Name": "D", "StaticLease": {"Lease": {"MACAddress": "AB"}}}
    ).static_leases == ({"MACAddress": "ab"},)
    assert parse_dhcp_server({"Name": "D", "StaticLease": "garbage"}).static_leases == ()
    assert parse_dhcp_server({"Name": "D", "StaticLease": {"Lease": "x"}}).static_leases == ()
    server = parse_dhcp_server({"Name": "D", "DefaultLeaseTime": "1 day", "MaxLeaseTime": {}})
    assert (server.default_lease_time, server.max_lease_time) == (None, None)


async def test_record_level_error_skips_only_that_record(client: SophosClient, xml_api: FakeSophosApi) -> None:
    xml_api.fail_tags["Interface"] = "529"
    assert await client.get_interfaces() == {}


async def test_rejected_login_is_auth_error(client: SophosClient, xml_api: FakeSophosApi) -> None:
    xml_api.password = "other"
    with pytest.raises(SophosAuthError):
        await client.get_interfaces()


@pytest.mark.parametrize("code", ["532", "534"])
async def test_api_disabled_or_ip_blocked_is_access_error(
    client: SophosClient, xml_api: FakeSophosApi, code: str
) -> None:
    xml_api.access_code = code
    with pytest.raises(SophosAccessError) as err:
        await client.get_interfaces()
    assert err.value.code == code


async def test_status_535_is_auth_error(client: SophosClient, xml_api: FakeSophosApi) -> None:
    xml_api.access_code = "535"
    with pytest.raises(SophosAuthError):
        await client.test_connection()


async def test_other_response_status_is_api_error(client: SophosClient, xml_api: FakeSophosApi) -> None:
    xml_api.access_code = "500"
    with pytest.raises(SophosAPIError):
        await client.test_connection()


async def test_http_403_is_access_error(client: SophosClient, xml_api: FakeSophosApi) -> None:
    xml_api.http_status = 403
    with pytest.raises(SophosAccessError):
        await client.test_connection()


async def test_http_500_is_api_error(client: SophosClient, xml_api: FakeSophosApi) -> None:
    xml_api.http_status = 500
    with pytest.raises(SophosAPIError):
        await client.test_connection()


async def test_timeout_is_connection_error(client: SophosClient, xml_api: FakeSophosApi) -> None:
    """Regression (A8): aiohttp's TimeoutError escaped as a raw exception."""
    xml_api.exc = TimeoutError()
    with pytest.raises(SophosConnectionError):
        await client.test_connection()


async def test_client_error_is_connection_error(client: SophosClient, xml_api: FakeSophosApi) -> None:
    xml_api.exc = aiohttp.ClientConnectionError("refused")
    with pytest.raises(SophosConnectionError):
        await client.test_connection()


async def test_invalid_xml_is_api_error(
    session: aiohttp.ClientSession, aioclient_mock: AiohttpClientMocker
) -> None:
    aioclient_mock.post(f"https://{HOST}:{PORT}/webconsole/APIController", text="<oops")
    client = SophosClient(session, HOST, PORT, USERNAME, PASSWORD)
    with pytest.raises(SophosAPIError):
        await client.test_connection()


async def test_credentials_are_xml_escaped(
    session: aiohttp.ClientSession, xml_api: FakeSophosApi
) -> None:
    xml_api.password = "p<&>\"'w"
    client = SophosClient(session, HOST, PORT, USERNAME, "p<&>\"'w")
    assert await client.test_connection() == "2200.1"


async def test_set_firewall_rule_status_keeps_the_rest_of_the_rule(
    client: SophosClient, xml_api: FakeSophosApi
) -> None:
    """Audit finding: v1.1.0 sent only Name and Status. SFOS updates need the
    whole object (PolicyType and Position are mandatory); the rule is read
    and written back unchanged except for its status."""
    import copy

    before = copy.deepcopy(xml_api.records["FirewallRule"][1])
    await client.set_firewall_rule_status("Block Guest", True)
    assert xml_api.requests[-2:] == [("get", "FirewallRule"), ("set", "FirewallRule")]
    assert xml_api.set_operations == ["update"]
    assert xml_api.records["FirewallRule"][1] == {**before, "Status": "Enable"}


async def test_set_web_filter_default_action_keeps_the_rule_list(
    client: SophosClient, xml_api: FakeSophosApi
) -> None:
    import copy

    before = copy.deepcopy(xml_api.records["WebFilterPolicy"][0])
    await client.set_web_filter_default_action("Kids", True)
    assert xml_api.records["WebFilterPolicy"][0] == {**before, "DefaultAction": "Allow"}


async def test_fake_rejects_a_partial_update_like_sfos(client: SophosClient) -> None:
    """The request v1.1.0 sent: the fake answers it like SFOS (501)."""
    root = await client._post(client._request(
        "<Set><FirewallRule><Name>Block Guest</Name><Status>Enable</Status></FirewallRule></Set>"
    ))
    status = root.find("FirewallRule/Status")
    assert status is not None and status.get("code") == "501"


async def test_write_of_an_unknown_rule_raises(client: SophosClient) -> None:
    with pytest.raises(SophosAPIError, match="not found"):
        await client.set_firewall_rule_status("No such rule", True)


@pytest.mark.parametrize(
    ("answer", "match"),
    [
        ("", "did not confirm"),  # no <FirewallRule> element in the answer
        ('<FirewallRule><Status>done</Status></FirewallRule>', "code \\?"),
        ('<FirewallRule><Status code="501">Configuration parameters validation failed.'
         "</Status><Params>/FirewallRule/Position</Params></FirewallRule>", "Position"),
    ],
)
async def test_write_needs_an_explicit_success_code(
    client: SophosClient, xml_api: FakeSophosApi, monkeypatch: pytest.MonkeyPatch,
    answer: str, match: str,
) -> None:
    """Audit finding: a missing status counted as success."""
    import xml.etree.ElementTree as ET

    real_post = client._post

    async def _post(xml: str, label: str = "request") -> ET.Element:
        if "<Set" in xml:
            return ET.fromstring(f"<Response>{answer}</Response>")
        return await real_post(xml, label)

    monkeypatch.setattr(client, "_post", _post)
    with pytest.raises(SophosAPIError, match=match):
        await client.set_firewall_rule_status("Block Guest", True)


async def test_empty_result_is_no_record(client: SophosClient, xml_api: FakeSophosApi) -> None:
    """SFOS answers an empty table with <Status>Number of records Zero.</Status>
    and no code; that is not a record."""
    xml_api.records["FirewallRule"] = []
    xml_api.records["BackupRestore"] = []
    assert await client.get_firewall_rules() == {}
    assert await client.get_backup() == BackupSettings(None, None)


async def test_rejected_write_raises(client: SophosClient, xml_api: FakeSophosApi) -> None:
    xml_api.reject_sets.add("FirewallRule")
    with pytest.raises(SophosAPIError):
        await client.set_firewall_rule_status("Block Guest", True)


def test_firewall_rule_action_nested_in_policy_block() -> None:
    """SFOS 22 puts the action under NetworkPolicy/UserPolicy (field test)."""
    from custom_components.sophos_firewall.sophos_client import parse_firewall_rule

    network = {"Name": "A", "Status": "Enable", "PolicyType": "Network",
               "NetworkPolicy": {"Action": "Accept"}}
    user = {"Name": "B", "Status": "Enable", "PolicyType": "User",
            "UserPolicy": {"Action": "Drop"}}
    assert parse_firewall_rule(network).action == "Accept"
    assert parse_firewall_rule(user).action == "Drop"
    assert parse_firewall_rule({"Name": "C"}).action is None


# ── Connection reuse against a real TLS server ────────────────────────────────


class _KeepAliveServer:
    """A TLS HTTP server that — like SFOS — keeps connections open even when
    the client asks for ``Connection: close``, and counts connections."""

    def __init__(self, *, serial_delay: float = 0.0) -> None:
        self.connections = 0
        self.port = 0
        self._server: asyncio.Server | None = None
        # > 0: answer one request after another, each after this many
        # seconds — how a real firewall processes XML requests (measured).
        self._serial_delay = serial_delay
        self._serial = asyncio.Lock()

    async def start(self, tmp_path) -> None:
        import datetime
        import ssl

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (tmp_path / "k.pem").write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=ctx)
        self.port = self._server.sockets[0].getsockname()[1]

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        body = (
            b'<?xml version="1.0" encoding="UTF-8"?><Response APIVersion="2200.1">'
            b"<Login><status>Authentication Successful</status></Login></Response>"
        )
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                length = 0
                for line in head.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":")[1])
                await reader.readexactly(length)
                if self._serial_delay:
                    async with self._serial:
                        await asyncio.sleep(self._serial_delay)
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nConnection: keep-alive\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
                )
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


async def test_connections_are_never_reused(socket_enabled: None, tmp_path) -> None:
    """Field test 1.1 beta: SFOS ignores 'Connection: close', aiohttp pooled
    the connection, and the next request on it hung until the timeout."""
    server = _KeepAliveServer()
    await server.start(tmp_path)
    from custom_components.sophos_firewall.session import create_xml_session

    session = create_xml_session(verify_ssl=False)
    try:
        client = SophosClient(session, "127.0.0.1", server.port, USERNAME, PASSWORD)
        for _ in range(3):
            assert await client.test_connection() == "2200.1"
        assert server.connections == 3
    finally:
        await session.close()
        await server.stop()


async def test_connection_close_header_alone_does_not_prevent_reuse(
    socket_enabled: None, tmp_path
) -> None:
    """Documents the root cause: HA's pooled session + 'Connection: close'
    still reuses the connection when the server keeps it open."""
    server = _KeepAliveServer()
    await server.start(tmp_path)
    session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False))
    try:
        client = SophosClient(session, "127.0.0.1", server.port, USERNAME, PASSWORD)
        for _ in range(3):
            await client.test_connection()
        assert server.connections == 1
    finally:
        await session.close()
        await server.stop()


@pytest.mark.parametrize(
    ("parser", "tag"),
    [
        ("parse_interface", "Interface"),
        ("parse_firewall_rule", "FirewallRule"),
        ("parse_web_filter_policy", "WebFilterPolicy"),
        ("parse_dhcp_server", "DHCPServer"),
    ],
)
def test_record_without_name_is_skipped(parser: str, tag: str) -> None:
    """A record the firewall returns without <Name> cannot be keyed."""
    from custom_components.sophos_firewall import sophos_client

    assert getattr(sophos_client, parser)({"Status": "1"}) is None


def test_malformed_static_leases_are_skipped() -> None:
    from custom_components.sophos_firewall.sophos_client import parse_dhcp_server

    server = parse_dhcp_server({
        "Name": "Main_DHCP",
        "StaticLease": {
            "Lease": ["junk", {"MACAddress": "AA:BB:CC:00:11:22", "IPAddress": "10.0.0.2"}]
        },
    })
    assert server is not None
    assert server.static_leases == ({"MACAddress": "aa:bb:cc:00:11:22", "IPAddress": "10.0.0.2"},)


# ── DHCP static leases as SFOS sends them (#29) ───────────────────────────────

# Structure of a real <DHCPServer> record: Sophos' own migration utility
# template (sophos/Sophos-Migration-Utility-CLI, tmpl/DHCPServer.tmpl) and an
# SFOS export posted in the Sophos Community (thread 145243). Every static
# mapping is a <Lease> inside <StaticLease>; the lease times are minutes.
_REAL_DHCP = """<DHCPServer transactionid="">
  <Name>Default_DHCP_Server</Name>
  <Status>1</Status>
  <Interface>PortA</Interface>
  <IPLease><IP>192.168.1.100-192.168.1.200</IP></IPLease>
  <StaticLease>{leases}</StaticLease>
  <ConflictDetection>Enable</ConflictDetection>
  <SubnetMask>255.255.255.0</SubnetMask>
  <DefaultLeaseTime>1440</DefaultLeaseTime>
  <MaxLeaseTime>2880</MaxLeaseTime>
  <UseApplianceDNSSettings>Disable</UseApplianceDNSSettings>
</DHCPServer>"""


def _lease(i: int) -> str:
    return (
        f"<Lease><HostName>host{i}</HostName><MACAddress>AA:BB:CC:00:00:{i:02X}</MACAddress>"
        f"<IPAddress>192.168.1.{i}</IPAddress></Lease>"
    )


def _parse_real(leases: str) -> DhcpServer:
    import xml.etree.ElementTree as ET

    from custom_components.sophos_firewall.sophos_client import _elem_to_dict, parse_dhcp_server

    server = parse_dhcp_server(_elem_to_dict(ET.fromstring(_REAL_DHCP.format(leases=leases))))
    assert server is not None
    return server


def test_real_dhcp_record_with_58_static_leases() -> None:
    """Regression (#29): 58 mappings came out as lease_count 1, leases [{}]."""
    server = _parse_real("".join(_lease(i) for i in range(1, 59)))
    assert len(server.static_leases) == 58
    assert server.static_leases[0] == {
        "HostName": "host1", "MACAddress": "aa:bb:cc:00:00:01", "IPAddress": "192.168.1.1"
    }
    assert server.static_leases[57]["IPAddress"] == "192.168.1.58"
    assert (server.default_lease_time, server.max_lease_time) == (1440, 2880)
    assert server.running is True and server.interface == "PortA"


def test_real_dhcp_record_with_one_static_lease() -> None:
    """A single <Lease> arrives as a mapping, not as a list."""
    server = _parse_real(_lease(7))
    assert server.static_leases == (
        {"HostName": "host7", "MACAddress": "aa:bb:cc:00:00:07", "IPAddress": "192.168.1.7"},
    )


def test_real_dhcp_record_without_static_leases() -> None:
    assert _parse_real("").static_leases == ()
