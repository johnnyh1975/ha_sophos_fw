"""A minimal SNMP v2c agent on a local UDP port, for tests.

The integration's real SNMPClient (and puresnmp underneath) talk to this
agent over real UDP sockets, so tests exercise the actual transport, PDU
encoding, GETBULK walks, timeouts and error handling — nothing in the
client is mocked.

Supported: GET, GETNEXT, GETBULK. Missing OIDs answer noSuchObject; walks
past the end answer endOfMibView — exactly like a real agent.

Test controls:
    agent.drop_all = True        → never answer (timeout)
    agent.answer_limit = n       → answer n more requests, then go silent
                                   (a walk that fails half-way)
    agent.drop_next = n          → ignore the next n requests (lost packets)
    agent.drop_prefixes = {oid}  → ignore requests touching these subtrees
    agent.serial_delay = s       → answer one request at a time, s seconds
                                   each (like the SFOS agent under load)
"""
from __future__ import annotations

import asyncio
from typing import Any

from puresnmp.pdu import BulkGetRequest, GetNextRequest, GetRequest, GetResponse, PDUContent
from puresnmp.types import Counter64, Gauge, TimeTicks
from puresnmp.varbind import VarBind
from x690 import decode
from x690.types import Integer, ObjectIdentifier, OctetString, Sequence

__all__ = ["Counter64", "FakeSnmpAgent", "Gauge", "Integer", "OctetString", "TimeTicks"]


class _Raw:
    """A pre-encoded value (puresnmp's NoSuchObject cannot encode itself)."""

    def __init__(self, data: bytes) -> None:
        self._data = data

    def __bytes__(self) -> bytes:
        return self._data


NO_SUCH_OBJECT = _Raw(b"\x80\x00")
END_OF_MIB_VIEW = _Raw(b"\x82\x00")


def _key(oid: str | ObjectIdentifier) -> tuple[int, ...]:
    return tuple(int(part) for part in str(oid).strip(".").split("."))


def _oid(key: tuple[int, ...]) -> ObjectIdentifier:
    return ObjectIdentifier(".".join(map(str, key)))


class FakeSnmpAgent(asyncio.DatagramProtocol):
    """UDP SNMP agent serving a static MIB."""

    def __init__(self, mib: dict[str, Any], community: str = "public") -> None:
        self.mib = {_key(oid): value for oid, value in mib.items()}
        self.community = community
        self.drop_all = False
        self.answer_limit: int | None = None
        self.drop_next = 0
        self.drop_prefixes: set[str] = set()
        self.serial_delay = 0.0
        self._queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] | None = None
        self._worker: asyncio.Task[None] | None = None
        self.requests: list[str] = []
        self._transport: asyncio.DatagramTransport | None = None
        self.port = 0

    # ── lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> FakeSnmpAgent:
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: self, local_addr=("127.0.0.1", 0)
        )
        self._transport = transport  # type: ignore[assignment]
        self.port = transport.get_extra_info("sockname")[1]
        return self

    def stop(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
            self._worker = None
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def set(self, oid: str, value: Any) -> None:
        self.mib[_key(oid)] = value

    def remove_prefix(self, prefix: str) -> None:
        p = _key(prefix)
        for key in [k for k in self.mib if k[: len(p)] == p]:
            del self.mib[key]

    # ── protocol ──────────────────────────────────────────────────────────────

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = transport  # type: ignore[assignment]

    def _next(self, key: tuple[int, ...]) -> tuple[int, ...] | None:
        candidates = [k for k in self.mib if k > key]
        return min(candidates) if candidates else None

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.serial_delay:
            if self._queue is None:
                self._queue = asyncio.Queue()
                self._worker = asyncio.get_running_loop().create_task(self._serial_worker())
            self._queue.put_nowait((data, addr))
            return
        self._handle(data, addr)

    async def _serial_worker(self) -> None:
        assert self._queue is not None
        while True:
            data, addr = await self._queue.get()
            await asyncio.sleep(self.serial_delay)
            self._handle(data, addr)

    def _handle(self, data: bytes, addr: tuple[str, int]) -> None:
        if self.drop_all:
            return
        if self.drop_next > 0:
            self.drop_next -= 1
            return
        if self.answer_limit is not None:
            if self.answer_limit <= 0:
                return
            self.answer_limit -= 1

        def header(pos: int) -> int:
            length = data[pos + 1]
            pos += 2
            if length & 0x80:
                pos += length & 0x7F
            return pos

        pos = header(0)
        version, pos = decode(data, pos)
        community, pos = decode(data, pos)
        if community.pythonize() != self.community.encode():
            return  # real agents silently drop wrong communities

        if data[pos] == 0xA5:  # GETBULK — puresnmp can't decode it as a type
            p = header(pos)
            request_id, p = decode(data, p)
            _non_repeaters, p = decode(data, p)
            max_repeaters, p = decode(data, p)
            varbinds, p = decode(data, p)
            kind = "getbulk"
            content = PDUContent(
                request_id.pythonize(), [VarBind(o, v) for o, v in varbinds]
            )
            repeat = max_repeaters.pythonize()
        else:
            pdu, _ = decode(data, pos)
            content = pdu.value
            kind = {GetRequest: "get", GetNextRequest: "getnext"}.get(type(pdu), "other")
            repeat = 1

        self.requests.append(kind)
        prefixes = [_key(p) for p in self.drop_prefixes]
        if any(_key(vb.oid)[: len(p)] == p for vb in content.varbinds for p in prefixes):
            return
        out: list[VarBind] = []
        for varbind in content.varbinds:
            key = _key(varbind.oid)
            if kind == "get":
                out.append(VarBind(varbind.oid, self.mib.get(key, NO_SUCH_OBJECT)))
                continue
            for _ in range(repeat):
                nxt = self._next(key)
                if nxt is None:
                    out.append(VarBind(_oid(key), END_OF_MIB_VIEW))
                    break
                out.append(VarBind(_oid(nxt), self.mib[nxt]))
                key = nxt

        response = GetResponse(PDUContent(content.request_id, out))
        packet = Sequence(
            [Integer(version.pythonize()), OctetString(community.pythonize()), response]
        )
        assert self._transport is not None
        self._transport.sendto(bytes(packet), addr)


# ── A Sophos appliance MIB ────────────────────────────────────────────────────

SOPHOS = "1.3.6.1.4.1.2604.5.1"
VPN_ENTRY = f"{SOPHOS}.6.1.1.1.1"
VPN_POLICY_ENTRY = f"{SOPHOS}.6.1.2.1.1"
HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"  # HOST-RESOURCES-MIB
IFX_ENTRY = "1.3.6.1.2.1.31.1.1.1"             # IF-MIB ifXTable
# ifIndex → ifName exactly as a real SFVH (SFOS 22.0.2) reports them
IF_NAMES = {
    1: "lo", 2: "dummy0", 3: "ipsec0", 4: "sit0", 5: "ip6tnl0", 6: "PortA", 7: "PortB",
    10: "gre0", 11: "gretap0", 12: "erspan0", 13: "ifb0", 14: "dfq", 15: "GuestAP",
    16: "PortA.40", 17: "PortA.50", 18: "PortA.30", 26: "spq",
}
FAN_SPEED = f"{SOPHOS}.9.3.1.2"
PSU_STATUS = f"{SOPHOS}.9.4.1.2"


def sophos_mib(*, hardware: bool = False) -> dict[str, Any]:
    """Return a realistic SFOS MIB (virtual appliance unless hardware=True)."""
    mib: dict[str, Any] = {
        # device info
        f"{SOPHOS}.1.1.0": OctetString(b"5HeyneXG"),
        f"{SOPHOS}.1.2.0": OctetString(b"SFVH_KV01_SFOS"),
        f"{SOPHOS}.1.3.0": OctetString(b"SFOS 22.0.0 GA-Build411"),
        f"{SOPHOS}.1.4.0": OctetString(b"C01001D2MQT76C4"),
        f"{SOPHOS}.1.5.0": OctetString(b"1.0.1.1207"),
        f"{SOPHOS}.1.6.0": OctetString(b"22.1.26"),
        # stats
        f"{SOPHOS}.2.1.0": OctetString(b"Sun Sep 27 09:00:00 2026"),
        f"{SOPHOS}.2.2.0": TimeTicks(650274300),  # 75 d 6 h 19 min
        f"{SOPHOS}.2.4.1.0": Integer(11969),
        f"{SOPHOS}.2.4.2.0": Integer(27),
        f"{SOPHOS}.2.5.1.0": Integer(72383),
        f"{SOPHOS}.2.5.2.0": Integer(33),
        f"{SOPHOS}.2.5.3.0": Integer(4095),
        f"{SOPHOS}.2.5.4.0": Integer(23),
        f"{SOPHOS}.2.6.0": Integer(1),
        f"{SOPHOS}.2.7.0": Counter64(21355078),
        f"{SOPHOS}.2.8.0": Counter64(0),
        f"{SOPHOS}.2.9.1.0": Counter64(12),
        f"{SOPHOS}.2.9.2.0": Counter64(47),
        f"{SOPHOS}.2.9.3.0": Counter64(19),
        # HA
        f"{SOPHOS}.4.1.0": Integer(0),
        f"{SOPHOS}.4.4.0": Integer(2),
        f"{SOPHOS}.4.5.0": Integer(0),
        # VPN tunnel table (sfosIPSecVpnTunnelTable): name(2), tunnels(8), status(9), activated(10)
        f"{VPN_ENTRY}.2.1": OctetString(b"Azure-VPN"),
        f"{VPN_ENTRY}.2.2": OctetString(b"Branch-VPN"),
        f"{VPN_ENTRY}.2.3": OctetString(b"DR-Site"),
        f"{VPN_ENTRY}.8.1": Integer(1),
        f"{VPN_ENTRY}.8.2": Integer(1),
        f"{VPN_ENTRY}.8.3": Integer(3),
        f"{VPN_ENTRY}.9.1": Integer(1),
        f"{VPN_ENTRY}.9.2": Integer(0),
        f"{VPN_ENTRY}.9.3": Integer(2),
        f"{VPN_ENTRY}.10.1": Integer(1),
        f"{VPN_ENTRY}.10.2": Integer(1),
        f"{VPN_ENTRY}.10.3": Integer(1),
        # The IPsec *policy* table right behind it — must never be read as tunnels (#18)
        f"{VPN_POLICY_ENTRY}.2.1": OctetString(b"IKEv2-Policy"),
        f"{VPN_POLICY_ENTRY}.2.7": OctetString(b"Legacy-Policy"),
    }
    # standard MIBs: four cores (loads as seen on a real SFVH); ifName +
    # 64-bit octet counters (index * 1e9 received, index * 1e8 sent)
    for offset, load in enumerate((22, 21, 23, 18)):
        mib[f"{HR_PROCESSOR_LOAD}.{196608 + offset}"] = Integer(load)
    for index, name in IF_NAMES.items():
        mib[f"{IFX_ENTRY}.1.{index}"] = OctetString(name.encode())
        mib[f"{IFX_ENTRY}.6.{index}"] = Counter64(index * 1_000_000_000)
        mib[f"{IFX_ENTRY}.10.{index}"] = Counter64(index * 100_000_000)
    # services: all running except anti-spam (1) and HA service (1); tomcat unimplemented
    for i in range(1, 22):
        if i != 13:
            mib[f"{SOPHOS}.3.{i}.0"] = Integer(1 if i in (7, 9) else 3)
    # licenses: base fw subscribed, net protect evaluating, enh plus not subscribed
    statuses = {1: 3, 2: 1, 3: 3, 4: 4, 5: 2, 6: 3, 7: 0, 8: 2, 9: 5}
    expiries = {1: b"Dec 31 2999", 2: b"Oct 15 2026", 3: b"Mar 1 2027", 4: b"Jan 5 2026"}
    for i, status in statuses.items():
        mib[f"{SOPHOS}.5.{i}.1.0"] = Integer(status)
        mib[f"{SOPHOS}.5.{i}.2.0"] = OctetString(expiries.get(i, b""))
    if hardware:
        mib.update({
            f"{SOPHOS}.9.1.0": Integer(650),   # NPU 65.0 °C
            f"{SOPHOS}.9.2.0": Integer(420),   # CPU 42.0 °C
            f"{SOPHOS}.9.3.1.1.1": Integer(1),
            f"{SOPHOS}.9.3.1.1.2": Integer(2),
            f"{SOPHOS}.9.3.1.1.3": Integer(3),
            f"{FAN_SPEED}.1": Gauge(3000),
            f"{FAN_SPEED}.2": Gauge(3150),
            f"{FAN_SPEED}.3": Gauge(2900),
            f"{SOPHOS}.9.4.1.1.1": Integer(1),
            f"{SOPHOS}.9.4.1.1.2": Integer(2),
            f"{PSU_STATUS}.1": Integer(1),
            f"{PSU_STATUS}.2": Integer(2),
        })
    return mib
