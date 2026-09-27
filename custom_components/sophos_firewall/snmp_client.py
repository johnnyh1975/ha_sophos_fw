"""SNMP client for Sophos Firewall system metrics (puresnmp 2.x, SNMP v2c).

Key implementation notes
------------------------
1. **Blocking plugin discovery.** puresnmp discovers its plugins with
   ``pkgutil``/``importlib`` (filesystem I/O) the first time a message is
   encoded. ``preload()`` runs that discovery once in the import executor and
   patches the loader so no call inside the event loop touches the disk.

2. **Failures raise.** Any transport or protocol failure raises
   ``SophosSNMPError``. An OID the agent does not implement
   (noSuchObject/noSuchInstance) is *not* a failure: that single value
   becomes None. Up to v1.0.x every failure was swallowed and turned into 0,
   which showed plausible but false values and reset TOTAL_INCREASING
   statistics.

3. **Bounded time.** Every PDU uses ``SNMP_TIMEOUT`` × ``SNMP_RETRIES``, and
   every complete operation (GET or table walk) is bounded by
   ``SNMP_OPERATION_BUDGET``. A walk that fails half-way raises instead of
   returning a partial table — a partial table would make rows disappear
   and their entities be removed from the registry.

4. **Walks use GETBULK** and fetch only the columns that are needed.

OID source: SOPHOS-XG-MIB / SFOS-FIREWALL-MIB, base 1.3.6.1.4.1.2604.5.1.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Awaitable, Sequence
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from .const import (
    DEFAULT_SNMP_PORT,
    HEALTH_COL_VALUE,
    HR_COL_PROCESSOR_LOAD,
    INTERNAL_INTERFACE_RE,
    IFX_COL_HC_IN,
    IFX_COL_HC_OUT,
    IFX_COL_NAME,
    LICENSE_OIDS,
    OID_CPU_TEMPERATURE,
    OID_CURRENT_DATE,
    OID_DEVICE_APP_KEY,
    OID_DEVICE_FW_VERSION,
    OID_DEVICE_NAME,
    OID_DEVICE_TYPE,
    OID_DISK_CAPACITY,
    OID_DISK_PERCENT,
    OID_FAN_TABLE,
    OID_FTP_HITS,
    OID_HA_CURRENT_STATE,
    OID_HA_PEER_STATE,
    OID_HA_STATUS,
    OID_HR_PROCESSOR_TABLE,
    OID_HTTP_HITS,
    OID_IFX_TABLE,
    OID_IMAP_HITS,
    OID_IPS_VERSION,
    OID_LIVE_USERS,
    OID_MEMORY_CAPACITY,
    OID_MEMORY_PERCENT,
    OID_NPU_TEMPERATURE,
    OID_POP3_HITS,
    OID_PSU_TABLE,
    OID_SMTP_HITS,
    OID_SWAP_CAPACITY,
    OID_SWAP_PERCENT,
    OID_UPTIME,
    OID_VPN_TABLE,
    OID_WEBCAT_VERSION,
    PSU_UP,
    SERVICE_OIDS,
    SNMP_BULK_SIZE,
    SNMP_MAX_CONCURRENT,
    SNMP_OPERATION_BUDGET,
    SNMP_RETRIES,
    SNMP_TIMEOUT,
    VPN_COL_ACTIVATED,
    VPN_COL_NAME,
    VPN_COL_STATUS,
    VPN_COL_TUNNELS,
)
from .models import (
    DeviceInfo,
    HaStatus,
    InterfaceCounters,
    License,
    SystemHealth,
    SystemStats,
    TrafficSample,
    VpnTunnel,
)

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant
    from puresnmp import Client

_LOGGER = logging.getLogger(__name__)

# Serialises the one-time puresnmp loader patch across concurrent preload()
# calls (several firewall entries set up in parallel, each in its own thread).
_PATCH_LOCK = threading.Lock()


class SophosSNMPError(Exception):
    """The SNMP agent did not answer, or answered with a protocol error."""


# ── Value conversion ──────────────────────────────────────────────────────────


def _py(value: Any) -> Any:
    """Convert a puresnmp/x690 value to a plain Python value.

    noSuchObject / noSuchInstance / endOfMibView pythonize to None.
    OctetStrings are decoded as UTF-8.
    """
    if value is None:
        return None
    if hasattr(value, "pythonize"):
        value = value.pythonize()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def to_int(value: Any) -> int | None:
    """Return an SNMP value as int, or None if missing or not numeric."""
    v = _py(value)
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v).split()[0])
    except (ValueError, IndexError):
        _LOGGER.debug("Cannot convert SNMP value %r to int", v)
        return None


def to_str(value: Any) -> str | None:
    """Return an SNMP value as stripped str, or None if missing or empty."""
    v = _py(value)
    if v is None:
        return None
    s = str(v).strip()
    return s or None


# Placeholder texts SFOS returns instead of a value (field test: webcat
# version "Not Available" on SFOS 22.0.2; license expiry "fail").
_PLACEHOLDERS = frozenset({"not available", "n/a", "na", "fail", "unknown", "none", "-"})


def to_value_str(value: Any) -> str | None:
    """Like to_str(), but a placeholder text such as "Not Available" is None."""
    text = to_str(value)
    return None if text is None or text.lower() in _PLACEHOLDERS else text


def timeticks_to_seconds(value: Any) -> int | None:
    """Convert TimeTicks (timedelta from puresnmp, or hundredths) to seconds."""
    v = _py(value)
    if v is None:
        return None
    if isinstance(v, timedelta):
        return int(v.total_seconds())
    ticks = to_int(v)
    return None if ticks is None else ticks // 100


def tenths_to_celsius(value: Any) -> float | None:
    """Convert a temperature in tenths of °C; non-positive means 'no sensor'."""
    v = to_int(value)
    return round(v / 10, 1) if v is not None and v > 0 else None


def table_column(data: dict[str, Any], table: str, column: str) -> dict[str, Any]:
    """Pick one column out of walked table rows, keyed by row index.

    SMI tables are laid out as ``<table>.1.<column>.<index>``. Only rows whose
    remainder after ``<table>.1.<column>.`` is a single numeric component are
    returned, so other columns, other entries and malformed OIDs are skipped
    instead of being misread (up to v1.1 the fan/PSU parser confused column
    and row index).
    """
    prefix = f"{table.strip('.')}.1.{column}."
    rows: dict[str, Any] = {}
    for oid, value in data.items():
        oid = str(oid).lstrip(".")
        if oid.startswith(prefix) and (idx := oid[len(prefix):]).isdigit():
            rows[idx] = value
    return rows


def _oid(dotted: str) -> Any:
    """Convert a dotted OID string to a puresnmp ObjectIdentifier."""
    from x690.types import ObjectIdentifier

    return ObjectIdentifier(dotted)


class _UDPRequest(asyncio.DatagramProtocol):
    """One request/response exchange on its own UDP socket."""

    def __init__(self, packet: bytes) -> None:
        self._packet = packet
        self.response: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        transport.sendto(self._packet)  # type: ignore[attr-defined]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if not self.response.done():
            self.response.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.response.done():
            self.response.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None and not self.response.done():
            self.response.set_exception(exc)


async def _send_udp(
    endpoint: Any,
    packet: bytes,
    timeout: int = 1,
    loop: asyncio.AbstractEventLoop | None = None,
    retries: int = 10,
) -> bytes:
    """Send one SNMP packet and return the raw reply (puresnmp ``sender``).

    Replaces puresnmp's send_udp, which leaks the UDP socket when the
    request is cancelled (our operation budget) or when the host answers
    with an ICMP error: it only closes the transport on success and on its
    own timeout. Here every attempt's socket is closed in ``finally``.
    """
    from puresnmp.exc import Timeout

    running_loop = asyncio.get_running_loop()
    for _ in range(max(retries, 1)):
        transport, protocol = await running_loop.create_datagram_endpoint(
            lambda: _UDPRequest(packet), remote_addr=(str(endpoint.ip), endpoint.port)
        )
        try:
            async with asyncio.timeout(timeout):
                return await protocol.response
        except TimeoutError:
            continue
        finally:
            transport.close()
    raise Timeout(f"No SNMP response from {endpoint.ip}:{endpoint.port} after {retries} attempt(s)")


async def _all_or_nothing[T](*aws: Awaitable[T]) -> list[T]:
    """Run awaitables concurrently; on the first failure cancel the others.

    Plain ``asyncio.gather`` re-raises the first exception but leaves the
    remaining walks running, unbounded by the operation budget.
    """
    tasks = [asyncio.ensure_future(aw) for aw in aws]
    try:
        return list(await asyncio.gather(*tasks))
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


def _is_transport_error(exc: BaseException) -> bool:
    """Return True for exceptions that mean 'no usable answer'."""
    from puresnmp.exc import SnmpError
    from x690.exc import X690Error

    # TimeoutError: operation budget exceeded; OSError: socket-level failure;
    # SnmpError: puresnmp timeout or error response; X690Error: undecodable reply.
    return isinstance(exc, (TimeoutError, OSError, SnmpError, X690Error))


# ── Client ────────────────────────────────────────────────────────────────────


class SNMPClient:
    """Async SNMP v2c client for one firewall.

    Call ``await client.preload(hass)`` once during setup before any request.
    """

    def __init__(
        self,
        host: str,
        community: str,
        port: int | None = None,
    ) -> None:
        self._host = host
        self._community = community
        self._port = DEFAULT_SNMP_PORT if port is None else port
        self._client: Client | None = None
        self._in_flight = asyncio.Semaphore(SNMP_MAX_CONCURRENT)

    # ── Setup ─────────────────────────────────────────────────────────────────

    async def preload(self, hass: HomeAssistant) -> None:
        """Load puresnmp's plugins in the import executor and create the client.

        puresnmp.plugins.security.create() builds a new Loader on every call,
        and the first use of a Loader walks the plugin package on disk. We
        populate one Loader in a worker thread and route every create() call
        (including the references the MPM plugins imported) to it. The patch
        is global, idempotent and serialised by _PATCH_LOCK.

        Hostname resolution (puresnmp resolves the host in Client.__init__)
        also happens here, off the event loop. Home Assistant's import
        executor is used because the work is dominated by module imports.
        """

        def _load() -> Client:
            from puresnmp import V2C, Client
            from puresnmp.plugins import security as sec_plugin
            from puresnmp.plugins.pluginbase import (
                Loader,
                discover_plugins,
            )

            with _PATCH_LOCK:
                if not getattr(sec_plugin, "_sophos_ha_patched", False):
                    cached_loader = Loader(
                        "puresnmp_plugins.security", sec_plugin.is_valid_sec_plugin
                    )
                    cached_loader.discovered_plugins = discover_plugins(
                        "puresnmp_plugins.security", sec_plugin.is_valid_sec_plugin
                    )

                    def _cached_create(identifier: int) -> Any:
                        # loader.create() returns the plugin MODULE; the
                        # original security.create() calls module.create().
                        mod = cached_loader.create(identifier)
                        if mod is None:
                            from puresnmp.exc import UnknownSecurityModel

                            raise UnknownSecurityModel(
                                "puresnmp_plugins.security",
                                identifier,
                                sorted(cached_loader.discovered_plugins.keys()),
                            )
                        return mod.create()

                    sec_plugin.create = _cached_create
                    sec_plugin._sophos_ha_patched = True  # type: ignore[attr-defined]

                    # puresnmp_plugins ships without type information.
                    import puresnmp_plugins.mpm.v1 as _v1  # type: ignore[import-untyped]
                    import puresnmp_plugins.mpm.v2c as _v2c  # type: ignore[import-untyped]

                    _v1.create_sm = _cached_create
                    _v2c.create_sm = _cached_create
                    try:
                        import puresnmp_plugins.mpm.v3 as _v3  # type: ignore[import-untyped]

                        _v3.create_sm = _cached_create
                    except ImportError:
                        pass

            client = Client(
                ip=self._host,
                credentials=V2C(self._community),
                port=self._port,
                sender=self._send,
            )
            client.configure(timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES)
            return client

        self._client = await hass.async_add_import_executor_job(_load)
        _LOGGER.debug("SNMP client for %s preloaded", self._host)

    async def _send(
        self,
        endpoint: Any,
        packet: bytes,
        timeout: int = 1,
        loop: asyncio.AbstractEventLoop | None = None,
        retries: int = 10,
    ) -> bytes:
        """puresnmp sender: at most SNMP_MAX_CONCURRENT requests in flight."""
        async with self._in_flight:
            return await _send_udp(endpoint, packet, timeout, loop, retries)

    def _get_client(self) -> Client:
        """Return the puresnmp client; preload() must have run."""
        if self._client is None:
            raise RuntimeError(
                "SNMPClient used before preload() — this would block the event loop"
            )
        return self._client

    # ── Low-level operations ──────────────────────────────────────────────────

    async def _multiget(self, oids: Sequence[str]) -> dict[str, Any]:
        """GET several scalar OIDs in one PDU; unimplemented OIDs map to None."""
        client = self._get_client()
        try:
            async with asyncio.timeout(SNMP_OPERATION_BUDGET):
                values = await client.multiget([_oid(o) for o in oids])
        except Exception as exc:
            if _is_transport_error(exc):
                raise SophosSNMPError(
                    f"SNMP GET to {self._host} failed: {type(exc).__name__}: {exc}"
                ) from exc
            raise
        return {oid: _py(value) for oid, value in zip(oids, values, strict=True)}

    async def _walk_columns(self, table: str, columns: Sequence[str]) -> dict[str, Any]:
        """Walk selected columns of a table with GETBULK; all-or-nothing.

        Each column is walked separately (concurrently): puresnmp 2.0.1's
        multi-root bulkwalk stops early once one root leaves its subtree and
        silently drops the remaining rows of the others (verified against a
        real agent: 84 of 118 rows for two 59-row columns).
        """
        client = self._get_client()

        async def _walk(root: str) -> list[tuple[str, Any]]:
            return [
                (str(varbind.oid), varbind.value)
                async for varbind in client.bulkwalk([_oid(root)], bulk_size=SNMP_BULK_SIZE)
            ]

        try:
            async with asyncio.timeout(SNMP_OPERATION_BUDGET):
                columns_data = await _all_or_nothing(
                    *(_walk(f"{table}.1.{col}") for col in columns)
                )
        except Exception as exc:
            if _is_transport_error(exc):
                raise SophosSNMPError(
                    f"SNMP walk of {table} on {self._host} failed: "
                    f"{type(exc).__name__}: {exc}"
                ) from exc
            raise
        return {oid: value for column in columns_data for oid, value in column}

    # ── Connection test ───────────────────────────────────────────────────────

    async def test_connection(self) -> str | None:
        """Return the device name; raise SophosSNMPError if unreachable."""
        return to_str((await self._multiget([OID_DEVICE_NAME]))[OID_DEVICE_NAME])

    # ── Data fetch methods ────────────────────────────────────────────────────

    async def get_device_info(self) -> DeviceInfo:
        """Return static appliance information."""
        raw = await self._multiget([
            OID_DEVICE_NAME, OID_DEVICE_TYPE, OID_DEVICE_FW_VERSION,
            OID_DEVICE_APP_KEY, OID_WEBCAT_VERSION, OID_IPS_VERSION,
        ])
        return DeviceInfo(
            name=to_str(raw[OID_DEVICE_NAME]),
            model=to_str(raw[OID_DEVICE_TYPE]),
            firmware=to_value_str(raw[OID_DEVICE_FW_VERSION]),
            serial=to_value_str(raw[OID_DEVICE_APP_KEY]),
            webcat_version=to_value_str(raw[OID_WEBCAT_VERSION]),
            ips_version=to_value_str(raw[OID_IPS_VERSION]),
        )

    async def get_stats(self) -> SystemStats:
        """Return resource usage and protocol hit counters."""
        raw = await self._multiget([
            OID_CURRENT_DATE, OID_UPTIME, OID_DISK_CAPACITY, OID_DISK_PERCENT,
            OID_MEMORY_CAPACITY, OID_MEMORY_PERCENT, OID_SWAP_CAPACITY,
            OID_SWAP_PERCENT, OID_LIVE_USERS, OID_HTTP_HITS, OID_FTP_HITS,
            OID_SMTP_HITS, OID_IMAP_HITS, OID_POP3_HITS,
        ])
        return SystemStats(
            current_date=to_str(raw[OID_CURRENT_DATE]),
            uptime_seconds=timeticks_to_seconds(raw[OID_UPTIME]),
            disk_capacity_mb=to_int(raw[OID_DISK_CAPACITY]),
            disk_percent=to_int(raw[OID_DISK_PERCENT]),
            memory_capacity_mb=to_int(raw[OID_MEMORY_CAPACITY]),
            memory_percent=to_int(raw[OID_MEMORY_PERCENT]),
            swap_capacity_mb=to_int(raw[OID_SWAP_CAPACITY]),
            swap_percent=to_int(raw[OID_SWAP_PERCENT]),
            live_users=to_int(raw[OID_LIVE_USERS]),
            http_hits=to_int(raw[OID_HTTP_HITS]),
            ftp_hits=to_int(raw[OID_FTP_HITS]),
            smtp_hits=to_int(raw[OID_SMTP_HITS]),
            imap_hits=to_int(raw[OID_IMAP_HITS]),
            pop3_hits=to_int(raw[OID_POP3_HITS]),
        )

    async def get_services(self) -> dict[str, int | None]:
        """Return the ServiceStatsType code of every monitored service."""
        raw = await self._multiget(list(SERVICE_OIDS))
        return {key: to_int(raw[oid]) for oid, (key, _) in SERVICE_OIDS.items()}

    async def get_licenses(self) -> dict[str, License]:
        """Return status and expiry of every subscription module."""
        oids: list[str] = []
        for status_oid, (_, _, expiry_oid) in LICENSE_OIDS.items():
            oids += [status_oid, expiry_oid]
        raw = await self._multiget(oids)
        return {
            key: License(
                key=key,
                name=friendly,
                status_code=to_int(raw[status_oid]),
                expiry_date=to_value_str(raw[expiry_oid]),
            )
            for status_oid, (key, friendly, expiry_oid) in LICENSE_OIDS.items()
        }

    async def get_vpn_tunnels(self) -> dict[str, VpnTunnel]:
        """Return IPsec connections from sfosIPSecVpnTunnelTable, keyed by row index."""
        data = await self._walk_columns(
            OID_VPN_TABLE, [VPN_COL_NAME, VPN_COL_TUNNELS, VPN_COL_STATUS, VPN_COL_ACTIVATED]
        )
        names = table_column(data, OID_VPN_TABLE, VPN_COL_NAME)
        configured = table_column(data, OID_VPN_TABLE, VPN_COL_TUNNELS)
        status = table_column(data, OID_VPN_TABLE, VPN_COL_STATUS)
        activated = table_column(data, OID_VPN_TABLE, VPN_COL_ACTIVATED)
        tunnels: dict[str, VpnTunnel] = {}
        for idx in sorted(names, key=int):
            if (name := to_str(names[idx])) is None:
                continue
            tunnels[idx] = VpnTunnel(
                index=idx,
                name=name,
                conn_status=to_int(status.get(idx)),
                activated=to_int(activated.get(idx)),
                tunnels_configured=to_int(configured.get(idx)),
            )
        return tunnels

    async def get_system_health(self) -> SystemHealth:
        """Return temperatures, fan speeds and PSU states."""
        temps, fan_data, psu_data = await _all_or_nothing(
            self._multiget([OID_CPU_TEMPERATURE, OID_NPU_TEMPERATURE]),
            self._walk_columns(OID_FAN_TABLE, [HEALTH_COL_VALUE]),
            self._walk_columns(OID_PSU_TABLE, [HEALTH_COL_VALUE]),
        )
        fans = table_column(fan_data, OID_FAN_TABLE, HEALTH_COL_VALUE)
        psus = table_column(psu_data, OID_PSU_TABLE, HEALTH_COL_VALUE)
        return SystemHealth(
            cpu_temperature_c=tenths_to_celsius(temps[OID_CPU_TEMPERATURE]),
            npu_temperature_c=tenths_to_celsius(temps[OID_NPU_TEMPERATURE]),
            fans={f"fan_{i}": to_int(fans[i]) for i in sorted(fans, key=int)},
            psus={
                f"psu_{i}": None if (code := to_int(psus[i])) is None else code == PSU_UP
                for i in sorted(psus, key=int)
            },
        )

    async def get_cpu_load(self) -> dict[str, int | None]:
        """Return the load of every processor core (HOST-RESOURCES-MIB).

        Cores are numbered 1, 2, … in table order: hrDeviceIndex values
        (196608, …) mean nothing to a user. Empty if the agent lacks the table.
        """
        data = await self._walk_columns(OID_HR_PROCESSOR_TABLE, [HR_COL_PROCESSOR_LOAD])
        loads = table_column(data, OID_HR_PROCESSOR_TABLE, HR_COL_PROCESSOR_LOAD)
        return {
            str(core): to_int(loads[idx])
            for core, idx in enumerate(sorted(loads, key=int), start=1)
        }

    async def get_traffic(self) -> TrafficSample:
        """Return the octet counters of every interface, keyed by ifName.

        Keyed by name, not ifIndex: the index is not guaranteed to survive a
        reboot or an interface change. The sample time is taken after the
        walk, the same way for every sample, so the difference between two
        samples is the real time between them.
        """
        data = await self._walk_columns(
            OID_IFX_TABLE, [IFX_COL_NAME, IFX_COL_HC_IN, IFX_COL_HC_OUT]
        )
        sampled_at = time.monotonic()
        names = table_column(data, OID_IFX_TABLE, IFX_COL_NAME)
        rx = table_column(data, OID_IFX_TABLE, IFX_COL_HC_IN)
        tx = table_column(data, OID_IFX_TABLE, IFX_COL_HC_OUT)
        counters: dict[str, InterfaceCounters] = {}
        for idx in sorted(names, key=int):
            name = to_str(names[idx])
            if name is None or INTERNAL_INTERFACE_RE.match(name) or name in counters:
                continue
            counters[name] = InterfaceCounters(
                in_octets=to_int(rx.get(idx)), out_octets=to_int(tx.get(idx))
            )
        return TrafficSample(sampled_at=sampled_at, counters=counters)

    async def get_ha_status(self) -> HaStatus:
        """Return the HA cluster state."""
        raw = await self._multiget([OID_HA_STATUS, OID_HA_CURRENT_STATE, OID_HA_PEER_STATE])
        enabled = to_int(raw[OID_HA_STATUS])
        return HaStatus(
            enabled=None if enabled is None else enabled == 1,
            current_state=to_int(raw[OID_HA_CURRENT_STATE]),
            peer_state=to_int(raw[OID_HA_PEER_STATE]),
        )
