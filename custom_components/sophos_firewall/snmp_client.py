"""SNMP client for Sophos Firewall system metrics.

Uses puresnmp 2.x — a pure-Python async SNMP library.

Key implementation notes
------------------------
1. Client instantiation: Client() is created ONCE and reused. Never use
   ``async with Client()`` — puresnmp's Client has no __aexit__ method.

2. Blocking I/O: puresnmp lazily imports its MPM (Message Processing Model)
   plugin on the first network call. This triggers blocking filesystem I/O
   (import_module, listdir). We preload the MPM in an executor thread during
   setup so all subsequent SNMP calls are non-blocking in the event loop.

3. OID syntax: ObjectIdentifier(dotted_string) — not from_string().

4. Error handling: every call is wrapped in try/except and returns a safe
   default (None or {}) so SNMP failures never crash the coordinator.

OID source: Official Sophos XG MIB (SOPHOS-XG-MIB.mib)
Base OID:   1.3.6.1.4.1.2604.5.1
Verified:   SFOS 22.0.0 GA-Build411 (APIVersion 2200.1)
"""
from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timedelta as _timedelta_type
from typing import Any

from .const import (
    DEFAULT_SNMP_TIMEOUT,
    LICENSE_OIDS,
    OID_CPU_TEMPERATURE,
    OID_CURRENT_DATE,
    OID_DEVICE_APP_KEY,
    OID_DEVICE_FW_VERSION,
    OID_DEVICE_NAME,
    OID_DEVICE_TYPE,
    OID_DISK_CAPACITY,
    OID_DISK_PERCENT,
    OID_FAN_TABLE_WALK,
    OID_FTP_HITS,
    OID_HA_CURRENT_STATE,
    OID_HA_PEER_STATE,
    OID_HA_STATUS,
    OID_HTTP_HITS,
    OID_IPS_VERSION,
    OID_LIVE_USERS,
    OID_MEMORY_CAPACITY,
    OID_MEMORY_PERCENT,
    OID_NPU_TEMPERATURE,
    OID_PSU_TABLE_WALK,
    OID_SMTP_HITS,
    OID_IMAP_HITS,
    OID_POP3_HITS,
    OID_SWAP_CAPACITY,
    OID_SWAP_PERCENT,
    OID_UPTIME,
    OID_VPN_WALK_BASE,
    OID_WEBCAT_VERSION,
    SERVICE_OIDS,
    VPN_COL_ACTIVATED,
    VPN_COL_NAME,
    VPN_COL_STATUS,
)

_LOGGER = logging.getLogger(__name__)

# Serialises the one-time puresnmp security-plugin monkeypatch across
# concurrent preload() calls. Multiple firewall config entries can run
# async_setup_entry (and thus preload) in parallel, each in its own executor
# thread; without this lock two threads could both pass the "_sophos_ha_patched"
# guard before either sets it, applying the patch twice. The patch is
# idempotent so this is a hygiene/efficiency fix, not a correctness bug — but
# serialising it keeps logs clean and avoids redundant plugin discovery.
_PATCH_LOCK = threading.Lock()


def _py(value: Any) -> Any:
    """Convert a puresnmp x690 type object to a native Python value.

    puresnmp returns typed objects (Integer, OctetString, TimeTicks, etc.)
    rather than plain Python values. Without conversion:
        str(Integer(27))      → "Integer(27)"   ← breaks _safe_int
        str(OctetString(...)) → "OctetString(b'5HeyneXG')"  ← wrong name

    pythonize() gives us:
        Integer(27).pythonize()       → 27  (int)
        OctetString(b'abc').pythonize() → b'abc'  (bytes)
        TimeTicks(n).pythonize()      → n  (int, hundredths of seconds)
    """
    if value is None:
        return None
    if hasattr(value, "pythonize"):
        py = value.pythonize()
        if isinstance(py, bytes):
            return py.decode("utf-8", errors="replace")
        return py
    return value


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert any SNMP value (including x690 types) to int.

    After _py() / pythonize(), puresnmp Integer values are already plain
    Python ints. The str() fallback handles edge cases from older puresnmp
    versions or unexpected OID types.
    """
    v = _py(value)
    if v is None:
        return default
    if isinstance(v, int):
        return v
    try:
        return int(str(v).split()[0])
    except (ValueError, IndexError, AttributeError):
        _LOGGER.debug(
            "_safe_int: could not convert %r to int, using default %d", v, default
        )
        return default


def _safe_str(value: Any) -> str | None:
    """Convert SNMP value to string, returning None if empty or missing."""
    v = _py(value)
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _timeticks_to_seconds(value: Any) -> int:
    """Convert SNMP Timeticks to seconds.

    puresnmp TimeTicks.pythonize() returns a datetime.timedelta, not an int.
    We handle both cases:
    - timedelta: total_seconds() gives float seconds directly
    - int: raw timeticks value in hundredths of seconds → divide by 100
    """
    if value is None:
        return 0
    py = _py(value)
    if py is None:
        return 0
    if isinstance(py, _timedelta_type):
        return int(py.total_seconds())
    # Raw int from older puresnmp versions: hundredths of seconds
    try:
        return int(py) // 100
    except (TypeError, ValueError):
        return 0


def _oid(dotted: str):
    """Convert dotted OID string to puresnmp ObjectIdentifier."""
    from x690.types import ObjectIdentifier
    return ObjectIdentifier(dotted)


class SNMPClient:
    """Async SNMP v2c client using puresnmp (pure Python, no system tools needed).

    The client is created once and reused across all poll cycles.
    Call ``await client.preload()`` once during setup to load the puresnmp
    MPM plugin in an executor thread, avoiding blocking I/O in the event loop.

    Usage::

        client = SNMPClient("192.168.1.1", community="public")
        await client.preload()   # once during setup
        if await client.test_connection():
            stats = await client.get_stats()
    """

    def __init__(
        self,
        host: str,
        community: str = "public",
        version: str = "2c",
        port: int = 161,
        timeout: int = DEFAULT_SNMP_TIMEOUT,
    ) -> None:
        self._host = host
        self._community = community
        self._port = port
        self._timeout = timeout
        self._client = None  # lazily created after preload

    # ── Setup ─────────────────────────────────────────────────────────────────

    @staticmethod
    def is_available() -> bool:
        """Return True if puresnmp is installed."""
        try:
            import puresnmp  # noqa: F401
            return True
        except ImportError:
            return False

    async def preload(self) -> None:
        """Preload all puresnmp plugins and patch the security plugin loader.

        Root cause of blocking I/O:
        puresnmp.plugins.security.create() creates a NEW Loader() instance on
        every call. Since Loader.discovered_plugins starts empty, it triggers
        discover_plugins() (→ pkgutil.iter_modules → listdir + import_module)
        on the first call — inside the event loop.

        Fix: Run discover_plugins() once in an executor thread, then
        monkey-patch security.create() to use a pre-populated cached Loader,
        so no further filesystem I/O occurs on subsequent calls.

        The patch is applied at module level and is idempotent — if multiple
        firewall entries call preload() concurrently, only the first patch
        takes effect; subsequent calls skip the patch and only create the
        puresnmp Client instance.
        """
        def _load() -> None:
            from puresnmp import Client, V2C
            from puresnmp.plugins import security as sec_plugin
            from puresnmp.plugins.pluginbase import Loader, discover_plugins

            # Guard: only apply the global patch once across all instances.
            # Multiple firewall entries share the same puresnmp module globals;
            # re-patching is harmless but wasteful and confusing in logs.
            # The lock makes the check-and-set atomic so two concurrent
            # preload() calls (each in its own executor thread) can't both
            # apply the patch.
            with _PATCH_LOCK:
                if not getattr(sec_plugin, "_sophos_ha_patched", False):
                    # Build a persistent Loader and populate it once (blocking I/O
                    # here is fine — we're in an executor thread, not the loop)
                    cached_loader = Loader(
                        "puresnmp_plugins.security",
                        sec_plugin.is_valid_sec_plugin,
                    )
                    cached_loader.discovered_plugins = discover_plugins(
                        "puresnmp_plugins.security",
                        sec_plugin.is_valid_sec_plugin,
                    )

                    # Monkey-patch security.create() to use the cached loader.
                    # IMPORTANT: loader.create() returns the MODULE, not an instance.
                    # The original security.create() calls result.create() on the
                    # module to get a SecurityModel instance. We must do the same.
                    def _cached_create(identifier: int):
                        mod = cached_loader.create(identifier)
                        if mod is None:
                            from puresnmp.exc import UnknownSecurityModel
                            raise UnknownSecurityModel(
                                "puresnmp_plugins.security",
                                identifier,
                                sorted(cached_loader.discovered_plugins.keys()),
                            )
                        return mod.create()  # ← SecurityModel instance, not module

                    sec_plugin.create = _cached_create
                    sec_plugin._sophos_ha_patched = True

                    # Also patch create_sm in each MPM plugin that imported it
                    import puresnmp_plugins.mpm.v1 as _v1
                    import puresnmp_plugins.mpm.v2c as _v2c
                    _v1.create_sm  = _cached_create
                    _v2c.create_sm = _cached_create
                    try:
                        import puresnmp_plugins.mpm.v3 as _v3
                        _v3.create_sm = _cached_create
                    except ImportError:
                        pass

            self._client = Client(
                ip=self._host,
                credentials=V2C(self._community),
                port=self._port,
            )

        # Fix: asyncio.get_event_loop() is deprecated in Python 3.10+.
        # asyncio.to_thread() uses the running loop's executor correctly.
        await asyncio.to_thread(_load)
        _LOGGER.debug(
            "SNMPClient preloaded for %s (security plugin loader patched — no blocking I/O)",
            self._host,
        )

    def _get_client(self):
        """Return the shared puresnmp Client instance.

        Raises RuntimeError if preload() was never called. Creating a Client
        without preload() would trigger blocking filesystem I/O (pkgutil.iter_modules)
        inside the event loop — exactly the bug preload() was designed to prevent.
        """
        if self._client is None:
            raise RuntimeError(
                "SNMPClient._get_client() called before preload() — "
                "this would cause blocking I/O in the event loop. "
                "Call await snmp_client.preload() during setup."
            )
        return self._client

    # ── Low-level helpers ─────────────────────────────────────────────────────

    async def _get(self, oid_str: str) -> Any:
        """Fetch a single scalar OID. Returns None on any error."""
        try:
            client = self._get_client()
            result = await asyncio.wait_for(
                client.get(_oid(oid_str)),
                timeout=self._timeout,
            )
            return result
        except asyncio.TimeoutError:
            _LOGGER.debug("SNMP get %s: timeout", oid_str)
            return None
        except RuntimeError as exc:
            # _get_client() raises RuntimeError only when preload() was never
            # called — this is an implementation bug, not a transient network
            # condition, so it gets its own WARNING instead of being silently
            # downgraded to DEBUG alongside ordinary timeouts.
            _LOGGER.warning("SNMP get %s: %s", oid_str, exc)
            return None
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("SNMP get %s: %s", oid_str, exc)
            return None

    async def _multiget(self, oids: list[str]) -> dict[str, Any]:
        """Fetch multiple OIDs in one PDU. Returns dict oid→value.

        Non-blocking because preload() patches security.create() to use a
        cached Loader, preventing listdir/import_module on every call.
        """
        if not oids:
            return {}
        try:
            client = self._get_client()
            results = await asyncio.wait_for(
                client.multiget([_oid(o) for o in oids]),
                timeout=self._timeout,
            )
            return dict(zip(oids, results))
        except asyncio.TimeoutError:
            _LOGGER.debug("SNMP multiget timeout (%d OIDs)", len(oids))
            return {o: None for o in oids}
        except RuntimeError as exc:
            # See _get() — preload() was never called, an implementation bug.
            _LOGGER.warning("SNMP multiget failed: %s", exc)
            return {o: None for o in oids}
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("SNMP multiget failed: %s", exc)
            return {o: None for o in oids}

    async def _walk(self, base_oid: str) -> dict[str, Any]:
        """Walk an OID subtree. Returns dict oid_string→value."""
        result: dict[str, Any] = {}
        try:
            client = self._get_client()
            async for varbind in client.walk(_oid(base_oid)):
                result[str(varbind.oid)] = varbind.value
        except asyncio.TimeoutError:
            _LOGGER.debug("SNMP walk %s: timeout", base_oid)
        except RuntimeError as exc:
            # See _get() — preload() was never called, an implementation bug.
            _LOGGER.warning("SNMP walk %s: %s", base_oid, exc)
        except Exception as exc:  # noqa: BLE001
            _LOGGER.debug("SNMP walk %s: %s", base_oid, exc)
        return result

    # ── Connection test ───────────────────────────────────────────────────────

    async def test_connection(self) -> bool:
        """Return True if the SNMP agent responds to the device name OID."""
        value = await self._get(OID_DEVICE_NAME)
        return value is not None

    # ── Data fetch methods ────────────────────────────────────────────────────

    async def get_device_info(self) -> dict[str, str]:
        """Return device info via single multiget PDU."""
        oids = [OID_DEVICE_NAME, OID_DEVICE_TYPE, OID_DEVICE_FW_VERSION,
                OID_DEVICE_APP_KEY, OID_WEBCAT_VERSION, OID_IPS_VERSION]
        raw = await self._multiget(oids)
        return {
            oid: _safe_str(val)
            for oid, val in raw.items()
            if _safe_str(val) is not None
        }

    async def get_stats(self) -> dict[str, Any]:
        """Return system performance stats via single multiget PDU."""
        oids = [OID_CURRENT_DATE, OID_UPTIME, OID_DISK_CAPACITY, OID_DISK_PERCENT,
                OID_MEMORY_CAPACITY, OID_MEMORY_PERCENT, OID_SWAP_CAPACITY,
                OID_SWAP_PERCENT, OID_LIVE_USERS, OID_HTTP_HITS,
                OID_FTP_HITS, OID_SMTP_HITS, OID_IMAP_HITS, OID_POP3_HITS]
        raw = await self._multiget(oids)
        return {
            "current_date":       _safe_str(raw.get(OID_CURRENT_DATE)) or "",
            "uptime_seconds":     _timeticks_to_seconds(raw.get(OID_UPTIME)),
            "disk_capacity_mb":   _safe_int(raw.get(OID_DISK_CAPACITY)),
            "disk_percent":       _safe_int(raw.get(OID_DISK_PERCENT)),
            "memory_capacity_mb": _safe_int(raw.get(OID_MEMORY_CAPACITY)),
            "memory_percent":     _safe_int(raw.get(OID_MEMORY_PERCENT)),
            "swap_capacity_mb":   _safe_int(raw.get(OID_SWAP_CAPACITY)),
            "swap_percent":       _safe_int(raw.get(OID_SWAP_PERCENT)),
            "live_users":         _safe_int(raw.get(OID_LIVE_USERS)),
            "http_hits":          _safe_int(raw.get(OID_HTTP_HITS)),
            "ftp_hits":           _safe_int(raw.get(OID_FTP_HITS)),
            "smtp_hits":          _safe_int(raw.get(OID_SMTP_HITS)),
            "imap_hits":          _safe_int(raw.get(OID_IMAP_HITS)),
            "pop3_hits":          _safe_int(raw.get(OID_POP3_HITS)),
        }

    async def get_services(self) -> dict[str, int]:
        """Return all 21 service status codes via single multiget PDU."""
        oids = list(SERVICE_OIDS.keys())
        raw = await self._multiget(oids)
        return {
            key: _safe_int(raw.get(oid), default=-1)
            for oid, (key, _) in SERVICE_OIDS.items()
        }

    async def get_licenses(self) -> dict[str, dict[str, Any]]:
        """Return license status + expiry for all modules via single multiget."""
        all_oids = []
        for status_oid, (_, _, expiry_oid) in LICENSE_OIDS.items():
            all_oids += [status_oid, expiry_oid]
        raw = await self._multiget(all_oids)
        return {
            key: {
                "name":        friendly,
                "status_code": _safe_int(raw.get(status_oid), 0),
                "expiry_date": _safe_str(raw.get(expiry_oid)) or "unknown",
            }
            for status_oid, (key, friendly, expiry_oid) in LICENSE_OIDS.items()
        }

    async def get_vpn_tunnels(self) -> list[dict[str, Any]]:
        """Return IPSec VPN tunnel list via table walk."""
        data = await self._walk(OID_VPN_WALK_BASE)
        tunnels: dict[str, dict[str, Any]] = {}
        for full_oid, value in data.items():
            parts = full_oid.split(".")
            if len(parts) < 2:
                continue
            field, idx = parts[-2], parts[-1]
            if idx not in tunnels:
                tunnels[idx] = {"index": idx, "name": "", "conn_status": -1, "activated": -1}
            if field == VPN_COL_NAME:
                tunnels[idx]["name"] = _safe_str(value) or ""
            elif field == VPN_COL_STATUS:
                tunnels[idx]["conn_status"] = _safe_int(value, -1)
            elif field == VPN_COL_ACTIVATED:
                tunnels[idx]["activated"] = _safe_int(value, -1)
        return [t for t in tunnels.values() if t["name"]]

    async def get_system_health(self) -> dict[str, Any]:
        """Return hardware health (temperatures, fans, PSUs)."""
        temp_raw = await self._multiget([OID_CPU_TEMPERATURE, OID_NPU_TEMPERATURE])

        def _temp(oid: str) -> float | None:
            val = _safe_int(temp_raw.get(oid), -1)
            return round(val / 10, 1) if val > 0 else None

        fan_data = await self._walk(OID_FAN_TABLE_WALK)
        psu_data = await self._walk(OID_PSU_TABLE_WALK)

        def _table_index(oid: str) -> str | None:
            """Extract the table-row index from an OID like '...<index>.2'.

            Returns None for malformed OIDs (too few components) instead of
            raising IndexError, so one unexpected OID can't break the whole
            health fetch.
            """
            parts = oid.rsplit(".", 2)
            if len(parts) < 2:
                return None
            return parts[-2]

        fans: dict[str, int] = {}
        for oid, val in fan_data.items():
            if not oid.endswith(".2"):
                continue
            idx = _table_index(oid)
            if idx:
                fans[f"fan_{idx}"] = _safe_int(val)

        psus: dict[str, bool] = {}
        for oid, val in psu_data.items():
            if not oid.endswith(".2"):
                continue
            idx = _table_index(oid)
            if idx:
                psus[f"psu_{idx}"] = _safe_int(val) == 1

        return {
            "cpu_temperature_c": _temp(OID_CPU_TEMPERATURE),
            "npu_temperature_c": _temp(OID_NPU_TEMPERATURE),
            "fans": fans,
            "psus": psus,
        }

    async def get_ha_status(self) -> dict[str, Any]:
        """Return HA cluster status via multiget.

        OID mapping (sfosXGHAStats .4.x):
          HaStatusType  — 0=disabled, 1=enabled
          HaState       — 0=notapplicable, 1=auxiliary, 2=standAlone,
                          3=primary, 4=faulty, 5=ready
        """
        raw = await self._multiget(
            [OID_HA_STATUS, OID_HA_CURRENT_STATE, OID_HA_PEER_STATE]
        )
        return {
            "ha_enabled":    _safe_int(raw.get(OID_HA_STATUS)) == 1,
            "current_state": _safe_int(raw.get(OID_HA_CURRENT_STATE)),
            "peer_state":    _safe_int(raw.get(OID_HA_PEER_STATE)),
        }
