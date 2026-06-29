"""DataUpdateCoordinator for the Sophos Firewall integration.

Polling architecture — 5 Tiers
--------------------------------
Each endpoint is assigned to a tier based on how often its data changes.
Tier intervals and which endpoints to poll are fully configurable in the
Options Flow and stored in config_entry.options.

    Tier 1 REALTIME  (default 30s):
        XML:  interfaces
        SNMP: stats (RAM/disk/traffic), services

    Tier 2 FAST      (default 2 min):
        SNMP: vpn_tunnels, ha_status

    Tier 3 OPERATIVE (default 10 min):
        XML:  firewall_rules
        SNMP: system_health
        Note: write-ops (switch/button) trigger async_request_refresh()
              immediately regardless of tier interval.

    Tier 4 STATIC    (default 30 min):
        XML:  dhcp_servers (incl. StaticLeases), web_filter_policies, backup
        SNMP: licenses

    Tier 5 ONCE      (only on first fetch, never re-polled):
        XML:  zones, admin_settings
        SNMP: device_info

API call reduction vs. polling everything every 30s:
    Before:  14 requests/30s  → 1,680/h
    After:   ~6 requests/30s avg → ~560/h  (67% reduction)
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import timedelta
from typing import Any, TypedDict

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    # Polling config keys
    CONF_INTERVAL_REALTIME, CONF_INTERVAL_FAST, CONF_INTERVAL_OPERATIVE,
    CONF_INTERVAL_STATIC,
    CONF_POLL_XML_INTERFACES, CONF_POLL_XML_FW_RULES, CONF_POLL_XML_DHCP,
    CONF_POLL_XML_WEBFILTER, CONF_POLL_XML_ZONES, CONF_POLL_XML_BACKUP,
    CONF_POLL_XML_ADMIN,
    CONF_POLL_SNMP_STATS, CONF_POLL_SNMP_SERVICES, CONF_POLL_SNMP_TUNNELS,
    CONF_POLL_SNMP_HEALTH, CONF_POLL_SNMP_HA, CONF_POLL_SNMP_LICENSES,
    CONF_POLL_SNMP_DEVICE,
    # Defaults
    DEFAULT_INTERVAL_REALTIME, DEFAULT_INTERVAL_FAST, DEFAULT_INTERVAL_OPERATIVE,
    DEFAULT_INTERVAL_STATIC,
    DEFAULT_POLL_XML_INTERFACES, DEFAULT_POLL_XML_FW_RULES, DEFAULT_POLL_XML_DHCP,
    DEFAULT_POLL_XML_WEBFILTER, DEFAULT_POLL_XML_ZONES, DEFAULT_POLL_XML_BACKUP,
    DEFAULT_POLL_XML_ADMIN,
    DEFAULT_POLL_SNMP_STATS, DEFAULT_POLL_SNMP_SERVICES, DEFAULT_POLL_SNMP_TUNNELS,
    DEFAULT_POLL_SNMP_HEALTH, DEFAULT_POLL_SNMP_HA, DEFAULT_POLL_SNMP_LICENSES,
    DEFAULT_POLL_SNMP_DEVICE,
    # SNMP
    CONF_SNMP_ENABLED,
    # Data keys
    DATA_ADMIN, DATA_BACKUP, DATA_DHCP_SERVERS, DATA_FIREWALL_RULES,
    DATA_INTERFACES, DATA_SNMP_DEVICE, DATA_SNMP_HA, DATA_SNMP_HEALTH,
    DATA_SNMP_LICENSES, DATA_SNMP_SERVICES, DATA_SNMP_STATS, DATA_SNMP_TUNNELS,
    DATA_WEB_FILTER_POLICIES, DATA_ZONES,
    DOMAIN,
)
from .sophos_client import SophosAPIError, SophosAuthError, SophosClient
from .snmp_client import SNMPClient

_LOGGER = logging.getLogger(__name__)

# Max concurrent XML requests (Keep-Alive, not cold TLS)
_XML_CONCURRENCY = 2


class SophosData(TypedDict):
    """Typed structure of coordinator data shared with all entity platforms."""

    # XML API
    interfaces:           list[dict[str, Any]]
    zones:                list[dict[str, Any]]
    firewall_rules:       list[dict[str, Any]]
    web_filter_policies:  list[dict[str, Any]]
    dhcp_servers:         list[dict[str, Any]]
    backup:               dict[str, Any]
    admin:                dict[str, Any]
    # SNMP
    snmp_device:          dict[str, Any]
    snmp_stats:           dict[str, Any]
    snmp_services:        dict[str, Any]
    snmp_licenses:        dict[str, Any]
    snmp_tunnels:         list[dict[str, Any]]
    snmp_health:          dict[str, Any]
    snmp_ha:              dict[str, Any]


class SophosCoordinator(DataUpdateCoordinator[SophosData]):
    """Tiered polling coordinator for Sophos Firewall XML API and SNMP."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        xml_client: SophosClient,
        snmp_client: SNMPClient | None,
    ) -> None:
        opts = entry.options
        data = entry.data

        # Helper: read from options, fall back to entry data, then default
        def _o(key: str, default: Any) -> Any:
            return opts.get(key, data.get(key, default))

        # Tier intervals
        self._iv_realtime  = _o(CONF_INTERVAL_REALTIME,  DEFAULT_INTERVAL_REALTIME)
        self._iv_fast      = _o(CONF_INTERVAL_FAST,      DEFAULT_INTERVAL_FAST)
        self._iv_operative = _o(CONF_INTERVAL_OPERATIVE, DEFAULT_INTERVAL_OPERATIVE)
        self._iv_static    = _o(CONF_INTERVAL_STATIC,    DEFAULT_INTERVAL_STATIC)

        # Defense-in-depth: the config flow validates intervals (min=10s), but
        # options could be set out-of-band (migration, manual .storage edit,
        # legacy entry). A zero/negative realtime interval would make
        # update_interval=timedelta(0) and busy-loop the coordinator, hammering
        # the firewall. Clamp the base interval to a safe floor here.
        if not isinstance(self._iv_realtime, int) or self._iv_realtime < 5:
            _LOGGER.warning(
                "Invalid realtime interval %r — clamping to %ds",
                self._iv_realtime, DEFAULT_INTERVAL_REALTIME,
            )
            self._iv_realtime = DEFAULT_INTERVAL_REALTIME

        # Poll toggles — XML
        self._poll_xml_interfaces = _o(CONF_POLL_XML_INTERFACES, DEFAULT_POLL_XML_INTERFACES)
        self._poll_xml_fw_rules   = _o(CONF_POLL_XML_FW_RULES,   DEFAULT_POLL_XML_FW_RULES)
        self._poll_xml_dhcp       = _o(CONF_POLL_XML_DHCP,       DEFAULT_POLL_XML_DHCP)
        self._poll_xml_webfilter  = _o(CONF_POLL_XML_WEBFILTER,  DEFAULT_POLL_XML_WEBFILTER)
        self._poll_xml_zones      = _o(CONF_POLL_XML_ZONES,      DEFAULT_POLL_XML_ZONES)
        self._poll_xml_backup     = _o(CONF_POLL_XML_BACKUP,     DEFAULT_POLL_XML_BACKUP)
        self._poll_xml_admin      = _o(CONF_POLL_XML_ADMIN,      DEFAULT_POLL_XML_ADMIN)

        # Poll toggles — SNMP
        self._poll_snmp_stats     = _o(CONF_POLL_SNMP_STATS,     DEFAULT_POLL_SNMP_STATS)
        self._poll_snmp_services  = _o(CONF_POLL_SNMP_SERVICES,  DEFAULT_POLL_SNMP_SERVICES)
        self._poll_snmp_tunnels   = _o(CONF_POLL_SNMP_TUNNELS,   DEFAULT_POLL_SNMP_TUNNELS)
        self._poll_snmp_health    = _o(CONF_POLL_SNMP_HEALTH,    DEFAULT_POLL_SNMP_HEALTH)
        self._poll_snmp_ha        = _o(CONF_POLL_SNMP_HA,        DEFAULT_POLL_SNMP_HA)
        self._poll_snmp_licenses  = _o(CONF_POLL_SNMP_LICENSES,  DEFAULT_POLL_SNMP_LICENSES)
        self._poll_snmp_device    = _o(CONF_POLL_SNMP_DEVICE,    DEFAULT_POLL_SNMP_DEVICE)

        self.xml_client   = xml_client
        self._snmp_client = snmp_client
        self._snmp_enabled = (
            entry.data.get(CONF_SNMP_ENABLED, False) and snmp_client is not None
        )
        self._xml_sem = asyncio.Semaphore(_XML_CONCURRENCY)

        # VM detection: once confirmed as virtual appliance, skip health polling
        # (temperature/fan OIDs always return None on SFVH)
        self._is_virtual: bool | None = None  # None = not yet determined

        # Timestamps of last fetch per tier (0 = never)
        self._last_realtime:  float = 0.0
        self._last_fast:      float = 0.0
        self._last_operative: float = 0.0
        self._last_static:    float = 0.0
        self._once_done:      bool  = False  # Tier 5: run exactly once

        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_{entry.entry_id}",
            update_interval=timedelta(seconds=self._iv_realtime),
            config_entry=entry,
        )

    async def async_close(self) -> None:
        """Close the HTTP session when the entry is unloaded."""
        await self.xml_client.close()

    def force_operative_refresh(self) -> None:
        """Force the operative tier to be treated as due on the next refresh.

        Call this after any write operation (switch toggle, button press) that
        modifies data polled in the operative tier (firewall rules, web filter).
        Without this, the switch state would show stale data for up to 10 minutes.
        """
        self._last_operative = 0.0

    # ── Tier due-checks ───────────────────────────────────────────────────────

    def _due(self, last: float, interval: int) -> bool:
        """Return True when enough time has elapsed since last fetch."""
        if interval <= 0:
            return False
        return (time.monotonic() - last) >= interval

    # ── Main update ───────────────────────────────────────────────────────────

    async def _async_update_data(self) -> SophosData:
        """Fetch data according to the tiered polling schedule."""
        now = time.monotonic()

        run_realtime  = self._due(self._last_realtime,  self._iv_realtime)
        run_fast      = self._due(self._last_fast,      self._iv_fast)
        run_operative = self._due(self._last_operative, self._iv_operative)
        run_static    = self._due(self._last_static,    self._iv_static)
        run_once      = not self._once_done

        _LOGGER.debug(
            "Tiers due — realtime:%s fast:%s operative:%s static:%s once:%s",
            run_realtime, run_fast, run_operative, run_static, run_once,
        )

        # ── XML API ───────────────────────────────────────────────────────────
        try:
            xml_data = await self._fetch_xml(
                run_realtime, run_operative, run_static, run_once
            )
        except SophosAuthError as exc:
            # Session-Timeouts oder transiente Firmware-Fehler können einen
            # Auth-Fehler auslösen obwohl die Credentials korrekt sind.
            # Einmaliger Retry nach kurzem Delay bevor wir ConfigEntryAuthFailed
            # werfen — das würde den Coordinator dauerhaft deaktivieren.
            _LOGGER.warning(
                "Auth error from XML API, attempting re-login (%s)", exc
            )
            await asyncio.sleep(2)
            try:
                xml_data = await self._fetch_xml(
                    run_realtime, run_operative, run_static, run_once
                )
                _LOGGER.info("Re-login successful after auth error")
            except SophosAuthError as exc2:
                _LOGGER.error(
                    "Re-login failed — credentials invalid or firewall unreachable: %s",
                    exc2,
                )
                raise ConfigEntryAuthFailed(
                    translation_domain=DOMAIN,
                    translation_key="auth_failed",
                ) from exc2
            except SophosAPIError as exc2:
                raise UpdateFailed(
                    translation_domain=DOMAIN,
                    translation_key="xml_api_error",
                ) from exc2
            else:
                # Re-login succeeded — reset all tier timestamps so every tier
                # runs on the next cycle regardless of when it last ran.
                # Without this, tiers that were "not due" before the auth error
                # would silently skip their first fetch after recovery.
                self._last_realtime  = 0.0
                self._last_fast      = 0.0
                self._last_operative = 0.0
                self._last_static    = 0.0
                self._once_done      = False
        except SophosAPIError as exc:
            raise UpdateFailed(
                translation_domain=DOMAIN,
                translation_key="xml_api_error",
            ) from exc

        # ── SNMP ──────────────────────────────────────────────────────────────
        if self._snmp_enabled:
            snmp_data = await self._fetch_snmp(
                run_realtime, run_fast, run_operative, run_static, run_once
            )
            # Detect virtual appliance only when health was actually polled
            if run_operative and self._poll_snmp_health:
                self._detect_virtual_appliance(snmp_data)
        else:
            snmp_data = self._empty_snmp()

        # ── Update timestamps ─────────────────────────────────────────────────
        if run_realtime:
            self._last_realtime = now
        if run_fast:
            self._last_fast = now
        if run_operative:
            self._last_operative = now
        if run_static:
            self._last_static = now
        if run_once:
            self._once_done = True

        return {**xml_data, **snmp_data}

    # ── XML fetch ─────────────────────────────────────────────────────────────

    async def _fetch_xml(
        self,
        realtime: bool,
        operative: bool,
        static: bool,
        once: bool,
    ) -> dict[str, Any]:
        """Fetch XML endpoints for tiers that are due.

        Endpoints within each tier are fetched concurrently via asyncio.gather()
        bounded by the Semaphore(2) — matching the pattern used by _fetch_snmp().
        Endpoints not due for their tier return the previously cached value.
        """
        sem = self._xml_sem

        async def g(coro):
            """Run coro with connection-pool semaphore."""
            async with sem:
                return await coro

        def _keep(key: str, default: Any) -> Any:
            """Return previous value from coordinator.data."""
            return (self.data.get(key) if self.data else None) or default

        # ── Build per-tier coroutine lists ────────────────────────────────────
        coros:    list = []
        keys:     list[str] = []

        # Tier 1 REALTIME
        if realtime and self._poll_xml_interfaces:
            coros.append(g(self.xml_client.get_interfaces()))
            keys.append(DATA_INTERFACES)

        # Tier 3 OPERATIVE
        if operative and self._poll_xml_fw_rules:
            coros.append(g(self.xml_client.get_firewall_rules()))
            keys.append(DATA_FIREWALL_RULES)

        # Tier 4 STATIC
        if static and self._poll_xml_dhcp:
            coros.append(g(self.xml_client.get_dhcp_servers()))
            keys.append(DATA_DHCP_SERVERS)
        if static and self._poll_xml_webfilter:
            coros.append(g(self.xml_client.get_web_filter_policies()))
            keys.append(DATA_WEB_FILTER_POLICIES)
        if static and self._poll_xml_backup:
            coros.append(g(self.xml_client.get_backup()))
            keys.append(DATA_BACKUP)

        # Tier 5 ONCE
        if once and self._poll_xml_zones:
            coros.append(g(self.xml_client.get_zones()))
            keys.append(DATA_ZONES)
        if once and self._poll_xml_admin:
            coros.append(g(self.xml_client.get_admin_settings()))
            keys.append(DATA_ADMIN)

        # ── Fetch all due endpoints concurrently ──────────────────────────────
        results = await asyncio.gather(*coros) if coros else []
        fetched = dict(zip(keys, results))

        def _r(key: str, default: Any) -> Any:
            """Return fetched value or fall back to cached/default."""
            return fetched[key] if key in fetched else _keep(key, default)

        return {
            DATA_INTERFACES:          _r(DATA_INTERFACES,          []),
            DATA_ZONES:               _r(DATA_ZONES,               []),
            DATA_FIREWALL_RULES:      _r(DATA_FIREWALL_RULES,      []),
            DATA_WEB_FILTER_POLICIES: _r(DATA_WEB_FILTER_POLICIES, []),
            DATA_DHCP_SERVERS:        _r(DATA_DHCP_SERVERS,        []),
            DATA_BACKUP:              _r(DATA_BACKUP,              {}),
            DATA_ADMIN:               _r(DATA_ADMIN,               {}),
        }

    # ── SNMP fetch ────────────────────────────────────────────────────────────

    async def _fetch_snmp(
        self,
        realtime: bool,
        fast: bool,
        operative: bool,
        static: bool,
        once: bool,
    ) -> dict[str, Any]:
        """Fetch SNMP endpoints for tiers that are due."""
        if self._snmp_client is None:
            _LOGGER.error("_fetch_snmp called but snmp_client is None — this is a bug")
            return self._empty_snmp()

        def _keep(key: str) -> Any:
            return self.data.get(key) if self.data else None

        async def _gather_tier(
            tier_name: str,
            coros: list,
            keys: list[str],
            defaults: dict[str, Any],
        ) -> dict[str, Any]:
            """Run one SNMP tier with return_exceptions so a single failing OID
            doesn't abort all other tiers.  Network errors are logged as warning
            (non-fatal); unexpected errors as error."""
            if not coros:
                return {}
            raw = await asyncio.gather(*coros, return_exceptions=True)
            result: dict[str, Any] = {}
            for key, val in zip(keys, raw):
                if isinstance(val, (asyncio.TimeoutError, OSError)):
                    _LOGGER.warning(
                        "SNMP tier %s: network error for %s (%s) — retaining cached value",
                        tier_name, key, val,
                    )
                    result[key] = _keep(key) if self.data else defaults.get(key)
                elif isinstance(val, Exception):
                    _LOGGER.error(
                        "SNMP tier %s: unexpected error for %s (%s)",
                        tier_name, key, val, exc_info=val,
                    )
                    result[key] = _keep(key) if self.data else defaults.get(key)
                else:
                    result[key] = val
            return result

        # ── Tier 1 REALTIME ───────────────────────────────────────────────
        coros_realtime: list = []
        keys_realtime:  list[str] = []
        if realtime and self._poll_snmp_stats:
            coros_realtime.append(self._snmp_client.get_stats())
            keys_realtime.append(DATA_SNMP_STATS)
        if realtime and self._poll_snmp_services:
            coros_realtime.append(self._snmp_client.get_services())
            keys_realtime.append(DATA_SNMP_SERVICES)

        results_realtime = await _gather_tier(
            "realtime", coros_realtime, keys_realtime,
            {DATA_SNMP_STATS: {}, DATA_SNMP_SERVICES: {}},
        )

        # ── Tier 2 FAST ───────────────────────────────────────────────────
        coros_fast: list = []
        keys_fast:  list[str] = []
        if fast and self._poll_snmp_tunnels:
            coros_fast.append(self._snmp_client.get_vpn_tunnels())
            keys_fast.append(DATA_SNMP_TUNNELS)
        if fast and self._poll_snmp_ha:
            coros_fast.append(self._snmp_client.get_ha_status())
            keys_fast.append(DATA_SNMP_HA)

        results_fast = await _gather_tier(
            "fast", coros_fast, keys_fast,
            {DATA_SNMP_TUNNELS: [], DATA_SNMP_HA: {}},
        )

        # ── Tier 3 OPERATIVE ─────────────────────────────────────────────
        coros_op: list = []
        keys_op:  list[str] = []
        # Skip health polling on confirmed virtual appliances —
        # temperature/fan OIDs always return None on SFVH
        poll_health = self._poll_snmp_health and self._is_virtual is not True
        if operative and poll_health:
            coros_op.append(self._snmp_client.get_system_health())
            keys_op.append(DATA_SNMP_HEALTH)

        results_op = await _gather_tier(
            "operative", coros_op, keys_op,
            {DATA_SNMP_HEALTH: {}},
        )

        # ── Tier 4 STATIC ─────────────────────────────────────────────────
        coros_static: list = []
        keys_static:  list[str] = []
        if static and self._poll_snmp_licenses:
            coros_static.append(self._snmp_client.get_licenses())
            keys_static.append(DATA_SNMP_LICENSES)

        results_static = await _gather_tier(
            "static", coros_static, keys_static,
            {DATA_SNMP_LICENSES: {}},
        )

        # ── Tier 5 ONCE ───────────────────────────────────────────────────
        coros_once: list = []
        keys_once:  list[str] = []
        if once and self._poll_snmp_device:
            coros_once.append(self._snmp_client.get_device_info())
            keys_once.append(DATA_SNMP_DEVICE)

        results_once = await _gather_tier(
            "once", coros_once, keys_once,
            {DATA_SNMP_DEVICE: {}},
        )

        # ── Merge results with previous data ──────────────────────────────────
        def _r(tier_result: dict[str, Any], data_key: str, default: Any) -> Any:
            """Return fetched value from tier dict, or fall back to cached/default."""
            if data_key in tier_result:
                return tier_result[data_key]
            return (_keep(data_key) if self.data else None) or default

        return {
            DATA_SNMP_STATS:    _r(results_realtime, DATA_SNMP_STATS,    {}),
            DATA_SNMP_SERVICES: _r(results_realtime, DATA_SNMP_SERVICES, {}),
            DATA_SNMP_TUNNELS:  _r(results_fast,     DATA_SNMP_TUNNELS,  []),
            DATA_SNMP_HA:       _r(results_fast,     DATA_SNMP_HA,       {}),
            DATA_SNMP_HEALTH:   _r(results_op,       DATA_SNMP_HEALTH,   {}),
            DATA_SNMP_LICENSES: _r(results_static,   DATA_SNMP_LICENSES, {}),
            DATA_SNMP_DEVICE:   _r(results_once,     DATA_SNMP_DEVICE,   {}),
        }

    def _detect_virtual_appliance(self, snmp_data: dict) -> None:
        """Detect virtual appliance from SNMP data after first health fetch.

        Sets self._is_virtual = True when:
        - cpu_temperature_c is None (OIDs unsupported on SFVH)
        - fans dict is empty (no hardware fans)

        Once confirmed virtual, health polling is skipped in future cycles
        to avoid unnecessary SNMP requests that always return nothing.
        """
        if self._is_virtual is not None:
            return  # already determined
        health = snmp_data.get(DATA_SNMP_HEALTH, {})
        if not health:
            return  # health not yet fetched

        cpu_temp = health.get("cpu_temperature_c")
        fans     = health.get("fans", {})

        if cpu_temp is None and not fans:
            self._is_virtual = True
            _LOGGER.info(
                "Virtual appliance detected (SFVH) — "
                "hardware health polling disabled (temperature/fan OIDs unavailable)"
            )
        else:
            self._is_virtual = False
            _LOGGER.debug("Physical appliance confirmed — hardware health polling active")

    @staticmethod
    def _empty_snmp() -> dict[str, Any]:
        return {
            DATA_SNMP_DEVICE:   {},
            DATA_SNMP_STATS:    {},
            DATA_SNMP_SERVICES: {},
            DATA_SNMP_LICENSES: {},
            DATA_SNMP_TUNNELS:  [],
            DATA_SNMP_HEALTH:   {},
            DATA_SNMP_HA:       {},
        }
