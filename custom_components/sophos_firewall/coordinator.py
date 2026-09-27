"""Data update coordinators for the Sophos Firewall integration.

Architecture
------------
Two coordinators, one per data source:

* ``SophosXmlCoordinator``  — XML API (HTTPS)
* ``SophosSnmpCoordinator`` — SNMP (UDP), only when SNMP is enabled

Each source has its own availability: an unreachable SNMP agent no longer
takes the XML entities down, and vice versa.

Both coordinators share one mechanism, ``SophosCoordinator``: a declarative
table of *endpoints* (one fetch each), a ``TierScheduler`` that decides which
endpoints are due, and per-endpoint success tracking.

Polling tiers
-------------
The coordinator runs every *realtime* interval. On each run it fetches the
endpoints whose tier is due:

    REALTIME   (default 30 s)   XML interfaces        SNMP stats, services, CPU,
                                                      interface traffic
    FAST       (default 2 min)                        SNMP VPN tunnels, HA state
    OPERATIVE  (default 10 min) XML firewall rules    SNMP hardware health
    STATIC     (default 30 min) XML DHCP, web filter, SNMP licenses, device info
                                backup, admin

Availability semantics
----------------------
* An endpoint whose last fetch failed is *unavailable*; entities fed by it
  report unavailable instead of stale or fabricated values.
* A failed endpoint is retried on the next run, not only after its tier
  interval.
* If *every* due endpoint fails with a connection-level error, the
  coordinator raises ``UpdateFailed`` — the whole source is unreachable and
  Home Assistant logs that once (and logs the recovery once).
* Endpoint-specific failures are logged once when they start and once when
  they recover.
* Conditions only the user can fix raise a repair issue (see issues.py):
  API access denied (532/534) and an SNMP agent that never answered.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    EMPTY_CONFIRMATIONS,
    CONF_POLL_SNMP_HA,
    CONF_POLL_SNMP_HEALTH,
    CONF_POLL_SNMP_LICENSES,
    CONF_POLL_SNMP_SERVICES,
    CONF_POLL_SNMP_STATS,
    CONF_POLL_SNMP_TRAFFIC,
    CONF_POLL_SNMP_TUNNELS,
    CONF_POLL_XML_BACKUP,
    CONF_POLL_XML_DHCP,
    CONF_POLL_XML_FW_RULES,
    CONF_POLL_XML_INTERFACES,
    CONF_POLL_XML_WEBFILTER,
    DEFAULT_INTERVAL_REALTIME,
    DEFAULT_POLL_SNMP_HA,
    DEFAULT_POLL_SNMP_HEALTH,
    DEFAULT_POLL_SNMP_LICENSES,
    DEFAULT_POLL_SNMP_SERVICES,
    DEFAULT_POLL_SNMP_STATS,
    DEFAULT_POLL_SNMP_TRAFFIC,
    DEFAULT_POLL_SNMP_TUNNELS,
    DEFAULT_POLL_XML_BACKUP,
    DEFAULT_POLL_XML_DHCP,
    DEFAULT_POLL_XML_FW_RULES,
    DEFAULT_POLL_XML_INTERFACES,
    DEFAULT_POLL_XML_WEBFILTER,
    DOMAIN,
    EP_ADMIN,
    EP_BACKUP,
    EP_CPU,
    EP_DEVICE,
    EP_DHCP_SERVERS,
    EP_FIREWALL_RULES,
    EP_HA,
    EP_HEALTH,
    EP_INTERFACES,
    EP_LICENSES,
    EP_SERVICES,
    EP_STATS,
    EP_TRAFFIC,
    EP_TUNNELS,
    EP_WEB_FILTER,
    TIER_INTERVAL_KEYS,
    Tier,
)
from .issues import (
    ISSUE_API_ACCESS_DENIED,
    ISSUE_SNMP_UNREACHABLE,
    async_clear_issue,
    async_raise_issue,
)
from .models import InterfaceTraffic, SnmpData, SystemHealth, TrafficSample, XmlData
from .snmp_client import SNMPClient, SophosSNMPError
from .sophos_client import (
    SophosAccessError,
    SophosAuthError,
    SophosClient,
    SophosConnectionError,
    SophosError,
)

_LOGGER = logging.getLogger(__name__)

# Delay before retrying endpoints that reported an authentication failure.
# The firewall occasionally rejects a single request with valid credentials;
# only a failure that survives the retry starts the reauth flow.
AUTH_RETRY_DELAY = 2.0

_MIN_BASE_INTERVAL = 5


def read_option(entry: ConfigEntry, key: str, default: Any) -> Any:
    """Read a setting from the entry options (all non-connection settings)."""
    return entry.options.get(key, default)


@dataclass(frozen=True, slots=True)
class Endpoint[ClientT]:
    """One independently fetched piece of data."""

    key: str  # field name in XmlData / SnmpData
    tier: Tier
    fetch: Callable[[ClientT], Awaitable[Any]]
    toggle: str | None = None  # option key that enables polling, None = always
    toggle_default: bool = True


class TierScheduler:
    """Decide which endpoints are due.

    An endpoint is due when it was never fetched successfully, or when its
    tier interval has elapsed since the last successful fetch — minus half a
    base interval of tolerance.

    Why the tolerance: Home Assistant schedules the next run at
    ``int(loop.time()) + µ + interval`` measured from the *end* of the
    previous run, so the elapsed time between two runs is the interval
    ± a fraction of a second. A strict ``elapsed >= interval`` check skipped
    about every second realtime run (v1.0.x). With the tolerance the
    realtime tier (interval == base) is due on every scheduled run, and slower
    tiers are due on the first run at or after their interval.

    "Never fetched" is None — not 0.0. ``time.monotonic()`` counts from host
    boot, so a 0.0 sentinel made operative/static endpoints look recently
    fetched for the first 10/30 minutes after a host reboot (v1.0.x).
    """

    def __init__(self, intervals: Mapping[Tier, int], base_interval: int) -> None:
        self._intervals = dict(intervals)
        self._tolerance = base_interval / 2
        self._last: dict[str, float] = {}

    def is_due(self, key: str, tier: Tier, now: float) -> bool:
        """Return True if the endpoint should be fetched now."""
        last = self._last.get(key)
        if last is None:
            return True
        return now - last >= self._intervals[tier] - self._tolerance

    def mark_fetched(self, key: str, when: float) -> None:
        """Record a successful fetch."""
        self._last[key] = when

    def invalidate(self, key: str) -> None:
        """Make the endpoint due on the next run."""
        self._last.pop(key, None)


def _int_option(entry: ConfigEntry, key: str, default: int) -> int:
    value = read_option(entry, key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < _MIN_BASE_INTERVAL:
        _LOGGER.warning("Invalid interval %s=%r — using %ds", key, value, default)
        return default
    return value


class SophosCoordinator[ClientT, DataT](DataUpdateCoordinator[DataT]):
    """Endpoint-table driven coordinator shared by the XML and SNMP sources."""

    config_entry: ConfigEntry
    #: Exceptions that mean "the source is unreachable".
    connection_errors: tuple[type[Exception], ...] = ()
    #: Exceptions the client raises by design (logged without traceback).
    expected_errors: tuple[type[Exception], ...] = ()
    #: Translation key for the UpdateFailed raised when the source is unreachable.
    unreachable_translation_key: str = ""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: ClientT,
        *,
        name: str,
        endpoints: Iterable[Endpoint[ClientT]],
        empty: DataT,
    ) -> None:
        self.client = client
        self._endpoints = tuple(endpoints)
        self._empty = empty
        intervals = {
            tier: _int_option(entry, key, default)
            for tier, (key, default) in TIER_INTERVAL_KEYS.items()
        }
        base = intervals[Tier.REALTIME] or DEFAULT_INTERVAL_REALTIME
        self._scheduler = TierScheduler(intervals, base)
        self._ok: dict[str, bool] = {}
        self._failure_logged: set[str] = set()
        self._fetched_at: dict[str, float] = {}
        # Bumped by invalidate(): a fetch that was already running when its
        # endpoint was invalidated (e.g. by a write) must not count as fresh.
        self._generation: dict[str, int] = {}
        self._runtime_disabled: set[str] = set()
        self._restrict_to: frozenset[str] | None = None
        # One update at a time: a background refresh right after setup must
        # not overlap with a scheduled or requested one (the XML API answers
        # one request after another anyway).
        self._update_lock = asyncio.Lock()
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} {name} {entry.data.get(CONF_HOST, '')}".strip(),
            update_interval=timedelta(seconds=base),
        )

    # ── Endpoint state (used by entities and platforms) ───────────────────────

    @property
    def endpoints(self) -> tuple[Endpoint[ClientT], ...]:
        """Return the endpoint table."""
        return self._endpoints

    def endpoint_enabled(self, key: str) -> bool:
        """Return True if the endpoint is polled (option on, not disabled at runtime)."""
        return key not in self._runtime_disabled and self.endpoint_configured(key)

    def endpoint_configured(self, key: str) -> bool:
        """Return True if the user's options enable polling of this endpoint."""
        for endpoint in self._endpoints:
            if endpoint.key == key:
                if endpoint.toggle is None:
                    return True
                return bool(
                    read_option(self.config_entry, endpoint.toggle, endpoint.toggle_default)
                )
        return False

    def endpoint_available(self, key: str) -> bool:
        """Return True if the last fetch of this endpoint succeeded."""
        return self._ok.get(key, False)

    def fetched_at(self, key: str) -> float | None:
        """Return the monotonic time of the last successful fetch."""
        return self._fetched_at.get(key)

    def invalidate(self, *keys: str) -> None:
        """Make the given endpoints due on the next run.

        A cycle that is running right now may already have read the old state
        (before a write): its result for these endpoints is still applied,
        but not recorded as a fetch, so the next run reads them again.
        """
        for key in keys:
            self._scheduler.invalidate(key)
            self._generation[key] = self._generation.get(key, 0) + 1

    async def async_refresh_endpoints(self, *keys: str) -> None:
        """Make the given endpoints due and request a refresh.

        Used after write operations so the written object is re-read no matter
        which tier it belongs to (v1.0.x only reset the operative tier, so the
        web-filter switch — static tier — flipped back for up to 30 minutes).
        """
        self.invalidate(*keys)
        await self.async_request_refresh()

    async def async_first_refresh_of(self, *keys: str) -> None:
        """First refresh limited to these endpoints; the others stay due.

        Setup only waits for what it needs (connectivity, credentials, the
        device name); the caller refreshes the rest in the background. If
        the limited fetch only yields API errors (e.g. an API profile without
        permission for that object), the other endpoints are fetched in the
        same refresh — the first refresh then behaves as before.
        """
        self._restrict_to = frozenset(keys)
        try:
            await self.async_config_entry_first_refresh()
        finally:
            self._restrict_to = None

    # ── Update cycle ──────────────────────────────────────────────────────────

    async def _async_update_data(self) -> DataT:
        """Fetch every due endpoint concurrently and merge the results."""
        async with self._update_lock:
            return await self._update()

    async def _update(self) -> DataT:
        now = time.monotonic()
        due = [
            ep for ep in self._endpoints
            if self.endpoint_enabled(ep.key) and self._scheduler.is_due(ep.key, ep.tier, now)
        ]
        previous: DataT = self.data if self.data is not None else self._empty
        if not due:
            return previous
        generation = dict(self._generation)

        later: list[Endpoint[ClientT]] = []
        if self._restrict_to is not None:
            limited = [ep for ep in due if ep.key in self._restrict_to]
            if limited:
                later = [ep for ep in due if ep.key not in self._restrict_to]
                due = limited

        updates, failures = await self._fetch(due)
        updates, failures = await self._handle_failures(updates, failures)
        if later and not updates and not all(
            isinstance(exc, self.connection_errors) for exc in failures.values()
        ):
            more_updates, more_failures = await self._handle_failures(*await self._fetch(later))
            updates.update(more_updates)
            failures.update(more_failures)

        done = time.monotonic()
        for key in updates:
            if self._generation.get(key) != generation.get(key):
                continue  # invalidated while this cycle ran: read it again
            self._scheduler.mark_fetched(key, done)
            self._fetched_at[key] = done

        outage = bool(failures) and not updates and all(
            isinstance(exc, self.connection_errors) for exc in failures.values()
        )
        for key in updates:
            self._set_endpoint_state(key, None, log=True)
        for key, exc in failures.items():
            self._set_endpoint_state(key, exc, log=not outage)

        if outage or (self.data is None and not updates):
            # Unreachable — or the very first refresh produced nothing usable
            # (e.g. every endpoint answered with an API error). Loading with
            # no data at all would create a device and entities without names.
            first = next(iter(failures.values()))
            raise UpdateFailed(
                translation_domain=DOMAIN,
                translation_key=self.unreachable_translation_key if outage else "no_data",
                translation_placeholders={
                    "host": self.config_entry.data.get(CONF_HOST, ""),
                    "error": str(first),
                },
            ) from first

        data = replace(previous, **self._prepare(updates))  # type: ignore[type-var]
        self._after_update(data, updates)
        return data

    async def _fetch(
        self, endpoints: Iterable[Endpoint[ClientT]]
    ) -> tuple[dict[str, Any], dict[str, Exception]]:
        endpoints = list(endpoints)
        results = await asyncio.gather(
            *(ep.fetch(self.client) for ep in endpoints), return_exceptions=True
        )
        updates: dict[str, Any] = {}
        failures: dict[str, Exception] = {}
        for ep, result in zip(endpoints, results, strict=True):
            if isinstance(result, Exception):
                failures[ep.key] = result
            elif isinstance(result, BaseException):
                raise result  # CancelledError, KeyboardInterrupt, …
            else:
                updates[ep.key] = result
        return updates, failures

    async def _handle_failures(
        self, updates: dict[str, Any], failures: dict[str, Exception]
    ) -> tuple[dict[str, Any], dict[str, Exception]]:
        """Hook for source-specific error handling (may raise)."""
        return updates, failures

    def _prepare(self, updates: dict[str, Any]) -> dict[str, Any]:
        """Hook turning fetched results into data fields (default: as fetched)."""
        return updates

    def _after_update(self, data: DataT, updates: Mapping[str, Any]) -> None:
        """Hook called with the merged data after a successful cycle."""

    def _set_endpoint_state(self, key: str, error: Exception | None, *, log: bool) -> None:
        """Record success/failure; log a failure once and its recovery once.

        ``log=False`` is used while the whole source is down: Home Assistant
        already logs that (and the recovery) once for the coordinator.
        """
        self._ok[key] = error is None
        if error is None:
            if key in self._failure_logged:
                self._failure_logged.discard(key)
                _LOGGER.info("%s: %s is available again", self.name, key)
            return
        if not log or key in self._failure_logged:
            return
        self._failure_logged.add(key)
        if isinstance(error, self.expected_errors):
            _LOGGER.warning("%s: fetching %s failed: %s", self.name, key, error)
        else:
            _LOGGER.error(
                "%s: unexpected error fetching %s", self.name, key, exc_info=error
            )

    def disable_endpoint(self, key: str) -> None:
        """Stop polling an endpoint for the rest of this session."""
        self._runtime_disabled.add(key)


# ── XML ───────────────────────────────────────────────────────────────────────

_XML_ENDPOINTS: tuple[Endpoint[SophosClient], ...] = (
    Endpoint(EP_INTERFACES, Tier.REALTIME, lambda c: c.get_interfaces(),
             CONF_POLL_XML_INTERFACES, DEFAULT_POLL_XML_INTERFACES),
    Endpoint(EP_FIREWALL_RULES, Tier.OPERATIVE, lambda c: c.get_firewall_rules(),
             CONF_POLL_XML_FW_RULES, DEFAULT_POLL_XML_FW_RULES),
    Endpoint(EP_DHCP_SERVERS, Tier.STATIC, lambda c: c.get_dhcp_servers(),
             CONF_POLL_XML_DHCP, DEFAULT_POLL_XML_DHCP),
    Endpoint(EP_WEB_FILTER, Tier.STATIC, lambda c: c.get_web_filter_policies(),
             CONF_POLL_XML_WEBFILTER, DEFAULT_POLL_XML_WEBFILTER),
    Endpoint(EP_BACKUP, Tier.STATIC, lambda c: c.get_backup(),
             CONF_POLL_XML_BACKUP, DEFAULT_POLL_XML_BACKUP),
    Endpoint(EP_ADMIN, Tier.STATIC, lambda c: c.get_admin_settings()),
)


class SophosXmlCoordinator(SophosCoordinator[SophosClient, XmlData]):
    """Coordinator for the XML API."""

    connection_errors = (SophosConnectionError,)
    expected_errors = (SophosError,)
    unreachable_translation_key = "xml_unreachable"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, client: SophosClient) -> None:
        super().__init__(
            hass, entry, client, name="XML", endpoints=_XML_ENDPOINTS, empty=XmlData()
        )

    async def _handle_failures(
        self, updates: dict[str, Any], failures: dict[str, Exception]
    ) -> tuple[dict[str, Any], dict[str, Exception]]:
        auth_failed = [k for k, exc in failures.items() if isinstance(exc, SophosAuthError)]
        if auth_failed:
            _LOGGER.debug("%s: auth error for %s — retrying once", self.name, auth_failed)
            await asyncio.sleep(AUTH_RETRY_DELAY)
            retry = [ep for ep in self._endpoints if ep.key in auth_failed]
            retry_updates, retry_failures = await self._fetch(retry)
            for key in auth_failed:
                failures.pop(key)
            updates.update(retry_updates)
            failures.update(retry_failures)
            if still := next(
                (exc for exc in retry_failures.values() if isinstance(exc, SophosAuthError)),
                None,
            ):
                raise ConfigEntryAuthFailed(
                    translation_domain=DOMAIN, translation_key="auth_failed"
                ) from still

        if access := next(
            (exc for exc in failures.values() if isinstance(exc, SophosAccessError)), None
        ):
            async_raise_issue(
                self.hass, self.config_entry, ISSUE_API_ACCESS_DENIED, code=access.code or ""
            )
            raise UpdateFailed(
                translation_domain=DOMAIN,
                translation_key="api_access_denied",
                translation_placeholders={
                    "host": self.config_entry.data.get(CONF_HOST, ""),
                    "code": access.code or "",
                },
            ) from access
        if updates:
            async_clear_issue(self.hass, self.config_entry, ISSUE_API_ACCESS_DENIED)
        return updates, failures


# ── SNMP ──────────────────────────────────────────────────────────────────────

_SNMP_ENDPOINTS: tuple[Endpoint[SNMPClient], ...] = (
    Endpoint(EP_STATS, Tier.REALTIME, lambda c: c.get_stats(),
             CONF_POLL_SNMP_STATS, DEFAULT_POLL_SNMP_STATS),
    Endpoint(EP_SERVICES, Tier.REALTIME, lambda c: c.get_services(),
             CONF_POLL_SNMP_SERVICES, DEFAULT_POLL_SNMP_SERVICES),
    Endpoint(EP_TUNNELS, Tier.FAST, lambda c: c.get_vpn_tunnels(),
             CONF_POLL_SNMP_TUNNELS, DEFAULT_POLL_SNMP_TUNNELS),
    Endpoint(EP_HA, Tier.FAST, lambda c: c.get_ha_status(),
             CONF_POLL_SNMP_HA, DEFAULT_POLL_SNMP_HA),
    Endpoint(EP_HEALTH, Tier.OPERATIVE, lambda c: c.get_system_health(),
             CONF_POLL_SNMP_HEALTH, DEFAULT_POLL_SNMP_HEALTH),
    Endpoint(EP_LICENSES, Tier.STATIC, lambda c: c.get_licenses(),
             CONF_POLL_SNMP_LICENSES, DEFAULT_POLL_SNMP_LICENSES),
    Endpoint(EP_DEVICE, Tier.STATIC, lambda c: c.get_device_info()),
    # CPU load belongs to the system statistics (same option).
    Endpoint(EP_CPU, Tier.REALTIME, lambda c: c.get_cpu_load(),
             CONF_POLL_SNMP_STATS, DEFAULT_POLL_SNMP_STATS),
    Endpoint(EP_TRAFFIC, Tier.REALTIME, lambda c: c.get_traffic(),
             CONF_POLL_SNMP_TRAFFIC, DEFAULT_POLL_SNMP_TRAFFIC),
)


def _rate(previous: int | None, current: int | None, seconds: float | None) -> float | None:
    """Bit/s between two octet counter readings, or None if not computable.

    A counter that went backwards was reset (reboot, interface re-created):
    no rate for that interval rather than a negative or wrapped value.
    """
    if previous is None or current is None or seconds is None or seconds < 1:
        return None
    if current < previous:
        return None
    return round((current - previous) * 8 / seconds, 1)


def traffic_rates(
    previous: TrafficSample | None, current: TrafficSample
) -> dict[str, InterfaceTraffic]:
    """Counters and rates per interface from two consecutive samples."""
    seconds = None if previous is None else current.sampled_at - previous.sampled_at
    result: dict[str, InterfaceTraffic] = {}
    for name, now in current.counters.items():
        before = previous.counters.get(name) if previous is not None else None
        result[name] = InterfaceTraffic(
            in_octets=now.in_octets,
            out_octets=now.out_octets,
            in_bps=_rate(before.in_octets if before else None, now.in_octets, seconds),
            out_bps=_rate(before.out_octets if before else None, now.out_octets, seconds),
        )
    return result


#: The "SNMP unreachable" issue needs both: this many failed attempts and
#: this much time since the first one, without any answer in between. The
#: time matters after a power outage: HA and the firewall boot together, the
#: XML API answers first and the SNMP agent a few minutes later.
SNMP_ISSUE_AFTER_ATTEMPTS = 3
SNMP_ISSUE_AFTER_SECONDS = 600


class SophosSnmpCoordinator(SophosCoordinator[SNMPClient, SnmpData]):
    """Coordinator for SNMP."""

    connection_errors = (SophosSNMPError,)
    expected_errors = (SophosSNMPError,)
    unreachable_translation_key = "snmp_unreachable"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, client: SNMPClient) -> None:
        super().__init__(
            hass, entry, client, name="SNMP", endpoints=_SNMP_ENDPOINTS, empty=SnmpData()
        )
        self.is_virtual: bool | None = None
        self._empty_health_reads = 0
        self._reached = False
        self._failed_attempts = 0
        self._first_failure: float | None = None
        self._traffic_sample: TrafficSample | None = None

    async def _async_update_data(self) -> SnmpData:
        """Raise a repair issue if the agent has not answered since setup.

        Only before the first answer: an agent that worked and then fails is
        an outage (entities unavailable, logged once), not a setup problem.
        See SNMP_ISSUE_AFTER_* for when it is raised.
        """
        try:
            data = await super()._async_update_data()
        except UpdateFailed:
            if not self._reached:
                now = time.monotonic()
                if self._first_failure is None:
                    self._first_failure = now
                self._failed_attempts += 1
                if (
                    self._failed_attempts >= SNMP_ISSUE_AFTER_ATTEMPTS
                    and now - self._first_failure >= SNMP_ISSUE_AFTER_SECONDS
                ):
                    async_raise_issue(self.hass, self.config_entry, ISSUE_SNMP_UNREACHABLE)
            raise
        if not self._reached and any(self._ok.values()):
            self._reached = True
            async_clear_issue(self.hass, self.config_entry, ISSUE_SNMP_UNREACHABLE)
        return data

    def _prepare(self, updates: dict[str, Any]) -> dict[str, Any]:
        """Turn a traffic sample into counters and rates.

        The rate uses the time between this sample and the previous
        successful one. After a failed walk that is simply a longer interval —
        the average over it is still correct.
        """
        sample = updates.get(EP_TRAFFIC)
        if isinstance(sample, TrafficSample):
            updates = {**updates, EP_TRAFFIC: traffic_rates(self._traffic_sample, sample)}
            self._traffic_sample = sample
        return updates

    def _after_update(self, data: SnmpData, updates: Mapping[str, Any]) -> None:
        """Detect a virtual appliance from *successful* health fetches.

        v1.0.x ran the detection on failed fetches too, so a single SNMP
        timeout at startup classified a hardware appliance as virtual and
        stopped health polling until the next restart. A booting appliance
        can also answer without sensor values, so only EMPTY_CONFIRMATIONS
        empty answers in a row mean "virtual".
        """
        health = updates.get(EP_HEALTH)
        if self.is_virtual is not None or not isinstance(health, SystemHealth):
            return
        if health.has_hardware_sensors:
            self.is_virtual = False
            return
        self._empty_health_reads += 1
        if self._empty_health_reads >= EMPTY_CONFIRMATIONS:
            self.is_virtual = True
            _LOGGER.info(
                "%s: no hardware sensors reported (virtual appliance) — "
                "health polling disabled for this session",
                self.name,
            )
            self.disable_endpoint(EP_HEALTH)
