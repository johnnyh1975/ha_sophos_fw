"""Sensor platform for the Sophos Firewall integration."""
from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    EntityCategory,
    UnitOfDataRate,
    UnitOfInformation,
    UnitOfTemperature,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import StateType
from homeassistant.util import dt as dt_util

from . import SophosConfigEntry
from .const import (
    CONF_SNMP_ENABLED,
    EP_BACKUP,
    EP_CPU,
    EP_DEVICE,
    EP_DHCP_SERVERS,
    EP_HA,
    EP_HEALTH,
    EP_INTERFACES,
    EP_LICENSES,
    EP_SERVICES,
    EP_STATS,
    EP_TRAFFIC,
    EP_WEB_FILTER,
    LICENSE_OIDS,
    LICENSE_OK_STATES,
    LICENSE_STATES,
    SERVICE_OIDS,
    SERVICE_RUNNING_STATE,
    SERVICE_STATES,
)
from .coordinator import SophosSnmpCoordinator, SophosXmlCoordinator
from .entity import (
    DynamicFamily,
    SophosSnmpEntity,
    SophosXmlEntity,
    async_add_static_entities,
    async_remove_entities,
    async_remove_stale_entities,
    async_setup_dynamic_entities,
)
from .models import DhcpServer, InterfaceTraffic, License, SnmpData, XmlData

_LOGGER = logging.getLogger(__name__)

PARALLEL_UPDATES = 0


# ── Descriptions ──────────────────────────────────────────────────────────────


@dataclass(frozen=True, kw_only=True)
class SophosXmlSensorDescription(SensorEntityDescription):
    """Sensor fed by the XML coordinator."""

    endpoint: str
    value_fn: Callable[[XmlData], StateType]


@dataclass(frozen=True, kw_only=True)
class SophosSnmpSensorDescription(SensorEntityDescription):
    """Sensor fed by the SNMP coordinator."""

    endpoint: str
    value_fn: Callable[[SnmpData], StateType]


def _stat(field: str) -> Callable[[SnmpData], StateType]:
    def _value(data: SnmpData) -> StateType:
        return getattr(data.stats, field) if data.stats else None

    return _value


_unknown_logged: set[tuple[str, str]] = set()


def _enum_state(key: str, value: str | None, options: list[str]) -> str | None:
    """Map a firewall value to an ENUM state ("Allow" → "allow").

    A value outside ``options`` becomes None (HA rejects it for ENUM sensors)
    and is logged once, so a new SFOS value can be reported and added.
    """
    if value is None:
        return None
    state = value.strip().lower()
    if state in options:
        return state
    if (key, value) not in _unknown_logged:
        _unknown_logged.add((key, value))
        _LOGGER.warning(
            "Unknown value %r for %s — please report it at "
            "https://github.com/johnnyh1975/ha_sophos_fw/issues",
            value, key,
        )
    return None


def _code_state(key: str, code: int | None, states: tuple[str, ...]) -> str | None:
    """Map an SNMP enumeration code to its ENUM state (unknown codes → None, logged once)."""
    if code is None:
        return None
    if 0 <= code < len(states):
        return states[code]
    return _enum_state(key, str(code), [])


# Both values seen on SFOS 22 (diagnostics of a real firewall).
WEB_FILTER_ACTIONS = ["allow", "deny"]
# Assumed from the SFOS web UI; the API documentation does not list them.
BACKUP_FREQUENCIES = ["never", "daily", "weekly", "monthly"]


def _default_web_filter_action(data: XmlData) -> StateType:
    """DefaultAction of the policy named '…default…', else of the first policy."""
    policies = list((data.web_filter_policies or {}).values())
    if not policies:
        return None
    policy = next((p for p in policies if "default" in p.name.lower()), policies[0])
    return _enum_state("web_filter_default_action", policy.default_action, WEB_FILTER_ACTIONS)


def _backup_frequency(data: XmlData) -> StateType:
    frequency = data.backup.frequency if data.backup else None
    return _enum_state("backup_frequency", frequency, BACKUP_FREQUENCIES)


XML_SENSORS: tuple[SophosXmlSensorDescription, ...] = (
    SophosXmlSensorDescription(
        key="web_filter_default_action",
        translation_key="web_filter_default_action",
        device_class=SensorDeviceClass.ENUM,
        options=WEB_FILTER_ACTIONS,
        endpoint=EP_WEB_FILTER,
        value_fn=_default_web_filter_action,
    ),
    SophosXmlSensorDescription(
        key="backup_frequency",
        translation_key="backup_frequency",
        device_class=SensorDeviceClass.ENUM,
        options=BACKUP_FREQUENCIES,
        entity_category=EntityCategory.DIAGNOSTIC,
        entity_registry_enabled_default=False,
        endpoint=EP_BACKUP,
        value_fn=_backup_frequency,
    ),
)

SNMP_SENSORS: tuple[SophosSnmpSensorDescription, ...] = (
    SophosSnmpSensorDescription(
        key="memory_percent", translation_key="memory_percent",
        native_unit_of_measurement=PERCENTAGE, state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        endpoint=EP_STATS, value_fn=_stat("memory_percent"),
    ),
    SophosSnmpSensorDescription(
        key="disk_percent", translation_key="disk_percent",
        native_unit_of_measurement=PERCENTAGE, state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        endpoint=EP_STATS, value_fn=_stat("disk_percent"),
    ),
    SophosSnmpSensorDescription(
        key="swap_percent", translation_key="swap_percent",
        entity_registry_enabled_default=False,
        native_unit_of_measurement=PERCENTAGE, state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        endpoint=EP_STATS, value_fn=_stat("swap_percent"),
    ),
    SophosSnmpSensorDescription(
        key="http_hits", translation_key="http_hits",
        state_class=SensorStateClass.TOTAL_INCREASING,
        endpoint=EP_STATS, value_fn=_stat("http_hits"),
    ),
    SophosSnmpSensorDescription(
        key="smtp_hits", translation_key="smtp_hits",
        entity_registry_enabled_default=False,
        state_class=SensorStateClass.TOTAL_INCREASING,
        endpoint=EP_STATS, value_fn=_stat("smtp_hits"),
    ),
    SophosSnmpSensorDescription(
        key="ftp_hits", translation_key="ftp_hits",
        entity_registry_enabled_default=False,
        state_class=SensorStateClass.TOTAL_INCREASING,
        endpoint=EP_STATS, value_fn=_stat("ftp_hits"),
    ),
    SophosSnmpSensorDescription(
        key="imap_hits", translation_key="imap_hits",
        entity_registry_enabled_default=False,
        state_class=SensorStateClass.TOTAL_INCREASING,
        endpoint=EP_STATS, value_fn=_stat("imap_hits"),
    ),
    SophosSnmpSensorDescription(
        key="pop3_hits", translation_key="pop3_hits",
        entity_registry_enabled_default=False,
        state_class=SensorStateClass.TOTAL_INCREASING,
        endpoint=EP_STATS, value_fn=_stat("pop3_hits"),
    ),
    SophosSnmpSensorDescription(
        key="live_users", translation_key="live_users",
        state_class=SensorStateClass.MEASUREMENT,
        endpoint=EP_STATS, value_fn=_stat("live_users"),
    ),
)

# Created only once the appliance reports a value (never on virtual appliances).
HARDWARE_SENSORS: tuple[SophosSnmpSensorDescription, ...] = (
    SophosSnmpSensorDescription(
        key="cpu_temperature", translation_key="cpu_temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT, suggested_display_precision=1,
        entity_category=EntityCategory.DIAGNOSTIC,
        endpoint=EP_HEALTH,
        value_fn=lambda d: d.health.cpu_temperature_c if d.health else None,
    ),
    SophosSnmpSensorDescription(
        key="npu_temperature", translation_key="npu_temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT, suggested_display_precision=1,
        entity_category=EntityCategory.DIAGNOSTIC,
        endpoint=EP_HEALTH,
        value_fn=lambda d: d.health.npu_temperature_c if d.health else None,
    ),
)

# Created once the agent reports a value; removed once it confirmably reports
# none (e.g. "not available" for the web category version on SFOS 22).
VERSION_SENSORS: tuple[SophosSnmpSensorDescription, ...] = (
    SophosSnmpSensorDescription(
        key="ips_version", translation_key="ips_version",
        entity_category=EntityCategory.DIAGNOSTIC, entity_registry_enabled_default=False,
        endpoint=EP_DEVICE, value_fn=lambda d: d.device.ips_version if d.device else None,
    ),
    SophosSnmpSensorDescription(
        key="webcat_version", translation_key="webcat_version",
        entity_category=EntityCategory.DIAGNOSTIC, entity_registry_enabled_default=False,
        endpoint=EP_DEVICE, value_fn=lambda d: d.device.webcat_version if d.device else None,
    ),
)


@dataclass(frozen=True, kw_only=True)
class SophosTrafficSensorDescription(SensorEntityDescription):
    """One traffic value of an interface (IF-MIB)."""

    value_fn: Callable[[InterfaceTraffic], float | int | None]
    enabled_for_xml_interfaces: bool


TRAFFIC_SENSORS: tuple[SophosTrafficSensorDescription, ...] = (
    SophosTrafficSensorDescription(
        key="rx_rate", translation_key="traffic_rx_rate",
        device_class=SensorDeviceClass.DATA_RATE,
        native_unit_of_measurement=UnitOfDataRate.BITS_PER_SECOND,
        suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        suggested_display_precision=2, state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda t: t.in_bps, enabled_for_xml_interfaces=True,
    ),
    SophosTrafficSensorDescription(
        key="tx_rate", translation_key="traffic_tx_rate",
        device_class=SensorDeviceClass.DATA_RATE,
        native_unit_of_measurement=UnitOfDataRate.BITS_PER_SECOND,
        suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
        suggested_display_precision=2, state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda t: t.out_bps, enabled_for_xml_interfaces=True,
    ),
    SophosTrafficSensorDescription(
        key="rx_bytes", translation_key="traffic_rx_bytes",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        suggested_unit_of_measurement=UnitOfInformation.GIGABYTES,
        suggested_display_precision=2, state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda t: t.in_octets, enabled_for_xml_interfaces=False,
    ),
    SophosTrafficSensorDescription(
        key="tx_bytes", translation_key="traffic_tx_bytes",
        device_class=SensorDeviceClass.DATA_SIZE,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        suggested_unit_of_measurement=UnitOfInformation.GIGABYTES,
        suggested_display_precision=2, state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda t: t.out_octets, enabled_for_xml_interfaces=False,
    ),
)


# ── Setup ─────────────────────────────────────────────────────────────────────


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SophosConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensors."""
    runtime = entry.runtime_data
    async_add_static_entities(
        hass, entry, "sensor", async_add_entities,
        [SophosXmlSensor(runtime.xml, desc) for desc in XML_SENSORS],
    )
    async_setup_dynamic_entities(
        hass, entry, runtime.xml, "sensor", async_add_entities,
        [DynamicFamily("dhcp_leases_", EP_DHCP_SERVERS, _dhcp_items, SophosDHCPLeaseSensor)],
    )

    if (snmp := runtime.snmp) is None:
        if not entry.options.get(CONF_SNMP_ENABLED, False):
            _async_remove_snmp_entities(hass, entry)
        return
    async_add_static_entities(
        hass, entry, "sensor", async_add_entities,
        [
            *(SophosSnmpSensor(snmp, desc) for desc in SNMP_SENSORS),
            SophosServicesSummarySensor(snmp),
            SophosLicensesSummarySensor(snmp),
            SophosUptimeSensor(snmp),
            SophosHAStateSensor(snmp),
            SophosHAPeerStateSensor(snmp),
            *(SophosServiceSensor(snmp, key, name) for key, name in SERVICE_OIDS.values()),
            *(SophosLicenseSensor(snmp, key, name) for key, name, _ in LICENSE_OIDS.values()),
        ],
    )

    def xml_interfaces() -> set[str] | None:
        """Interfaces the XML API lists; None while not known yet.

        Unknown only if the XML interface fetch has not succeeded yet. Then
        the traffic entities wait: enabled-by-default is decided once, when
        an entity is created, so PortA/PortB would stay disabled for good.
        With XML interface polling switched off there is nothing to wait for.
        """
        if not runtime.xml.endpoint_configured(EP_INTERFACES):
            return set()
        data = runtime.xml.data
        if data is None or data.interfaces is None:
            return None
        # SNMP reports the device name; the XML Name can be user-defined.
        return {iface.hardware or iface.name for iface in data.interfaces.values()}

    # CPU and interface traffic come from standard MIBs; entities appear for
    # what the agent reports. Traffic sensors of interfaces the XML API does
    # not list (VLANs, wireless networks, tunnels, …) are created disabled.
    async_setup_dynamic_entities(
        hass, entry, snmp, "sensor", async_add_entities,
        [
            DynamicFamily("sensor_cpu_usage", EP_CPU, _cpu_usage_items, SophosCpuUsageSensor),
            DynamicFamily(
                "sensor_cpu_core_", EP_CPU, _cpu_core_items, SophosCpuCoreSensor,
                confirm_missing=True,
            ),
            *(
                DynamicFamily(
                    f"traffic_{desc.key}_", EP_TRAFFIC, _traffic_items(desc.key, xml_interfaces),
                    _traffic_factory(desc, xml_interfaces), confirm_missing=True,
                )
                for desc in TRAFFIC_SENSORS
            ),
        ],
    )
    # Hardware sensors appear once the appliance reports a value and never
    # disappear because a single reading is missing (a failed fan may drop
    # out of the table — its sensor must stay so alerts can fire).
    # Version sensors are removed once the agent reported no value for
    # EMPTY_CONFIRMATIONS successful fetches in a row: the value is a fixed
    # property of the firmware, not a transient reading.
    async_setup_dynamic_entities(
        hass, entry, snmp, "sensor", async_add_entities,
        [
            DynamicFamily("sensor_fan_", EP_HEALTH, _fan_items, SophosFanSensor, remove_stale=False),
            *(
                DynamicFamily(
                    f"sensor_{desc.key}", desc.endpoint, _present(desc), SophosSnmpSensor,
                    remove_stale=False,
                )
                for desc in HARDWARE_SENSORS
            ),
            *(
                DynamicFamily(
                    f"sensor_{desc.key}", desc.endpoint, _present(desc), SophosSnmpSensor,
                    trust_empty=True,
                )
                for desc in VERSION_SENSORS
            ),
        ],
    )


@callback
def _async_remove_snmp_entities(hass: HomeAssistant, entry: SophosConfigEntry) -> None:
    """Remove every SNMP sensor: SNMP was switched off in the options.

    Configuration-driven, like switching off a single source; without it the
    entities stayed "unavailable" for good. Not done when SNMP is on but
    could not be initialised — that is not the user's choice.
    """
    async_remove_entities(
        hass, entry, "sensor",
        [
            *(f"sensor_{desc.key}" for desc in (*SNMP_SENSORS, *HARDWARE_SENSORS, *VERSION_SENSORS)),
            "sensor_services_summary", "sensor_licenses_summary", "sensor_uptime",
            "ha_current_state", "ha_peer_state", "sensor_cpu_usage",
        ],
    )
    for prefix in ("service_", "license_", "sensor_cpu_core_", "traffic_", "sensor_fan_"):
        async_remove_stale_entities(hass, entry, "sensor", prefix, (), remove_all=True)


def _cpu_usage_items(data: SnmpData) -> dict[str, None] | None:
    if data.cpu is None:
        return None
    return {"sensor_cpu_usage": None} if data.cpu else {}


def _cpu_core_items(data: SnmpData) -> dict[str, str] | None:
    return None if data.cpu is None else {f"sensor_cpu_core_{core}": core for core in data.cpu}


def _traffic_items(
    key: str, xml_interfaces: Callable[[], set[str] | None]
) -> Callable[[SnmpData], dict[str, str] | None]:
    def _items(data: SnmpData) -> dict[str, str] | None:
        if data.traffic is None or xml_interfaces() is None:
            return None
        return {f"traffic_{key}_{name}": name for name in data.traffic}

    return _items


def _traffic_factory(
    desc: SophosTrafficSensorDescription, xml_interfaces: Callable[[], set[str] | None]
) -> Callable[[SophosSnmpCoordinator, str], SophosTrafficSensor]:
    def _factory(coordinator: SophosSnmpCoordinator, name: str) -> SophosTrafficSensor:
        enabled = desc.enabled_for_xml_interfaces and name in (xml_interfaces() or set())
        return SophosTrafficSensor(coordinator, desc, name, enabled_default=enabled)

    return _factory


def _dhcp_items(data: XmlData) -> dict[str, DhcpServer] | None:
    if data.dhcp_servers is None:
        return None
    return {f"dhcp_leases_{name}": server for name, server in data.dhcp_servers.items()}


def _fan_items(data: SnmpData) -> dict[str, str] | None:
    return None if data.health is None else {f"sensor_{key}": key for key in data.health.fans}


def _present(
    desc: SophosSnmpSensorDescription,
) -> Callable[[SnmpData], dict[str, SophosSnmpSensorDescription]]:
    """Items callback: the sensor exists once its value was reported."""

    def _items(data: SnmpData) -> dict[str, SophosSnmpSensorDescription]:
        return {f"sensor_{desc.key}": desc} if desc.value_fn(data) is not None else {}

    return _items


# ── Description-based sensors ─────────────────────────────────────────────────


class SophosXmlSensor(SophosXmlEntity, SensorEntity):
    """Sensor described by a SophosXmlSensorDescription."""

    entity_description: SophosXmlSensorDescription

    def __init__(
        self, coordinator: SophosXmlCoordinator, description: SophosXmlSensorDescription
    ) -> None:
        super().__init__(coordinator, f"sensor_{description.key}", description.endpoint)
        self.entity_description = description

    @property
    def native_value(self) -> StateType:
        return self.entity_description.value_fn(self.xml)


class SophosSnmpSensor(SophosSnmpEntity, SensorEntity):
    """Sensor described by a SophosSnmpSensorDescription."""

    entity_description: SophosSnmpSensorDescription

    def __init__(
        self, coordinator: SophosSnmpCoordinator, description: SophosSnmpSensorDescription
    ) -> None:
        super().__init__(coordinator, f"sensor_{description.key}", description.endpoint)
        self.entity_description = description

    @property
    def native_value(self) -> StateType:
        return self.entity_description.value_fn(self.snmp)


# ── XML sensors ───────────────────────────────────────────────────────────────


class SophosDHCPLeaseSensor(SophosXmlEntity, SensorEntity):
    """DHCP server state ("on"/"off") with its static leases as attributes."""

    _attr_translation_key = "dhcp_leases"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = ["off", "on"]

    def __init__(self, coordinator: SophosXmlCoordinator, server: DhcpServer) -> None:
        super().__init__(coordinator, f"dhcp_leases_{server.name}", EP_DHCP_SERVERS)
        self._name = server.name
        self._attr_translation_placeholders = {"server": server.name}

    def _server(self) -> DhcpServer | None:
        return (self.xml.dhcp_servers or {}).get(self._name)

    @property
    def native_value(self) -> str | None:
        server = self._server()
        if server is None or server.running is None:
            return None
        return "on" if server.running else "off"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if (server := self._server()) is None:
            return {}
        return {
            "server_name": server.name,
            "interface": server.interface,
            "lease_range": server.lease_time,
            "lease_count": len(server.static_leases),
            "leases": [dict(lease) for lease in server.static_leases],
        }


# ── SNMP sensors ──────────────────────────────────────────────────────────────


class SophosFanSensor(SophosSnmpEntity, SensorEntity):
    """Speed of one fan (hardware appliances only)."""

    # "RPM" kept verbatim: changing the unit string would break existing statistics.
    _attr_native_unit_of_measurement = "RPM"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 0
    _attr_translation_key = "fan_speed"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: SophosSnmpCoordinator, fan_key: str) -> None:
        super().__init__(coordinator, f"sensor_{fan_key}", EP_HEALTH)
        self._key = fan_key
        self._attr_translation_placeholders = {"fan": fan_key.replace("_", " ")}

    @property
    def native_value(self) -> int | None:
        return self.snmp.health.fans.get(self._key) if self.snmp.health else None


class SophosServicesSummarySensor(SophosSnmpEntity, SensorEntity):
    """Number of running services; all states as attributes.

    No unit: v1.0.x used "/ 21 running", which is not a unit (the total is
    the ``total`` attribute now).
    """

    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_translation_key = "services_summary"

    def __init__(self, coordinator: SophosSnmpCoordinator) -> None:
        super().__init__(coordinator, "sensor_services_summary", EP_SERVICES)

    @property
    def native_value(self) -> int | None:
        codes = [code for code in (self.snmp.services or {}).values() if code is not None]
        if not codes:  # no service reported a state: unknown, not "0 running"
            return None
        return sum(1 for code in codes if code == SERVICE_RUNNING_STATE)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        services = self.snmp.services or {}
        names = {key: friendly for key, friendly in SERVICE_OIDS.values()}
        running: list[str] = []
        stopped: list[str] = []
        details: dict[str, int | None] = {}
        for key, code in services.items():
            friendly = names.get(key, key)
            details[friendly] = code
            (running if code == SERVICE_RUNNING_STATE else stopped).append(friendly)
        return {
            "total": len(services),
            "running": sorted(running),
            "stopped": sorted(stopped),
            "details": details,
        }


def _parse_expiry(value: str) -> datetime | None:
    for fmt in ("%b %d %Y", "%b  %d %Y"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return None


class SophosLicensesSummarySensor(SophosSnmpEntity, SensorEntity):
    """Number of valid subscriptions; details as attributes.

    No unit: v1.0.x used "/ 9 OK" (the total is the ``total`` attribute now).
    """

    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_translation_key = "licenses_summary"

    def __init__(self, coordinator: SophosSnmpCoordinator) -> None:
        super().__init__(coordinator, "sensor_licenses_summary", EP_LICENSES)

    @property
    def native_value(self) -> int | None:
        codes = [
            lic.status_code for lic in (self.snmp.licenses or {}).values()
            if lic.status_code is not None
        ]
        if not codes:  # no license reported a status: unknown, not "0 OK"
            return None
        return sum(1 for code in codes if code in LICENSE_OK_STATES)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        licenses = self.snmp.licenses or {}
        ok: list[str] = []
        problem: list[str] = []
        details: list[dict[str, Any]] = []
        expiries: list[tuple[datetime, str]] = []
        for lic in licenses.values():
            details.append(
                {"name": lic.name, "status_code": lic.status_code, "expiry": lic.expiry_date}
            )
            (ok if lic.status_code in LICENSE_OK_STATES else problem).append(lic.name)
            if lic.expiry_date and (parsed := _parse_expiry(lic.expiry_date)):
                expiries.append((parsed, lic.expiry_date))
        return {
            "total": len(licenses),
            "ok": sorted(ok),
            "problem": sorted(problem),
            "next_expiry": min(expiries)[1] if expiries else None,
            "details": sorted(details, key=lambda d: d["name"]),
        }


class SophosUptimeSensor(SophosSnmpEntity, SensorEntity):
    """Time of the last boot, derived from the reported uptime.

    v1.0.x showed the uptime as text ("75 d 6 h") plus a seconds attribute —
    a new state every 30 s, i.e. one recorder row per poll. The boot time only
    changes on a reboot. It is recomputed on every poll but only replaced when
    it moved by more than BOOT_TIME_TOLERANCE (poll timing and the agent's
    clock make it jitter by a second or two).
    """

    _attr_translation_key = "uptime"
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    BOOT_TIME_TOLERANCE = timedelta(seconds=60)

    def __init__(self, coordinator: SophosSnmpCoordinator) -> None:
        super().__init__(coordinator, "sensor_uptime", EP_STATS)
        self._boot_time: datetime | None = None

    def _reported_boot_time(self) -> datetime | None:
        stats = self.snmp.stats
        fetched = self.coordinator.fetched_at(EP_STATS)
        if stats is None or stats.uptime_seconds is None or fetched is None:
            return None
        # The uptime was valid when it was fetched, not now.
        age = time.monotonic() - fetched
        boot = dt_util.utcnow() - timedelta(seconds=age + stats.uptime_seconds)
        return boot.replace(microsecond=0)

    @property
    def native_value(self) -> datetime | None:
        reported = self._reported_boot_time()
        if reported is None:
            self._boot_time = None
        elif self._boot_time is None or abs(reported - self._boot_time) > self.BOOT_TIME_TOLERANCE:
            self._boot_time = reported
        return self._boot_time


# sfosXGHAStats HaState
_HA_STATE_MAP: dict[int, str] = {
    0: "not_applicable",
    1: "auxiliary",
    2: "standalone",
    3: "primary",
    4: "faulty",
    5: "ready",
}


class _SophosHAStateBase(SophosSnmpEntity, SensorEntity):
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = list(_HA_STATE_MAP.values())
    _field: str

    def __init__(self, coordinator: SophosSnmpCoordinator) -> None:
        super().__init__(coordinator, self._attr_translation_key or "", EP_HA)

    def _code(self) -> int | None:
        return getattr(self.snmp.ha, self._field) if self.snmp.ha else None

    @property
    def native_value(self) -> str | None:
        code = self._code()
        return None if code is None else _HA_STATE_MAP.get(code)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"state_code": self._code()}


class SophosHAStateSensor(_SophosHAStateBase):
    """This node's role in the HA cluster."""

    _attr_translation_key = "ha_current_state"
    _field = "current_state"


class SophosHAPeerStateSensor(_SophosHAStateBase):
    """The peer node's role in the HA cluster."""

    _attr_translation_key = "ha_peer_state"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False
    _field = "peer_state"


# ── Standard-MIB sensors (CPU, interface traffic) ─────────────────────────────


class SophosCpuUsageSensor(SophosSnmpEntity, SensorEntity):
    """Average load of all cores (hrProcessorLoad: 1-minute average each)."""

    _attr_translation_key = "cpu_usage"
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 0

    def __init__(self, coordinator: SophosSnmpCoordinator, _item: None = None) -> None:
        super().__init__(coordinator, "sensor_cpu_usage", EP_CPU)

    @property
    def native_value(self) -> float | None:
        loads = [load for load in (self.snmp.cpu or {}).values() if load is not None]
        return round(sum(loads) / len(loads), 1) if loads else None


class SophosCpuCoreSensor(SophosSnmpEntity, SensorEntity):
    """Load of one core."""

    _attr_translation_key = "cpu_core"
    _attr_native_unit_of_measurement = PERCENTAGE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 0
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: SophosSnmpCoordinator, core: str) -> None:
        super().__init__(coordinator, f"sensor_cpu_core_{core}", EP_CPU)
        self._core = core
        self._attr_translation_placeholders = {"core": core}

    @property
    def native_value(self) -> int | None:
        return (self.snmp.cpu or {}).get(self._core)


class SophosTrafficSensor(SophosSnmpEntity, SensorEntity):
    """Receive/transmit rate or byte counter of one interface."""

    entity_description: SophosTrafficSensorDescription

    def __init__(
        self,
        coordinator: SophosSnmpCoordinator,
        description: SophosTrafficSensorDescription,
        interface: str,
        *,
        enabled_default: bool,
    ) -> None:
        super().__init__(coordinator, f"traffic_{description.key}_{interface}", EP_TRAFFIC)
        self.entity_description = description
        self._interface = interface
        self._attr_translation_placeholders = {"name": interface}
        self._attr_entity_registry_enabled_default = enabled_default

    @property
    def native_value(self) -> float | int | None:
        traffic = (self.snmp.traffic or {}).get(self._interface)
        return None if traffic is None else self.entity_description.value_fn(traffic)


# ── Per-service and per-license sensors (disabled by default) ─────────────────


class SophosServiceSensor(SophosSnmpEntity, SensorEntity):
    """State of one firewall service (ServiceStatsType)."""

    _attr_translation_key = "service"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = list(SERVICE_STATES)
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: SophosSnmpCoordinator, key: str, name: str) -> None:
        super().__init__(coordinator, f"service_{key}", EP_SERVICES)
        self._key = key
        self._attr_translation_placeholders = {"name": name}

    def _code(self) -> int | None:
        return (self.snmp.services or {}).get(self._key)

    @property
    def native_value(self) -> str | None:
        return _code_state(f"service {self._key}", self._code(), SERVICE_STATES)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"state_code": self._code()}


class SophosLicenseSensor(SophosSnmpEntity, SensorEntity):
    """Subscription status of one license module; expiry as attribute."""

    _attr_translation_key = "license"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = list(LICENSE_STATES)
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: SophosSnmpCoordinator, key: str, name: str) -> None:
        super().__init__(coordinator, f"license_{key}", EP_LICENSES)
        self._key = key
        self._attr_translation_placeholders = {"name": name}

    def _license(self) -> License | None:
        return (self.snmp.licenses or {}).get(self._key)

    @property
    def native_value(self) -> str | None:
        lic = self._license()
        return (
            None if lic is None
            else _code_state(f"license {self._key}", lic.status_code, LICENSE_STATES)
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        lic = self._license()
        expiry = _parse_expiry(lic.expiry_date) if lic and lic.expiry_date else None
        return {
            "status_code": lic.status_code if lic else None,
            "expiry_date": expiry.date().isoformat() if expiry else None,
        }
