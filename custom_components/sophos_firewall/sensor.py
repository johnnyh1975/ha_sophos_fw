"""Sensor platform for Sophos Firewall integration.

Sensors are read-only measurements.  Each SensorEntityDescription defines
the data source, unit, and how to extract the value from coordinator.data.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    UnitOfInformation,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONF_SNMP_ENABLED,
    DATA_BACKUP,
    DATA_DHCP_SERVERS,
    DATA_SNMP_DEVICE,
    DATA_SNMP_HEALTH,
    DATA_SNMP_LICENSES,
    DATA_SNMP_SERVICES,
    DATA_SNMP_STATS,
    DATA_WEB_FILTER_POLICIES,
    LICENSE_OK_STATES,
    LICENSE_OIDS,
    OID_IPS_VERSION,
    OID_WEBCAT_VERSION,
    SERVICE_OIDS,
    SERVICE_RUNNING_STATE,
)
from .coordinator import SophosCoordinator
from .entity import SophosEntity

PARALLEL_UPDATES = 0


@dataclass(frozen=True, kw_only=True)


class SophosSensorDescription(SensorEntityDescription):
    """Extends SensorEntityDescription with a value extractor callable."""

    value_fn: Callable[[dict[str, Any]], Any]
    # Only added when SNMP is enabled
    requires_snmp: bool = False
    # Only added when hardware is confirmed available (not on virtual appliances)
    # These are moved to Phase 2 dynamic registration so we can check actual values
    requires_hardware: bool = False


def _stats(key: str) -> Callable[[dict[str, Any]], Any]:
    """Shorthand: extract a value from DATA_SNMP_STATS."""
    return lambda data: data.get(DATA_SNMP_STATS, {}).get(key)


SENSOR_DESCRIPTIONS: tuple[SophosSensorDescription, ...] = (
    # ── SNMP stats ────────────────────────────────────────────────────────────
    SophosSensorDescription(
        key="memory_percent",
        translation_key="memory_percent",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        icon="mdi:memory",
        value_fn=_stats("memory_percent"),
        requires_snmp=True,
    ),
    SophosSensorDescription(
        key="disk_percent",
        translation_key="disk_percent",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        icon="mdi:harddisk",
        value_fn=_stats("disk_percent"),
        requires_snmp=True,
    ),
    SophosSensorDescription(
        key="swap_percent",
        translation_key="swap_percent",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        icon="mdi:swap-horizontal",
        value_fn=_stats("swap_percent"),
        requires_snmp=True,
    ),
    # Uptime wird als SophosUptimeSensor (eigene Klasse) registriert — nicht hier
    # Grund: formatierter State ("77 d 14 h") + Rohwert als Attribut
    SophosSensorDescription(
        key="http_hits",
        translation_key="http_hits",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:web",
        value_fn=_stats("http_hits"),
        requires_snmp=True,
    ),
    SophosSensorDescription(
        key="smtp_hits",
        translation_key="smtp_hits",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:email-outline",
        value_fn=_stats("smtp_hits"),
        requires_snmp=True,
    ),
    SophosSensorDescription(
        key="ftp_hits",
        translation_key="ftp_hits",
        state_class=SensorStateClass.TOTAL_INCREASING,
        icon="mdi:folder-network-outline",
        value_fn=_stats("ftp_hits"),
        requires_snmp=True,
    ),
    SophosSensorDescription(
        key="live_users",
        translation_key="live_users",
        state_class=SensorStateClass.MEASUREMENT,
        icon="mdi:account-multiple-outline",
        value_fn=_stats("live_users"),
        requires_snmp=True,
    ),
    # ── SNMP hardware health (physical appliances only) ───────────────────────
    SophosSensorDescription(
        key="cpu_temperature",
        translation_key="cpu_temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        icon="mdi:thermometer",
        value_fn=lambda d: d.get(DATA_SNMP_HEALTH, {}).get("cpu_temperature_c"),
        requires_snmp=True,
        requires_hardware=True,
    ),
    SophosSensorDescription(
        key="npu_temperature",
        translation_key="npu_temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        icon="mdi:thermometer",
        value_fn=lambda d: d.get(DATA_SNMP_HEALTH, {}).get("npu_temperature_c"),
        requires_snmp=True,
        requires_hardware=True,
    ),
    # ── XML API ───────────────────────────────────────────────────────────────
    SophosSensorDescription(
        key="web_filter_default_action",
        translation_key="web_filter_default_action",
        icon="mdi:filter-outline",
        value_fn=lambda d: next(
            (
                p.get("DefaultAction")
                for p in (d.get(DATA_WEB_FILTER_POLICIES) or [])
                if "default" in p.get("Name", "").lower()
            ),
            (d.get(DATA_WEB_FILTER_POLICIES) or [{}])[0].get("DefaultAction"),
        ),
    ),
    SophosSensorDescription(
        key="backup_frequency",
        translation_key="backup_frequency",
        icon="mdi:backup-restore",
        value_fn=lambda d: (
            d.get(DATA_BACKUP, {})
            .get("ScheduleBackup", {})
            .get("BackupFrequency")
        ),
    ),
    SophosSensorDescription(
        key="ips_version",
        translation_key="ips_version",
        icon="mdi:shield-bug-outline",
        value_fn=lambda d: d.get(DATA_SNMP_DEVICE, {}).get(OID_IPS_VERSION),
        requires_snmp=True,
        requires_hardware=True,
    ),
    SophosSensorDescription(
        key="webcat_version",
        translation_key="webcat_version",
        icon="mdi:web-check",
        value_fn=lambda d: d.get(DATA_SNMP_DEVICE, {}).get(OID_WEBCAT_VERSION),
        requires_snmp=True,
        requires_hardware=True,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensor entities.

    Phase 1 (immediate): Static sensors that don't depend on data.
                         Hardware sensors (requires_hardware=True) are excluded —
                         they move to Phase 2 where we can check actual values.

    Phase 2 (on first data): Dynamic sensors created after the first fetch:
                              - DHCP lease sensors (one per DHCP server)
                              - Fan RPM sensors (one per fan, hardware only)
                              - Temperature sensors (only if values are not None)
    """
    coordinator: SophosCoordinator = entry.runtime_data
    snmp_enabled: bool = entry.data.get(CONF_SNMP_ENABLED, False)

    # ── Phase 1: Static sensors ───────────────────────────────────────────────
    static_entities: list[SensorEntity] = [
        SophosSensor(coordinator, desc)
        for desc in SENSOR_DESCRIPTIONS
        if (not desc.requires_snmp or snmp_enabled)
        and not desc.requires_hardware   # hardware sensors deferred to Phase 2
    ]
    # Aggregations-Sensoren für Dienste und Lizenzen (nur wenn SNMP aktiv)
    if snmp_enabled:
        static_entities.append(SophosServicesSummarySensor(coordinator))
        static_entities.append(SophosLicensesSummarySensor(coordinator))
        static_entities.append(SophosUptimeSensor(coordinator))
    async_add_entities(static_entities)

    # ── Phase 2: Dynamic sensors via coordinator listener ─────────────────────
    added_ids: set[str] = set()

    def _add_dynamic_sensors() -> None:
        data = coordinator.data
        if not data:
            return
        new_entities: list[SensorEntity] = []

        # ── DHCP Lease sensors — one per DHCP server ──────────────────────────
        current_dhcp_names: set[str] = {
            s.get("Name", "") for s in data.get(DATA_DHCP_SERVERS, [])
        }
        for server in data.get(DATA_DHCP_SERVERS, []):
            uid = f"{entry.entry_id}_dhcp_leases_{server.get('Name','')}"
            if uid not in added_ids:
                added_ids.add(uid)
                new_entities.append(SophosDHCPLeaseSensor(coordinator, server))

        # Remove stale DHCP sensors whose server no longer exists
        reg = er.async_get(coordinator.hass)
        for uid in list(added_ids):
            if not uid.startswith(f"{entry.entry_id}_dhcp_leases_"):
                continue
            server_name = uid[len(f"{entry.entry_id}_dhcp_leases_"):]
            if server_name not in current_dhcp_names:
                entity_id = reg.async_get_entity_id("sensor", "sophos_firewall", uid)
                if entity_id:
                    reg.async_remove(entity_id)
                added_ids.discard(uid)

        if snmp_enabled:
            health = data.get(DATA_SNMP_HEALTH, {})

            # Fan RPM sensors — only on physical appliances (fans dict non-empty)
            for fan_key in health.get("fans", {}):
                uid = f"{entry.entry_id}_sensor_{fan_key}"
                if uid not in added_ids:
                    added_ids.add(uid)
                    new_entities.append(SophosFanSensor(coordinator, fan_key))

            # Temperature sensors — only if values are not None
            # None = virtual appliance (SFVH) or unsupported hardware
            for desc in SENSOR_DESCRIPTIONS:
                if not desc.requires_hardware:
                    continue
                uid = f"{entry.entry_id}_sensor_{desc.key}"
                if uid in added_ids:
                    continue
                value = desc.value_fn(data)
                if value is not None:
                    # Value available → physical appliance → create sensor
                    added_ids.add(uid)
                    new_entities.append(SophosSensor(coordinator, desc))
                else:
                    # Mark as checked so we don't retry every cycle
                    # We add to added_ids only after health data has been fetched
                    # (health is a slow-tier fetch — check if it's populated)
                    if health:
                        added_ids.add(uid)  # None on VM → never create

        if new_entities:
            async_add_entities(new_entities)

    entry.async_on_unload(
        coordinator.async_add_listener(_add_dynamic_sensors)
    )

    if coordinator.data:
        _add_dynamic_sensors()


class SophosDHCPLeaseSensor(SophosEntity, SensorEntity):
    """Kombinierter DHCP-Sensor: Server-Status + Lease-Anzahl.

    native_value:  "off" | "on"  (maschinenlesbar, lokalisierbar über translations)
    Attributes:    lease_count (int) für Automationen/Graphen, plus server-Details
    """

    _attr_translation_key = "dhcp_leases"
    _attr_icon = "mdi:server-network"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = ["off", "on"]

    def __init__(
        self,
        coordinator: SophosCoordinator,
        server: dict[str, Any],
    ) -> None:
        self._server_name = server.get("Name", "unknown")
        super().__init__(
            coordinator,
            unique_suffix=f"dhcp_leases_{self._server_name}",
        )
        self._attr_translation_placeholders = {"server": self._server_name}

    def _get_server(self) -> dict[str, Any]:
        if not self.coordinator.data:
            return {}
        for s in self.coordinator.data.get(DATA_DHCP_SERVERS, []):
            if s.get("Name") == self._server_name:
                return s
        return {}

    def _get_leases(self) -> list[dict[str, Any]]:
        server = self._get_server()
        raw = server.get("StaticLease", [])
        if isinstance(raw, dict):
            return [raw]
        return raw if isinstance(raw, list) else []

    @property
    def native_value(self) -> str | None:
        if self.coordinator.data is None:
            return None
        server = self._get_server()
        if not server:
            return None
        running = str(server.get("Status", "0")) == "1"
        return "on" if running else "off"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        server = self._get_server()
        leases = self._get_leases()
        normalised = [
            {**lease, "MACAddress": lease.get("MACAddress", "").lower()}
            for lease in leases
        ]
        return {
            "server_name":  self._server_name,
            "interface":    server.get("Interface"),
            "lease_range":  server.get("LeaseTime"),
            "lease_count":  len(leases),
            "leases":       normalised,
        }


class SophosSensor(SophosEntity, SensorEntity):
    """A sensor entity backed by a SophosSensorDescription."""

    entity_description: SophosSensorDescription

    def __init__(
        self,
        coordinator: SophosCoordinator,
        description: SophosSensorDescription,
    ) -> None:
        super().__init__(coordinator, unique_suffix=f"sensor_{description.key}")
        self.entity_description = description

    @property
    def native_value(self) -> Any:
        if self.coordinator.data is None:
            return None
        return self.entity_description.value_fn(self.coordinator.data)


class SophosFanSensor(SophosEntity, SensorEntity):
    """Sensor for a single fan's RPM reading from SNMP sfosXGSystemHealth."""

    _attr_native_unit_of_measurement = "RPM"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_suggested_display_precision = 0
    _attr_icon = "mdi:fan"

    def __init__(self, coordinator: SophosCoordinator, fan_key: str) -> None:
        super().__init__(coordinator, unique_suffix=f"sensor_{fan_key}")
        self._fan_key = fan_key
        self._attr_translation_key = "fan_speed"
        self._attr_translation_placeholders = {"fan": fan_key.replace("_", " ")}

    @property
    def native_value(self) -> int | None:
        if self.coordinator.data is None:
            return None
        return (
            self.coordinator.data
            .get(DATA_SNMP_HEALTH, {})
            .get("fans", {})
            .get(self._fan_key)
        )


class SophosServicesSummarySensor(SophosEntity, SensorEntity):
    """Aggregations-Sensor: Anzahl laufender Dienste + vollständige Liste als Attribut.

    State:      Anzahl laufender Dienste (int)
    Unit:       "/ 21 running"
    Attributes:
        running  — sorted list of running service names
        stopped  — sorted list of stopped/unknown service names
        details  — dict {friendly_name: state_code} for all services
    """

    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:application-cog-outline"
    _attr_translation_key = "services_summary"

    def __init__(self, coordinator: SophosCoordinator) -> None:
        super().__init__(coordinator, unique_suffix="sensor_services_summary")
        self._attr_native_unit_of_measurement = f"/ {len(SERVICE_OIDS)} running"

    @property
    def native_value(self) -> int | None:
        if self.coordinator.data is None:
            return None
        services = self.coordinator.data.get(DATA_SNMP_SERVICES, {})
        if not services:
            return None
        return sum(1 for code in services.values() if code == SERVICE_RUNNING_STATE)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if self.coordinator.data is None:
            return {}
        services = self.coordinator.data.get(DATA_SNMP_SERVICES, {})
        key_to_name: dict[str, str] = {
            svc_key: friendly
            for _oid, (svc_key, friendly) in SERVICE_OIDS.items()
        }
        running: list[str] = []
        stopped: list[str] = []
        details: dict[str, int] = {}
        for svc_key, code in services.items():
            friendly = key_to_name.get(svc_key, svc_key)
            details[friendly] = code
            if code == SERVICE_RUNNING_STATE:
                running.append(friendly)
            else:
                stopped.append(friendly)
        return {
            "running": sorted(running),
            "stopped": sorted(stopped),
            "details": details,
        }


class SophosLicensesSummarySensor(SophosEntity, SensorEntity):
    """Aggregations-Sensor: Anzahl gültiger Lizenzen + Details als Attribut.

    State:      Anzahl OK-Lizenzen (int)
    Unit:       "/ 9 OK"
    Attributes:
        ok          — sorted list of OK license names
        problem     — sorted list of problem license names
        next_expiry — earliest expiry date (ISO string) or None
        details     — list of {name, status_code, expiry} for all modules
    """

    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_icon = "mdi:license"
    _attr_translation_key = "licenses_summary"

    def __init__(self, coordinator: SophosCoordinator) -> None:
        super().__init__(coordinator, unique_suffix="sensor_licenses_summary")
        self._attr_native_unit_of_measurement = f"/ {len(LICENSE_OIDS)} OK"

    @property
    def native_value(self) -> int | None:
        if self.coordinator.data is None:
            return None
        licenses = self.coordinator.data.get(DATA_SNMP_LICENSES, {})
        if not licenses:
            return None
        return sum(
            1 for lic in licenses.values()
            if lic.get("status_code") in LICENSE_OK_STATES
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if self.coordinator.data is None:
            return {}
        licenses = self.coordinator.data.get(DATA_SNMP_LICENSES, {})
        ok: list[str] = []
        problem: list[str] = []
        details: list[dict[str, Any]] = []
        expiry_dates: list[str] = []
        for _key, lic in licenses.items():
            name = lic.get("name", _key)
            code = lic.get("status_code", 0)
            expiry = lic.get("expiry_date")
            details.append({"name": name, "status_code": code, "expiry": expiry})
            if code in LICENSE_OK_STATES:
                ok.append(name)
            else:
                problem.append(name)
            if expiry:
                expiry_dates.append(expiry)
        def _parse_expiry(s: str):
            for fmt in ("%b %d %Y", "%b  %d %Y"):
                try:
                    return datetime.strptime(s.strip(), fmt)
                except ValueError:
                    continue
            return None

        parsed = [(_parse_expiry(e), e) for e in expiry_dates if _parse_expiry(e)]
        next_expiry = min(parsed, key=lambda x: x[0])[1] if parsed else None

        return {
            "ok":          sorted(ok),
            "problem":     sorted(problem),
            "next_expiry": next_expiry,
            "details":     sorted(details, key=lambda d: d["name"]),
        }

class SophosUptimeSensor(SophosEntity, SensorEntity):
    """Sensor für Uptime — lesbarer State + Rohwert in Sekunden als Attribut.

    State:      "77 d 14 h" (formatiert, gut lesbar)
    Attributes: uptime_seconds — Rohwert für Graphing/Automationen
    """

    _attr_translation_key = "uptime"
    _attr_icon = "mdi:timer-outline"

    def __init__(self, coordinator: SophosCoordinator) -> None:
        super().__init__(coordinator, unique_suffix="sensor_uptime")

    @staticmethod
    def _format(seconds: int) -> str:
        days, rem = divmod(seconds, 86400)
        hours = rem // 3600
        if days > 0:
            return f"{days} d {hours} h"
        minutes = rem // 60
        return f"{hours} h {minutes} min"

    @property
    def native_value(self) -> str | None:
        if self.coordinator.data is None:
            return None
        seconds = self.coordinator.data.get(DATA_SNMP_STATS, {}).get("uptime_seconds")
        if seconds is None:
            return None
        return self._format(int(seconds))

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        if self.coordinator.data is None:
            return {}
        seconds = self.coordinator.data.get(DATA_SNMP_STATS, {}).get("uptime_seconds")
        return {"uptime_seconds": seconds}

