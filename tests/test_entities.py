"""Tests for entity state logic — sensors, binary_sensors, switches.

All tests use the mock_coordinator fixture from conftest.py.
"""
from __future__ import annotations
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from unittest.mock import AsyncMock, MagicMock
import pytest

from custom_components.sophos_firewall.sensor import (
    SophosSensor, SophosServicesSummarySensor, SophosLicensesSummarySensor,
    SophosDHCPLeaseSensor, SophosUptimeSensor, SENSOR_DESCRIPTIONS,
    SophosHAStateSensor, SophosHAPeerStateSensor,
)
from custom_components.sophos_firewall.binary_sensor import (
    SophosInterfaceSensor, SophosFirewallRuleSensor, SophosVPNTunnelSensor,
    SophosHAEnabledSensor, SophosPSUSensor,
)
from custom_components.sophos_firewall.switch import (
    SophosFirewallRuleSwitch, SophosWebFilterSwitch,
)
from tests.conftest import MOCK_SNMP_LICENSES, MOCK_SNMP_TUNNELS


# ── Sensor: statische Descriptions ───────────────────────────────────────────

class TestSensors:
    def test_memory_percent(self, mock_coordinator):
        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "memory_percent")
        assert SophosSensor(mock_coordinator, desc).native_value == 33

    def test_disk_percent(self, mock_coordinator):
        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "disk_percent")
        assert SophosSensor(mock_coordinator, desc).native_value == 27

    def test_ftp_hits(self, mock_coordinator):
        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "ftp_hits")
        assert SophosSensor(mock_coordinator, desc).native_value == 0

    def test_imap_hits(self, mock_coordinator):
        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "imap_hits")
        assert SophosSensor(mock_coordinator, desc).native_value == 47

    def test_pop3_hits(self, mock_coordinator):
        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "pop3_hits")
        assert SophosSensor(mock_coordinator, desc).native_value == 12

    def test_web_filter_finds_default_policy_by_name(self, mock_coordinator):
        mock_coordinator.data["web_filter_policies"] = [
            {"Name": "Strict Policy", "DefaultAction": "Deny"},
            {"Name": "DefaultPolicy", "DefaultAction": "Allow"},
        ]
        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "web_filter_default_action")
        assert SophosSensor(mock_coordinator, desc).native_value == "Allow"

    def test_web_filter_falls_back_to_first(self, mock_coordinator):
        mock_coordinator.data["web_filter_policies"] = [
            {"Name": "Strict", "DefaultAction": "Deny"},
        ]
        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "web_filter_default_action")
        assert SophosSensor(mock_coordinator, desc).native_value == "Deny"

    def test_backup_frequency(self, mock_coordinator):
        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "backup_frequency")
        assert SophosSensor(mock_coordinator, desc).native_value == "Monthly"

    def test_none_when_no_data(self, mock_coordinator):
        mock_coordinator.data = None
        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "memory_percent")
        assert SophosSensor(mock_coordinator, desc).native_value is None

    def test_cpu_temperature_none_on_vm(self, mock_coordinator):
        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "cpu_temperature")
        assert SophosSensor(mock_coordinator, desc).native_value is None


# ── Sensor: Uptime ────────────────────────────────────────────────────────────

class TestUptimeSensor:
    def test_formats_days_and_hours(self, mock_coordinator):
        mock_coordinator.data["snmp_stats"]["uptime_seconds"] = 77 * 86400 + 14 * 3600
        assert SophosUptimeSensor(mock_coordinator).native_value == "77 d 14 h"

    def test_formats_hours_and_minutes(self, mock_coordinator):
        mock_coordinator.data["snmp_stats"]["uptime_seconds"] = 3 * 3600 + 25 * 60
        assert SophosUptimeSensor(mock_coordinator).native_value == "3 h 25 min"

    def test_raw_seconds_in_attributes(self, mock_coordinator):
        mock_coordinator.data["snmp_stats"]["uptime_seconds"] = 6502743
        attrs = SophosUptimeSensor(mock_coordinator).extra_state_attributes
        assert attrs["uptime_seconds"] == 6502743

    def test_none_when_no_data(self, mock_coordinator):
        mock_coordinator.data = None
        assert SophosUptimeSensor(mock_coordinator).native_value is None


# ── Sensor: Dienste-Aggregation ───────────────────────────────────────────────

class TestServicesSummarySensor:
    def test_counts_running(self, mock_coordinator):
        entity = SophosServicesSummarySensor(mock_coordinator)
        # MOCK_SNMP_SERVICES has 19 services at code 3 (running) and
        # 2 at code 1 (stopped: antispam, ha_svc) — 21 total.
        assert entity.native_value == 19

    def test_unit_has_21(self, mock_coordinator):
        entity = SophosServicesSummarySensor(mock_coordinator)
        assert "21" in entity._attr_native_unit_of_measurement

    def test_running_attribute(self, mock_coordinator):
        attrs = SophosServicesSummarySensor(mock_coordinator).extra_state_attributes
        assert "DNS" in attrs["running"]
        assert "Antivirus" in attrs["running"]

    def test_stopped_attribute(self, mock_coordinator):
        attrs = SophosServicesSummarySensor(mock_coordinator).extra_state_attributes
        assert "Anti-Spam" in attrs["stopped"]
        assert "HA-Service" in attrs["stopped"]

    def test_none_when_empty_services(self, mock_coordinator):
        mock_coordinator.data["snmp_services"] = {}
        assert SophosServicesSummarySensor(mock_coordinator).native_value is None

    def test_none_when_no_data(self, mock_coordinator):
        mock_coordinator.data = None
        assert SophosServicesSummarySensor(mock_coordinator).native_value is None


# ── Sensor: Lizenzen-Aggregation ──────────────────────────────────────────────

class TestLicensesSummarySensor:
    def test_counts_ok(self, mock_coordinator):
        assert SophosLicensesSummarySensor(mock_coordinator).native_value == 2

    def test_ok_attribute(self, mock_coordinator):
        attrs = SophosLicensesSummarySensor(mock_coordinator).extra_state_attributes
        assert "Basis-Firewall" in attrs["ok"]
        assert "Network Protection" in attrs["ok"]

    def test_problem_attribute(self, mock_coordinator):
        attrs = SophosLicensesSummarySensor(mock_coordinator).extra_state_attributes
        assert "Enhanced Plus" in attrs["problem"]

    def test_next_expiry_chronologically_correct(self, mock_coordinator):
        mock_coordinator.data["snmp_licenses"] = {
            "a": {"name": "A", "status_code": 3, "expiry_date": "Dec 31 2027"},
            "b": {"name": "B", "status_code": 3, "expiry_date": "Jan 15 2027"},
            "c": {"name": "C", "status_code": 3, "expiry_date": "Nov 1 2026"},
        }
        attrs = SophosLicensesSummarySensor(mock_coordinator).extra_state_attributes
        # Nov 2026 ist das früheste — lexikografisch wäre "Dec" falsch
        assert attrs["next_expiry"] == "Nov 1 2026"

    def test_none_when_no_data(self, mock_coordinator):
        mock_coordinator.data = None
        assert SophosLicensesSummarySensor(mock_coordinator).native_value is None


# ── Sensor: DHCP kombiniert ───────────────────────────────────────────────────

class TestDHCPLeaseSensor:
    def test_running_returns_on(self, mock_coordinator):
        entity = SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"})
        assert entity.native_value == "on"

    def test_not_running_returns_off(self, mock_coordinator):
        mock_coordinator.data["dhcp_servers"] = [{"Name": "Main_DHCP", "Status": "0"}]
        assert SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"}).native_value == "off"

    def test_lease_count_zero(self, mock_coordinator):
        entity = SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"})
        assert entity.extra_state_attributes["lease_count"] == 0

    def test_lease_count_single_dict(self, mock_coordinator):
        mock_coordinator.data["dhcp_servers"] = [{
            "Name": "Main_DHCP", "Status": "1", "Interface": "PortA",
            "StaticLease": {"MACAddress": "AA:BB:CC:DD:EE:FF", "IPAddress": "10.0.0.1", "Hostname": "PC"},
        }]
        attrs = SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"}).extra_state_attributes
        assert attrs["lease_count"] == 1

    def test_lease_count_multiple(self, mock_coordinator):
        mock_coordinator.data["dhcp_servers"] = [{
            "Name": "Main_DHCP", "Status": "1", "Interface": "PortA",
            "StaticLease": [
                {"MACAddress": "AA:BB:CC:DD:EE:01", "IPAddress": "10.0.0.1", "Hostname": "PC1"},
                {"MACAddress": "AA:BB:CC:DD:EE:02", "IPAddress": "10.0.0.2", "Hostname": "PC2"},
            ],
        }]
        attrs = SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"}).extra_state_attributes
        assert attrs["lease_count"] == 2

    def test_mac_normalized_to_lowercase(self, mock_coordinator):
        mock_coordinator.data["dhcp_servers"] = [{
            "Name": "Main_DHCP", "Status": "1",
            "StaticLease": {"MACAddress": "AA:BB:CC:DD:EE:FF", "IPAddress": "10.0.0.1", "Hostname": "X"},
        }]
        leases = SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"}).extra_state_attributes["leases"]
        assert leases[0]["MACAddress"] == "aa:bb:cc:dd:ee:ff"

    def test_none_when_no_data(self, mock_coordinator):
        mock_coordinator.data = None
        assert SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"}).native_value is None


# ── Binary Sensor: Interface ──────────────────────────────────────────────────

class TestInterfaceSensor:
    def test_is_on(self, mock_coordinator):
        assert SophosInterfaceSensor(mock_coordinator, {"Name": "PortA"}).is_on is True

    def test_is_off(self, mock_coordinator):
        mock_coordinator.data["interfaces"] = [
            {"Name": "PortA", "InterfaceStatus": "OFF", "NetworkZone": "LAN"}
        ]
        assert SophosInterfaceSensor(mock_coordinator, {"Name": "PortA"}).is_on is False

    def test_none_when_not_found(self, mock_coordinator):
        assert SophosInterfaceSensor(mock_coordinator, {"Name": "PortZ"}).is_on is None

    def test_attributes(self, mock_coordinator):
        attrs = SophosInterfaceSensor(mock_coordinator, {"Name": "PortA"}).extra_state_attributes
        assert attrs["zone"] == "LAN"
        assert attrs["mtu"] == "1500"

    def test_none_when_no_data(self, mock_coordinator):
        mock_coordinator.data = None
        assert SophosInterfaceSensor(mock_coordinator, {"Name": "PortA"}).is_on is None


# ── Binary Sensor: Firewall Rule ──────────────────────────────────────────────

class TestFirewallRuleSensor:
    def test_enabled_is_on(self, mock_coordinator):
        assert SophosFirewallRuleSensor(mock_coordinator, {"Name": "Allow LAN to IoT"}).is_on is True

    def test_disabled_is_off(self, mock_coordinator):
        mock_coordinator.data["firewall_rules"] = [
            {"Name": "Block All", "Status": "Disable", "Action": "Drop",
             "PolicyType": "Network", "IPFamily": "IPv4"}
        ]
        assert SophosFirewallRuleSensor(mock_coordinator, {"Name": "Block All"}).is_on is False

    def test_attributes(self, mock_coordinator):
        attrs = SophosFirewallRuleSensor(mock_coordinator, {"Name": "Allow LAN to IoT"}).extra_state_attributes
        assert attrs["action"] == "Accept"
        assert attrs["policy_type"] == "Network"


# ── Binary Sensor: VPN Tunnel ─────────────────────────────────────────────────

class TestVPNTunnelSensor:
    def test_active_is_on(self, mock_coordinator):
        assert SophosVPNTunnelSensor(mock_coordinator, MOCK_SNMP_TUNNELS[0]).is_on is True

    def test_inactive_is_off(self, mock_coordinator):
        assert SophosVPNTunnelSensor(mock_coordinator, MOCK_SNMP_TUNNELS[1]).is_on is False

    def test_attributes(self, mock_coordinator):
        attrs = SophosVPNTunnelSensor(mock_coordinator, MOCK_SNMP_TUNNELS[0]).extra_state_attributes
        assert attrs["conn_status_code"] == 1
        assert attrs["activated"] is True


# ── Switch: Firewall Rule ─────────────────────────────────────────────────────

class TestFirewallRuleSwitch:
    def test_enabled_is_on(self, mock_coordinator):
        assert SophosFirewallRuleSwitch(mock_coordinator, {"Name": "Allow LAN to IoT"}).is_on is True

    @pytest.mark.asyncio
    async def test_turn_off_calls_force_refresh(self, mock_coordinator):
        mock_coordinator.force_operative_refresh = MagicMock()
        entity = SophosFirewallRuleSwitch(mock_coordinator, {"Name": "Allow LAN to IoT"})
        entity.async_write_ha_state = MagicMock()  # entity not added to hass in test
        await entity.async_turn_off()
        mock_coordinator.xml_client.set_firewall_rule_status.assert_awaited_once_with("Allow LAN to IoT", False)
        mock_coordinator.force_operative_refresh.assert_called_once()
        mock_coordinator.async_request_refresh.assert_awaited_once()
        # Optimistic state reflects the change immediately
        assert entity._optimistic is False

    @pytest.mark.asyncio
    async def test_api_error_raises_and_reverts(self, mock_coordinator):
        from custom_components.sophos_firewall.sophos_client import SophosAPIError
        from homeassistant.exceptions import HomeAssistantError
        mock_coordinator.force_operative_refresh = MagicMock()
        mock_coordinator.xml_client.set_firewall_rule_status.side_effect = SophosAPIError("fail")
        entity = SophosFirewallRuleSwitch(mock_coordinator, {"Name": "Allow LAN to IoT"})
        # On failure the switch raises (surfaces error to user) and forces a
        # refresh so the UI reverts to the real state — it no longer silently
        # swallows the error.
        with pytest.raises(HomeAssistantError):
            await entity.async_turn_off()
        mock_coordinator.force_operative_refresh.assert_called_once()
        mock_coordinator.async_request_refresh.assert_awaited_once()
        # No optimistic state was set since the write failed
        assert entity._optimistic is None


# ── Switch: Web Filter ────────────────────────────────────────────────────────

class TestWebFilterSwitch:
    def test_allow_is_on(self, mock_coordinator):
        assert SophosWebFilterSwitch(mock_coordinator, {"Name": "DefaultPolicy"}).is_on is True

    def test_deny_is_off(self, mock_coordinator):
        mock_coordinator.data["web_filter_policies"] = [
            {"Name": "Block All", "DefaultAction": "Deny"}
        ]
        assert SophosWebFilterSwitch(mock_coordinator, {"Name": "Block All"}).is_on is False

    @pytest.mark.asyncio
    async def test_turn_off_calls_force_refresh(self, mock_coordinator):
        mock_coordinator.force_operative_refresh = MagicMock()
        entity = SophosWebFilterSwitch(mock_coordinator, {"Name": "DefaultPolicy"})
        entity.async_write_ha_state = MagicMock()  # entity not added to hass in test
        await entity.async_turn_off()
        mock_coordinator.xml_client.set_web_filter_default_action.assert_awaited_once_with("DefaultPolicy", False)
        mock_coordinator.force_operative_refresh.assert_called_once()


# ── HA Cluster Entities ───────────────────────────────────────────────────────

MOCK_HA_ENABLED  = {"ha_enabled": True,  "current_state": 3, "peer_state": 1}
MOCK_HA_DISABLED = {"ha_enabled": False, "current_state": 2, "peer_state": 0}


class TestHAEnabledSensor:
    def test_is_on_when_ha_enabled(self, mock_coordinator):
        mock_coordinator.data["snmp_ha"] = MOCK_HA_ENABLED
        assert SophosHAEnabledSensor(mock_coordinator).is_on is True

    def test_is_off_when_ha_disabled(self, mock_coordinator):
        mock_coordinator.data["snmp_ha"] = MOCK_HA_DISABLED
        assert SophosHAEnabledSensor(mock_coordinator).is_on is False

    def test_none_when_no_data(self, mock_coordinator):
        mock_coordinator.data = None
        assert SophosHAEnabledSensor(mock_coordinator).is_on is None

    def test_none_when_ha_dict_empty(self, mock_coordinator):
        mock_coordinator.data["snmp_ha"] = {}
        assert SophosHAEnabledSensor(mock_coordinator).is_on is None

    def test_attributes_contain_state_codes(self, mock_coordinator):
        mock_coordinator.data["snmp_ha"] = MOCK_HA_ENABLED
        attrs = SophosHAEnabledSensor(mock_coordinator).extra_state_attributes
        assert attrs["current_state_code"] == 3
        assert attrs["peer_state_code"] == 1


class TestHAStateSensor:
    def test_primary_state(self, mock_coordinator):
        mock_coordinator.data["snmp_ha"] = MOCK_HA_ENABLED
        assert SophosHAStateSensor(mock_coordinator).native_value == "primary"

    def test_standalone_state(self, mock_coordinator):
        mock_coordinator.data["snmp_ha"] = MOCK_HA_DISABLED
        assert SophosHAStateSensor(mock_coordinator).native_value == "standalone"

    def test_all_states_map_correctly(self, mock_coordinator):
        expected = {0: "not_applicable", 1: "auxiliary", 2: "standalone",
                    3: "primary", 4: "faulty", 5: "ready"}
        for code, label in expected.items():
            mock_coordinator.data["snmp_ha"] = {"ha_enabled": True, "current_state": code, "peer_state": 0}
            assert SophosHAStateSensor(mock_coordinator).native_value == label

    def test_none_when_no_data(self, mock_coordinator):
        mock_coordinator.data = None
        assert SophosHAStateSensor(mock_coordinator).native_value is None

    def test_attribute_contains_raw_code(self, mock_coordinator):
        mock_coordinator.data["snmp_ha"] = MOCK_HA_ENABLED
        assert SophosHAStateSensor(mock_coordinator).extra_state_attributes["state_code"] == 3


class TestHAPeerStateSensor:
    def test_auxiliary_peer(self, mock_coordinator):
        mock_coordinator.data["snmp_ha"] = MOCK_HA_ENABLED
        assert SophosHAPeerStateSensor(mock_coordinator).native_value == "auxiliary"

    def test_not_applicable_peer_when_standalone(self, mock_coordinator):
        mock_coordinator.data["snmp_ha"] = MOCK_HA_DISABLED
        assert SophosHAPeerStateSensor(mock_coordinator).native_value == "not_applicable"

    def test_none_when_no_data(self, mock_coordinator):
        mock_coordinator.data = None
        assert SophosHAPeerStateSensor(mock_coordinator).native_value is None

    def test_attribute_contains_raw_code(self, mock_coordinator):
        mock_coordinator.data["snmp_ha"] = MOCK_HA_ENABLED
        assert SophosHAPeerStateSensor(mock_coordinator).extra_state_attributes["state_code"] == 1


# ── PSU Binary Sensors ────────────────────────────────────────────────────────

MOCK_HEALTH_WITH_PSUS = {
    "cpu_temperature_c": None,
    "npu_temperature_c": None,
    "fans": {},
    "psus": {"psu_1": True, "psu_2": False},
}


class TestPSUSensor:
    def test_is_on_when_psu_operational(self, mock_coordinator):
        mock_coordinator.data["snmp_health"] = MOCK_HEALTH_WITH_PSUS
        assert SophosPSUSensor(mock_coordinator, "psu_1").is_on is True

    def test_is_off_when_psu_failed(self, mock_coordinator):
        mock_coordinator.data["snmp_health"] = MOCK_HEALTH_WITH_PSUS
        assert SophosPSUSensor(mock_coordinator, "psu_2").is_on is False

    def test_none_when_no_data(self, mock_coordinator):
        mock_coordinator.data = None
        assert SophosPSUSensor(mock_coordinator, "psu_1").is_on is None

    def test_none_when_psu_key_absent(self, mock_coordinator):
        mock_coordinator.data["snmp_health"] = {"psus": {}}
        assert SophosPSUSensor(mock_coordinator, "psu_1").is_on is None

    def test_none_on_virtual_appliance(self, mock_coordinator):
        # SFVH returns empty psus dict — entity would not be created,
        # but if it somehow is, native_value must be None not crash
        mock_coordinator.data["snmp_health"] = {
            "cpu_temperature_c": None, "npu_temperature_c": None,
            "fans": {}, "psus": {},
        }
        assert SophosPSUSensor(mock_coordinator, "psu_1").is_on is None

    def test_unique_suffix_per_psu(self, mock_coordinator):
        e1 = SophosPSUSensor(mock_coordinator, "psu_1")
        e2 = SophosPSUSensor(mock_coordinator, "psu_2")
        assert e1._unique_suffix != e2._unique_suffix


# ── Hardening: malformed XML field values must not crash state properties ──────

from custom_components.sophos_firewall.entity import field_str


class TestFieldStrHardening:
    """field_str() guarantees a str so downstream .lower()/.upper() is safe."""

    def test_normal_string(self):
        assert field_str({"Name": "PortA"}, "Name") == "PortA"

    def test_missing_key_returns_default(self):
        assert field_str({}, "Name") == ""
        assert field_str({}, "Name", "fallback") == "fallback"

    def test_explicit_none_returns_default(self):
        assert field_str({"Name": None}, "Name") == ""

    def test_nested_dict_coerced_to_str(self):
        # Sophos returning <Name><Sub>x</Sub></Name> yields a dict — must not crash
        result = field_str({"Name": {"Sub": "x"}}, "Name")
        assert isinstance(result, str)
        result.lower()  # must not raise

    def test_number_coerced_to_str(self):
        assert isinstance(field_str({"Status": 1}, "Status"), str)


class TestInterfaceSensorHardening:
    """Interface sensor must survive malformed InterfaceStatus values."""

    def test_none_status_does_not_crash(self, mock_coordinator):
        mock_coordinator.data["interfaces"] = [{"Name": "PortA", "InterfaceStatus": None}]
        entity = SophosInterfaceSensor(mock_coordinator, {"Name": "PortA"})
        # Previously .upper() on None crashed — now returns a clean False
        assert entity.is_on is False

    def test_nested_dict_status_does_not_crash(self, mock_coordinator):
        mock_coordinator.data["interfaces"] = [
            {"Name": "PortA", "InterfaceStatus": {"unexpected": "shape"}}
        ]
        entity = SophosInterfaceSensor(mock_coordinator, {"Name": "PortA"})
        assert entity.is_on is False  # str(dict).upper() != "ON", no crash


class TestFirewallRuleSwitchHardening:
    def test_none_status_does_not_crash(self, mock_coordinator):
        mock_coordinator.data["firewall_rules"] = [{"Name": "R1", "Status": None}]
        entity = SophosFirewallRuleSwitch(mock_coordinator, {"Name": "R1"})
        assert entity.is_on is False
