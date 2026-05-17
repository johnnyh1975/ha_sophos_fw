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
)
from custom_components.sophos_firewall.binary_sensor import (
    SophosInterfaceSensor, SophosFirewallRuleSensor, SophosVPNTunnelSensor,
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
        assert entity.native_value == 8  # 8 running in MOCK_SNMP_SERVICES

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
    def test_running_zero_leases(self, mock_coordinator):
        entity = SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"})
        assert entity.native_value == "In Betrieb · 0 Leases"

    def test_running_one_lease(self, mock_coordinator):
        mock_coordinator.data["dhcp_servers"] = [{
            "Name": "Main_DHCP", "Status": "1", "Interface": "PortA",
            "StaticLease": {"MACAddress": "AA:BB:CC:DD:EE:FF", "IPAddress": "10.0.0.1", "Hostname": "PC"},
        }]
        assert SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"}).native_value == "In Betrieb · 1 Lease"

    def test_running_multiple_leases(self, mock_coordinator):
        mock_coordinator.data["dhcp_servers"] = [{
            "Name": "Main_DHCP", "Status": "1", "Interface": "PortA",
            "StaticLease": [
                {"MACAddress": "AA:BB:CC:DD:EE:01", "IPAddress": "10.0.0.1", "Hostname": "PC1"},
                {"MACAddress": "AA:BB:CC:DD:EE:02", "IPAddress": "10.0.0.2", "Hostname": "PC2"},
            ],
        }]
        assert SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"}).native_value == "In Betrieb · 2 Leases"

    def test_not_running(self, mock_coordinator):
        mock_coordinator.data["dhcp_servers"] = [{"Name": "Main_DHCP", "Status": "0"}]
        assert SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"}).native_value == "Außer Betrieb"

    def test_mac_normalized_to_lowercase(self, mock_coordinator):
        mock_coordinator.data["dhcp_servers"] = [{
            "Name": "Main_DHCP", "Status": "1",
            "StaticLease": {"MACAddress": "AA:BB:CC:DD:EE:FF", "IPAddress": "10.0.0.1", "Hostname": "X"},
        }]
        leases = SophosDHCPLeaseSensor(mock_coordinator, {"Name": "Main_DHCP"}).extra_state_attributes["leases"]
        assert leases[0]["MACAddress"] == "aa:bb:cc:dd:ee:ff"


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
        await entity.async_turn_off()
        mock_coordinator.xml_client.set_firewall_rule_status.assert_awaited_once_with("Allow LAN to IoT", False)
        mock_coordinator.force_operative_refresh.assert_called_once()
        mock_coordinator.async_request_refresh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_api_error_skips_refresh(self, mock_coordinator):
        from custom_components.sophos_firewall.sophos_client import SophosAPIError
        mock_coordinator.force_operative_refresh = MagicMock()
        mock_coordinator.xml_client.set_firewall_rule_status.side_effect = SophosAPIError("fail")
        entity = SophosFirewallRuleSwitch(mock_coordinator, {"Name": "Allow LAN to IoT"})
        await entity.async_turn_off()
        mock_coordinator.force_operative_refresh.assert_not_called()
        mock_coordinator.async_request_refresh.assert_not_awaited()


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
        await entity.async_turn_off()
        mock_coordinator.xml_client.set_web_filter_default_action.assert_awaited_once_with("DefaultPolicy", False)
        mock_coordinator.force_operative_refresh.assert_called_once()
