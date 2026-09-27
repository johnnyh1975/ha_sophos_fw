"""Every translation_key used in the code must resolve in strings.json.

Regression guard for a v1.0.2 bug: 23 entity translations (almost every
sensor name, plus the interface / firewall-rule / VPN binary sensors) were
silently dropped from strings.json and both translation files. Home Assistant
then fell back to generic device-class names such as "Konnektivität".
scripts/check_translations.py did not notice, because it only compares the
three JSON files with EACH OTHER — and all three were broken identically.

This test closes that gap from the other side: it reads the integration's
real source with the ast module (no imports, no mocks) and checks every key
against the real strings.json.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

COMPONENT = Path(__file__).resolve().parent.parent / "custom_components" / "sophos_firewall"
STRINGS = json.loads((COMPONENT / "strings.json").read_text(encoding="utf-8"))

# Entity platform modules → the strings.json "entity.<platform>" section.
PLATFORM_FILES = {
    "binary_sensor": "binary_sensor.py",
    "sensor": "sensor.py",
    "switch": "switch.py",
    "button": "button.py",
}

# Calls whose translation_key refers to strings.json "exceptions", not "entity".
EXCEPTION_CALLS = {
    "HomeAssistantError",
    "ConfigEntryNotReady",
    "ConfigEntryAuthFailed",
    "UpdateFailed",
    "ServiceValidationError",
}


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _collect(path: Path) -> tuple[set[str], set[str]]:
    """Return (entity_keys, exception_keys) used in one source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    entity: set[str] = set()
    exceptions: set[str] = set()

    for node in ast.walk(tree):
        # _attr_translation_key = "x"   /   self._attr_translation_key = "x"
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
                if name == "_attr_translation_key" and isinstance(node.value.value, str):
                    entity.add(node.value.value)

        # SomethingDescription(translation_key="x")  /  HomeAssistantError(translation_key="x")
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "translation_key" and isinstance(kw.value, ast.Constant):
                    if _call_name(node) in EXCEPTION_CALLS:
                        exceptions.add(kw.value.value)
                    else:
                        entity.add(kw.value.value)
    return entity, exceptions


@pytest.mark.parametrize("platform", sorted(PLATFORM_FILES))
def test_entity_translation_keys_exist(platform: str) -> None:
    entity_keys, _ = _collect(COMPONENT / PLATFORM_FILES[platform])
    assert entity_keys, f"collector found no translation keys in {platform} — collector broken?"

    available = set(STRINGS.get("entity", {}).get(platform, {}))
    missing = sorted(entity_keys - available)
    assert not missing, (
        f"entity.{platform} is missing translations for {missing} — HA would fall "
        f"back to a generic device-class name for these entities"
    )


def test_exception_translation_keys_exist() -> None:
    used: set[str] = set()
    for path in COMPONENT.glob("*.py"):
        used |= _collect(path)[1]
    assert used, "collector found no exception translation keys — collector broken?"

    missing = sorted(used - set(STRINGS.get("exceptions", {})))
    assert not missing, f"exceptions section is missing {missing}"


def test_known_regression_keys_present() -> None:
    """Pin the specific keys lost in v1.0.2, so a collector bug can't hide them."""
    ent = STRINGS["entity"]
    for key in ("interface_status", "firewall_rule_status", "vpn_tunnel_status"):
        assert key in ent["binary_sensor"], key
    for key in ("memory_percent", "uptime", "services_summary", "licenses_summary",
                "dhcp_leases", "imap_hits", "pop3_hits"):
        assert key in ent["sensor"], key


def test_coordinator_unreachable_keys_exist() -> None:
    """UpdateFailed keys set via class attributes are invisible to the AST collector."""
    from custom_components.sophos_firewall.coordinator import (
        SophosSnmpCoordinator,
        SophosXmlCoordinator,
    )

    for cls in (SophosXmlCoordinator, SophosSnmpCoordinator):
        assert cls.unreachable_translation_key in STRINGS["exceptions"], cls.__name__
    assert "api_access_denied" in STRINGS["exceptions"]
    assert "api_access_denied" in STRINGS["config"]["error"]
    assert "snmp_cannot_connect" in STRINGS["options"]["error"]


# ── icons.json (icon translations) ────────────────────────────────────────────

ICONS = json.loads((COMPONENT / "icons.json").read_text(encoding="utf-8"))

# Every icon icons.json uses, checked against the Material Design Icons
# package (@mdi/svg 7.4.47, meta.json). Regression guard: v1.0.x used
# "mdi:email-receive-outline", which is only an *alias* there (of
# email-arrow-left-outline); the HA frontend does not resolve aliases, so the
# IMAP and POP3 sensors showed no icon. Only add names listed as "name".
VERIFIED_MDI = {
    "account-multiple-outline", "application-cog-outline", "backup-restore",
    "clock-start", "email-arrow-left-outline", "email-outline", "email-sync-outline",
    "ethernet", "ethernet-off", "fan", "filter-check-outline", "filter-outline",
    "filter-remove-outline", "folder-network-outline", "harddisk", "license", "memory",
    "server-network", "server-network-off", "server-network-outline",
    "shield-bug-outline", "shield-check-outline", "shield-off-outline", "shield-outline",
    "swap-horizontal", "vpn", "web", "web-check",
    "cpu-64-bit", "download-network-outline", "upload-network-outline",
    "tray-arrow-down", "tray-arrow-up",
}

# Entities whose icon comes from their device class (temperature, power).
DEVICE_CLASS_ICON = {
    "sensor": {"cpu_temperature", "npu_temperature"},
    "binary_sensor": {"psu_status"},
}


def _icon_sections() -> list[tuple[str, str, dict]]:
    return [
        (platform, key, section)
        for platform, keys in ICONS["entity"].items()
        for key, section in keys.items()
    ]


def test_icons_belong_to_translated_entities() -> None:
    for platform, key, section in _icon_sections():
        assert key in STRINGS["entity"].get(platform, {}), f"{platform}.{key}"
        states = set(section.get("state", {}))
        if platform in ("binary_sensor", "switch"):
            assert states <= {"on", "off"}, f"{platform}.{key}: {states}"
        else:
            translated = set(STRINGS["entity"][platform][key].get("state", {}))
            assert states <= translated, f"{platform}.{key}: {states - translated}"


def test_icons_are_valid_mdi_icons() -> None:
    for platform, key, section in _icon_sections():
        icons = [section["default"], *section.get("state", {}).values()]
        for icon in icons:
            assert icon.startswith("mdi:"), f"{platform}.{key}: {icon}"
            assert icon.removeprefix("mdi:") in VERIFIED_MDI, f"{platform}.{key}: {icon}"
        # hassfest rejects a state icon equal to the default
        assert section["default"] not in section.get("state", {}).values(), f"{platform}.{key}"


def test_every_entity_has_an_icon() -> None:
    for platform, keys in STRINGS["entity"].items():
        expected = set(keys) - DEVICE_CLASS_ICON.get(platform, set())
        missing = expected - set(ICONS["entity"].get(platform, {}))
        assert not missing, f"{platform}: no icon for {sorted(missing)}"


@pytest.mark.parametrize("platform", sorted(PLATFORM_FILES))
def test_no_hard_coded_icons(platform: str) -> None:
    """icon-translations: icons live in icons.json, not in _attr_icon / icon=."""
    tree = ast.parse((COMPONENT / PLATFORM_FILES[platform]).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
                assert name != "_attr_icon", f"{platform}: line {node.lineno}"
        if isinstance(node, ast.Call):
            assert all(kw.arg != "icon" for kw in node.keywords), f"{platform}: line {node.lineno}"


def test_issue_translations_exist() -> None:
    import re

    from custom_components.sophos_firewall.issues import ISSUES

    for kind in ISSUES:
        issue = STRINGS["issues"][kind]
        for field in ("title", "description"):
            placeholders = set(re.findall(r"{(\w+)}", issue[field]))
            assert placeholders <= {"title", "host", "code"}, f"{kind}.{field}: {placeholders}"
