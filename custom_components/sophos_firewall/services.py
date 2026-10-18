"""Actions: block or unblock a site (URL group) or a device (IP host group).

The integration does not create rules. The user prepares the firewall once:
a web filter URL group used by a web policy (for sites), or an IP host group
used as the source of a drop/reject rule (for devices). The actions then only
change the membership of that group, with the same read-modify-write as the
switches (sophos_client._modify_record).

They change the firewall's configuration, so they need the "Allow changes"
option, like the switches.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, NoReturn

import voluptuous as vol
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv

from .const import CONF_WRITE_ACCESS, DOMAIN
from .sophos_client import SophosClient, SophosError, SophosNotFoundError, SophosWriteError

ATTR_CONFIG_ENTRY_ID = "config_entry_id"
ATTR_URL_GROUP = "url_group"
ATTR_URL = "url"
ATTR_HOST_GROUP = "host_group"
ATTR_IP_ADDRESS = "ip_address"
ATTR_HOST_NAME = "host_name"

SERVICE_BLOCK_URL = "block_url"
SERVICE_UNBLOCK_URL = "unblock_url"
SERVICE_BLOCK_DEVICE = "block_device"
SERVICE_UNBLOCK_DEVICE = "unblock_device"

# SFOS accepts domain names only in URL groups: "You must enter a valid domain
# name. Regular expressions aren't allowed." (SFOS 22 help); Sophos' migration
# utility keeps "simple domain tokens (A-Za-z0-9.-)"; max 250 characters.
_DOMAIN_RE = re.compile(r"^(?=.{1,250}$)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
# IP host names: max 50 characters, no comma, not starting with "#" (API docs
# allow 60; Sophos' migration utility truncates to 50).
_HOST_NAME_RE = re.compile(r"^[^#,][^,]{0,49}$")


def _domain(value: Any) -> str:
    text = str(value).strip().lower()
    if text.startswith(("http://", "https://")):
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    if not _DOMAIN_RE.match(text):
        raise vol.Invalid("expected a domain name such as example.com")
    return text


def _ipv4(value: Any) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except ValueError as err:
        raise vol.Invalid("expected an IPv4 address") from err


def _host_name(value: Any) -> str:
    text = str(value).strip()
    if not _HOST_NAME_RE.match(text):
        raise vol.Invalid("host name: max. 50 characters, no comma, not starting with #")
    return text


_ENTRY: dict[vol.Marker, Any] = {vol.Required(ATTR_CONFIG_ENTRY_ID): cv.string}
URL_SCHEMA = vol.Schema(
    {**_ENTRY, vol.Required(ATTR_URL_GROUP): cv.string, vol.Required(ATTR_URL): _domain}
)
BLOCK_DEVICE_SCHEMA = vol.Schema(
    {
        **_ENTRY,
        vol.Required(ATTR_HOST_GROUP): cv.string,
        vol.Required(ATTR_IP_ADDRESS): _ipv4,
        vol.Optional(ATTR_HOST_NAME): _host_name,
    }
)
UNBLOCK_DEVICE_SCHEMA = vol.Schema(
    {**_ENTRY, vol.Required(ATTR_HOST_GROUP): cv.string, vol.Required(ATTR_IP_ADDRESS): _ipv4}
)


def _client(hass: HomeAssistant, call: ServiceCall) -> SophosClient:
    """The XML client of the targeted entry, if it is loaded and may write."""
    entry_id = call.data[ATTR_CONFIG_ENTRY_ID]
    entry = hass.config_entries.async_get_entry(entry_id)
    if entry is None or entry.domain != DOMAIN:
        raise ServiceValidationError(
            translation_domain=DOMAIN, translation_key="entry_not_found",
            translation_placeholders={"entry_id": entry_id},
        )
    if entry.state is not ConfigEntryState.LOADED:
        raise ServiceValidationError(
            translation_domain=DOMAIN, translation_key="entry_not_loaded",
            translation_placeholders={"title": entry.title},
        )
    if not entry.options.get(CONF_WRITE_ACCESS, False):
        raise ServiceValidationError(
            translation_domain=DOMAIN, translation_key="write_access_disabled",
            translation_placeholders={"title": entry.title},
        )
    client: SophosClient = entry.runtime_data.xml.client
    return client


def _raise(err: SophosError, name: str) -> NoReturn:
    """Translate a failed write; the firewall's code picks the message."""
    code = err.code if isinstance(err, SophosWriteError) else None
    key = {
        "528": "group_not_editable",
        "522": "group_full", "523": "group_full", "524": "group_full", "525": "group_full",
    }.get(code or "", "write_failed")
    if isinstance(err, SophosNotFoundError):
        key = "group_not_found"
    raise HomeAssistantError(
        translation_domain=DOMAIN, translation_key=key,
        translation_placeholders={"name": name, "error": str(err)},
    ) from err


async def _set_url(hass: HomeAssistant, call: ServiceCall, present: bool) -> ServiceResponse:
    client = _client(hass, call)
    group = call.data[ATTR_URL_GROUP]
    try:
        changed = await client.set_url_in_group(group, call.data[ATTR_URL], present)
    except SophosError as err:
        _raise(err, group)
    return {"changed": changed}


async def _block_device(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    client = _client(hass, call)
    group = call.data[ATTR_HOST_GROUP]
    ip = call.data[ATTR_IP_ADDRESS]
    try:
        host = await client.ensure_ip_host(ip, call.data.get(ATTR_HOST_NAME) or f"HA {ip}")
        changed = await client.set_host_in_group(group, host, True)
    except SophosError as err:
        _raise(err, group)
    return {"changed": changed, "host": host}


async def _unblock_device(hass: HomeAssistant, call: ServiceCall) -> ServiceResponse:
    client = _client(hass, call)
    group = call.data[ATTR_HOST_GROUP]
    try:
        if (host := await client.find_ip_host(call.data[ATTR_IP_ADDRESS])) is None:
            return {"changed": False}
        changed = await client.set_host_in_group(group, host, False)
    except SophosError as err:
        _raise(err, group)
    return {"changed": changed, "host": host}


def async_setup_services(hass: HomeAssistant) -> None:
    """Register the actions (once, in async_setup)."""

    async def block_url(call: ServiceCall) -> ServiceResponse:
        return await _set_url(hass, call, True)

    async def unblock_url(call: ServiceCall) -> ServiceResponse:
        return await _set_url(hass, call, False)

    async def block_device(call: ServiceCall) -> ServiceResponse:
        return await _block_device(hass, call)

    async def unblock_device(call: ServiceCall) -> ServiceResponse:
        return await _unblock_device(hass, call)

    for service, handler, schema in (
        (SERVICE_BLOCK_URL, block_url, URL_SCHEMA),
        (SERVICE_UNBLOCK_URL, unblock_url, URL_SCHEMA),
        (SERVICE_BLOCK_DEVICE, block_device, BLOCK_DEVICE_SCHEMA),
        (SERVICE_UNBLOCK_DEVICE, unblock_device, UNBLOCK_DEVICE_SCHEMA),
    ):
        hass.services.async_register(
            DOMAIN, service, handler, schema=schema, supports_response=SupportsResponse.OPTIONAL
        )
