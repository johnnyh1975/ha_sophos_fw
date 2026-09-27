"""Constants for the Sophos Firewall integration.

All magic strings, OIDs, XML tags, and tunable defaults live here.
Never import from other integration modules in this file to avoid circular imports.
"""
from __future__ import annotations

import re
from enum import StrEnum
from typing import Final

from homeassistant.const import Platform

# ── Integration identity ──────────────────────────────────────────────────────
DOMAIN: Final = "sophos_firewall"
PLATFORMS: Final = [Platform.BINARY_SENSOR, Platform.BUTTON, Platform.SENSOR, Platform.SWITCH]
MANUFACTURER: Final = "Sophos"

# ── Config entry ──────────────────────────────────────────────────────────────
# Version 2 (v1.1.0): entity unique_ids are "{entry_id}_{suffix}" (were
# "{host}_{port}_{suffix}"), and everything except the connection settings
# lives in entry.options (was entry.data). See async_migrate_entry().
CONFIG_ENTRY_VERSION = 2

# CONF_HOST, CONF_PORT, CONF_USERNAME, CONF_PASSWORD come from homeassistant.const.
CONF_VERIFY_SSL     = "verify_ssl"
CONF_SNMP_ENABLED   = "snmp_enabled"
CONF_SNMP_COMMUNITY = "snmp_community"
CONF_SNMP_VERSION   = "snmp_version"
CONF_WRITE_ACCESS   = "write_access"

# Polling tier intervals (seconds)
CONF_INTERVAL_REALTIME  = "interval_realtime"
CONF_INTERVAL_FAST      = "interval_fast"
CONF_INTERVAL_OPERATIVE = "interval_operative"
CONF_INTERVAL_STATIC    = "interval_static"

# Keys stored by v1.0.x that no longer have any effect (removed by migration)
OBSOLETE_KEYS: Final = frozenset({
    CONF_SNMP_VERSION, "xml_interval", "snmp_interval", "interval_once",
    "poll_xml_zones", "poll_xml_admin", "poll_snmp_device",
})

# Which data sources to poll (can be disabled individually)
CONF_POLL_XML_INTERFACES = "poll_xml_interfaces"
CONF_POLL_XML_FW_RULES   = "poll_xml_fw_rules"
CONF_POLL_XML_DHCP       = "poll_xml_dhcp"
CONF_POLL_XML_WEBFILTER  = "poll_xml_webfilter"
CONF_POLL_XML_BACKUP     = "poll_xml_backup"
CONF_POLL_SNMP_STATS     = "poll_snmp_stats"
CONF_POLL_SNMP_SERVICES  = "poll_snmp_services"
CONF_POLL_SNMP_TUNNELS   = "poll_snmp_tunnels"
CONF_POLL_SNMP_HEALTH    = "poll_snmp_health"
CONF_POLL_SNMP_HA        = "poll_snmp_ha"
CONF_POLL_SNMP_LICENSES  = "poll_snmp_licenses"
CONF_POLL_SNMP_TRAFFIC   = "poll_snmp_traffic"

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_PORT           = 4444
DEFAULT_USERNAME       = "admin"
DEFAULT_SNMP_PORT      = 161
DEFAULT_SNMP_COMMUNITY = "public"
DEFAULT_TIMEOUT        = 20   # seconds for one XML API request

# SNMP timing. puresnmp retries each PDU itself; the per-operation budget
# bounds a whole GET or table walk, so a dead agent can never stall a poll
# cycle for more than SNMP_OPERATION_BUDGET seconds.
# The SFOS agent answers requests one after another: a burst of parallel
# requests (every endpoint at startup) made the last ones time out after 2 s
# in the first 1.1 beta. Hence few requests in flight and a generous timeout.
SNMP_TIMEOUT           = 5    # seconds per UDP attempt
SNMP_RETRIES           = 2    # attempts per PDU
SNMP_MAX_CONCURRENT    = 2    # requests in flight per firewall
SNMP_OPERATION_BUDGET  = 20   # seconds for one complete GET or walk (incl. queueing)
SNMP_BULK_SIZE         = 25   # max-repetitions per GETBULK

# Polling tier defaults (seconds)
DEFAULT_INTERVAL_REALTIME  = 30
DEFAULT_INTERVAL_FAST      = 120
DEFAULT_INTERVAL_OPERATIVE = 600
DEFAULT_INTERVAL_STATIC    = 1800

# Default polling toggles
DEFAULT_POLL_XML_INTERFACES = True
DEFAULT_POLL_XML_FW_RULES   = True
DEFAULT_POLL_XML_DHCP       = True
DEFAULT_POLL_XML_WEBFILTER  = True
DEFAULT_POLL_XML_BACKUP     = False  # only relevant for the backup-frequency sensor
DEFAULT_POLL_SNMP_STATS     = True
DEFAULT_POLL_SNMP_SERVICES  = True
DEFAULT_POLL_SNMP_TUNNELS   = True
DEFAULT_POLL_SNMP_HEALTH    = True
DEFAULT_POLL_SNMP_HA        = False  # HA cluster — opt-in
DEFAULT_POLL_SNMP_LICENSES  = True
DEFAULT_POLL_SNMP_TRAFFIC   = True


class Tier(StrEnum):
    """Polling tier. Each endpoint belongs to exactly one tier."""

    REALTIME  = "realtime"
    FAST      = "fast"
    OPERATIVE = "operative"
    STATIC    = "static"


TIER_INTERVAL_KEYS: Final[dict[Tier, tuple[str, int]]] = {
    Tier.REALTIME:  (CONF_INTERVAL_REALTIME,  DEFAULT_INTERVAL_REALTIME),
    Tier.FAST:      (CONF_INTERVAL_FAST,      DEFAULT_INTERVAL_FAST),
    Tier.OPERATIVE: (CONF_INTERVAL_OPERATIVE, DEFAULT_INTERVAL_OPERATIVE),
    Tier.STATIC:    (CONF_INTERVAL_STATIC,    DEFAULT_INTERVAL_STATIC),
}

# ── Coordinator endpoint keys (= field names of XmlData / SnmpData) ───────────
EP_INTERFACES     = "interfaces"
EP_FIREWALL_RULES = "firewall_rules"
EP_WEB_FILTER     = "web_filter_policies"
EP_DHCP_SERVERS   = "dhcp_servers"
EP_BACKUP         = "backup"
EP_ADMIN          = "admin"
EP_DEVICE         = "device"
EP_STATS          = "stats"
EP_SERVICES       = "services"
EP_LICENSES       = "licenses"
EP_TUNNELS        = "tunnels"
EP_HEALTH         = "health"
EP_HA             = "ha"
EP_CPU            = "cpu"
EP_TRAFFIC        = "traffic"

# ── XML API ───────────────────────────────────────────────────────────────────
XML_API_PATH = "/webconsole/APIController"
# One request at a time. Measured on a real firewall (SFOS 22): it answers
# XML requests strictly one after another, 5-10 s each. With two in flight
# the second one waited on the firewall while its 20 s timeout was already
# running — the admin settings timed out that way (20.03 s in a debug log,
# timeouts in the first 1.1 field test). Sequential requests take no longer.
XML_MAX_CONCURRENT_REQUESTS = 1
XML_TAG_INTERFACE      = "Interface"
XML_TAG_FIREWALL_RULE  = "FirewallRule"
XML_TAG_WEB_FILTER     = "WebFilterPolicy"
XML_TAG_DHCP_SERVER    = "DHCPServer"
XML_TAG_BACKUP         = "BackupRestore"
XML_TAG_ADMIN          = "AdminSettings"

# ── SNMP OIDs (Sophos MIB: enterprises.2604.5.1.x) ───────────────────────────
_BASE = "1.3.6.1.4.1.2604.5.1"

# sfosXGDeviceInfo (.1.x)
OID_DEVICE_NAME        = f"{_BASE}.1.1.0"   # hostname
OID_DEVICE_TYPE        = f"{_BASE}.1.2.0"   # model
OID_DEVICE_FW_VERSION  = f"{_BASE}.1.3.0"   # firmware version
OID_DEVICE_APP_KEY     = f"{_BASE}.1.4.0"   # serial number (appliance key)
OID_WEBCAT_VERSION     = f"{_BASE}.1.5.0"   # web category DB version
OID_IPS_VERSION        = f"{_BASE}.1.6.0"   # IPS signature version

# sfosXGDeviceStats (.2.x)
OID_CURRENT_DATE       = f"{_BASE}.2.1.0"   # system time (string)
OID_UPTIME             = f"{_BASE}.2.2.0"   # uptime (TimeTicks)
OID_DISK_CAPACITY      = f"{_BASE}.2.4.1.0" # disk total (MB)
OID_DISK_PERCENT       = f"{_BASE}.2.4.2.0" # disk used (%)
OID_MEMORY_CAPACITY    = f"{_BASE}.2.5.1.0" # RAM total (MB)
OID_MEMORY_PERCENT     = f"{_BASE}.2.5.2.0" # RAM used (%)
OID_SWAP_CAPACITY      = f"{_BASE}.2.5.3.0" # swap total (MB)
OID_SWAP_PERCENT       = f"{_BASE}.2.5.4.0" # swap used (%)
OID_LIVE_USERS         = f"{_BASE}.2.6.0"   # captive-portal users
OID_HTTP_HITS          = f"{_BASE}.2.7.0"   # HTTP hits (Counter64)
OID_FTP_HITS           = f"{_BASE}.2.8.0"   # FTP hits (Counter64)
OID_POP3_HITS          = f"{_BASE}.2.9.1.0" # POP3 hits
OID_IMAP_HITS          = f"{_BASE}.2.9.2.0" # IMAP hits
OID_SMTP_HITS          = f"{_BASE}.2.9.3.0" # SMTP hits

# sfosXGServiceStatus (.3.x)
# ServiceStatsType: 0=untouched, 1=stopped, 2=initializing,
#                   3=running, 4=exiting, 5=dead, 6=frozen, 7=unregistered
SERVICE_STATES: Final = (
    "untouched", "stopped", "initializing", "running", "exiting", "dead", "frozen",
    "unregistered",
)  # index = ServiceStatsType code
# Mapping: OID → (key, friendly_name). Names are English (the {name} of the
# per-service entities and the summary attributes; up to v1.1 partly German).
SERVICE_OIDS: Final[dict[str, tuple[str, str]]] = {
    f"{_BASE}.3.1.0":  ("pop3",      "POP3"),
    f"{_BASE}.3.2.0":  ("imap",      "IMAP"),
    f"{_BASE}.3.3.0":  ("smtp",      "SMTP"),
    f"{_BASE}.3.4.0":  ("ftp",       "FTP"),
    f"{_BASE}.3.5.0":  ("http",      "HTTP-Proxy"),
    f"{_BASE}.3.6.0":  ("av",        "Antivirus"),
    f"{_BASE}.3.7.0":  ("antispam",  "Anti-Spam"),
    f"{_BASE}.3.8.0":  ("dns",       "DNS"),
    f"{_BASE}.3.9.0":  ("ha_svc",    "HA-Service"),
    f"{_BASE}.3.10.0": ("ips",       "IPS"),
    f"{_BASE}.3.11.0": ("apache",    "Apache"),
    f"{_BASE}.3.12.0": ("ntp",       "NTP"),
    f"{_BASE}.3.13.0": ("tomcat",    "Tomcat"),
    f"{_BASE}.3.14.0": ("ssl_vpn",   "SSL-VPN"),
    f"{_BASE}.3.15.0": ("ipsec_vpn", "IPSec-VPN"),
    f"{_BASE}.3.16.0": ("database",  "Database"),
    f"{_BASE}.3.17.0": ("network",   "Network"),
    f"{_BASE}.3.18.0": ("garner",    "Garner"),
    f"{_BASE}.3.19.0": ("drouting",  "Dynamic Routing"),
    f"{_BASE}.3.20.0": ("sshd",      "SSH"),
    f"{_BASE}.3.21.0": ("dgd",       "DGD"),
}
SERVICE_RUNNING_STATE = 3  # ServiceStatsType.running

# sfosXGHAStats (.4.x)
# HaStatusType: 0=disabled, 1=enabled
# HaState: 0=notapplicable, 1=auxiliary, 2=standAlone, 3=primary, 4=faulty, 5=ready
OID_HA_STATUS          = f"{_BASE}.4.1.0"
OID_HA_CURRENT_STATE   = f"{_BASE}.4.4.0"
OID_HA_PEER_STATE      = f"{_BASE}.4.5.0"

# sfosXGLicenseDetails (.5.x)
# SubscriptionStatusType: 0=none, 1=evaluating, 2=notsubscribed, 3=subscribed,
#                         4=expired, 5=deactivated
LICENSE_STATES: Final = (
    "none", "evaluating", "not_subscribed", "subscribed", "expired", "deactivated",
)  # index = SubscriptionStatusType code
# Mapping: status_oid → (key, friendly_name, expiry_oid)
LICENSE_OIDS: Final[dict[str, tuple[str, str, str]]] = {
    f"{_BASE}.5.1.1.0": ("base_fw",      "Base Firewall",         f"{_BASE}.5.1.2.0"),
    f"{_BASE}.5.2.1.0": ("net_protect",  "Network Protection",    f"{_BASE}.5.2.2.0"),
    f"{_BASE}.5.3.1.0": ("web_protect",  "Web Protection",        f"{_BASE}.5.3.2.0"),
    f"{_BASE}.5.4.1.0": ("mail_protect", "Email Protection",      f"{_BASE}.5.4.2.0"),
    f"{_BASE}.5.5.1.0": ("web_server",   "Web Server Protection", f"{_BASE}.5.5.2.0"),
    f"{_BASE}.5.6.1.0": ("sandstorm",    "Zero-Day Protection",   f"{_BASE}.5.6.2.0"),
    f"{_BASE}.5.7.1.0": ("enh_support",  "Enhanced Support",      f"{_BASE}.5.7.2.0"),
    f"{_BASE}.5.8.1.0": ("enh_plus",     "Enhanced Plus Support", f"{_BASE}.5.8.2.0"),
    f"{_BASE}.5.9.1.0": ("central_orch", "Central Orchestration", f"{_BASE}.5.9.2.0"),
}
LICENSE_OK_STATES = frozenset({1, 3})  # evaluating or subscribed

# sfosXGTunnelInfo (.6) → sfosVPNInfo (.6.1)
#   .6.1.1  sfosIPSecVPNConnInfo    → sfosIPSecVpnTunnelTable (.6.1.1.1)  ← live tunnels
#   .6.1.2  sfosIPSecVPNPolicyInfo  → sfosIPSecVpnPolicyTable (.6.1.2.1)  ← IPsec policies
# Up to v1.0.2 this walked .6.1.2.1 (the POLICY table) by mistake — every
# tunnel sensor showed policy names with conn_status -1 (GitHub issue #18).
# Source: SFOS-FIREWALL-MIB.
OID_VPN_TABLE      = f"{_BASE}.6.1.1.1"  # sfosIPSecVpnTunnelTable
VPN_COL_NAME       = "2"   # sfosIPSecVpnConnName
VPN_COL_TUNNELS    = "8"   # sfosIPSecVpnActiveTunnel — despite the name, the MIB
                           # defines it as "Count of total tunnels configured"
VPN_COL_STATUS     = "9"   # sfosIPSecVpnConnStatus
VPN_COL_ACTIVATED  = "10"  # sfosIPSecVpnActivated

# IPSecVPNConnectionStatus
VPN_STATUS_INACTIVE         = 0
VPN_STATUS_ACTIVE           = 1
VPN_STATUS_PARTIALLY_ACTIVE = 2  # some, not all, of the connection's SAs are up
# IPSecVPNActivationStatus: 0=inactive, 1=active
VPN_ACTIVATED = 1

# sfosXGSystemHealth (.9.x)
OID_NPU_TEMPERATURE    = f"{_BASE}.9.1.0"    # tenths of °C
OID_CPU_TEMPERATURE    = f"{_BASE}.9.2.0"    # tenths of °C
OID_FAN_TABLE          = f"{_BASE}.9.3"      # fan table
OID_PSU_TABLE          = f"{_BASE}.9.4"      # power-supply table
# Both tables: rows are <table>.1.<column>.<index>; column 1 is the index,
# column 2 the value (fan: speed in RPM; PSU: PowerSupplyStatusType).
HEALTH_COL_VALUE = "2"
# PowerSupplyStatusType: 1=up, 2=down
PSU_UP = 1

# ── Standard MIBs (Net-SNMP agent of SFOS) ────────────────────────────────────
# Not part of SFOS-FIREWALL-MIB. Sophos refers to hrProcessorLoad for the CPU
# load; whether an agent serves these tables is only known at runtime, so the
# entities are created from what the agent returns (nothing if a table is absent).
#
# HOST-RESOURCES-MIB::hrProcessorTable — one row per processor (core);
# hrProcessorLoad = average load over the last minute, percent.
OID_HR_PROCESSOR_TABLE = "1.3.6.1.2.1.25.3.3"
HR_COL_PROCESSOR_LOAD  = "2"
# IF-MIB::ifXTable — ifName and the 64-bit octet counters (a 32-bit counter
# wraps within ~34 s at 1 Gbit/s, i.e. between two polls).
OID_IFX_TABLE    = "1.3.6.1.2.1.31.1.1"
IFX_COL_NAME     = "1"   # ifName
IFX_COL_HC_IN    = "6"   # ifHCInOctets (Counter64)
IFX_COL_HC_OUT   = "10"  # ifHCOutOctets (Counter64)
# Interfaces without traffic entities: loopback and kernel/SFOS helper
# devices, almost all without traffic. Seen on a real SFVH (SFOS 22): dummy0,
# ipsec0, sit0, ip6tnl0, gre0, gretap0, erspan0, ifb0 and the QoS devices
# dfq/spq. Not seen there but created the same way by the Linux tunnel and
# queueing modules: tunl0, ip_vti0, ip6_vti0, ip6gre0, teql0. Ports, VLANs
# (PortA.30), bridges, wireless networks and route-based VPN interfaces
# (xfrm…) are kept.
INTERNAL_INTERFACE_RE: Final = re.compile(
    r"^(lo|dummy\d+|ipsec\d+|sit\d+|ip6tnl\d+|gre\d+|gretap\d+|erspan\d+|ifb\d+"
    r"|tunl\d+|ip_vti\d+|ip6_vti\d+|ip6gre\d+|teql\d+|dfq|spq)$"
)

# Successful reads a list (or the hardware sensors) must stay empty before
# the integration acts on it: removes entities, or treats the firewall as a
# virtual appliance. One empty answer can be a firewall that is still booting.
EMPTY_CONFIRMATIONS = 3
