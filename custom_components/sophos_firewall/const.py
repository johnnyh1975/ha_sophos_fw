"""Constants for the Sophos Firewall integration.

All magic strings, OIDs, XML tags, and tunable defaults live here.
Never import from other integration modules in this file to avoid circular imports.
"""
from __future__ import annotations

# ── Integration identity ──────────────────────────────────────────────────────
DOMAIN = "sophos_firewall"
PLATFORMS = ["binary_sensor", "button", "sensor", "switch"]

# ── Config entry keys ─────────────────────────────────────────────────────────
# Note: CONF_HOST, CONF_PORT, CONF_USERNAME, CONF_PASSWORD are imported
# from homeassistant.const — do not redefine them here.
CONF_VERIFY_SSL = "verify_ssl"
CONF_SNMP_ENABLED = "snmp_enabled"
CONF_SNMP_COMMUNITY = "snmp_community"
CONF_SNMP_VERSION = "snmp_version"
CONF_WRITE_ACCESS = "write_access"
CONF_XML_INTERVAL = "xml_interval"
CONF_SNMP_INTERVAL = "snmp_interval"

# Polling tier intervals (seconds)
CONF_INTERVAL_REALTIME  = "interval_realtime"   # XML: interfaces; SNMP: stats, services
CONF_INTERVAL_FAST      = "interval_fast"        # SNMP: VPN-tunnels, HA-status
CONF_INTERVAL_OPERATIVE = "interval_operative"   # XML: firewall rules; SNMP: health
CONF_INTERVAL_STATIC    = "interval_static"      # XML: DHCP+leases, webfilter, backup
CONF_INTERVAL_ONCE      = "interval_once"        # XML: zones, admin; SNMP: device-info

# Which data sources to poll (can be disabled individually)
CONF_POLL_XML_INTERFACES    = "poll_xml_interfaces"
CONF_POLL_XML_FW_RULES      = "poll_xml_fw_rules"
CONF_POLL_XML_DHCP          = "poll_xml_dhcp"
CONF_POLL_XML_WEBFILTER     = "poll_xml_webfilter"
CONF_POLL_XML_ZONES         = "poll_xml_zones"
CONF_POLL_XML_BACKUP        = "poll_xml_backup"
CONF_POLL_XML_ADMIN         = "poll_xml_admin"
CONF_POLL_SNMP_STATS        = "poll_snmp_stats"
CONF_POLL_SNMP_SERVICES     = "poll_snmp_services"
CONF_POLL_SNMP_TUNNELS      = "poll_snmp_tunnels"
CONF_POLL_SNMP_HEALTH       = "poll_snmp_health"
CONF_POLL_SNMP_HA           = "poll_snmp_ha"
CONF_POLL_SNMP_LICENSES     = "poll_snmp_licenses"
CONF_POLL_SNMP_DEVICE       = "poll_snmp_device"

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_PORT = 4444
DEFAULT_SNMP_PORT = 161
DEFAULT_SNMP_COMMUNITY = "public"
DEFAULT_SNMP_VERSION = "2c"
DEFAULT_XML_INTERVAL  = 30   # seconds — base interval (Echtzeit-Tier)
DEFAULT_SNMP_INTERVAL = 60   # seconds — kept for backwards compat
DEFAULT_TIMEOUT = 20         # seconds for HTTP requests
DEFAULT_SNMP_TIMEOUT = 5     # seconds per SNMP request

# Polling tier defaults (in seconds)
DEFAULT_INTERVAL_REALTIME  = 30     # Interfaces, SNMP-Stats, Services
DEFAULT_INTERVAL_FAST      = 120    # VPN-Tunnel, HA-Status
DEFAULT_INTERVAL_OPERATIVE = 600    # Firewall-Rules, SNMP-Health
DEFAULT_INTERVAL_STATIC    = 1800   # DHCP+Leases, WebFilter, Backup, Lizenzen
DEFAULT_INTERVAL_ONCE      = 0      # Zones, Admin, SNMP-DeviceInfo (nur beim Start)

# Default polling toggles — all enabled except zone/admin (rarely useful in automations)
DEFAULT_POLL_XML_INTERFACES = True
DEFAULT_POLL_XML_FW_RULES   = True
DEFAULT_POLL_XML_DHCP       = True
DEFAULT_POLL_XML_WEBFILTER  = True
DEFAULT_POLL_XML_ZONES      = False  # rarely changes, not used in automations
DEFAULT_POLL_XML_BACKUP     = False  # only relevant for backup sensor
DEFAULT_POLL_XML_ADMIN      = True   # needed for device_info hostname
DEFAULT_POLL_SNMP_STATS     = True
DEFAULT_POLL_SNMP_SERVICES  = True
DEFAULT_POLL_SNMP_TUNNELS   = True
DEFAULT_POLL_SNMP_HEALTH    = True
DEFAULT_POLL_SNMP_HA        = False  # HA-Cluster Ausnahmefall — manuell aktivieren
DEFAULT_POLL_SNMP_LICENSES  = True
DEFAULT_POLL_SNMP_DEVICE    = True   # needed for device_info model/firmware

# ── Coordinator data keys ─────────────────────────────────────────────────────
# XML API
DATA_INTERFACES = "interfaces"
DATA_ZONES = "zones"
DATA_FIREWALL_RULES = "firewall_rules"
DATA_WEB_FILTER_POLICIES = "web_filter_policies"
DATA_DHCP_SERVERS = "dhcp_servers"
DATA_BACKUP = "backup"
DATA_ADMIN = "admin"
# SNMP
DATA_SNMP_DEVICE = "snmp_device"
DATA_SNMP_STATS = "snmp_stats"
DATA_SNMP_SERVICES = "snmp_services"
DATA_SNMP_LICENSES = "snmp_licenses"
DATA_SNMP_TUNNELS = "snmp_tunnels"
DATA_SNMP_HEALTH = "snmp_health"
DATA_SNMP_HA = "snmp_ha"

# ── XML API tags ──────────────────────────────────────────────────────────────
XML_TAG_INTERFACE = "Interface"
XML_TAG_ZONE = "Zone"
XML_TAG_FIREWALL_RULE = "FirewallRule"
XML_TAG_WEB_FILTER_POLICY = "WebFilterPolicy"
XML_TAG_DHCP_SERVER = "DHCPServer"
XML_TAG_BACKUP = "BackupRestore"
XML_TAG_ADMIN = "AdminSettings"

# ── SNMP OIDs (Sophos MIB: enterprises.2604.5.1.x) ───────────────────────────
# Base: 1.3.6.1.4.1.2604.5.1
_BASE = "1.3.6.1.4.1.2604.5.1"

# sfosXGDeviceInfo (.1.x)
OID_DEVICE_NAME        = f"{_BASE}.1.1.0"   # Hostname
OID_DEVICE_TYPE        = f"{_BASE}.1.2.0"   # Modell
OID_DEVICE_FW_VERSION  = f"{_BASE}.1.3.0"   # Firmware-Version
OID_DEVICE_APP_KEY     = f"{_BASE}.1.4.0"   # Seriennummer
OID_WEBCAT_VERSION     = f"{_BASE}.1.5.0"   # Web-Kategorie-DB-Version
OID_IPS_VERSION        = f"{_BASE}.1.6.0"   # IPS-Signatur-Version

# sfosXGDeviceStats (.2.x)
OID_CURRENT_DATE       = f"{_BASE}.2.1.0"   # Systemzeit (String)
OID_UPTIME             = f"{_BASE}.2.2.0"   # Uptime (Timeticks)
OID_DISK_CAPACITY      = f"{_BASE}.2.4.1.0" # Disk gesamt (MB)
OID_DISK_PERCENT       = f"{_BASE}.2.4.2.0" # Disk genutzt (%)
OID_MEMORY_CAPACITY    = f"{_BASE}.2.5.1.0" # RAM gesamt (MB)
OID_MEMORY_PERCENT     = f"{_BASE}.2.5.2.0" # RAM genutzt (%)
OID_SWAP_CAPACITY      = f"{_BASE}.2.5.3.0" # Swap gesamt (MB)
OID_SWAP_PERCENT       = f"{_BASE}.2.5.4.0" # Swap genutzt (%)
OID_LIVE_USERS         = f"{_BASE}.2.6.0"   # Captive-Portal-User
OID_HTTP_HITS          = f"{_BASE}.2.7.0"   # HTTP-Hits (Counter64)
OID_FTP_HITS           = f"{_BASE}.2.8.0"   # FTP-Hits (Counter64)
OID_POP3_HITS          = f"{_BASE}.2.9.1.0" # POP3-Hits
OID_IMAP_HITS          = f"{_BASE}.2.9.2.0" # IMAP-Hits
OID_SMTP_HITS          = f"{_BASE}.2.9.3.0" # SMTP-Hits

# sfosXGServiceStatus (.3.x)
# ServiceStatsType: 0=untouched, 1=stopped, 2=initializing,
#                   3=running, 4=exiting, 5=dead, 6=frozen, 7=unregistered
OID_SVC_POP3           = f"{_BASE}.3.1.0"
OID_SVC_IMAP           = f"{_BASE}.3.2.0"
OID_SVC_SMTP           = f"{_BASE}.3.3.0"
OID_SVC_FTP            = f"{_BASE}.3.4.0"
OID_SVC_HTTP           = f"{_BASE}.3.5.0"
OID_SVC_AV             = f"{_BASE}.3.6.0"
OID_SVC_AS             = f"{_BASE}.3.7.0"  # Anti-Spam
OID_SVC_DNS            = f"{_BASE}.3.8.0"
OID_SVC_HA             = f"{_BASE}.3.9.0"
OID_SVC_IPS            = f"{_BASE}.3.10.0"
OID_SVC_APACHE         = f"{_BASE}.3.11.0"
OID_SVC_NTP            = f"{_BASE}.3.12.0"
OID_SVC_TOMCAT         = f"{_BASE}.3.13.0"
OID_SVC_SSL_VPN        = f"{_BASE}.3.14.0"
OID_SVC_IPSEC_VPN      = f"{_BASE}.3.15.0"
OID_SVC_DATABASE       = f"{_BASE}.3.16.0"
OID_SVC_NETWORK        = f"{_BASE}.3.17.0"
OID_SVC_GARNER         = f"{_BASE}.3.18.0"
OID_SVC_DROUTING       = f"{_BASE}.3.19.0"
OID_SVC_SSHD           = f"{_BASE}.3.20.0"
OID_SVC_DGD            = f"{_BASE}.3.21.0"

# Mapping: OID → (name, friendly_name)
SERVICE_OIDS: dict[str, tuple[str, str]] = {
    OID_SVC_POP3:      ("pop3",      "POP3"),
    OID_SVC_IMAP:      ("imap",      "IMAP"),
    OID_SVC_SMTP:      ("smtp",      "SMTP"),
    OID_SVC_FTP:       ("ftp",       "FTP"),
    OID_SVC_HTTP:      ("http",      "HTTP-Proxy"),
    OID_SVC_AV:        ("av",        "Antivirus"),
    OID_SVC_AS:        ("antispam",  "Anti-Spam"),
    OID_SVC_DNS:       ("dns",       "DNS"),
    OID_SVC_HA:        ("ha_svc",    "HA-Service"),
    OID_SVC_IPS:       ("ips",       "IPS"),
    OID_SVC_APACHE:    ("apache",    "Apache"),
    OID_SVC_NTP:       ("ntp",       "NTP"),
    OID_SVC_TOMCAT:    ("tomcat",    "Tomcat"),
    OID_SVC_SSL_VPN:   ("ssl_vpn",   "SSL-VPN"),
    OID_SVC_IPSEC_VPN: ("ipsec_vpn", "IPSec-VPN"),
    OID_SVC_DATABASE:  ("database",  "Datenbank"),
    OID_SVC_NETWORK:   ("network",   "Netzwerk"),
    OID_SVC_GARNER:    ("garner",    "Garner"),
    OID_SVC_DROUTING:  ("drouting",  "Dynamic Routing"),
    OID_SVC_SSHD:      ("sshd",      "SSH"),
    OID_SVC_DGD:       ("dgd",       "DGD"),
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
OID_LIC_BASE_FW        = f"{_BASE}.5.1.1.0"   # Basis-Firewall
OID_LIC_BASE_FW_EXP    = f"{_BASE}.5.1.2.0"
OID_LIC_NET_PROTECT    = f"{_BASE}.5.2.1.0"   # Network Protection
OID_LIC_NET_PROTECT_EXP= f"{_BASE}.5.2.2.0"
OID_LIC_WEB_PROTECT    = f"{_BASE}.5.3.1.0"   # Web-Schutz
OID_LIC_WEB_PROTECT_EXP= f"{_BASE}.5.3.2.0"
OID_LIC_MAIL_PROTECT   = f"{_BASE}.5.4.1.0"   # E-Mail-Schutz
OID_LIC_MAIL_PROTECT_EXP= f"{_BASE}.5.4.2.0"
OID_LIC_WEB_SERVER     = f"{_BASE}.5.5.1.0"   # Web Server Protection
OID_LIC_WEB_SERVER_EXP = f"{_BASE}.5.5.2.0"
OID_LIC_SANDSTORM      = f"{_BASE}.5.6.1.0"   # Zero-Day / Sandstorm
OID_LIC_SANDSTORM_EXP  = f"{_BASE}.5.6.2.0"
OID_LIC_ENH_SUPPORT    = f"{_BASE}.5.7.1.0"   # Enhanced Support
OID_LIC_ENH_SUPPORT_EXP= f"{_BASE}.5.7.2.0"
OID_LIC_ENH_PLUS       = f"{_BASE}.5.8.1.0"   # Enhanced Plus Support
OID_LIC_ENH_PLUS_EXP   = f"{_BASE}.5.8.2.0"
OID_LIC_CENTRAL_ORCH   = f"{_BASE}.5.9.1.0"   # Central Orchestration
OID_LIC_CENTRAL_ORCH_EXP= f"{_BASE}.5.9.2.0"

# Mapping: status_oid → (key, friendly_name, expiry_oid)
LICENSE_OIDS: dict[str, tuple[str, str, str]] = {
    OID_LIC_BASE_FW:     ("base_fw",     "Basis-Firewall",         OID_LIC_BASE_FW_EXP),
    OID_LIC_NET_PROTECT: ("net_protect", "Network Protection",     OID_LIC_NET_PROTECT_EXP),
    OID_LIC_WEB_PROTECT: ("web_protect", "Web-Schutz",             OID_LIC_WEB_PROTECT_EXP),
    OID_LIC_MAIL_PROTECT:("mail_protect","E-Mail-Schutz",          OID_LIC_MAIL_PROTECT_EXP),
    OID_LIC_WEB_SERVER:  ("web_server",  "Web Server Protection",  OID_LIC_WEB_SERVER_EXP),
    OID_LIC_SANDSTORM:   ("sandstorm",   "Zero-Day-Schutz",        OID_LIC_SANDSTORM_EXP),
    OID_LIC_ENH_SUPPORT: ("enh_support", "Enhanced Support",       OID_LIC_ENH_SUPPORT_EXP),
    OID_LIC_ENH_PLUS:    ("enh_plus",    "Enhanced Plus Support",  OID_LIC_ENH_PLUS_EXP),
    OID_LIC_CENTRAL_ORCH:("central_orch","Central Orchestration",  OID_LIC_CENTRAL_ORCH_EXP),
}
LICENSE_OK_STATES = {1, 3}   # evaluating or subscribed → OK
LICENSE_PROBLEM_STATES = {2, 4, 5}  # notsubscribed, expired, deactivated → problem

# sfosXGTunnelInfo (.6.1.2.1.1.x) — IPSec VPN Tunnel table
# IPSecVPNConnectionStatus: 0=inactive, 1=active, 2=partially-active
# IPSecVPNActivationStatus: 0=inactive, 1=active
_VPN_TABLE = f"{_BASE}.6.1.2.1.1"
OID_VPN_TABLE_NAME     = f"{_VPN_TABLE}.2"   # connection name (index appended)
OID_VPN_TABLE_STATUS   = f"{_VPN_TABLE}.9"   # connection status
OID_VPN_TABLE_ACTIVATED= f"{_VPN_TABLE}.10"  # activation status
OID_VPN_WALK_BASE      = f"{_BASE}.6.1.2.1"  # walk from here for tunnel table

# sfosXGSystemHealth (.9.x)
OID_NPU_TEMPERATURE    = f"{_BASE}.9.1.0"    # tenths of °C
OID_CPU_TEMPERATURE    = f"{_BASE}.9.2.0"    # tenths of °C
OID_FAN_TABLE_WALK     = f"{_BASE}.9.3"      # walk for fan speeds
OID_PSU_TABLE_WALK     = f"{_BASE}.9.4"      # walk for PSU status
# PowerSupplyStatusType: 1=up, 2=down
PSU_UP = 1

# ── Value helpers ─────────────────────────────────────────────────────────────
HA_STATE_VALUES = {
    0: "notapplicable",
    1: "auxiliary",
    2: "standalone",
    3: "primary",
    4: "faulty",
    5: "ready",
}
