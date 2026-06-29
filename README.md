# Sophos Firewall — Home Assistant Integration

[![HACS Custom](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![Version](https://img.shields.io/badge/Version-1.0.2-green)](https://github.com/hacs/integration)
[![HA Version](https://img.shields.io/badge/HA-2024.9%2B-blue)](https://www.home-assistant.io)
[![Quality Scale](https://img.shields.io/badge/Quality_Scale-Gold-gold)](https://www.home-assistant.io/docs/quality_scale/)

Home Assistant Custom Integration für Sophos Firewall (SFOS 20.x / 22.x). Verbindet HA mit der Firewall über XML API und SNMP — ohne Cloud, ohne Drittanbieter.

---

## Features

| Kategorie | Entities |
|---|---|
| **Interfaces** | PortA, PortB — Verbunden/Getrennt, Zone, IP-Assignment |
| **Firewall-Rules** | Schalter (mit Schreibzugriff) oder Nur-Lese-Sensor — im Konfigurationsbereich |
| **DHCP** | Kombinierter Sensor: Server-Status + Lease-Anzahl + vollständige Lease-Liste als Attribut |
| **System** | RAM, Disk, Swap (%), Uptime (`"77 d 14 h"`), Backup-Häufigkeit |
| **Verbindungen** | HTTP-, SMTP-, IMAP-, POP3-Verbindungen, FTP-Hits, Captive-Portal-User |
| **Dienste** | Aggregations-Sensor: `"19 / 21 running"` — `running`/`stopped`-Listen als Attribut |
| **VPN-Tunnel** | IPSec-Tunnel mit Verbindungsstatus |
| **Hochverfügbarkeit** | HA-Cluster-Status (aktiv/inaktiv), Rolle dieses Knotens und des Peers (primär/sekundär/standalone/…) |
| **Lizenzen** | Aggregations-Sensor: `"8 / 9 OK"` — nächstes Ablaufdatum, Details als Attribut |
| **Sicherheit** | Web-Filter Standardaktion, IPS-Signaturversion, Webcat-Version |
| **Hardware-Health** | CPU/NPU-Temperatur, Lüfter-RPM, Netzteil-Status (nur physische Appliances) |
| **Steuerung** | Backup auslösen (Button), Firewall-Rules und Web-Filter schalten |

### Konfigurationsbereich (EntityCategory.CONFIG)

Firewall-Rules und Web-Filter-Policies erscheinen im Konfigurationsbereich der Geräte-Seite — nicht in der Standardansicht. Sie sind weiterhin voll schaltbar und für Automationen nutzbar.

---

## Voraussetzungen

- Home Assistant 2024.9+
- Sophos Firewall SFOS 20.x oder 22.x
- Python 3.12+ (puresnmp 2.x, pysnmp ist nicht kompatibel)
- API-Zugang: **Netzwerk → Administration → Geräte-Zugang → HTTPS-Admin aktivieren**
- Optional SNMP: **System → Administration → SNMP → Community-String konfigurieren**

---

## Installation

### Via HACS (empfohlen)

1. HACS → Integrationen → ⋮ → Benutzerdefinierte Repositories
2. URL: `https://github.com/<dein-repo>/sophos_firewall`, Kategorie: Integration
3. Integration suchen: „Sophos Firewall" → Installieren
4. HA neu starten

### Manuell

```bash
cp -r custom_components/sophos_firewall \
  /config/custom_components/sophos_firewall
```

HA neu starten.

---

## Einrichtung

**Einstellungen → Geräte & Dienste → Integration hinzufügen → „Sophos Firewall"**

Der Setup-Assistent führt durch 4 Schritte:

**Schritt 1 — Verbindung:** Host/IP, API-Port (Standard: 4444), Benutzername, Passwort, SSL-Verifizierung

**Schritt 2 — SNMP (optional):** Aktiviere SNMP für Systemmetriken, Dienste, VPN-Tunnel und Lizenzen. Community-String und SNMP-Version (1 oder 2c) konfigurieren.

**Schritt 3 — Schreibzugriff (optional):** Erlaubt das Schalten von Firewall-Rules und Web-Filter-Policies aus HA. Mit Schreibzugriff: Switches. Ohne: Nur-Lese-Sensoren.

**Schritt 4 — Abfrage-Konfiguration:** Polling-Intervalle und aktive Endpunkte — gruppiert nach Tier. Alle Standardwerte sind optimal voreingestellt.

---

## Abfrage-Intervalle (Tiered Polling)

| Tier | Standard | XML-Endpunkte | SNMP-Endpunkte |
|---|---|---|---|
| ⚡ Echtzeit | 30s | Interfaces | Stats, Dienste |
| 🔄 Schnell | 120s | — | VPN-Tunnel, HA-Status |
| 🔧 Operativ | 600s | Firewall-Rules | System-Health |
| 🗄 Statisch | 1800s | DHCP, Web-Filter, Backup | Lizenzen |
| 🔁 Einmalig | beim Start | Admin-Settings | Geräteinformationen |

Schreiboperationen (Schalter, Button) lösen immer sofort einen Refresh des betroffenen Tiers aus.

---

## Technische Architektur

### Datenquellen

**XML API** (Port 4444, HTTPS): Interfaces, Firewall-Rules, DHCP-Server + StaticLeases, Web-Filter, Backup, Admin-Settings.

**SNMP** (Port 161, UDP, puresnmp 2.x): System-Statistiken, Dienste (21), VPN-Tunnel, Lizenzen (9 Module), Hardware-Health, Geräteinfo (Modell, Firmware, IPS-Version, Webcat-Version).

OID-Basis: `1.3.6.1.4.1.2604.5.1` (Sophos proprietäre MIB, SFOS 22.x, getestet auf APIVersion 2200.1)

### Session-Management

Persistente `aiohttp.TCPConnector`-Session mit `force_close=True` und `asyncio.Semaphore(2)`. Verhindert Timeouts durch Server-seitige Keep-Alive-Trennung und begrenzt parallele Requests auf 2.

### SNMP-Besonderheiten

`puresnmp 2.x` statt pysnmp (auf Python 3.12+ inkompatibel). Security-Plugin-Discovery wird einmalig beim Start im Executor-Thread ausgeführt und gecacht — kein Blocking-I/O im HA Event Loop.

### VM-Erkennung (SFVH)

Auf virtuellen Appliances sind Temperatur- und Lüfter-OIDs nicht verfügbar. Die Integration erkennt dies nach dem ersten Health-Fetch automatisch und deaktiviert das Hardware-Health-Polling dauerhaft.

### Multi-Firewall-Support

Entity-IDs basieren auf dem Firewall-Hostnamen — kollisionsfrei bei mehreren Instanzen:

```
sensor.5heynexg_system_dienste
sensor.buero_fw_system_dienste   ← zweite Firewall, kein Konflikt
```

---

## DHCP Lease-Sensor

Pro DHCP-Server ein kombinierter Sensor:

```
Netz · DHCP Main_DHCP    →   In Betrieb · 3 Leases
Netz · DHCP Guest VLAN   →   In Betrieb · 0 Leases
Netz · DHCP DMZ          →   Außer Betrieb
```

Vollständige Lease-Liste im Attribut — direkt in Automationen nutzbar:

```yaml
{{ state_attr('sensor.5heynexg_dhcp_leases_main_dhcp', 'leases')
   | selectattr('MACAddress', 'eq', 'aa:bb:cc:dd:ee:ff')
   | map(attribute='IPAddress') | first }}
```

---

## Dienste-Aggregations-Sensor

Statt 21 einzelner Binary Sensors ein Sensor mit vollständiger Übersicht:

```
System · Dienste    →   19 / 21 running
Attribute:
  running: [Antivirus, DNS, HTTP-Proxy, IPS, ...]
  stopped: [Anti-Spam, HA-Service]
```

Für Automationen:

```yaml
{{ 'Anti-Spam' in state_attr('sensor.5heynexg_system_dienste', 'stopped') }}
```

---

## Automations-Beispiele

**Benachrichtigung wenn Lizenz abläuft:**
```yaml
trigger:
  - platform: template
    value_template: >
      {{ state_attr('sensor.5heynexg_sicherheit_lizenzen', 'problem') | length > 0 }}
action:
  - service: notify.mobile_app
    data:
      message: >
        Sophos Lizenz-Problem:
        {{ state_attr('sensor.5heynexg_sicherheit_lizenzen', 'problem') | join(', ') }}
```

**Firewall-Rule bei Heimkehr aktivieren:**
```yaml
trigger:
  - platform: state
    entity_id: person.jean_christoph
    to: home
action:
  - service: switch.turn_on
    target:
      entity_id: switch.5heynexg_rule_homeautomation_to
```

---

## Advanced Guides

| Guide | Description |
|---|---|
| [Top-25 Blocked Connections Dashboard](docs/top25_blocked_connections.md) | Build a live "Top 25 blocked source IPs" card using Sophos syslog + HACS Syslog Receiver + pyscript — no changes to this integration required |

---

## Kompatibilität

| Gerät / Version | Status | Getestet mit |
|---|---|---|
| SFVH (Virtual Appliance) | ✅ vollständig | KV01, SFOS 22.0.0 GA-Build411 |
| XGS-Serie (Hardware) | ✅ unterstützt | Hardware-Health aktiv |
| SFOS 20.x | ✅ unterstützt | API-kompatibel |
| SFOS 22.x | ✅ getestet | APIVersion 2200.1 |
| HA 2024.9+ | ✅ erforderlich | Sections API im Config Flow |

---

## Troubleshooting

**Alle Entitäten zeigen „Unbekannt" nach Start**
→ Erster Fetch dauert 30–45s. Nach Reload kurz abwarten.

**SNMP-Sensoren bleiben auf „Unbekannt"**
→ Community String prüfen: System → Administration → SNMP

**„Cannot connect" beim Setup**
→ API-Zugang prüfen: Netzwerk → Administration → Geräte-Zugang → HTTPS-Admin aktivieren

**Temperatur-Sensoren fehlen**
→ Normal auf SFVH (virtuelle Appliance). Automatisch erkannt — kein Fehler.

**Blocking I/O im HA Log**
→ Nur beim ersten Start nach Installation. Bei Persistenz: HA neu starten.

---

## Changelog

| Version | Änderungen |
|---|---|
| **v1.0.2** | **Neue Entities:** High-Availability-Cluster (Issue von adi-debug99) — `SophosHAEnabledSensor`, `SophosHAStateSensor`, `SophosHAPeerStateSensor` (Rollen via ENUM, lokalisiert); Netzteil-Status (`SophosPSUSensor`, nur physische Appliances); IMAP- und POP3-Verbindungssensoren. **Bugfixes (aus Code-Review):** `trigger_backup()` prüft jetzt den Response-Status — fehlgeschlagene Backups werden nicht mehr still verschluckt, sondern als sichtbarer Fehler gemeldet; `RestoreEntity` tatsächlich implementiert (Switches/Sensoren zeigen letzten State nach Neustart statt `unavailable`); Response-Level-Status-Codes 532/534/535 (API deaktiviert / IP gesperrt / Auth) werden erkannt statt als leere Antwort durchzurutschen; optimistischer Switch-State (sofortiges UI-Feedback, Revert bei Fehler); `_get_tag` überspringt fehlerhafte Einzel-Records statt die ganze Liste zu verwerfen; toter Code und ungenutzte Importe entfernt. **Hardening:** zentrale `field_str()`-Absicherung gegen fehlerhafte XML-Feldwerte (verhindert Plattform-Absturz bei `None`/verschachtelten Werten); robustes OID-Parsing in der Health-Abfrage; exception-tolerantes Schließen der HTTP-Session; Schutz gegen Busy-Loop bei ungültigem Poll-Intervall; Thread-Lock für den SNMP-Plugin-Patch bei parallelem Multi-Firewall-Setup. **Tests:** von ~120 auf 164 erweitert, komplette Suite läuft ohne Deselects. |
| **v1.0.1** | Bugfix (Issue von taracraft): SNMP-Connectivity-Test in Config-Flow und Options-Flow schlug *immer* mit "snmp_cannot_connect" fehl, unabhängig von echten Credentials/Erreichbarkeit — `preload()` wurde nie vor `test_connection()` aufgerufen, der resultierende `RuntimeError` wurde von `_get()`s pauschalem Exception-Handler verschluckt. Fix: `preload()` jetzt korrekt aufgerufen; `RuntimeError` aus `_get_client()` wird in `_get`/`_multiget`/`_walk` separat als `WARNING` geloggt statt mit normalen Timeouts auf `DEBUG` vermischt. Zusätzlich beim Testen entdeckt und behoben: `SophosUptimeSensor` zeigte falsche Minutenzahl bei Uptimes <24h (z.B. "3 h 205 min" statt "3 h 25 min"). Test-Suite erstmals vollständig mit pytest ausgeführt statt nur syntaxgeprüft — dabei zwei veraltete Test-Erwartungen korrigiert. |
| **v1.0.0** | Quality Scale Gold vollständig: `exception-translations` (alle Exceptions mit `translation_key`/`translation_domain`), `strict-typing` (`SophosData` TypedDict, `DataUpdateCoordinator[SophosData]`). Vollständige Config-Flow-Tests: `test_config_flow.py` neu (user/snmp/write_access/polling/reauth/reconfigure inkl. aller Error-Paths). DHCP-Sensor-Tests auf ENUM-Pattern angepasst. |
| **v0.10.0** | Bugfix: `async_step_reauth()` implementiert — HA zeigt jetzt UI-Dialog bei Auth-Fehlern statt `UnknownStep`-Crash. Tier-Timestamps werden nach Re-Login zurückgesetzt. SNMP-Fehler-Handling per-Tier (ein fehlgeschlagenes OID bricht nicht mehr alle anderen Tiers ab). Stale-Entity-Cleanup für Interfaces, FW-Rules, VPN-Tunnel, DHCP-Server und Switches. DHCP-Sensor lokalisierbar (`SensorDeviceClass.ENUM`, `lease_count`-Attribut). `CONF_SNMP_ENABLED`-Literal-Bug behoben. Neue Tests. |
| **v0.9.0** | 5-Tier Coordinator: Realtime/Fast/Operative/Static/Once. Konfigurierbare Poll-Intervalle und Quellen per Options-Flow. SNMP-Semaphore-Concurrency. VM-Detection (SFVH). Sections-API im Config-Flow. Reconfigure-Flow. Quality Scale Silver. |
| **v0.8.1** | Quality Scale Silver: `async_migrate_entry()`, `unique_id` auf Config Entry. IPS- und Webcat-Versions-Sensoren. README aktualisiert. |
| **v0.8.0** | Bugfixes: Switch-Tier-Force, Lizenz-Datum chronologisch, XML-Escaping. Uptime als `"77 d 14 h"`. FTP-Sensor. RestoreEntity. `DEFAULT_POLL_SNMP_HA=False`. `hacs.json`. |
| **v0.7.0** | Aggregations-Sensoren für Dienste und Lizenzen. EntityCategory.CONFIG für Rules und Web-Filter. Sortier-Präfixe in Entity-Namen. DHCP-Sensor kombiniert. |
| **v0.6.6** | Fix: SNMP SecurityModel-Instanz korrekt via `mod.create()` erzeugt |
| **v0.6.5** | Fix: puresnmp Security-Plugin-Loader gecacht — kein Blocking-I/O mehr |
| **v0.6.4** | Fix: Entity-ID Dopplung `5heynexg_5heynexg_...` behoben |
| **v0.6.2** | Sections API für Config Flow — gruppierte Abfrage-Konfiguration |
| **v0.5.8** | VM-Erkennung (SFVH) — Hardware-Sensoren nie erstellt wenn keine Daten |
| **v0.5.6** | Hostname-basierte Entity-IDs für Multi-Firewall-Setups |

---

## Lizenz

MIT — Nutzung auf eigene Gefahr. Schreibzugriff kann die Firewall-Konfiguration verändern.
