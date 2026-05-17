# Sophos Firewall — Home Assistant Integration

[![HACS Custom](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![Version](https://img.shields.io/badge/Version-0.9.0-green)](https://github.com/johnnyh1975/ha_sophos_fw/releases)
[![HA Version](https://img.shields.io/badge/HA-2024.9%2B-blue)](https://www.home-assistant.io)

Home Assistant Custom Integration für Sophos Firewall (SFOS 18.x – 22.x). Verbindet HA mit der Firewall über XML API und SNMP — ohne Cloud, ohne Drittanbieter.

---

## Features

| Kategorie | Entities |
|---|---|
| **Interfaces** | PortA, PortB — Verbunden/Getrennt, Zone, IP-Assignment |
| **VPN-Tunnel** | IPSec-Tunnel mit Verbindungsstatus (SNMP) |
| **Firewall-Rules** | Schalter (mit Schreibzugriff) oder Nur-Lese-Sensor |
| **Web-Filter** | Schalter für DefaultAction Allow/Deny (mit Schreibzugriff) |
| **DHCP** | Kombinierter Sensor: Server-Status + Lease-Anzahl + vollständige Lease-Liste als Attribut |
| **System** | RAM, Disk, Swap (%), Uptime, Backup-Häufigkeit |
| **Verbindungen** | HTTP-, SMTP- und FTP-Verbindungen, Captive-Portal-User |
| **Dienste** | Aggregations-Sensor: `19 / 21 running` — `running`/`stopped`-Listen als Attribut |
| **Lizenzen** | Aggregations-Sensor: `8 / 9 OK` — nächstes Ablaufdatum, Details als Attribut |
| **Sicherheit** | Web-Filter Standardaktion, IPS-Signaturversion, Webcat-Version |
| **Hardware-Health** | CPU/NPU-Temperatur, Lüfter-RPM (nur physische Appliances) |
| **Steuerung** | Backup auslösen (Button), Firewall-Rules und Web-Filter schalten |

---

## Voraussetzungen

- Home Assistant 2024.9+
- Sophos Firewall SFOS 18.x – 22.x
- API-Zugang: **Netzwerk → Administration → Geräte-Zugang → HTTPS-Admin aktivieren**
- Optional SNMP: **System → Administration → SNMP → Community-String konfigurieren**

---

## Installation

### Via HACS (empfohlen)

1. HACS → Integrationen → ⋮ → Benutzerdefinierte Repositories
2. URL: `https://github.com/johnnyh1975/ha_sophos_fw`, Kategorie: Integration
3. Integration suchen: „Sophos Firewall" → Installieren
4. HA neu starten

### Manuell

```bash
cp -r custom_components/sophos_firewall /config/custom_components/sophos_firewall
```

HA neu starten.

---

## Einrichtung

**Einstellungen → Geräte & Dienste → Integration hinzufügen → „Sophos Firewall"**

Der Setup-Assistent führt durch 4 Schritte:

**Schritt 1 — Verbindung:** Host/IP, API-Port (Standard: 4444), Benutzername, Passwort, SSL-Verifizierung.

**Schritt 2 — SNMP (optional):** Aktiviere SNMP für Systemmetriken, Dienste, VPN-Tunnel und Lizenzen. Community-String und SNMP-Version (1 oder 2c) konfigurieren.

**Schritt 3 — Schreibzugriff (optional):** Erlaubt das Schalten von Firewall-Rules und Web-Filter-Policies direkt aus HA. Mit Schreibzugriff: Switches. Ohne: Nur-Lese-Sensoren.

**Schritt 4 — Abfrage-Konfiguration:** Polling-Intervalle und aktive Endpunkte — gruppiert nach Tier. Alle Standardwerte sind optimal voreingestellt.

Nach der Einrichtung können Host, Port und Zugangsdaten jederzeit über **Konfigurieren → Verbindung ändern** angepasst werden, ohne die Integration neu einzurichten.

---

## Abfrage-Intervalle (Tiered Polling)

| Tier | Standard | XML-Endpunkte | SNMP-Endpunkte |
|---|---|---|---|
| ⚡ Realtime | 30 s | Interfaces | Stats, Dienste |
| 🔄 Fast | 120 s | — | VPN-Tunnel, HA-Status |
| 🔧 Operative | 600 s | Firewall-Rules | System-Health |
| 🗄 Static | 1800 s | DHCP, Web-Filter, Backup | Lizenzen |
| 🔁 Once | beim Start | Admin-Settings | Geräteinformationen |

Schreiboperationen (Schalter, Button) lösen immer sofort einen Refresh des betroffenen Tiers aus.

---

## Kompatibilität

| Gerät / Version | Status |
|---|---|
| SFVH (Virtual Appliance) | ✅ vollständig unterstützt, automatische VM-Erkennung |
| XGS-Serie (Hardware) | ✅ unterstützt, Hardware-Health aktiv |
| SFOS 18.x – 22.x | ✅ unterstützt |
| HA 2024.9+ | ✅ erforderlich |

---

## Automations-Beispiele

**Benachrichtigung wenn Lizenz abläuft:**
```yaml
trigger:
  - platform: template
    value_template: >
      {{ state_attr('sensor.5heynexg_licenses', 'problem') | length > 0 }}
action:
  - service: notify.mobile_app
    data:
      message: >
        Sophos Lizenz-Problem:
        {{ state_attr('sensor.5heynexg_licenses', 'problem') | join(', ') }}
```

**Firewall-Rule bei Heimkehr aktivieren:**
```yaml
trigger:
  - platform: state
    entity_id: person.john
    to: home
action:
  - service: switch.turn_on
    target:
      entity_id: switch.5heynexg_rule_homeautomation_to_iot
```

**DHCP-Lease-Suche per MAC-Adresse:**
```yaml
{{ state_attr('sensor.5heynexg_dhcp_leases_main_dhcp', 'leases')
   | selectattr('MACAddress', 'eq', 'aa:bb:cc:dd:ee:ff')
   | map(attribute='IPAddress') | first }}
```

---

## Troubleshooting

**Entities zeigen „Nicht verfügbar" nach Start**
→ Ab v0.9.0 werden Entities sofort nach dem Setup geladen. Bei Timeout: HA-Log prüfen, Host und Port verifizieren.

**SNMP-Sensoren bleiben auf „Unbekannt"**
→ Community String prüfen: System → Administration → SNMP. SNMP muss auf der Firewall aktiviert sein.

**„Cannot connect" beim Setup**
→ API-Zugang prüfen: Netzwerk → Administration → Geräte-Zugang → HTTPS-Admin aktivieren.

**Temperatur-Sensoren fehlen**
→ Normal auf SFVH (virtuelle Appliance). Automatisch erkannt — kein Fehler.

**Host oder Port falsch konfiguriert**
→ Konfigurieren → Verbindung ändern — kein Löschen und Neueinrichten nötig.

---

## Changelog

| Version | Änderungen |
|---|---|
| **v0.9.0** | Initial HACS Release. Reconfigure Flow, `async_config_entry_first_refresh`, `PARALLEL_UPDATES = 0`, `config_entry=entry` im Coordinator, englische `en.json`, `quality_scale.yaml`, CI-Workflow, MIT-Lizenz. |

---

## Lizenz

[MIT](LICENSE) — Nutzung auf eigene Gefahr. Schreibzugriff kann die Firewall-Konfiguration verändern.
