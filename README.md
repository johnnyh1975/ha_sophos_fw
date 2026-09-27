# Sophos Firewall — Home Assistant Integration

[![HACS Custom](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
[![Version](https://img.shields.io/badge/Version-1.1.0-green)](https://github.com/johnnyh1975/ha_sophos_fw/releases)
[![HA Version](https://img.shields.io/badge/HA-2025.5%2B-blue)](https://www.home-assistant.io)
[![Quality Scale](https://img.shields.io/badge/Quality_Scale-Platinum_(Selbsteinsch%C3%A4tzung)-blueviolet)](custom_components/sophos_firewall/quality_scale.yaml)
[![Validate](https://github.com/johnnyh1975/ha_sophos_fw/actions/workflows/validate.yml/badge.svg)](https://github.com/johnnyh1975/ha_sophos_fw/actions/workflows/validate.yml)
[![Typing](https://github.com/johnnyh1975/ha_sophos_fw/actions/workflows/typing.yml/badge.svg)](https://github.com/johnnyh1975/ha_sophos_fw/actions/workflows/typing.yml)

Custom Integration für Firewalls mit **Sophos Firewall OS (SFOS)**, also die Sophos XGS-Hardware und die virtuelle Appliance SFVH. Sie liest den Zustand der Firewall lokal über die **XML-API** und optional über **SNMP**, ohne Cloud und ohne Sophos Central. Mit freigegebenem Schreibzugriff kann sie außerdem Firewall-Regeln und Web-Filter schalten sowie ein Backup auslösen.

Die Einstufung „Platinum“ ist eine **Selbsteinschätzung**: Für Custom Integrations prüft niemand die Quality Scale. Welche Regel wodurch erfüllt ist, steht Regel für Regel in [`quality_scale.yaml`](custom_components/sophos_firewall/quality_scale.yaml). Nachprüfbar belegen lassen sich die CI-Prüfungen: `mypy --strict` und mindestens 95 % Testabdeckung in jedem Modul.

## Inhalt

- [Was die Integration kann](#was-die-integration-kann)
- [Unterstützte Geräte](#unterstützte-geräte)
- [Voraussetzungen auf der Firewall](#voraussetzungen-auf-der-firewall)
- [Installation](#installation)
- [Einrichtung](#einrichtung)
- [Optionen](#optionen)
- [Entitäten](#entitäten)
- [Wie und wann Daten aktualisiert werden](#wie-und-wann-daten-aktualisiert-werden)
- [Anwendungsfälle](#anwendungsfälle)
- [Beispiele](#beispiele)
- [Bekannte Einschränkungen](#bekannte-einschränkungen)
- [Fehlerbehebung](#fehlerbehebung)
- [Entfernen](#entfernen)
- [Technik](#technik)
- [Änderungen](#änderungen)
- [Lizenz](#lizenz)

---

## Was die Integration kann

| Bereich | Quelle | Was du bekommst |
|---|---|---|
| Interfaces | XML | Link-Status jedes Ports, Zone, IP-Zuweisung, MTU |
| Traffic | SNMP | Empfangen/Gesendet in Mbit/s pro Interface, übertragene Datenmenge |
| System | SNMP | CPU (gesamt und pro Kern), RAM, Disk, Swap, letzter Start |
| Dienste | SNMP | Sammelsensor mit der Zahl laufender Dienste, optional jeder der 21 Dienste einzeln |
| Lizenzen | SNMP | Sammelsensor mit der Zahl gültiger Lizenzen und dem frühesten Ablaufdatum, optional jede Lizenz einzeln |
| IPsec-VPN | SNMP | Verbindungsstatus jeder IPsec-Verbindung |
| Hochverfügbarkeit | SNMP | Cluster aktiv, Rolle dieses Knotens und des Peers |
| Hardware | SNMP | CPU-/NPU-Temperatur, Lüfter, Netzteile (nur XGS-Hardware) |
| Zähler | SNMP | HTTP-, SMTP-, IMAP-, POP3-, FTP-Verbindungen, Captive-Portal-Nutzer |
| DHCP | XML | Status jedes DHCP-Servers mit seinen statischen Leases |
| Web-Filter | XML | Standardaktion (Zulassen/Verweigern) |
| Firewall-Regeln | XML | Aktiv/Inaktiv jeder Regel, schaltbar mit Schreibzugriff |
| Backup | XML | Backup auslösen (Button), Backup-Häufigkeit |
| Reparaturen | — | Hinweise unter *Einstellungen → Reparaturen*, wenn die Firewall den API-Zugriff verweigert oder SNMP nicht antwortet |

Ohne SNMP bleiben die XML-Funktionen: Interfaces, Firewall-Regeln, DHCP, Web-Filter und Backup.

---

## Unterstützte Geräte

| Gerät / Version | Stand |
|---|---|
| SFVH (virtuelle Appliance), SFOS 22.0.2 MR-2 | ✅ im Feld getestet (API-Version 2200.1) |
| XGS-Hardware | ⚠️ Temperaturen, Lüfter und Netzteile sind nach der Sophos-MIB umgesetzt und mit Testdaten geprüft, aber nicht an echter Hardware |
| SFOS 20.x / 21.x | ⚠️ nicht getestet; XML-API und MIB sind dort nach Sophos-Doku gleich aufgebaut |
| Home Assistant | 2025.5 oder neuer; in CI getestet mit 2025.5.2 und 2026.8.3 |

Nicht unterstützt sind die ältere Sophos UTM (SG) und die Cloud-Verwaltung über Sophos Central.

---

## Voraussetzungen auf der Firewall

Die Menüpfade sind die der englischen Oberfläche von SFOS 22.

### XML-API (Pflicht)

1. **Backup & firmware → API:** „API configuration“ aktivieren und die IP-Adresse von Home Assistant unter „Allowed IP address“ eintragen. Fehlt das, antwortet die Firewall mit Status 532 oder 534 (oder HTTP 403); die Integration zeigt dann einen Reparaturhinweis.
2. **Administration → Device access:** HTTPS für die Zone erlauben, in der Home Assistant steht. Die API läuft über den Port der Web-Admin-Konsole, meist 4444.
3. **Benutzer:** Empfohlen ist ein eigener Administrator für Home Assistant mit einem Profil, das nur lesen darf. Soll Home Assistant Regeln oder Web-Filter schalten, braucht das Profil Schreibrecht für Firewall-Regeln und Web-Filter. Der Button *Backup auslösen* schickt ebenfalls eine Schreibanfrage und braucht deshalb Schreibrecht für Backup.

### SNMP (optional, empfohlen)

1. **Administration → SNMP:** den SNMP-Agenten aktivieren und unter „SNMPv1/v2c“ eine Community anlegen. Der Name der Community ist der Community-String. Als autorisierten Host die IP von Home Assistant eintragen und Anfragen zulassen.
2. **Administration → Device access:** SNMP für die Zone von Home Assistant erlauben.

Die Integration spricht SNMP v2c. Der Name der Community muss in Home Assistant exakt gleich eingetragen sein; Groß- und Kleinschreibung zählt.

---

## Installation

### Über HACS (empfohlen)

1. HACS → ⋮ → *Benutzerdefinierte Repositories* → `https://github.com/johnnyh1975/ha_sophos_fw`, Typ *Integration*.
2. „Sophos Firewall“ suchen und herunterladen.
3. Home Assistant neu starten.

### Manuell

1. Die `sophos_firewall.zip` der [aktuellen Version](https://github.com/johnnyh1975/ha_sophos_fw/releases) nach `config/custom_components/sophos_firewall/` entpacken, sodass dort `manifest.json` liegt.
2. Home Assistant neu starten.

---

## Einrichtung

*Einstellungen → Geräte & Dienste → Integration hinzufügen → „Sophos Firewall“*

### Schritt 1: Verbindung

| Feld | Bedeutung |
|---|---|
| Host | IP-Adresse oder Hostname der Firewall |
| API-Port | Port der Web-Admin-Konsole, Standard 4444 |
| Benutzername, Passwort | der Administrator aus den Voraussetzungen |
| TLS-Zertifikat prüfen | beim selbstsignierten Zertifikat der Firewall ausgeschaltet lassen; einschalten, wenn die Firewall ein Zertifikat nutzt, dem Home Assistant vertraut |

Die Verbindung wird sofort geprüft. Falsche Zugangsdaten, eine nicht erreichbare Firewall und eine verweigerte API-Freigabe werden direkt im Formular gemeldet.

### Schritt 2: SNMP (optional)

| Feld | Bedeutung |
|---|---|
| SNMP verwenden | schaltet alle SNMP-Werte ein (System, Traffic, Dienste, Lizenzen, VPN, Hardware, Cluster) |
| Community-String | der Name der SNMPv2c-Community auf der Firewall |

Mit eingeschaltetem SNMP wird der Agent vor dem Speichern abgefragt.

### Schritt 3: Schreibzugriff (optional)

| Feld | Bedeutung |
|---|---|
| Änderungen erlauben | legt Schalter für Firewall-Regeln und Web-Filter-Richtlinien an. Ohne Schreibzugriff zeigen stattdessen Nur-Lese-Sensoren den Zustand der Regeln |

### Schritt 4: Abfrage

Intervalle und Datenquellen wie unter [Optionen](#optionen). Die Standardwerte passen für die meisten Installationen.

### Später ändern

- **Verbindung** (Host, Port, Zugangsdaten, TLS-Prüfung): *⋮ → Neu konfigurieren*. Entitäten und ihre Historie bleiben erhalten.
- **Passwort abgelehnt:** Home Assistant startet von selbst die erneute Anmeldung.
- **Alles andere:** *Konfigurieren* (Optionen).

---

## Optionen

*Einstellungen → Geräte & Dienste → Sophos Firewall → Konfigurieren*

| Option | Standard | Bereich / Bedeutung |
|---|---|---|
| SNMP verwenden | aus | wie in Schritt 2 |
| Community-String | `public` | wie in Schritt 2; eine geänderte Community wird vor dem Speichern getestet |
| Änderungen erlauben | aus | wie in Schritt 3 |
| **Echtzeit**: Intervall | 30 s | 10–300 s; Grundtakt der Integration |
| Interfaces | an | Link-Status der Interfaces; legt auch fest, für welche Interfaces die Traffic-Raten standardmäßig eingeschaltet werden |
| Systemstatistik (SNMP) | an | CPU, RAM, Disk, Swap, letzter Start, Zähler, Captive-Portal-Nutzer |
| Dienste (SNMP) | an | Status der 21 Dienste |
| Interface-Traffic (SNMP) | an | Raten und Datenmengen pro Interface |
| **Schnell**: Intervall | 120 s | 60–600 s |
| IPsec-VPN-Verbindungen (SNMP) | an | ein Sensor pro IPsec-Verbindung |
| Hochverfügbarkeits-Cluster (SNMP) | aus | nur sinnvoll bei einem Hochverfügbarkeits-Paar |
| **Operativ**: Intervall | 600 s | 60–3600 s |
| Firewall-Regeln | an | Aktiv/Inaktiv jeder Regel |
| Hardware-Zustand (SNMP) | an | Temperaturen, Lüfter, Netzteile; stoppt auf virtuellen Appliances von selbst (nach drei Abfragen ohne Hardware-Werte) |
| **Statisch**: Intervall | 1800 s | 300–86400 s; in diesem Takt werden auch Hostname, Modell und Firmware gelesen |
| DHCP-Server | an | Status und statische Leases |
| Web-Filter-Richtlinien | an | Standardaktion jeder Richtlinie |
| Backup-Zeitplan | aus | Backup-Häufigkeit |
| Lizenzen (SNMP) | an | Status und Ablaufdatum der Lizenzmodule |

Bei der Einrichtung (Schritt 4) erscheinen die SNMP-Datenquellen nur, wenn SNMP eingeschaltet ist. In den Optionen sind sie immer zu sehen, wirken aber nur mit eingeschaltetem SNMP.

Schaltest du eine Datenquelle oder SNMP als Ganzes aus, verschwinden die zugehörigen Entitäten; schaltest du sie wieder ein, werden sie neu angelegt. Kann SNMP beim Start nur vorübergehend nicht genutzt werden, bleiben die Entitäten erhalten.

---

## Entitäten

Entity-IDs beginnen mit dem Hostnamen der Firewall, hier `5heynexg` für die Firewall „5HeyneXG“. Ein Suffix wie `porta` steht für das jeweilige Objekt. Die Namen in der Tabelle sind die deutschen Anzeigenamen.

**Standard:** *an* = eingeschaltet, *aus* = beim ersten Anlegen ausgeschaltet; unter *Entitäten* mit einem Klick einschaltbar. Das gilt nur für neu angelegte Entitäten; bestehende behalten ihren Zustand. **Diagnose** bzw. **Konfiguration** = Kategorie auf der Geräteseite.

### Aus der XML-API

| Entität (Beispiel-ID) | Name | Standard | Hinweis |
|---|---|---|---|
| `binary_sensor.5heynexg_iface_porta` | Netz · Interface PortA | an | Verbunden/Getrennt; Attribute `zone`, `ipv4_assignment`, `speed`, `mtu` |
| `binary_sensor.5heynexg_fwrule_<regel>` | Regel … | aus, Diagnose | nur ohne Schreibzugriff; Attribute `action`, `policy_type`, `ip_family` |
| `switch.5heynexg_switch_fwrule_<regel>` | Regel … | an, Konfiguration | nur mit Schreibzugriff |
| `switch.5heynexg_switch_webfilter_<richtlinie>` | Web-Filter … | an, Konfiguration | nur mit Schreibzugriff; an = Zulassen |
| `sensor.5heynexg_dhcp_leases_<server>` | Netz · DHCP-Leases … | an | In Betrieb/Außer Betrieb; Attribute `server_name`, `interface`, `lease_count`, `leases` und `lease_range` (bleibt bisher leer) |
| `sensor.5heynexg_sensor_web_filter_default_action` | Sicherheit · Web-Filter-Standardaktion | an | Zulassen/Verweigern, von der Richtlinie mit „default“ im Namen, sonst von der ersten |
| `sensor.5heynexg_sensor_backup_frequency` | System · Backup-Häufigkeit | aus, Diagnose | Nie/Täglich/Wöchentlich/Monatlich; nur mit Option „Backup-Zeitplan“ |
| `button.5heynexg_button_backup` | Backup auslösen | an, Konfiguration | löst ein Backup im eingestellten Backup-Modus aus (z. B. lokal oder per E-Mail); auch ohne die Option „Änderungen erlauben“, aber das API-Profil braucht Schreibrecht für Backup |

### Aus SNMP

| Entität (Beispiel-ID) | Name | Standard | Hinweis |
|---|---|---|---|
| `sensor.5heynexg_sensor_cpu_usage` | System · CPU-Auslastung | an | Mittel aller Kerne, % |
| `sensor.5heynexg_sensor_cpu_core_1` | System · CPU-Kern 1 | aus | pro Kern, % |
| `sensor.5heynexg_sensor_memory_percent` | System · RAM-Auslastung | an | % |
| `sensor.5heynexg_sensor_disk_percent` | System · Disk-Auslastung | an | % |
| `sensor.5heynexg_sensor_swap_percent` | System · Swap-Auslastung | aus | % |
| `sensor.5heynexg_sensor_uptime` | System · Letzter Start | an, Diagnose | Zeitpunkt des letzten Starts |
| `sensor.5heynexg_traffic_rx_rate_portb` | Netz · Interface PortB empfangen | an* | Mbit/s |
| `sensor.5heynexg_traffic_tx_rate_portb` | Netz · Interface PortB gesendet | an* | Mbit/s |
| `sensor.5heynexg_traffic_rx_bytes_portb` | Netz · Interface PortB empfangen gesamt | aus | GB, steigender Zähler |
| `sensor.5heynexg_traffic_tx_bytes_portb` | Netz · Interface PortB gesendet gesamt | aus | GB, steigender Zähler |
| `sensor.5heynexg_sensor_services_summary` | System · Dienste | an | Anzahl laufender Dienste; Attribute `total`, `running`, `stopped` (alle nicht laufenden), `details` |
| `sensor.5heynexg_service_ips` | System · Dienst IPS | aus, Diagnose | Läuft/Gestoppt/…/Nicht registriert, für jeden der 21 Dienste |
| `sensor.5heynexg_sensor_licenses_summary` | Sicherheit · Lizenzen | an | Anzahl gültiger Lizenzen; Attribute `total`, `ok`, `problem` (alle übrigen, auch nie lizenzierte Module), `next_expiry` (frühestes Datum, auch ein vergangenes), `details` |
| `sensor.5heynexg_license_base_fw` | Sicherheit · Lizenz Base Firewall | aus, Diagnose | Abonniert/Evaluierung/Abgelaufen/…; Attribut `expiry_date` |
| `binary_sensor.5heynexg_vpn_1` | VPN … | an | IPsec-Verbindung verbunden; Attribute `partially_active`, `activated`, `tunnels_configured` |
| `binary_sensor.5heynexg_ha_enabled` | Hochverfügbarkeit · Status | an, Diagnose | nur mit Option „Hochverfügbarkeits-Cluster“ |
| `sensor.5heynexg_ha_current_state` | Hochverfügbarkeit · Rolle (dieser Knoten) | an | Primär/Sekundär/Einzelbetrieb/Bereit/Fehler/Nicht zutreffend; nur mit derselben Option |
| `sensor.5heynexg_ha_peer_state` | Hochverfügbarkeit · Rolle (Peer) | aus, Diagnose | wie oben |
| `sensor.5heynexg_sensor_http_hits` | Netz · HTTP-Verbindungen | an | steigender Zähler |
| `sensor.5heynexg_sensor_smtp_hits` usw. | Netz · SMTP-, IMAP-, POP3-, FTP-Verbindungen | aus | steigende Zähler |
| `sensor.5heynexg_sensor_live_users` | Netz · Aktive Captive-Portal-Nutzer | an | |
| `sensor.5heynexg_sensor_ips_version` | Sicherheit · IPS-Signaturversion | aus, Diagnose | |
| `sensor.5heynexg_sensor_webcat_version` | Sicherheit · Webcat-Version | aus, Diagnose | entfällt, wenn die Firewall keine Version meldet |
| `sensor.5heynexg_sensor_cpu_temperature` | System · CPU-Temperatur | an, Diagnose | nur Hardware; ebenso die NPU-Temperatur |
| `sensor.5heynexg_sensor_fan_1` | System · Lüfter fan 1 | aus, Diagnose | nur Hardware, U/min |
| `binary_sensor.5heynexg_psu_psu_1` | System · Netzteil psu 1 | an, Diagnose | nur Hardware |

\* **Traffic:** Eingeschaltet sind die Raten der Interfaces, die die XML-API als Interface kennt, also die Ports wie PortA und PortB. VLANs (z. B. PortA.30), WLAN-Netze und Tunnel-Interfaces werden ausgeschaltet angelegt. Interne Hilfs-Interfaces der Firewall (`lo`, `dummy0`, `ipsec0`, `sit0`, `ip6tnl0`, `gre0`, `gretap0`, `erspan0`, `ifb0`, `dfq`, `spq` u. ä.) bekommen gar keine Entitäten. „Empfangen“ und „Gesendet“ zählen aus Sicht der Firewall: Beim WAN-Port ist „empfangen“ dein Download, beim LAN-Port ist es „gesendet“.

Temperatur-, Lüfter- und Netzteil-Entitäten entstehen erst, wenn die Firewall Werte meldet. Auf der virtuellen Appliance gibt es sie nicht.

---

## Wie und wann Daten aktualisiert werden

Die Integration fragt ab (*local polling*); die Firewall meldet nichts von sich aus. Jede Datenquelle gehört zu einer Stufe:

| Stufe | Standard | XML-API | SNMP |
|---|---|---|---|
| Echtzeit | 30 s | Interfaces | Systemstatistik, CPU, Dienste, Interface-Traffic |
| Schnell | 2 min | — | IPsec-VPN, Hochverfügbarkeit |
| Operativ | 10 min | Firewall-Regeln | Hardware-Zustand |
| Statisch | 30 min | DHCP, Web-Filter, Backup, Admin-Einstellungen (Hostname) | Lizenzen, Geräteinfo (Modell, Firmware, Versionen) |

- **Die XML-API ist langsam.** Die Firewall beantwortet XML-Anfragen nacheinander und braucht pro Anfrage etwa 5 bis 10 Sekunden. Gemessen an einer SFVH: Interfaces 4,6 s, Admin-Einstellungen 10,5 s. Die Integration stellt deshalb immer nur eine Anfrage gleichzeitig; jede hat bis zu 20 Sekunden Zeit.
- **Beim Start** wartet die Einrichtung nur auf die Admin-Einstellungen, rund 10 Sekunden. Die übrigen XML-Daten folgen im Hintergrund; nach weiteren rund 25 Sekunden sind alle da (gemessen an einer SFVH). Bis dahin stehen deren Entitäten auf „Nicht verfügbar“.
- **SNMP** ist schnell (meist unter einer Sekunde pro Durchlauf, der erste etwa 2 Sekunden) und startet ebenfalls im Hintergrund.
- **Nach einem Schaltvorgang** wird genau die geänderte Regel- bzw. Web-Filter-Liste sofort neu gelesen, unabhängig von ihrer Stufe.
- **Fällt eine Datenquelle aus,** werden nur die Entitäten dieser Quelle „Nicht verfügbar“. Es werden keine Ersatzwerte wie 0 angezeigt. Die Integration schreibt den Ausfall einmal ins Log und die Erholung ebenfalls einmal.
- **Traffic-Raten** werden aus zwei aufeinanderfolgenden Zählerständen und der tatsächlich gemessenen Zeit dazwischen berechnet. Nach einem Neustart von Home Assistant ist die erste Rate daher erst nach dem zweiten Durchlauf da. Nach einem Neustart der Firewall wird eine Messung ausgelassen, statt eine falsche Spitze zu zeigen.

---

## Anwendungsfälle

- **Internet-Ausfall erkennen:** Benachrichtigung, wenn das WAN-Interface die Verbindung verliert.
- **Bandbreite im Blick:** Download und Upload am WAN-Port im Dashboard oder in der Langzeitstatistik.
- **Lizenzen nicht verpassen:** Hinweis, wenn ein Lizenzmodul abläuft oder nicht mehr gültig ist.
- **Zeitgesteuerte Regeln:** Gäste-Internet nur tagsüber freigeben, Kinder-Web-Filter abends verschärfen (Schreibzugriff nötig).
- **Firewall-Gesundheit:** Warnung bei hoher CPU-Last, voller Disk oder gestopptem Dienst.
- **Backup vor Änderungen:** Backup per Knopfdruck oder per Automation vor einem Wartungsfenster auslösen.

---

## Beispiele

Die Entity-IDs gelten für eine Firewall mit dem Hostnamen „5HeyneXG“; passe sie an deine an.

**Benachrichtigung bei WAN-Ausfall:**

```yaml
triggers:
  - trigger: state
    entity_id: binary_sensor.5heynexg_iface_portb
    to: "off"
    for: "00:01:00"
actions:
  - action: notify.notify
    data:
      message: "Internetverbindung der Firewall ist getrennt."
```

**Melden, wenn eine Lizenz ungültig wird:**

Der Sammelsensor zählt die gültigen Lizenzen. Sinkt die Zahl, ist ein Modul abgelaufen oder ungültig geworden. (Das Attribut `problem` eignet sich dafür nicht, weil darin auch Module stehen, die nie lizenziert waren.)

```yaml
triggers:
  - trigger: state
    entity_id: sensor.5heynexg_sensor_licenses_summary
conditions:
  - condition: template
    value_template: >
      {{ trigger.from_state.state | is_number
         and trigger.to_state.state | is_number
         and trigger.to_state.state | int < trigger.from_state.state | int }}
actions:
  - action: notify.notify
    data:
      message: >
        Sophos: nur noch {{ trigger.to_state.state }} von
        {{ state_attr(trigger.entity_id, 'total') }} Lizenzen gültig.
```

**Warnung bei dauerhaft hoher CPU-Last:**

```yaml
triggers:
  - trigger: numeric_state
    entity_id: sensor.5heynexg_sensor_cpu_usage
    above: 90
    for: "00:10:00"
actions:
  - action: notify.notify
    data:
      message: "Firewall-CPU seit 10 Minuten über 90 %."
```

**Nicht laufende Dienste anzeigen (Template):**

```yaml
{{ state_attr('sensor.5heynexg_sensor_services_summary', 'stopped') | join(', ') }}
```

**Firewall-Regel zeitgesteuert schalten** (Schreibzugriff nötig):

```yaml
triggers:
  - trigger: time
    at: "22:00:00"
actions:
  - action: switch.turn_off
    target:
      entity_id: switch.5heynexg_switch_fwrule_guest_access_internet
```

**IP-Adresse zu einer MAC aus den statischen DHCP-Leases (Template):**

```yaml
{{ state_attr('sensor.5heynexg_dhcp_leases_main_dhcp', 'leases')
   | selectattr('MACAddress', 'eq', 'aa:bb:cc:dd:ee:ff')
   | map(attribute='IPAddress') | first }}
```

Weiterführend: [Top-25 geblockte Verbindungen als Dashboard](docs/top25_blocked_connections.md), per Syslog ganz ohne diese Integration.

---

## Bekannte Einschränkungen

- **XML-API-Tempo:** Jede XML-Anfrage kostet die Firewall 5 bis 10 Sekunden, und sie bearbeitet eine nach der anderen. Deshalb sind die XML-Intervalle bewusst lang, und nach dem Start dauert es rund 35 Sekunden, bis alle Daten da sind.
- **Nur SNMP v2c:** SNMPv3 wird nicht unterstützt. Die frühere Einstellung „SNMP-Version 1“ wurde ohnehin nie verwendet und ist in 1.1 entfallen.
- **Keine Auslastung in Prozent der Leitung:** Die Integration zeigt Traffic nur in Mbit/s. Die Port-Geschwindigkeit steht als Attribut `speed` am Interface; die SFVH meldet dort 0.
- **„Letzter Start“ nach 497 Tagen:** Der Uptime-Zähler der Firewall ist ein 32-Bit-Wert und läuft nach etwa 497 Tagen über. Danach springt „Letzter Start“ vor, als hätte die Firewall neu gestartet.
- **Webcat-Version:** SFOS 22 meldet sie teils nicht („not available“). Dann wird die Entität nicht angelegt bzw. nach drei Abfragen ohne Wert entfernt.
- **Backup-Häufigkeit:** Die Werte Nie/Täglich/Wöchentlich/Monatlich stammen aus der Weboberfläche; die API-Doku listet sie nicht auf, und an einer echten Firewall ist noch keiner geprüft. Ein anderer Wert zeigt „Unbekannt“ und eine einmalige Warnung im Log; bitte dann melden.
- **Hardware-Sensoren** (Temperaturen, Lüfter, Netzteile) sind an echter XGS-Hardware nicht getestet.
- **Traffic-Zähler** beginnen nach einem Neustart der Firewall bei 0. Home Assistant erkennt das als Zähler-Reset; die Langzeitstatistik bleibt korrekt.
- **Kurz fehlende Interfaces:** Fehlt ein Interface beim Start der Firewall kurz, bleiben seine Traffic-Entitäten erhalten; erst nach drei SNMP-Abfragen ohne das Interface werden sie entfernt. Der Link-Status (XML) wird dagegen entfernt, sobald eine erfolgreiche Abfrage das Interface nicht mehr enthält.
- **Ein Gerät pro Eintrag:** Jede Firewall ist ein eigener Integrationseintrag; ein Hochverfügbarkeits-Paar erscheint als ein Gerät (der abgefragte Knoten).
- **Logo** in der Integrationsliste erst ab Home Assistant 2026.3.

---

## Fehlerbehebung

**Reparaturhinweis „API-Zugriff verweigert“ (Status 532/534 oder HTTP 403)**
Die API ist aus, oder die IP von Home Assistant fehlt unter *Backup & firmware → API → Allowed IP address*. Nach der Korrektur verschwindet der Hinweis beim nächsten Versuch von selbst.

**Reparaturhinweis „SNMP-Agent antwortet nicht“**
Erscheint, wenn der Agent seit dem Start der Integration über 10 Minuten nicht geantwortet hat. Zu prüfen: Agent aktiviert, Community-Name exakt gleich, IP von Home Assistant als autorisierter Host, SNMP unter *Device access* für die Zone erlaubt. Eine falsche Community ignoriert die Firewall ohne Fehlermeldung, das sieht aus wie ein Timeout. Wer SNMP nicht nutzt, schaltet es in den Optionen aus.

**„Passwort abgelehnt“ / erneute Anmeldung**
Home Assistant fragt das neue Passwort über den Dialog *Erneut anmelden* ab. Die XML-Abfragen pausieren bis dahin; SNMP läuft weiter.

**Einrichtung scheitert mit „nicht erreichbar“**
Host, Port (meist 4444) und HTTPS unter *Administration → Device access* für die Zone von Home Assistant prüfen und den Dialog erneut absenden. Ist die Integration schon eingerichtet und die Firewall beim Start von Home Assistant nicht erreichbar, versucht Home Assistant es von selbst weiter.

**Entitäten „Nicht verfügbar“ direkt nach dem Start**
Normal für etwa 35 Sekunden, siehe [Wie und wann Daten aktualisiert werden](#wie-und-wann-daten-aktualisiert-werden).

**Eine Gruppe von Entitäten bleibt „Nicht verfügbar“**
Die zugehörige Abfrage schlägt fehl; die Ursache steht einmal im Log (`fetching … failed`). Häufig fehlt dem API-Administrator die Leseberechtigung für diesen Bereich.

**Temperatur- und Lüfter-Sensoren fehlen**
Normal auf der virtuellen Appliance, dort gibt es diese Werte nicht.

**Nach dem Update: Hinweis „Einheit geändert“ für Dienste/Lizenzen**
Die beiden Sensoren haben keine Pseudo-Einheit mehr (siehe [Release Notes](release-notes/v1.1.0.md)). Unter *Entwicklerwerkzeuge → Statistiken* mit einem Klick bestätigen; bis dahin pausiert ihre Langzeitstatistik.

**Debug-Log und Diagnose**
1. In der `configuration.yaml`:
   ```yaml
   logger:
     logs:
       custom_components.sophos_firewall: debug
   ```
   Home Assistant neu starten. Das Debug-Log enthält für jede XML-Anfrage die Wartezeit und die Antwortzeit der Firewall sowie die Dauer der Einrichtung.
2. Diagnose: *Einstellungen → Geräte & Dienste → Sophos Firewall → ⋮ → Diagnosedaten herunterladen*. Passwort, Benutzername, Community, Host, Seriennummer und die statischen DHCP-Leases sind darin geschwärzt.
3. Beides einem [Issue](https://github.com/johnnyh1975/ha_sophos_fw/issues) anhängen.

---

## Entfernen

1. *Einstellungen → Geräte & Dienste → Sophos Firewall → ⋮ → Löschen*. Damit verschwinden Gerät, Entitäten und die Reparaturhinweise der Integration.
2. Bei Installation über HACS: in HACS die Integration entfernen. Manuell: den Ordner `config/custom_components/sophos_firewall` löschen.
3. Home Assistant neu starten.
4. Optional auf der Firewall: den API-Administrator, die Freigabe unter *Backup & firmware → API* und die SNMP-Community für Home Assistant entfernen.

---

## Technik

- **Zwei Koordinatoren:** einer für die XML-API, einer für SNMP. Fällt SNMP aus, bleiben die XML-Entitäten verfügbar, und umgekehrt.
- **XML-API:** eigene HTTP-Session, deren Verbindungen nie wiederverwendet werden, weil SFOS bei wiederverwendeten Keep-Alive-Verbindungen hängen bleibt. Dazu höchstens eine Anfrage gleichzeitig, siehe oben.
- **SNMP:** puresnmp 2.x über asyncio. Die Plugin-Erkennung von puresnmp lädt Module, deshalb läuft sie einmal beim Start im Import-Executor und nie im Event-Loop. Tabellen werden spaltenweise per GETBULK gelesen, mit einem Zeitbudget pro Abfrage.
- **Werte:** Sophos-eigene MIB (`1.3.6.1.4.1.2604.5.1`) sowie Standard-MIBs für CPU (HOST-RESOURCES-MIB) und Interfaces (IF-MIB, 64-Bit-Zähler).
- **unique_id:** `{Config-Entry-ID}_{Objekt}`, unabhängig von Host und IP. Bis 1.0.x war es `{Host}_{Port}_{Objekt}`; das Update migriert automatisch.
- **Tests:** über 250 Tests mit dem Home-Assistant-Testrahmen, einem echten UDP-SNMP-Agenten und einer nachgebauten XML-API. Mindestens 95 % Abdeckung in jedem Modul, `mypy --strict`; beides in CI geprüft.

---

## Änderungen

Alle Versionen mit Details: [Releases](https://github.com/johnnyh1975/ha_sophos_fw/releases) und [`release-notes/`](release-notes/).

**1.1.0**, die wichtigsten Punkte. Die [Release Notes](release-notes/v1.1.0.md) enthalten die vollständige Liste der Änderungen, die bestehende Automationen betreffen können.
- Neu: CPU-Auslastung, Traffic pro Interface, jeder Dienst und jede Lizenz einzeln, Reparaturhinweise.
- Ausfälle von SNMP zeigen „Nicht verfügbar“ statt erfundener Nullwerte.
- „Uptime“ ist jetzt „Letzter Start“ (Zeitstempel); der Web-Filter zeigt „Zulassen/Verweigern“ statt „Allow/Deny“; Dienste und Lizenzen ohne Pseudo-Einheit.
- Einrichtung in etwa 10 statt 34 Sekunden; Timeouts beim Start behoben.
- Stabile Entity-IDs auch nach einer Änderung von Host oder IP; Einstellungen in den Optionen; Mindestversion Home Assistant 2025.5.

---

## Lizenz

MIT. Nutzung auf eigene Gefahr: Mit Schreibzugriff ändert Home Assistant die laufende Konfiguration der Firewall.
