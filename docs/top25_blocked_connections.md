# Top-25 Blocked Connections Dashboard

This guide shows how to build a "Top 25 blocked connections" card in Home Assistant using Sophos Firewall syslog data — entirely **outside** the `sophos_firewall` integration.

Field names and event schemas below follow the Sophos syslog guide and the Syslog Receiver's README. The Sophos log format and menu names have changed between SFOS releases, so check them against your own firewall (Step 3).

## Architecture

```
Sophos Firewall → Syslog (UDP) → Syslog Receiver (HACS) → HA Event
                                                               │
                                                               ▼
                                               pyscript: parse + count
                                                               │
                                                               ▼
                                            sensor.sophos_top_blocked_ips
                                                               │
                                                               ▼
                                                  Markdown dashboard card
```

Three independent pieces — none of them are part of `sophos_firewall`.

---

## Why not inside `sophos_firewall`?

The short version: the integration is built around a pull/poll coordinator model (`DataUpdateCoordinator`), while a blocked-connections tracker requires a persistent push-based syslog listener — a fundamentally different runtime model. Key problems with combining them:

- **Port binding with multiple firewalls**: each config entry gets its own coordinator, but UDP port 514 can only be bound once per host. A domain-wide singleton listener routing by source IP is a different architecture entirely.
- **A better generic solution already exists**: `homeassistant-syslog-receiver` (HACS) already handles receiving, filtering, and IP-allowlisting syslog from any device. Duplicating that inside this integration means two half-maintained copies of the same problem.
- **Security surface**: a permanently listening network socket accepting unauthenticated UDP is a different risk profile than an outbound-only polling client.

---

## Step 1 — Enable syslog export on Sophos

1. SFOS web admin console → **System services → Log settings**
2. Click **Add** to create a new syslog server
3. Fill in:
   - **Name**: e.g. `HomeAssistant`
   - **IP Address**: your Home Assistant host IP
   - **Port**: e.g. `5514` (avoid `514` to prevent conflicts with any system syslog daemon on the HA host)
   - **Protocol**: UDP (simplest; TCP/TLS is also supported by the receiver in Step 2)
4. **Log types to forward**: select **Firewall** only — forwarding Antivirus, Web, IPS etc. generates unnecessary traffic for this use case

This is the only step that touches the firewall itself.

---

## Step 2 — Install Syslog Receiver in Home Assistant

Use **[`zollak/homeassistant-syslog-receiver`](https://github.com/zollak/homeassistant-syslog-receiver)** — a maintained HACS integration that listens for UDP/TCP/TLS syslog, filters by source IP, and fires HA events.

1. HACS → Add repository `https://github.com/zollak/homeassistant-syslog-receiver` → Install → Restart HA
2. **Settings → Devices & Services → Add Integration → Syslog Receiver**
3. Configure:
   - **Host**: `0.0.0.0`
   - **Port**: `5514` (must match Step 1)
   - **Protocol**: `UDP`
   - **Allowed IPs**: your Sophos firewall's IP — **always set this**, otherwise any device on your network can inject fake events
   - **Enable Sensors**: leave disabled (avoids unnecessary recorder history writes)

After this, every incoming syslog line fires a `syslog_receiver_message` event with fields `message`, `source_ip`, and `severity`.

---

## Step 3 — Understand the Sophos log format

A "Deny" firewall log line looks like this (quoting varies slightly between SFOS versions):

```
device="SFW" date=2024-01-01 time=12:00:00 ... log_type="Firewall"
log_component="Firewall Rule" log_subtype="Denied" status="Deny"
fw_rule_id=1 ... src_ip=10.198.32.19 dst_ip=8.8.8.8
protocol="UDP" src_port=1353 dst_port=53 ...
```

Key fields for filtering:
- `log_type="Firewall"` — scopes to firewall events only (not IPS/Web/Antivirus)
- `status="Deny"` or `log_subtype="Denied"` — the blocked marker (`status="Allow"` is the allow counterpart); the script below accepts either
- `src_ip=` — the source IP to count; may appear with or without quotes depending on SFOS version — the parser below handles both

**Recommendation**: before writing code, capture one real "Deny" line from your own firewall: briefly turn on **Enable Sensors** in the Syslog Receiver config and read the last message from its sensor, or set `logger: logs: custom_components.syslog_receiver: debug` and read it in the HA log. Verify the exact quoting against your SFOS version — Sophos has changed this between releases.

---

## Step 4 — pyscript: parse, count, maintain Top 25

The generic syslog receiver delivers raw lines as events — aggregation ("Top 25 over time") needs to be built on top. **[pyscript](https://github.com/custom-components/pyscript)** (HACS) is the right tool: it runs real Python with event-trigger decorators, without requiring a custom integration.

1. Install `pyscript` via HACS
2. Create `/config/pyscript/sophos_blocked.py`:

```python
"""Counts blocked connections from Sophos syslog and maintains a Top-25 list."""
import json
import re

STORAGE_FILE = "/config/sophos_blocked_counts.json"
TOP_N = 25

_SRC_IP_RE = re.compile(r'src_ip="?([0-9a-fA-F:.]+)"?')


# File access blocks: @pyscript_executor runs these as plain Python in an
# executor thread instead of Home Assistant's event loop.
@pyscript_executor
def _read_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


@pyscript_executor
def _write_file(path, counts):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(counts, f)


counts = {}


def _publish_top25():
    top = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:TOP_N]
    blocked_list = [{"ip": ip, "count": count} for ip, count in top]
    state.set(
        "sensor.sophos_top_blocked_ips",
        value=len(blocked_list),
        new_attributes={"blocked_ips": blocked_list},
    )


@time_trigger("startup")
def load_counts():
    counts.update(_read_file(STORAGE_FILE))
    _publish_top25()


@event_trigger("syslog_receiver_message")
def on_syslog_message(message=None, **kwargs):
    if not message:
        return
    if 'log_type="Firewall"' not in message:
        return
    if 'status="Deny"' not in message and 'log_subtype="Denied"' not in message:
        return

    match = _SRC_IP_RE.search(message)
    if not match:
        return

    src_ip = match.group(1)
    counts[src_ip] = counts.get(src_ip, 0) + 1


# Publish and save every 5 minutes instead of on every blocked packet:
# each published state is also a row in the recorder database.
@time_trigger("cron(*/5 * * * *)")
def save_counts():
    _publish_top25()
    _write_file(STORAGE_FILE, dict(counts))


# Also save when Home Assistant shuts down.
@time_trigger("shutdown")
def save_on_shutdown():
    _write_file(STORAGE_FILE, dict(counts))


# Optional: reset daily at midnight for a "top 25 in the last 24h" view
# instead of a running total since installation.
# Remove this block if a cumulative total is what you want.
@time_trigger("cron(0 0 * * *)")
def reset_daily_counts():
    counts.clear()
    _write_file(STORAGE_FILE, {})
    _publish_top25()
```

3. pyscript loads a changed file on its own (from pyscript 1.2.0); on older versions run **Developer Tools → Actions → `pyscript.reload`**.

**Design choice**: the counts live in memory. The sensor and the file are updated every 5 minutes, so a busy firewall does not cause a database row and a file write for every blocked packet; the dashboard therefore lags by up to 5 minutes. On a clean shutdown the counts are saved and loaded again on start; a crash or a reload of the script can lose up to 5 minutes of counts. The counter runs cumulatively by default. With the `@time_trigger` block above it resets nightly — closer to "last 24h" but in discrete day buckets, not a true rolling window. A real rolling window would require per-entry timestamps and pruning logic — significantly more code for limited practical benefit in a home dashboard context.

---

## Step 5 — Dashboard card

A Markdown card renders the list as a table:

```yaml
type: markdown
title: Top 25 Blocked Connections
content: |
  | # | Source IP | Count |
  |---|-----------|-------|
  {%- for entry in state_attr('sensor.sophos_top_blocked_ips', 'blocked_ips') or [] %}
  | {{ loop.index }} | {{ entry.ip }} | {{ entry.count }} |
  {%- endfor %}
```

---

## Security notes

- Always set **Allowed IPs** in the Syslog Receiver to your Sophos firewall's IP. Without it, any device on the network can inject fake syslog events that the pyscript treats as real Sophos deny logs.
- The listening port should not be reachable from outside your LAN (standard home network, but relevant if you have port forwards or a DMZ setup).
- The counts (in memory and in `/config/sophos_blocked_counts.json`) grow with the number of distinct source IPs seen. If your firewall is exposed to large-scale distributed scans (many thousands of unique attacker IPs), consider adding a max dict size guard to the pyscript.

---

## Sources

- Sophos syslog field reference: [SFOS Syslog Guide 21.5](https://docs.sophos.com/nsg/sophos-firewall/21.5/syslog/index.html)
- Syslog Receiver integration: [zollak/homeassistant-syslog-receiver](https://github.com/zollak/homeassistant-syslog-receiver)
- pyscript: [custom-components/pyscript](https://github.com/custom-components/pyscript)
