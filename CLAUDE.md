# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the Application

```bash
# Via wrapper script (recommended)
./hosts

# Or directly
python3 hosts_app.py
```

## Dependencies

Install the required Python package:
```bash
pip install PyQt6
```

Optional system tools that enhance functionality (Linux):
- `arp-scan` — full ARP scan (requires `sudo`); falls back to `ip neigh` if absent
- `avahi-browse` / `avahi-resolve` — mDNS discovery
- `nmblookup` — NetBIOS name resolution (from `samba-common-bin`)

## Architecture

This is a single-file PyQt6 GUI application (`hosts_app.py`) with a `.desktop` launcher and a bash wrapper script.

### Data flow

1. **`NetworkScannerThread`** (QThread) discovers devices:
   - Primary: MikroTik REST API DHCP leases (`/rest/ip/dhcp-server/lease`)
   - Secondary: local ARP table (`arp-scan`→`ip neigh` on Linux; ping-sweep+`arp -a` on Windows)
   - Emits `finished(list)` with `[(ip, mac, vendor), ...]`

2. **`HostnameResolverThread`** (QThread) resolves names per device in priority order:
   - MikroTik DHCP comment or host-name (by IP)
   - mDNS via `avahi-browse` batch then `avahi-resolve` per-IP
   - Reverse DNS (PTR)
   - NetBIOS (`nmblookup` / `nbtstat`)
   - `/etc/hosts`
   - MikroTik by MAC fallback
   - Emits `resolved(ip, hostname, method, last_seen)` incrementally

3. **`HostsApp`** (QMainWindow) owns the UI and coordinates the two threads sequentially: scan → resolve → populate table.

### Key classes

| Class | Purpose |
|---|---|
| `MikroTikClient` | REST API client; `build_hostname_maps()` returns `{ip: (name, source, last_seen)}` and `{mac: ...}` |
| `MacVendorDB` | Downloads/caches IEEE OUI database at `~/.cache/hosts_app/oui_db.json` |
| `MdnsCache` | Runs `avahi-browse -atrp` once and caches results; Linux only |
| `EtcHostsCache` | Reads hosts file at startup (cross-platform path) |
| `LastSeenItem` | QTableWidgetItem subclass that sorts by underlying seconds value from MikroTik duration strings (e.g. `3d5h12m30s`) |

### MikroTik configuration

The router connection is hardcoded at the top of `hosts_app.py` (lines 45–47):
```python
MIKROTIK_HOST = '192.168.0.1'
MIKROTIK_USER = 'admin'
MIKROTIK_PASS = '...'
```

Requires RouterOS ≥ 7.1 for the REST API. HTTPS is supported but certificate verification is disabled when used.

### Desktop integration

`hosts.desktop` points to the `hosts` bash wrapper. To install it system-wide:
```bash
cp hosts.desktop ~/.local/share/applications/
```
