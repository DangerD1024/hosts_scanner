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
   - Primary: Asus router via SSH (`AsusClient`) or MikroTik REST API DHCP leases
   - Secondary: local ARP table (`arp-scan`→`ip neigh` on Linux; ping-sweep+`arp -a` on Windows)
   - Emits `finished(list)` with `[(ip, mac, vendor), ...]`

2. **`HostnameResolverThread`** (QThread) resolves names per device in priority order:
   - Asus router client data (names + connection duration)
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
| `AsusClient` | SSH client for Asus routers; reads `/jffs/nmp_cl_json.js` (client metadata), `/var/lib/misc/dnsmasq.leases` (IP-MAC), `/tmp/clientlist.json` (WiFi info), `wl sta_info` (WiFi association duration) |
| `IpAddressItem` | QTableWidgetItem subclass that sorts IPs naturally by numeric octets |
| `MikroTikClient` | REST API client; `build_hostname_maps()` returns `{ip: (name, source, last_seen)}` and `{mac: ...}` |
| `MacVendorDB` | Downloads/caches IEEE OUI database at `~/.cache/hosts_app/oui_db.json` |
| `MdnsCache` | Runs `avahi-browse -atrp` once and caches results; Linux only |
| `EtcHostsCache` | Reads hosts file at startup (cross-platform path) |
| `LastSeenItem` | QTableWidgetItem subclass that sorts by underlying seconds value (supports both HH:MM:SS and MikroTik duration strings) |

### Asus router configuration

The SSH connection is configured at the top of `hosts_app.py`:
```python
ASUS_HOST = '192.168.50.1'
ASUS_USER = 'DroneRouter'
ASUS_SSH_KEY = '~/.ssh/asus_router'
```

Requires SSH enabled on the router (Administration → System → SSH Daemon) with the public key in authorized keys.

Data sources on the router:
- `/jffs/nmp_cl_json.js` — all known clients with names, online status, `conn_ts`
- `/var/lib/misc/dnsmasq.leases` — DHCP leases (IP-MAC mapping)
- `/tmp/clientlist.json` — currently connected WiFi clients with RSSI and band
- `wl -i eth2/eth3 sta_info <MAC>` — real WiFi association duration (`in network N seconds`); eth2=2.4GHz, eth3=5GHz on RT-AX57

Only online clients are shown (offline clients from nmp_cl_json.js are filtered out).

### MikroTik configuration

The router connection is hardcoded at the top of `hosts_app.py`:
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
