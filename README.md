# Hosts Scanner

A PyQt6 GUI application that scans your local network and displays connected devices with hostnames, MAC addresses, vendor information, and last-seen times.

![Python](https://img.shields.io/badge/python-3.8+-blue) ![PyQt6](https://img.shields.io/badge/PyQt6-required-green)

## Features

- Pulls device list from a **MikroTik router** via its REST API (RouterOS ≥ 7.1)
- Falls back to the local ARP table (`arp-scan` / `ip neigh` on Linux; ping-sweep + `arp -a` on Windows)
- Resolves hostnames through multiple sources in priority order:
  1. MikroTik DHCP comment / host-name
  2. mDNS / Avahi (`.local` names, smart-home devices)
  3. Reverse DNS (PTR records)
  4. NetBIOS (Windows / Samba machines)
  5. `/etc/hosts`
- Looks up vendor names from the IEEE OUI database (downloaded and cached locally)
- Click any IP address to copy it to the clipboard
- Sortable columns; **Last Seen** sorts correctly by duration (seconds, not alphabetically)

## Requirements

**Python package:**
```bash
pip install PyQt6
```

**Optional system tools** (Linux — enhance hostname resolution):

| Tool | Purpose | Install |
|---|---|---|
| `arp-scan` | Full ARP scan (requires `sudo`) | `apt install arp-scan` |
| `avahi-browse` / `avahi-resolve` | mDNS discovery | `apt install avahi-utils` |
| `nmblookup` | NetBIOS names | `apt install samba-common-bin` |

## Configuration

Edit the three constants near the top of `hosts_app.py`:

```python
MIKROTIK_HOST = '192.168.0.1'
MIKROTIK_USER = 'admin'
MIKROTIK_PASS = 'your-password'
```

## Running

```bash
# Via wrapper script
./hosts

# Or directly
python3 hosts_app.py
```

### Desktop integration (Linux)

```bash
cp hosts.desktop ~/.local/share/applications/
```

The app will then appear in your application launcher under **Network / System**.

## OUI Vendor Database

On first run, the app downloads the IEEE OUI database (~5 MB) and caches it at `~/.cache/hosts_app/oui_db.json`. Subsequent launches use the cache.
