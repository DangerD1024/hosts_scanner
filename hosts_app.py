#!/usr/bin/env python3
"""
Hosts - Network Scanner GUI Application
Scans local network and displays devices with hostnames and vendor information.
"""

import sys
import os
import subprocess
import socket
import re
import json
import ssl
import time
import platform
import base64
import tempfile
import atexit
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, Tuple, List, Dict
from urllib.request import urlopen, Request
from urllib.error import URLError

IS_WINDOWS = platform.system() == 'Windows'

# On Windows, prevent subprocess from opening visible console windows
_SUBPROCESS_FLAGS: Dict = {}
if IS_WINDOWS:
    _SUBPROCESS_FLAGS['creationflags'] = subprocess.CREATE_NO_WINDOW


def get_local_interfaces() -> List[str]:
    """Return non-loopback interface names that are currently up."""
    interfaces: List[str] = []
    if IS_WINDOWS:
        try:
            result = subprocess.run(
                ['ipconfig'],
                capture_output=True, text=True, timeout=5, check=False,
                **_SUBPROCESS_FLAGS,
            )
            for line in result.stdout.split('\n'):
                m = re.match(r'^[\w\s]+ adapter (.+):$', line)
                if m:
                    interfaces.append(m.group(1).strip())
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
    else:
        try:
            result = subprocess.run(
                ['ip', '-o', 'link', 'show', 'up'],
                capture_output=True, text=True, timeout=5, check=False,
            )
            for line in result.stdout.split('\n'):
                m = re.match(r'^\d+:\s+(\S+):', line)
                if m:
                    name = m.group(1).split('@')[0]  # strip veth peer suffix
                    if name != 'lo':
                        interfaces.append(name)
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
    return interfaces

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTableWidget, QTableWidgetItem, QPushButton, QLabel, QMessageBox,
        QHeaderView, QProgressDialog, QComboBox, QDialog, QTextEdit
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QClipboard, QFont
except ImportError:
    print("PyQt6 is required. Install it with: pip install PyQt6")
    sys.exit(1)


# ---------------------------------------------------------------------------
# MikroTik REST API client
# ---------------------------------------------------------------------------

MIKROTIK_HOST = '192.168.0.1'
MIKROTIK_USER = 'admin'
MIKROTIK_PASS = 'Thm90_1234'

# ---------------------------------------------------------------------------
# Asus Router SSH client
# ---------------------------------------------------------------------------

ASUS_HOST = '192.168.50.1'
ASUS_USER = 'DroneRouter'

# ---------------------------------------------------------------------------
# Device SSH config (for fetching device ID from /root/config.ini)
# ---------------------------------------------------------------------------

DEVICE_SSH_USER = 'pi'

# ---------------------------------------------------------------------------
# Embedded SSH keys (written to temp files at startup, cleaned up on exit)
# ---------------------------------------------------------------------------

_ASUS_KEY = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAxJJdJRr5AiG7YQulduc8Ra4Z9Nir5GF5t0bIcKFbZEQAAAKBtgBEqbYAR
KgAAAAtzc2gtZWQyNTUxOQAAACAxJJdJRr5AiG7YQulduc8Ra4Z9Nir5GF5t0bIcKFbZEQ
AAAEBkPXdLUWOm7sXzex+l29WCka9WKuZXJxK7Eb/yfAmXgDEkl0lGvkCIbthC6V25zxFr
hn02KvkYXm3RshwoVtkRAAAAF2NsYXVkZS1jb2RlQGFzdXMtcm91dGVyAQIDBAUG
-----END OPENSSH PRIVATE KEY-----
"""

_DEVICE_KEY = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBwNU/cQBjNCfZ0bA9bEtxAxBvjfUItjiTLfIAsYK4pCAAAAKijhENvo4RD
bwAAAAtzc2gtZWQyNTUxOQAAACBwNU/cQBjNCfZ0bA9bEtxAxBvjfUItjiTLfIAsYK4pCA
AAAECUby3zJd9bJMlWJ8Lo44nRv2602gq9Hpd83+rkKVyxBnA1T9xAGM0J9nRsD1sS3EDE
G+N9Qi2OJMt8gCxgrikIAAAAHmRhbmdlcmRAZGFuZ2VyZC1aZW5Cb29rLVE0MDZEQQECAw
QFBgc=
-----END OPENSSH PRIVATE KEY-----
"""


def _write_temp_key(key_data: str) -> str:
    """Write an SSH key to a temp file with 0600 permissions, return path."""
    fd, path = tempfile.mkstemp(prefix='hosts_app_key_')
    os.write(fd, key_data.encode())
    os.close(fd)
    os.chmod(path, 0o600)
    atexit.register(lambda p=path: os.unlink(p) if os.path.exists(p) else None)
    return path


ASUS_SSH_KEY = _write_temp_key(_ASUS_KEY)
DEVICE_SSH_KEY = _write_temp_key(_DEVICE_KEY)
DEVICE_ID_HOSTNAMES = {'ebaka', 'ebakam'}  # hostnames (lowercase) to query


def _host_reachable(host: str, port: int, timeout: float = 1.0) -> bool:
    """Quick TCP connect check — returns True if the port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


class MikroTikClient:
    """Fetch DHCP leases (and ARP table) from MikroTik via its REST API.

    The REST API (RouterOS >= 7.1) is a JSON wrapper around the CLI.
    Endpoint examples:
        GET /rest/ip/dhcp-server/lease
        GET /rest/ip/arp
    """

    def __init__(self, host: str, username: str, password: str, use_https: bool = False):
        self.host = host
        self.username = username
        self.password = password
        self.port = 443 if use_https else 80
        scheme = 'https' if use_https else 'http'
        self.base_url = f'{scheme}://{host}/rest'
        self._reachable: Optional[bool] = None

    # -- helpers --

    def is_reachable(self) -> bool:
        """Quick check whether the router API port is open."""
        if self._reachable is None:
            self._reachable = _host_reachable(self.host, self.port)
        return self._reachable

    def _get(self, path: str, timeout: float = 10) -> list:
        """Perform an authenticated GET and return parsed JSON."""
        if not self.is_reachable():
            return []
        url = f'{self.base_url}{path}'
        req = Request(url)
        creds = base64.b64encode(f'{self.username}:{self.password}'.encode()).decode()
        req.add_header('Authorization', f'Basic {creds}')

        ctx = None
        if url.startswith('https'):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read().decode())

    # -- public API --

    def get_dhcp_leases(self) -> List[dict]:
        """Return list of DHCP lease dicts with keys like
        'address', 'mac-address', 'host-name', 'comment', 'status', etc."""
        try:
            return self._get('/ip/dhcp-server/lease')
        except Exception as e:
            print(f'[MikroTik] Failed to fetch DHCP leases: {e}')
            return []

    def get_arp_table(self) -> List[dict]:
        """Return ARP entries (address, mac-address, interface, …)."""
        try:
            return self._get('/ip/arp')
        except Exception as e:
            print(f'[MikroTik] Failed to fetch ARP table: {e}')
            return []

    @staticmethod
    def parse_duration(s: str) -> int:
        """Parse MikroTik duration string like '3d5h12m30s' into total seconds."""
        if not s:
            return -1
        total = 0
        for m in re.finditer(r'(\d+)([wdhms])', s):
            val = int(m.group(1))
            unit = m.group(2)
            if unit == 'w':
                total += val * 604800
            elif unit == 'd':
                total += val * 86400
            elif unit == 'h':
                total += val * 3600
            elif unit == 'm':
                total += val * 60
            elif unit == 's':
                total += val
        return total

    def build_hostname_maps(self) -> Tuple[
        Dict[str, Tuple[str, str, str]],   # ip_map:  {ip:  (name, source, last_seen)}
        Dict[str, Tuple[str, str, str]],   # mac_map: {mac: (name, source, last_seen)}
    ]:
        """Fetch DHCP leases once and return two mappings.

        Prefers 'comment' over 'host-name' when both are present,
        because router admins often label devices via comments.
        """
        ip_map: Dict[str, Tuple[str, str, str]] = {}
        mac_map: Dict[str, Tuple[str, str, str]] = {}
        for lease in self.get_dhcp_leases():
            ip = lease.get('address', '').strip()
            mac = lease.get('mac-address', '').strip().lower()
            dhcp_hostname = lease.get('host-name', '').strip()
            comment = lease.get('comment', '').strip()
            last_seen = lease.get('last-seen', '').strip()

            name = comment or dhcp_hostname
            source = 'MikroTik/comment' if comment else 'MikroTik/DHCP'

            if ip:
                ip_map[ip] = (name or '', source if name else '', last_seen)
            if mac:
                mac_map[mac] = (name or '', source if name else '', last_seen)
        return ip_map, mac_map


class AsusClient:
    """Fetch client data from Asus router via SSH.

    Reads /jffs/nmp_cl_json.js for client metadata (names, online status,
    connection timestamps) and /tmp/dnsmasq.leases for IP-MAC mappings.
    """

    def __init__(self, host: str, username: str, ssh_key: str):
        self.host = host
        self.username = username
        self.ssh_key = ssh_key
        self._reachable: Optional[bool] = None

    def is_reachable(self) -> bool:
        """Quick check whether SSH port is open on the router."""
        if self._reachable is None:
            self._reachable = _host_reachable(self.host, 22)
        return self._reachable

    def _ssh(self, command: str, timeout: float = 10) -> str:
        """Run a command on the router via SSH and return stdout."""
        cmd = [
            'ssh', '-i', self.ssh_key,
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', f'ConnectTimeout={int(timeout)}',
            '-o', 'BatchMode=yes',
            f'{self.username}@{self.host}',
            command,
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout + 5, check=False,
            **_SUBPROCESS_FLAGS,
        )
        if result.returncode != 0 and not result.stdout.strip():
            raise RuntimeError(f'SSH failed ({result.returncode}): {result.stderr.strip()}')
        return result.stdout

    def get_clients(self) -> List[dict]:
        """Fetch all known clients with IP, MAC, hostname, online status,
        connection timestamp, and wireless band.

        Returns list of dicts with keys:
            ip, mac, name, online, conn_ts, band, rssi
        """
        if not self.is_reachable():
            return []

        # 1. Client metadata from nmp_cl_json.js
        try:
            raw = self._ssh('cat /jffs/nmp_cl_json.js')
            nmp_data = json.loads(raw)
        except Exception as e:
            print(f'[Asus] Failed to read nmp_cl_json.js: {e}')
            nmp_data = {}

        # 2. DHCP leases for IP-MAC mapping
        mac_to_ip: Dict[str, str] = {}
        try:
            leases_raw = self._ssh('cat /var/lib/misc/dnsmasq.leases')
            for line in leases_raw.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 4:
                    mac = parts[1].upper()
                    ip = parts[2]
                    mac_to_ip[mac] = ip
        except Exception as e:
            print(f'[Asus] Failed to read dnsmasq.leases: {e}')

        # 3. WiFi client list for band info and assoc list per interface
        wifi_info: Dict[str, dict] = {}  # mac -> {band, rssi}
        iface_clients: Dict[str, List[str]] = {}  # iface -> [mac, ...]
        try:
            raw = self._ssh('cat /tmp/clientlist.json')
            cl_data = json.loads(raw)
            for _router_mac, bands in cl_data.items():
                for band_name, band_clients in bands.items():
                    for mac, info in band_clients.items():
                        wifi_info[mac.upper()] = {
                            'band': band_name,
                            'rssi': info.get('rssi', ''),
                        }
        except Exception as e:
            print(f'[Asus] Failed to read clientlist.json: {e}')

        # 4. Get "in network" seconds from wl sta_info for each WiFi client
        # eth2 = 2.4GHz, eth3 = 5GHz on RT-AX57
        sta_duration: Dict[str, int] = {}  # mac -> seconds
        try:
            # Build a single SSH command that queries all associated clients
            cmds = []
            for iface in ('eth2', 'eth3'):
                cmds.append(
                    f'for mac in $(wl -i {iface} assoclist 2>/dev/null '
                    f'| awk \'{{print $2}}\'); do '
                    f'echo "STA:$mac"; '
                    f'wl -i {iface} sta_info $mac 2>/dev/null '
                    f'| grep "in network"; done'
                )
            raw = self._ssh(' ; '.join(cmds), timeout=15)
            current_mac = ''
            for line in raw.strip().split('\n'):
                line = line.strip()
                if line.startswith('STA:'):
                    current_mac = line[4:].upper()
                elif 'in network' in line and current_mac:
                    m = re.search(r'in network\s+(\d+)\s+seconds', line)
                    if m:
                        sta_duration[current_mac] = int(m.group(1))
        except Exception as e:
            print(f'[Asus] Failed to get sta_info: {e}')

        # Merge everything
        clients: List[dict] = []
        seen_macs: set = set()
        for mac_key, entry in nmp_data.items():
            mac = entry.get('mac', mac_key).upper()
            if mac in seen_macs:
                continue
            seen_macs.add(mac)
            ip = mac_to_ip.get(mac, '')
            online = entry.get('online', 0) == 1
            wi = wifi_info.get(mac, {})

            # Use real WiFi association time from sta_info
            duration_secs = sta_duration.get(mac, 0)

            clients.append({
                'ip': ip,
                'mac': mac,
                'name': entry.get('name', ''),
                'online': online,
                'duration_secs': duration_secs,
                'band': wi.get('band', ''),
                'rssi': wi.get('rssi', ''),
                'vendor': entry.get('vendorclass', ''),
            })

        return clients

    @staticmethod
    def format_duration(seconds: int) -> str:
        """Format seconds into HH:MM:SS like the Asus web UI."""
        if seconds <= 0:
            return ''
        h = seconds // 3600
        m = (seconds % 3600) // 60
        s = seconds % 60
        return f'{h:02d}:{m:02d}:{s:02d}'


class NetworkScannerThread(QThread):
    """Thread for running network scan to avoid blocking UI.

    Primary source: Asus router SSH or MikroTik DHCP leases.
    Secondary: local ARP table — arp-scan on Linux, 'arp -a' on Windows.
    The two are merged so devices not in DHCP (e.g. static IPs) still appear.
    """
    device_found = pyqtSignal(str, str, str)  # ip, mac, vendor_raw
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    # Asus clients carry extra metadata; stored here for the resolver
    asus_clients: List[dict] = []

    def __init__(self, mikrotik_client: Optional['MikroTikClient'] = None,
                 asus_client: Optional['AsusClient'] = None,
                 iface: Optional[str] = None):
        super().__init__()
        self.mikrotik_client = mikrotik_client
        self.asus_client = asus_client
        self.iface = iface
        self.asus_clients = []

    def run(self):
        seen_ips: set[str] = set()
        devices: List[Tuple[str, str, str]] = []

        # 1a. Asus router (primary when configured)
        if self.asus_client:
            try:
                self.asus_clients = self.asus_client.get_clients()
                for cl in self.asus_clients:
                    if not cl.get('online'):
                        continue
                    ip = cl['ip']
                    mac = cl['mac']
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        devices.append((ip, mac, ''))
                        self.device_found.emit(ip, mac, '')
            except Exception as e:
                print(f'[Asus] client fetch in scanner: {e}')

        # 1b. MikroTik DHCP leases (if no Asus client)
        if self.mikrotik_client and not self.asus_client:
            try:
                for lease in self.mikrotik_client.get_dhcp_leases():
                    ip = lease.get('active-address', '').strip() or lease.get('address', '').strip()
                    mac = (lease.get('active-mac-address', '') or lease.get('mac-address', '')).strip().upper()
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        devices.append((ip, mac, ''))
                        self.device_found.emit(ip, mac, '')
            except Exception as e:
                print(f'[MikroTik] lease fetch in scanner: {e}')

        # 2. Local ARP table (supplement — catches static-IP devices)
        try:
            local_devices = self._local_arp_scan(self.iface)
            for ip, mac, vendor in local_devices:
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    devices.append((ip, mac, vendor))
                    self.device_found.emit(ip, mac, vendor)
        except Exception as e:
            print(f'[ARP] local scan: {e}')

        if not devices:
            self.error.emit('No devices found. Check network connection and router credentials.')
            return

        self.finished.emit(devices)

    # ---- platform-specific ARP ----

    @staticmethod
    def _local_arp_scan(iface: Optional[str] = None) -> List[Tuple[str, str, str]]:
        if IS_WINDOWS:
            return NetworkScannerThread._arp_windows(iface)
        return NetworkScannerThread._arp_linux(iface)

    @staticmethod
    def _is_noarp(iface: str) -> bool:
        """Return True if the interface has the NOARP flag (e.g. WireGuard, tun)."""
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', iface],
                capture_output=True, text=True, timeout=5, check=False,
            )
            return 'NOARP' in result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False

    @staticmethod
    def _is_wireguard(iface: str) -> bool:
        """Return True if wg recognises the interface as a WireGuard interface."""
        try:
            result = subprocess.run(
                ['wg', 'show', iface],
                capture_output=True, text=True, timeout=5, check=False,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False

    @staticmethod
    def _tailscale_scan() -> List[Tuple[str, str, str]]:
        """Return peer IPv4 addresses from 'tailscale status --json'."""
        devices: List[Tuple[str, str, str]] = []
        try:
            result = subprocess.run(
                ['tailscale', 'status', '--json'],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if result.returncode != 0:
                return devices
            data = json.loads(result.stdout)
            seen: set[str] = set()
            for peer in data.get('Peer', {}).values():
                for ip in peer.get('TailscaleIPs', []):
                    if ':' not in ip and ip not in seen:  # IPv4 only
                        seen.add(ip)
                        devices.append((ip, '', ''))
        except (subprocess.TimeoutExpired, FileNotFoundError,
                subprocess.SubprocessError, json.JSONDecodeError):
            pass
        return devices

    @staticmethod
    def _wireguard_scan(iface: str) -> List[Tuple[str, str, str]]:
        """Return peer IPv4 host addresses from 'wg show <iface> allowed-ips'.

        Only /32 routes are used — these are individual peer IPs.
        Catch-all routes like 0.0.0.0/0 are ignored.
        """
        devices: List[Tuple[str, str, str]] = []
        try:
            result = subprocess.run(
                ['wg', 'show', iface, 'allowed-ips'],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if result.returncode != 0:
                return devices
            seen: set[str] = set()
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) < 2:
                    continue
                for cidr in parts[1:]:
                    if '/' not in cidr:
                        continue
                    ip, prefix = cidr.rsplit('/', 1)
                    if prefix == '32' and ':' not in ip and ip not in seen:
                        seen.add(ip)
                        devices.append((ip, '', ''))
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        return devices

    @staticmethod
    def _get_iface_addr(iface: str) -> Optional[Tuple[str, int]]:
        """Return (ip, prefix_len) of the first IPv4 address on the interface."""
        try:
            result = subprocess.run(
                ['ip', '-o', 'addr', 'show', 'dev', iface],
                capture_output=True, text=True, timeout=5, check=False,
            )
            for line in result.stdout.split('\n'):
                m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                if m:
                    return m.group(1), int(m.group(2))
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        return None

    @staticmethod
    def _ping_sweep_noarp(iface: str) -> List[Tuple[str, str, str]]:
        """Parallel ping sweep for NOARP interfaces (WireGuard, tun, etc.).

        Derives the /24 subnet from the interface address and pings all 254
        hosts simultaneously, returning those that respond.
        """
        addr_info = NetworkScannerThread._get_iface_addr(iface)
        if not addr_info:
            return []
        local_ip, _ = addr_info
        # Always sweep a /24 derived from the interface IP to avoid scanning
        # thousands of hosts on wider subnets.
        prefix = '.'.join(local_ip.split('.')[:3])

        procs: Dict[str, subprocess.Popen] = {}
        for i in range(1, 255):
            ip = f'{prefix}.{i}'
            if ip == local_ip:
                continue
            procs[ip] = subprocess.Popen(
                ['ping', '-c1', '-W1', ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        devices: List[Tuple[str, str, str]] = []
        for ip, proc in procs.items():
            try:
                if proc.wait(timeout=3) == 0:
                    devices.append((ip, '', ''))
            except subprocess.TimeoutExpired:
                proc.kill()
        return devices

    @staticmethod
    def _arp_linux(iface: Optional[str] = None) -> List[Tuple[str, str, str]]:
        """Try arp-scan first, fall back to 'ip neigh'.
        For Tailscale/WireGuard/NOARP interfaces use specialised peer discovery."""
        if iface == 'tailscale0':
            return NetworkScannerThread._tailscale_scan()

        if iface and NetworkScannerThread._is_wireguard(iface):
            return NetworkScannerThread._wireguard_scan(iface)

        # Generic NOARP interfaces (tun, etc.) — fall back to ping sweep.
        if iface and NetworkScannerThread._is_noarp(iface):
            return NetworkScannerThread._ping_sweep_noarp(iface)

        devices: List[Tuple[str, str, str]] = []
        seen: set[str] = set()

        # Try arp-scan
        try:
            cmd = ['sudo', 'arp-scan', '--localnet']
            if iface:
                cmd += ['-I', iface]
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=30, check=False,
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    m = re.match(r'^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17})\s+(.*)$', line)
                    if m:
                        ip = m.group(1)
                        if ip not in seen:
                            seen.add(ip)
                            devices.append((ip, m.group(2).upper(), m.group(3).strip()))
                if devices:
                    return devices
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass

        # Fallback: ip neigh
        try:
            cmd = ['ip', 'neigh', 'show']
            if iface:
                cmd += ['dev', iface]
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=5, check=False,
            )
            for line in result.stdout.split('\n'):
                parts = line.split()
                if len(parts) >= 5 and parts[2] == 'lladdr':
                    ip = parts[0]
                    mac = parts[4].upper()
                    if ip not in seen and re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                        seen.add(ip)
                        devices.append((ip, mac, ''))
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass

        return devices

    @staticmethod
    def _arp_windows(iface: Optional[str] = None) -> List[Tuple[str, str, str]]:
        """Ping-sweep the local /24 subnet, then parse 'arp -a'."""
        # Detect local subnet from the default gateway
        subnet_prefix = NetworkScannerThread._detect_subnet_windows()

        # Ping sweep to populate ARP cache (fast, parallel via cmd)
        if subnet_prefix:
            NetworkScannerThread._ping_sweep_windows(subnet_prefix)

        devices: List[Tuple[str, str, str]] = []
        seen: set[str] = set()
        try:
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True, text=True, timeout=10, check=False,
                **_SUBPROCESS_FLAGS,
            )
            for line in result.stdout.split('\n'):
                # Typical: "  192.168.0.1          aa-bb-cc-dd-ee-ff     dynamic"
                m = re.match(
                    r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+\w+',
                    line,
                )
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace('-', ':').upper()
                    if ip not in seen and not ip.endswith('.255'):
                        seen.add(ip)
                        devices.append((ip, mac, ''))
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        return devices

    @staticmethod
    def _detect_subnet_windows() -> Optional[str]:
        """Return the first 3 octets of the local subnet, e.g. '192.168.0'."""
        try:
            result = subprocess.run(
                ['ipconfig'],
                capture_output=True, text=True, timeout=5, check=False,
                **_SUBPROCESS_FLAGS,
            )
            # Find lines like "IPv4 Address. . . . . . . . . . . : 192.168.0.225"
            for line in result.stdout.split('\n'):
                m = re.search(r'IPv4.*?:\s*(\d+\.\d+\.\d+)\.\d+', line)
                if m:
                    prefix = m.group(1)
                    # Skip loopback and link-local
                    if not prefix.startswith('127.') and not prefix.startswith('169.254.'):
                        return prefix
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        return None

    @staticmethod
    def _ping_sweep_windows(subnet_prefix: str):
        """Fire off parallel pings to .1-.254 using a single cmd /c for loop.
        Waits up to 15s for the batch to finish."""
        try:
            cmd = (
                f'for /L %i in (1,1,254) do @start /b ping -n 1 -w 300 '
                f'{subnet_prefix}.%i >nul 2>&1'
            )
            subprocess.run(
                ['cmd', '/c', cmd],
                capture_output=True, text=True, timeout=20, check=False,
                **_SUBPROCESS_FLAGS,
            )
            # Brief pause to let ARP cache settle
            time.sleep(2)
        except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass


class MdnsCache:
    """Cache for mDNS/Avahi discovered hostnames (IP -> name)."""

    def __init__(self):
        self.cache: dict[str, str] = {}

    def refresh(self):
        """Run avahi-browse to discover mDNS device names on the LAN."""
        self.cache.clear()
        try:
            result = subprocess.run(
                ['avahi-browse', '-atrp'],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
            if result.returncode != 0:
                return

            for line in result.stdout.split('\n'):
                if not line.startswith('='):
                    continue
                parts = line.split(';')
                # Format: =;iface;proto;name;type;domain;host;address;port;txt
                if len(parts) < 9:
                    continue
                ip_addr = parts[7].strip()
                raw_name = parts[3].strip()
                if not ip_addr or not raw_name:
                    continue

                # Decode avahi escapes (\032 = space, \058 = colon, etc.)
                name = self._decode_avahi(raw_name)

                # Skip names that look like hashes / UUIDs / JSON blobs
                if name.startswith('{') or len(name) > 60:
                    continue

                # Also try to extract a friendlier name from TXT "name=" field
                txt = parts[9] if len(parts) > 9 else ''
                friendly = self._extract_txt_name(txt)
                if friendly:
                    name = friendly

                # First name per IP wins (avahi lists multiple services)
                if ip_addr not in self.cache:
                    self.cache[ip_addr] = name
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass

    @staticmethod
    def _decode_avahi(s: str) -> str:
        """Decode avahi-browse escaped strings (\\032 -> space, etc.)."""
        def _repl(m):
            return chr(int(m.group(1)))
        return re.sub(r'\\(\d{3})', _repl, s)

    @staticmethod
    def _extract_txt_name(txt: str) -> Optional[str]:
        """Extract 'name=...' from avahi TXT record field."""
        m = re.search(r'"name=([^"]+)"', txt)
        if m:
            return m.group(1).strip()
        return None

    def lookup(self, ip: str) -> Optional[str]:
        return self.cache.get(ip)


class EtcHostsCache:
    """Cache for hosts file entries (IP -> hostname). Works on Linux and Windows."""

    HOSTS_PATH = (r'C:\Windows\System32\drivers\etc\hosts' if IS_WINDOWS
                  else '/etc/hosts')

    def __init__(self):
        self.cache: dict[str, str] = {}
        self._load()

    def _load(self):
        try:
            with open(self.HOSTS_PATH, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        hostname = parts[1]
                        # Skip loopback aliases
                        if ip.startswith('127.') or ip.startswith('::'):
                            continue
                        self.cache[ip] = hostname
        except OSError:
            pass

    def lookup(self, ip: str) -> Optional[str]:
        return self.cache.get(ip)


class HostnameResolverThread(QThread):
    """Thread for resolving hostnames to avoid blocking UI.

    All devices are resolved in parallel via a ThreadPoolExecutor.

    Resolution order per IP:
        0. Asus router     (SSH client data — names + connection duration)
        0b. MikroTik DHCP  (admin comments + DHCP host-name from the router)
        1. mDNS / Avahi   (per-device avahi-resolve, concurrent across devices)
        2. Reverse DNS     (PTR records — routers, servers)
        3. NetBIOS         (Windows / Samba machines)
        4. /etc/hosts      (static local mappings)
        5. MikroTik by MAC (fallback: match by MAC when IP changed)
    """
    resolved = pyqtSignal(str, str, str, str)  # ip, hostname, method, last_seen
    finished = pyqtSignal()

    def __init__(self, devices: List[Tuple[str, str, str]],
                 mikrotik_client: Optional[MikroTikClient] = None,
                 asus_clients: Optional[List[dict]] = None):
        super().__init__()
        self.devices = devices
        self.mikrotik_client = mikrotik_client
        self.etc_hosts = EtcHostsCache()
        # Asus data indexed by IP and MAC
        self.asus_by_ip: Dict[str, dict] = {}
        self.asus_by_mac: Dict[str, dict] = {}
        if asus_clients:
            for cl in asus_clients:
                if cl.get('ip'):
                    self.asus_by_ip[cl['ip']] = cl
                if cl.get('mac'):
                    self.asus_by_mac[cl['mac'].upper()] = cl
        # Filled at run-time  {ip/mac: (name, source, last_seen)}
        self.mt_ip_map: Dict[str, Tuple[str, str, str]] = {}
        self.mt_mac_map: Dict[str, Tuple[str, str, str]] = {}

    def run(self):
        # Pre-fetch MikroTik DHCP leases (single HTTP call, ~0.5 s)
        if self.mikrotik_client:
            self.mt_ip_map, self.mt_mac_map = self.mikrotik_client.build_hostname_maps()

        # Resolve all devices in parallel; per-device avahi-resolve calls are
        # themselves concurrent so mDNS no longer blocks on a batch sweep.
        max_workers = min(32, max(8, len(self.devices)))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self._resolve, ip, mac): ip
                       for ip, mac, _ in self.devices}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    hostname, method, last_seen = future.result()
                except Exception:
                    hostname, method, last_seen = None, '', ''
                self.resolved.emit(ip, hostname or '(Unknown)', method, last_seen)
        self.finished.emit()

    def _resolve(self, ip: str, mac: str) -> Tuple[Optional[str], str, str]:
        """Try multiple resolution strategies, return first success.
        Returns (hostname, method, last_seen)."""

        # 0. Asus router data (by IP then MAC)
        asus_entry = self.asus_by_ip.get(ip)
        if not asus_entry and mac:
            asus_entry = self.asus_by_mac.get(mac.upper())

        if asus_entry:
            duration = AsusClient.format_duration(asus_entry.get('duration_secs', 0))
            name = asus_entry.get('name', '')
            if name and name != '*':
                return name, 'Asus/DHCP', duration

        # Always grab last_seen from MikroTik if available (even if name
        # comes from another source)
        mt_entry = self.mt_ip_map.get(ip)
        last_seen = mt_entry[2] if mt_entry else ''
        if not last_seen and mac:
            mac_entry = self.mt_mac_map.get(mac.lower())
            last_seen = mac_entry[2] if mac_entry else ''
        # If we have Asus duration, prefer it over MikroTik last_seen
        if asus_entry:
            duration = AsusClient.format_duration(asus_entry.get('duration_secs', 0))
            if duration:
                last_seen = duration

        # 0. MikroTik DHCP lease (by IP) — name resolution
        if mt_entry and mt_entry[0]:
            return mt_entry[0], mt_entry[1], last_seen

        # 1. mDNS / Avahi (Linux only) — runs concurrently across devices
        if not IS_WINDOWS:
            name = self._avahi_resolve(ip)
            if name:
                return name, 'mDNS', last_seen

        # 3. Reverse DNS (PTR)
        name = self._reverse_dns(ip)
        if name:
            return name, 'DNS', last_seen

        # 4. NetBIOS (Windows / Samba)
        name = self._netbios(ip)
        if name:
            return name, 'NetBIOS', last_seen

        # 5. /etc/hosts
        name = self.etc_hosts.lookup(ip)
        if name:
            return name, '/etc/hosts', last_seen

        # 6. MikroTik by MAC (fallback for hostname)
        if mac:
            mac_entry = self.mt_mac_map.get(mac.lower())
            if mac_entry and mac_entry[0]:
                return mac_entry[0], mac_entry[1], last_seen

        # 7. SSH hostname (last resort — works on mobile hotspot for Pis)
        name = self._ssh_hostname(ip)
        if name:
            return name, 'SSH', last_seen

        return None, '', last_seen

    # ---- individual resolvers ----

    @staticmethod
    def _avahi_resolve(ip: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ['avahi-resolve', '-a', ip],
                capture_output=True, text=True, timeout=2, check=False,
            )
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    hostname = parts[1].rstrip('.')
                    if hostname:
                        return hostname
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        return None

    @staticmethod
    def _reverse_dns(ip: str) -> Optional[str]:
        old_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(1.5)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError, socket.timeout):
            return None
        finally:
            socket.setdefaulttimeout(old_timeout)

    @staticmethod
    def _netbios(ip: str) -> Optional[str]:
        if IS_WINDOWS:
            return HostnameResolverThread._netbios_windows(ip)
        return HostnameResolverThread._netbios_linux(ip)

    @staticmethod
    def _netbios_linux(ip: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ['nmblookup', '-A', ip],
                capture_output=True, text=True, timeout=2, check=False,
            )
            for line in result.stdout.split('\n'):
                if '<00>' in line and 'GROUP' not in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1].split('<')[0]
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        return None

    @staticmethod
    def _ssh_hostname(ip: str) -> Optional[str]:
        """Try to get hostname via SSH (works on mobile hotspot for known devices)."""
        try:
            result = subprocess.run(
                [
                    'ssh', '-i', DEVICE_SSH_KEY,
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null',
                    '-o', 'ConnectTimeout=2',
                    '-o', 'BatchMode=yes',
                    f'{DEVICE_SSH_USER}@{ip}',
                    'hostname',
                ],
                capture_output=True, text=True, timeout=5, check=False,
                **_SUBPROCESS_FLAGS,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        return None

    @staticmethod
    def _netbios_windows(ip: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ['nbtstat', '-A', ip],
                capture_output=True, text=True, timeout=3, check=False,
                **_SUBPROCESS_FLAGS,
            )
            for line in result.stdout.split('\n'):
                if '<00>' in line and 'GROUP' not in line and 'UNIQUE' in line:
                    name = line.split('<')[0].strip()
                    if name:
                        return name
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        return None


class MacVendorDB:
    """MAC vendor database using IEEE OUI."""
    
    def __init__(self):
        self.db_path = Path.home() / '.cache' / 'hosts_app' / 'oui_db.json'
        self.db = {}
        self.load_db()

    def load_db(self):
        """Load vendor database from cache or download."""
        if self.db_path.exists():
            try:
                with open(self.db_path, 'r') as f:
                    self.db = json.load(f)
                return
            except Exception:
                pass
        
        # Download if not exists
        self.update_db()

    def update_db(self):
        """Download and update OUI database from IEEE."""
        try:
            print("Downloading OUI database from IEEE...")
            url = "https://standards-oui.ieee.org/oui/oui.txt"
            
            # Create request with proper headers to avoid 418 error
            from urllib.request import Request
            req = Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
            req.add_header('Accept', 'text/plain,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
            req.add_header('Accept-Language', 'en-US,en;q=0.5')
            
            with urlopen(req, timeout=30) as response:
                data = response.read().decode('utf-8')
            
            # Parse OUI file
            self.db = {}
            for line in data.split('\n'):
                if '(base 16)' in line:
                    parts = line.split('(base 16)')
                    if len(parts) == 2:
                        oui = parts[0].strip().replace('-', ':').upper()
                        vendor = parts[1].strip()
                        # Normalize OUI (remove colons for lookup)
                        oui_key = oui.replace(':', '').upper()[:6]
                        self.db[oui_key] = vendor
            
            # Save to cache
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.db_path, 'w') as f:
                json.dump(self.db, f)
            
            print(f"Downloaded {len(self.db)} vendor entries")
        except URLError as e:
            print(f"Failed to download OUI database: {e}")
            # Try alternative URL (Wireshark manuf file)
            try:
                print("Trying alternative OUI database source (Wireshark)...")
                alt_url = "https://www.wireshark.org/download/automated/data/manuf"
                req = Request(alt_url)
                req.add_header('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
                with urlopen(req, timeout=30) as response:
                    data = response.read().decode('utf-8')
                
                # Parse Wireshark format (different from IEEE format)
                self.db = {}
                for line in data.split('\n'):
                    if line and not line.startswith('#') and '\t' in line:
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            oui = parts[0].strip().replace(':', '').upper()[:6]
                            vendor = parts[1].strip()
                            if oui and len(oui) == 6:
                                self.db[oui] = vendor
                
                # Save to cache
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.db_path, 'w') as f:
                    json.dump(self.db, f)
                print(f"Downloaded {len(self.db)} vendor entries from alternative source")
            except Exception as e2:
                print(f"Alternative source also failed: {e2}")
                self.db = {}
        except Exception as e:
            print(f"Error updating database: {e}")
            self.db = {}

    def lookup(self, mac: str) -> str:
        """Look up vendor for MAC address."""
        # Normalize MAC address
        mac_clean = mac.replace(':', '').replace('-', '').upper()
        if len(mac_clean) >= 6:
            oui = mac_clean[:6]
            return self.db.get(oui, 'Unknown')
        return 'Unknown'


class IpAddressItem(QTableWidgetItem):
    """QTableWidgetItem that sorts IP addresses naturally (by numeric octets)."""

    def __init__(self, ip: str):
        super().__init__(ip)
        try:
            self._key = tuple(int(o) for o in ip.split('.'))
        except (ValueError, AttributeError):
            self._key = (999, 999, 999, 999)

    def __lt__(self, other):
        if isinstance(other, IpAddressItem):
            return self._key < other._key
        return super().__lt__(other)


class LastSeenItem(QTableWidgetItem):
    """QTableWidgetItem that sorts by the underlying seconds value.
    Empty values (seconds < 0) always sort to the bottom."""

    def __init__(self, display: str, seconds: int):
        super().__init__(display)
        self._seconds = seconds

    def __lt__(self, other):
        if isinstance(other, LastSeenItem):
            # Push empty (-1) to the bottom regardless of sort direction:
            # When ascending: empty is "not less than" anything → goes last
            # When descending: empty is "less than" everything → goes last
            if self._seconds < 0 and other._seconds >= 0:
                return False
            if other._seconds < 0 and self._seconds >= 0:
                return True
            return self._seconds < other._seconds
        return super().__lt__(other)


class DeviceIdResolverThread(QThread):
    """SSH into devices to fetch their device ID from /root/config.ini.

    Only targets devices whose hostname matches DEVICE_ID_HOSTNAMES.
    All SSH calls run in parallel via ThreadPoolExecutor.
    """
    resolved = pyqtSignal(str, str)  # ip, device_id
    finished = pyqtSignal()

    def __init__(self, devices: List[Tuple[str, str]]):
        """devices: list of (ip, hostname) pairs to query."""
        super().__init__()
        self.devices = devices

    def run(self):
        max_workers = min(16, max(4, len(self.devices)))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self._fetch_id, ip): ip
                       for ip, _hostname in self.devices}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    device_id = future.result()
                except Exception:
                    device_id = ''
                if device_id:
                    self.resolved.emit(ip, device_id)
        self.finished.emit()

    @staticmethod
    def _fetch_id(ip: str) -> str:
        """SSH into device and extract device ID from first line of config.ini."""
        try:
            result = subprocess.run(
                [
                    'ssh', '-i', DEVICE_SSH_KEY,
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null',
                    '-o', 'ConnectTimeout=5',
                    '-o', 'BatchMode=yes',
                    f'{DEVICE_SSH_USER}@{ip}',
                    'sudo cat /root/config.ini',
                ],
                capture_output=True, text=True, timeout=10, check=False,
                **_SUBPROCESS_FLAGS,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return ''
            first_line = result.stdout.strip().split('\n')[0]
            # Format: RD_<12 hex chars><device_id>  e.g. RD_b3c528d36857CDMA_CM4_2
            m = re.match(r'^RD_[0-9a-fA-F]{12}(.+)$', first_line)
            if m:
                return m.group(1)
            return ''
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return ''


class HostsApp(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.vendor_db = MacVendorDB()
        self.scanner_thread = None
        self.hostname_thread = None
        self.device_id_thread = None
        self.devices = []
        self.mikrotik_client = MikroTikClient(
            host=MIKROTIK_HOST,
            username=MIKROTIK_USER,
            password=MIKROTIK_PASS,
        )
        self.asus_client = AsusClient(
            host=ASUS_HOST,
            username=ASUS_USER,
            ssh_key=ASUS_SSH_KEY,
        )
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle('Hosts List - Ebaka Network Scanner')
        self.setGeometry(100, 100, 1100, 600)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # Header with refresh button
        header_layout = QHBoxLayout()
        title = QLabel('Network Devices')
        title.setFont(QFont('Arial', 16, QFont.Weight.Bold))
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        iface_label = QLabel('Interface:')
        header_layout.addWidget(iface_label)

        self.iface_combo = QComboBox()
        self.iface_combo.addItem('All interfaces', userData=None)
        for iface in get_local_interfaces():
            self.iface_combo.addItem(iface, userData=iface)
        self.iface_combo.setMinimumWidth(120)
        header_layout.addWidget(self.iface_combo)

        self.refresh_btn = QPushButton('Refresh')
        self.refresh_btn.setMinimumWidth(100)
        self.refresh_btn.clicked.connect(self.scan_network)
        header_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(header_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            'IP Address', 'MAC Address', 'Hostname', 'Device ID', 'Method', 'Access Time', 'Vendor',
        ])
        self.table.setSortingEnabled(True)

        # Configure table
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        
        # Make IP addresses clickable, Device ID double-clickable
        self.table.cellClicked.connect(self.on_cell_clicked)
        self.table.cellDoubleClicked.connect(self.on_cell_double_clicked)
        
        layout.addWidget(self.table)
        
        # Status bar
        self.statusBar().showMessage('Ready. Click Refresh to scan network.')
        
        # Auto-refresh on startup
        QTimer.singleShot(500, self.scan_network)

    def scan_network(self):
        """Start network scan in background thread."""
        if self.scanner_thread and self.scanner_thread.isRunning():
            return
        
        self.refresh_btn.setEnabled(False)
        self.statusBar().showMessage('Scanning network...')
        self.table.setRowCount(0)
        self.table.setSortingEnabled(False)

        # Reset reachability cache so network changes are detected
        self.asus_client._reachable = None
        self.mikrotik_client._reachable = None

        iface = self.iface_combo.currentData()
        self.scanner_thread = NetworkScannerThread(
            self.mikrotik_client, asus_client=self.asus_client, iface=iface,
        )
        self.scanner_thread.device_found.connect(self.on_device_found)
        self.scanner_thread.finished.connect(self.on_scan_finished)
        self.scanner_thread.error.connect(self.on_scan_error)
        self.scanner_thread.start()

    def on_device_found(self, ip: str, mac: str, vendor_raw: str):
        """Add a single device row as soon as it is discovered."""
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, IpAddressItem(ip))
        self.table.setItem(row, 1, QTableWidgetItem(mac))
        self.table.setItem(row, 2, QTableWidgetItem('Resolving...'))
        self.table.setItem(row, 3, QTableWidgetItem(''))  # Device ID
        self.table.setItem(row, 4, QTableWidgetItem(''))  # Method
        self.table.setItem(row, 5, LastSeenItem('', -1))
        vendor = self.vendor_db.lookup(mac)
        if vendor == 'Unknown' and vendor_raw and vendor_raw != '(Unknown)':
            vendor = vendor_raw
        self.table.setItem(row, 6, QTableWidgetItem(vendor))

    def on_scan_finished(self, devices: List[Tuple[str, str, str]]):
        """Kick off hostname resolution once scanning is complete."""
        self.devices = devices
        self.resolve_hostnames(devices)

    def resolve_hostnames(self, devices: List[Tuple[str, str, str]]):
        """Resolve hostnames for all devices."""
        if self.hostname_thread and self.hostname_thread.isRunning():
            return
        
        asus_clients = self.scanner_thread.asus_clients if self.scanner_thread else []
        self.hostname_thread = HostnameResolverThread(
            devices, self.mikrotik_client, asus_clients=asus_clients,
        )
        self.hostname_thread.resolved.connect(self.on_hostname_resolved)
        self.hostname_thread.finished.connect(self.on_hostnames_finished)
        self.hostname_thread.start()

    def on_hostname_resolved(self, ip: str, hostname: str, method: str, last_seen: str):
        """Update hostname and last-seen in table."""
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0) and self.table.item(row, 0).text() == ip:
                self.table.setItem(row, 2, QTableWidgetItem(hostname))
                if method:
                    self.table.setItem(row, 4, QTableWidgetItem(method))
                if last_seen:
                    # Parse HH:MM:SS (Asus) or MikroTik duration
                    hms = re.match(r'^(\d+):(\d+):(\d+)$', last_seen)
                    if hms:
                        secs = int(hms.group(1)) * 3600 + int(hms.group(2)) * 60 + int(hms.group(3))
                    else:
                        secs = MikroTikClient.parse_duration(last_seen)
                    self.table.setItem(row, 5, LastSeenItem(last_seen, secs))
                break

    def on_hostnames_finished(self):
        """Hostname resolution completed — start device ID resolution."""
        self.table.setSortingEnabled(True)
        # Default sort: Access Time ascending (most recently connected first)
        self.table.sortItems(5, Qt.SortOrder.AscendingOrder)
        self.statusBar().showMessage(f'Found {len(self.devices)} devices — fetching device IDs...')

        # Collect "ebaka" devices to query for device ID
        targets: List[Tuple[str, str]] = []
        for row in range(self.table.rowCount()):
            hostname_item = self.table.item(row, 2)
            ip_item = self.table.item(row, 0)
            if hostname_item and ip_item:
                hostname = hostname_item.text().strip().lower()
                if hostname in DEVICE_ID_HOSTNAMES:
                    targets.append((ip_item.text(), hostname))

        if targets:
            self.device_id_thread = DeviceIdResolverThread(targets)
            self.device_id_thread.resolved.connect(self.on_device_id_resolved)
            self.device_id_thread.finished.connect(self.on_device_ids_finished)
            self.device_id_thread.start()
        else:
            self.refresh_btn.setEnabled(True)

    def on_device_id_resolved(self, ip: str, device_id: str):
        """Update Device ID column for a device."""
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0) and self.table.item(row, 0).text() == ip:
                self.table.setItem(row, 3, QTableWidgetItem(device_id))
                break

    def on_device_ids_finished(self):
        """Device ID resolution completed."""
        self.refresh_btn.setEnabled(True)
        self.statusBar().showMessage(f'Found {len(self.devices)} devices')

    def on_scan_error(self, error: str):
        """Handle scan error."""
        self.refresh_btn.setEnabled(True)
        self.statusBar().showMessage('Error: ' + error)
        QMessageBox.warning(self, 'Scan Error', error)

    def on_cell_clicked(self, row: int, col: int):
        """Handle cell click - copy IP if clicked on IP column."""
        if col == 0:  # IP Address column
            ip = self.table.item(row, col).text()
            clipboard = QApplication.clipboard()
            clipboard.setText(ip)
            self.statusBar().showMessage(f'Copied {ip} to clipboard', 2000)

    def on_cell_double_clicked(self, row: int, col: int):
        """Handle double-click — open config editor for Device ID column."""
        if col != 3:  # Device ID column
            return
        ip_item = self.table.item(row, 0)
        hostname_item = self.table.item(row, 2)
        if not ip_item or not hostname_item:
            return
        hostname = hostname_item.text().strip().lower()
        if hostname not in DEVICE_ID_HOSTNAMES:
            return
        ip = ip_item.text()
        dlg = ConfigEditorDialog(ip, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            # Refresh the Device ID cell after save
            device_id = DeviceIdResolverThread._fetch_id(ip)
            if device_id:
                self.table.setItem(row, 3, QTableWidgetItem(device_id))


class ConfigEditorDialog(QDialog):
    """Dialog to edit /root/config.ini on a remote device via SSH."""

    def __init__(self, ip: str, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.setWindowTitle(f'config.ini — {ip}')
        self.resize(500, 350)

        layout = QVBoxLayout(self)

        self.editor = QTextEdit()
        self.editor.setFont(QFont('Monospace', 10))
        layout.addWidget(self.editor)

        insert_btn = QPushButton('Insert server ip')
        insert_btn.clicked.connect(self._insert_server_ip)
        layout.addWidget(insert_btn)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        restart_unpacker_btn = QPushButton('Restart unpacker')
        restart_unpacker_btn.clicked.connect(self._restart_unpacker)
        btn_layout.addWidget(restart_unpacker_btn)
        reboot_btn = QPushButton('Reboot')
        reboot_btn.clicked.connect(self._reboot)
        btn_layout.addWidget(reboot_btn)
        self.save_btn = QPushButton('Save && Restart')
        self.save_btn.clicked.connect(self._save)
        btn_layout.addWidget(self.save_btn)
        layout.addLayout(btn_layout)

        self._load()

    def _ssh_run(self, command: str, timeout: float = 10) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                'ssh', '-i', DEVICE_SSH_KEY,
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'ConnectTimeout=5',
                '-o', 'BatchMode=yes',
                f'{DEVICE_SSH_USER}@{self.ip}',
                command,
            ],
            capture_output=True, text=True, timeout=timeout, check=False,
            **_SUBPROCESS_FLAGS,
        )

    @staticmethod
    def _get_local_ip() -> str:
        """Return the local IP address used to reach the internet."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return '127.0.0.1'

    def _insert_server_ip(self):
        """Append server_ip/server_port lines at end of text."""
        local_ip = self._get_local_ip()
        cursor = self.editor.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.editor.setTextCursor(cursor)
        self.editor.insertPlainText(f'server_ip={local_ip}\nserver_port=5555\n')

    def _restart_unpacker(self):
        """Run 'sudo service unpacker restart' on the remote device."""
        try:
            result = self._ssh_run('sudo service unpacker restart')
            if result.returncode == 0:
                self.parent().statusBar().showMessage(
                    f'Unpacker restarted on {self.ip}', 3000)
            else:
                QMessageBox.warning(self, 'Error',
                                    f'Failed to restart unpacker:\n{result.stderr.strip()}')
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            QMessageBox.warning(self, 'SSH Error', str(e))

    def _reboot(self):
        """Run 'sudo reboot' on the remote device."""
        try:
            self._ssh_run('sudo reboot')
            self.parent().statusBar().showMessage(
                f'Reboot sent to {self.ip}', 3000)
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass

    def _load(self):
        """Fetch config.ini content from the device."""
        try:
            result = self._ssh_run('sudo cat /root/config.ini')
            if result.returncode == 0:
                self.editor.setPlainText(result.stdout)
            else:
                self.editor.setPlainText(f'# Error reading config.ini:\n# {result.stderr.strip()}')
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            self.editor.setPlainText(f'# SSH error: {e}')

    def _save(self):
        """Write config.ini back and run sudo pkill main."""
        content = self.editor.toPlainText()
        try:
            # Write file via stdin pipe to sudo tee
            result = subprocess.run(
                [
                    'ssh', '-i', DEVICE_SSH_KEY,
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'UserKnownHostsFile=/dev/null',
                    '-o', 'ConnectTimeout=5',
                    '-o', 'BatchMode=yes',
                    f'{DEVICE_SSH_USER}@{self.ip}',
                    'sudo tee /root/config.ini > /dev/null',
                ],
                input=content, capture_output=True, text=True,
                timeout=10, check=False, **_SUBPROCESS_FLAGS,
            )
            if result.returncode != 0:
                QMessageBox.warning(self, 'Save Error', f'Failed to save:\n{result.stderr.strip()}')
                return

            # Restart the process
            self._ssh_run('sudo pkill main')

            self.accept()
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError) as e:
            QMessageBox.warning(self, 'SSH Error', str(e))


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('Hosts List')
    
    window = HostsApp()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
