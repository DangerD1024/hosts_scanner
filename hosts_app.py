#!/usr/bin/env python3
"""
Hosts - Network Scanner GUI Application
Scans local network and displays devices with hostnames and vendor information.
"""

import sys
import subprocess
import socket
import re
import json
import ssl
import time
import platform
import base64
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
        QHeaderView, QProgressDialog, QComboBox
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
        scheme = 'https' if use_https else 'http'
        self.base_url = f'{scheme}://{host}/rest'

    # -- helpers --

    def _get(self, path: str, timeout: float = 10) -> list:
        """Perform an authenticated GET and return parsed JSON."""
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


class NetworkScannerThread(QThread):
    """Thread for running network scan to avoid blocking UI.

    Primary source: MikroTik DHCP leases (cross-platform, always available).
    Secondary: local ARP table — arp-scan on Linux, 'arp -a' on Windows.
    The two are merged so devices not in DHCP (e.g. static IPs) still appear.
    """
    device_found = pyqtSignal(str, str, str)  # ip, mac, vendor_raw
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, mikrotik_client: Optional['MikroTikClient'] = None,
                 iface: Optional[str] = None):
        super().__init__()
        self.mikrotik_client = mikrotik_client
        self.iface = iface

    def run(self):
        seen_ips: set[str] = set()
        devices: List[Tuple[str, str, str]] = []

        # 1. MikroTik DHCP leases (primary — works on every OS)
        if self.mikrotik_client:
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
            self.error.emit('No devices found. Check network connection and MikroTik credentials.')
            return

        self.finished.emit(devices)

    # ---- platform-specific ARP ----

    @staticmethod
    def _local_arp_scan(iface: Optional[str] = None) -> List[Tuple[str, str, str]]:
        if IS_WINDOWS:
            return NetworkScannerThread._arp_windows(iface)
        return NetworkScannerThread._arp_linux(iface)

    @staticmethod
    def _arp_linux(iface: Optional[str] = None) -> List[Tuple[str, str, str]]:
        """Try arp-scan first, fall back to 'ip neigh'."""
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
        0. MikroTik DHCP  (admin comments + DHCP host-name from the router)
        1. mDNS / Avahi   (per-device avahi-resolve, concurrent across devices)
        2. Reverse DNS     (PTR records — routers, servers)
        3. NetBIOS         (Windows / Samba machines)
        4. /etc/hosts      (static local mappings)
        5. MikroTik by MAC (fallback: match by MAC when IP changed)
    """
    resolved = pyqtSignal(str, str, str, str)  # ip, hostname, method, last_seen
    finished = pyqtSignal()

    def __init__(self, devices: List[Tuple[str, str, str]],
                 mikrotik_client: Optional[MikroTikClient] = None):
        super().__init__()
        self.devices = devices
        self.mikrotik_client = mikrotik_client
        self.etc_hosts = EtcHostsCache()
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

        # Always grab last_seen from MikroTik if available (even if name
        # comes from another source)
        mt_entry = self.mt_ip_map.get(ip)
        last_seen = mt_entry[2] if mt_entry else ''
        if not last_seen and mac:
            mac_entry = self.mt_mac_map.get(mac.lower())
            last_seen = mac_entry[2] if mac_entry else ''

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
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None

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


class LastSeenItem(QTableWidgetItem):
    """QTableWidgetItem that sorts by the underlying seconds value
    so that '24s' sorts before '5m30s' before '1h2m'."""

    def __init__(self, display: str, seconds: int):
        super().__init__(display)
        self._seconds = seconds

    def __lt__(self, other):
        if isinstance(other, LastSeenItem):
            return self._seconds < other._seconds
        return super().__lt__(other)


class HostsApp(QMainWindow):
    """Main application window."""
    
    def __init__(self):
        super().__init__()
        self.vendor_db = MacVendorDB()
        self.scanner_thread = None
        self.hostname_thread = None
        self.devices = []
        self.mikrotik_client = MikroTikClient(
            host=MIKROTIK_HOST,
            username=MIKROTIK_USER,
            password=MIKROTIK_PASS,
        )
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle('Hosts List - Network Scanner')
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
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            'IP Address', 'MAC Address', 'Hostname', 'Method', 'Last Seen', 'Vendor',
        ])
        self.table.setSortingEnabled(True)
        
        # Configure table
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        
        # Make IP addresses clickable
        self.table.cellClicked.connect(self.on_cell_clicked)
        
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

        iface = self.iface_combo.currentData()
        self.scanner_thread = NetworkScannerThread(self.mikrotik_client, iface=iface)
        self.scanner_thread.device_found.connect(self.on_device_found)
        self.scanner_thread.finished.connect(self.on_scan_finished)
        self.scanner_thread.error.connect(self.on_scan_error)
        self.scanner_thread.start()

    def on_device_found(self, ip: str, mac: str, vendor_raw: str):
        """Add a single device row as soon as it is discovered."""
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(ip))
        self.table.setItem(row, 1, QTableWidgetItem(mac))
        self.table.setItem(row, 2, QTableWidgetItem('Resolving...'))
        self.table.setItem(row, 3, QTableWidgetItem(''))
        self.table.setItem(row, 4, LastSeenItem('', -1))
        vendor = self.vendor_db.lookup(mac)
        if vendor == 'Unknown' and vendor_raw and vendor_raw != '(Unknown)':
            vendor = vendor_raw
        self.table.setItem(row, 5, QTableWidgetItem(vendor))

    def on_scan_finished(self, devices: List[Tuple[str, str, str]]):
        """Kick off hostname resolution once scanning is complete."""
        self.devices = devices
        self.resolve_hostnames(devices)

    def resolve_hostnames(self, devices: List[Tuple[str, str, str]]):
        """Resolve hostnames for all devices."""
        if self.hostname_thread and self.hostname_thread.isRunning():
            return
        
        self.hostname_thread = HostnameResolverThread(devices, self.mikrotik_client)
        self.hostname_thread.resolved.connect(self.on_hostname_resolved)
        self.hostname_thread.finished.connect(self.on_hostnames_finished)
        self.hostname_thread.start()

    def on_hostname_resolved(self, ip: str, hostname: str, method: str, last_seen: str):
        """Update hostname and last-seen in table."""
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0) and self.table.item(row, 0).text() == ip:
                self.table.setItem(row, 2, QTableWidgetItem(hostname))
                if method:
                    self.table.setItem(row, 3, QTableWidgetItem(method))
                if last_seen:
                    secs = MikroTikClient.parse_duration(last_seen)
                    self.table.setItem(row, 4, LastSeenItem(last_seen, secs))
                break

    def on_hostnames_finished(self):
        """Hostname resolution completed."""
        self.table.setSortingEnabled(True)
        # Default sort: Last Seen ascending (most recently seen first = smallest value)
        self.table.sortItems(4, Qt.SortOrder.AscendingOrder)
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


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('Hosts List')
    
    window = HostsApp()
    window.show()
    
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
