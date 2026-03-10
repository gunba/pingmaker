"""Port detection — tracks game server ports via netstat polling.

Detects direct connections and VPN/proxy tunnels (ExitLag, GearUp).
When a proxy is detected, switches to loopback capture mode.
"""

import subprocess
import threading
import time


class PortTracker:
    """Polls netstat to discover active game server ports."""

    EXCLUDE_PORTS = {80, 443, 8080, 8443, 53, 853}
    VPN_NAMES = {'exitlag': 'ExitLag', 'gearup': 'GearUp'}
    PORT_MEMORY_DURATION = 30.0
    PORT_CONFIDENCE_THRESHOLD = 2

    def __init__(self, refresh_interval: float = 2.0):
        self.refresh_interval = refresh_interval
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._on_change = None

        # State (protected by _lock)
        self._active_ports: set[int] = set()
        self._detected_via: str | None = None
        self._loopback_mode = False

        # Port history for confidence-based detection
        self._port_history: dict[int, dict] = {}
        self._validated_ports: set[int] = set()

    def start(self, on_change=None):
        """Start port tracking. on_change(ports) called when ports change."""
        self._on_change = on_change
        self._stop.clear()
        self._refresh()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def get_ports(self) -> set:
        with self._lock:
            return self._active_ports.copy()

    def get_detected_via(self) -> str | None:
        with self._lock:
            return self._detected_via

    def get_loopback_mode(self) -> bool:
        with self._lock:
            return self._loopback_mode

    def validate_port(self, port: int):
        with self._lock:
            self._validated_ports.add(port)

    # ── Internal ──────────────────────────────────────────────

    def _loop(self):
        while not self._stop.is_set():
            self._stop.wait(self.refresh_interval)
            if not self._stop.is_set():
                self._refresh()

    def _refresh(self):
        try:
            netstat = self._run_netstat()
            if not netstat:
                return
            pids = self._get_aion_pids()
            if not pids:
                return

            raw_ports = set()
            detected_via = None
            loopback_mode = False

            # Try direct connections first
            direct, has_localhost = self._find_direct_ports(netstat, pids)
            if direct:
                raw_ports.update(direct)
                detected_via = "Direct"

            # Check for VPN/proxy if localhost connections exist or no direct
            if has_localhost or not raw_ports:
                vpn_ports, vpn_name, proxy_ports = self._find_vpn_ports(netstat, pids)
                if proxy_ports:
                    loopback_mode = True
                    raw_ports = proxy_ports.copy()
                    detected_via = vpn_name or "VPN"
                elif vpn_ports:
                    raw_ports.update(vpn_ports)
                    detected_via = vpn_name or detected_via or "VPN"

            effective = self._apply_history(raw_ports)

            with self._lock:
                old = self._active_ports
                changed = effective != old
                self._active_ports = effective
                self._loopback_mode = loopback_mode
                if changed:
                    self._detected_via = detected_via
                    if self._on_change:
                        self._on_change(effective)
        except Exception:
            pass

    def _apply_history(self, detected: set) -> set:
        """Apply confidence thresholds and port memory."""
        now = time.time()
        for port in detected:
            if port in self._port_history:
                self._port_history[port]['last_seen'] = now
                self._port_history[port]['hit_count'] += 1
            else:
                self._port_history[port] = {
                    'last_seen': now,
                    'hit_count': 1,
                    'validated': port in self._validated_ports,
                }

        effective = set(detected)
        expired = []
        for port, info in self._port_history.items():
            age = now - info['last_seen']
            if age > self.PORT_MEMORY_DURATION:
                expired.append(port)
            elif port not in detected:
                if info['validated'] or info['hit_count'] >= self.PORT_CONFIDENCE_THRESHOLD:
                    effective.add(port)

        for port in expired:
            del self._port_history[port]
            self._validated_ports.discard(port)

        return effective

    def _run_netstat(self) -> str:
        try:
            r = subprocess.run(
                ['netstat', '-ano'],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return r.stdout
        except Exception:
            return ""

    def _get_aion_pids(self) -> list[str]:
        try:
            r = subprocess.run(
                ['powershell', '-Command',
                 "Get-Process -Name 'Aion2' -ErrorAction SilentlyContinue "
                 "| Select-Object -ExpandProperty Id"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            return [p.strip() for p in r.stdout.strip().split('\n')
                    if p.strip().isdigit()]
        except Exception:
            return []

    def _pid_in_line(self, pids: list[str], line: str) -> bool:
        parts = line.split()
        return len(parts) >= 5 and parts[-1] in pids

    def _find_direct_ports(self, netstat: str, pids: list[str]) -> tuple[set, bool]:
        """Find non-loopback ESTABLISHED connections for Aion2."""
        ports = set()
        has_localhost = False
        pid_set = set(pids)
        for line in netstat.split('\n'):
            if 'ESTABLISHED' not in line or 'TCP' not in line:
                continue
            parts = line.split()
            if len(parts) < 5 or parts[-1] not in pid_set:
                continue
            remote = parts[2]
            if ':' not in remote:
                continue
            ip, port_str = remote.rsplit(':', 1)
            if ip.startswith('127.') or ip == '[::1]':
                has_localhost = True
                continue
            try:
                port = int(port_str)
                if port not in self.EXCLUDE_PORTS:
                    ports.add(port)
            except ValueError:
                pass
        return ports, has_localhost

    def _find_vpn_ports(self, netstat: str, pids: list[str]) -> tuple[set, str | None, set]:
        """Find VPN/proxy forwarded ports."""
        pid_set = set(pids)

        # Step 1: find Aion's localhost connections (proxy targets)
        proxy_ports = set()
        for line in netstat.split('\n'):
            if 'ESTABLISHED' not in line or 'TCP' not in line:
                continue
            parts = line.split()
            if len(parts) < 5 or parts[-1] not in pid_set:
                continue
            remote = parts[2]
            if ':' not in remote:
                continue
            ip, port_str = remote.rsplit(':', 1)
            if ip.startswith('127.') or ip == '[::1]':
                try:
                    proxy_ports.add(int(port_str))
                except ValueError:
                    pass

        if not proxy_ports:
            return set(), None, set()

        # Step 2: find which PIDs are listening on those proxy ports
        vpn_pids = set()
        for line in netstat.split('\n'):
            if 'LISTENING' not in line or 'TCP' not in line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            local = parts[1]
            if ':' not in local:
                continue
            _, port_str = local.rsplit(':', 1)
            try:
                if int(port_str) in proxy_ports:
                    vpn_pids.add(parts[-1])
            except ValueError:
                pass

        if not vpn_pids:
            return set(), None, proxy_ports

        # Step 3: find those PIDs' outbound (non-loopback) connections
        remote_ports = set()
        for line in netstat.split('\n'):
            if 'ESTABLISHED' not in line or 'TCP' not in line:
                continue
            parts = line.split()
            if len(parts) < 5 or parts[-1] not in vpn_pids:
                continue
            remote = parts[2]
            if ':' not in remote:
                continue
            ip, port_str = remote.rsplit(':', 1)
            if ip.startswith('127.') or ip == '[::1]':
                continue
            try:
                port = int(port_str)
                if port not in self.EXCLUDE_PORTS:
                    remote_ports.add(port)
            except ValueError:
                pass

        vpn_name = self._identify_vpn(vpn_pids) if vpn_pids else None
        return remote_ports, vpn_name, proxy_ports

    def _identify_vpn(self, pids: set) -> str | None:
        try:
            pid_list = ','.join(pids)
            r = subprocess.run(
                ['powershell', '-Command',
                 f"Get-Process -Id {pid_list} -ErrorAction SilentlyContinue "
                 "| Select-Object -ExpandProperty ProcessName"],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            for proc in r.stdout.strip().split('\n'):
                proc_lower = proc.strip().lower()
                for key, name in self.VPN_NAMES.items():
                    if key in proc_lower:
                        return name
        except Exception:
            pass
        return None
