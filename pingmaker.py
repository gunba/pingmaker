"""
Pingmaker — Packet speed modifier
==================================
Intercepts game packets and modifies attack speed values.
Plugin-extensible: optional plugins (e.g. WeavePlugin) add extra
functionality when their dependencies are available.

Base: PingmakerV3/pingmaker.py (forked, not imported)
"""

import struct
import time
import sys
import os
import json
import subprocess
import threading
import queue
import ctypes
import argparse
import random
from datetime import datetime
from collections import defaultdict
from difflib import SequenceMatcher

from packet_model import (
    find_attack_speed_offset, extract_packet_info,
    encode_varint, encode_varint_fixed, parse_varint,
)

# Hide console window when running as GUI
if sys.platform == 'win32':
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass

try:
    import pydivert
except ImportError:
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror("Missing Dependency", "pydivert not installed.\n\nRun: pip install pydivert")
    sys.exit(1)

import tkinter as tk
from tkinter import ttk

from plugins.base import PacketPlugin, PacketContext, SkillEvent


# ============================================================================
# RESOURCE HELPER
# ============================================================================

def get_resource_path(filename):
    """Get path to resource, works for dev, PyInstaller, and Nuitka bundle."""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, filename)
    # Nuitka --onefile/--standalone: check next to the executable
    if getattr(sys, 'frozen', False) or hasattr(sys, '__compiled__'):
        exe_dir = os.path.dirname(sys.executable)
        candidate = os.path.join(exe_dir, filename)
        if os.path.exists(candidate):
            return candidate
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)


# ============================================================================
# SETTINGS
# ============================================================================

def get_settings_path():
    """Get path to settings file (next to exe or script)."""
    if hasattr(sys, '__compiled__'):
        # Nuitka onefile: sys.executable is in temp dir, use argv[0] for real location
        base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    elif getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "pingmaker_settings.json")


def _migrate_settings():
    """One-time migration: copy old settings file to new name."""
    new_path = get_settings_path()
    if os.path.exists(new_path):
        return
    old_path = os.path.join(os.path.dirname(new_path), "templar_pingmaker_settings.json")
    if os.path.exists(old_path):
        import shutil
        shutil.copy2(old_path, new_path)


def load_settings() -> dict:
    _migrate_settings()
    settings_file = get_settings_path()
    if not os.path.exists(settings_file):
        return {}
    try:
        with open(settings_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}


def save_settings(settings: dict):
    try:
        settings_file = get_settings_path()
        with open(settings_file, 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        print(f"Failed to save settings: {e}")


# ============================================================================
# SKILL DATA
# ============================================================================

SKILLS = {}
SKILL_ID_TO_NAME = {}
ALL_SKILL_IDS = set()
SKILL_FIRST_BYTES = set()

WORKER_COUNT = min(os.cpu_count() or 2, 4)
WORKERS_PER_HANDLE = 1  # workers per WinDivert handle when using per-port handles

CAPTURE_FILTER = (
    "inbound and tcp and tcp.DstPort > 1024 and tcp.SrcPort > 1024 "
    "and ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1"
)


def build_port_filter(ports):
    """Build a WinDivert filter targeting specific game server source ports."""
    if not ports:
        return CAPTURE_FILTER
    clauses = ' or '.join(f'tcp.SrcPort == {p}' for p in sorted(ports))
    return (
        f"inbound and tcp and ({clauses}) "
        "and ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1"
    )


def _build_single_port_filter(port):
    """Build a WinDivert filter for a single game server source port."""
    return (
        f"inbound and tcp and tcp.SrcPort == {port} "
        "and ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1"
    )


LOOPBACK_CAPTURE_FILTER = (
    "loopback and tcp and !impostor "
    "and tcp.DstPort > 1024 and tcp.SrcPort > 1024"
)

SNIFF_FILTER = (
    "tcp and tcp.DstPort > 1024 and tcp.SrcPort > 1024 and ("
    "(inbound and ip.DstAddr != 127.0.0.1 and ip.SrcAddr != 127.0.0.1) or "
    "loopback"
    ")"
)


def build_loopback_port_filter(ports):
    """Build a WinDivert loopback filter targeting specific proxy source ports."""
    if not ports:
        return LOOPBACK_CAPTURE_FILTER
    clauses = ' or '.join(f'tcp.SrcPort == {p}' for p in sorted(ports))
    return f"loopback and tcp and !impostor and ({clauses})"


def _build_single_loopback_port_filter(port):
    """Build a WinDivert loopback filter for a single proxy source port."""
    return f"loopback and tcp and !impostor and tcp.SrcPort == {port}"


def _tune_handle(w):
    """Max out WinDivert internal buffers on a handle."""
    try:
        from pydivert import Param
        w.set_param(Param.QUEUE_LEN, 16384)
        w.set_param(Param.QUEUE_SIZE, 33554432)  # 32MB
        w.set_param(Param.QUEUE_TIME, 4000)       # 4s
    except Exception:
        pass


def load_skills():
    global SKILLS, SKILL_ID_TO_NAME, ALL_SKILL_IDS, SKILL_FIRST_BYTES
    skills_file = get_resource_path("skills.json")
    if not os.path.exists(skills_file):
        return False
    try:
        with open(skills_file, 'r', encoding='utf-8') as f:
            SKILLS = json.load(f)
        for name, ids in SKILLS.items():
            for skill_id in ids:
                SKILL_ID_TO_NAME[skill_id] = name
                ALL_SKILL_IDS.add(skill_id)
                SKILL_FIRST_BYTES.add(skill_id & 0xFF)
        return True
    except Exception as e:
        print(f"Error loading skills: {e}")
        return False


def fuzzy_search(query: str, limit: int = 10) -> list:
    if not query or len(query) < 2:
        return []
    query_lower = query.lower()
    results = []
    for name in SKILLS.keys():
        name_lower = name.lower()
        if query_lower in name_lower:
            if name_lower.startswith(query_lower):
                score = 1.0
            elif f" {query_lower}" in f" {name_lower}":
                score = 0.95
            else:
                score = 0.9
            results.append((name, score))
        else:
            from difflib import SequenceMatcher
            ratio = SequenceMatcher(None, query_lower, name_lower).ratio()
            if ratio > 0.5:
                results.append((name, ratio * 0.8))
    results.sort(key=lambda x: -x[1])
    return [name for name, score in results[:limit]]



# ============================================================================
# PORT DETECTION (from pingmaker.py)
# ============================================================================

class PortTracker:
    EXCLUDE_PORTS = {80, 443, 8080, 8443, 53, 853}
    EXCLUDE_RANGES = []
    VPN_NAMES = {'exitlag': 'ExitLag', 'gearup': 'GearUp'}
    PORT_MEMORY_DURATION = 30.0
    PORT_CONFIDENCE_THRESHOLD = 2

    def __init__(self, refresh_interval: float = 2.0):
        self.refresh_interval = refresh_interval
        self.active_ports = set()
        self.detected_via = None
        self.vpn_proxy_ports = set()
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._on_change = None
        self._port_history = {}
        self._validated_ports = set()
        self._connection_pairs = {}
        self.loopback_mode = False

    def start(self, on_change=None):
        self._on_change = on_change
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._tracking_loop, daemon=True)
        self._thread.start()
        self._refresh_ports()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

    def get_ports(self) -> set:
        with self._lock:
            return self.active_ports.copy()

    def get_detected_via(self) -> str:
        with self._lock:
            return self.detected_via

    def get_vpn_proxy_ports(self) -> set:
        with self._lock:
            return self.vpn_proxy_ports.copy()

    def get_loopback_mode(self) -> bool:
        with self._lock:
            return self.loopback_mode

    def validate_port(self, port: int):
        with self._lock:
            self._validated_ports.add(port)
            if port in self._port_history:
                self._port_history[port]['validated'] = True

    def get_validated_ports(self) -> set:
        with self._lock:
            return self._validated_ports.copy()

    def _tracking_loop(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(self.refresh_interval)
            if not self._stop_event.is_set():
                self._refresh_ports()

    def _is_excluded_port(self, port: int) -> bool:
        return port in self.EXCLUDE_PORTS

    def _pid_matches_line(self, pid: str, line: str) -> bool:
        parts = line.split()
        if len(parts) >= 5:
            return parts[-1] == pid
        return False

    def _update_port_history(self, detected_ports: set, current_time: float):
        for port in detected_ports:
            if port in self._port_history:
                self._port_history[port]['last_seen'] = current_time
                self._port_history[port]['hit_count'] += 1
            else:
                self._port_history[port] = {
                    'last_seen': current_time,
                    'hit_count': 1,
                    'validated': port in self._validated_ports
                }
        effective_ports = set(detected_ports)
        expired_ports = []
        for port, info in self._port_history.items():
            age = current_time - info['last_seen']
            if age > self.PORT_MEMORY_DURATION:
                expired_ports.append(port)
            elif port not in detected_ports:
                if info['validated'] or info['hit_count'] >= self.PORT_CONFIDENCE_THRESHOLD:
                    effective_ports.add(port)
        for port in expired_ports:
            del self._port_history[port]
            self._validated_ports.discard(port)
        return effective_ports

    def _refresh_ports(self):
        raw_ports = set()
        new_detected_via = None
        new_vpn_proxy_ports = set()
        new_loopback_mode = False
        current_time = time.time()
        try:
            netstat_output = self._get_netstat_output()
            if not netstat_output:
                return
            aion_pids = self._get_aion_pids()
            if aion_pids:
                direct_ports, has_localhost = self._get_aion_direct_ports(netstat_output, aion_pids)
                if direct_ports:
                    raw_ports.update(direct_ports)
                    new_detected_via = "Direct"
                if has_localhost or not raw_ports:
                    vpn_ports, vpn_name, vpn_local_ports = self._get_vpn_forwarded_ports(netstat_output, aion_pids)
                    new_vpn_proxy_ports = vpn_local_ports
                    if vpn_local_ports:
                        # Proxy detected — use loopback capture on proxy ports
                        new_loopback_mode = True
                        raw_ports = vpn_local_ports.copy()
                        if vpn_name:
                            new_detected_via = vpn_name
                        elif not new_detected_via:
                            new_detected_via = "VPN"
                    elif vpn_ports:
                        raw_ports.update(vpn_ports)
                        if vpn_name:
                            new_detected_via = vpn_name
                        elif not new_detected_via:
                            new_detected_via = "VPN"
        except Exception:
            pass

        effective_ports = self._update_port_history(raw_ports, current_time)
        with self._lock:
            old = self.active_ports
            if effective_ports != self.active_ports:
                self.active_ports = effective_ports
                self.detected_via = new_detected_via
            self.loopback_mode = new_loopback_mode
            if new_vpn_proxy_ports:
                self.vpn_proxy_ports = new_vpn_proxy_ports
            if self._on_change and effective_ports != old:
                self._on_change(effective_ports)

    def _get_netstat_output(self) -> str:
        try:
            result = subprocess.run(
                ['netstat', '-ano'],
                capture_output=True, text=True, timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            return result.stdout
        except Exception:
            return ""

    def _get_aion_pids(self) -> list:
        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 "Get-Process -Name 'Aion2' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id"],
                capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
            )
            return [p.strip() for p in result.stdout.strip().split('\n') if p.strip().isdigit()]
        except Exception:
            return []

    def _get_aion_direct_ports(self, netstat_output: str, aion_pids: list) -> tuple:
        ports = set()
        has_localhost = False
        for line in netstat_output.split('\n'):
            if 'ESTABLISHED' not in line or 'TCP' not in line:
                continue
            matching_pid = None
            for pid in aion_pids:
                if self._pid_matches_line(pid, line):
                    matching_pid = pid
                    break
            if not matching_pid:
                continue
            parts = line.split()
            if len(parts) < 5:
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
                if not self._is_excluded_port(port):
                    ports.add(port)
            except ValueError:
                pass
        return ports, has_localhost

    def _get_vpn_forwarded_ports(self, netstat_output: str, aion_pids: list) -> tuple:
        ports = set()
        vpn_name = None
        local_proxy_ports = set()
        for line in netstat_output.split('\n'):
            if 'ESTABLISHED' not in line or 'TCP' not in line:
                continue
            matching_pid = None
            for pid in aion_pids:
                if self._pid_matches_line(pid, line):
                    matching_pid = pid
                    break
            if not matching_pid:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            remote = parts[2]
            if ':' not in remote:
                continue
            ip, port_str = remote.rsplit(':', 1)
            if ip.startswith('127.') or ip == '[::1]':
                try:
                    local_proxy_ports.add(int(port_str))
                except ValueError:
                    pass
        if not local_proxy_ports:
            return ports, vpn_name, local_proxy_ports

        vpn_pids = set()
        for line in netstat_output.split('\n'):
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
                port = int(port_str)
                if port in local_proxy_ports:
                    vpn_pids.add(parts[-1])
            except ValueError:
                pass

        if not vpn_pids:
            return ports, vpn_name, local_proxy_ports

        for line in netstat_output.split('\n'):
            if 'ESTABLISHED' not in line or 'TCP' not in line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            line_pid = parts[-1]
            if line_pid not in vpn_pids:
                continue
            remote = parts[2]
            if ':' not in remote:
                continue
            ip, port_str = remote.rsplit(':', 1)
            if ip.startswith('127.') or ip == '[::1]':
                continue
            try:
                port = int(port_str)
                if not self._is_excluded_port(port):
                    ports.add(port)
            except ValueError:
                pass

        if vpn_pids:
            vpn_name = self._identify_vpn_process(vpn_pids)
        return ports, vpn_name, local_proxy_ports

    def _identify_vpn_process(self, vpn_pids: set) -> str:
        try:
            pid_list = ','.join(vpn_pids)
            result = subprocess.run(
                ['powershell', '-Command',
                 f"Get-Process -Id {pid_list} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName"],
                capture_output=True, text=True, timeout=5, creationflags=subprocess.CREATE_NO_WINDOW
            )
            for proc_name in result.stdout.strip().split('\n'):
                proc_lower = proc_name.strip().lower()
                for key, name in self.VPN_NAMES.items():
                    if key in proc_lower:
                        return name
        except:
            pass
        return None


# ============================================================================
# PACKET PROCESSING (from pingmaker.py)
# ============================================================================

def get_direction(data: bytes) -> str:
    if len(data) < 12:
        return None
    if data[10:12] == b'\x01\x01':
        return 'SRV'
    return None


def has_skill_prefix(data: bytes, offset: int) -> bool:
    if len(data) <= 62:
        return False
    if offset < 4 or offset + 6 > len(data):
        return False
    prefix = data[offset-4:offset]
    if prefix[0] != 0x38:
        return False
    if prefix[3] not in (0x00, 0x01):
        return False
    if prefix[2] == 0x00:
        return False
    pkt_type = data[offset + 5]
    return pkt_type in (0x00, 0x02, 0x03, 0x04, 0x06)


def find_skill_id(data, target_ids: set = None, skip_prefix_check: bool = False) -> tuple:
    ids_to_check = target_ids if target_ids else ALL_SKILL_IDS
    first_bytes = SKILL_FIRST_BYTES
    _unpack_from = struct.unpack_from
    end = min(len(data) - 3, 200)
    for i in range(32, end):
        if data[i] not in first_bytes:
            continue
        val = _unpack_from('<I', data, i)[0]
        if val in ids_to_check:
            if skip_prefix_check:
                return (val, i)
            if has_skill_prefix(data, i):
                return (val, i)
            return (None, -1)
    return (None, -1)


def get_packet_type(data: bytes, skill_offset: int) -> int:
    type_offset = skill_offset + 5
    if type_offset < len(data):
        return data[type_offset]
    return -1


def get_tick_byte(data: bytes, skill_offset: int) -> int:
    tick_offset = skill_offset + 4
    if tick_offset < len(data):
        return data[tick_offset]
    return -1


# ============================================================================
# ASYNC LOG WRITER
# ============================================================================

class AsyncLogWriter:
    def __init__(self, filepath: str):
        self._queue = queue.Queue()
        self._file = open(filepath, 'w', encoding='utf-8')
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def put(self, entry: dict):
        try:
            self._queue.put_nowait(entry)
        except queue.Full:
            pass

    def _drain(self):
        while not self._stop.is_set():
            try:
                entry = self._queue.get(timeout=0.5)
                self._file.write(json.dumps(entry) + '\n')
                self._file.flush()
            except queue.Empty:
                continue
            except Exception:
                pass

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)
        while not self._queue.empty():
            try:
                entry = self._queue.get_nowait()
                self._file.write(json.dumps(entry) + '\n')
            except:
                break
        try:
            self._file.flush()
            self._file.close()
        except:
            pass


# ============================================================================
# ENTITY TRACKING — nickname binding (0x04 0x8D) parser
# ============================================================================

class EntityTracker:
    """Tracks the player's entity IDs by accumulating nickname bindings.

    Accepts all bindings for the player's character name except those from
    byte5=0x20 packets (other players' property updates, major source of
    false positives).
    """

    def __init__(self, character_names: list[str]):
        self._lock = threading.Lock()
        self._character_names = {n.strip().lower() for n in character_names if n.strip()}
        self._my_keys = set()

    def update_character_names(self, names: list[str]):
        with self._lock:
            self._character_names = {n.strip().lower() for n in names if n.strip()}
            self._my_keys.clear()

    def on_nickname_binding(self, actor_id: int, name: str, byte5: int = 0) -> bool:
        with self._lock:
            if name.strip().lower() not in self._character_names:
                return False
            if actor_id in self._my_keys:
                return False
            self._my_keys.add(actor_id)
            return True

    def is_my_entity(self, entity_key: int) -> bool:
        return entity_key in self._my_keys

    def has_any_keys(self) -> bool:
        return bool(self._my_keys)

    @property
    def is_configured(self) -> bool:
        return bool(self._character_names)

    def get_my_keys(self) -> set:
        with self._lock:
            return set(self._my_keys)

    def confirm_sole_key(self, entity_key: int):
        with self._lock:
            if entity_key in self._my_keys and len(self._my_keys) > 1:
                self._my_keys = {entity_key}
                return True
            return False

    def clear(self):
        with self._lock:
            self._my_keys.clear()


GAME_MSG_DELIMITER = b'\x06\x00\x36'
MAX_STREAM_BUFFER = 2 * 1024 * 1024


def _sanitize_nickname(raw: str) -> str:
    """Sanitize a raw name string — matches DPS meter's sanitizeNickname."""
    name = raw.split('\x00')[0].strip()
    clean = []
    for ch in name:
        if ch.isalnum():
            clean.append(ch)
        else:
            break
    return ''.join(clean)


def _try_parse_nickname_0x04_0x8D(segment: bytes) -> tuple:
    """
    Strategy 1: parse [varint_len][0x04][0x8D]...[actor_id][name_len][name]
    Matches DPS meter's parsingNickname().
    """
    if len(segment) < 14:
        return None
    varint_val, varint_len = parse_varint(segment, 0)
    if varint_len <= 0:
        return None
    opcode_pos = varint_len
    if opcode_pos + 1 >= len(segment):
        return None
    if segment[opcode_pos] != 0x04 or segment[opcode_pos + 1] != 0x8D:
        return None
    # actor_id at absolute offset 10 (matches DPS meter)
    if 10 >= len(segment):
        return None
    actor_id, actor_len = parse_varint(segment, 10)
    if actor_len <= 0 or actor_id <= 0 or actor_id > 0x7FFFFFFF:
        return None
    name_len_pos = 10 + actor_len
    if name_len_pos >= len(segment):
        return None
    name_length = segment[name_len_pos]
    if name_length < 1 or name_length > 72:
        return None
    name_start = name_len_pos + 1
    name_end = name_start + name_length
    if name_end > len(segment):
        return None
    try:
        raw_name = segment[name_start:name_end].decode('utf-8')
    except UnicodeDecodeError:
        return None
    name = _sanitize_nickname(raw_name)
    if len(name) < 2:
        return None
    return (actor_id, name)


def _scan_actor_name_bindings(data: bytes) -> list:
    """
    Scan for 0x36 byte + varint actor_id, then 0x07 + name_len + name.
    Matches DPS meter's parseActorNameBindingRules().
    """
    results = []
    i = 0
    dlen = len(data)
    last_actor_id = None
    last_actor_end = -1
    while i < dlen:
        if data[i] == 0x36:
            actor_id, alen = parse_varint(data, i + 1)
            if alen > 0 and 100 <= actor_id <= 99999:
                last_actor_id = actor_id
                last_actor_end = i + 1 + alen
            i += 1
            continue
        if data[i] == 0x07 and last_actor_id is not None:
            length_idx = i + 1
            if length_idx < dlen:
                name_length = data[length_idx]
                if 1 <= name_length <= 24:
                    name_start = length_idx + 1
                    name_end = name_start + name_length
                    if name_end <= dlen and i >= last_actor_end:
                        try:
                            raw_name = data[name_start:name_end].decode('utf-8')
                        except UnicodeDecodeError:
                            i += 1
                            continue
                        name = _sanitize_nickname(raw_name)
                        if len(name) >= 2:
                            results.append((last_actor_id, name))
                            last_actor_id = None
        i += 1
    return results


class StreamReassembler:
    """
    Reassembles TCP stream and splits on 06 00 36 delimiters,
    matching the DPS meter's StreamAssembler + PacketAccumulator.
    """

    def __init__(self, diag_writer=None):
        self._buffer = bytearray()
        self._diag = diag_writer  # AsyncLogWriter or None
        self._msg_count = 0

    def feed(self, chunk: bytes) -> list:
        """
        Feed a TCP payload chunk. Returns list of (actor_id, name) tuples
        found in complete messages.
        """
        self._buffer.extend(chunk)
        # Safety: prevent unbounded growth
        if len(self._buffer) > MAX_STREAM_BUFFER:
            self._buffer = bytearray()
            return []

        results = []
        while True:
            idx = self._buffer.find(GAME_MSG_DELIMITER)
            if idx < 0:
                break
            # Everything up to and including the delimiter is one message
            cut_point = idx + 3
            message = bytes(self._buffer[:cut_point])
            del self._buffer[:cut_point]

            if len(message) < 6:
                continue

            self._msg_count += 1

            msg_hex = message[:128].hex()
            byte5 = message[5] if len(message) > 5 else 0
            binding = _try_parse_nickname_0x04_0x8D(message)
            if binding:
                results.append((binding[0], binding[1], '0x04_0x8D', msg_hex, byte5))
                if self._diag:
                    self._diag.put({
                        'type': 'nickname_found',
                        'strategy': '0x04_0x8D',
                        'actor_id': binding[0],
                        'name': binding[1],
                        'msg_len': len(message),
                        'msg_hex': message[:64].hex(),
                        'msg_num': self._msg_count,
                    })
                continue
            bindings = _scan_actor_name_bindings(message)
            if bindings:
                for b in bindings:
                    results.append((b[0], b[1], 'actor_name', msg_hex, byte5))
                if self._diag:
                    for b in bindings:
                        self._diag.put({
                            'type': 'nickname_found',
                            'strategy': 'actor_name_binding',
                            'actor_id': b[0],
                            'name': b[1],
                            'msg_len': len(message),
                            'msg_hex': message[:64].hex(),
                            'msg_num': self._msg_count,
                        })
                continue
            # Log unmatched messages that have potential nickname indicators
            if self._diag and len(message) > 14:
                has_04_8d = b'\x04\x8d' in message
                has_07 = 0x07 in message
                if has_04_8d or has_07:
                    self._diag.put({
                        'type': 'unmatched_interesting',
                        'msg_len': len(message),
                        'msg_hex': message[:128].hex(),
                        'has_04_8d': has_04_8d,
                        'has_07': has_07,
                        'msg_num': self._msg_count,
                    })

        return results


# ============================================================================
# MODERN GUI
# ============================================================================

class ModernStyle:
    BG = "#0d1b2a"
    BG_LIGHT = "#1b263b"
    BG_CARD = "#1b263b"
    RED = "#c41e3a"
    RED_HOVER = "#e63946"
    BLUE = "#3a86ff"
    BLUE_DIM = "#2a5faa"
    YELLOW = "#ffd700"
    TEXT = "#f5f0e6"
    TEXT_DIM = "#a89a80"
    BORDER = "#2d3f5a"
    ACCENT = RED
    ACCENT_HOVER = RED_HOVER
    HIGHLIGHT = YELLOW
    SUCCESS = BLUE
    ERROR = RED


class TickToolApp:
    def __init__(self, root, plugins=None):
        self.root = root
        self.root.title("Pingmaker")
        self.root.geometry("380x650")
        self.root.minsize(330, 450)
        self.root.configure(bg=ModernStyle.BG)

        # Set window icon
        try:
            icon_path = get_resource_path("pingmaker.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except:
            pass

        # State
        self.selected_skills = {}
        self.is_running = False
        self.capture_active = False
        self.is_learning = False
        self.loading_settings = True
        self.stop_event = threading.Event()
        self.worker_thread = None
        self.target_ids = set()

        # Stats
        self.stats = defaultdict(int)
        self.learned_skills = set()

        # Logging
        self.log_writer = None
        self.csv_logging_enabled = tk.BooleanVar(value=False)

        # Uniform speed override (blank = disabled, int = %)
        self.uniform_speed = tk.StringVar(value="")
        self.uniform_break = tk.BooleanVar(value=False)

        # Skill row widgets
        self._skill_rows = {}

        # Entity tracking
        self.entity_tracker = EntityTracker([])
        self.char_names_var = tk.StringVar()

        # Packet plugins
        self._plugins = plugins or []
        for p in self._plugins:
            p.set_save_callback(self.save_current_settings)

        # Build UI
        self.setup_styles()
        self.build_ui()

        # Load saved settings
        self.load_saved_settings()

        # Background nickname sniffer (always-on, read-only)
        self._sniffer_stop = threading.Event()
        self._sniffer_thread = None
        self._start_nickname_sniffer()

        # Save on close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        self._stop_nickname_sniffer()
        if self.capture_active:
            self.full_stop_capture()
        for p in self._plugins:
            try: p.on_stop()
            except Exception: pass
        self.save_current_settings()
        self.root.destroy()

    @staticmethod
    def _discover_plugins() -> list:
        """Return list of PacketPlugin subclasses available."""
        plugins = []
        try:
            from plugins.conditional_logger import ConditionalLoggerPlugin
            plugins.append(ConditionalLoggerPlugin)
        except ImportError:
            pass
        try:
            from plugins.weave_plugin import WeavePlugin
            plugins.append(WeavePlugin)
        except ImportError:
            pass
        return plugins

    def _start_nickname_sniffer(self):
        """Start a read-only background sniffer that learns nickname bindings."""
        self._stop_nickname_sniffer()
        self._sniffer_stop.clear()
        self._sniffer_thread = threading.Thread(
            target=self._nickname_sniffer_loop, daemon=True)
        self._sniffer_thread.start()
        self._entity_status_poll()

    def _entity_status_poll(self):
        """Refresh entity status label periodically while sniffer is running."""
        if self._sniffer_stop.is_set():
            return
        self._update_entity_status_label()
        self.root.after(1000, self._entity_status_poll)

    def _stop_nickname_sniffer(self):
        self._sniffer_stop.set()
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=3)
            self._sniffer_thread = None

    def _nickname_sniffer_loop(self):
        """Background loop: sniff packets (read-only) and parse nickname bindings."""
        try:
            w = pydivert.WinDivert(SNIFF_FILTER, flags=pydivert.Flag.SNIFF)
            w.open()
        except Exception:
            return

        reassembler = StreamReassembler()
        entity_tracker = self.entity_tracker
        stop = self._sniffer_stop
        ui_q = getattr(self, '_ui_log_queue', None)

        def sniffer_log(msg):
            if ui_q:
                try:
                    ui_q.put_nowait(msg)
                except queue.Full:
                    pass

        try:
            while not stop.is_set():
                # Yield if capture is active (workers handle it)
                if self.capture_active:
                    stop.wait(1.0)
                    continue
                try:
                    packet = w.recv()
                except Exception:
                    if stop.is_set():
                        break
                    continue

                raw = packet.raw
                raw_len = len(raw)
                if raw_len < 40:
                    continue

                ip_hdr_len = (raw[0] & 0x0F) * 4
                tcp_hdr_len = (raw[ip_hdr_len + 12] >> 4) * 4
                payload_offset = ip_hdr_len + tcp_hdr_len
                if payload_offset >= raw_len:
                    continue

                payload = bytes(raw[payload_offset:])
                if len(payload) < 4:
                    continue

                bindings = reassembler.feed(payload)
                for actor_id, name, strategy, msg_hex, byte5 in bindings:
                    is_candidate = entity_tracker.on_nickname_binding(actor_id, name, byte5=byte5)
                    if is_candidate:
                        sniffer_log(f"[Entity] Bound: {name} -> key {actor_id} ({strategy} b5=0x{byte5:02x})")
        except Exception:
            pass
        finally:
            try:
                w.close()
            except Exception:
                pass

    def load_saved_settings(self):
        self.loading_settings = True
        try:
            settings = load_settings()
            needs_migration = settings.get('settings_version', 0) < 2
            saved_skills = settings.get('skills', {})
            if isinstance(saved_skills, list):
                for name in saved_skills:
                    if name in SKILLS:
                        self.selected_skills[name] = {
                            "ids": SKILLS[name],
                            "attack_speed": None,
                            "overflow": False,
                        }
            elif isinstance(saved_skills, dict):
                for name, skill_data in saved_skills.items():
                    if name in SKILLS:
                        if isinstance(skill_data, dict):
                            spd = skill_data.get("attack_speed", 0)
                            # Migrate: old 0 meant passthrough, now None = passthrough
                            if needs_migration and spd == 0:
                                spd = None
                            self.selected_skills[name] = {
                                "ids": SKILLS[name],
                                "attack_speed": spd,
                                "overflow": bool(skill_data.get("overflow", False)),
                            }
                        else:
                            self.selected_skills[name] = {
                                "ids": SKILLS[name],
                                "attack_speed": None,
                                "overflow": False,
                            }
            if not self.selected_skills:
                self._load_default_skills()
            self.refresh_skill_list()
            if 'csv_logging_enabled' in settings:
                self.csv_logging_enabled.set(settings['csv_logging_enabled'])
            self.char_names_var.set(settings.get('character_names', ''))
            saved_uniform = settings.get('uniform_speed')
            # Migrate: old int 0 meant disabled, now blank means disabled
            if needs_migration and saved_uniform == 0:
                saved_uniform = None
            if saved_uniform is None:
                self.uniform_speed.set('')
            else:
                self.uniform_speed.set(str(saved_uniform))
            self.uniform_break.set(settings.get('uniform_break', False))
            for p in self._plugins:
                p.load_settings(settings)
        finally:
            self.loading_settings = False

    def _load_default_skills(self):
        pass

    def save_current_settings(self):
        if self.loading_settings:
            return
        try:
            self._sync_speed_values_from_ui()
            skills_dict = {}
            for name, data in self.selected_skills.items():
                sd = {"attack_speed": data.get("attack_speed")}
                if data.get("overflow"):
                    sd["overflow"] = True
                skills_dict[name] = sd
            settings = {
                'settings_version': 2,
                'skills': skills_dict,
                'csv_logging_enabled': self.csv_logging_enabled.get(),
                'character_names': self.char_names_var.get(),
                'uniform_speed': self._parse_uniform_speed(),
                'uniform_break': self.uniform_break.get(),
            }
            for p in self._plugins:
                p.save_settings(settings)
            save_settings(settings)
        except Exception as e:
            if hasattr(self, 'log_text'):
                self.log(f"Settings save error: {e}")

    def _sync_speed_values_from_ui(self):
        for name, row_info in self._skill_rows.items():
            if name in self.selected_skills:
                entry = row_info.get('speed_entry')
                if entry:
                    try:
                        text = entry.get().strip()
                    except tk.TclError:
                        text = ''
                    if text == '':
                        self.selected_skills[name]['attack_speed'] = None  # passthrough
                    else:
                        try:
                            self.selected_skills[name]['attack_speed'] = int(text)
                        except ValueError:
                            self.selected_skills[name]['attack_speed'] = None
                ovf_var = row_info.get('overflow_var')
                if ovf_var is not None:
                    self.selected_skills[name]['overflow'] = ovf_var.get()

    def on_setting_changed(self, *args):
        try:
            self.save_current_settings()
        except:
            pass
        # Hot-reload speed lookups while capture is running
        if self.capture_active:
            try:
                self._rebuild_lookups()
            except:
                pass

    def _on_char_names_changed(self, *args):
        names = [n.strip() for n in self.char_names_var.get().split(',') if n.strip()]
        self.entity_tracker.update_character_names(names)
        self._update_entity_status_label()
        self.save_current_settings()

    def _update_entity_status_label(self):
        if not hasattr(self, 'entity_status_label'):
            return
        tracker = self.entity_tracker
        if not tracker.is_configured:
            self.entity_status_label.config(
                text="No filter active (modifies all players' packets)",
                fg=ModernStyle.TEXT_DIM)
        elif not tracker.has_any_keys():
            self.entity_status_label.config(
                text="Rezone or wait for name binding...",
                fg=ModernStyle.YELLOW)
        else:
            keys = tracker.get_my_keys()
            keys_str = ', '.join(str(k) for k in sorted(keys))
            self.entity_status_label.config(
                text=f"Filtering active — key {keys_str}",
                fg=ModernStyle.BLUE)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(".", background=ModernStyle.BG, foreground=ModernStyle.TEXT)
        style.configure("TFrame", background=ModernStyle.BG)
        style.configure("Card.TFrame", background=ModernStyle.BG_CARD)
        style.configure("TLabel", background=ModernStyle.BG, foreground=ModernStyle.TEXT, font=("Segoe UI", 9))
        style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"), foreground=ModernStyle.RED)
        style.configure("Subtitle.TLabel", foreground=ModernStyle.TEXT_DIM, font=("Segoe UI", 8))
        style.configure("Stat.TLabel", font=("Segoe UI", 9))
        style.configure("StatValue.TLabel", font=("Segoe UI", 11, "bold"), foreground=ModernStyle.BLUE)
        style.configure("TEntry",
            fieldbackground=ModernStyle.BG_LIGHT,
            foreground=ModernStyle.TEXT,
            insertcolor=ModernStyle.TEXT,
            borderwidth=0
        )
        style.configure("Accent.TButton",
            background=ModernStyle.ACCENT,
            foreground=ModernStyle.TEXT,
            font=("Segoe UI", 9, "bold"),
            borderwidth=0,
            padding=(12, 6)
        )
        style.map("Accent.TButton",
            background=[("active", ModernStyle.ACCENT_HOVER), ("disabled", ModernStyle.BG_LIGHT)]
        )
        style.configure("TSpinbox",
            fieldbackground=ModernStyle.BG_LIGHT,
            foreground=ModernStyle.TEXT,
            arrowcolor=ModernStyle.TEXT
        )
        style.configure("TNotebook", background=ModernStyle.BG, borderwidth=0)
        style.configure("TNotebook.Tab",
            background=ModernStyle.BG_LIGHT,
            foreground=ModernStyle.TEXT_DIM,
            font=("Segoe UI", 9, "bold"),
            padding=(10, 4),
            borderwidth=0
        )
        style.map("TNotebook.Tab",
            background=[("selected", ModernStyle.BG_CARD)],
            foreground=[("selected", ModernStyle.TEXT)],
        )

    def build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # ─── HEADER WITH LOGO ────────────────────────────────────
        header = ttk.Frame(main)
        header.pack(fill=tk.X, pady=(0, 5))

        header_row = tk.Frame(header, bg=ModernStyle.BG)
        header_row.pack(fill=tk.X)

        try:
            from PIL import Image, ImageTk
            logo_path = get_resource_path("pingmaker.png")
            if os.path.exists(logo_path):
                img = Image.open(logo_path)
                img = img.resize((32, 32), Image.Resampling.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(img)
                logo_label = tk.Label(header_row, image=self.logo_img, bg=ModernStyle.BG)
                logo_label.pack(side=tk.LEFT, padx=(0, 8))
        except:
            pass

        title_frame = tk.Frame(header_row, bg=ModernStyle.BG)
        title_frame.pack(side=tk.LEFT, fill=tk.X)

        tk.Label(title_frame, text="Pingmaker", font=("Segoe UI", 14, "bold"),
                 bg=ModernStyle.BG, fg=ModernStyle.RED).pack(anchor="w")

        subtitle = "Packet speed modifier"
        if self._plugins:
            plugin_names = ", ".join(p.name for p in self._plugins)
            subtitle += f" + {plugin_names}"
        tk.Label(title_frame, text=subtitle,
                 font=("Segoe UI", 8), bg=ModernStyle.BG, fg=ModernStyle.TEXT_DIM).pack(anchor="w")

        # ─── NOTEBOOK (TABBED UI) ────────────────────────────────
        notebook = ttk.Notebook(main)
        notebook.pack(fill=tk.X, pady=(3, 0))

        # ─── TAB: PINGMAKER ──────────────────────────────────────
        pingmaker_tab = tk.Frame(notebook, bg=ModernStyle.BG, padx=3, pady=3)
        notebook.add(pingmaker_tab, text="Pingmaker")

        # ─── SKILL SEARCH ────────────────────────────────────────
        search_frame = ttk.Frame(pingmaker_tab)
        search_frame.pack(fill=tk.X, pady=(5, 3))

        search_header = tk.Frame(search_frame, bg=ModernStyle.BG)
        search_header.pack(fill=tk.X, pady=(0, 3))

        ttk.Label(search_header, text="Add Skills").pack(side=tk.LEFT)

        self.learn_btn = tk.Button(
            search_header, text="Auto-Detect", font=("Segoe UI", 8),
            bg=ModernStyle.BLUE, fg=ModernStyle.TEXT,
            activebackground=ModernStyle.HIGHLIGHT, activeforeground=ModernStyle.BG,
            relief=tk.FLAT, cursor="hand2", padx=6,
            command=self.toggle_learning
        )
        self.learn_btn.pack(side=tk.RIGHT)

        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.on_search_changed)

        self.search_entry = tk.Entry(
            search_frame, textvariable=self.search_var, font=("Segoe UI", 9),
            bg=ModernStyle.BG_LIGHT, fg=ModernStyle.TEXT,
            insertbackground=ModernStyle.TEXT, relief=tk.FLAT,
            highlightthickness=1, highlightcolor=ModernStyle.ACCENT,
            highlightbackground=ModernStyle.BORDER
        )
        self.search_entry.pack(fill=tk.X, ipady=4)

        self.results_frame = tk.Frame(search_frame, bg=ModernStyle.BG_CARD)
        self.results_listbox = tk.Listbox(
            self.results_frame, font=("Segoe UI", 9),
            bg=ModernStyle.BG_CARD, fg=ModernStyle.TEXT,
            selectbackground=ModernStyle.ACCENT, selectforeground=ModernStyle.TEXT,
            relief=tk.FLAT, highlightthickness=1,
            highlightbackground=ModernStyle.BORDER, height=5, activestyle='none'
        )
        self.results_listbox.pack(fill=tk.X)
        self.results_listbox.bind('<Button-1>', self.on_result_click)
        self.results_listbox.bind('<Return>', self.on_result_click)

        # ─── UNIFORM SPEED OVERRIDE ──────────────────────────────
        uniform_frame = tk.Frame(pingmaker_tab, bg=ModernStyle.BG_CARD,
                                 highlightthickness=1, highlightbackground=ModernStyle.BORDER)
        uniform_frame.pack(fill=tk.X, pady=(3, 5))
        uniform_inner = tk.Frame(uniform_frame, bg=ModernStyle.BG_CARD, padx=10, pady=5)
        uniform_inner.pack(fill=tk.X)
        tk.Label(uniform_inner, text="Uniform Speed Override",
                 font=("Segoe UI", 9, "bold"), bg=ModernStyle.BG_CARD,
                 fg=ModernStyle.TEXT).pack(side=tk.LEFT)
        self.uniform_speed_entry = tk.Entry(
            uniform_inner, textvariable=self.uniform_speed, font=("Consolas", 9),
            width=8, bg=ModernStyle.BG_LIGHT, fg=ModernStyle.TEXT,
            insertbackground=ModernStyle.TEXT, relief=tk.FLAT,
            highlightthickness=1, highlightbackground=ModernStyle.BORDER,
            justify=tk.RIGHT
        )
        self.uniform_speed_entry.pack(side=tk.RIGHT, padx=(8, 2))
        self.uniform_speed_entry.bind('<FocusOut>', lambda e: self.save_current_settings())
        self.uniform_speed_entry.bind('<Return>', lambda e: self.save_current_settings())
        tk.Label(uniform_inner, text="%", font=("Segoe UI", 8),
                 bg=ModernStyle.BG_CARD, fg=ModernStyle.TEXT_DIM).pack(side=tk.RIGHT)
        uniform_brk_cb = tk.Checkbutton(
            uniform_inner, text="Break Packet", font=("Segoe UI", 7),
            variable=self.uniform_break,
            bg=ModernStyle.BG_CARD, fg=ModernStyle.TEXT_DIM,
            activebackground=ModernStyle.BG_CARD, selectcolor=ModernStyle.BG_LIGHT,
            command=self.save_current_settings
        )
        uniform_brk_cb.pack(side=tk.RIGHT, padx=(6, 0))
        tk.Label(uniform_inner, text="blank=off",
                 font=("Segoe UI", 7), bg=ModernStyle.BG_CARD,
                 fg=ModernStyle.TEXT_DIM).pack(side=tk.LEFT, padx=(6, 0))

        # ─── PER-SKILL ATTACK SPEED LIST ─────────────────────────
        skills_frame = ttk.Frame(pingmaker_tab)
        skills_frame.pack(fill=tk.X, pady=(0, 5))

        skills_header = tk.Frame(skills_frame, bg=ModernStyle.BG)
        skills_header.pack(fill=tk.X, pady=(0, 3))
        ttk.Label(skills_header, text="Skills & Attack Speed (%)").pack(side=tk.LEFT)
        tk.Label(skills_header, text="blank=skip",
                 font=("Segoe UI", 7), bg=ModernStyle.BG, fg=ModernStyle.TEXT_DIM).pack(side=tk.RIGHT)

        skills_outer = tk.Frame(skills_frame, bg=ModernStyle.BG_CARD,
                                highlightthickness=1, highlightbackground=ModernStyle.BORDER)
        skills_outer.pack(fill=tk.X)

        self.skills_canvas = tk.Canvas(skills_outer, bg=ModernStyle.BG_CARD,
                                        highlightthickness=0, bd=0, height=120)
        skills_scroll = tk.Scrollbar(skills_outer, orient=tk.VERTICAL,
                                      command=self.skills_canvas.yview)

        self.skills_inner = tk.Frame(self.skills_canvas, bg=ModernStyle.BG_CARD)
        self.skills_inner.bind("<Configure>",
            lambda e: self.skills_canvas.configure(scrollregion=self.skills_canvas.bbox("all")))

        self.skills_canvas_window = self.skills_canvas.create_window(
            (0, 0), window=self.skills_inner, anchor="nw")
        self.skills_canvas.configure(yscrollcommand=skills_scroll.set)

        self.skills_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        skills_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.skills_canvas.bind("<Configure>", self._on_skills_canvas_configure)
        self.skills_canvas.bind("<MouseWheel>", self._on_skills_mousewheel)
        self.skills_inner.bind("<MouseWheel>", self._on_skills_mousewheel)

        # ─── START/STOP BUTTON ───────────────────────────────────
        self.start_btn = tk.Button(
            pingmaker_tab, text="Start", font=("Segoe UI", 10, "bold"),
            bg=ModernStyle.ACCENT, fg="#ffffff",
            activebackground=ModernStyle.ACCENT_HOVER, activeforeground="#ffffff",
            relief=tk.FLAT, cursor="hand2",
            command=self.toggle_running
        )
        self.start_btn.pack(fill=tk.X, ipady=6, pady=(0, 5))

        # ─── STATUS ──────────────────────────────────────────────
        self.status_label = tk.Label(
            pingmaker_tab, text="Ready", font=("Segoe UI", 9),
            bg=ModernStyle.BG, fg=ModernStyle.TEXT_DIM
        )
        self.status_label.pack(pady=(0, 5))

        # ─── STATS ───────────────────────────────────────────────
        stats_frame = tk.Frame(pingmaker_tab, bg=ModernStyle.BG_CARD,
                               highlightthickness=1, highlightbackground=ModernStyle.BORDER)
        stats_frame.pack(fill=tk.X, pady=(0, 5))

        stats_inner = ttk.Frame(stats_frame, style="Card.TFrame", padding=(10, 6))
        stats_inner.pack(fill=tk.X)
        stats_inner.columnconfigure(0, weight=1)
        stats_inner.columnconfigure(1, weight=1)

        left_stats = ttk.Frame(stats_inner, style="Card.TFrame")
        left_stats.grid(row=0, column=0, sticky="w")
        ttk.Label(left_stats, text="Packets Modified", style="Stat.TLabel",
                  background=ModernStyle.BG_CARD).pack(anchor="w")
        self.modified_label = ttk.Label(left_stats, text="0", style="StatValue.TLabel",
                                         background=ModernStyle.BG_CARD)
        self.modified_label.pack(anchor="w")

        right_stats = ttk.Frame(stats_inner, style="Card.TFrame")
        right_stats.grid(row=0, column=1, sticky="e")
        ttk.Label(right_stats, text="Status", style="Stat.TLabel",
                  background=ModernStyle.BG_CARD).pack(anchor="e")
        self.status_label2 = ttk.Label(right_stats, text="Ready", style="StatValue.TLabel",
                                        background=ModernStyle.BG_CARD)
        self.status_label2.pack(anchor="e")

        # ─── PARTY FILTERING ────────────────────────────────────
        entity_frame = tk.Frame(pingmaker_tab, bg=ModernStyle.BG_CARD,
                                highlightthickness=1, highlightbackground=ModernStyle.BORDER)
        entity_frame.pack(fill=tk.X, pady=(0, 5))
        entity_inner = tk.Frame(entity_frame, bg=ModernStyle.BG_CARD, padx=10, pady=6)
        entity_inner.pack(fill=tk.X)
        tk.Label(entity_inner, text="Character Names", font=("Segoe UI", 9, "bold"),
                 bg=ModernStyle.BG_CARD, fg=ModernStyle.TEXT).pack(anchor="w")
        tk.Label(entity_inner, text="comma-separated, for party filtering",
                 font=("Segoe UI", 7), bg=ModernStyle.BG_CARD, fg=ModernStyle.TEXT_DIM).pack(anchor="w")
        char_entry = tk.Entry(
            entity_inner, textvariable=self.char_names_var, font=("Segoe UI", 9),
            bg=ModernStyle.BG_LIGHT, fg=ModernStyle.TEXT,
            insertbackground=ModernStyle.TEXT, relief=tk.FLAT,
            highlightthickness=1, highlightcolor=ModernStyle.ACCENT,
            highlightbackground=ModernStyle.BORDER
        )
        char_entry.pack(fill=tk.X, ipady=2, pady=(2, 2))
        self.char_names_var.trace('w', self._on_char_names_changed)
        self.entity_status_label = tk.Label(
            entity_inner, text="No filter active (modifies all players' packets)",
            font=("Segoe UI", 7), bg=ModernStyle.BG_CARD, fg=ModernStyle.TEXT_DIM
        )
        self.entity_status_label.pack(anchor="w")

        # ─── PLUGIN TABS ─────────────────────────────────────────
        for plugin in self._plugins:
            try:
                plugin.build_ui(notebook)
            except Exception:
                pass

        # ─── LOGGING OPTION (below notebook) ─────────────────────
        log_opt_frame = tk.Frame(main, bg=ModernStyle.BG)
        log_opt_frame.pack(fill=tk.X, pady=(3, 3))

        tk.Checkbutton(
            log_opt_frame, text="Write tool action logs", variable=self.csv_logging_enabled,
            font=("Segoe UI", 8), bg=ModernStyle.BG, fg=ModernStyle.TEXT,
            activebackground=ModernStyle.BG, activeforeground=ModernStyle.TEXT,
            selectcolor=ModernStyle.BG_LIGHT, command=self.on_setting_changed
        ).pack(side=tk.LEFT)

        # ─── LOG (below notebook) ────────────────────────────────
        log_frame = ttk.Frame(main)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 0))

        self.log_text = tk.Text(
            log_frame, font=("Consolas", 8),
            bg=ModernStyle.BG_LIGHT, fg=ModernStyle.TEXT_DIM,
            relief=tk.FLAT, highlightthickness=1,
            highlightbackground=ModernStyle.BORDER, height=5
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.configure(state=tk.DISABLED)

    def _on_skills_canvas_configure(self, event):
        self.skills_canvas.itemconfig(self.skills_canvas_window, width=event.width)

    def _on_skills_mousewheel(self, event):
        self.skills_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # ─── Skill Search ────────────────────────────────────────────

    def on_search_changed(self, *args):
        query = self.search_var.get()
        self.results_listbox.delete(0, tk.END)
        if len(query) < 2:
            self.results_frame.pack_forget()
            return
        results = fuzzy_search(query)
        if results:
            self.results_frame.pack(fill=tk.X, pady=(2, 0))
            for name in results:
                self.results_listbox.insert(tk.END, name)
        else:
            self.results_frame.pack_forget()

    def on_result_click(self, event):
        selection = self.results_listbox.curselection()
        if selection:
            name = self.results_listbox.get(selection[0])
            self.add_skill(name)
            self.search_var.set("")
            self.results_frame.pack_forget()

    # ─── Skill Management ────────────────────────────────────────

    def add_skill(self, name: str):
        if name in self.selected_skills:
            return
        if name not in SKILLS:
            return
        self.selected_skills[name] = {
            "ids": SKILLS[name],
            "attack_speed": None,
            "overflow": False,
        }
        self._add_skill_row(name)
        self.save_current_settings()

    def remove_skill(self, name: str):
        if name in self.selected_skills:
            del self.selected_skills[name]
            row = self._skill_rows.pop(name, None)
            if row:
                row['frame'].destroy()
            self.save_current_settings()

    def refresh_skill_list(self):
        for row_info in self._skill_rows.values():
            row_info['frame'].destroy()
        self._skill_rows.clear()
        for name in self.selected_skills:
            self._add_skill_row(name)

    def _add_skill_row(self, name: str):
        data = self.selected_skills.get(name)
        if not data:
            return

        row = tk.Frame(self.skills_inner, bg=ModernStyle.BG_CARD)
        row.pack(fill=tk.X, padx=4, pady=2)

        name_label = tk.Label(
            row, text=name, font=("Segoe UI", 8), anchor="w",
            bg=ModernStyle.BG_CARD, fg=ModernStyle.TEXT, width=20
        )
        name_label.pack(side=tk.LEFT, padx=(4, 6))

        speed_entry = tk.Entry(
            row, font=("Consolas", 8), width=7,
            bg=ModernStyle.BG_LIGHT, fg=ModernStyle.TEXT,
            insertbackground=ModernStyle.TEXT, relief=tk.FLAT,
            highlightthickness=1, highlightbackground=ModernStyle.BORDER,
            justify=tk.RIGHT
        )
        spd_val = data.get("attack_speed")
        if spd_val is None:
            speed_entry.insert(0, "")
        else:
            speed_entry.insert(0, str(spd_val))
        speed_entry.pack(side=tk.LEFT, padx=(0, 2))

        speed_entry.bind('<FocusOut>', lambda e: self.save_current_settings())
        speed_entry.bind('<Return>', lambda e: self.save_current_settings())
        speed_entry.bind("<MouseWheel>", self._on_skills_mousewheel)

        tk.Label(row, text="%", font=("Segoe UI", 8),
                 bg=ModernStyle.BG_CARD, fg=ModernStyle.TEXT_DIM).pack(side=tk.LEFT)

        overflow_var = tk.BooleanVar(value=data.get("overflow", False))
        overflow_cb = tk.Checkbutton(
            row, text="Break Packet", font=("Segoe UI", 7), variable=overflow_var,
            bg=ModernStyle.BG_CARD, fg=ModernStyle.TEXT_DIM,
            activebackground=ModernStyle.BG_CARD, selectcolor=ModernStyle.BG_LIGHT,
            command=self.save_current_settings
        )
        overflow_cb.pack(side=tk.LEFT, padx=(6, 0))

        remove_btn = tk.Button(
            row, text="\u2715", font=("Segoe UI", 8, "bold"),
            bg=ModernStyle.BG_CARD, fg=ModernStyle.RED,
            activebackground=ModernStyle.RED, activeforeground="#ffffff",
            relief=tk.FLAT, width=2, cursor="hand2",
            command=lambda n=name: self.remove_skill(n)
        )
        remove_btn.pack(side=tk.RIGHT, padx=4)

        for widget in row.winfo_children():
            if widget != speed_entry:
                widget.bind("<MouseWheel>", self._on_skills_mousewheel)

        self._skill_rows[name] = {
            'frame': row,
            'speed_entry': speed_entry,
            'overflow_var': overflow_var,
        }

    # ─── Logging ─────────────────────────────────────────────────

    def log(self, message: str):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def get_logs_folder(self):
        exe_dir = os.path.dirname(get_settings_path())
        logs_dir = os.path.join(exe_dir, "logs")
        if not os.path.exists(logs_dir):
            try:
                os.makedirs(logs_dir)
            except:
                logs_dir = exe_dir
        return logs_dir

    def start_packet_log(self):
        if not self.csv_logging_enabled.get():
            return
        try:
            logs_dir = self.get_logs_folder()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_path = os.path.join(logs_dir, f"packets_{timestamp}.jsonl")
            self.log_writer = AsyncLogWriter(log_path)
            self.log(f"Packet log: logs/packets_{timestamp}.jsonl")
        except Exception as e:
            self.log(f"Packet log error: {e}")
            self.log_writer = None

    def stop_packet_log(self):
        if self.log_writer:
            self.log_writer.close()
            self.log_writer = None

    def log_packet(self, entry: dict):
        if not self.log_writer:
            return
        entry['timestamp'] = datetime.now().isoformat()
        self.log_writer.put(entry)

    def set_status(self, text: str, color: str = None):
        self.status_label.config(text=text, fg=color or ModernStyle.TEXT_DIM)

    # ─── Capture Control ─────────────────────────────────────────

    def toggle_running(self):
        if self.is_running:
            self.stop_capture()
        else:
            self.start_capture()

    def toggle_learning(self):
        if self.is_learning:
            self.stop_learning()
        else:
            self.start_learning()

    def start_learning(self):
        if self.is_running:
            self.set_status("Stop capture first", ModernStyle.ERROR)
            return
        if not self.entity_tracker.is_configured:
            self.set_status("Set character names first", ModernStyle.ERROR)
            return
        self.is_learning = True
        self.stop_event.clear()
        self.learned_skills = set()
        self.learn_btn.config(text="Stop", bg=ModernStyle.RED, fg="#ffffff")
        self.start_btn.config(state=tk.DISABLED)
        self.set_status("Use skills in game to detect them...", ModernStyle.ACCENT)
        self.log("Learning mode: Use your skills in game")
        self.worker_thread = threading.Thread(target=self.learning_worker, daemon=True)
        self.worker_thread.start()

    def stop_learning(self):
        self.stop_event.set()
        self.is_learning = False
        self.learn_btn.config(text="Auto-Detect", bg=ModernStyle.BLUE, fg=ModernStyle.TEXT)
        self.start_btn.config(state=tk.NORMAL)
        if self.learned_skills:
            self.set_status(f"Learned {len(self.learned_skills)} skills", ModernStyle.SUCCESS)
            self.log(f"Detected {len(self.learned_skills)} skills")
        else:
            self.set_status("No skills detected", ModernStyle.TEXT_DIM)

    def learning_worker(self):
        def on_ports_change(ports):
            self.root.after(0, lambda: self.log(f"Ports: {sorted(ports)}"))

        tracker = PortTracker(refresh_interval=2.0)
        tracker.start(on_change=on_ports_change)

        time.sleep(0.5)
        initial_ports = tracker.get_ports()
        detected_via = tracker.get_detected_via()

        if initial_ports:
            via_str = f" via {detected_via}" if detected_via else ""
            self.root.after(0, lambda: self.log(f"Monitoring ports{via_str}: {sorted(initial_ports)}"))
        else:
            self.root.after(0, lambda: self.log("Waiting for game connection..."))

        try:
            w = pydivert.WinDivert(SNIFF_FILTER, flags=pydivert.Flag.SNIFF)
            w.open()
            self.root.after(0, lambda: self.log("Listening for skills..."))
        except PermissionError:
            self.root.after(0, lambda: self.log("ERROR: Run as Administrator"))
            self.root.after(0, lambda: self.set_status("Run as Administrator", ModernStyle.ERROR))
            tracker.stop()
            self.root.after(0, self.stop_learning)
            return
        except Exception as e:
            self.root.after(0, lambda: self.log(f"ERROR: {e}"))
            self.root.after(0, lambda: self.set_status("WinDivert error", ModernStyle.ERROR))
            tracker.stop()
            self.root.after(0, self.stop_learning)
            return

        try:
            while not self.stop_event.is_set():
                try:
                    packet = w.recv()
                except Exception:
                    if self.stop_event.is_set():
                        break
                    continue
                if not packet.payload:
                    continue
                data = packet.payload
                if len(data) < 50 or data[10:12] != b'\x01\x01' or data[32] != 0x22:
                    continue
                skill_id, skill_offset = find_skill_id(data)
                if skill_id and skill_id in SKILL_ID_TO_NAME:
                    name = SKILL_ID_TO_NAME[skill_id]
                    if name not in self.selected_skills and name not in self.learned_skills:
                        self.learned_skills.add(name)
                        self.root.after(0, lambda n=name: self._add_learned_skill(n))
        except Exception as e:
            self.root.after(0, lambda: self.log(f"Error: {e}"))
        finally:
            try:
                w.close()
            except:
                pass
            tracker.stop()
            self.root.after(0, self.stop_learning)

    def _add_learned_skill(self, name: str):
        if name not in self.selected_skills:
            self.add_skill(name)
            self.log(f"  + {name}")

    def start_capture(self):
        uniform = self._parse_uniform_speed()
        if not self.selected_skills and uniform is None:
            self.set_status("No skills selected", ModernStyle.ERROR)
            return

        self._rebuild_lookups()

        self.is_running = True

        if not self.capture_active:
            self.stop_event.clear()
            self.stats = defaultdict(int)
            self._ui_log_queue = queue.Queue()

            self.start_packet_log()

            active_skills = sum(1 for d in self.selected_skills.values()
                                if d.get("attack_speed") is not None)
            self.log(f"Starting with {len(self.selected_skills)} skills ({active_skills} with speed override)")

            self.capture_active = True
            self.worker_thread = threading.Thread(target=self.capture_worker, daemon=True)
            self.worker_thread.start()
        else:
            self.log("Resumed capture")

        self.start_btn.config(text="Stop", bg=ModernStyle.BLUE, fg="#ffffff")
        self.set_status("Active", ModernStyle.SUCCESS)
        self.update_stats_loop()

    def stop_capture(self):
        self.is_running = False
        self.start_btn.config(text="Start", bg=ModernStyle.ACCENT, fg="#ffffff")
        if self.capture_active:
            self.set_status("Logging (paused)", ModernStyle.TEXT_DIM)
            self.log("Paused - still logging skills")
        else:
            self.set_status("Stopped")
            self.log("Stopped")

    def full_stop_capture(self):
        self.stop_event.set()
        self.is_running = False
        self.capture_active = False
        self.stop_packet_log()
        if hasattr(self, '_stream_diag_writer') and self._stream_diag_writer:
            self._stream_diag_writer.close()
            self._stream_diag_writer = None
        self.start_btn.config(text="Start", bg=ModernStyle.ACCENT, fg="#ffffff")
        self.set_status("Stopped")

    def update_stats_loop(self):
        if not self.is_running and not self.capture_active:
            return

        ui_q = getattr(self, '_ui_log_queue', None)
        if ui_q:
            for _ in range(20):
                try:
                    msg = ui_q.get_nowait()
                    self.log(msg)
                except queue.Empty:
                    break

        modified = self.stats.get('modified', 0)
        self.modified_label.config(text=str(modified))
        self.status_label2.config(text="Active" if self.is_running else "Ready")

        # Update plugin status
        for plugin in self._plugins:
            try: plugin.update_status()
            except Exception: pass

        # Update entity tracking status
        self._update_entity_status_label()

        self.root.after(250, self.update_stats_loop)

    # ─── Pre-computation ─────────────────────────────────────────

    def _parse_uniform_speed(self):
        """Parse uniform speed StringVar → None | int."""
        text = self.uniform_speed.get().strip()
        if text == '':
            return None
        try:
            return int(text)
        except ValueError:
            return None

    def _build_speed_lookup(self) -> dict:
        uniform = self._parse_uniform_speed()
        uniform_brk = self.uniform_break.get()
        lookup = {}
        if uniform is not None and isinstance(uniform, int) and uniform > 0:
            varint_value = uniform * 100
            encoded = encode_varint(varint_value)
            entry = (encoded, len(encoded), uniform, uniform_brk)
            for skill_id in ALL_SKILL_IDS:
                lookup[skill_id] = entry
        # Per-skill overrides (or primary entries when uniform is blank)
        for name, data in self.selected_skills.items():
            speed_val = data.get("attack_speed")
            if speed_val is None:
                continue  # passthrough
            brk = data.get("overflow", False)
            if isinstance(speed_val, int) and speed_val >= 0:
                varint_value = speed_val * 100
                encoded = encode_varint(varint_value)
                entry = (encoded, len(encoded), speed_val, brk)
            else:
                continue
            for skill_id in data["ids"]:
                lookup[skill_id] = entry
        return lookup

    # ─── N-Worker Capture Pool ────────────────────────────────────

    def _rebuild_lookups(self):
        """Rebuild speed lookup and target first-bytes from current UI settings.
        Called on start and whenever settings change at runtime."""
        self._sync_speed_values_from_ui()
        uniform = self._parse_uniform_speed()
        if uniform is not None:
            self.target_ids = set(ALL_SKILL_IDS)
        else:
            self.target_ids = set()
            for data in self.selected_skills.values():
                self.target_ids.update(data["ids"])
        # Merge IDs required by plugins (e.g. weave trigger skills)
        for p in self._plugins:
            try:
                self.target_ids.update(p.get_required_skill_ids())
            except Exception:
                pass
        self.skill_id_to_speed = self._build_speed_lookup()
        self.target_first_bytes = set()
        for sid in self.target_ids:
            self.target_first_bytes.add(sid & 0xFF)

    def capture_worker(self):
        self._rebuild_lookups()

        # Adopt the entity tracker that the background sniffer has been populating
        # (don't create a new one — it already has learned bindings)

        # Stream reassembler for nickname packet parsing (shared across workers)
        diag_writer = None
        diag_log_msg = None
        if self.csv_logging_enabled.get():
            try:
                logs_dir = self.get_logs_folder()
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                diag_path = os.path.join(logs_dir, f"stream_diag_{timestamp}.jsonl")
                diag_writer = AsyncLogWriter(diag_path)
                diag_log_msg = f"Stream diag: logs/stream_diag_{timestamp}.jsonl"
            except Exception:
                diag_writer = None
        self._stream_diag_writer = diag_writer
        self._stream_reassembler = StreamReassembler(diag_writer=diag_writer)
        self._reassembler_lock = threading.Lock()

        self._ui_log_queue = queue.Queue()

        self._learned_speed_bytes = None
        self._learned_speed_value = 0
        self._learned_session_bytes = None

        def ui_log(msg):
            try:
                self._ui_log_queue.put_nowait(msg)
            except queue.Full:
                pass

        # Start plugins
        _plugins = self._plugins
        logs_dir = self.get_logs_folder()
        for p in _plugins:
            try: p.on_start(logs_dir, ui_log)
            except Exception: pass

        if diag_log_msg:
            ui_log(diag_log_msg)

        _reopen_event = threading.Event()
        _current_ports = [None]
        _loopback_mode = [False]

        def on_ports_change(ports):
            ui_log(f"Ports: {sorted(ports)}")
            _current_ports[0] = ports
            # Read attribute directly — callback runs inside tracker._lock,
            # so calling get_loopback_mode() would deadlock (non-reentrant lock).
            _loopback_mode[0] = tracker.loopback_mode
            _reopen_event.set()

        tracker = PortTracker(refresh_interval=2.0)
        tracker.start(on_change=on_ports_change)

        time.sleep(0.5)
        initial_ports = tracker.get_ports()
        _current_ports[0] = initial_ports
        detected_via = tracker.get_detected_via()
        _loopback_mode[0] = tracker.get_loopback_mode()

        if initial_ports:
            if detected_via == "Direct":
                self.root.after(0, lambda: self.set_status("Active (Direct)", ModernStyle.SUCCESS))
                ui_log(f"Direct: ports {sorted(initial_ports)}")
            elif _loopback_mode[0]:
                self.root.after(0, lambda dv=detected_via: self.set_status(f"Active via {dv or 'VPN'} (loopback)", ModernStyle.SUCCESS))
                ui_log(f"Loopback via {detected_via or 'VPN'}: proxy ports {sorted(initial_ports)}")
            else:
                self.root.after(0, lambda dv=detected_via: self.set_status(f"Active via {dv or 'VPN'}", ModernStyle.SUCCESS))
                ui_log(f"VPN proxy: ports {sorted(initial_ports)}")
        else:
            self.root.after(0, lambda: self.set_status("Scanning for game traffic...", ModernStyle.ACCENT))
            ui_log("Waiting to detect game traffic...")

        first_open = True
        while not self.stop_event.is_set():
            ports = _current_ports[0]
            handles = []

            try:
                is_loopback = _loopback_mode[0]
                if ports:
                    # One WinDivert handle per port — independent kernel queues
                    for port in sorted(ports):
                        if is_loopback:
                            filt = _build_single_loopback_port_filter(port)
                        else:
                            filt = _build_single_port_filter(port)
                        w = pydivert.WinDivert(filt)
                        w.open()
                        _tune_handle(w)
                        handles.append(w)
                    total_workers = len(handles) * WORKERS_PER_HANDLE
                    mode_str = "loopback" if is_loopback else "direct"
                    ui_log(f"Intercepting packets ({len(handles)} handles, "
                           f"{WORKERS_PER_HANDLE} workers each = {total_workers} total, {mode_str})")
                else:
                    # No ports detected — single broad handle
                    if is_loopback:
                        w = pydivert.WinDivert(LOOPBACK_CAPTURE_FILTER)
                    else:
                        w = pydivert.WinDivert(CAPTURE_FILTER)
                    w.open()
                    _tune_handle(w)
                    handles.append(w)
                    mode_str = "loopback" if is_loopback else "direct"
                    ui_log(f"Intercepting packets (broad filter, {WORKER_COUNT} workers, {mode_str})")
            except PermissionError:
                for h in handles:
                    try: h.close()
                    except: pass
                if first_open:
                    self.root.after(0, lambda: self.log("ERROR: Run as Administrator"))
                    self.root.after(0, lambda: self.set_status("Run as Administrator", ModernStyle.ERROR))
                    tracker.stop()
                    self.root.after(0, self.stop_capture)
                    return
                ui_log("Reopen failed (permission), falling back to broad filter")
                _current_ports[0] = None
                continue
            except Exception as e:
                for h in handles:
                    try: h.close()
                    except: pass
                if first_open:
                    self.root.after(0, lambda: self.log(f"ERROR: {e}"))
                    self.root.after(0, lambda: self.set_status("WinDivert error", ModernStyle.ERROR))
                    tracker.stop()
                    self.root.after(0, self.stop_capture)
                    return
                ui_log(f"Reopen failed: {e}, falling back to broad filter")
                _current_ports[0] = None
                continue

            first_open = False
            workers = []
            for h in handles:
                n = WORKERS_PER_HANDLE if len(handles) > 1 else WORKER_COUNT
                for _ in range(n):
                    t = threading.Thread(
                        target=self._packet_worker,
                        args=(h, ui_log, _plugins),
                        daemon=True,
                    )
                    t.start()
                    workers.append(t)

            # Wait for stop or port change
            _reopen_event.clear()
            if _current_ports[0] != ports:
                pass  # ports changed during open — reopen immediately
            else:
                while not self.stop_event.is_set() and not _reopen_event.is_set():
                    self.stop_event.wait(timeout=0.5)

            for h in handles:
                try: h.close()
                except: pass

            for t in workers:
                t.join(timeout=3)

            if self.stop_event.is_set():
                break

            new_ports = _current_ports[0]
            new_lb = "loopback" if _loopback_mode[0] else "direct"
            ui_log(f"Port change — reopening handles ({len(new_ports) if new_ports else 'broad'} ports, {new_lb})")

        # Stop plugins
        for p in _plugins:
            try: p.on_stop()
            except Exception: pass

        tracker.stop()
        self.capture_active = False
        self.root.after(0, self.full_stop_capture)

    def _packet_worker(self, w, ui_log, _plugins):
        _unpack_from = struct.unpack_from
        _has_prefix = has_skill_prefix
        _find_speed = find_attack_speed_offset
        _parse_varint = parse_varint
        _id_to_name = SKILL_ID_TO_NAME
        stop = self.stop_event
        stats = self.stats
        is_running_ref = lambda: self.is_running
        entity_tracker = self.entity_tracker
        stream_reassembler = self._stream_reassembler
        _reassembler_lock = self._reassembler_lock

        while not stop.is_set():
            try:
                packet = w.recv()
            except Exception:
                break

            raw = packet.raw
            raw_len = len(raw)
            if raw_len < 40:
                try:
                    w.send(packet)
                except Exception:
                    pass
                continue

            ip_hdr_len = (raw[0] & 0x0F) * 4
            tcp_hdr_len = (raw[ip_hdr_len + 12] >> 4) * 4
            payload_offset = ip_hdr_len + tcp_hdr_len
            if payload_offset >= raw_len:
                try:
                    w.send(packet)
                except Exception:
                    pass
                continue

            payload = raw[payload_offset:]   # memoryview — zero copy
            plen = raw_len - payload_offset

            # ── FAST PATH: non-skill packets ──
            # Check structure signature first — most packets fail here.
            # Send them back immediately, THEN do reassembly/plugins.
            #
            # Loopback capture: identical game protocol, just without the
            # ~25-byte transport framing that direct mode prepends.
            # Skill prefix starts at byte 7 (vs 32 direct), minimum
            # packet length 62 (vs 87 direct).
            is_skill_candidate = (plen >= 62)
            scan_start = 7

            if not is_skill_candidate:
                # Re-inject immediately — don't hold the packet while processing
                try:
                    w.send(packet)
                except Exception:
                    pass
                # Now do non-critical work (reassembly, plugins) without blocking
                if plen > 3:
                    with _reassembler_lock:
                        bindings = stream_reassembler.feed(payload)
                    for actor_id, name, strategy, msg_hex, byte5 in bindings:
                        is_candidate = entity_tracker.on_nickname_binding(actor_id, name, byte5=byte5)
                        self.log_packet({
                            'action': 'entity_binding' if is_candidate else 'entity_rejected',
                            'accepted': is_candidate,
                            'actor_id': actor_id,
                            'name': name,
                            'strategy': strategy,
                            'byte5': byte5,
                            'msg_hex': msg_hex,
                            'all_keys': sorted(entity_tracker.get_my_keys()),
                        })
                        if is_candidate:
                            ui_log(f"[Entity] Bound: {name} -> key {actor_id} ({strategy} b5=0x{byte5:02x})")
                if _plugins:
                    _src_port = _unpack_from('>H', raw, ip_hdr_len)[0]
                    _dst_port = _unpack_from('>H', raw, ip_hdr_len + 2)[0]
                    ctx = PacketContext(payload, plen, raw, payload_offset, time.time(),
                                       _src_port, _dst_port)
                    for p in _plugins:
                        try: p.on_packet(ctx)
                        except Exception: pass
                continue

            # ── SKILL CANDIDATE PATH: modify + re-inject ASAP ──

            # Inline skill ID scan (read live from self for hot-reload)
            skill_id = 0
            skill_offset = -1
            prefix_ok = False
            _target_first_bytes = self.target_first_bytes
            _target_ids = self.target_ids
            end = min(plen - 3, scan_start + 200)
            for i in range(scan_start, end):
                if payload[i] not in _target_first_bytes:
                    continue
                val = _unpack_from('<I', payload, i)[0]
                if val in _target_ids:
                    skill_id = val
                    skill_offset = i
                    prefix_ok = _has_prefix(payload, i)
                    break

            if not skill_id:
                # Secondary scan for unknown IDs — send immediately
                _unknown_log = None
                for i in range(scan_start, end - 7):
                    if payload[i] != 0x38:
                        continue
                    if i + 10 > plen:
                        break
                    yy = payload[i + 3]
                    if yy not in (0x00, 0x01):
                        continue
                    if yy == 0x00 and payload[i + 2] == 0x00:
                        continue
                    if payload[i + 9] not in (0x00, 0x02, 0x03, 0x04, 0x06):
                        continue
                    unknown_id = _unpack_from('<I', payload, i + 4)[0]
                    if unknown_id not in _target_ids:
                        unknown_name = _id_to_name.get(unknown_id)
                        _unknown_log = {
                            'action': 'unknown_id',
                            'unknown_id': unknown_id,
                            'unknown_id_hex': f"0x{unknown_id:08X}",
                            'known_name': unknown_name,
                            'prefix_offset': i,
                            'prefix': payload[i:i+4].hex(),
                            'pkt_type': payload[i + 9],
                            'pkt_len': plen,
                            'raw': payload.hex(),
                        }
                try:
                    w.send(packet)
                except Exception:
                    pass
                if _unknown_log:
                    self.log_packet(_unknown_log)
                continue

            # Found a skill ID — extract metadata
            pkt_type = payload[skill_offset + 5] if skill_offset + 5 < plen else -1
            tick_byte = payload[skill_offset + 4] if skill_offset + 4 < plen else -1
            skill_name = _id_to_name.get(skill_id, f"ID:{skill_id}")

            entity_key = None
            if skill_offset >= 3:
                ek, ek_len = _parse_varint(payload, skill_offset - 3)
                if ek_len > 0 and ek > 0:
                    entity_key = ek
                else:
                    ek, ek_len = _parse_varint(payload, skill_offset - 2)
                    if ek_len > 0 and ek > 0:
                        entity_key = ek

            pfx_start = skill_offset - 4
            prefix_hex = payload[pfx_start:skill_offset].hex() if pfx_start >= 0 else ''

            log_entry = {
                'skill_name': skill_name,
                'skill_id': skill_id,
                'skill_id_hex': f"0x{skill_id:08X}",
                'skill_offset': skill_offset,
                'prefix': prefix_hex,
                'tick': tick_byte,
                'pkt_type': pkt_type,
                'pkt_len': plen,
                'prefix_ok': prefix_ok,
            }
            if entity_key is not None:
                log_entry['entity_key'] = entity_key

            # Entity filter — send immediately if not ours
            if entity_tracker.is_configured:
                if not entity_tracker.has_any_keys():
                    log_entry['action'] = 'no_entity_keys'
                    try:
                        w.send(packet)
                    except Exception:
                        pass
                    log_entry['raw'] = payload.hex()
                    self.log_packet(log_entry)
                    continue
                if entity_key is not None and not entity_tracker.is_my_entity(entity_key):
                    log_entry['action'] = 'foreign_entity'
                    try:
                        w.send(packet)
                    except Exception:
                        pass
                    log_entry['raw'] = payload.hex()
                    self.log_packet(log_entry)
                    continue

            # Confirm entity on ACT
            if (pkt_type == 0x02 and entity_key is not None
                    and entity_tracker.is_configured):
                if entity_tracker.confirm_sole_key(entity_key):
                    ui_log(f"[Entity] Confirmed key {entity_key} from ACT {skill_name}")

            # Learn session + speed bytes (ACT only)
            speed_result = None
            if prefix_ok and pkt_type == 0x02:
                speed_result = _find_speed(payload, skill_offset)
                if speed_result:
                    spd_off, spd_len, spd_val = speed_result
                    self._learned_speed_bytes = bytes(payload[spd_off:spd_off + spd_len])
                    self._learned_speed_value = spd_val
                    if pfx_start >= 0:
                        self._learned_session_bytes = bytes(payload[pfx_start + 1:pfx_start + 3])

            # ── Speed modification (the only thing that touches packet bytes) ──
            if prefix_ok and pkt_type == 0x02 and is_running_ref():
                speed_info = self.skill_id_to_speed.get(skill_id)
                if not speed_info:
                    u = self._parse_uniform_speed()
                    if u is not None and isinstance(u, int) and u > 0:
                        ue = encode_varint(u * 100)
                        speed_info = (ue, len(ue), u, self.uniform_break.get())

                if speed_info and speed_result:
                    encoded_speed, encoded_len, speed_pct, allow_break = speed_info
                    spd_off, spd_len, spd_val = speed_result
                    raw_off = payload_offset + spd_off

                    if spd_val < 10000:
                        log_entry['action'] = 'below_threshold'
                    elif allow_break:
                        broken = b'\xff' * spd_len
                        packet.raw[raw_off:raw_off + spd_len] = broken
                        stats['modified'] += 1
                        log_entry['action'] = 'modified_break'
                        log_entry['original_speed'] = spd_val
                    else:
                        if encoded_len != spd_len:
                            encoded_speed = encode_varint_fixed(speed_pct * 100, spd_len)
                            encoded_len = len(encoded_speed)
                        if encoded_len == spd_len:
                            packet.raw[raw_off:raw_off + spd_len] = encoded_speed
                            stats['modified'] += 1
                            log_entry['action'] = 'modified'
                            log_entry['original_speed'] = spd_val
                            log_entry['new_speed'] = speed_pct * 100
                        else:
                            max_val = (1 << (7 * spd_len)) - 1
                            capped = encode_varint_fixed(min(speed_pct * 100, max_val), spd_len)
                            packet.raw[raw_off:raw_off + spd_len] = capped
                            stats['modified'] += 1
                            log_entry['action'] = 'modified_capped'
                            log_entry['original_speed'] = spd_val
                            log_entry['new_speed'] = min(speed_pct * 100, max_val)
                            log_entry['cap_limit'] = max_val
                elif speed_info:
                    log_entry['action'] = 'no_speed_offset'
                else:
                    log_entry['action'] = 'no_speed_config'

            elif not prefix_ok and is_running_ref():
                learned_speed = self._learned_speed_bytes
                learned_session = self._learned_session_bytes
                speed_info = self.skill_id_to_speed.get(skill_id)
                if not speed_info:
                    u = self._parse_uniform_speed()
                    if u is not None and isinstance(u, int) and u > 0:
                        ue = encode_varint(u * 100)
                        speed_info = (ue, len(ue), u, self.uniform_break.get())
                if learned_speed and learned_session and speed_info:
                    payload_b = bytes(payload)
                    has_session = payload_b.find(learned_session, 7) >= 0
                    if has_session:
                        encoded_speed, encoded_len, speed_pct, allow_break = speed_info
                        learned_len = len(learned_speed)
                        pos = payload_b.find(learned_speed, skill_offset + 6)
                        if pos >= 0 and self._learned_speed_value < 10000:
                            log_entry['action'] = 'below_threshold'
                        elif pos >= 0:
                            raw_off = payload_offset + pos
                            fb_speed_pct = speed_pct
                            if allow_break:
                                broken = b'\xff' * learned_len
                                packet.raw[raw_off:raw_off + learned_len] = broken
                                log_entry['break'] = True
                            else:
                                if encoded_len != learned_len:
                                    encoded_speed = encode_varint_fixed(speed_pct * 100, learned_len)
                                    encoded_len = len(encoded_speed)
                                if learned_len == encoded_len:
                                    packet.raw[raw_off:raw_off + learned_len] = encoded_speed
                                else:
                                    max_val = (1 << (7 * learned_len)) - 1
                                    capped = encode_varint_fixed(min(speed_pct * 100, max_val), learned_len)
                                    packet.raw[raw_off:raw_off + learned_len] = capped
                                    fb_speed_pct = min(speed_pct * 100, max_val) / 100
                                    log_entry['capped'] = True
                            stats['modified'] += 1
                            log_entry['action'] = 'fallback_break' if log_entry.get('break') else 'fallback_modified'
                            log_entry['original_speed'] = self._learned_speed_value
                            log_entry['new_speed'] = fb_speed_pct * 100
                            log_entry['speed_offset'] = pos
                        else:
                            log_entry['action'] = 'prefix_fail_no_speed'
                    else:
                        log_entry['action'] = 'prefix_fail'
                else:
                    log_entry['action'] = 'prefix_fail'

            elif prefix_ok and pkt_type != 0x02:
                log_entry['action'] = 'non_act'
            elif prefix_ok:
                log_entry['action'] = 'paused'
            else:
                log_entry['action'] = 'prefix_fail'

            # ── RE-INJECT IMMEDIATELY — packet is done ──
            try:
                w.send(packet)
            except Exception as e:
                ui_log(f"SEND ERR: {e}")

            # ── POST-SEND: non-critical work (doesn't touch packet) ──

            # Reassembly for entity detection
            if plen > 3:
                with _reassembler_lock:
                    bindings = stream_reassembler.feed(payload)
                for actor_id, name, strategy, msg_hex, byte5 in bindings:
                    is_candidate = entity_tracker.on_nickname_binding(actor_id, name, byte5=byte5)
                    self.log_packet({
                        'action': 'entity_binding' if is_candidate else 'entity_rejected',
                        'accepted': is_candidate,
                        'actor_id': actor_id,
                        'name': name,
                        'strategy': strategy,
                        'byte5': byte5,
                        'msg_hex': msg_hex,
                        'all_keys': sorted(entity_tracker.get_my_keys()),
                    })
                    if is_candidate:
                        ui_log(f"[Entity] Bound: {name} -> key {actor_id} ({strategy} b5=0x{byte5:02x})")

            # Plugin callbacks
            if _plugins:
                _src_port = _unpack_from('>H', raw, ip_hdr_len)[0]
                _dst_port = _unpack_from('>H', raw, ip_hdr_len + 2)[0]
                ctx = PacketContext(payload, plen, raw, payload_offset, time.time(),
                                   _src_port, _dst_port)
                for p in _plugins:
                    try: p.on_packet(ctx)
                    except Exception: pass

            # Dispatch to weave plugin (on_skill_act is async, won't block)
            if pkt_type in (0x02, 0x03) and _plugins:
                evt = SkillEvent(skill_name, skill_id, pkt_type, tick_byte, prefix_ok, entity_key)
                for p in _plugins:
                    try:
                        p.on_skill_event(evt)
                    except Exception as e:
                        ui_log(f"[Plugin] {p.name} error: {e}")

            # Notify plugins of learned speed
            if speed_result and _plugins:
                spd_off, spd_len, spd_val = speed_result
                raw_spd = bytes(payload[spd_off:spd_off + spd_len])
                for p in _plugins:
                    try: p.set_learned_speed(spd_val, raw_spd)
                    except Exception: pass

            # Log (deferred raw hex)
            log_entry['raw'] = payload.hex()
            self.log_packet(log_entry)


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="Pingmaker — Packet speed modifier")

    # Let plugins register their CLI args
    plugin_classes = TickToolApp._discover_plugins()
    for cls in plugin_classes:
        cls.add_arguments(parser)

    args = parser.parse_args()

    if not load_skills():
        import tkinter.messagebox as mb
        root = tk.Tk()
        root.withdraw()
        mb.showerror("Error", "Could not load skills.json\n\nRun build_skill_list.py first.")
        return

    # Instantiate plugins from CLI args
    plugins = []
    for cls in plugin_classes:
        instance = cls.from_args(args)
        if instance:
            plugins.append(instance)

    root = tk.Tk()
    app = TickToolApp(root, plugins=plugins)
    root.mainloop()


if __name__ == "__main__":
    main()
