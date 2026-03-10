"""Weave engine — vision-driven follow-up key sender via Pico HID bridge.

When the capture engine detects an ACT packet for a trigger skill
(Vicious Strike, Decisive Strike, Desperate Strike, Threatening Blow),
the weave engine checks screen state via template matching and sends
the appropriate follow-up key through the Raspberry Pi Pico.

Flow:
  1. Player holds key 2 -> trigger loop sends key 1 via Pico every 45ms
  2. Server responds with ACT packet -> capture engine calls on_skill_act()
  3. Vision checks which skills are off cooldown (template matching)
  4. Follow-up key sent via Pico (3, V, 5, X, 4, or 9 fallback)
"""

import os
import time
import threading
from pathlib import Path
from datetime import datetime

try:
    import win32gui
    import win32ui
    import win32con
    import numpy as np
    import cv2
    HAS_VISION_DEPS = True
except ImportError:
    HAS_VISION_DEPS = False

from pico_bridge import PicoBridge, find_pico_port
from raw_input_reader import RawInputReader


# ── Scancode constants ─────────────────────────────────────────

KEY_MAP = {
    0x31: 0x02, 0x32: 0x03, 0x33: 0x04, 0x34: 0x05, 0x35: 0x06,
    0x36: 0x07, 0x37: 0x08, 0x38: 0x09, 0x39: 0x0A, 0x30: 0x0B,
    0x52: 0x13,  # R
    0x70: 0x3B, 0x71: 0x3C, 0x72: 0x3D, 0x73: 0x3E, 0x74: 0x3F,
    0x75: 0x40, 0x76: 0x41, 0x77: 0x42, 0x78: 0x43, 0x79: 0x44,
    0x7A: 0x57, 0x7B: 0x58,
}

SCANCODE_NAMES = {
    0x02: '1', 0x03: '2', 0x04: '3', 0x05: '4', 0x06: '5',
    0x07: '6', 0x08: '7', 0x09: '8', 0x0A: '9', 0x0B: '0',
    0x13: 'R', 0x16: 'U', 0x22: 'G',
    0x2D: 'X', 0x2F: 'V',
}

SC_1 = 0x02
SC_2 = 0x03
SC_3 = 0x04
SC_4 = 0x05
SC_5 = 0x06
SC_9 = 0x0A
SC_X = 0x2D
SC_V = 0x2F
SC_R = 0x13
SC_U = 0x16
SC_G = 0x22

TRIGGER_KEYS = {SC_2}
SHIELD_KEYS = {SC_R}
SLEEP_HOLD = 0.005

# ── Vision constants ───────────────────────────────────────────

MATCH_THRESHOLD = 0.95
BRIGHTNESS_TOLERANCE = 25
POTION_COOLDOWN = 1.0
HEALTH_THRESHOLD = 60

# Screen regions (1920x1080)
PUNISHMENT_REGION = (625, 1032, 46, 22)
NOBLE_ARMOR_REGION = (965, 1030, 46, 25)
TAUNT_REGION = (1027, 1032, 33, 19)
STAGGER_REGION = (1091, 1036, 33, 19)
SHIELD_SMITE_REGION = (1140, 1031, 43, 23)
HEALTHBAR_REGION = (666, 938, 252, 1)
BUFFBAR_REGION = (959, 897, 294, 34)

# ── Trigger skill names ───────────────────────────────────────

WEAVE_TRIGGER_NAMES = [
    "Vicious Strike", "Decisive Strike",
    "Desperate Strike", "Threatening Blow",
]


def build_trigger_ids(skills: dict) -> set:
    """Build set of skill IDs for the trigger skills."""
    ids = set()
    for name in WEAVE_TRIGGER_NAMES:
        ids.update(skills.get(name, []))
    return ids


# ── Screen capture ─────────────────────────────────────────────

class ScreenCapture:
    """Lightweight GDI screen capture."""

    def __init__(self):
        hwnd = win32gui.GetDesktopWindow()
        hwnd_dc = win32gui.GetWindowDC(hwnd)
        self.mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
        self.save_dc = self.mfc_dc.CreateCompatibleDC()

    def capture_region(self, x, y, w, h):
        try:
            bmp = win32ui.CreateBitmap()
            bmp.CreateCompatibleBitmap(self.mfc_dc, w, h)
            self.save_dc.SelectObject(bmp)
            self.save_dc.BitBlt((0, 0), (w, h), self.mfc_dc, (x, y), win32con.SRCCOPY)
            img = np.frombuffer(bmp.GetBitmapBits(True), dtype='uint8')
            img.shape = (h, w, 4)
            win32gui.DeleteObject(bmp.GetHandle())
            return cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
        except Exception:
            return None


# ── Template matching ──────────────────────────────────────────

class TemplateData:
    def __init__(self, path, region, threshold=MATCH_THRESHOLD, check_brightness=True):
        self.img = cv2.imread(str(path), cv2.IMREAD_COLOR)
        if self.img is None:
            raise RuntimeError(f"Could not load template: {path}")
        gray = cv2.cvtColor(self.img, cv2.COLOR_BGR2GRAY)
        self.brightness = np.mean(gray)
        self.region = region
        self.threshold = threshold
        self.check_brightness = check_brightness


class MatchResult:
    def __init__(self, template_match=False, brightness_match=False,
                 confidence=0.0, region_brightness=0.0):
        self.template_match = template_match
        self.brightness_match = brightness_match
        self.confidence = confidence
        self.region_brightness = region_brightness
        self.detected = template_match and brightness_match


class VisionEngine:
    """Template matching against skill bar for cooldown detection."""

    def __init__(self, templates_dir: Path):
        self.capture = ScreenCapture()
        self.templates = {}
        self._health_pct = 100.0
        self._health_poison = False
        self._load_templates(templates_dir)
        self._compute_bounds()

    def _load_templates(self, templates_dir: Path):
        defs = [
            ('punishment',   'punishment.png',   PUNISHMENT_REGION),
            ('noble_armor',  'noble_armor.png',  NOBLE_ARMOR_REGION),
            ('taunt',        'taunt.png',        TAUNT_REGION),
            ('stagger',      'stagger.png',      STAGGER_REGION),
            ('shield_smite', 'shield_smite.png', SHIELD_SMITE_REGION),
        ]
        for name, filename, region in defs:
            path = templates_dir / filename
            if path.exists():
                self.templates[name] = TemplateData(path, region)

        fury_path = templates_dir / "fury.png"
        if fury_path.exists():
            self.templates['fury'] = TemplateData(
                fury_path, BUFFBAR_REGION, threshold=0.80)

        hb = templates_dir / "healthbar.png"
        self.healthbar_template = cv2.imread(str(hb), cv2.IMREAD_COLOR) if hb.exists() else None

    def _compute_bounds(self):
        regions = [t.region for t in self.templates.values()]
        regions.append(HEALTHBAR_REGION)
        if not regions:
            self.bounds = (0, 0, 1920, 1080)
            return
        min_x = min(r[0] for r in regions)
        min_y = min(r[1] for r in regions)
        max_x = max(r[0] + r[2] for r in regions)
        max_y = max(r[1] + r[3] for r in regions)
        self.bounds = (min_x, min_y, max_x - min_x, max_y - min_y)

    def _extract_region(self, frame, region):
        x, y, w, h = region
        rx = x - self.bounds[0]
        ry = y - self.bounds[1]
        return frame[ry:ry+h, rx:rx+w]

    def _match(self, screen_region, template: TemplateData) -> MatchResult:
        try:
            result = cv2.matchTemplate(screen_region, template.img, cv2.TM_CCOEFF_NORMED)
            _, max_val, _, _ = cv2.minMaxLoc(result)
            tmatch = max_val >= template.threshold
            bmatch = True
            rb = 0.0
            if template.check_brightness:
                gray = cv2.cvtColor(screen_region, cv2.COLOR_BGR2GRAY)
                rb = np.mean(gray)
                bmatch = (template.brightness - BRIGHTNESS_TOLERANCE
                          <= rb <= template.brightness + BRIGHTNESS_TOLERANCE)
            return MatchResult(tmatch, bmatch, max_val, rb)
        except Exception:
            return MatchResult()

    def scan_frame(self) -> dict:
        results = {}
        bx, by, bw, bh = self.bounds
        frame = self.capture.capture_region(bx, by, bw, bh)
        if frame is None:
            return {name: MatchResult() for name in self.templates}
        for name, template in self.templates.items():
            roi = self._extract_region(frame, template.region)
            results[name] = self._match(roi, template)

        # Extract health info from the same frame
        bar = self._extract_region(frame, HEALTHBAR_REGION)
        if bar is not None and bar.size > 0:
            pixel_sums = np.sum(bar, axis=2)
            total = bar.shape[0] * bar.shape[1]
            # Only trust health readings if the region isn't completely dark
            max_brightness = np.max(pixel_sums)
            if max_brightness > 50:
                healthy = np.sum(pixel_sums > 120)
                pct = (healthy / total) * 100
                b, g, r = cv2.split(bar)
                poison = np.sum((g > 100) & (b < 80) & (r < 80)) > (total * 0.10)
                self._health_pct = pct
                self._health_poison = poison
        return results

    def get_health_info(self) -> tuple[float, bool]:
        return self._health_pct, self._health_poison

    def stop(self):
        pass


# ── Weave engine ───────────────────────────────────────────────

class WeaveEngine:
    """Packet-triggered weave follow-up engine.

    When a trigger skill ACT fires, checks vision state and sends
    the best follow-up key via Pico.
    """

    PRIORITY_SKILLS = [
        ('noble_armor',  SC_V, 'noble_armor_enabled',  'Noble Armor',  'V'),
        ('punishment',   SC_5, 'punishment_enabled',    'Punishment',   '5'),
        ('taunt',        SC_X, 'taunt_enabled',         'Taunt',        'X'),
        ('shield_smite', SC_4, 'shield_smite_enabled',  'Shield Smite', '4'),
    ]

    def __init__(self, pico_port: str, vision: VisionEngine,
                 skills: dict, shield_ids: set):
        self.pico = PicoBridge(pico_port)
        self.vision = vision

        # Skill toggles — dict of {name: BooleanVar or bool}
        self.skill_toggles: dict = {}

        # Raw input tracks trigger key state
        self.raw_reader = RawInputReader()
        self.current_trigger = None
        self._primary_device = None
        self.raw_reader.register_callback(self._raw_input_callback)

        self.send_lock = threading.Lock()
        self.running = True

        # Vision state — updated by background thread
        self._latest_vision: dict = {}
        self._vision_lock = threading.Lock()

        # ACT deduplication
        self._last_act_key = None
        self._last_act_time = 0.0
        self._act_dedup_window = 0.100

        # Potion state
        self.last_health_pot = 0.0
        self.last_cleanse_pot = 0.0
        self.potion_enabled = True

        # Shield of Protection
        self._shield_active = False

        # UI log callback
        self.ui_log = lambda msg: None

        # Skill timing log
        self._skill_log = None
        self._skill_log_last = (None, 0.0)

        # Skill IDs
        self.trigger_ids = build_trigger_ids(skills)
        self.shield_ids = shield_ids

    def start(self):
        """Start all background threads."""
        self.raw_reader.start()

        self._trigger_thread = threading.Thread(
            target=self._trigger_send_loop, daemon=True)
        self._trigger_thread.start()

        self._vision_thread = threading.Thread(
            target=self._vision_loop, daemon=True)
        self._vision_thread.start()

        self._potion_thread = threading.Thread(
            target=self._potion_loop, daemon=True)
        self._potion_thread.start()

    def stop(self):
        self.running = False
        self.raw_reader.stop()
        self.pico.close()
        if self._skill_log:
            try:
                self._skill_log.close()
            except Exception:
                pass

    def open_skill_log(self, logs_dir: str):
        try:
            os.makedirs(logs_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(logs_dir, f"skills_{ts}.log")
            self._skill_log = open(path, 'w', encoding='utf-8')
            self._skill_log.write("timestamp,elapsed_ms,skill,key,trigger\n")
            self._skill_log_start = time.perf_counter()
        except Exception:
            self._skill_log = None

    # ── Key sending ────────────────────────────────────────────

    def send_key(self, scancode):
        """Send a single keypress via Pico (down + hold + up as atomic unit)."""
        with self.send_lock:
            self.pico.send_key(scancode, 0x00)
            time.sleep(SLEEP_HOLD)
            self.pico.send_key(scancode, 0x01)

    # ── Skill event handlers (called from capture thread) ──────

    def on_skill_event(self, skill_name: str, skill_id: int,
                       pkt_type: int, tick: int):
        """Called by capture engine on ACT/FB packets for any detected skill."""
        if pkt_type not in (0x02, 0x03):
            return

        self._log_skill(skill_name, 'ACT', 'packet')

        # Shield of Protection handling
        if skill_id in self.shield_ids:
            if not self._shield_active:
                self._shield_active = True
                self.ui_log("[Weave] Shield active — direct follow-up")
        elif skill_id not in self.trigger_ids:
            if self._shield_active:
                self._shield_active = False
                self.ui_log(f"[Weave] Shield cleared by {skill_name}")

        # Trigger skill → send follow-up on separate thread
        if skill_id in self.trigger_ids:
            threading.Thread(
                target=self._fire_followup,
                args=(skill_name, skill_id, tick),
                daemon=True,
            ).start()

    def _fire_followup(self, skill_name: str, skill_id: int, tick: int):
        """Pick and send the follow-up key based on vision state."""
        trigger = self.current_trigger
        if trigger not in TRIGGER_KEYS:
            return

        # Deduplicate
        now = time.time()
        act_key = (skill_id, tick)
        if act_key == self._last_act_key and (now - self._last_act_time) < self._act_dedup_window:
            return
        self._last_act_key = act_key
        self._last_act_time = now

        # Read vision state
        with self._vision_lock:
            results = self._latest_vision

        # Stagger ready (3) is highest priority — only if vision confirms
        stagger = results.get('stagger')
        if stagger is not None and stagger.confidence > 0 and not stagger.detected:
            self.send_key(SC_3)
            self._log_skill(skill_name, '3', 'stagger_ready')
            self.ui_log(f"[Weave] {skill_name} -> 3 (stagger ready)")
            return

        # Priority skills — first detected+enabled wins
        for skill_key, scancode, toggle_name, display, key_name in self.PRIORITY_SKILLS:
            toggle = self.skill_toggles.get(toggle_name)
            enabled = (toggle.get() if hasattr(toggle, 'get')
                       else bool(toggle) if toggle is not None else True)
            if not enabled:
                continue
            result = results.get(skill_key, MatchResult())
            if result.detected:
                self.send_key(scancode)
    
                self._log_skill(skill_name, key_name, display)
                self.ui_log(f"[Weave] {display} -> {key_name} (on {skill_name})")
                return

        # Fallback
        self.send_key(SC_9)
        self._log_skill(skill_name, '9', 'stagger_inactive')
        self.ui_log(f"[Weave] {skill_name} -> 9 (stagger inactive)")

    def _pick_followup_key(self):
        """Pick best follow-up key from current vision state."""
        with self._vision_lock:
            results = self._latest_vision

        stagger = results.get('stagger')
        if stagger is not None and stagger.confidence > 0 and not stagger.detected:
            return SC_3

        for skill_key, scancode, toggle_name, _, _ in self.PRIORITY_SKILLS:
            toggle = self.skill_toggles.get(toggle_name)
            enabled = (toggle.get() if hasattr(toggle, 'get')
                       else bool(toggle) if toggle is not None else True)
            if not enabled:
                continue
            result = results.get(skill_key, MatchResult())
            if result.detected:
                return scancode

        return SC_9

    # ── Background loops ───────────────────────────────────────

    def _vision_loop(self):
        """Scan screen every 10ms, store latest results."""
        while self.running:
            try:
                results = self.vision.scan_frame()
                with self._vision_lock:
                    self._latest_vision = results
            except Exception:
                pass
            time.sleep(0.010)

    def _trigger_send_loop(self):
        """While trigger key is held, send key 1 every 45ms."""
        while self.running:
            trigger = self.current_trigger
            if trigger is not None:
                try:
                    hwnd = win32gui.GetForegroundWindow()
                    title = win32gui.GetWindowText(hwnd).lower()
                except Exception:
                    title = ""
                if not title.startswith("aion2 l "):
                    time.sleep(0.045)
                    continue

                # Judgment weave toggle — if off, spam 3 when stagger ready
                judgment = self.skill_toggles.get('judgment_enabled')
                judgment_on = (judgment.get() if hasattr(judgment, 'get')
                               else bool(judgment) if judgment is not None else True)
                if not judgment_on:
                    with self._vision_lock:
                        stagger = self._latest_vision.get('stagger')
                    if stagger is not None and stagger.confidence > 0 and not stagger.detected:
                        self.send_key(SC_3)
                        time.sleep(0.045)
                        continue

                if self._shield_active:
                    self.send_key(self._pick_followup_key())
                else:
                    self.send_key(SC_1)
            time.sleep(0.045)

    def _potion_loop(self):
        """Auto-use health/cleanse potions based on health bar vision."""
        while self.running:
            try:
                try:
                    hwnd = win32gui.GetForegroundWindow()
                    title = win32gui.GetWindowText(hwnd).lower()
                except Exception:
                    title = ""

                if not title.startswith("aion2 l ") or not self.potion_enabled:
                    time.sleep(0.1)
                    continue

                health_pct, has_poison = self.vision.get_health_info()
                now = time.time()

                if health_pct < HEALTH_THRESHOLD and (now - self.last_health_pot) > POTION_COOLDOWN:
                    self.send_key(SC_U)
                    self.last_health_pot = now
                    self.ui_log(f"[Potion] Health pot (HP: {health_pct:.0f}%)")

                if has_poison and (now - self.last_cleanse_pot) > POTION_COOLDOWN:
                    self.send_key(SC_G)
                    self.last_cleanse_pot = now
                    self.ui_log("[Potion] Cleanse pot (poison)")
            except Exception:
                pass
            time.sleep(0.050)

    # ── Raw input callback ─────────────────────────────────────

    def _raw_input_callback(self, vkey, msg, flags, hDevice):
        """Track trigger key state from physical keyboard."""
        if vkey not in KEY_MAP:
            return

        scancode = KEY_MAP[vkey]
        is_up = (flags & 1) == 1

        # R key activates shield mode
        if scancode in SHIELD_KEYS:
            if not is_up:
                self._shield_active = True
                self.ui_log("[Weave] Shield active (R)")
            return

        if scancode not in TRIGGER_KEYS:
            return

        # Toggle mode check
        toggle_var = self.skill_toggles.get('toggle_mode')
        is_toggle = (toggle_var.get() if hasattr(toggle_var, 'get')
                     else bool(toggle_var) if toggle_var is not None else False)

        if is_toggle:
            if is_up:
                return
            if hDevice == 0 or hDevice is None:
                return
            if self._primary_device is None:
                self._primary_device = hDevice
            if self._primary_device is not None and hDevice != self._primary_device:
                return
            if self.current_trigger == scancode:
                self.current_trigger = None
                self.ui_log("[Weave] Toggle OFF")
            else:
                self.current_trigger = scancode
                self.ui_log("[Weave] Toggle ON")
                if self._shield_active:
                    self.send_key(self._pick_followup_key())
                else:
                    self.send_key(SC_1)
            return

        # Normal hold mode
        if is_up:
            if self.current_trigger == scancode:
                self.current_trigger = None
            return

        if hDevice == 0 or hDevice is None:
            return
        if self._primary_device is None:
            self._primary_device = hDevice
        if self._primary_device is not None and hDevice != self._primary_device:
            return

        if self.current_trigger != scancode:
            self.current_trigger = scancode
            if self._shield_active:
                self.send_key(self._pick_followup_key())
            else:
                self.send_key(SC_1)

    # ── Logging ────────────────────────────────────────────────

    def _log_skill(self, skill_name: str, key_name: str, trigger: str):
        if not self._skill_log:
            return
        now_pc = time.perf_counter()
        last_name, last_time = self._skill_log_last
        if skill_name == last_name and (now_pc - last_time) < 0.010:
            return
        self._skill_log_last = (skill_name, now_pc)
        now = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        elapsed = (now_pc - self._skill_log_start) * 1000
        self._skill_log.write(
            f"{now},{elapsed:.1f},{skill_name},{key_name},{trigger}\n")
        self._skill_log.flush()
