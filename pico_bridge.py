import serial
import serial.tools.list_ports
import time
import threading

# Mapping: Scancode (Set 1) -> HID Usage ID
SCANCODE_TO_HID = {
    0x01: 0x29, # Esc
    0x02: 0x1E, # 1
    0x03: 0x1F, # 2
    0x04: 0x20, # 3
    0x05: 0x21, # 4
    0x06: 0x22, # 5
    0x07: 0x23, # 6
    0x08: 0x24, # 7
    0x09: 0x25, # 8
    0x0A: 0x26, # 9
    0x0B: 0x27, # 0
    0x0C: 0x2D, # -
    0x0D: 0x2E, # =
    0x0E: 0x2A, # Backspace
    0x0F: 0x2B, # Tab
    0x10: 0x14, # Q
    0x11: 0x1A, # W
    0x12: 0x08, # E
    0x13: 0x15, # R
    0x14: 0x17, # T
    0x15: 0x1C, # Y
    0x16: 0x18, # U
    0x17: 0x0C, # I
    0x18: 0x12, # O
    0x19: 0x13, # P
    0x1E: 0x04, # A
    0x1F: 0x16, # S
    0x20: 0x07, # D
    0x21: 0x09, # F
    0x22: 0x0A, # G
    0x23: 0x0B, # H
    0x24: 0x0D, # J
    0x25: 0x0E, # K
    0x26: 0x0F, # L
    0x2C: 0x1D, # Z
    0x2D: 0x1B, # X
    0x2E: 0x06, # C
    0x2F: 0x19, # V
    0x30: 0x05, # B
    0x31: 0x11, # N
    0x32: 0x10, # M
    0x33: 0x36, # ,
    0x34: 0x37, # .
    0x35: 0x38, # /
    0x39: 0x2C, # Space
    0x3B: 0x3A, # F1
    0x3C: 0x3B, # F2
    0x3D: 0x3C, # F3
    0x3E: 0x3D, # F4
    0x3F: 0x3E, # F5
    0x40: 0x3F, # F6
    0x41: 0x40, # F7
    0x42: 0x41, # F8
    0x43: 0x42, # F9
    0x44: 0x43, # F10
    0x57: 0x44, # F11
    0x58: 0x45, # F12
    0x48: 0x52, # Up
    0x4B: 0x50, # Left
    0x4D: 0x4F, # Right
    0x50: 0x51, # Down
    0x1D: 0xE0, # L Ctrl
    0x38: 0xE2, # L Alt
    0x2A: 0xE1, # L Shift
}

def find_pico_port() -> str | None:
    """Auto-detect Raspberry Pi Pico COM port."""
    for p in serial.tools.list_ports.comports():
        desc = (p.description or '').lower()
        mfr = (p.manufacturer or '').lower()
        if 'pico' in desc or 'pico' in mfr or (p.vid == 0x2E8A):
            return p.device
    return None


class PicoBridge:
    def __init__(self, port, baudrate=115200):
        self.port = port
        self.baudrate = baudrate
        self.serial = None
        self.lock = threading.Lock()
        self.connect()

    def connect(self):
        try:
            self.serial = serial.Serial(self.port, self.baudrate, timeout=1)
            time.sleep(1) 
        except Exception as e:
            print(f"Failed to connect to Pico at {self.port}: {e}")
            raise

    def send_key(self, scancode, state, device=None):
        """
        Sends a key command to the Pico.
        scancode: int (e.g. 0x02 for '1')
        state: 0=Down, 1=Up
        device: Ignored (kept for compatibility)
        """
        if not self.serial or not self.serial.is_open:
            return

        # NEW: Convert Scancode to HID code for Unified Firmware
        hid_code = SCANCODE_TO_HID.get(int(scancode), 0)
        if hid_code == 0:
            return # Unknown key, cannot send

        cmd_type = "KD" if state == 0 else "KU"
        command = f"{cmd_type}:{int(hid_code)}\n"
        
        with self.lock:
            try:
                self.serial.write(command.encode('utf-8'))
            except Exception as e:
                print(f"Serial write error: {e}")

    def close(self):
        if self.serial and self.serial.is_open:
            self.serial.close()
