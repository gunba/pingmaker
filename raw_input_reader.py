import ctypes
import ctypes.wintypes
import threading
import time

# Windows Constants
WM_INPUT = 0x00FF
RIM_TYPEKEYBOARD = 1
RIDEV_INPUTSINK = 0x00000100

# Define types for 64-bit compatibility
LRESULT = ctypes.c_int64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long
WPARAM = ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint
LPARAM = ctypes.c_int64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long

class RAWINPUTDEVICE(ctypes.Structure):
    _fields_ = [
        ("usUsagePage", ctypes.c_ushort),
        ("usUsage", ctypes.c_ushort),
        ("dwFlags", ctypes.c_uint),
        ("hwndTarget", ctypes.c_void_p),
    ]

class RAWINPUTHEADER(ctypes.Structure):
    _fields_ = [
        ("dwType", ctypes.c_uint),
        ("dwSize", ctypes.c_uint),
        ("hDevice", ctypes.c_void_p),
        ("wParam", ctypes.c_void_p),
    ]

class RAWKEYBOARD(ctypes.Structure):
    _fields_ = [
        ("MakeCode", ctypes.c_ushort),
        ("Flags", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("VKey", ctypes.c_ushort),
        ("Message", ctypes.c_uint),
        ("ExtraInformation", ctypes.c_ulong),
    ]

class RAWINPUT(ctypes.Structure):
    _fields_ = [
        ("header", RAWINPUTHEADER),
        ("keyboard", RAWKEYBOARD),
    ]

# Define WNDCLASS manually
class WNDCLASS(ctypes.Structure):
    _fields_ = [
        ("style", ctypes.c_uint),
        ("lpfnWndProc", ctypes.WINFUNCTYPE(LRESULT, ctypes.c_void_p, ctypes.c_uint, WPARAM, LPARAM)),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", ctypes.c_void_p),
        ("hIcon", ctypes.c_void_p),
        ("hCursor", ctypes.c_void_p),
        ("hbrBackground", ctypes.c_void_p),
        ("lpszMenuName", ctypes.c_wchar_p),
        ("lpszClassName", ctypes.c_wchar_p),
    ]

class RawInputReader:
    def __init__(self):
        self.callbacks = []
        self.running = False
        self.hwnd = None
        self.thread = None
        
        # Configure user32 signatures
        self.user32 = ctypes.windll.user32
        self.user32.DefWindowProcW.argtypes = [ctypes.c_void_p, ctypes.c_uint, WPARAM, LPARAM]
        self.user32.DefWindowProcW.restype = LRESULT
        self.user32.GetRawInputData.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint), ctypes.c_uint]
        self.user32.GetRawInputData.restype = ctypes.c_uint

    def register_callback(self, func):
        """Register a function to call on key event. func(vkey, msg, flags, hDevice)"""
        self.callbacks.append(func)

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        if msg == WM_INPUT:
            size = ctypes.c_uint()
            # Get size first
            res = self.user32.GetRawInputData(
                ctypes.cast(lparam, ctypes.c_void_p),
                0x10000003, # RID_INPUT
                None,
                ctypes.byref(size),
                ctypes.sizeof(RAWINPUTHEADER)
            )
            
            if size.value > 0:
                buf = ctypes.create_string_buffer(size.value)
                if self.user32.GetRawInputData(
                    ctypes.cast(lparam, ctypes.c_void_p),
                    0x10000003,
                    buf,
                    ctypes.byref(size),
                    ctypes.sizeof(RAWINPUTHEADER)
                ) == size.value:
                    data = ctypes.cast(buf, ctypes.POINTER(RAWINPUT)).contents
                    if data.header.dwType == RIM_TYPEKEYBOARD:
                        vkey = data.keyboard.VKey
                        msg_key = data.keyboard.Message
                        flags = data.keyboard.Flags
                        hDevice = data.header.hDevice
                        
                        for cb in self.callbacks:
                            try:
                                cb(vkey, msg_key, flags, hDevice)
                            except Exception as e:
                                print(f"Callback error: {e}")
                        
        return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _worker(self):
        hinst = ctypes.windll.kernel32.GetModuleHandleW(None)
        
        WNDPROC = ctypes.WINFUNCTYPE(LRESULT, ctypes.c_void_p, ctypes.c_uint, WPARAM, LPARAM)
        self.wnd_proc_ptr = WNDPROC(self._wnd_proc) 
        
        wc = WNDCLASS()
        wc.lpfnWndProc = self.wnd_proc_ptr
        wc.hInstance = hinst
        wc.lpszClassName = "RawInputHidden"
        
        atom = self.user32.RegisterClassW(ctypes.byref(wc))
        
        self.hwnd = self.user32.CreateWindowExW(
            0, "RawInputHidden", "RawInputListener", 0, 0, 0, 0, 0, 0, 0, hinst, 0
        )
        
        rid = RAWINPUTDEVICE()
        rid.usUsagePage = 0x01
        rid.usUsage = 0x06
        rid.dwFlags = RIDEV_INPUTSINK
        rid.hwndTarget = self.hwnd
        
        if not self.user32.RegisterRawInputDevices(ctypes.byref(rid), 1, ctypes.sizeof(rid)):
            print("Failed to register raw input device.")
            return

        msg = ctypes.wintypes.MSG()
        while self.running:
            if self.user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) > 0:
                self.user32.TranslateMessage(ctypes.byref(msg))
                self.user32.DispatchMessageW(ctypes.byref(msg))
            else:
                break

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._worker)
        self.thread.daemon = True
        self.thread.start()
        time.sleep(0.1)

    def stop(self):
        self.running = False
        if self.hwnd:
            self.user32.PostMessageW(self.hwnd, 0x0012, 0, 0) # WM_QUIT
