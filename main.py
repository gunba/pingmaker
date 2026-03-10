"""Pingmaker — Packet speed modifier + Weave engine.

Intercepts game packets and modifies attack speed values.
Weave engine learns speed from verified ACT packets and applies
to fallback packets by pattern matching.
"""

import sys
import ctypes

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
