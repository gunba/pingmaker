"""Settings persistence — load/save JSON settings next to the executable."""

import json
import os
import sys


def _get_app_dir() -> str:
    """Get the directory containing the exe or script.

    In Nuitka onefile builds, __file__ points to the temp extraction dir,
    so we use sys.argv[0] which is the original exe path. To handle UAC
    changing CWD to System32, we check if sys.argv[0] exists as-is first.
    """
    argv0 = sys.argv[0]
    # If argv0 is already absolute or exists at that path, use it directly
    if os.path.isabs(argv0):
        return os.path.dirname(argv0)
    # Check if it exists relative to __file__'s dir (Nuitka standalone/source)
    file_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(file_dir, os.path.basename(argv0))
    if os.path.exists(candidate):
        return file_dir
    # Fall back to __file__ dir (running from source)
    return file_dir


def get_settings_path() -> str:
    """Get path to settings file (next to exe or script)."""
    return os.path.join(_get_app_dir(), "pingmaker_settings.json")


def load_settings() -> dict:
    path = get_settings_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(settings: dict):
    try:
        with open(get_settings_path(), 'w', encoding='utf-8') as f:
            json.dump(settings, f, indent=2)
    except Exception:
        pass
