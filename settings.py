"""Settings persistence — load/save JSON settings next to the executable."""

import json
import os
import sys


def get_settings_path() -> str:
    """Get path to settings file (next to exe or script)."""
    if hasattr(sys, '__compiled__'):
        base = os.path.dirname(os.path.abspath(sys.argv[0]))
    elif getattr(sys, 'frozen', False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "pingmaker_settings.json")


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
