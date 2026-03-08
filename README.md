# Pingmaker

Packet speed modifier for Aion 2. Intercepts inbound game packets and modifies attack speed values in real time.

Works with **ExitLag**, **GearUp**, and other gaming proxies/VPNs — captures both direct and loopback traffic.

## Requirements

- **Windows 10/11** (uses WinDivert kernel driver)
- **Python 3.10+**
- **Run as Administrator** (required for packet capture)
- No pip dependencies — `pydivert` is vendored in the repo

## Quick Start

```bash
# Run from source (as Administrator)
python pingmaker.py
```

The GUI will launch. Click **Start** to begin capturing and modifying packets. The tool auto-detects game server ports.

### Pre-built Release

Download `Pingmaker.exe` from [Releases](../../releases) — no Python needed, just run as Administrator.

## How It Works

1. **Port detection** — Scans active TCP connections for Aion 2 game server ports
2. **Packet capture** — Uses WinDivert to intercept inbound game packets
3. **Speed modification** — Finds attack speed varint fields and replaces them with your target value
4. **Re-injection** — Sends modified packets back into the network stack

Supports both direct connections and proxy/VPN setups (loopback capture mode).

## Plugin System

Pingmaker is plugin-extensible. Plugins can hook into the packet pipeline, add UI tabs, persist settings, and register CLI flags.

### Writing a Plugin

Create a file in `plugins/` that subclasses `PacketPlugin`:

```python
from plugins.base import PacketPlugin, PacketContext, SkillEvent

class MyPlugin(PacketPlugin):
    @property
    def name(self) -> str:
        return "My Plugin"

    # Optional: register CLI arguments
    @classmethod
    def add_arguments(cls, parser) -> None:
        parser.add_argument("--my-flag", help="Enable my plugin")

    @classmethod
    def from_args(cls, args) -> 'MyPlugin | None':
        if getattr(args, 'my_flag', None):
            return cls()
        return None

    # Lifecycle
    def on_start(self, logs_dir, ui_log) -> None:
        ui_log("[MyPlugin] Started")

    def on_stop(self) -> None:
        pass

    # Packet hooks (called from worker threads)
    def on_skill_event(self, event: SkillEvent) -> None:
        pass  # React to detected skill casts

    # UI (called from main thread)
    def build_ui(self, notebook) -> None:
        pass  # Add a tab to the notebook widget

    # Settings
    def load_settings(self, settings: dict) -> None:
        pass

    def save_settings(self, settings: dict) -> None:
        pass
```

Then register it in `pingmaker.py`'s `_discover_plugins()` method.

### Plugin Hooks

| Hook | Thread | Purpose |
|------|--------|---------|
| `on_start(logs_dir, ui_log)` | Main | Initialize on capture start |
| `on_stop()` | Main | Cleanup on capture stop |
| `on_packet(ctx)` | Worker | Inspect every captured packet |
| `on_skill_event(event)` | Worker | React to detected skill casts |
| `build_ui(notebook)` | Main | Add tabs to the GUI |
| `update_status()` | Main | Periodic UI refresh |
| `load_settings(settings)` | Main | Restore saved state |
| `save_settings(settings)` | Main | Persist state to JSON |

## Building from Source

Requires [Nuitka](https://nuitka.net/) and a C compiler:

```bash
pip install nuitka
build_pingmaker.bat
```

Produces a standalone `Pingmaker.exe` (~12MB).

## License

[MIT](LICENSE)
