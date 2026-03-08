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
