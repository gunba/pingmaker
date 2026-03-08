from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class PacketContext:
    payload: bytes
    plen: int
    raw: memoryview
    payload_offset: int
    timestamp: float
    src_port: int = 0
    dst_port: int = 0


@dataclass
class SkillEvent:
    skill_name: str
    skill_id: int
    pkt_type: int        # 0x02=ACT, 0x03=FB, etc.
    tick: int
    prefix_ok: bool
    entity_key: int | None


class PacketPlugin(ABC):
    @property
    @abstractmethod
    def name(self) -> str: ...

    # Lifecycle
    def on_start(self, logs_dir: str, ui_log) -> None: pass
    def on_stop(self) -> None: pass

    # Skill ID registration — IDs the plugin needs detected in packets
    def get_required_skill_ids(self) -> set:
        """Return skill IDs that must be in target_ids for packet scanning."""
        return set()

    # Packet hooks (called from worker threads)
    def on_packet(self, ctx: PacketContext) -> None: pass
    def on_skill_event(self, event: SkillEvent) -> None: pass
    def set_learned_speed(self, value: int, raw_bytes: bytes) -> None: pass

    # UI (called from main thread)
    def build_ui(self, notebook) -> None: pass
    def update_status(self) -> None: pass

    # Settings persistence
    def load_settings(self, settings: dict) -> None: pass
    def save_settings(self, settings: dict) -> None: pass
    def set_save_callback(self, callback) -> None: pass

    # CLI argument registration (classmethods)
    @classmethod
    def add_arguments(cls, parser) -> None: pass

    @classmethod
    def from_args(cls, args) -> 'PacketPlugin | None': return None
