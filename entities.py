"""Entity tracking — maps character names to entity keys via nickname bindings."""

import threading


class EntityTracker:
    """Tracks the player's entity ID by locking on nickname bindings.

    Thread-safe: the capture thread writes bindings, the UI thread reads status.
    """

    def __init__(self, character_names: list[str] = None):
        self._lock = threading.Lock()
        self._names: dict[str, str] = {}  # lowercase -> original case
        self._key: int | None = None
        self._key_name: str | None = None  # lowercase name for current key
        if character_names:
            self.update_names(character_names)

    def update_names(self, names: list[str]):
        """Set character names to filter for. Clears learned key."""
        with self._lock:
            self._names = {n.strip().lower(): n.strip() for n in names if n.strip()}
            self._key = None
            self._key_name = None

    def on_binding(self, actor_id: int, name: str,
                   strategy: str = '', msg_hex: str = '') -> bool:
        """Register a nickname binding. Returns True if accepted (matches config).

        Immediately locks this as the entity ID, replacing any previous one.
        """
        with self._lock:
            clean = name.strip().lower()
            if clean not in self._names:
                return False
            if actor_id == self._key:
                return True
            self._key = actor_id
            self._key_name = clean
            return True

    def is_mine(self, entity_key: int) -> bool:
        """Check if entity_key belongs to our character."""
        return entity_key == self._key

    def get_name_for_key(self, entity_key: int) -> str | None:
        """Return the character name (original case) associated with an entity key."""
        with self._lock:
            if entity_key == self._key and self._key_name is not None:
                return self._names.get(self._key_name, self._key_name)
        return None

    @property
    def is_configured(self) -> bool:
        return bool(self._names)

    def has_any_keys(self) -> bool:
        return self._key is not None

    def get_keys(self) -> set:
        with self._lock:
            return {self._key} if self._key is not None else set()

    def clear(self):
        with self._lock:
            self._key = None
            self._key_name = None
