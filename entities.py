"""Entity tracking — maps character names to entity keys via nickname bindings."""

import threading


class EntityTracker:
    """Tracks the player's entity IDs by accumulating nickname bindings.

    Thread-safe: the capture thread writes bindings, the UI thread reads status.
    """

    def __init__(self, character_names: list[str] = None):
        self._lock = threading.Lock()
        self._names: dict[str, str] = {}  # lowercase -> original case
        self._keys: set[int] = set()
        self._name_to_key: dict[str, int] = {}
        self._key_bindings: dict[int, dict] = {}  # key -> {name, strategy, msg_hex}
        if character_names:
            self.update_names(character_names)

    def update_names(self, names: list[str]):
        """Set character names to filter for. Clears learned keys."""
        with self._lock:
            self._names = {n.strip().lower(): n.strip() for n in names if n.strip()}
            self._keys.clear()
            self._name_to_key.clear()
            self._key_bindings.clear()

    def on_binding(self, actor_id: int, name: str,
                   strategy: str = '', msg_hex: str = '') -> bool:
        """Register a nickname binding. Returns True if accepted (matches config).

        Accumulates keys — confirm_key() prunes to the correct one on first ACT.
        """
        with self._lock:
            clean = name.strip().lower()
            if clean not in self._names:
                return False
            if actor_id in self._keys:
                return False
            self._keys.add(actor_id)
            self._name_to_key[clean] = actor_id
            self._key_bindings[actor_id] = {
                'name': name, 'strategy': strategy, 'msg_hex': msg_hex,
            }
            return True

    def is_mine(self, entity_key: int) -> bool:
        """Check if entity_key belongs to our character."""
        return entity_key in self._keys

    def get_name_for_key(self, entity_key: int) -> str | None:
        """Return the character name (original case) associated with an entity key."""
        with self._lock:
            for lower_name, key in self._name_to_key.items():
                if key == entity_key:
                    return self._names.get(lower_name, lower_name)
        return None

    def confirm_key(self, entity_key: int) -> dict | None:
        """Confirm entity key from ACT packet — discard alternative keys.

        Returns {good: binding_info, bad: [binding_info, ...]} or None if no pruning.
        """
        with self._lock:
            if entity_key not in self._keys or len(self._keys) <= 1:
                return None
            good = self._key_bindings.get(entity_key, {})
            bad = []
            for k in self._keys:
                if k != entity_key:
                    info = self._key_bindings.get(k, {})
                    info['key'] = k
                    bad.append(info)
            good['key'] = entity_key
            self._keys = {entity_key}
            self._name_to_key = {
                n: k for n, k in self._name_to_key.items()
                if k == entity_key
            }
            self._key_bindings = {
                k: v for k, v in self._key_bindings.items()
                if k == entity_key
            }
            return {'good': good, 'bad': bad}

    @property
    def is_configured(self) -> bool:
        return bool(self._names)

    def has_any_keys(self) -> bool:
        return bool(self._keys)

    def get_keys(self) -> set:
        with self._lock:
            return set(self._keys)

    def clear(self):
        with self._lock:
            self._keys.clear()
            self._name_to_key.clear()
            self._key_bindings.clear()
