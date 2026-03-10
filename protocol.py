"""Aion 2 packet protocol parsing.

Varint codec, skill packet structure, attack speed location,
and TCP stream reassembly for entity name bindings.

Wire format (from skill_offset X):
[X-4:X]   prefix        4 bytes   38 XX NN YY pattern
[X:X+4]   skill_id      int32     Skill identifier
[X+4]     tick          uint8     Action tick counter
[X+5]     packet_type   uint8     0x02=Start, 0x00=End, 0x03=Effect
[X+6:?]   entity_key    varint    Context/entity key
[?:?]     parts_id      varint    (optional, if high entity_key)
[?:?+16]  position      4xfloat   yaw, x, z, y
[?:?]     attack_speed  varint    Value to modify
"""

import struct
import math
from typing import Optional


# ── Varint codec ───────────────────────────────────────────────

def parse_varint(data, offset: int) -> tuple[int, int]:
    """Parse protobuf-style varint. Returns (value, bytes_consumed)."""
    result = 0
    shift = 0
    consumed = 0
    length = len(data)
    while offset + consumed < length:
        byte = data[offset + consumed]
        result |= (byte & 0x7F) << shift
        consumed += 1
        if not (byte & 0x80):
            break
        shift += 7
        if consumed > 10:
            break
    return result, consumed


def encode_varint(value: int) -> bytes:
    """Encode integer as protobuf-style varint (minimal encoding)."""
    if value < 0:
        value = value & 0xFFFFFFFFFFFFFFFF
    parts = []
    while value > 0x7F:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value & 0x7F)
    return bytes(parts) if parts else b'\x00'


def encode_varint_fixed(value: int, target_len: int) -> bytes:
    """Encode varint padded to exactly target_len bytes.
    Uses non-canonical continuation bytes so decoder reads the same value."""
    minimal = encode_varint(value)
    if len(minimal) >= target_len:
        return minimal
    result = list(minimal)
    while len(result) < target_len:
        result[-1] |= 0x80
        result.append(0x00)
    return bytes(result)


# ── Skill packet parsing ──────────────────────────────────────

def has_skill_prefix(data, offset: int) -> bool:
    """Validate the 4-byte prefix before a skill ID at offset."""
    if offset < 4 or offset + 6 > len(data):
        return False
    prefix = data[offset - 4:offset]
    if prefix[0] != 0x38:
        return False
    if prefix[3] not in (0x00, 0x01):
        return False
    if prefix[2] == 0x00:
        return False
    return data[offset + 5] in (0x00, 0x02, 0x03, 0x04, 0x06)



def find_all_skill_ids(data, target_ids: set, first_bytes: set,
                       scan_start: int = 7) -> list[tuple[int, int, bool]]:
    """Scan payload for ALL known skill IDs.

    Returns list of (skill_id, offset, prefix_ok) for every match found.
    """
    results = []
    _unpack = struct.unpack_from
    dlen = len(data)
    end = dlen - 3
    for i in range(scan_start, end):
        if data[i] not in first_bytes:
            continue
        val = _unpack('<I', data, i)[0]
        if val in target_ids:
            results.append((val, i, has_skill_prefix(data, i)))
    return results


def extract_entity_key(data, skill_offset: int) -> Optional[int]:
    """Extract entity key from the prefix bytes before the skill ID."""
    if skill_offset < 3:
        return None
    # Try 3 bytes back first (3-byte varint), then 2 bytes
    for back in (3, 2):
        if skill_offset >= back:
            ek, ek_len = parse_varint(data, skill_offset - back)
            if ek_len > 0 and ek > 0:
                return ek
    return None


def find_attack_speed_offset(data, skill_offset: int) -> Optional[tuple[int, int, int]]:
    """Walk packet structure to locate the attack_speed varint.

    Structure from skill_offset:
      skill_id(4) + tick(1) + pkt_type(1) + entity_key(varint)
      + optional parts_id(varint) + position(4 floats) + attack_speed(varint)

    Returns (offset, length, value) or None if structure doesn't match.
    """
    length = len(data)
    pos = skill_offset + 6  # skip skill_id(4) + tick(1) + pkt_type(1)

    if pos >= length:
        return None

    # entity_key varint
    entity_key, key_len = parse_varint(data, pos)
    pos += key_len
    if pos >= length:
        return None

    # optional parts_id for high entity keys
    if entity_key >= 100_000_000:
        _, parts_len = parse_varint(data, pos)
        pos += parts_len

    # 4 coordinate floats (yaw, x, z, y)
    if pos + 16 > length:
        return None
    floats = struct.unpack_from('<4f', data, pos)
    if not all(-600000 < f < 600000 and not (math.isnan(f) or math.isinf(f))
               for f in floats):
        return None
    pos += 16

    if pos + 1 > length:
        return None

    # attack_speed varint
    speed, speed_len = parse_varint(data, pos)
    if speed > 9999999:
        return None

    # structural validation: skill_id bytes must reappear shortly after speed
    post = pos + speed_len
    skill_id_bytes = bytes(data[skill_offset:skill_offset + 4])
    post_region = bytes(data[post:min(post + 16, length)])
    if skill_id_bytes not in post_region:
        return None

    return (pos, speed_len, speed)


# ── Stream reassembly for entity detection ─────────────────────

GAME_MSG_DELIMITER = b'\x06\x00\x36'
_MAX_BUFFER = 2 * 1024 * 1024


def _sanitize_nickname(raw: str) -> str:
    """Strip non-alphanumeric suffix from raw name."""
    name = raw.split('\x00')[0].strip()
    clean = []
    for ch in name:
        if ch.isalnum():
            clean.append(ch)
        else:
            break
    return ''.join(clean)


def _try_parse_nickname_0x04_0x8D(segment: bytes) -> Optional[tuple[int, str]]:
    """Strategy 1: parse [varint_len][0x04][0x8D]...[actor_id][name_len][name]."""
    if len(segment) < 14:
        return None
    _, vlen = parse_varint(segment, 0)
    if vlen <= 0:
        return None
    op = vlen
    if op + 1 >= len(segment) or segment[op] != 0x04 or segment[op + 1] != 0x8D:
        return None
    if 10 >= len(segment):
        return None
    actor_id, alen = parse_varint(segment, 10)
    if alen <= 0 or actor_id <= 0 or actor_id > 0x7FFFFFFF:
        return None
    npos = 10 + alen
    if npos >= len(segment):
        return None
    nlen = segment[npos]
    if nlen < 1 or nlen > 72:
        return None
    nstart = npos + 1
    nend = nstart + nlen
    if nend > len(segment):
        return None
    try:
        raw_name = segment[nstart:nend].decode('utf-8')
    except UnicodeDecodeError:
        return None
    name = _sanitize_nickname(raw_name)
    return (actor_id, name) if len(name) >= 2 else None


def _scan_actor_name_bindings(data: bytes) -> list[tuple[int, str]]:
    """Strategy 2: scan for 0x36 + varint actor_id, then 0x07 + name_len + name."""
    results = []
    i = 0
    dlen = len(data)
    last_actor_id = None
    last_actor_end = -1
    while i < dlen:
        if data[i] == 0x36:
            actor_id, alen = parse_varint(data, i + 1)
            if alen > 0 and 100 <= actor_id <= 99999:
                last_actor_id = actor_id
                last_actor_end = i + 1 + alen
            i += 1
            continue
        if data[i] == 0x07 and last_actor_id is not None:
            li = i + 1
            if li < dlen:
                nlen = data[li]
                if 1 <= nlen <= 24:
                    ns = li + 1
                    ne = ns + nlen
                    if ne <= dlen and i >= last_actor_end:
                        try:
                            raw_name = data[ns:ne].decode('utf-8')
                        except UnicodeDecodeError:
                            i += 1
                            continue
                        name = _sanitize_nickname(raw_name)
                        if len(name) >= 2:
                            results.append((last_actor_id, name))
                            last_actor_id = None
        i += 1
    return results


class StreamReassembler:
    """TCP stream reassembly — splits on 06 00 36 delimiters,
    extracts nickname bindings from complete messages."""

    def __init__(self):
        self._buffer = bytearray()

    def feed(self, chunk) -> list[tuple[int, str, str]]:
        """Feed TCP payload chunk. Returns [(actor_id, name, strategy), ...]."""
        self._buffer.extend(chunk)
        if len(self._buffer) > _MAX_BUFFER:
            self._buffer = bytearray()
            return []

        results = []
        while True:
            idx = self._buffer.find(GAME_MSG_DELIMITER)
            if idx < 0:
                break
            message = bytes(self._buffer[:idx + 3])
            del self._buffer[:idx + 3]
            if len(message) < 6:
                continue

            binding = _try_parse_nickname_0x04_0x8D(message)
            if binding:
                results.append((binding[0], binding[1], '0x04_0x8D'))
                continue
            bindings = _scan_actor_name_bindings(message)
            for b in bindings:
                results.append((b[0], b[1], 'actor_name'))

        return results

    def reset(self):
        self._buffer = bytearray()
