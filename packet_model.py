"""
Packet Model for Aion 2 Skill Packets (Lightweight)

Minimal parsing for attack speed modification:
- find_attack_speed_offset(): locate attack_speed byte position
- extract_packet_info(): lightweight info extraction for logging
- varint encode/decode
- coordinate validation

Wire format (from skill_offset X):
[X-4:X]   prefix        4 bytes   38 XX NN YY pattern
[X:X+4]   skill_id      int32     Skill identifier
[X+4]     tick          uint8     Action tick counter
[X+5]     packet_type   uint8     0x02=Start, 0x00=End, 0x03=Effect, 0x0c=Compound
[X+6:?]   entity_key    varint    Context/entity key
[?:?]     parts_id      varint    (optional, if high entity_key)
[?:?+16]  position      4xfloat   yaw, x, z, y (player position)
[?:?]     attack_speed  varint    Attack speed value
"""
import struct
import math
from typing import Tuple, Optional, Dict, Any


# =============================================================================
# VARINT ENCODING/DECODING
# =============================================================================

def parse_varint(data, offset: int) -> Tuple[int, int]:
    """
    Parse Protocol Buffers style VarInt.
    Returns (value, bytes_consumed).
    """
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
    """Encode integer as Protocol Buffers style VarInt."""
    if value < 0:
        value = value & 0xFFFFFFFFFFFFFFFF
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result) if result else b'\x00'


def encode_varint_fixed(value: int, target_len: int) -> bytes:
    """Encode varint padded to exactly target_len bytes.
    Uses non-canonical encoding (extra 0x80 continuation bytes) so the
    decoder still reads the same value but the byte length matches."""
    minimal = encode_varint(value)
    if len(minimal) >= target_len:
        return minimal
    # Pad: turn the final byte into a continuation byte, add 0x00 terminators
    result = list(minimal)
    while len(result) < target_len:
        result[-1] |= 0x80  # mark current last byte as continuation
        result.append(0x00)  # add a zero-payload terminator
    return bytes(result)


# =============================================================================
# COORDINATE VALIDATION
# =============================================================================

def is_valid_coordinate(f: float) -> bool:
    """Check if float could be a valid game coordinate."""
    if math.isnan(f) or math.isinf(f):
        return False
    return -600000 < f < 600000


# =============================================================================
# ATTACK SPEED OFFSET FINDING
# =============================================================================

def find_attack_speed_offset(data, skill_offset: int) -> Optional[Tuple[int, int, int]]:
    """
    Walk the packet structure to locate the attack_speed varint.

    Returns (offset, length, current_value) or None if not found.

    Walks: skill_id(4) -> tick(1) -> packet_type(1) -> entity_key(varint)
           -> optional parts_id(varint) -> position(16 bytes) -> attack_speed(varint)
    """
    length = len(data)
    pos = skill_offset + 6  # Skip skill_id(4) + tick(1) + packet_type(1)

    if pos >= length:
        return None

    # Parse entity_key (varint)
    entity_key, key_len = parse_varint(data, pos)
    pos += key_len

    if pos >= length:
        return None

    # Optional parts_id if entity_key is high
    if entity_key >= 100_000_000:
        _, parts_len = parse_varint(data, pos)
        pos += parts_len

    if pos + 16 > length:
        return None

    # Validate 4 floats as coordinates
    floats = struct.unpack_from('<4f', data, pos)
    if not all(is_valid_coordinate(f) for f in floats):
        return None

    pos += 16  # Skip 4 floats

    if pos + 1 > length:
        return None

    # Parse attack_speed varint
    attack_speed, speed_len = parse_varint(data, pos)

    if attack_speed > 9999999:
        return None

    # Structural validation: in a real skill activation the skill_id bytes
    # reappear shortly after the speed field (typically at +8).  If they
    # don't, the structure is some other sub-message that happens to share
    # the same prefix/coords layout but has different trailing fields.
    post = pos + speed_len
    skill_id_bytes = bytes(data[skill_offset:skill_offset + 4])
    post_region = bytes(data[post:min(post + 16, length)])
    if skill_id_bytes not in post_region:
        return None

    return (pos, speed_len, attack_speed)


# =============================================================================
# CONDITIONAL PACKET SCANNING
# =============================================================================

def find_int32_le(data, target: int, start: int = 0, end: int = 0) -> list:
    """Find all offsets where target appears as a little-endian int32.

    Returns list of byte offsets.  Uses bytes.find() for C-level speed.
    """
    needle = struct.pack('<I', target)
    if end <= 0:
        end = len(data)
    results = []
    buf = bytes(data) if not isinstance(data, bytes) else data
    pos = buf.find(needle, start, end)
    while pos >= 0:
        results.append(pos)
        pos = buf.find(needle, pos + 1, end)
    return results


def find_varint_value(data, target: int, start: int = 0, end: int = 0) -> list:
    """Scan for a varint-encoded target value in data[start:end].

    Returns list of (offset, byte_length) tuples where parse_varint
    decodes to exactly *target*.
    """
    if end <= 0:
        end = len(data)
    results = []
    length = len(data)
    for off in range(start, min(end, length)):
        val, consumed = parse_varint(data, off)
        if consumed > 0 and val == target:
            results.append((off, consumed))
    return results


def find_hex_pattern(data, pattern: bytes, start: int = 0, end: int = 0) -> list:
    """Find all offsets of a raw byte pattern in data[start:end].

    *pattern* must already be a bytes object (caller converts hex string).
    Returns list of byte offsets.
    """
    if end <= 0:
        end = len(data)
    results = []
    buf = bytes(data) if not isinstance(data, bytes) else data
    pos = buf.find(pattern, start, end)
    while pos >= 0:
        results.append(pos)
        pos = buf.find(pattern, pos + 1, end)
    return results


# =============================================================================
# LIGHTWEIGHT PACKET INFO FOR LOGGING
# =============================================================================

def extract_packet_info(data, skill_offset: int, skill_name: str) -> Optional[Dict[str, Any]]:
    """
    Extract minimal packet info for logging without creating objects.

    Returns dict with: skill_id, skill_name, tick, packet_type, attack_speed
    or None if parsing fails.
    """
    length = len(data)
    if skill_offset + 6 > length:
        return None

    skill_id = struct.unpack_from('<I', data, skill_offset)[0]
    tick = data[skill_offset + 4]
    packet_type = data[skill_offset + 5]

    info = {
        'skill_id': skill_id,
        'skill_name': skill_name,
        'tick': tick,
        'packet_type': packet_type,
    }

    # Try to get attack_speed
    result = find_attack_speed_offset(data, skill_offset)
    if result:
        info['attack_speed'] = result[2]
        info['attack_speed_offset'] = result[0]
        info['attack_speed_length'] = result[1]

    return info
