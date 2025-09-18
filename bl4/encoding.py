import enum
import struct

from dataclasses import dataclass
from typing import Dict
from typing import List
from typing import Optional


from enum import Enum


class ConfidenceLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "high"
    UNKNOWN = "unknown"


class StatType(enum.Enum):
    RARITY = 'rarity'
    ITEM_CLASS = 'item_class'
    MANUFACTURER = 'manufacturer'
    PRIMARY = 'primary_stat'
    SECONDARY = 'secondary_stat'


@dataclass
class ItemStats:
    primary_stat: Optional[int] = None
    secondary_stat: Optional[int] = None
    level: Optional[int] = None
    rarity: Optional[int] = None
    manufacturer: Optional[int] = None
    item_class: Optional[int] = None
    flags: Optional[List[int]] = None


@dataclass
class DecodedItem:
    serial: str
    item_type: str
    item_category: str
    length: int
    stats: ItemStats
    raw_fields: Dict[str, int | List[int]]
    confidence: ConfidenceLevel


DECODE_CHARS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789+/=!$%&*()[]{}~`^_<>?#;"
)


ITEM_LAYOUTS = {
    # Weapons
    "r": {
        "u16": {StatType.PRIMARY: 0, StatType.SECONDARY: 12},

        "u8":  {
            StatType.RARITY: 1,
            StatType.MANUFACTURER: 4,
            StatType.ITEM_CLASS: 8,
        },
    },

    # Equipment
    "e": {
        "u16": {StatType.PRIMARY: 2, StatType.SECONDARY: 8},

        "u8":  {
            StatType.MANUFACTURER: 1,
            StatType.ITEM_CLASS: 3,
            StatType.RARITY: 9,
        },
    },

    # Devices
    "d": {
        "u16": {StatType.PRIMARY: 4,  StatType.SECONDARY: 8},
        "u8":  {StatType.MANUFACTURER: 5, StatType.ITEM_CLASS: 6},
    },
}


def bit_pack_decode(serial: str) -> bytes:
    if serial.startswith("@Ug"):
        payload = serial[3:]
    else:
        payload = serial

    char_map = {}

    for i, c in enumerate(DECODE_CHARS):
        char_map[c] = i

    bits = []
    for c in payload:
        if c in char_map:
            val = char_map[c]
            bits.extend(format(val, "06b"))

    bit_string = "".join(bits)
    while len(bit_string) % 8 != 0:
        bit_string += "0"

    byte_data = bytearray()
    for i in range(0, len(bit_string), 8):
        byte_val = int(bit_string[i:i+8], 2)
        byte_data.append(byte_val)

    return bytes(byte_data)


def bit_pack_encode(data: bytes, prefix: str = "@Ug") -> str:
    bit_string = "".join(format(byte, "08b") for byte in data)

    while len(bit_string) % 6 != 0:
        bit_string += "0"

    result = []
    for i in range(0, len(bit_string), 6):
        chunk = bit_string[i:i+6]
        val = int(chunk, 2)
        if val < len(DECODE_CHARS):
            result.append(DECODE_CHARS[val])

    return prefix + "".join(result)


def check_fits(buf: bytearray, offset: int, size: int) -> bool:
    """ Check if [offset, offset+size) fits within the buffer """

    return len(buf) >= offset + size


def write_u16_le(buf: bytearray, offset: int, value: int) -> None:
    """Write little-endian uint16 if it fits."""
    if value is not None and check_fits(buf, offset, 2):
        struct.pack_into("<H", buf, offset, value)


def write_u8(buf: bytearray, offset: int, value: int) -> None:
    """Write one byte if it fits."""
    if value is not None and check_fits(buf, offset, 1):
        buf[offset] = value


def apply_stats_in_place(data: bytearray, item_type: str, stats) -> None:
    """ Apply stat fields onto decoded data according to its related layout

    'stats' is expected to have attributes:

        - primary_stat
        - secondary_stat
        - rarity
        - manufacturer
        - item_class (potentially None)

    """

    item_layout = ITEM_LAYOUTS.get(item_type)

    if not item_layout:
        return

    u16_map = item_layout.get("u16", {})

    write_u16_le(
        data,
        u16_map.get("primary_stat", -1),
        getattr(stats, "primary_stat", None),
    )

    write_u16_le(
        data,
        u16_map.get("secondary_stat", -1),
        getattr(stats, "secondary_stat", None),
    )

    u8_map = item_layout.get("u8", {})

    write_u8(
       data,
       u8_map.get("rarity", -1),
       getattr(stats, "rarity", None),
    )

    write_u8(
        data,
        u8_map.get("manufacturer", -1),
        getattr(stats, "manufacturer", None),
    )

    write_u8(
        data,
        u8_map.get("item_class", -1),
        getattr(stats, "item_class", None),
    )


def encode_item_serial(decoded_item: "DecodedItem") -> str:
    """ Encodes a DecodedItem into an encoded string for its given values

    Decode original bit-packed serial -> mutable bytes, patch fields
    based on item_type + stats, then re-encode to a bit-packed string
    with the '@Ug{type}' prefix. Falls back to the original serial if
    anything goes wrong.

    """

    original = bit_pack_decode(decoded_item.serial)
    data = bytearray(original)

    apply_stats_in_place(data, decoded_item.item_type, decoded_item.stats)

    prefix = f"@Ug{decoded_item.item_type}"
    return bit_pack_encode(bytes(data), prefix)
