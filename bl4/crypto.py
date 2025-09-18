#!/usr/bin/env python3

# based on work from glacierpiece
# https://github.com/glacierpiece/borderlands-4-save-utlity

import zlib
import yaml
import struct

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from pathlib import Path

from bl4.encoding import DecodedItem
from bl4.encoding import ItemStats
from bl4.encoding import ConfidenceLevel
from bl4.encoding import encode_item_serial


from typing import Collection
from typing import Dict
from typing import List


BASE_KEY = bytes(
    (
        0x35,
        0xEC,
        0x33,
        0x77,
        0xF3,
        0x5D,
        0xB0,
        0xEA,
        0xBE,
        0x6B,
        0x83,
        0x11,
        0x54,
        0x03,
        0xEB,
        0xFB,
        0x27,
        0x25,
        0x64,
        0x2E,
        0xD5,
        0x49,
        0x06,
        0x29,
        0x05,
        0x78,
        0xBD,
        0x60,
        0xBA,
        0x4A,
        0xA7,
        0x87,
    )
)


def unknown_constructor(loader, _tag_suffix, node):
    """Custom YAML constructor that allows returns None for unknown node types

    """

    match node:
        case yaml.ScalarNode():
            return loader.construct_scalar(node)

        case yaml.SequenceNode():
            return loader.construct_sequence(node)

        case yaml.MappingNode():
            return loader.construct_mapping(node)

        case _:
            return None


yaml.add_multi_constructor("!", unknown_constructor, yaml.SafeLoader)


def extract_fields(data: bytes) -> Dict[str, int | List[int]]:
    fields = {}

    if len(data) >= 4:
        fields["header_le"] = struct.unpack("<I", data[:4])[0]
        fields["header_be"] = struct.unpack(">I", data[:4])[0]

    if len(data) >= 8:
        fields["field2_le"] = struct.unpack("<I", data[4:8])[0]

    if len(data) >= 12:
        fields["field3_le"] = struct.unpack("<I", data[8:12])[0]

    stats_16 = []
    for i in range(0, min(len(data) - 1, 20), 2):
        val16 = struct.unpack("<H", data[i:i+2])[0]
        fields[f"val16_at_{i}"] = val16
        if 100 <= val16 <= 10000:
            stats_16.append((i, val16))

    fields["potential_stats"] = stats_16

    flags = []
    for i in range(min(len(data), 20)):
        byte_val = data[i]
        fields[f"byte_{i}"] = byte_val
        if byte_val < 100:
            flags.append((i, byte_val))

    fields["potential_flags"] = flags

    return fields


def get_confidence_by_field_equality(
    fields: Dict[str, int],
    field_name: str,
    value: int,
) -> ConfidenceLevel:
    actual_value = fields.get(field_name)

    if value == actual_value:
        return ConfidenceLevel.HIGH

    return ConfidenceLevel.MEDIUM


def get_confidence_by_data_length(
    data: Collection,
    valid_lengths: Collection[int],
) -> ConfidenceLevel:
    if len(data) in valid_lengths:
        return ConfidenceLevel.HIGH

    return ConfidenceLevel.MEDIUM


def decode_weapon(data: bytes, serial: str) -> DecodedItem:
    fields = extract_fields(data)
    stats = ItemStats()

    if "val16_at_0" in fields:
        stats.primary_stat = fields["val16_at_0"]

    if "val16_at_12" in fields:
        stats.secondary_stat = fields["val16_at_12"]

    if "byte_4" in fields:
        stats.manufacturer = fields["byte_4"]

    if "byte_8" in fields:
        stats.item_class = fields["byte_8"]

    if "byte_1" in fields:
        stats.rarity = fields["byte_1"]

    if "byte_13" in fields and fields["byte_13"] in [2, 34]:
        stats.level = fields["byte_13"]

    confidence = get_confidence_by_data_length(data, {24, 26})

    return DecodedItem(
        serial=serial,
        item_type="r",
        item_category="weapon",
        length=len(data),
        stats=stats,
        raw_fields=fields,
        confidence=confidence,
    )


def decode_equipment_e(data: bytes, serial: str) -> DecodedItem:
    fields = extract_fields(data)
    stats = ItemStats()

    if "val16_at_2" in fields:
        stats.primary_stat = fields["val16_at_2"]

    if "val16_at_8" in fields:
        stats.secondary_stat = fields["val16_at_8"]

    if "val16_at_10" in fields and len(data) > 38:
        stats.level = fields["val16_at_10"]

    if "byte_1" in fields:
        stats.manufacturer = fields["byte_1"]

    if "byte_3" in fields:
        stats.item_class = fields["byte_3"]

    if "byte_9" in fields:
        stats.rarity = fields["byte_9"]

    confidence = get_confidence_by_field_equality(fields, "byte_1", 49)

    return DecodedItem(
        serial=serial,
        item_type="e",
        item_category="equipment",
        length=len(data),
        stats=stats,
        raw_fields=fields,
        confidence=confidence,
    )


def decode_equipment_d(data: bytes, serial: str) -> DecodedItem:
    fields = extract_fields(data)
    stats = ItemStats()

    if "val16_at_4" in fields:
        stats.primary_stat = fields["val16_at_4"]

    if "val16_at_8" in fields:
        stats.secondary_stat = fields["val16_at_8"]

    if "val16_at_10" in fields:
        stats.level = fields["val16_at_10"]

    if "byte_5" in fields:
        stats.manufacturer = fields["byte_5"]

    if "byte_6" in fields:
        stats.item_class = fields["byte_6"]

    if "byte_14" in fields:
        stats.rarity = fields["byte_14"]

    confidence = get_confidence_by_field_equality(fields, "byte_5", 15)

    return DecodedItem(
        serial=serial,
        item_type="d",
        item_category="equipment_alt",
        length=len(data),
        stats=stats,
        raw_fields=fields,
        confidence=confidence,
    )


def decode_other_type(data: bytes, serial: str, item_type: str) -> DecodedItem:
    fields = extract_fields(data)
    stats = ItemStats()

    potential_stats = fields.get("potential_stats", [])

    if potential_stats:
        if potential_stats[0][1]:
            stats.primary_stat = potential_stats[0][1]

        if len(potential_stats) > 1:
            stats.secondary_stat = potential_stats[1][1]

    if "byte_1" in fields:
        stats.manufacturer = fields["byte_1"]

    if "byte_2" in fields:
        stats.rarity = fields["byte_2"]

    category_map = {
        "w": "weapon_special",
        "u": "utility",
        "f": "consumable",
        "!": "special",
    }

    return DecodedItem(
        serial=serial,
        item_type=item_type,
        item_category=category_map.get(item_type, "unknown"),
        length=len(data),
        stats=stats,
        raw_fields=fields,
        confidence=ConfidenceLevel.LOW,
    )


def decode_item_serial(serial: str) -> DecodedItem:
    try:
        data = bit_pack_decode(serial)

        if len(serial) >= 4 and serial.startswith("@Ug"):
            item_type = serial[3]
        else:
            item_type = "?"

        if item_type == "r":
            return decode_weapon(data, serial)
        elif item_type == "e":
            return decode_equipment_e(data, serial)
        elif item_type == "d":
            return decode_equipment_d(data, serial)
        else:
            return decode_other_type(data, serial, item_type)

    except Exception as e:
        return DecodedItem(
            serial=serial,
            item_type="error",
            item_category="decode_failed",
            length=0,
            stats=ItemStats(),
            raw_fields={"error": str(e)},
            confidence=ConfidenceLevel.UNKNOWN,
        )


def find_and_decode_serials_in_yaml(yaml_data: dict) -> Dict[str, DecodedItem]:
    decoded_serials = {}

    def search_dict(obj, path=""):
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                if isinstance(value, str) and value.startswith("@Ug"):
                    decoded = decode_item_serial(value)
                    if decoded.confidence != "none":
                        decoded_serials[new_path] = decoded
                elif isinstance(value, (dict, list)):
                    search_dict(value, new_path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                new_path = f"{path}[{i}]"
                if isinstance(item, str) and item.startswith("@Ug"):
                    decoded = decode_item_serial(item)
                    if decoded.confidence != "none":
                        decoded_serials[new_path] = decoded
                elif isinstance(item, (dict, list)):
                    search_dict(item, new_path)

    search_dict(yaml_data)
    return decoded_serials


def insert_decoded_items_in_yaml(
    yaml_data: dict, decoded_serials: Dict[str, DecodedItem]
) -> dict:
    result = yaml_data.copy()

    result["_DECODED_ITEMS"] = {}

    for path, decoded_item in decoded_serials.items():
        item_info = {
            "original_serial": decoded_item.serial,
            "item_type": decoded_item.item_type,
            "category": decoded_item.item_category,
            "confidence": decoded_item.confidence.value,
            "stats": {},
        }

        stats = item_info["stats"]

        if decoded_item.stats.primary_stat is not None:
            stats["primary_stat"] = decoded_item.stats.primary_stat

        if decoded_item.stats.secondary_stat is not None:
            stats["secondary_stat"] = decoded_item.stats.secondary_stat

        if decoded_item.stats.level is not None:
            stats["level"] = decoded_item.stats.level

        if decoded_item.stats.rarity is not None:
            stats["rarity"] = decoded_item.stats.rarity

        if decoded_item.stats.manufacturer is not None:
            stats["manufacturer"] = decoded_item.stats.manufacturer

        if decoded_item.stats.item_class is not None:
            stats["item_class"] = decoded_item.stats.item_class

        result["_DECODED_ITEMS"][path] = item_info

    return result


def extract_and_encode_serials_from_yaml(yaml_data: dict) -> dict:
    result = yaml_data.copy()

    if "_DECODED_ITEMS" not in yaml_data:
        return result

    decoded_items_section = yaml_data["_DECODED_ITEMS"]

    for path, item_info in decoded_items_section.items():
        stats = ItemStats()
        if "stats" in item_info:
            stats_data = item_info["stats"]
            stats.primary_stat = stats_data.get("primary_stat")
            stats.secondary_stat = stats_data.get("secondary_stat")
            stats.level = stats_data.get("level")
            stats.rarity = stats_data.get("rarity")
            stats.manufacturer = stats_data.get("manufacturer")
            stats.item_class = stats_data.get("item_class")

        decoded_item = DecodedItem(
            serial=item_info["original_serial"],
            item_type=item_info["item_type"],
            item_category=item_info["category"],
            length=0,
            stats=stats,
            raw_fields={},
            confidence=item_info["confidence"],
        )

        new_serial = encode_item_serial(decoded_item)
        set_nested_value(result, path, new_serial)

    if "_DECODED_ITEMS" in result:
        del result["_DECODED_ITEMS"]

    return result


def set_nested_value(data: dict, path: str, value: str):
    parts = path.split(".")
    current = data

    for part in parts[:-1]:
        if "[" in part and "]" in part:
            key, index_str = part.split("[")
            index = int(index_str.rstrip("]"))
            current = current[key][index]
        else:
            current = current[part]

    final_part = parts[-1]

    if "[" in final_part and "]" in final_part:
        key, index_str = final_part.split("[")
        index = int(index_str.rstrip("]"))
        current[key][index] = value
    else:
        current[final_part] = value


def derive_key(
    steamid: str,
    base_key: bytes | bytearray = BASE_KEY,
) -> bytes:
    if not isinstance(base_key, (bytes, bytearray)):
        raise ValueError('Expected bytes for base key')

    if len(base_key) < 8:
        raise ValueError('Invalid base key for derivation')

    digits = int("".join(ch for ch in steamid if ch.isdigit()), 10)
    little = digits.to_bytes(8, "little", signed=False)

    k = bytearray(base_key)

    for i in range(8):
        k[i] ^= little[i]

    return bytes(k)


def decrypt_sav_to_yaml(sav_path: Path, steamid: str) -> bytes:
    ciph = sav_path.read_bytes()

    if len(ciph) % 16 != 0:
        raise ValueError(f"input .sav size {len(ciph)} not multiple of 16")

    key = derive_key(steamid)
    pt_padded = AES.new(key, AES.MODE_ECB).decrypt(ciph)

    try:
        body = unpad(pt_padded, 16, style="pkcs7")
    except ValueError:
        body = pt_padded

    yaml_data = zlib.decompress(body)
    return yaml_data


def encrypt_yaml_to_sav(yaml_path: Path, steamid: str) -> bytes:
    current_yaml = yaml_path.read_bytes()
    compressed = zlib.compress(current_yaml, level=9)

    adler32 = zlib.adler32(current_yaml) & 0xFFFFFFFF
    uncompressed_length = len(current_yaml)

    packed = compressed
    packed += struct.pack("<I", adler32)
    packed += struct.pack("<I", uncompressed_length)

    pt_padded = pad(packed, 16, style="pkcs7")

    key = derive_key(steamid)
    ciph = AES.new(key, AES.MODE_ECB).encrypt(pt_padded)

    return ciph
