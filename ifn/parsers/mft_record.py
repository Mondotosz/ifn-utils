"""Parse a single NTFS MFT record (1024 bytes)."""
from __future__ import annotations
import struct
from dataclasses import dataclass, field
from datetime import datetime

from ifn.parsers.windows_time import filetime_to_datetime

MFT_RECORD_MAGIC = b"FILE"
MFT_RECORD_SIZE = 1024

_ATTR_TYPES: dict[int, str] = {
    0x10: "$STANDARD_INFORMATION",
    0x20: "$ATTRIBUTE_LIST",
    0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID",
    0x50: "$SECURITY_DESCRIPTOR",
    0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION",
    0x80: "$DATA",
    0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION",
    0xB0: "$BITMAP",
    0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION",
    0xE0: "$EA",
    0xF0: "$PROPERTY_SET",
    0x100: "$LOGGED_UTILITY_STREAM",
    0xFFFFFFFF: "End marker",
}

_FILE_FLAGS = {
    0x0001: "In use",
    0x0002: "Directory",
    0x0004: "In $Extend",
    0x0008: "Is index",
}

_FILENAME_NAMESPACES = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32&DOS"}


@dataclass
class MFTAttribute:
    attr_type: int
    attr_name: str
    length: int
    non_resident: bool
    name: str
    offset: int
    flags: int
    attr_id: int
    data: bytes
    decoded: dict = field(default_factory=dict)


@dataclass
class MFTRecord:
    magic: bytes
    update_seq_offset: int
    update_seq_size: int
    log_file_seq: int
    seq_number: int
    hard_link_count: int
    first_attr_offset: int
    flags: int
    used_size: int
    alloc_size: int
    base_record_ref: int
    next_attr_id: int
    record_number: int
    attributes: list[MFTAttribute]

    @property
    def is_valid(self) -> bool:
        return self.magic == MFT_RECORD_MAGIC

    @property
    def is_directory(self) -> bool:
        return bool(self.flags & 0x0002)

    @property
    def is_in_use(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def flag_names(self) -> str:
        return ", ".join(v for k, v in _FILE_FLAGS.items() if self.flags & k) or "None"


def _decode_standard_info(data: bytes) -> dict:
    if len(data) < 48:
        return {}
    created, modified, mft_modified, accessed = struct.unpack_from("<4Q", data, 0)
    file_attrs = struct.unpack_from("<I", data, 32)[0]
    return {
        "Created":      filetime_to_datetime(created).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Modified":     filetime_to_datetime(modified).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "MFT Modified": filetime_to_datetime(mft_modified).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Accessed":     filetime_to_datetime(accessed).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "File attrs":   f"0x{file_attrs:08X}",
    }


def _decode_filename(data: bytes) -> dict:
    if len(data) < 66:
        return {}
    parent_ref = struct.unpack_from("<Q", data, 0)[0] & 0x0000FFFFFFFFFFFF
    created, modified, mft_modified, accessed = struct.unpack_from("<4Q", data, 8)
    alloc_size, real_size = struct.unpack_from("<QQ", data, 40)
    name_len = data[64]
    namespace = data[65]
    name = data[66: 66 + name_len * 2].decode("utf-16-le", errors="replace")
    return {
        "Filename":     name,
        "Namespace":    _FILENAME_NAMESPACES.get(namespace, str(namespace)),
        "Parent MFT#":  str(parent_ref),
        "Created":      filetime_to_datetime(created).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Modified":     filetime_to_datetime(modified).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Accessed":     filetime_to_datetime(accessed).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Alloc size":   f"{alloc_size:,} bytes",
        "Real size":    f"{real_size:,} bytes",
    }


def _parse_attribute(data: bytes, offset: int) -> MFTAttribute | None:
    if offset + 8 > len(data):
        return None
    attr_type = struct.unpack_from("<I", data, offset)[0]
    if attr_type == 0xFFFFFFFF:
        return MFTAttribute(0xFFFFFFFF, "End marker", 0, False, "", offset, 0, 0, b"", {})

    if offset + 16 > len(data):
        return None
    length = struct.unpack_from("<I", data, offset + 4)[0]
    if length == 0 or offset + length > len(data):
        return None

    non_resident = bool(data[offset + 8])
    name_len = data[offset + 9]
    name_offset = struct.unpack_from("<H", data, offset + 10)[0]
    flags = struct.unpack_from("<H", data, offset + 12)[0]
    attr_id = struct.unpack_from("<H", data, offset + 14)[0]

    attr_name = ""
    if name_len > 0:
        name_start = offset + name_offset
        attr_name = data[name_start: name_start + name_len * 2].decode("utf-16-le", errors="replace")

    attr_type_name = _ATTR_TYPES.get(attr_type, f"Unknown (0x{attr_type:X})")

    if not non_resident:
        content_len = struct.unpack_from("<I", data, offset + 16)[0]
        content_offset = struct.unpack_from("<H", data, offset + 20)[0]
        content = data[offset + content_offset: offset + content_offset + content_len]
    else:
        content = b""

    decoded = {}
    if attr_type == 0x10:
        decoded = _decode_standard_info(content)
    elif attr_type == 0x30:
        decoded = _decode_filename(content)

    return MFTAttribute(attr_type, attr_type_name, length, non_resident, attr_name, offset, flags, attr_id, content, decoded)


def parse(data: bytes) -> MFTRecord:
    if len(data) < 48:
        raise ValueError(f"MFT record too short: {len(data)} bytes")

    magic = data[0:4]
    upd_offset, upd_size = struct.unpack_from("<HH", data, 4)
    log_seq = struct.unpack_from("<Q", data, 8)[0]
    seq_num, hard_links, first_attr, flags, used_sz, alloc_sz = struct.unpack_from("<HHHHI I", data, 16)
    # Reread without gaps
    seq_num = struct.unpack_from("<H", data, 16)[0]
    hard_links = struct.unpack_from("<H", data, 18)[0]
    first_attr = struct.unpack_from("<H", data, 20)[0]
    flags = struct.unpack_from("<H", data, 22)[0]
    used_sz = struct.unpack_from("<I", data, 24)[0]
    alloc_sz = struct.unpack_from("<I", data, 28)[0]
    base_ref = struct.unpack_from("<Q", data, 32)[0]
    next_id = struct.unpack_from("<H", data, 40)[0]
    record_num = struct.unpack_from("<I", data, 44)[0] if len(data) >= 48 else 0

    attributes = []
    offset = first_attr
    while offset < len(data) - 4:
        attr = _parse_attribute(data, offset)
        if attr is None:
            break
        attributes.append(attr)
        if attr.attr_type == 0xFFFFFFFF or attr.length == 0:
            break
        offset += attr.length

    return MFTRecord(magic, upd_offset, upd_size, log_seq, seq_num, hard_links,
                     first_attr, flags, used_sz, alloc_sz, base_ref, next_id,
                     record_num, attributes)
