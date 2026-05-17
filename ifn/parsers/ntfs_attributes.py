"""Decoders for the contents of NTFS attributes beyond $STANDARD_INFORMATION / $FILE_NAME.

Every decoder returns a printable representation (typically dict of field
name → string). They never raise on truncated input — they return whatever
they can decode. The decoders are used by `parsers/mft_record.py`; the CLI
just renders the dicts.
"""
from __future__ import annotations
import struct
import uuid


# ──────────────────────────────────────────────────────────────────────────
# Attribute type identifiers (canonical names from the NTFS course)
# ──────────────────────────────────────────────────────────────────────────
ATTR_NAMES: dict[int, str] = {
    0x10:  "$STANDARD_INFORMATION",
    0x20:  "$ATTRIBUTE_LIST",
    0x30:  "$FILE_NAME",
    0x40:  "$OBJECT_ID",
    0x50:  "$SECURITY_DESCRIPTOR",
    0x60:  "$VOLUME_NAME",
    0x70:  "$VOLUME_INFORMATION",
    0x80:  "$DATA",
    0x90:  "$INDEX_ROOT",
    0xA0:  "$INDEX_ALLOCATION",
    0xB0:  "$BITMAP",
    0xC0:  "$REPARSE_POINT",
    0xD0:  "$EA_INFORMATION",
    0xE0:  "$EA",
    0xF0:  "$PROPERTY_SET",
    0x100: "$LOGGED_UTILITY_STREAM",
    0xFFFFFFFF: "End marker",
}


# File attribute flags — appear in $STANDARD_INFORMATION at offset 0x20
# and in $FILE_NAME at offset 0x38.
FILE_ATTR_FLAGS: list[tuple[int, str]] = [
    (0x00000001, "Read-only"),
    (0x00000002, "Hidden"),
    (0x00000004, "System"),
    (0x00000020, "Archive"),
    (0x00000040, "Device"),
    (0x00000080, "Normal"),
    (0x00000100, "Temporary"),
    (0x00000200, "Sparse"),
    (0x00000400, "Reparse point"),
    (0x00000800, "Compressed"),
    (0x00001000, "Offline"),
    (0x00002000, "Not content indexed"),
    (0x00004000, "Encrypted"),
    (0x10000000, "Directory"),
    (0x20000000, "Index view"),
]

# $FILE_NAME namespace codes (offset 0x41 of the attribute body).
FN_NAMESPACES = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32&DOS"}


def fmt_file_attrs(value: int) -> str:
    parts = [name for bit, name in FILE_ATTR_FLAGS if value & bit]
    return f"0x{value:08X}  ({', '.join(parts) if parts else 'None'})"


def fmt_mft_reference(ref: int) -> str:
    """An MFT reference is 6 bytes record # + 2 bytes sequence #."""
    record = ref & 0x0000_FFFF_FFFF_FFFF
    seq    = (ref >> 48) & 0xFFFF
    return f"record={record}  seq={seq}"


def decode_mft_reference(ref: int) -> tuple[int, int]:
    """Return (record_number, sequence_number)."""
    return (ref & 0x0000_FFFF_FFFF_FFFF, (ref >> 48) & 0xFFFF)


# ──────────────────────────────────────────────────────────────────────────
# $OBJECT_ID  (0x40, 16/32/48/64 B)
# ──────────────────────────────────────────────────────────────────────────
def _guid(buf: bytes) -> str:
    """The on-disk GUID is little-endian for the first 3 fields."""
    return str(uuid.UUID(bytes_le=buf))


def decode_object_id(data: bytes) -> dict[str, str]:
    if len(data) < 16:
        return {}
    out = {"Object ID": _guid(data[0:16])}
    if len(data) >= 32:
        out["Birth Volume ID"] = _guid(data[16:32])
    if len(data) >= 48:
        out["Birth Object ID"] = _guid(data[32:48])
    if len(data) >= 64:
        out["Domain ID"] = _guid(data[48:64])
    return out


# ──────────────────────────────────────────────────────────────────────────
# $VOLUME_NAME / $VOLUME_INFORMATION  (0x60 / 0x70)
# ──────────────────────────────────────────────────────────────────────────
def decode_volume_name(data: bytes) -> dict[str, str]:
    return {"Volume name": data.decode("utf-16-le", errors="replace")}


_VOL_INFO_FLAGS = [
    (0x0001, "Dirty"),
    (0x0002, "Resize logfile"),
    (0x0004, "Upgrade on mount"),
    (0x0008, "Mounted on NT4"),
    (0x0010, "Delete USN underway"),
    (0x0020, "Repair object IDs"),
    (0x8000, "Modified by chkdsk"),
]


def decode_volume_information(data: bytes) -> dict[str, str]:
    if len(data) < 12:
        return {}
    major = data[8]
    minor = data[9]
    flags = struct.unpack_from("<H", data, 10)[0]
    names = [n for b, n in _VOL_INFO_FLAGS if flags & b]
    return {
        "NTFS version": f"{major}.{minor}",
        "Flags":        f"0x{flags:04X}  ({', '.join(names) if names else 'Clean'})",
    }


# ──────────────────────────────────────────────────────────────────────────
# $ATTRIBUTE_LIST  (0x20)
# ──────────────────────────────────────────────────────────────────────────
def decode_attribute_list(data: bytes) -> list[dict[str, str]]:
    """Parse the variable-length entries of $ATTRIBUTE_LIST.

    Each entry:
        0x00 4   Attribute type
        0x04 2   Entry length
        0x06 1   Name length (chars)
        0x07 1   Name offset
        0x08 8   Starting VCN
        0x10 8   MFT reference (record # + sequence)
        0x18 2   Attribute ID
        0x1A x   Name (UTF-16) if name_len > 0
    """
    entries: list[dict[str, str]] = []
    pos = 0
    while pos + 0x1A <= len(data):
        attr_type = struct.unpack_from("<I", data, pos)[0]
        if attr_type == 0xFFFFFFFF or attr_type == 0:
            break
        length = struct.unpack_from("<H", data, pos + 4)[0]
        if length == 0 or pos + length > len(data):
            break
        name_len    = data[pos + 6]
        name_offset = data[pos + 7]
        start_vcn   = struct.unpack_from("<Q", data, pos + 8)[0]
        mft_ref     = struct.unpack_from("<Q", data, pos + 16)[0]
        attr_id     = struct.unpack_from("<H", data, pos + 24)[0]
        name = ""
        if name_len > 0:
            n_start = pos + name_offset
            name = data[n_start: n_start + name_len * 2].decode("utf-16-le", errors="replace")
        entries.append({
            "Type":      f"0x{attr_type:02X}  {ATTR_NAMES.get(attr_type, '?')}",
            "Length":    str(length),
            "Start VCN": str(start_vcn),
            "MFT ref":   fmt_mft_reference(mft_ref),
            "Attr ID":   str(attr_id),
            "Name":      name or "—",
        })
        pos += length
    return entries


# ──────────────────────────────────────────────────────────────────────────
# $REPARSE_POINT  (0xC0)  — minimal header decode
# ──────────────────────────────────────────────────────────────────────────
_REPARSE_TAGS = {
    0xA0000003: "MOUNT_POINT (junction)",
    0xA000000C: "SYMLINK",
    0x80000023: "AF_UNIX",
    0x80000017: "WOF (compression)",
    0x8000001E: "WCI (container)",
}


def decode_reparse_point(data: bytes) -> dict[str, str]:
    if len(data) < 8:
        return {}
    tag, length = struct.unpack_from("<IH", data, 0)
    return {
        "Reparse tag":   f"0x{tag:08X}  {_REPARSE_TAGS.get(tag, '?')}",
        "Data length":   f"{length} bytes",
        "Is Microsoft":  "Yes" if tag & 0x80000000 else "No",
        "Is name surrogate": "Yes" if tag & 0x20000000 else "No",
    }


# ──────────────────────────────────────────────────────────────────────────
# $BITMAP  (0xB0)  — describes which index buffers are in use
# ──────────────────────────────────────────────────────────────────────────
def decode_bitmap(data: bytes) -> dict[str, str]:
    used = sum(bin(b).count("1") for b in data)
    total = len(data) * 8
    return {
        "Bitmap size": f"{len(data)} bytes ({total} bits)",
        "Bits set":    f"{used} / {total}  (=> {used} index buffer(s) in use)",
        "First bytes": data[:16].hex(" ").upper() + (" …" if len(data) > 16 else ""),
    }
