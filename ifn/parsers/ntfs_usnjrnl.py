"""Parsers for the NTFS USN change journal ($Extend\\$UsnJrnl).

Works directly on a **raw stream dump** (eg. the exhibits in the IFN course),
unlike `cli.image.usnjrnl` which streams from an E01 image via icat.

Two streams:

* $UsnJrnl:$Max — 32-byte configuration record:
    0x00 8   Maximum journal size (bytes)
    0x08 8   Allocation delta     (grow-by chunk)
    0x10 8   USN journal ID       (unique per journal incarnation)
    0x18 8   Lowest valid USN

* $UsnJrnl:$J — sequence of USN_RECORD_V2 records:
    0x00 4   Record length (whole record incl. padding, multiple of 8)
    0x04 2   Major version (2)
    0x06 2   Minor version (0)
    0x08 8   File reference        (MFT ref of the file)
    0x10 8   Parent file reference
    0x18 8   USN                   (offset of this record inside $J)
    0x20 8   Timestamp (FILETIME)
    0x28 4   Reason flags          (what changed)
    0x2C 4   Source info           (who changed it — system / antivirus / …)
    0x30 4   Security ID
    0x34 4   File attributes
    0x38 2   File name length      (bytes, UTF-16)
    0x3A 2   File name offset
    0x3C ... File name (UTF-16) + padding to record length

A record of length 0 marks a sparse hole — the iterator steps past it 8
bytes at a time until a real record header appears.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass
from typing import Iterator

from ifn.parsers.windows_time import filetime_to_datetime, fmt_filetime
from ifn.parsers.ntfs_attributes import fmt_file_attrs, fmt_mft_reference


# Reason flags — a single record may set several bits.
REASON_FLAGS: list[tuple[int, str]] = [
    (0x00000001, "DATA_OVERWRITE"),
    (0x00000002, "DATA_EXTEND"),
    (0x00000004, "DATA_TRUNCATION"),
    (0x00000010, "NAMED_DATA_OVERWRITE"),
    (0x00000020, "NAMED_DATA_EXTEND"),
    (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"),
    (0x00000200, "FILE_DELETE"),
    (0x00000400, "EA_CHANGE"),
    (0x00000800, "SECURITY_CHANGE"),
    (0x00001000, "RENAME_OLD_NAME"),
    (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"),
    (0x00008000, "BASIC_INFO_CHANGE"),
    (0x00010000, "HARD_LINK_CHANGE"),
    (0x00020000, "COMPRESSION_CHANGE"),
    (0x00040000, "ENCRYPTION_CHANGE"),
    (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"),
    (0x00200000, "STREAM_CHANGE"),
    (0x00400000, "TRANSACTED_CHANGE"),
    (0x80000000, "CLOSE"),
]

SOURCE_FLAGS: list[tuple[int, str]] = [
    (0x00000001, "DATA_MANAGEMENT"),
    (0x00000002, "AUXILIARY_DATA"),
    (0x00000004, "REPLICATION_MANAGEMENT"),
    (0x00000008, "CLIENT_REPLICATION_MANAGEMENT"),
]


def fmt_reason(value: int) -> str:
    parts = [n for b, n in REASON_FLAGS if value & b]
    return f"0x{value:08X}  ({'|'.join(parts) if parts else '—'})"


def fmt_source(value: int) -> str:
    parts = [n for b, n in SOURCE_FLAGS if value & b]
    return f"0x{value:08X}  ({'|'.join(parts) if parts else 'User'})"


# ──────────────────────────────────────────────────────────────────────────
# $Max
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class UsnJrnlMax:
    max_size: int
    allocation_delta: int
    journal_id: int
    lowest_valid_usn: int


def parse_max(data: bytes) -> UsnJrnlMax:
    if len(data) < 32:
        raise ValueError(f"$Max must be at least 32 bytes, got {len(data)}")
    max_size, delta, journal_id, lowest = struct.unpack_from("<QQQQ", data, 0)
    return UsnJrnlMax(max_size, delta, journal_id, lowest)


# ──────────────────────────────────────────────────────────────────────────
# $J  — USN_RECORD_V2
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class UsnRecord:
    offset: int               # offset inside the $J stream
    length: int
    major: int
    minor: int
    file_ref: int
    parent_ref: int
    usn: int
    timestamp: int            # FILETIME
    reason: int
    source: int
    security_id: int
    file_attrs: int
    name: str

    def as_row(self) -> dict[str, str]:
        return {
            "Offset":     f"0x{self.offset:08X}",
            "USN":        str(self.usn),
            "Timestamp":  fmt_filetime(self.timestamp),
            "Filename":   self.name,
            "Reason":     fmt_reason(self.reason),
            "Source":     fmt_source(self.source),
            "File ref":   fmt_mft_reference(self.file_ref),
            "Parent ref": fmt_mft_reference(self.parent_ref),
            "Attributes": fmt_file_attrs(self.file_attrs),
        }

    def as_json(self) -> dict:
        return {
            "offset":     self.offset,
            "usn":        self.usn,
            "timestamp":  fmt_filetime(self.timestamp),
            "filename":   self.name,
            "reason":     f"0x{self.reason:08X}",
            "reason_names": [n for b, n in REASON_FLAGS if self.reason & b],
            "source":     f"0x{self.source:08X}",
            "source_names": [n for b, n in SOURCE_FLAGS if self.source & b],
            "file_ref":   self.file_ref,
            "parent_ref": self.parent_ref,
            "file_attrs": f"0x{self.file_attrs:08X}",
        }


def iter_records(data: bytes, start: int = 0) -> Iterator[UsnRecord]:
    """Walk a raw $J stream, yielding parsed USN_RECORD_V2 records.

    Skips sparse holes (records of length 0) by advancing 8 bytes at a time
    until a real record header is found.
    """
    pos = start
    end = len(data)
    while pos + 4 <= end:
        length = struct.unpack_from("<I", data, pos)[0]
        if length == 0:
            pos += 8                              # sparse hole
            continue
        if length < 0x3C or pos + length > end:
            break
        major = struct.unpack_from("<H", data, pos + 4)[0]
        minor = struct.unpack_from("<H", data, pos + 6)[0]
        if major != 2:
            pos += length                          # V3 has a different layout
            continue
        file_ref, parent_ref, usn, ts = struct.unpack_from("<QQQQ", data, pos + 8)
        reason, source, sec_id, attrs = struct.unpack_from("<IIII", data, pos + 40)
        name_len = struct.unpack_from("<H", data, pos + 56)[0]
        name_off = struct.unpack_from("<H", data, pos + 58)[0]
        name = ""
        if name_len and pos + name_off + name_len <= end:
            name = data[pos + name_off: pos + name_off + name_len] \
                .decode("utf-16-le", errors="replace")
        yield UsnRecord(pos, length, major, minor, file_ref, parent_ref,
                        usn, ts, reason, source, sec_id, attrs, name)
        pos += length
