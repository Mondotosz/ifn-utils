"""Parse Windows Recycle Bin $I index files."""
from __future__ import annotations
import struct
from dataclasses import dataclass
from datetime import datetime

from ifn.parsers.windows_time import filetime_to_datetime


@dataclass
class RecycleBinInfo:
    version: int
    file_size: int
    deleted_at: datetime
    filename_length: int    # number of UTF-16 code units
    original_path: str


def parse_i_file(data: bytes) -> RecycleBinInfo:
    """Parse a $I Recycle Bin index file (version 2 format)."""
    if len(data) < 28:
        raise ValueError(f"$I file too short: {len(data)} bytes")

    version = struct.unpack_from("<Q", data, 0)[0]
    if version not in (1, 2):
        raise ValueError(f"Unsupported $I version: {version}")

    file_size = struct.unpack_from("<Q", data, 8)[0]
    deletion_ft = struct.unpack_from("<Q", data, 16)[0]
    deleted_at = filetime_to_datetime(deletion_ft)

    if version == 2:
        name_len = struct.unpack_from("<I", data, 24)[0]
        name_bytes = data[28: 28 + name_len * 2]
    else:
        # Version 1: fixed 520 bytes for the filename (260 chars UTF-16LE)
        name_len = 260
        name_bytes = data[24: 24 + 520]

    original_path = name_bytes.decode("utf-16-le").rstrip("\x00")
    return RecycleBinInfo(version, file_size, deleted_at, name_len, original_path)
