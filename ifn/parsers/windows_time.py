"""Parse Windows and Unix timestamp formats."""
from __future__ import annotations
import struct
from datetime import datetime, timezone, timedelta

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_UNIX_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

_SYSTEMTIME_FIELDS = [
    "Year", "Month", "Day of week", "Day",
    "Hour", "Minute", "Second", "Milliseconds",
]
_DOW = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
_MONTHS = ["", "January", "February", "March", "April", "May", "June",
           "July", "August", "September", "October", "November", "December"]


def _read_hex_text(text: str) -> bytes:
    """Parse a text file containing space-separated hex bytes like '8D 39 E4 CC A9 8E DB 01'."""
    tokens = text.strip().split()
    return bytes(int(t, 16) for t in tokens)


def parse_systemtime(text: str) -> tuple[bytes, list[tuple[str, int, str]]]:
    """Return (raw_bytes, [(field_name, value, interpretation), ...])."""
    raw = _read_hex_text(text)
    if len(raw) < 16:
        raise ValueError(f"SYSTEMTIME must be 16 bytes, got {len(raw)}")
    values = struct.unpack_from("<8H", raw)
    result = []
    for i, (name, val) in enumerate(zip(_SYSTEMTIME_FIELDS, values)):
        if name == "Day of week":
            interp = _DOW[val] if val < 7 else f"Unknown ({val})"
        elif name == "Month":
            interp = _MONTHS[val] if 1 <= val <= 12 else f"Unknown ({val})"
        else:
            interp = str(val)
        result.append((name, val, interp))
    return raw, result


def parse_filetime(text: str) -> tuple[bytes, datetime]:
    """Parse a FILETIME (uint64 LE, 100-ns intervals since 1601-01-01)."""
    raw = _read_hex_text(text)
    if len(raw) < 8:
        raise ValueError(f"FILETIME must be 8 bytes, got {len(raw)}")
    ticks = struct.unpack_from("<Q", raw)[0]
    dt = _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    return raw, dt


def filetime_to_datetime(ticks: int) -> datetime:
    """Convert a raw FILETIME integer to a UTC datetime."""
    return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)


def parse_unixtime(text: str) -> tuple[int, datetime]:
    """Parse a Unix timestamp from a hex string like '0x676f94cc'."""
    ts = int(text.strip(), 16)
    dt = _UNIX_EPOCH + timedelta(seconds=ts)
    return ts, dt
