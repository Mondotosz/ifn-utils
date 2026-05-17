"""Parse Windows and Unix timestamp formats."""
from __future__ import annotations
import struct
import sys
from pathlib import Path
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


def read_bytes_flexible(src: Path | None, expected_size: int) -> bytes:
    """Read exactly ``expected_size`` bytes from many input formats.

    Accepted sources (auto-detected in order):
    - ``None`` or ``"-"``  → read from stdin (binary or text)
    - binary file of the right length → use directly
    - text: ``"0x..."`` hex integer (LE)
    - text: space-separated hex bytes ``"8D 39 E4 CC …"``
    - text: continuous hex string ``"8D39E4CC…"``
    - text: decimal integer (LE)
    """
    if src is None or str(src) == "-":
        raw = sys.stdin.buffer.read()
    else:
        raw = src.read_bytes()

    if len(raw) == expected_size:
        return raw

    text = raw.decode("utf-8", errors="strict").strip()

    if text.lower().startswith("0x"):
        val = int(text, 16)
        return val.to_bytes(expected_size, "little")

    tokens = text.split()
    _HEX = set("0123456789abcdefABCDEF")
    if tokens and all(1 <= len(t) <= 2 and set(t) <= _HEX for t in tokens):
        return bytes(int(t, 16) for t in tokens)

    stripped = text.replace(" ", "").replace("\n", "").replace("\r", "")
    if stripped and set(stripped) <= _HEX:
        return bytes.fromhex(stripped)

    val = int(text)
    return val.to_bytes(expected_size, "little")


def _read_hex_text(text: str) -> bytes:
    """Parse a text file containing space-separated hex bytes like '8D 39 E4 CC A9 8E DB 01'."""
    tokens = text.strip().split()
    return bytes(int(t, 16) for t in tokens)


def parse_systemtime_bytes(raw: bytes) -> tuple[bytes, list[tuple[str, int, str]]]:
    """Return (raw_bytes, [(field_name, value, interpretation), ...])."""
    if len(raw) < 16:
        raise ValueError(f"SYSTEMTIME must be 16 bytes, got {len(raw)}")
    values = struct.unpack_from("<8H", raw)
    result = []
    for name, val in zip(_SYSTEMTIME_FIELDS, values):
        if name == "Day of week":
            interp = _DOW[val] if val < 7 else f"Unknown ({val})"
        elif name == "Month":
            interp = _MONTHS[val] if 1 <= val <= 12 else f"Unknown ({val})"
        else:
            interp = str(val)
        result.append((name, val, interp))
    return raw, result


def parse_systemtime(text: str) -> tuple[bytes, list[tuple[str, int, str]]]:
    """Parse SYSTEMTIME from space-separated hex text (legacy interface)."""
    return parse_systemtime_bytes(_read_hex_text(text))


def parse_filetime(text: str) -> tuple[bytes, datetime]:
    """Parse a FILETIME from space-separated hex text (legacy interface)."""
    raw = _read_hex_text(text)
    if len(raw) < 8:
        raise ValueError(f"FILETIME must be 8 bytes, got {len(raw)}")
    ticks = struct.unpack_from("<Q", raw)[0]
    return raw, filetime_to_datetime(ticks)


def filetime_to_datetime(ticks: int) -> datetime:
    """Convert a raw FILETIME integer to a UTC datetime."""
    return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)


def fmt_filetime(ticks: int) -> str:
    """Format a FILETIME as a printable UTC string, '—' if zero."""
    if ticks == 0:
        return "—"
    return filetime_to_datetime(ticks).strftime("%Y-%m-%d %H:%M:%S.%f UTC")


def unix_to_datetime(ts: int) -> datetime:
    """Convert a Unix timestamp (seconds since 1970-01-01) to a UTC datetime."""
    return _UNIX_EPOCH + timedelta(seconds=ts)


def parse_unixtime(text: str) -> tuple[int, datetime]:
    """Parse a Unix timestamp from a hex string like '0x676f94cc' (legacy interface)."""
    ts = int(text.strip(), 16)
    return ts, unix_to_datetime(ts)
