from __future__ import annotations

import base64
import struct
from abc import ABC, abstractmethod

from rich.table import Table
from rich import box

from ifn.display.hex_table import render_hex_table


class ValueParser(ABC):
    """Base class for registry value parsers.

    Each subclass must set `name` (used as the JSON key in `hives get` output),
    declare what (hive_type, key_path, value_name) combinations it handles via
    matches(), and implement parse() + render().

    parse() must return a JSON-serializable dict (datetimes as ISO strings,
    bytes as hex or base64 strings).
    """

    name: str  # JSON key for this parser; must be set by each concrete subclass

    @abstractmethod
    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        """Return True if this parser applies to the given context."""
        ...

    @abstractmethod
    def parse(self, data: bytes) -> dict:
        """Return a JSON-serializable dict describing the value."""
        ...

    @abstractmethod
    def render(self, data: bytes, title: str, console) -> None:
        """Render the parsed value to console using Rich or render_hex_table."""
        ...


# ---------------------------------------------------------------------------
# Intermediate bases — hive-type filters
# ---------------------------------------------------------------------------

class SystemHiveParser(ValueParser):
    """Base for SYSTEM hive parsers."""

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return hive_type == "SYSTEM"


class SamHiveParser(ValueParser):
    """Base for SAM hive parsers."""

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return hive_type == "SAM"


# ---------------------------------------------------------------------------
# SYSTEM — MountedDevices
# ---------------------------------------------------------------------------

def _parse_win_guid(data: bytes) -> str:
    d1, = struct.unpack_from("<I", data, 0)
    d2, = struct.unpack_from("<H", data, 4)
    d3, = struct.unpack_from("<H", data, 6)
    d4 = data[8:16]
    return (f"{{{d1:08X}-{d2:04X}-{d3:04X}-"
            f"{d4[0]:02X}{d4[1]:02X}-"
            f"{''.join(f'{b:02X}' for b in d4[2:])}}}")


class MountedDeviceParser(SystemHiveParser):
    """Parses binary values under SYSTEM\\MountedDevices.

    Handles four formats:
      • 'DMIO:ID:' magic (24 bytes) — LDM dynamic disk
      • 12 bytes — MBR disk signature + partition byte offset
      • 16 bytes — GPT partition GUID
      • UTF-16LE GUID string — {DiskGUID}#PartitionByteOffsetHex
    """

    name = "mounted_device"

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return super().matches(hive_type, key_path, value_name) and key_path.lower() == "mounteddevices"

    def parse(self, data: bytes) -> dict:
        if data[:8] == b"DMIO:ID:":
            identifier = data[8:24] if len(data) >= 24 else data[8:]
            guid_str = _parse_win_guid(identifier) if len(identifier) == 16 else ""
            return {"type": "dmio", "guid": guid_str}

        if len(data) == 12:
            sig, = struct.unpack_from("<I", data, 0)
            offset_b, = struct.unpack_from("<Q", data, 4)
            return {
                "type": "mbr",
                "disk_signature": f"0x{sig:08X}",
                "partition_byte_offset": offset_b,
                "partition_sector_offset": offset_b // 512,
            }

        if len(data) == 16:
            return {"type": "gpt", "partition_guid": _parse_win_guid(data)}

        if len(data) >= 2 and data[0] == 0x7B and data[1] == 0x00:
            try:
                text = data.decode("utf-16-le")
                if "#" in text:
                    guid_part, _, offset_hex = text.partition("#")
                    out: dict = {"type": "guid_string", "disk_guid": guid_part}
                    try:
                        partition_offset = int(offset_hex, 16)
                        out["partition_byte_offset"] = partition_offset
                        out["partition_sector_offset"] = partition_offset // 512
                    except ValueError:
                        pass
                    return out
                return {"type": "guid_string", "path": text}
            except Exception:
                pass

        return {"type": "unknown", "hex": data.hex(" ").upper()}

    def render(self, data: bytes, title: str, console) -> None:
        if data[:8] == b"DMIO:ID:":
            identifier = data[8:24] if len(data) >= 24 else data[8:]
            guid_str = _parse_win_guid(identifier) if len(identifier) == 16 else ""
            fields: list[tuple[int, int, str, str]] = [
                (0x00, 8, "Magic", "DMIO:ID:  (LDM dynamic disk)"),
            ]
            if len(identifier) >= 16:
                d1, = struct.unpack_from("<I", identifier, 0)
                d2, = struct.unpack_from("<H", identifier, 4)
                d3, = struct.unpack_from("<H", identifier, 6)
                fields += [
                    (0x08, 4, "GUID Data1 (LE)", f"0x{d1:08X}"),
                    (0x0C, 2, "GUID Data2 (LE)", f"0x{d2:04X}"),
                    (0x0E, 2, "GUID Data3 (LE)", f"0x{d3:04X}"),
                    (0x10, 8, "GUID Data4 (BE)", identifier[8:16].hex(" ").upper()),
                ]
            render_hex_table(data, fields, title=f"{title} — DMIO:ID:", console=console)
            if guid_str:
                console.print(f"\n  [bold]Volume identifier GUID:[/bold]  {guid_str}")
            return

        if len(data) == 12:
            sig, = struct.unpack_from("<I", data, 0)
            offset_b, = struct.unpack_from("<Q", data, 4)
            offset_s = offset_b // 512
            fields = [
                (0, 4, "MBR disk signature", f"0x{sig:08X}"),
                (4, 8, "Partition byte offset", f"{offset_b:,} bytes  → sector {offset_s:,}  ({offset_b / 2**20:.1f} MiB)"),
            ]
            render_hex_table(data, fields, title=f"{title} — MBR Partition", console=console)
            return

        if len(data) == 16:
            guid_str = _parse_win_guid(data)
            d1, = struct.unpack_from("<I", data, 0)
            d2, = struct.unpack_from("<H", data, 4)
            d3, = struct.unpack_from("<H", data, 6)
            fields = [
                (0,  4, "GUID Data1 (LE)", f"0x{d1:08X}"),
                (4,  2, "GUID Data2 (LE)", f"0x{d2:04X}"),
                (6,  2, "GUID Data3 (LE)", f"0x{d3:04X}"),
                (8,  2, "GUID Data4[0:2]", data[8:10].hex(" ").upper()),
                (10, 6, "GUID Data4[2:8]", data[10:16].hex(" ").upper()),
            ]
            render_hex_table(data, fields, title=f"{title} — GPT Partition GUID", console=console)
            console.print(f"\n  [bold]Partition GUID:[/bold]  {guid_str}")
            return

        if len(data) >= 2 and data[0] == 0x7B and data[1] == 0x00:
            try:
                text = data.decode("utf-16-le")
            except Exception as e:
                console.print(f"[red]Failed to decode as UTF-16LE: {e}[/red]")
                return

            if "#" in text:
                guid_part, _, offset_hex = text.partition("#")
                guid_len = len(guid_part) * 2
                sep_off = guid_len
                val_off = sep_off + 2
                val_len = len(data) - val_off

                partition_offset: int | None = None
                offset_label = offset_hex
                try:
                    partition_offset = int(offset_hex, 16)
                    offset_label = (f"0x{offset_hex.upper()}  → "
                                    f"{partition_offset:,} bytes  "
                                    f"(sector {partition_offset // 512:,}, "
                                    f"{partition_offset / 2**20:.1f} MiB)")
                except ValueError:
                    pass

                fields = [
                    (0,       guid_len, "Disk GUID (UTF-16LE)", guid_part),
                    (sep_off, 2,        "Separator",            "#"),
                    (val_off, val_len,  "Partition byte offset (hex string)", offset_label),
                ]
                render_hex_table(data, fields, title=f"{title} — GUID String", console=console)
            else:
                fields = [(0, len(data), "Volume path (UTF-16LE)", text)]
                render_hex_table(data, fields, title=f"{title} — Volume Path", console=console)
            return

        fields = [(0, len(data), "Unknown data", f"{len(data)} bytes")]
        render_hex_table(data, fields, title=f"{title} — Unknown", console=console)


# ---------------------------------------------------------------------------
# SAM — user account blobs
# ---------------------------------------------------------------------------

_SAM_USER_PREFIX = "SAM\\Domains\\Account\\Users\\"


class SamUserVParser(SamHiveParser):
    """Parses the V (identity) blob for a SAM user account."""

    name = "sam_user_v"

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return (super().matches(hive_type, key_path, value_name)
                and key_path.startswith(_SAM_USER_PREFIX)
                and value_name == "V")

    def parse(self, data: bytes) -> dict:
        from ifn.parsers.sam import parse_v_blob
        result = parse_v_blob(data)
        return {
            "username":  result["username"],
            "fullname":  result["fullname"],
            "comment":   result["comment"],
            "lm_hash":   result["lm_hash"].hex(" ").upper() if result["lm_hash"] else None,
            "nt_hash":   result["nt_hash"].hex(" ").upper() if result["nt_hash"] else None,
        }

    def render(self, data: bytes, title: str, console) -> None:
        from ifn.parsers.sam import parse_v_blob
        result = parse_v_blob(data)
        t = Table(title=f"{title} — SAM User Identity (V)", box=box.ROUNDED, header_style="bold")
        t.add_column("Field", style="bold", no_wrap=True)
        t.add_column("Value")
        t.add_row("Username",  result["username"] or "[dim]—[/dim]")
        t.add_row("Full name", result["fullname"] or "[dim]—[/dim]")
        t.add_row("Comment",   result["comment"]  or "[dim]—[/dim]")
        t.add_row("LM hash",   result["lm_hash"].hex(" ").upper() if result["lm_hash"] else "[dim](none / not stored)[/dim]")
        t.add_row("NT hash",   result["nt_hash"].hex(" ").upper() if result["nt_hash"] else "[dim](none)[/dim]")
        console.print(t)


class SamUserFParser(SamHiveParser):
    """Parses the F (account metadata) blob for a SAM user account."""

    name = "sam_user_f"

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return (super().matches(hive_type, key_path, value_name)
                and key_path.startswith(_SAM_USER_PREFIX)
                and value_name == "F")

    def parse(self, data: bytes) -> dict:
        from ifn.parsers.sam import parse_f_blob, fmt_flags
        raw = parse_f_blob(data)

        def _fmt(v) -> str | None:
            if v is None:
                return None
            if isinstance(v, str):
                return v
            return v.strftime("%Y-%m-%dT%H:%M:%S") + "Z"

        return {
            "rid":               raw["rid"],
            "account_flags":     raw["account_flags"],
            "flags_decoded":     fmt_flags(raw["account_flags"]),
            "last_logon":        _fmt(raw["last_logon"]),
            "last_pw_change":    _fmt(raw["last_pw_change"]),
            "pw_must_change":    raw["pw_must_change"],
            "account_expires":   _fmt(raw["account_expires"]),
            "last_failed_logon": _fmt(raw["last_failed_logon"]),
            "failed_count":      raw["failed_count"],
            "logon_count":       raw["logon_count"],
        }

    def render(self, data: bytes, title: str, console) -> None:
        from ifn.parsers.sam import parse_f_blob, fmt_flags
        raw = parse_f_blob(data)

        def _fmt(v) -> str:
            if v is None:
                return "[dim]—[/dim]"
            if isinstance(v, str):
                return v
            return v.strftime("%Y-%m-%d %H:%M:%S UTC")

        t = Table(title=f"{title} — SAM Account Metadata (F)", box=box.ROUNDED, header_style="bold")
        t.add_column("Field", style="bold", no_wrap=True)
        t.add_column("Value")
        t.add_row("RID",                     f"0x{raw['rid']:08X}  ({raw['rid']})")
        t.add_row("Account flags",           fmt_flags(raw["account_flags"]))
        t.add_row("Last logon",              _fmt(raw["last_logon"]))
        t.add_row("Last password change",    _fmt(raw["last_pw_change"]))
        t.add_row("Must change at next logon", "Yes" if raw["pw_must_change"] else "No")
        t.add_row("Account expires",         _fmt(raw["account_expires"]))
        t.add_row("Last failed logon",       _fmt(raw["last_failed_logon"]))
        t.add_row("Failed logon count",      str(raw["failed_count"]))
        t.add_row("Logon count",             str(raw["logon_count"]))
        console.print(t)


# ---------------------------------------------------------------------------
# Default — raw hex dump (always last, always matches)
# ---------------------------------------------------------------------------

class HexDumpParser(ValueParser):
    """Fallback parser that renders the raw binary data for every value.

    Always matches so that raw bytes are always visible alongside any
    specialised interpretation.  In JSON output, emits base64 instead of
    a hex string.
    """

    name = "hex"

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return True

    def parse(self, data: bytes) -> dict:
        return {"base64": base64.b64encode(data).decode()}

    def render(self, data: bytes, title: str, console) -> None:
        render_hex_table(
            data,
            [(0, len(data), "Data", f"{len(data)} bytes")],
            title=title,
            console=console,
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_PARSERS: list[ValueParser] = [
    MountedDeviceParser(),
    SamUserVParser(),
    SamUserFParser(),
]

HEX_PARSER = HexDumpParser()


def find_parsers(hive_type: str, key_path: str, value_name: str) -> list[ValueParser]:
    """Return specialized parsers that match the given (hive_type, key_path, value_name).

    Does not include HexDumpParser — callers decide whether to include it via HEX_PARSER.
    """
    return [p for p in _PARSERS if p.matches(hive_type, key_path, value_name)]
