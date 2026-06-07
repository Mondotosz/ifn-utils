from __future__ import annotations

import base64
import re
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


class NtUserHiveParser(ValueParser):
    """Base for NTUSER.DAT hive parsers."""

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return hive_type == "NTUSER"


# ---------------------------------------------------------------------------
# SYSTEM — ShutdownTime
# ---------------------------------------------------------------------------

class SystemShutdownTimeParser(SystemHiveParser):
    """Parses the ShutdownTime FILETIME value under ControlSet*\\Control\\Windows."""

    name = "shutdown_time"

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return (super().matches(hive_type, key_path, value_name)
                and key_path.lower().endswith("control\\windows")
                and value_name == "ShutdownTime")

    def parse(self, data: bytes) -> dict:
        if len(data) < 8:
            return {"timestamp": None, "error": "too short"}
        ticks, = struct.unpack_from("<Q", data)
        if ticks == 0:
            return {"timestamp": None}
        from ifn.parsers.windows_time import filetime_to_datetime
        dt = filetime_to_datetime(ticks)
        return {"timestamp": dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"}

    def render(self, data: bytes, title: str, console) -> None:
        from ifn.parsers.windows_time import fmt_filetime
        if len(data) < 8:
            console.print("[red]ShutdownTime: too short[/red]")
            return
        ticks, = struct.unpack_from("<Q", data)
        ts_str = fmt_filetime(ticks)
        fields: list[tuple[int, int, str, str]] = [(0, 8, "ShutdownTime (FILETIME)", ts_str)]
        render_hex_table(data, fields, title=f"{title} — Shutdown Time", console=console)
        console.print(f"\n  [bold]Last shutdown:[/bold]  {ts_str}")


# ---------------------------------------------------------------------------
# SYSTEM — MountedDevices
# ---------------------------------------------------------------------------

def _is_device_path(data: bytes) -> bool:
    """True for UTF-16LE strings with a \\??\\ or _??_ prefix."""
    return (len(data) >= 8 and
            data[1] == 0x00 and
            data[2] == 0x3F and data[3] == 0x00 and
            data[4] == 0x3F and data[5] == 0x00 and
            data[0] in (0x5C, 0x5F) and
            data[6] in (0x5C, 0x5F) and data[7] == 0x00)


def _parse_device_path(text: str) -> dict:
    """Decompose an NT device instance path (\\??\\BusType#HwID#Serial#{GUID})."""
    raw_parts = text.rstrip("\x00").split("#")
    out: dict = {"path": text.rstrip("\x00")}

    # Bus type is always in parts[0]: "_??_USBSTOR" or "\??\SCSI"
    first = raw_parts[0]
    for sep in ("_??_", "\\??\\"):
        if first.startswith(sep):
            out["bus_type"] = first[len(sep):]
            break
    else:
        out["bus_type"] = first

    parts = list(raw_parts)

    # Interface GUID is the last part when it starts with '{'
    if parts and parts[-1].startswith("{") and parts[-1].endswith("}"):
        out["interface_guid"] = parts.pop()

    # Instance ID (serial&instance) is now the last remaining part after bus type
    if len(parts) >= 3:
        out["instance_id"] = parts.pop()
        # Serial is everything before the first '&' in the instance ID
        serial, _, _ = out["instance_id"].partition("&")
        if serial:
            out["serial"] = serial

    # Hardware ID: everything between bus type and instance ID
    # Join with '#' to reassemble paths that had embedded '#' (e.g. HS-SD#MMC)
    if len(parts) >= 2:
        hw_id = "#".join(parts[1:])
        out["hardware_id"] = hw_id
        for seg in hw_id.split("&"):
            if "_" in seg:
                key, _, val = seg.partition("_")
                if key in ("Ven", "Prod", "Rev"):
                    out[key.lower()] = val
            elif "device_type" not in out:
                out["device_type"] = seg

    return out


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

        if data[:15] == b"VeraCryptVolume":
            identifier = data.decode("ascii", errors="replace").rstrip("\x00")
            return {"type": "veracrypt", "identifier": identifier}

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

        if _is_device_path(data):
            try:
                text = data.decode("utf-16-le")
                d = _parse_device_path(text)
                d["type"] = "device_path"
                return d
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

        if data[:15] == b"VeraCryptVolume":
            identifier = data.decode("ascii", errors="replace").rstrip("\x00")
            fields: list[tuple[int, int, str, str]] = [
                (0, len(data), "VeraCrypt volume identifier (ASCII)", identifier),
            ]
            render_hex_table(data, fields, title=f"{title} — VeraCrypt Volume", console=console)
            console.print(f"\n  [bold]Identifier:[/bold]  {identifier}")
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

        if _is_device_path(data):
            try:
                text = data.decode("utf-16-le")
                parsed = _parse_device_path(text)
            except Exception as e:
                console.print(f"[red]Failed to decode device path: {e}[/red]")
                return
            path_str = parsed["path"]
            fields = [(0, len(data), "Device path (UTF-16LE)", path_str[:80] + ("…" if len(path_str) > 80 else ""))]
            render_hex_table(data, fields, title=f"{title} — Device Path", console=console)
            t = Table(title="Device Path Components", box=box.ROUNDED, header_style="bold")
            t.add_column("Field", style="bold", no_wrap=True)
            t.add_column("Value")
            t.add_row("Bus type",        parsed.get("bus_type", "—"))
            t.add_row("Device type",     parsed.get("device_type", "—"))
            if "ven" in parsed:
                t.add_row("Vendor",      parsed["ven"] or "[dim](empty)[/dim]")
            if "prod" in parsed:
                t.add_row("Product",     parsed["prod"])
            if "rev" in parsed:
                t.add_row("Revision",    parsed["rev"])
            if "serial" in parsed:
                t.add_row("Serial",      parsed["serial"])
            if "instance_id" in parsed:
                t.add_row("Instance ID", parsed["instance_id"])
            if "hardware_id" in parsed:
                t.add_row("Hardware ID", parsed["hardware_id"])
            if "interface_guid" in parsed:
                t.add_row("Interface GUID", parsed["interface_guid"])
            console.print(t)
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
# SAM — group alias C blob
# ---------------------------------------------------------------------------

def _extract_group_name(data: bytes) -> str:
    """Extract the group name from a SAM alias C blob.

    Name field descriptor is at offsets 0x10 (rel) and 0x14 (length in bytes),
    relative to data section base at 0x34.
    """
    try:
        BASE = 0x34
        rel = struct.unpack_from("<I", data, 0x10)[0]
        ln  = struct.unpack_from("<I", data, 0x14)[0]
        if 0 < ln <= 256:
            start = BASE + rel
            raw = data[start: start + ln]
            candidate = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            if candidate and all(0x20 <= ord(c) <= 0x7E or c in (" ", "\t") for c in candidate):
                return candidate
    except Exception:
        pass
    return ""


class SamGroupCParser(SamHiveParser):
    """Parses the C (alias metadata) blob for SAM local groups."""

    name = "sam_group_c"

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return (super().matches(hive_type, key_path, value_name)
                and "aliases\\" in key_path.lower()
                and value_name == "C")

    def parse(self, data: bytes) -> dict:
        return {"group_name": _extract_group_name(data) or None}

    def render(self, data: bytes, title: str, console) -> None:
        name = _extract_group_name(data)
        fields: list[tuple[int, int, str, str]] = []
        if name:
            try:
                BASE = 0x34
                rel = struct.unpack_from("<I", data, 0x10)[0]
                ln  = struct.unpack_from("<I", data, 0x14)[0]
                fields = [
                    (0x10, 4, "Name offset (relative to 0x34)", str(rel)),
                    (0x14, 4, "Name length (bytes)", str(ln)),
                    (BASE + rel, ln, "Name (UTF-16LE)", name),
                ]
            except Exception:
                pass
        if not fields:
            fields = [(0, len(data), "C blob", f"{len(data)} bytes")]
        render_hex_table(data, fields, title=f"{title} — SAM Group Alias", console=console)
        if name:
            console.print(f"\n  [bold]Group name:[/bold]  {name}")


# ---------------------------------------------------------------------------
# NTUSER — MRUListEx (universal MRU order array)
# ---------------------------------------------------------------------------

def _decode_mrulistex(data: bytes) -> list[int]:
    order = []
    for i in range(0, len(data) - 3, 4):
        idx, = struct.unpack_from("<I", data, i)
        if idx == 0xFFFFFFFF:
            break
        order.append(idx)
    return order


class MRUListExParser(ValueParser):
    """Parses MRUListEx binary values (4-byte int array, terminated by 0xFFFFFFFF)."""

    name = "mru_list_ex"

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return value_name == "MRUListEx"

    def parse(self, data: bytes) -> dict:
        return {"order": _decode_mrulistex(data)}

    def render(self, data: bytes, title: str, console) -> None:
        order = _decode_mrulistex(data)
        fields: list[tuple[int, int, str, str]] = []
        for i, idx in enumerate(order):
            fields.append((i * 4, 4, f"MRU slot {i}", str(idx)))
        term_off = len(order) * 4
        if term_off + 4 <= len(data):
            fields.append((term_off, 4, "Terminator", "0xFFFFFFFF"))
        render_hex_table(data, fields, title=f"{title} — MRUListEx", console=console)
        console.print(f"\n  [bold]MRU order (most-recent first):[/bold]  {order}")


# ---------------------------------------------------------------------------
# NTUSER — BagMRU shell items
# ---------------------------------------------------------------------------

_BEEF0004 = 0xBEEF0004
_BEEF_UNICODE_OFFSET: dict[int, int] = {3: 0x12, 7: 0x22, 8: 0x1E, 9: 0x30}


def _extract_unicode_name(data: bytes, short_name_end: int) -> str:
    pos = short_name_end + 1
    if pos % 2:
        pos += 1
    if pos + 8 > len(data):
        return ""
    ext_size = struct.unpack_from("<H", data, pos)[0]
    if ext_size < 8 or pos + ext_size > len(data):
        return ""
    version = struct.unpack_from("<H", data, pos + 2)[0]
    sig     = struct.unpack_from("<I", data, pos + 4)[0]
    if sig != _BEEF0004:
        return ""
    uni_off = _BEEF_UNICODE_OFFSET.get(version, 0)
    if not uni_off:
        return ""
    name_start = pos + uni_off
    if name_start + 2 > len(data):
        return ""
    i = name_start
    while i + 1 < len(data) and not (data[i] == 0 and data[i + 1] == 0):
        i += 2
    raw = data[name_start:i]
    try:
        return raw.decode("utf-16-le", errors="replace") if raw else ""
    except Exception:
        return ""


def _decode_shellitem(data: bytes) -> str:
    if len(data) < 3:
        return data.hex(" ").upper()
    item_type = data[2]
    try:
        if item_type == 0x1F:
            return "[Desktop / Special Folder]"
        if item_type == 0x2F:
            return chr(data[3]) + ":\\"
        if item_type in (0x31, 0x32, 0xB1):
            end = data.find(b"\x00", 0x0E)
            if end > 0x0E:
                short = data[0x0E:end].decode("ascii", errors="replace")
                if all(0x20 <= ord(c) < 0x7F for c in short):
                    long_name = _extract_unicode_name(data, end)
                    return long_name if long_name else short
        if item_type == 0x74:
            end = data.find(b"\x00", 5)
            if end > 5:
                return data[5:end].decode("ascii", errors="replace")
    except Exception:
        pass
    return f"[type=0x{item_type:02X}] " + data[:16].hex(" ").upper()


class ShellItemParser(ValueParser):
    """Parses numeric shell item entries under BagMRU keys."""

    name = "shell_item"

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return "bagmru" in key_path.lower() and bool(re.match(r"^\d+$", value_name))

    def parse(self, data: bytes) -> dict:
        return {"name": _decode_shellitem(data)}

    def render(self, data: bytes, title: str, console) -> None:
        name = _decode_shellitem(data)
        label = name[:80] + ("…" if len(name) > 80 else "")
        fields: list[tuple[int, int, str, str]] = [(0, len(data), "Shell item", label)]
        render_hex_table(data, fields, title=f"{title} — BagMRU Shell Item", console=console)
        console.print(f"\n  [bold]Decoded:[/bold]  {name}")


# ---------------------------------------------------------------------------
# NTUSER — RecentDocs entries
# ---------------------------------------------------------------------------

def _decode_recent_name(data: bytes) -> str:
    i = 0
    while i < len(data):
        if 0x20 <= data[i] <= 0x7E:
            j = i
            while j < len(data) and 0x20 <= data[j] <= 0x7E:
                j += 1
            if j - i >= 4:
                return data[i:j].decode("ascii", errors="replace")
        i += 1
    return data[:32].hex(" ").upper()


class RecentDocParser(NtUserHiveParser):
    """Parses numeric entries under Explorer\\RecentDocs (and subkeys by extension)."""

    name = "recent_doc"

    def matches(self, hive_type: str, key_path: str, value_name: str) -> bool:
        return (super().matches(hive_type, key_path, value_name)
                and "recentdocs" in key_path.lower()
                and bool(re.match(r"^\d+$", value_name)))

    def parse(self, data: bytes) -> dict:
        return {"name": _decode_recent_name(data)}

    def render(self, data: bytes, title: str, console) -> None:
        name = _decode_recent_name(data)
        fields: list[tuple[int, int, str, str]] = [(0, len(data), "RecentDoc entry", name)]
        render_hex_table(data, fields, title=f"{title} — Recent Document", console=console)
        console.print(f"\n  [bold]Document name:[/bold]  {name}")


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
    SystemShutdownTimeParser(),
    MountedDeviceParser(),
    SamUserVParser(),
    SamUserFParser(),
    SamGroupCParser(),
    MRUListExParser(),
    ShellItemParser(),
    RecentDocParser(),
]

HEX_PARSER = HexDumpParser()


def find_parsers(hive_type: str, key_path: str, value_name: str) -> list[ValueParser]:
    """Return specialized parsers that match the given (hive_type, key_path, value_name).

    Does not include HexDumpParser — callers decide whether to include it via HEX_PARSER.
    """
    return [p for p in _PARSERS if p.matches(hive_type, key_path, value_name)]
