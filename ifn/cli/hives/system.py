from __future__ import annotations
import csv
import json
import struct
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table
from rich import box
from Registry import Registry

from ifn import context
from ifn.display.hex_table import render_hex_table
from ifn.parsers.windows_time import filetime_to_datetime

app = typer.Typer(help="SYSTEM hive analysis")

_USBSTOR_HEADERS = ["Device string", "Serial", "Last connected"]
_MOUNTED_HEADERS = ["Mount point", "Identifier (first 12 bytes hex)"]


def _open_hive(path: Path) -> Registry.Registry:
    console = context.get_console()
    try:
        return Registry.Registry(str(path))
    except Exception as e:
        console.print(f"[red]Failed to open hive: {e}[/red]")
        raise typer.Exit(1)


def _fmt_ts(dt) -> str:
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _csv_path(base: Path, table: str) -> Path:
    return base.with_stem(base.stem + "_" + table)


@app.command()
def info(
    hive: Path = typer.Argument(..., help="Path to SYSTEM hive", exists=True),
    controlset: str = typer.Option("ControlSet001", "--controlset", "-c", help="ControlSet key name"),
) -> None:
    """Computer name, timezone, and last shutdown time."""
    console = context.get_console()
    reg = _open_hive(hive)

    computer_name = "—"
    try:
        key = reg.open(f"{controlset}\\Control\\ComputerName\\ComputerName")
        computer_name = key.value("ComputerName").value()
    except Exception:
        pass

    tz_name, utc_label, bias_min = "—", "—", None
    try:
        tz_key = reg.open(f"{controlset}\\Control\\TimeZoneInformation")
        tz_name = tz_key.value("TimeZoneKeyName").value()
        raw_bias = tz_key.value("Bias").value()
        bias_min = struct.unpack("<i", struct.pack("<I", raw_bias))[0]
        offset_min = -bias_min
        sign = "+" if offset_min >= 0 else "-"
        utc_label = f"UTC{sign}{abs(offset_min) // 60}:{abs(offset_min) % 60:02d}"
    except Exception:
        pass

    shutdown_iso: str | None = None
    shutdown_str = "—"
    win_fields: list[tuple[str, str]] = []
    try:
        win_key = reg.open(f"{controlset}\\Control\\Windows")
        sd_data = win_key.value("ShutdownTime").value()
        if isinstance(sd_data, bytes) and len(sd_data) >= 8:
            ticks = struct.unpack_from("<Q", sd_data)[0]
            if ticks:
                dt = filetime_to_datetime(ticks)
                shutdown_str = _fmt_ts(dt)
                shutdown_iso = dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"

        def _wval(name: str) -> str:
            try:
                v = win_key.value(name).value()
                return str(v) if not isinstance(v, bytes) else v.hex(" ").upper()
            except Exception:
                return "—"

        win_fields = [
            ("Directory",                 _wval("Directory")),
            ("SystemDirectory",           _wval("SystemDirectory")),
            ("ErrorMode",                 _wval("ErrorMode")),
            ("ShellErrorMode",            _wval("ShellErrorMode")),
            ("NoInteractiveServices",     _wval("NoInteractiveServices")),
            ("ComponentizedBuild",        _wval("ComponentizedBuild")),
            ("CSDVersion",               _wval("CSDVersion")),
            ("CSDReleaseType",            _wval("CSDReleaseType")),
            ("CSDBuildNumber",            _wval("CSDBuildNumber")),
        ]
    except Exception:
        pass

    if context.output_json:
        result = {
            "computer_name": computer_name,
            "timezone": tz_name,
            "utc_offset": utc_label,
            "bias_minutes": bias_min,
            "last_shutdown": shutdown_iso,
            "controlset": controlset,
        }
        for field, value in win_fields:
            result[field] = value if value != "—" else None
        print(json.dumps(result, indent=2))
        return

    bias_display = f"{bias_min} min  (UTC offset = {-bias_min:+d} min)" if bias_min is not None else "—"
    table = Table(title="SYSTEM — Host Information", box=box.ROUNDED, header_style="bold")
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value")
    table.add_row("Computer name",  computer_name)
    table.add_row("Timezone",       f"{tz_name}  ({utc_label})")
    table.add_row("Bias",           bias_display)
    table.add_row("Last shutdown",  shutdown_str)
    table.add_row("[dim]Control set[/dim]", f"[dim]{controlset}[/dim]")
    if win_fields:
        table.add_section()
        for field, value in win_fields:
            table.add_row(field, value if value != "—" else "[dim]—[/dim]")
    console.print(table)


@app.command()
def usb(
    hive: Path = typer.Argument(..., help="Path to SYSTEM hive", exists=True),
    controlset: str = typer.Option("ControlSet001", "--controlset", "-c", help="ControlSet key name"),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export to CSV (produces _usbstor.csv and _mounted.csv)"),
) -> None:
    """List USB storage devices from USBSTOR and MountedDevices."""
    console = context.get_console()
    reg = _open_hive(hive)

    usb_rows: list[tuple[str, str, str]] = []
    try:
        usbstor = reg.open(f"{controlset}\\Enum\\USBSTOR")
        for dev_key in usbstor.subkeys():
            for serial_key in dev_key.subkeys():
                ts = serial_key.timestamp()
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "—"
                usb_rows.append((dev_key.name(), serial_key.name(), ts_str))
    except Registry.RegistryKeyNotFoundException:
        pass

    mount_rows: list[tuple[str, str]] = []
    try:
        md_key = reg.open("MountedDevices")
        for val in md_key.values():
            name = val.name()
            if not name.startswith(("\\DosDevices\\", "\\??\\")):
                continue
            raw = val.value()
            hex_id = raw[:12].hex(" ").upper() if isinstance(raw, bytes) else str(raw)[:40]
            mount_rows.append((name, hex_id))
    except Registry.RegistryKeyNotFoundException:
        pass

    if context.output_json:
        print(json.dumps({
            "usbstor": [{"device": d, "serial": s, "last_connected": t} for d, s, t in usb_rows],
            "mounted_devices": [{"mount_point": m, "identifier_hex": h} for m, h in mount_rows],
        }, indent=2))
        return

    usb_table = Table(title="USB Storage Devices (USBSTOR)", box=box.ROUNDED, header_style="bold")
    usb_table.add_column("Device string")
    usb_table.add_column("Serial")
    usb_table.add_column("Last connected")
    for device, serial, ts_str in usb_rows:
        usb_table.add_row(device, serial, ts_str)
    if usb_rows:
        console.print(usb_table)
    else:
        console.print("[dim]No USB storage devices found.[/dim]")

    mount_table = Table(title="Mounted Devices", box=box.ROUNDED, header_style="bold")
    mount_table.add_column("Mount point")
    mount_table.add_column("Identifier (first 12 bytes hex)")
    for mount_point, hex_id in mount_rows:
        mount_table.add_row(mount_point, hex_id)
    if mount_rows:
        console.print(mount_table)

    if csv_out is not None:
        _write_csv(_csv_path(csv_out, "usbstor"), _USBSTOR_HEADERS, [list(r) for r in usb_rows], console)
        _write_csv(_csv_path(csv_out, "mounted"), _MOUNTED_HEADERS, [list(r) for r in mount_rows], console)


def _write_csv(path: Path, headers: list[str], rows: list[list[str]], console) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(rows)
    console.print(f"[green]✓ Exported {len(rows)} row(s) → {path}[/green]")


def _parse_win_guid(data: bytes) -> str:
    """Format 16 bytes in Windows GUID binary encoding to a GUID string."""
    d1, = struct.unpack_from("<I", data, 0)
    d2, = struct.unpack_from("<H", data, 4)
    d3, = struct.unpack_from("<H", data, 6)
    d4 = data[8:16]
    return (f"{{{d1:08X}-{d2:04X}-{d3:04X}-"
            f"{d4[0]:02X}{d4[1]:02X}-"
            f"{''.join(f'{b:02X}' for b in d4[2:])}}}")


@app.command(name="mounted-devices-bin")
def mounted_devices_bin(
    file: Path = typer.Argument(..., help="Path to binary dump of a MountedDevices value", exists=True),
) -> None:
    """Parse a raw MountedDevices binary value (e.g. dumped from SYSTEM\\MountedDevices).

    Handles four formats:\\n
      • 'DMIO-ID' magic (24 bytes) — LDM dynamic disk\\n
      • 12 bytes — MBR disk signature + partition byte offset\\n
      • 16 bytes — GPT partition GUID\\n
      • UTF-16LE GUID string — {DiskGUID}#PartitionByteOffsetHex
    """
    console = context.get_console()
    data = file.read_bytes()

    if not data:
        console.print("[red]Empty file.[/red]")
        raise typer.Exit(1)

    # --- DMIO:ID: (dynamic / LDM disk) ---
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
        if context.output_json:
            print(json.dumps({"type": "dmio", "guid": guid_str}, indent=2))
            return
        render_hex_table(data, fields, title=f"MountedDevices — DMIO:ID: — {file.name}", console=console)
        if guid_str:
            console.print(f"\n  [bold]Volume identifier GUID:[/bold]  {guid_str}")
        return

    # --- MBR basic disk (12 bytes) ---
    if len(data) == 12:
        sig, = struct.unpack_from("<I", data, 0)
        offset_b, = struct.unpack_from("<Q", data, 4)
        offset_s = offset_b // 512
        fields = [
            (0, 4, "MBR disk signature", f"0x{sig:08X}"),
            (4, 8, "Partition byte offset", f"{offset_b:,} bytes  → sector {offset_s:,}  ({offset_b / 2**20:.1f} MiB)"),
        ]
        if context.output_json:
            print(json.dumps({
                "type": "mbr",
                "disk_signature": f"0x{sig:08X}",
                "partition_byte_offset": offset_b,
                "partition_sector_offset": offset_s,
            }, indent=2))
            return
        render_hex_table(data, fields, title=f"MountedDevices — MBR Partition — {file.name}", console=console)
        return

    # --- GPT partition (16 bytes) ---
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
        if context.output_json:
            print(json.dumps({"type": "gpt", "partition_guid": guid_str}, indent=2))
            return
        render_hex_table(data, fields, title=f"MountedDevices — GPT Partition GUID — {file.name}", console=console)
        console.print(f"\n  [bold]Partition GUID:[/bold]  {guid_str}")
        return

    # --- UTF-16LE GUID string ({DiskGUID}#PartitionByteOffsetHex) ---
    if len(data) >= 2 and data[0] == 0x7B and data[1] == 0x00:
        try:
            text = data.decode("utf-16-le")
        except Exception as e:
            console.print(f"[red]Failed to decode as UTF-16LE: {e}[/red]")
            raise typer.Exit(1)

        if "#" in text:
            guid_part, _, offset_hex = text.partition("#")
            guid_len = len(guid_part) * 2        # bytes consumed by GUID chars
            sep_off = guid_len
            val_off = sep_off + 2                # skip '#' (2 bytes in UTF-16LE)
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
            if context.output_json:
                out: dict = {"type": "guid_string", "disk_guid": guid_part}
                if partition_offset is not None:
                    out["partition_byte_offset"] = partition_offset
                    out["partition_sector_offset"] = partition_offset // 512
                print(json.dumps(out, indent=2))
                return
            render_hex_table(data, fields, title=f"MountedDevices — GUID String — {file.name}", console=console)
        else:
            fields = [(0, len(data), "Volume path (UTF-16LE)", text)]
            if context.output_json:
                print(json.dumps({"type": "guid_string", "path": text}, indent=2))
                return
            render_hex_table(data, fields, title=f"MountedDevices — Volume Path — {file.name}", console=console)
        return

    # --- Unknown format ---
    fields = [(0, len(data), "Unknown data", f"{len(data)} bytes")]
    if context.output_json:
        print(json.dumps({"type": "unknown", "hex": data.hex(" ").upper()}, indent=2))
        return
    render_hex_table(data, fields, title=f"MountedDevices — Unknown — {file.name}", console=console)
