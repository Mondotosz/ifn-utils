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
from ifn.parsers.windows_time import filetime_to_datetime
from ifn.cli.hives._parsers import MountedDeviceParser

_MOUNTED_PARSER = MountedDeviceParser()

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

    if context.output_json:
        print(json.dumps(_MOUNTED_PARSER.parse(data), indent=2))
        return

    _MOUNTED_PARSER.render(data, f"MountedDevices — {file.name}", console)
