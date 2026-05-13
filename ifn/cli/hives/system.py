import struct
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich import box
from Registry import Registry

from ifn.parsers.windows_time import filetime_to_datetime

app = typer.Typer(help="SYSTEM hive analysis")
console = Console()


def _open_hive(path: Path) -> Registry.Registry:
    try:
        return Registry.Registry(str(path))
    except Exception as e:
        console.print(f"[red]Failed to open hive: {e}[/red]")
        raise typer.Exit(1)


def _fmt_ts(dt) -> str:
    if dt is None:
        return "—"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


@app.command()
def info(
    hive: Path = typer.Argument(..., help="Path to SYSTEM hive", exists=True),
    controlset: str = typer.Option("ControlSet001", "--controlset", "-c", help="ControlSet key name"),
):
    """Computer name, timezone, and last shutdown time."""
    reg = _open_hive(hive)

    computer_name = "—"
    try:
        key = reg.open(f"{controlset}\\Control\\ComputerName\\ComputerName")
        computer_name = key.value("ComputerName").value()
    except Exception:
        pass

    tz_name, utc_label, bias_display = "—", "—", "—"
    try:
        tz_key = reg.open(f"{controlset}\\Control\\TimeZoneInformation")
        tz_name = tz_key.value("TimeZoneKeyName").value()
        raw_bias = tz_key.value("Bias").value()
        # Bias is stored as uint32 but represents a signed int32 (minutes west of UTC)
        bias_min = struct.unpack("<i", struct.pack("<I", raw_bias))[0]
        offset_min = -bias_min
        sign = "+" if offset_min >= 0 else "-"
        utc_label = f"UTC{sign}{abs(offset_min) // 60}:{abs(offset_min) % 60:02d}"
        bias_display = f"{bias_min} min  (UTC offset = {offset_min:+d} min)"
    except Exception:
        pass

    shutdown = "—"
    win_fields: list[tuple[str, str]] = []
    try:
        win_key = reg.open(f"{controlset}\\Control\\Windows")

        sd_data = win_key.value("ShutdownTime").value()
        if isinstance(sd_data, bytes) and len(sd_data) >= 8:
            ticks = struct.unpack_from("<Q", sd_data)[0]
            if ticks:
                shutdown = _fmt_ts(filetime_to_datetime(ticks))

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
            ("FullProcessInformationSID", _wval("FullProcessInformationSID")),
        ]
    except Exception:
        pass

    table = Table(title="SYSTEM — Host Information", box=box.ROUNDED, header_style="bold")
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value")

    table.add_row("Computer name",  computer_name)
    table.add_row("Timezone",       f"{tz_name}  ({utc_label})")
    table.add_row("Bias",           bias_display)
    table.add_row("Last shutdown",  shutdown)
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
):
    """List USB storage devices from USBSTOR and MountedDevices."""
    reg = _open_hive(hive)

    # --- USBSTOR ---
    usb_table = Table(title="USB Storage Devices (USBSTOR)", box=box.ROUNDED, header_style="bold")
    usb_table.add_column("Device string")
    usb_table.add_column("Serial")
    usb_table.add_column("Last connected")

    try:
        usbstor = reg.open(f"{controlset}\\Enum\\USBSTOR")
        for dev_key in usbstor.subkeys():
            for serial_key in dev_key.subkeys():
                ts = serial_key.timestamp()
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "—"
                usb_table.add_row(dev_key.name(), serial_key.name(), ts_str)
    except Registry.RegistryKeyNotFoundException:
        console.print(f"[dim]{controlset}\\Enum\\USBSTOR not found.[/dim]")

    if usb_table.row_count:
        console.print(usb_table)
    else:
        console.print("[dim]No USB storage devices found.[/dim]")

    # --- MountedDevices ---
    mount_table = Table(title="Mounted Devices", box=box.ROUNDED, header_style="bold")
    mount_table.add_column("Mount point")
    mount_table.add_column("Identifier (first 12 bytes hex)")

    try:
        md_key = reg.open("MountedDevices")
        for val in md_key.values():
            name = val.name()
            if not name.startswith(("\\DosDevices\\", "\\??\\")):
                continue
            raw = val.value()
            hex_id = raw[:12].hex(" ").upper() if isinstance(raw, bytes) else str(raw)[:40]
            mount_table.add_row(name, hex_id)
    except Registry.RegistryKeyNotFoundException:
        console.print("[dim]MountedDevices key not found.[/dim]")

    if mount_table.row_count:
        console.print(mount_table)
