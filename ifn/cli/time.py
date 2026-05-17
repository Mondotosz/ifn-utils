from __future__ import annotations
import json
import struct
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table
from rich.panel import Panel
from rich import box

from ifn import context
from ifn.parsers import windows_time as wt
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Decode Windows and Unix timestamp formats")


@app.command()
def systemtime(
    file: Optional[Path] = typer.Argument(
        None,
        help="Text file with space-separated hex bytes, binary 16-byte file, or '-' for stdin",
    ),
) -> None:
    """Parse a SYSTEMTIME struct (8 × uint16 LE) from various input formats."""
    console = context.get_console()
    raw = wt.read_bytes_flexible(file, expected_size=16)
    _, fields = wt.parse_systemtime_bytes(raw)

    if context.output_json:
        field_list = [{"field": name, "raw": val, "interpretation": interp} for name, val, interp in fields]
        iso = f"{fields[0][1]:04d}-{fields[1][1]:02d}-{fields[3][1]:02d}T{fields[4][1]:02d}:{fields[5][1]:02d}:{fields[6][1]:02d}.{fields[7][1]:03d}"
        print(json.dumps({"fields": field_list, "iso": iso}, indent=2))
        return

    src_name = str(file) if file and str(file) != "-" else "<stdin>"
    hex_fields: list[tuple[int, int, str, str]] = [
        (i * 2, 2, f[0], f[2]) for i, f in enumerate(fields)
    ]
    render_hex_table(raw, hex_fields, title=f"SYSTEMTIME — {src_name}", console=console)

    table = Table(box=box.ROUNDED, header_style="bold")
    table.add_column("Field")
    table.add_column("Raw value", justify="right")
    table.add_column("Interpretation")
    for name, val, interp in fields:
        table.add_row(name, str(val), interp if interp != str(val) else "—")
    console.print(table)


@app.command()
def filetime(
    file: Optional[Path] = typer.Argument(
        None,
        help="Text file with space-separated hex bytes, binary 8-byte file, or '-' for stdin",
    ),
) -> None:
    """Parse a FILETIME (uint64 LE, 100 ns since 1601-01-01) from various input formats."""
    console = context.get_console()
    raw = wt.read_bytes_flexible(file, expected_size=8)
    ticks = struct.unpack_from("<Q", raw)[0]
    dt = wt.filetime_to_datetime(ticks)

    if context.output_json:
        print(json.dumps({"ticks": ticks, "utc": dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"}, indent=2))
        return

    src_name = str(file) if file and str(file) != "-" else "<stdin>"
    hex_fields: list[tuple[int, int, str, str]] = [
        (0, 8, "FILETIME (100-ns ticks)", str(ticks)),
    ]
    render_hex_table(raw, hex_fields, title=f"FILETIME — {src_name}", console=console)
    console.print(Panel(
        f"[bold]Ticks:[/bold] {ticks:,}  (100-ns intervals since 1601-01-01)\n"
        f"[bold]UTC:[/bold]   {dt.strftime('%Y-%m-%d %H:%M:%S.%f')} UTC",
        title="Decoded",
        border_style="green",
    ))


@app.command()
def unixtime(
    file: Optional[Path] = typer.Argument(
        None,
        help="Text file with '0x…' hex, decimal, binary 4-byte file, or '-' for stdin",
    ),
) -> None:
    """Parse a Unix timestamp from hex, decimal, or binary input."""
    console = context.get_console()
    raw = wt.read_bytes_flexible(file, expected_size=4)
    ts = struct.unpack_from("<I", raw)[0]
    dt = wt.unix_to_datetime(ts)

    if context.output_json:
        print(json.dumps({
            "decimal": ts,
            "hex": f"0x{ts:08X}",
            "utc": dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z",
        }, indent=2))
        return

    src_name = str(file) if file and str(file) != "-" else "<stdin>"
    console.print(Panel(
        f"[bold]Hex:[/bold]    0x{ts:08X}\n"
        f"[bold]Decimal:[/bold] {ts:,}\n"
        f"[bold]UTC:[/bold]    {dt.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        title=f"Unix Timestamp — {src_name}",
        border_style="green",
    ))


@app.command()
def tzid(id: int = typer.Argument(..., help="Windows timezone ID integer")) -> None:
    """Look up a Windows timezone ID in the TZ_DATA mapping."""
    console = context.get_console()
    try:
        import importlib.util
        tz_path = Path(__file__).parents[2] / "exhibits" / "tz" / "tz.py"
        if not tz_path.exists():
            console.print(f"[red]tz.py not found at {tz_path}[/red]")
            raise typer.Exit(1)
        spec = importlib.util.spec_from_file_location("tz_data", tz_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        tz_data: dict[int, str] = mod.TZ_DATA
    except Exception as e:
        console.print(f"[red]Failed to load TZ_DATA: {e}[/red]")
        raise typer.Exit(1)

    name = tz_data.get(id)

    if context.output_json:
        print(json.dumps({"id": id, "name": name}, indent=2))
        return

    if name:
        console.print(f"[bold cyan]{id}[/bold cyan]  →  {name}")
    else:
        console.print(f"[yellow]Timezone ID {id} not found in TZ_DATA.[/yellow]")
        nearby = [(k, v) for k, v in sorted(tz_data.items()) if abs(k - id) <= 5]
        if nearby:
            console.print("[dim]Nearby IDs:[/dim]")
            for k, v in nearby:
                console.print(f"  {k}  →  {v}")
