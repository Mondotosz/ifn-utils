from pathlib import Path
import sys

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from ifn.parsers import windows_time as wt
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Decode Windows and Unix timestamp formats")
console = Console()


@app.command()
def systemtime(file: Path = typer.Argument(..., help="Text file with space-separated hex bytes", exists=True)):
    """Parse a SYSTEMTIME struct (8 × uint16 LE) from a hex text file."""
    raw, fields = wt.parse_systemtime(file.read_text())

    hex_fields: list[tuple[int, int, str, str]] = [
        (i * 2, 2, f[0], f[2]) for i, f in enumerate(fields)
    ]
    render_hex_table(raw, hex_fields, title=f"SYSTEMTIME — {file.name}")

    table = Table(box=box.ROUNDED, header_style="bold")
    table.add_column("Field")
    table.add_column("Raw value", justify="right")
    table.add_column("Interpretation")
    for name, val, interp in fields:
        table.add_row(name, str(val), interp if interp != str(val) else "—")
    console.print(table)


@app.command()
def filetime(file: Path = typer.Argument(..., help="Text file with space-separated hex bytes", exists=True)):
    """Parse a FILETIME (uint64 LE, 100 ns since 1601-01-01) from a hex text file."""
    raw, dt = wt.parse_filetime(file.read_text())

    import struct
    ticks = struct.unpack_from("<Q", raw)[0]

    hex_fields: list[tuple[int, int, str, str]] = [
        (0, 8, "FILETIME (100-ns ticks)", str(ticks)),
    ]
    render_hex_table(raw, hex_fields, title=f"FILETIME — {file.name}")
    console.print(Panel(
        f"[bold]Ticks:[/bold] {ticks:,}  (100-ns intervals since 1601-01-01)\n"
        f"[bold]UTC:[/bold]   {dt.strftime('%Y-%m-%d %H:%M:%S.%f')} UTC",
        title="Decoded",
        border_style="green",
    ))


@app.command()
def unixtime(file: Path = typer.Argument(..., help="Text file containing a hex timestamp", exists=True)):
    """Parse a Unix timestamp from a hex string (e.g. 0x676f94cc) in a text file."""
    text = file.read_text().strip()
    ts, dt = wt.parse_unixtime(text)

    console.print(Panel(
        f"[bold]Hex:[/bold]    {text}\n"
        f"[bold]Decimal:[/bold] {ts:,}\n"
        f"[bold]UTC:[/bold]    {dt.strftime('%Y-%m-%d %H:%M:%S')} UTC",
        title=f"Unix Timestamp — {file.name}",
        border_style="green",
    ))


@app.command()
def tzid(id: int = typer.Argument(..., help="Windows timezone ID integer")):
    """Look up a Windows timezone ID in the TZ_DATA mapping."""
    try:
        # Import TZ_DATA from the tz.py exhibit file
        import importlib.util, os
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

    if id in tz_data:
        console.print(f"[bold cyan]{id}[/bold cyan]  →  {tz_data[id]}")
    else:
        console.print(f"[yellow]Timezone ID {id} not found in TZ_DATA.[/yellow]")
        # Show nearby IDs
        nearby = [(k, v) for k, v in sorted(tz_data.items()) if abs(k - id) <= 5]
        if nearby:
            console.print("[dim]Nearby IDs:[/dim]")
            for k, v in nearby:
                console.print(f"  {k}  →  {v}")
