from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
import struct

from ifn.parsers import recycle
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse Windows Recycle Bin artifacts")
console = Console()


@app.command()
def info(file: Path = typer.Argument(..., help="Path to $I index file", exists=True)):
    """Parse a $I Recycle Bin index file (original path, size, deletion time)."""
    data = file.read_bytes()
    rec = recycle.parse_i_file(data)

    deletion_ft = struct.unpack_from("<Q", data, 16)[0]

    fields: list[tuple[int, int, str, str]] = [
        (0,  8, "Version",           str(rec.version)),
        (8,  8, "Original file size", f"{rec.file_size:,} bytes"),
        (16, 8, "Deletion FILETIME",  f"{deletion_ft}  →  {rec.deleted_at.strftime('%Y-%m-%d %H:%M:%S')} UTC"),
    ]
    if rec.version == 2:
        fields.append((24, 4, "Filename length", f"{rec.filename_length} chars"))
        fields.append((28, rec.filename_length * 2, "Original path (UTF-16LE)", rec.original_path))
    else:
        fields.append((24, 520, "Original path (UTF-16LE, 260 chars)", rec.original_path))

    render_hex_table(data, fields, title=f"Recycle Bin $I — {file.name}")

    console.print(Panel(
        f"[bold]Version:[/bold]       {rec.version}\n"
        f"[bold]Deleted at:[/bold]    {rec.deleted_at.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        f"[bold]Original size:[/bold] {rec.file_size:,} bytes\n"
        f"[bold]Original path:[/bold] {rec.original_path}",
        title="Decoded",
        border_style="green",
    ))


@app.command()
def dump(file: Path = typer.Argument(..., help="Path to $R data file", exists=True)):
    """Show hex preview of a $R Recycle Bin data file."""
    data = file.read_bytes()
    preview = data[:256]  # first 256 bytes

    console.print(Panel(
        f"[bold]File:[/bold]  {file}\n"
        f"[bold]Size:[/bold]  {len(data):,} bytes\n"
        f"[bold]Showing first {len(preview)} bytes[/bold]",
        title=f"$R file — {file.name}",
    ))
    render_hex_table(preview, [], title="")
