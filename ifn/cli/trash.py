from __future__ import annotations
import json
import struct
from pathlib import Path

import typer
from rich.panel import Panel

from ifn import context
from ifn.parsers import recycle
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse Windows Recycle Bin artifacts")


@app.command()
def info(file: Path = typer.Argument(..., help="Path to $I index file", exists=True)) -> None:
    """Parse a $I Recycle Bin index file (original path, size, deletion time)."""
    console = context.get_console()
    data = file.read_bytes()
    rec = recycle.parse_i_file(data)

    if context.output_json:
        print(json.dumps({
            "version": rec.version,
            "file_size": rec.file_size,
            "deleted_at": rec.deleted_at.strftime("%Y-%m-%dT%H:%M:%S") + "Z",
            "original_path": rec.original_path,
        }, indent=2))
        return

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

    render_hex_table(data, fields, title=f"Recycle Bin $I — {file.name}", console=console)

    console.print(Panel(
        f"[bold]Version:[/bold]       {rec.version}\n"
        f"[bold]Deleted at:[/bold]    {rec.deleted_at.strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        f"[bold]Original size:[/bold] {rec.file_size:,} bytes\n"
        f"[bold]Original path:[/bold] {rec.original_path}",
        title="Decoded",
        border_style="green",
    ))


@app.command()
def dump(file: Path = typer.Argument(..., help="Path to $R data file", exists=True)) -> None:
    """Show hex preview of a $R Recycle Bin data file."""
    console = context.get_console()
    data = file.read_bytes()
    preview = data[:256]

    if context.output_json:
        print(json.dumps({
            "file": str(file),
            "size": len(data),
            "preview_hex": preview.hex(" ").upper(),
        }, indent=2))
        return

    console.print(Panel(
        f"[bold]File:[/bold]  {file}\n"
        f"[bold]Size:[/bold]  {len(data):,} bytes\n"
        f"[bold]Showing first {len(preview)} bytes[/bold]",
        title=f"$R file — {file.name}",
    ))
    render_hex_table(preview, [], title="", console=console)
