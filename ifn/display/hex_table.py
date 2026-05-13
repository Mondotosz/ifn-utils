"""
Reusable Rich renderer that shows a hex dump alongside an annotated field table.

Usage:
    from ifn.display.hex_table import render_hex_table
    render_hex_table(data, fields, title="MBR Partition Table")

fields is a list of (offset, length, field_name, interpreted_value) tuples.
Offset and length are byte positions within `data`.
"""
from __future__ import annotations

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

_HIGHLIGHT_COLORS = [
    "bold cyan", "bold yellow", "bold green", "bold magenta",
    "bold blue", "bold red", "bold white", "bold dark_orange",
]


def _hex_dump(data: bytes, fields: list[tuple[int, int, str, str]], width: int = 16) -> Text:
    """Build a coloured hex dump Text where each field region gets its own colour."""
    offset_map: dict[int, int] = {}
    for idx, (off, length, _, _) in enumerate(fields):
        for i in range(off, off + length):
            offset_map[i] = idx % len(_HIGHLIGHT_COLORS)

    text = Text()
    for row_start in range(0, len(data), width):
        chunk = data[row_start: row_start + width]
        text.append(f"{row_start:08X}  ", style="dim")
        for i, byte in enumerate(chunk):
            pos = row_start + i
            color = _HIGHLIGHT_COLORS[offset_map[pos]] if pos in offset_map else "default"
            text.append(f"{byte:02X}", style=color)
            text.append(" " if i != 7 else "  ")
        # Pad incomplete last row
        missing = width - len(chunk)
        text.append("   " * missing + ("  " if missing > 8 else ""))
        text.append(" |")
        for i, byte in enumerate(chunk):
            pos = row_start + i
            color = _HIGHLIGHT_COLORS[offset_map[pos]] if pos in offset_map else "dim"
            char = chr(byte) if 0x20 <= byte < 0x7F else "."
            text.append(char, style=color)
        text.append("|\n")
    return text


def render_hex_table(
    data: bytes,
    fields: list[tuple[int, int, str, str]],
    title: str = "",
    console: Console | None = None,
) -> None:
    """Render a hex dump panel alongside an annotated field table."""
    if console is None:
        console = Console()

    hex_text = _hex_dump(data, fields)
    hex_panel = Panel(hex_text, title="Hex Dump", border_style="dim", padding=(0, 1))

    field_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    field_table.add_column("Offset", style="dim", justify="right")
    field_table.add_column("Len", style="dim", justify="right")
    field_table.add_column("Field", style="bold")
    field_table.add_column("Raw (hex)")
    field_table.add_column("Value")

    for idx, (off, length, name, value) in enumerate(fields):
        color = _HIGHLIGHT_COLORS[idx % len(_HIGHLIGHT_COLORS)]
        raw = data[off: off + length].hex(" ").upper()
        field_table.add_row(
            f"0x{off:04X}",
            str(length),
            Text(name, style=color),
            raw,
            value,
        )

    field_panel = Panel(field_table, title="Fields", border_style="dim", padding=(0, 1))

    if title:
        console.rule(f"[bold]{title}[/bold]")
    console.print(Columns([hex_panel, field_panel], equal=False, expand=True))
