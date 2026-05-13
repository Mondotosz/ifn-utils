from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from ifn.parsers import mft_record as mft_parser
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse NTFS Master File Table records")
console = Console()

_RECORD_SIZE = 1024


@app.command()
def record(file: Path = typer.Argument(..., help="Path to a single MFT record dump", exists=True)):
    """Parse a single MFT record: magic, header fields, and all attributes."""
    data = file.read_bytes()
    rec = mft_parser.parse(data)

    if not rec.is_valid:
        console.print(f"[red]Invalid MFT record magic: {rec.magic!r} (expected b'FILE')[/red]")
        raise typer.Exit(1)

    header_fields: list[tuple[int, int, str, str]] = [
        (0,  4, "Magic",              rec.magic.decode()),
        (4,  2, "Update seq offset",  str(rec.update_seq_offset)),
        (6,  2, "Update seq size",    str(rec.update_seq_size)),
        (8,  8, "Log file seq#",      str(rec.log_file_seq)),
        (16, 2, "Sequence number",    str(rec.seq_number)),
        (18, 2, "Hard link count",    str(rec.hard_link_count)),
        (20, 2, "First attr offset",  f"0x{rec.first_attr_offset:04X}"),
        (22, 2, "Flags",              f"0x{rec.flags:04X}  ({rec.flag_names})"),
        (24, 4, "Used size",          f"{rec.used_size} bytes"),
        (28, 4, "Allocated size",     f"{rec.alloc_size} bytes"),
        (32, 8, "Base record ref",    str(rec.base_record_ref)),
        (40, 2, "Next attr ID",       str(rec.next_attr_id)),
        (44, 4, "Record number",      str(rec.record_number)),
    ]
    render_hex_table(data[:min(512, len(data))], header_fields, title=f"MFT Record — {file.name}")

    attr_table = Table(title="Attributes", box=box.ROUNDED, header_style="bold")
    attr_table.add_column("ID", justify="right")
    attr_table.add_column("Type")
    attr_table.add_column("Offset", justify="right")
    attr_table.add_column("Length", justify="right")
    attr_table.add_column("Resident")
    attr_table.add_column("Name")

    for attr in rec.attributes:
        if attr.attr_type == 0xFFFFFFFF:
            break
        attr_table.add_row(
            str(attr.attr_id),
            f"0x{attr.attr_type:02X}  {attr.attr_name}",
            f"0x{attr.offset:04X}",
            str(attr.length),
            "No" if attr.non_resident else "Yes",
            attr.name or "—",
        )
    console.print(attr_table)

    for attr in rec.attributes:
        if attr.attr_type == 0xFFFFFFFF or not attr.decoded:
            continue
        detail = Table(title=f"{attr.attr_name} details", box=box.SIMPLE, header_style="bold")
        detail.add_column("Field")
        detail.add_column("Value")
        for k, v in attr.decoded.items():
            detail.add_row(k, v)
        console.print(detail)


@app.command()
def scan(
    file: Path = typer.Argument(..., help="Path to full MFT dump", exists=True),
    limit: int = typer.Option(0, "--limit", "-n", help="Stop after N records (0 = all)"),
    show_deleted: bool = typer.Option(False, "--deleted", help="Include deleted (not in use) records"),
):
    """Iterate all records in an MFT dump and print a filename table (streaming)."""
    table = Table(title=f"MFT Scan — {file.name}", box=box.ROUNDED, header_style="bold")
    table.add_column("MFT#", justify="right")
    table.add_column("Filename")
    table.add_column("Parent#", justify="right")
    table.add_column("Type")
    table.add_column("Created")
    table.add_column("Modified")
    table.add_column("Size", justify="right")

    count = 0
    shown = 0
    with file.open("rb") as f:
        while True:
            chunk = f.read(_RECORD_SIZE)
            if not chunk:
                break
            if len(chunk) < 48:
                break
            if chunk[:4] != b"FILE":
                count += 1
                continue
            try:
                rec = mft_parser.parse(chunk)
            except Exception:
                count += 1
                continue

            if not show_deleted and not rec.is_in_use:
                count += 1
                continue

            fn_attrs = [a for a in rec.attributes if a.attr_type == 0x30]
            if not fn_attrs:
                count += 1
                continue

            for fn_attr in fn_attrs:
                d = fn_attr.decoded
                if not d:
                    continue
                table.add_row(
                    str(rec.record_number or count),
                    d.get("Filename", "?"),
                    d.get("Parent MFT#", "?"),
                    "DIR" if rec.is_directory else "file",
                    d.get("Created", "?"),
                    d.get("Modified", "?"),
                    d.get("Real size", "?"),
                )
                shown += 1
                break

            count += 1
            if limit and shown >= limit:
                break

    console.print(table)
    console.print(f"[dim]Scanned {count} records, displayed {shown}[/dim]")
