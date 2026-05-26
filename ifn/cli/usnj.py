"""`tool.py usnj` — parse $UsnJrnl on **raw stream dumps**.

This is complementary to `image usnjrnl`, which reads $UsnJrnl from a live
E01 image via icat. Use `usnj` when you only have the extracted $J / $Max
streams (typical for course exhibits or pre-collected evidence).
"""
from __future__ import annotations
import csv
import json
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.table import Table

from ifn import context
from ifn.parsers import ntfs_usnjrnl as usn


app = typer.Typer(help="Parse $UsnJrnl raw streams ($J records, $Max metadata)")


@app.command("max")
def max_cmd(
    file: Path = typer.Argument(..., exists=True, help="Raw $UsnJrnl:$Max dump (≥ 32 B)"),
) -> None:
    """Decode the $UsnJrnl:$Max configuration record."""
    console = context.get_console()
    data = file.read_bytes()
    try:
        m = usn.parse_max(data)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    if context.output_json:
        print(json.dumps({
            "max_size":         m.max_size,
            "allocation_delta": m.allocation_delta,
            "journal_id":       f"0x{m.journal_id:016X}",
            "lowest_valid_usn": m.lowest_valid_usn,
        }, indent=2))
        return

    t = Table(title=f"$UsnJrnl:$Max — {file.name}", box=box.SIMPLE, header_style="bold")
    t.add_column("Field"); t.add_column("Value")
    t.add_row("Maximum size",     f"0x{m.max_size:016X}  ({m.max_size / 2**20:.2f} MiB)")
    t.add_row("Allocation delta", f"0x{m.allocation_delta:016X}  "
                                   f"({m.allocation_delta / 2**10:.2f} KiB)")
    t.add_row("Journal ID",       f"0x{m.journal_id:016X}")
    t.add_row("Lowest valid USN", f"0x{m.lowest_valid_usn:016X}")
    console.print(t)


@app.command("j")
def j_cmd(
    file: Path = typer.Argument(..., exists=True, help="Raw $UsnJrnl:$J dump"),
    limit: int = typer.Option(0, "--limit", "-n", help="Stop after N records (0 = all)"),
    reason: Optional[str] = typer.Option(None, "--reason",
                                          help="Only show records whose Reason flags contain this "
                                               "substring (e.g. FILE_CREATE, FILE_DELETE, "
                                               "RENAME_NEW_NAME)"),
    filename: Optional[str] = typer.Option(None, "--filename",
                                            help="Only show records whose filename contains this "
                                                 "substring (case-insensitive)"),
    start: int = typer.Option(0, "--start", "-s",
                               help="Byte offset to begin scanning (use lowest_valid_usn from $Max "
                                    "to skip the sparse region)"),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export to a CSV file"),
) -> None:
    """List USN_RECORD_V2 records from $UsnJrnl:$J."""
    console = context.get_console()
    data = file.read_bytes()

    headers = ["Offset", "USN", "Timestamp", "Filename", "Reason",
               "Source", "File ref", "Parent ref", "Attributes"]

    rows: list[list[str]] = []
    json_rows: list[dict] = []
    shown = 0

    for rec in usn.iter_records(data, start=start):
        row_dict = rec.as_row()
        if reason and reason.upper() not in row_dict["Reason"].upper():
            continue
        if filename and filename.lower() not in row_dict["Filename"].lower():
            continue
        rows.append([row_dict[h] for h in headers])
        if context.output_json:
            json_rows.append(rec.as_json())
        shown += 1
        if limit and shown >= limit:
            break

    if context.output_json:
        print(json.dumps(json_rows, indent=2))
        return

    if shown == 0:
        console.print("[yellow]No USN V2 records found.[/yellow]")
        if start == 0:
            console.print(
                "[dim]Hint: if this file is extracted from a 7z archive, the non-sparse "
                "USN records may start at a higher offset. Check lowest_valid_usn in $Max "
                "and rerun with --start <offset>.[/dim]"
            )
        return

    table = Table(title=f"$UsnJrnl:$J — {file.name}", box=box.ROUNDED, header_style="bold")
    for col in headers:
        table.add_column(col, overflow="fold")
    for row in rows:
        table.add_row(*row)
    console.print(table)
    console.print(f"[dim]Displayed {shown} record(s).[/dim]")

    if csv_out is not None:
        with csv_out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(headers)
            w.writerows(rows)
        console.print(f"[green]✓ Wrote {shown} rows → {csv_out}[/green]")
