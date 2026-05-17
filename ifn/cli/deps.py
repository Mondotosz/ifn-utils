from __future__ import annotations
import csv
import json
import shutil
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table
from rich import box

from ifn import context

app = typer.Typer(help="Check system tool dependencies")

_REQUIRED = [
    ("ewfinfo",    "libewf-tools"),
    ("ewfmount",   "libewf-tools"),
    ("ewfacquire", "libewf-tools"),
    ("mmls",       "sleuthkit"),
    ("fls",        "sleuthkit"),
    ("icat",       "sleuthkit"),
    ("fsstat",     "sleuthkit"),
    ("cryptsetup", "cryptsetup"),
    ("losetup",    "util-linux"),
]

_OPTIONAL = [
    ("mount",      "util-linux"),
    ("dd",         "coreutils"),
]

_HEADERS = ["Tool", "Package", "Required", "Status", "Path"]


@app.command()
def check(
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export tool status to CSV"),
) -> None:
    """Verify all required system tools are installed and on PATH."""
    console = context.get_console()

    rows: list[tuple[str, str, str, str, str]] = []
    all_ok = True

    for tool, pkg in _REQUIRED:
        path = shutil.which(tool)
        found = path is not None
        if not found:
            all_ok = False
        rows.append((tool, pkg, "yes", "FOUND" if found else "MISSING", path or ""))

    for tool, pkg in _OPTIONAL:
        path = shutil.which(tool)
        found = path is not None
        rows.append((tool, pkg, "optional", "FOUND" if found else "MISSING", path or ""))

    if context.output_json:
        print(json.dumps([
            {"name": t, "package": p, "required": r == "yes", "found": s == "FOUND", "path": path or None}
            for t, p, r, s, path in rows
        ], indent=2))
        if not all_ok:
            raise typer.Exit(1)
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Tool", style="cyan")
    table.add_column("Package")
    table.add_column("Required")
    table.add_column("Status")

    plain = context.output_simple
    for tool, pkg, required, status, path in rows:
        if status == "FOUND":
            status_cell = f"FOUND  {path}" if plain else f"[green]FOUND[/green]  {path}"
        elif required == "yes":
            status_cell = "MISSING" if plain else "[red]MISSING[/red]"
        else:
            status_cell = "MISSING" if plain else "[yellow]MISSING[/yellow]"
        req_cell = required if plain else (f"[bold]{required}[/bold]" if required == "yes" else required)
        table.add_row(tool, pkg, req_cell, status_cell)

    console.print(table)

    if csv_out is not None:
        with csv_out.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(_HEADERS)
            writer.writerows(rows)
        console.print(f"[green]✓ Exported {len(rows)} row(s) → {csv_out}[/green]")

    if not all_ok:
        console.print("[red]One or more required tools are missing.[/red]")
        raise typer.Exit(1)
