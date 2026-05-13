import shutil
import sys
import typer
from rich.console import Console
from rich.table import Table
from rich import box

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


@app.command()
def check():
    """Verify all required system tools are installed and on PATH."""
    console = Console()
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Tool", style="cyan")
    table.add_column("Package")
    table.add_column("Required")
    table.add_column("Status")

    all_ok = True

    for tool, pkg in _REQUIRED:
        path = shutil.which(tool)
        if path:
            status = f"[green]FOUND[/green]  {path}"
        else:
            status = "[red]MISSING[/red]"
            all_ok = False
        table.add_row(tool, pkg, "[bold]yes[/bold]", status)

    for tool, pkg in _OPTIONAL:
        path = shutil.which(tool)
        status = f"[green]FOUND[/green]  {path}" if path else "[yellow]MISSING[/yellow]"
        table.add_row(tool, pkg, "optional", status)

    console.print(table)

    if not all_ok:
        console.print("[red]One or more required tools are missing.[/red]")
        raise typer.Exit(1)
