from __future__ import annotations
import csv
import json
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table
from rich import box
from Registry import Registry

from ifn import context

app = typer.Typer(help="SECURITY hive analysis")

_HEADERS = ["Secret name", "Sub-values present", "Last written"]


def _open_hive(path: Path) -> Registry.Registry:
    console = context.get_console()
    try:
        return Registry.Registry(str(path))
    except Exception as e:
        console.print(f"[red]Failed to open hive: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def secrets(
    hive: Path = typer.Argument(..., help="Path to SECURITY hive", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export secret names to CSV file"),
) -> None:
    """List LSA secret names (values are encrypted; SYSKEY required to decode)."""
    console = context.get_console()
    reg = _open_hive(hive)

    try:
        secrets_key = reg.open("Policy\\Secrets")
    except Registry.RegistryKeyNotFoundException:
        console.print("[red]Policy\\Secrets not found — is this a SECURITY hive?[/red]")
        raise typer.Exit(1)

    rows: list[tuple[str, str, str]] = []
    for subkey in secrets_key.subkeys():
        vals = [v.name() for v in subkey.values() if v.name()]
        ts = subkey.timestamp()
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "—"
        rows.append((subkey.name(), ", ".join(vals) or "—", ts_str))

    if context.output_json:
        print(json.dumps([
            {"name": name, "sub_values": sub.split(", ") if sub != "—" else [], "last_written": ts}
            for name, sub, ts in rows
        ], indent=2))
        return

    table = Table(title="LSA Secrets", box=box.ROUNDED, header_style="bold")
    table.add_column("Secret name")
    table.add_column("Sub-values present")
    table.add_column("Last written")
    csv_rows: list[list[str]] = []
    for name, sub, ts in rows:
        table.add_row(name, sub, ts)
        csv_rows.append([name, sub, ts])
    console.print(table)
    console.print(
        "\n[dim]Values (CurrVal, OldVal, etc.) are AES/RC4-encrypted with the SYSKEY.\n"
        "SYSKEY is derived from SYSTEM\\ControlSet001\\Control\\Lsa\\{JD, Skew1, GBG, Data}.[/dim]"
    )
    _write_csv(csv_out, _HEADERS, csv_rows, console)


def _write_csv(path: Optional[Path], headers: list[str], rows: list[list[str]], console) -> None:
    if path is None:
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(rows)
    console.print(f"[green]✓ Exported {len(rows)} row(s) → {path}[/green]")
