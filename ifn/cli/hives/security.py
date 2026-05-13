from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich import box
from Registry import Registry

app = typer.Typer(help="SECURITY hive analysis")
console = Console()


def _open_hive(path: Path) -> Registry.Registry:
    try:
        return Registry.Registry(str(path))
    except Exception as e:
        console.print(f"[red]Failed to open hive: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def secrets(hive: Path = typer.Argument(..., help="Path to SECURITY hive", exists=True)):
    """List LSA secret names (values are encrypted; SYSKEY required to decode)."""
    reg = _open_hive(hive)

    try:
        secrets_key = reg.open("Policy\\Secrets")
    except Registry.RegistryKeyNotFoundException:
        console.print("[red]Policy\\Secrets not found — is this a SECURITY hive?[/red]")
        raise typer.Exit(1)

    table = Table(title="LSA Secrets", box=box.ROUNDED, header_style="bold")
    table.add_column("Secret name")
    table.add_column("Sub-values present")
    table.add_column("Last written")

    for subkey in secrets_key.subkeys():
        vals = [v.name() for v in subkey.values() if v.name()]
        ts = subkey.timestamp()
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "—"
        table.add_row(subkey.name(), ", ".join(vals) or "—", ts_str)

    console.print(table)
    console.print(
        "\n[dim]Values (CurrVal, OldVal, etc.) are AES/RC4-encrypted with the SYSKEY.\n"
        "SYSKEY is derived from SYSTEM\\ControlSet001\\Control\\Lsa\\{JD, Skew1, GBG, Data}.[/dim]"
    )
