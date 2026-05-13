from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box
from Registry import Registry

app = typer.Typer(help="Parse Windows Registry hive files")
console = Console()


def _open_hive(path: Path) -> Registry.Registry:
    try:
        return Registry.Registry(str(path))
    except Exception as e:
        console.print(f"[red]Failed to open hive: {e}[/red]")
        raise typer.Exit(1)


def _fmt_ts(ts) -> str:
    if ts is None:
        return "—"
    try:
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


def _key_path(reg: Registry.Registry, path: str | None) -> Registry.RegistryKey:
    try:
        if path:
            return reg.open(path)
        return reg.root()
    except Registry.RegistryKeyNotFoundException:
        console.print(f"[red]Key not found: {path!r}[/red]")
        raise typer.Exit(1)


def _build_tree(node: Tree, key: Registry.RegistryKey, current_depth: int, max_depth: int) -> None:
    if current_depth >= max_depth:
        remaining = len(list(key.subkeys()))
        if remaining:
            node.add(f"[dim]… {remaining} subkey{'s' if remaining != 1 else ''} (increase --depth to expand)[/dim]")
        return
    for subkey in key.subkeys():
        label = f"[cyan]{subkey.name()}[/cyan]  [dim]{_fmt_ts(subkey.timestamp())}[/dim]"
        child = node.add(label)
        _build_tree(child, subkey, current_depth + 1, max_depth)


@app.command()
def tree(
    hive: Path = typer.Argument(..., help="Path to hive file", exists=True),
    path: Optional[str] = typer.Argument(None, help="Registry key path to start from (default: root)"),
    depth: int = typer.Option(2, "--depth", "-d", help="Maximum depth to expand"),
):
    """Show a tree view of registry subkeys up to a given depth."""
    reg = _open_hive(hive)
    key = _key_path(reg, path)

    display_path = path or key.name()
    root_label = (
        f"[bold cyan]{display_path}[/bold cyan]"
        f"  [dim]{_fmt_ts(key.timestamp())}[/dim]"
    )
    t = Tree(root_label)
    _build_tree(t, key, 0, depth)
    console.print(t)


@app.command()
def info(hive: Path = typer.Argument(..., help="Path to hive file", exists=True)):
    """Show hive type, root key name, and last written timestamp."""
    reg = _open_hive(hive)
    root = reg.root()
    console.print(Panel(
        f"[bold]File:[/bold]         {hive}\n"
        f"[bold]Hive type:[/bold]    {reg.hive_type().name}\n"
        f"[bold]Root key:[/bold]     {root.name()}\n"
        f"[bold]Last written:[/bold] {_fmt_ts(root.timestamp())}",
        title="Registry Hive Info",
        border_style="green",
    ))


@app.command()
def ls(
    hive: Path = typer.Argument(..., help="Path to hive file", exists=True),
    path: Optional[str] = typer.Argument(None, help="Registry key path (default: root)"),
):
    """List subkeys and values under a registry path."""
    reg = _open_hive(hive)
    key = _key_path(reg, path)

    display_path = path or key.name()
    console.rule(f"[bold]{display_path}[/bold]")
    console.print(f"[dim]Last written: {_fmt_ts(key.timestamp())}[/dim]")

    subkeys = list(key.subkeys())
    if subkeys:
        sk_table = Table(title="Subkeys", box=box.SIMPLE, header_style="bold")
        sk_table.add_column("Name")
        sk_table.add_column("Last written")
        for sk in subkeys:
            sk_table.add_row(sk.name(), _fmt_ts(sk.timestamp()))
        console.print(sk_table)

    values = list(key.values())
    if values:
        v_table = Table(title="Values", box=box.SIMPLE, header_style="bold")
        v_table.add_column("Name")
        v_table.add_column("Type")
        v_table.add_column("Data")
        for val in values:
            name = val.name() or "(Default)"
            vtype = val.value_type_str()
            try:
                raw = val.value()
                if isinstance(raw, bytes):
                    data_str = raw.hex(" ").upper()[:80] + ("…" if len(raw) > 40 else "")
                elif isinstance(raw, list):
                    data_str = "; ".join(str(x) for x in raw)
                else:
                    data_str = str(raw)
            except Exception as e:
                data_str = f"[red]Error: {e}[/red]"
            v_table.add_row(name, vtype, data_str)
        console.print(v_table)

    if not subkeys and not values:
        console.print("[dim](empty key)[/dim]")


@app.command()
def get(
    hive: Path = typer.Argument(..., help="Path to hive file", exists=True),
    path: str = typer.Argument(..., help="Registry key path"),
    value: str = typer.Argument(..., help="Value name"),
):
    """Print a single registry value with its type and data."""
    reg = _open_hive(hive)
    key = _key_path(reg, path)

    try:
        val = key.value(value)
    except Registry.RegistryValueNotFoundException:
        console.print(f"[red]Value not found: {value!r} in {path!r}[/red]")
        raise typer.Exit(1)

    vtype = val.value_type_str()
    try:
        raw = val.value()
        if isinstance(raw, bytes):
            data_str = raw.hex(" ").upper()
        elif isinstance(raw, list):
            data_str = "\n".join(str(x) for x in raw)
        else:
            data_str = str(raw)
    except Exception as e:
        data_str = f"Error: {e}"

    console.print(Panel(
        f"[bold]Key:[/bold]   {path}\n"
        f"[bold]Value:[/bold] {val.name() or '(Default)'}\n"
        f"[bold]Type:[/bold]  {vtype}\n"
        f"[bold]Data:[/bold]  {data_str}",
        title="Registry Value",
        border_style="green",
    ))


# Register per-hive sub-apps at the bottom to avoid circular imports
from ifn.cli.hives import sam, software, system, ntuser, security  # noqa: E402

app.add_typer(sam.app,      name="sam")
app.add_typer(software.app, name="software")
app.add_typer(system.app,   name="system")
app.add_typer(ntuser.app,   name="ntuser")
app.add_typer(security.app, name="security")
