from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich import box
from Registry import Registry

from ifn import context
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse Windows Registry hive files")


def _open_hive(path: Path) -> Registry.Registry:
    console = context.get_console()
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


def _fmt_ts_iso(ts) -> str | None:
    if ts is None:
        return None
    try:
        return ts.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    except Exception:
        return str(ts)


def _key_path(reg: Registry.Registry, path: str | None) -> Registry.RegistryKey:
    console = context.get_console()
    try:
        if path:
            return reg.open(path)
        return reg.root()
    except Registry.RegistryKeyNotFoundException:
        console.print(f"[red]Key not found: {path!r}[/red]")
        raise typer.Exit(1)


def _val_to_json(val) -> str | int | list | None:
    try:
        raw = val.value()
        if isinstance(raw, bytes):
            return raw.hex(" ").upper()
        if isinstance(raw, list):
            return [str(x) for x in raw]
        return raw
    except Exception:
        return None


def _compute_hive_visible_paths(key, current_path: tuple, pattern: re.Pattern) -> set[tuple]:
    """Return path tuples for keys that match the pattern or are ancestors of a match."""
    result: set[tuple] = set()
    for subkey in key.subkeys():
        child_path = current_path + (subkey.name(),)
        is_match = bool(pattern.search(subkey.name()))
        desc_paths = _compute_hive_visible_paths(subkey, child_path, pattern)
        if is_match or desc_paths:
            result.add(child_path)
            result.update(desc_paths)
    return result


def _build_tree(
    node: Tree,
    key,
    current_depth: int,
    max_depth: int,
    visible_paths: set[tuple] | None = None,
    current_path: tuple = (),
    pattern: re.Pattern | None = None,
) -> None:
    if visible_paths is None and current_depth >= max_depth:
        remaining = len(list(key.subkeys()))
        if remaining:
            node.add(f"[dim]… {remaining} subkey{'s' if remaining != 1 else ''} (increase --depth to expand)[/dim]")
        return
    for subkey in key.subkeys():
        name = subkey.name()
        child_path = current_path + (name,)
        if visible_paths is not None and child_path not in visible_paths:
            continue
        is_match = pattern is not None and bool(pattern.search(name))
        if is_match:
            label = f"[bold yellow]{name}[/bold yellow]  [dim]{_fmt_ts(subkey.timestamp())}[/dim]"
        else:
            label = f"[cyan]{name}[/cyan]  [dim]{_fmt_ts(subkey.timestamp())}[/dim]"
        child = node.add(label)
        _build_tree(child, subkey, current_depth + 1, max_depth, visible_paths, child_path, pattern)


def _build_tree_dict(
    key,
    current_depth: int,
    max_depth: int,
    visible_paths: set[tuple] | None = None,
    current_path: tuple = (),
    pattern: re.Pattern | None = None,
) -> dict:
    result = {
        "name": key.name(),
        "timestamp": _fmt_ts_iso(key.timestamp()),
        "children": [],
    }
    effective_max = max_depth if visible_paths is None else 10 ** 9
    if current_depth < effective_max:
        for subkey in key.subkeys():
            child_path = current_path + (subkey.name(),)
            if visible_paths is not None and child_path not in visible_paths:
                continue
            child_dict = _build_tree_dict(subkey, current_depth + 1, max_depth, visible_paths, child_path, pattern)
            if pattern is not None:
                child_dict["match"] = bool(pattern.search(subkey.name()))
            result["children"].append(child_dict)
    return result


@app.command()
def tree(
    hive: Path = typer.Argument(..., help="Path to hive file", exists=True),
    path: Optional[str] = typer.Argument(None, help="Registry key path to start from (default: root)"),
    depth: int = typer.Option(2, "--depth", "-d", help="Maximum depth to expand"),
    filter_pattern: Optional[str] = typer.Option(None, "--filter", "-f", help="Regex to filter keys — shows matching keys and their parent path (case-insensitive)"),
) -> None:
    """Show a tree view of registry subkeys up to a given depth."""
    console = context.get_console()
    reg = _open_hive(hive)
    key = _key_path(reg, path)

    pat: re.Pattern | None = None
    if filter_pattern:
        try:
            pat = re.compile(filter_pattern, re.IGNORECASE)
        except re.error as exc:
            console.print(f"[red]Invalid regex: {exc}[/red]")
            raise typer.Exit(1)

    if context.output_json:
        visible: set[tuple] | None = None
        if pat is not None:
            visible = _compute_hive_visible_paths(key, (), pat)
        print(json.dumps(_build_tree_dict(key, 0, depth, visible, (), pat), indent=2))
        return

    display_path = path or key.name()
    root_label = (
        f"[bold cyan]{display_path}[/bold cyan]"
        f"  [dim]{_fmt_ts(key.timestamp())}[/dim]"
    )
    t = Tree(root_label)

    if pat is not None:
        visible = _compute_hive_visible_paths(key, (), pat)
        if not visible:
            console.print(f"[yellow]No keys matching {filter_pattern!r} found.[/yellow]")
            raise typer.Exit(0)
        _build_tree(t, key, 0, depth, visible, (), pat)
    else:
        _build_tree(t, key, 0, depth)

    console.print(t)


@app.command()
def info(hive: Path = typer.Argument(..., help="Path to hive file", exists=True)) -> None:
    """Show hive type, root key name, and last written timestamp."""
    console = context.get_console()
    reg = _open_hive(hive)
    root = reg.root()

    if context.output_json:
        print(json.dumps({
            "file": str(hive),
            "hive_type": reg.hive_type().name,
            "root_key": root.name(),
            "last_written": _fmt_ts_iso(root.timestamp()),
        }, indent=2))
        return

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
) -> None:
    """List subkeys and values under a registry path."""
    console = context.get_console()
    reg = _open_hive(hive)
    key = _key_path(reg, path)
    display_path = path or key.name()

    if context.output_json:
        print(json.dumps({
            "key": display_path,
            "last_written": _fmt_ts_iso(key.timestamp()),
            "subkeys": [
                {"name": sk.name(), "last_written": _fmt_ts_iso(sk.timestamp())}
                for sk in key.subkeys()
            ],
            "values": [
                {"name": v.name() or "(Default)", "type": v.value_type_str(), "data": _val_to_json(v)}
                for v in key.values()
            ],
        }, indent=2))
        return

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
    dump: Optional[Path] = typer.Option(None, "--dump", "-d", help="Dump raw value bytes to this file"),
) -> None:
    """Print a single registry value with its type and data."""
    console = context.get_console()
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
        raw = None

    if context.output_json:
        print(json.dumps({
            "key": path,
            "name": val.name() or "(Default)",
            "type": vtype,
            "data": _val_to_json(val),
        }, indent=2))
        return

    if isinstance(raw, bytes):
        vname = val.name() or "(Default)"
        console.print(
            f"[bold]Key:[/bold] {path}  [dim]│[/dim]  "
            f"[bold]Value:[/bold] {vname}  [dim]│[/dim]  "
            f"[bold]Type:[/bold] {vtype}  [dim]│[/dim]  "
            f"[bold]Length:[/bold] {len(raw)} bytes"
        )
        render_hex_table(
            raw,
            [(0, len(raw), "Data", f"{vtype}  {len(raw)} bytes")],
            title=f"{vname} ({vtype})",
            console=console,
        )
    else:
        console.print(Panel(
            f"[bold]Key:[/bold]   {path}\n"
            f"[bold]Value:[/bold] {val.name() or '(Default)'}\n"
            f"[bold]Type:[/bold]  {vtype}\n"
            f"[bold]Data:[/bold]  {data_str}",
            title="Registry Value",
            border_style="green",
        ))

    if dump is not None:
        if not isinstance(raw, bytes):
            console.print(f"[yellow]Warning: value type is {vtype}, not REG_BINARY — dumping as-is may not be useful[/yellow]")
        dump.write_bytes(raw if isinstance(raw, bytes) else str(raw).encode())
        console.print(f"[green]Dumped {len(raw) if isinstance(raw, bytes) else len(str(raw))} bytes to {dump}[/green]")


# Register per-hive sub-apps at the bottom to avoid circular imports
from ifn.cli.hives import sam, software, system, ntuser, security  # noqa: E402

app.add_typer(sam.app,      name="sam")
app.add_typer(software.app, name="software")
app.add_typer(system.app,   name="system")
app.add_typer(ntuser.app,   name="ntuser")
app.add_typer(security.app, name="security")
