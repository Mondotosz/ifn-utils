from __future__ import annotations
import csv
import json
import struct
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table
from rich.tree import Tree
from rich import box
from Registry import Registry

from ifn import context

app = typer.Typer(help="NTUSER.DAT analysis")

_RECENT_DOCS_HEADERS = ["MRU #", "Type", "Name"]
_AUTORUN_HEADERS = ["Source", "Name", "Command"]
_TYPED_URLS_HEADERS = ["Key", "URL"]
_ENV_HEADERS = ["Variable", "Value"]


def _open_hive(path: Path) -> Registry.Registry:
    console = context.get_console()
    try:
        return Registry.Registry(str(path))
    except Exception as e:
        console.print(f"[red]Failed to open hive: {e}[/red]")
        raise typer.Exit(1)


def _try_open(reg: Registry.Registry, path: str):
    try:
        return reg.open(path)
    except Registry.RegistryKeyNotFoundException:
        return None


def _mru_order(mru_data: bytes) -> list[int]:
    order = []
    for i in range(0, len(mru_data) - 3, 4):
        idx = struct.unpack_from("<I", mru_data, i)[0]
        if idx == 0xFFFFFFFF:
            break
        order.append(idx)
    return order


def _decode_recent_name(data: bytes) -> str:
    i = 0
    while i < len(data):
        if 0x20 <= data[i] <= 0x7E:
            j = i
            while j < len(data) and 0x20 <= data[j] <= 0x7E:
                j += 1
            if j - i >= 4:
                return data[i:j].decode("ascii", errors="replace")
        i += 1
    return data[:32].hex(" ").upper()


def _decode_shellitem(data: bytes) -> str:
    if len(data) < 3:
        return data.hex(" ").upper()
    item_type = data[2]
    try:
        if item_type == 0x1F:
            return "[Desktop / Special Folder]"
        if item_type == 0x2F:
            return chr(data[3]) + ":\\"
        if item_type in (0x31, 0x32, 0xB1):
            end = data.find(b"\x00", 6)
            if end > 6:
                name = data[6:end].decode("ascii", errors="replace")
                if all(0x20 <= ord(c) < 0x7F for c in name):
                    return name
        if item_type == 0x74:
            end = data.find(b"\x00", 5)
            if end > 5:
                return data[5:end].decode("ascii", errors="replace")
    except Exception:
        pass
    return f"[type=0x{item_type:02X}] " + data[:16].hex(" ").upper()


def _build_shellbag_tree(node: Tree, key, depth: int = 0) -> None:
    if depth > 20:
        return
    try:
        mru_data = key.value("MRUListEx").value()
        order = _mru_order(mru_data)
    except Exception:
        order = []

    items: dict[int, str] = {}
    for val in key.values():
        if val.name() in ("MRUListEx", "NodeSlot"):
            continue
        try:
            idx = int(val.name())
            raw = val.value()
            if isinstance(raw, bytes):
                items[idx] = _decode_shellitem(raw)
        except (ValueError, Exception):
            pass

    shown: set[int] = set()
    for idx in order:
        if idx in items:
            label = f"[cyan]{items[idx]}[/cyan]  [dim](MRU {idx})[/dim]"
            child = node.add(label)
            shown.add(idx)
            sub = next((sk for sk in key.subkeys() if sk.name() == str(idx)), None)
            if sub:
                _build_shellbag_tree(child, sub, depth + 1)

    for idx, name in sorted(items.items()):
        if idx not in shown:
            node.add(f"[dim]{name}[/dim]  (entry {idx})")


def _build_shellbag_dict(key, depth: int = 0) -> list[dict]:
    if depth > 20:
        return []
    try:
        order = _mru_order(key.value("MRUListEx").value())
    except Exception:
        order = []
    items: dict[int, str] = {}
    for val in key.values():
        if val.name() in ("MRUListEx", "NodeSlot"):
            continue
        try:
            idx = int(val.name())
            raw = val.value()
            if isinstance(raw, bytes):
                items[idx] = _decode_shellitem(raw)
        except Exception:
            pass
    result = []
    for idx in order:
        if idx in items:
            sub = next((sk for sk in key.subkeys() if sk.name() == str(idx)), None)
            result.append({
                "mru": idx,
                "name": items[idx],
                "children": _build_shellbag_dict(sub, depth + 1) if sub else [],
            })
    return result


def _csv_path(base: Path, table: str) -> Path:
    return base.with_stem(base.stem + "_" + table)


@app.command()
def activity(
    hive: Path = typer.Argument(..., help="Path to NTUSER.DAT", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export to CSV (produces _recent_docs.csv, _autorun.csv, _typed_urls.csv)"),
) -> None:
    """Recent documents, user Run keys, and Typed URLs."""
    console = context.get_console()
    reg = _open_hive(hive)

    # --- RecentDocs ---
    recent_docs: list[tuple[str, str, str]] = []
    rd_key = _try_open(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
    if rd_key:
        try:
            order = _mru_order(rd_key.value("MRUListEx").value())
        except Exception:
            order = []
        for mru_pos, entry_idx in enumerate(order):
            try:
                name = _decode_recent_name(rd_key.value(str(entry_idx)).value())
            except Exception:
                name = f"entry {entry_idx}"
            recent_docs.append((str(mru_pos), "Any", name))
        for subkey in sorted(rd_key.subkeys(), key=lambda k: k.name()):
            ext = subkey.name()
            try:
                sub_order = _mru_order(subkey.value("MRUListEx").value())
            except Exception:
                continue
            for mru_pos, entry_idx in enumerate(sub_order[:5]):
                try:
                    name = _decode_recent_name(subkey.value(str(entry_idx)).value())
                except Exception:
                    name = f"entry {entry_idx}"
                recent_docs.append((str(mru_pos), ext, name))

    # --- Run / RunOnce ---
    autorun_rows: list[tuple[str, str, str]] = []
    for run_path in (
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ):
        key = _try_open(reg, run_path)
        if not key:
            continue
        short = run_path.rsplit("\\", 1)[-1]
        for val in key.values():
            autorun_rows.append((short, val.name() or "(Default)", str(val.value())))

    # --- TypedURLs ---
    typed_urls: list[tuple[str, str]] = []
    url_key = _try_open(reg, "Software\\Microsoft\\Internet Explorer\\TypedURLs")
    if url_key:
        for val in sorted(url_key.values(), key=lambda v: v.name()):
            typed_urls.append((val.name(), str(val.value())))

    if context.output_json:
        print(json.dumps({
            "recent_docs": [{"mru": m, "type": t, "name": n} for m, t, n in recent_docs],
            "autorun": [{"source": s, "name": n, "command": c} for s, n, c in autorun_rows],
            "typed_urls": [{"key": k, "url": u} for k, u in typed_urls],
        }, indent=2))
        return

    # --- Rich display ---
    console.rule("[bold]Recent Documents[/bold]")
    if recent_docs:
        rd_table = Table(box=box.SIMPLE, header_style="bold")
        rd_table.add_column("MRU #", justify="right")
        rd_table.add_column("Type")
        rd_table.add_column("Name")
        for mru, typ, name in recent_docs:
            rd_table.add_row(mru, typ, name)
        console.print(rd_table)
    else:
        console.print("[dim]RecentDocs key not found.[/dim]")

    console.rule("[bold]User Autorun (Run / RunOnce)[/bold]")
    if autorun_rows:
        run_table = Table(box=box.SIMPLE, header_style="bold")
        run_table.add_column("Source")
        run_table.add_column("Name")
        run_table.add_column("Command")
        for source, name, command in autorun_rows:
            run_table.add_row(source, name, command)
        console.print(run_table)
    else:
        console.print("[dim]No Run entries found.[/dim]")

    console.rule("[bold]Typed URLs (Internet Explorer)[/bold]")
    if typed_urls:
        url_table = Table(box=box.SIMPLE, header_style="bold")
        url_table.add_column("Key")
        url_table.add_column("URL")
        for key_name, url in typed_urls:
            url_table.add_row(key_name, url)
        console.print(url_table)
    else:
        console.print("[dim]TypedURLs key not found.[/dim]")

    if csv_out is not None:
        _write_csv(_csv_path(csv_out, "recent_docs"), _RECENT_DOCS_HEADERS, [list(r) for r in recent_docs], console)
        _write_csv(_csv_path(csv_out, "autorun"), _AUTORUN_HEADERS, [list(r) for r in autorun_rows], console)
        _write_csv(_csv_path(csv_out, "typed_urls"), _TYPED_URLS_HEADERS, [list(r) for r in typed_urls], console)


@app.command()
def env(
    hive: Path = typer.Argument(..., help="Path to NTUSER.DAT", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export environment variables to CSV file"),
) -> None:
    """User environment variables."""
    console = context.get_console()
    reg = _open_hive(hive)
    key = _try_open(reg, "Environment")
    if not key:
        console.print("[dim]Environment key not found.[/dim]")
        return

    rows: list[tuple[str, str]] = [(val.name(), str(val.value())) for val in key.values()]

    if context.output_json:
        print(json.dumps({r[0]: r[1] for r in rows}, indent=2))
        return

    table = Table(title="User Environment Variables", box=box.ROUNDED, header_style="bold")
    table.add_column("Variable")
    table.add_column("Value")
    csv_rows: list[list[str]] = []
    for variable, value in rows:
        table.add_row(variable, value)
        csv_rows.append([variable, value])
    console.print(table)
    _write_csv(csv_out, _ENV_HEADERS, csv_rows, console)


@app.command()
def shellbags(hive: Path = typer.Argument(..., help="Path to NTUSER.DAT or UsrClass.dat", exists=True)) -> None:
    """ShellBags: Explorer folder navigation history from BagMRU."""
    console = context.get_console()
    reg = _open_hive(hive)

    for root_path in (
        "Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    ):
        key = _try_open(reg, root_path)
        if key:
            break
    else:
        console.print("[red]BagMRU key not found.[/red]")
        return

    if context.output_json:
        print(json.dumps({"root": root_path, "entries": _build_shellbag_dict(key)}, indent=2))
        return

    t = Tree(f"[bold]BagMRU[/bold]  [dim]{root_path}[/dim]")
    _build_shellbag_tree(t, key)
    console.print(t)
    console.print("[dim]Note: display names are best-effort; unknown ShellItem types shown as hex.[/dim]")


def _write_csv(path: Optional[Path], headers: list[str], rows: list[list[str]], console) -> None:
    if path is None:
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(rows)
    console.print(f"[green]✓ Exported {len(rows)} row(s) → {path}[/green]")
