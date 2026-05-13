import struct
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich import box
from Registry import Registry

app = typer.Typer(help="NTUSER.DAT analysis")
console = Console()


def _open_hive(path: Path) -> Registry.Registry:
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
    """Decode MRUListEx: sequence of uint32 LE terminated by 0xFFFFFFFF."""
    order = []
    for i in range(0, len(mru_data) - 3, 4):
        idx = struct.unpack_from("<I", mru_data, i)[0]
        if idx == 0xFFFFFFFF:
            break
        order.append(idx)
    return order


def _decode_recent_name(data: bytes) -> str:
    """Best-effort: find the first ASCII run ≥4 chars in a RecentDocs binary blob."""
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
    """Best-effort ShellItem (ItemID) display name extraction."""
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


@app.command()
def activity(hive: Path = typer.Argument(..., help="Path to NTUSER.DAT", exists=True)):
    """Recent documents, user Run keys, and Typed URLs."""
    reg = _open_hive(hive)

    # --- RecentDocs ---
    console.rule("[bold]Recent Documents[/bold]")
    rd_key = _try_open(reg, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
    if rd_key:
        rd_table = Table(box=box.SIMPLE, header_style="bold")
        rd_table.add_column("MRU #", justify="right")
        rd_table.add_column("Type")
        rd_table.add_column("Name")

        try:
            order = _mru_order(rd_key.value("MRUListEx").value())
        except Exception:
            order = []

        for mru_pos, entry_idx in enumerate(order):
            try:
                name = _decode_recent_name(rd_key.value(str(entry_idx)).value())
            except Exception:
                name = f"[dim]entry {entry_idx}[/dim]"
            rd_table.add_row(str(mru_pos), "Any", name)

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
                    name = f"[dim]entry {entry_idx}[/dim]"
                rd_table.add_row(str(mru_pos), ext, name)

        console.print(rd_table)
    else:
        console.print("[dim]RecentDocs key not found.[/dim]")

    # --- Run / RunOnce ---
    console.rule("[bold]User Autorun (Run / RunOnce)[/bold]")
    run_table = Table(box=box.SIMPLE, header_style="bold")
    run_table.add_column("Source")
    run_table.add_column("Name")
    run_table.add_column("Command")
    for run_path in (
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ):
        key = _try_open(reg, run_path)
        if not key:
            continue
        short = run_path.rsplit("\\", 1)[-1]
        for val in key.values():
            run_table.add_row(short, val.name() or "(Default)", str(val.value()))
    if run_table.row_count:
        console.print(run_table)
    else:
        console.print("[dim]No Run entries found.[/dim]")

    # --- TypedURLs ---
    console.rule("[bold]Typed URLs (Internet Explorer)[/bold]")
    url_key = _try_open(reg, "Software\\Microsoft\\Internet Explorer\\TypedURLs")
    if url_key:
        url_table = Table(box=box.SIMPLE, header_style="bold")
        url_table.add_column("Key")
        url_table.add_column("URL")
        for val in sorted(url_key.values(), key=lambda v: v.name()):
            url_table.add_row(val.name(), str(val.value()))
        console.print(url_table)
    else:
        console.print("[dim]TypedURLs key not found.[/dim]")


@app.command()
def env(hive: Path = typer.Argument(..., help="Path to NTUSER.DAT", exists=True)):
    """User environment variables."""
    reg = _open_hive(hive)
    key = _try_open(reg, "Environment")
    if not key:
        console.print("[dim]Environment key not found.[/dim]")
        return

    table = Table(title="User Environment Variables", box=box.ROUNDED, header_style="bold")
    table.add_column("Variable")
    table.add_column("Value")
    for val in key.values():
        table.add_row(val.name(), str(val.value()))
    console.print(table)


@app.command()
def shellbags(hive: Path = typer.Argument(..., help="Path to NTUSER.DAT or UsrClass.dat", exists=True)):
    """ShellBags: Explorer folder navigation history from BagMRU."""
    reg = _open_hive(hive)

    # NTUSER.DAT path; UsrClass.dat uses a different root
    for root_path in (
        "Software\\Microsoft\\Windows\\Shell\\BagMRU",
        "Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
    ):
        key = _try_open(reg, root_path)
        if key:
            break
    else:
        console.print("[red]BagMRU key not found.[/red]")
        console.print("[dim]NTUSER.DAT: Software\\Microsoft\\Windows\\Shell\\BagMRU[/dim]")
        console.print("[dim]UsrClass.dat: Local Settings\\...\\Shell\\BagMRU[/dim]")
        return

    t = Tree(f"[bold]BagMRU[/bold]  [dim]{root_path}[/dim]")
    _build_shellbag_tree(t, key)
    console.print(t)
    console.print("[dim]Note: display names are best-effort; unknown ShellItem types shown as hex.[/dim]")
