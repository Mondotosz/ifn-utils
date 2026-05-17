from __future__ import annotations
import json
from pathlib import Path

import typer
from rich.table import Table
from rich import box
import LnkParse3

from ifn import context

app = typer.Typer(help="Parse Windows LNK shortcut files")

_SHOW_WINDOW = {
    1: "Normal", 2: "Minimized", 3: "Maximized", 4: "Normal (no activate)",
    5: "Show", 6: "Minimize", 7: "Minimize (no activate)", 8: "Hidden",
    9: "Restore", 10: "Default", 11: "Force minimize",
}


def _flat_table(title: str, data: dict) -> Table:
    t = Table(title=title, box=box.ROUNDED, header_style="bold", show_header=True)
    t.add_column("Field")
    t.add_column("Value")
    for k, v in data.items():
        if isinstance(v, dict):
            for sk, sv in v.items():
                t.add_row(f"{k} / {sk}", str(sv))
        elif isinstance(v, list):
            t.add_row(k, ", ".join(str(i) for i in v))
        else:
            t.add_row(k, str(v) if v is not None else "—")
    return t


@app.command()
def parse(file: Path = typer.Argument(..., help="Path to .lnk file", exists=True)) -> None:
    """Extract all fields from a Windows Shell Link file."""
    console = context.get_console()
    with file.open("rb") as f:
        lnk = LnkParse3.lnk_file(f)

    data = lnk.get_json(get_all=True)

    if context.output_json:
        # LnkParse3 already produces a JSON-serialisable dict
        print(json.dumps(data, indent=2, default=str))
        return

    hdr = data.get("header", {})
    hdr_table = Table(title=f"LNK Header — {file.name}", box=box.ROUNDED, header_style="bold")
    hdr_table.add_column("Field")
    hdr_table.add_column("Value")
    hdr_table.add_row("GUID",          str(hdr.get("guid", "—")))
    hdr_table.add_row("Header size",   str(hdr.get("header_size", "—")))
    hdr_table.add_row("File size",     f"{hdr.get('file_size', 0):,} bytes")
    hdr_table.add_row("Created",       str(hdr.get("creation_time", "—")))
    hdr_table.add_row("Accessed",      str(hdr.get("accessed_time", "—")))
    hdr_table.add_row("Modified",      str(hdr.get("modified_time", "—")))
    hdr_table.add_row("Icon index",    str(hdr.get("icon_index", "—")))
    hdr_table.add_row("Window style",  _SHOW_WINDOW.get(hdr.get("windowstyle", 0), str(hdr.get("windowstyle"))))
    hdr_table.add_row("Hot key",       str(hdr.get("hotkey", "—")))
    flags = hdr.get("link_flags") or hdr.get("r_link_flags")
    hdr_table.add_row("Link flags",    str(flags))
    file_flags = hdr.get("file_flags") or hdr.get("r_file_flags")
    hdr_table.add_row("File flags",    str(file_flags))
    console.print(hdr_table)

    target = data.get("target")
    if target:
        t = Table(title="Link Target ID List", box=box.ROUNDED, header_style="bold")
        t.add_column("Field")
        t.add_column("Value")
        t.add_row("Size", str(target.get("size", "—")))
        items = target.get("items", [])
        for i, item in enumerate(items):
            if isinstance(item, dict):
                for k, v in item.items():
                    t.add_row(f"Item {i} / {k}", str(v))
            else:
                t.add_row(f"Item {i}", str(item))
        console.print(t)

    link_info = data.get("link_info", {})
    if link_info:
        console.print(_flat_table("Link Info", link_info))

    strings = data.get("data", {})
    if strings:
        st = Table(title="String Data", box=box.ROUNDED, header_style="bold")
        st.add_column("Field")
        st.add_column("Value")
        for k, v in strings.items():
            st.add_row(str(k), str(v))
        console.print(st)

    extras = data.get("extra", {})
    if extras:
        et = Table(title="Extra Data", box=box.ROUNDED, header_style="bold")
        et.add_column("Block")
        et.add_column("Field")
        et.add_column("Value")
        for block_name, block_data in extras.items():
            if isinstance(block_data, dict):
                for k, v in block_data.items():
                    et.add_row(str(block_name), str(k), str(v))
            else:
                et.add_row(str(block_name), "", str(block_data))
        console.print(et)
