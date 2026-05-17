"""`tool.py index` — decode NTFS directory indexes ($INDEX_ROOT bodies and INDX buffers).

When you have a raw dump of an $INDEX_ROOT attribute body, use `index root`.
When you have a raw $INDEX_ALLOCATION dump (one or several INDX buffers),
use `index indx`. The course exhibits in `cours-ntfs/NTFS/05 - Repertoires/`
fit both cases.
"""
from __future__ import annotations
import json
from pathlib import Path

import typer
from rich import box
from rich.table import Table

from ifn import context
from ifn.parsers import ntfs_index as nindex
from ifn.parsers.ntfs_attributes import ATTR_NAMES, fmt_mft_reference


app = typer.Typer(help="Parse NTFS directory indexes ($I30, INDX buffers)")


def _render_entries(title: str, entries: list[nindex.IndexEntry], console) -> None:
    t = Table(title=title, box=box.ROUNDED, header_style="bold")
    for col in ("MFT#", "Flags", "Filename", "Namespace", "Real size", "Modified"):
        t.add_column(col)
    for e in entries:
        if e.is_last:
            t.add_row("—", "LAST", "—", "—", "—", "—")
            continue
        d = e.decoded_filename()
        flags = []
        if e.has_subnode:
            flags.append(f"→VCN {e.child_vcn}")
        t.add_row(
            str(e.mft_ref & 0xFFFFFFFFFFFF),
            ", ".join(flags) or "leaf",
            d.get("Filename", "?"),
            d.get("Namespace", "?"),
            d.get("Real size", "?"),
            d.get("Modified", "?"),
        )
    console.print(t)


def _entry_to_json(e: nindex.IndexEntry) -> dict:
    d = e.decoded_filename() if not e.is_last else {}
    return {
        "mft_ref":        e.mft_ref & 0xFFFFFFFFFFFF,
        "mft_sequence":   (e.mft_ref >> 48) & 0xFFFF,
        "entry_length":   e.entry_length,
        "content_length": e.content_length,
        "flags":          f"0x{e.flags:02X}",
        "is_last":        e.is_last,
        "has_subnode":    e.has_subnode,
        "child_vcn":      e.child_vcn,
        "filename":       d.get("Filename"),
        "namespace":      d.get("Namespace"),
        "real_size":      d.get("Real size"),
        "modified":       d.get("Modified"),
    }


@app.command()
def root(file: Path = typer.Argument(..., exists=True,
                                       help="Raw $INDEX_ROOT attribute body")) -> None:
    """Decode a raw $INDEX_ROOT body dump (the body after the attribute header)."""
    console = context.get_console()
    data = file.read_bytes()
    try:
        root_obj = nindex.parse_index_root(data)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1)

    if context.output_json:
        print(json.dumps({
            "attribute_type":     f"0x{root_obj.attribute_type:02X}",
            "attribute_name":     ATTR_NAMES.get(root_obj.attribute_type, "?"),
            "collation_rule":     root_obj.collation_rule,
            "index_buffer_size":  root_obj.index_buffer_size,
            "clusters_per_buffer":root_obj.clusters_per_buffer,
            "has_subnodes":       root_obj.header.has_subnodes,
            "entries_size":       root_obj.header.entries_size,
            "allocated_size":     root_obj.header.allocated_size,
            "entries":            [_entry_to_json(e) for e in root_obj.entries],
        }, indent=2))
        return

    meta = Table(title=f"$INDEX_ROOT — {file.name}", box=box.SIMPLE, header_style="bold")
    meta.add_column("Field"); meta.add_column("Value")
    meta.add_row("Indexed attribute",   f"0x{root_obj.attribute_type:02X}  "
                                         f"{ATTR_NAMES.get(root_obj.attribute_type, '?')}")
    meta.add_row("Collation rule",      str(root_obj.collation_rule))
    meta.add_row("Index buffer size",   f"{root_obj.index_buffer_size} B")
    meta.add_row("Clusters per buffer", str(root_obj.clusters_per_buffer))
    meta.add_row("Has sub-nodes",       "Yes" if root_obj.header.has_subnodes else "No")
    meta.add_row("Entries area size",   f"{root_obj.header.entries_size} B")
    meta.add_row("Allocated size",      f"{root_obj.header.allocated_size} B")
    console.print(meta)

    _render_entries("Entries", root_obj.entries, console)


@app.command()
def indx(
    file: Path = typer.Argument(..., exists=True,
                                 help="Raw $INDEX_ALLOCATION dump (one or more INDX buffers)"),
    buffer_size: int = typer.Option(4096, "--size", "-s",
                                     help="INDX buffer size in bytes (from the VBR, default 4096)"),
) -> None:
    """Decode every INDX buffer in a raw $INDEX_ALLOCATION dump."""
    console = context.get_console()
    data = file.read_bytes()
    buffers = nindex.iter_indx_buffers(data, buffer_size)
    if not buffers:
        console.print(f"[red]No INDX buffer found in {file} (size={buffer_size}).[/red]")
        raise typer.Exit(1)

    if context.output_json:
        print(json.dumps([{
            "vcn":             b.vcn,
            "usa_offset":      f"0x{b.usa_offset:04X}",
            "usa_count":       b.usa_count,
            "log_seq":         b.log_seq,
            "entries_size":    b.header.entries_size,
            "allocated_size":  b.header.allocated_size,
            "has_subnodes":    b.header.has_subnodes,
            "entries":         [_entry_to_json(e) for e in b.entries],
        } for b in buffers], indent=2))
        return

    for n, buf in enumerate(buffers):
        meta = Table(title=f"INDX buffer #{n}  (VCN={buf.vcn})",
                     box=box.SIMPLE, header_style="bold")
        meta.add_column("Field"); meta.add_column("Value")
        meta.add_row("USA offset",        f"0x{buf.usa_offset:04X}")
        meta.add_row("USA count",         str(buf.usa_count))
        meta.add_row("LogFile seq",       str(buf.log_seq))
        meta.add_row("Entries area size", f"{buf.header.entries_size} B")
        meta.add_row("Allocated size",    f"{buf.header.allocated_size} B")
        meta.add_row("Has sub-nodes",     "Yes" if buf.header.has_subnodes else "No")
        console.print(meta)

        _render_entries(f"Entries (buffer #{n})", buf.entries, console)
