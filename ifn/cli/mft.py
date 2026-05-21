from __future__ import annotations
from pathlib import Path
from typing import Optional, Iterator
from dataclasses import dataclass
import csv
import gzip
import hashlib
import io
import json
import subprocess
import struct

import typer
from rich.table import Table
from rich.tree import Tree as RichTree
from rich import box

from ifn import context
from ifn.parsers import mft_record as mft_parser
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse NTFS Master File Table records")

_RECORD_SIZE = 1024
_SECTOR = 512


# ---------------------------------------------------------------------------
# Update Sequence Array fixup
# ---------------------------------------------------------------------------

def _apply_usa_fixup(data: bytes) -> bytes:
    """Restore the original last-two-bytes of each sector from the USA table."""
    if len(data) < 48:
        return data
    usa_off = struct.unpack_from("<H", data, 4)[0]
    usa_cnt = struct.unpack_from("<H", data, 6)[0]
    if usa_off == 0 or usa_cnt < 2 or usa_off + usa_cnt * 2 > len(data):
        return data
    out = bytearray(data)
    check = struct.unpack_from("<H", out, usa_off)[0]
    for i in range(1, usa_cnt):
        end = i * _SECTOR - 2
        if end + 2 > len(out):
            break
        if struct.unpack_from("<H", out, end)[0] != check:
            return data  # USA check mismatch — return original
        original = struct.unpack_from("<H", out, usa_off + i * 2)[0]
        struct.pack_into("<H", out, end, original)
    return bytes(out)


# ---------------------------------------------------------------------------
# Data run parsing
# ---------------------------------------------------------------------------

def _parse_data_runs(run_bytes: bytes) -> list[tuple[int, int]]:
    """Parse an NTFS data run list.

    Returns [(lcn, cluster_count)] pairs.  A sparse run has lcn = -1.
    """
    runs: list[tuple[int, int]] = []
    pos = 0
    cur_lcn = 0
    while pos < len(run_bytes):
        header = run_bytes[pos]
        if header == 0:
            break
        len_sz = header & 0x0F
        off_sz = (header >> 4) & 0x0F
        pos += 1
        if len_sz == 0 or pos + len_sz > len(run_bytes):
            break
        length = int.from_bytes(run_bytes[pos: pos + len_sz], "little")
        pos += len_sz
        if off_sz == 0:
            runs.append((-1, length))  # sparse run
        else:
            if pos + off_sz > len(run_bytes):
                break
            ob = run_bytes[pos: pos + off_sz]
            delta = int.from_bytes(ob, "little", signed=False)
            if ob[-1] & 0x80:
                delta -= 1 << (off_sz * 8)
            cur_lcn += delta
            runs.append((cur_lcn, length))
        pos += off_sz
    return runs


# ---------------------------------------------------------------------------
# Volume geometry
# ---------------------------------------------------------------------------

def _vol_geometry(vol: Path) -> tuple[int, int]:
    """Read (sectors_per_cluster, bytes_per_sector) from the volume's VBR (sector 0)."""
    with open(vol, "rb") as f:
        vbr = f.read(512)
    bps = struct.unpack_from("<H", vbr, 0x0B)[0]
    spc = vbr[0x0D]
    if bps not in (512, 1024, 2048, 4096) or spc not in (1, 2, 4, 8, 16, 32, 64):
        raise ValueError(f"Suspicious VBR geometry: bps={bps}, spc={spc}")
    return spc, bps


# ---------------------------------------------------------------------------
# File data extraction (resident + non-resident)
# ---------------------------------------------------------------------------

def _extract_file_data(
    vol: Path,
    record_bytes: bytes,
    attr: "mft_parser.MFTAttribute",
) -> bytes:
    """Return the full file content for a $DATA attribute.

    For resident attributes the content is already in `attr.data`.
    For non-resident attributes the data run list is followed and clusters
    are read directly from the raw volume file.
    """
    if not attr.non_resident:
        return attr.data

    # Non-resident: parse header fields from the raw record bytes
    a = attr.offset  # start of this attribute within the record
    run_off_rel = struct.unpack_from("<H", record_bytes, a + 0x20)[0]
    data_length  = struct.unpack_from("<Q", record_bytes, a + 0x30)[0]
    run_data = record_bytes[a + run_off_rel: a + attr.length]

    try:
        spc, bps = _vol_geometry(vol)
    except (ValueError, OSError) as e:
        raise RuntimeError(f"Cannot read volume geometry: {e}") from e

    cluster_size = spc * bps
    runs = _parse_data_runs(run_data)

    buf = bytearray()
    with open(vol, "rb") as f:
        for lcn, count in runs:
            if lcn == -1:
                buf.extend(b"\x00" * count * cluster_size)
            else:
                f.seek(lcn * cluster_size)
                buf.extend(f.read(count * cluster_size))

    return bytes(buf[:data_length])


# ---------------------------------------------------------------------------
# Raw volume helpers
# ---------------------------------------------------------------------------

def _find_entry_raw(vol: Path, entry_num: int, offset_sectors: int = 0) -> bytes | None:
    """Scan a raw NTFS volume at 512-byte boundaries for a FILE record with the given entry number."""
    CHUNK = 1024 * 1024
    buf = bytearray()
    with open(vol, "rb") as f:
        if offset_sectors:
            f.seek(offset_sectors * 512)
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            buf.extend(chunk)
            i = 0
            while i + _RECORD_SIZE <= len(buf):
                if buf[i: i + 4] == b"FILE":
                    if len(buf) >= i + 48 and struct.unpack_from("<I", buf, i + 44)[0] == entry_num:
                        return bytes(buf[i: i + _RECORD_SIZE])
                i += _SECTOR
            overlap = _RECORD_SIZE - _SECTOR  # 512 bytes
            if len(buf) > overlap:
                del buf[: len(buf) - overlap]
    return None


# ---------------------------------------------------------------------------
# Shared display helper
# ---------------------------------------------------------------------------

def _display_record(data: bytes, title: str, full_dump: bool = False, console=None):
    """Pretty-print one MFT record: hex table, attribute list, decoded fields."""
    if console is None:
        console = context.get_console()
    fixed = _apply_usa_fixup(data)
    rec = mft_parser.parse(fixed)

    if not rec.is_valid:
        console.print(f"[red]Invalid MFT record magic: {rec.magic!r} (expected b'FILE')[/red]")
        raise typer.Exit(1)

    if not context.output_json:
        hex_len = len(fixed) if full_dump else min(512, len(fixed))
        header_fields: list[tuple[int, int, str, str]] = [
            (0,  4, "Magic",             rec.magic.decode()),
            (4,  2, "Update seq offset", str(rec.update_seq_offset)),
            (6,  2, "Update seq size",   str(rec.update_seq_size)),
            (8,  8, "Log file seq#",     str(rec.log_file_seq)),
            (16, 2, "Sequence number",   str(rec.seq_number)),
            (18, 2, "Hard link count",   str(rec.hard_link_count)),
            (20, 2, "First attr offset", f"0x{rec.first_attr_offset:04X}"),
            (22, 2, "Flags",             f"0x{rec.flags:04X}  ({rec.flag_names})"),
            (24, 4, "Used size",         f"{rec.used_size} bytes"),
            (28, 4, "Allocated size",    f"{rec.alloc_size} bytes"),
            (32, 8, "Base record ref",   (f"record={rec.base_record_ref & 0xFFFFFFFFFFFF}"
                                              f"  seq={(rec.base_record_ref >> 48) & 0xFFFF}"
                                              if rec.base_record_ref else "0  (this is a base record)")),
            (40, 2, "Next attr ID",      str(rec.next_attr_id)),
            (44, 4, "Record number",     str(rec.record_number)),
        ]
        # Annotate the actual USA data (check word + per-sector replacements)
        usa_off = rec.update_seq_offset
        if usa_off > 0 and usa_off + rec.update_seq_size * 2 <= len(fixed):
            check = struct.unpack_from("<H", fixed, usa_off)[0]
            header_fields.append((usa_off, 2, "USA check word", f"0x{check:04X}"))
            for _i in range(1, rec.update_seq_size):
                _rep_off = usa_off + _i * 2
                if _rep_off + 2 <= len(fixed):
                    _rep = struct.unpack_from("<H", fixed, _rep_off)[0]
                    header_fields.append((_rep_off, 2, f"USA replacement[{_i}]", f"0x{_rep:04X}"))

        # Annotate attribute headers that fall within the displayed hex range
        for _attr in rec.attributes:
            if _attr.attr_type == 0xFFFFFFFF:
                break
            _off = _attr.offset
            if _off >= hex_len:
                break
            _lbl = _attr.attr_name
            if _off + 4  <= hex_len: header_fields.append((_off,    4, f"{_lbl} type",        f"0x{_attr.attr_type:08X}"))
            if _off + 8  <= hex_len: header_fields.append((_off+4,  4, f"{_lbl} length",      str(_attr.length)))
            if _off + 9  <= hex_len: header_fields.append((_off+8,  1, f"{_lbl} resident",    "No" if _attr.non_resident else "Yes"))
            if _off + 16 <= hex_len: header_fields.append((_off+14, 2, f"{_lbl} attr_id",     str(_attr.attr_id)))
            if not _attr.non_resident:
                if _off + 22 <= hex_len:
                    _c_len = struct.unpack_from("<I", fixed, _off + 16)[0]
                    _c_off = struct.unpack_from("<H", fixed, _off + 20)[0]
                    header_fields.append((_off+16, 4, f"{_lbl} content_len", str(_c_len)))
                    header_fields.append((_off+20, 2, f"{_lbl} content_off", f"0x{_c_off:04X}"))
            else:
                if _off + 34 <= hex_len:
                    header_fields.append((_off+16, 8, f"{_lbl} start_vcn",  str(_attr.start_vcn)))
                    header_fields.append((_off+24, 8, f"{_lbl} last_vcn",   str(_attr.last_vcn)))
                    header_fields.append((_off+32, 2, f"{_lbl} run_offset", str(_attr.run_offset)))

        render_hex_table(fixed[:hex_len], header_fields, title=title, console=console)

        attr_table = Table(title="Attributes", box=box.ROUNDED, header_style="bold")
        attr_table.add_column("ID", justify="right")
        attr_table.add_column("Type")
        attr_table.add_column("Offset", justify="right")
        attr_table.add_column("Hdr (B)", justify="right")
        attr_table.add_column("Data (B)", justify="right")
        attr_table.add_column("Resident")
        attr_table.add_column("Name")

        for attr in rec.attributes:
            if attr.attr_type == 0xFFFFFFFF:
                break
            hdr_size = "24" if not attr.non_resident else "64"
            data_size = str(len(attr.data)) if not attr.non_resident else "—"
            attr_table.add_row(
                str(attr.attr_id),
                f"0x{attr.attr_type:02X}  {attr.attr_name}",
                f"0x{attr.offset:04X}",
                hdr_size,
                data_size,
                "No" if attr.non_resident else "Yes",
                attr.name or "—",
            )
        console.print(attr_table)

        for attr in rec.attributes:
            if attr.attr_type == 0xFFFFFFFF:
                continue
            label = f"{attr.attr_name} details" + (f" ({attr.name})" if attr.name else "")

            # $ATTRIBUTE_LIST → list of entries
            if attr.attribute_list:
                t = Table(title=label, box=box.SIMPLE, header_style="bold")
                for col in ("Type", "Length", "Start VCN", "MFT ref", "Attr ID", "Name"):
                    t.add_column(col)
                for e in attr.attribute_list:
                    t.add_row(e["Type"], e["Length"], e["Start VCN"],
                              e["MFT ref"], e["Attr ID"], e["Name"])
                console.print(t)
                continue

            # $INDEX_ROOT → header + entries
            if attr.index_root is not None:
                _print_index_root(label, attr.index_root, console)
                continue

            # Non-resident attribute → data runs summary
            if attr.non_resident and attr.runs:
                rt = Table(title=label + " (non-resident)", box=box.SIMPLE, header_style="bold")
                rt.add_column("Field"); rt.add_column("Value")
                rt.add_row("Start VCN",      str(attr.start_vcn))
                rt.add_row("Last VCN",       str(attr.last_vcn))
                rt.add_row("Allocated size", f"{attr.allocated_size:,} bytes")
                rt.add_row("Real size",      f"{attr.real_size:,} bytes")
                rt.add_row("Initialised",    f"{attr.initialised_size:,} bytes")
                if attr.flags & 0x0001:
                    rt.add_row("Compressed size", f"{attr.compressed_size:,} bytes")
                console.print(rt)

                rrt = Table(title=label + " — Data Runs", box=box.SIMPLE, header_style="bold")
                for col in ("#", "Header", "LCN", "Clusters"):
                    rrt.add_column(col, justify="right" if col != "Header" else "left")
                for i, run in enumerate(attr.runs):
                    rrt.add_row(str(i), f"0x{run.header:02X}",
                                "sparse" if run.is_sparse else str(run.lcn),
                                str(run.length))
                console.print(rrt)
                continue

            # Resident $DATA: hex + ASCII preview of file content
            if attr.attr_type == 0x80 and not attr.non_resident and attr.data:
                _MAX = 256
                _preview = attr.data[:_MAX]
                _extra = f", first {_MAX} B shown" if len(attr.data) > _MAX else ""
                _size_lbl = f" ({len(attr.data)} B{_extra})"
                _dt = Table(title=label + _size_lbl, box=box.SIMPLE, header_style="bold")
                _dt.add_column("Hex"); _dt.add_column("ASCII")
                for _rs in range(0, len(_preview), 16):
                    _chunk = _preview[_rs: _rs + 16]
                    _dt.add_row(_chunk.hex(" ").upper(),
                                "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in _chunk))
                console.print(_dt)
                continue

            # Generic dict decoders
            if attr.decoded:
                detail = Table(title=label, box=box.SIMPLE, header_style="bold")
                detail.add_column("Field")
                detail.add_column("Value")
                for k, v in attr.decoded.items():
                    detail.add_row(k, v)
                console.print(detail)

    return fixed, rec  # return for callers that need to do further work


def _print_index_root(label: str, root, console) -> None:
    """Render an $INDEX_ROOT body (header + B+Tree entries)."""
    from ifn.parsers import ntfs_attributes as _na
    meta = Table(title=label, box=box.SIMPLE, header_style="bold")
    meta.add_column("Field"); meta.add_column("Value")
    meta.add_row("Indexed attribute",   f"0x{root.attribute_type:02X}  "
                                         f"{_na.ATTR_NAMES.get(root.attribute_type, '?')}")
    meta.add_row("Collation rule",      str(root.collation_rule))
    meta.add_row("Index buffer size",   f"{root.index_buffer_size} B")
    meta.add_row("Clusters per buffer", str(root.clusters_per_buffer))
    meta.add_row("Has sub-nodes",       "Yes" if root.header.has_subnodes else "No")
    meta.add_row("Entries area",        f"{root.header.entries_size} B "
                                         f"(allocated {root.header.allocated_size} B)")
    console.print(meta)

    if not root.entries:
        return
    et = Table(title=label + " — entries", box=box.SIMPLE, header_style="bold")
    for col in ("MFT#", "Flags", "Filename", "Namespace", "Real size"):
        et.add_column(col)
    for e in root.entries:
        if e.is_last:
            et.add_row("—", "LAST", "", "", "")
            continue
        d = e.decoded_filename()
        flags = []
        if e.has_subnode: flags.append(f"→VCN {e.child_vcn}")
        et.add_row(
            str(e.mft_ref & 0xFFFFFFFFFFFF),
            ", ".join(flags) or "leaf",
            d.get("Filename", "?"),
            d.get("Namespace", "?"),
            d.get("Real size", "?"),
        )
    console.print(et)


# ---------------------------------------------------------------------------
# Image helpers (E01)
# ---------------------------------------------------------------------------

def _stream_mft_from_image(image: Path, offset: int) -> Iterator[tuple[int, bytes]]:
    """Stream the raw $MFT bytes from an E01 image using icat, 1 record at a time."""
    proc = subprocess.Popen(
        ["icat", "-o", str(offset), str(image), "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        buf = bytearray()
        mft_offset = 0
        while True:
            chunk = proc.stdout.read(64 * 1024)
            if not chunk:
                break
            buf.extend(chunk)
            while len(buf) >= _RECORD_SIZE:
                yield mft_offset, bytes(buf[:_RECORD_SIZE])
                del buf[:_RECORD_SIZE]
                mft_offset += _RECORD_SIZE
    finally:
        proc.stdout.close()
        proc.wait()


def _read_mft_entry_from_image(image: Path, offset: int, entry_num: int) -> bytes:
    """Read a single MFT entry by streaming $MFT from an E01 image."""
    console = context.get_console()
    proc = subprocess.Popen(
        ["icat", "-o", str(offset), str(image), "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        skip = entry_num * _RECORD_SIZE
        remaining = skip
        while remaining > 0:
            chunk = proc.stdout.read(min(64 * 1024, remaining))
            if not chunk:
                console.print(f"[red]MFT entry {entry_num} is beyond the end of $MFT.[/red]")
                raise typer.Exit(1)
            remaining -= len(chunk)
        data = proc.stdout.read(_RECORD_SIZE)
    finally:
        proc.stdout.close()
        proc.wait()
    if len(data) < _RECORD_SIZE:
        console.print(f"[red]Could not read {_RECORD_SIZE} bytes for MFT entry {entry_num}.[/red]")
        raise typer.Exit(1)
    return data


# ---------------------------------------------------------------------------
# record command
# ---------------------------------------------------------------------------

@app.command()
def record(
    file: Optional[Path] = typer.Argument(
        None,
        help="Raw 1 KB MFT record dump  OR  raw NTFS volume (when --raw is set)",
    ),
    image: Optional[Path]  = typer.Option(None, "--image", "-i", help="E01 image"),
    offset: Optional[int]  = typer.Option(None, "--offset", "-o", help="Partition start in sectors (for --image or --raw)"),
    entry: Optional[int]   = typer.Option(None, "--entry", "-e", help="MFT entry number (required for --image / --raw)"),
    raw: bool              = typer.Option(False, "--raw", help="Treat FILE as a raw NTFS volume and scan for --entry"),
    dump: bool             = typer.Option(False, "--dump", help="Show the full 1 KB hex dump (default: first 512 B)"),
    extract: Optional[Path] = typer.Option(None, "--extract", "-x",
                                            help="Write $DATA content to this path (requires --raw for non-resident data)"),
    stream: Optional[str] = typer.Option(None, "--stream",
                                          help="Name of the $DATA stream to extract (default: unnamed). "
                                               "Use to pull an alternate data stream like 'Zone.Identifier'."),
):
    """Parse a single MFT record: header, attributes, and decoded fields.

    Sources (pick one):\\n
      mft record entry.bin                             Raw 1 KB dump\\n
      mft record --image disk.E01 --offset 128 --entry 5   From live E01 image\\n
      mft record --raw recovered.bin --entry 60        Scan raw volume for entry\\n

    Extra flags (combinable):\\n
      --dump      Show the full 1 KB hex dump instead of just the first sector\\n
      --extract X Write file content to X  (resident always; non-resident needs --raw)
    """
    console = context.get_console()

    # ── 1. Obtain the raw 1 KB record bytes ────────────────────────────────
    raw_vol: Path | None = None      # set when source is a raw volume file
    archive_source: _ArchiveSource | None = None  # set when source is a .7z archive

    if image is not None:
        if offset is None:
            console.print("[red]--offset is required with --image.[/red]")
            raise typer.Exit(1)
        if entry is None:
            console.print("[red]--entry is required with --image.[/red]")
            raise typer.Exit(1)
        data = _read_mft_entry_from_image(image, offset, entry)
        title = f"MFT Entry #{entry} — {image.name}"

    elif file is not None:
        if not file.exists():
            console.print(f"[red]File not found: {file}[/red]")
            raise typer.Exit(1)
        if file.suffix.lower() == ".7z":
            if entry is None:
                console.print("[red]--entry is required for 7z archive sources.[/red]")
                raise typer.Exit(1)
            archive_source = _ArchiveSource(file)
            data = archive_source.read_entry(entry, console=console if not context.output_json else None)
            if data is None:
                console.print(f"[red]Entry #{entry} is beyond the end of $MFT in {file.name}.[/red]")
                raise typer.Exit(1)
            title = f"MFT Entry #{entry} — {file.name}"
        elif raw:
            if entry is None:
                console.print("[red]--entry is required with --raw.[/red]")
                raise typer.Exit(1)
            if not context.output_json:
                console.print(f"[dim]Scanning {file.name} for MFT entry #{entry}…[/dim]")
            data = _find_entry_raw(file, entry, offset_sectors=offset or 0)
            if data is None:
                console.print(f"[red]Entry #{entry} not found in {file}.[/red]")
                raise typer.Exit(1)
            raw_vol = file
            title = f"MFT Entry #{entry} — {file.name} (raw scan)"
        else:
            data = file.read_bytes()
            title = f"MFT Record — {file.name}"

    else:
        console.print("[red]Provide a file argument or --image / --offset / --entry.[/red]")
        raise typer.Exit(1)

    # ── 2. Parse the record ─────────────────────────────────────────────────
    fixed = _apply_usa_fixup(data)
    rec = mft_parser.parse(fixed)

    if not rec.is_valid:
        console.print(f"[red]Invalid MFT record magic: {rec.magic!r} (expected b'FILE')[/red]")
        raise typer.Exit(1)

    if context.output_json:
        attrs = []
        for attr in rec.attributes:
            if attr.attr_type == 0xFFFFFFFF:
                break
            attrs.append({
                "id": attr.attr_id,
                "type": f"0x{attr.attr_type:02X}",
                "name": attr.attr_name,
                "offset": f"0x{attr.offset:04X}",
                "resident": not attr.non_resident,
                "hdr_size": 24 if not attr.non_resident else 64,
                "data_size": len(attr.data) if not attr.non_resident else None,
                "decoded": attr.decoded or {},
            })
        _bref = rec.base_record_ref
        print(json.dumps({
            "magic": rec.magic.decode(errors="replace"),
            "seq_number": rec.seq_number,
            "hard_link_count": rec.hard_link_count,
            "flags": f"0x{rec.flags:04X}",
            "flag_names": rec.flag_names,
            "is_directory": rec.is_directory,
            "is_in_use": rec.is_in_use,
            "is_extension_record": rec.is_extension_record,
            "base_record_number": _bref & 0xFFFFFFFFFFFF,
            "base_record_seq": (_bref >> 48) & 0xFFFF,
            "record_number": rec.record_number,
            "used_size": rec.used_size,
            "alloc_size": rec.alloc_size,
            "attributes": attrs,
        }, indent=2))
        return

    # ── 3. Display the record ───────────────────────────────────────────────
    result = _display_record(data, title, full_dump=dump, console=console)
    if result is None:
        raise typer.Exit(1)
    fixed, rec = result

    # ── 4. Extract $DATA if requested ──────────────────────────────────────
    if extract is not None:
        data_attrs = [a for a in rec.attributes if a.attr_type == 0x80]
        if not data_attrs:
            console.print("[yellow]No $DATA attribute found in this record.[/yellow]")
            raise typer.Exit(1)

        if stream is None:
            attr = next((a for a in data_attrs if a.name == ""), None)
            stream_label = "unnamed $DATA"
        else:
            attr = next((a for a in data_attrs if a.name == stream), None)
            stream_label = f"$DATA:{stream}"

        if attr is None:
            names = [a.name or "<unnamed>" for a in data_attrs]
            console.print(f"[red]{stream_label} not found. Available streams: "
                          f"{', '.join(names)}[/red]")
            raise typer.Exit(1)

        if archive_source is not None:
            # ── Archive (7z) extraction path ───────────────────────────────
            if not attr.non_resident:
                content = attr.data
            elif not rec.is_in_use:
                console.print(
                    "[red]Cannot extract non-resident $DATA: record is deleted.[/red]\n"
                    "[dim]The file's clusters were on the volume but are not preserved "
                    "in the archive.[/dim]"
                )
                raise typer.Exit(1)
            else:
                if stream is not None:
                    console.print(
                        "[red]Alternate data stream extraction is not supported for "
                        "archive sources.[/red]"
                    )
                    raise typer.Exit(1)
                arc_path = archive_source.resolve_path(entry)
                if arc_path is None:
                    console.print(
                        "[red]Could not reconstruct the file path from the MFT parent chain.[/red]"
                    )
                    raise typer.Exit(1)
                console.print(f"[dim]Extracting '{arc_path}' from archive → {extract}…[/dim]")
                content = archive_source.extract_file(arc_path)
                if content is None:
                    console.print(
                        f"[red]File not found in archive: {arc_path}[/red]\n"
                        "[dim]The file may have been excluded when the archive was created.[/dim]"
                    )
                    raise typer.Exit(1)
            extract.write_bytes(content)
            console.print(f"[green]✓ Extracted {len(content):,} bytes → {extract}[/green]")

        elif attr.non_resident and raw_vol is None:
            console.print(
                "[red]$DATA is non-resident (file content is stored in clusters on disk).[/red]\n"
                "[dim]Re-run with --raw <volume.bin> --entry <N> so the tool can follow "
                "the data runs.[/dim]"
            )
            raise typer.Exit(1)

        elif attr.non_resident and raw_vol is not None:
            # Verify the raw_vol file looks like an actual volume (has a valid VBR)
            # before attempting cluster reads; $MFT dumps lack a VBR at offset 0.
            try:
                _vol_geometry(raw_vol)
            except (ValueError, OSError):
                console.print(
                    f"[red]Cannot extract non-resident $DATA: "
                    f"'{raw_vol.name}' does not appear to be a raw volume image.[/red]\n"
                    f"[dim]The $DATA attribute stores its content in clusters on disk "
                    f"(LCN {attr.runs[0].lcn if attr.runs else '?'}, "
                    f"{attr.real_size:,} bytes across {len(attr.runs)} run(s)).\n"
                    f"Provide the full raw NTFS volume instead of the $MFT file to follow data runs.[/dim]"
                )
                raise typer.Exit(1)

            console.print(f"[dim]Extracting {stream_label} → {extract}…[/dim]")
            try:
                content = _extract_file_data(raw_vol, fixed, attr)
            except (OSError, RuntimeError) as e:
                console.print(f"[red]Extraction failed: {e}[/red]")
                raise typer.Exit(1)

            extract.write_bytes(content)

            a = attr.offset
            run_off_rel = struct.unpack_from("<H", fixed, a + 0x20)[0]
            run_data = fixed[a + run_off_rel: a + attr.length]
            try:
                spc, bps = _vol_geometry(raw_vol)
                cluster_size = spc * bps
                runs = _parse_data_runs(run_data)
                run_table = Table(title="Data Runs", box=box.SIMPLE, header_style="bold")
                run_table.add_column("Run #", justify="right")
                run_table.add_column("LCN", justify="right")
                run_table.add_column("Clusters", justify="right")
                run_table.add_column("Byte offset", justify="right")
                run_table.add_column("Size", justify="right")
                for idx, (lcn, cnt) in enumerate(runs):
                    if lcn == -1:
                        run_table.add_row(str(idx), "sparse", str(cnt), "—",
                                          f"{cnt * cluster_size:,} B")
                    else:
                        run_table.add_row(str(idx), str(lcn), str(cnt),
                                          f"{lcn * cluster_size:,}",
                                          f"{cnt * cluster_size:,} B")
                console.print(run_table)
            except Exception:
                pass

            console.print(f"[green]✓ Extracted {len(content):,} bytes → {extract}[/green]")

        else:
            # Resident, no archive — extract directly
            console.print(f"[dim]Extracting {stream_label} → {extract}…[/dim]")
            try:
                content = _extract_file_data(file, fixed, attr)
            except (OSError, RuntimeError) as e:
                console.print(f"[red]Extraction failed: {e}[/red]")
                raise typer.Exit(1)
            extract.write_bytes(content)
            console.print(f"[green]✓ Extracted {len(content):,} bytes → {extract}[/green]")


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@app.command()
def scan(
    file: Optional[Path] = typer.Argument(None, help="$MFT dump file, or raw NTFS volume (with --raw)"),
    image: Optional[Path] = typer.Option(None, "--image", "-i", help="E01 image — streams $MFT via icat"),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Partition start in sectors (for --image or file-based scanning)"),
    sectors: int = typer.Option(0, "--sectors", help="Read at most N sectors from the file (0 = all; file-based only)"),
    raw: bool = typer.Option(False, "--raw",
                              help="Raw volume scan: find FILE records at 512-byte boundaries "
                                   "(bypasses MFT index; use for broken partitions)"),
    limit: int = typer.Option(0, "--limit", "-n", help="Stop after N records (0 = all)"),
    skip: int = typer.Option(0, "--skip", "-s", help="Skip the first N matched records before showing"),
    show_deleted: bool = typer.Option(False, "--deleted", help="Include deleted (not in use) records"),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export results to a CSV file"),
):
    """Iterate MFT records and print a filename table.

    Sources (pick one):\\n
      mft scan mft.bin                        Pre-extracted $MFT dump\\n
      mft scan --image disk.E01 --offset 128  Stream $MFT from an E01 image\\n
      mft scan --raw recovered.bin            Raw volume scan (bypass broken MFT index)
    """
    console = context.get_console()

    if image is not None:
        if offset is None:
            console.print("[red]--offset is required with --image.[/red]")
            raise typer.Exit(1)
        if not context.output_json:
            console.print(f"[dim]Streaming $MFT from {image.name} at offset {offset}…[/dim]")
        source = _stream_mft_from_image(image, offset)
        source_name = f"{image.name} (offset {offset})"
    elif file is not None:
        if not file.exists():
            console.print(f"[red]File not found: {file}[/red]")
            raise typer.Exit(1)
        if file.suffix.lower() == ".7z":
            _arc = _ArchiveSource(file)
            source = _arc.iter_mft(console=console if not context.output_json else None)
            source_name = file.name
        elif raw:
            if not context.output_json:
                console.print(f"[dim]Raw volume scan of {file.name} "
                              "(FILE records at 512-byte boundaries)…[/dim]")
            source = _iter_raw_volume(file, offset_sectors=offset or 0, max_sectors=sectors)
            source_name = file.name
        else:
            if not context.output_json:
                console.print(f"[dim]Scanning $MFT dump: {file.name}[/dim]")
            source = _iter_file(file, offset_sectors=offset or 0, max_sectors=sectors)
            source_name = file.name
    else:
        console.print("[red]Provide a file argument or --image / --offset.[/red]")
        raise typer.Exit(1)

    _CSV_HEADERS = ["MFT#", "Filename", "Parent#", "Type", "Created", "Modified", "Size", "Offset", "Sector"]

    table = Table(
        title=f"MFT Scan — {source_name}{'  [raw volume]' if raw else ''}",
        box=box.ROUNDED,
        header_style="bold",
    )
    for col, kw in zip(
        _CSV_HEADERS,
        [{"justify": "right"}, {}, {"justify": "right"}, {}, {}, {}, {"justify": "right"}, {"justify": "right"}, {"justify": "right"}],
    ):
        table.add_column(col, **kw)

    count = 0
    shown = 0
    skipped = 0
    csv_rows: list[list[str]] = []
    json_rows: list[dict] = []

    for entry_offset, chunk in source:
        if len(chunk) < 48 or chunk[:4] != b"FILE":
            count += 1
            continue
        fixed = _apply_usa_fixup(chunk)
        try:
            rec = mft_parser.parse(fixed)
        except Exception:
            count += 1
            continue
        if not show_deleted and not rec.is_in_use:
            count += 1
            continue
        fn_attrs = [a for a in rec.attributes if a.attr_type == 0x30]
        if not fn_attrs:
            count += 1
            continue
        decoded_fns = [a.decoded for a in fn_attrs if a.decoded]
        if not decoded_fns:
            count += 1
            continue
        if skip and skipped < skip:
            skipped += 1
            count += 1
            continue
        d = decoded_fns[0]
        filename_str = " | ".join(
            fn.get("Filename", "?") for fn in decoded_fns if fn.get("Filename")
        ) or "?"
        row = [
            str(rec.record_number or count),
            filename_str,
            d.get("Parent MFT#", "?"),
            "DIR" if rec.is_directory else "file",
            d.get("Created", "?"),
            d.get("Modified", "?"),
            d.get("Real size", "?"),
            str(entry_offset),
            str(entry_offset // _SECTOR),
        ]
        if not context.output_json:
            table.add_row(*row)
        if csv_out is not None:
            csv_rows.append(row)
        if context.output_json:
            json_rows.append({
                "mft_num": row[0],
                "filename": row[1],
                "parent_mft": row[2],
                "type": row[3],
                "created": row[4],
                "modified": row[5],
                "size": row[6],
                "offset": entry_offset,
                "sector": entry_offset // _SECTOR,
            })
        shown += 1
        count += 1
        if limit and shown >= limit:
            break

    if context.output_json:
        print(json.dumps(json_rows, indent=2))
        return

    console.print(table)
    mode = "(raw volume scan)" if raw else ""
    console.print(f"[dim]Scanned {count} record(s), displayed {shown}  {mode}[/dim]")

    if csv_out is not None:
        with csv_out.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(_CSV_HEADERS)
            writer.writerows(csv_rows)
        console.print(f"[green]✓ Exported {shown} row(s) → {csv_out}[/green]")


# ---------------------------------------------------------------------------
# Internal iterators
# ---------------------------------------------------------------------------

def _iter_file(path: Path, offset_sectors: int = 0, max_sectors: int = 0) -> Iterator[tuple[int, bytes]]:
    start_byte = offset_sectors * 512
    pos = start_byte
    with path.open("rb") as f:
        if offset_sectors:
            f.seek(start_byte)
        remaining = max_sectors * 512 if max_sectors else None
        while True:
            to_read = _RECORD_SIZE
            if remaining is not None:
                to_read = min(to_read, remaining)
                if to_read <= 0:
                    break
            chunk = f.read(to_read)
            if not chunk:
                break
            if remaining is not None:
                remaining -= len(chunk)
            yield pos, chunk
            pos += len(chunk)


def _iter_raw_volume(path: Path, offset_sectors: int = 0, max_sectors: int = 0) -> Iterator[tuple[int, bytes]]:
    """Scan a raw volume for FILE records at 512-byte boundaries."""
    CHUNK = 1024 * 1024
    buf = bytearray()
    remaining = max_sectors * 512 if max_sectors else None
    buf_base = offset_sectors * 512
    with open(path, "rb") as f:
        if offset_sectors:
            f.seek(buf_base)
        while True:
            to_read = CHUNK
            if remaining is not None:
                to_read = min(to_read, remaining)
                if to_read <= 0:
                    break
            chunk = f.read(to_read)
            if not chunk:
                break
            if remaining is not None:
                remaining -= len(chunk)
            buf.extend(chunk)
            i = 0
            while i + _RECORD_SIZE <= len(buf):
                if buf[i: i + 4] == b"FILE":
                    yield buf_base + i, bytes(buf[i: i + _RECORD_SIZE])
                i += _SECTOR
            keep = _RECORD_SIZE - _SECTOR
            if len(buf) > keep:
                trimmed = len(buf) - keep
                buf_base += trimmed
                del buf[:trimmed]


# ---------------------------------------------------------------------------
# 7z archive source
# ---------------------------------------------------------------------------

class _MemWriterFactory:
    """py7zr WriterFactory implementation that writes extracted files to BytesIO buffers."""

    def __init__(self) -> None:
        self.buffers: dict[str, io.BytesIO] = {}

    def create(self, filename: str) -> io.BytesIO:
        buf = io.BytesIO()
        self.buffers[filename] = buf
        return buf

    def get(self, filename: str) -> bytes:
        buf = self.buffers.get(filename)
        if buf is None:
            return b""
        buf.seek(0)
        return buf.read()


# Make it a proper py7zr WriterFactory subclass at import time so we don't
# import py7zr at module level (keeping the dependency optional).
def _make_writer_factory_class():
    try:
        from py7zr.py7zr import WriterFactory as _WF
        class _RealMemWriterFactory(_MemWriterFactory, _WF):  # type: ignore[misc]
            pass
        return _RealMemWriterFactory
    except ImportError:
        return _MemWriterFactory

_MemWriterFactoryCls = _make_writer_factory_class()


class _ArchiveSource:
    """Lazy-loading 7z archive that caches the $MFT bytes in memory.

    All MFT scanning and single-entry reads use the in-memory copy.
    Per-file extraction opens a fresh SevenZipFile to avoid state issues.
    """

    _MFT_NAME = "$MFT"
    # MFT entry numbers that are reserved / root — stop walking parents here
    _ROOT_ENTRIES = frozenset({0, 1, 2, 3, 4, 5})
    # $FILE_NAME namespaces we prefer for path reconstruction (avoid 8.3 names)
    _LONG_NAME_NS = {"POSIX", "Win32", "Win32&DOS"}

    def __init__(self, path: Path) -> None:
        self.path = path
        self._mft: bytes | None = None

    # ------------------------------------------------------------------
    # MFT access
    # ------------------------------------------------------------------

    def _load_mft(self, console=None) -> bytes:
        if self._mft is None:
            import py7zr
            if console is not None:
                console.print(f"[dim]Decompressing $MFT from {self.path.name}…[/dim]")
            factory = _MemWriterFactoryCls()
            with py7zr.SevenZipFile(self.path, "r") as z:
                z.extract(targets=[self._MFT_NAME], factory=factory)
            self._mft = factory.get(self._MFT_NAME)
            if not self._mft:
                raise RuntimeError(f"$MFT not found in {self.path.name}")
        return self._mft

    def iter_mft(self, console=None) -> Iterator[tuple[int, bytes]]:
        data = self._load_mft(console)
        pos = 0
        while pos + _RECORD_SIZE <= len(data):
            yield pos, data[pos: pos + _RECORD_SIZE]
            pos += _RECORD_SIZE

    def read_entry(self, entry_num: int, console=None) -> bytes | None:
        data = self._load_mft(console)
        offset = entry_num * _RECORD_SIZE
        if offset + _RECORD_SIZE > len(data):
            return None
        return data[offset: offset + _RECORD_SIZE]

    # ------------------------------------------------------------------
    # Path reconstruction
    # ------------------------------------------------------------------

    def resolve_path(self, entry_num: int) -> str | None:
        """Walk the MFT parent chain to reconstruct the archive path for entry_num.

        Returns a forward-slash path like 'Users/Alice/file.txt', or None if the
        chain cannot be resolved.
        """
        parts: list[str] = []
        seen: set[int] = set()
        current = entry_num
        while current not in self._ROOT_ENTRIES and current not in seen:
            seen.add(current)
            raw = self.read_entry(current)
            if raw is None:
                return None
            fixed = _apply_usa_fixup(raw)
            rec = mft_parser.parse(fixed)
            fn_attrs = [a for a in rec.attributes if a.attr_type == 0x30]
            decoded_fns = [a.decoded for a in fn_attrs if a.decoded]
            if not decoded_fns:
                return None
            # Prefer long (Win32/POSIX) name to avoid 8.3 aliases in path
            best = next(
                (d for d in decoded_fns if d.get("Namespace") in self._LONG_NAME_NS),
                decoded_fns[0],
            )
            name = best.get("Filename", "")
            if not name:
                return None
            parts.append(name)
            try:
                current = int(best.get("Parent MFT#", "5"))
            except ValueError:
                break
        return "/".join(reversed(parts))

    # ------------------------------------------------------------------
    # File extraction
    # ------------------------------------------------------------------

    def extract_file(self, archive_path: str) -> bytes | None:
        """Extract a single file from the archive into memory. Returns None if not found."""
        import py7zr
        factory = _MemWriterFactoryCls()
        with py7zr.SevenZipFile(self.path, "r") as z:
            z.extract(targets=[archive_path], factory=factory)
        data = factory.get(archive_path)
        return data if data else None


# ---------------------------------------------------------------------------
# Shared directory-index helpers (used by ls + tree)
# ---------------------------------------------------------------------------

_LONG_NS = {"POSIX", "Win32", "Win32&DOS"}


@dataclass
class _MFTEntry:
    mft_num: int
    names: list[str]        # long name first; multiple names joined with " | " for display
    parent: int
    is_dir: bool
    is_in_use: bool
    size: str               # e.g. "1,234 bytes"
    created: str
    modified: str

    @property
    def label(self) -> str:
        return " | ".join(self.names) or "?"


def _build_dir_index(
    source: Iterator[tuple[int, bytes]],
    include_deleted: bool = False,
) -> tuple[dict[int, list[_MFTEntry]], dict[int, _MFTEntry]]:
    """Scan the MFT and return ({parent_mft: [children]}, {mft_num: entry})."""
    by_num: dict[int, _MFTEntry] = {}

    for offset, chunk in source:
        if len(chunk) < 48 or chunk[:4] != b"FILE":
            continue
        fixed = _apply_usa_fixup(chunk)
        try:
            rec = mft_parser.parse(fixed)
        except Exception:
            continue
        if not rec.is_valid:
            continue
        if not include_deleted and not rec.is_in_use:
            continue

        fn_attrs = [a for a in rec.attributes if a.attr_type == 0x30]
        decoded_fns = [a.decoded for a in fn_attrs if a.decoded]
        if not decoded_fns:
            continue

        entry_num = rec.record_number or (offset // _RECORD_SIZE)
        if entry_num in by_num:
            continue  # first-seen wins (MFT entries are contiguous in dumps)

        best = next(
            (d for d in decoded_fns if d.get("Namespace") in _LONG_NS),
            decoded_fns[0],
        )
        parent = int(best.get("Parent MFT#", "0") or "0")

        # Collect names: long-name variants first, then remaining (e.g. 8.3)
        seen_n: set[str] = set()
        names: list[str] = []
        for d in sorted(decoded_fns, key=lambda x: 0 if x.get("Namespace") in _LONG_NS else 1):
            n = d.get("Filename", "")
            if n and n not in seen_n:
                seen_n.add(n)
                names.append(n)

        by_num[entry_num] = _MFTEntry(
            mft_num=entry_num,
            names=names,
            parent=parent,
            is_dir=rec.is_directory,
            is_in_use=rec.is_in_use,
            size=best.get("Real size", "0 bytes"),
            created=best.get("Created", ""),
            modified=best.get("Modified", ""),
        )

    by_parent: dict[int, list[_MFTEntry]] = {}
    for e in by_num.values():
        by_parent.setdefault(e.parent, []).append(e)

    return by_parent, by_num


def _open_mft_source(
    file: Optional[Path],
    image: Optional[Path],
    offset: Optional[int],
    raw: bool,
    sectors: int,
    console,
) -> tuple[Iterator[tuple[int, bytes]], str]:
    """Resolve source options to (record_iterator, display_name).

    Raises typer.Exit(1) on bad arguments (prints error first).
    """
    if image is not None:
        if offset is None:
            console.print("[red]--offset is required with --image.[/red]")
            raise typer.Exit(1)
        if not context.output_json:
            console.print(f"[dim]Streaming $MFT from {image.name} at offset {offset}…[/dim]")
        return _stream_mft_from_image(image, offset), f"{image.name} (offset {offset})"

    if file is None:
        console.print("[red]Provide a file argument or --image.[/red]")
        raise typer.Exit(1)
    if not file.exists():
        console.print(f"[red]File not found: {file}[/red]")
        raise typer.Exit(1)

    if file.suffix.lower() == ".7z":
        arc = _ArchiveSource(file)
        return arc.iter_mft(console=console if not context.output_json else None), file.name
    elif raw:
        if not context.output_json:
            console.print(f"[dim]Raw volume scan of {file.name} (FILE records at 512-byte boundaries)…[/dim]")
        return _iter_raw_volume(file, offset_sectors=offset or 0, max_sectors=sectors), file.name
    else:
        if not context.output_json:
            console.print(f"[dim]Scanning $MFT dump: {file.name}[/dim]")
        return _iter_file(file, offset_sectors=offset or 0, max_sectors=sectors), file.name


# ---------------------------------------------------------------------------
# Directory index cache (7z archives only)
# ---------------------------------------------------------------------------

_CACHE_VERSION = 1


def _archive_hash(path: Path) -> str:
    """Return the SHA-256 hex digest of the entire file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8 * 1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def _cache_path(archive: Path) -> Path:
    return archive.parent / (archive.name + ".mftidx")


def _save_index_cache(path: Path, archive_hash: str, by_num: dict[int, _MFTEntry]) -> None:
    payload = {
        "v": _CACHE_VERSION,
        "hash": archive_hash,
        # Compact array-of-arrays: [mft_num, names, parent, is_dir, is_in_use, size, created, modified]
        "e": [
            [e.mft_num, e.names, e.parent, e.is_dir, e.is_in_use, e.size, e.created, e.modified]
            for e in by_num.values()
        ],
    }
    with gzip.open(path, "wt", encoding="utf-8", compresslevel=6) as f:
        json.dump(payload, f, separators=(",", ":"))


def _load_index_cache(
    path: Path,
    archive_hash: str | None,
) -> tuple[dict[int, list[_MFTEntry]], dict[int, _MFTEntry]] | None:
    """Load the cached index.

    If archive_hash is None the hash stored in the cache is not verified —
    the caller is responsible for warning the user.  Returns None on any
    version mismatch, corruption, or hash mismatch (when hash is provided).
    """
    if not path.exists():
        return None
    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return None
    if payload.get("v") != _CACHE_VERSION:
        return None
    if archive_hash is not None and payload.get("hash") != archive_hash:
        return None

    by_num: dict[int, _MFTEntry] = {}
    for row in payload["e"]:
        n, names, p, d, u, s, c, m = row
        by_num[n] = _MFTEntry(mft_num=n, names=names, parent=p,
                               is_dir=d, is_in_use=u, size=s, created=c, modified=m)

    by_parent: dict[int, list[_MFTEntry]] = {}
    for e in by_num.values():
        by_parent.setdefault(e.parent, []).append(e)

    return by_parent, by_num


_UNVERIFIED_HINT = (
    "Cache loaded without hash verification — use --check-hash to confirm "
    "the index matches the current archive."
)


def _get_dir_index(
    file: Optional[Path],
    image: Optional[Path],
    offset: Optional[int],
    raw: bool,
    sectors: int,
    console,
    check_hash: bool = False,
) -> tuple[dict[int, list[_MFTEntry]], dict[int, _MFTEntry], str, str | None]:
    """Return (by_parent, by_num, source_name, hint).

    *hint* is a non-None string when the cache was loaded without hash
    verification; commands should print it as a dim notice at the end.

    For .7z archives the index (always built with deleted entries) is cached
    to <archive>.mftidx.  By default the cache is loaded as-is; pass
    check_hash=True to compute SHA-256 and reject a stale cache.
    """
    if file is not None and file.suffix.lower() == ".7z":
        cache_file = _cache_path(file)

        if check_hash:
            if not context.output_json:
                console.print(f"[dim]Hashing {file.name}…[/dim]")
            ahash: str | None = _archive_hash(file)
        else:
            ahash = None  # skip verification when loading

        cached = _load_index_cache(cache_file, ahash)
        if cached is not None:
            by_parent, by_num = cached
            hint = None if check_hash else _UNVERIFIED_HINT
            if not context.output_json:
                console.print(
                    f"[dim]Loaded index from {cache_file.name}  "
                    f"({len(by_num):,} entries)[/dim]"
                )
            return by_parent, by_num, file.name, hint

        # Cache miss — always compute hash so we can store it
        if ahash is None:
            if not context.output_json:
                console.print(f"[dim]Hashing {file.name} (first run — building cache)…[/dim]")
            ahash = _archive_hash(file)

        source, source_name = _open_mft_source(file, None, None, False, 0, console)
        if not context.output_json:
            console.print(f"[dim]Building directory index from {source_name}…[/dim]")
        by_parent, by_num = _build_dir_index(source, include_deleted=True)

        try:
            _save_index_cache(cache_file, ahash, by_num)
            if not context.output_json:
                console.print(
                    f"[dim]Index saved to {cache_file.name}  "
                    f"({len(by_num):,} entries)[/dim]"
                )
        except OSError as exc:
            if not context.output_json:
                console.print(f"[yellow]Warning: could not write cache: {exc}[/yellow]")

        return by_parent, by_num, source_name, None

    # Non-archive: build without caching
    source, source_name = _open_mft_source(file, image, offset, raw, sectors, console)
    if not context.output_json:
        console.print(f"[dim]Building directory index from {source_name}…[/dim]")
    by_parent, by_num = _build_dir_index(source, include_deleted=True)
    return by_parent, by_num, source_name, None


# ---------------------------------------------------------------------------
# ls command
# ---------------------------------------------------------------------------

@app.command(name="ls")
def ls_cmd(
    file: Optional[Path] = typer.Argument(None, help="$MFT dump, raw NTFS volume, or .7z archive"),
    image: Optional[Path] = typer.Option(None, "--image", "-i", help="E01 image — streams $MFT via icat"),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Partition start in sectors"),
    raw: bool = typer.Option(False, "--raw", help="Raw volume scan (FILE records at 512-byte boundaries)"),
    entry: int = typer.Option(5, "--entry", "-e", help="MFT entry number of the directory to list (default: 5 = root)"),
    show_deleted: bool = typer.Option(False, "--deleted", help="Include deleted entries"),
    check_hash: bool = typer.Option(False, "--check-hash", help="Verify the .7z cache against the archive SHA-256 before use"),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export listing to CSV"),
) -> None:
    """List the contents of an NTFS directory by MFT entry number.

    Sources (pick one):\\n
      mft ls mft.bin --entry 5         From a pre-extracted $MFT dump\\n
      mft ls evidence.7z               From a 7z archive (auto-detected)\\n
      mft ls --image disk.E01 --offset 128
    """
    console = context.get_console()
    by_parent, by_num, source_name, cache_hint = _get_dir_index(
        file, image, offset, raw, 0, console, check_hash=check_hash
    )

    if entry not in by_num and entry not in by_parent:
        console.print(f"[red]MFT entry #{entry} not found.[/red]")
        raise typer.Exit(1)

    children = [e for e in by_parent.get(entry, []) if e.mft_num != entry]
    if not show_deleted:
        children = [e for e in children if e.is_in_use]
    children.sort(key=lambda e: (0 if e.is_dir else 1, e.label.lower()))

    _LS_HEADERS = ["MFT#", "Type", "Filename", "Size", "Modified"]

    if context.output_json:
        print(json.dumps([
            {
                "mft_num": e.mft_num,
                "type": "DIR" if e.is_dir else "file",
                "filenames": e.names,
                "size": e.size,
                "modified": e.modified,
                "deleted": not e.is_in_use,
            }
            for e in children
        ], indent=2))
        return

    dir_entry = by_num.get(entry)
    dir_label = dir_entry.label if dir_entry else f"#{entry}"
    table = Table(
        title=f"Directory listing — [{entry}] {dir_label}  ({source_name})",
        box=box.ROUNDED,
        header_style="bold",
    )
    table.add_column("MFT#", justify="right")
    table.add_column("Type")
    table.add_column("Filename")
    table.add_column("Size", justify="right")
    table.add_column("Modified")

    csv_rows: list[list[str]] = []
    for e in children:
        mft_cell = f"[{e.mft_num}]"
        type_cell = "DIR" if e.is_dir else "file"
        name_cell = e.label
        size_cell = "—" if e.is_dir else e.size
        mod_cell = e.modified
        style = "dim" if not e.is_in_use else ""
        table.add_row(mft_cell, type_cell, name_cell, size_cell, mod_cell, style=style)
        csv_rows.append([mft_cell, type_cell, name_cell, size_cell, mod_cell])

    console.print(table)
    console.print(f"[dim]{len(children)} item(s)[/dim]")

    if csv_out is not None:
        with csv_out.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(_LS_HEADERS)
            writer.writerows(csv_rows)
        console.print(f"[green]✓ Exported {len(csv_rows)} row(s) → {csv_out}[/green]")

    if cache_hint:
        console.print(f"[dim]{cache_hint}[/dim]")


# ---------------------------------------------------------------------------
# tree command
# ---------------------------------------------------------------------------

def _build_rich_tree(
    node: RichTree,
    entry_num: int,
    by_parent: dict[int, list[_MFTEntry]],
    current_depth: int,
    max_depth: int,
    seen: set[int],
    show_deleted: bool = False,
) -> None:
    if entry_num in seen:
        return
    seen.add(entry_num)

    children = [c for c in by_parent.get(entry_num, []) if c.mft_num != entry_num]
    if not show_deleted:
        children = [c for c in children if c.is_in_use]
    children.sort(key=lambda e: (0 if e.is_dir else 1, e.label.lower()))

    if current_depth >= max_depth:
        if children:
            node.add(
                f"[dim]… {len(children)} item{'s' if len(children) != 1 else ''} "
                f"(increase --depth to expand)[/dim]"
            )
        return

    for child in children:
        n = child.mft_num
        names = child.names
        num_part = f"[dim][[/dim]{n}[dim]][/dim]"
        if len(names) > 1:
            aliases = " | ".join(names[1:])
            name_part = (
                f"[bold]{names[0]}[/bold] [dim]| {aliases}[/dim]"
                if child.is_dir
                else f"{names[0]} [dim]| {aliases}[/dim]"
            )
        else:
            name_part = f"[bold]{names[0]}[/bold]" if child.is_dir else (names[0] if names else "?")

        label = (
            f"[dim]{num_part} {name_part}[/dim]"
            if not child.is_in_use
            else f"{num_part} {name_part}"
        )

        child_node = node.add(label)
        if child.is_dir:
            _build_rich_tree(child_node, n, by_parent, current_depth + 1, max_depth, seen, show_deleted)


def _build_tree_dict(
    entry_num: int,
    by_parent: dict[int, list[_MFTEntry]],
    by_num: dict[int, _MFTEntry],
    current_depth: int,
    max_depth: int,
    seen: set[int],
    show_deleted: bool = False,
) -> dict:
    e = by_num.get(entry_num)
    result: dict = {
        "mft_num": entry_num,
        "filenames": e.names if e else [],
        "type": "DIR" if (e and e.is_dir) else "file",
        "children": [],
    }
    if entry_num in seen:
        return result
    seen.add(entry_num)

    children = [c for c in by_parent.get(entry_num, []) if c.mft_num != entry_num]
    if not show_deleted:
        children = [c for c in children if c.is_in_use]
    children.sort(key=lambda x: (0 if x.is_dir else 1, x.label.lower()))

    if current_depth < max_depth:
        for child in children:
            result["children"].append(
                _build_tree_dict(child.mft_num, by_parent, by_num,
                                 current_depth + 1, max_depth, set(seen), show_deleted)
            )
    elif children:
        result["truncated"] = len(children)

    return result


@app.command(name="tree")
def tree_cmd(
    file: Optional[Path] = typer.Argument(None, help="$MFT dump, raw NTFS volume, or .7z archive"),
    image: Optional[Path] = typer.Option(None, "--image", "-i", help="E01 image — streams $MFT via icat"),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Partition start in sectors"),
    raw: bool = typer.Option(False, "--raw", help="Raw volume scan (FILE records at 512-byte boundaries)"),
    entry: int = typer.Option(5, "--entry", "-e", help="Root entry number (default: 5 = volume root)"),
    depth: int = typer.Option(3, "--depth", "-d", help="Maximum recursion depth (default: 3)"),
    show_deleted: bool = typer.Option(False, "--deleted", help="Include deleted entries"),
    check_hash: bool = typer.Option(False, "--check-hash", help="Verify the .7z cache against the archive SHA-256 before use"),
) -> None:
    """Show a recursive directory tree from any MFT source.

    Sources (pick one):\\n
      mft tree mft.bin                  From a pre-extracted $MFT dump\\n
      mft tree evidence.7z              From a 7z archive (auto-detected)\\n
      mft tree --image disk.E01 --offset 128
    """
    console = context.get_console()
    by_parent, by_num, source_name, cache_hint = _get_dir_index(
        file, image, offset, raw, 0, console, check_hash=check_hash
    )

    if entry not in by_num and entry not in by_parent:
        console.print(f"[red]MFT entry #{entry} not found.[/red]")
        raise typer.Exit(1)

    root_entry = by_num.get(entry)
    root_label_name = root_entry.label if root_entry else f"#{entry}"

    if context.output_json:
        print(json.dumps(
            _build_tree_dict(entry, by_parent, by_num, 0, depth, set(), show_deleted),
            indent=2,
        ))
        return

    root_label = (
        f"[dim][[/dim][bold cyan]{entry}[/bold cyan][dim]][/dim]"
        f" [bold cyan]{root_label_name}[/bold cyan]"
        f"  [dim]{source_name}[/dim]"
    )
    t = RichTree(root_label)
    _build_rich_tree(t, entry, by_parent, 0, depth, set(), show_deleted)
    console.print(t)
    if cache_hint:
        console.print(f"[dim]{cache_hint}[/dim]")
