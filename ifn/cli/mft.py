from pathlib import Path
from typing import Optional, Iterator
import csv
import subprocess
import struct

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from ifn.parsers import mft_record as mft_parser
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse NTFS Master File Table records")
console = Console()

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

def _find_entry_raw(vol: Path, entry_num: int) -> bytes | None:
    """Scan a raw NTFS volume at 512-byte boundaries for a FILE record with the given entry number."""
    CHUNK = 1024 * 1024
    buf = bytearray()
    with open(vol, "rb") as f:
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

def _display_record(data: bytes, title: str, full_dump: bool = False) -> None:
    """Pretty-print one MFT record: hex table, attribute list, decoded fields."""
    fixed = _apply_usa_fixup(data)
    rec = mft_parser.parse(fixed)

    if not rec.is_valid:
        console.print(f"[red]Invalid MFT record magic: {rec.magic!r} (expected b'FILE')[/red]")
        raise typer.Exit(1)

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
        (32, 8, "Base record ref",   str(rec.base_record_ref)),
        (40, 2, "Next attr ID",      str(rec.next_attr_id)),
        (44, 4, "Record number",     str(rec.record_number)),
    ]
    render_hex_table(fixed[:hex_len], header_fields, title=title)

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
        if attr.attr_type == 0xFFFFFFFF or not attr.decoded:
            continue
        detail = Table(title=f"{attr.attr_name} details", box=box.SIMPLE, header_style="bold")
        detail.add_column("Field")
        detail.add_column("Value")
        for k, v in attr.decoded.items():
            detail.add_row(k, v)
        console.print(detail)

    return fixed, rec  # return for callers that need to do further work


# ---------------------------------------------------------------------------
# Image helpers (E01)
# ---------------------------------------------------------------------------

def _stream_mft_from_image(image: Path, offset: int) -> Iterator[bytes]:
    """Stream the raw $MFT bytes from an E01 image using icat, 1 record at a time."""
    proc = subprocess.Popen(
        ["icat", "-o", str(offset), str(image), "0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        buf = bytearray()
        while True:
            chunk = proc.stdout.read(64 * 1024)
            if not chunk:
                break
            buf.extend(chunk)
            while len(buf) >= _RECORD_SIZE:
                yield bytes(buf[:_RECORD_SIZE])
                del buf[:_RECORD_SIZE]
    finally:
        proc.stdout.close()
        proc.wait()


def _read_mft_entry_from_image(image: Path, offset: int, entry_num: int) -> bytes:
    """Read a single MFT entry by streaming $MFT from an E01 image."""
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
    offset: Optional[int]  = typer.Option(None, "--offset", "-o", help="Partition start sector (for --image)"),
    entry: Optional[int]   = typer.Option(None, "--entry", "-e", help="MFT entry number (required for --image / --raw)"),
    raw: bool              = typer.Option(False, "--raw", help="Treat FILE as a raw NTFS volume and scan for --entry"),
    dump: bool             = typer.Option(False, "--dump", help="Show the full 1 KB hex dump (default: first 512 B)"),
    extract: Optional[Path] = typer.Option(None, "--extract", "-x",
                                            help="Write $DATA content to this path (requires --raw for non-resident data)"),
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
    # ── 1. Obtain the raw 1 KB record bytes ────────────────────────────────
    raw_vol: Path | None = None  # set when source is a raw volume file

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
        if raw:
            if entry is None:
                console.print("[red]--entry is required with --raw.[/red]")
                raise typer.Exit(1)
            console.print(f"[dim]Scanning {file.name} for MFT entry #{entry}…[/dim]")
            data = _find_entry_raw(file, entry)
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

    # ── 2. Display the record ───────────────────────────────────────────────
    result = _display_record(data, title, full_dump=dump)
    if result is None:
        raise typer.Exit(1)
    fixed, rec = result

    # ── 3. Extract $DATA if requested ──────────────────────────────────────
    if extract is not None:
        data_attrs = [a for a in rec.attributes if a.attr_type == 0x80]
        if not data_attrs:
            console.print("[yellow]No $DATA attribute found in this record.[/yellow]")
            raise typer.Exit(1)

        attr = data_attrs[0]

        if attr.non_resident and raw_vol is None:
            console.print(
                "[red]$DATA is non-resident (file content is stored in clusters on disk).[/red]\n"
                "[dim]Re-run with --raw <volume.bin> --entry <N> so the tool can follow "
                "the data runs.[/dim]"
            )
            raise typer.Exit(1)

        console.print(f"[dim]Extracting $DATA → {extract}…[/dim]")
        try:
            content = _extract_file_data(raw_vol or file, fixed, attr)
        except (OSError, RuntimeError) as e:
            console.print(f"[red]Extraction failed: {e}[/red]")
            raise typer.Exit(1)

        extract.write_bytes(content)

        # Show info about the non-resident layout for educational purposes
        if attr.non_resident:
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

        console.print(
            f"[green]✓ Extracted {len(content):,} bytes → {extract}[/green]"
        )


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@app.command()
def scan(
    file: Optional[Path] = typer.Argument(None, help="$MFT dump file, or raw NTFS volume (with --raw)"),
    image: Optional[Path] = typer.Option(None, "--image", "-i", help="E01 image — streams $MFT via icat"),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Partition start sector (for --image)"),
    raw: bool = typer.Option(False, "--raw",
                              help="Raw volume scan: find FILE records at 512-byte boundaries "
                                   "(bypasses MFT index; use for broken partitions)"),
    limit: int = typer.Option(0, "--limit", "-n", help="Stop after N records (0 = all)"),
    show_deleted: bool = typer.Option(False, "--deleted", help="Include deleted (not in use) records"),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export results to a CSV file"),
):
    """Iterate MFT records and print a filename table.

    Sources (pick one):\\n
      mft scan mft.bin                        Pre-extracted $MFT dump\\n
      mft scan --image disk.E01 --offset 128  Stream $MFT from an E01 image\\n
      mft scan --raw recovered.bin            Raw volume scan (bypass broken MFT index)
    """
    if image is not None:
        if offset is None:
            console.print("[red]--offset is required with --image.[/red]")
            raise typer.Exit(1)
        console.print(f"[dim]Streaming $MFT from {image.name} at offset {offset}…[/dim]")
        source = _stream_mft_from_image(image, offset)
        source_name = f"{image.name} (offset {offset})"
    elif file is not None:
        if not file.exists():
            console.print(f"[red]File not found: {file}[/red]")
            raise typer.Exit(1)
        if raw:
            console.print(f"[dim]Raw volume scan of {file.name} "
                          "(FILE records at 512-byte boundaries)…[/dim]")
            source = _iter_raw_volume(file)
        else:
            console.print(f"[dim]Scanning $MFT dump: {file.name}[/dim]")
            source = _iter_file(file)
        source_name = file.name
    else:
        console.print("[red]Provide a file argument or --image / --offset.[/red]")
        raise typer.Exit(1)

    _CSV_HEADERS = ["MFT#", "Filename", "Parent#", "Type", "Created", "Modified", "Size"]

    table = Table(
        title=f"MFT Scan — {source_name}{'  [raw volume]' if raw else ''}",
        box=box.ROUNDED,
        header_style="bold",
    )
    for col, kw in zip(
        _CSV_HEADERS,
        [{"justify": "right"}, {}, {"justify": "right"}, {}, {}, {}, {"justify": "right"}],
    ):
        table.add_column(col, **kw)

    count = 0
    shown = 0
    csv_rows: list[list[str]] = []

    for chunk in source:
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
        for fn_attr in fn_attrs:
            d = fn_attr.decoded
            if not d:
                continue
            row = [
                str(rec.record_number or count),
                d.get("Filename", "?"),
                d.get("Parent MFT#", "?"),
                "DIR" if rec.is_directory else "file",
                d.get("Created", "?"),
                d.get("Modified", "?"),
                d.get("Real size", "?"),
            ]
            table.add_row(*row)
            if csv_out is not None:
                csv_rows.append(row)
            shown += 1
            break
        count += 1
        if limit and shown >= limit:
            break

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

def _iter_file(path: Path) -> Iterator[bytes]:
    with path.open("rb") as f:
        while True:
            chunk = f.read(_RECORD_SIZE)
            if not chunk:
                break
            yield chunk


def _iter_raw_volume(path: Path) -> Iterator[bytes]:
    """Scan a raw volume for FILE records at 512-byte boundaries."""
    CHUNK = 1024 * 1024
    buf = bytearray()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            buf.extend(chunk)
            i = 0
            while i + _RECORD_SIZE <= len(buf):
                if buf[i: i + 4] == b"FILE":
                    yield bytes(buf[i: i + _RECORD_SIZE])
                i += _SECTOR
            keep = _RECORD_SIZE - _SECTOR
            if len(buf) > keep:
                del buf[: len(buf) - keep]
