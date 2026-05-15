from pathlib import Path
from typing import Optional, Iterator
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
# Shared helpers
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
    """Read a single MFT entry (1024 bytes) from an E01 image by streaming $MFT."""
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


def _iter_raw_volume(path: Path) -> Iterator[bytes]:
    """Scan a raw volume image for FILE records at 512-byte boundaries.

    Unlike a normal $MFT stream (which is a contiguous array of 1 KB records),
    this mode searches the entire volume byte-by-byte at sector granularity.
    It is useful when the MFT index (entry #0) is damaged or missing.
    """
    CHUNK = 1024 * 1024
    buf = bytearray()
    with open(path, "rb") as f:
        pos = 0
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            buf.extend(chunk)
            # Scan at 512-byte steps
            i = 0
            while i + _RECORD_SIZE <= len(buf):
                if buf[i: i + 4] == b"FILE":
                    yield bytes(buf[i: i + _RECORD_SIZE])
                i += _SECTOR
            # Keep up to one record worth of tail for the next iteration
            keep = len(buf) % _SECTOR
            keep = max(keep, _RECORD_SIZE - _SECTOR)
            del buf[:len(buf) - keep]
            pos += len(chunk)


def _apply_usa_fixup(data: bytes) -> bytes:
    """Apply NTFS Update Sequence Array fixup to a metadata record.

    Each sector's last two bytes are replaced in the on-disk form with the USA
    check value; the originals are stored in the USA table.  Restoring them
    before parsing prevents false attribute-length errors.
    """
    if len(data) < 48:
        return data
    usa_off = struct.unpack_from("<H", data, 4)[0]
    usa_cnt = struct.unpack_from("<H", data, 6)[0]  # includes the check word itself
    if usa_off == 0 or usa_cnt < 2 or usa_off + usa_cnt * 2 > len(data):
        return data

    out = bytearray(data)
    check_word = struct.unpack_from("<H", out, usa_off)[0]
    for i in range(1, usa_cnt):
        sector_end = i * _SECTOR - 2
        if sector_end + 2 > len(out):
            break
        disk_val = struct.unpack_from("<H", out, sector_end)[0]
        if disk_val != check_word:
            return data  # USA check fails — return original (caller handles bad records)
        original = struct.unpack_from("<H", out, usa_off + i * 2)[0]
        struct.pack_into("<H", out, sector_end, original)
    return bytes(out)


def _display_record(data: bytes, title: str) -> None:
    """Parse and pretty-print one MFT record (hex table + attribute list + decoded fields)."""
    fixed = _apply_usa_fixup(data)
    rec = mft_parser.parse(fixed)

    if not rec.is_valid:
        console.print(f"[red]Invalid MFT record magic: {rec.magic!r} (expected b'FILE')[/red]")
        raise typer.Exit(1)

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
    render_hex_table(fixed[:min(512, len(fixed))], header_fields, title=title)

    attr_table = Table(title="Attributes", box=box.ROUNDED, header_style="bold")
    attr_table.add_column("ID", justify="right")
    attr_table.add_column("Type")
    attr_table.add_column("Offset", justify="right")
    attr_table.add_column("Length", justify="right")
    attr_table.add_column("Resident")
    attr_table.add_column("Name")

    for attr in rec.attributes:
        if attr.attr_type == 0xFFFFFFFF:
            break
        attr_table.add_row(
            str(attr.attr_id),
            f"0x{attr.attr_type:02X}  {attr.attr_name}",
            f"0x{attr.offset:04X}",
            str(attr.length),
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


# ---------------------------------------------------------------------------
# record command
# ---------------------------------------------------------------------------

@app.command()
def record(
    file: Optional[Path] = typer.Argument(None, help="Path to a raw 1 KB MFT record dump"),
    image: Optional[Path] = typer.Option(None, "--image", "-i",
                                          help="E01 image to read $MFT from"),
    offset: Optional[int] = typer.Option(None, "--offset", "-o",
                                          help="Partition start sector (for --image)"),
    entry: Optional[int] = typer.Option(None, "--entry", "-e",
                                         help="MFT entry number to extract (for --image)"),
):
    """Parse a single MFT record: magic, header fields, and all attributes.

    Sources (use one):
      mft record record.bin            Raw 1 KB dump from a file
      mft record --image disk.E01 --offset 128 --entry 5   Live entry from an image
    """
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
        data = file.read_bytes()
        title = f"MFT Record — {file.name}"
    else:
        console.print("[red]Provide either a file argument or --image / --offset / --entry.[/red]")
        raise typer.Exit(1)

    _display_record(data, title)


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------

@app.command()
def scan(
    file: Optional[Path] = typer.Argument(None, help="$MFT dump file, or raw NTFS volume (with --raw)"),
    image: Optional[Path] = typer.Option(None, "--image", "-i",
                                          help="E01 image — streams $MFT directly via icat"),
    offset: Optional[int] = typer.Option(None, "--offset", "-o",
                                          help="Partition start sector (for --image)"),
    raw: bool = typer.Option(False, "--raw", help=(
        "Raw volume scan: search the entire file for FILE signatures at 512-byte "
        "boundaries.  Use this for broken partitions where MFT entry #0 is missing."
    )),
    limit: int = typer.Option(0, "--limit", "-n", help="Stop after N records (0 = all)"),
    show_deleted: bool = typer.Option(False, "--deleted", help="Include deleted (not in use) records"),
):
    """Iterate MFT records and print a filename table.

    Sources (use one):
      mft scan mft.bin                       Pre-extracted $MFT dump (sequential, streaming)
      mft scan --image disk.E01 --offset 128 Stream $MFT directly from an E01 image
      mft scan --raw recovered.bin           Raw volume scan (bypass broken MFT index)
    """
    # ── Determine record source ─────────────────────────────────────────────
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
            console.print(f"[dim]Raw volume scan of {file.name} (searching FILE signatures "
                          "at 512-byte boundaries)…[/dim]")
            source = _iter_raw_volume(file)
        else:
            console.print(f"[dim]Scanning $MFT dump: {file.name}[/dim]")
            source = _iter_file(file)
        source_name = file.name
    else:
        console.print("[red]Provide a file argument or --image / --offset.[/red]")
        raise typer.Exit(1)

    # ── Scan loop ───────────────────────────────────────────────────────────
    table = Table(
        title=f"MFT Scan — {source_name}{'  [raw volume]' if raw else ''}",
        box=box.ROUNDED,
        header_style="bold",
    )
    table.add_column("MFT#", justify="right")
    table.add_column("Filename")
    table.add_column("Parent#", justify="right")
    table.add_column("Type")
    table.add_column("Created")
    table.add_column("Modified")
    table.add_column("Size", justify="right")

    count = 0
    shown = 0

    for chunk in source:
        if len(chunk) < 48:
            count += 1
            continue
        if chunk[:4] != b"FILE":
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
            table.add_row(
                str(rec.record_number or count),
                d.get("Filename", "?"),
                d.get("Parent MFT#", "?"),
                "DIR" if rec.is_directory else "file",
                d.get("Created", "?"),
                d.get("Modified", "?"),
                d.get("Real size", "?"),
            )
            shown += 1
            break  # one row per record (prefer first $FILE_NAME attr)

        count += 1
        if limit and shown >= limit:
            break

    console.print(table)
    mode_note = "(raw volume scan — FILE records at 512-byte boundaries)" if raw else ""
    console.print(f"[dim]Scanned {count} record(s), displayed {shown}  {mode_note}[/dim]")


# ---------------------------------------------------------------------------
# Internal file iterator (unchanged behaviour for plain $MFT dump files)
# ---------------------------------------------------------------------------

def _iter_file(path: Path) -> Iterator[bytes]:
    with path.open("rb") as f:
        while True:
            chunk = f.read(_RECORD_SIZE)
            if not chunk:
                break
            yield chunk
