from __future__ import annotations
import csv
import json
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table
from rich import box

from ifn import context
from ifn.parsers import mbr as mbr_parser
from ifn.parsers import gpt as gpt_parser
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse MBR and GPT partition tables")

_MBR_HEADERS = ["#", "Status", "Type code", "Type name", "LBA start", "LBA end", "Sectors", "Size bytes"]
_GPT_HEADERS = ["#", "Name", "Type", "First LBA", "Last LBA", "Size bytes", "GUID"]


@app.command()
def mbr(
    file: Path = typer.Argument(..., help="Path to 512-byte MBR dump", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export partition table to CSV"),
) -> None:
    """Parse a Master Boot Record partition table."""
    console = context.get_console()
    data = file.read_bytes()
    rec = mbr_parser.parse(data)

    partitions = [p for p in rec.partitions if not (p.type_code == 0x00 and p.lba_start == 0)]

    if context.output_json:
        print(json.dumps({
            "disk_signature": f"0x{rec.disk_signature:08X}",
            "boot_signature_valid": rec.signature_valid,
            "partitions": [
                {
                    "index": p.index,
                    "active": p.active,
                    "type_code": f"0x{p.type_code:02X}",
                    "type_name": p.type_name,
                    "lba_start": p.lba_start,
                    "lba_end": p.lba_end,
                    "lba_size": p.lba_size,
                    "size_bytes": p.size_bytes,
                }
                for p in partitions
            ],
        }, indent=2))
        return

    fields: list[tuple[int, int, str, str]] = [
        (0,   446, "Bootstrap code", f"{len(rec.bootstrap)} bytes"),
        (440,   4, "Disk signature", f"0x{rec.disk_signature:08X}"),
        (444,   2, "Reserved",       f"0x{rec.reserved:04X}"),
    ]
    for i, p in enumerate(rec.partitions):
        off = 446 + i * 16
        fields += [
            (off,      1, f"P{i} Status",    f"0x{p.status:02X} ({'Active' if p.active else 'Inactive'})"),
            (off + 1,  3, f"P{i} CHS First", f"H={p.chs_first[0]} S={p.chs_first[1]} C={p.chs_first[2]}"),
            (off + 4,  1, f"P{i} Type",      f"0x{p.type_code:02X}  {p.type_name}"),
            (off + 5,  3, f"P{i} CHS Last",  f"H={p.chs_last[0]} S={p.chs_last[1]} C={p.chs_last[2]}"),
            (off + 8,  4, f"P{i} LBA Start", str(p.lba_start)),
            (off + 12, 4, f"P{i} LBA Size",  f"{p.lba_size} sectors ({p.size_bytes:,} bytes)"),
        ]
    fields.append((510, 2, "Boot signature", f"0x{rec.boot_signature:04X} ({'Valid' if rec.signature_valid else 'INVALID'})"))
    render_hex_table(data, fields, title="Master Boot Record", console=console)

    table = Table(title="Partition Entries", box=box.ROUNDED, show_header=True, header_style="bold")
    for col, kw in zip(_MBR_HEADERS, [{}, {}, {}, {}, {"justify": "right"}, {"justify": "right"}, {"justify": "right"}, {"justify": "right"}]):
        table.add_column(col, **kw)

    csv_rows: list[list[str]] = []
    for p in partitions:
        row = [
            str(p.index),
            "Active" if p.active else "Inactive",
            f"0x{p.type_code:02X}",
            p.type_name,
            str(p.lba_start),
            str(p.lba_end),
            str(p.lba_size),
            str(p.size_bytes),
        ]
        table.add_row(*row)
        csv_rows.append(row)

    console.print(table)
    _write_csv(csv_out, _MBR_HEADERS, csv_rows, console)


@app.command()
def gpt(
    file: Path = typer.Argument(..., help="Path to GPT dump (≥1024 bytes)", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export partition table to CSV"),
) -> None:
    """Parse a GUID Partition Table."""
    console = context.get_console()
    data = file.read_bytes()
    rec = gpt_parser.parse(data)
    h = rec.header

    if context.output_json:
        print(json.dumps({
            "header": {
                "signature": h.signature.decode(),
                "revision": f"0x{h.revision:08X}",
                "header_size": h.header_size,
                "current_lba": h.current_lba,
                "backup_lba": h.backup_lba,
                "first_usable_lba": h.first_usable_lba,
                "last_usable_lba": h.last_usable_lba,
                "disk_guid": h.disk_guid,
                "num_partitions": h.num_partitions,
            },
            "partitions": [
                {
                    "index": p.index,
                    "name": p.name,
                    "type": p.type_name,
                    "first_lba": p.first_lba,
                    "last_lba": p.last_lba,
                    "size_bytes": p.size_bytes,
                    "guid": p.unique_guid,
                }
                for p in rec.partitions
            ],
        }, indent=2))
        return

    hdr_off = 512
    fields: list[tuple[int, int, str, str]] = [
        (hdr_off,      8,  "Signature",        h.signature.decode()),
        (hdr_off + 8,  4,  "Revision",         f"0x{h.revision:08X}"),
        (hdr_off + 12, 4,  "Header size",      f"{h.header_size} bytes"),
        (hdr_off + 16, 4,  "Header CRC32",     f"0x{h.header_crc32:08X}"),
        (hdr_off + 20, 4,  "Reserved",         "0x00000000"),
        (hdr_off + 24, 8,  "Current LBA",      str(h.current_lba)),
        (hdr_off + 32, 8,  "Backup LBA",       str(h.backup_lba)),
        (hdr_off + 40, 8,  "First usable LBA", str(h.first_usable_lba)),
        (hdr_off + 48, 8,  "Last usable LBA",  str(h.last_usable_lba)),
        (hdr_off + 56, 16, "Disk GUID",        h.disk_guid),
        (hdr_off + 72, 8,  "Partition LBA",    str(h.partition_array_lba)),
        (hdr_off + 80, 4,  "# partitions",     str(h.num_partitions)),
        (hdr_off + 84, 4,  "Entry size",       f"{h.partition_entry_size} bytes"),
        (hdr_off + 88, 4,  "Array CRC32",      f"0x{h.partition_array_crc32:08X}"),
    ]
    render_hex_table(data[hdr_off: hdr_off + 92], fields, title="GPT Header (LBA 1)", console=console)

    table = Table(title="GPT Partition Entries", box=box.ROUNDED, header_style="bold")
    for col, kw in zip(_GPT_HEADERS, [{}, {}, {}, {"justify": "right"}, {"justify": "right"}, {"justify": "right"}, {}]):
        table.add_column(col, **kw)

    csv_rows: list[list[str]] = []
    for p in rec.partitions:
        row = [
            str(p.index),
            p.name or "",
            p.type_name,
            str(p.first_lba),
            str(p.last_lba),
            str(p.size_bytes),
            p.unique_guid,
        ]
        table.add_row(*row)
        csv_rows.append(row)

    console.print(table)
    _write_csv(csv_out, _GPT_HEADERS, csv_rows, console)


def _write_csv(path: Optional[Path], headers: list[str], rows: list[list[str]], console) -> None:
    if path is None:
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(rows)
    console.print(f"[green]✓ Exported {len(rows)} row(s) → {path}[/green]")


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
