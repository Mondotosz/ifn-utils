from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from ifn.parsers import mbr as mbr_parser
from ifn.parsers import gpt as gpt_parser
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse MBR and GPT partition tables")
console = Console()


@app.command()
def mbr(file: Path = typer.Argument(..., help="Path to 512-byte MBR dump", exists=True)):
    """Parse a Master Boot Record partition table."""
    data = file.read_bytes()
    rec = mbr_parser.parse(data)

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

    render_hex_table(data, fields, title="Master Boot Record")

    table = Table(title="Partition Entries", box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("#", justify="center")
    table.add_column("Status")
    table.add_column("Type")
    table.add_column("LBA Start", justify="right")
    table.add_column("LBA End", justify="right")
    table.add_column("Sectors", justify="right")
    table.add_column("Size")

    for p in rec.partitions:
        if p.type_code == 0x00 and p.lba_start == 0:
            continue
        table.add_row(
            str(p.index),
            "[green]Active[/green]" if p.active else "Inactive",
            f"0x{p.type_code:02X}  {p.type_name}",
            str(p.lba_start),
            str(p.lba_end),
            str(p.lba_size),
            _human_size(p.size_bytes),
        )

    console.print(table)


@app.command()
def gpt(file: Path = typer.Argument(..., help="Path to GPT dump (≥1024 bytes)", exists=True)):
    """Parse a GUID Partition Table."""
    data = file.read_bytes()
    rec = gpt_parser.parse(data)
    h = rec.header

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

    render_hex_table(data[hdr_off: hdr_off + 92], fields, title="GPT Header (LBA 1)")

    table = Table(title="GPT Partition Entries", box=box.ROUNDED, header_style="bold")
    table.add_column("#", justify="center")
    table.add_column("Name")
    table.add_column("Type")
    table.add_column("First LBA", justify="right")
    table.add_column("Last LBA", justify="right")
    table.add_column("Size")
    table.add_column("Unique GUID")

    for p in rec.partitions:
        table.add_row(
            str(p.index),
            p.name or "[dim](unnamed)[/dim]",
            p.type_name,
            str(p.first_lba),
            str(p.last_lba),
            _human_size(p.size_bytes),
            p.unique_guid,
        )

    console.print(table)


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
