from pathlib import Path

import typer
from rich.console import Console

from ifn.parsers import fat32 as fat32_parser
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse Volume Boot Records")
console = Console()


@app.command()
def parse(file: Path = typer.Argument(..., help="Path to 512-byte VBR dump", exists=True)):
    """Parse a FAT32 Volume Boot Record (BIOS Parameter Block)."""
    data = file.read_bytes()
    v = fat32_parser.parse(data)

    fields: list[tuple[int, int, str, str]] = [
        (0,   3,  "Jump instruction",      data[0:3].hex(" ").upper()),
        (3,   8,  "OEM ID",                v.oem_id),
        (11,  2,  "Bytes per sector",      str(v.bytes_per_sector)),
        (13,  1,  "Sectors per cluster",   f"{v.sectors_per_cluster}  ({v.cluster_size_bytes} bytes/cluster)"),
        (14,  2,  "Reserved sectors",      str(v.reserved_sectors)),
        (16,  1,  "Number of FATs",        str(v.num_fats)),
        (17,  2,  "Root entry count",      str(v.root_entry_count)),
        (19,  2,  "Total sectors (16-bit)",str(v.total_sectors_16) + (" (use 32-bit field)" if v.total_sectors_16 == 0 else "")),
        (21,  1,  "Media type",            f"0x{v.media_type:02X}  {v.media_name}"),
        (22,  2,  "FAT size (16-bit)",     str(v.fat_size_16) + (" (FAT32: see offset 36)" if v.fat_size_16 == 0 else "")),
        (24,  2,  "Sectors per track",     str(v.sectors_per_track)),
        (26,  2,  "Number of heads",       str(v.num_heads)),
        (28,  4,  "Hidden sectors",        str(v.hidden_sectors)),
        (32,  4,  "Total sectors (32-bit)",str(v.total_sectors_32)),
        # FAT32 extended BPB
        (36,  4,  "FAT size (32-bit)",     f"{v.fat_size_32} sectors"),
        (40,  2,  "Ext flags",             f"0x{v.ext_flags:04X}"),
        (42,  2,  "FS version",            f"{v.fs_version >> 8}.{v.fs_version & 0xFF}"),
        (44,  4,  "Root cluster",          str(v.root_cluster)),
        (48,  2,  "FS Info sector",        str(v.fs_info_sector)),
        (50,  2,  "Backup boot sector",    str(v.backup_boot_sector)),
        (64,  1,  "Drive number",          f"0x{v.drive_number:02X}"),
        (66,  1,  "Boot signature",        f"0x{v.boot_signature:02X}"),
        (67,  4,  "Volume ID",             f"0x{v.volume_id:08X}"),
        (71,  11, "Volume label",          v.volume_label),
        (82,  8,  "FS type",               v.fs_type),
        (510, 2,  "Sector signature",      f"0x{v.signature:04X} ({'Valid' if v.signature_valid else 'INVALID'})"),
    ]

    render_hex_table(data, fields, title=f"FAT32 VBR — {file.name}")
