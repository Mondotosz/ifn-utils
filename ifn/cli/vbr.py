from __future__ import annotations
import json
from pathlib import Path

import typer

from ifn import context
from ifn.parsers import fat32 as fat32_parser
from ifn.parsers import ntfs_vbr as ntfs_vbr_parser
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse Volume Boot Records")


@app.command()
def parse(file: Path = typer.Argument(..., help="Path to 512-byte VBR dump", exists=True)) -> None:
    """Parse a FAT32 Volume Boot Record (BIOS Parameter Block)."""
    console = context.get_console()
    data = file.read_bytes()
    v = fat32_parser.parse(data)

    if context.output_json:
        print(json.dumps({
            "oem_id": v.oem_id,
            "bytes_per_sector": v.bytes_per_sector,
            "sectors_per_cluster": v.sectors_per_cluster,
            "cluster_size_bytes": v.cluster_size_bytes,
            "reserved_sectors": v.reserved_sectors,
            "num_fats": v.num_fats,
            "root_entry_count": v.root_entry_count,
            "total_sectors_16": v.total_sectors_16,
            "media_type": f"0x{v.media_type:02X}",
            "media_name": v.media_name,
            "fat_size_16": v.fat_size_16,
            "sectors_per_track": v.sectors_per_track,
            "num_heads": v.num_heads,
            "hidden_sectors": v.hidden_sectors,
            "total_sectors_32": v.total_sectors_32,
            "fat_size_32": v.fat_size_32,
            "ext_flags": f"0x{v.ext_flags:04X}",
            "fs_version": f"{v.fs_version >> 8}.{v.fs_version & 0xFF}",
            "root_cluster": v.root_cluster,
            "fs_info_sector": v.fs_info_sector,
            "backup_boot_sector": v.backup_boot_sector,
            "drive_number": f"0x{v.drive_number:02X}",
            "boot_signature": f"0x{v.boot_signature:02X}",
            "volume_id": f"0x{v.volume_id:08X}",
            "volume_label": v.volume_label,
            "fs_type": v.fs_type,
            "signature_valid": v.signature_valid,
        }, indent=2))
        return

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
    render_hex_table(data, fields, title=f"FAT32 VBR — {file.name}", console=console)


@app.command()
def ntfs(
    file: Path = typer.Argument(..., help="Path to a 512-byte NTFS VBR dump (or larger file)",
                                 exists=True),
    offset: int = typer.Option(0, "--offset", "-o",
                                help="Partition start in sectors (e.g. 128 → seeks to byte 65536)"),
) -> None:
    """Parse an NTFS Volume Boot Record (jump code, BPB, $MFT/$MFTMirr LCN, serial, …)."""
    console = context.get_console()
    with file.open("rb") as f:
        f.seek(offset * 512)
        data = f.read(512)
    if len(data) < 512:
        console.print(f"[red]Could not read 512 bytes at offset {offset}.[/red]")
        raise typer.Exit(1)

    v = ntfs_vbr_parser.parse(data)
    if not v.is_ntfs:
        console.print(f"[yellow]Warning: OEM ID is {v.oem_id!r}, not 'NTFS    '.[/yellow]")

    if context.output_json:
        print(json.dumps({
            "oem_id":               v.oem_id,
            "jump_code":            v.jump_code.hex(),
            "bytes_per_sector":     v.bytes_per_sector,
            "sectors_per_cluster":  v.sectors_per_cluster,
            "cluster_size":         v.cluster_size,
            "media_descriptor":     f"0x{v.media_descriptor:02X}",
            "sectors_per_track":    v.sectors_per_track,
            "num_heads":            v.num_heads,
            "hidden_sectors":       v.hidden_sectors,
            "total_sectors":        v.total_sectors,
            "volume_size_bytes":    v.volume_size_bytes,
            "mft_lcn":              v.mft_lcn,
            "mft_offset_bytes":     v.mft_offset_bytes,
            "mftmirr_lcn":          v.mftmirr_lcn,
            "mftmirr_offset_bytes": v.mftmirr_offset_bytes,
            "mft_record_size_raw":  v.mft_record_size_raw,
            "mft_record_size":      v.mft_record_size,
            "index_buffer_size_raw":v.index_buffer_size_raw,
            "index_buffer_size":    v.index_buffer_size,
            "volume_serial":        f"0x{v.volume_serial:016X}",
            "volume_serial_short":  ntfs_vbr_parser.fmt_serial(v.volume_serial),
            "checksum":             f"0x{v.checksum:08X}",
            "signature":            f"0x{v.signature:04X}",
            "signature_valid":      v.signature_valid,
            "is_ntfs":              v.is_ntfs,
        }, indent=2))
        return

    fields: list[tuple[int, int, str, str]] = [
        (0x00,  3, "Jump code",         v.jump_code.hex(" ").upper()),
        (0x03,  8, "OEM ID",            repr(v.oem_id)),
        (0x0B,  2, "Bytes per sector",  str(v.bytes_per_sector)),
        (0x0D,  1, "Sectors/cluster",   f"{v.sectors_per_cluster}  ({v.cluster_size} B/cluster)"),
        (0x15,  1, "Media descriptor",  f"0x{v.media_descriptor:02X}"),
        (0x18,  2, "Sectors/track",     str(v.sectors_per_track)),
        (0x1A,  2, "Heads",             str(v.num_heads)),
        (0x1C,  4, "Hidden sectors",    str(v.hidden_sectors)),
        (0x28,  8, "Total sectors",     f"{v.total_sectors:,}  ({v.volume_size_bytes / 2**30:.2f} GiB)"),
        (0x30,  8, "$MFT LCN",          f"{v.mft_lcn}  → byte offset {v.mft_offset_bytes:,}"),
        (0x38,  8, "$MFTMirr LCN",      f"{v.mftmirr_lcn}  → byte offset {v.mftmirr_offset_bytes:,}"),
        (0x40,  1, "MFT record size",   f"{v.mft_record_size_raw} (signed) → {v.mft_record_size} B"),
        (0x44,  1, "Index buffer size", f"{v.index_buffer_size_raw} (signed) → {v.index_buffer_size} B"),
        (0x48,  8, "Volume serial",     f"0x{v.volume_serial:016X}  "
                                          f"(vol: {ntfs_vbr_parser.fmt_serial(v.volume_serial)})"),
        (0x50,  4, "Checksum",          f"0x{v.checksum:08X}"),
        (0x1FE, 2, "Signature",         f"0x{v.signature:04X}  "
                                          f"({'OK' if v.signature_valid else 'INVALID'})"),
    ]
    render_hex_table(data, fields, title=f"NTFS VBR — {file.name}", console=console)
