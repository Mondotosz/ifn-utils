import typer
from typing import Annotated
from pathlib import Path
import struct
from .utils import format_offset

mbr_app = typer.Typer(help="MBR specific tools")

# Mapping of common MBR Partition Type IDs
PARTITION_TYPES = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 (small)",
    0x05: "Extended Partition (CHS)",
    0x06: "FAT16B",
    0x07: "NTFS / exFAT / HPFS",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16B (LBA)",
    0x0F: "Extended Partition (LBA)",
    0x11: "Hidden FAT12",
    0x17: "Hidden NTFS",
    0x27: "Windows Recovery Environment",
    0x42: "Windows Dynamic Volume",
    0x82: "Linux Swap",
    0x83: "Linux Native (ext2/3/4, etc.)",
    0x85: "Linux Extended",
    0x87: "NTFS volume set",
    0x8E: "Linux LVM",
    0xA5: "FreeBSD",
    0xA6: "OpenBSD",
    0xA8: "Mac OS X",
    0xAF: "HFS / HFS+",
    0xBE: "Solaris Boot",
    0xEE: "GPT Protective MBR",
    0xEF: "EFI System Partition",
}


def get_type_name(p_type: int) -> str:
    return PARTITION_TYPES.get(p_type, "Unknown / Unlisted")


def parse_chs(raw_3bytes: bytes):
    """
    Parses the 3-byte CHS format.
    Byte 0: Head
    Byte 1: Sector (bits 0-5), Cylinder high (bits 6-7)
    Byte 2: Cylinder low (bits 0-7)
    """
    h = raw_3bytes[0]
    s = raw_3bytes[1] & 0x3F
    # Cylinder is 10 bits: top 2 bits from sector byte + all 8 bits of cylinder byte
    c = ((raw_3bytes[1] & 0xC0) << 2) | raw_3bytes[2]
    return c, h, s


def get_addressing_mode(p_type: int, start_lba: int) -> str:
    """
    Identifies if the partition primarily uses LBA or CHS.
    0x0B, 0x0C, 0x0E, 0x0F, 0xEE (GPT), etc., are typically LBA.
    Additionally, if LBA start is > 0, modern OSs treat it as LBA.
    """
    # Specific LBA-only types
    lba_types = {0x0C, 0x0E, 0x0F, 0xEE, 0xEF}
    if p_type in lba_types or start_lba >= 16450560:  # Max CHS addressable sectors
        return "LBA"
    return "CHS/Legacy"


def parse_mbr_id(data: bytes):
    # Located at offset 440 (0x1B8), 4 bytes long
    disk_id = data[440:444]
    return disk_id.hex().upper()


@mbr_app.command("analyze")
def analyze(
    file: Annotated[Path, typer.Argument(help="Path to the MBR dump", exists=True)],
):
    data = file.read_bytes()
    if len(data) < 512:
        typer.secho("Error: File must be 512 bytes.", fg="red")
        raise typer.Exit(1)

    disk_id = parse_mbr_id(data)
    typer.secho(f"MBR Disk Identifier: {disk_id} at 0x1B8", fg="cyan", bold=True)

    # MBR Signature at 0x1FE
    sig = data[510:512]
    typer.secho(
        f"MBR Signature: {sig[::-1].hex().upper()} at 0x1FE", fg="cyan", bold=True
    )
    print("=" * 60)

    for i in range(4):
        base = 0x1BE + (i * 16)
        p = data[base : base + 16]

        p_type_id = p[4]
        if p_type_id == 0x00:  # Skip empty
            continue

        # Extracting LBA values (Little Endian 4-byte integers)
        lba_start = struct.unpack("<I", p[8:12])[0]
        lba_total = struct.unpack("<I", p[12:16])[0]
        mode = get_addressing_mode(p_type_id, lba_start)
        type_name = get_type_name(p_type_id)

        # Extracting CHS values
        start_c, start_h, start_s = parse_chs(p[1:4])
        end_c, end_h, end_s = parse_chs(p[5:8])
        typer.secho(f"Partition #{i + 1} [{mode} Mode]", fg="yellow", bold=True)

        # Table of information
        print(f"{'Field':<25} | {'Offset':<8} | {'Value'}")
        print("-" * 50)
        print(
            f"{'Boot Flag':<25} | {format_offset(base):<8} | {hex(p[0])} ({'Bootable' if p[0] == 0x80 else 'No'})"
        )
        print(
            f"{'Partition Type':<25} | {format_offset(base + 4):<8} | {hex(p_type_id)} ({type_name})"
        )

        print(
            f"{'[LBA] Relative Sector':<25} | {format_offset(base + 8):<8} | {lba_start}"
        )
        print(
            f"{'[LBA] Total Sectors':<25} | {format_offset(base + 12):<8} | {lba_total}"
        )

        print(f"{'[CHS Start] Head':<25} | {format_offset(base + 1):<8} | {start_h}")
        print(
            f"{'[CHS Start] Cyl/Sec':<25} | {format_offset(base + 2):<8} | C:{start_c} S:{start_s}"
        )

        print(f"{'[CHS End] Head':<25} | {format_offset(base + 5):<8} | {end_h}")
        print(
            f"{'[CHS End] Cyl/Sec':<25} | {format_offset(base + 6):<8} | C:{end_c} S:{end_s}"
        )
        print("\n")
