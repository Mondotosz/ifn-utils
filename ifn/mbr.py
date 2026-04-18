import typer
from typing import Annotated
from pathlib import Path
import struct
from .utils import console
from rich.console import Group, RenderableType
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule

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
    return disk_id[::-1].hex().upper()


@mbr_app.command("analyze")
def analyze(
    file: Annotated[Path, typer.Argument(help="Path to the MBR dump", exists=True)],
):
    data = file.read_bytes()
    if len(data) < 512:
        typer.secho("Error: File must be 512 bytes.", fg="red")
        raise typer.Exit(1)

    disk_id = parse_mbr_id(data)

    # MBR Signature at 0x1FE
    sig = data[510:512]

    is_gpt_protective = any(data[0x1BE + (i * 16) + 4] == 0xEE for i in range(4))
    label_type = "gpt (protective)" if is_gpt_protective else "dos"

    header_table = Table(
        show_header=True,
        box=None,
        header_style="bold yellow",
    )
    header_table.add_column("Field", style="magenta")
    header_table.add_column("Offset", justify="center")
    header_table.add_column("Value", style="green")

    header_table.add_row("Disklabel type", "", label_type)
    header_table.add_row("MBR Disk Identifier", hex(0x1B8), disk_id)
    header_table.add_row("MBR Signature", hex(0x1FE), sig.hex().upper())

    console.print(
        Panel(
            header_table,
            title="[bold cyan]MBR headers[/bold cyan]",
            border_style="bright_blue",
            expand=False,
        )
    )

    parts: list[RenderableType] = []
    for i in range(4):
        base = 0x1BE + (i * 16)
        p = data[base : base + 16]

        p_type_id = p[4]
        if p_type_id == 0x00:  # Skip empty
            parts.append(
                Rule(title=f"[bold red]No partition #{i}[/bold red]", style="red")
            )
            continue

        # Extracting LBA values (Little Endian 4-byte integers)
        lba_start = struct.unpack("<I", p[8:12])[0]
        lba_total = struct.unpack("<I", p[12:16])[0]
        mode = get_addressing_mode(p_type_id, lba_start)
        type_name = get_type_name(p_type_id)

        # Extracting CHS values
        start_c, start_h, start_s = parse_chs(p[1:4])
        end_c, end_h, end_s = parse_chs(p[5:8])

        part_table = Table(
            box=None,
            show_header=True,
            header_style="bold yellow",
        )
        part_table.add_column("Field", width=25)
        part_table.add_column("Offset", width=8)
        part_table.add_column("Value")

        part_table.add_row(
            "Boot Flag",
            hex(base),
            f"{hex(p[0])} ({'Bootable' if p[0] == 0x80 else 'No'})",
        )
        part_table.add_row(
            "Partition Type", hex(base + 4), f"{hex(p_type_id)} ({type_name})"
        )

        part_table.add_row("[LBA] Relative Sector", hex(base + 8), str(lba_start))
        part_table.add_row("[LBA] Total Sectors", hex(base + 12), str(lba_total))
        part_table.add_row("[CHS Start] Head", hex(base + 1), str(start_h))
        part_table.add_row(
            "[CHS Start] Cyl/Sec", hex(base + 2), f"C:{start_c} S:{start_s}"
        )
        part_table.add_row("[CHS End] Head", hex(base + 5), hex(end_h))
        part_table.add_row("[CHS End] Cyl/Sec", hex(base + 6), f"C:{end_c} S:{end_s}")

        parts.append(
            Panel(
                part_table,
                title=f"[bold yellow]Partition #{i + 1} [{mode} Mode][/bold yellow]",
                subtitle=f"Offset: {hex(base)}",
                border_style="yellow",
            )
        )

    console.print(
        Panel(
            Group(*parts),
            expand=False,
            title="[bold cyan]Partition Table Entries[/bold cyan]",
            border_style="bright_blue",
        )
    )
