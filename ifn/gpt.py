import typer
from typing import Annotated
from pathlib import Path
import struct
import uuid
from .utils import console
from rich.console import Group, RenderableType
from rich.table import Table
from rich.panel import Panel


gpt_app = typer.Typer(help="GPT specific tools")


def parse_gpt_header(data: bytes):
    # GPT Header is usually at LBA 1 (Offset 512)
    # Signature is "EFI PART" (8 bytes)
    sig = data[0:8]
    if sig != b"EFI PART":
        return None

    current_lba = struct.unpack("<Q", data[24:32])[0]
    first_usable = struct.unpack("<Q", data[40:48])[0]
    last_usable = struct.unpack("<Q", data[48:56])[0]
    num_entries = struct.unpack("<I", data[80:84])[0]
    entry_size = struct.unpack("<I", data[84:88])[0]
    disk_guid = uuid.UUID(bytes_le=data[56:72])

    return {
        "disk_guid": disk_guid,
        "current_lba": current_lba,
        "first_usable": first_usable,
        "last_usable": last_usable,
        "num_entries": num_entries,
        "entry_size": entry_size,
    }


def parse_gpt_partition(entry: bytes):
    # GUIDs are 16 bytes
    type_guid = uuid.UUID(bytes_le=entry[0:16])
    if type_guid == uuid.UUID(int=0):  # Empty entry
        return None

    unique_guid = uuid.UUID(bytes_le=entry[16:32])
    first_lba = struct.unpack("<Q", entry[32:40])[0]
    last_lba = struct.unpack("<Q", entry[40:48])[0]
    # Name is UTF-16LE, 72 bytes
    name = entry[56:128].decode("utf-16-le").strip("\x00")

    return {
        "name": name,
        "type": type_guid,
        "uuid": unique_guid,
        "first_lba": first_lba,
        "last_lba": last_lba,
        "size_sectors": (last_lba - first_lba) + 1,
    }


@gpt_app.command("analyze")
def gpt_analyze(file: Annotated[Path, typer.Argument(exists=True)]):
    data = file.read_bytes()

    # GPT Header is at LBA 1 (Offset 512)
    header_offset = 512
    header_data = data[header_offset : header_offset + 92]  # Header is 92 bytes min
    header = parse_gpt_header(header_data)

    if not header:
        console.print("[bold red]Valid GPT Header not found at LBA 1[/bold red]")
        return

    # --- Print Header Information ---
    header_table = Table(
        show_header=True,
        box=None,
        header_style="bold yellow",
    )
    header_table.add_column("Field", style="magenta")
    header_table.add_column("Offset", justify="center")
    header_table.add_column("Value", style="green")

    header_table.add_row("Signature", "0x200", "EFI PART")
    header_table.add_row("Current LBA", "0x218", str(header["current_lba"]))
    header_table.add_row("First Usable LBA", "0x228", str(header["first_usable"]))
    header_table.add_row("Last Usable LBA", "0x230", str(header["last_usable"]))
    header_table.add_row("Disk GUID", "0x238", str(header["disk_guid"]))
    header_table.add_row("Number of Entries", "0x250", str(header["num_entries"]))
    header_table.add_row("Entry Size", "0x254", f"{header['entry_size']} bytes")

    console.print(
        Panel(
            header_table,
            title="[bold cyan]GPT Header (LBA 1)[/bold cyan]",
            border_style="bright_blue",
            expand=False,
        )
    )

    # --- Print Partition Table Entries ---

    # Partition entries start at LBA 2 (Offset 1024)
    start_offset = 1024

    parts: list[RenderableType] = []

    for i in range(header["num_entries"]):
        entry_offset = start_offset + (i * header["entry_size"])

        # Guard against reading past file end
        if entry_offset + header["entry_size"] > len(data):
            break

        entry_data = data[entry_offset : entry_offset + header["entry_size"]]
        part = parse_gpt_partition(entry_data)

        if part:
            # Create a table for each partition
            part_table = Table(
                box=None,
                show_header=True,
                header_style="bold yellow",
            )
            part_table.add_column("Field", width=25)
            part_table.add_column("Offset", width=10)
            part_table.add_column("Value")

            size_mib = (part["size_sectors"] * 512) / 1024 / 1024

            part_table.add_row(
                "Partition Name",
                hex(entry_offset + 0x38),
                part["name"] or "[No Name]",
            )
            part_table.add_row("Type GUID", hex(entry_offset), str(part["type"]))
            part_table.add_row(
                "Unique GUID", hex(entry_offset + 0x10), str(part["uuid"])
            )
            part_table.add_row("First LBA", hex(0x4A0), str(part["first_lba"]))
            part_table.add_row("Last LBA", hex(0x4A8), str(part["last_lba"]))
            part_table.add_row("Total sectors", "", str(part["size_sectors"]))
            part_table.add_row(
                "Calculated Size", "", f"[bold green]{size_mib:.2f} MiB[/bold green]"
            )

            # Using a Panel to wrap each partition makes the terminal look like a real UI
            parts.append(
                Panel(
                    part_table,
                    title=f"[bold yellow]Partition #{i}[/bold yellow]",
                    subtitle=f"Offset: {hex(entry_offset)}",
                    border_style="yellow",
                )
            )

    if len(parts):
        console.print(
            Panel(
                Group(*parts),
                expand=False,
                title="[bold cyan]Partition Table Entries[/bold cyan]",
                border_style="bright_blue",
            )
        )
    else:
        console.print("[bold red]No active partitions found in the table.[/bold red]")
