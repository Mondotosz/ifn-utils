import typer
from typing import Annotated
from pathlib import Path
import struct
import uuid

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
        typer.secho("Valid GPT Header not found at LBA 1", fg="red", bold=True)
        return

    # --- Print Header Information ---
    typer.secho("\n=== GPT Header (LBA 1) ===", fg="cyan", bold=True)
    print(f"{'Field':<25} | {'Offset':<8} | {'Value'}")
    print("-" * 55)
    print(f"{'Signature':<25} | 0x200    | EFI PART")
    print(f"{'Disk GUID':<25} | 0x238    | {header['disk_guid']}")  # Added Disk GUID
    print(f"{'Current LBA':<25} | 0x218    | {header['current_lba']}")
    print(f"{'First Usable LBA':<25} | 0x228    | {header['first_usable']}")
    print(f"{'Last Usable LBA':<25} | 0x230    | {header['last_usable']}")
    print(f"{'Number of Entries':<25} | 0x250    | {header['num_entries']}")
    print(f"{'Entry Size':<25} | 0x254    | {header['entry_size']} bytes")
    print("\n")

    # --- Print Partition Table Entries ---
    typer.secho("=== Partition Table Entries ===", fg="cyan", bold=True)

    # Partition entries start at LBA 2 (Offset 1024)
    start_offset = 1024
    found_any = False

    for i in range(header["num_entries"]):
        entry_offset = start_offset + (i * header["entry_size"])

        # Guard against reading past file end
        if entry_offset + header["entry_size"] > len(data):
            break

        entry_data = data[entry_offset : entry_offset + header["entry_size"]]
        part = parse_gpt_partition(entry_data)

        if part:
            found_any = True
            typer.secho(
                f"\nPartition #{i} at offset {hex(entry_offset)}",
                fg="yellow",
                bold=True,
            )
            print(f"{'Field':<25} | {'Offset':<8} | {'Value'}")
            print("-" * 75)

            # Name logic
            name_val = part["name"] if part["name"] else "[No Name]"

            print(
                f"{'Partition Name':<25} | {hex(entry_offset + 0x38):<8} | {name_val}"
            )
            print(f"{'Type GUID':<25} | {hex(entry_offset + 0x00):<8} | {part['type']}")
            print(
                f"{'Unique GUID':<25} | {hex(entry_offset + 0x10):<8} | {part['uuid']}"
            )
            print(
                f"{'First LBA':<25} | {hex(entry_offset + 0x20):<8} | {part['first_lba']}"
            )
            print(
                f"{'Last LBA':<25} | {hex(entry_offset + 0x28):<8} | {part['last_lba']}"
            )
            print(
                f"{'Total Sectors':<25} | {hex(entry_offset + 0x28):<8} | {part['size_sectors']}"
            )

            # Human readable size (not a direct disk value, but useful)
            size_mib = (part["size_sectors"] * 512) / 1024 / 1024
            print(f"{'Calculated Size':<25} | {'N/A':<8} | {size_mib:.2f} MiB")
            print("-" * 75)

    if not found_any:
        typer.echo("No active partitions found in the table.")
