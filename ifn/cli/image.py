from pathlib import Path
from typing import Optional
import re
import subprocess
import sys

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

app = typer.Typer(help="Work with EWF/E01 disk images")
console = Console()


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=check)
    except FileNotFoundError:
        console.print(f"[red]Tool not found: {cmd[0]}. Run 'tool deps check'.[/red]")
        raise typer.Exit(1)
    except subprocess.CalledProcessError as e:
        console.print(f"[red]{cmd[0]} failed (exit {e.returncode}):[/red]")
        if e.stderr:
            console.print(e.stderr)
        raise typer.Exit(1)


@app.command()
def info(file: Path = typer.Argument(..., help="Path to .E01 image", exists=True)):
    """Run ewfinfo and display image metadata."""
    result = _run(["ewfinfo", str(file)])
    table = Table(title=f"EWF Info — {file.name}", box=box.ROUNDED, header_style="bold")
    table.add_column("Field")
    table.add_column("Value")
    for line in result.stdout.splitlines():
        if ":" in line and not line.strip().startswith("ewf"):
            key, _, val = line.partition(":")
            k = key.strip()
            v = val.strip()
            if k and v:
                table.add_row(k, v)
    console.print(table)


@app.command()
def mmls(file: Path = typer.Argument(..., help="Path to .E01 image", exists=True)):
    """Run mmls and display the partition table."""
    result = _run(["mmls", str(file)])
    lines = result.stdout.splitlines()

    # Parse header lines (before the table)
    header_lines = []
    table_lines = []
    in_table = False
    for line in lines:
        if re.match(r"^\s*\d{3}:", line):
            in_table = True
        if in_table:
            table_lines.append(line)
        else:
            header_lines.append(line)

    for h in header_lines:
        if h.strip():
            console.print(f"[dim]{h}[/dim]")

    pt = Table(title=f"Partition Table — {file.name}", box=box.ROUNDED, header_style="bold")
    pt.add_column("Slot")
    pt.add_column("Start", justify="right")
    pt.add_column("End", justify="right")
    pt.add_column("Length", justify="right")
    pt.add_column("Description")

    for line in table_lines:
        # Format: "NNN:  SLOT_TYPE  START  END  LENGTH  DESCRIPTION"
        m = re.match(r"(\d{3}):\s+([\w:/-]+)\s+(\d+)\s+(\d+)\s+(\d+)\s*(.*)", line)
        if m:
            num, slot_type, start, end, length, desc = m.groups()
            pt.add_row(f"{num} ({slot_type})", start, end, length, desc.strip())

    console.print(pt)


@app.command()
def fls(
    file: Path = typer.Argument(..., help="Path to .E01 image", exists=True),
    inode: Optional[str] = typer.Argument(None, help="Partition offset (from mmls Start column) or inode"),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Partition start sector offset"),
):
    """Run fls to list files in a partition."""
    cmd = ["fls"]
    if offset is not None:
        cmd += ["-o", str(offset)]
    elif inode and inode.isdigit():
        cmd += ["-o", inode]
    cmd.append(str(file))

    result = _run(cmd)
    ft = Table(title=f"File Listing — {file.name}", box=box.SIMPLE, header_style="bold")
    ft.add_column("Type")
    ft.add_column("Inode")
    ft.add_column("Name")

    for line in result.stdout.splitlines():
        if line.strip():
            parts = line.split(None, 2)
            if len(parts) >= 3:
                ft.add_row(parts[0], parts[1].rstrip(":"), parts[2])
            else:
                ft.add_row("", "", line)
    console.print(ft)


@app.command()
def icat(
    file: Path = typer.Argument(..., help="Path to .E01 image", exists=True),
    inode: str = typer.Argument(..., help="Inode number (from fls)"),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Partition start sector offset"),
    output: Optional[Path] = typer.Option(None, "--output", "-O", help="Save to file instead of stdout"),
):
    """Run icat to extract a file from the image."""
    cmd = ["icat"]
    if offset is not None:
        cmd += ["-o", str(offset)]
    cmd += [str(file), inode]

    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        console.print(f"[red]icat failed: {result.stderr.decode(errors='replace')}[/red]")
        raise typer.Exit(1)

    if output:
        output.write_bytes(result.stdout)
        console.print(f"[green]Saved {len(result.stdout):,} bytes to {output}[/green]")
    else:
        sys.stdout.buffer.write(result.stdout)


@app.command()
def unlock(
    file: Path = typer.Argument(..., help="Path to .E01 image", exists=True),
    slot: int = typer.Argument(..., help="Partition slot number (Start value from mmls)"),
    name: str = typer.Argument(..., help="Name for the mapper device (e.g. bitlocker_partition)"),
    ewf_dir: Path = typer.Option(Path("ewf"), "--ewf-dir", help="Directory to mount the EWF image"),
    loop_dev: str = typer.Option("/dev/loop0", "--loop", help="Loop device to use"),
):
    """Mount EWF image and unlock a BitLocker partition with cryptsetup (requires sudo).

    Equivalent to:
      sudo ewfmount <file> <ewf_dir>
      sudo losetup -o <slot*512> <loop_dev> <ewf_dir>/ewf1
      sudo cryptsetup bitlkOpen <loop_dev> <name>
    """
    ewf_path = ewf_dir / "ewf1"
    byte_offset = slot * 512

    console.print(Panel(
        f"[bold]Image:[/bold]       {file}\n"
        f"[bold]Partition:[/bold]   slot {slot} → byte offset {byte_offset:,}  ({slot} × 512)\n"
        f"[bold]EWF mount:[/bold]   {ewf_dir}\n"
        f"[bold]Loop device:[/bold] {loop_dev}\n"
        f"[bold]Mapper name:[/bold] /dev/mapper/{name}",
        title="BitLocker Unlock Plan",
    ))

    console.print(f"\n[yellow]Step 1:[/yellow] sudo ewfmount {file} {ewf_dir}")
    r = _run(["sudo", "ewfmount", str(file), str(ewf_dir)])

    console.print(f"[yellow]Step 2:[/yellow] sudo losetup -o {byte_offset} {loop_dev} {ewf_path}")
    _run(["sudo", "losetup", "-o", str(byte_offset), loop_dev, str(ewf_path)])

    console.print(f"[yellow]Step 3:[/yellow] sudo cryptsetup bitlkOpen {loop_dev} {name}")
    # Run without capture so the passphrase prompt is visible
    result = subprocess.run(["sudo", "cryptsetup", "bitlkOpen", loop_dev, name])
    if result.returncode != 0:
        console.print("[red]cryptsetup failed. Run cleanup manually or use 'tool image lock'.[/red]")
        raise typer.Exit(1)

    console.print(f"\n[green]✓ BitLocker partition available at /dev/mapper/{name}[/green]")
    console.print(f"[dim]Mount with: sudo mount /dev/mapper/{name} <mountpoint>[/dim]")
    console.print(f"[dim]Cleanup with: tool image lock {name} <mountpoint> {loop_dev} {ewf_dir}[/dim]")


@app.command()
def lock(
    name: str = typer.Argument(..., help="Mapper device name (from unlock)"),
    mountpoint: str = typer.Argument(..., help="Path where partition is mounted (use NONE if not mounted)"),
    loop: str = typer.Argument(..., help="Loop device path (e.g. /dev/loop0)"),
    ewf_mount: str = typer.Argument(..., help="Path where EWF is mounted (e.g. ./ewf)"),
):
    """Cleanup: unmount, close BitLocker, detach loop device, unmount EWF."""
    steps = []
    if mountpoint.upper() != "NONE":
        steps.append(["sudo", "umount", mountpoint])
    steps += [
        ["sudo", "cryptsetup", "close", name],
        ["sudo", "losetup", "-d", loop],
        ["sudo", "umount", ewf_mount],
    ]

    for cmd in steps:
        console.print(f"[yellow]Running:[/yellow] {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            console.print(f"[red]  ✗ {r.stderr.strip() or 'failed'}[/red]")
        else:
            console.print(f"[green]  ✓ ok[/green]")


@app.command()
def dump(
    mapper: str = typer.Argument(..., help="Path to mapper device (e.g. /dev/mapper/name)"),
    output: str = typer.Argument(..., help="Output E01 base path (without extension)"),
):
    """Acquire a decrypted BitLocker partition to a new E01 with ewfacquire."""
    console.print(Panel(
        f"[bold]Source:[/bold]  {mapper}\n"
        f"[bold]Output:[/bold]  {output}.E01\n\n"
        f"[dim]ewfacquire will prompt for acquisition parameters.[/dim]",
        title="EWF Acquire",
    ))
    console.print(f"[yellow]Running:[/yellow] sudo ewfacquire -t {output} {mapper}")
    # Run interactively so ewfacquire can prompt for parameters
    result = subprocess.run(["sudo", "ewfacquire", "-t", output, mapper])
    if result.returncode != 0:
        console.print("[red]ewfacquire failed.[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Acquisition complete: {output}.E01[/green]")
