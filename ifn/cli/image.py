from pathlib import Path
from typing import Optional
import re
import subprocess
import sys
import tempfile

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from ifn.parsers import recycle as _recycle_parser
from ifn.parsers.sam import parse_v_blob, extract_user_sid

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


# ---------------------------------------------------------------------------
# Recycle Bin helpers
# ---------------------------------------------------------------------------

def _auto_detect_offset(image: Path) -> int:
    """Find the Windows NTFS partition offset via mmls (largest Basic data partition)."""
    result = _run(["mmls", str(image)], check=False)
    best_start: int | None = None
    best_len = 0
    for line in result.stdout.splitlines():
        m = re.match(r"\d{3}:\s+\S+\s+(\d+)\s+\d+\s+(\d+)\s*(.*)", line)
        if m:
            start, length, desc = int(m.group(1)), int(m.group(2)), m.group(3).strip()
            if "basic data" in desc.lower() and length > best_len:
                best_start, best_len = start, length
    if best_start is None:
        console.print("[red]Could not auto-detect Windows partition. Use --offset.[/red]")
        raise typer.Exit(1)
    return best_start


def _fls_list(offset: int, image: Path, inode: str | None = None) -> list[tuple[str, str, str]]:
    """Run fls and return list of (entry_type, inode_spec, name) tuples."""
    cmd = ["fls", "-o", str(offset), str(image)]
    if inode:
        cmd.append(inode)
    result = subprocess.run(cmd, capture_output=True, text=True)
    entries = []
    for line in result.stdout.splitlines():
        m = re.match(r"([rd]/[rd])\s+(\S+):\t(.+)", line)
        if m:
            entries.append((m.group(1), m.group(2), m.group(3).strip()))
    return entries


def _find_child(offset: int, image: Path, parent: str | None, name: str) -> str | None:
    """Return the inode spec of a named child entry (case-insensitive)."""
    for _, inode, fname in _fls_list(offset, image, parent):
        if fname.lower() == name.lower():
            return inode
    return None


_WELL_KNOWN_SIDS: dict[str, str] = {
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
}


def _build_sid_map(sam_path: Path) -> dict[str, str]:
    """Return {full_sid_string: username} from a SAM hive file."""
    from Registry import Registry

    sid_map = dict(_WELL_KNOWN_SIDS)
    try:
        reg = Registry.Registry(str(sam_path))
        users_key = reg.open("SAM\\Domains\\Account\\Users")
        entries: list[tuple[int, bytes]] = []
        for subkey in users_key.subkeys():
            if subkey.name() == "Names":
                continue
            try:
                rid = int(subkey.name(), 16)
                v_data = subkey.value("V").value()
                entries.append((rid, v_data))
            except Exception:
                pass
        domain_sid: str | None = None
        for rid, v_data in entries:
            sid = extract_user_sid(v_data, rid)
            if sid:
                domain_sid = sid.rsplit("-", 1)[0]
                break
        for rid, v_data in entries:
            v = parse_v_blob(v_data)
            sid = extract_user_sid(v_data, rid) or (f"{domain_sid}-{rid}" if domain_sid else None)
            if sid and v["username"]:
                sid_map[sid] = v["username"]
    except Exception as e:
        console.print(f"[yellow]Warning: SAM parse error: {e}[/yellow]")
    return sid_map


# ---------------------------------------------------------------------------
# recycle command
# ---------------------------------------------------------------------------

@app.command()
def recycle(
    file: Path = typer.Argument(..., help="Path to .E01 image", exists=True),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Partition start sector (auto-detected if omitted)"),
    sam: Optional[Path] = typer.Option(None, "--sam", "-s", help="Local SAM hive to resolve SIDs to usernames"),
    auto_sam: bool = typer.Option(False, "--auto-sam", "-a", help="Auto-extract SAM from the image to resolve SIDs"),
):
    """Analyze all $Recycle.Bin entries from a disk image."""
    if offset is None:
        offset = _auto_detect_offset(file)
        console.print(f"[dim]Auto-detected Windows partition at sector {offset}[/dim]")

    # Find $Recycle.Bin inode
    rb_inode = _find_child(offset, file, None, "$Recycle.Bin")
    if not rb_inode:
        console.print("[red]$Recycle.Bin not found in partition root.[/red]")
        raise typer.Exit(1)

    # Build SID→username map
    sid_map: dict[str, str] = {}
    if sam:
        sid_map = _build_sid_map(sam)
        console.print(f"[dim]SAM loaded from {sam} — {len(sid_map)} SID entries[/dim]")
    elif auto_sam:
        sam_inode = _find_child(offset, file, None, "Windows")
        for step in ["System32", "config", "SAM"]:
            if sam_inode is None:
                break
            sam_inode = _find_child(offset, file, sam_inode, step)
        if sam_inode:
            with tempfile.NamedTemporaryFile(suffix=".SAM", delete=False) as tmp:
                tmp_path = Path(tmp.name)
            try:
                r = subprocess.run(["icat", "-o", str(offset), str(file), sam_inode],
                                   capture_output=True)
                tmp_path.write_bytes(r.stdout)
                sid_map = _build_sid_map(tmp_path)
                console.print(f"[dim]Auto-extracted SAM ({len(r.stdout):,} bytes) — {len(sid_map)} SID entries[/dim]")
            finally:
                tmp_path.unlink(missing_ok=True)
        else:
            console.print("[yellow]Warning: SAM not found on image — SIDs will not be resolved.[/yellow]")

    # Enumerate SID subdirectories and their $I files
    table = Table(title=f"$Recycle.Bin — {file.name}", box=box.ROUNDED, header_style="bold")
    if sid_map:
        table.add_column("User")
    table.add_column("SID")
    table.add_column("$I file")
    table.add_column("Deleted at")
    table.add_column("Orig. size", justify="right")
    table.add_column("Original path")

    for _, sid_inode, sid_name in _fls_list(offset, file, rb_inode):
        username = sid_map.get(sid_name) or _WELL_KNOWN_SIDS.get(sid_name)
        for _, file_inode, fname in _fls_list(offset, file, sid_inode):
            # Only $I index files; skip ADS entries (contain ":")
            if not fname.startswith("$I") or ":" in fname:
                continue
            r = subprocess.run(["icat", "-o", str(offset), str(file), file_inode],
                                capture_output=True)
            if r.returncode != 0:
                continue
            try:
                rec = _recycle_parser.parse_i_file(r.stdout)
                deleted_str = rec.deleted_at.strftime("%Y-%m-%d %H:%M:%S UTC")
                size_str = f"{rec.file_size:,}"
                path_str = rec.original_path
            except Exception as e:
                deleted_str = "[red]parse error[/red]"
                size_str = "?"
                path_str = str(e)

            row: list[str] = []
            if sid_map:
                row.append(username or "[dim]—[/dim]")
            row += [sid_name, fname, deleted_str, size_str, path_str]
            table.add_row(*row)

    if table.row_count == 0:
        console.print("[dim]No $Recycle.Bin entries found.[/dim]")
    else:
        console.print(table)
