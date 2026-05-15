from pathlib import Path, PureWindowsPath
from typing import Optional, Iterator
import re
import struct
import subprocess
import sys
import tempfile

from ifn.parsers.windows_time import filetime_to_datetime

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
    extract: Optional[Path] = typer.Option(None, "--extract", "-e", help="Extract $R files to this directory"),
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

    if extract is not None:
        extract.mkdir(parents=True, exist_ok=True)

    # Enumerate SID subdirectories and their $I/$R file pairs
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

        # Build $R suffix→inode map and collect $I entries in one fls call
        dir_entries = _fls_list(offset, file, sid_inode)
        r_map: dict[str, str] = {
            fname[2:]: inode
            for _, inode, fname in dir_entries
            if fname.startswith("$R") and ":" not in fname
        }

        # Prepare per-SID extract directory (created lazily on first file)
        sid_extract_dir: Path | None = None

        for _, i_inode, i_fname in dir_entries:
            if not i_fname.startswith("$I") or ":" in i_fname:
                continue

            r = subprocess.run(["icat", "-o", str(offset), str(file), i_inode],
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
                rec = None

            row: list[str] = []
            if sid_map:
                row.append(username or "[dim]—[/dim]")
            row += [sid_name, i_fname, deleted_str, size_str, path_str]
            table.add_row(*row)

            # Extract $I and $R files if requested
            if extract is not None and rec is not None:
                suffix = i_fname[2:]  # e.g. "2UXVB4.jpg"
                r_inode = r_map.get(suffix)

                # Create per-user directory on first file
                if sid_extract_dir is None:
                    dir_name = username if username else sid_name
                    sid_extract_dir = extract / dir_name
                    sid_extract_dir.mkdir(parents=True, exist_ok=True)

                    # Write info.txt only when username is resolved from SAM
                    if username and username not in _WELL_KNOWN_SIDS.values():
                        info_txt = (
                            f"SID:      {sid_name}\n"
                            f"Username: {username}\n"
                        )
                        (sid_extract_dir / "info.txt").write_text(info_txt, encoding="utf-8")

                # Extract the $I index file
                (sid_extract_dir / i_fname).write_bytes(r.stdout)
                console.print(f"[green]  Extracted {i_fname} → {sid_extract_dir / i_fname}[/green]")

                # Extract the matching $R data file
                if r_inode is None:
                    console.print(f"[yellow]  No $R file found for {i_fname}[/yellow]")
                else:
                    r_fname = f"$R{suffix}"
                    rdata = subprocess.run(["icat", "-o", str(offset), str(file), r_inode],
                                           capture_output=True)
                    if rdata.returncode == 0:
                        (sid_extract_dir / r_fname).write_bytes(rdata.stdout)
                        console.print(f"[green]  Extracted $R{suffix} → {sid_extract_dir / r_fname}[/green]")
                    else:
                        console.print(f"[red]  Failed to extract $R{suffix}[/red]")

    if table.row_count == 0:
        console.print("[dim]No $Recycle.Bin entries found.[/dim]")
    else:
        console.print(table)


# ---------------------------------------------------------------------------
# USN Journal helpers
# ---------------------------------------------------------------------------

_USN_REASONS: dict[int, str] = {
    0x00000001: "DATA_OVR",
    0x00000002: "DATA_EXT",
    0x00000004: "DATA_TRUNC",
    0x00000010: "NDATA_OVR",
    0x00000020: "NDATA_EXT",
    0x00000040: "NDATA_TRUNC",
    0x00000100: "CREATE",
    0x00000200: "DELETE",
    0x00000400: "EA_CHG",
    0x00000800: "SEC_CHG",
    0x00001000: "REN_OLD",
    0x00002000: "REN_NEW",
    0x00004000: "IDX_CHG",
    0x00008000: "BASIC_CHG",
    0x00010000: "LINK_CHG",
    0x00020000: "COMP_CHG",
    0x00040000: "ENC_CHG",
    0x00080000: "OID_CHG",
    0x00100000: "REPARSE",
    0x00200000: "STREAM_CHG",
    0x00400000: "TRANS_CHG",
    0x80000000: "CLOSE",
}


def _fmt_reasons(reason: int) -> str:
    parts = [name for bit, name in _USN_REASONS.items() if reason & bit]
    return " | ".join(parts) if parts else f"0x{reason:08X}"


def _parse_usn_max(data: bytes) -> dict:
    """Parse the on-disk $Max stream (32-byte format stored in $UsnJrnl).

    On-disk layout (not the same as the user-mode USN_JOURNAL_DATA struct):
      0x00  uint64  MaximumSize
      0x08  uint64  AllocationDelta
      0x10  uint64  JournalId
      0x18  int64   LowestValidUsn  (0 = all records from start are valid)
    """
    if len(data) < 24:
        raise ValueError(f"$Max too short: {len(data)} bytes (expected ≥24)")
    return {
        "max_size":    struct.unpack_from("<Q", data, 0x00)[0],
        "alloc_delta": struct.unpack_from("<Q", data, 0x08)[0],
        "journal_id":  struct.unpack_from("<Q", data, 0x10)[0],
        "lowest_usn":  struct.unpack_from("<q", data, 0x18)[0] if len(data) >= 32 else 0,
    }


def _stream_usn_j(image: Path, offset: int, j_inode: str) -> Iterator[dict]:
    """Stream-parse USN_RECORD_V2 entries from $UsnJrnl:$J via icat.

    Skips leading sparse (zero) regions automatically without loading the
    entire file — $J can be hundreds of MB due to NTFS sparse allocation.
    """
    proc = subprocess.Popen(
        ["icat", "-o", str(offset), str(image), j_inode],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    CHUNK = 512 * 1024  # 512 KB read buffer
    MIN_REC = 60        # USN_RECORD_V2 fixed header size

    try:
        buf = bytearray()
        found_records = False

        while True:
            chunk = proc.stdout.read(CHUNK)
            if not chunk:
                break
            buf.extend(chunk)

            pos = 0
            while pos < len(buf):
                # Skip sparse (zero) 4-byte words until first record
                if pos + 4 > len(buf):
                    break
                rec_len = struct.unpack_from("<I", buf, pos)[0]
                if rec_len == 0:
                    if not found_records:
                        # Still in the sparse leading-zero region.  Find the first
                        # non-zero byte, then back-align to the nearest 4-byte boundary
                        # so record parsing stays aligned.
                        nz = next((i for i in range(pos, len(buf)) if buf[i] != 0), None)
                        if nz is None:
                            # Entirely zero chunk — discard the whole buffer.
                            # No leftover bytes: USN records are 8-byte aligned in $J,
                            # so each chunk boundary stays 4-byte aligned.
                            pos = len(buf)
                        else:
                            pos = nz & ~3  # align down to 4-byte boundary
                    else:
                        pos += 4
                    continue

                if rec_len < MIN_REC or rec_len > 65536:
                    pos += 4
                    continue
                if pos + rec_len > len(buf):
                    break  # wait for more data

                major = struct.unpack_from("<H", buf, pos + 4)[0]
                if major != 2:
                    pos += (rec_len + 7) & ~7
                    continue

                file_ref = struct.unpack_from("<Q", buf, pos + 8)[0]
                par_ref  = struct.unpack_from("<Q", buf, pos + 16)[0]
                usn      = struct.unpack_from("<q", buf, pos + 24)[0]
                ts_ft    = struct.unpack_from("<Q", buf, pos + 32)[0]
                reason   = struct.unpack_from("<I", buf, pos + 40)[0]
                name_len = struct.unpack_from("<H", buf, pos + 56)[0]
                name_off = struct.unpack_from("<H", buf, pos + 58)[0]

                name_raw = bytes(buf[pos + name_off: pos + name_off + name_len])
                name = name_raw.decode("utf-16-le", errors="replace") if name_raw else "?"

                try:
                    ts = filetime_to_datetime(ts_ft) if ts_ft else None
                except Exception:
                    ts = None

                found_records = True
                yield {
                    "usn":        usn,
                    "ts":         ts,
                    "reason":     reason,
                    "file_mft":   file_ref & 0x0000_FFFF_FFFF_FFFF,
                    "parent_mft": par_ref  & 0x0000_FFFF_FFFF_FFFF,
                    "name":       name,
                }

                pos += (rec_len + 7) & ~7

            del buf[:pos]
    finally:
        proc.stdout.close()
        proc.wait()


def _get_all_partition_offsets(image: Path) -> list[tuple[int, str]]:
    """Return [(start_sector, description)] for every numbered (non-Meta) partition."""
    result = subprocess.run(["mmls", str(image)], capture_output=True, text=True)
    partitions = []
    for line in result.stdout.splitlines():
        m = re.match(r"\d{3}:\s+(\S+)\s+(\d+)\s+\d+\s+\d+\s*(.*)", line)
        if m and re.fullmatch(r"\d+", m.group(1)):
            start = int(m.group(2))
            desc  = m.group(3).strip() or f"sector {start}"
            partitions.append((start, desc))
    return partitions


def _check_usnjrnl(image: Path, offset: int, limit: int) -> bool:
    """Analyze $UsnJrnl on one partition. Returns True if journal was found."""
    extend_inode = _find_child(offset, image, None, "$Extend")
    if extend_inode is None:
        console.print("[dim]  $Extend not found — skipping (not NTFS).[/dim]")
        return False

    entries = _fls_list(offset, image, extend_inode)
    max_inode = next(
        (inode for _, inode, name in entries if name.lower() == "$usnjrnl:$max"), None
    )
    j_inode = next(
        (inode for _, inode, name in entries if name.lower() == "$usnjrnl:$j"), None
    )

    if max_inode is None:
        console.print("[yellow]  $UsnJrnl not present — journal not enabled on this partition.[/yellow]")
        return False

    r = subprocess.run(["icat", "-o", str(offset), str(image), max_inode], capture_output=True)
    if r.returncode != 0 or len(r.stdout) < 24:
        console.print("[red]  Failed to read $UsnJrnl:$Max.[/red]")
        return False
    try:
        mx = _parse_usn_max(r.stdout)
    except ValueError as e:
        console.print(f"[red]  {e}[/red]")
        return False

    mb = 1024 * 1024
    console.print(Panel(
        f"[bold]Journal ID:[/bold]       0x{mx['journal_id']:016X}\n"
        f"[bold]Lowest Valid USN:[/bold] {mx['lowest_usn']}\n"
        f"[bold]Maximum Size:[/bold]     {mx['max_size'] // mb} MB\n"
        f"[bold]Allocation Delta:[/bold] {mx['alloc_delta'] // mb} MB",
        title="$UsnJrnl:$Max",
        border_style="green",
    ))

    if j_inode is None:
        console.print("[yellow]  $UsnJrnl:$J not found.[/yellow]")
        return True

    console.print("[dim]  Streaming $UsnJrnl:$J (skipping sparse leading zeros)…[/dim]")

    table = Table(
        title=f"$UsnJrnl:$J{f'  — first {limit} records' if limit else ''}",
        box=box.ROUNDED,
        header_style="bold",
    )
    table.add_column("USN", justify="right", no_wrap=True)
    table.add_column("Timestamp", no_wrap=True)
    table.add_column("Reason")
    table.add_column("Filename")
    table.add_column("MFT#", justify="right")
    table.add_column("Parent MFT#", justify="right")

    count = 0
    for rec in _stream_usn_j(image, offset, j_inode):
        ts_str = rec["ts"].strftime("%Y-%m-%d %H:%M:%S UTC") if rec["ts"] else "—"
        table.add_row(
            str(rec["usn"]),
            ts_str,
            _fmt_reasons(rec["reason"]),
            rec["name"],
            str(rec["file_mft"]),
            str(rec["parent_mft"]),
        )
        count += 1
        if limit and count >= limit:
            break

    if count == 0:
        console.print("[dim]  No USN records found in $J.[/dim]")
    else:
        console.print(table)
        if limit and count == limit:
            console.print(f"[dim]  Showing first {limit} records. Use --limit 0 for all.[/dim]")
    return True


# ---------------------------------------------------------------------------
# usnjrnl command
# ---------------------------------------------------------------------------

@app.command()
def usnjrnl(
    file: Path = typer.Argument(..., help="Path to .E01 image", exists=True),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Partition start sector (checks all if omitted)"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max records to display per partition (0 = all)"),
):
    """Parse the $UsnJrnl change journal from NTFS partitions in a disk image."""
    if offset is not None:
        partitions = [(offset, f"sector {offset}")]
    else:
        partitions = _get_all_partition_offsets(file)
        if not partitions:
            console.print("[red]No partitions found via mmls.[/red]")
            raise typer.Exit(1)

    found_any = False
    for part_offset, part_desc in partitions:
        console.rule(f"[bold]{part_desc}  (offset {part_offset})[/bold]")
        if _check_usnjrnl(file, part_offset, limit):
            found_any = True

    if not found_any:
        console.print("\n[yellow]No USN journal found on any checked partition.[/yellow]")
