from __future__ import annotations
from pathlib import Path, PureWindowsPath
from typing import Optional, Iterator
import contextlib
import csv
import json
import re
import struct
import subprocess
import sys
import tempfile

from ifn.parsers.windows_time import filetime_to_datetime

import typer
from rich.table import Table
from rich.panel import Panel
from rich import box

from ifn import context
from ifn.parsers import recycle as _recycle_parser
from ifn.parsers.sam import parse_v_blob, extract_user_sid

app = typer.Typer(help="Work with EWF/E01 disk images")


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    console = context.get_console()
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
def info(file: Path = typer.Argument(..., help="Path to .E01 image", exists=True)) -> None:
    """Run ewfinfo and display image metadata."""
    console = context.get_console()
    result = _run(["ewfinfo", str(file)])
    fields: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if ":" in line and not line.strip().startswith("ewf"):
            key, _, val = line.partition(":")
            k, v = key.strip(), val.strip()
            if k and v:
                fields[k] = v

    if context.output_json:
        print(json.dumps(fields, indent=2))
        return

    table = Table(title=f"EWF Info — {file.name}", box=box.ROUNDED, header_style="bold")
    table.add_column("Field")
    table.add_column("Value")
    for k, v in fields.items():
        table.add_row(k, v)
    console.print(table)


_MMLS_HEADERS = ["Slot", "Start", "End", "Length", "Description"]


@app.command()
def mmls(
    file: Path = typer.Argument(..., help="Path to .E01 image", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export partition table to CSV"),
) -> None:
    """Run mmls and display the partition table."""
    console = context.get_console()
    result = _run(["mmls", str(file)])
    lines = result.stdout.splitlines()

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

    rows: list[tuple[str, str, str, str, str]] = []
    for line in table_lines:
        m = re.match(r"(\d{3}):\s+([\w:/-]+)\s+(\d+)\s+(\d+)\s+(\d+)\s*(.*)", line)
        if m:
            num, slot_type, start, end, length, desc = m.groups()
            rows.append((f"{num} ({slot_type})", start, end, length, desc.strip()))

    if context.output_json:
        print(json.dumps([
            {"slot": s, "start": int(st), "end": int(e), "length": int(l), "description": d}
            for s, st, e, l, d in rows
        ], indent=2))
        return

    for h in header_lines:
        if h.strip():
            console.print(f"[dim]{h}[/dim]")

    pt = Table(title=f"Partition Table — {file.name}", box=box.ROUNDED, header_style="bold")
    for col, kw in zip(_MMLS_HEADERS, [{}, {"justify": "right"}, {"justify": "right"}, {"justify": "right"}, {}]):
        pt.add_column(col, **kw)
    for row in rows:
        pt.add_row(*row)
    console.print(pt)
    _write_csv(csv_out, _MMLS_HEADERS, [list(r) for r in rows], console)


_FLS_HEADERS = ["Type", "Inode", "Name"]


@app.command()
def fls(
    file: Path = typer.Argument(..., help="Path to .E01 image", exists=True),
    inode: Optional[str] = typer.Argument(None, help="Partition offset (from mmls Start column) or inode"),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Partition start sector offset"),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export file listing to CSV"),
) -> None:
    """Run fls to list files in a partition."""
    console = context.get_console()
    cmd = ["fls"]
    if offset is not None:
        cmd += ["-o", str(offset)]
    elif inode and inode.isdigit():
        cmd += ["-o", inode]
    cmd.append(str(file))

    result = _run(cmd)
    rows: list[tuple[str, str, str]] = []
    for line in result.stdout.splitlines():
        if line.strip():
            parts = line.split(None, 2)
            if len(parts) >= 3:
                rows.append((parts[0], parts[1].rstrip(":"), parts[2]))
            else:
                rows.append(("", "", line))

    if context.output_json:
        print(json.dumps([{"type": t, "inode": i, "name": n} for t, i, n in rows], indent=2))
        return

    ft = Table(title=f"File Listing — {file.name}", box=box.SIMPLE, header_style="bold")
    ft.add_column("Type")
    ft.add_column("Inode")
    ft.add_column("Name")
    for row in rows:
        ft.add_row(*row)
    console.print(ft)
    _write_csv(csv_out, _FLS_HEADERS, [list(r) for r in rows], console)


@app.command()
def icat(
    file: Path = typer.Argument(..., help="Path to .E01 image", exists=True),
    inode: str = typer.Argument(..., help="Inode number (from fls)"),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Partition start sector offset"),
    output: Optional[Path] = typer.Option(None, "--output", "-O", help="Save to file instead of stdout"),
) -> None:
    """Run icat to extract a file from the image."""
    console = context.get_console()
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
    console = context.get_console()
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
    console = context.get_console()
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
    console = context.get_console()
    console.print(Panel(
        f"[bold]Source:[/bold]  {mapper}\n"
        f"[bold]Output:[/bold]  {output}.E01\n\n"
        f"[dim]ewfacquire will prompt for acquisition parameters.[/dim]",
        title="EWF Acquire",
    ))
    console.print(f"[yellow]Running:[/yellow] sudo ewfacquire -t {output} {mapper}")
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
    console = context.get_console()
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
        context.get_console().print(f"[yellow]Warning: SAM parse error: {e}[/yellow]")
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
    console = context.get_console()
    if offset is None:
        offset = _auto_detect_offset(file)
        if not context.output_json:
            console.print(f"[dim]Auto-detected Windows partition at sector {offset}[/dim]")

    rb_inode = _find_child(offset, file, None, "$Recycle.Bin")
    if not rb_inode:
        console.print("[red]$Recycle.Bin not found in partition root.[/red]")
        raise typer.Exit(1)

    sid_map: dict[str, str] = {}
    if sam:
        sid_map = _build_sid_map(sam)
        if not context.output_json:
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
                if not context.output_json:
                    console.print(f"[dim]Auto-extracted SAM ({len(r.stdout):,} bytes) — {len(sid_map)} SID entries[/dim]")
            finally:
                tmp_path.unlink(missing_ok=True)
        else:
            if not context.output_json:
                console.print("[yellow]Warning: SAM not found on image — SIDs will not be resolved.[/yellow]")

    if extract is not None:
        extract.mkdir(parents=True, exist_ok=True)

    # Enumerate SID subdirectories and their $I/$R file pairs
    json_rows: list[dict] = []
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

        dir_entries = _fls_list(offset, file, sid_inode)
        r_map: dict[str, str] = {
            fname[2:]: inode
            for _, inode, fname in dir_entries
            if fname.startswith("$R") and ":" not in fname
        }

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
                deleted_iso = rec.deleted_at.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
                size_str = f"{rec.file_size:,}"
                path_str = rec.original_path
            except Exception as e:
                deleted_str = "parse error"
                deleted_iso = None
                size_str = "?"
                path_str = str(e)
                rec = None

            json_rows.append({
                "sid": sid_name,
                "username": username,
                "i_file": i_fname,
                "deleted_at": deleted_iso,
                "file_size": rec.file_size if rec else None,
                "original_path": path_str,
            })

            if not context.output_json:
                row: list[str] = []
                if sid_map:
                    row.append(username or "[dim]—[/dim]")
                row += [sid_name, i_fname, deleted_str, size_str, path_str]
                table.add_row(*row)

            if extract is not None and rec is not None:
                suffix = i_fname[2:]
                r_inode = r_map.get(suffix)

                if sid_extract_dir is None:
                    dir_name = username if username else sid_name
                    sid_extract_dir = extract / dir_name
                    sid_extract_dir.mkdir(parents=True, exist_ok=True)

                    if username and username not in _WELL_KNOWN_SIDS.values():
                        info_txt = f"SID:      {sid_name}\nUsername: {username}\n"
                        (sid_extract_dir / "info.txt").write_text(info_txt, encoding="utf-8")

                (sid_extract_dir / i_fname).write_bytes(r.stdout)
                if not context.output_json:
                    console.print(f"[green]  Extracted {i_fname} → {sid_extract_dir / i_fname}[/green]")

                if r_inode is None:
                    if not context.output_json:
                        console.print(f"[yellow]  No $R file found for {i_fname}[/yellow]")
                else:
                    r_fname = f"$R{suffix}"
                    rdata = subprocess.run(["icat", "-o", str(offset), str(file), r_inode],
                                           capture_output=True)
                    if rdata.returncode == 0:
                        (sid_extract_dir / r_fname).write_bytes(rdata.stdout)
                        if not context.output_json:
                            console.print(f"[green]  Extracted $R{suffix} → {sid_extract_dir / r_fname}[/green]")
                    else:
                        if not context.output_json:
                            console.print(f"[red]  Failed to extract $R{suffix}[/red]")

    if context.output_json:
        print(json.dumps(json_rows, indent=2))
        return

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
    """Return [(start_sector, description)] for every numbered (non-Meta) partition.

    Handles both GPT-style ('000', '001') and MBR/DOS-style ('000:000', '000:001')
    slot names produced by mmls.
    """
    result = subprocess.run(["mmls", str(image)], capture_output=True, text=True)
    partitions = []
    for line in result.stdout.splitlines():
        m = re.match(r"\d{3}:\s+(\S+)\s+(\d+)\s+\d+\s+\d+\s*(.*)", line)
        if m and re.fullmatch(r"\d+(?::\d+)?", m.group(1)):
            start = int(m.group(2))
            desc  = m.group(3).strip() or f"sector {start}"
            partitions.append((start, desc))
    return partitions


def _check_usnjrnl(
    image: Path,
    offset: int,
    skip: int,
    limit: int,
    csv_out: Optional[Path],
) -> tuple[bool, list[dict]]:
    """Analyze $UsnJrnl on one partition. Returns (found, records)."""
    console = context.get_console()
    root_result = subprocess.run(
        ["fls", "-o", str(offset), str(image)],
        capture_output=True, text=True,
    )
    combined = (root_result.stdout + root_result.stderr).lower()
    if "bitlocker" in combined or "encryption detected" in combined:
        if not context.output_json:
            console.print("[yellow]  BitLocker-encrypted partition — cannot read without key.[/yellow]")
        return False, []

    extend_inode = next(
        (re.match(r"[rd]/[rd]\s+(\S+):\t(.+)", ln).group(1)
         for ln in root_result.stdout.splitlines()
         if re.match(r"[rd]/[rd]\s+(\S+):\t(.+)", ln)
         and re.match(r"[rd]/[rd]\s+(\S+):\t(.+)", ln).group(2).strip().lower() == "$extend"),
        None,
    )
    if extend_inode is None:
        if not context.output_json:
            console.print("[dim]  $Extend not found — skipping (not NTFS).[/dim]")
        return False, []

    entries = _fls_list(offset, image, extend_inode)
    max_inode = next((inode for _, inode, name in entries if name.lower() == "$usnjrnl:$max"), None)
    j_inode = next((inode for _, inode, name in entries if name.lower() == "$usnjrnl:$j"), None)

    if max_inode is None:
        if not context.output_json:
            console.print("[yellow]  $UsnJrnl not present — journal not enabled on this partition.[/yellow]")
        return False, []

    r = subprocess.run(["icat", "-o", str(offset), str(image), max_inode], capture_output=True)
    if r.returncode != 0 or len(r.stdout) < 24:
        if not context.output_json:
            console.print("[red]  Failed to read $UsnJrnl:$Max.[/red]")
        return False, []
    try:
        mx = _parse_usn_max(r.stdout)
    except ValueError as e:
        if not context.output_json:
            console.print(f"[red]  {e}[/red]")
        return False, []

    if not context.output_json:
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
        if not context.output_json:
            console.print("[yellow]  $UsnJrnl:$J not found.[/yellow]")
        return True, []

    if not context.output_json:
        console.print("[dim]  Streaming $UsnJrnl:$J (skipping sparse leading zeros)…[/dim]")

    records: list[dict] = []
    early_stop = False
    need = (skip + limit) if limit else 0
    for rec in _stream_usn_j(image, offset, j_inode):
        records.append(rec)
        if csv_out is None and not context.output_json and need and len(records) >= need:
            early_stop = True
            break

    if csv_out is not None:
        _write_usn_csv(csv_out, records)
        if not context.output_json:
            console.print(f"[green]  Exported {len(records)} records → {csv_out}[/green]")

    if context.output_json:
        return True, records

    display = records[skip: (skip + limit) if limit else None]

    if not display:
        console.print("[dim]  No USN records to display (check --skip value).[/dim]")
    else:
        total_hint = "" if not early_stop and not (limit and len(display) == limit) else \
            f"  records {skip}–{skip + len(display) - 1}"
        table = Table(
            title=f"$UsnJrnl:$J{total_hint}",
            box=box.ROUNDED,
            header_style="bold",
        )
        table.add_column("USN", justify="right", no_wrap=True)
        table.add_column("Timestamp", no_wrap=True)
        table.add_column("Reason")
        table.add_column("Filename")
        table.add_column("MFT#", justify="right")
        table.add_column("Parent MFT#", justify="right")

        for rec in display:
            ts_str = rec["ts"].strftime("%Y-%m-%d %H:%M:%S UTC") if rec["ts"] else "—"
            table.add_row(
                str(rec["usn"]),
                ts_str,
                _fmt_reasons(rec["reason"]),
                rec["name"],
                str(rec["file_mft"]),
                str(rec["parent_mft"]),
            )
        console.print(table)

        if early_stop or (limit and len(display) == limit):
            console.print(
                f"[dim]  Showing records {skip}–{skip + len(display) - 1}."
                "  Use --skip / --limit for pagination, --limit 0 for all.[/dim]"
            )
    return True, []


def _write_usn_csv(path: Path, records: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["usn", "timestamp", "reason", "filename", "file_mft", "parent_mft"])
        for rec in records:
            ts_str = rec["ts"].strftime("%Y-%m-%d %H:%M:%S UTC") if rec["ts"] else ""
            writer.writerow([
                rec["usn"],
                ts_str,
                _fmt_reasons(rec["reason"]),
                rec["name"],
                rec["file_mft"],
                rec["parent_mft"],
            ])


# ---------------------------------------------------------------------------
# usnjrnl command
# ---------------------------------------------------------------------------

@app.command()
def usnjrnl(
    file: Path = typer.Argument(..., help="Path to .E01 image", exists=True),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Partition start sector (checks all if omitted)"),
    skip: int = typer.Option(0, "--skip", "-s", help="Skip the first N records before displaying"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max records to display (0 = all)"),
    csv_out: Optional[Path] = typer.Option(None, "--csv", "-c", help="Export all records to a CSV file"),
):
    """Parse the $UsnJrnl change journal from NTFS partitions in a disk image."""
    console = context.get_console()
    if offset is not None:
        partitions = [(offset, f"sector {offset}")]
    else:
        partitions = _get_all_partition_offsets(file)
        if not partitions:
            console.print("[red]No partitions found via mmls.[/red]")
            raise typer.Exit(1)

    found_any = False
    all_records: list[dict] = []
    for part_offset, part_desc in partitions:
        if not context.output_json:
            console.rule(f"[bold]{part_desc}  (offset {part_offset})[/bold]")
        found, records = _check_usnjrnl(file, part_offset, skip, limit, csv_out)
        if found:
            found_any = True
            all_records.extend(records)

    if context.output_json:
        def _rec_to_json(r: dict) -> dict:
            return {
                "usn": r["usn"],
                "timestamp": r["ts"].strftime("%Y-%m-%dT%H:%M:%S") + "Z" if r["ts"] else None,
                "reason": _fmt_reasons(r["reason"]),
                "filename": r["name"],
                "file_mft": r["file_mft"],
                "parent_mft": r["parent_mft"],
            }
        print(json.dumps([_rec_to_json(r) for r in all_records], indent=2))
        return

    if not found_any:
        console.print("\n[yellow]No USN journal found on any checked partition.[/yellow]")


# ---------------------------------------------------------------------------
# VBR scan helpers
# ---------------------------------------------------------------------------

_NTFS_OEM = b"NTFS    "
_BVE_OEM  = b"-FVE-FS-"
_VBR_SECTOR = 512


def _ewfmount_temp(image: Path) -> tuple[Path, Path]:
    """Mount an EWF image to a fresh temp dir. Returns (tmpdir, ewf1_path).
    Caller must call _ewfumount(tmpdir) when done."""
    console = context.get_console()
    tmpdir = Path(tempfile.mkdtemp(prefix="ifn_ewf_"))
    r = subprocess.run(["ewfmount", str(image), str(tmpdir)], capture_output=True, text=True)
    if r.returncode != 0:
        tmpdir.rmdir()
        console.print(f"[red]ewfmount failed: {r.stderr.strip()}[/red]")
        raise typer.Exit(1)
    return tmpdir, tmpdir / "ewf1"


def _ewfumount(tmpdir: Path) -> None:
    subprocess.run(["fusermount", "-u", str(tmpdir)], capture_output=True)
    try:
        tmpdir.rmdir()
    except OSError:
        pass


def _decode_ntfs_vbr(data: bytes) -> dict | None:
    """Decode an NTFS VBR sector. Returns None if the OEM ID is not NTFS."""
    if len(data) < 512 or data[3:11] != _NTFS_OEM:
        return None
    hidden = struct.unpack_from("<I", data, 0x1C)[0]
    total  = struct.unpack_from("<q", data, 0x28)[0]
    mft    = struct.unpack_from("<q", data, 0x30)[0]
    spc    = data[0x0D]
    return {
        "hidden_sectors":      hidden,
        "total_sectors":       total,
        "backup_sector":       hidden + total,
        "mft_cluster":         mft,
        "sectors_per_cluster": spc,
    }


def _scan_vbr_signatures(ewf1: Path) -> list[tuple[int, bytes]]:
    """Scan an entire raw device image for sectors containing NTFS or BitLocker OEM IDs.
    Returns (sector_number, sector_bytes) pairs in disk order."""
    CHUNK = 1024 * 1024  # 1 MB read buffer
    found: list[tuple[int, bytes]] = []
    with open(ewf1, "rb") as f:
        base = 0
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            for i in range(0, len(chunk), _VBR_SECTOR):
                s = chunk[i: i + _VBR_SECTOR]
                if len(s) >= 11 and s[3:11] in (_NTFS_OEM, _BVE_OEM):
                    found.append(((base + i) // _VBR_SECTOR, bytes(s)))
            base += len(chunk)
    return found


def _read_sector(ewf1: Path, sector: int) -> bytes:
    with open(ewf1, "rb") as f:
        f.seek(sector * _VBR_SECTOR)
        return f.read(_VBR_SECTOR)


# ---------------------------------------------------------------------------
# vbr-scan command
# ---------------------------------------------------------------------------

_VBR_SCAN_HEADERS = ["Sector", "Role", "FS", "Part start", "Total sectors", "Backup at", "Status"]


@app.command()
def vbr_scan(
    file: Path = typer.Argument(..., help="Path to .E01 image or raw disk file", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export VBR scan results to CSV"),
) -> None:
    """Scan all sectors for VBR signatures and identify primary, backup, and broken partitions."""
    console = context.get_console()
    mmls_result = subprocess.run(["mmls", str(file)], capture_output=True, text=True)
    known_starts: set[int] = set()
    for line in mmls_result.stdout.splitlines():
        m = re.match(r"\d{3}:\s+(\S+)\s+(\d+)\s+\d+\s+\d+", line)
        if m and re.fullmatch(r"\d+(?::\d+)?", m.group(1)):
            known_starts.add(int(m.group(2)))

    if not context.output_json:
        console.print(f"[dim]Partition table: {len(known_starts)} partition(s) at sectors "
                      f"{sorted(known_starts)}[/dim]")

    is_ewf = file.suffix.upper() in {".E01", ".E02", ".EWF"}
    if is_ewf:
        if not context.output_json:
            console.print("[dim]Mounting image and scanning for VBR signatures…[/dim]")
        tmpdir, ewf1 = _ewfmount_temp(file)
    else:
        if not context.output_json:
            console.print("[dim]Scanning for VBR signatures…[/dim]")
        tmpdir, ewf1 = None, file

    try:
        vbrs = _scan_vbr_signatures(ewf1)
        vbr_map: dict[int, bytes] = {sec: data for sec, data in vbrs}

        if not context.output_json:
            console.print(f"[dim]Scan complete: {len(vbrs)} VBR signature(s) found.[/dim]\n")

        table = Table(title=f"VBR Scan — {file.name}", box=box.ROUNDED, header_style="bold")
        for col, kw in zip(_VBR_SCAN_HEADERS,
                           [{"justify": "right"}, {}, {}, {"justify": "right"}, {"justify": "right"}, {"justify": "right"}, {"no_wrap": True}]):
            table.add_column(col, **kw)

        broken: list[dict] = []
        vbr_result_rows: list[dict] = []
        csv_rows: list[list[str]] = []

        for sector, data in sorted(vbrs):
            oem = data[3:11]

            if oem == _BVE_OEM:
                in_table = sector in known_starts
                style = "green" if in_table else "yellow"
                status = "In part. table" if in_table else "Not in part. table"
                row = [str(sector), "Primary", "BitLocker", str(sector), "—", "—", status]
                table.add_row(*row, style=style)
                csv_rows.append(row)
                vbr_result_rows.append({"sector": sector, "role": "Primary", "fs": "BitLocker",
                                        "part_start": sector, "total_sectors": None, "backup_at": None, "status": status})
                continue

            vbr_info = _decode_ntfs_vbr(data)
            if not vbr_info:
                continue

            H = vbr_info["hidden_sectors"]
            T = vbr_info["total_sectors"]
            B = vbr_info["backup_sector"]

            if sector == H:
                role = "Primary"
                in_table = sector in known_starts
                backup_data = vbr_map.get(B)
                backup_valid = backup_data is not None and backup_data[3:11] == _NTFS_OEM
                if in_table and backup_valid:
                    status, style = "Intact", "green"
                elif in_table and not backup_valid:
                    status, style = "Backup missing", "yellow"
                elif not in_table and backup_valid:
                    status, style = "Not in part. table", "yellow"
                else:
                    status, style = "Orphan primary", "yellow"
            elif sector == B:
                role = "Backup"
                primary_data = vbr_map.get(H)
                if primary_data is not None and primary_data[3:11] == _NTFS_OEM:
                    primary_info = _decode_ntfs_vbr(primary_data)
                    if primary_info and primary_info["backup_sector"] == sector:
                        status, style = "Intact", "green"
                    else:
                        status, style = "Stale (primary resized)", "yellow"
                else:
                    if H not in vbr_map:
                        raw = _read_sector(ewf1, H)
                        primary_zeroed = all(b == 0 for b in raw)
                    else:
                        primary_zeroed = False
                    if primary_zeroed:
                        status, style = "PRIMARY VBR MISSING", "red"
                        broken.append({"sector": sector, "start": H, "total": T, "backup": B})
                    else:
                        status, style = "Primary VBR corrupt", "yellow"
            else:
                role = "Unknown"
                status, style = "sector != partition start/end", "dim"

            row = [str(sector), role, "NTFS", str(H), f"{T:,}", str(B), status]
            table.add_row(*row, style=style)
            csv_rows.append(row)
            vbr_result_rows.append({"sector": sector, "role": role, "fs": "NTFS",
                                    "part_start": H, "total_sectors": T, "backup_at": B, "status": status})

        if context.output_json:
            print(json.dumps(vbr_result_rows, indent=2))
            return

        console.print(table)
        _write_csv(csv_out, _VBR_SCAN_HEADERS, csv_rows, console)

        if broken:
            console.print()
            for b in broken:
                size_mib = b["total"] * 512 // (1024 * 1024)
                console.print(Panel(
                    f"[bold]Backup VBR at sector:[/bold]   {b['sector']}\n"
                    f"[bold]Expected start sector:[/bold]  {b['start']}\n"
                    f"[bold]Partition size:[/bold]         {b['total']:,} sectors  ({size_mib:,} MiB)\n\n"
                    f"[bold]Recover with:[/bold]\n"
                    f"  uv run tool.py image recover-partition {file} {b['sector']} "
                    f"--output recovered.bin",
                    title="[bold red]Broken Partition Detected[/bold red]",
                    border_style="red",
                ))
        else:
            console.print("[green]No broken partitions detected.[/green]")

    finally:
        if is_ewf:
            _ewfumount(tmpdir)


# ---------------------------------------------------------------------------
# recover-partition command
# ---------------------------------------------------------------------------

@app.command()
def recover_partition(
    file: Path = typer.Argument(..., help="Path to .E01 image or raw disk file", exists=True),
    backup_sector: int = typer.Argument(..., help="Sector number of the intact backup VBR"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file for the recovered raw partition"),
):
    """Reconstruct a partition whose primary VBR was wiped, using its intact backup VBR.

    Extracts the full partition extent from the image with dd, then copies the
    backup VBR (last sector) to sector 0, making the partition readable again.
    """
    console = context.get_console()
    is_ewf = file.suffix.upper() in {".E01", ".E02", ".EWF"}
    if is_ewf:
        tmpdir, ewf1 = _ewfmount_temp(file)
    else:
        tmpdir, ewf1 = None, file
    try:
        vbr_data = _read_sector(ewf1, backup_sector)
        if vbr_data[3:11] != _NTFS_OEM:
            console.print(f"[red]Sector {backup_sector} does not contain an NTFS VBR (OEM ID: "
                          f"{vbr_data[3:11]!r}).[/red]")
            raise typer.Exit(1)

        vbr_info = _decode_ntfs_vbr(vbr_data)
        assert vbr_info
        start  = vbr_info["hidden_sectors"]
        total  = vbr_info["total_sectors"]
        backup = vbr_info["backup_sector"]

        if backup != backup_sector:
            console.print(
                f"[red]Sector {backup_sector} is not the backup VBR of its partition.[/red]\n"
                f"[dim]  VBR fields: hidden={start}, total={total} → backup at {backup}[/dim]"
            )
            raise typer.Exit(1)

        num_sectors = total + 1
        size_mib = num_sectors * 512 // (1024 * 1024)

        console.print(Panel(
            f"[bold]Backup VBR sector:[/bold]   {backup_sector}\n"
            f"[bold]Partition start:[/bold]     sector {start}\n"
            f"[bold]Partition end:[/bold]       sector {backup_sector}  (inclusive)\n"
            f"[bold]Size:[/bold]                {num_sectors:,} sectors  ({size_mib:,} MiB)\n"
            f"[bold]Output file:[/bold]         {output}",
            title="Partition Recovery Plan",
        ))

        console.print(f"\n[yellow]Step 1:[/yellow] Extracting {num_sectors:,} sectors "
                      f"(sectors {start}–{backup_sector}) with dd…")
        r = subprocess.run([
            "dd", f"if={ewf1}", f"of={output}", "bs=512",
            f"skip={start}", f"count={num_sectors}", "status=progress",
        ])
        if r.returncode != 0:
            console.print("[red]dd extraction failed.[/red]")
            raise typer.Exit(1)

        console.print(f"[yellow]Step 2:[/yellow] Copying backup VBR → sector 0 of {output.name}…")
        with open(output, "r+b") as f:
            f.seek(total * _VBR_SECTOR)
            backup_vbr_bytes = bytearray(f.read(_VBR_SECTOR))
            struct.pack_into("<I", backup_vbr_bytes, 0x1C, 0)
            f.seek(0)
            f.write(backup_vbr_bytes)

        console.print(f"\n[green]✓ Partition recovered: {output}[/green]")
        console.print(
            f"[dim]  Sector 0 contains the backup VBR with hidden_sectors zeroed.[/dim]\n"
            f"[dim]  Note: if MFT entry #0/$MFTMirr are damaged (overwritten partition),[/dim]\n"
            f"[dim]  use raw signature scan to recover surviving file records:[/dim]\n"
            f"[dim]    uv run tool.py mft scan --raw {output}[/dim]\n"
            f"[dim]  Standard tools: fls -f ntfs {output}[/dim]"
        )
    finally:
        if is_ewf:
            _ewfumount(tmpdir)


def _write_csv(path: Optional[Path], headers: list[str], rows: list[list[str]], console) -> None:
    if path is None:
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(rows)
    console.print(f"[green]✓ Exported {len(rows)} row(s) → {path}[/green]")
