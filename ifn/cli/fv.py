from __future__ import annotations
import csv
import json
import struct
from pathlib import Path
from typing import Optional

import typer
from rich.panel import Panel
from rich.table import Table
from rich import box

from ifn import context
from ifn.parsers.windows_time import filetime_to_datetime
from ifn.parsers.sam import (
    BASE as _V_BASE,
    ACCOUNT_FLAGS as _ACCOUNT_FLAGS,
    parse_v_blob, parse_f_blob, fmt_flags, extract_sid_from_v_blob,
)
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse SAM hive F and V value blobs")

_ACCOUNT_HEADERS = ["RID", "SID", "Username", "Full name", "Comment",
                    "Flags", "Last logon", "Last PW change", "Expires", "Logons", "Failed"]


def _ft(val) -> str:
    """Format a parsed parse_f_blob timestamp (datetime, 'never expires', or None)."""
    if val is None:
        return "Never"
    if isinstance(val, str):
        return val.capitalize()
    return val.strftime("%Y-%m-%d %H:%M:%S UTC")


def _ft_iso(val) -> str | None:
    if val is None or isinstance(val, str):
        return None
    try:
        return val.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    except Exception:
        return str(val)


def _ft_raw(ticks: int) -> str:
    """Format a raw FILETIME int for hex-table annotations."""
    if ticks == 0x7FFFFFFFFFFFFFFF:
        return "Never expires"
    if ticks == 0:
        return "Never"
    return filetime_to_datetime(ticks).strftime("%Y-%m-%d %H:%M:%S UTC")


def _write_csv(path: Optional[Path], headers: list[str], rows: list[list[str]], console) -> None:
    if path is None:
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(rows)
    console.print(f"[green]✓ Exported {len(rows)} row(s) → {path}[/green]")


@app.command(name="v-blob")
def v_blob(
    file: Path = typer.Argument(..., help="Path to V blob binary", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export to CSV file"),
) -> None:
    """Decode a SAM V blob: username, full name, comment, SID, NT/LM hash locations.

    NOTE: Hash bytes are obfuscated. SYSKEY (from SYSTEM hive) is required to decrypt.
    """
    console = context.get_console()
    data = file.read_bytes()

    v = parse_v_blob(data)
    sid = extract_sid_from_v_blob(data)

    lm_present = v["lm_hash"] is not None
    nt_present = v["nt_hash"] is not None

    if context.output_json:
        print(json.dumps({
            "username": v["username"],
            "fullname": v["fullname"],
            "comment": v["comment"],
            "sid": sid,
            "lm_hash": v["lm_hash"].hex(" ").upper() if v["lm_hash"] else None,
            "nt_hash": v["nt_hash"].hex(" ").upper() if v["nt_hash"] else None,
            "note": "LM/NT hashes are RC4-obfuscated with SYSKEY",
        }, indent=2))
        return

    # Build hex-table annotations using raw field offsets
    fields: list[tuple[int, int, str, str]] = []
    for i, label in [(0, "acct blob"), (1, "username"), (2, "full name"),
                     (3, "comment"), (12, "LM hash"), (13, "NT hash")]:
        off = i * 12
        rel_off = struct.unpack_from("<I", data, off)[0]
        length = struct.unpack_from("<I", data, off + 4)[0]
        abs_off = _V_BASE + rel_off
        fields.append((off, 4, f"F{i} {label} offset", str(rel_off)))
        fields.append((off + 4, 4, f"F{i} {label} length", str(length)))
        if length and abs_off + length <= len(data):
            raw = data[abs_off: abs_off + length]
            if i == 1:
                fields.append((abs_off, length, "Username (UTF-16LE)", v["username"]))
            elif i == 2:
                fields.append((abs_off, length, "Full name (UTF-16LE)", v["fullname"]))
            elif i == 3:
                fields.append((abs_off, length, "Comment (UTF-16LE)", v["comment"]))
            elif i == 12 and lm_present:
                fields.append((abs_off, length, "LM hash (obfuscated)", raw.hex(" ").upper()))
            elif i == 13 and nt_present:
                nt_start = abs_off + 8
                fields.append((nt_start, 16, "NT hash (obfuscated, 16 B)", v["nt_hash"].hex(" ").upper()))

    render_hex_table(data, fields, title=f"SAM V Blob — {file.name}", console=console)

    lm_str = "[yellow]present (obfuscated)[/yellow]" if lm_present else "[dim]not present[/dim]"
    nt_str = "[yellow]present (obfuscated)[/yellow]" if nt_present else "[dim]not present[/dim]"
    panel_lines = [
        f"[bold]Username:[/bold]  {v['username'] or '—'}",
        f"[bold]SID:[/bold]       {sid or '—'}",
        f"[bold]Full name:[/bold] {v['fullname'] or '—'}",
        f"[bold]Comment:[/bold]   {v['comment'] or '—'}",
        "",
        f"[bold]LM hash:[/bold]   {lm_str}",
        f"[bold]NT hash:[/bold]   {nt_str}",
        "",
        "[dim]LM/NT hash bytes are RC4-obfuscated with the SYSKEY.[/dim]",
        "[dim]SYSKEY: SYSTEM\\ControlSet001\\Control\\Lsa\\{JD,Skew1,GBG,Data}[/dim]",
    ]
    console.print(Panel("\n".join(panel_lines), title="Decoded", border_style="green"))

    if csv_out is not None:
        rid_from_sid = sid.rsplit("-", 1)[-1] if sid else ""
        _write_csv(csv_out,
                   ["Username", "RID", "SID", "Full name", "Comment", "LM hash", "NT hash"],
                   [[v["username"], rid_from_sid, sid or "",
                     v["fullname"], v["comment"],
                     v["lm_hash"].hex() if v["lm_hash"] else "",
                     v["nt_hash"].hex() if v["nt_hash"] else ""]], console)


@app.command(name="f-blob")
def f_blob(
    file: Path = typer.Argument(..., help="Path to F blob binary", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export to CSV file"),
) -> None:
    """Decode a SAM F blob: account flags, last login time, RID, password age."""
    console = context.get_console()
    data = file.read_bytes()

    if len(data) < 0x44:
        console.print(f"[red]F blob too short: {len(data)} bytes (expected ≥0x44)[/red]")
        raise typer.Exit(1)

    f = parse_f_blob(data)
    flags_decoded = fmt_flags(f["account_flags"])
    flags_str = f"0x{f['account_flags']:04X}  {flags_decoded}"
    pw_change_str = "Must change at next logon" if f["pw_must_change"] else _ft(f["last_pw_change"])

    if context.output_json:
        flag_list = [name for bit, name in _ACCOUNT_FLAGS.items() if f["account_flags"] & bit]
        print(json.dumps({
            "rid": f["rid"],
            "account_flags": f"0x{f['account_flags']:04X}",
            "account_flags_decoded": flag_list,
            "last_logon": _ft_iso(f["last_logon"]),
            "last_pw_change": None if f["pw_must_change"] else _ft_iso(f["last_pw_change"]),
            "pw_must_change": f["pw_must_change"],
            "account_expires": _ft_iso(f["account_expires"]),
            "last_failed_logon": _ft_iso(f["last_failed_logon"]),
            "logon_count": f["logon_count"],
            "failed_count": f["failed_count"],
        }, indent=2))
        return

    hex_fields: list[tuple[int, int, str, str]] = [
        (0x00, 2, "Revision",          str(struct.unpack_from("<H", data, 0x00)[0])),
        (0x08, 8, "Last logon",        _ft_raw(struct.unpack_from("<Q", data, 0x08)[0])),
        (0x18, 8, "Last PW change",    _ft_raw(struct.unpack_from("<Q", data, 0x18)[0])),
        (0x20, 8, "Account expires",   _ft_raw(struct.unpack_from("<Q", data, 0x20)[0])),
        (0x28, 8, "Last failed logon", _ft_raw(struct.unpack_from("<Q", data, 0x28)[0])),
        (0x30, 4, "RID",               str(f["rid"])),
        (0x38, 4, "Account flags",     flags_str),
        (0x40, 2, "Failed count",      str(f["failed_count"])),
        (0x42, 2, "Logon count",       str(f["logon_count"])),
    ]
    render_hex_table(data[:0x44], hex_fields, title=f"SAM F Blob — {file.name}", console=console)

    console.print(Panel(
        f"[bold]RID:[/bold]               {f['rid']}\n"
        f"[bold]Account flags:[/bold]     {flags_str}\n"
        f"[bold]Last logon:[/bold]        {_ft(f['last_logon'])}\n"
        f"[bold]Last PW change:[/bold]    {pw_change_str}\n"
        f"[bold]Account expires:[/bold]   {_ft(f['account_expires'])}\n"
        f"[bold]Last failed logon:[/bold] {_ft(f['last_failed_logon'])}\n"
        f"[bold]Failed logon count:[/bold]{f['failed_count']}\n"
        f"[bold]Total logon count:[/bold] {f['logon_count']}",
        title="Decoded",
        border_style="green",
    ))

    if csv_out is not None:
        _write_csv(csv_out,
                   ["RID", "Flags", "Last logon", "Last PW change", "Account expires",
                    "Last failed logon", "Logon count", "Failed count"],
                   [[str(f["rid"]), f"0x{f['account_flags']:04X}", _ft(f["last_logon"]),
                     pw_change_str, _ft(f["account_expires"]), _ft(f["last_failed_logon"]),
                     str(f["logon_count"]), str(f["failed_count"])]], console)


@app.command()
def account(
    f_file: Path = typer.Argument(..., help="Path to F blob binary", exists=True),
    v_file: Path = typer.Argument(..., help="Path to V blob binary", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export to CSV file"),
) -> None:
    """Combine F and V blobs: full account view like 'hives sam users' for a single account."""
    console = context.get_console()

    f_data = f_file.read_bytes()
    v_data = v_file.read_bytes()

    if len(f_data) < 0x44:
        console.print(f"[red]F blob too short: {len(f_data)} bytes (expected ≥0x44)[/red]")
        raise typer.Exit(1)

    v = parse_v_blob(v_data)
    f = parse_f_blob(f_data)

    effective_rid = f["rid"]
    sid = extract_sid_from_v_blob(v_data) or f"S-1-5-21-???-{effective_rid}"
    flags_decoded = fmt_flags(f["account_flags"])
    flags_str = f"0x{f['account_flags']:04X}  {flags_decoded}"
    pw_change_str = "Must change at next logon" if f["pw_must_change"] else _ft(f["last_pw_change"])
    username = v["username"] or f"RID {effective_rid}"

    # Detect mismatched F/V pair by comparing RIDs
    v_sid = extract_sid_from_v_blob(v_data)
    v_rid: int | None = None
    if v_sid:
        try:
            v_rid = int(v_sid.rsplit("-", 1)[-1])
        except ValueError:
            pass
    mismatch = v_rid is not None and v_rid != effective_rid

    if context.output_json:
        flag_list = [name for bit, name in _ACCOUNT_FLAGS.items() if f["account_flags"] & bit]
        out: dict = {
            "rid": effective_rid,
            "sid": sid,
            "username": v["username"],
            "fullname": v["fullname"],
            "comment": v["comment"],
            "lm_hash": v["lm_hash"].hex(" ").upper() if v["lm_hash"] else None,
            "nt_hash": v["nt_hash"].hex(" ").upper() if v["nt_hash"] else None,
            "account_flags": f"0x{f['account_flags']:04X}",
            "account_flags_decoded": flag_list,
            "last_logon": _ft_iso(f["last_logon"]),
            "last_pw_change": None if f["pw_must_change"] else _ft_iso(f["last_pw_change"]),
            "pw_must_change": f["pw_must_change"],
            "account_expires": _ft_iso(f["account_expires"]),
            "last_failed_logon": _ft_iso(f["last_failed_logon"]),
            "logon_count": f["logon_count"],
            "failed_count": f["failed_count"],
        }
        if mismatch:
            out["mismatch_warning"] = (
                f"F blob RID ({effective_rid}) does not match V blob RID ({v_rid}) — "
                "these blobs belong to different accounts"
            )
        print(json.dumps(out, indent=2))
        return

    if mismatch:
        console.print(
            f"[bold yellow]WARNING:[/bold yellow] F blob RID ({effective_rid}) does not match "
            f"V blob RID ({v_rid}) — these blobs belong to different accounts. "
            f"Results below combine mismatched data."
        )

    id_table = Table(title="Identity", box=box.ROUNDED, header_style="bold")
    id_table.add_column("RID", justify="right")
    id_table.add_column("SID")
    id_table.add_column("Username")
    id_table.add_column("Full name")
    id_table.add_column("Comment", max_width=44)
    id_table.add_row(str(effective_rid), sid, v["username"] or f"[dim]RID {effective_rid}[/dim]",
                     v["fullname"] or "—", v["comment"] or "—")
    console.print(id_table)

    sec_table = Table(title="Security & Logon", box=box.ROUNDED, header_style="bold")
    sec_table.add_column("RID", justify="right")
    sec_table.add_column("Username")
    sec_table.add_column("Flags")
    sec_table.add_column("Last logon")
    sec_table.add_column("Last PW change")
    sec_table.add_column("Expires")
    sec_table.add_column("Logons", justify="right")
    sec_table.add_column("Failed", justify="right")
    sec_table.add_row(str(effective_rid), username, flags_str,
                      _ft(f["last_logon"]), pw_change_str, _ft(f["account_expires"]),
                      str(f["logon_count"]), str(f["failed_count"]))
    console.print(sec_table)

    lm_str = "[yellow]present (obfuscated)[/yellow]" if v["lm_hash"] else "[dim]not present[/dim]"
    nt_str = "[yellow]present (obfuscated)[/yellow]" if v["nt_hash"] else "[dim]not present[/dim]"
    console.print(f"  LM hash: {lm_str}    NT hash: {nt_str}")
    console.print("[dim]  LM/NT hash bytes are RC4-obfuscated with the SYSKEY.[/dim]")

    if csv_out is not None:
        _write_csv(csv_out, _ACCOUNT_HEADERS,
                   [[str(effective_rid), sid, username, v["fullname"], v["comment"],
                     f"0x{f['account_flags']:04X}", _ft(f["last_logon"]), pw_change_str,
                     _ft(f["account_expires"]), str(f["logon_count"]), str(f["failed_count"])]], console)
