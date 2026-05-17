from __future__ import annotations
import json
import struct
from pathlib import Path

import typer
from rich.panel import Panel

from ifn import context
from ifn.parsers.windows_time import filetime_to_datetime
from ifn.parsers.sam import ACCOUNT_FLAGS as _ACCOUNT_FLAGS
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse SAM hive F and V value blobs")


@app.command(name="v-blob")
def v_blob(file: Path = typer.Argument(..., help="Path to V blob binary", exists=True)) -> None:
    """Decode a SAM V blob: username, account info, NT/LM hash locations.

    NOTE: Hash bytes are obfuscated. SYSKEY (from SYSTEM hive) is required to decrypt.
    """
    console = context.get_console()
    data = file.read_bytes()

    BASE = 0xCC

    def read_field(index: int) -> tuple[int, int, bytes]:
        off = index * 12
        rel_off = struct.unpack_from("<I", data, off)[0]
        length = struct.unpack_from("<I", data, off + 4)[0]
        abs_off = BASE + rel_off
        content = data[abs_off: abs_off + length] if abs_off + length <= len(data) else b""
        return rel_off, length, content

    rel0, ln0, raw0 = read_field(0)
    rel1, ln1, raw1 = read_field(1)
    rel2, ln2, raw2 = read_field(2)
    rel3, ln3, raw3 = read_field(3)
    rel12, ln12, raw12 = read_field(12)
    rel13, ln13, raw13 = read_field(13)

    username = raw1.decode("utf-16-le", errors="replace") if raw1 else "?"
    fullname = raw2.decode("utf-16-le", errors="replace") if raw2 else ""
    comment = raw3.decode("utf-16-le", errors="replace") if raw3 else ""
    lm_offset = BASE + rel12 if ln12 > 8 else None
    nt_offset = BASE + rel13 if ln13 >= 20 else None

    if context.output_json:
        print(json.dumps({
            "username": username,
            "fullname": fullname,
            "comment": comment,
            "lm_hash_offset": lm_offset,
            "lm_hash_length": ln12,
            "nt_hash_offset": nt_offset,
            "nt_hash_length": ln13,
            "note": "LM/NT hashes are RC4-obfuscated with SYSKEY",
        }, indent=2))
        return

    fields: list[tuple[int, int, str, str]] = []
    fields.append((0,  4, "F0 acct blob offset", str(rel0)))
    fields.append((4,  4, "F0 acct blob length", str(ln0)))
    if ln0:
        fields.append((BASE + rel0, min(ln0, 32), "Account blob (first 32 B)", raw0[:32].hex(" ").upper()))
    fields.append((12, 4, "F1 username offset", str(rel1)))
    fields.append((16, 4, "F1 username length", str(ln1)))
    if ln1:
        fields.append((BASE + rel1, ln1, "Username (UTF-16LE)", username))
    fields.append((24, 4, "F2 full name offset", str(rel2)))
    fields.append((28, 4, "F2 full name length", str(ln2)))
    if ln2:
        fields.append((BASE + rel2, ln2, "Full name (UTF-16LE)", fullname))
    fields.append((36, 4, "F3 comment offset", str(rel3)))
    fields.append((40, 4, "F3 comment length", str(ln3)))
    if ln3:
        fields.append((BASE + rel3, ln3, "Comment (UTF-16LE)", comment))
    fields.append((144, 4, "F12 LM hash offset", str(rel12)))
    fields.append((148, 4, "F12 LM hash length", f"{ln12} bytes" + (" (disabled)" if ln12 <= 8 else "")))
    if ln12 > 8:
        fields.append((BASE + rel12, ln12, "LM hash (obfuscated)", raw12.hex(" ").upper()))
    fields.append((156, 4, "F13 NT hash offset", str(rel13)))
    fields.append((160, 4, "F13 NT hash length", f"{ln13} bytes"))
    if ln13 >= 20:
        hash_bytes = raw13[8:24] if len(raw13) >= 24 else raw13[4:20]
        fields.append((BASE + rel13 + 8, 16, "NT hash (obfuscated, 16 B)", hash_bytes.hex(" ").upper()))

    render_hex_table(data, fields, title=f"SAM V Blob — {file.name}", console=console)
    console.print(Panel(
        f"[bold]Username:[/bold]  {username}\n"
        f"[bold]Full name:[/bold] {fullname or '—'}\n"
        f"[bold]Comment:[/bold]   {comment}\n"
        f"\n[dim]LM/NT hash bytes at offsets above are RC4-obfuscated with the SYSKEY.[/dim]\n"
        f"[dim]SYSKEY is derived from SYSTEM\\ControlSet001\\Control\\Lsa\\{{JD,Skew1,GBG,Data}}[/dim]",
        title="Decoded",
        border_style="green",
    ))


@app.command(name="f-blob")
def f_blob(file: Path = typer.Argument(..., help="Path to F blob binary", exists=True)) -> None:
    """Decode a SAM F blob: account flags, last login time, RID, password age."""
    console = context.get_console()
    data = file.read_bytes()

    if len(data) < 72:
        console.print(f"[red]F blob too short: {len(data)} bytes (expected ≥72)[/red]")
        raise typer.Exit(1)

    revision = struct.unpack_from("<H", data, 0x00)[0]
    last_logon_ft      = struct.unpack_from("<Q", data, 0x08)[0]
    last_pw_change_ft  = struct.unpack_from("<Q", data, 0x18)[0]
    account_expires_ft = struct.unpack_from("<Q", data, 0x20)[0]
    last_failed_ft     = struct.unpack_from("<Q", data, 0x28)[0]
    rid                = struct.unpack_from("<I", data, 0x30)[0]
    acct_flags         = struct.unpack_from("<I", data, 0x38)[0]
    failed_count       = struct.unpack_from("<H", data, 0x40)[0]
    logon_count        = struct.unpack_from("<H", data, 0x42)[0]

    def ft(ticks: int) -> str:
        if ticks == 0x7FFFFFFFFFFFFFFF:
            return "Never expires"
        if ticks == 0:
            return "Never"
        return filetime_to_datetime(ticks).strftime("%Y-%m-%d %H:%M:%S UTC")

    def ft_iso(ticks: int) -> str | None:
        if ticks in (0, 0x7FFFFFFFFFFFFFFF):
            return None
        return filetime_to_datetime(ticks).strftime("%Y-%m-%dT%H:%M:%S") + "Z"

    flag_names = [name for bit, name in _ACCOUNT_FLAGS.items() if acct_flags & bit]

    if context.output_json:
        print(json.dumps({
            "rid": rid,
            "account_flags": f"0x{acct_flags:08X}",
            "account_flags_decoded": flag_names,
            "last_logon": ft_iso(last_logon_ft),
            "last_pw_change": ft_iso(last_pw_change_ft),
            "account_expires": ft_iso(account_expires_ft),
            "last_failed_logon": ft_iso(last_failed_ft),
            "logon_count": logon_count,
            "failed_count": failed_count,
        }, indent=2))
        return

    hex_fields: list[tuple[int, int, str, str]] = [
        (0x00, 2, "Revision",          str(revision)),
        (0x08, 8, "Last logon",        ft(last_logon_ft)),
        (0x18, 8, "Last PW change",    ft(last_pw_change_ft)),
        (0x20, 8, "Account expires",   ft(account_expires_ft)),
        (0x28, 8, "Last failed logon", ft(last_failed_ft)),
        (0x30, 4, "RID",               str(rid)),
        (0x38, 4, "Account flags",     f"0x{acct_flags:08X}"),
        (0x40, 2, "Failed count",      str(failed_count)),
        (0x42, 2, "Logon count",       str(logon_count)),
    ]
    render_hex_table(data[:0x44], hex_fields, title=f"SAM F Blob — {file.name}", console=console)

    pw_change_str = "Must change at next logon" if last_pw_change_ft == 0 else ft(last_pw_change_ft)
    console.print(Panel(
        f"[bold]RID:[/bold]               {rid}\n"
        f"[bold]Account flags:[/bold]     0x{acct_flags:08X}  ({', '.join(flag_names) or 'None'})\n"
        f"[bold]Last logon:[/bold]        {ft(last_logon_ft)}\n"
        f"[bold]Last PW change:[/bold]    {pw_change_str}\n"
        f"[bold]Account expires:[/bold]   {ft(account_expires_ft)}\n"
        f"[bold]Last failed logon:[/bold] {ft(last_failed_ft)}\n"
        f"[bold]Failed logon count:[/bold]{failed_count}\n"
        f"[bold]Total logon count:[/bold] {logon_count}",
        title="Decoded",
        border_style="green",
    ))
