from pathlib import Path

import struct
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from ifn.parsers.windows_time import filetime_to_datetime
from ifn.display.hex_table import render_hex_table

app = typer.Typer(help="Parse SAM hive F and V value blobs")
console = Console()

_ACCOUNT_FLAGS = {
    0x0001: "Account disabled",
    0x0002: "Home directory required",
    0x0004: "Password not required",
    0x0008: "Temporary duplicate account",
    0x0010: "Normal user account",
    0x0020: "MNS logon account",
    0x0040: "Interdomain trust account",
    0x0080: "Workstation trust account",
    0x0100: "Server trust account",
    0x0200: "Password does not expire",
    0x0400: "Account auto-locked",
}


@app.command(name="v-blob")
def v_blob(file: Path = typer.Argument(..., help="Path to V blob binary", exists=True)):
    """Decode a SAM V blob: username, account info, NT/LM hash locations.

    NOTE: Hash bytes are obfuscated. SYSKEY (from SYSTEM hive) is required to decrypt.
    """
    data = file.read_bytes()

    # V blob header: 12 triples of (offset, length, ??) each 4 bytes
    # Relative to offset 0xCC in the blob
    BASE = 0xCC

    def read_field(index: int) -> tuple[int, int, bytes]:
        off = index * 12
        rel_off = struct.unpack_from("<I", data, off)[0]
        length = struct.unpack_from("<I", data, off + 4)[0]
        abs_off = BASE + rel_off
        content = data[abs_off: abs_off + length] if abs_off + length <= len(data) else b""
        return rel_off, length, content

    fields: list[tuple[int, int, str, str]] = []

    # Field 0: account metadata / ACL (large binary blob — NOT the username)
    rel0, ln0, raw0 = read_field(0)
    fields.append((0,  4, "F0 acct blob offset", str(rel0)))
    fields.append((4,  4, "F0 acct blob length", str(ln0)))
    if ln0:
        fields.append((BASE + rel0, min(ln0, 32), "Account blob (first 32 B)", raw0[:32].hex(" ").upper()))

    # Field 1: username (UTF-16LE)
    rel, ln, raw = read_field(1)
    username = raw.decode("utf-16-le", errors="replace") if raw else "?"
    fields.append((12, 4, "F1 username offset", str(rel)))
    fields.append((16, 4, "F1 username length", str(ln)))
    if ln:
        fields.append((BASE + rel, ln, "Username (UTF-16LE)", username))

    # Field 2: full name (UTF-16LE)
    rel, ln, raw = read_field(2)
    fullname = raw.decode("utf-16-le", errors="replace") if raw else "—"
    fields.append((24, 4, "F2 full name offset", str(rel)))
    fields.append((28, 4, "F2 full name length", str(ln)))
    if ln:
        fields.append((BASE + rel, ln, "Full name (UTF-16LE)", fullname))

    # Field 3: comment
    rel, ln, raw = read_field(3)
    comment = raw.decode("utf-16-le", errors="replace") if raw else "—"
    fields.append((36, 4, "F3 comment offset", str(rel)))
    fields.append((40, 4, "F3 comment length", str(ln)))
    if ln:
        fields.append((BASE + rel, ln, "Comment (UTF-16LE)", comment))

    # Field 12: LM hash (obfuscated; 8 bytes = disabled, 20 bytes = 4-byte hdr + 16-byte hash)
    rel12, ln12, raw12 = read_field(12)
    fields.append((144, 4, "F12 LM hash offset", str(rel12)))
    fields.append((148, 4, "F12 LM hash length", f"{ln12} bytes" + (" (disabled)" if ln12 <= 8 else "")))
    if ln12 > 8:
        fields.append((BASE + rel12, ln12, "LM hash (obfuscated)", raw12.hex(" ").upper()))

    # Field 13: NT hash (obfuscated; 24 bytes = 8-byte hdr + 16-byte hash)
    rel13, ln13, raw13 = read_field(13)
    fields.append((156, 4, "F13 NT hash offset", str(rel13)))
    fields.append((160, 4, "F13 NT hash length", f"{ln13} bytes"))
    if ln13 >= 20:
        # Skip 8-byte header, next 16 bytes are the obfuscated hash
        hash_bytes = raw13[8:24] if len(raw13) >= 24 else raw13[4:20]
        fields.append((BASE + rel13 + 8, 16, "NT hash (obfuscated, 16 B)", hash_bytes.hex(" ").upper()))

    render_hex_table(data, fields, title=f"SAM V Blob — {file.name}")

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
def f_blob(file: Path = typer.Argument(..., help="Path to F blob binary", exists=True)):
    """Decode a SAM F blob: account flags, last login time, RID, password age."""
    data = file.read_bytes()

    if len(data) < 72:
        console.print(f"[red]F blob too short: {len(data)} bytes (expected ≥72)[/red]")
        raise typer.Exit(1)

    revision = struct.unpack_from("<H", data, 0)[0]
    last_logon_ft = struct.unpack_from("<Q", data, 8)[0]
    last_pw_change_ft = struct.unpack_from("<Q", data, 24)[0]
    account_expires_ft = struct.unpack_from("<Q", data, 32)[0]
    last_failed_ft = struct.unpack_from("<Q", data, 40)[0]
    rid = struct.unpack_from("<I", data, 48)[0]
    acct_flags = struct.unpack_from("<H", data, 52)[0]
    failed_count = struct.unpack_from("<H", data, 64)[0]
    logon_count = struct.unpack_from("<H", data, 66)[0]

    def ft(ticks: int) -> str:
        if ticks == 0:
            return "Never"
        if ticks == 0x7FFFFFFFFFFFFFFF:
            return "Never expires"
        return filetime_to_datetime(ticks).strftime("%Y-%m-%d %H:%M:%S UTC")

    flag_names = [name for bit, name in _ACCOUNT_FLAGS.items() if acct_flags & bit]

    hex_fields: list[tuple[int, int, str, str]] = [
        (0,  2,  "Revision",         str(revision)),
        (8,  8,  "Last logon",       ft(last_logon_ft)),
        (24, 8,  "Last PW change",   ft(last_pw_change_ft)),
        (32, 8,  "Account expires",  ft(account_expires_ft)),
        (40, 8,  "Last failed logon",ft(last_failed_ft)),
        (48, 4,  "RID",              str(rid)),
        (52, 2,  "Account flags",    f"0x{acct_flags:04X}"),
        (64, 2,  "Failed count",     str(failed_count)),
        (66, 2,  "Logon count",      str(logon_count)),
    ]
    render_hex_table(data[:72], hex_fields, title=f"SAM F Blob — {file.name}")

    console.print(Panel(
        f"[bold]RID:[/bold]              {rid}\n"
        f"[bold]Account flags:[/bold]    0x{acct_flags:04X}  ({', '.join(flag_names) or 'None'})\n"
        f"[bold]Last logon:[/bold]       {ft(last_logon_ft)}\n"
        f"[bold]Last PW change:[/bold]   {ft(last_pw_change_ft)}\n"
        f"[bold]Account expires:[/bold]  {ft(account_expires_ft)}\n"
        f"[bold]Last failed logon:[/bold]{ft(last_failed_ft)}\n"
        f"[bold]Failed logon count:[/bold]{failed_count}\n"
        f"[bold]Total logon count:[/bold] {logon_count}",
        title="Decoded",
        border_style="green",
    ))
