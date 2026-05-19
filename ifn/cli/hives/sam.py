from __future__ import annotations
import csv
import json
import struct
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table
from rich import box
from Registry import Registry

from ifn import context
from ifn.parsers.sam import parse_v_blob, parse_f_blob, fmt_flags, extract_sid_from_v_blob

app = typer.Typer(help="SAM hive analysis")

_BUILTIN_GROUPS = {
    544: "Administrators",
    545: "Users",
    546: "Guests",
    547: "Power Users",
    548: "Account Operators",
    549: "Server Operators",
    550: "Print Operators",
    551: "Backup Operators",
    552: "Replicators",
    553: "RAS and IAS Servers",
    554: "Pre-Windows 2000 Compatible Access",
    555: "Remote Desktop Users",
    556: "Network Configuration Operators",
    558: "Performance Monitor Users",
    559: "Performance Log Users",
    562: "Distributed COM Users",
    568: "IIS_IUSRS",
    569: "Cryptographic Operators",
    573: "Event Log Readers",
    574: "Certificate Service DCOM Access",
    578: "Hyper-V Administrators",
    579: "Access Control Assistance Operators",
    580: "Remote Management Users",
    581: "System Managed Accounts Group",
    583: "Device Owners",
}

_USERS_HEADERS = ["RID", "SID", "Username", "Full name", "Comment", "Flags", "Last logon",
                  "Last PW change", "Expires", "Logons", "Failed"]
_GROUPS_HEADERS = ["RID", "Name", "Source", "Last written"]


def _open_hive(path: Path) -> Registry.Registry:
    console = context.get_console()
    try:
        return Registry.Registry(str(path))
    except Exception as e:
        console.print(f"[red]Failed to open hive: {e}[/red]")
        raise typer.Exit(1)


def _fmt_ts(dt, pw_must_change: bool = False) -> str:
    if pw_must_change:
        return "Must change at next logon"
    if dt is None:
        return "Never"
    if isinstance(dt, str):
        return dt
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_ts_iso(dt) -> str | None:
    if dt is None:
        return None
    try:
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    except Exception:
        return str(dt)


@app.command()
def users(
    hive: Path = typer.Argument(..., help="Path to SAM hive", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export users to CSV file"),
) -> None:
    """List all local users: RID, account flags, timestamps, logon metadata."""
    console = context.get_console()
    reg = _open_hive(hive)

    try:
        users_key = reg.open("SAM\\Domains\\Account\\Users")
    except Registry.RegistryKeyNotFoundException:
        console.print("[red]SAM\\Domains\\Account\\Users not found — is this a SAM hive?[/red]")
        raise typer.Exit(1)

    entries: list[tuple[int, bytes, bytes]] = []
    for subkey in sorted(users_key.subkeys(), key=lambda k: k.name()):
        if subkey.name() == "Names":
            continue
        try:
            rid = int(subkey.name(), 16)
        except ValueError:
            continue
        try:
            v_data = subkey.value("V").value()
            f_data = subkey.value("F").value()
            entries.append((rid, v_data, f_data))
        except Exception:
            pass

    domain_sid: str | None = None
    for rid, v_data, _ in entries:
        sid = extract_sid_from_v_blob(v_data)
        if sid:
            domain_sid = sid.rsplit("-", 1)[0]
            break

    if context.output_json:
        result = []
        for rid, v_data, f_data in entries:
            v = parse_v_blob(v_data)
            f = parse_f_blob(f_data)
            sid = extract_sid_from_v_blob(v_data) or (f"{domain_sid}-{rid}" if domain_sid else f"S-1-5-21-???-{rid}")
            result.append({
                "rid": rid,
                "sid": sid,
                "username": v["username"],
                "fullname": v["fullname"],
                "comment": v["comment"],
                "account_flags": f"0x{f['account_flags']:04X}",
                "account_flags_decoded": fmt_flags(f["account_flags"]),
                "last_logon": _fmt_ts_iso(f["last_logon"]),
                "last_pw_change": None if f["pw_must_change"] else _fmt_ts_iso(f["last_pw_change"]),
                "pw_must_change": f["pw_must_change"],
                "account_expires": _fmt_ts_iso(f["account_expires"]),
                "logon_count": f["logon_count"],
                "failed_count": f["failed_count"],
            })
        print(json.dumps(result, indent=2))
        return

    id_table = Table(title="SAM Users — Identity", box=box.ROUNDED, header_style="bold")
    id_table.add_column("RID", justify="right")
    id_table.add_column("SID")
    id_table.add_column("Username")
    id_table.add_column("Full name")
    id_table.add_column("Comment", max_width=44)

    sec_table = Table(title="SAM Users — Security & Logon", box=box.ROUNDED, header_style="bold")
    sec_table.add_column("RID", justify="right")
    sec_table.add_column("Username")
    sec_table.add_column("Flags (0xHHHH)")
    sec_table.add_column("Last logon")
    sec_table.add_column("Last PW change")
    sec_table.add_column("Expires")
    sec_table.add_column("Logons", justify="right")
    sec_table.add_column("Failed", justify="right")

    csv_rows: list[list[str]] = []
    for rid, v_data, f_data in entries:
        v = parse_v_blob(v_data)
        f = parse_f_blob(f_data)
        sid = extract_sid_from_v_blob(v_data) or (f"{domain_sid}-{rid}" if domain_sid else f"S-1-5-21-???-{rid}")
        flags_str = f"0x{f['account_flags']:04X}  {fmt_flags(f['account_flags'])}"
        username = v["username"] or f"RID {rid}"
        last_pw = _fmt_ts(f["last_pw_change"], pw_must_change=f["pw_must_change"])
        id_table.add_row(str(rid), sid, v["username"] or f"[dim]RID {rid}[/dim]", v["fullname"] or "—", v["comment"] or "—")
        sec_table.add_row(str(rid), v["username"] or f"[dim]{rid}[/dim]", flags_str,
                          _fmt_ts(f["last_logon"]), last_pw, _fmt_ts(f["account_expires"]),
                          str(f["logon_count"]), str(f["failed_count"]))
        csv_rows.append([str(rid), sid, username, v["fullname"] or "", v["comment"] or "",
                         f"0x{f['account_flags']:04X}", _fmt_ts(f["last_logon"]), last_pw,
                         _fmt_ts(f["account_expires"]), str(f["logon_count"]), str(f["failed_count"])])

    console.print(id_table)
    console.print(sec_table)
    _write_csv(csv_out, _USERS_HEADERS, csv_rows, console)


@app.command()
def groups(
    hive: Path = typer.Argument(..., help="Path to SAM hive", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export groups to CSV file"),
) -> None:
    """List builtin and account groups with best-effort name resolution."""
    console = context.get_console()
    reg = _open_hive(hive)

    group_rows: list[tuple[int, str, str, str]] = []
    for domain_path, source_label in [
        ("SAM\\Domains\\Builtin\\Aliases", "Builtin"),
        ("SAM\\Domains\\Account\\Aliases", "Account"),
    ]:
        try:
            aliases_key = reg.open(domain_path)
        except Registry.RegistryKeyNotFoundException:
            continue
        for subkey in aliases_key.subkeys():
            if subkey.name() == "Members":
                continue
            try:
                rid = int(subkey.name(), 16)
            except ValueError:
                continue
            name = _BUILTIN_GROUPS.get(rid) or _try_group_name(subkey) or f"Group_{rid}"
            ts = subkey.timestamp()
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "—"
            group_rows.append((rid, name, source_label, ts_str))

    if context.output_json:
        print(json.dumps([
            {"rid": rid, "name": name, "source": src, "last_written": ts}
            for rid, name, src, ts in group_rows
        ], indent=2))
        return

    if not group_rows:
        console.print("[dim]No group entries found.[/dim]")
        return

    table = Table(title="SAM Groups", box=box.ROUNDED, header_style="bold")
    table.add_column("RID", justify="right")
    table.add_column("Name")
    table.add_column("Source")
    table.add_column("Last written")

    csv_rows: list[list[str]] = []
    for rid, name, source_label, ts_str in group_rows:
        table.add_row(str(rid), name, source_label, ts_str)
        csv_rows.append([str(rid), name, source_label, ts_str])

    console.print(table)
    _write_csv(csv_out, _GROUPS_HEADERS, csv_rows, console)


def _try_group_name(subkey) -> str:
    """Best-effort: extract group name from SAM alias C blob (UTF-16LE at known offset)."""
    try:
        c_data = subkey.value("C").value()
        BASE = 0x34
        rel = struct.unpack_from("<I", c_data, 0x24)[0]
        ln = struct.unpack_from("<I", c_data, 0x28)[0]
        if 0 < ln <= 512:
            start = BASE + rel
            raw = c_data[start: start + ln]
            candidate = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            if candidate and all(0x20 <= ord(c) <= 0x7E or c in (" ", "\t") for c in candidate):
                return candidate
    except Exception:
        pass
    return ""


def _write_csv(path: Optional[Path], headers: list[str], rows: list[list[str]], console) -> None:
    if path is None:
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(rows)
    console.print(f"[green]✓ Exported {len(rows)} row(s) → {path}[/green]")
