from __future__ import annotations
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.table import Table
from rich import box
from Registry import Registry

from ifn import context
from ifn.parsers.windows_time import filetime_to_datetime

app = typer.Typer(help="SOFTWARE hive analysis")

_AUTORUN_HEADERS = ["Source", "Name", "Command"]
_PROFILES_HEADERS = ["SID", "RID", "Profile path", "Last written"]


def _open_hive(path: Path) -> Registry.Registry:
    console = context.get_console()
    try:
        return Registry.Registry(str(path))
    except Exception as e:
        console.print(f"[red]Failed to open hive: {e}[/red]")
        raise typer.Exit(1)


def _val(key, name: str, default: str = "—") -> str:
    try:
        v = key.value(name).value()
        s = str(v) if v is not None else ""
        return s if s else default
    except Exception:
        return default


def _val_raw(key, name: str):
    try:
        return key.value(name).value()
    except Exception:
        return None


@app.command()
def info(hive: Path = typer.Argument(..., help="Path to SOFTWARE hive", exists=True)) -> None:
    """Comprehensive Windows installation info from Microsoft\\Windows NT\\CurrentVersion."""
    console = context.get_console()
    reg = _open_hive(hive)
    try:
        key = reg.open("Microsoft\\Windows NT\\CurrentVersion")
    except Registry.RegistryKeyNotFoundException:
        console.print("[red]Microsoft\\Windows NT\\CurrentVersion not found — is this a SOFTWARE hive?[/red]")
        raise typer.Exit(1)

    def _ts_unix(name: str) -> str:
        try:
            return datetime.fromtimestamp(key.value(name).value(), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return "—"

    def _ts_ft(name: str) -> str:
        try:
            return filetime_to_datetime(key.value(name).value()).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return "—"

    def _hex(name: str, n: int = 32) -> str:
        try:
            raw = key.value(name).value()
            if isinstance(raw, bytes):
                return raw[:n].hex(" ").upper() + ("…" if len(raw) > n else "")
            return str(raw)
        except Exception:
            return "—"

    fields = [
        ("ProductName",                _val(key, "ProductName")),
        ("SoftwareType",               _val(key, "SoftwareType")),
        ("InstallationType",           _val(key, "InstallationType")),
        ("EditionID",                  _val(key, "EditionID")),
        ("CompositionEditionID",       _val(key, "CompositionEditionID")),
        ("EditionSubstring",           _val(key, "EditionSubstring")),
        ("EditionSubVersion",          _val(key, "EditionSubVersion")),
        ("EditionSubManufacturer",     _val(key, "EditionSubManufacturer")),
        ("RegisteredOwner",            _val(key, "RegisteredOwner")),
        ("RegisteredOrganization",     _val(key, "RegisteredOrganization")),
        ("ProductId",                  _val(key, "ProductId")),
        ("DisplayVersion",             _val(key, "DisplayVersion")),
        ("ReleaseId",                  _val(key, "ReleaseId")),
        ("CurrentVersion",             _val(key, "CurrentVersion")),
        ("CurrentMajorVersionNumber",  _val(key, "CurrentMajorVersionNumber")),
        ("CurrentMinorVersionNumber",  _val(key, "CurrentMinorVersionNumber")),
        ("CurrentType",                _val(key, "CurrentType")),
        ("CurrentBuild",               _val(key, "CurrentBuild")),
        ("CurrentBuildNumber",         _val(key, "CurrentBuildNumber")),
        ("BaseBuildRevisionNumber",    _val(key, "BaseBuildRevisionNumber")),
        ("UBR",                        _val(key, "UBR")),
        ("BuildBranch",                _val(key, "BuildBranch")),
        ("BuildLab",                   _val(key, "BuildLab")),
        ("BuildLabEx",                 _val(key, "BuildLabEx")),
        ("BuildGUID",                  _val(key, "BuildGUID")),
        ("SystemRoot",                 _val(key, "SystemRoot")),
        ("PathName",                   _val(key, "PathName")),
        ("WinREVersion",               _val(key, "WinREVersion")),
        ("InstallDate",                _ts_unix("InstallDate")),
        ("InstallTime",                _ts_ft("InstallTime")),
        ("DigitalProductId",           _hex("DigitalProductId")),
        ("DigitalProductId4",          _hex("DigitalProductId4")),
    ]

    if context.output_json:
        print(json.dumps(dict(fields), indent=2))
        return

    table = Table(title="SOFTWARE — Windows Installation", box=box.ROUNDED, header_style="bold")
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value")
    for field, value in fields:
        table.add_row(field, value if value != "—" else "[dim]—[/dim]")
    console.print(table)


@app.command()
def autorun(
    hive: Path = typer.Argument(..., help="Path to SOFTWARE hive", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export autorun entries to CSV file"),
) -> None:
    """List auto-start programs from Run and RunOnce keys."""
    console = context.get_console()
    reg = _open_hive(hive)

    run_paths = [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows\\CurrentVersion\\RunServices",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]

    rows: list[tuple[str, str, str]] = []
    for path in run_paths:
        try:
            key = reg.open(path)
        except Registry.RegistryKeyNotFoundException:
            continue
        short = path.rsplit("\\", 2)[-2] + "\\" + path.rsplit("\\", 1)[-1]
        for val in key.values():
            rows.append((short, val.name() or "(Default)", str(val.value())))

    if context.output_json:
        print(json.dumps([{"source": s, "name": n, "command": c} for s, n, c in rows], indent=2))
        return

    if not rows:
        console.print("[dim]No auto-start entries found.[/dim]")
        return

    table = Table(title="Auto-Start Programs", box=box.ROUNDED, header_style="bold")
    table.add_column("Source")
    table.add_column("Name")
    table.add_column("Command")
    csv_rows: list[list[str]] = []
    for source, name, command in rows:
        table.add_row(source, name, command)
        csv_rows.append([source, name, command])
    console.print(table)
    _write_csv(csv_out, _AUTORUN_HEADERS, csv_rows, console)


@app.command()
def profiles(
    hive: Path = typer.Argument(..., help="Path to SOFTWARE hive", exists=True),
    csv_out: Optional[Path] = typer.Option(None, "--csv", help="Export profiles to CSV file"),
) -> None:
    """List user profiles: SID → home directory mapping."""
    console = context.get_console()
    reg = _open_hive(hive)
    try:
        pl_key = reg.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    except Registry.RegistryKeyNotFoundException:
        console.print("[red]ProfileList key not found.[/red]")
        raise typer.Exit(1)

    profile_rows: list[tuple[str, str, str, str]] = []
    for subkey in pl_key.subkeys():
        sid = subkey.name()
        rid_str = sid.rsplit("-", 1)[-1] if "-" in sid else "—"
        try:
            profile_path = str(subkey.value("ProfileImagePath").value())
        except Exception:
            profile_path = "—"
        ts = subkey.timestamp()
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "—"
        profile_rows.append((sid, rid_str, profile_path, ts_str))

    if context.output_json:
        print(json.dumps([
            {"sid": sid, "rid": rid, "profile_path": path, "last_written": ts}
            for sid, rid, path, ts in profile_rows
        ], indent=2))
        return

    table = Table(title="User Profiles", box=box.ROUNDED, header_style="bold")
    table.add_column("SID")
    table.add_column("RID", justify="right")
    table.add_column("Profile path")
    table.add_column("Last written")
    csv_rows: list[list[str]] = []
    for sid, rid_str, profile_path, ts_str in profile_rows:
        table.add_row(sid, rid_str, profile_path, ts_str)
        csv_rows.append([sid, rid_str, profile_path, ts_str])
    console.print(table)
    _write_csv(csv_out, _PROFILES_HEADERS, csv_rows, console)


def _write_csv(path: Optional[Path], headers: list[str], rows: list[list[str]], console) -> None:
    if path is None:
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        writer.writerows(rows)
    console.print(f"[green]✓ Exported {len(rows)} row(s) → {path}[/green]")
