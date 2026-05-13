from datetime import datetime, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich import box
from Registry import Registry

from ifn.parsers.windows_time import filetime_to_datetime

app = typer.Typer(help="SOFTWARE hive analysis")
console = Console()


def _open_hive(path: Path) -> Registry.Registry:
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


@app.command()
def info(hive: Path = typer.Argument(..., help="Path to SOFTWARE hive", exists=True)):
    """Comprehensive Windows installation info from Microsoft\\Windows NT\\CurrentVersion."""
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

    table = Table(title="SOFTWARE — Windows Installation", box=box.ROUNDED, header_style="bold")
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value")

    for field, value in [
        # Identity
        ("ProductName",                _val(key, "ProductName")),
        ("SoftwareType",               _val(key, "SoftwareType")),
        ("InstallationType",           _val(key, "InstallationType")),
        ("EditionID",                  _val(key, "EditionID")),
        ("CompositionEditionID",       _val(key, "CompositionEditionID")),
        ("EditionSubstring",           _val(key, "EditionSubstring")),
        ("EditionSubVersion",          _val(key, "EditionSubVersion")),
        ("EditionSubManufacturer",     _val(key, "EditionSubManufacturer")),
        # Owner / registration
        ("RegisteredOwner",            _val(key, "RegisteredOwner")),
        ("RegisteredOrganization",     _val(key, "RegisteredOrganization")),
        ("ProductId",                  _val(key, "ProductId")),
        # Version
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
        ("CSDVersion",                 _val(key, "CSDVersion")),
        ("CSDReleaseType",             _val(key, "CSDReleaseType")),
        ("CSDBuildNumber",             _val(key, "CSDBuildNumber")),
        # Build info
        ("BuildBranch",                _val(key, "BuildBranch")),
        ("BuildLab",                   _val(key, "BuildLab")),
        ("BuildLabEx",                 _val(key, "BuildLabEx")),
        ("BuildGUID",                  _val(key, "BuildGUID")),
        # Paths
        ("SystemRoot",                 _val(key, "SystemRoot")),
        ("PathName",                   _val(key, "PathName")),
        # Recovery
        ("WinREVersion",               _val(key, "WinREVersion")),
        # Timestamps
        ("InstallDate",                _ts_unix("InstallDate")),
        ("InstallTime",                _ts_ft("InstallTime")),
        # Binary IDs (first 32 bytes as hex)
        ("DigitalProductId",           _hex("DigitalProductId")),
        ("DigitalProductId4",          _hex("DigitalProductId4")),
    ]:
        table.add_row(field, value if value != "—" else "[dim]—[/dim]")

    console.print(table)


@app.command()
def autorun(hive: Path = typer.Argument(..., help="Path to SOFTWARE hive", exists=True)):
    """List auto-start programs from Run and RunOnce keys."""
    reg = _open_hive(hive)

    table = Table(title="Auto-Start Programs", box=box.ROUNDED, header_style="bold")
    table.add_column("Source")
    table.add_column("Name")
    table.add_column("Command")

    run_paths = [
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows\\CurrentVersion\\RunServices",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]

    for path in run_paths:
        try:
            key = reg.open(path)
        except Registry.RegistryKeyNotFoundException:
            continue
        short = path.rsplit("\\", 2)[-2] + "\\" + path.rsplit("\\", 1)[-1]
        for val in key.values():
            table.add_row(short, val.name() or "(Default)", str(val.value()))

    if table.row_count == 0:
        console.print("[dim]No auto-start entries found.[/dim]")
    else:
        console.print(table)


@app.command()
def profiles(hive: Path = typer.Argument(..., help="Path to SOFTWARE hive", exists=True)):
    """List user profiles: SID → home directory mapping."""
    reg = _open_hive(hive)
    try:
        pl_key = reg.open("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    except Registry.RegistryKeyNotFoundException:
        console.print("[red]ProfileList key not found.[/red]")
        raise typer.Exit(1)

    table = Table(title="User Profiles", box=box.ROUNDED, header_style="bold")
    table.add_column("SID")
    table.add_column("RID", justify="right")
    table.add_column("Profile path")
    table.add_column("Last written")

    for subkey in pl_key.subkeys():
        sid = subkey.name()
        rid_str = sid.rsplit("-", 1)[-1] if "-" in sid else "—"
        try:
            profile_path = subkey.value("ProfileImagePath").value()
        except Exception:
            profile_path = "—"
        ts = subkey.timestamp()
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else "—"
        table.add_row(sid, rid_str, str(profile_path), ts_str)

    console.print(table)
