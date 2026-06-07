# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

IFN Forensics Toolkit — a CLI tool for the HEIG-VD digital forensics course. Each subcommand parses a specific Windows artifact (MBR, GPT, NTFS VBR, MFT, USN Journal, LNK files, Recycle Bin, Registry hives, EVTX logs, etc.) and displays raw bytes alongside field-by-field interpretation.

## Setup and Running

```bash
uv sync                          # install dependencies
uv run tool.py --help            # run the CLI
uv run tool.py deps check        # verify system deps (ewfinfo, mmls, fls, cryptsetup, losetup)
```

**This project is strictly managed with `uv`. Never invoke `python` or `python3` directly — always use `uv run python` or `.venv/bin/python`.**

No test suite or Makefile. The project requires Python 3.13+ and system tools (libewf, sleuthkit, cryptsetup).

## Architecture

### Entry Point

`tool.py` creates a Typer app and aggregates subcommand groups from `ifn/cli/*.py` via `app.add_typer()`. A root `--callback` sets global output mode flags (`--json`, `--simple`).

### Three-Layer Structure

**`ifn/parsers/`** — binary format parsers. Each exposes a `parse(bytes) -> DataClass` function (or similar). Dataclasses carry structured fields plus derived properties. USA (Update Sequence Array) fixup for multi-sector NTFS structures is applied in this layer.

**`ifn/cli/`** — Typer command modules. Each command reads binary input, calls parsers, and routes output through the display layer. Handles file type detection (raw image vs. E01/EWF — auto-mounted via `ewfmount`; 7z archives with caching).

**`ifn/display/`** — Rich-based rendering. `hex_table.py` is the core primitive: `render_hex_table(data, fields, title, console)` produces a color-coded hex dump (each field region uniquely colored) alongside an offset/length/name/value annotation table.

### Output Modes

`ifn/context.py` holds global flags `output_json` and `output_simple`. Commands check these to emit JSON (for `jq` piping) or Rich-formatted output. `context.get_console()` returns an appropriate Rich Console. **Never put Rich markup into JSON or CSV output.**

### Field Spec Convention

Hex field specs are tuples: `(offset: int, length: int, field_name: str, interpreted_value: str)`. These drive both the hex coloring and the annotation table in `render_hex_table`.

---

## Complete Command Map

```text
tool.py [--json] [--simple]
  partitions parse <file>          # MBR + GPT partition table
  partitions mbr  <file>           # MBR sector hex breakdown
  vbr parse  <file>                # Generic VBR parse (any FS)
  vbr ntfs   <file>                # NTFS VBR with full BPB decode
  vbr compare <primary> <backup>   # Field-by-field VBR comparison
  lnk parse  <file>                # Windows .lnk shortcut
  trash info <file>                # $I metadata file (Recycle Bin)
  trash data <file>                # $R data file (Recycle Bin)
  mft record <source> [opts]       # Parse a single MFT entry
  mft scan   <source> [opts]       # Scan all MFT entries
  mft ls     <source> -e <num>     # Directory listing
  mft tree   <source> -e <num>     # Directory tree
  mft events <source> [opts]       # Parse .evtx logs (direct/7z/E01)
  index root <file>                # $INDEX_ROOT attribute decode
  index indx <file>                # INDX buffer(s) decode
  usnj max   <file>                # $UsnJrnl:$Max decode
  usnj j     <file> [opts]         # $UsnJrnl:$J records (--start for sparse skip)
  hives tree/ls/info/get <hive>    # Generic hive navigation; get auto-dispatches binary values via _parsers.py
  hives sam   users/groups <hive>  # SAM hive — accounts, groups
  hives system info/usb <hive>     # SYSTEM hive — config, USB devices
  hives system mounted-devices-bin <file>  # Parse a raw MountedDevices binary value (uses MountedDeviceParser directly)
  hives software info/autorun/profiles <hive>
  hives ntuser activity/env/shellbags <hive>
  hives security secrets <hive>
  fv v-blob  <file>                # Volume shadow copy / BitLocker blob
  fv f-blob  <file>                # File-level encrypted blob
  fv account <file>                # BitLocker recovery key / account
  image info/mmls/fls/icat <image> # Thin wrappers around ewf/sleuthkit
  image unlock/lock <image>        # BitLocker via cryptsetup
  image dump <image>               # Raw sector dump
  image recycle <image>            # Recycle Bin across partitions
  image usnjrnl <image>            # USN journal from live E01 via icat
  time systemtime/filetime/unixtime/tzid  # Timestamp decode utilities
  deps check                       # Verify system dependencies
```

**Source types for `mft` commands:** raw MFT file, raw NTFS volume, `.E01` image (auto-detected by extension), `.7z` archive.

---

## Key Parsers

| File | Exports |
|------|---------|
| `ifn/parsers/mft_record.py` | `parse(data) -> MFTRecord`, `MFTRecord`, `MFTAttribute` |
| `ifn/parsers/ntfs_usnjrnl.py` | `parse_max()`, `iter_records()`, `UsnRecord`, `UsnJrnlMax` |
| `ifn/parsers/ntfs_index.py` | `parse_index_root()`, `parse_indx_buffer()`, `iter_indx_buffers()` |
| `ifn/parsers/ntfs_vbr.py` | `parse(data) -> NtfsVbr` |
| `ifn/parsers/ntfs_data_runs.py` | `parse_runs(bytes) -> list[DataRun]` |
| `ifn/parsers/ntfs_attributes.py` | `fmt_file_attrs()`, `fmt_mft_reference()`, `decode_*()` functions |
| `ifn/parsers/windows_time.py` | `filetime_to_datetime()`, `fmt_filetime()`, `suspicious_filetime()`, `check_si_fn_mismatch()` |
| `ifn/parsers/evtx_parser.py` | `iter_records(path)`, `parse_record_xml()`, `FORENSIC_EVENT_IDS` |
| `ifn/parsers/sam.py` | SAM V/C structure decoders |

### MFT Record Structure (`mft_record.py`)

- `MFTRecord`: `record_number`, `flags`, `attributes: list[MFTAttribute]`, `is_directory`, `is_in_use`, `base_record_ref`, `update_seq_offset`, `update_seq_size`
- `MFTAttribute`: `attr_type`, `attr_name`, `length`, `non_resident`, `data: bytes`, `decoded: dict`, `offset`, `start_vcn`, `last_vcn`, `run_offset`, `attr_id`
- `attr.decoded` is populated by `_decode_standard_info()` (type 0x10), `_decode_filename()` (type 0x30), and `decode_*()` functions in `ntfs_attributes.py`
- **`_ticks_` convention:** `_decode_standard_info()` and `_decode_filename()` include raw FILETIME integer values alongside each formatted timestamp string, with an underscore-prefixed key (`_ticks_Created`, `_ticks_Modified`, `_ticks_MFT Modified`, `_ticks_Accessed`). These are internal and must be skipped when iterating `decoded.items()` for display (check `key.startswith("_")`).

### Timestamp Handling (`windows_time.py`)

- `filetime_to_datetime(ticks)` — raw FILETIME integer → UTC `datetime`
- `fmt_filetime(ticks)` — formatted string with microseconds (`%Y-%m-%d %H:%M:%S.%f UTC`); returns `"—"` for zero
- `suspicious_filetime(ticks) -> str | None` — returns a reason string if the timestamp is forensically suspicious (future timestamp, or zero sub-second precision indicating possible timestomping); returns `None` if clean
- `check_si_fn_mismatch(si_ticks, fn_ticks) -> list[str]` — compares $STANDARD_INFORMATION vs $FILE_NAME timestamp pairs; flags timezone-offset-sized discrepancies (~N hours) and large arbitrary deltas
- Rich display functions wrap suspicious timestamps in `[bold red]...[/bold red]`; CSV/JSON always use the plain formatted string

---

## Source Handling in `mft.py`

### `_ArchiveSource` class (line 1057)

Wraps a `.7z` archive. Key methods:

- `resolve_path(entry_num) -> str | None` — reconstructs full path from MFT parent chain
- `extract_file(path) -> bytes | None` — extracts a named entry

**ADS separator:** py7zr uses `·` (U+00B7, MIDDLE DOT) for alternate data streams, NOT `:`. So `$UsnJrnl:$J` is stored as `$Extend/$UsnJrnl·$J`. When extracting ADS via `--stream '$J'`, the lookup path is built as `f"{arc_path}·{stream}"`.

### `_open_mft_source()` (line 1243)

Detects source type (raw file, E01, 7z) and returns an iterator of `(offset, raw_bytes)` MFT entry tuples.

### MFT Index Cache (`_get_dir_index`, line 1386)

Builds a `dict[int, _MFTEntry]` indexed by MFT number. Cached to `<source>.mftidx` (JSON) and validated by file size + mtime. The cache maps MFT numbers to filenames, parent refs, size, and modified timestamp — used by `ls`, `tree`, and archive path resolution.

---

## USN Journal Specifics

`$UsnJrnl:$J` parsing notes:

- `$UsnJrnl:$J` is a sparse file. The sparse region (all zeros) comes first. Actual USN records start at `lowest_valid_usn` (from `$Max`). Always provide `--start <lowest_valid_usn>` when the file was extracted from a 7z archive to skip the sparse prefix.
- `iter_records()` in `ntfs_usnjrnl.py`: length=0 means sparse hole (advance 8 bytes); length<0x3C means malformed/padding (advance 8 bytes and continue, do not break); `pos + length > end` means truncated (break).
- When a 7z archive stores `$J`, it typically only captures the sparse run — the actual non-sparse USN records may not be present (they start at a high logical offset). Use `icat` directly against an E01 image for complete data.

---

## Suspicious Timestamp Display Pattern

When displaying timestamps in Rich tables, commands must separate plain strings (for CSV/JSON) from display strings (for Rich output):

```python
# usnj j — example pattern
plain_rows:   list[list[str]] = []
display_rows: list[list[str]] = []

for rec in usn.iter_records(...):
    row_dict = rec.as_row()          # plain strings only
    reason   = suspicious_filetime(rec.timestamp)
    ts_plain = row_dict["Timestamp"]
    ts_rich  = f"[bold red]{ts_plain}[/bold red]" if reason else ts_plain
    plain_rows.append([row_dict[h] for h in headers])
    display_rows.append([ts_rich if h == "Timestamp" else row_dict[h] for h in headers])

# Rich table uses display_rows; CSV uses plain_rows
```

For `mft record`, after displaying $SI and $FN attributes, compare their `_ticks_*` values with `check_si_fn_mismatch()` and render a warning `Panel` if any anomalies are found.

---

## Hives `get` — Parser Registry

`hives get` dispatches all binary values through a class-based parser registry in **`ifn/cli/hives/_parsers.py`**.

### Class hierarchy

```
ValueParser (ABC)          — name: str, matches(), parse() → dict, render()
  SystemHiveParser         — matches hive_type == "SYSTEM"
    MountedDeviceParser    — MountedDevices key; 6 formats (DMIO, VeraCrypt, MBR, GPT, GUID string, device path)
  SamHiveParser            — matches hive_type == "SAM"
    SamUserVParser         — SAM\Domains\Account\Users\*, value "V"
    SamUserFParser         — SAM\Domains\Account\Users\*, value "F"
  HexDumpParser            — not in _PARSERS; exported as HEX_PARSER singleton
```

`_PARSERS` contains only specialized parsers. `find_parsers(hive_type, key_path, value_name)` returns the matching subset. `HexDumpParser` is exported separately as `HEX_PARSER` and included by `get()` based on the `--hex` flag:
- No `--hex`: hex dump shown only when no specialized parser matches (fallback).
- `--hex`: hex dump shown first (before specialized output, so parsed results aren't buried by the large hex table).

`hives ls` also calls `find_parsers` for each value and shows the result as a **Parsers** column (`name1 | name2` in the console table, array in JSON). Only specialized parsers appear — `HexDumpParser` is excluded since it matches every binary value and would add noise.

### Output format

- **Console:** each matching parser renders in sequence, separated by `console.rule()`. Order: hex (if present) → specialized parsers.
- **JSON:** `"parsed"` is always a `{parser.name: parser.parse(raw)}` dict — one key per active parser (e.g. `"hex"` + `"mounted_device"`).

`parse()` must return a JSON-serializable dict (datetimes → ISO strings, bytes → hex strings). `HexDumpParser.parse()` returns `{"base64": ...}`.

### Adding a new parser

1. Add a class to `_parsers.py` inheriting from the appropriate hive base (or `ValueParser` directly).
2. Set `name = "my_parser"` (used as JSON key).
3. Implement `matches()`, `parse()`, `render()`.
4. Append an instance to `_PARSERS`.

Subcommands that need the same logic (e.g. `mounted-devices-bin`) instantiate the parser class directly at module level — no duplication.

---

## Known Gotchas

Common traps when adding new features:

- **py7zr ADS paths use `·` (U+00B7)**, not `:`. Attempting `$Extend/$UsnJrnl:$J` will return `None`; the correct lookup is `$Extend/$UsnJrnl·$J`.
- **FILETIME ticks=0** displays as `"—"` (em dash); never pass zero to `filetime_to_datetime()` without guarding.
- **MFT attribute `decoded` dicts** contain `_ticks_*` integer keys alongside string values — skip them in display loops with `if key.startswith("_"): continue`.
- **E01 images** are mounted via `ewfmount` to a temp directory, which is cleaned up on exit. The mount point is cached in `ewf/` within the working directory.
- **`mft scan` / `mft ls` / `mft tree`** all build from the MFT index cache. If the cache is stale (source file changed), delete `<source>.mftidx` to force rebuild.
- **`image usnjrnl`** reads $J via `icat` from a live E01 (complete data). **`usnj j`** reads a pre-extracted raw stream dump (may only have the sparse region).
- **`MountedDeviceParser` detection order matters:** VeraCrypt entries are exactly 16 bytes (`VeraCryptVolume*` ASCII) and must be checked *before* the 16-byte GPT GUID branch, otherwise they're misidentified. Device paths (`\??\` or `_??_` prefix in UTF-16LE) must also be checked separately — the `\??\` prefix starts with `0x5C` (not `0x7B`), so it won't match the GUID string handler.
- **Device path hardware IDs can contain `#`** (e.g. `HS-SD#MMC`). Parse from both ends: strip interface GUID last, strip instance ID second-to-last, then rejoin remaining middle parts with `#` for the hardware ID.
