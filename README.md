# IFN Forensics Toolkit

A CLI tool for the HEIG-VD IFN forensics class. Each subcommand parses a specific artifact type and shows raw bytes alongside field-by-field interpretation.

## Installation

```fish
uv sync
uv run tool.py --help
```

## Dependency check

Verify that all required system tools (`ewfinfo`, `mmls`, `fls`, `cryptsetup`, …) are installed:

```fish
uv run tool.py deps check
```

```text
╭────────────┬──────────────┬──────────┬────────────────────────────╮
│ Tool       │ Package      │ Required │ Status                     │
├────────────┼──────────────┼──────────┼────────────────────────────┤
│ ewfinfo    │ libewf-tools │ yes      │ FOUND  /usr/bin/ewfinfo    │
│ ewfmount   │ libewf-tools │ yes      │ FOUND  /usr/bin/ewfmount   │
│ ewfacquire │ libewf-tools │ yes      │ FOUND  /usr/bin/ewfacquire │
│ mmls       │ sleuthkit    │ yes      │ FOUND  /usr/bin/mmls       │
│ fls        │ sleuthkit    │ yes      │ FOUND  /usr/bin/fls        │
│ icat       │ sleuthkit    │ yes      │ FOUND  /usr/bin/icat       │
│ fsstat     │ sleuthkit    │ yes      │ FOUND  /usr/bin/fsstat     │
│ cryptsetup │ cryptsetup   │ yes      │ FOUND  /usr/bin/cryptsetup │
│ losetup    │ util-linux   │ yes      │ FOUND  /usr/bin/losetup    │
╰────────────┴──────────────┴──────────┴────────────────────────────╯
```

---

## partitions — MBR and GPT

Parse a 512-byte Master Boot Record:

```fish
uv run tool.py partitions mbr exhibits/partitions/mbr.bin
```

Outputs a hex dump of the 512 bytes with each field highlighted by colour, followed by a partition table summary:

```text
┌───┬──────────┬──────────────────────┬────────────┬────────────┬────────────┬──────────┐
│ # │ Status   │ Type                 │  LBA Start │    LBA End │    Sectors │ Size     │
├───┼──────────┼──────────────────────┼────────────┼────────────┼────────────┼──────────┤
│ 0 │ Active   │ 0x07  NTFS / exFAT  │       2048 │     104447 │     102400 │ 50.0 MB  │
│ 1 │ Inactive │ 0x07  NTFS / exFAT  │     104448 │ 1952493567 │ 1952389120 │ 931.0 GB │
│ 2 │ Inactive │ 0x27  Windows RE    │ 1952493568 │ 1953515519 │    1021952 │ 499.0 MB │
└───┴──────────┴──────────────────────┴────────────┴────────────┴────────────┴──────────┘
```

Parse a GPT image (reads the protective MBR at LBA 0 and the GPT header at LBA 1):

```fish
uv run tool.py partitions gpt exhibits/partitions/gpt.bin
```

---

## vbr — Volume Boot Record

Parse a FAT32 BIOS Parameter Block:

```fish
uv run tool.py vbr parse exhibits/vbr/vbr_partition1.bin
```

Shows every BPB field (OEM ID, bytes/sector, sectors/cluster, FAT size, root cluster, volume label, FS type, boot signature) with its offset, raw hex value, and interpreted value.

---

## lnk — Windows Shortcuts

```fish
uv run tool.py lnk parse exhibits/lnk/rome.lnk
```

```text
┌──────────────┬──────────────────────────────────────────────────────────────┐
│ GUID         │ 00021401-0000-0000-C000-000000000046                         │
│ File size    │ 1,087,444 bytes                                              │
│ Created      │ 2025-03-02 15:00:55.670000+00:00                             │
│ Accessed     │ 2025-03-01 23:00:00+00:00                                    │
│ Modified     │ 2025-03-02 15:17:12+00:00                                    │
│ Window style │ SW_SHOWNORMAL                                                │
│ Link flags   │ HasTargetIDList, HasLinkInfo, HasWorkingDir, IsUnicode, …    │
└──────────────┴──────────────────────────────────────────────────────────────┘

┌────────────────────────────────┬──────────────────────────────────────┐
│ Item 1 / volume_name           │ G:\                                  │
│ Item 2 / primary_name          │ rome.jpg                             │
│ local_base_path                │ G:\rome.jpg                          │
│ drive_type                     │ DRIVE_REMOVABLE                      │
│ volume_label                   │ PLANROME                             │
│ drive_serial_number            │ 0x48b280e2                           │
└────────────────────────────────┴──────────────────────────────────────┘
```

---

## trash — Recycle Bin

Parse a `$I` index file to recover the original path and deletion time:

```fish
uv run tool.py trash info 'exhibits/trash/$ICSE34Y.jpg'
```

```text
╭──────────────────────────────────── Decoded ─────────────────────────────────╮
│ Version:       2                                                             │
│ Deleted at:    2025-03-06 13:11:50 UTC                                       │
│ Original size: 8,305 bytes                                                   │
│ Original path: C:\Users\Xavier\Downloads\images.jpg                          │
╰──────────────────────────────────────────────────────────────────────────────╯
```

Hex-preview a `$R` data file:

```fish
uv run tool.py trash dump 'exhibits/trash/$RCSE34Y.jpg'
```

---

## mft — NTFS Master File Table

Parse a single dumped MFT record (1 KB):

```fish
uv run tool.py mft record exhibits/mft/Ypenser.bin
```

```text
┌────┬─────────────────────────────┬────────┬────────┬──────────┐
│ ID │ Type                        │ Offset │ Length │ Resident │
├────┼─────────────────────────────┼────────┼────────┼──────────┤
│  0 │ 0x10  $STANDARD_INFORMATION │ 0x0038 │     96 │ Yes      │
│  4 │ 0x30  $FILE_NAME            │ 0x0098 │    112 │ Yes      │
│  5 │ 0x40  $OBJECT_ID            │ 0x0108 │     40 │ Yes      │
│  1 │ 0x80  $DATA                 │ 0x0130 │     80 │ Yes      │
└────┴─────────────────────────────┴────────┴────────┴──────────┘

  Filename: YPenser.txt   Parent MFT#: 107571
  Created:  2025-03-06 10:36:29 UTC
  Modified: 2025-03-06 10:37:07 UTC
```

Stream all records from a full MFT dump (320 MB, never loaded entirely into memory):

```fish
uv run tool.py mft scan exhibits/mft/mft.bin --limit 100
uv run tool.py mft scan exhibits/mft/mft.bin --deleted   # include deleted entries
```

---

## hives — Windows Registry

```fish
uv run tool.py hives info exhibits/hives/SAM
```

```text
╭──────────────────────────── Registry Hive Info ──────────────────────────────╮
│ File:         exhibits/hives/SAM                                             │
│ Hive type:    SAM                                                            │
│ Root key:     ROOT                                                           │
│ Last written: 2024-12-28 06:00:27 UTC                                        │
╰──────────────────────────────────────────────────────────────────────────────╯
```

List users in the SAM hive:

```fish
uv run tool.py hives ls exhibits/hives/SAM 'SAM\Domains\Account\Users\Names'
```

```text
  Name                 Last written
  Administrator        2024-12-28 06:03:44 UTC
  DefaultAccount       2024-12-28 06:03:44 UTC
  Guest                2024-12-28 06:03:44 UTC
  Mathibou             2025-02-05 13:39:38 UTC
  Xavier               2024-12-28 06:39:04 UTC
```

Read a single value:

```fish
uv run tool.py hives get exhibits/hives/NTUSER.DAT \
  'Software\Microsoft\Windows\CurrentVersion\Run' OneDrive
```

---

## fv — SAM F and V blobs

Decode a raw V value blob extracted from the SAM hive (username, full name, NT/LM hash locations):

```fish
uv run tool.py fv v-blob exhibits/FV/V.bin
```

```text
╭───────────────────────────────── Decoded ─────────────────────────────────────╮
│ Username:  Mathibou                                                           │
│ Full name: —                                                                  │
│ Comment:   —                                                                  │
│                                                                               │
│ LM/NT hash bytes at offsets above are RC4-obfuscated with the SYSKEY.         │
│ SYSKEY is derived from SYSTEM\ControlSet001\Control\Lsa\{JD,Skew1,GBG,Data}  │
╰───────────────────────────────────────────────────────────────────────────────╯
```

The hex dump shows the 16 obfuscated NT hash bytes at their exact offset in the blob.

Decode an F value blob (account flags, logon timestamps, RID):

```fish
uv run tool.py fv f-blob exhibits/FV/F.bin
```

---

## time — Timestamp decoding

### FILETIME (Windows 64-bit, 100 ns since 1601-01-01)

Input file contains space-separated hex bytes (e.g. `8D 39 E4 CC A9 8E DB 01`):

```fish
uv run tool.py time filetime exhibits/tz/filetime.txt
```

```text
╭──────────────────────────────── Decoded ────────────────────────────────────╮
│ Ticks: 133,857,473,875,687,821  (100-ns intervals since 1601-01-01)         │
│ UTC:   2025-03-06 15:09:47.568782 UTC                                       │
╰─────────────────────────────────────────────────────────────────────────────╯
```

### SYSTEMTIME struct (8 × uint16 LE)

Input file contains the transition-to-summer-time date as space-separated hex bytes:

```fish
uv run tool.py time systemtime exhibits/tz/date.txt
```

```text
┌──────────────┬───────────┬────────────────┐
│ Field        │ Raw value │ Interpretation │
├──────────────┼───────────┼────────────────┤
│ Year         │         0 │ —              │
│ Month        │         3 │ March          │
│ Day of week  │         5 │ Friday         │
│ Day          │         2 │ 2              │
│ Hour         │         0 │ —              │
│ Minute       │         0 │ —              │
│ Second       │         0 │ —              │
│ Milliseconds │         0 │ —              │
└──────────────┴───────────┴────────────────┘
```

### Unix timestamp

Input file contains a hex string (e.g. `0x676f94cc`):

```fish
uv run tool.py time unixtime exhibits/tz/unixtime.txt
```

```text
╭──────────────────── Unix Timestamp — unixtime.txt ──────────────────────────╮
│ Hex:     0x676f94cc                                                         │
│ Decimal: 1,735,365,836                                                      │
│ UTC:     2024-12-28 06:03:56 UTC                                             │
╰─────────────────────────────────────────────────────────────────────────────╯
```

### Windows timezone ID lookup

```fish
uv run tool.py time tzid 110
# 110  →  (UTC-05:00) Eastern Time (US & Canada)

uv run tool.py time tzid 105
# 105  →  Central Brazilian Standard Time
```

---

## image — EWF / E01 disk images

Show image metadata:

```fish
uv run tool.py image info exhibits/image/disk.E01
```

```text
┌───────────────────────┬──────────────────────────────────────────────────┐
│ Case number           │ TP06 - NTFS                                      │
│ Examiner name         │ Michel Hèche                                     │
│ Acquisition date      │ Sat May  3 10:07:05 2025                         │
│ Media size            │ 3.7 GiB (4026531840 bytes)                       │
│ MD5                   │ 2573e8af9b60803a0605b5e2715c343c                 │
│ SHA1                  │ b7ea908c56c125a951da05748fd8a40972ca2e77         │
└───────────────────────┴──────────────────────────────────────────────────┘
```

List partitions:

```fish
uv run tool.py image mmls exhibits/image/disk.E01
```

```text
┌───────────────┬────────────┬────────────┬────────────┬─────────────────────┐
│ Slot          │      Start │        End │     Length │ Description         │
├───────────────┼────────────┼────────────┼────────────┼─────────────────────┤
│ 002 (000:000) │ 0000000128 │ 0004194431 │ 0004194304 │ NTFS / exFAT (0x07) │
│ 003 (000:001) │ 0004194432 │ 0007860351 │ 0003665920 │ NTFS / exFAT (0x07) │
└───────────────┴────────────┴────────────┴────────────┴─────────────────────┘
```

List files in a partition (pass the Start sector as offset):

```fish
uv run tool.py image fls exhibits/image/disk.E01 --offset 128
```

Extract a file by inode:

```fish
uv run tool.py image icat exhibits/image/disk.E01 25 --offset 128 --output recovered.bin
```

### BitLocker decryption workflow

Unlock a BitLocker partition (requires `sudo`). Pass the **Start** sector from `mmls` as the slot:

```fish
uv run tool.py image unlock exhibits/image/disk.E01 4194432 bitlocker_partition
# → ewfmount → losetup -o (4194432 × 512) → cryptsetup bitlkOpen
# Enter passphrase at the prompt.
# Partition becomes available at /dev/mapper/bitlocker_partition
```

Mount the decrypted partition:

```fish
sudo mount /dev/mapper/bitlocker_partition mnt/
```

Acquire the decrypted partition to a new E01 (ewfacquire will prompt for parameters):

```fish
uv run tool.py image dump /dev/mapper/bitlocker_partition decrypted_partition
```

Cleanup when done:

```fish
uv run tool.py image lock bitlocker_partition mnt/ /dev/loop0 ewf/
```
