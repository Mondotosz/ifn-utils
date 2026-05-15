# IFN Forensics Toolkit

A CLI tool for the HEIG-VD IFN forensics class. Each subcommand parses a
specific artifact type and shows raw bytes alongside field-by-field
interpretation.

## Installation

```fish
uv sync
uv run tool.py --help
```

## Dependency check

Verify that all required system tools (`ewfinfo`, `mmls`, `fls`, `cryptsetup`,
…) are installed:

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

Outputs a hex dump of the 512 bytes with each field highlighted by colour,
followed by a partition table summary:

```text
┌───┬──────────┬──────────────────────┬────────────┬────────────┬────────────┬──────────┐
│ # │ Status   │ Type                 │  LBA Start │    LBA End │    Sectors │ Size     │
├───┼──────────┼──────────────────────┼────────────┼────────────┼────────────┼──────────┤
│ 0 │ Active   │ 0x07  NTFS / exFAT   │       2048 │     104447 │     102400 │ 50.0 MB  │
│ 1 │ Inactive │ 0x07  NTFS / exFAT   │     104448 │ 1952493567 │ 1952389120 │ 931.0 GB │
│ 2 │ Inactive │ 0x27  Windows RE     │ 1952493568 │ 1953515519 │    1021952 │ 499.0 MB │
└───┴──────────┴──────────────────────┴────────────┴────────────┴────────────┴──────────┘
```

Parse a GPT image (reads the protective MBR at LBA 0 and the GPT header at LBA
1):

```fish
uv run tool.py partitions gpt exhibits/partitions/gpt.bin
```

```text
────────────────────────────────────────── GPT Header (LBA 1) ──────────────────────────────────────────
╭────────────────────────────────────────────── Hex Dump ──────────────────────────────────────────────╮
│ 00000000  45 46 49 20 50 41 52 54  00 00 01 00 5C 00 00 00  |EFI PART....\...|                       │
│ 00000010  AE 73 D8 2B 00 00 00 00  01 00 00 00 00 00 00 00  |.s.+............|                       │
│ 00000020  FF FF 7F 0C 00 00 00 00  22 00 00 00 00 00 00 00  |........".......|                       │
│ 00000030  DE FF 7F 0C 00 00 00 00  FE 6D 77 44 F8 93 2A 44  |.........mwD..*D|                       │
│ 00000040  A5 D6 06 3C 65 9C B5 8C  02 00 00 00 00 00 00 00  |...<e...........|                       │
│ 00000050  80 00 00 00 80 00 00 00  AE D2 77 1D              |..........w.|                           │
│                                                                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────────────────────────── Fields ───────────────────────────────────────────────╮
│                                                                                                      │
│   Offset   Len   Field              Raw (hex)   Value                                                │
│  ────────────────────────────────────────────────────────────────────────────────────                │
│   0x0200     8   Signature                      EFI PART                                             │
│   0x0208     4   Revision                       0x00010000                                           │
│   0x020C     4   Header size                    92 bytes                                             │
│   0x0210     4   Header CRC32                   0x2BD873AE                                           │
│   0x0214     4   Reserved                       0x00000000                                           │
│   0x0218     8   Current LBA                    1                                                    │
│   0x0220     8   Backup LBA                     209715199                                            │
│   0x0228     8   First usable LBA               34                                                   │
│   0x0230     8   Last usable LBA                209715166                                            │
│   0x0238    16   Disk GUID                      44776DFE-93F8-442A-A5D6-063C659CB58C                 │
│   0x0248     8   Partition LBA                  2                                                    │
│   0x0250     4   # partitions                   128                                                  │
│   0x0254     4   Entry size                     128 bytes                                            │
│   0x0258     4   Array CRC32                    0x1D77D2AE                                           │
│                                                                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
                                         GPT Partition Entries
╭───┬───────────┬────────────┬───────────┬───────────┬──────────┬──────────────────────────────────────╮
│ # │ Name      │ Type       │ First LBA │  Last LBA │ Size     │ Unique GUID                          │
├───┼───────────┼────────────┼───────────┼───────────┼──────────┼──────────────────────────────────────┤
│ 0 │ my_label  │ BIOS Boot  │      2048 │      4095 │ 1.0 MB   │ 0EC23827-28EC-49C4-90F9-E96185E16B1E │
│ 1 │ (unnamed) │ Linux Data │      4096 │ 209713151 │ 100.0 GB │ C029B714-5E12-4A66-BD35-E98E8EB3523D │
╰───┴───────────┴────────────┴───────────┴───────────┴──────────┴──────────────────────────────────────╯
```

---

## vbr — Volume Boot Record

Parse a FAT32 BIOS Parameter Block:

```fish
uv run tool.py vbr parse exhibits/vbr/vbr_partition1.bin
```

```txt
────────────────────────────────────── FAT32 VBR — vbr_partition1.bin ──────────────────────────────────────
╭──────────────────────────────────────────────── Hex Dump ────────────────────────────────────────────────╮
│ 00000000  EB 58 90 4D 53 57 49 4E  34 2E 31 00 02 08 2E 00  |.X.MSWIN4.1.....|                           │
│ 00000010  02 00 00 00 00 F8 00 00  3F 00 FF 00 80 00 00 00  |........?.......|                           │
│ 00000020  80 FF 77 00 F9 1D 00 00  00 00 00 00 C9 A8 00 00  |..w.............|                           │
│ 00000030  01 00 06 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|                           │
│ 00000040  80 00 29 B2 73 8A 38 4E  4F 20 4E 41 4D 45 20 20  |..).s.8NO NAME  |                           │
│ 00000050  20 20 46 41 54 33 32 20  20 20 33 C9 8E D1 BC F4  |  FAT32   3.....|                           │
│ 00000060  7B 8E C1 8E D9 BD 00 7C  88 56 40 88 4E 02 8A 56  |{......|.V@.N..V|                           │
│ 00000070  40 B4 41 BB AA 55 CD 13  72 10 81 FB 55 AA 75 0A  |@.A..U..r...U.u.|                           │
│ 00000080  F6 C1 01 74 05 FE 46 02  EB 2D 8A 56 40 B4 08 CD  |...t..F..-.V@...|                           │
│ 00000090  13 73 05 B9 FF FF 8A F1  66 0F B6 C6 40 66 0F B6  |.s......f...@f..|                           │
│ 000000A0  D1 80 E2 3F F7 E2 86 CD  C0 ED 06 41 66 0F B7 C9  |...?.......Af...|                           │
│ 000000B0  66 F7 E1 66 89 46 F8 83  7E 16 00 75 39 83 7E 2A  |f..f.F..~..u9.~*|                           │
│ 000000C0  00 77 33 66 8B 46 1C 66  83 C0 0C BB 00 80 B9 01  |.w3f.F.f........|                           │
│ 000000D0  00 E8 2C 00 E9 A8 03 A1  F8 7D 80 C4 7C 8B F0 AC  |..,......}..|...|                           │
│ 000000E0  84 C0 74 17 3C FF 74 09  B4 0E BB 07 00 CD 10 EB  |..t.<.t.........|                           │
│ 000000F0  EE A1 FA 7D EB E4 A1 7D  80 EB DF 98 CD 16 CD 19  |...}...}........|                           │
│ 00000100  66 60 80 7E 02 00 0F 84  20 00 66 6A 00 66 50 06  |f`.~.... .fj.fP.|                           │
│ 00000110  53 66 68 10 00 01 00 B4  42 8A 56 40 8B F4 CD 13  |Sfh.....B.V@....|                           │
│ 00000120  66 58 66 58 66 58 66 58  EB 33 66 3B 46 F8 72 03  |fXfXfXfX.3f;F.r.|                           │
│ 00000130  F9 EB 2A 66 33 D2 66 0F  B7 4E 18 66 F7 F1 FE C2  |..*f3.f..N.f....|                           │
│ 00000140  8A CA 66 8B D0 66 C1 EA  10 F7 76 1A 86 D6 8A 56  |..f..f....v....V|                           │
│ 00000150  40 8A E8 C0 E4 06 0A CC  B8 01 02 CD 13 66 61 0F  |@............fa.|                           │
│ 00000160  82 74 FF 81 C3 00 02 66  40 49 75 94 C3 42 4F 4F  |.t.....f@Iu..BOO|                           │
│ 00000170  54 4D 47 52 20 20 20 20  00 00 00 00 00 00 00 00  |TMGR    ........|                           │
│ 00000180  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|                           │
│ 00000190  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|                           │
│ 000001A0  00 00 00 00 00 00 00 00  00 00 00 00 0D 0A 44 69  |..............Di|                           │
│ 000001B0  73 6B 20 65 72 72 6F 72  FF 0D 0A 50 72 65 73 73  |sk error...Press|                           │
│ 000001C0  20 61 6E 79 20 6B 65 79  20 74 6F 20 72 65 73 74  | any key to rest|                           │
│ 000001D0  61 72 74 0D 0A 00 00 00  00 00 00 00 00 00 00 00  |art.............|                           │
│ 000001E0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|                           │
│ 000001F0  00 00 00 00 00 00 00 00  AC 01 B9 01 00 00 55 AA  |..............U.|                           │
│                                                                                                          │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭───────────────────────────────────────────────── Fields ─────────────────────────────────────────────────╮
│                                                                                                          │
│   Offset   Len   Field                    Raw (hex)                          Value                       │
│  ─────────────────────────────────────────────────────────────────────────────────────────────────────   │
│   0x0000     3   Jump instruction         EB 58 90                           EB 58 90                    │
│   0x0003     8   OEM ID                   4D 53 57 49 4E 34 2E 31            MSWIN4.1                    │
│   0x000B     2   Bytes per sector         00 02                              512                         │
│   0x000D     1   Sectors per cluster      08                                 8  (4096 bytes/cluster)     │
│   0x000E     2   Reserved sectors         2E 00                              46                          │
│   0x0010     1   Number of FATs           02                                 2                           │
│   0x0011     2   Root entry count         00 00                              0                           │
│   0x0013     2   Total sectors (16-bit)   00 00                              0 (use 32-bit field)        │
│   0x0015     1   Media type               F8                                 0xF8  Fixed disk            │
│   0x0016     2   FAT size (16-bit)        00 00                              0 (FAT32: see offset 36)    │
│   0x0018     2   Sectors per track        3F 00                              63                          │
│   0x001A     2   Number of heads          FF 00                              255                         │
│   0x001C     4   Hidden sectors           80 00 00 00                        128                         │
│   0x0020     4   Total sectors (32-bit)   80 FF 77 00                        7864192                     │
│   0x0024     4   FAT size (32-bit)        F9 1D 00 00                        7673 sectors                │
│   0x0028     2   Ext flags                00 00                              0x0000                      │
│   0x002A     2   FS version               00 00                              0.0                         │
│   0x002C     4   Root cluster             C9 A8 00 00                        43209                       │
│   0x0030     2   FS Info sector           01 00                              1                           │
│   0x0032     2   Backup boot sector       06 00                              6                           │
│   0x0040     1   Drive number             80                                 0x80                        │
│   0x0042     1   Boot signature           29                                 0x29                        │
│   0x0043     4   Volume ID                B2 73 8A 38                        0x388A73B2                  │
│   0x0047    11   Volume label             4E 4F 20 4E 41 4D 45 20 20 20 20   NO NAME                     │
│   0x0052     8   FS type                  46 41 54 33 32 20 20 20            FAT32                       │
│   0x01FE     2   Sector signature         55 AA                              0xAA55 (Valid)              │
│                                                                                                          │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

Shows every BPB field (OEM ID, bytes/sector, sectors/cluster, FAT size, root
cluster, volume label, FS type, boot signature) with its offset, raw hex value,
and interpreted value.

---

## lnk — Windows Shortcuts

```fish
uv run tool.py lnk parse exhibits/lnk/Biologie.lnk.bin
```

```text
                                       LNK Header — Biologie.lnk.bin
╭──────────────┬───────────────────────────────────────────────────────────────────────────────────────────╮
│ Field        │ Value                                                                                     │
├──────────────┼───────────────────────────────────────────────────────────────────────────────────────────┤
│ GUID         │ 00021401-0000-0000-C000-000000000046                                                      │
│ Header size  │ 76                                                                                        │
│ File size    │ 1,247,275 bytes                                                                           │
│ Created      │ 2026-04-21 14:59:01.628000+00:00                                                          │
│ Accessed     │ 2026-04-21 15:45:01.628000+00:00                                                          │
│ Modified     │ 2026-04-21 15:45:01.628000+00:00                                                          │
│ Icon index   │ 0                                                                                         │
│ Window style │ SW_SHOWNORMAL                                                                             │
│ Hot key      │ UNSET - UNSET {0x0000}                                                                    │
│ Link flags   │ ['HasTargetIDList', 'HasLinkInfo', 'HasRelativePath', 'HasWorkingDir', 'IsUnicode',       │
│              │ 'DisableKnownFolderTracking']                                                             │
│ File flags   │ ['FILE_ATTRIBUTE_ARCHIVE']                                                                │
╰──────────────┴───────────────────────────────────────────────────────────────────────────────────────────╯
                          Link Target ID List
╭───────────────────────────────┬──────────────────────────────────────╮
│ Field                         │ Value                                │
├───────────────────────────────┼──────────────────────────────────────┤
│ Size                          │ 144                                  │
│ Item 0 / class                │ Root Folder                          │
│ Item 0 / sort_index           │ My Computer                          │
│ Item 0 / sort_index_value     │ 80                                   │
│ Item 0 / guid                 │ 20D04FE0-3AEA-1069-A2D8-08002B30309D │
│ Item 1 / class                │ Volume Item                          │
│ Item 1 / flags                │ 0xe                                  │
│ Item 1 / volume_identifier    │ 088E3905-0323-4B02-9826-5D99428E115F │
│ Item 2 / class                │ File entry                           │
│ Item 2 / flags                │ Is file                              │
│ Item 2 / file_size            │ 0                                    │
│ Item 2 / modification_time    │ None                                 │
│ Item 2 / file_attribute_flags │ 128                                  │
│ Item 2 / primary_name         │ Biulogie.pdf                         │
╰───────────────────────────────┴──────────────────────────────────────╯
                                    Link Info
╭─────────────────────────────────────┬──────────────────────────────────────────╮
│ Field                               │ Value                                    │
├─────────────────────────────────────┼──────────────────────────────────────────┤
│ link_info_size                      │ 87                                       │
│ link_info_header_size               │ 28                                       │
│ link_info_flags                     │ 1                                        │
│ volume_id_offset                    │ 28                                       │
│ local_base_path_offset              │ 45                                       │
│ common_network_relative_link_offset │ 0                                        │
│ common_path_suffix_offset           │ 86                                       │
│ local_base_path                     │ C:\Users\Mathibou\Downloads\Biulogie.pdf │
│ common_path_suffix                  │                                          │
│ location_info / volume_id_size      │ 17                                       │
│ location_info / r_drive_type        │ 3                                        │
│ location_info / volume_label_offset │ 16                                       │
│ location_info / drive_serial_number │ 0x34e5eb84                               │
│ location_info / drive_type          │ DRIVE_FIXED                              │
│ location_info / volume_label        │                                          │
│ location                            │ Local                                    │
╰─────────────────────────────────────┴──────────────────────────────────────────╯
                         String Data
╭───────────────────┬───────────────────────────────────────╮
│ Field             │ Value                                 │
├───────────────────┼───────────────────────────────────────┤
│ relative_path     │ ..\..\..\..\..\Downloads\Biulogie.pdf │
│ working_directory │ C:\Users\Mathibou\Downloads           │
╰───────────────────┴───────────────────────────────────────╯
                                                 Extra Data
╭────────────────────────────────┬───────────────────────────────┬─────────────────────────────────────────╮
│ Block                          │ Field                         │ Value                                   │
├────────────────────────────────┼───────────────────────────────┼─────────────────────────────────────────┤
│ DISTRIBUTED_LINK_TRACKER_BLOCK │ size                          │ 96                                      │
│ DISTRIBUTED_LINK_TRACKER_BLOCK │ length                        │ 88                                      │
│ DISTRIBUTED_LINK_TRACKER_BLOCK │ version                       │ 0                                       │
│ DISTRIBUTED_LINK_TRACKER_BLOCK │ machine_identifier            │ desktop-fq2sg8v                         │
│ DISTRIBUTED_LINK_TRACKER_BLOCK │ droid_volume_identifier       │ 514E0B56-C87B-436B-919A-959905A39E1C    │
│ DISTRIBUTED_LINK_TRACKER_BLOCK │ droid_file_identifier         │ FFE1D665-E410-11EF-9DBB-080027F21382    │
│ DISTRIBUTED_LINK_TRACKER_BLOCK │ birth_droid_volume_identifier │ 514E0B56-C87B-436B-919A-959905A39E1C    │
│ DISTRIBUTED_LINK_TRACKER_BLOCK │ birth_droid_file_identifier   │ FFE1D665-E410-11EF-9DBB-080027F21382    │
│ METADATA_PROPERTIES_BLOCK      │ size                          │ 69                                      │
│ METADATA_PROPERTIES_BLOCK      │ property_store                │ [{'storage_size': 57, 'version':        │
│                                │                               │ '0x53505331', 'format_id':              │
│                                │                               │ '446D16B1-8DAD-4870-A748-402EA43D788C', │
│                                │                               │ 'serialized_property_values':           │
│                                │                               │ [{'value_size': 29, 'id': 104, 'value': │
│                                │                               │ None, 'value_type': 'VT_CLSID'}]}]      │
╰────────────────────────────────┴───────────────────────────────┴─────────────────────────────────────────╯
```

---

## trash — Recycle Bin

Parse a `$I` index file to recover the original path and deletion time:

```fish
uv run tool.py trash info 'exhibits/trash/$ICSE34Y.jpg'
```

```text
────────────────────────────────────────────────── Recycle Bin $I — $ICSE34Y.jpg ───────────────────────────────────────────────────
╭──────────────────────────────────────────────────────────── Hex Dump ────────────────────────────────────────────────────────────╮
│ 00000000  02 00 00 00 00 00 00 00  71 20 00 00 00 00 00 00  |........q ......|                                                   │
│ 00000010  50 35 D2 52 99 8E DB 01  25 00 00 00 43 00 3A 00  |P5.R....%...C.:.|                                                   │
│ 00000020  5C 00 55 00 73 00 65 00  72 00 73 00 5C 00 58 00  |\.U.s.e.r.s.\.X.|                                                   │
│ 00000030  61 00 76 00 69 00 65 00  72 00 5C 00 44 00 6F 00  |a.v.i.e.r.\.D.o.|                                                   │
│ 00000040  77 00 6E 00 6C 00 6F 00  61 00 64 00 73 00 5C 00  |w.n.l.o.a.d.s.\.|                                                   │
│ 00000050  69 00 6D 00 61 00 67 00  65 00 73 00 2E 00 6A 00  |i.m.a.g.e.s...j.|                                                   │
│ 00000060  70 00 67 00 00 00                                  |p.g...|                                                            │
│                                                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭───────────────────────────────────────────────────────────── Fields ─────────────────────────────────────────────────────────────╮
│                                                                                                                                  │
│   Offset   Len   Field                      Raw (hex)                                  Value                                     │
│  ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────  │
│   0x0000     8   Version                    02 00 00 00 00 00 00 00                    2                                         │
│   0x0008     8   Original file size         71 20 00 00 00 00 00 00                    8,305 bytes                               │
│   0x0010     8   Deletion FILETIME          50 35 D2 52 99 8E DB 01                    133857403108210000  →  2025-03-06         │
│                                                                                        13:11:50 UTC                              │
│   0x0018     4   Filename length            25 00 00 00                                37 chars                                  │
│   0x001C    74   Original path (UTF-16LE)   43 00 3A 00 5C 00 55 00 73 00 65 00 72     C:\Users\Xavier\Downloads\images.jpg      │
│                                             00 73 00 5C 00 58 00 61 00 76 00 69 00                                               │
│                                             65 00 72 00 5C 00 44 00 6F 00 77 00 6E                                               │
│                                             00 6C 00 6F 00 61 00 64 00 73 00 5C 00                                               │
│                                             69 00 6D 00 61 00 67 00 65 00 73 00 2E                                               │
│                                             00 6A 00 70 00 67 00 00 00                                                           │
│                                                                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────────────────────────────── Decoded ─────────────────────────────────────────────────────────────╮
│ Version:       2                                                                                                                 │
│ Deleted at:    2025-03-06 13:11:50 UTC                                                                                           │
│ Original size: 8,305 bytes                                                                                                       │
│ Original path: C:\Users\Xavier\Downloads\images.jpg                                                                              │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

Hex-preview a `$R` data file:

```fish
uv run tool.py trash dump 'exhibits/trash/$RCSE34Y.jpg'
```

```txt
╭──────────────────────────── $R file — $RCSE34Y.jpg ─────────────────────────────╮
│ File:  exhibits/trash/$RCSE34Y.jpg                                              │
│ Size:  8,305 bytes                                                              │
│ Showing first 256 bytes                                                         │
╰─────────────────────────────────────────────────────────────────────────────────╯
╭─────────────────────────────────── Hex Dump ────────────────────────────────────╮
│ 00000000  FF D8 FF E0 00 10 4A 46  49 46 00 01 01 00 00 01  |......JFIF......|  │
│ 00000010  00 01 00 00 FF DB 00 84  00 09 06 07 12 12 12 15  |................|  │
│ 00000020  12 12 12 15 15 15 15 17  15 15 15 15 16 17 15 15  |................|  │
│ 00000030  15 15 15 15 15 17 18 15  15 16 15 18 1D 28 20 18  |.............( .|  │
│ 00000040  1A 25 1D 15 15 21 31 21  25 29 2B 2E 2E 2E 17 1F  |.%...!1!%)+.....|  │
│ 00000050  33 38 33 2C 37 28 2D 2E  2B 01 0A 0A 0A 0E 0D 0E  |383,7(-.+.......|  │
│ 00000060  1B 10 10 18 2D 26 1F 26  31 2B 2D 2D 2B 2F 2D 2B  |....-&.&1+--+/-+|  │
│ 00000070  2D 2D 2D 30 2D 2B 2F 2D  2D 2D 2D 30 2D 2D 2D 2D  |---0-+/----0----|  │
│ 00000080  2F 2D 2B 2B 2D 2B 2B 2D  2D 2F 2B 2F 2D 2D 2D 2D  |/-++-++--/+/----|  │
│ 00000090  2D 2D 2D 2D 2B 36 2D 2D  2D 2F FF C0 00 11 08 00  |----+6---/......|  │
│ 000000A0  FB 00 C9 03 01 22 00 02  11 01 03 11 01 FF C4 00  |....."..........|  │
│ 000000B0  1C 00 00 00 07 01 01 00  00 00 00 00 00 00 00 00  |................|  │
│ 000000C0  00 00 00 01 02 03 04 05  06 07 08 FF C4 00 3F 10  |..............?.|  │
│ 000000D0  00 02 01 02 04 04 04 03  06 03 07 03 05 00 00 00  |................|  │
│ 000000E0  01 02 11 00 03 04 12 21  31 05 06 41 51 13 22 61  |.......!1..AQ."a|  │
│ 000000F0  71 32 81 91 07 42 52 62  A1 B1 14 C1 F0 15 23 33  |q2...BRb......#3|  │
│                                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────── Fields ─────────────────────────────────────╮
│                                                                                 │
│   Offset   Len   Field   Raw (hex)   Value                                      │
│  ──────────────────────────────────────────                                     │
│                                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────╯
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

Stream all records from a full MFT dump (320 MB, never loaded entirely into
memory):

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

Decode a raw V value blob extracted from the SAM hive (username, full name,
NT/LM hash locations):

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

The hex dump shows the 16 obfuscated NT hash bytes at their exact offset in the
blob.

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

Input file contains the transition-to-summer-time date as space-separated hex
bytes:

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
uv run tool.py image info exhibits/image/partition.E01
```

```text
                    EWF Info — partition.E01
╭───────────────────────┬──────────────────────────────────────╮
│ Field                 │ Value                                │
├───────────────────────┼──────────────────────────────────────┤
│ Case number           │ Decrypted Bitlocker partition        │
│ Description           │ Decrypted partition from the USB key │
│ Examiner name         │ Kenan Augsburger                     │
│ Evidence number       │ TP06                                 │
│ Acquisition date      │ Tue May  5 19:07:04 2026             │
│ System date           │ Tue May  5 19:07:04 2026             │
│ Operating system used │ Linux                                │
│ Software version used │ 20140816                             │
│ Password              │ N/A                                  │
│ File format           │ EnCase 6                             │
│ Sectors per chunk     │ 64                                   │
│ Error granularity     │ 64                                   │
│ Compression method    │ deflate                              │
│ Compression level     │ best compression                     │
│ Media type            │ removable disk                       │
│ Is physical           │ no                                   │
│ Bytes per sector      │ 512                                  │
│ Number of sectors     │ 3670016                              │
│ Media size            │ 1.7 GiB (1879048192 bytes)           │
│ MD5                   │ e15e97380937644cdedfdbbc4c889a92     │
╰───────────────────────┴──────────────────────────────────────╯
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

Unlock a BitLocker partition (requires `sudo`). Pass the **Start** sector from
`mmls` as the slot:

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

Acquire the decrypted partition to a new E01 (ewfacquire will prompt for
parameters):

```fish
uv run tool.py image dump /dev/mapper/bitlocker_partition decrypted_partition
```

Cleanup when done:

```fish
uv run tool.py image lock bitlocker_partition mnt/ /dev/loop0 ewf/
```
