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
──────────────────────────── MFT Record — Ypenser.bin ─────────────────────────────
╭─────────────────────────────────── Hex Dump ────────────────────────────────────╮
│ 00000000  46 49 4C 45 30 00 03 00  ED 35 08 77 00 00 00 00  |FILE0....5.w....|  │
│ 00000010  07 00 01 00 38 00 01 00  88 01 00 00 00 04 00 00  |....8...........|  │
│ 00000020  00 00 00 00 00 00 00 00  06 00 00 00 EE 82 04 00  |................|  │
│ 00000030  0E 00 00 00 00 00 00 00  10 00 00 00 60 00 00 00  |............`...|  │
│ 00000040  00 00 00 00 00 00 00 00  48 00 00 00 18 00 00 00  |........H.......|  │
│ 00000050  58 D5 EC 9E 83 8E DB 01  15 47 A4 B5 83 8E DB 01  |X........G......|  │
│ 00000060  15 47 A4 B5 83 8E DB 01  15 47 A4 B5 83 8E DB 01  |.G.......G......|  │
│ 00000070  20 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  | ...............|  │
│ 00000080  00 00 00 00 34 07 00 00  00 00 00 00 00 00 00 00  |....4...........|  │
│ 00000090  48 37 1D 14 00 00 00 00  30 00 00 00 70 00 00 00  |H7......0...p...|  │
│ 000000A0  00 00 00 00 00 00 04 00  58 00 00 00 18 00 01 00  |........X.......|  │
│ 000000B0  33 A4 01 00 00 00 01 00  58 D5 EC 9E 83 8E DB 01  |3.......X.......|  │
│ 000000C0  58 D5 EC 9E 83 8E DB 01  97 1A EE 9E 83 8E DB 01  |X...............|  │
│ 000000D0  58 D5 EC 9E 83 8E DB 01  00 00 00 00 00 00 00 00  |X...............|  │
│ 000000E0  00 00 00 00 00 00 00 00  20 00 00 00 00 00 00 00  |........ .......|  │
│ 000000F0  0B 03 59 00 50 00 65 00  6E 00 73 00 65 00 72 00  |..Y.P.e.n.s.e.r.|  │
│ 00000100  2E 00 74 00 78 00 74 00  40 00 00 00 28 00 00 00  |..t.x.t.@...(...|  │
│ 00000110  00 00 00 00 00 00 05 00  10 00 00 00 18 00 00 00  |................|  │
│ 00000120  A7 FF 94 90 75 FA EF 11  9D C4 08 00 27 F2 13 82  |....u.......'...|  │
│ 00000130  80 00 00 00 50 00 00 00  00 00 18 00 00 00 01 00  |....P...........|  │
│ 00000140  33 00 00 00 18 00 00 00  50 72 65 6E 64 72 65 20  |3.......Prendre |  │
│ 00000150  6C 65 20 6D 61 74 6F 73  20 64 61 6E 73 20 6C 61  |le matos dans la|  │
│ 00000160  20 62 6F 75 74 69 71 75  65 20 65 74 20 70 61 79  | boutique et pay|  │
│ 00000170  65 72 20 65 6E 20 63 61  73 68 2E 00 44 00 6F 00  |er en cash..D.o.|  │
│ 00000180  FF FF FF FF 82 79 47 11  6E 00 74 00 2E 00 74 00  |.....yG.n.t...t.|  │
│ 00000190  78 00 74 00 00 00 00 00  80 00 00 00 18 00 00 00  |x.t.............|  │
│ 000001A0  00 00 18 00 00 00 01 00  00 00 00 00 18 00 00 00  |................|  │
│ 000001B0  FF FF FF FF 82 79 47 11  00 00 00 00 00 00 00 00  |.....yG.........|  │
│ 000001C0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|  │
│ 000001D0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|  │
│ 000001E0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|  │
│ 000001F0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 0E 00  |................|  │
│                                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────── Fields ─────────────────────────────────────╮
│                                                                                 │
│   Offset   Len   Field               Raw (hex)               Value              │
│  ─────────────────────────────────────────────────────────────────────────────  │
│   0x0000     4   Magic               46 49 4C 45             FILE               │
│   0x0004     2   Update seq offset   30 00                   48                 │
│   0x0006     2   Update seq size     03 00                   3                  │
│   0x0008     8   Log file seq#       ED 35 08 77 00 00 00    1997026797         │
│                                      00                                         │
│   0x0010     2   Sequence number     07 00                   7                  │
│   0x0012     2   Hard link count     01 00                   1                  │
│   0x0014     2   First attr offset   38 00                   0x0038             │
│   0x0016     2   Flags               01 00                   0x0001  (In use)   │
│   0x0018     4   Used size           88 01 00 00             392 bytes          │
│   0x001C     4   Allocated size      00 04 00 00             1024 bytes         │
│   0x0020     8   Base record ref     00 00 00 00 00 00 00    0                  │
│                                      00                                         │
│   0x0028     2   Next attr ID        06 00                   6                  │
│   0x002C     4   Record number       EE 82 04 00             295662             │
│                                                                                 │
╰─────────────────────────────────────────────────────────────────────────────────╯
                               Attributes
╭────┬─────────────────────────────┬────────┬────────┬──────────┬──────╮
│ ID │ Type                        │ Offset │ Length │ Resident │ Name │
├────┼─────────────────────────────┼────────┼────────┼──────────┼──────┤
│  0 │ 0x10  $STANDARD_INFORMATION │ 0x0038 │     96 │ Yes      │ —    │
│  4 │ 0x30  $FILE_NAME            │ 0x0098 │    112 │ Yes      │ —    │
│  5 │ 0x40  $OBJECT_ID            │ 0x0108 │     40 │ Yes      │ —    │
│  1 │ 0x80  $DATA                 │ 0x0130 │     80 │ Yes      │ —    │
╰────┴─────────────────────────────┴────────┴────────┴──────────┴──────╯
      $STANDARD_INFORMATION details

  Field          Value
 ────────────────────────────────────────
  Created        2025-03-06 10:36:29 UTC
  Modified       2025-03-06 10:37:07 UTC
  MFT Modified   2025-03-06 10:37:07 UTC
  Accessed       2025-03-06 10:37:07 UTC
  File attrs     0x00000020

           $FILE_NAME details

  Field         Value
 ───────────────────────────────────────
  Filename      YPenser.txt
  Namespace     Win32&DOS
  Parent MFT#   107571
  Created       2025-03-06 10:36:29 UTC
  Modified      2025-03-06 10:36:29 UTC
  Accessed      2025-03-06 10:36:29 UTC
  Alloc size    0 bytes
  Real size     0 bytes
```

Stream all records from a full MFT dump (320 MB, never loaded entirely into
memory):

```fish
uv run tool.py mft scan exhibits/mft/mft.bin --limit 50
uv run tool.py mft scan exhibits/mft/mft.bin --deleted   # include deleted entries
```

```text
                                              MFT Scan — mft.bin
╭──────┬──────────────┬─────────┬──────┬─────────────────────────┬─────────────────────────┬──────────────────╮
│ MFT# │ Filename     │ Parent# │ Type │ Created                 │ Modified                │             Size │
├──────┼──────────────┼─────────┼──────┼─────────────────────────┼─────────────────────────┼──────────────────┤
│    0 │ $MFT         │       5 │ file │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │     16,384 bytes │
│    1 │ $MFTMirr     │       5 │ file │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │      4,096 bytes │
│    2 │ $LogFile     │       5 │ file │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │ 67,108,864 bytes │
│    3 │ $Volume      │       5 │ file │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │          0 bytes │
│    4 │ $AttrDef     │       5 │ file │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │      2,400 bytes │
│    5 │ .            │       5 │ DIR  │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │          0 bytes │
│    6 │ $Bitmap      │       5 │ file │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │  4,190,528 bytes │
│    7 │ $Boot        │       5 │ file │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │      8,192 bytes │
│    8 │ $BadClus     │       5 │ file │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │          0 bytes │
│    9 │ $Secure      │       5 │ file │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │          0 bytes │
│   10 │ $UpCase      │       5 │ file │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │    131,072 bytes │
│   11 │ $Extend      │       5 │ DIR  │ 2024-12-28 05:54:02 UTC │ 2024-12-28 05:54:02 UTC │          0 bytes │
│   24 │ $Quota       │      11 │ file │ 2024-12-28 05:54:03 UTC │ 2024-12-28 05:54:03 UTC │          0 bytes │
│   25 │ $ObjId       │      11 │ file │ 2024-12-28 05:54:03 UTC │ 2024-12-28 05:54:03 UTC │          0 bytes │
│   26 │ $Reparse     │      11 │ file │ 2024-12-28 05:54:03 UTC │ 2024-12-28 05:54:03 UTC │          0 bytes │
│   27 │ $RmMetadata  │      11 │ DIR  │ 2024-12-28 05:54:03 UTC │ 2024-12-28 05:54:03 UTC │          0 bytes │
│   28 │ $Repair      │      27 │ file │ 2024-12-28 05:54:03 UTC │ 2024-12-28 05:54:03 UTC │          0 bytes │
│   29 │ $Deleted     │      11 │ DIR  │ 2024-12-28 05:54:03 UTC │ 2024-12-28 05:54:03 UTC │          0 bytes │
│   30 │ $TxfLog      │      27 │ DIR  │ 2024-12-28 05:54:03 UTC │ 2024-12-28 05:54:03 UTC │          0 bytes │
│   31 │ $Txf         │      27 │ DIR  │ 2024-12-28 05:54:03 UTC │ 2024-12-28 05:54:03 UTC │          0 bytes │
│   32 │ $Tops        │      30 │ file │ 2024-12-28 05:54:03 UTC │ 2024-12-28 05:54:03 UTC │          0 bytes │
│   33 │ $TxfLog.blf  │      30 │ file │ 2024-12-28 05:54:03 UTC │ 2024-12-28 05:54:03 UTC │          0 bytes │
│   34 │ E3022B~1     │   40335 │ file │ 2025-04-03 06:17:53 UTC │ 2025-04-03 06:17:53 UTC │          0 bytes │
│   35 │ 15DC64~1     │   21780 │ DIR  │ 2025-04-03 06:50:28 UTC │ 2025-04-03 06:50:28 UTC │          0 bytes │
│   36 │ MAINQU~2.QUE │      45 │ file │ 2024-12-28 06:03:16 UTC │ 2024-12-28 06:03:16 UTC │          0 bytes │
│   37 │ CONTEN~2.DIR │      45 │ file │ 2024-12-28 06:03:16 UTC │ 2024-12-28 06:03:16 UTC │          0 bytes │
│   38 │ Setup.evtx   │    4478 │ file │ 2024-12-28 06:03:17 UTC │ 2024-12-28 06:03:17 UTC │          0 bytes │
│   39 │ MIA934~1.EVT │    4478 │ file │ 2024-12-28 06:03:17 UTC │ 2024-12-28 06:03:17 UTC │          0 bytes │
│   40 │ MI033E~1.EVT │    4478 │ file │ 2024-12-28 06:03:18 UTC │ 2024-12-28 06:03:18 UTC │          0 bytes │
│   41 │ PFSVPE~1.BIN │  103986 │ file │ 2024-12-28 06:03:22 UTC │ 2024-12-28 06:03:22 UTC │          0 bytes │
│   42 │ AgRobust.db  │  103986 │ file │ 2024-12-28 06:03:22 UTC │ 2024-12-28 06:03:22 UTC │          0 bytes │
│   43 │ AGGLGL~1.DB  │  103986 │ file │ 2024-12-28 06:03:22 UTC │ 2024-12-28 06:03:22 UTC │          0 bytes │
│   44 │ AGGLFA~1.DB  │  103986 │ file │ 2024-12-28 06:03:22 UTC │ 2024-12-28 06:03:22 UTC │          0 bytes │
│   45 │ Panther      │    1579 │ DIR  │ 2024-12-28 06:00:14 UTC │ 2024-12-28 06:00:14 UTC │          0 bytes │
│   46 │ AGGLFG~1.DB  │  103986 │ file │ 2024-12-28 06:03:22 UTC │ 2024-12-28 06:03:22 UTC │          0 bytes │
│   47 │ REGID1~1.SWI │    1512 │ file │ 2024-12-28 06:01:31 UTC │ 2025-04-03 08:32:55 UTC │          0 bytes │
│   48 │ 95D9A2~1.TBR │  108755 │ file │ 2024-12-30 14:13:04 UTC │ 2024-12-30 14:13:04 UTC │          0 bytes │
│   49 │ PRESEN~1.DLL │  114966 │ file │ 2025-03-02 14:27:02 UTC │ 2025-03-02 14:27:02 UTC │ 24,062,976 bytes │
│   50 │ rblayout.xin │  103988 │ file │ 2024-12-28 06:04:37 UTC │ 2024-12-28 06:04:37 UTC │          0 bytes │
│   51 │ SYSTEM~1.DLL │     205 │ file │ 2025-03-02 10:39:56 UTC │ 2025-03-02 10:39:56 UTC │ 33,253,376 bytes │
│   52 │ WDICON~1.002 │    4314 │ file │ 2024-12-28 06:03:34 UTC │ 2024-12-28 06:03:34 UTC │          0 bytes │
│   53 │ DYNRES~1.7DB │  103986 │ file │ 2025-03-02 10:45:11 UTC │ 2025-03-02 10:45:11 UTC │          0 bytes │
│   54 │ SYSTEM~1     │    2232 │ DIR  │ 2025-03-02 10:48:58 UTC │ 2025-03-02 10:48:58 UTC │          0 bytes │
│   55 │ LOCKAP~1.PF  │  103986 │ file │ 2024-12-30 21:35:29 UTC │ 2024-12-30 21:35:29 UTC │          0 bytes │
│   56 │ DI6AC0~1.ETL │  106072 │ file │ 2025-03-02 10:39:36 UTC │ 2025-03-02 10:39:45 UTC │    196,608 bytes │
│   57 │ WDICON~1.003 │    4314 │ file │ 2024-12-30 21:34:27 UTC │ 2024-12-30 21:34:27 UTC │          0 bytes │
│   58 │ TASKSC~1.DLL │   40347 │ file │ 2025-03-02 10:40:03 UTC │ 2025-03-02 10:40:03 UTC │    268,800 bytes │
│   59 │ 122877~1     │    3233 │ DIR  │ 2024-12-28 06:03:43 UTC │ 2024-12-28 06:03:43 UTC │          0 bytes │
│   60 │ 383930~1.PRI │      59 │ file │ 2024-12-28 06:03:43 UTC │ 2024-12-28 06:03:43 UTC │          0 bytes │
│   61 │ SCESET~1.ETL │    3261 │ file │ 2024-12-28 06:00:36 UTC │ 2024-12-28 06:00:36 UTC │          0 bytes │
╰──────┴──────────────┴─────────┴──────┴─────────────────────────┴─────────────────────────┴──────────────────╯
Scanned 62 records, displayed 50
```

---

## hives — Windows Registry

```fish
uv run tool.py hives info exhibits/hives/SAM
```

```text
╭────────────────── Registry Hive Info ───────────────────╮
│ File:         exhibits/hives/SAM                        │
│ Hive type:    SAM                                       │
│ Root key:     ROOT                                      │
│ Last written: 2026-02-19 15:05:16 UTC                   │
╰─────────────────────────────────────────────────────────╯
```

List users in the SAM hive:

```fish
uv run tool.py hives ls exhibits/hives/SAM 'SAM\Domains\Account\Users\Names'
```

```text
───────────── SAM\Domains\Account\Users\Names ─────────────
Last written: 2026-05-13 13:41:31 UTC
                    Subkeys

  Name                 Last written
 ──────────────────────────────────────────────
  Administrator        2026-02-19 15:08:05 UTC
  DefaultAccount       2026-02-19 15:08:05 UTC
  Guest                2026-02-19 15:08:05 UTC
  Quickemu             2026-02-19 15:08:03 UTC
  TMP                  2026-05-13 13:41:31 UTC
  WDAGUtilityAccount   2026-02-19 15:08:05 UTC

            Values

  Name        Type      Data
 ────────────────────────────
  (default)   RegNone
```

Read a single value:

```fish
uv run tool.py hives get exhibits/hives/NTUSER.DAT \
  'Software\Microsoft\Windows\CurrentVersion\Run' OneDrive
```

```text
╭──────────────────── Registry Value ─────────────────────╮
│ Key:   Software\Microsoft\Windows\CurrentVersion\Run    │
│ Value: OneDrive                                         │
│ Type:  RegSZ                                            │
│ Data:  "C:\Program Files\Microsoft                      │
│ OneDrive\OneDrive.exe" /background                      │
╰─────────────────────────────────────────────────────────╯
```

---

## fv — SAM F and V blobs

Decode a raw V value blob extracted from the SAM hive (username, full name,
NT/LM hash locations):

```fish
uv run tool.py fv v-blob exhibits/FV/QUICKEMU.V.bin
```

```text
───────────────────────────── SAM V Blob — QUICKEMU.V.bin ─────────────────────────────
╭───────────────────────────────────── Hex Dump ──────────────────────────────────────╮
│ 00000000  00 00 00 00 F4 00 00 00  03 00 01 00 F4 00 00 00  |................|      │
│ 00000010  10 00 00 00 00 00 00 00  04 01 00 00 10 00 00 00  |................|      │
│ 00000020  00 00 00 00 14 01 00 00  10 00 00 00 00 00 00 00  |................|      │
│ 00000030  24 01 00 00 00 00 00 00  00 00 00 00 24 01 00 00  |$...........$...|      │
│ 00000040  00 00 00 00 00 00 00 00  24 01 00 00 00 00 00 00  |........$.......|      │
│ 00000050  00 00 00 00 24 01 00 00  00 00 00 00 00 00 00 00  |....$...........|      │
│ 00000060  24 01 00 00 00 00 00 00  00 00 00 00 24 01 00 00  |$...........$...|      │
│ 00000070  00 00 00 00 00 00 00 00  24 01 00 00 00 00 00 00  |........$.......|      │
│ 00000080  00 00 00 00 24 01 00 00  15 00 00 00 A8 00 00 00  |....$...........|      │
│ 00000090  3C 01 00 00 08 00 00 00  01 00 00 00 44 01 00 00  |<...........D...|      │
│ 000000A0  18 00 00 00 00 00 00 00  5C 01 00 00 38 00 00 00  |........\...8...|      │
│ 000000B0  00 00 00 00 94 01 00 00  18 00 00 00 00 00 00 00  |................|      │
│ 000000C0  AC 01 00 00 18 00 00 00  00 00 00 00 01 00 14 80  |................|      │
│ 000000D0  D4 00 00 00 E4 00 00 00  14 00 00 00 44 00 00 00  |............D...|      │
│ 000000E0  02 00 30 00 02 00 00 00  02 C0 14 00 44 00 05 01  |..0.........D...|      │
│ 000000F0  01 01 00 00 00 00 00 01  00 00 00 00 02 C0 14 00  |................|      │
│ 00000100  FF 07 0F 00 01 01 00 00  00 00 00 05 07 00 00 00  |................|      │
│ 00000110  02 00 90 00 04 00 00 00  00 00 24 00 44 00 02 00  |..........$.D...|      │
│ 00000120  01 05 00 00 00 00 00 05  15 00 00 00 70 9B 36 DB  |............p.6.|      │
│ 00000130  FE FA F7 7E 9A A0 A4 F0  E8 03 00 00 00 00 38 00  |...~..........8.|      │
│ 00000140  1B 03 02 00 01 0A 00 00  00 00 00 0F 03 00 00 00  |................|      │
│ 00000150  00 04 00 00 DE A2 28 67  21 3E D2 AF 19 AD 5D 79  |......(g!>....]y|      │
│ 00000160  B0 C1 07 29 27 56 FC 20  D8 AD 66 F6 10 F2 68 FA  |...)'V. ..f...h.|      │
│ 00000170  DF 2A F8 0F 00 00 18 00  FF 07 0F 00 01 02 00 00  |.*..............|      │
│ 00000180  00 00 00 05 20 00 00 00  20 02 00 00 00 00 14 00  |.... ... .......|      │
│ 00000190  5B 03 02 00 01 01 00 00  00 00 00 01 00 00 00 00  |[...............|      │
│ 000001A0  01 02 00 00 00 00 00 05  20 00 00 00 20 02 00 00  |........ ... ...|      │
│ 000001B0  01 02 00 00 00 00 00 05  20 00 00 00 20 02 00 00  |........ ... ...|      │
│ 000001C0  51 00 75 00 69 00 63 00  6B 00 65 00 6D 00 75 00  |Q.u.i.c.k.e.m.u.|      │
│ 000001D0  51 00 75 00 69 00 63 00  6B 00 65 00 6D 00 75 00  |Q.u.i.c.k.e.m.u.|      │
│ 000001E0  51 00 75 00 69 00 63 00  6B 00 65 00 6D 00 75 00  |Q.u.i.c.k.e.m.u.|      │
│ 000001F0  FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|      │
│ 00000200  FF FF FF FF FF 87 25 76  01 02 00 00 07 00 00 00  |......%v........|      │
│ 00000210  02 00 02 00 00 00 00 00  29 B0 BD C2 50 1C 48 7C  |........)...P.H||      │
│ 00000220  CC 33 17 8F 4D 6D AC C7  02 00 02 00 10 00 00 00  |.3..Mm..........|      │
│ 00000230  AD 1D 88 65 3C B9 F6 07  0F 73 3A 32 ED 63 F3 00  |...e<....s:2.c..|      │
│ 00000240  65 53 88 AC 59 CF 74 FA  0F 6B 28 FB B0 D1 40 27  |eS..Y.t..k(...@'|      │
│ 00000250  03 23 F7 78 8A 12 2B 23  C1 17 44 BF 40 B0 CD 48  |.#.x..+#..D.@..H|      │
│ 00000260  02 00 02 00 00 00 00 00  66 ED 1F 74 B6 C0 CE 0D  |........f..t....|      │
│ 00000270  A9 21 B3 7E 85 AB F5 DA  02 00 02 00 00 00 00 00  |.!.~............|      │
│ 00000280  7A FA 90 00 F2 1F 56 7B  2B E6 47 82 BA 6C 70 4C  |z.....V{+.G..lpL|      │
│                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────── Fields ───────────────────────────────────────╮
│                                                                                     │
│   Offset   Len   Field                 Raw (hex)              Value                 │
│  ─────────────────────────────────────────────────────────────────────────────────  │
│   0x0000     4   F0 acct blob offset   00 00 00 00            0                     │
│   0x0004     4   F0 acct blob length   F4 00 00 00            244                   │
│   0x00CC    32   Account blob (first   01 00 14 80 D4 00 00   01 00 14 80 D4 00     │
│                  32 B)                 00 E4 00 00 00 14 00   00 00 E4 00 00 00     │
│                                        00 00 44 00 00 00 02   14 00 00 00 44 00     │
│                                        00 30 00 02 00 00 00   00 00 02 00 30 00     │
│                                        02 C0 14 00            02 00 00 00 02 C0     │
│                                                               14 00                 │
│   0x000C     4   F1 username offset    F4 00 00 00            244                   │
│   0x0010     4   F1 username length    10 00 00 00            16                    │
│   0x01C0    16   Username (UTF-16LE)   51 00 75 00 69 00 63   Quickemu              │
│                                        00 6B 00 65 00 6D 00                         │
│                                        75 00                                        │
│   0x0018     4   F2 full name offset   04 01 00 00            260                   │
│   0x001C     4   F2 full name length   10 00 00 00            16                    │
│   0x01D0    16   Full name             51 00 75 00 69 00 63   Quickemu              │
│                  (UTF-16LE)            00 6B 00 65 00 6D 00                         │
│                                        75 00                                        │
│   0x0024     4   F3 comment offset     14 01 00 00            276                   │
│   0x0028     4   F3 comment length     10 00 00 00            16                    │
│   0x01E0    16   Comment (UTF-16LE)    51 00 75 00 69 00 63   Quickemu              │
│                                        00 6B 00 65 00 6D 00                         │
│                                        75 00                                        │
│   0x0090     4   F12 LM hash offset    3C 01 00 00            316                   │
│   0x0094     4   F12 LM hash length    08 00 00 00            8 bytes (disabled)    │
│   0x009C     4   F13 NT hash offset    44 01 00 00            324                   │
│   0x00A0     4   F13 NT hash length    18 00 00 00            24 bytes              │
│   0x0218    16   NT hash               29 B0 BD C2 50 1C 48   29 B0 BD C2 50 1C     │
│                  (obfuscated, 16 B)    7C CC 33 17 8F 4D 6D   48 7C CC 33 17 8F     │
│                                        AC C7                  4D 6D AC C7           │
│                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────── Decoded ──────────────────────────────────────╮
│ Username:  Quickemu                                                                 │
│ Full name: Quickemu                                                                 │
│ Comment:   Quickemu                                                                 │
│                                                                                     │
│ LM/NT hash bytes at offsets above are RC4-obfuscated with the SYSKEY.               │
│ SYSKEY is derived from SYSTEM\ControlSet001\Control\Lsa\{JD,Skew1,GBG,Data}         │
╰─────────────────────────────────────────────────────────────────────────────────────╯
```

The hex dump shows the 16 obfuscated NT hash bytes at their exact offset in the
blob.

Decode an F value blob (account flags, logon timestamps, RID):

```fish
uv run tool.py fv f-blob exhibits/FV/QUICKEMU.F.bin
```

```text
───────────────────────────── SAM F Blob — QUICKEMU.F.bin ─────────────────────────────
╭───────────────────────────────────── Hex Dump ──────────────────────────────────────╮
│ 00000000  03 00 01 00 00 00 00 00  24 5C C6 D6 DC E2 DC 01  |........$\......|      │
│ 00000010  00 00 00 00 00 00 00 00  D2 A2 C5 8B B1 A1 DC 01  |................|      │
│ 00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|      │
│ 00000030  E8 03 00 00 01 02 00 00  10 00 00 00 2C 00 E4 04  |............,...|      │
│ 00000040  00 00 17 00                                        |....|                 │
│                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────── Fields ───────────────────────────────────────╮
│                                                                                     │
│   Offset   Len   Field               Raw (hex)               Value                  │
│  ─────────────────────────────────────────────────────────────────────────────────  │
│   0x0000     2   Revision            03 00                   3                      │
│   0x0008     8   Last logon          24 5C C6 D6 DC E2 DC    2026-05-13 13:31:43    │
│                                      01                      UTC                    │
│   0x0018     8   Last PW change      D2 A2 C5 8B B1 A1 DC    2026-02-19 15:08:04    │
│                                      01                      UTC                    │
│   0x0020     8   Account expires     00 00 00 00 00 00 00    Never                  │
│                                      00                                             │
│   0x0028     8   Last failed logon   00 00 00 00 00 00 00    Never                  │
│                                      00                                             │
│   0x0030     4   RID                 E8 03 00 00             1000                   │
│   0x0038     4   Account flags       10 00 00 00             0x00000010             │
│   0x0040     2   Failed count        00 00                   0                      │
│   0x0042     2   Logon count         17 00                   23                     │
│                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────╯
╭────────────────────────────────────── Decoded ──────────────────────────────────────╮
│ RID:               1000                                                             │
│ Account flags:     0x00000010  (Normal account)                                     │
│ Last logon:        2026-05-13 13:31:43 UTC                                          │
│ Last PW change:    2026-02-19 15:08:04 UTC                                          │
│ Account expires:   Never                                                            │
│ Last failed logon: Never                                                            │
│ Failed logon count:0                                                                │
│ Total logon count: 23                                                               │
╰─────────────────────────────────────────────────────────────────────────────────────╯
```

---

## time — Timestamp decoding

### FILETIME (Windows 64-bit, 100 ns since 1601-01-01)

Input file contains space-separated hex bytes (e.g. `8D 39 E4 CC A9 8E DB 01`):

```fish
uv run tool.py time filetime exhibits/tz/filetime.txt
```

```text
────────────────────────────────── FILETIME — filetime.txt ──────────────────────────────────
╭──────────────────────────────────────── Hex Dump ─────────────────────────────────────────╮
│ 00000000  8D 39 E4 CC A9 8E DB 01                           |.9......|                    │
│                                                                                           │
╰───────────────────────────────────────────────────────────────────────────────────────────╯
╭───────────────────────────────────────── Fields ──────────────────────────────────────────╮
│                                                                                           │
│   Offset   Len   Field                     Raw (hex)                 Value                │
│  ───────────────────────────────────────────────────────────────────────────────────────  │
│   0x0000     8   FILETIME (100-ns ticks)   8D 39 E4 CC A9 8E DB 01   133857473875687821   │
│                                                                                           │
╰───────────────────────────────────────────────────────────────────────────────────────────╯
╭───────────────────────────────────────── Decoded ─────────────────────────────────────────╮
│ Ticks: 133,857,473,875,687,821  (100-ns intervals since 1601-01-01)                       │
│ UTC:   2025-03-06 15:09:47.568782 UTC                                                     │
╰───────────────────────────────────────────────────────────────────────────────────────────╯
```

### SYSTEMTIME struct (8 × uint16 LE)

Input file contains the transition-to-summer-time date as space-separated hex
bytes: `00 00 03 00 05 00 02 00 00 00 00 00 00 00 00 00`

```fish
uv run tool.py time systemtime exhibits/tz/date.txt
```

> [!TODO] Fix the interpretation

```text
───────────────────────────── SYSTEMTIME — date.txt ──────────────────────────────
╭─────────────────────────────────── Hex Dump ───────────────────────────────────╮
│ 00000000  00 00 03 00 05 00 02 00  00 00 00 00 00 00 00 00  |................| │
│                                                                                │
╰────────────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────────── Fields ────────────────────────────────────╮
│                                                                                │
│   Offset   Len   Field          Raw (hex)   Value                              │
│  ──────────────────────────────────────────────────                            │
│   0x0000     2   Year           00 00       0                                  │
│   0x0002     2   Month          03 00       March                              │
│   0x0004     2   Day of week    05 00       Friday                             │
│   0x0006     2   Day            02 00       2                                  │
│   0x0008     2   Hour           00 00       0                                  │
│   0x000A     2   Minute         00 00       0                                  │
│   0x000C     2   Second         00 00       0                                  │
│   0x000E     2   Milliseconds   00 00       0                                  │
│                                                                                │
╰────────────────────────────────────────────────────────────────────────────────╯
╭──────────────┬───────────┬────────────────╮
│ Field        │ Raw value │ Interpretation │
├──────────────┼───────────┼────────────────┤
│ Year         │         0 │ —              │
│ Month        │         3 │ March          │
│ Day of week  │         5 │ Friday         │
│ Day          │         2 │ —              │
│ Hour         │         0 │ —              │
│ Minute       │         0 │ —              │
│ Second       │         0 │ —              │
│ Milliseconds │         0 │ —              │
╰──────────────┴───────────┴────────────────╯
```

### Unix timestamp

Input file contains a hex string (e.g. `0x676f94cc`):

```fish
uv run tool.py time unixtime exhibits/tz/unixtime.txt
```

```text
╭────────── Unix Timestamp — unixtime.txt ──────────╮
│ Hex:    0x676f94cc                                │
│ Decimal: 1,735,365,836                            │
│ UTC:    2024-12-28 06:03:56 UTC                   │
╰───────────────────────────────────────────────────╯
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

### NTFS partition recovery

Find deleted/broken NTFS partitions using the VBR

```fish
uv run tool.py image vbr-scan exhibits/image/disk.E01
```

```text
Partition table: 2 partition(s) at sectors [128, 4194432]
Mounting image and scanning for VBR signatures…
Scan complete: 5 VBR signature(s) found.

                                          VBR Scan — disk.E01
╭─────────┬─────────┬───────────┬─────────────┬───────────────┬───────────┬───────────────────────────╮
│  Sector │ Role    │ FS        │ Part. Start │ Total Sectors │ Backup At │ Status                    │
├─────────┼─────────┼───────────┼─────────────┼───────────────┼───────────┼───────────────────────────┤
│     128 │ Primary │ NTFS      │         128 │     4,194,303 │   4194431 │ ✓ Intact                  │
│ 1945726 │ Backup  │ NTFS      │         128 │     1,945,598 │   1945726 │ ⚠ Stale (primary resized) │
│ 4188286 │ Backup  │ NTFS      │     2097279 │     2,091,007 │   4188286 │ ✗ PRIMARY VBR MISSING     │
│ 4194431 │ Backup  │ NTFS      │         128 │     4,194,303 │   4194431 │ ✓ Intact                  │
│ 4194432 │ Primary │ BitLocker │     4194432 │             — │         — │ ✓ In part. table          │
╰─────────┴─────────┴───────────┴─────────────┴───────────────┴───────────┴───────────────────────────╯

╭───────────────────────────────────── Broken Partition Detected ─────────────────────────────────────╮
│ Backup VBR at sector:   4188286                                                                     │
│ Expected start sector:  2097279                                                                     │
│ Partition size:         2,091,007 sectors  (1,020 MiB)                                              │
│                                                                                                     │
│ Recover with:                                                                                       │
│   uv run tool.py image recover-partition exhibits/image/disk.E01 4188286 --output recovered.bin     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

If a broken partition is found you can recover it with the provided command.

> [!NOTE] The recovered partition might be broken. In this example, the primary
> VBR as well as \$MFT and \$MFTMirr were overwritten.

With a broken NTFS partition, it's still possible to bruteforce the MFT using
the following command:

```fish
uv run tool.py mft scan --raw recovered.bin --deleted
```

```text
Raw volume scan of recovered.bin (searching FILE signatures at 512-byte boundaries)…
                                                  MFT Scan — recovered.bin
╭──────┬─────────────────────────────┬─────────┬──────┬─────────────────────────┬─────────────────────────┬─────────────────╮
│ MFT# │ Filename                    │ Parent# │ Type │ Created                 │ Modified                │            Size │
├──────┼─────────────────────────────┼─────────┼──────┼─────────────────────────┼─────────────────────────┼─────────────────┤
│    2 │ $LogFile                    │       5 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │ 5,013,504 bytes │
│    3 │ $Volume                     │       5 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│    4 │ $AttrDef                    │       5 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │     2,400 bytes │
│    5 │ .                           │       5 │ DIR  │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│    6 │ $Bitmap                     │       5 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │    32,672 bytes │
│    7 │ $Boot                       │       5 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │     8,192 bytes │
│    8 │ $BadClus                    │       5 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│    9 │ $Secure                     │       5 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   10 │ $UpCase                     │       5 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │   131,072 bytes │
│   11 │ $Extend                     │       5 │ DIR  │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   24 │ $Quota                      │      11 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   25 │ $ObjId                      │      11 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   26 │ $Reparse                    │      11 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   27 │ $RmMetadata                 │      11 │ DIR  │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   28 │ $Repair                     │      27 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   29 │ $Deleted                    │      11 │ DIR  │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   30 │ $TxfLog                     │      27 │ DIR  │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   31 │ $Txf                        │      27 │ DIR  │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   32 │ $Tops                       │      30 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   33 │ $TxfLog.blf                 │      30 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   34 │ $TxfLogContainer0000000000… │      30 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   35 │ $TxfLogContainer0000000000… │      30 │ file │ 2025-04-30 13:39:39 UTC │ 2025-04-30 13:39:39 UTC │         0 bytes │
│   36 │ 00020000000000245FF6D41F    │      29 │ DIR  │ 2025-04-30 09:24:01 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   37 │ 26870853.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:34 UTC │         0 bytes │
│   38 │ 26869278.ZZZ                │      36 │ file │ 2025-04-30 13:44:38 UTC │ 2025-04-30 14:43:34 UTC │         0 bytes │
│   39 │ 26870631.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:34 UTC │         0 bytes │
│   40 │ 26870229.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:34 UTC │         0 bytes │
│   41 │ 26870846.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:34 UTC │         0 bytes │
│   42 │ 26869518.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   43 │ 26866740.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   44 │ 26868899.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   45 │ 26866231.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   46 │ 26871038.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   47 │ 26871804.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   48 │ 26871533.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   49 │ 26871225.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   50 │ 26870148.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   51 │ 26870113.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   52 │ 26870216.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   53 │ 26870410.ZZZ                │      36 │ file │ 2025-04-30 13:43:44 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   54 │ 26871899.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   55 │ 26867722.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   56 │ 26867050.ZZZ                │      36 │ file │ 2010-04-17 10:19:49 UTC │ 2025-04-30 14:43:35 UTC │         0 bytes │
│   57 │ Documents                   │       5 │ DIR  │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   58 │ +ou-.bmp                    │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   59 │ 21.12.2012.wps              │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   60 │ 24.01.07.bmp                │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   61 │ 26.02.07.bmp                │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   62 │ Annonce portes-ouvertes     │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│      │ automales.docx              │         │      │                         │                         │                 │
│   63 │ Astro Mathilde et Alex.doc  │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   64 │ ChromeSetup.exe             │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   65 │ clownarticle.docx           │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   66 │ ClownAvrilbillets.wps       │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   67 │ cours et pense-b_te.doc     │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   68 │ Document sans titre.wps     │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   69 │ D_marche Ayadi.doc          │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   70 │ D_marche Billioud 2.doc     │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   71 │ D_marche Billioud.doc       │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   72 │ D_marche Boub.doc           │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   73 │ D_marche Ovanis.doc         │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   74 │ Enfants.doc                 │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   75 │ Les bases du                │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│      │ magnétisme.docx             │         │      │                         │                         │                 │
│   76 │ Logo FFH.JPG                │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   77 │ mspde.doc                   │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   78 │ Organisation du soin.doc    │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   79 │ Pain-proteine.pdf           │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   80 │ Plannif.doc                 │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   81 │ PV_14-~1.DOC                │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   82 │ swissmilk_soupe-a-loignon.… │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   83 │ Tutti fruitti.wps           │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│   84 │ Votre offre SpaDreams       │      57 │ file │ 2025-04-30 13:49:05 UTC │ 2025-04-30 13:49:05 UTC │         0 bytes │
│      │ 356756.pdf                  │         │      │                         │                         │                 │
│   85 │ Sub0_glitch.bmp             │       5 │ file │ 2025-04-30 14:29:32 UTC │ 2025-04-30 14:29:32 UTC │         0 bytes │
│   86 │ 0002000000000056204019CD    │      29 │ DIR  │ 2010-04-17 12:06:17 UTC │ 2025-04-30 14:41:48 UTC │         0 bytes │
│   87 │ 26761912.ZZZ                │      86 │ file │ 2010-04-17 12:06:17 UTC │ 2025-04-30 14:41:48 UTC │         0 bytes │
│   88 │ 26765921.ZZZ                │      86 │ file │ 2010-04-17 12:06:19 UTC │ 2025-04-30 14:41:48 UTC │         0 bytes │
│   89 │ TeraCopyTestFile-1234567890 │       5 │ file │ 2025-04-30 14:27:25 UTC │ 2025-04-30 14:27:25 UTC │         0 bytes │
│   90 │ 000200000000005A30BB51E7    │      29 │ DIR  │ 2010-04-17 12:09:26 UTC │ 2025-04-30 14:42:01 UTC │         0 bytes │
│   91 │ 26778574.ZZZ                │      90 │ file │ 2010-04-17 12:09:27 UTC │ 2025-04-30 14:42:01 UTC │         0 bytes │
│   92 │ 26774123.ZZZ                │      90 │ file │ 2010-04-17 12:09:57 UTC │ 2025-04-30 14:42:01 UTC │         0 bytes │
│   93 │ 26820280.ZZZ                │       5 │ file │ 2022-10-19 07:03:56 UTC │ 2025-04-30 14:42:45 UTC │         0 bytes │
│   94 │ TeraCopyTestFile-1234567890 │       5 │ file │ 2025-04-30 14:25:38 UTC │ 2025-04-30 14:25:38 UTC │         0 bytes │
│   95 │ 26843388.ZZZ                │       5 │ file │ 2010-04-17 12:11:14 UTC │ 2025-04-30 14:43:11 UTC │         0 bytes │
│   96 │ 26837188.ZZZ                │       5 │ file │ 2010-04-17 12:10:19 UTC │ 2025-04-30 14:43:05 UTC │         0 bytes │
│   97 │ $RECYCLE.BIN                │       5 │ DIR  │ 2025-04-30 14:14:39 UTC │ 2025-04-30 14:14:39 UTC │         0 bytes │
│   98 │ S-1-5-21-1518623724-286941… │      97 │ DIR  │ 2025-04-30 14:14:39 UTC │ 2025-04-30 14:14:39 UTC │         0 bytes │
│   99 │ desktop.ini                 │      98 │ file │ 2025-04-30 14:14:39 UTC │ 2025-04-30 14:14:39 UTC │         0 bytes │
│  100 │ 26884880.ZZZ                │       5 │ file │ 2014-06-27 11:37:37 UTC │ 2025-04-30 14:43:47 UTC │         0 bytes │
│  101 │ Je_Vous_Deteste-Fais_comme… │       5 │ file │ 2025-04-30 14:19:59 UTC │ 2025-04-30 14:19:59 UTC │         0 bytes │
│  102 │ 26889304.ZZZ                │       5 │ file │ 2013-08-14 11:33:13 UTC │ 2025-04-30 14:43:56 UTC │         0 bytes │
╰──────┴─────────────────────────────┴─────────┴──────┴─────────────────────────┴─────────────────────────┴─────────────────╯
Scanned 94 record(s), displayed 89  (raw volume scan — FILE records at 512-byte boundaries)
```
