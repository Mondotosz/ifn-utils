"""Parse a GPT (GUID Partition Table) from a disk dump."""
from __future__ import annotations
import struct
import uuid
from dataclasses import dataclass

GPT_SIGNATURE = b"EFI PART"
GPT_HEADER_REVISION = 0x00010000

_PARTITION_TYPES: dict[str, str] = {
    "00000000-0000-0000-0000-000000000000": "Unused",
    "024DEE41-33E7-11D3-9D69-0008C781F39F": "MBR Partition Scheme",
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI System Partition",
    "21686148-6449-6E6F-744E-656564454649": "BIOS Boot",
    "D3BFE2DE-3DAF-11DF-BA40-E3A556D89593": "Intel Fast Flash",
    "F4019732-066E-4E12-8273-346C5641494F": "Sony Boot",
    "BFBFAFE7-A34F-448A-9A5B-6213EB736C22": "Lenovo Boot",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft Reserved",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Microsoft Basic Data",
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Windows LDM Metadata",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "Windows LDM Data",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows Recovery",
    "37AFFC90-EF7D-4E96-91C3-2D7AE055B174": "IBM GPFS",
    "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D": "Windows Storage Spaces",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux Data",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux Swap",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "8DA63339-0007-60C0-C436-083AC8230908": "Linux Reserved",
    "83BD6B9D-7F41-11DC-BE0B-001560B84F0F": "FreeBSD Boot",
    "516E7CB4-6ECF-11D6-8FF8-00022D09712B": "FreeBSD Data",
    "516E7CB5-6ECF-11D6-8FF8-00022D09712B": "FreeBSD Swap",
    "516E7CB6-6ECF-11D6-8FF8-00022D09712B": "FreeBSD UFS",
    "516E7CBA-6ECF-11D6-8FF8-00022D09712B": "FreeBSD ZFS",
    "48465300-0000-11AA-AA11-00306543ECAC": "macOS HFS+",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "macOS APFS",
    "55465300-0000-11AA-AA11-00306543ECAC": "macOS UFS",
    "52414944-0000-11AA-AA11-00306543ECAC": "macOS RAID",
    "426F6F74-0000-11AA-AA11-00306543ECAC": "macOS Boot",
    "4C616265-6C00-11AA-AA11-00306543ECAC": "macOS Label",
    "5265636F-7665-11AA-AA11-00306543ECAC": "macOS Recovery",
}


def _guid_str(raw: bytes) -> str:
    """Convert mixed-endian GPT GUID bytes to standard UUID string (uppercase)."""
    p1 = struct.unpack_from("<IHH", raw, 0)
    p2 = raw[8:10]
    p3 = raw[10:16]
    return f"{p1[0]:08X}-{p1[1]:04X}-{p1[2]:04X}-{p2.hex().upper()}-{p3.hex().upper()}"


@dataclass
class GPTHeader:
    signature: bytes
    revision: int
    header_size: int
    header_crc32: int
    current_lba: int
    backup_lba: int
    first_usable_lba: int
    last_usable_lba: int
    disk_guid: str
    partition_array_lba: int
    num_partitions: int
    partition_entry_size: int
    partition_array_crc32: int


@dataclass
class GPTPartition:
    index: int
    type_guid: str
    unique_guid: str
    first_lba: int
    last_lba: int
    attributes: int
    name: str

    @property
    def type_name(self) -> str:
        return _PARTITION_TYPES.get(self.type_guid, f"Unknown ({self.type_guid})")

    @property
    def size_bytes(self) -> int:
        return (self.last_lba - self.first_lba + 1) * 512


@dataclass
class GPT:
    protective_mbr: bytes
    header: GPTHeader
    partitions: list[GPTPartition]


def parse(data: bytes) -> GPT:
    if len(data) < 1024:
        raise ValueError(f"GPT dump must be ≥1024 bytes, got {len(data)}")

    protective_mbr = data[:512]
    hdr_off = 512

    sig = data[hdr_off: hdr_off + 8]
    if sig != GPT_SIGNATURE:
        raise ValueError(f"Invalid GPT signature: {sig!r}")

    revision, hdr_size, hdr_crc32 = struct.unpack_from("<III", data, hdr_off + 8)
    current_lba, backup_lba = struct.unpack_from("<QQ", data, hdr_off + 24)
    first_usable, last_usable = struct.unpack_from("<QQ", data, hdr_off + 40)
    disk_guid = _guid_str(data[hdr_off + 56: hdr_off + 72])
    part_lba, num_parts, part_size, part_crc = struct.unpack_from("<QIIH", data, hdr_off + 72)
    # part_size is 4 bytes, num_parts is 4 bytes — re-read correctly
    part_lba, num_parts, part_size, part_crc = struct.unpack_from("<QIII", data, hdr_off + 72)

    header = GPTHeader(
        sig, revision, hdr_size, hdr_crc32,
        current_lba, backup_lba, first_usable, last_usable,
        disk_guid, part_lba, num_parts, part_size, part_crc,
    )

    partitions = []
    part_array_off = part_lba * 512
    if part_array_off + num_parts * part_size > len(data):
        # Partition array may be beyond the dumped data — parse what we can
        available = (len(data) - part_array_off) // part_size if part_array_off < len(data) else 0
        num_parts = available

    for i in range(num_parts):
        off = part_array_off + i * part_size
        if off + part_size > len(data):
            break
        type_guid = _guid_str(data[off: off + 16])
        unique_guid = _guid_str(data[off + 16: off + 32])
        first_lba, last_lba, attrs = struct.unpack_from("<QQQ", data, off + 32)
        name_raw = data[off + 56: off + 128]
        name = name_raw.decode("utf-16-le").rstrip("\x00")
        if type_guid == "00000000-0000-0000-0000-000000000000":
            continue
        partitions.append(GPTPartition(i, type_guid, unique_guid, first_lba, last_lba, attrs, name))

    return GPT(protective_mbr, header, partitions)
