"""Parse a 512-byte Master Boot Record."""
from __future__ import annotations
import struct
from dataclasses import dataclass

_PARTITION_TYPES: dict[int, str] = {
    0x00: "Empty",
    0x01: "FAT12",
    0x04: "FAT16 <32M",
    0x05: "Extended (CHS)",
    0x06: "FAT16",
    0x07: "NTFS / exFAT",
    0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)",
    0x0E: "FAT16 (LBA)",
    0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12",
    0x14: "Hidden FAT16 <32M",
    0x16: "Hidden FAT16",
    0x17: "Hidden NTFS",
    0x1B: "Hidden FAT32 (CHS)",
    0x1C: "Hidden FAT32 (LBA)",
    0x1E: "Hidden FAT16 (LBA)",
    0x27: "Windows RE",
    0x42: "Dynamic Disk",
    0x82: "Linux Swap",
    0x83: "Linux",
    0x85: "Linux Extended",
    0x8E: "Linux LVM",
    0xA0: "Hibernation",
    0xA8: "macOS",
    0xAB: "macOS Boot",
    0xAF: "HFS+",
    0xBE: "Solaris Boot",
    0xBF: "Solaris",
    0xEE: "GPT Protective MBR",
    0xEF: "EFI System Partition",
    0xFB: "VMware VMFS",
    0xFC: "VMware VMKCORE",
    0xFD: "Linux RAID",
    0xFE: "Hidden",
    0xFF: "BBT",
}


@dataclass
class PartitionEntry:
    index: int
    status: int
    chs_first: tuple[int, int, int]
    type_code: int
    chs_last: tuple[int, int, int]
    lba_start: int
    lba_size: int

    @property
    def type_name(self) -> str:
        return _PARTITION_TYPES.get(self.type_code, f"Unknown (0x{self.type_code:02X})")

    @property
    def active(self) -> bool:
        return self.status == 0x80

    @property
    def lba_end(self) -> int:
        return self.lba_start + self.lba_size - 1

    @property
    def size_bytes(self) -> int:
        return self.lba_size * 512


@dataclass
class MBR:
    bootstrap: bytes
    disk_signature: int
    reserved: int
    partitions: list[PartitionEntry]
    boot_signature: int

    @property
    def signature_valid(self) -> bool:
        return self.boot_signature == 0xAA55


def _parse_chs(raw: bytes) -> tuple[int, int, int]:
    """Unpack 3-byte CHS: head, sector (bits 5-0 of byte 1), cylinder (bits 7-6 of byte 1 + byte 2)."""
    head = raw[0]
    sector = raw[1] & 0x3F
    cylinder = ((raw[1] & 0xC0) << 2) | raw[2]
    return head, sector, cylinder


def parse(data: bytes) -> MBR:
    if len(data) < 512:
        raise ValueError(f"MBR must be 512 bytes, got {len(data)}")

    bootstrap = data[0:446]
    disk_sig, reserved = struct.unpack_from("<IH", data, 440)
    boot_sig = struct.unpack_from("<H", data, 510)[0]

    partitions = []
    for i in range(4):
        off = 446 + i * 16
        entry = data[off: off + 16]
        status = entry[0]
        chs_first = _parse_chs(entry[1:4])
        type_code = entry[4]
        chs_last = _parse_chs(entry[5:8])
        lba_start, lba_size = struct.unpack_from("<II", entry, 8)
        partitions.append(PartitionEntry(i, status, chs_first, type_code, chs_last, lba_start, lba_size))

    return MBR(bootstrap, disk_sig, reserved, partitions, boot_sig)
