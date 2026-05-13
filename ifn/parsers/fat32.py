"""Parse a FAT32 Volume Boot Record (BPB)."""
from __future__ import annotations
import struct
from dataclasses import dataclass

_MEDIA_TYPES = {
    0xF0: "Removable (3.5\" floppy)",
    0xF8: "Fixed disk",
    0xF9: "Removable (3.5\" DS/HD floppy)",
    0xFA: "Removable (5.25\" SS/LD floppy)",
    0xFB: "Removable (3.5\" SS/HD floppy)",
    0xFC: "Removable (5.25\" SS/DD floppy)",
    0xFD: "Removable (5.25\" DS/DD floppy)",
    0xFE: "Removable (5.25\" SS/SD floppy)",
    0xFF: "Removable (5.25\" DS/HD floppy)",
}


@dataclass
class FAT32VBR:
    jump: bytes
    oem_id: str
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    root_entry_count: int       # 0 for FAT32
    total_sectors_16: int       # 0 if >65535
    media_type: int
    fat_size_16: int            # 0 for FAT32
    sectors_per_track: int
    num_heads: int
    hidden_sectors: int
    total_sectors_32: int
    # FAT32 extended BPB
    fat_size_32: int
    ext_flags: int
    fs_version: int
    root_cluster: int
    fs_info_sector: int
    backup_boot_sector: int
    drive_number: int
    boot_signature: int
    volume_id: int
    volume_label: str
    fs_type: str
    signature: int

    @property
    def media_name(self) -> str:
        return _MEDIA_TYPES.get(self.media_type, f"Unknown (0x{self.media_type:02X})")

    @property
    def cluster_size_bytes(self) -> int:
        return self.sectors_per_cluster * self.bytes_per_sector

    @property
    def total_sectors(self) -> int:
        return self.total_sectors_32 if self.total_sectors_16 == 0 else self.total_sectors_16

    @property
    def signature_valid(self) -> bool:
        return self.signature == 0xAA55


def parse(data: bytes) -> FAT32VBR:
    if len(data) < 512:
        raise ValueError(f"VBR must be 512 bytes, got {len(data)}")

    jump = data[0:3]
    oem_id = data[3:11].decode("ascii", errors="replace").rstrip()

    (bytes_per_sec, sec_per_clus, reserved, num_fats,
     root_entry_count, total_sec16, media, fat_size16,
     sec_per_track, num_heads, hidden_sec, total_sec32) = struct.unpack_from("<HBHBHHBHHHII", data, 11)

    (fat_size32, ext_flags, fs_version, root_cluster,
     fs_info, backup_boot) = struct.unpack_from("<IHHIHH", data, 36)

    drive_num = data[64]
    boot_sig = data[66]
    vol_id = struct.unpack_from("<I", data, 67)[0]
    vol_label = data[71:82].decode("ascii", errors="replace").rstrip()
    fs_type = data[82:90].decode("ascii", errors="replace").rstrip()
    signature = struct.unpack_from("<H", data, 510)[0]

    return FAT32VBR(
        jump, oem_id, bytes_per_sec, sec_per_clus, reserved, num_fats,
        root_entry_count, total_sec16, media, fat_size16, sec_per_track,
        num_heads, hidden_sec, total_sec32, fat_size32, ext_flags,
        fs_version, root_cluster, fs_info, backup_boot, drive_num,
        boot_sig, vol_id, vol_label, fs_type, signature,
    )
