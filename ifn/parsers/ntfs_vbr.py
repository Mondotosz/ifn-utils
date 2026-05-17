"""NTFS Volume Boot Record (VBR) parser.

Layout of the first 512 bytes of an NTFS volume:

    0x000 3   Jump code (eg EB 52 90)
    0x003 8   OEM ID    (eg "NTFS    ")
    0x00B 73  BIOS Parameter Block (BPB + extended BPB)
    0x054 426 Bootstrap code
    0x1FE 2   Signature 0x55AA

Key BPB fields (offsets into the VBR):

    0x00B 2   Bytes per sector       (usually 512)
    0x00D 1   Sectors per cluster    (1, 2, 4, 8, 16, …)
    0x015 1   Media descriptor       (0xF8 = fixed disk)
    0x018 2   Sectors per track
    0x01A 2   Number of heads
    0x01C 4   Hidden sectors         (partition start LBA on the disk)
    0x028 8   Total sectors in the volume
    0x030 8   LCN of $MFT
    0x038 8   LCN of $MFTMirr
    0x040 1   $MFT record size       (SIGNED — see formula below)
    0x044 1   Index buffer size      (SIGNED — same formula)
    0x048 8   Volume serial number
    0x050 4   Checksum (unused, 0)

Record / index-buffer size formula (signed byte):
    if value >= 0: size_in_clusters = value
    if value <  0: size_in_bytes    = 2 ** (-value)
The signed encoding lets values < 1 cluster (typical 1024-B record on
4 KiB cluster volumes) coexist with larger multi-cluster records.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass


NTFS_OEM = b"NTFS    "
VBR_SIGNATURE = 0xAA55


@dataclass
class NtfsVbr:
    raw: bytes
    jump_code: bytes
    oem_id: str
    bytes_per_sector: int
    sectors_per_cluster: int
    media_descriptor: int
    sectors_per_track: int
    num_heads: int
    hidden_sectors: int
    total_sectors: int
    mft_lcn: int
    mftmirr_lcn: int
    mft_record_size_raw: int        # signed byte at 0x40
    index_buffer_size_raw: int      # signed byte at 0x44
    volume_serial: int
    checksum: int
    signature: int

    # ── Derived helpers ──────────────────────────────────────────────────
    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def mft_offset_bytes(self) -> int:
        return self.mft_lcn * self.cluster_size

    @property
    def mftmirr_offset_bytes(self) -> int:
        return self.mftmirr_lcn * self.cluster_size

    @property
    def mft_record_size(self) -> int:
        return _decode_size(self.mft_record_size_raw, self.cluster_size)

    @property
    def index_buffer_size(self) -> int:
        return _decode_size(self.index_buffer_size_raw, self.cluster_size)

    @property
    def volume_size_bytes(self) -> int:
        return self.total_sectors * self.bytes_per_sector

    @property
    def signature_valid(self) -> bool:
        return self.signature == VBR_SIGNATURE

    @property
    def is_ntfs(self) -> bool:
        return self.oem_id.encode("ascii", "replace").startswith(b"NTFS")


def _decode_size(value: int, cluster_size: int) -> int:
    """Decode the signed size field used for MFT record size & index buffer size."""
    if value >= 0:
        return value * cluster_size
    return 1 << (-value)


def parse(data: bytes) -> NtfsVbr:
    """Parse a 512-byte NTFS VBR."""
    if len(data) < 512:
        raise ValueError(f"VBR must be at least 512 bytes, got {len(data)}")

    return NtfsVbr(
        raw=bytes(data[:512]),
        jump_code=bytes(data[0:3]),
        oem_id=data[3:11].decode("ascii", errors="replace"),
        bytes_per_sector   = struct.unpack_from("<H", data, 0x0B)[0],
        sectors_per_cluster= data[0x0D],
        media_descriptor   = data[0x15],
        sectors_per_track  = struct.unpack_from("<H", data, 0x18)[0],
        num_heads          = struct.unpack_from("<H", data, 0x1A)[0],
        hidden_sectors     = struct.unpack_from("<I", data, 0x1C)[0],
        total_sectors      = struct.unpack_from("<Q", data, 0x28)[0],
        mft_lcn            = struct.unpack_from("<q", data, 0x30)[0],
        mftmirr_lcn        = struct.unpack_from("<q", data, 0x38)[0],
        mft_record_size_raw= struct.unpack_from("<b", data, 0x40)[0],
        index_buffer_size_raw = struct.unpack_from("<b", data, 0x44)[0],
        volume_serial      = struct.unpack_from("<Q", data, 0x48)[0],
        checksum           = struct.unpack_from("<I", data, 0x50)[0],
        signature          = struct.unpack_from("<H", data, 0x1FE)[0],
    )


def fmt_serial(serial: int) -> str:
    """Format the 64-bit serial like Windows' `vol` command (high32-low32)."""
    high = (serial >> 32) & 0xFFFFFFFF
    low  = serial & 0xFFFFFFFF
    return f"{high:08X}-{low:08X}"
