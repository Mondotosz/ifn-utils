"""Parse a single NTFS MFT record (1024 bytes).

Layout of the entry header:
    0x00 4   Magic "FILE"
    0x04 2   USA offset
    0x06 2   USA size
    0x08 8   $LogFile sequence number (LSN)
    0x10 2   Sequence number
    0x12 2   Hard link count
    0x14 2   First attribute offset
    0x16 2   Flags  (0x01 in use, 0x02 directory, 0x04 in $Extend, 0x08 view index)
    0x18 4   Used size
    0x1C 4   Allocated size
    0x20 8   Base record reference
    0x28 2   Next attribute ID
    0x2C 4   Record number

Attribute header:
    0x00 4   Type
    0x04 4   Total length
    0x08 1   Non-resident flag
    0x09 1   Name length
    0x0A 2   Name offset
    0x0C 2   Flags  (0x0001 compressed, 0x0040 encrypted, 0x0080 sparse)
    0x0E 2   Attribute ID

    Resident extension:
        0x10 4   Content length
        0x14 2   Content offset
        0x16 1   Indexed flag

    Non-resident extension:
        0x10 8   Start VCN
        0x18 8   Last VCN
        0x20 2   Data-run offset
        0x22 2   Compression unit
        0x28 8   Allocated size
        0x30 8   Real size
        0x38 8   Initialised size
        0x40 8   Compressed size (only if compressed)
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field

from ifn.parsers.windows_time import filetime_to_datetime
from ifn.parsers.ntfs_data_runs import DataRun, parse_runs
from ifn.parsers import ntfs_attributes as nattr
from ifn.parsers import ntfs_index as nindex


MFT_RECORD_MAGIC = b"FILE"
MFT_RECORD_SIZE = 1024

# Re-export the attribute names dict so external callers can keep using
# `mft_record._ATTR_TYPES` if they want.
_ATTR_TYPES: dict[int, str] = nattr.ATTR_NAMES

_FILE_FLAGS = {
    0x0001: "In use",
    0x0002: "Directory",
    0x0004: "In $Extend",
    0x0008: "Is index",
}

_FILENAME_NAMESPACES = nattr.FN_NAMESPACES

# Attribute header flags (offset 0x0C).
_ATTR_HDR_FLAGS = [
    (0x0001, "Compressed"),
    (0x0040, "Encrypted"),
    (0x0080, "Sparse"),
]


@dataclass
class MFTAttribute:
    """One parsed attribute from a record.

    The shape of `decoded` is preserved from earlier versions of this file
    (a `dict[str, str]` used as a Field → Value table). Two additional
    structured fields cover types that don't fit that shape:

      * `attribute_list` — list of dicts for $ATTRIBUTE_LIST entries
      * `index_root`     — IndexRoot dataclass for $INDEX_ROOT bodies

    Non-resident layout fields are populated when `non_resident == True`;
    they default to 0 so existing positional constructions keep working.
    """
    attr_type: int
    attr_name: str
    length: int
    non_resident: bool
    name: str
    offset: int
    flags: int
    attr_id: int
    data: bytes
    decoded: dict = field(default_factory=dict)

    # ── New structured decoders ─────────────────────────────────────────
    attribute_list: list[dict[str, str]] = field(default_factory=list)
    index_root: nindex.IndexRoot | None = None

    # ── Resident header extras ──────────────────────────────────────────
    indexed: bool = False

    # ── Non-resident layout (zero if resident) ──────────────────────────
    start_vcn: int = 0
    last_vcn: int = 0
    run_offset: int = 0
    compression_unit: int = 0
    allocated_size: int = 0
    real_size: int = 0
    initialised_size: int = 0
    compressed_size: int = 0
    runs: list[DataRun] = field(default_factory=list)

    @property
    def header_flag_names(self) -> str:
        names = [n for b, n in _ATTR_HDR_FLAGS if self.flags & b]
        return ", ".join(names) if names else "None"


@dataclass
class MFTRecord:
    magic: bytes
    update_seq_offset: int
    update_seq_size: int
    log_file_seq: int
    seq_number: int
    hard_link_count: int
    first_attr_offset: int
    flags: int
    used_size: int
    alloc_size: int
    base_record_ref: int
    next_attr_id: int
    record_number: int
    attributes: list[MFTAttribute]

    @property
    def is_valid(self) -> bool:
        return self.magic == MFT_RECORD_MAGIC

    @property
    def is_directory(self) -> bool:
        return bool(self.flags & 0x0002)

    @property
    def is_in_use(self) -> bool:
        return bool(self.flags & 0x0001)

    @property
    def is_extension_record(self) -> bool:
        """True for records pointed to by a $ATTRIBUTE_LIST of a base record."""
        return self.base_record_ref != 0

    @property
    def flag_names(self) -> str:
        return ", ".join(v for k, v in _FILE_FLAGS.items() if self.flags & k) or "None"

    # ── Helpers ─────────────────────────────────────────────────────────
    def attributes_of_type(self, attr_type: int) -> list[MFTAttribute]:
        return [a for a in self.attributes if a.attr_type == attr_type]


# ──────────────────────────────────────────────────────────────────────────
# Decoders for the resident attribute bodies
# ──────────────────────────────────────────────────────────────────────────
def _ft(ticks: int) -> str:
    """Short UTC timestamp matching the existing key style."""
    return filetime_to_datetime(ticks).strftime("%Y-%m-%d %H:%M:%S UTC")


def _decode_standard_info(data: bytes) -> dict:
    if len(data) < 48:
        return {}
    created, modified, mft_modified, accessed = struct.unpack_from("<4Q", data, 0)
    file_attrs = struct.unpack_from("<I", data, 32)[0]
    out = {
        "Created":      _ft(created),
        "Modified":     _ft(modified),
        "MFT Modified": _ft(mft_modified),
        "Accessed":     _ft(accessed),
        "File attrs":   nattr.fmt_file_attrs(file_attrs),
    }
    if len(data) >= 72:
        owner_id, sec_id, quota, usn = struct.unpack_from("<IIQQ", data, 48)
        out.update({
            "Owner ID":    str(owner_id),
            "Security ID": str(sec_id),
            "Quota used":  f"{quota:,} bytes",
            "USN":         str(usn),
        })
    return out


def _decode_filename(data: bytes) -> dict:
    if len(data) < 66:
        return {}
    parent_ref_raw = struct.unpack_from("<Q", data, 0)[0]
    parent_record  = parent_ref_raw & 0x0000FFFFFFFFFFFF
    parent_seq     = (parent_ref_raw >> 48) & 0xFFFF
    created, modified, mft_modified, accessed = struct.unpack_from("<4Q", data, 8)
    alloc_size, real_size = struct.unpack_from("<QQ", data, 40)
    file_attrs = struct.unpack_from("<I", data, 56)[0]
    name_len = data[64]
    namespace = data[65]
    name = data[66: 66 + name_len * 2].decode("utf-16-le", errors="replace")
    return {
        "Filename":     name,
        "Namespace":    _FILENAME_NAMESPACES.get(namespace, str(namespace)),
        "Parent MFT#":  str(parent_record),
        "Parent seq":   str(parent_seq),
        "Created":      _ft(created),
        "Modified":     _ft(modified),
        "MFT Modified": _ft(mft_modified),
        "Accessed":     _ft(accessed),
        "Alloc size":   f"{alloc_size:,} bytes",
        "Real size":    f"{real_size:,} bytes",
        "File attrs":   nattr.fmt_file_attrs(file_attrs),
    }


# ──────────────────────────────────────────────────────────────────────────
# Attribute parser
# ──────────────────────────────────────────────────────────────────────────
def _parse_attribute(data: bytes, offset: int) -> MFTAttribute | None:
    if offset + 8 > len(data):
        return None
    attr_type = struct.unpack_from("<I", data, offset)[0]
    if attr_type == 0xFFFFFFFF:
        return MFTAttribute(0xFFFFFFFF, "End marker", 0, False, "", offset, 0, 0, b"", {})

    if offset + 16 > len(data):
        return None
    length = struct.unpack_from("<I", data, offset + 4)[0]
    if length == 0 or offset + length > len(data):
        return None

    non_resident = bool(data[offset + 8])
    name_len = data[offset + 9]
    name_offset = struct.unpack_from("<H", data, offset + 10)[0]
    flags = struct.unpack_from("<H", data, offset + 12)[0]
    attr_id = struct.unpack_from("<H", data, offset + 14)[0]

    attr_name = ""
    if name_len > 0 and offset + name_offset + name_len * 2 <= len(data):
        attr_name = data[offset + name_offset: offset + name_offset + name_len * 2] \
            .decode("utf-16-le", errors="replace")

    attr_type_name = _ATTR_TYPES.get(attr_type, f"Unknown (0x{attr_type:X})")

    attr = MFTAttribute(
        attr_type=attr_type, attr_name=attr_type_name, length=length,
        non_resident=non_resident, name=attr_name, offset=offset,
        flags=flags, attr_id=attr_id, data=b"",
    )

    if not non_resident:
        content_len = struct.unpack_from("<I", data, offset + 16)[0]
        content_offset = struct.unpack_from("<H", data, offset + 20)[0]
        attr.indexed = bool(data[offset + 22])
        body_start = offset + content_offset
        body_end   = body_start + content_len
        if 0 <= body_start <= body_end <= len(data):
            attr.data = bytes(data[body_start: body_end])
    else:
        # Non-resident header extras
        attr.start_vcn        = struct.unpack_from("<Q", data, offset + 16)[0]
        attr.last_vcn         = struct.unpack_from("<Q", data, offset + 24)[0]
        attr.run_offset       = struct.unpack_from("<H", data, offset + 32)[0]
        attr.compression_unit = struct.unpack_from("<H", data, offset + 34)[0]
        attr.allocated_size   = struct.unpack_from("<Q", data, offset + 40)[0]
        attr.real_size        = struct.unpack_from("<Q", data, offset + 48)[0]
        attr.initialised_size = struct.unpack_from("<Q", data, offset + 56)[0]
        if flags & 0x0001 and offset + 72 <= len(data):
            attr.compressed_size = struct.unpack_from("<Q", data, offset + 64)[0]
        run_data = data[offset + attr.run_offset: offset + length]
        attr.data = bytes(run_data)
        attr.runs = parse_runs(run_data)

    # ── Decode the body when we can ────────────────────────────────────
    if not non_resident and attr.data:
        if attr_type == 0x10:
            attr.decoded = _decode_standard_info(attr.data)
        elif attr_type == 0x20:
            attr.attribute_list = nattr.decode_attribute_list(attr.data)
        elif attr_type == 0x30:
            attr.decoded = _decode_filename(attr.data)
        elif attr_type == 0x40:
            attr.decoded = nattr.decode_object_id(attr.data)
        elif attr_type == 0x60:
            attr.decoded = nattr.decode_volume_name(attr.data)
        elif attr_type == 0x70:
            attr.decoded = nattr.decode_volume_information(attr.data)
        elif attr_type == 0x90:
            try:
                attr.index_root = nindex.parse_index_root(attr.data)
            except ValueError:
                pass
        elif attr_type == 0xB0:
            attr.decoded = nattr.decode_bitmap(attr.data)
        elif attr_type == 0xC0:
            attr.decoded = nattr.decode_reparse_point(attr.data)

    return attr


def parse(data: bytes) -> MFTRecord:
    if len(data) < 48:
        raise ValueError(f"MFT record too short: {len(data)} bytes")

    magic = data[0:4]
    upd_offset, upd_size = struct.unpack_from("<HH", data, 4)
    log_seq = struct.unpack_from("<Q", data, 8)[0]
    seq_num    = struct.unpack_from("<H", data, 16)[0]
    hard_links = struct.unpack_from("<H", data, 18)[0]
    first_attr = struct.unpack_from("<H", data, 20)[0]
    flags      = struct.unpack_from("<H", data, 22)[0]
    used_sz    = struct.unpack_from("<I", data, 24)[0]
    alloc_sz   = struct.unpack_from("<I", data, 28)[0]
    base_ref   = struct.unpack_from("<Q", data, 32)[0]
    next_id    = struct.unpack_from("<H", data, 40)[0]
    record_num = struct.unpack_from("<I", data, 44)[0] if len(data) >= 48 else 0

    attributes: list[MFTAttribute] = []
    offset = first_attr
    while offset < len(data) - 4:
        attr = _parse_attribute(data, offset)
        if attr is None:
            break
        attributes.append(attr)
        if attr.attr_type == 0xFFFFFFFF or attr.length == 0:
            break
        offset += attr.length

    return MFTRecord(magic, upd_offset, upd_size, log_seq, seq_num, hard_links,
                     first_attr, flags, used_sz, alloc_sz, base_ref, next_id,
                     record_num, attributes)
