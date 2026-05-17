"""NTFS directory index parsing ($INDEX_ROOT, $INDEX_ALLOCATION, INDX buffers).

A directory in NTFS is a B+Tree of INDEX_ENTRY records keyed by $FILE_NAME.
Two attributes work together:

  * $INDEX_ROOT (0x90, always resident) — root of the tree, contains the
    first entries (or all of them for small directories).
  * $INDEX_ALLOCATION (0xA0, non-resident) — extra "index buffers" (INDX
    records) for large directories, addressed by data runs.

Index entry layout:
    0x00 8   MFT reference of the indexed file (record + sequence)
    0x08 2   Total entry length
    0x0A 2   Content length ($FILE_NAME body length, 0 for end-marker)
    0x0C 1   Flags  (0x01 = has sub-node, 0x02 = last entry)
    0x0D 3   Padding
    0x10 ... $FILE_NAME body
    end-8    VCN of the child INDX buffer (only if flag 0x01 set)

An INDX buffer (typically 4096 B) starts with:
    0x00 4   Signature "INDX"
    0x04 2   USA offset
    0x06 2   USA count
    0x08 8   $LogFile sequence number
    0x10 8   VCN of this buffer in $INDEX_ALLOCATION
    0x18 ... Index header (entries_offset is RELATIVE to 0x18)
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field

from ifn.parsers.windows_time import filetime_to_datetime, fmt_filetime
from ifn.parsers.ntfs_attributes import FN_NAMESPACES, fmt_file_attrs, fmt_mft_reference


INDX_MAGIC = b"INDX"

INDEX_ENTRY_FLAG_SUBNODE = 0x01
INDEX_ENTRY_FLAG_LAST    = 0x02


def _decode_filename_body(data: bytes) -> dict[str, str]:
    """Decode the $FILE_NAME body embedded in an index entry."""
    if len(data) < 66:
        return {}
    parent_ref = struct.unpack_from("<Q", data, 0)[0]
    created, modified, mft_modified, accessed = struct.unpack_from("<4Q", data, 8)
    alloc_size, real_size = struct.unpack_from("<QQ", data, 40)
    file_attrs = struct.unpack_from("<I", data, 56)[0]
    name_len   = data[64]
    namespace  = data[65]
    name = data[66: 66 + name_len * 2].decode("utf-16-le", errors="replace")
    return {
        "Filename":        name,
        "Namespace":       f"{namespace} ({FN_NAMESPACES.get(namespace, '?')})",
        "Parent MFT ref":  fmt_mft_reference(parent_ref),
        "Created":         fmt_filetime(created),
        "Modified":        fmt_filetime(modified),
        "MFT Modified":    fmt_filetime(mft_modified),
        "Accessed":        fmt_filetime(accessed),
        "Allocated size":  f"{alloc_size:,} bytes",
        "Real size":       f"{real_size:,} bytes",
        "File attributes": fmt_file_attrs(file_attrs),
    }


@dataclass
class IndexEntry:
    mft_ref: int
    entry_length: int
    content_length: int
    flags: int
    body: bytes
    child_vcn: int | None = None

    @property
    def is_last(self) -> bool:
        return bool(self.flags & INDEX_ENTRY_FLAG_LAST)

    @property
    def has_subnode(self) -> bool:
        return bool(self.flags & INDEX_ENTRY_FLAG_SUBNODE)

    def decoded_filename(self) -> dict[str, str]:
        return _decode_filename_body(self.body)


@dataclass
class IndexHeader:
    entries_offset: int   # relative to the start of this header
    entries_size: int
    allocated_size: int
    has_subnodes: bool


@dataclass
class IndexRoot:
    """Body of an $INDEX_ROOT attribute."""
    attribute_type: int
    collation_rule: int
    index_buffer_size: int
    clusters_per_buffer: int
    header: IndexHeader
    entries: list[IndexEntry] = field(default_factory=list)


@dataclass
class IndxBuffer:
    """One INDX record from $INDEX_ALLOCATION."""
    raw: bytes
    usa_offset: int
    usa_count: int
    log_seq: int
    vcn: int
    header: IndexHeader
    entries: list[IndexEntry] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────────
# Update Sequence Array (USA) — same mechanism as MFT records
# ──────────────────────────────────────────────────────────────────────────
def apply_usa(data: bytes, sector_size: int = 512) -> bytes:
    """Restore the last 2 bytes of each sector from the USA table."""
    if len(data) < 48:
        return data
    usa_off = struct.unpack_from("<H", data, 4)[0]
    usa_cnt = struct.unpack_from("<H", data, 6)[0]
    if usa_off == 0 or usa_cnt < 2 or usa_off + usa_cnt * 2 > len(data):
        return data
    out = bytearray(data)
    check = struct.unpack_from("<H", out, usa_off)[0]
    for i in range(1, usa_cnt):
        end = i * sector_size - 2
        if end + 2 > len(out):
            break
        if struct.unpack_from("<H", out, end)[0] != check:
            return data
        original = struct.unpack_from("<H", out, usa_off + i * 2)[0]
        struct.pack_into("<H", out, end, original)
    return bytes(out)


# ──────────────────────────────────────────────────────────────────────────
# Shared entry-list parser
# ──────────────────────────────────────────────────────────────────────────
def _parse_index_header(data: bytes, offset: int) -> IndexHeader:
    entries_off, entries_sz, alloc_sz = struct.unpack_from("<III", data, offset)
    has_sub = bool(data[offset + 12] & 0x01)
    return IndexHeader(entries_off, entries_sz, alloc_sz, has_sub)


def _parse_entries(data: bytes, start: int, end: int) -> list[IndexEntry]:
    entries: list[IndexEntry] = []
    pos = start
    while pos + 16 <= end:
        mft_ref = struct.unpack_from("<Q", data, pos)[0]
        entry_len, content_len = struct.unpack_from("<HH", data, pos + 8)
        flags = data[pos + 12]
        if entry_len == 0 or pos + entry_len > end:
            break

        body = data[pos + 16: pos + 16 + content_len] if content_len > 0 else b""

        child_vcn = None
        if flags & INDEX_ENTRY_FLAG_SUBNODE and entry_len >= 8:
            child_vcn = struct.unpack_from("<Q", data, pos + entry_len - 8)[0]

        entries.append(IndexEntry(mft_ref, entry_len, content_len, flags, bytes(body), child_vcn))

        if flags & INDEX_ENTRY_FLAG_LAST:
            break
        pos += entry_len
    return entries


# ──────────────────────────────────────────────────────────────────────────
# $INDEX_ROOT parser (body of attribute 0x90)
# ──────────────────────────────────────────────────────────────────────────
def parse_index_root(data: bytes) -> IndexRoot:
    if len(data) < 32:
        raise ValueError(f"$INDEX_ROOT body too short: {len(data)} B")
    attr_type, collation, idx_size, clusters_pb = struct.unpack_from("<IIIB", data, 0)
    header = _parse_index_header(data, 16)
    entries_start = 16 + header.entries_offset
    entries_end   = min(16 + header.entries_offset + header.entries_size, len(data))
    entries = _parse_entries(data, entries_start, entries_end)
    return IndexRoot(attr_type, collation, idx_size, clusters_pb, header, entries)


# ──────────────────────────────────────────────────────────────────────────
# INDX buffer parser
# ──────────────────────────────────────────────────────────────────────────
def parse_indx_buffer(raw: bytes, sector_size: int = 512) -> IndxBuffer:
    """Parse a single INDX buffer. Applies the USA fixup first."""
    if len(raw) < 0x28 or raw[:4] != INDX_MAGIC:
        raise ValueError(f"Not an INDX buffer (magic={raw[:4]!r})")
    data = apply_usa(raw, sector_size)
    usa_off = struct.unpack_from("<H", data, 4)[0]
    usa_cnt = struct.unpack_from("<H", data, 6)[0]
    log_seq = struct.unpack_from("<Q", data, 8)[0]
    vcn     = struct.unpack_from("<q", data, 16)[0]
    header  = _parse_index_header(data, 0x18)
    entries_start = 0x18 + header.entries_offset
    entries_end   = min(0x18 + header.entries_offset + header.entries_size, len(data))
    entries = _parse_entries(data, entries_start, entries_end)
    return IndxBuffer(data, usa_off, usa_cnt, log_seq, vcn, header, entries)


def iter_indx_buffers(stream: bytes, buffer_size: int) -> list[IndxBuffer]:
    """Split a raw $INDEX_ALLOCATION dump into INDX buffers and parse each one.

    If `stream` is shorter than `buffer_size` (eg. a truncated 512-byte
    lab exhibit) it is parsed as a single buffer when possible.
    """
    if len(stream) < buffer_size and stream[:4] == INDX_MAGIC:
        try:
            return [parse_indx_buffer(stream)]
        except ValueError:
            return []
    buffers: list[IndxBuffer] = []
    for off in range(0, len(stream), buffer_size):
        chunk = stream[off: off + buffer_size]
        if len(chunk) < 0x28 or chunk[:4] != INDX_MAGIC:
            continue
        try:
            buffers.append(parse_indx_buffer(chunk))
        except ValueError:
            continue
    return buffers
