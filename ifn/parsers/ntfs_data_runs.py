"""NTFS data run (runlist) parser.

A data run describes the on-disk location of a non-resident attribute.
Each run is encoded as:

    +---------+---------------------+--------------------------+
    | header  | cluster length (L)  | LCN delta (signed, O)    |
    +---------+---------------------+--------------------------+
       1 B            1..8 B                  0..8 B

The header byte packs two nibbles:
    high nibble = number of bytes used for the offset delta
    low  nibble = number of bytes used for the length

A run with offset size 0 is a **sparse** run (no clusters allocated).
The LCN delta is **signed** and relative to the previous run — that is what
allows a runlist to describe fragmented (non-contiguous) extents.
A header byte of 0x00 marks the end of the runlist.
"""
from __future__ import annotations
from dataclasses import dataclass


SPARSE_LCN = -1


@dataclass
class DataRun:
    """One on-disk extent of a non-resident attribute."""
    lcn: int          # absolute Logical Cluster Number, or SPARSE_LCN
    length: int       # number of clusters in this run
    header: int       # raw header byte (for display)
    offset_size: int  # nibble: bytes used to encode the offset delta
    length_size: int  # nibble: bytes used to encode the length

    @property
    def is_sparse(self) -> bool:
        return self.lcn == SPARSE_LCN


def parse_runs(run_bytes: bytes) -> list[DataRun]:
    """Decode a runlist into a list of DataRun objects.

    Stops at the first 0x00 header byte or at a malformed run.
    """
    runs: list[DataRun] = []
    pos = 0
    current_lcn = 0
    while pos < len(run_bytes):
        header = run_bytes[pos]
        if header == 0:
            break
        length_size = header & 0x0F
        offset_size = (header >> 4) & 0x0F
        pos += 1
        if length_size == 0 or pos + length_size > len(run_bytes):
            break

        length = int.from_bytes(run_bytes[pos: pos + length_size], "little")
        pos += length_size

        if offset_size == 0:
            runs.append(DataRun(SPARSE_LCN, length, header, offset_size, length_size))
        else:
            if pos + offset_size > len(run_bytes):
                break
            raw = run_bytes[pos: pos + offset_size]
            delta = int.from_bytes(raw, "little", signed=False)
            if raw[-1] & 0x80:                       # sign-extend
                delta -= 1 << (offset_size * 8)
            current_lcn += delta
            runs.append(DataRun(current_lcn, length, header, offset_size, length_size))
            pos += offset_size
    return runs
