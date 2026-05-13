import struct

from ifn.parsers.windows_time import filetime_to_datetime

BASE = 0xCC  # V blob: field data section starts at this offset

ACCOUNT_FLAGS = {
    0x0001: "Disabled",
    0x0002: "Home dir required",
    0x0004: "Password not required",
    0x0008: "Temp duplicate account",
    0x0010: "Normal user account",
    0x0020: "MNS logon account",
    0x0040: "Interdomain trust account",
    0x0080: "Workstation trust account",
    0x0100: "Server trust account",
    0x0200: "Password never expires",
    0x0400: "Auto-locked",
}


def fmt_flags(acct_flags: int) -> str:
    names = [name for bit, name in ACCOUNT_FLAGS.items() if acct_flags & bit]
    return ", ".join(names) if names else "None"


def _read_field(data: bytes, index: int) -> tuple[int, int, bytes]:
    off = index * 12
    rel_off = struct.unpack_from("<I", data, off)[0]
    length = struct.unpack_from("<I", data, off + 4)[0]
    abs_off = BASE + rel_off
    content = data[abs_off: abs_off + length] if abs_off + length <= len(data) else b""
    return rel_off, length, content


def extract_user_sid(v_data: bytes, rid: int) -> str | None:
    """Scan V blob for the embedded user SID (S-1-5-21-X-Y-Z-RID) and return it as a string."""
    rid_bytes = struct.pack("<I", rid)
    # SID layout: 01 05 00 00 00 00 00 05 | 15 00 00 00 | X(4) | Y(4) | Z(4) | RID(4)
    #              8-byte header            sub-auth[0]=21        domain             user
    # RID is at offset 24 from the SID start, so SID start = match_pos - 24
    pos = v_data.find(rid_bytes)
    while pos >= 24:
        sid_start = pos - 24
        h = v_data[sid_start: sid_start + 8]
        if (h[0] == 1 and h[1] == 5
                and h[2:8] == b"\x00\x00\x00\x00\x00\x05"):
            sub0 = struct.unpack_from("<I", v_data, sid_start + 8)[0]
            if sub0 == 21:
                x = struct.unpack_from("<I", v_data, sid_start + 12)[0]
                y = struct.unpack_from("<I", v_data, sid_start + 16)[0]
                z = struct.unpack_from("<I", v_data, sid_start + 20)[0]
                return f"S-1-5-21-{x}-{y}-{z}-{rid}"
        pos = v_data.find(rid_bytes, pos + 1)
    return None


def parse_v_blob(data: bytes) -> dict:
    """Extract user info from a SAM V blob.

    Returns: username, fullname, comment, lm_hash (bytes|None), nt_hash (bytes|None).
    Hash bytes are obfuscated; SYSKEY required to decrypt.
    """
    def _str(raw: bytes) -> str:
        return raw.decode("utf-16-le", errors="replace") if raw else ""

    _, _, raw1 = _read_field(data, 1)
    _, _, raw2 = _read_field(data, 2)
    _, _, raw3 = _read_field(data, 3)

    _, ln12, raw12 = _read_field(data, 12)
    lm_hash = raw12 if ln12 > 8 else None

    _, ln13, raw13 = _read_field(data, 13)
    nt_hash = None
    if ln13 >= 20:
        nt_hash = raw13[8:24] if len(raw13) >= 24 else raw13[4:20]

    return {
        "username": _str(raw1),
        "fullname": _str(raw2),
        "comment": _str(raw3),
        "lm_hash": lm_hash,
        "nt_hash": nt_hash,
    }


def parse_f_blob(data: bytes) -> dict:
    """Extract account metadata from a SAM F blob.

    Returns: rid, account_flags, last_logon, last_pw_change, account_expires,
             last_failed_logon (datetime | None | "never expires"), failed_count, logon_count.
    """
    if len(data) < 72:
        raise ValueError(f"F blob too short: {len(data)} bytes (expected ≥72)")

    def _ft(ticks: int):
        if ticks == 0:
            return None
        if ticks == 0x7FFFFFFFFFFFFFFF:
            return "never expires"
        return filetime_to_datetime(ticks)

    return {
        "rid":               struct.unpack_from("<I", data, 48)[0],
        "account_flags":     struct.unpack_from("<H", data, 52)[0],
        "last_logon":        _ft(struct.unpack_from("<Q", data, 8)[0]),
        "last_pw_change":    _ft(struct.unpack_from("<Q", data, 24)[0]),
        "account_expires":   _ft(struct.unpack_from("<Q", data, 32)[0]),
        "last_failed_logon": _ft(struct.unpack_from("<Q", data, 40)[0]),
        "failed_count":      struct.unpack_from("<H", data, 64)[0],
        "logon_count":       struct.unpack_from("<H", data, 66)[0],
    }
