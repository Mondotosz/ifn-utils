import struct

from ifn.parsers.windows_time import filetime_to_datetime

BASE = 0xCC  # V blob: field data section starts at this offset

# MS-SAMR Section 2.2.1.12 USER_ACCOUNT Codes
# Binary F blob field: uint32 at offset 0x38 (56).
ACCOUNT_FLAGS = {
    0x00000001: "Account disabled",
    0x00000002: "Home directory required",
    0x00000004: "Password not required",
    0x00000008: "Temp duplicate account",
    0x00000010: "Normal account",
    0x00000020: "MNS logon account",
    0x00000040: "Interdomain trust account",
    0x00000080: "Workstation trust account",
    0x00000100: "Server trust account",
    0x00000200: "Password never expires",
    0x00000400: "Account auto-locked",
    0x00000800: "Encrypted text password allowed",
    0x00001000: "Smartcard required",
    0x00002000: "Trusted for delegation",
    0x00004000: "Not delegated",
    0x00008000: "Use DES key only",
    0x00010000: "Don't require preauth",
    0x00020000: "Password expired",
    0x00040000: "Trusted to auth for delegation",
    0x00080000: "No auth data required",
    0x00100000: "Partial secrets account",
    0x00200000: "Use AES keys",
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

    F blob layout (verified against Windows 10/11 SAM):
      0x00 uint16  Revision
      0x08 uint64  LastLogon (FILETIME)
      0x18 uint64  LastPwChange (FILETIME; 0 = must change at next logon)
      0x20 uint64  AccountExpires (FILETIME; 0x7FFFFFFFFFFFFFFF = never)
      0x28 uint64  LastFailedLogon (FILETIME)
      0x30 uint32  RID
      0x38 uint32  AccountFlags (USER_ACCOUNT Codes, MS-SAMR 2.2.1.12)
      0x40 uint16  FailedLogonCount
      0x42 uint16  LogonCount
    """
    if len(data) < 0x44:
        raise ValueError(f"F blob too short: {len(data)} bytes (expected ≥0x44)")

    def _ft(ticks: int):
        if ticks == 0x7FFFFFFFFFFFFFFF:
            return "never expires"
        if ticks == 0:
            return None
        return filetime_to_datetime(ticks)

    last_pw_change_ticks = struct.unpack_from("<Q", data, 0x18)[0]
    return {
        "rid":               struct.unpack_from("<I", data, 0x30)[0],
        "account_flags":     struct.unpack_from("<I", data, 0x38)[0],
        "last_logon":        _ft(struct.unpack_from("<Q", data, 0x08)[0]),
        "last_pw_change":    _ft(last_pw_change_ticks),
        "pw_must_change":    last_pw_change_ticks == 0,
        "account_expires":   _ft(struct.unpack_from("<Q", data, 0x20)[0]),
        "last_failed_logon": _ft(struct.unpack_from("<Q", data, 0x28)[0]),
        "failed_count":      struct.unpack_from("<H", data, 0x40)[0],
        "logon_count":       struct.unpack_from("<H", data, 0x42)[0],
    }
