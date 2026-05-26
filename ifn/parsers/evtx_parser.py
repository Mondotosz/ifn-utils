from __future__ import annotations
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

import Evtx.Evtx as evtx_lib

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

SECURITY_EVENT_NAMES: dict[int, str] = {
    1100: "Logging service stopped",
    4104: "PowerShell script logged",
    4608: "Windows starting up",
    4609: "Windows shutting down",
    4616: "System time modified",
    4625: "Logon failure",
    4634: "Account logged off",
    4648: "Explicit credentials logon",
    4688: "New process created",
    4720: "User account created",
    4778: "Terminal session reconnect",
}

FORENSIC_EVENT_IDS: frozenset[int] = frozenset(SECURITY_EVENT_NAMES)

_INTERESTING_FIELDS: dict[int, list[str]] = {
    4688: ["SubjectUserName", "NewProcessName", "CommandLine", "ParentProcessName"],
    4625: ["TargetUserName", "LogonType", "IpAddress", "FailureReason"],
    4634: ["SubjectUserName", "LogonType"],
    4648: ["SubjectUserName", "TargetUserName", "ProcessName", "IpAddress"],
    4720: ["SubjectUserName", "TargetUserName"],
    4616: ["SubjectUserName", "OldTime", "NewTime"],
    4778: ["AccountName", "ClientName", "ClientAddress"],
    4104: ["ScriptBlockText"],
    1100: [],
    4608: [],
    4609: [],
}


def parse_record_xml(xml_str: str) -> dict | None:
    """Parse an event XML string into a structured dict. Returns None on error."""
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return None

    system = root.find(f"{{{_NS}}}System")
    if system is None:
        return None

    event_id_el = system.find(f"{{{_NS}}}EventID")
    if event_id_el is None:
        return None
    try:
        event_id = int(event_id_el.text or "0")
    except ValueError:
        return None

    time_el = system.find(f"{{{_NS}}}TimeCreated")
    timestamp = time_el.get("SystemTime") if time_el is not None else None

    computer_el = system.find(f"{{{_NS}}}Computer")
    computer = computer_el.text if computer_el is not None else None

    event_data = root.find(f"{{{_NS}}}EventData")
    fields: dict[str, str] = {}
    if event_data is not None:
        for data_el in event_data.findall(f"{{{_NS}}}Data"):
            name = data_el.get("Name", "")
            text = (data_el.text or "").strip()
            if name:
                fields[name] = text

    interesting = _INTERESTING_FIELDS.get(event_id, [])
    details = {k: fields[k] for k in interesting if k in fields}

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": computer,
        "description": SECURITY_EVENT_NAMES.get(event_id, f"Event {event_id}"),
        "fields": fields,
        "details": details,
    }


def iter_records(path: str | Path) -> Iterator[dict]:
    """Yield parsed event dicts from an .evtx file path."""
    with evtx_lib.Evtx(str(path)) as log:
        for record in log.records():
            try:
                xml = record.xml()
                parsed = parse_record_xml(xml)
                if parsed is not None:
                    parsed["record_num"] = record.record_num()
                    yield parsed
            except Exception:
                continue
