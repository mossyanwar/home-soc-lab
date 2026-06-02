"""Loading and normalising event logs into flat dicts the evaluator can match.

Three input shapes are supported:

* ``json`` / ``jsonl`` -- one JSON object per line, already flat. This is the
  shape of the OTRF Security-Datasets Windows files and of the JSONL written by
  ``lab/windows/export-events.ps1``. Loaded unchanged.
* ``sysmon-xml`` -- Windows-style Sysmon event XML, either one ``<Event>`` per
  line (Sysmon for Linux via journald) or wrapped in a JSON ``SyslogMessage``
  field (the OTRF syslog datasets). Each event becomes a flat dict with the
  ``<Data Name=...>`` fields at the top level, plus ``Channel`` and ``EventID``.
  Truncated lines are parsed as far as they go rather than dropped.
* ``auditd`` -- raw ``auditd`` text, one record per line. Each line becomes one
  dict of its ``key=value`` pairs, with the hex ``proctitle`` decoded to text.
  Both the kernel format (epoch timestamps, quoted values) and the
  ``ausearch``-interpreted format (human timestamps, decoded values) are read.
"""

from __future__ import annotations

import html
import json
import re
from typing import Iterator

_EVENTID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
_COMPUTER = re.compile(r"<Computer>([^<]*)</Computer>")
_UTC = re.compile(r'<TimeCreated SystemTime="([^"]*)"')
_DATA = re.compile(r'<Data Name="([^"]+)">(.*?)</Data>', re.S)
# Tolerate a final, truncated <Data ...> with no closing tag.
_DATA_OPEN = re.compile(r'<Data Name="([^"]+)">([^<]*)\Z')


def load_jsonl(path: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                events.append(obj)
    return events


def _parse_sysmon_xml(xml: str) -> dict | None:
    m = _EVENTID.search(xml)
    if not m:
        return None
    event: dict = {
        "Channel": "Linux-Sysmon/Operational",
        "EventID": int(m.group(1)),
    }
    c = _COMPUTER.search(xml)
    if c:
        event["Hostname"] = html.unescape(c.group(1))
    t = _UTC.search(xml)
    if t:
        event["TimeCreated"] = t.group(1)
    for name, value in _DATA.findall(xml):
        event[name] = html.unescape(value)
    tail = _DATA_OPEN.search(xml)
    if tail and tail.group(1) not in event:
        event[tail.group(1)] = html.unescape(tail.group(2))
    return event


def normalise_sysmon_xml(path: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            xml = line
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                xml = obj.get("SyslogMessage") or obj.get("message") or ""
                if "<Event" not in xml:
                    continue
            ev = _parse_sysmon_xml(xml)
            if ev is not None:
                events.append(ev)
    return events


_AUDIT_ID = re.compile(r"audit\(([^)]*)\)")
_KV = re.compile(r"(\w+)=((?:\"[^\"]*\")|(?:\([^)]*\))|(?:\S+))")


def _decode_proctitle(value: str) -> str:
    """auditd proctitle is hex with NUL argument separators in the kernel
    format, or already decoded in the ausearch format."""
    v = value.strip()
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", v):
        try:
            return bytes.fromhex(v).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except ValueError:
            return v
    return v


def _parse_auditd_line(line: str) -> dict | None:
    if "type=" not in line or "audit(" not in line:
        return None
    event: dict = {"_logsource": "auditd"}
    tm = _AUDIT_ID.search(line)
    if tm:
        event["_audit_id"] = tm.group(1)
    # Strip the "msg=audit(...)" chunk so its inner commas do not confuse the
    # key=value scan, then collect the remaining pairs.
    rest = line
    for key, value in _KV.findall(rest):
        if key == "msg":
            continue
        val = value
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        event[key] = val
    if "proctitle" in event:
        event["proctitle"] = _decode_proctitle(event["proctitle"])
    return event


def normalise_auditd(path: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ev = _parse_auditd_line(line)
            if ev is not None:
                events.append(ev)
    return events


def _guess_format(path: str) -> str:
    lower = path.lower()
    if lower.endswith((".jsonl", ".json")):
        # A sysmon syslog export is also .json; sniff the first useful line.
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if '"SyslogMessage"' in line or line.startswith("<Event"):
                    return "sysmon-xml"
                return "jsonl"
        return "jsonl"
    with open(path, encoding="utf-8", errors="replace") as fh:
        head = fh.read(4096)
    if "<Event" in head:
        return "sysmon-xml"
    if "type=" in head and "audit(" in head:
        return "auditd"
    return "jsonl"


def load_events(path: str, fmt: str = "auto") -> list[dict]:
    if fmt == "auto":
        fmt = _guess_format(path)
    if fmt in ("json", "jsonl"):
        return load_jsonl(path)
    if fmt == "sysmon-xml":
        return normalise_sysmon_xml(path)
    if fmt == "auditd":
        return normalise_auditd(path)
    raise ValueError(f"unknown event format '{fmt}'")


def iter_events(paths: list[str], fmt: str = "auto") -> Iterator[tuple[str, dict]]:
    for path in paths:
        for event in load_events(path, fmt):
            yield path, event
