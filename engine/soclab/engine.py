"""Routing events to rules by log source, and running rules over events."""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass

from .events import load_events
from .sigma import Rule, load_rule_file


def _channel(event: dict) -> str:
    return str(event.get("Channel") or event.get("channel") or "")


def _event_id(event: dict) -> str:
    eid = event.get("EventID", event.get("event_id"))
    return "" if eid is None else str(eid)


def in_scope(logsource: dict, event: dict) -> bool:
    """Decide whether an event belongs to a rule's declared log source.

    The mapping is deliberately small and covers only the categories the rules
    in ``detections/`` use. It routes by Sysmon/Windows channel and event id,
    and by the ``_logsource`` marker the auditd normaliser sets.
    """
    product = logsource.get("product")
    category = logsource.get("category")
    service = logsource.get("service")
    channel = _channel(event)
    eid = _event_id(event)
    is_lin_sysmon = channel == "Linux-Sysmon/Operational"
    is_win_sysmon = "Sysmon" in channel and not is_lin_sysmon
    is_auditd = event.get("_logsource") == "auditd"

    if product == "linux":
        if is_auditd and service in (None, "auditd"):
            # auditd records only satisfy an auditd/unspecified-service source
            return service == "auditd" or category is None
        if category == "process_creation":
            return is_lin_sysmon and eid == "1"
        if category == "network_connection":
            return is_lin_sysmon and eid == "3"
        if category == "file_event":
            return is_lin_sysmon and eid == "11"
        if service == "auditd":
            return is_auditd
        return False

    if product == "windows":
        if is_lin_sysmon:
            return False
        if category == "process_creation":
            return (is_win_sysmon and eid == "1") or eid == "4688"
        if category in ("registry_set", "registry_add", "registry_event", "registry_delete"):
            want = {
                "registry_add": {"12"},
                "registry_set": {"13"},
                "registry_delete": {"12"},
                "registry_event": {"12", "13", "14"},
            }[category]
            return is_win_sysmon and eid in want
        if category == "create_remote_thread":
            return is_win_sysmon and eid == "8"
        if category == "image_load":
            return is_win_sysmon and eid == "7"
        if category == "wmi_event":
            return is_win_sysmon and eid in {"19", "20", "21"}
        if service == "sysmon":
            return is_win_sysmon
        if service == "system":
            return channel == "System"
        if service == "security":
            return channel == "Security"
        if service == "powershell":
            return "PowerShell" in channel
        # product windows, no category/service we route: any windows channel
        return is_win_sysmon or channel in ("Security", "System", "Application")

    # No product declared: let the rule see everything.
    return True


def load_rules(path: str) -> list[Rule]:
    """Load every ``.yml`` / ``.yaml`` rule under a directory, or one file."""
    if os.path.isdir(path):
        files = sorted(
            f for ext in ("yml", "yaml")
            for f in glob.glob(os.path.join(path, "**", f"*.{ext}"), recursive=True)
        )
    else:
        files = [path]
    return [load_rule_file(f) for f in files]


@dataclass
class Hit:
    rule: Rule
    source: str
    index: int
    event: dict


def run_rules(rules: list[Rule], events: list[dict], source: str = "") -> list[Hit]:
    hits: list[Hit] = []
    for index, event in enumerate(events):
        for rule in rules:
            if not in_scope(rule.logsource, event):
                continue
            if rule.matches(event):
                hits.append(Hit(rule, source, index, event))
    return hits


def run_over_files(rules: list[Rule], paths: list[str], fmt: str = "auto") -> list[Hit]:
    hits: list[Hit] = []
    for path in paths:
        events = load_events(path, fmt)
        hits.extend(run_rules(rules, events, source=path))
    return hits
