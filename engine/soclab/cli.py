"""Command-line interface for the home SOC lab engine.

    soclab run --rules detections events.jsonl [more.jsonl ...]
    soclab convert --target lucene detections
    soclab normalise -f auditd audit.log -o out.jsonl
    soclab list-rules detections
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

from . import events as events_mod
from .convert import ConvertUnavailable, convert_file
from .engine import Hit, load_rules, run_rules
from .sigma import SigmaError

# A few fields worth showing when a rule fires, in priority order.
_INTERESTING = [
    "UtcTime", "TimeCreated", "Hostname", "Image", "ParentImage", "CommandLine",
    "TargetObject", "Details", "TargetFilename", "DestinationIp", "DestinationPort",
    "ServiceName", "ImagePath", "Query", "Destination", "Consumer",
    "proctitle", "exe", "comm", "a0", "a1", "a2", "key",
]


def _event_summary(event: dict) -> str:
    parts = []
    for field in _INTERESTING:
        if field in event and event[field] not in (None, "", "-"):
            value = str(event[field])
            if len(value) > 160:
                value = value[:157] + "..."
            parts.append(f"{field}={value}")
    return "  ".join(parts) if parts else json.dumps(event)[:200]


def _expand_rule_paths(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        out.extend(sorted(glob.glob(p)) if any(c in p for c in "*?[") else [p])
    return out


def cmd_run(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.rules)
    except SigmaError as exc:
        print(f"error loading rules: {exc}", file=sys.stderr)
        return 2
    if not rules:
        print(f"no rules found under {args.rules}", file=sys.stderr)
        return 2

    all_hits: list[Hit] = []
    total_events = 0
    for path in args.events:
        evs = events_mod.load_events(path, args.format)
        total_events += len(evs)
        all_hits.extend(run_rules(rules, evs, source=path))

    by_rule: dict[str, list[Hit]] = {}
    for hit in all_hits:
        by_rule.setdefault(hit.rule.title, []).append(hit)

    print(f"loaded {len(rules)} rules, read {total_events} events from {len(args.events)} file(s)")
    print(f"{len(all_hits)} hit(s) across {len(by_rule)} rule(s)\n")
    for title in sorted(by_rule):
        hits = by_rule[title]
        rule = hits[0].rule
        tags = ", ".join(t for t in rule.tags if t.startswith("attack."))
        print(f"[{rule.level or 'n/a'}] {title}  ({len(hits)} hit(s))  {tags}")
        shown = hits if args.verbose else hits[: args.sample]
        for hit in shown:
            print(f"    {os.path.basename(hit.source)}#{hit.index}: {_event_summary(hit.event)}")
        if not args.verbose and len(hits) > args.sample:
            print(f"    ... and {len(hits) - args.sample} more")
        print()

    if args.json:
        payload = [
            {
                "rule_id": h.rule.id,
                "rule_title": h.rule.title,
                "level": h.rule.level,
                "tags": h.rule.tags,
                "source": h.source,
                "event_index": h.index,
                "event": h.event,
            }
            for h in all_hits
        ]
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"wrote {len(payload)} hit(s) to {args.json}")
    return 0


def cmd_convert(args: argparse.Namespace) -> int:
    files = []
    for rp in _expand_rule_paths(args.rules):
        if os.path.isdir(rp):
            for ext in ("yml", "yaml"):
                files.extend(sorted(glob.glob(os.path.join(rp, "**", f"*.{ext}"), recursive=True)))
        else:
            files.append(rp)
    if not files:
        print("no rule files given", file=sys.stderr)
        return 2
    rc = 0
    for path in sorted(set(files)):
        try:
            queries = convert_file(path, args.target)
        except ConvertUnavailable as exc:
            print(f"conversion unavailable: {exc}", file=sys.stderr)
            return 3
        except Exception as exc:  # a single bad rule should not stop the rest
            print(f"# {os.path.basename(path)}: conversion failed: {exc}", file=sys.stderr)
            rc = 1
            continue
        for q in queries:
            print(f"# {os.path.basename(path)}")
            print(q)
            print()
    return rc


def cmd_normalise(args: argparse.Namespace) -> int:
    evs = events_mod.load_events(args.input, args.format)
    out = args.out or (os.path.splitext(args.input)[0] + ".jsonl")
    with open(out, "w", encoding="utf-8") as fh:
        for ev in evs:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print(f"wrote {len(evs)} events to {out}")
    return 0


def cmd_list_rules(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.rules)
    except SigmaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for rule in sorted(rules, key=lambda r: r.path):
        tags = ",".join(t for t in rule.tags if t.startswith("attack.t"))
        print(f"{rule.level:9} {os.path.basename(rule.path):52} {tags}  {rule.title}")
    print(f"\n{len(rules)} rules")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="soclab", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run rules over event logs")
    p_run.add_argument("--rules", default="detections", help="rule file or directory")
    p_run.add_argument("--format", default="auto", choices=["auto", "jsonl", "json", "sysmon-xml", "auditd"])
    p_run.add_argument("--sample", type=int, default=2, help="sample events shown per rule")
    p_run.add_argument("--verbose", action="store_true", help="show every matching event")
    p_run.add_argument("--json", help="also write all hits as JSON to this path")
    p_run.add_argument("events", nargs="+", help="event log files")
    p_run.set_defaults(func=cmd_run)

    p_conv = sub.add_parser("convert", help="convert rules to Splunk or Lucene queries")
    p_conv.add_argument("--target", required=True, choices=["splunk", "lucene"])
    p_conv.add_argument("rules", nargs="+", help="rule files or directories")
    p_conv.set_defaults(func=cmd_convert)

    p_norm = sub.add_parser("normalise", help="normalise one log file to JSONL")
    p_norm.add_argument("-f", "--format", default="auto", choices=["auto", "jsonl", "json", "sysmon-xml", "auditd"])
    p_norm.add_argument("-o", "--out", help="output path (default: alongside input)")
    p_norm.add_argument("input", help="input log file")
    p_norm.set_defaults(func=cmd_normalise)

    p_list = sub.add_parser("list-rules", help="list loaded rules")
    p_list.add_argument("--rules", default="detections")
    p_list.set_defaults(func=cmd_list_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
