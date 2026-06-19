"""Per-rule tests: each rule fires on its real attack fixture and stays quiet
on benign events of the same log-source category.

The attack fixtures are small extracts from public datasets (see
tests/fixtures/SOURCES.md). The benign fixtures are in-scope events from the
same datasets that should not match any rule.
"""

import glob
import os

import pytest

from soclab import load_events, load_rule_file
from soclab.engine import in_scope, load_rules

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RULES_DIR = os.path.join(ROOT, "detections")
FX = os.path.join(HERE, "fixtures")


def _rule_by_id():
    rules = load_rules(RULES_DIR)
    return {os.path.basename(r.path)[:-4]: r for r in rules}


RULES = _rule_by_id()

# Attack fixtures are named <rule_id>.attack.<ext>.
ATTACK_FIXTURES = sorted(
    glob.glob(os.path.join(FX, "windows", "*.attack.*"))
    + glob.glob(os.path.join(FX, "linux", "*.attack.*"))
)


def _rule_id_from_fixture(path: str) -> str:
    return os.path.basename(path).split(".attack.")[0]


def _benign_fixture_for(rule) -> str | None:
    ls = rule.logsource
    product = ls.get("product")
    category = ls.get("category")
    service = ls.get("service")
    if product == "windows":
        if category == "process_creation":
            return os.path.join(FX, "windows", "process_creation_benign.jsonl")
        if category and category.startswith("registry"):
            return os.path.join(FX, "windows", "registry_benign.jsonl")
        if category == "wmi_event":
            return os.path.join(FX, "windows", "wmi_benign.jsonl")
        if service == "system":
            return os.path.join(FX, "windows", "system_benign.jsonl")
    if product == "linux":
        if category == "process_creation":
            return os.path.join(FX, "linux", "process_creation_benign.log")
        if category == "network_connection":
            return os.path.join(FX, "linux", "network_benign.json")
        if category == "file_event":
            return os.path.join(FX, "linux", "file_benign.log")
        if service == "auditd":
            return os.path.join(FX, "linux", "auditd_benign.log")
    return None


def _count_matches(rule, path: str) -> int:
    events = load_events(path)
    return sum(1 for e in events if in_scope(rule.logsource, e) and rule.matches(e))


def test_every_rule_has_an_attack_fixture():
    have = {_rule_id_from_fixture(p) for p in ATTACK_FIXTURES}
    missing = set(RULES) - have
    assert not missing, f"rules without an attack fixture: {sorted(missing)}"


@pytest.mark.parametrize("fixture", ATTACK_FIXTURES, ids=_rule_id_from_fixture)
def test_rule_fires_on_its_attack_fixture(fixture):
    rule_id = _rule_id_from_fixture(fixture)
    rule = RULES[rule_id]
    assert _count_matches(rule, fixture) >= 1, f"{rule_id} did not fire on {fixture}"


@pytest.mark.parametrize("fixture", ATTACK_FIXTURES, ids=_rule_id_from_fixture)
def test_rule_quiet_on_benign_fixture(fixture):
    rule_id = _rule_id_from_fixture(fixture)
    rule = RULES[rule_id]
    benign = _benign_fixture_for(rule)
    assert benign is not None, f"no benign fixture mapped for {rule_id}"
    assert _count_matches(rule, benign) == 0, f"{rule_id} fired on benign events in {benign}"


def test_all_rules_parse():
    files = (
        glob.glob(os.path.join(RULES_DIR, "**", "*.yml"), recursive=True)
        + glob.glob(os.path.join(RULES_DIR, "**", "*.yaml"), recursive=True)
    )
    assert len(files) >= 12
    for f in files:
        load_rule_file(f)  # raises on any problem


def test_benign_fixtures_quiet_for_all_rules():
    """No rule should fire on any benign fixture."""
    all_rules = list(RULES.values())
    for benign in glob.glob(os.path.join(FX, "*", "*benign*")):
        events = load_events(benign)
        for rule in all_rules:
            hits = sum(1 for e in events if in_scope(rule.logsource, e) and rule.matches(e))
            assert hits == 0, f"{os.path.basename(rule.path)} fired on {os.path.basename(benign)}"
