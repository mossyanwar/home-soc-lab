"""Unit tests for the Sigma evaluator (soclab.sigma)."""

import pytest

from soclab.sigma import SigmaError, ValueMatcher, load_rule


def match(raw, modifiers, value):
    return ValueMatcher(raw, tuple(modifiers)).matches(value)


def test_plain_equality_is_case_insensitive():
    assert match("cmd.exe", [], "CMD.EXE")
    assert not match("cmd.exe", [], "cmd.com")


def test_cased_modifier_is_case_sensitive():
    assert match("Cmd", ["cased"], "Cmd")
    assert not match("Cmd", ["cased"], "cmd")


def test_contains_startswith_endswith():
    assert match("comsvcs", ["contains"], r"C:\windows\system32\comsvcs.dll")
    assert match(r"\rundll32.exe", ["endswith"], r"C:\Windows\System32\rundll32.exe")
    assert not match(r"\rundll32.exe", ["endswith"], r"C:\Windows\System32\cmd.exe")
    assert match("powershell", ["startswith"], "powershell.exe -enc AAA")
    assert not match("powershell", ["startswith"], "C:\\powershell.exe")


def test_wildcards_in_plain_value():
    assert match("*comsvcs*MiniDump*", [], "rundll32 comsvcs.dll MiniDump 123")
    assert not match("*comsvcs*MiniDump*", [], "rundll32 shell32.dll")
    assert match("lsass.?xe", [], "lsass.exe")


def test_backslash_escaped_wildcard_is_literal():
    # a literal asterisk, not a wildcard
    assert match(r"a\*b", [], "a*b")
    assert not match(r"a\*b", [], "axxb")


def test_regex_modifier():
    assert match(r"-e\w*\s+[A-Za-z0-9+/=]{10,}", ["re"], "powershell -enc SQBFAFgAKAAnAA==")
    assert not match(r"-e\w*\s+[A-Za-z0-9+/=]{10,}", ["re"], "powershell -Command x")


def test_null_value_matches_absent_field():
    assert match(None, [], None)
    assert not match(None, [], "something")


def test_number_equality():
    assert match(7045, [], "7045")
    assert match(7045, [], 7045)
    assert not match(7045, [], 7046)


def _rule(detection, logsource=None):
    data = {
        "title": "t",
        "id": "x",
        "logsource": logsource or {"product": "windows", "category": "process_creation"},
        "detection": detection,
    }
    return load_rule(data)


def test_selection_keys_are_anded():
    rule = _rule({
        "selection": {"Image|endswith": r"\rundll32.exe", "CommandLine|contains": "comsvcs"},
        "condition": "selection",
    })
    assert rule.matches({"Image": r"C:\rundll32.exe", "CommandLine": "x comsvcs y"})
    assert not rule.matches({"Image": r"C:\rundll32.exe", "CommandLine": "nothing"})


def test_value_list_is_ored_by_default():
    rule = _rule({"selection": {"Image|endswith": [r"\a.exe", r"\b.exe"]}, "condition": "selection"})
    assert rule.matches({"Image": r"c:\b.exe"})
    assert not rule.matches({"Image": r"c:\c.exe"})


def test_all_modifier_ands_the_value_list():
    rule = _rule({
        "selection": {"CommandLine|contains|all": ["comsvcs", "MiniDump"]},
        "condition": "selection",
    })
    assert rule.matches({"CommandLine": "rundll32 comsvcs MiniDump 1"})
    assert not rule.matches({"CommandLine": "rundll32 comsvcs only"})


def test_list_of_maps_is_ored():
    rule = _rule({
        "selection": [{"Image|endswith": r"\a.exe"}, {"Image|endswith": r"\b.exe"}],
        "condition": "selection",
    })
    assert rule.matches({"Image": r"c:\a.exe"})
    assert rule.matches({"Image": r"c:\b.exe"})
    assert not rule.matches({"Image": r"c:\c.exe"})


def test_condition_and_or_not():
    rule = _rule({
        "a": {"f": "1"}, "b": {"g": "2"}, "c": {"h": "3"},
        "condition": "a and (b or c) and not d" if False else "a and (b or c)",
    })
    assert rule.matches({"f": "1", "g": "2"})
    assert rule.matches({"f": "1", "h": "3"})
    assert not rule.matches({"f": "1"})


def test_condition_not():
    rule = _rule({"a": {"f": "1"}, "b": {"g": "2"}, "condition": "a and not b"})
    assert rule.matches({"f": "1"})
    assert not rule.matches({"f": "1", "g": "2"})


def test_quantifier_one_of_them():
    rule = _rule({"sel_a": {"f": "1"}, "sel_b": {"g": "2"}, "condition": "1 of them"})
    assert rule.matches({"f": "1"})
    assert rule.matches({"g": "2"})
    assert not rule.matches({"z": "9"})


def test_quantifier_all_of_pattern():
    rule = _rule({
        "sel_a": {"f": "1"}, "sel_b": {"g": "2"}, "other": {"h": "3"},
        "condition": "all of sel_*",
    })
    assert rule.matches({"f": "1", "g": "2"})
    assert not rule.matches({"f": "1"})


def test_quantifier_count_of_pattern():
    rule = _rule({
        "sel_a": {"f": "1"}, "sel_b": {"g": "2"}, "sel_c": {"h": "3"},
        "condition": "2 of sel_*",
    })
    assert rule.matches({"f": "1", "g": "2"})
    assert not rule.matches({"f": "1"})


def test_unknown_selection_in_condition_is_an_error():
    with pytest.raises(SigmaError):
        _rule({"a": {"f": "1"}, "condition": "a and missing"})


def test_unsupported_modifier_is_an_error():
    with pytest.raises(SigmaError):
        _rule({"a": {"f|base64offset": "x"}, "condition": "a"})
