"""A small Sigma rule model and evaluator.

This covers the subset of the Sigma specification the rules in ``detections/``
use, and no more:

* field modifiers ``contains``, ``startswith``, ``endswith``, ``re``, ``all``,
  and ``cased`` (case-sensitive), including combinations such as
  ``CommandLine|contains|all``;
* values with ``*`` and ``?`` wildcards, case-insensitive by default;
* a null value (``field: null``) meaning the field is absent or null;
* a numeric value, matched by equality;
* selections that are maps (keys AND'd) or lists of maps (elements OR'd);
* a value list under a key (OR'd, or AND'd with ``all``);
* condition strings with ``and`` / ``or`` / ``not``, parentheses,
  ``x of <pattern>``, ``all of <pattern>``, ``1 of them`` / ``all of them``,
  where ``<pattern>`` may end in ``*`` to match several selection names.

It is intentionally not a full implementation: there is no field-name mapping,
no value-type coercion beyond str/number, and none of the base64/utf16/windash
transforms. The rules were written to stay inside what is here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml


class SigmaError(ValueError):
    """A rule could not be parsed or is outside the supported subset."""


# --------------------------------------------------------------------------
# value matching
# --------------------------------------------------------------------------

def _wildcard_to_regex(pattern: str) -> str:
    """Translate a Sigma wildcard string into a regex, honouring backslash
    escapes of ``*``, ``?`` and ``\\``."""
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


@dataclass
class ValueMatcher:
    """Matches one Sigma value against one field value, given the modifiers on
    the field key."""

    raw: Any
    modifiers: tuple[str, ...]

    def __post_init__(self) -> None:
        self._cased = "cased" in self.modifiers
        self._kind = "equal"
        self._regex: re.Pattern[str] | None = None

        if self.raw is None:
            self._kind = "null"
            return
        if isinstance(self.raw, bool):
            self._kind = "bool"
            return
        if isinstance(self.raw, (int, float)):
            self._kind = "number"
            return

        text = str(self.raw)
        flags = 0 if self._cased else re.IGNORECASE

        if "re" in self.modifiers:
            self._kind = "regex"
            self._regex = re.compile(text, flags)
            return

        if "contains" in self.modifiers:
            body = _wildcard_to_regex(text)
            self._regex = re.compile(body, flags | re.DOTALL)
            self._kind = "search"
        elif "startswith" in self.modifiers:
            self._regex = re.compile(_wildcard_to_regex(text), flags | re.DOTALL)
            self._kind = "prefix"
        elif "endswith" in self.modifiers:
            self._regex = re.compile(_wildcard_to_regex(text) + r"\Z", flags | re.DOTALL)
            self._kind = "suffix"
        else:
            # Plain value. Wildcards make it a full-string regex match; without
            # them it is a (case-insensitive) string equality test.
            if "*" in text or "?" in text:
                self._regex = re.compile(_wildcard_to_regex(text) + r"\Z", flags | re.DOTALL)
                self._kind = "fullmatch"
            else:
                self._kind = "equal"

    def matches(self, value: Any) -> bool:
        if self._kind == "null":
            return value is None
        if value is None:
            return False
        if self._kind == "bool":
            return bool(value) == self.raw
        if self._kind == "number":
            try:
                return float(value) == float(self.raw)
            except (TypeError, ValueError):
                return str(value) == str(self.raw)

        text = value if isinstance(value, str) else str(value)
        if self._kind == "equal":
            return text == str(self.raw) if self._cased else text.lower() == str(self.raw).lower()
        if self._kind == "regex":
            return self._regex.search(text) is not None
        if self._kind == "search":
            return self._regex.search(text) is not None
        if self._kind == "prefix":
            return self._regex.match(text) is not None
        if self._kind == "suffix":
            return self._regex.search(text) is not None
        if self._kind == "fullmatch":
            return self._regex.match(text) is not None
        return False


# --------------------------------------------------------------------------
# field tests and selections
# --------------------------------------------------------------------------

@dataclass
class FieldTest:
    """One ``field|modifiers: value(s)`` entry of a selection map."""

    field: str
    modifiers: tuple[str, ...]
    matchers: list[ValueMatcher]
    match_all: bool  # True when the value list is AND'd (the ``all`` modifier)

    def matches(self, event: dict) -> bool:
        value = event.get(self.field)
        results = (m.matches(value) for m in self.matchers)
        return all(results) if self.match_all else any(results)


def _parse_field_key(key: str) -> tuple[str, tuple[str, ...]]:
    parts = key.split("|")
    return parts[0], tuple(parts[1:])


_KNOWN_MODIFIERS = {"contains", "startswith", "endswith", "re", "all", "cased"}


def _build_field_test(key: str, raw_value: Any) -> FieldTest:
    name, modifiers = _parse_field_key(key)
    unknown = set(modifiers) - _KNOWN_MODIFIERS
    if unknown:
        raise SigmaError(f"unsupported field modifier(s) {sorted(unknown)} in '{key}'")
    match_all = "all" in modifiers
    value_mods = tuple(m for m in modifiers if m != "all")
    values = raw_value if isinstance(raw_value, list) else [raw_value]
    matchers = [ValueMatcher(v, value_mods) for v in values]
    return FieldTest(name, modifiers, matchers, match_all)


@dataclass
class Selection:
    """A named search identifier: a map (AND of field tests) or a list of such
    maps (OR)."""

    name: str
    branches: list[list[FieldTest]]  # outer list OR'd, inner list AND'd
    keywords: list[ValueMatcher] | None = None

    def matches(self, event: dict) -> bool:
        if self.keywords is not None:
            haystack = [v for v in event.values() if isinstance(v, str)]
            return any(any(m.matches(h) for h in haystack) for m in self.keywords)
        return any(all(ft.matches(event) for ft in branch) for branch in self.branches)


def _build_selection(name: str, spec: Any) -> Selection:
    # A list of plain strings is a keyword search across string field values.
    if isinstance(spec, list) and spec and all(not isinstance(x, dict) for x in spec):
        return Selection(name, branches=[], keywords=[ValueMatcher(x, ()) for x in spec])
    maps = spec if isinstance(spec, list) else [spec]
    branches: list[list[FieldTest]] = []
    for m in maps:
        if not isinstance(m, dict):
            raise SigmaError(f"selection '{name}' must be a map or list of maps")
        branches.append([_build_field_test(k, v) for k, v in m.items()])
    return Selection(name, branches=branches)


# --------------------------------------------------------------------------
# condition grammar
# --------------------------------------------------------------------------
# Grammar (lowest to highest precedence):
#   expr   := or_expr
#   or_expr:= and_expr ( 'or' and_expr )*
#   and_expr:= not_expr ( 'and' not_expr )*
#   not_expr:= 'not' not_expr | atom
#   atom   := '(' expr ')' | quantifier | identifier
#   quantifier := ('1' | 'all' | <int>) 'of' ('them' | pattern)

_TOKEN = re.compile(r"\(|\)|\b(?:and|or|not|of|them|all)\b|[A-Za-z0-9_*]+")


class _CondParser:
    def __init__(self, text: str, selection_names: list[str]):
        self.tokens = _TOKEN.findall(text)
        self.pos = 0
        self.names = selection_names

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self):
        node = self._or()
        if self.pos != len(self.tokens):
            raise SigmaError(f"trailing tokens in condition: {self.tokens[self.pos:]}")
        return node

    def _or(self):
        node = self._and()
        while self._peek() == "or":
            self._next()
            node = ("or", node, self._and())
        return node

    def _and(self):
        node = self._not()
        while self._peek() == "and":
            self._next()
            node = ("and", node, self._not())
        return node

    def _not(self):
        if self._peek() == "not":
            self._next()
            return ("not", self._not())
        return self._atom()

    def _atom(self):
        tok = self._peek()
        if tok == "(":
            self._next()
            node = self._or()
            if self._next() != ")":
                raise SigmaError("missing closing parenthesis in condition")
            return node
        if tok in ("all", "1") or (tok and tok.isdigit()):
            return self._quantifier()
        if tok is None:
            raise SigmaError("unexpected end of condition")
        # a bare selection identifier
        self._next()
        return ("id", tok)

    def _quantifier(self):
        count_tok = self._next()  # 'all', '1' or an int
        if self._next() != "of":
            raise SigmaError("expected 'of' in quantifier")
        target = self._next()
        if target == "them":
            pattern = None
        else:
            pattern = target
        want_all = count_tok == "all"
        n = None if want_all else int(count_tok)
        return ("quant", want_all, n, pattern)


def _selected_names(pattern: str | None, names: list[str]) -> list[str]:
    if pattern is None:
        return list(names)
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return [n for n in names if n.startswith(prefix)]
    return [n for n in names if n == pattern]


def _validate_ast(node, names: list[str]) -> None:
    """Walk the whole condition AST and raise on any unknown selection name,
    regardless of short-circuit evaluation."""
    kind = node[0]
    if kind == "id":
        if node[1] not in names:
            raise SigmaError(f"condition refers to unknown selection '{node[1]}'")
    elif kind == "not":
        _validate_ast(node[1], names)
    elif kind in ("and", "or"):
        _validate_ast(node[1], names)
        _validate_ast(node[2], names)
    elif kind == "quant":
        _, _, _, pattern = node
        if not _selected_names(pattern, names):
            raise SigmaError(f"quantifier pattern '{pattern}' matches no selection")


def _eval_condition(node, truths: dict[str, bool], names: list[str]) -> bool:
    kind = node[0]
    if kind == "id":
        if node[1] not in truths:
            raise SigmaError(f"condition refers to unknown selection '{node[1]}'")
        return truths[node[1]]
    if kind == "not":
        return not _eval_condition(node[1], truths, names)
    if kind == "and":
        return _eval_condition(node[1], truths, names) and _eval_condition(node[2], truths, names)
    if kind == "or":
        return _eval_condition(node[1], truths, names) or _eval_condition(node[2], truths, names)
    if kind == "quant":
        _, want_all, n, pattern = node
        targets = _selected_names(pattern, names)
        hits = sum(1 for t in targets if truths.get(t, False))
        if want_all:
            return hits == len(targets) and len(targets) > 0
        return hits >= n
    raise SigmaError(f"bad condition node {node!r}")


# --------------------------------------------------------------------------
# rule
# --------------------------------------------------------------------------

@dataclass
class Rule:
    title: str
    id: str
    level: str
    logsource: dict
    selections: dict[str, Selection]
    condition_text: str
    tags: list[str] = field(default_factory=list)
    description: str = ""
    falsepositives: list[str] = field(default_factory=list)
    status: str = ""
    path: str = ""

    _ast: Any = field(default=None, repr=False)

    def matches(self, event: dict) -> bool:
        truths = {name: sel.matches(event) for name, sel in self.selections.items()}
        return _eval_condition(self._ast, truths, list(self.selections.keys()))


def load_rule(data: dict, path: str = "") -> Rule:
    try:
        detection = data["detection"]
        condition = detection["condition"]
        logsource = data.get("logsource", {})
    except KeyError as exc:
        raise SigmaError(f"rule missing required key {exc}") from exc
    if isinstance(condition, list):
        raise SigmaError("multiple conditions (condition list) are not supported")

    selections = {
        name: _build_selection(name, spec)
        for name, spec in detection.items()
        if name != "condition"
    }
    if not selections:
        raise SigmaError("rule has no selections")

    rule = Rule(
        title=data.get("title", ""),
        id=data.get("id", ""),
        level=data.get("level", ""),
        logsource=logsource,
        selections=selections,
        condition_text=condition,
        tags=list(data.get("tags", []) or []),
        description=data.get("description", ""),
        falsepositives=list(data.get("falsepositives", []) or []),
        status=data.get("status", ""),
        path=path,
    )
    rule._ast = _CondParser(condition, list(selections.keys())).parse()
    # Validate every referenced selection name now, rather than waiting for a
    # short-circuited branch to be reached during matching.
    _validate_ast(rule._ast, list(selections.keys()))
    return rule


def load_rule_file(path: str) -> Rule:
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise SigmaError(f"{path}: not a single Sigma document")
    return load_rule(data, path=path)
