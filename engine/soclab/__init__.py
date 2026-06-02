"""soclab: a small Sigma evaluator and detection pipeline for the home SOC lab."""

from .engine import Hit, in_scope, load_rules, run_rules
from .events import load_events
from .sigma import Rule, SigmaError, load_rule, load_rule_file

__version__ = "0.1.0"
__all__ = [
    "Hit", "in_scope", "load_rules", "run_rules", "load_events",
    "Rule", "SigmaError", "load_rule", "load_rule_file",
]
