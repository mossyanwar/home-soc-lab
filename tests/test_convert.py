"""Conversion tests. Skipped cleanly if the pySigma backends are not installed."""

import glob
import os

import pytest

from soclab.convert import ConvertUnavailable, convert_file

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(os.path.dirname(HERE), "detections")

pysigma = pytest.importorskip("sigma", reason="pySigma not installed")

RULE_FILES = sorted(
    glob.glob(os.path.join(RULES, "**", "*.yml"), recursive=True)
)


@pytest.mark.parametrize("target", ["splunk", "lucene"])
@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: os.path.basename(p))
def test_rule_converts(path, target):
    try:
        queries = convert_file(path, target)
    except ConvertUnavailable:
        pytest.skip("conversion backend unavailable")
    assert queries and all(isinstance(q, str) and q for q in queries)
