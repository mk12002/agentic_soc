"""Asset identity resolution on a messy synthetic estate (R01): never merge two real hosts."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "eval_resolution_at_scale.py"


@pytest.mark.parametrize("seed", [3, 19])
def test_no_false_merges_and_bounded_splits(seed):
    spec = importlib.util.spec_from_file_location("eval_res", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    r = mod.evaluate(150, seed)
    assert r["false_merges"] == 0, r["false_merge_examples"]      # the dangerous error: zero tolerance
    assert r["split_rate"] <= 0.15, r
    assert r["unresolved_rate"] <= 0.10, r
