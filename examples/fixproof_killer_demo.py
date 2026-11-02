"""FixProof-Killer Demo Scenarios for Cordis Demo (100% Stdlib Runnable)."""
from __future__ import annotations

OLD_BUGGY_SOURCE = """
def parse_discount_tier(amount: float) -> float:
    if amount < 0:
        raise ValueError("Negative amount not allowed")
    if amount > 100.0:  # BUG: should be amount >= 100.0
        return 0.15
    return 0.0
"""

REFERENCE_CORRECT_SOURCE = """
def parse_discount_tier(amount: float) -> float:
    if amount < 0:
        raise ValueError("Negative amount not allowed")
    if amount >= 100.0:
        return 0.15
    return 0.0
"""

BAD_AGENT_PATCH_SOURCE = """
def parse_discount_tier(amount: float) -> float:
    if amount == 100.0:
        return 0.15
    return 0.0
"""

OLD_TEST_SOURCE = """
def test_discount_zero():
    assert parse_discount_tier(0.0) == 0.0
"""

BAD_AGENT_TEST_SOURCE = """
def test_discount_zero():
    assert parse_discount_tier(0.0) is not None

def test_discount_100():
    assert parse_discount_tier(100.0) == 0.15
"""

GOOD_AGENT_TEST_SOURCE = """
def test_discount_zero():
    assert parse_discount_tier(0.0) == 0.0
    assert parse_discount_tier(50.0) == 0.0

def test_discount_tier_boundary_and_above():
    assert parse_discount_tier(100.0) == 0.15
    assert parse_discount_tier(250.0) == 0.15

def test_discount_negative_raises():
    raised = False
    try:
        parse_discount_tier(-10.0)
    except ValueError:
        raised = True
    assert raised
"""


if __name__ == "__main__":
    import sys
    from pathlib import Path

    # Ensure repo root is on sys.path
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from cordis.cli import run_demo

    sys.exit(run_demo(github_comment=True))