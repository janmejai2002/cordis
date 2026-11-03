"""FixProof-Killer Demo Scenarios for Cordis Demo (100% Stdlib Runnable)."""
from __future__ import annotations

from cordis.demo_fixtures import (
    BAD_AGENT_PATCH_SOURCE,
    BAD_AGENT_TEST_SOURCE,
    GOOD_AGENT_TEST_SOURCE,
    OLD_BUGGY_SOURCE,
    OLD_TEST_SOURCE,
    REFERENCE_CORRECT_SOURCE,
)


if __name__ == "__main__":
    import sys
    from pathlib import Path

    # Ensure repo root is on sys.path
    repo_root = Path(__file__).resolve().parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    from cordis.cli import run_demo

    sys.exit(run_demo(github_comment=True))