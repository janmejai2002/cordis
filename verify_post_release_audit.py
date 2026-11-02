#!/usr/bin/env python3
r"""Independent Post-Release Verification Audit for Cordis.
Asserts and prints proof of all 5 invariants:
1. Markdown Table Integrity: 0 instances of r"^\|.*\|\n\n\|"
2. Backtick Integrity: 0 instances of `Replace return expression with ` or `Flip ` or `Boundary shift `
3. Line Ending Cleanliness: 0 \r\n bytes in README.md and REAL_GITHUB_BENCHMARK.md (pure UTF-8 with \n)
4. Upstream Patches Verification: All 5 .patch files in upstream_prs/patches/ exist, are non-empty, and contain diff --git headers
5. Unit Test Suite: 32/32 tests pass
"""
from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys

# Ensure UTF-8 output on Windows PowerShell
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

def main() -> int:
    repo_root = pathlib.Path(__file__).resolve().parent
    print("=" * 80)
    print("🛡️ CORDIS: INDEPENDENT POST-RELEASE VERIFICATION AUDIT")
    print(f"📁 Repository Root: {repo_root}")
    print("=" * 80)

    # List of primary documentation files
    doc_files = [
        repo_root / "README.md",
        repo_root / "REAL_GITHUB_BENCHMARK.md",
        repo_root / "TECHNICAL_REPORT.md",
        *sorted((repo_root / "upstream_prs").glob("*.md")),
    ]

    all_md_files = [
        p for p in repo_root.rglob("*.md")
        if ".real_repos_cache" not in p.parts and "YC_SUBMISSION_KIT" not in p.name
    ]

    # Invariant 1: Markdown Table Integrity
    print("\n[Invariant 1] Checking Markdown Table Integrity (0 instances of r'^\\|.*\\|\\n\\n\\|')...")
    broken_table_pattern = re.compile(r"^\|.*\|\n\n\|", re.MULTILINE)
    inv1_passed = True
    for p in doc_files:
        content = p.read_text(encoding="utf-8", errors="replace")
        matches = broken_table_pattern.findall(content)
        rel_path = p.relative_to(repo_root)
        if matches:
            print(f"  ❌ {rel_path}: {len(matches)} broken table instances found!")
            inv1_passed = False
        else:
            print(f"  ✅ {rel_path}: 0 broken table instances")
    assert inv1_passed, "Invariant 1 Failed: Broken Markdown tables found!"
    print("  🏆 Invariant 1 Verified: ZERO broken table rows across all audit documents.")

    # Invariant 2: Backtick Integrity
    print("\n[Invariant 2] Checking Backtick Integrity (0 instances of nested outer backticks)...")
    nested_patterns = [
        re.compile(r"`Replace return expression with `"),
        re.compile(r"`Flip `"),
        re.compile(r"`Boundary shift `"),
    ]
    inv2_passed = True
    for p in all_md_files:
        content = p.read_text(encoding="utf-8", errors="replace")
        rel_path = p.relative_to(repo_root)
        file_violations = 0
        for pat in nested_patterns:
            matches = pat.findall(content)
            file_violations += len(matches)
        if file_violations > 0:
            print(f"  ❌ {rel_path}: {file_violations} nested backtick instances found!")
            inv2_passed = False
        else:
            print(f"  ✅ {rel_path}: 0 nested backtick instances")
    assert inv2_passed, "Invariant 2 Failed: Nested backticks found!"
    print("  🏆 Invariant 2 Verified: ZERO nested backtick corruptions across all markdown files.")

    # Invariant 3: Line Ending Cleanliness
    print("\n[Invariant 3] Checking Line Ending Cleanliness (0 \\r\\n bytes in README.md & REAL_GITHUB_BENCHMARK.md)...")
    inv3_files = [repo_root / "README.md", repo_root / "REAL_GITHUB_BENCHMARK.md"]
    inv3_passed = True
    for p in inv3_files:
        raw_bytes = p.read_bytes()
        crlf_count = raw_bytes.count(b"\r\n")
        rel_path = p.relative_to(repo_root)
        if crlf_count > 0:
            print(f"  ❌ {rel_path}: Contains {crlf_count} CRLF bytes!")
            inv3_passed = False
        else:
            print(f"  ✅ {rel_path}: Pure UTF-8 with \\n line endings (0 CRLF bytes, {len(raw_bytes):,} bytes)")
    assert inv3_passed, "Invariant 3 Failed: CRLF bytes found in target files!"
    print("  🏆 Invariant 3 Verified: Clean UNIX \\n line endings in README.md and REAL_GITHUB_BENCHMARK.md.")

    # Invariant 4: Upstream Patches Verification
    print("\n[Invariant 4] Verifying 5 Upstream .patch Files in upstream_prs/patches/...")
    patches_dir = repo_root / "upstream_prs" / "patches"
    expected_patches = [
        "01_boltons.patch",
        "02_python_dotenv.patch",
        "03_click.patch",
        "04_fastmcp.patch",
        "05_smolagents.patch",
    ]
    assert patches_dir.is_dir(), f"Patches directory not found: {patches_dir}"
    inv4_passed = True
    for name in expected_patches:
        patch_file = patches_dir / name
        if not patch_file.is_file():
            print(f"  ❌ Missing patch file: {name}")
            inv4_passed = False
            continue
        patch_text = patch_file.read_text(encoding="utf-8", errors="replace")
        if len(patch_text.strip()) == 0:
            print(f"  ❌ Patch file is empty: {name}")
            inv4_passed = False
            continue
        if "diff --git" not in patch_text:
            print(f"  ❌ Patch file missing valid 'diff --git' header: {name}")
            inv4_passed = False
            continue
        print(f"  ✅ {name}: Valid unified diff ({len(patch_text):,} bytes, contains 'diff --git')")
    assert inv4_passed, "Invariant 4 Failed: Invalid or missing upstream patch files!"
    print("  🏆 Invariant 4 Verified: All 5 upstream patches exist, are non-empty, and valid.")

    # Invariant 5: Unit Test Suite
    print("\n[Invariant 5] Running Full Unit Test Suite (python -m unittest discover -s tests -v)...")
    res = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    test_output = res.stdout + res.stderr
    print(test_output)
    
    assert res.returncode == 0, f"Invariant 5 Failed: Unit tests returned exit code {res.returncode}"
    assert "Ran 32 tests" in test_output, f"Invariant 5 Failed: Expected 32 tests, output was: {test_output}"
    assert "OK" in test_output, "Invariant 5 Failed: Unit test suite did not report OK"
    print("  🏆 Invariant 5 Verified: 32/32 unit tests passed successfully!")

    print("\n" + "=" * 80)
    print("🎉 ALL 5 INVARIANTS VERIFIED: ZERO CORRUPTION DETECTED")
    print("=" * 80)
    return 0

if __name__ == "__main__":
    sys.exit(main())
