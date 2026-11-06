"""Cordis Git Diff Auto-Extractor.
Zero-dependency git diff parser using `subprocess.run` and Python's `ast` module.
Extracts modified source files, test files, and exact modified function names and line ranges.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple


@dataclass
class ModifiedFunction:
    name: str
    file_path: str
    lineno: int
    end_lineno: int
    is_test: bool
    scope: str = ""  # e.g., class name if method


@dataclass
class GitDiffReport:
    base_ref: str
    target_ref: Optional[str]
    source_files: List[str] = field(default_factory=list)
    test_files: List[str] = field(default_factory=list)
    modified_functions: List[ModifiedFunction] = field(default_factory=list)
    raw_diff: str = ""
    error: Optional[str] = None

    @property
    def target_function_names(self) -> List[str]:
        """Returns non-test modified function names."""
        names = []
        for f in self.modified_functions:
            if not f.is_test and f.name not in names:
                names.append(f.name)
        return names

    @property
    def all_modified_files(self) -> List[str]:
        return self.source_files + self.test_files


def is_test_file(path_str: str) -> bool:
    """Identifies if a file is a test file based on standard Python and TypeScript/JS conventions."""
    p = Path(path_str)
    name = p.name.lower()
    if (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith(".test.ts")
        or name.endswith(".spec.ts")
        or name.endswith(".test.tsx")
        or name.endswith(".spec.tsx")
        or name.endswith(".test.js")
        or name.endswith(".spec.js")
        or name.endswith(".test.jsx")
        or name.endswith(".spec.jsx")
    ):
        return True
    parts = [part.lower() for part in p.parts]
    if any(part in ("tests", "test", "__tests__") for part in parts):
        return True
    return False


class _FunctionVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.functions: List[Tuple[str, str, int, int]] = []  # (name, scope, lineno, end_lineno)
        self.scope_stack: List[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._record_func(node)
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._record_func(node)
        self.scope_stack.append(node.name)
        self.generic_visit(node)
        self.scope_stack.pop()

    def _record_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        scope = ".".join(self.scope_stack)
        end_lineno = getattr(node, "end_lineno", node.lineno)
        self.functions.append((node.name, scope, node.lineno, end_lineno))


def find_functions_in_source(source_code: str) -> List[Tuple[str, str, int, int]]:
    """Returns a list of (function_name, scope, start_lineno, end_lineno) found in source_code."""
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return []
    visitor = _FunctionVisitor()
    visitor.visit(tree)
    return visitor.functions


# Regex to parse unified diff hunk header: @@ -old_start[,old_count] +new_start[,new_count] @@
HUNK_HEADER_RE = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")


def parse_unified_diff_hunks(diff_text: str) -> Dict[str, Set[int]]:
    """Parses a unified diff and returns a dict mapping modified file path (b-side)
    to a set of 1-based modified line numbers in that file.
    """
    files_changed_lines: Dict[str, Set[int]] = {}
    current_file: Optional[str] = None
    current_line = 0

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            # e.g., diff --git a/cordis/calc.py b/cordis/calc.py
            parts = line.split()
            if len(parts) >= 4:
                b_path = parts[3]
                if b_path.startswith("b/"):
                    b_path = b_path[2:]
                current_file = b_path
                if current_file not in files_changed_lines:
                    files_changed_lines[current_file] = set()
            continue

        if line.startswith("+++ "):
            # e.g. +++ b/path/to/file or +++ /dev/null
            raw_path = line[4:].strip()
            if raw_path.startswith("b/"):
                raw_path = raw_path[2:]
            if raw_path != "/dev/null":
                current_file = raw_path
                if current_file not in files_changed_lines:
                    files_changed_lines[current_file] = set()
            else:
                current_file = None
            continue

        if not current_file:
            continue

        hunk_match = HUNK_HEADER_RE.match(line)
        if hunk_match:
            new_start = int(hunk_match.group(3))
            current_line = new_start
            # If hunk has 0 new lines (deletion at this point), mark new_start
            new_count_str = hunk_match.group(4)
            if new_count_str is not None and int(new_count_str) == 0:
                files_changed_lines[current_file].add(max(1, new_start))
            continue

        if line.startswith("+") and not line.startswith("+++"):
            files_changed_lines[current_file].add(current_line)
            current_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            # Deletion in hunk: mark the current location in the new file
            files_changed_lines[current_file].add(max(1, current_line))
        elif line.startswith(" "):
            # Context line in new file
            current_line += 1

    return files_changed_lines


def parse_git_diff_text(
    diff_text: str,
    base_ref: str = "HEAD~1",
    target_ref: Optional[str] = None,
    file_reader: Optional[Callable[[str], Optional[str]]] = None,
) -> GitDiffReport:
    """Parses a unified diff text, mapping modified lines to exact AST functions.
    `file_reader` receives the file path and returns its source code text (or None if missing).
    """
    report = GitDiffReport(base_ref=base_ref, target_ref=target_ref, raw_diff=diff_text)
    file_lines = parse_unified_diff_hunks(diff_text)

    TS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx")
    SUPPORTED_EXTENSIONS = (".py",) + TS_EXTENSIONS

    for file_path, lines in file_lines.items():
        if not any(file_path.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
            continue

        if is_test_file(file_path):
            if file_path not in report.test_files:
                report.test_files.append(file_path)
        else:
            if file_path not in report.source_files:
                report.source_files.append(file_path)

        content: Optional[str] = None
        if file_reader:
            content = file_reader(file_path)
        else:
            p = Path(file_path)
            if p.is_file():
                try:
                    content = p.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    content = None

        if not content:
            continue

        if file_path.endswith(".py"):
            funcs = find_functions_in_source(content)
        else:
            from cordis.ts_gate import index_ts_ast_anchors
            ts_anchors = index_ts_ast_anchors(content, file_path=file_path)
            funcs = [
                (a.identifier, a.scope_path, a.lineno, a.end_lineno)
                for a in ts_anchors.values()
            ]

        file_is_test = is_test_file(file_path)
        for name, scope, start_line, end_line in funcs:
            func_line_range = set(range(start_line, end_line + 1))
            if func_line_range.intersection(lines):
                report.modified_functions.append(
                    ModifiedFunction(
                        name=name,
                        file_path=file_path,
                        lineno=start_line,
                        end_lineno=end_line,
                        is_test=file_is_test or name.startswith("test_") or name.startswith("it_") or name.startswith("test"),
                        scope=scope,
                    )
                )

    return report


def get_git_file_content(ref: str, file_path: str, repo_dir: str | Path = ".") -> Optional[str]:
    """Retrieves file contents from a specific git revision using `git show <ref>:<path>`."""
    # Convert path to forward slashes for git
    clean_path = str(file_path).replace("\\", "/")
    cmd = ["git", "show", f"{ref}:{clean_path}"]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_dir),
            capture_output=True,
            timeout=10,
        )
        if proc.returncode == 0:
            return proc.stdout.decode("utf-8-sig", errors="replace")
        return None
    except Exception:
        return None


def extract_git_diff(
    repo_dir: str | Path = ".",
    base_ref: str = "HEAD~1",
    target_ref: Optional[str] = None,
) -> GitDiffReport:
    """Runs `git diff` via subprocess and parses modified files and functions.
    Default: diff between `base_ref` and working tree (or `target_ref` if given).
    If `base_ref` is 'HEAD~1' and repo has only 1 commit, falls back to 'HEAD'.
    """
    actual_base = base_ref
    if base_ref == "HEAD~1":
        # Check if HEAD~1 exists
        check = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD~1"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
        )
        if check.returncode != 0:
            actual_base = "HEAD"

    cmd = ["git", "diff", actual_base]
    if target_ref:
        cmd.append(target_ref)

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
        if proc.returncode != 0:
            return GitDiffReport(
                base_ref=actual_base,
                target_ref=target_ref,
                error=f"git diff failed (code {proc.returncode}): {proc.stderr.strip()}",
            )
        diff_text = proc.stdout
    except FileNotFoundError:
        return GitDiffReport(base_ref=actual_base, target_ref=target_ref, error="git executable not found on PATH")
    except Exception as exc:
        return GitDiffReport(base_ref=actual_base, target_ref=target_ref, error=f"Failed to execute git diff: {exc}")

    def reader(path_str: str) -> Optional[str]:
        if target_ref:
            return get_git_file_content(target_ref, path_str, repo_dir=repo_dir)
        p = Path(repo_dir) / path_str
        if p.is_file():
            try:
                return p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return None
        return None

    report = parse_git_diff_text(
        diff_text,
        base_ref=actual_base,
        target_ref=target_ref,
        file_reader=reader,
    )
    return report
