"""Gate 1: 64-Bit BLAKE2b AST Node Hasher & Test-Tampering / Anti-Mock Auditor."""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class ASTAnchor:
    file_path: str
    scope_path: str
    node_type: str
    identifier: str
    signature: str
    lineno: int
    end_lineno: int
    hash_tag: str

    @property
    def tag(self) -> str:
        return f"¶{self.file_path}#{self.hash_tag}"


@dataclass
class TestTamperingReport:
    passed: bool
    old_assert_count: int
    new_assert_count: int
    violations: List[str] = field(default_factory=list)
    anchors: Dict[str, ASTAnchor] = field(default_factory=dict)


def compute_node_hash(
    file_path: str,
    scope_path: str,
    node_type: str,
    identifier: str,
    signature: str,
    normalized_body_dump: str,
) -> str:
    """Computes a 16-hex (64-bit) BLAKE2b hash including identifier & signature.
    Fixes the v1 16-bit collision bug where structurally identical getters collided.
    """
    payload = "|".join([
        file_path.replace("\\", "/"),
        scope_path,
        node_type,
        identifier,
        signature,
        normalized_body_dump,
    ])
    digest = hashlib.blake2b(payload.encode("utf-8"), digest_size=8).hexdigest()
    return digest  # 16 hex chars = 64 bits


def index_ast_anchors(source_code: str, file_path: str = "module.py") -> Dict[str, ASTAnchor]:
    """Indexes all functions and classes in a module with 64-bit AST anchors."""
    tree = ast.parse(source_code.lstrip("\ufeff"))
    anchors: Dict[str, ASTAnchor] = {}

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.scope_stack: List[str] = []

        def _visit_callable(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            scope_str = ".".join(self.scope_stack) if self.scope_stack else "<module>"
            args_sig = ",".join(a.arg for a in node.args.args)
            body_dump = ast.dump(ast.Module(body=node.body, type_ignores=[]), include_attributes=False)
            h = compute_node_hash(
                file_path=file_path,
                scope_path=scope_str,
                node_type=type(node).__name__,
                identifier=node.name,
                signature=f"({args_sig})",
                normalized_body_dump=body_dump,
            )
            qualname = f"{scope_str}.{node.name}" if self.scope_stack else node.name
            anchors[qualname] = ASTAnchor(
                file_path=file_path,
                scope_path=scope_str,
                node_type=type(node).__name__,
                identifier=node.name,
                signature=f"({args_sig})",
                lineno=getattr(node, "lineno", 1),
                end_lineno=getattr(node, "end_lineno", getattr(node, "lineno", 1)),
                hash_tag=h,
            )
            self.scope_stack.append(node.name)
            self.generic_visit(node)
            self.scope_stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_callable(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_callable(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.scope_stack.append(node.name)
            self.generic_visit(node)
            self.scope_stack.pop()

    Visitor().visit(tree)
    return anchors


def _is_unittest_assert_call(node: ast.AST) -> bool:
    if isinstance(node, ast.Call):
        func = getattr(node, "func", None)
        name = getattr(func, "attr", None) or getattr(func, "id", None)
        if isinstance(name, str) and name.startswith("assert"):
            return True
    return False


def _is_tautological_assert(node: ast.AST) -> Optional[str]:
    """Detects hollow assertions like `assert True` or `assert x == x` or `self.assertTrue(True)`."""
    if isinstance(node, ast.Assert):
        test = node.test
        if isinstance(test, ast.Constant) and bool(test.value) is True:
            return f"Line {node.lineno}: Tautological assertion `assert {repr(test.value)}`"
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and len(test.comparators) == 1:
            left_dump = ast.dump(test.left)
            right_dump = ast.dump(test.comparators[0])
            if isinstance(test.ops[0], (ast.Eq, ast.Is)) and left_dump == right_dump:
                return f"Line {node.lineno}: Self-comparison tautology in `assert`"
    elif isinstance(node, ast.Call):
        func = getattr(node, "func", None)
        attr = getattr(func, "attr", "") or getattr(func, "id", "")
        if attr == "assertTrue" and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and bool(first_arg.value) is True:
                return f"Line {node.lineno}: Tautological assertion `self.assertTrue(True)`"
        elif attr == "assertEqual" and len(node.args) >= 2:
            if ast.dump(node.args[0]) == ast.dump(node.args[1]):
                return f"Line {node.lineno}: Self-comparison tautology in `self.assertEqual`"
    return None


def _is_weak_not_none_assert(node: ast.AST) -> bool:
    """Checks if an assertion only checks `assert x is not None` without value verification."""
    if isinstance(node, ast.Assert):
        test = node.test
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            if isinstance(test.ops[0], (ast.IsNot, ast.NotEq)):
                comp = test.comparators[0]
                if isinstance(comp, ast.Constant) and comp.value is None:
                    return True
    elif isinstance(node, ast.Call):
        func = getattr(node, "func", None)
        attr = getattr(func, "attr", "") or getattr(func, "id", "")
        if attr == "assertIsNotNone":
            return True
    return False


def audit_test_tampering(
    old_test_code: str,
    new_test_code: str,
    target_function_names: Optional[List[str]] = None,
    file_path: str = "test_module.py",
) -> TestTamperingReport:
    """Audits old vs. new test AST to catch 'VICTORY CONFIRMED' test tampering:
    1. Deleted or reduced `assert` count.
    2. Replacing value equality assertions (`assert f(x) == y`) with hollow `assert f(x) is not None`.
    3. Adding `@pytest.mark.skip`, `@pytest.mark.xfail`, or `@unittest.skip`.
    4. Mocking out the target function under test (`mock.patch('...target_func')`).
    5. Tautological assertions (`assert True`).
    """
    target_set = set(target_function_names or [])
    clean_old = old_test_code.lstrip("\ufeff")
    clean_new = new_test_code.lstrip("\ufeff")
    old_tree = ast.parse(clean_old) if clean_old.strip() else ast.parse("")
    new_tree = ast.parse(clean_new)

    old_asserts = [n for n in ast.walk(old_tree) if isinstance(n, ast.Assert) or _is_unittest_assert_call(n)]
    new_asserts = [n for n in ast.walk(new_tree) if isinstance(n, ast.Assert) or _is_unittest_assert_call(n)]

    old_strong_asserts = [a for a in old_asserts if not _is_weak_not_none_assert(a)]
    new_strong_asserts = [a for a in new_asserts if not _is_weak_not_none_assert(a)]

    violations: List[str] = []

    if len(new_asserts) < len(old_asserts):
        violations.append(
            f"Assertion count decreased from {len(old_asserts)} to {len(new_asserts)} (deleted assertions)."
        )

    if len(old_strong_asserts) > len(new_strong_asserts):
        violations.append(
            f"Strong value assertions weakened to hollow `is not None` checks "
            f"(strong asserts dropped from {len(old_strong_asserts)} to {len(new_strong_asserts)})."
        )

    # Per-function assertion weakening check (catches weakening an existing test while adding a new one)
    old_funcs = {
        n.name: n for n in ast.walk(old_tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    new_funcs = {
        n.name: n for n in ast.walk(new_tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for fn_name, old_fn in old_funcs.items():
        if fn_name not in new_funcs:
            violations.append(f"Existing test function `{fn_name}` was deleted.")
            continue
        new_fn = new_funcs[fn_name]
        old_fn_strong = [
            a for a in ast.walk(old_fn) if (isinstance(a, ast.Assert) or _is_unittest_assert_call(a)) and not _is_weak_not_none_assert(a)
        ]
        new_fn_strong = [
            a for a in ast.walk(new_fn) if (isinstance(a, ast.Assert) or _is_unittest_assert_call(a)) and not _is_weak_not_none_assert(a)
        ]
        if len(old_fn_strong) > len(new_fn_strong):
            violations.append(
                f"Line {new_fn.lineno}: Test `{fn_name}` weakened strong value assertion to hollow `is not None` check."
            )

    # Check for newly added hollow test functions (only weak asserts)
    for fn_name, new_fn in new_funcs.items():
        if fn_name not in old_funcs and fn_name.startswith("test_"):
            new_fn_asserts = [
                a for a in ast.walk(new_fn) if (isinstance(a, ast.Assert) or _is_unittest_assert_call(a))
            ]
            new_fn_strong = [a for a in new_fn_asserts if not _is_weak_not_none_assert(a)]
            new_fn_weak = [a for a in new_fn_asserts if _is_weak_not_none_assert(a)]
            if len(new_fn_asserts) > 0 and len(new_fn_strong) == 0 and len(new_fn_weak) > 0:
                violations.append(
                    f"Line {new_fn.lineno}: New test `{fn_name}` is hollow (asserts only weak `is not None` with zero strong value checks)."
                )

    if len(new_asserts) == 0:
        violations.append("Test file contains zero `assert` statements.")

    # Record pre-existing tautologies, skip decorators, and mock calls in old_tree to avoid false positives
    old_taut_dumps: set[str] = set()
    old_skip_decorations: set[tuple[str, str]] = set()
    old_skip_calls: set[str] = set()
    old_target_mocks: set[tuple[str, str]] = set()

    if clean_old.strip():
        for node in old_asserts:
            if _is_tautological_assert(node):
                old_taut_dumps.add(ast.dump(node, include_attributes=False))
        for node in ast.walk(old_tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    old_skip_decorations.add((node.name, ast.unparse(dec)))
            elif isinstance(node, ast.Call):
                func_str = ast.unparse(node.func)
                old_skip_calls.add(func_str)
                for target_fn in target_set:
                    if target_fn in ast.unparse(node):
                        old_target_mocks.add((target_fn, func_str))

    for node in new_asserts:
        taut = _is_tautological_assert(node)
        if taut:
            dumped = ast.dump(node, include_attributes=False)
            if dumped not in old_taut_dumps:
                violations.append(taut)

    # Check for newly added skip/xfail decorators or calls
    skip_markers = {"skip", "skipIf", "skipUnless", "xfail"}
    for node in ast.walk(new_tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                dec_str = ast.unparse(dec)
                if any(m in dec_str for m in skip_markers):
                    if (node.name, dec_str) not in old_skip_decorations:
                        violations.append(
                            f"Line {node.lineno}: Test `{node.name}` decorated with skip/xfail (`@{dec_str}`)."
                        )
        if isinstance(node, ast.Call):
            func_str = ast.unparse(node.func)
            if func_str in {"pytest.skip", "pytest.xfail", "unittest.skip"}:
                if func_str not in old_skip_calls:
                    violations.append(f"Line {node.lineno}: Explicit `{func_str}()` call inside test body.")
            if any(m in func_str for m in ("patch", "MagicMock", "monkeypatch.setattr")):
                call_dump = ast.unparse(node)
                for target_fn in target_set:
                    if target_fn in call_dump and (target_fn, func_str) not in old_target_mocks:
                        violations.append(
                            f"Line {node.lineno}: Test mocks out target function `{target_fn}` via `{func_str}`."
                        )

    anchors = index_ast_anchors(new_test_code, file_path=file_path)
    return TestTamperingReport(
        passed=(len(violations) == 0),
        old_assert_count=len(old_asserts),
        new_assert_count=len(new_asserts),
        violations=violations,
        anchors=anchors,
    )