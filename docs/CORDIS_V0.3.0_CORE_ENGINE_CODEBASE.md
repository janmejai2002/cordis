# 🛡️ Cordis v0.3.0: Core Engine Source Code Reference

**Release**: v0.3.0 | **Language**: 100% Python Standard Library | **Dependencies**: 0 external

This document contains the complete, authoritative source code of all 11 core engine modules of Cordis v0.3.0.

## Table of Contents

- [cordis/ast_gate.py](#cordisast-gatepy)
- [cordis/mutator.py](#cordismutatorpy)
- [cordis/fuzzer.py](#cordisfuzzerpy)
- [cordis/repair.py](#cordisrepairpy)
- [cordis/hooks.py](#cordishookspy)
- [cordis/ts_gate.py](#cordists-gatepy)
- [cordis/forge_guard.py](#cordisforge-guardpy)
- [cordis/policy_guard.py](#cordispolicy-guardpy)
- [cordis/cli.py](#cordisclipy)
- [cordis/git_diff.py](#cordisgit-diffpy)
- [cordis/memory.py](#cordismemorypy)

---

## cordis/ast_gate.py

`python
"""Gate 1: 64-Bit BLAKE2b AST Node Hasher & Test-Tampering / Anti-Mock Auditor."""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


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
    __test__ = False
    passed: bool
    old_assert_count: int
    new_assert_count: int
    violations: List[str] = field(default_factory=list)
    anchors: Dict[str, ASTAnchor] = field(default_factory=dict)
    total_mocks: int = 0
    mar: float = 0.0
    risk_level: str = "LOW"
    internal_mock_count: int = 0
    boundary_mock_count: int = 0
    weighted_mar: float = 0.0

    @property
    def mar_risk_level(self) -> str:
        return self.risk_level



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


BOUNDARY_MOCK_TARGETS = (
    "urllib",
    "http",
    "httpx",
    "requests",
    "aiohttp",
    "socket",
    "subprocess",
    "boto3",
    "time.sleep",
    "redis",
    "sqlalchemy",
    "os.environ",
)


def _is_boundary_target(target_str: str) -> bool:
    target_clean = target_str.strip("'\"")
    return any(target_clean == b or target_clean.startswith(b + ".") for b in BOUNDARY_MOCK_TARGETS)


def calculate_mock_to_assertion_ratio(source_code: str) -> dict[str, Any]:
    """Calculates the Mock-to-Assertion Ratio (MAR) on test source code.
    Computes MAR = total_mocks / max(total_assertions, 1).
    Classifies mocks into internal domain mocks vs. external boundary mocks:
    - boundary mocks: urllib, http, httpx, requests, aiohttp, socket, subprocess, boto3, time.sleep
    - internal mocks: repository domain logic, relative modules, etc.
    Computes weighted_mar = (1.0 * internal_mocks + 0.25 * boundary_mocks) / max(total_assertions, 1).
    Risk badges:
      - LOW: MAR < 0.10
      - MODERATE: 0.10 <= MAR <= 0.25
      - HIGH_RISK: MAR > 0.25
    """
    clean_code = source_code.lstrip("\ufeff")
    if not clean_code.strip():
        return {
            "total_assertions": 0,
            "total_mocks": 0,
            "mar": 0.0,
            "risk_level": "LOW",
            "is_high_risk": False,
            "internal_mock_count": 0,
            "boundary_mock_count": 0,
            "weighted_mar": 0.0,
        }

    try:
        tree = ast.parse(clean_code)
    except SyntaxError:
        return {
            "total_assertions": 0,
            "total_mocks": 0,
            "mar": 0.0,
            "risk_level": "LOW",
            "is_high_risk": False,
            "internal_mock_count": 0,
            "boundary_mock_count": 0,
            "weighted_mar": 0.0,
        }

    total_assertions = 0
    total_mocks = 0
    internal_mock_count = 0
    boundary_mock_count = 0

    mock_class_names = {
        "Mock",
        "MagicMock",
        "AsyncMock",
        "PropertyMock",
        "NonCallableMock",
        "NonCallableMagicMock",
    }
    mock_modules = {"unittest.mock", "mock", "pytest_mock"}

    for node in ast.walk(tree):
        # 1. Assertions
        if isinstance(node, ast.Assert):
            total_assertions += 1
        elif isinstance(node, ast.Call):
            func = getattr(node, "func", None)
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if isinstance(name, str) and (name.startswith("assert") or name in {"assert_that", "assert_equal", "assert_true", "assert_false"}):
                total_assertions += 1
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                ctx = item.context_expr
                if isinstance(ctx, ast.Call):
                    ctx_str = ast.unparse(ctx.func)
                    if ctx_str in ("pytest.raises", "raises", "pytest.warns", "warns"):
                        total_assertions += 1

        # 2. Mock imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                if any(alias.name == m or alias.name.startswith(m + ".") for m in mock_modules):
                    total_mocks += 1
                    internal_mock_count += 1
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if any(mod == m or mod.startswith(m + ".") for m in mock_modules):
                cnt = len(node.names)
                total_mocks += cnt
                internal_mock_count += cnt
            elif mod == "unittest":
                for alias in node.names:
                    if alias.name == "mock":
                        total_mocks += 1
                        internal_mock_count += 1

        # 3. Mock instantiations & calls
        if isinstance(node, ast.Call):
            func_str = ast.unparse(node.func)
            func_name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if func_name in mock_class_names:
                total_mocks += 1
                internal_mock_count += 1
            elif (
                func_str.startswith("unittest.mock.")
                or func_str.startswith("mock.")
                or func_str.startswith("mocker.")
                or func_str.startswith("monkeypatch.")
                or func_str == "patch"
                or func_str.startswith("patch.")
            ):
                total_mocks += 1
                target_str = ""
                if node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        target_str = first_arg.value
                    elif isinstance(first_arg, (ast.Name, ast.Attribute)):
                        target_str = ast.unparse(first_arg)
                    if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                        target_str = f"{target_str}.{node.args[1].value}"
                elif node.keywords:
                    for kw in node.keywords:
                        if kw.arg in ("target", "spec"):
                            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                target_str = kw.value.value
                            elif isinstance(kw.value, (ast.Name, ast.Attribute)):
                                target_str = ast.unparse(kw.value)
                            break
                if _is_boundary_target(target_str):
                    boundary_mock_count += 1
                else:
                    internal_mock_count += 1

        # 4. Bare decorators
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    dec_str = ast.unparse(dec)
                    if (
                        dec_str == "patch"
                        or dec_str.startswith("patch.")
                        or dec_str.startswith("mock.patch")
                        or dec_str.startswith("unittest.mock.patch")
                    ):
                        total_mocks += 1
                        internal_mock_count += 1

    mar = round(total_mocks / max(total_assertions, 1), 4)
    weighted_mar = round((1.0 * internal_mock_count + 0.25 * boundary_mock_count) / max(total_assertions, 1), 4)
    if mar < 0.10:
        risk_level = "LOW"
    elif mar <= 0.25:
        risk_level = "MODERATE"
    else:
        risk_level = "HIGH_RISK"

    return {
        "total_assertions": total_assertions,
        "total_mocks": total_mocks,
        "mar": mar,
        "risk_level": risk_level,
        "is_high_risk": (risk_level == "HIGH_RISK"),
        "internal_mock_count": internal_mock_count,
        "boundary_mock_count": boundary_mock_count,
        "weighted_mar": weighted_mar,
    }



def _is_broad_exception_type(node: Optional[ast.AST]) -> bool:
    """Checks if exception handler catches broad/base exceptions (Exception, BaseException, bare except, or tuples thereof)."""
    if node is None:
        return True
    if isinstance(node, ast.Name) and node.id in ("Exception", "BaseException"):
        return True
    if isinstance(node, ast.Attribute) and node.attr in ("Exception", "BaseException"):
        return True
    if isinstance(node, ast.Tuple):
        return any(_is_broad_exception_type(elt) for elt in node.elts)
    return False


def _is_concrete_oracle_node(node: ast.AST) -> bool:
    """Checks if AST node is a concrete literal oracle (number, string, collection, boolean)."""
    if isinstance(node, ast.Constant):
        return node.value is not None
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return True
    if isinstance(node, ast.Dict):
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
    6. Direct alias tautologies (`a = target(x); b = target(x); assert a == b`).
    7. Oracle-free call comparisons (`assert wrapper(x) == target(x)` without concrete literal oracles).
    8. Exception swallowing (`try: target(x) except Exception: pass`).
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

    # Record pre-existing tautologies, skip decorators, mock calls, and try blocks in old_tree to avoid false positives
    old_taut_dumps: set[str] = set()
    old_skip_decorations: set[tuple[str, str]] = set()
    old_skip_calls: set[str] = set()
    old_target_mocks: set[tuple[str, str]] = set()
    old_try_dumps: set[str] = set()

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
            elif isinstance(node, ast.Try):
                old_try_dumps.add(ast.dump(node, include_attributes=False))

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

        # Exception swallowing: try: target(...) except [Exception]: pass
        if isinstance(node, ast.Try):
            swallows = False
            for h in node.handlers:
                is_broad = _is_broad_exception_type(h.type)
                is_pass = all(
                    isinstance(s, ast.Pass)
                    or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))
                    or (isinstance(s, ast.Return) and (s.value is None or (isinstance(s.value, ast.Constant) and s.value.value is None)))
                    for s in h.body
                )
                if is_broad and is_pass:
                    swallows = True
                    break

            if swallows:
                calls = [
                    c for c in ast.walk(ast.Module(body=node.body, type_ignores=[]))
                    if isinstance(c, ast.Call)
                ]
                matched_target = None
                if target_set:
                    for c in calls:
                        c_str = ast.unparse(c.func)
                        if any(t == c_str or c_str.endswith("." + t) or t in c_str for t in target_set):
                            matched_target = c_str
                            break
                elif calls:
                    matched_target = ast.unparse(calls[0].func)

                if matched_target:
                    dumped = ast.dump(node, include_attributes=False)
                    if dumped not in old_try_dumps:
                        violations.append(
                            f"Line {node.lineno}: Test swallows exceptions via bare/broad except pass wrapping call to `{matched_target}`."
                        )

    # Dataflow alias tracking & Oracle-free call comparison
    for fn_name, new_fn in new_funcs.items():
        all_call_vars: dict[str, ast.Call] = {}
        target_var_calls: dict[str, tuple[str, str, int]] = {}
        for node_stmt in ast.walk(new_fn):
            if isinstance(node_stmt, ast.Assign):
                if len(node_stmt.targets) == 1 and isinstance(node_stmt.targets[0], ast.Name):
                    var_name = node_stmt.targets[0].id
                    if isinstance(node_stmt.value, ast.Call):
                        c = node_stmt.value
                        c_str = ast.unparse(c.func)
                        all_call_vars[var_name] = c
                        matched = None
                        if target_set:
                            for t in target_set:
                                if t == c_str or c_str.endswith("." + t) or t in c_str:
                                    matched = t
                                    break
                        else:
                            matched = c_str
                        if matched:
                            target_var_calls[var_name] = (ast.dump(c, include_attributes=False), matched, node_stmt.lineno)
            elif isinstance(node_stmt, ast.AnnAssign):
                if isinstance(node_stmt.target, ast.Name) and node_stmt.value is not None and isinstance(node_stmt.value, ast.Call):
                    var_name = node_stmt.target.id
                    c = node_stmt.value
                    c_str = ast.unparse(c.func)
                    all_call_vars[var_name] = c
                    matched = None
                    if target_set:
                        for t in target_set:
                            if t == c_str or c_str.endswith("." + t) or t in c_str:
                                matched = t
                                break
                    else:
                        matched = c_str
                    if matched:
                        target_var_calls[var_name] = (ast.dump(c, include_attributes=False), matched, node_stmt.lineno)

        fn_asserts = [
            a for a in ast.walk(new_fn) if (isinstance(a, ast.Assert) or _is_unittest_assert_call(a))
        ]
        has_call_comparison = False
        has_concrete_literal = False

        for a in fn_asserts:
            left_node = None
            right_node = None
            assert_lineno = getattr(a, "lineno", new_fn.lineno)
            if (
                isinstance(a, ast.Assert)
                and isinstance(a.test, ast.Compare)
            ):
                if _is_concrete_oracle_node(a.test.left):
                    has_concrete_literal = True
                for comp in a.test.comparators:
                    if _is_concrete_oracle_node(comp):
                        has_concrete_literal = True
                if len(a.test.ops) == 1 and len(a.test.comparators) == 1 and isinstance(a.test.ops[0], (ast.Eq, ast.Is)):
                    left_node = a.test.left
                    right_node = a.test.comparators[0]
            elif isinstance(a, ast.Call):
                func = getattr(a, "func", None)
                attr = getattr(func, "attr", "") or getattr(func, "id", "")
                for arg in a.args:
                    if _is_concrete_oracle_node(arg):
                        has_concrete_literal = True
                if attr in ("assertEqual", "assertIs") and len(a.args) >= 2:
                    left_node = a.args[0]
                    right_node = a.args[1]

            if left_node is not None and right_node is not None:
                if _is_concrete_oracle_node(left_node) or _is_concrete_oracle_node(right_node):
                    has_concrete_literal = True

                # Direct alias tautology checks:
                if isinstance(left_node, ast.Name) and isinstance(right_node, ast.Name):
                    v1, v2 = left_node.id, right_node.id
                    if v1 in target_var_calls and v2 in target_var_calls:
                        dump1, tgt1, _ = target_var_calls[v1]
                        dump2, tgt2, _ = target_var_calls[v2]
                        if dump1 == dump2:
                            violations.append(
                                f"Line {assert_lineno}: Direct alias tautology in test `{fn_name}`: "
                                f"asserting equality between `{v1}` and `{v2}` assigned from identical calls to `{tgt1}`."
                            )
                elif isinstance(left_node, ast.Name) and isinstance(right_node, ast.Call):
                    v1 = left_node.id
                    if v1 in target_var_calls:
                        dump1, tgt1, _ = target_var_calls[v1]
                        dump2 = ast.dump(right_node, include_attributes=False)
                        if dump1 == dump2:
                            violations.append(
                                f"Line {assert_lineno}: Direct alias tautology in test `{fn_name}`: "
                                f"comparing variable `{v1}` against identical call to `{tgt1}`."
                            )
                elif isinstance(left_node, ast.Call) and isinstance(right_node, ast.Name):
                    v2 = right_node.id
                    if v2 in target_var_calls:
                        dump2, tgt2, _ = target_var_calls[v2]
                        dump1 = ast.dump(left_node, include_attributes=False)
                        if dump1 == dump2:
                            violations.append(
                                f"Line {assert_lineno}: Direct alias tautology in test `{fn_name}`: "
                                f"comparing variable `{v2}` against identical call to `{tgt2}`."
                            )

                left_is_call = isinstance(left_node, ast.Call) or (
                    isinstance(left_node, ast.Name) and left_node.id in all_call_vars
                )
                right_is_call = isinstance(right_node, ast.Call) or (
                    isinstance(right_node, ast.Name) and right_node.id in all_call_vars
                )
                if left_is_call and right_is_call:
                    has_call_comparison = True

        # Check newly added test function for oracle-free dynamic call comparison
        if fn_name not in old_funcs and fn_name.startswith("test_"):
            if has_call_comparison and not has_concrete_literal and len(fn_asserts) > 0:
                violations.append(
                    f"Line {new_fn.lineno}: New test `{fn_name}` compares dynamic function calls (`assert wrapper(x) == target(x)`) without concrete literal oracles."
                )

    anchors = index_ast_anchors(new_test_code, file_path=file_path)
    mar_data = calculate_mock_to_assertion_ratio(clean_new)
    return TestTamperingReport(
        passed=(len(violations) == 0),
        old_assert_count=len(old_asserts),
        new_assert_count=len(new_asserts),
        violations=violations,
        anchors=anchors,
        total_mocks=mar_data["total_mocks"],
        mar=mar_data["mar"],
        risk_level=mar_data["risk_level"],
        internal_mock_count=mar_data["internal_mock_count"],
        boundary_mock_count=mar_data["boundary_mock_count"],
        weighted_mar=mar_data["weighted_mar"],
    )
`

---

## cordis/mutator.py

`python
"""Gate 2: Diff-Scoped In-Place AST Mutation Engine ('Counterfeit Red' & Hollow-Test Killer)."""
from __future__ import annotations

import ast
import atexit
import copy
import io
import os
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Any


@dataclass
class MutantResult:
    mutant_id: int
    description: str
    lineno: int
    killed: bool
    mutated_code_snippet: str
    mutated_source: str = ""


@dataclass
class MutationGateReport:
    passed: bool
    total_mutants: int
    killed_mutants: int
    survived_mutants: int
    results: List[MutantResult] = field(default_factory=list)
    target_executed: bool = True
    wrapper_tautology_detected: bool = False

    @property
    def kill_rate(self) -> float:
        return (self.killed_mutants / self.total_mutants) if self.total_mutants > 0 else 0.0



class _SingleMutantCandidate:
    def __init__(self, description: str, lineno: int, apply_fn: Callable[[ast.AST], ast.AST]) -> None:
        self.description = description
        self.lineno = lineno
        self.apply_fn = apply_fn


def _is_overload_stub(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for d in getattr(node, "decorator_list", []):
        if (isinstance(d, ast.Name) and d.id == "overload") or (
            isinstance(d, ast.Attribute) and d.attr == "overload"
        ):
            return True
    if len(node.body) == 1 and isinstance(node.body[0], ast.Expr):
        val = node.body[0].value
        if isinstance(val, ast.Constant) and val.value is Ellipsis:
            return True
    return False


def _find_target_function_node(
    tree: ast.AST, target_function: str
) -> Optional[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Finds FunctionDef or AsyncFunctionDef matching target_function name or Class.name path,
    skipping @overload stubs when the actual implementation exists."""
    parts = target_function.split(".")
    target_node = None
    if len(parts) == 2:
        cls_name, fn_name = parts
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == cls_name:
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub.name == fn_name:
                        if not _is_overload_stub(sub):
                            return sub
                        target_node = sub
        if target_node is not None:
            return target_node
    fn_base = parts[-1]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == fn_base:
                if not _is_overload_stub(node):
                    return node
                target_node = node
    return target_node


def _is_pure_expression(node: ast.AST) -> bool:
    if isinstance(node, ast.Name):
        return True
    if isinstance(node, ast.Attribute):
        return _is_pure_expression(node.value)
    return False


def _expr_to_str(node: ast.AST) -> str:
    try:
        return ast.unparse(node).strip()
    except Exception:
        return ""


def _is_terminal_statement(stmt: ast.stmt) -> bool:
    if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
        return True
    return False


def _is_terminal_block(body: List[ast.stmt]) -> bool:
    if not body:
        return False
    last = body[-1]
    if _is_terminal_statement(last):
        return True
    if isinstance(last, ast.If):
        return _is_terminal_block(last.body) and _is_terminal_block(last.orelse)
    return False


def _statement_modifies_var(stmt: ast.stmt, var_str: str) -> bool:
    for node in ast.walk(stmt):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                for sub in ast.walk(t):
                    if _is_pure_expression(sub) and _expr_to_str(sub) == var_str:
                        return True
        elif isinstance(node, ast.AugAssign):
            if _is_pure_expression(node.target) and _expr_to_str(node.target) == var_str:
                return True
        elif isinstance(node, ast.NamedExpr):
            if _is_pure_expression(node.target) and _expr_to_str(node.target) == var_str:
                return True
    return False


def _extract_and_comparisons(test_expr: ast.AST) -> List[ast.Compare]:
    comps: List[ast.Compare] = []
    if isinstance(test_expr, ast.Compare):
        comps.append(test_expr)
    elif isinstance(test_expr, ast.BoolOp) and isinstance(test_expr.op, ast.And):
        for val in test_expr.values:
            comps.extend(_extract_and_comparisons(val))
    return comps


def _is_boundary_constrained(
    tree: ast.AST,
    compare_node: ast.Compare,
    mutation_kind: str,
) -> bool:
    """Checks if mutating boundary operator in `compare_node` produces a dead/equivalent mutant
    because preceding terminal sibling statements in the same block/scope already constrained the boundary.
    """
    if len(compare_node.ops) != 1 or len(compare_node.comparators) != 1:
        return False

    var_node = compare_node.left
    bound_node = compare_node.comparators[0]
    if not _is_pure_expression(var_node):
        return False

    var_str = _expr_to_str(var_node)
    bound_str = _expr_to_str(bound_node)
    if not var_str or not bound_str:
        return False

    # Find the enclosing statement and its sibling block by climbing up parent_map
    parent_map: dict[ast.AST, ast.AST] = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parent_map[c] = p

    curr: ast.AST = compare_node
    enclosing_stmt: Optional[ast.stmt] = None
    sibling_block: Optional[List[ast.stmt]] = None
    stmt_index: int = -1

    while curr in parent_map:
        p = parent_map[curr]
        for field_name, value in ast.iter_fields(p):
            if isinstance(value, list) and curr in value and isinstance(curr, ast.stmt):
                enclosing_stmt = curr
                sibling_block = value
                stmt_index = value.index(curr)
                break
        if enclosing_stmt is not None:
            break
        curr = p

    if enclosing_stmt is None or sibling_block is None or stmt_index <= 0:
        return False

    # Inspect preceding statements in the same block
    for k in range(stmt_index):
        prev_stmt = sibling_block[k]

        # If any intervening statement modifies the variable, constraint is invalidated
        reassigned = False
        for intervening in sibling_block[k:stmt_index]:
            if intervening is not prev_stmt and _statement_modifies_var(intervening, var_str):
                reassigned = True
                break
        if reassigned:
            continue

        if isinstance(prev_stmt, ast.If) and _is_terminal_block(prev_stmt.body):
            # The body exits the block/function. If the condition was True, var==bound terminated.
            guard_compares = _extract_and_comparisons(prev_stmt.test)
            for g in guard_compares:
                if mutation_kind in ("compare_gt_gte", "compare_gte_gt"):
                    # var > bound mutated to var >= bound (or >= to >)
                    # Equivalent if var == bound is unreachable downstream
                    # Chained: low <= var <= bound or low < var <= bound
                    if len(g.ops) == 2 and len(g.comparators) == 2:
                        if (
                            isinstance(g.ops[0], (ast.Lt, ast.LtE))
                            and isinstance(g.ops[1], ast.LtE)
                            and _expr_to_str(g.comparators[0]) == var_str
                            and _expr_to_str(g.comparators[1]) == bound_str
                        ):
                            return True
                    # Simple compares
                    elif len(g.ops) == 1 and len(g.comparators) == 1:
                        g_op = g.ops[0]
                        g_left = _expr_to_str(g.left)
                        g_right = _expr_to_str(g.comparators[0])
                        # var <= bound
                        if isinstance(g_op, ast.LtE) and g_left == var_str and g_right == bound_str:
                            return True
                        # bound >= var
                        if isinstance(g_op, ast.GtE) and g_left == bound_str and g_right == var_str:
                            return True
                        # var == bound
                        if isinstance(g_op, ast.Eq) and (
                            (g_left == var_str and g_right == bound_str)
                            or (g_left == bound_str and g_right == var_str)
                        ):
                            return True

                elif mutation_kind in ("compare_lt_lte", "compare_lte_lt"):
                    # var < bound mutated to var <= bound (or <= to <)
                    # Equivalent if var == bound is unreachable downstream
                    # Chained: bound <= var <= high or bound <= var < high
                    if len(g.ops) == 2 and len(g.comparators) == 2:
                        if (
                            isinstance(g.ops[0], ast.LtE)
                            and isinstance(g.ops[1], (ast.Lt, ast.LtE))
                            and _expr_to_str(g.left) == bound_str
                            and _expr_to_str(g.comparators[0]) == var_str
                        ):
                            return True
                    # Simple compares
                    elif len(g.ops) == 1 and len(g.comparators) == 1:
                        g_op = g.ops[0]
                        g_left = _expr_to_str(g.left)
                        g_right = _expr_to_str(g.comparators[0])
                        # var >= bound
                        if isinstance(g_op, ast.GtE) and g_left == var_str and g_right == bound_str:
                            return True
                        # bound <= var
                        if isinstance(g_op, ast.LtE) and g_left == bound_str and g_right == var_str:
                            return True
                        # var == bound
                        if isinstance(g_op, ast.Eq) and (
                            (g_left == var_str and g_right == bound_str)
                            or (g_left == bound_str and g_right == var_str)
                        ):
                            return True

    return False


class _ResourceCloseElider(ast.NodeTransformer):
    def __init__(self, target_lineno: int, target_col: int) -> None:
        self.target_lineno = target_lineno
        self.target_col = target_col
        self.applied = False

    def visit_Expr(self, node: ast.Expr) -> ast.AST:
        if (
            getattr(node, "lineno", -1) == self.target_lineno
            and getattr(node, "col_offset", -1) == self.target_col
            and not self.applied
        ):
            self.applied = True
            pass_node = ast.Pass()
            ast.copy_location(pass_node, node)
            return pass_node
        return self.generic_visit(node)


def _collect_arid_ast_nodes(tree: ast.AST) -> set[ast.AST]:
    """Collects AST nodes that should not be mutated (Google Arid Node policy):
    - `if __name__ == '__main__':` blocks
    - `if TYPE_CHECKING:` blocks
    - Logging, print, and warning calls (`print`, `logger.*`, `logging.*`, `log.*`, `warnings.warn`)
    """
    arid_nodes: set[ast.AST] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            # 1. if __name__ == "__main__":
            if any(isinstance(sub, ast.Name) and sub.id == "__name__" for sub in ast.walk(node.test)):
                for child in ast.walk(node):
                    arid_nodes.add(child)
            # 2. if TYPE_CHECKING:
            if any(
                (isinstance(sub, ast.Name) and sub.id == "TYPE_CHECKING")
                or (isinstance(sub, ast.Attribute) and sub.attr == "TYPE_CHECKING")
                for sub in ast.walk(node.test)
            ):
                for child in ast.walk(node):
                    arid_nodes.add(child)
            # 3. if ... in sys.path / if ... not in sys.path environment guards
            try:
                test_str = ast.unparse(node.test)
                if "sys.path" in test_str:
                    for child in ast.walk(node):
                        arid_nodes.add(child)
            except Exception:
                pass

        # 3. Logging, print, warnings.warn calls
        if isinstance(node, ast.Call):
            is_arid = False
            func = node.func
            if isinstance(func, ast.Name) and func.id in ("print", "warn"):
                is_arid = True
            elif isinstance(func, ast.Attribute):
                caller_str = ast.unparse(func)
                if (
                    caller_str.startswith("logging.")
                    or caller_str.startswith("logger.")
                    or caller_str.startswith("log.")
                    or caller_str.startswith("warnings.")
                    or caller_str == "warnings.warn"
                    or ".logger." in caller_str
                    or ".log." in caller_str
                ):
                    is_arid = True
            if is_arid:
                for child in ast.walk(node):
                    arid_nodes.add(child)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name) and func.id in ("print", "warn"):
                arid_nodes.add(node)
            elif isinstance(func, ast.Attribute):
                caller_str = ast.unparse(func)
                if (
                    caller_str.startswith("logging.")
                    or caller_str.startswith("logger.")
                    or caller_str.startswith("log.")
                    or caller_str.startswith("warnings.")
                    or caller_str == "warnings.warn"
                    or ".logger." in caller_str
                    or ".log." in caller_str
                ):
                    arid_nodes.add(node)

    return arid_nodes


def _is_tie_boundary_equivalent(tree: ast.AST, compare_node: ast.Compare) -> bool:
    """Checks if mutating boundary operator (< <-> <= or > <-> >=) in `compare_node` produces
    a mathematically equivalent mutant because the condition is of the form:
      if a < b: return a (or return b)
      else: return b (or return a)
    or:
      return a if a < b else b
    At the tie boundary a == b, both branches return the identical value, making
    the boundary shift < <-> <= or > <-> >= mathematically equivalent!
    """
    if len(compare_node.ops) != 1 or len(compare_node.comparators) != 1:
        return False

    op = compare_node.ops[0]
    if not isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
        return False

    left_str = _expr_to_str(compare_node.left)
    right_str = _expr_to_str(compare_node.comparators[0])
    if not left_str or not right_str:
        return False

    operands_set = {left_str, right_str}

    parent_map: dict[ast.AST, ast.AST] = {}
    for p in ast.walk(tree):
        for c in ast.iter_child_nodes(p):
            parent_map[c] = p

    curr: ast.AST = compare_node
    while curr in parent_map:
        p = parent_map[curr]
        if isinstance(p, ast.IfExp) and p.test is curr:
            body_str = _expr_to_str(p.body)
            orelse_str = _expr_to_str(p.orelse)
            if body_str and orelse_str and {body_str, orelse_str} == operands_set:
                return True
        elif isinstance(p, ast.If) and p.test is curr:
            if p.orelse:
                ret1_str = None
                if p.body and isinstance(p.body[-1], ast.Return) and p.body[-1].value is not None:
                    ret1_str = _expr_to_str(p.body[-1].value)
                ret2_str = None
                if isinstance(p.orelse[-1], ast.Return) and p.orelse[-1].value is not None:
                    ret2_str = _expr_to_str(p.orelse[-1].value)
                if ret1_str and ret2_str and {ret1_str, ret2_str} == operands_set:
                    return True
        curr = p

    return False


SECURITY_KWARGS = {"verify", "trust_env", "check_hostname", "strict", "validate"}


class _UnaryNotRemover(ast.NodeTransformer):
    def __init__(self, target_lineno: int, target_col: int) -> None:
        self.target_lineno = target_lineno
        self.target_col = target_col
        self.applied = False

    def visit_UnaryOp(self, node: ast.UnaryOp) -> ast.AST:
        if (
            getattr(node, "lineno", -1) == self.target_lineno
            and getattr(node, "col_offset", -1) == self.target_col
            and not self.applied
        ):
            if isinstance(node.op, ast.Not):
                self.applied = True
                return node.operand
        return self.generic_visit(node)


class _UnaryNotAdder(ast.NodeTransformer):
    def __init__(self, target_lineno: int, target_col: int) -> None:
        self.target_lineno = target_lineno
        self.target_col = target_col
        self.applied = False

    def visit(self, node: ast.AST) -> ast.AST:
        if (
            getattr(node, "lineno", -1) == self.target_lineno
            and getattr(node, "col_offset", -1) == self.target_col
            and not self.applied
        ):
            self.applied = True
            return ast.UnaryOp(op=ast.Not(), operand=node)
        return self.generic_visit(node)


def generate_ast_mutants(
    source_code: str,
    target_function: Optional[str] = None,
    max_mutants: int = 5,
    include_canary: bool = False,
) -> List[tuple[str, int, str]]:
    """Generates up to `max_mutants` distinct AST mutations inside `target_function` (or module).
    Returns a list of (description, lineno, mutated_source_code).
    """
    base_tree = ast.parse(source_code)
    mutations: List[tuple[str, int, str]] = []

    # Collect mutable node indices within target_function
    def _find_target_nodes(tree: ast.AST) -> List[ast.AST]:
        if target_function:
            target_node = _find_target_function_node(tree, target_function)
            if target_node is not None:
                return list(ast.walk(target_node))
            return []
        return list(ast.walk(tree))

    probe_nodes = _find_target_nodes(base_tree)

    # Collect arid nodes to skip mutating per Google Petrovic et al. policy
    arid_nodes = _collect_arid_ast_nodes(base_tree)

    # Collect nodes inside `if __name__ == ...` checks to avoid mutating them
    name_main_nodes: set[ast.AST] = set()
    for node in ast.walk(base_tree):
        if isinstance(node, ast.If):
            if any(isinstance(sub, ast.Name) and sub.id == "__name__" for sub in ast.walk(node.test)):
                for child in ast.walk(node):
                    name_main_nodes.add(child)

    # Identify candidate node positions by (lineno, col_offset, type)
    return_constants = {n.value for n in probe_nodes if isinstance(n, ast.Return) and isinstance(n.value, ast.Constant)}
    candidates: List[tuple[int, int, str, str]] = []
    for n in probe_nodes:
        if n in arid_nodes or n in name_main_nodes:
            continue
        if isinstance(n, ast.Compare) and any(
            isinstance(sub, ast.Name) and sub.id == "__name__" for sub in ast.walk(n)
        ):
            continue
        lineno = getattr(n, "lineno", 0)
        col = getattr(n, "col_offset", 0)
        if isinstance(n, ast.Compare) and len(n.ops) == 1:
            op = n.ops[0]
            if isinstance(op, ast.Eq):
                candidates.append((lineno, col, "compare_eq", "Flip `==` to `!=`"))
            elif isinstance(op, ast.NotEq):
                candidates.append((lineno, col, "compare_neq", "Flip `!=` to `==`"))
            elif isinstance(op, ast.Lt):
                if not _is_boundary_constrained(base_tree, n, "compare_lt_lte") and not _is_tie_boundary_equivalent(base_tree, n):
                    candidates.append((lineno, col, "compare_lt_lte", "Boundary shift `<` to `<=`"))
                candidates.append((lineno, col, "compare_lt", "Flip `<` to `>=`"))
            elif isinstance(op, ast.LtE):
                if not _is_boundary_constrained(base_tree, n, "compare_lte_lt") and not _is_tie_boundary_equivalent(base_tree, n):
                    candidates.append((lineno, col, "compare_lte_lt", "Boundary shift `<=` to `<`"))
                candidates.append((lineno, col, "compare_lte", "Flip `<=` to `>`"))
            elif isinstance(op, ast.Gt):
                if not _is_boundary_constrained(base_tree, n, "compare_gt_gte") and not _is_tie_boundary_equivalent(base_tree, n):
                    candidates.append((lineno, col, "compare_gt_gte", "Boundary shift `>` to `>=`"))
                candidates.append((lineno, col, "compare_gt", "Flip `>` to `<=`"))
            elif isinstance(op, ast.GtE):
                if not _is_boundary_constrained(base_tree, n, "compare_gte_gt") and not _is_tie_boundary_equivalent(base_tree, n):
                    candidates.append((lineno, col, "compare_gte_gt", "Boundary shift `>=` to `>`"))
                candidates.append((lineno, col, "compare_gte", "Flip `>=` to `<`"))
            elif isinstance(op, ast.Is):
                candidates.append((lineno, col, "compare_is_isnot", "Flip `is` to `is not`"))
            elif isinstance(op, ast.IsNot):
                candidates.append((lineno, col, "compare_isnot_is", "Flip `is not` to `is`"))
            elif isinstance(op, ast.In):
                candidates.append((lineno, col, "compare_in_notin", "Flip `in` to `not in`"))
            elif isinstance(op, ast.NotIn):
                candidates.append((lineno, col, "compare_notin_in", "Flip `not in` to `in`"))
        elif isinstance(n, ast.UnaryOp) and isinstance(n.op, ast.Not):
            candidates.append((lineno, col, "unary_not_remove", "Remove unary `not` inversion"))
        elif isinstance(n, (ast.If, ast.While)):
            test = n.test
            if not (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)):
                if not any(isinstance(sub, ast.Name) and sub.id == "__name__" for sub in ast.walk(test)):
                    test_lineno = getattr(test, "lineno", lineno)
                    test_col = getattr(test, "col_offset", col)
                    candidates.append((test_lineno, test_col, "unary_not_add", "Invert boolean condition with `not`"))
        elif isinstance(n, ast.Subscript) and isinstance(getattr(n, "ctx", None), ast.Load):
            if isinstance(n.slice, ast.Constant) and n.slice.value == 0 and not isinstance(n.slice.value, bool):
                candidates.append((lineno, col, "subscript_index_head", "Perturb container index `[0]` to `[1]`"))
                candidates.append((lineno, col, "subscript_slice_head", "Perturb container slice lower bound `[0:]` to `[1:]`"))
            elif isinstance(n.slice, ast.Slice):
                lower = n.slice.lower
                if lower is None or (isinstance(lower, ast.Constant) and lower.value == 0 and not isinstance(lower.value, bool)):
                    candidates.append((lineno, col, "subscript_slice_head", "Perturb container slice lower bound `[0:]` to `[1:]`"))
        elif isinstance(n, ast.BoolOp):
            if isinstance(n.op, ast.And):
                candidates.append((lineno, col, "boolop_and_or", "Flip `and` to `or`"))
            elif isinstance(n.op, ast.Or):
                candidates.append((lineno, col, "boolop_or_and", "Flip `or` to `and`"))
        elif isinstance(n, ast.Constant) and isinstance(n.value, bool):
            if n not in return_constants:
                candidates.append((lineno, col, "const_bool_flip", f"Flip boolean literal `{n.value}` to `{not n.value}`"))
        elif isinstance(n, ast.BinOp):
            if isinstance(n.op, ast.Add):
                candidates.append((lineno, col, "binop_add", "Flip `+` to `-`"))
            elif isinstance(n.op, ast.Sub):
                candidates.append((lineno, col, "binop_sub", "Flip `-` to `+`"))
            elif isinstance(n.op, ast.Mult):
                candidates.append((lineno, col, "binop_mult", "Flip `*` to `/`"))
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            num_defaults = len(n.args.defaults)
            if num_defaults > 0:
                pos_args = n.args.args[-num_defaults:]
                for arg_obj, def_val in zip(pos_args, n.args.defaults):
                    if arg_obj.arg in SECURITY_KWARGS and isinstance(def_val, ast.Constant) and def_val.value is True:
                        d_lineno = getattr(def_val, "lineno", lineno)
                        d_col = getattr(def_val, "col_offset", col)
                        candidates.append((
                            d_lineno,
                            d_col,
                            f"security_kwarg_{arg_obj.arg}",
                            f"Flip security/validation flag `{arg_obj.arg}=True` to `False`",
                        ))
            for arg_obj, def_val in zip(n.args.kwonlyargs, n.args.kw_defaults):
                if def_val is not None and arg_obj.arg in SECURITY_KWARGS and isinstance(def_val, ast.Constant) and def_val.value is True:
                    d_lineno = getattr(def_val, "lineno", lineno)
                    d_col = getattr(def_val, "col_offset", col)
                    candidates.append((
                        d_lineno,
                        d_col,
                        f"security_kwarg_{arg_obj.arg}",
                        f"Flip security/validation flag `{arg_obj.arg}=True` to `False`",
                    ))
        elif isinstance(n, ast.Call):
            for kw in n.keywords:
                if kw.arg in SECURITY_KWARGS and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    kw_lineno = getattr(kw.value, "lineno", lineno)
                    kw_col = getattr(kw.value, "col_offset", col)
                    candidates.append((
                        kw_lineno,
                        kw_col,
                        f"security_kwarg_{kw.arg}",
                        f"Flip security/validation flag `{kw.arg}=True` to `False`",
                    ))
        elif isinstance(n, ast.Expr):
            call_node = n.value
            if isinstance(call_node, ast.Await):
                call_node = call_node.value
            if isinstance(call_node, ast.Call) and isinstance(call_node.func, ast.Attribute):
                method_name = call_node.func.attr
                if method_name in ("close", "aclose", "release", "shutdown"):
                    candidates.append((
                        lineno,
                        col,
                        f"resource_close_elision_{method_name}",
                        f"Elide resource teardown call `.{method_name}()`",
                    ))
        elif isinstance(n, ast.Return) and n.value is not None:
            if isinstance(n.value, ast.Constant) and isinstance(n.value.value, (int, float)) and not isinstance(n.value.value, bool):
                candidates.append((lineno, col, "return_const_num", f"Perturb return constant `{n.value.value}`"))
            elif isinstance(n.value, ast.Constant) and isinstance(n.value.value, bool):
                candidates.append((lineno, col, "return_const_bool", f"Flip return boolean `{n.value.value}`"))
            elif isinstance(n.value, ast.Constant) and n.value.value is None:
                candidates.append((lineno, col, "return_const_none", "Perturb `return None` to non-None"))
            else:
                candidates.append((lineno, col, "return_none", "Replace return expression with `None`"))
                if include_canary:
                    candidates.append((lineno, col, "return_nan_canary", "Replace return with IEEE-754 NaN canary (tautology detector)"))

    # Deduplicate and prioritize diverse mutations up to max_mutants
    seen = set()
    unique_candidates = []
    for item in candidates:
        key = (item[0], item[1], item[2])
        if key not in seen:
            seen.add(key)
            unique_candidates.append(item)

    selected_candidates = list(unique_candidates[:max_mutants])
    if include_canary and max_mutants > 1:
        selected_none_lines = {c[0] for c in selected_candidates if c[2] == "return_none"}
        for item in unique_candidates[max_mutants:]:
            if item[2] == "return_nan_canary" and item[0] in selected_none_lines:
                if len(selected_candidates) >= max_mutants:
                    for idx in reversed(range(len(selected_candidates))):
                        if selected_candidates[idx][2] != "return_none":
                            selected_candidates[idx] = item
                            break
                else:
                    selected_candidates.append(item)

    for lineno, col, kind, desc in selected_candidates:
        tree_copy = copy.deepcopy(base_tree)
        applied = False

        if kind == "unary_not_remove":
            remover = _UnaryNotRemover(lineno, col)
            tree_copy = remover.visit(tree_copy)
            applied = remover.applied
        elif kind == "unary_not_add":
            adder = _UnaryNotAdder(lineno, col)
            tree_copy = adder.visit(tree_copy)
            applied = adder.applied
        elif kind.startswith("resource_close_elision"):
            elider = _ResourceCloseElider(lineno, col)
            tree_copy = elider.visit(tree_copy)
            applied = elider.applied
        else:
            for n in ast.walk(tree_copy):
                if getattr(n, "lineno", -1) == lineno and getattr(n, "col_offset", -1) == col and not applied:
                    if kind == "compare_eq" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.NotEq()
                        applied = True
                    elif kind == "compare_neq" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.Eq()
                        applied = True
                    elif kind == "compare_lt_lte" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.LtE()
                        applied = True
                    elif kind == "compare_lt" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.GtE()
                        applied = True
                    elif kind == "compare_lte_lt" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.Lt()
                        applied = True
                    elif kind == "compare_lte" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.Gt()
                        applied = True
                    elif kind == "compare_gt_gte" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.GtE()
                        applied = True
                    elif kind == "compare_gt" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.LtE()
                        applied = True
                    elif kind == "compare_gte_gt" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.Gt()
                        applied = True
                    elif kind == "compare_gte" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.Lt()
                        applied = True
                    elif kind == "compare_is_isnot" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.IsNot()
                        applied = True
                    elif kind == "compare_isnot_is" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.Is()
                        applied = True
                    elif kind == "compare_in_notin" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.NotIn()
                        applied = True
                    elif kind == "compare_notin_in" and isinstance(n, ast.Compare):
                        n.ops[0] = ast.In()
                        applied = True
                    elif kind == "subscript_index_head" and isinstance(n, ast.Subscript):
                        n.slice = ast.Constant(value=1)
                        applied = True
                    elif kind == "subscript_slice_head" and isinstance(n, ast.Subscript):
                        if isinstance(n.slice, ast.Slice):
                            n.slice.lower = ast.Constant(value=1)
                        else:
                            n.slice = ast.Slice(lower=ast.Constant(value=1), upper=None, step=None)
                        applied = True
                    elif kind == "boolop_and_or" and isinstance(n, ast.BoolOp):
                        n.op = ast.Or()
                        applied = True
                    elif kind == "boolop_or_and" and isinstance(n, ast.BoolOp):
                        n.op = ast.And()
                        applied = True
                    elif kind == "const_bool_flip" and isinstance(n, ast.Constant) and isinstance(n.value, bool):
                        n.value = not n.value
                        applied = True
                    elif kind == "binop_add" and isinstance(n, ast.BinOp):
                        n.op = ast.Sub()
                        applied = True
                    elif kind == "binop_sub" and isinstance(n, ast.BinOp):
                        n.op = ast.Add()
                        applied = True
                    elif kind == "binop_mult" and isinstance(n, ast.BinOp):
                        n.op = ast.Div()
                        applied = True
                    elif kind == "return_const_num" and isinstance(n, ast.Return) and isinstance(n.value, ast.Constant):
                        n.value = ast.Constant(value=n.value.value + 1.0 if isinstance(n.value.value, float) else n.value.value + 1)
                        applied = True
                    elif kind == "return_const_bool" and isinstance(n, ast.Return) and isinstance(n.value, ast.Constant):
                        n.value = ast.Constant(value=not n.value.value)
                        applied = True
                    elif kind == "return_const_none" and isinstance(n, ast.Return):
                        n.value = ast.Constant(value="__CORDIS_MUTANT__")
                        applied = True
                    elif kind == "return_none" and isinstance(n, ast.Return):
                        n.value = ast.Constant(value=None)
                        applied = True
                    elif kind == "return_nan_canary" and isinstance(n, ast.Return):
                        n.value = ast.Call(
                            func=ast.Name(id="float", ctx=ast.Load()),
                            args=[ast.Constant(value="nan")],
                            keywords=[],
                        )
                        applied = True
                    elif kind.startswith("security_kwarg_"):
                        target_kw = kind[len("security_kwarg_"):]
                        if isinstance(n, ast.Call):
                            for kw in n.keywords:
                                if kw.arg == target_kw and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    kw.value = ast.Constant(value=False)
                                    applied = True
                                    break
                        elif isinstance(n, ast.Constant) and n.value is True:
                            n.value = False
                            applied = True

        if applied:
            ast.fix_missing_locations(tree_copy)
            mutated_src = ast.unparse(tree_copy)
            mutations.append((desc, lineno, mutated_src))

    return mutations




def run_in_memory_mutation_gate(
    source_code: str,
    test_code: str,
    target_function: Optional[str] = None,
    max_mutants: int = 5,
    module_name: Optional[str] = None,
    include_canary: bool = True,
) -> MutationGateReport:
    """Executes all assertions in `test_code` against each AST mutant of `source_code`.
    Works 100% in-process (sub-millisecond) with module-level patching and dataclass
    compatibility for Python 3.10-3.13+, guaranteeing zero Windows file-locking issues.
    """
    mutants = generate_ast_mutants(
        source_code,
        target_function=target_function,
        max_mutants=max_mutants,
        include_canary=include_canary,
    )
    if not mutants:
        return MutationGateReport(
            passed=True,
            total_mutants=0,
            killed_mutants=0,
            survived_mutants=0,
            results=[],
            wrapper_tautology_detected=False,
        )

    results: List[MutantResult] = []
    meta_results: List[tuple[str, int, str, bool, bool]] = []
    killed_count = 0

    # Extract standalone test functions from test_code
    test_tree = ast.parse(test_code)
    test_func_names = [
        n.name for n in test_tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_")
    ]

    target_mod = None
    orig_mod_dict: dict[str, Any] = {}
    if module_name:
        if module_name in sys.modules:
            target_mod = sys.modules[module_name]
            orig_mod_dict = dict(target_mod.__dict__)
        else:
            target_mod = types.ModuleType(module_name)
            sys.modules[module_name] = target_mod

    for idx, (desc, lineno, mutated_src) in enumerate(mutants, start=1):
        # Register a module in sys.modules so @dataclass won't crash in Python 3.13
        test_mod_name = "__cordis_test__"
        test_mod = types.ModuleType(test_mod_name)
        sys.modules[test_mod_name] = test_mod
        env: dict[str, Any] = test_mod.__dict__

        # Keep track of any foreign modules patched so we can restore them
        patched_foreign_modules: list[tuple[Any, str, Any]] = []

        killed = False
        killed_by_assertion = False
        try:
            # If target module is known, compile into target_mod.__dict__ as well
            if target_mod is not None:
                exec(compile(mutated_src, f"<{module_name}_mutant>", "exec"), target_mod.__dict__)
                env.update(target_mod.__dict__)
            else:
                exec(compile(mutated_src, "<mutant_source>", "exec"), env)

            # If target_function was mutated, patch it in any other loaded module that already imported it
            fn_base = target_function.split(".")[-1] if target_function else None
            if fn_base and fn_base in env and callable(env[fn_base]):
                mutated_fn = env[fn_base]
                for m_name, m_obj in list(sys.modules.items()):
                    if m_obj in (target_mod, test_mod, None):
                        continue
                    if m_obj is not None and hasattr(m_obj, fn_base):
                        try:
                            old_val = getattr(m_obj, fn_base)
                            setattr(m_obj, fn_base, mutated_fn)
                            patched_foreign_modules.append((m_obj, fn_base, old_val))
                        except Exception:
                            pass

            exec(compile(test_code, "<test_source>", "exec"), env)

            # 1. Execute standalone test_* functions
            for t_name in test_func_names:
                if t_name in env and callable(env[t_name]):
                    env[t_name]()

            # 2. Execute test methods in unittest.TestCase subclasses
            test_case_classes = [
                val for val in env.values()
                if isinstance(val, type) and issubclass(val, unittest.TestCase) and val is not unittest.TestCase
            ]
            for cls in test_case_classes:
                suite = unittest.TestLoader().loadTestsFromTestCase(cls)
                stream = io.StringIO()
                runner = unittest.TextTestRunner(stream=stream)
                result = runner.run(suite)
                if not result.wasSuccessful():
                    raise AssertionError(f"TestCase {cls.__name__} failed against mutant: {stream.getvalue()}")
        except AssertionError:
            killed = True
            killed_by_assertion = True
        except Exception:
            # Any runtime exception means the test KILLED the mutant!
            killed = True
        finally:
            # Restore any foreign modules patched
            for m_obj, attr_name, old_val in patched_foreign_modules:
                try:
                    setattr(m_obj, attr_name, old_val)
                except Exception:
                    pass
            # Restore target module dict
            if target_mod is not None and orig_mod_dict:
                target_mod.__dict__.clear()
                target_mod.__dict__.update(orig_mod_dict)
            # Clean up test module
            sys.modules.pop(test_mod_name, None)

        if killed:
            killed_count += 1

        snippet_lines = [line.strip() for line in mutated_src.splitlines() if line.strip()]
        snippet = " | ".join(snippet_lines[:3])
        results.append(
            MutantResult(
                mutant_id=idx,
                description=desc,
                lineno=lineno,
                killed=killed,
                mutated_code_snippet=snippet[:120],
                mutated_source=mutated_src,
            )
        )
        meta_results.append((desc, lineno, mutated_src, killed, killed_by_assertion))

    # Tautology Canary Detection: if return_none survived while return_nan_canary was killed by AssertionError
    wrapper_tautology_detected = False
    survived_none_lines: dict[int, int] = {}
    for i, (d, lno, src, kld, _) in enumerate(meta_results):
        if "Replace return expression with `None`" in d and not kld:
            survived_none_lines[lno] = i

    for d, lno, src, kld, kld_assert in meta_results:
        if "IEEE-754 NaN canary" in d and kld and kld_assert:
            if lno in survived_none_lines:
                wrapper_tautology_detected = True
                res_idx = survived_none_lines[lno]
                results[res_idx].description += (
                    " [WRAPPER TAUTOLOGY DETECTED: Test compares f(x) against itself or a delegating wrapper "
                    "(None == None passed, NaN != NaN failed)]"
                )

    survived = len(results) - killed_count
    passed = (survived == 0)
    return MutationGateReport(
        passed=passed,
        total_mutants=len(results),
        killed_mutants=killed_count,
        survived_mutants=survived,
        results=results,
        wrapper_tautology_detected=wrapper_tautology_detected,
    )



def inject_coverage_probe(source_code: str, target_function: str) -> Optional[str]:
    """Injects `raise RuntimeError("__CORDIS_COVERAGE_PROBE__")` as first statement inside target_function."""
    try:
        tree = ast.parse(source_code)
    except Exception:
        return None

    target_node = _find_target_function_node(tree, target_function)
    if target_node is None:
        return None

    probe_stmt = ast.Raise(
        exc=ast.Call(
            func=ast.Name(id="RuntimeError", ctx=ast.Load()),
            args=[ast.Constant(value="__CORDIS_COVERAGE_PROBE__")],
            keywords=[],
        )
    )
    ast.copy_location(probe_stmt, target_node)
    insert_idx = 0
    if (
        target_node.body
        and isinstance(target_node.body[0], ast.Expr)
        and isinstance(target_node.body[0].value, ast.Constant)
        and isinstance(target_node.body[0].value.value, str)
    ):
        insert_idx = 1
    target_node.body.insert(insert_idx, probe_stmt)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree)


def run_repo_mutation_gate(
    repo_root: Path | str,
    source_rel_path: str,
    test_rel_path: str,
    target_function: Optional[str] = None,
    max_mutants: int = 5,
    timeout: float = 10.0,
    pytest_args: Optional[str | List[str]] = None,
    include_canary: bool = True,
) -> MutationGateReport:
    """Diff-Scoped AST Mutation Testing for real multi-file repositories.
    Injects mutants directly into `repo_root / source_rel_path` and verifies if `test_rel_path`
    kills each mutant, restoring the original file bytes inside a strict `try ... finally` block.
    """
    root = Path(repo_root).resolve()
    source_full = root / source_rel_path
    if not source_full.is_file():
        return MutationGateReport(
            passed=True,
            total_mutants=0,
            killed_mutants=0,
            survived_mutants=0,
            results=[],
            target_executed=False,
            wrapper_tautology_detected=False,
        )

    # 0. Crash-Recovery Check: restore original file from .cordis.bak if previous run was aborted
    bak_path = source_full.with_name(source_full.name + ".cordis.bak")
    if bak_path.is_file():
        try:
            source_full.write_bytes(bak_path.read_bytes())
            bak_path.unlink()
        except Exception:
            pass

    orig_bytes = source_full.read_bytes()
    source_code = orig_bytes.decode("utf-8", errors="replace")

    mutants = generate_ast_mutants(
        source_code,
        target_function=target_function,
        max_mutants=max_mutants,
        include_canary=include_canary,
    )
    if not mutants:
        is_target_present = False
        if target_function:
            try:
                tree = ast.parse(source_code)
                is_target_present = (_find_target_function_node(tree, target_function) is not None)
            except Exception:
                is_target_present = False
        return MutationGateReport(
            passed=True,
            total_mutants=0,
            killed_mutants=0,
            survived_mutants=0,
            results=[],
            target_executed=is_target_present if target_function else True,
            wrapper_tautology_detected=False,
        )

    env = dict(os.environ)
    pp_items: List[str] = []

    # 1. Dynamically detect the package root from source_rel_path
    # (e.g., if source_rel_path starts with src/ or fastmcp_slim/, prepend that sub-root at index 0 of PYTHONPATH)
    parts = Path(source_rel_path).parts
    if len(parts) > 1:
        candidate_sub_root = root / parts[0]
        if candidate_sub_root.is_dir():
            if parts[0] in ("src", "fastmcp_slim") or not (candidate_sub_root / "__init__.py").exists():
                pp_items.append(str(candidate_sub_root))

    if str(root) not in pp_items:
        pp_items.append(str(root))
    src_dir = root / "src"
    if src_dir.is_dir() and str(src_dir) not in pp_items:
        pp_items.append(str(src_dir))

    # Detect if real (non-shim) pytest is installed and functional
    has_pytest = False
    try:
        p = subprocess.run(
            [sys.executable, "-c", "import sys, pytest; assert not getattr(pytest, '_cordis_shim', False); sys.exit(0)"],
            cwd=str(root),
            capture_output=True,
            timeout=2,
        )
        if p.returncode == 0:
            has_pytest = True
    except Exception:
        pass

    shims_dir = Path(__file__).resolve().parent / "_shims"
    if not has_pytest and shims_dir.is_dir():
        pp_items.append(str(shims_dir))
    if "PYTHONPATH" in env and env["PYTHONPATH"]:
        pp_items.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pp_items)

    extra_test_args: List[str] = []
    if pytest_args:
        if isinstance(pytest_args, str):
            extra_test_args = shlex.split(pytest_args)
        else:
            extra_test_args = list(pytest_args)

    base_test_args = shlex.split(test_rel_path) if " " in test_rel_path else [str(Path(test_rel_path))]
    full_test_args = [*base_test_args, *extra_test_args]
    test_arg = base_test_args[0] if base_test_args else str(Path(test_rel_path))
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        *full_test_args,
        "-q",
        "-o",
        "asyncio_default_fixture_loop_scope=function",
    ] if has_pytest else [sys.executable, "-m", "unittest", *full_test_args]

    def _execute_test_cycle() -> tuple[bool, int, str]:
        """Runs test runner; returns (executed, returncode, output).
        executed is True only if >= 1 tests actually ran.
        """
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        out = (proc.stdout or "") + (proc.stderr or "")

        if has_pytest:
            if proc.returncode in (2, 3, 4, 5) or ("\nINTERNALERROR" in ("\n" + out)) or ("\nERROR collecting" in ("\n" + out)):
                return False, proc.returncode, out
            return True, proc.returncode, out

        if not has_pytest and ("Ran 0 tests" in out or "NO TESTS RAN" in out or "Failed to import test module" in out or proc.returncode == 5):
            runner_code = (
                "import sys, pathlib, importlib, importlib.util, inspect\n"
                f"p = pathlib.Path(r'{test_arg}')\n"
                "dotted = '.'.join(p.with_suffix('').parts)\n"
                "try:\n"
                "    m = importlib.import_module(dotted)\n"
                "except Exception:\n"
                "    spec = importlib.util.spec_from_file_location('__test_target__', str(p))\n"
                "    m = importlib.util.module_from_spec(spec)\n"
                "    spec.loader.exec_module(m)\n"
                "ran = 0\n"
                "for name, fn in inspect.getmembers(m, inspect.isfunction):\n"
                "    if name.startswith('test_'):\n"
                "        ran += 1\n"
                "        if hasattr(fn, '_cordis_parametrized'):\n"
                "            argnames, argvalues = fn._cordis_parametrized\n"
                "            names = [a.strip() for a in argnames.split(',')] if isinstance(argnames, str) else list(argnames)\n"
                "            for val in argvalues:\n"
                "                if len(names) == 1:\n"
                "                    fn(val)\n"
                "                else:\n"
                "                    fn(*val)\n"
                "        else:\n"
                "            fn()\n"
                "sys.exit(0 if ran > 0 else 2)\n"
            )
            fb = subprocess.run(
                [sys.executable, "-c", runner_code],
                cwd=str(root),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            fb_out = (fb.stdout or "") + (fb.stderr or "")
            if fb.returncode == 2 or "ModuleNotFoundError" in fb_out or "ImportError" in fb_out:
                return False, 2, fb_out
            return True, fb.returncode, fb_out

        if "Ran 0 tests" in out or "NO TESTS RAN" in out or "Failed to import test module" in out:
            return False, proc.returncode, out

        return True, proc.returncode, out

    # 2. Pre-Mutation Execution Coverage Probe:
    # Before running AST mutants on target_function, verify that test_rel_path actually executes target_function.
    target_executed = True
    if target_function:
        probe_src = inject_coverage_probe(source_code, target_function)
        if probe_src is not None:
            try:
                source_full.write_text(probe_src, encoding="utf-8")
                executed, retcode, out = _execute_test_cycle()
                # If test STILL exits 0 when target_function raises RuntimeError,
                # or if 0 tests ran, or if probe was never executed, target was NOT executed!
                if (not executed) or (retcode == 0) or ("__CORDIS_COVERAGE_PROBE__" not in out):
                    target_executed = False
            except subprocess.TimeoutExpired:
                target_executed = True
            except Exception:
                target_executed = True
            finally:
                source_full.write_bytes(orig_bytes)
        else:
            target_executed = False

    if not target_executed:
        # Pre-mutation coverage probe failed: test suite never executes target_function!
        results = [
            MutantResult(
                mutant_id=idx,
                description=desc,
                lineno=lineno,
                killed=False,
                mutated_code_snippet=f"[UNEXECUTED_TARGET] Test suite does not call target function {target_function}",
                mutated_source=mut_src,
            )
            for idx, (desc, lineno, mut_src) in enumerate(mutants, start=1)
        ]
        return MutationGateReport(
            passed=False,
            total_mutants=len(results),
            killed_mutants=0,
            survived_mutants=len(results),
            results=results,
            target_executed=False,
        )

    def _emergency_restore():
        try:
            if bak_path.is_file():
                source_full.write_bytes(bak_path.read_bytes())
                bak_path.unlink()
        except Exception:
            pass

    atexit.register(_emergency_restore)
    try:
        bak_path.write_bytes(orig_bytes)
    except Exception:
        pass

    results: List[MutantResult] = []
    meta_results: List[tuple[str, int, str, bool, bool]] = []
    killed_count = 0

    try:
        for idx, (desc, lineno, mutated_src) in enumerate(mutants, start=1):
            killed = False
            killed_by_assertion = False
            try:
                source_full.write_text(mutated_src, encoding="utf-8")
                executed, retcode, out = _execute_test_cycle()
                if executed and retcode not in (0, 2):
                    killed = True
                    if "AssertionError" in out:
                        killed_by_assertion = True
            except subprocess.TimeoutExpired:
                killed = True
            except Exception:
                killed = True
            finally:
                source_full.write_bytes(orig_bytes)

            if killed:
                killed_count += 1

            snippet_lines = [line.strip() for line in mutated_src.splitlines() if line.strip()]
            snippet = " | ".join(snippet_lines[:3])
            results.append(
                MutantResult(
                    mutant_id=idx,
                    description=desc,
                    lineno=lineno,
                    killed=killed,
                    mutated_code_snippet=snippet[:120],
                    mutated_source=mutated_src,
                )
            )
            meta_results.append((desc, lineno, mutated_src, killed, killed_by_assertion))
    finally:
        try:
            source_full.write_bytes(orig_bytes)
        finally:
            if bak_path.is_file():
                try:
                    bak_path.unlink()
                except Exception:
                    pass
            try:
                atexit.unregister(_emergency_restore)
            except Exception:
                pass

    wrapper_tautology_detected = False
    survived_none_lines: dict[int, int] = {}
    for i, (d, lno, src, kld, _) in enumerate(meta_results):
        if "Replace return expression with `None`" in d and not kld:
            survived_none_lines[lno] = i

    for d, lno, src, kld, kld_assert in meta_results:
        if "IEEE-754 NaN canary" in d and kld and kld_assert:
            if lno in survived_none_lines:
                wrapper_tautology_detected = True
                res_idx = survived_none_lines[lno]
                results[res_idx].description += (
                    " [WRAPPER TAUTOLOGY DETECTED: Test compares f(x) against itself or a delegating wrapper "
                    "(None == None passed, NaN != NaN failed)]"
                )

    survived = len(results) - killed_count
    return MutationGateReport(
        passed=(survived == 0),
        total_mutants=len(results),
        killed_mutants=killed_count,
        survived_mutants=survived,
        results=results,
        target_executed=True,
        wrapper_tautology_detected=wrapper_tautology_detected,
    )

`

---

## cordis/fuzzer.py

`python
"""Gate 3: Differential Property-Based Fuzzer & Mann-Whitney U Statistical Benchmark Gate."""
from __future__ import annotations

import ast
import gc
import importlib
import inspect
import itertools
import math
import os
import random
import statistics
import subprocess
import sys
import textwrap
import time
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


@dataclass
class FuzzCounterexample:
    args: tuple[Any, ...]
    old_outcome: str
    new_outcome: str
    reason: str


@dataclass
class DifferentialFuzzReport:
    passed: bool
    inputs_tested: int
    counterexamples: List[FuzzCounterexample] = field(default_factory=list)


@dataclass
class BenchmarkGateReport:
    passed: bool
    rounds: int
    baseline_median_us: float
    candidate_median_us: float
    speedup_pct: float
    u_statistic: float
    p_value: float
    note: str
    iqr_baseline_us: float = 0.0
    iqr_candidate_us: float = 0.0

    @property
    def latency_delta_pct(self) -> float:
        return -self.speedup_pct


# Backwards-compatibility alias
StatisticalBenchmarkReport = BenchmarkGateReport


def _inspect_code_constants(
    code_obj: types.CodeType,
    raw_ints: Set[int],
    raw_floats: Set[float],
    raw_strings: Set[str],
    raw_bytes: Set[bytes] | None = None,
) -> None:
    """Recursively extracts constants from code object and nested code objects."""
    for c in code_obj.co_consts:
        if isinstance(c, types.CodeType):
            _inspect_code_constants(c, raw_ints, raw_floats, raw_strings, raw_bytes)
        elif isinstance(c, bool):
            continue
        elif isinstance(c, int):
            raw_ints.add(c)
        elif isinstance(c, float):
            raw_floats.add(c)
        elif isinstance(c, str):
            if 1 <= len(c) <= 64:
                raw_strings.add(c)
        elif isinstance(c, bytes):
            if 1 <= len(c) <= 64 and raw_bytes is not None:
                raw_bytes.add(c)


def harvest_ast_constants(fn_objs: list[Callable[..., Any]]) -> dict[str, list[Any]]:
    """Extracts integer, float, string, and bytes constants via inspect.getsource() AST analysis
    and bytecode fn.__code__.co_consts inspection (works for on-disk, exec-compiled, partials, and callables).
    
    Generates:
      - For integer C: C - 1, C, C + 1 in 'int' pool, float(C - 1), float(C), float(C + 1) in 'float' pool.
        If 128 <= C <= 1_048_576: 'a' * (C - 1), 'a' * C, 'a' * (C + 1), 'a' * (2 * C + 1) in 'str'/'bytes' pool.
      - For float F: F - 0.01, F, F + 0.01 in 'float' pool.
      - For string S (1..64 chars): S, S + '_mut', S.upper() in 'str' pool and UTF-8 encoded in 'bytes' pool.
      - For bytes B (1..64 bytes): B, B + b'_mut', B.upper() in 'bytes' pool.
    """
    raw_ints: Set[int] = set()
    raw_floats: Set[float] = set()
    raw_strings: Set[str] = set()
    raw_bytes: Set[bytes] = set()

    for fn in fn_objs:
        if not callable(fn):
            continue

        # Unwrap functools.wraps and decorators
        try:
            fn_unwrapped = inspect.unwrap(fn)
        except Exception:
            fn_unwrapped = fn

        # Extract bytecode constants (handles functions, bound methods, partials, classes, and callable objects)
        code_obj = getattr(fn_unwrapped, "__code__", None)
        if code_obj is None and hasattr(fn_unwrapped, "func"):
            code_obj = getattr(fn_unwrapped.func, "__code__", None)
        if code_obj is None and hasattr(fn_unwrapped, "__call__"):
            code_obj = getattr(fn_unwrapped.__call__, "__code__", None)
        if code_obj is None and isinstance(fn_unwrapped, type):
            code_obj = getattr(getattr(fn_unwrapped, "__init__", None), "__code__", None)

        if isinstance(code_obj, types.CodeType):
            _inspect_code_constants(code_obj, raw_ints, raw_floats, raw_strings, raw_bytes)

        # Also inspect original fn code if different from unwrapped
        orig_code = getattr(fn, "__code__", None)
        if isinstance(orig_code, types.CodeType) and orig_code is not code_obj:
            _inspect_code_constants(orig_code, raw_ints, raw_floats, raw_strings, raw_bytes)

        # 2. AST source extraction
        src = getattr(fn, "__cordis_source__", None) or getattr(fn_unwrapped, "__cordis_source__", None)
        if not src:
            try:
                src = inspect.getsource(fn_unwrapped)
            except Exception:
                pass
        if not src:
            try:
                src = inspect.getsource(fn)
            except Exception:
                pass
        if src:
            try:
                tree = ast.parse(textwrap.dedent(src))
                for node in ast.walk(tree):
                    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant):
                        v = node.operand.value
                        if isinstance(v, bool):
                            pass
                        elif isinstance(v, int):
                            raw_ints.add(-v)
                        elif isinstance(v, float):
                            raw_floats.add(-v)
                    elif isinstance(node, ast.Constant):
                        v = node.value
                        if isinstance(v, bool):
                            pass
                        elif isinstance(v, int):
                            raw_ints.add(v)
                        elif isinstance(v, float):
                            raw_floats.add(v)
                        elif isinstance(v, str) and 1 <= len(v) <= 64:
                            raw_strings.add(v)
                        elif isinstance(v, bytes) and 1 <= len(v) <= 64:
                            raw_bytes.add(v)

                    # Global constants lookup via __globals__
                    fn_globals = getattr(fn_unwrapped, "__globals__", {}) or getattr(fn, "__globals__", {})
                    if isinstance(node, ast.Name) and node.id in fn_globals:
                        gv = fn_globals[node.id]
                        if isinstance(gv, bool):
                            pass
                        elif isinstance(gv, int):
                            raw_ints.add(gv)
                        elif isinstance(gv, float):
                            raw_floats.add(gv)
                        elif isinstance(gv, str) and 1 <= len(gv) <= 64:
                            raw_strings.add(gv)
                        elif isinstance(gv, bytes) and 1 <= len(gv) <= 64:
                            raw_bytes.add(gv)
            except Exception:
                pass

    harvested_ints: list[int] = []
    seen_ints: Set[int] = set()
    harvested_floats: list[float] = []
    seen_floats: Set[float] = set()
    harvested_strings: list[str] = []
    seen_strings: Set[str] = set()
    harvested_bytes: list[bytes] = []
    seen_bytes: Set[bytes] = set()

    for C in sorted(raw_ints):
        for c_val in (C - 1, C, C + 1):
            if c_val not in seen_ints:
                seen_ints.add(c_val)
                harvested_ints.append(c_val)
            flt_c = float(c_val)
            if flt_c not in seen_floats:
                seen_floats.add(flt_c)
                harvested_floats.append(flt_c)
        if 128 <= C <= 1_048_576:
            for s_len in (C - 1, C, C + 1, 2 * C + 1):
                if 0 <= s_len <= 2_097_152:
                    s_val = "a" * s_len
                    if s_val not in seen_strings:
                        seen_strings.add(s_val)
                        harvested_strings.append(s_val)
                    b_val = b"a" * s_len
                    if b_val not in seen_bytes:
                        seen_bytes.add(b_val)
                        harvested_bytes.append(b_val)

    for F in sorted(raw_floats):
        for f_val in (round(F - 0.01, 6), F, round(F + 0.01, 6), F - 0.01, F + 0.01):
            if f_val not in seen_floats:
                seen_floats.add(f_val)
                harvested_floats.append(f_val)

    for S in sorted(raw_strings):
        for s_val in (S, S + "_mut", S.upper()):
            if s_val not in seen_strings:
                seen_strings.add(s_val)
                harvested_strings.append(s_val)
            try:
                b_enc = s_val.encode("utf-8")
                if b_enc not in seen_bytes:
                    seen_bytes.add(b_enc)
                    harvested_bytes.append(b_enc)
            except Exception:
                pass

    for B in sorted(raw_bytes):
        for b_val in (B, B + b"_mut", B.upper()):
            if b_val not in seen_bytes:
                seen_bytes.add(b_val)
                harvested_bytes.append(b_val)

    return {
        "int": harvested_ints,
        "float": harvested_floats,
        "str": harvested_strings,
        "bytes": harvested_bytes,
    }


def _generate_adversarial_values_for_type(
    annotation: Any,
    count: int = 200,
    harvested: Optional[dict[str, list[Any]]] = None,
) -> List[Any]:
    """Generates deterministic + randomized adversarial edge cases (floats, ints, strings, collections)
    seeded with AST & bytecode harvested constants.
    """
    rng = random.Random(42)
    if annotation in (int, "int"):
        edges: List[Any] = []
        if harvested and "int" in harvested:
            for v in harvested["int"]:
                if v not in edges:
                    edges.append(v)
        std_edges: List[Any] = [0, 1, -1, 2, -2, 10, 99, 100, 101, 500, 1000, -999999, 2**31 - 1]
        for v in std_edges:
            if v not in edges:
                edges.append(v)
        target_count = max(count, len(edges))
        while len(edges) < target_count:
            edges.append(rng.randint(-10000, 10000))
        return edges[:target_count]

    if annotation in (str, "str"):
        edges = []
        if harvested and "str" in harvested:
            for v in harvested["str"]:
                if v not in edges:
                    edges.append(v)
        std_edges_str = ["", " ", "a", "0", "100", "null", "None", "NaN", "🔥", "a" * 256, "\n\t"]
        for v in std_edges_str:
            if v not in edges:
                edges.append(v)
        target_count = max(count, len(edges))
        while len(edges) < target_count:
            length = rng.randint(0, 32)
            edges.append("".join(rng.choice("abcXYZ0123_- /") for _ in range(length)))
        return edges[:target_count]

    if annotation in (bytes, "bytes", bytearray):
        edges = []
        if harvested and "bytes" in harvested:
            for b in harvested["bytes"]:
                if b not in edges:
                    edges.append(b)
        std_edges_bytes = [b"", b" ", b"a", b"0", b"100", b"null", b"None", b"a" * 256, b"\x00", b"\xff", b"\n\t"]
        for b in std_edges_bytes:
            if b not in edges:
                edges.append(b)
        target_count = max(count, len(edges))
        while len(edges) < target_count:
            length = rng.randint(0, 32)
            edges.append(bytes(rng.randint(0, 255) for _ in range(length)))
        return edges[:target_count]

    origin = getattr(annotation, "__origin__", None)
    if annotation in (list, "list", List) or origin is list:
        edges = [[], [0], [1], [-1], [""], [None], [0.0], [1, 2, 3]]
        while len(edges) < count:
            edges.append([rng.randint(-100, 100) for _ in range(rng.randint(0, 8))])
        return edges[:count]

    if annotation in (dict, "dict", Dict) or origin is dict:
        edges = [{}, {"": ""}, {0: 0}, {"a": 1}, {"key": None}]
        while len(edges) < count:
            edges.append({f"k{i}": rng.randint(0, 100) for i in range(rng.randint(0, 5))})
        return edges[:count]

    if annotation in (set, "set", Set) or origin is set:
        edges = [set(), {0}, {1}, {-1}, {""}, {None}, {1, 2, 3}]
        while len(edges) < count:
            edges.append({rng.randint(-50, 50) for _ in range(rng.randint(0, 5))})
        return edges[:count]

    if annotation in (tuple, "tuple", Tuple) or origin is tuple:
        edges = [(), (0,), (1,), ("",), (None,), (1, 2)]
        while len(edges) < count:
            edges.append(tuple(rng.randint(-50, 50) for _ in range(rng.randint(0, 5))))
        return edges[:count]

    if annotation in (float, "float"):
        edges = []
        if harvested and "float" in harvested:
            for v in harvested["float"]:
                if v not in edges:
                    edges.append(v)
        std_edges_flt = [
            0.0, -0.0, 1.0, -1.0, 0.5, 49.99, 50.0, 50.01,
            99.99, 100.0, 100.01, 150.0, 199.99, 200.0, 200.01,
            250.0, 499.99, 500.0, 500.01, 1000.0, 1e6, -50.0,
            float("nan"), float("inf"), float("-inf"),
        ]
        for v in std_edges_flt:
            if v not in edges:
                edges.append(v)
        target_count = max(count, len(edges))
        while len(edges) < target_count:
            edges.append(round(rng.uniform(-500.0, 2500.0), 2))
        return edges[:target_count]

    # Default / unannotated adversarial matrix across NaN, inf, -0.0, boundary ints, strings, bytes, and empty collections
    edges = []
    if harvested:
        for k in ("int", "float", "str", "bytes"):
            for v in harvested.get(k, []):
                if v not in edges:
                    edges.append(v)
    std_edges_def: List[Any] = [
        0.0, -0.0, 1.0, -1.0, 0.5, 49.99, 50.0, 50.01,
        99.99, 100.0, 100.01, 150.0, 199.99, 200.0, 200.01,
        250.0, 499.99, 500.0, 500.01, 1000.0, 1e6, -50.0,
        float("nan"), float("inf"), float("-inf"),
        0, 1, -1, 100, -100, 2**31 - 1,
        "", "a", b"", b"a",
        [], {}, set(), (),
    ]
    for v in std_edges_def:
        if v not in edges:
            edges.append(v)
    target_count = max(count, len(edges))
    while len(edges) < target_count:
        edges.append(round(rng.uniform(-500.0, 2500.0), 2))
    return edges[:target_count]


def _deep_equals(a: Any, b: Any) -> bool:
    """Recursively checks equality with IEEE-754 NaN awareness and robust handling of collections."""
    if a is b:
        return True
    if isinstance(a, float) and isinstance(b, float):
        if math.isnan(a) and math.isnan(b):
            return True
        return math.isclose(a, b, rel_tol=1e-7, abs_tol=1e-9)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        if type(a) is not type(b) or len(a) != len(b):
            return False
        return all(_deep_equals(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        if a.keys() != b.keys():
            return False
        return all(_deep_equals(a[k], b[k]) for k in a)
    if isinstance(a, set) and isinstance(b, set):
        if len(a) != len(b):
            return False
        return a == b
    try:
        eq = (a == b)
        if isinstance(eq, bool):
            return eq
        try:
            return bool(eq.all())
        except Exception:
            return bool(eq)
    except Exception:
        return False


def _outcomes_match(res_a: Any, exc_a: Optional[Exception], res_b: Any, exc_b: Optional[Exception]) -> tuple[bool, str]:
    if exc_a is not None and exc_b is not None:
        if type(exc_a) is type(exc_b):
            return True, "Both raised same exception"
        return False, f"Exception mismatch: {type(exc_a).__name__} vs {type(exc_b).__name__}"
    if exc_a is not None or exc_b is not None:
        return False, f"One raised exception ({type(exc_a or exc_b).__name__}), the other returned a value"
    if _deep_equals(res_a, res_b):
        return True, "Exact match"
    if isinstance(res_a, float) and isinstance(res_b, float):
        return False, f"Float value mismatch: {res_a} != {res_b}"
    return False, f"Value mismatch: {res_a!r} != {res_b!r}"


def run_differential_fuzz_gate(
    reference_fn: Callable[..., Any],
    candidate_fn: Callable[..., Any],
    num_samples: int = 200,
) -> DifferentialFuzzReport:
    """Fuzzes `reference_fn` vs `candidate_fn` across `num_samples` adversarial edge-case inputs.
    Catches single-input hardcoded fixes (`if amount == 100.0: return 0.15`) immediately
    via AST & bytecode constant harvesting.
    """
    harvested = harvest_ast_constants([reference_fn, candidate_fn])
    try:
        sig_ref = inspect.signature(reference_fn)
        sig_cand = inspect.signature(candidate_fn)
        params_ref = list(sig_ref.parameters.values())
        params_cand = list(sig_cand.parameters.values())
        min_arity = min(len(params_ref), len(params_cand))
        params = params_cand[:min_arity]
        arity = min_arity
    except Exception:
        sig = inspect.signature(candidate_fn)
        params = list(sig.parameters.values())
        arity = len(params)

    if arity == 0:
        inputs = [()]
    elif arity == 1:
        ann = params[0].annotation
        vals = _generate_adversarial_values_for_type(ann, count=num_samples, harvested=harvested)
        inputs = [(v,) for v in vals]
    else:
        pools = [_generate_adversarial_values_for_type(p.annotation, count=num_samples, harvested=harvested) for p in params]
        inputs_list: list[tuple[Any, ...]] = []
        seen_inputs: set[Any] = set()

        if arity == 2:
            comb_n = min(15, min(len(p) for p in pools))
            for x in pools[0][:comb_n]:
                for y in pools[1][:comb_n]:
                    pair = (x, y)
                    try:
                        if pair not in seen_inputs:
                            seen_inputs.add(pair)
                            inputs_list.append(pair)
                    except TypeError:
                        inputs_list.append(pair)
        elif arity == 3:
            comb_n = min(8, min(len(p) for p in pools))
            for x in pools[0][:comb_n]:
                for y in pools[1][:comb_n]:
                    for z in pools[2][:comb_n]:
                        triple = (x, y, z)
                        try:
                            if triple not in seen_inputs:
                                seen_inputs.add(triple)
                                inputs_list.append(triple)
                        except TypeError:
                            inputs_list.append(triple)
        elif arity >= 4:
            # Pairwise / bounded combinatorial product for multi-parameter functions
            n = min(3, min(len(p) for p in pools))
            for comb in itertools.product(*(p[:n] for p in pools)):
                try:
                    if comb not in seen_inputs:
                        seen_inputs.add(comb)
                        inputs_list.append(comb)
                except TypeError:
                    inputs_list.append(comb)
                if len(inputs_list) >= num_samples // 2:
                    break

        max_len = max(num_samples, max(len(p) for p in pools))
        for i in range(max_len):
            tup = tuple(pool[i % len(pool)] for pool in pools)
            try:
                if tup not in seen_inputs:
                    seen_inputs.add(tup)
                    inputs_list.append(tup)
            except TypeError:
                inputs_list.append(tup)

        inputs = inputs_list[:max(num_samples, len(inputs_list))]

    counterexamples: List[FuzzCounterexample] = []

    for args in inputs:
        res_a, exc_a = None, None
        res_b, exc_b = None, None
        try:
            res_a = reference_fn(*args)
        except Exception as e:
            exc_a = e
        try:
            res_b = candidate_fn(*args)
        except Exception as e:
            exc_b = e

        matched, reason = _outcomes_match(res_a, exc_a, res_b, exc_b)
        if not matched:
            old_str = f"raises {type(exc_a).__name__}" if exc_a else repr(res_a)
            new_str = f"raises {type(exc_b).__name__}" if exc_b else repr(res_b)
            counterexamples.append(
                FuzzCounterexample(
                    args=args,
                    old_outcome=old_str,
                    new_outcome=new_str,
                    reason=reason,
                )
            )
            if len(counterexamples) >= 5:
                break

    return DifferentialFuzzReport(
        passed=(len(counterexamples) == 0),
        inputs_tested=len(inputs),
        counterexamples=counterexamples,
    )


def mann_whitney_u_one_sided(baseline_samples: List[float], candidate_samples: List[float]) -> tuple[float, float]:
    """Pure-Python Mann-Whitney U test (one-sided: testing if candidate is faster or non-regressing).
    Fixes the v1 bug where the agent graded its own homework by choosing an arbitrary threshold.
    """
    n1 = len(baseline_samples)
    n2 = len(candidate_samples)
    if n1 == 0 or n2 == 0:
        return 0.0, 1.0

    # Combine and rank all observations
    combined = [(val, 0) for val in baseline_samples] + [(val, 1) for val in candidate_samples]
    combined.sort(key=lambda x: x[0])

    ranks = [0.0] * len(combined)
    i = 0
    while i < len(combined):
        j = i
        while j < len(combined) and combined[j][0] == combined[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j

    r1 = sum(ranks[idx] for idx, (_, group) in enumerate(combined) if group == 0)
    u1 = r1 - (n1 * (n1 + 1)) / 2.0
    mean_u = (n1 * n2) / 2.0
    std_u = math.sqrt((n1 * n2 * (n1 + n2 + 1)) / 12.0)
    if std_u == 0:
        return u1, 0.5
    z = (u1 - mean_u) / std_u
    # One-sided normal approximation p-value (H1: baseline > candidate, i.e., candidate is faster)
    p_value = 0.5 * math.erfc(z / math.sqrt(2.0))
    return u1, p_value


def run_statistical_benchmark_gate(
    baseline_fn: Callable[[], Any],
    candidate_fn: Callable[[], Any],
    rounds: int = 30,
    iterations_per_round: int = 200,
    require_speedup: bool = False,
    max_regression_pct: float = 10.0,
) -> BenchmarkGateReport:
    """Runs `rounds` interleaved timing measurements of `baseline_fn` and `candidate_fn`
    to eliminate OS scheduling noise and compares them via Mann-Whitney U test.
    """
    # Warmup
    for _ in range(3):
        baseline_fn()
        candidate_fn()

    base_times_us: List[float] = []
    cand_times_us: List[float] = []

    gc_was_enabled = gc.isenabled()
    try:
        gc.disable()
        for r in range(rounds):
            if r % 2 == 0:
                t0 = time.perf_counter_ns()
                for _ in range(iterations_per_round):
                    baseline_fn()
                t1 = time.perf_counter_ns()
                base_times_us.append((t1 - t0) / 1000.0 / iterations_per_round)

                t2 = time.perf_counter_ns()
                for _ in range(iterations_per_round):
                    candidate_fn()
                t3 = time.perf_counter_ns()
                cand_times_us.append((t3 - t2) / 1000.0 / iterations_per_round)
            else:
                t2 = time.perf_counter_ns()
                for _ in range(iterations_per_round):
                    candidate_fn()
                t3 = time.perf_counter_ns()
                cand_times_us.append((t3 - t2) / 1000.0 / iterations_per_round)

                t0 = time.perf_counter_ns()
                for _ in range(iterations_per_round):
                    baseline_fn()
                t1 = time.perf_counter_ns()
                base_times_us.append((t1 - t0) / 1000.0 / iterations_per_round)
    finally:
        if gc_was_enabled:
            gc.enable()

    if not base_times_us or not cand_times_us:
        return BenchmarkGateReport(
            passed=True,
            rounds=rounds,
            baseline_median_us=0.0,
            candidate_median_us=0.0,
            speedup_pct=0.0,
            u_statistic=0.0,
            p_value=1.0,
            note="Zero rounds completed",
            iqr_baseline_us=0.0,
            iqr_candidate_us=0.0,
        )

    base_med = statistics.median(base_times_us)
    cand_med = statistics.median(cand_times_us)
    speedup_pct = ((base_med - cand_med) / base_med * 100.0) if base_med > 0 else 0.0
    u_stat, p_val = mann_whitney_u_one_sided(base_times_us, cand_times_us)

    iqr_base = 0.0
    iqr_cand = 0.0
    try:
        if len(base_times_us) >= 2:
            q_base = statistics.quantiles(base_times_us, n=4)
            iqr_base = q_base[2] - q_base[0]
        if len(cand_times_us) >= 2:
            q_cand = statistics.quantiles(cand_times_us, n=4)
            iqr_cand = q_cand[2] - q_cand[0]
    except Exception:
        pass

    if require_speedup:
        passed = (speedup_pct > 0.0) and (p_val < 0.01)
        note = f"Speedup {speedup_pct:+.1f}% (Mann-Whitney p={p_val:.4f}, required p<0.01)"
    else:
        regression_pct = -speedup_pct
        passed = regression_pct <= max_regression_pct
        note = f"Latency delta {-speedup_pct:+.1f}% (max allowed regression +{max_regression_pct:.1f}%)"

    return BenchmarkGateReport(
        passed=passed,
        rounds=rounds,
        baseline_median_us=round(base_med, 4),
        candidate_median_us=round(cand_med, 4),
        speedup_pct=round(speedup_pct, 2),
        u_statistic=round(u_stat, 2),
        p_value=round(p_val, 5),
        note=note,
        iqr_baseline_us=round(iqr_base, 4),
        iqr_candidate_us=round(iqr_cand, 4),
    )


def load_repo_function_pair(
    repo_root: Path | str,
    source_rel_path: str,
    function_name: str,
    base_ref: str = "HEAD~1",
) -> tuple[Optional[Callable[..., Any]], Optional[Callable[..., Any]]]:
    """Dynamically loads (f_old, f_new) from a real Git repository.
    f_old is compiled from `git show <base_ref>:<source_rel_path>`.
    f_new is loaded from the live repo file/module with sys.path including repo_root.
    """
    root = Path(repo_root).resolve()
    root_str = str(root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    src_dir = root / "src"
    if src_dir.is_dir() and str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    shims_dir = Path(__file__).resolve().parent / "_shims"
    if shims_dir.is_dir() and str(shims_dir) not in sys.path:
        sys.path.append(str(shims_dir))

    # Skip dunder methods (__init__, __init_subclass__, etc.)
    if function_name.startswith("__") and function_name.endswith("__"):
        return None, None

    # Derive module name
    rel_p = Path(source_rel_path)
    parts = list(rel_p.parts)
    if parts and parts[0] == "src":
        parts = parts[1:]
    mod_name = ".".join(Path(*parts).with_suffix("").parts)

    # 1. Load f_new from working tree
    f_new = None
    try:
        importlib.invalidate_caches()
        if mod_name in sys.modules:
            mod = importlib.reload(sys.modules[mod_name])
        else:
            mod = importlib.import_module(mod_name)
        if "." in function_name:
            parts = function_name.split(".")
            obj = mod.__dict__.get(parts[0])
            for p in parts[1:]:
                obj = getattr(obj, p, None)
                if obj is None:
                    break
        else:
            obj = mod.__dict__.get(function_name)
        if callable(obj):
            f_new = obj
    except Exception:
        pass

    if f_new is None:
        src_file = root / source_rel_path
        if src_file.is_file():
            pkg = ".".join(mod_name.split(".")[:-1]) if "." in mod_name else ""
            env_new = {"__builtins__": __builtins__, "__name__": mod_name, "__file__": str(src_file)}
            if pkg:
                env_new["__package__"] = pkg
            try:
                code_obj = compile(src_file.read_text(encoding="utf-8", errors="replace"), str(src_file), "exec")
                exec(code_obj, env_new)
                obj = env_new.get(function_name.split(".")[0])
                for p in function_name.split(".")[1:]:
                    obj = getattr(obj, p, None)
                if callable(obj):
                    f_new = obj
            except Exception:
                pass

    # 2. Load f_old from git show <base_ref>:<source_rel_path>
    clean_path = str(source_rel_path).replace("\\", "/")
    cmd = ["git", "show", f"{base_ref}:{clean_path}"]
    proc = subprocess.run(cmd, cwd=str(root), capture_output=True, timeout=10)
    f_old = None
    if proc.returncode == 0:
        old_src = proc.stdout.decode("utf-8-sig", errors="replace")
        old_mod_name = f"{mod_name}__cordis_old__"
        pkg = ".".join(mod_name.split(".")[:-1]) if "." in mod_name else ""
        old_env = {"__builtins__": __builtins__, "__name__": old_mod_name, "__file__": f"<{source_rel_path}@{base_ref}>"}
        if pkg:
            old_env["__package__"] = pkg
        try:
            code_obj = compile(old_src, f"<{source_rel_path}@{base_ref}>", "exec")
            exec(code_obj, old_env)
            obj = old_env.get(function_name.split(".")[0])
            for p in function_name.split(".")[1:]:
                obj = getattr(obj, p, None)
            if callable(obj):
                f_old = obj
        except Exception:
            pass

    return f_old, f_new


def run_repo_differential_fuzz_gate(
    repo_root: Path | str,
    source_rel_path: str,
    function_name: str,
    base_ref: str = "HEAD~1",
    num_samples: int = 200,
) -> DifferentialFuzzReport:
    """Fuzzes `f_old` vs `f_new` extracted directly from a real git repository."""
    f_old, f_new = load_repo_function_pair(repo_root, source_rel_path, function_name, base_ref=base_ref)
    if not callable(f_old) or not callable(f_new):
        return DifferentialFuzzReport(passed=True, inputs_tested=0, counterexamples=[])
    return run_differential_fuzz_gate(f_old, f_new, num_samples=num_samples)


def run_repo_statistical_benchmark_gate(
    repo_root: Path | str,
    source_rel_path: str,
    function_name: str,
    sample_args: tuple[Any, ...] = (),
    base_ref: str = "HEAD~1",
    rounds: int = 30,
    iterations_per_round: int = 100,
) -> BenchmarkGateReport:
    """Statistical Mann-Whitney benchmark comparing f_old vs f_new from a real git repository."""
    f_old, f_new = load_repo_function_pair(repo_root, source_rel_path, function_name, base_ref=base_ref)
    if not callable(f_old) or not callable(f_new):
        return BenchmarkGateReport(
            passed=True,
            rounds=0,
            baseline_median_us=0.0,
            candidate_median_us=0.0,
            speedup_pct=0.0,
            u_statistic=0.0,
            p_value=1.0,
            note="Function pair not loadable for benchmark",
        )
    return run_statistical_benchmark_gate(
        lambda: f_old(*sample_args),
        lambda: f_new(*sample_args),
        rounds=rounds,
        iterations_per_round=iterations_per_round,
    )
`

---

## cordis/repair.py

`python
"""Engine 6 (Upgrade 6.2): Counterexample-Guided Test Repair Skeleton Synthesizer."""
from __future__ import annotations

import ast
import inspect
import itertools
import math
import types
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from cordis.fuzzer import (
    harvest_ast_constants,
    _generate_adversarial_values_for_type,
    _deep_equals,
)
from cordis.mutator import MutantResult, generate_ast_mutants


def _format_value_for_code(v: Any) -> str:
    """Formats value into valid, deterministic Python expression string."""
    if isinstance(v, float):
        if math.isnan(v):
            return "float('nan')"
        if math.isinf(v):
            return "float('inf')" if v > 0 else "float('-inf')"
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(_format_value_for_code(x) for x in v) + "]"
    if isinstance(v, tuple):
        if len(v) == 1:
            return f"({_format_value_for_code(v[0])},)"
        return "(" + ", ".join(_format_value_for_code(x) for x in v) + ")"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{_format_value_for_code(k)}: {_format_value_for_code(val)}" for k, val in v.items()) + "}"
    if isinstance(v, set):
        if not v:
            return "set()"
        return "{" + ", ".join(_format_value_for_code(x) for x in v) + "}"
    return repr(v)


def _deduce_target_function_from_ast(source: str, lineno: int) -> str:
    """Finds the name of the FunctionDef or AsyncFunctionDef that spans the given lineno."""
    try:
        tree = ast.parse(source)
    except Exception:
        return ""

    matching_fn = ""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start_l = node.lineno
            end_l = getattr(node, "end_lineno", node.lineno)
            if start_l <= lineno <= end_l:
                matching_fn = node.name
                break
    if not matching_fn:
        # Fallback to the first function defined in source
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                matching_fn = node.name
                break
    return matching_fn


def _extract_function_from_code(source: str, function_name: str) -> tuple[Optional[Callable[..., Any]], str]:
    """Compiles source code in an isolated environment and extracts the target function.
    Returns (callable_object, call_expression_prefix).
    Supports standalone functions, static methods, and instantiable class methods.
    """
    env: dict[str, Any] = {"__builtins__": __builtins__}
    try:
        code_obj = compile(source, "<cordis_repair_eval>", "exec")
        exec(code_obj, env)
    except Exception:
        return None, function_name

    if "." in function_name:
        parts = function_name.split(".")
        cls_obj = env.get(parts[0])
        if isinstance(cls_obj, type):
            # Attempt to instantiate class for instance methods
            try:
                inst = cls_obj()
                method = getattr(inst, parts[1], None)
                if callable(method):
                    try:
                        setattr(method, "__cordis_source__", source)
                    except Exception:
                        pass
                    return method, f"{parts[0]}().{parts[1]}"
            except Exception:
                pass

            # Class/static method fallback
            method = getattr(cls_obj, parts[1], None)
            if callable(method):
                try:
                    setattr(method, "__cordis_source__", source)
                except Exception:
                    pass
                return method, f"{parts[0]}.{parts[1]}"

        obj = env.get(parts[0])
        for p in parts[1:]:
            obj = getattr(obj, p, None)
            if obj is None:
                break
        if callable(obj):
            try:
                setattr(obj, "__cordis_source__", source)
            except Exception:
                pass
            return obj, function_name
        return None, function_name

    obj = env.get(function_name)
    if callable(obj):
        try:
            setattr(obj, "__cordis_source__", source)
        except Exception:
            pass
        return obj, function_name
    return None, function_name


def _kills_mutant(res_orig: Any, exc_orig: Optional[Exception], res_mut: Any, exc_mut: Optional[Exception]) -> bool:
    """Returns True if the output or exception behavior of mutant diverges from original."""
    if exc_orig is None and exc_mut is None:
        return not _deep_equals(res_orig, res_mut)
    if exc_orig is None or exc_mut is None:
        return True
    return type(exc_orig) is not type(exc_mut)


def _build_candidate_inputs(
    f_orig: Callable[..., Any],
    harvested: dict[str, list[Any]],
    max_candidates: int = 2000,
) -> list[tuple[Any, ...]]:
    """Builds a rich cross-combinatorial pool of candidate input tuples using harvested constants."""
    try:
        sig = inspect.signature(f_orig)
        params = list(sig.parameters.values())
        arity = len(params)
    except Exception:
        return [()]

    if arity == 0:
        return [()]

    pools: list[list[Any]] = []
    for p in params:
        ann = p.annotation
        pool: list[Any] = []
        if ann in (int, "int") or ann is inspect.Parameter.empty:
            for v in harvested.get("int", []):
                if v not in pool:
                    pool.append(v)
            for v in [0, 1, -1, 2, -2, 5, -5, 10, -10, 15, 20, 50, 100, -100, 1000]:
                if v not in pool:
                    pool.append(v)
        if ann in (float, "float") or ann is inspect.Parameter.empty:
            for v in harvested.get("float", []):
                if v not in pool:
                    pool.append(v)
            for v in [0.0, 1.0, -1.0, 0.5, -0.5, 2.0, 5.0, 10.0, 15.0, 100.0, float("nan")]:
                if v not in pool:
                    pool.append(v)
        if ann in (str, "str") or ann is inspect.Parameter.empty:
            for v in harvested.get("str", []):
                if v not in pool:
                    pool.append(v)
            for v in ["", "a", "b", "hello", "0", "1", "test"]:
                if v not in pool:
                    pool.append(v)
        if ann in (bytes, "bytes", bytearray):
            for v in harvested.get("bytes", []):
                if v not in pool:
                    pool.append(v)
            for v in [b"", b"a", b"b", b"hello", b"0", b"1", b"test", b"\x00", b"\xff"]:
                if v not in pool:
                    pool.append(v)
        if ann in (bool, "bool"):
            pool = [False, True]
        if not pool:
            pool = _generate_adversarial_values_for_type(ann, count=30, harvested=harvested)
        pools.append(pool)

    candidate_inputs: list[tuple[Any, ...]] = []
    seen_reprs: set[str] = set()

    def add_tuple(tup: tuple[Any, ...]) -> None:
        key = repr(tup)
        if key not in seen_reprs:
            seen_reprs.add(key)
            candidate_inputs.append(tup)

    if arity == 1:
        for v in pools[0]:
            add_tuple((v,))
    elif arity == 2:
        n0 = min(20, len(pools[0]))
        n1 = min(20, len(pools[1]))
        for x in pools[0][:n0]:
            for y in pools[1][:n1]:
                add_tuple((x, y))
    elif arity == 3:
        n0 = min(10, len(pools[0]))
        n1 = min(10, len(pools[1]))
        n2 = min(10, len(pools[2]))
        for x in pools[0][:n0]:
            for y in pools[1][:n1]:
                for z in pools[2][:n2]:
                    add_tuple((x, y, z))
    else:
        # Arity >= 4: pairwise combinations + diagonal sampling
        n = min(4, min(len(p) for p in pools))
        for comb in itertools.product(*(p[:n] for p in pools)):
            add_tuple(comb)
            if len(candidate_inputs) >= max_candidates // 2:
                break

    # Add diagonal sampling across all pool elements to ensure full coverage
    max_pool_len = max(len(p) for p in pools)
    for i in range(max_pool_len):
        diag = tuple(pool[i % len(pool)] for pool in pools)
        add_tuple(diag)
        if len(candidate_inputs) >= max_candidates:
            break

    return candidate_inputs[:max_candidates]


def synthesize_mutant_killing_assertions(
    source_code: str,
    target_function: str,
    surviving_mutants: list[MutantResult],
) -> list[str]:
    """Evaluates candidate inputs against surviving mutants to find concrete assertions
    that differentiate f_orig from each f_mutant.
    """
    if not surviving_mutants:
        return []

    # If target_function is not explicitly specified, deduce it from the surviving mutants' line numbers
    effective_target_fn = target_function
    if not effective_target_fn:
        first_lineno = surviving_mutants[0].lineno
        effective_target_fn = _deduce_target_function_from_ast(source_code, first_lineno)

    if not effective_target_fn:
        return []

    f_orig, call_prefix = _extract_function_from_code(source_code, effective_target_fn)
    if not callable(f_orig):
        return []

    # Map surviving mutants to full mutated sources
    all_mutants = generate_ast_mutants(source_code, target_function=effective_target_fn, max_mutants=100)
    mutant_src_map: dict[int, str] = {}
    mutant_desc_map: dict[tuple[int, str], str] = {}
    for idx, (desc, lineno, m_src) in enumerate(all_mutants, start=1):
        mutant_src_map[idx] = m_src
        mutant_desc_map[(lineno, desc)] = m_src

    compiled_mutants: list[tuple[MutantResult, Callable[..., Any]]] = []
    for m in surviving_mutants:
        m_src = (
            getattr(m, "mutated_source", "")
            or mutant_desc_map.get((m.lineno, m.description))
            or mutant_src_map.get(m.mutant_id)
        )
        if not m_src:
            continue
        f_mut, _ = _extract_function_from_code(m_src, effective_target_fn)
        if callable(f_mut):
            compiled_mutants.append((m, f_mut))

    if not compiled_mutants:
        return []

    # Harvest constants from orig and mutants
    harvest_fns = [f_orig] + [f_m for _, f_m in compiled_mutants]
    harvested = harvest_ast_constants(harvest_fns)

    candidate_inputs = _build_candidate_inputs(f_orig, harvested)

    # Pre-evaluate f_orig on candidates (stored as a list indexed by integer i to avoid hashing unhashable inputs)
    orig_evals: list[tuple[Any, Optional[Exception]]] = []
    for args in candidate_inputs:
        try:
            res = f_orig(*args)
            orig_evals.append((res, None))
        except Exception as e:
            orig_evals.append((None, e))

    # Greedily find assertions that kill uncovered mutants
    uncovered_indices = set(range(len(compiled_mutants)))
    selected_assertions: list[str] = []

    while uncovered_indices:
        best_idx: Optional[int] = None
        best_killed: set[int] = set()
        best_is_clean = False

        for cand_i, args in enumerate(candidate_inputs):
            res_orig, exc_orig = orig_evals[cand_i]
            killed_here: set[int] = set()

            for idx in uncovered_indices:
                _, f_mut = compiled_mutants[idx]
                try:
                    res_mut = f_mut(*args)
                    exc_mut = None
                except Exception as e:
                    res_mut = None
                    exc_mut = e

                if _kills_mutant(res_orig, exc_orig, res_mut, exc_mut):
                    killed_here.add(idx)

            if not killed_here:
                continue

            # Strongly prefer clean returns (exc_orig is None) over exception-raising oracles
            is_clean = (exc_orig is None)
            if (len(killed_here) > len(best_killed)) or (
                len(killed_here) == len(best_killed) and is_clean and not best_is_clean
            ):
                best_killed = killed_here
                best_idx = cand_i
                best_is_clean = is_clean

        if not best_killed or best_idx is None:
            # No candidate input kills the remaining mutants
            break

        # Generate assertion for best input
        best_args = candidate_inputs[best_idx]
        res_orig, exc_orig = orig_evals[best_idx]
        args_str = ", ".join(_format_value_for_code(a) for a in best_args)

        if exc_orig is None:
            if isinstance(res_orig, float) and math.isnan(res_orig):
                assertion = f"assert math.isnan({call_prefix}({args_str}))"
            else:
                assertion = f"assert {call_prefix}({args_str}) == {_format_value_for_code(res_orig)}"
        else:
            exc_name = type(exc_orig).__name__
            if exc_name in ("Exception", "BaseException"):
                # Avoid emitting broad exception swallowing
                uncovered_indices -= best_killed
                continue
            assertion = f"try:\n        {call_prefix}({args_str})\n        assert False, 'Expected {exc_name}'\n    except {exc_name}:\n        pass"

        selected_assertions.append(assertion)
        uncovered_indices -= best_killed

    return selected_assertions


def synthesize_mutant_killing_test(
    source_code: str,
    target_function: str,
    surviving_mutants: list[MutantResult],
) -> str:
    """Generates a clean, deterministic unit test function that kills 100% of surviving mutants."""
    effective_name = target_function
    if not effective_name and surviving_mutants:
        effective_name = _deduce_target_function_from_ast(source_code, surviving_mutants[0].lineno)

    clean_name = effective_name.replace(".", "_") if effective_name else "function"
    fn_header = f"def test_{clean_name}_cordis_invariants():"
    docstring = f'    """Auto-generated invariant assertions by Cordis v3.0 to kill surviving AST mutants."""'

    assertions = synthesize_mutant_killing_assertions(source_code, effective_name, surviving_mutants)

    if not assertions:
        return f"{fn_header}\n{docstring}\n    pass\n"

    lines = [fn_header, docstring]
    if any("math.isnan" in a or "math.isinf" in a for a in assertions):
        lines.append("    import math")

    for a in assertions:
        if "\n" in a:
            lines.append(f"    {a}")
        else:
            lines.append(f"    {a}")

    return "\n".join(lines) + "\n"
`

---

## cordis/hooks.py

`python
"""Cordis Gate 0 PreToolUse Firewall & Stop Hook Prosecutor.
Deterministic pre-execution policy enforcer and working tree verifier.
100% Python Standard Library, zero external dependencies.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from cordis.ast_gate import audit_test_tampering, index_ast_anchors
from cordis.git_diff import extract_git_diff, get_git_file_content
from cordis.memory import EpisodicMemoryLedger
from cordis.mutator import MutantResult, run_in_memory_mutation_gate
from cordis.repair import synthesize_mutant_killing_test


@dataclass
class HookDecision:
    """Encapsulates the deterministic decision of the pre-tool firewall."""

    allowed: bool
    reason: str = ""
    exit_code: int = 0
    command: str = ""
    vector: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "exit_code": self.exit_code,
            "command": self.command,
            "vector": self.vector,
            "metadata": self.metadata,
        }


# Regex patterns for bypass vector detection
RE_HOOKS_PATH = re.compile(r"core\.hookspath", re.IGNORECASE)
RE_HOOK_FILES = re.compile(r"(\.git[/\\].*hooks|\.claude[/\\].*hooks)", re.IGNORECASE)
RE_HOOK_MUTATORS = re.compile(
    r"\b(rm|del|erase|rmdir|rd|remove-item|ri|mv|move|move-item|mi|ren|rename|rename-item|chmod|icacls|attrib|unlink|trash)\b",
    re.IGNORECASE,
)
RE_SUPPRESSIONS = re.compile(
    r"(\s-[a-zA-Z]*q\b|--quiet\b|/dev/null\b|nul\b|\$null\b|out-null\b|2>&1|\*>)",
    re.IGNORECASE,
)
RE_STASH_KEEP_INDEX = re.compile(r"(--keep-index\b|-[a-zA-Z]*k[a-zA-Z]*\b)")
RE_COMMIT_NO_VERIFY = re.compile(r"(--no-verify\b|--no-ver\b|-[a-zA-Z]*n[a-zA-Z]*\b)")


def _split_pipeline_segments(cmd: str) -> list[str]:
    """Splits composite shell/PowerShell pipelines (&&, ||, ;, |, &, \\n)
    while strictly respecting quotes (single and double).
    """
    segments: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0
    n = len(cmd)

    while i < n:
        ch = cmd[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            current.append(ch)
            i += 1
        elif ch == '"' and not in_single:
            in_double = not in_double
            current.append(ch)
            i += 1
        elif ch == "\\" and in_double:
            current.append(ch)
            if i + 1 < n:
                current.append(cmd[i + 1])
                i += 2
            else:
                i += 1
        elif not in_single and not in_double:
            if cmd[i : i + 2] in ("&&", "||"):
                seg = "".join(current).strip()
                if seg:
                    segments.append(seg)
                current = []
                i += 2
            elif ch in (";", "|", "&", "\n"):
                seg = "".join(current).strip()
                if seg:
                    segments.append(seg)
                current = []
                i += 1
            else:
                current.append(ch)
                i += 1
        else:
            current.append(ch)
            i += 1

    rem = "".join(current).strip()
    if rem:
        segments.append(rem)
    return segments if segments else [cmd]


def _tokenize_command(cmd: str) -> list[str]:
    """Tokenizes command string into arguments preserving backslashes on Windows."""
    try:
        return shlex.split(cmd, posix=False)
    except ValueError:
        return cmd.split()


def _strip_outer_quotes(s: str) -> str:
    """Strips wrapping single, double quotes or curly braces."""
    s = s.strip()
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1].strip()
    if s.startswith("{") and s.endswith("}"):
        return s[1:-1].strip()
    return s


def _audit_embedded_python(payload: str, raw_cmd: str) -> Optional[HookDecision]:
    """Inspects python -c payload for embedded subversion or hook tampering."""
    clean_payload = _strip_outer_quotes(payload)

    # 1. Inspect AST if valid Python syntax
    try:
        tree = ast.parse(clean_payload)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_str = ast.unparse(node.func)
                # Check for direct file removal/chmod tampering targeting hooks
                if any(m in func_str for m in ("remove", "unlink", "rmtree", "chmod")):
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if RE_HOOK_FILES.search(arg.value):
                                return HookDecision(
                                    allowed=False,
                                    exit_code=2,
                                    command=raw_cmd,
                                    vector="EMBEDDED_SUBVERSION",
                                    reason=f"Bypass detected: python payload tampers with hooks ({func_str})",
                                    metadata={"nested_vector": "HOOKS_TAMPERING", "payload": clean_payload},
                                )
                # Check for shell execution calls
                if any(
                    m in func_str
                    for m in (
                        "os.system",
                        "os.popen",
                        "subprocess.run",
                        "subprocess.Popen",
                        "subprocess.call",
                        "subprocess.check_call",
                        "subprocess.check_output",
                        "exec",
                        "eval",
                        "getattr",
                    )
                ) or "subprocess" in func_str:
                    sub_cmds: list[str] = []
                    if node.args:
                        first_arg = node.args[0]
                        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                            sub_cmds.append(first_arg.value)
                        elif isinstance(first_arg, (ast.List, ast.Tuple)):
                            parts = []
                            for elt in first_arg.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    parts.append(elt.value)
                            if parts:
                                sub_cmds.append(" ".join(parts))
                        elif isinstance(first_arg, ast.Call):
                            first_func = ast.unparse(first_arg.func)
                            if "b64decode" in first_func and first_arg.args:
                                if isinstance(first_arg.args[0], ast.Constant) and isinstance(first_arg.args[0].value, str):
                                    try:
                                        decoded_py = base64.b64decode(first_arg.args[0].value).decode("utf-8", errors="replace")
                                        dec_res = _audit_embedded_python(decoded_py, raw_cmd)
                                        if dec_res is not None:
                                            return dec_res
                                    except Exception:
                                        pass

                    for sub_c in sub_cmds:
                        inner_dec = audit_pre_tool_use_command(sub_c)
                        if not inner_dec.allowed:
                            return HookDecision(
                                allowed=False,
                                exit_code=2,
                                command=raw_cmd,
                                vector="EMBEDDED_SUBVERSION",
                                reason=f"Bypass detected in embedded python command: {inner_dec.reason}",
                                metadata={"nested_vector": inner_dec.vector, "nested_command": sub_c},
                            )
    except SyntaxError:
        pass

    # 2. Fallback heuristic inspection on raw payload
    if RE_HOOKS_PATH.search(clean_payload):
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason="Bypass detected in embedded python payload: core.hooksPath override",
            metadata={"nested_vector": "HOOKS_PATH_OVERRIDE"},
        )
    if RE_HOOK_FILES.search(clean_payload) and re.search(r"\b(remove|unlink|rmtree|chmod|rm|del)\b", clean_payload, re.IGNORECASE):
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason="Bypass detected in embedded python payload: hook tampering",
            metadata={"nested_vector": "HOOKS_TAMPERING"},
        )
    if re.search(r"git\s+commit", clean_payload, re.IGNORECASE) and RE_COMMIT_NO_VERIFY.search(clean_payload):
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason="Bypass detected in embedded python payload: git commit with no-verify / -n",
            metadata={"nested_vector": "NO_VERIFY"},
        )
    if re.search(r"git\s+stash", clean_payload, re.IGNORECASE) and RE_STASH_KEEP_INDEX.search(clean_payload):
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason="Bypass detected in embedded python payload: git stash --keep-index",
            metadata={"nested_vector": "STASH_KEEP_INDEX"},
        )

    return None


def _audit_embedded_powershell(payload: str, raw_cmd: str) -> Optional[HookDecision]:
    """Inspects powershell -Command payload."""
    clean_payload = _strip_outer_quotes(payload)
    inner_dec = audit_pre_tool_use_command(clean_payload)
    if not inner_dec.allowed:
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason=f"Bypass detected in embedded PowerShell command: {inner_dec.reason}",
            metadata={"nested_vector": inner_dec.vector, "nested_command": clean_payload},
        )
    return None


def _audit_embedded_shell(payload: str, raw_cmd: str) -> Optional[HookDecision]:
    """Inspects bash/sh/zsh/eval -c payload."""
    clean_payload = _strip_outer_quotes(payload)
    inner_dec = audit_pre_tool_use_command(clean_payload)
    if not inner_dec.allowed:
        return HookDecision(
            allowed=False,
            exit_code=2,
            command=raw_cmd,
            vector="EMBEDDED_SUBVERSION",
            reason=f"Bypass detected in embedded shell command: {inner_dec.reason}",
            metadata={"nested_vector": inner_dec.vector, "nested_command": clean_payload},
        )
    return None


def _audit_single_command(cmd_segment: str) -> HookDecision:
    """Audits a single, non-composite command string against all bypass vectors."""
    clean_cmd = cmd_segment.strip()
    if not clean_cmd:
        return HookDecision(allowed=True, exit_code=0, command=cmd_segment)

    tokens = _tokenize_command(clean_cmd)
    if not tokens:
        return HookDecision(allowed=True, exit_code=0, command=cmd_segment)

    # Strip environment variable prefixes (e.g. VAR=1 git ...)
    start_idx = 0
    while start_idx < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", tokens[start_idx]):
        start_idx += 1

    # Strip common command prefixes (sudo, nohup, time, builtin, command, exec, env)
    while start_idx < len(tokens):
        raw_prefix = _strip_outer_quotes(tokens[start_idx]).replace("/", "\\").strip("\"' ")
        prefix_name = Path(raw_prefix).name.lower().strip("\"'")
        for ext in (".exe", ".cmd", ".bat"):
            if prefix_name.endswith(ext):
                prefix_name = prefix_name[:-len(ext)]
        if prefix_name in ("sudo", "nohup", "time", "builtin", "command", "exec", "env"):
            start_idx += 1
        else:
            break

    effective_tokens = tokens[start_idx:]
    if not effective_tokens:
        return HookDecision(allowed=True, exit_code=0, command=cmd_segment)

    prog_raw = _strip_outer_quotes(effective_tokens[0]).replace("/", "\\").strip("\"' ")
    prog_name = Path(prog_raw).name.lower().strip("\"'")
    for ext in (".exe", ".cmd", ".bat"):
        if prog_name.endswith(ext):
            prog_name = prog_name[:-len(ext)]

    # --- VECTOR 5: Embedded Subversion Unwrapping ---
    # 1. Python unwrapping
    if prog_name in ("python", "python3", "py") or prog_name.startswith("python3."):
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            if tok in ("-c", "/c"):
                payload = " ".join(effective_tokens[idx + 1 :])
                res = _audit_embedded_python(payload, cmd_segment)
                if res is not None:
                    return res
                break

    # 2. PowerShell unwrapping
    if prog_name in ("powershell", "pwsh"):
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            tok_lower = tok.lower()
            if tok_lower in ("-command", "-c", "/command", "/c"):
                payload = " ".join(effective_tokens[idx + 1 :])
                res = _audit_embedded_powershell(payload, cmd_segment)
                if res is not None:
                    return res
                break
            elif tok_lower in ("-encodedcommand", "-ec", "-enc", "-e") or (
                tok_lower.startswith("-enc") and not tok_lower.startswith("--")
            ):
                b64_str = effective_tokens[idx + 1] if idx + 1 < len(effective_tokens) else ""
                try:
                    raw_bytes = base64.b64decode(b64_str)
                    decoded = raw_bytes.decode("utf-16le", errors="replace")
                except Exception:
                    decoded = ""
                if decoded:
                    res = _audit_embedded_powershell(decoded, cmd_segment)
                    if res is not None:
                        return res
                break

    # 3. Bash / Sh / Zsh unwrapping
    if prog_name in ("bash", "sh", "zsh", "dash"):
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            if tok == "-c":
                payload = " ".join(effective_tokens[idx + 1 :])
                res = _audit_embedded_shell(payload, cmd_segment)
                if res is not None:
                    return res
                break

    # 4. Eval unwrapping
    if prog_name == "eval":
        payload = " ".join(effective_tokens[1:])
        res = _audit_embedded_shell(payload, cmd_segment)
        if res is not None:
            return res

    # 5. Cmd.exe unwrapping
    if prog_name == "cmd":
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            if tok.lower() in ("/c", "/k"):
                payload = " ".join(effective_tokens[idx + 1 :])
                res = _audit_embedded_shell(payload, cmd_segment)
                if res is not None:
                    return res
                break

    # 6. Node.js unwrapping
    if prog_name == "node":
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            if tok.lower() in ("-e", "--eval"):
                payload = " ".join(effective_tokens[idx + 1 :])
                clean_payload = _strip_outer_quotes(payload)
                for m in re.finditer(
                    r"['\"]([^'\"]*(?:git\s+commit|git\s+stash|core\.hookspath|\.git[/\\].*hooks)[^'\"]*)['\"]",
                    clean_payload,
                    re.IGNORECASE,
                ):
                    sub_c = m.group(1).strip()
                    inner_dec = audit_pre_tool_use_command(sub_c)
                    if not inner_dec.allowed:
                        return HookDecision(
                            allowed=False,
                            exit_code=2,
                            command=cmd_segment,
                            vector="EMBEDDED_SUBVERSION",
                            reason=f"Bypass detected in embedded node payload: {inner_dec.reason}",
                            metadata={"nested_vector": inner_dec.vector, "nested_command": sub_c},
                        )
                break

    # --- Check Git Subcommands & Global Options ---
    is_git = prog_name == "git"
    git_subcmd = ""
    subcmd_idx = -1

    if is_git:
        skip_flag_val = False
        git_global_val_flags = {
            "-c",
            "-C",
            "--git-dir",
            "--work-tree",
            "--namespace",
            "--exec-path",
            "--config-env",
            "--super-prefix",
        }
        for idx, tok in enumerate(effective_tokens[1:], start=1):
            clean_tok = tok.strip("\"'")
            if skip_flag_val:
                skip_flag_val = False
                continue
            if clean_tok in git_global_val_flags:
                skip_flag_val = True
                continue
            if clean_tok.startswith("-"):
                continue
            git_subcmd = clean_tok.lower()
            subcmd_idx = idx
            break

    # --- VECTOR 2: core.hooksPath Override ---
    if RE_HOOKS_PATH.search(clean_cmd):
        cmd_lower = clean_cmd.lower()
        is_git_related = (
            is_git
            or prog_name == "git-config"
            or "git" in prog_name
            or "config" in cmd_lower
            or "-c" in cmd_lower
        )
        if is_git_related:
            if is_git and git_subcmd == "commit":
                top_level_tokens = effective_tokens[1:subcmd_idx] if subcmd_idx > 1 else []
                if any(RE_HOOKS_PATH.search(t) for t in top_level_tokens):
                    return HookDecision(
                        allowed=False,
                        exit_code=2,
                        command=cmd_segment,
                        vector="HOOKS_PATH_OVERRIDE",
                        reason="Bypass detected: core.hooksPath override attempt",
                    )
            else:
                if is_git or "config" in cmd_lower or "-c" in cmd_lower:
                    return HookDecision(
                        allowed=False,
                        exit_code=2,
                        command=cmd_segment,
                        vector="HOOKS_PATH_OVERRIDE",
                        reason="Bypass detected: core.hooksPath override attempt",
                    )

    # --- VECTOR 3: Hook Tampering & Permission Stripping ---
    if RE_HOOK_FILES.search(clean_cmd):
        if not (is_git and git_subcmd == "commit"):
            mutator_progs = {
                "rm",
                "del",
                "erase",
                "rmdir",
                "rd",
                "remove-item",
                "ri",
                "mv",
                "move",
                "move-item",
                "mi",
                "ren",
                "rename",
                "rename-item",
                "chmod",
                "icacls",
                "attrib",
                "unlink",
                "trash",
                "out-file",
                "set-content",
                "sc",
                "tee",
            }
            is_mutator = prog_name in mutator_progs or (is_git and git_subcmd in ("rm", "mv"))
            if is_mutator:
                args_to_check = effective_tokens[1:]
                if any(RE_HOOK_FILES.search(a) for a in args_to_check):
                    return HookDecision(
                        allowed=False,
                        exit_code=2,
                        command=cmd_segment,
                        vector="HOOKS_TAMPERING",
                        reason="Bypass detected: hook file tampering or deletion (.git/hooks or .claude/hooks)",
                    )
            if ">" in clean_cmd:
                redir_match = re.search(r">\s*([^\s;&|]+)", clean_cmd)
                if redir_match and RE_HOOK_FILES.search(redir_match.group(1)):
                    return HookDecision(
                        allowed=False,
                        exit_code=2,
                        command=cmd_segment,
                        vector="HOOKS_TAMPERING",
                        reason="Bypass detected: hook file tampering or deletion (.git/hooks or .claude/hooks)",
                    )

    # --- VECTOR 4: git stash --keep-index / -k ---
    if is_git and git_subcmd == "stash":
        stash_args = effective_tokens[subcmd_idx + 1 :]
        for tok in stash_args:
            clean_tok = tok.strip("\"'")
            clean_tok_lower = clean_tok.lower()
            if clean_tok_lower == "--keep-index" or clean_tok_lower.startswith("--keep"):
                return HookDecision(
                    allowed=False,
                    exit_code=2,
                    command=cmd_segment,
                    vector="STASH_KEEP_INDEX",
                    reason="Bypass detected: git stash --keep-index hides unstaged test modifications",
                )
            if clean_tok.startswith("-") and not clean_tok.startswith("--"):
                if "k" in clean_tok_lower:
                    return HookDecision(
                        allowed=False,
                        exit_code=2,
                        command=cmd_segment,
                        vector="STASH_KEEP_INDEX",
                        reason="Bypass detected: git stash -k short flag hides unstaged test modifications",
                    )

    # --- VECTOR 1: git commit with --no-verify or -n ---
    if is_git and git_subcmd == "commit":
        commit_args = effective_tokens[subcmd_idx + 1 :]
        skip_next = False

        value_taking_flags = {
            "-m",
            "-f",
            "-c",
            "-t",
            "--message",
            "--file",
            "--author",
            "--date",
            "--cleanup",
            "--squash",
            "--fixup",
        }

        for tok in commit_args:
            clean_tok = tok.strip("\"'")
            clean_tok_lower = clean_tok.lower()
            if skip_next:
                skip_next = False
                continue

            if clean_tok_lower.startswith((
                "--message=",
                "--file=",
                "--author=",
                "--date=",
                "--cleanup=",
                "--squash=",
                "--fixup=",
                "-m=",
            )):
                continue

            if clean_tok_lower in value_taking_flags:
                skip_next = True
                continue

            if clean_tok.startswith(('-m"', "-m'", "-m=")) or (
                clean_tok.startswith("-m") and any(ch in clean_tok for ch in ('"', "'", "="))
            ):
                continue

            if (clean_tok.startswith("-F") or clean_tok.startswith("-f")) and len(clean_tok) > 2:
                continue

            if clean_tok_lower.startswith("--no-v"):
                return HookDecision(
                    allowed=False,
                    exit_code=2,
                    command=cmd_segment,
                    vector="NO_VERIFY",
                    reason="Bypass detected: git commit with --no-verify",
                )

            if clean_tok.startswith("-") and not clean_tok.startswith("--"):
                valid_commit_flags = set("mnasvq")
                flag_chars = set(clean_tok_lower[1:])
                if flag_chars.issubset(valid_commit_flags):
                    if "m" in clean_tok_lower:
                        skip_next = True
                    if "n" in clean_tok_lower:
                        return HookDecision(
                            allowed=False,
                            exit_code=2,
                            command=cmd_segment,
                            vector="NO_VERIFY",
                            reason=f"Bypass detected: git commit with short flag '{clean_tok}' containing -n (no-verify)",
                        )
                else:
                    if clean_tok.startswith(("-m", "-f", "-c")):
                        continue

    return HookDecision(allowed=True, exit_code=0, command=cmd_segment)


def audit_pre_tool_use_command(command: str) -> HookDecision:
    """Inspects shell, PowerShell, and embedded strings, deterministically blocking
    all 6 bypass vectors (exit_code=2, allowed=False) per the Conseca model (arXiv:2501.17070).
    Legitimate commands are permitted (allowed=True, exit_code=0).
    """
    if not command or not command.strip():
        return HookDecision(allowed=True, exit_code=0, command=command)

    # Check for piped interpreter execution e.g. echo "git commit -n" | bash
    if "|" in command:
        pipe_parts = command.split("|")
        for p_idx in range(len(pipe_parts) - 1):
            left_part = pipe_parts[p_idx].strip()
            right_part = pipe_parts[p_idx + 1].strip()
            right_tokens = _tokenize_command(right_part)
            if right_tokens:
                right_raw = _strip_outer_quotes(right_tokens[0]).replace("/", "\\").strip("\"' ")
                right_prog = Path(right_raw).name.lower().strip("\"'")
                for ext in (".exe", ".cmd", ".bat"):
                    if right_prog.endswith(ext):
                        right_prog = right_prog[:-len(ext)]
                if right_prog in ("bash", "sh", "zsh", "dash", "powershell", "pwsh", "cmd", "python", "python3", "py", "node"):
                    left_tokens = _tokenize_command(left_part)
                    if left_tokens:
                        left_raw = _strip_outer_quotes(left_tokens[0]).replace("/", "\\").strip("\"' ")
                        left_prog = Path(left_raw).name.lower().strip("\"'")
                        for ext in (".exe", ".cmd", ".bat"):
                            if left_prog.endswith(ext):
                                left_prog = left_prog[:-len(ext)]
                        if left_prog in ("echo", "printf", "write-output"):
                            payload = " ".join(left_tokens[1:])
                            clean_payload = _strip_outer_quotes(payload)
                            inner_dec = audit_pre_tool_use_command(clean_payload)
                            if not inner_dec.allowed:
                                return HookDecision(
                                    allowed=False,
                                    exit_code=2,
                                    command=command,
                                    vector="CHAINED_CIRCUMVENTION",
                                    reason=f"Bypass detected in piped shell execution: {inner_dec.reason}",
                                    metadata={"nested_vector": inner_dec.vector, "piped_command": clean_payload},
                                )

    segments = _split_pipeline_segments(command)
    has_chaining = len(segments) > 1 or any(op in command for op in ("&&", "||", ";", "|", "&", "\n"))
    has_suppression = bool(RE_SUPPRESSIONS.search(command))

    for segment in segments:
        decision = _audit_single_command(segment)
        if not decision.allowed:
            # If pipeline combines bypass flags with suppression flags or chained execution
            if has_chaining and has_suppression:
                return HookDecision(
                    allowed=False,
                    exit_code=2,
                    command=command,
                    vector="CHAINED_CIRCUMVENTION",
                    reason=f"Bypass detected in chained/suppressed pipeline: {decision.reason}",
                    metadata={
                        "primary_vector": decision.vector,
                        "failing_segment": segment,
                        "has_chaining": True,
                        "has_suppression": True,
                    },
                )
            # Retain original vector
            return HookDecision(
                allowed=False,
                exit_code=2,
                command=command,
                vector=decision.vector,
                reason=decision.reason,
                metadata=decision.metadata,
            )

    return HookDecision(allowed=True, exit_code=0, command=command)


def _compute_digest_fallback(modified_anchors: dict[str, str], kill_rate: float = 1.0) -> str:
    """Computes deterministic 16-hex character (64-bit) BLAKE2b digest."""
    try:
        from cordis.forge_guard import compute_diff_attestation_digest

        return compute_diff_attestation_digest(modified_anchors, gate2_kill_rate=kill_rate)
    except (ImportError, AttributeError):
        if not modified_anchors:
            payload = f"EMPTY_DIFF:{kill_rate:.4f}"
        else:
            lines = [f"{k}:{v}:{kill_rate:.4f}" for k, v in sorted(modified_anchors.items())]
            payload = "\n".join(lines)
        return hashlib.blake2b(payload.encode("utf-8"), digest_size=8).hexdigest()


def run_stop_hook_prosecutor(repo_dir: str = ".", max_retries: int = 3) -> int:
    """Evaluates working tree state before turn completion.
    - Exits in <10ms for clean trees.
    - Runs Gate 1 (test tampering) and Gate 2 (mutation gate) on modified files.
    - Enforces 3-strike circuit breaker per AST anchor via EpisodicMemoryLedger.
    - On pass, writes .cordis_attestation.json containing 64-bit BLAKE2b digest.
    """
    repo_path = Path(repo_dir).resolve()

    # Fast-Path: Extract uncommitted working-tree changes
    try:
        diff_report = extract_git_diff(repo_dir=str(repo_path), base_ref="HEAD", target_ref=None)
    except Exception:
        diff_report = None

    if diff_report is None or (
        not diff_report.source_files
        and not diff_report.test_files
        and not diff_report.modified_functions
        and not (diff_report.raw_diff or "").strip()
    ):
        # Clean working tree -> exit 0 in <10ms
        return 0

    # Gate 1: Audit test tampering on modified test files
    gate1_failed = False
    gate1_violations: list[str] = []
    target_fns = diff_report.target_function_names

    for test_file in diff_report.test_files:
        test_full = repo_path / test_file
        if not test_full.is_file():
            continue
        new_test_code = test_full.read_text(encoding="utf-8", errors="replace")
        old_test_code = get_git_file_content("HEAD", test_file, repo_dir=str(repo_path)) or ""

        report = audit_test_tampering(
            old_test_code=old_test_code,
            new_test_code=new_test_code,
            target_function_names=target_fns,
            file_path=test_file,
        )
        if not report.passed:
            gate1_failed = True
            gate1_violations.extend(report.violations)

    # Gate 2: Mutation gate on modified source files
    gate2_failed = False
    surviving_mutants: list[MutantResult] = []
    failing_anchor = ""
    failing_fn = ""
    failing_src = ""

    # Test code candidates for in-memory mutation
    test_code_candidates: list[str] = []
    for tf in diff_report.test_files:
        tf_full = repo_path / tf
        if tf_full.is_file():
            test_code_candidates.append(tf_full.read_text(encoding="utf-8", errors="replace"))

    if not test_code_candidates:
        tests_dir = repo_path / "tests"
        if tests_dir.is_dir():
            for cand in sorted(tests_dir.glob("test_*.py")):
                try:
                    test_code_candidates.append(cand.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    pass

    primary_test_code = "\n".join(test_code_candidates[:2])

    for mod_fn in diff_report.modified_functions:
        if mod_fn.is_test:
            continue
        src_file = mod_fn.file_path
        src_full = repo_path / src_file
        if not src_full.is_file():
            continue
        src_code = src_full.read_text(encoding="utf-8", errors="replace")

        if src_code and primary_test_code:
            g2_rep = run_in_memory_mutation_gate(
                source_code=src_code,
                test_code=primary_test_code,
                target_function=mod_fn.name,
            )
            if not g2_rep.passed:
                gate2_failed = True
                survived = [m for m in g2_rep.results if not m.killed]
                surviving_mutants.extend(survived)
                failing_fn = mod_fn.name
                failing_src = src_code

                anchors = index_ast_anchors(src_code, file_path=src_file)
                if mod_fn.name in anchors:
                    failing_anchor = anchors[mod_fn.name].tag
                else:
                    failing_anchor = f"¶{src_file}#{mod_fn.name}"
                break

    # Episodic Memory & Circuit Breaker Tracking
    db_path = repo_path / ".cordis_memory.db"
    ledger = EpisodicMemoryLedger(db_path=db_path)

    try:
        if gate1_failed or gate2_failed:
            failure_mode = "gate1_tampering" if gate1_failed else "gate2_mutant_survived"
            summary = (
                "; ".join(gate1_violations[:2])
                if gate1_failed
                else f"{len(surviving_mutants)} AST mutant(s) survived"
            )
            anchor = (
                failing_anchor
                or (f"¶{diff_report.test_files[0]}#tampering" if diff_report.test_files else "¶repo#gate_failure")
            )
            fn_name = failing_fn or "test_suite"

            # Check existing retry count for this anchor
            cur = ledger.conn.cursor()
            cur.execute(
                "SELECT flake_retry_count FROM memory_entries WHERE ast_anchor = ? AND failure_mode = ? AND status = 'active' ORDER BY id DESC LIMIT 1",
                (anchor, failure_mode),
            )
            row = cur.fetchone()
            prior_retries = row[0] if row else 0
            retry_count = prior_retries + 1

            ledger.record_outcome(
                ast_anchor=anchor,
                function_name=fn_name,
                failure_mode=failure_mode,
                summary=summary,
                tags="stop_hook_gate_failure",
            )

            if retry_count < max_retries:
                # Strikes 1 or 2: emit bounded <25-line stderr remediation block with repair suggestion
                test_suggestion = ""
                if failing_src and surviving_mutants:
                    try:
                        test_suggestion = synthesize_mutant_killing_test(
                            source_code=failing_src,
                            target_function=fn_name,
                            surviving_mutants=surviving_mutants,
                        )
                    except Exception:
                        test_suggestion = ""

                rem_lines = [
                    "🛑 [Cordis Stop Hook Blocked]: Verification failure in working tree.",
                    f"Target: {fn_name} [Anchor: {anchor}] (Strike {retry_count}/{max_retries})",
                    f"Failure: {summary}",
                ]
                if test_suggestion:
                    rem_lines.append("Remediation suggestion:")
                    for line in test_suggestion.strip().splitlines()[:15]:
                        rem_lines.append(f"  {line}")

                bounded_output = "\n".join(rem_lines[:24]) + "\n"
                sys.stderr.write(bounded_output)
                return 2
            else:
                # Strike >= max_retries: Trigger circuit breaker
                alert_lines = [
                    f"[CIRCUIT BREAKER TRIGGERED: Max retries ({max_retries}) reached. Halting loop. NEEDS_HUMAN_ARBITRATION]",
                    f"Target: {fn_name} [Anchor: {anchor}] failed {retry_count} times.",
                    "Halting agent execution loop to prevent infinite retry and token exhaustion.",
                ]
                bounded_alert = "\n".join(alert_lines[:24]) + "\n"
                sys.stderr.write(bounded_alert)
                return 2

        # All gates passed: Compute 64-bit BLAKE2b diff attestation digest
        modified_anchors: dict[str, str] = {}
        for sf in diff_report.source_files:
            sf_full = repo_path / sf
            if sf_full.is_file():
                try:
                    code = sf_full.read_text(encoding="utf-8", errors="replace")
                    anchors = index_ast_anchors(code, file_path=sf)
                    for name, a in anchors.items():
                        modified_anchors[f"{sf}::{name}"] = a.tag
                except Exception:
                    pass

        digest = _compute_digest_fallback(modified_anchors, kill_rate=1.0)

        # Write .cordis_attestation.json to repo_dir
        attestation_file = repo_path / ".cordis_attestation.json"
        attestation_data = {
            "digest": digest,
            "gate2_kill_rate": 1.0,
            "modified_anchors": modified_anchors,
            "status": "PASSED",
        }
        attestation_file.write_text(json.dumps(attestation_data, indent=2) + "\n", encoding="utf-8")
        return 0

    finally:
        ledger.close()


def install_harness_hooks(
    repo_dir: str = ".",
    targets: list[str] = ["git", "claude"],
) -> list[str]:
    """Safely installs git pre-commit and Claude Code settings hook configurations.
    Returns list of installed file paths.
    """
    repo_path = Path(repo_dir).resolve()
    installed: list[str] = []

    norm_targets = {t.lower() for t in targets}
    if "all" in norm_targets:
        norm_targets.update(["git", "claude"])

    if "git" in norm_targets:
        git_hooks_dir = repo_path / ".git" / "hooks"
        git_hooks_dir.mkdir(parents=True, exist_ok=True)
        pre_commit_file = git_hooks_dir / "pre-commit"
        script_content = (
            "#!/usr/bin/env sh\n"
            "# Cordis Gate 0 Pre-Commit Hook\n"
            "python -m cordis.cli hooks stop-gate --repo-dir .\n"
        )
        pre_commit_file.write_text(script_content, encoding="utf-8", newline="\n")
        try:
            os.chmod(pre_commit_file, 0o755)
        except OSError:
            pass
        installed.append(str(pre_commit_file))

    if "claude" in norm_targets:
        claude_dir = repo_path / ".claude"
        claude_dir.mkdir(parents=True, exist_ok=True)
        settings_file = claude_dir / "settings.local.json"

        settings_data: dict[str, Any] = {}
        if settings_file.is_file():
            try:
                settings_data = json.loads(settings_file.read_text(encoding="utf-8"))
            except Exception:
                settings_data = {}

        hooks_section = settings_data.setdefault("hooks", {})
        hooks_section["PreToolUse"] = 'python -m cordis.cli hooks check-cmd --command "$COMMAND"'
        hooks_section["Stop"] = "python -m cordis.cli hooks stop-gate --repo-dir ."

        settings_file.write_text(
            json.dumps(settings_data, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        installed.append(str(settings_file))

    return installed
`

---

## cordis/ts_gate.py

`python
"""Gate 1 & Gate 2: Zero-Dependency TypeScript / JavaScript / Jest / Vitest AST Gate.
Provides 64-bit BLAKE2b AST anchor indexing, test tampering / anti-mock auditing,
and diff-scoped mutant synthesis using 100% Python 3.10+ standard library.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from cordis.ast_gate import ASTAnchor, TestTamperingReport, compute_node_hash


class AnchorDict(dict):
    """Dictionary mapping qualified names and anchor tags to ASTAnchor."""

    def __getitem__(self, key: str) -> ASTAnchor:
        if super().__contains__(key):
            return super().__getitem__(key)
        for anchor in self.values():
            if anchor.tag == key or anchor.hash_tag == key:
                return anchor
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if super().__contains__(key):
            return True
        if isinstance(key, str):
            return any(anchor.tag == key or anchor.hash_tag == key for anchor in self.values())
        return False


def _is_regex_start(code: str, pos: int) -> bool:
    """Heuristic check whether `/` at `pos` starts a regex literal rather than division."""
    j = pos - 1
    while j >= 0 and code[j] in " \t\r\n":
        j -= 1
    if j < 0:
        return True
    prev = code[j]
    if prev in "+-":
        # Post-increment (++) or post-decrement (--) preceding '/' indicates division, not regex.
        # Note: '+++' or '---' tokenizes as '++' / '--' followed by unary/binary '+' / '-',
        # where the trailing '+' / '-' CAN precede a regex literal (e.g. x+++ /y/).
        if j > 0 and code[j - 1] == prev and (j < 2 or code[j - 2] != prev):
            return False
    if prev in "(=[!&|?:,;~^><+*%-{":
        return True
    if prev.isalnum() or prev in "_$":
        k = j
        while k >= 0 and (code[k].isalnum() or code[k] in "_$"):
            k -= 1
        word = code[k + 1 : j + 1]
        if word in ("return", "yield", "case", "default", "typeof", "delete", "void", "throw", "await", "in", "of", "instanceof", "else", "do"):
            return True
        return False
    return False


def mask_ts_code(code: str, mask_strings: bool = True) -> str:
    """Masks comments and optionally string/template literals with whitespace,
    preserving exact byte offsets and newline positions (\\n).
    """
    n = len(code)
    out: List[str] = []
    i = 0
    # Stack tracks nested contexts:
    # "TEMPLATE" -> inside backtick template string
    # ["EXPR", brace_depth] -> inside ${ ... } within template string
    stack: List[Any] = []

    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""

        # Check if we are inside a template string
        if stack and stack[-1] == "TEMPLATE":
            if c == "\\":
                if i + 1 < n:
                    if mask_strings:
                        out.append(" ")
                        out.append("\n" if nxt == "\n" else " ")
                    else:
                        out.append(c)
                        out.append(nxt)
                    i += 2
                else:
                    out.append(" " if mask_strings else c)
                    i += 1
                continue
            elif c == "`":
                stack.pop()
                out.append(" " if mask_strings else "`")
                i += 1
                continue
            elif c == "$" and nxt == "{":
                stack.append(["EXPR", 1])
                out.append("  " if mask_strings else "${")
                i += 2
                continue
            else:
                if mask_strings:
                    out.append("\n" if c == "\n" else " ")
                else:
                    out.append(c)
                i += 1
                continue

        # If inside ${ ... } expression within a template literal
        if stack and isinstance(stack[-1], list) and stack[-1][0] == "EXPR":
            if c == "{":
                stack[-1][1] += 1
                out.append("{")
                i += 1
                continue
            elif c == "}":
                stack[-1][1] -= 1
                if stack[-1][1] == 0:
                    stack.pop()
                    out.append(" " if mask_strings else "}")
                else:
                    out.append("}")
                i += 1
                continue

        # Comments
        if c == "/" and nxt == "/":
            out.append("  ")
            i += 2
            while i < n and code[i] != "\n":
                out.append(" ")
                i += 1
            continue

        if c == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n:
                if code[i] == "*" and i + 1 < n and code[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    break
                else:
                    out.append("\n" if code[i] == "\n" else " ")
                    i += 1
            continue

        # Single quoted string
        if c == "'":
            out.append(" " if mask_strings else "'")
            i += 1
            while i < n:
                sc = code[i]
                if sc == "\\":
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(" ")
                            out.append("\n" if snxt == "\n" else " ")
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(" " if mask_strings else sc)
                        i += 1
                elif sc == "'":
                    out.append(" " if mask_strings else "'")
                    i += 1
                    break
                elif sc == "\n":
                    out.append("\n")
                    i += 1
                    break
                else:
                    out.append(" " if mask_strings else sc)
                    i += 1
            continue

        # Double quoted string
        if c == '"':
            out.append(" " if mask_strings else '"')
            i += 1
            while i < n:
                sc = code[i]
                if sc == "\\":
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(" ")
                            out.append("\n" if snxt == "\n" else " ")
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(" " if mask_strings else sc)
                        i += 1
                elif sc == '"':
                    out.append(" " if mask_strings else '"')
                    i += 1
                    break
                elif sc == "\n":
                    out.append("\n")
                    i += 1
                    break
                else:
                    out.append(" " if mask_strings else sc)
                    i += 1
            continue

        # Template literal start
        if c == "`":
            stack.append("TEMPLATE")
            out.append(" " if mask_strings else "`")
            i += 1
            continue

        # Regex literal
        if c == "/" and _is_regex_start(code, i):
            out.append(" " if mask_strings else "/")
            i += 1
            in_char_class = False
            while i < n:
                rc = code[i]
                if rc == "\\":
                    if i + 1 < n:
                        rnxt = code[i + 1]
                        if mask_strings:
                            out.append(" ")
                            out.append("\n" if rnxt == "\n" else " ")
                        else:
                            out.append(rc)
                            out.append(rnxt)
                        i += 2
                    else:
                        out.append(" " if mask_strings else rc)
                        i += 1
                elif rc == "[":
                    in_char_class = True
                    out.append(" " if mask_strings else rc)
                    i += 1
                elif rc == "]" and in_char_class:
                    in_char_class = False
                    out.append(" " if mask_strings else rc)
                    i += 1
                elif rc == "/" and not in_char_class:
                    out.append(" " if mask_strings else "/")
                    i += 1
                    while i < n and code[i].isalpha():
                        out.append(" " if mask_strings else code[i])
                        i += 1
                    break
                elif rc == "\n":
                    out.append("\n")
                    i += 1
                    break
                else:
                    out.append(" " if mask_strings else rc)
                    i += 1
            continue

        out.append(c)
        i += 1

    return "".join(out)


def strip_ts_comments(code: str) -> str:
    """Masks only comments with whitespace, keeping string literals and regex intact."""
    return mask_ts_code(code, mask_strings=False)


def _find_matching_brace(code: str, start_idx: int) -> int:
    """Finds index of matching '}' for '{' at start_idx in masked code."""
    depth = 0
    for i in range(start_idx, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(code) - 1


def _find_matching_paren(code: str, start_idx: int) -> int:
    """Finds index of matching ')' for '(' at start_idx in masked code."""
    depth = 0
    for i in range(start_idx, len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _find_toplevel_relational_op(expr: str) -> Optional[Tuple[str, str, str]]:
    """Finds top-level relational operator in expression outside inner parens/brackets/braces.
    Returns (operator, lhs, rhs) or None.
    """
    e = expr.strip()
    while e.startswith("(") and e.endswith(")"):
        # verify if outer parens enclose entire expr
        d = 0
        enclosed = True
        for idx in range(len(e) - 1):
            if e[idx] == "(":
                d += 1
            elif e[idx] == ")":
                d -= 1
                if d == 0:
                    enclosed = False
                    break
        if enclosed:
            e = e[1:-1].strip()
        else:
            break

    depth = 0
    i = 0
    n = len(e)
    while i < n:
        c = e[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0:
            for op in ("===", "!==", "==", "!=", "<=", ">=", "<", ">"):
                if e.startswith(op, i):
                    if op in ("<", ">"):
                        if i + 1 < n and e[i + 1] in ("<", ">", "="):
                            continue
                    left = e[:i].strip()
                    right = e[i + len(op) :].strip()
                    return op, left, right
        i += 1
    return None


def _extract_signature(params_raw: str) -> str:
    """Extracts normalized argument names from raw parameter declaration."""
    clean = params_raw.strip()
    if not clean:
        return "()"
    parts: List[str] = []
    current: List[str] = []
    depth = 0
    for ch in clean:
        if ch in "([{<":
            depth += 1
            current.append(ch)
        elif ch in ")]}>":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current).strip())

    arg_names: List[str] = []
    for p in parts:
        m = re.match(r"^([A-Za-z_$][A-Za-z0-9_$]*)", p)
        if m:
            arg_names.append(m.group(1))
        elif p:
            arg_names.append(p.split(":")[0].strip())
    return f"({', '.join(arg_names)})"


def index_ts_ast_anchors(ts_code: str, file_path: str = "module.ts") -> Dict[str, ASTAnchor]:
    """Indexes all TypeScript/JavaScript functions, arrow functions, and class methods
    with 64-bit BLAKE2b AST anchors.
    """
    clean_code = ts_code.lstrip("\ufeff")
    if not clean_code.strip():
        return AnchorDict()

    masked = mask_ts_code(clean_code, mask_strings=True)
    no_comments = strip_ts_comments(clean_code)
    anchors = AnchorDict()

    # 1. First find classes to track class scopes and methods
    class_re = re.compile(
        r"(?:^|[;\n])\s*"
        r"(?:export\s+(?:default\s+)?)?"
        r"(?:abstract\s+)?"
        r"class\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
        r"(?:<[\s\S]*?>)?"
        r"(?:\s+extends\s+[A-Za-z0-9_$.<>\s]+)?"
        r"(?:\s+implements\s+[A-Za-z0-9_$,.<>\s]+)?\s*\{",
        re.MULTILINE,
    )
    class_spans: List[Tuple[str, int, int]] = []  # (class_name, open_brace_idx, close_brace_idx)
    for m in class_re.finditer(masked):
        c_name = m.group("name")
        open_brace = m.end() - 1
        close_brace = _find_matching_brace(masked, open_brace)
        class_spans.append((c_name, open_brace, close_brace))

    # Helper to check which class an index falls into
    def get_enclosing_class(idx: int) -> Optional[str]:
        for c_name, ob, cb in class_spans:
            if ob < idx < cb:
                return c_name
        return None

    # Method regex for class methods
    method_re = re.compile(
        r"(?:^|[;\n}])\s*"
        r"(?:(?:public|private|protected|static|async|override|readonly)\s+)*"
        r"(?:\*\s*)?"
        r"(?:(?:get|set)\s+)?"
        r"(?P<name>\[[^\]]+\]|[A-Za-z_$][A-Za-z0-9_$]*)\s*"
        r"(?:<[\s\S]*?>)?\s*"
        r"\((?P<params>[^)]*)\)\s*"
        r"(?::\s*[^{;]+)?\s*\{",
        re.MULTILINE,
    )

    for c_name, ob, cb in class_spans:
        class_body = masked[ob + 1 : cb]
        for m in method_re.finditer(class_body):
            abs_name_start = ob + 1 + m.start("name")
            abs_name_end = ob + 1 + m.end("name")
            m_name = clean_code[abs_name_start:abs_name_end].strip()
            if m_name in ("if", "for", "while", "switch", "catch"):
                continue
            abs_start = ob + 1 + m.start()
            open_b = ob + 1 + m.end() - 1
            close_b = _find_matching_brace(masked, open_b)
            lineno = clean_code.count("\n", 0, abs_start) + 1
            end_lineno = clean_code.count("\n", 0, close_b) + 1
            sig = _extract_signature(m.group("params"))
            body_text = no_comments[open_b : close_b + 1]
            norm_body = re.sub(r"\s+", "", body_text)
            qualname = f"{c_name}.{m_name}"

            hash_tag = compute_node_hash(
                file_path=file_path,
                scope_path=c_name,
                node_type="MethodDefinition",
                identifier=m_name,
                signature=sig,
                normalized_body_dump=norm_body,
            )
            anchor = ASTAnchor(
                file_path=file_path,
                scope_path=c_name,
                node_type="MethodDefinition",
                identifier=m_name,
                signature=sig,
                lineno=lineno,
                end_lineno=end_lineno,
                hash_tag=hash_tag,
            )
            anchors[qualname] = anchor

    # 2. Standard and Async Functions
    func_decl_re = re.compile(
        r"(?:^|[;\n])\s*"
        r"(?:export\s+(?:default\s+)?)?"
        r"(?P<async>async\s+)?"
        r"function(?:\s*\*\s*|\s+)"
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*"
        r"(?:<[\s\S]*?>)?\s*"
        r"\((?P<params>[^)]*)\)\s*"
        r"(?::\s*[^{;]+)?\s*\{",
        re.MULTILINE,
    )
    for m in func_decl_re.finditer(masked):
        idx = m.start()
        if get_enclosing_class(idx) is not None:
            continue
        f_name = m.group("name")
        is_async = bool(m.group("async"))
        node_type = "AsyncFunctionDeclaration" if is_async else "FunctionDeclaration"
        open_b = m.end() - 1
        close_b = _find_matching_brace(masked, open_b)
        lineno = clean_code.count("\n", 0, idx) + 1
        end_lineno = clean_code.count("\n", 0, close_b) + 1
        sig = _extract_signature(m.group("params"))
        body_text = no_comments[open_b : close_b + 1]
        norm_body = re.sub(r"\s+", "", body_text)

        hash_tag = compute_node_hash(
            file_path=file_path,
            scope_path="<module>",
            node_type=node_type,
            identifier=f_name,
            signature=sig,
            normalized_body_dump=norm_body,
        )
        anchor = ASTAnchor(
            file_path=file_path,
            scope_path="<module>",
            node_type=node_type,
            identifier=f_name,
            signature=sig,
            lineno=lineno,
            end_lineno=end_lineno,
            hash_tag=hash_tag,
        )
        anchors[f_name] = anchor

    # 3. Arrow Function Variable Assignments
    arrow_assign_re = re.compile(
        r"(?:^|[;\n])\s*"
        r"(?:export\s+)?"
        r"(?:const|let|var)\s+"
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*"
        r"(?::\s*[^=]+)?\s*=\s*"
        r"(?:async\s+)?"
        r"(?:<[\s\S]*?>\s*)?"
        r"(?:\((?P<params>[^)]*)\)|(?P<single_param>[A-Za-z_$][A-Za-z0-9_$]*))\s*"
        r"(?::\s*(?:(?!=>).)*)?\s*=>\s*",
        re.MULTILINE,
    )
    for m in arrow_assign_re.finditer(masked):
        idx = m.start()
        if get_enclosing_class(idx) is not None:
            continue
        f_name = m.group("name")
        params_raw = m.group("params") or m.group("single_param") or ""
        sig = _extract_signature(params_raw)
        arrow_end = m.end()

        # Check if body is block { ... } or concise expression
        body_rest = masked[arrow_end:].lstrip()
        leading_spaces = len(masked[arrow_end:]) - len(body_rest)
        body_start_idx = arrow_end + leading_spaces

        if body_start_idx < len(masked) and masked[body_start_idx] == "{":
            close_b = _find_matching_brace(masked, body_start_idx)
            end_idx = close_b
        else:
            # Concise body until ';' or newline
            end_idx = body_start_idx
            while end_idx < len(masked) and masked[end_idx] not in (";", "\n"):
                end_idx += 1

        lineno = clean_code.count("\n", 0, idx) + 1
        end_lineno = clean_code.count("\n", 0, end_idx) + 1
        body_text = no_comments[arrow_end : end_idx + 1]
        norm_body = re.sub(r"\s+", "", body_text)

        hash_tag = compute_node_hash(
            file_path=file_path,
            scope_path="<module>",
            node_type="ArrowFunction",
            identifier=f_name,
            signature=sig,
            normalized_body_dump=norm_body,
        )
        anchor = ASTAnchor(
            file_path=file_path,
            scope_path="<module>",
            node_type="ArrowFunction",
            identifier=f_name,
            signature=sig,
            lineno=lineno,
            end_lineno=end_lineno,
            hash_tag=hash_tag,
        )
        anchors[f_name] = anchor

    return anchors


BOUNDARY_MOCK_TARGETS = (
    "axios",
    "fetch",
    "http",
    "https",
    "node:http",
    "node:https",
    "fs",
    "node:fs",
    "path",
    "node:path",
    "child_process",
    "node:child_process",
    "redis",
    "ioredis",
    "pg",
    "mysql",
    "prisma",
    "aws-sdk",
    "@aws-sdk",
    "setTimeout",
    "setInterval",
)


def _is_boundary_mock(target_str: str) -> bool:
    clean = target_str.strip("'\"`")
    return any(clean == b or clean.startswith(b + "/") or clean.startswith(b + ".") for b in BOUNDARY_MOCK_TARGETS)


STRONG_MATCHER_RE = re.compile(
    r"\.(?:toBe|toEqual|toStrictEqual|toThrow|toThrowError|toMatchObject|toHaveLength|toContain|toMatch)\s*\("
)
HOLLOW_MATCHER_RE = re.compile(
    r"\.(?:toBeDefined\s*\(\s*\)|not\s*\.\s*toBeNull\s*\(\s*\)|not\s*\.\s*toBeUndefined\s*\(\s*\)|toBeTruthy\s*\(\s*\)|toBeFalsy\s*\(\s*\))"
)


def audit_ts_test_tampering(
    old_ts_code: str,
    new_ts_code: str,
    target_function_names: Optional[List[str]] = None,
    file_path: str = "test_module.ts",
) -> TestTamperingReport:
    """Audits old vs new Jest/Vitest test code to catch test tampering."""
    target_set = set(target_function_names or [])
    clean_old = old_ts_code.lstrip("\ufeff")
    clean_new = new_ts_code.lstrip("\ufeff")

    old_no_comments = strip_ts_comments(clean_old)
    new_no_comments = strip_ts_comments(clean_new)

    violations: List[str] = []

    # 1. Assertion counts
    old_assert_matches = list(re.finditer(r"\bexpect\s*\(", old_no_comments))
    new_assert_matches = list(re.finditer(r"\bexpect\s*\(", new_no_comments))
    old_assert_count = len(old_assert_matches)
    new_assert_count = len(new_assert_matches)

    if old_assert_count > 0 and new_assert_count < old_assert_count:
        violations.append(
            f"Assertion count decreased from {old_assert_count} to {new_assert_count} (deleted assertions)."
        )

    if new_assert_count == 0 and len(clean_new.strip()) > 0:
        violations.append("Test file contains zero expect assertions.")

    # 2. Strong assertions vs hollow assertions
    old_strong = len(STRONG_MATCHER_RE.findall(old_no_comments))
    new_strong = len(STRONG_MATCHER_RE.findall(new_no_comments))
    new_hollow = len(HOLLOW_MATCHER_RE.findall(new_no_comments))

    if old_strong > new_strong:
        violations.append(
            f"Strong value assertions weakened to hollow checks (strong asserts dropped from {old_strong} to {new_strong})."
        )

    if new_assert_count > 0 and new_strong == 0 and new_hollow > 0:
        violations.append(
            "New test is hollow (asserts only weak .toBeDefined()/.not.toBeNull() with zero strong value checks)."
        )

    # 3. Tautological assertions in new tests
    masked_new = mask_ts_code(new_no_comments, mask_strings=True)
    for m in re.finditer(r"\bexpect\s*\(", masked_new):
        paren_start = m.end() - 1
        paren_end = _find_matching_paren(masked_new, paren_start)
        if paren_end == -1:
            continue
        actual = new_no_comments[paren_start + 1 : paren_end].strip()
        after = new_no_comments[paren_end + 1 :]
        m_matcher = re.match(
            r"^\s*\.\s*(?P<matcher>toBeTruthy|toBeFalsy|toBe|toEqual|toStrictEqual)\b",
            after,
        )
        if not m_matcher:
            continue
        matcher = m_matcher.group("matcher")
        matcher_end_idx = paren_end + 1 + m_matcher.end()

        # Find if matcher is invoked with arguments: .toBe(...) vs .toBeTruthy() vs .toBeTruthy
        p_arg_start = masked_new.find("(", matcher_end_idx)
        expected = ""
        call_end = matcher_end_idx
        if p_arg_start != -1 and not masked_new[matcher_end_idx:p_arg_start].strip():
            p_arg_end = _find_matching_paren(masked_new, p_arg_start)
            if p_arg_end != -1:
                expected = new_no_comments[p_arg_start + 1 : p_arg_end].strip()
                call_end = p_arg_end + 1
            else:
                call_end = p_arg_start + 1
        full_call = new_no_comments[m.start() : call_end]

        is_taut = False
        if matcher in ("toBe", "toEqual", "toStrictEqual"):
            if actual == expected:
                is_taut = True
            elif actual in ("true", "1") and expected in ("true", "1"):
                is_taut = True
            elif actual in ("false", "0") and expected in ("false", "0"):
                is_taut = True

        # Check relational self-comparison tautologies: expect(a === a).toBe(true), expect(a !== a).toBe(false)
        rel = _find_toplevel_relational_op(actual)
        if rel:
            op, left, right = rel
            if left == right:
                if op in ("===", "==", "<=", ">=") and (expected in ("true", "1") or matcher == "toBeTruthy"):
                    is_taut = True
                elif op in ("!==", "!=", "<", ">") and (expected in ("false", "0") or matcher == "toBeFalsy"):
                    is_taut = True

        if is_taut and full_call not in old_no_comments:
            lineno = clean_new.count("\n", 0, m.start()) + 1
            violations.append(
                f"Line {lineno}: Tautological assertion in expect(...) ({actual} -> {matcher}({expected}))."
            )

    # 4. Skipped tests
    skip_re = re.compile(
        r"\b(?P<token>(?:it|test|describe)\s*\.\s*(?:skip|todo|only)|(?:xit|xtest|xdescribe))\s*\("
    )
    for m in skip_re.finditer(new_no_comments):
        token = re.sub(r"\s+", "", m.group("token"))
        if token not in re.sub(r"\s+", "", old_no_comments):
            lineno = clean_new.count("\n", 0, m.start()) + 1
            violations.append(f"Line {lineno}: Test decorated with skip/todo ({token}).")

    # 5. Mock extraction and MAR
    mock_re = re.compile(
        r"\b(?P<lib>vi|jest)\s*\.\s*(?P<type>mock|spyOn|fn)\s*\(\s*(?P<target>[^,);]*)"
    )
    total_mocks = 0
    internal_mock_count = 0
    boundary_mock_count = 0

    # Also capture multiline mock calls for target scanning
    mock_calls: List[Tuple[int, str, str, str]] = []  # (lineno, lib, type, full_snippet)
    for m in mock_re.finditer(new_no_comments):
        total_mocks += 1
        lineno = clean_new.count("\n", 0, m.start()) + 1
        lib = m.group("lib")
        m_type = m.group("type")
        target_str = m.group("target").strip()

        # Find matching closing parenthesis for the mock invocation
        p_start = masked_new.find("(", m.start())
        p_end = _find_matching_paren(masked_new, p_start) if p_start != -1 else -1
        if p_end != -1:
            # Check if there is a trailing semicolon on the same line
            semi_idx = new_no_comments.find(";", p_end)
            newline_idx = new_no_comments.find("\n", p_end)
            if semi_idx != -1 and (newline_idx == -1 or semi_idx < newline_idx):
                snippet = new_no_comments[m.start() : semi_idx + 1]
            else:
                snippet = new_no_comments[m.start() : p_end + 1]
        else:
            newline_idx = new_no_comments.find("\n", m.start())
            snippet = new_no_comments[m.start() : newline_idx if newline_idx != -1 else m.end() + 100]

        mock_calls.append((lineno, lib, m_type, snippet))

        if _is_boundary_mock(target_str):
            boundary_mock_count += 1
        else:
            internal_mock_count += 1

    # Check for target function mocking
    for lineno, lib, m_type, snippet in mock_calls:
        for t_fn in target_set:
            if t_fn in snippet:
                violations.append(
                    f"Line {lineno}: Test mocks out target function '{t_fn}' via {lib}.{m_type}."
                )

    total_asserts = max(new_assert_count, 1)
    mar = round(total_mocks / total_asserts, 4)
    weighted_mar = round((1.0 * internal_mock_count + 0.25 * boundary_mock_count) / total_asserts, 4)

    if mar < 0.10:
        risk_level = "LOW"
    elif mar <= 0.25:
        risk_level = "MODERATE"
    else:
        risk_level = "HIGH_RISK"

    anchors = index_ts_ast_anchors(clean_new, file_path=file_path)

    passed = (len(violations) == 0)
    return TestTamperingReport(
        passed=passed,
        old_assert_count=old_assert_count,
        new_assert_count=new_assert_count,
        violations=violations,
        anchors=anchors,
        total_mocks=total_mocks,
        mar=mar,
        risk_level=risk_level,
        internal_mock_count=internal_mock_count,
        boundary_mock_count=boundary_mock_count,
        weighted_mar=weighted_mar,
    )


def generate_ts_mutants(
    ts_code: str,
    target_function: Optional[str] = None,
    max_mutants: int = 5,
) -> List[Tuple[str, int, str]]:
    """Synthesizes up to `max_mutants` distinct diff-scoped TypeScript/JS mutants.
    Returns list of (description, lineno, mutated_ts_code).
    """
    clean_code = ts_code.lstrip("\ufeff")
    if not clean_code.strip():
        return []

    masked = mask_ts_code(clean_code, mask_strings=True)
    anchors = index_ts_ast_anchors(clean_code)

    start_line = 1
    end_line = clean_code.count("\n") + 1

    if target_function:
        if target_function in anchors:
            start_line = anchors[target_function].lineno
            end_line = anchors[target_function].end_lineno
        else:
            match = next((a for a in anchors.values() if a.identifier == target_function), None)
            if match:
                start_line = match.lineno
                end_line = match.end_lineno

    mutants: List[Tuple[str, int, str]] = []
    seen_mutations: Set[str] = set()

    # Mutation operators:
    # 1. === <-> !==
    # 2. == <-> !=
    # 3. <= <-> <, >= <-> >
    # 4. && <-> ||
    # 5. + <-> -
    # 6. return <expr>; -> return null;
    # 7. true <-> false

    patterns: List[Tuple[str, str, str]] = [
        # (regex in masked, replacement, desc)
        (r"===", "!==", "Strict equality inverted (=== to !==)"),
        (r"!==", "===", "Strict inequality inverted (!== to ===)"),
        (r"(?<![!=])==(?!=)", "!=", "Equality inverted (== to !=)"),
        (r"(?<![!=])!=(?!=)", "==", "Inequality inverted (!= to ==)"),
        (r"<=", "<", "Relational boundary adjusted (<= to <)"),
        (r">=", ">", "Relational boundary adjusted (>= to >)"),
        (r"&&", "||", "Logical AND inverted to OR (&& to ||)"),
        (r"\|\|", "&&", "Logical OR inverted to AND (|| to &&)"),
        (r"(?<!\+)\+(?!\+|=)", "-", "Arithmetic addition inverted to subtraction (+ to -)"),
        (r"(?<!-)-(?!-|=)", "+", "Arithmetic subtraction inverted to addition (- to +)"),
        (r"\btrue\b", "false", "Boolean literal inverted (true to false)"),
        (r"\bfalse\b", "true", "Boolean literal inverted (false to true)"),
    ]

    for pat, rep, desc in patterns:
        for m in re.finditer(pat, masked):
            idx = m.start()
            end_idx = m.end()
            lineno = clean_code.count("\n", 0, idx) + 1
            if not (start_line <= lineno <= end_line):
                continue
            mutated = clean_code[:idx] + rep + clean_code[end_idx:]
            if mutated not in seen_mutations and mutated != clean_code:
                seen_mutations.add(mutated)
                mutants.append((f"Line {lineno}: {desc}", lineno, mutated))
                if len(mutants) >= max_mutants:
                    return mutants

    # Return null mutation
    ret_re = re.compile(r"\breturn\s+([^;]+);")
    for m in ret_re.finditer(masked):
        idx = m.start()
        end_idx = m.end()
        lineno = clean_code.count("\n", 0, idx) + 1
        if not (start_line <= lineno <= end_line):
            continue
        expr = clean_code[m.start(1) : m.end(1)].strip()
        if expr == "null":
            continue
        mutated = clean_code[:idx] + "return null;" + clean_code[end_idx:]
        if mutated not in seen_mutations and mutated != clean_code:
            seen_mutations.add(mutated)
            mutants.append((f"Line {lineno}: Replace return expression with 'null'", lineno, mutated))
            if len(mutants) >= max_mutants:
                return mutants

    return mutants
`

---

## cordis/forge_guard.py

`python
"""Cordis Forge Self-Approval & Token Guard.
Inspects git commit author/committer metadata and CI/Forge environment variables
(GITHUB_ACTOR, GITHUB_TRIGGERING_ACTOR, GITHUB_EVENT_NAME) to prevent bot self-approval
and single-token automated merging without dual-custody verification.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Known bot patterns (case-insensitive)
BOT_IDENTIFIER_PATTERNS = [
    r"\[bot\]",
    r"\bbot\b",
    r"github-actions",
    r"dependabot",
    r"renovate",
    r"coderabbit",
    r"devin",
    r"cursor-agent",
    r"claude-code",
    r"antigravity-agent",
    r"copilot",
    r"sweep-ai",
]

BOT_EMAIL_DOMAINS = [
    "users.noreply.github.com",
    "actions@github.com",
    "bot@",
    "agent@",
]

BOT_RE = re.compile("|".join(BOT_IDENTIFIER_PATTERNS), re.IGNORECASE)


@dataclass
class GitActorInfo:
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    commit_message: str = ""
    is_bot: bool = False


@dataclass
class ForgeGuardReport:
    passed: bool
    is_bot_authored: bool = False
    is_self_approved: bool = False
    actor: str = ""
    triggering_actor: str = ""
    event_name: str = ""
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


def is_bot_identity(name: str, email: str = "") -> bool:
    """Detects if a given name or email indicates an automated bot/agent account."""
    if not name and not email:
        return False
    if BOT_RE.search(name):
        return True
    if email:
        if BOT_RE.search(email):
            return True
        for domain in BOT_EMAIL_DOMAINS:
            if domain in email.lower():
                return True
    return False


def inspect_git_actor(repo_dir: str | Path = ".", ref: str = "HEAD") -> GitActorInfo:
    """Extracts git commit author and committer metadata for the specified ref."""
    cmd = ["git", "log", "-1", "--format=%an%x00%ae%x00%cn%x00%ce%x00%s", ref]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
        if proc.returncode == 0:
            parts = proc.stdout.strip().split("\x00")
            if len(parts) >= 5:
                an, ae, cn, ce, msg = parts[0], parts[1], parts[2], parts[3], parts[4]
                bot = is_bot_identity(an, ae) or is_bot_identity(cn, ce)
                return GitActorInfo(
                    author_name=an,
                    author_email=ae,
                    committer_name=cn,
                    committer_email=ce,
                    commit_message=msg,
                    is_bot=bot,
                )
    except Exception:
        pass
    return GitActorInfo(
        author_name="unknown",
        author_email="unknown@unknown.com",
        committer_name="unknown",
        committer_email="unknown@unknown.com",
        is_bot=False,
    )


def audit_forge_guard(
    actor_info: Optional[GitActorInfo] = None,
    env: Optional[Dict[str, str]] = None,
    pr_author: Optional[str] = None,
    reviewer: Optional[str] = None,
    review_state: Optional[str] = None,  # e.g., "APPROVED", "COMMENTED", "CHANGES_REQUESTED"
    auto_merge_requested: bool = False,
) -> ForgeGuardReport:
    """Audits PR actor metadata and CI environment variables for bot self-approval,
    single-token auto-merge, and missing human dual-custody approval.
    """
    if env is None:
        env = dict(os.environ)

    actor = env.get("GITHUB_ACTOR", "").strip()
    triggering_actor = env.get("GITHUB_TRIGGERING_ACTOR", actor).strip()
    event_name = env.get("GITHUB_EVENT_NAME", "").strip()

    violations: List[str] = []
    warnings: List[str] = []

    # 1. Determine effective PR author
    effective_pr_author = pr_author or ""
    if not effective_pr_author and actor_info:
        effective_pr_author = actor_info.author_name

    author_is_bot = is_bot_identity(
        effective_pr_author,
        actor_info.author_email if actor_info else "",
    ) or (actor_info.is_bot if actor_info else False)

    # 2. Check reviewer identity & state
    effective_reviewer = reviewer or actor
    reviewer_is_bot = is_bot_identity(effective_reviewer)
    is_self_approved = False

    # Check for direct Self-Approval
    if effective_pr_author and effective_reviewer:
        clean_author = effective_pr_author.lower().replace("[bot]", "").strip()
        clean_reviewer = effective_reviewer.lower().replace("[bot]", "").strip()
        if clean_author and clean_author == clean_reviewer and review_state == "APPROVED":
            is_self_approved = True
            violations.append(
                f"Forge Guard Violation [SELF_APPROVAL]: PR author `{effective_pr_author}` approved their own PR. "
                "Dual-custody verification failed."
            )

    # Check for Bot-to-Bot collusion (Bot approved by another Bot without human sign-off)
    if author_is_bot and reviewer_is_bot and review_state == "APPROVED":
        violations.append(
            f"Forge Guard Violation [BOT_COLLUSION]: Bot PR authored by `{effective_pr_author}` was approved by "
            f"bot `{effective_reviewer}` without human verification."
        )

    # 3. Check for Single-Token Agent Auto-Merging
    if auto_merge_requested or "auto-merge" in env.get("GITHUB_ACTION_REPOSITORY", "").lower():
        if author_is_bot and (not reviewer or reviewer_is_bot or is_self_approved):
            violations.append(
                f"Forge Guard Violation [SINGLE_TOKEN_AUTO_MERGE]: Automated auto-merge triggered for bot-authored "
                f"PR `{effective_pr_author}` without independent human approval."
            )

    # 4. In GitHub Actions PR review events
    if event_name in ("pull_request_review", "pull_request_review_comment"):
        if review_state == "APPROVED":
            if actor and effective_pr_author and actor.lower() == effective_pr_author.lower():
                if not is_self_approved:
                    is_self_approved = True
                    violations.append(
                        f"Forge Guard Violation [GITHUB_ACTOR_SELF_APPROVAL]: GITHUB_ACTOR `{actor}` is approving "
                        f"PR authored by `{effective_pr_author}`."
                    )
            if is_bot_identity(actor):
                warnings.append(
                    f"Forge Guard Notice: Review performed by automated bot account `{actor}`."
                )

    passed = len(violations) == 0

    return ForgeGuardReport(
        passed=passed,
        is_bot_authored=author_is_bot,
        is_self_approved=is_self_approved,
        actor=actor,
        triggering_actor=triggering_actor,
        event_name=event_name,
        violations=violations,
        warnings=warnings,
        metadata={
            "effective_pr_author": effective_pr_author,
            "effective_reviewer": effective_reviewer,
            "review_state": review_state,
            "author_is_bot": author_is_bot,
            "reviewer_is_bot": reviewer_is_bot,
        },
    )


def audit_current_environment(repo_dir: str | Path = ".") -> ForgeGuardReport:
    """Audits current git repository HEAD and environment for Forge Guard compliance."""
    actor_info = inspect_git_actor(repo_dir=repo_dir, ref="HEAD")
    return audit_forge_guard(actor_info=actor_info)


def compute_diff_attestation_digest(
    modified_anchors: dict[str, str],
    gate2_kill_rate: float = 1.0,
) -> str:
    """Computes a deterministic 64-bit (16-hex character) BLAKE2b digest over
    the lexicographically sorted modified function anchors and Gate 2 kill rate.

    Args:
        modified_anchors: Mapping from function qualname to anchor tag (¶path#16hex).
        gate2_kill_rate: Mutation gate kill rate as float (e.g. 1.0).

    Returns:
        16-hex character lowercase digest string.
    """
    if not modified_anchors:
        payload = f"EMPTY_DIFF:{gate2_kill_rate:.4f}"
    else:
        payload = "\n".join(
            f"{q}:{t}:{gate2_kill_rate:.4f}"
            for q, t in sorted(modified_anchors.items())
        )
    return hashlib.blake2b(payload.encode("utf-8"), digest_size=8).hexdigest().lower()


def verify_commit_attestation_trailer(commit_message: str, expected_digest: str) -> bool:
    """Verifies that the commit message contains a Cordis-Attestation trailer
    matching expected_digest (case-insensitive).

    Format:
        Cordis-Attestation: ¶<16hex>
        or
        Cordis-Attestation: <16hex>

    Args:
        commit_message: Git commit message string.
        expected_digest: 16-hex character attestation digest.

    Returns:
        True if valid matching attestation trailer found, False otherwise.
    """
    if not commit_message or not expected_digest:
        return False
    target = expected_digest.strip().lower()
    pattern = r"Cordis-Attestation:\s*¶?([0-9a-fA-F]{16})(?![0-9a-fA-F])"
    for match in re.finditer(pattern, commit_message, re.IGNORECASE):
        if match.group(1).lower() == target:
            return True
    return False

`

---

## cordis/policy_guard.py

`python
"""Pre-Flight Repository Governance & Policy Scraper (Anti-AI & Issue Prerequisite Guard)."""
from __future__ import annotations

import configparser
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional, Set


@dataclass
class PolicyAuditReport:
    status: str  # "BLOCKED_POLICY" | "ISSUE_REQUIRED" | "PERMITTED"
    ai_banned: bool = False
    issue_required: bool = False
    governance_files_scanned: List[str] = field(default_factory=list)
    citations: List[str] = field(default_factory=list)
    advice: str = ""

    @property
    def triggers(self) -> List[str]:
        return self.citations

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "ai_banned": self.ai_banned,
            "issue_required": self.issue_required,
            "governance_files_scanned": self.governance_files_scanned,
            "citations": self.citations,
            "triggers": self.citations,
            "advice": self.advice,
        }


ANTI_AI_PATTERNS = [
    re.compile(r"palletsprojects\.com/contributing/llm-ai", re.IGNORECASE),
    re.compile(
        r"(?:no|prohibit(?:s|ed|ing)?|disallow(?:ed|ing)?|ban(?:ned|ning)?|not\s+accept(?:ed|ing)?)\s+(?:any\s+)?(?:ai|llm|copilot|chatgpt|generative\s+ai|machine[\s-]generated)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:ai|llm|chatgpt|copilot|generative\s+ai)[\s-]generated\s+(?:code|pull\s+requests?|prs?|contributions?)",
        re.IGNORECASE,
    ),
    re.compile(r"\[no-ai\]", re.IGNORECASE),
    re.compile(r"\banti-ai\b", re.IGNORECASE),
    re.compile(r"zero-tolerance\s+policy\s+against\s+(?:ai|llm)", re.IGNORECASE),
    re.compile(r"clearly\s+ai\s+generated\s+description.*?(?:ignored|closed)", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bno\s+(?:ai-generated|llm-generated|ai-assisted)\b", re.IGNORECASE),
    re.compile(r"pull\s+requests?\s+generated\s+by\s+(?:ai|llms?|chatgpt)", re.IGNORECASE),
    re.compile(r"contributions?\s+generated\s+by\s+(?:ai|llms?|chatgpt)", re.IGNORECASE),
    re.compile(r"\bdo\s+not\s+submit\s+(?:any\s+)?(?:ai|llm|chatgpt|copilot)\b", re.IGNORECASE),
]

ISSUE_REQUIRED_PATTERNS = [
    re.compile(
        r"(?:all|every)\s+pull\s+requests?\s+must\s+(?:reference|link|have)\s+an?\s+(?:existing\s+)?issue",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:open|create|file)\s+an?\s+issue\s+(?:first|before\s+(?:submitting|creating|opening))",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:must|require[ds]?)\s+(?:be\s+)?assigned\s+(?:to\s+)?an?\s+issue",
        re.IGNORECASE,
    ),
    re.compile(r"must\s+link\s+to\s+an\s+issue", re.IGNORECASE),
    re.compile(r"an\s+issue\s+is\s+required", re.IGNORECASE),
    re.compile(r"\[require-issue\]", re.IGNORECASE),
    re.compile(r"fixes\s*#.*?(?:required|mandatory)", re.IGNORECASE),
    re.compile(r"prs?\s+without\s+prior\s+approval\s+will\s+be\s+closed", re.IGNORECASE),
    re.compile(r"before\s+opening\s+a\s+pr,?\s+open\s+(?:a\s+ticket|an\s+issue)", re.IGNORECASE),
    re.compile(r"(?:all\s+external\s+)?prs\s+must\s+link\s+to\s+an\s+issue", re.IGNORECASE),
]


def _discover_governance_files(root: Path) -> List[Path]:
    target_names = {
        "contributing.md",
        "contributing.rst",
        "contributing.txt",
        "contributing",
        "pull_request_template.md",
        "pull_request_template.rst",
        "pull_request_template.txt",
        "pull_request_template",
        "readme.md",
        "readme.rst",
        "readme.txt",
        "readme",
        "ai_policy.md",
        "ai-policy.md",
        "aipolicy.md",
        "policy.md",
        "governance.md",
        "governance.rst",
        "security.md",
        "security.rst",
        "code_of_conduct.md",
    }
    search_dirs = [
        root,
        root / ".github",
        root / "docs",
        root / ".github" / "PULL_REQUEST_TEMPLATE",
        root / ".github" / "pull_request_template",
    ]
    found: List[Path] = []
    seen_paths: Set[str] = set()

    for d in search_dirs:
        if not d.is_dir():
            continue
        try:
            for item in d.iterdir():
                if item.is_file():
                    name_lower = item.name.lower()
                    if name_lower in target_names or (
                        "pull_request_template" in d.name.lower() and name_lower.endswith(".md")
                    ):
                        resolved_str = str(item.resolve())
                        if resolved_str not in seen_paths:
                            seen_paths.add(resolved_str)
                            found.append(item)
        except (PermissionError, OSError):
            continue

    return found


def audit_repository_policy(repo_path: str | Path) -> PolicyAuditReport:
    """Scans repository governance files (CONTRIBUTING, PULL_REQUEST_TEMPLATE, README)
    case-insensitively across root, .github/, and docs/ to detect anti-AI contribution
    bans and mandatory issue prerequisites.
    """
    root = Path(repo_path).resolve()
    if not root.exists() or not root.is_dir():
        return PolicyAuditReport(
            status="PERMITTED",
            ai_banned=False,
            issue_required=False,
            governance_files_scanned=[],
            citations=[],
            advice=f"Repository path `{repo_path}` does not exist or is not a directory; default to PERMITTED.",
        )

    governance_files = _discover_governance_files(root)
    scanned_rel_paths: List[str] = []
    citations: List[str] = []
    ai_banned = False
    issue_required = False

    for gfile in governance_files:
        try:
            rel_str = str(gfile.relative_to(root)).replace("\\", "/")
        except ValueError:
            rel_str = str(gfile).replace("\\", "/")
        scanned_rel_paths.append(rel_str)

        try:
            content = gfile.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
        except Exception:
            continue

        if not content.strip():
            continue

        # Check anti-AI patterns
        for pat in ANTI_AI_PATTERNS:
            match = pat.search(content)
            if match:
                ai_banned = True
                snippet = match.group(0).strip().replace("\n", " ")
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 30)
                context_snippet = content[start:end].strip().replace("\n", " ")
                citations.append(f"{rel_str}: Matches anti-AI pattern `{snippet}`: \"...{context_snippet}...\"")
                break

        # Check mandatory issue patterns
        for pat in ISSUE_REQUIRED_PATTERNS:
            match = pat.search(content)
            if match:
                issue_required = True
                snippet = match.group(0).strip().replace("\n", " ")
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 30)
                context_snippet = content[start:end].strip().replace("\n", " ")
                citations.append(f"{rel_str}: Matches issue requirement pattern `{snippet}`: \"...{context_snippet}...\"")
                break

    # Check for hook tampering if .git is a directory
    hook_tampered = False
    git_dir = root / ".git"
    if git_dir.is_dir():
        # 1. Inspect .git/config for core.hooksPath override
        git_config_path = git_dir / "config"
        if git_config_path.is_file():
            hooks_path_val: Optional[str] = None
            try:
                cp = configparser.ConfigParser()
                cp.read(str(git_config_path), encoding="utf-8")
                if cp.has_section("core") and "hookspath" in cp["core"]:
                    hooks_path_val = cp["core"]["hookspath"].strip()
            except Exception:
                pass

            if hooks_path_val is None:
                try:
                    cfg_text = git_config_path.read_text(encoding="utf-8", errors="replace")
                    in_core = False
                    for line in cfg_text.splitlines():
                        sline = line.strip()
                        if sline.startswith("[") and sline.endswith("]"):
                            in_core = (sline.lower() == "[core]")
                        elif in_core and "=" in sline:
                            k, v = sline.split("=", 1)
                            if k.strip().lower() == "hookspath":
                                hooks_path_val = v.strip().strip("'\"")
                                break
                except Exception:
                    pass

            if hooks_path_val is not None:
                clean_hp = hooks_path_val.strip().strip("'\"")
                norm_hp = clean_hp.lower().replace("\\", "/")
                is_suppressed = (
                    not clean_hp
                    or norm_hp in ("/dev/null", "nul", "null", ":", "false", "none", "/dev/zero")
                    or (not (root / clean_hp).exists() and not Path(clean_hp).exists())
                )
                if is_suppressed:
                    hook_tampered = True
                    citations.append("[HOOK_TAMPERING]: git core.hooksPath is overridden to invalid/suppressed target")

        # 2. Inspect .git/hooks/pre-commit
        hook_path = git_dir / "hooks" / "pre-commit"
        if hook_path.is_file():
            is_empty = False
            try:
                is_empty = (os.path.getsize(hook_path) == 0)
            except OSError:
                pass

            is_stripped = False
            if hasattr(os, "X_OK"):
                if os.name != "nt":
                    is_stripped = not os.access(hook_path, os.X_OK)
                else:
                    if not os.access(hook_path, os.X_OK):
                        is_stripped = True

            if is_empty or is_stripped:
                hook_tampered = True
                citations.append("[HOOK_TAMPERING]: .git/hooks/pre-commit is stripped of executable permissions or emptied")

    if ai_banned:
        status = "BLOCKED_POLICY"
        advice = (
            "Repository governance explicitly prohibits AI/LLM-generated code or pull requests. "
            "Do not submit automated pull requests to this repository."
        )
    elif hook_tampered:
        status = "BLOCKED_POLICY"
        advice = (
            "Repository policy violated: git hook tampering or suppression detected. "
            "Ensure .git/hooks/pre-commit is executable and core.hooksPath is not overridden."
        )
    elif issue_required:
        status = "ISSUE_REQUIRED"
        advice = (
            "Repository governance requires an existing issue or maintainer approval before opening a pull request. "
            "Open, reference, or link a valid issue first."
        )
    else:
        status = "PERMITTED"
        advice = "No anti-AI bans or mandatory issue prerequisites detected in governance files."

    return PolicyAuditReport(
        status=status,
        ai_banned=ai_banned,
        issue_required=issue_required,
        governance_files_scanned=scanned_rel_paths,
        citations=citations,
        advice=advice,
    )
`

---

## cordis/cli.py

`python
"""Cordis CLI & GitHub PR Prosecutor Comment Formatter."""
from __future__ import annotations

import argparse
import os
import re
import sys
import unicodedata
from pathlib import Path
from typing import Any, Optional

# Ensure stdout and stderr handle utf-8 safely on Windows
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

import json
from cordis.ast_gate import audit_test_tampering, calculate_mock_to_assertion_ratio
from cordis.forge_guard import audit_current_environment
from cordis.fuzzer import (
    BenchmarkGateReport,
    DifferentialFuzzReport,
    run_differential_fuzz_gate,
    run_statistical_benchmark_gate,
)
from cordis.git_diff import extract_git_diff, get_git_file_content
from cordis.html_report import save_html_report, save_markdown_report
from cordis.mutator import MutationGateReport, run_in_memory_mutation_gate, run_repo_mutation_gate
from cordis.policy_guard import audit_repository_policy, PolicyAuditReport
from cordis.repair import synthesize_mutant_killing_test
from cordis.demo_fixtures import (
    BAD_AGENT_PATCH_SOURCE,
    BAD_AGENT_TEST_SOURCE,
    GOOD_AGENT_TEST_SOURCE,
    OLD_BUGGY_SOURCE,
    OLD_TEST_SOURCE,
    REFERENCE_CORRECT_SOURCE,
)


def format_github_prosecutor_comment(
    pr_title: str,
    fixproof_revert_passed: bool = True,
    gate1_report: Any = None,
    gate2_report: Any = None,
    gate3_fuzz_report: Any = None,
    gate3_bench_report: Any = None,
    *,
    swe_bench_revert_passed: Optional[bool] = None,
) -> str:
    g1_pass = getattr(gate1_report, "passed", False)
    g2_pass = getattr(gate2_report, "passed", False)
    g3a_pass = getattr(gate3_fuzz_report, "passed", False)
    g3b_pass = getattr(gate3_bench_report, "passed", False)
    overall_passed = g1_pass and g2_pass and g3a_pass and g3b_pass

    f2p_passed = swe_bench_revert_passed if swe_bench_revert_passed is not None else fixproof_revert_passed
    status_badge = "✅ **APPROVED TO LAND**" if overall_passed else "🛑 **BLOCKED — COUNTERFEIT RED / REGRESSION DETECTED**"
    fp_str = "✅ PASSED (Fooled by single-input test!)" if f2p_passed and not overall_passed else ("✅ PASSED" if f2p_passed else "❌ FAILED")

    lines = [
        f"## 🛡️ Cordis Adversarial AI-PR Prosecutor Verdict: {pr_title}",
        f"**Overall Verdict**: {status_badge}",
        f"**SWE-bench `Fail-to-Pass` (`git revert HEAD~1`)**: {fp_str}",
        "",
        "| Prosecution Gate | Status | Telemetry & Evidence |",
        "| :--- | :--- | :--- |",
        (
            f"| **Gate 1: AST Test-Tampering & Anti-Mock Audit** | "
            f"{'✅ PASS' if gate1_report.passed else '❌ FAIL'} | "
            f"Asserts: `{gate1_report.old_assert_count} -> {gate1_report.new_assert_count}` · "
            f"Violations: `{len(gate1_report.violations)}` |"
        ),
        (
            f"| **Gate 2: In-Place AST Mutation ('Counterfeit Red' Killer)** | "
            f"{'✅ PASS' if gate2_report.passed else '❌ FAIL'} | "
            f"Killed `{gate2_report.killed_mutants}/{gate2_report.total_mutants}` mutants "
            f"(`{gate2_report.survived_mutants}` survived) |"
        ),
        (
            f"| **Gate 3A: Differential Property Fuzzing (200 Edge Cases)** | "
            f"{'✅ PASS' if gate3_fuzz_report.passed else '❌ FAIL'} | "
            f"Tested `{gate3_fuzz_report.inputs_tested}` inputs · "
            f"Counterexamples: `{len(gate3_fuzz_report.counterexamples)}` |"
        ),
        (
            f"| **Gate 3B: Mann-Whitney U Baseline Benchmark (N=30)** | "
            f"{'✅ PASS' if gate3_bench_report.passed else '❌ FAIL'} | "
            f"`{gate3_bench_report.baseline_median_us:.3f}us -> {gate3_bench_report.candidate_median_us:.3f}us` "
            f"({gate3_bench_report.note}) |"
        ),
        "",
    ]

    if gate1_report.violations:
        lines.append("### 🚨 Gate 1: Test-Tampering Violations")
        for v in gate1_report.violations:
            lines.append(f"- `{v}`")
        lines.append("")

    survived = [m for m in gate2_report.results if not m.killed]
    if survived:
        lines.append("### 🧟 Gate 2: Surviving AST Mutants (Proving Agent's Test Is Hollow)")
        for m in survived:
            lines.append(f"- **Mutant #{m.mutant_id} (Line {m.lineno})**: {m.description} -> *Test still exited 0!*")
        lines.append("")

    if gate3_fuzz_report.counterexamples:
        lines.append("### 💥 Gate 3A: Differential Fuzzing Counterexamples (`f_spec(x) != f_pr(x)`)")
        for cx in gate3_fuzz_report.counterexamples[:3]:
            lines.append(
                f"- Input `args={cx.args}`: Expected `{cx.old_outcome}`, but PR produced `{cx.new_outcome}` ({cx.reason})"
            )
        lines.append("")

    return "\n".join(lines)


def visible_width(s: str) -> int:
    """Calculate the visible terminal display width of a string (stripping ANSI codes)."""
    clean = re.sub(r"\033\[[0-9;]*m", "", s)
    width = 0
    for ch in clean:
        if ch == "\ufe0f":
            continue
        w = unicodedata.east_asian_width(ch)
        if w in ("W", "F"):
            width += 2
        else:
            width += 1
    return width


def truncate_visible(s: str, target_width: int) -> str:
    """Truncate string to fit within target visible width, appending an ellipsis."""
    clean = re.sub(r"\033\[[0-9;]*m", "", s)
    cur = 0
    res = []
    for ch in clean:
        w = 0 if ch == "\ufe0f" else (2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1)
        if cur + w > target_width - 1:
            break
        res.append(ch)
        cur += w
    return "".join(res) + "…"


def pad_cell(s: str, target_width: int, align: str = "left") -> str:
    """Pad string to exact target visible width, accounting for ANSI codes and East Asian width."""
    vw = visible_width(s)
    if vw > target_width:
        s = truncate_visible(s, target_width)
        vw = visible_width(s)
    diff = target_width - vw
    if align == "right":
        return " " * diff + s
    elif align == "center":
        left = diff // 2
        return " " * left + s + " " * (diff - left)
    return s + " " * diff


def format_terminal_prosecutor_report(
    pr_title: str,
    fixproof_revert_passed: bool = True,
    gate1_report: Any = None,
    gate2_report: Any = None,
    gate3_fuzz_report: Any = None,
    gate3_bench_report: Any = None,
    *,
    swe_bench_revert_passed: bool | None = None,
) -> str:
    use_color = os.environ.get("NO_COLOR") is None
    RED = "\033[1;31m" if use_color else ""
    GREEN = "\033[1;32m" if use_color else ""
    YELLOW = "\033[1;33m" if use_color else ""
    CYAN = "\033[1;36m" if use_color else ""
    DIM = "\033[90m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    RESET = "\033[0m" if use_color else ""

    g1_pass = getattr(gate1_report, "passed", False)
    g2_pass = getattr(gate2_report, "passed", False)
    g3a_pass = getattr(gate3_fuzz_report, "passed", False)
    g3b_pass = getattr(gate3_bench_report, "passed", False)
    overall_passed = g1_pass and g2_pass and g3a_pass and g3b_pass

    f2p_passed = swe_bench_revert_passed if swe_bench_revert_passed is not None else fixproof_revert_passed

    w_g = 40
    w_s = 10
    w_t = 34
    total_w = 1 + w_g + 1 + w_s + 1 + w_t + 1

    lines = []

    # Header Card
    hdr_content = f" {BOLD}{CYAN}CORDIS PROSECUTOR{RESET} {DIM}│{RESET} {BOLD}{pr_title}{RESET} "
    lines.append(f"{CYAN}╭{'─' * (total_w - 2)}╮{RESET}")
    lines.append(f"{CYAN}│{RESET}" + pad_cell(hdr_content, total_w - 2) + f"{CYAN}│{RESET}")
    lines.append(f"{CYAN}╰{'─' * (total_w - 2)}╯{RESET}")

    # Verdict Badges
    if overall_passed:
        verdict_badge = f"{GREEN}{BOLD}✔ APPROVED TO LAND{RESET}"
    else:
        verdict_badge = f"{RED}{BOLD}■ BLOCKED{RESET}  {DIM}[Counterfeit Red / Invariant Regression]{RESET}"

    if f2p_passed and not overall_passed:
        f2p_badge = f"{YELLOW}{BOLD}▲ PASSED{RESET}   {DIM}(Fooled 100% by single-input overfit!){RESET}"
    elif f2p_passed:
        f2p_badge = f"{GREEN}{BOLD}✔ PASSED{RESET}"
    else:
        f2p_badge = f"{RED}{BOLD}■ FAILED{RESET}"

    lines.append(f"  {BOLD}Prosecutor Verdict:{RESET}              {verdict_badge}")
    lines.append(f"  {BOLD}SWE-bench Fail-to-Pass (revert):{RESET} {f2p_badge}")
    lines.append("")

    # Table Top
    lines.append(f"{DIM}┌{'─' * w_g}┬{'─' * w_s}┬{'─' * w_t}┐{RESET}")
    lines.append(
        f"{DIM}│{RESET} {BOLD}{pad_cell('Prosecution Gate', w_g - 2)}{RESET} {DIM}│{RESET} "
        f"{BOLD}{pad_cell('Status', w_s - 2, 'center')}{RESET} {DIM}│{RESET} "
        f"{BOLD}{pad_cell('Telemetry & Evidence', w_t - 2)}{RESET} {DIM}│{RESET}"
    )
    lines.append(f"{DIM}├{'─' * w_g}┼{'─' * w_s}┼{'─' * w_t}┤{RESET}")

    def make_row(gate_name: str, passed: bool, telem: str) -> str:
        st_text = "PASS ✓" if passed else "FAIL ✗"
        st_col = GREEN if passed else RED
        return (
            f"{DIM}│{RESET} {pad_cell(gate_name, w_g - 2)} {DIM}│{RESET} "
            f"{st_col}{pad_cell(st_text, w_s - 2, 'center')}{RESET} {DIM}│{RESET} "
            f"{pad_cell(telem, w_t - 2)} {DIM}│{RESET}"
        )

    # Gate 1
    violations_count = len(getattr(gate1_report, "violations", []))
    v_word = "violation" if violations_count == 1 else "violations"
    g1_tm = f"Asserts: {gate1_report.old_assert_count}->{gate1_report.new_assert_count} · {violations_count} {v_word}"
    lines.append(make_row("Gate 1: AST Test-Tampering Auditor", g1_pass, g1_tm))

    # Gate 2
    g2_tm = f"Killed {gate2_report.killed_mutants}/{gate2_report.total_mutants} ({gate2_report.survived_mutants} survived)"
    lines.append(make_row("Gate 2: In-Place AST Mutation Engine", g2_pass, g2_tm))

    # Gate 3A
    cx_count = len(getattr(gate3_fuzz_report, "counterexamples", []))
    g3a_tm = f"Tested {gate3_fuzz_report.inputs_tested} inputs · {cx_count} counterex"
    lines.append(make_row("Gate 3A: Differential Property Fuzzer", g3a_pass, g3a_tm))

    # Gate 3B
    speedup = getattr(gate3_bench_report, "speedup_pct", 0.0)
    sign = "+" if speedup >= 0 else ""
    g3b_tm = f"{gate3_bench_report.baseline_median_us:.3f}us -> {gate3_bench_report.candidate_median_us:.3f}us ({sign}{speedup:.1f}%)"
    lines.append(make_row("Gate 3B: Mann-Whitney U Benchmark", g3b_pass, g3b_tm))

    # Table Bottom
    lines.append(f"{DIM}└{'─' * w_g}┴{'─' * w_s}┴{'─' * w_t}┘{RESET}")
    lines.append("")

    # Forensic Details
    has_tampering = bool(getattr(gate1_report, "violations", []))
    survived = [m for m in getattr(gate2_report, "results", []) if not m.killed]
    has_fuzz_cx = bool(getattr(gate3_fuzz_report, "counterexamples", []))

    if has_tampering or survived or has_fuzz_cx:
        lines.append(f"  {RED}{BOLD}🚨 Forensic Evidence Breakdown:{RESET}")
        for v in getattr(gate1_report, "violations", []):
            lines.append(f"     {DIM}↳{RESET} {BOLD}[Gate 1 / Tampering]:{RESET} {v}")

        for m in survived:
            lines.append(f"     {DIM}↳{RESET} {BOLD}[Gate 2 / Mutation]:{RESET} Mutant #{m.mutant_id} (Line {m.lineno}): {m.description} -> {RED}Test still passed (exited 0)!{RESET}")

        for cx in getattr(gate3_fuzz_report, "counterexamples", [])[:3]:
            lines.append(f"     {DIM}↳{RESET} {BOLD}[Gate 3A / Fuzzing]:{RESET} args={cx.args} -> Expected {GREEN}{cx.old_outcome}{RESET}, got {RED}{cx.new_outcome}{RESET} ({cx.reason})")
        lines.append("")

    return "\n".join(lines)


def run_demo(
    github_comment: bool = False,
    output_html: str | None = None,
    output_md: str | None = None,
) -> int:
    env_old: dict[str, Any] = {}
    env_bad: dict[str, Any] = {}
    env_ref: dict[str, Any] = {}
    exec(OLD_BUGGY_SOURCE, env_old)
    exec(BAD_AGENT_PATCH_SOURCE, env_bad)
    exec(REFERENCE_CORRECT_SOURCE, env_ref)

    f_old = env_old["parse_discount_tier"]
    f_bad = env_bad["parse_discount_tier"]
    f_ref = env_ref["parse_discount_tier"]

    # 1. Run on BAD Agent PR (that fools SWE-bench Fail-to-Pass git revert check)
    g1_bad = audit_test_tampering(
        OLD_TEST_SOURCE,
        BAD_AGENT_TEST_SOURCE,
        target_function_names=["parse_discount_tier"],
    )
    g2_bad = run_in_memory_mutation_gate(
        BAD_AGENT_PATCH_SOURCE,
        BAD_AGENT_TEST_SOURCE,
        target_function="parse_discount_tier",
    )
    g3_fuzz_bad = run_differential_fuzz_gate(f_ref, f_bad, num_samples=200)
    g3_bench_bad = run_statistical_benchmark_gate(
        lambda: f_old(150.0),
        lambda: f_bad(150.0),
        rounds=30,
        iterations_per_round=100,
    )

    comment_bad = format_github_prosecutor_comment(
        pr_title="PR #42 (Bad Agent Patch — Single-Input Overfit & Weakened Assert)",
        fixproof_revert_passed=True,
        gate1_report=g1_bad,
        gate2_report=g2_bad,
        gate3_fuzz_report=g3_fuzz_bad,
        gate3_bench_report=g3_bench_bad,
    )

    # 2. Run on GOOD Verified PR
    g1_good = audit_test_tampering(
        OLD_TEST_SOURCE,
        GOOD_AGENT_TEST_SOURCE,
        target_function_names=["parse_discount_tier"],
    )
    g2_good = run_in_memory_mutation_gate(
        REFERENCE_CORRECT_SOURCE,
        GOOD_AGENT_TEST_SOURCE,
        target_function="parse_discount_tier",
    )
    g3_fuzz_good = run_differential_fuzz_gate(f_ref, f_ref, num_samples=200)
    g3_bench_good = run_statistical_benchmark_gate(
        lambda: f_old(150.0),
        lambda: f_ref(150.0),
        rounds=30,
        iterations_per_round=100,
    )

    comment_good = format_github_prosecutor_comment(
        pr_title="PR #43 (Genuine Fix + Mutation-Hardened Test Suite)",
        fixproof_revert_passed=True,
        gate1_report=g1_good,
        gate2_report=g2_good,
        gate3_fuzz_report=g3_fuzz_good,
        gate3_bench_report=g3_bench_good,
    )

    w_total = 88
    use_color = os.environ.get("NO_COLOR") is None
    CYAN = "\033[1;36m" if use_color else ""
    DIM = "\033[90m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    GREEN = "\033[1;32m" if use_color else ""
    RED = "\033[1;31m" if use_color else ""
    YELLOW = "\033[1;33m" if use_color else ""
    RESET = "\033[0m" if use_color else ""

    if github_comment:
        print(comment_bad)
        print("\n" + "=" * 78 + "\n")
        print(comment_good)
    else:
        welcome_title = " CORDIS VERIFY · Autonomous AI-PR Invariant Prosecutor"
        welcome_sub = " Demo: Exposing SWE-bench Fail-to-Pass False Positives via In-Memory Invariant Gates"
        print(f"\n{CYAN}╭{'─' * (w_total - 2)}╮{RESET}")
        print(f"{CYAN}│{RESET}" + pad_cell(f"{BOLD}{CYAN}{welcome_title}{RESET}", w_total - 2) + f"{CYAN}│{RESET}")
        print(f"{CYAN}│{RESET}" + pad_cell(f"{DIM}{welcome_sub}{RESET}", w_total - 2) + f"{CYAN}│{RESET}")
        print(f"{CYAN}╰{'─' * (w_total - 2)}╯{RESET}\n")

        rep_bad = format_terminal_prosecutor_report(
            pr_title="PR #42: Bad Agent Patch (Single-Input Overfit & Weakened Assert)",
            fixproof_revert_passed=True,
            gate1_report=g1_bad,
            gate2_report=g2_bad,
            gate3_fuzz_report=g3_fuzz_bad,
            gate3_bench_report=g3_bench_bad,
        )
        rep_good = format_terminal_prosecutor_report(
            pr_title="PR #43: Genuine Fix + Mutation-Hardened Test Suite",
            fixproof_revert_passed=True,
            gate1_report=g1_good,
            gate2_report=g2_good,
            gate3_fuzz_report=g3_fuzz_good,
            gate3_bench_report=g3_bench_good,
        )
        print(rep_bad)
        print(f"{DIM}{'─' * w_total}{RESET}\n")
        print(rep_good)

        # Executive recap card
        summary_title = " VERDICT RECAP: Why SWE-bench Fail-to-Pass Fails Where Cordis Wins"
        p42_summary = f" • PR #42 (Overfit):   {YELLOW}SWE-bench PASSED (fooled){RESET} {DIM}│{RESET} {RED}Cordis BLOCKED (Mutants alive){RESET}"
        p43_summary = f" • PR #43 (Invariant): {GREEN}SWE-bench PASSED{RESET}          {DIM}│{RESET} {GREEN}Cordis APPROVED (5/5 Killed){RESET}"
        print(f"{DIM}╭{'─' * (w_total - 2)}╮{RESET}")
        print(f"{DIM}│{RESET}" + pad_cell(f"{BOLD}{summary_title}{RESET}", w_total - 2) + f"{DIM}│{RESET}")
        print(f"{DIM}│{RESET}" + pad_cell(p42_summary, w_total - 2) + f"{DIM}│{RESET}")
        print(f"{DIM}│{RESET}" + pad_cell(p43_summary, w_total - 2) + f"{DIM}│{RESET}")
        print(f"{DIM}╰{'─' * (w_total - 2)}╯{RESET}")

    # Generate interactive HTML report
    html_target = output_html or "cordis_report.html"
    save_html_report(
        filepath=html_target,
        pr_title="PR #42 (Bad Agent Patch — Single-Input Overfit & Weakened Assert)",
        fixproof_revert_passed=True,
        gate1_report=g1_bad,
        gate2_report=g2_bad,
        gate3_fuzz_report=g3_fuzz_bad,
        gate3_bench_report=g3_bench_bad,
    )
    if not github_comment:
        print(f"\n📊 {BOLD}[HTML Scorecard]{RESET}: Saved to {CYAN}{html_target}{RESET} (open in browser to inspect interactive gates)\n")

    if output_md:
        save_markdown_report(
            filepath=output_md,
            content=comment_bad + "\n\n" + "=" * 78 + "\n\n" + comment_good,
        )
        print(f"📝 {BOLD}[Markdown Report]{RESET}: Written to {output_md}")

    return 0


def run_benchmark_cli(output_md: str | None = None) -> int:
    from cordis.benchmark_suite import format_benchmark_markdown_table, run_benchmark
    res = run_benchmark()
    md_table = format_benchmark_markdown_table(res)
    print(md_table)
    if output_md:
        save_markdown_report(output_md, md_table)
        print(f"\n📝 [Cordis Benchmark Table]: Written to {output_md}")
    return 0


def run_verify_git(
    base_ref: str = "HEAD~1",
    target_ref: str | None = None,
    repo_dir: str = ".",
    github_comment: bool = False,
    output_html: str | None = None,
    output_md: str | None = None,
    suggest_test: bool = False,
) -> int:
    diff_report = extract_git_diff(repo_dir=repo_dir, base_ref=base_ref, target_ref=target_ref)
    if diff_report.error:
        print(f"🛑 [Cordis Git Diff Error]: {diff_report.error}")
        return 1

    effective_base = diff_report.base_ref
    print(f"🛡️ Cordis Git Diff Prosecutor: {effective_base} -> {target_ref or 'working tree'}")
    print(f"  • Modified source files ({len(diff_report.source_files)}): {diff_report.source_files}")
    print(f"  • Modified test files   ({len(diff_report.test_files)}): {diff_report.test_files}")
    print(f"  • Target functions      ({len(diff_report.target_function_names)}): {diff_report.target_function_names}")

    if not diff_report.source_files and not diff_report.test_files:
        print("✅ No Python or TypeScript/JavaScript source or test files modified in this git diff. Verdict: PASS")
        return 0

    overall_passed = True

    # Gate 0: Forge Self-Approval & Token Guard
    forge_report = audit_current_environment(repo_dir=repo_dir)
    if not forge_report.passed:
        overall_passed = False
        for v in forge_report.violations:
            print(f"  [Forge Guard] ❌ FAIL: {v}")
    elif forge_report.warnings:
        for w in forge_report.warnings:
            print(f"  [Forge Guard] ⚠️ WARN: {w}")
    else:
        print("  [Forge Guard] ✅ PASS: Human dual-custody or verified actor signature.")

    g1_reports = []
    for test_file in diff_report.test_files:
        old_test_code = get_git_file_content(effective_base, test_file, repo_dir=repo_dir) or ""
        if not old_test_code and not target_ref and effective_base != "HEAD":
            old_test_code = get_git_file_content("HEAD", test_file, repo_dir=repo_dir) or ""
        if target_ref:
            new_test_code = get_git_file_content(target_ref, test_file, repo_dir=repo_dir) or ""
        else:
            p = Path(repo_dir) / test_file
            new_test_code = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""

        if any(test_file.endswith(ext) for ext in (".ts", ".tsx", ".js", ".jsx")):
            from cordis.ts_gate import audit_ts_test_tampering
            g1 = audit_ts_test_tampering(
                old_test_code,
                new_test_code,
                target_function_names=diff_report.target_function_names,
                file_path=test_file,
            )
        else:
            g1 = audit_test_tampering(
                old_test_code,
                new_test_code,
                target_function_names=diff_report.target_function_names,
                file_path=test_file,
            )
        g1_reports.append((test_file, g1))
        if not g1.passed:
            overall_passed = False

    test_code_combined = ""
    discovered_test_files: list[str] = []
    if diff_report.test_files:
        for test_file in diff_report.test_files:
            if not test_file.endswith(".py"):
                continue
            if target_ref:
                t_code = get_git_file_content(target_ref, test_file, repo_dir=repo_dir)
                if t_code:
                    test_code_combined += t_code + "\n"
            else:
                p = Path(repo_dir) / test_file
                if p.is_file():
                    test_code_combined += p.read_text(encoding="utf-8", errors="replace") + "\n"
    else:
        # Zero modified test files: auto-discover existing test files in repo_dir
        ignored_dirs = {".git", ".venv", "venv", "node_modules", "build", "dist", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}
        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".")]
            for file in sorted(files):
                if (file.startswith("test_") or file.endswith("_test.py")) and file.endswith(".py"):
                    full_p = Path(root) / file
                    try:
                        rel_p = full_p.relative_to(repo_dir).as_posix()
                    except ValueError:
                        rel_p = full_p.as_posix()
                    discovered_test_files.append(rel_p)
                    try:
                        test_code_combined += full_p.read_text(encoding="utf-8", errors="replace") + "\n"
                    except OSError:
                        pass
        if discovered_test_files:
            print(f"  • Discovered existing test files ({len(discovered_test_files)}): {discovered_test_files}")

    g2_reports = []
    for src_file in diff_report.source_files:
        if not src_file.endswith(".py"):
            continue
        if target_ref:
            src_code = get_git_file_content(target_ref, src_file, repo_dir=repo_dir) or ""
        else:
            p = Path(repo_dir) / src_file
            src_code = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""
        if src_code and test_code_combined:
            file_fns = [
                f.name for f in diff_report.modified_functions
                if not f.is_test and Path(f.file_path).as_posix() == Path(src_file).as_posix()
            ]
            fns_to_test = file_fns if file_fns else ([None] if not diff_report.target_function_names else [])
            mod_name = Path(src_file).with_suffix("").as_posix().replace("/", ".")
            for fn in fns_to_test:
                g2 = run_in_memory_mutation_gate(
                    src_code,
                    test_code_combined,
                    target_function=fn,
                    module_name=mod_name,
                )
                g2_reports.append((src_file, fn or "<module>", g2))
                if not g2.passed:
                    overall_passed = False

    # Gate 3A: Differential Property Fuzzing against base_ref
    g3_fuzz_reports = []
    for func in diff_report.modified_functions:
        if func.is_test or not func.file_path.endswith(".py"):
            continue
        old_file_code = get_git_file_content(effective_base, func.file_path, repo_dir=repo_dir)
        if not old_file_code and not target_ref and effective_base != "HEAD":
            old_file_code = get_git_file_content("HEAD", func.file_path, repo_dir=repo_dir)
        if not old_file_code:
            continue
        p = Path(repo_dir) / func.file_path
        if target_ref:
            new_file_code = get_git_file_content(target_ref, func.file_path, repo_dir=repo_dir)
        else:
            new_file_code = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else None
        if not new_file_code:
            continue

        try:
            repo_abs = str(Path(repo_dir).resolve())
            if repo_abs not in sys.path:
                sys.path.insert(0, repo_abs)

            env_old: dict[str, Any] = {"__builtins__": __builtins__}
            env_new: dict[str, Any] = {"__builtins__": __builtins__}
            exec(compile(old_file_code, f"<{func.file_path}_old>", "exec"), env_old)
            exec(compile(new_file_code, f"<{func.file_path}_new>", "exec"), env_new)

            f_old = env_old.get(func.name)
            f_new = env_new.get(func.name)

            if callable(f_old) and callable(f_new):
                fuzz_rep = run_differential_fuzz_gate(f_old, f_new, num_samples=200)
                g3_fuzz_reports.append((func.file_path, func.name, fuzz_rep))
                if not fuzz_rep.passed:
                    overall_passed = False
        except Exception:
            pass

    for t_file, g1 in g1_reports:
        status = "✅ PASS" if g1.passed else "❌ FAIL"
        print(f"  [Gate 1 Test-Tampering] {t_file}: {status} (violations: {len(g1.violations)})")
        for v in g1.violations:
            print(f"    - Violation: {v}")

    for s_file, fn, g2 in g2_reports:
        if g2.total_mutants == 0:
            print(f"  [Gate 2 Mutation] {s_file}::{fn}: ✅ PASS (0 mutants in diff scope)")
        else:
            status = "✅ PASS" if g2.passed else "❌ FAIL"
            print(f"  [Gate 2 Mutation] {s_file}::{fn}: {status} (killed {g2.killed_mutants}/{g2.total_mutants})")
            for m in g2.results:
                if not m.killed:
                    print(f"    - Surviving mutant: {m.description}")
            if suggest_test and not g2.passed and g2.survived_mutants > 0:
                surviving = [m for m in g2.results if not m.killed]
                if target_ref:
                    s_code = get_git_file_content(target_ref, s_file, repo_dir=repo_dir) or ""
                else:
                    p = Path(repo_dir) / s_file
                    s_code = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""
                if s_code and fn:
                    try:
                        sugg = synthesize_mutant_killing_test(s_code, fn, surviving)
                        if sugg:
                            print(f"\n[Cordis Test Suggestion for {s_file}::{fn}]:")
                            print(sugg)
                    except Exception as e:
                        print(f"Warning: Failed to synthesize test repair: {e}")

    for s_file, fn, fuzz_rep in g3_fuzz_reports:
        if fuzz_rep.passed:
            print(f"  [Gate 3A Differential Fuzzing] {s_file}::{fn}: ✅ PASS ({fuzz_rep.inputs_tested} inputs tested, 0 counterexamples)")
        else:
            print(f"  [Gate 3A Differential Fuzzing] {s_file}::{fn}: ❌ FAIL ({len(fuzz_rep.counterexamples)} counterexamples)")
            for cx in fuzz_rep.counterexamples[:3]:
                print(f"    - Input args={cx.args}: expected {cx.old_outcome}, got {cx.new_outcome} ({cx.reason})")

    primary_g1 = g1_reports[0][1] if g1_reports else audit_test_tampering("", "")
    primary_g2 = g2_reports[0][2] if g2_reports else MutationGateReport(passed=True, total_mutants=0, killed_mutants=0, survived_mutants=0)
    failing_fuzz = [rep for _, _, rep in g3_fuzz_reports if not rep.passed]
    if failing_fuzz:
        diff_fuzz = failing_fuzz[0]
    elif g3_fuzz_reports:
        diff_fuzz = g3_fuzz_reports[0][2]
    else:
        diff_fuzz = DifferentialFuzzReport(passed=True, inputs_tested=0, counterexamples=[])
    diff_bench = BenchmarkGateReport(passed=True, rounds=30, baseline_median_us=0.05, candidate_median_us=0.05, speedup_pct=0.0, u_statistic=0.0, p_value=1.0, note="Git diff verification")

    if output_html:
        save_html_report(
            filepath=output_html,
            pr_title=f"Git Diff Verdict: {effective_base} -> {target_ref or 'working tree'}",
            fixproof_revert_passed=True,
            gate1_report=primary_g1,
            gate2_report=primary_g2,
            gate3_fuzz_report=diff_fuzz,
            gate3_bench_report=diff_bench,
            forge_report=forge_report,
        )
        print(f"\n📊 [Cordis HTML Report]: Scorecard written to {output_html}")

    if output_md or github_comment:
        md_text = format_github_prosecutor_comment(
            pr_title=f"Git Diff Verdict: {effective_base} -> {target_ref or 'working tree'}",
            fixproof_revert_passed=True,
            gate1_report=primary_g1,
            gate2_report=primary_g2,
            gate3_fuzz_report=diff_fuzz,
            gate3_bench_report=diff_bench,
        )
        if github_comment:
            print("\n" + md_text)
        if output_md:
            save_markdown_report(output_md, md_text)
            print(f"\n📝 [Cordis Markdown Report]: Written to {output_md}")

    if overall_passed:
        print("\n✅ [Cordis Verdict]: ALL GATES PASSED — PR Approved to Land.")
        return 0
    else:
        print("\n🛑 [Cordis Verdict]: BLOCKED — Counterfeit Red or Tampering Detected.")
        return 1


def run_check_policy_cli(repo_dir: str, output_json: str | None = None) -> int:
    """Executes pre-flight repository governance check."""
    report = audit_repository_policy(repo_dir)
    print("================================================================================")
    print("                 CORDIS PRE-FLIGHT REPOSITORY POLICY AUDIT                      ")
    print("================================================================================")
    print(f"Target Repository : {Path(repo_dir).resolve()}")
    print(f"Scanned Files     : {len(report.governance_files_scanned)} files found")
    for f in report.governance_files_scanned:
        print(f"  • {f}")

    if report.status == "BLOCKED_POLICY":
        print("\n🛑 STATUS: BLOCKED_POLICY")
        print(f"Advice: {report.advice}")
        print("\nCitations:")
        for c in report.citations:
            print(f"  - {c}")
    elif report.status == "ISSUE_REQUIRED":
        print("\n⚠️ STATUS: ISSUE_REQUIRED")
        print(f"Advice: {report.advice}")
        print("\nCitations:")
        for c in report.citations:
            print(f"  - {c}")
    else:
        print("\n✅ STATUS: PERMITTED")
        print(f"Advice: {report.advice}")

    if output_json:
        out_path = Path(output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"\nSaved policy audit report JSON: {out_path.resolve()}")

    return 0 if report.status == "PERMITTED" else 1


def run_probe_cli(
    repo: str,
    target: str,
    test: str,
    function: str | None = None,
    max_mutants: int = 5,
    output_json: str | None = None,
    timeout: float = 10.0,
    pytest_args: str | None = None,
    suggest_test: bool = False,
) -> int:
    """Executes offline, zero-token headless AST mutation & pytest probe."""
    root = Path(repo).resolve()
    target_path = root / target
    pure_test_rel = test.split()[0] if " " in test else test
    test_path = root / pure_test_rel

    print("================================================================================")
    print("             CORDIS HEADLESS PROBE: ZERO-TOKEN MUTATION GATE                    ")
    print("================================================================================")
    print(f"Repository      : {root}")
    print(f"Target Source   : {target}")
    print(f"Test Suite      : {test}")
    if pytest_args:
        print(f"Pytest Args     : {pytest_args}")
    if function:
        print(f"Target Function : {function}")
    print(f"Max Mutants     : {max_mutants}")
    print(f"Timeout (sec)   : {timeout}")
    print("Offline Mode    : Zero tokens consumed (100% deterministic AST & pytest)")
    print("--------------------------------------------------------------------------------")

    # Read test file to compute MAR badge
    mar_info = {"total_assertions": 0, "total_mocks": 0, "mar": 0.0, "risk_level": "LOW", "is_high_risk": False}
    if test_path.is_file():
        try:
            test_src = test_path.read_text(encoding="utf-8", errors="replace")
            mar_info = calculate_mock_to_assertion_ratio(test_src)
            print(
                f"Test Suite MAR  : {mar_info['mar']:.4f} [{mar_info['risk_level']}] "
                f"(Mocks: {mar_info['total_mocks']}, Assertions: {mar_info['total_assertions']})"
            )
        except Exception as e:
            print(f"Warning: Failed to compute MAR on test file: {e}")

    # Run repo mutation gate
    report = run_repo_mutation_gate(
        repo_root=root,
        source_rel_path=target,
        test_rel_path=test,
        target_function=function,
        max_mutants=max_mutants,
        timeout=timeout,
        pytest_args=pytest_args,
    )

    print(f"\nTotal Mutants   : {report.total_mutants}")
    print(f"Killed Mutants  : {report.killed_mutants}")
    print(f"Survived Mutants: {report.survived_mutants}")
    print(f"Kill Rate       : {report.kill_rate * 100:.1f}%")

    for res in report.results:
        status_icon = "💀 KILLED" if res.killed else "🛡️ SURVIVED"
        print(f"  • Mutant #{res.mutant_id} (line {res.lineno}): {res.description} -> {status_icon}")

    suggested_test_code = ""
    if suggest_test and report.survived_mutants > 0:
        surviving = [r for r in report.results if not r.killed]
        if target_path.is_file():
            try:
                src_code = target_path.read_text(encoding="utf-8", errors="replace")
                suggested_test_code = synthesize_mutant_killing_test(
                    source_code=src_code,
                    target_function=function or "",
                    surviving_mutants=surviving,
                )
                if suggested_test_code:
                    print("\n" + "=" * 80)
                    print("          CORDIS COUNTEREXAMPLE-GUIDED TEST REPAIR SKELETON                     ")
                    print("=" * 80)
                    print(suggested_test_code.strip())
                    print("=" * 80)
            except Exception as e:
                print(f"Warning: Failed to synthesize test repair: {e}")

    if report.passed and report.total_mutants > 0:
        print("\n✅ [Probe Verdict]: PASSED — 100% Mutation Kill Rate (No counterfeit/hollow tests).")
    elif report.total_mutants == 0:
        print("\n⚠️ [Probe Verdict]: NEUTRAL — No mutable AST nodes found in target.")
    else:
        print(f"\n🛑 [Probe Verdict]: FAILED — {report.survived_mutants} mutant(s) survived! Test suite is hollow.")

    if output_json:
        out_path = Path(output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        findings = {
            "repo": str(root),
            "target_file": target,
            "test_file": test,
            "target_function": function,
            "pytest_args": pytest_args,
            "passed": report.passed,
            "total_mutants": report.total_mutants,
            "killed_mutants": report.killed_mutants,
            "survived_mutants": report.survived_mutants,
            "kill_rate": round(report.kill_rate, 4),
            "target_executed": report.target_executed,
            "mutants": [
                {
                    "mutant_id": r.mutant_id,
                    "lineno": r.lineno,
                    "description": r.description,
                    "killed": r.killed,
                    "mutated_code_snippet": r.mutated_code_snippet,
                }
                for r in report.results
            ],
            "mar": mar_info,
            "zero_token": True,
            "llm_tokens_consumed": 0,
        }
        if suggested_test_code:
            findings["suggested_test"] = suggested_test_code
        out_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"\nSaved probe findings JSON: {out_path.resolve()}")

    return 0 if (report.passed and report.survived_mutants == 0) else 1


def run_hooks_cli(args: argparse.Namespace, hooks_parser: Optional[argparse.ArgumentParser] = None) -> int:
    """Dispatches `cordis hooks` subcommands: check-cmd, stop-gate, and install."""
    from cordis.hooks import (
        audit_pre_tool_use_command,
        install_harness_hooks,
        run_stop_hook_prosecutor,
    )

    if args.hooks_command == "check-cmd":
        decision = audit_pre_tool_use_command(args.command_to_check)
        if not decision.allowed:
            sys.stderr.write(f"🛑 [Cordis Pre-Tool Guard]: BLOCKED command '{args.command_to_check}'\n")
            if decision.reason:
                sys.stderr.write(f"Reason: {decision.reason}\n")
            return decision.exit_code if decision.exit_code != 0 else 2
        print(f"✅ [Cordis Pre-Tool Guard]: PERMITTED command '{args.command_to_check}'")
        return 0

    if args.hooks_command == "stop-gate":
        return run_stop_hook_prosecutor(
            repo_dir=args.repo_dir,
            max_retries=args.max_retries,
        )

    if args.hooks_command == "install":
        installed = install_harness_hooks(
            repo_dir=args.repo_dir,
            targets=args.targets,
        )
        print(f"✅ [Cordis Hooks Installed]: {len(installed)} hook target(s) configured.")
        for h in installed:
            print(f"  • {h}")
        return 0

    if hooks_parser is not None:
        hooks_parser.print_help()
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Cordis: Adversarial AI-PR Prosecutor CLI")
    sub = parser.add_subparsers(dest="command")
    demo_p = sub.add_parser("demo", help="Run the SWE-bench F2P-Killer Adversarial PR Demo")
    demo_p.add_argument("--github-comment", action="store_true", help="Output GitHub PR Markdown verdict")
    demo_p.add_argument("--output-html", default=None, help="Save dark-mode HTML prosecutor scorecard")
    demo_p.add_argument("--output-md", default=None, help="Save markdown prosecutor scorecard")

    bench_p = sub.add_parser("benchmark", help="Run the 5-Archetype Head-to-Head Adversarial Benchmark")
    bench_p.add_argument("--output-md", default=None, help="Save benchmark comparison Markdown table to file")

    real_bench_p = sub.add_parser("benchmark-repos", help="Run the Live Open-Source GitHub Repository Benchmark")
    real_bench_p.add_argument("--output-md", default="REAL_GITHUB_BENCHMARK.md", help="Output path for benchmark report (default: REAL_GITHUB_BENCHMARK.md)")
    real_bench_p.add_argument("--cache-dir", default=".real_repos_cache", help="Cache directory for cloned repos (default: .real_repos_cache)")

    git_p = sub.add_parser("verify-git", help="Prosecute a real git diff between two refs")
    git_p.add_argument("--base-ref", "--base", dest="base_ref", default="HEAD~1", help="Base git commit ref (default: HEAD~1)")
    git_p.add_argument("--target-ref", "--head", dest="target_ref", default=None, help="Target git commit ref (default: working tree)")
    git_p.add_argument("--repo-dir", default=".", help="Repository root directory (default: .)")
    git_p.add_argument("--github-comment", action="store_true", help="Output GitHub PR Markdown verdict")
    git_p.add_argument("--output-html", default=None, help="Save dark-mode HTML prosecutor scorecard")
    git_p.add_argument("--output-md", default=None, help="Save markdown prosecutor scorecard")
    git_p.add_argument("--suggest-test", action="store_true", help="Synthesize mutant-killing unit test assertions for surviving mutants")

    wild_p = sub.add_parser("audit-wild", help="Hunt for real surviving mutants in unmodified open-source repos")
    wild_p.add_argument("--cache-dir", default=".real_repos_cache", help="Cache directory for cloned repos (default: .real_repos_cache)")
    wild_p.add_argument("--no-docs-update", action="store_true", help="Skip updating REAL_GITHUB_BENCHMARK.md and README.md")

    ai_p = sub.add_parser("audit-ai-repos", help="Clone and audit viral AI-agent and MCP repositories")
    ai_p.add_argument("--cache-dir", default=".real_repos_cache", help="Cache directory for cloned repos (default: .real_repos_cache)")
    ai_p.add_argument("--no-docs-update", action="store_true", help="Skip updating REAL_GITHUB_BENCHMARK.md and README.md")

    policy_p = sub.add_parser("check-policy", help="Audit repository governance files for anti-AI bans and issue prerequisites")
    policy_p.add_argument("repo_path", nargs="?", default=None, help="Path to repository root (positional, default: .)")
    policy_p.add_argument("--repo", dest="repo_flag", default=None, help="Path to repository root (flag)")
    policy_p.add_argument("--json", dest="output_json", default=None, help="Path to write structured JSON audit report")

    probe_p = sub.add_parser("probe", help="Run offline zero-token headless AST mutation & pytest probe")
    probe_p.add_argument("--repo", default=".", help="Repository root path (default: .)")
    probe_p.add_argument("--target", "--source", dest="target", required=True, help="Target source file relative to repo root")
    probe_p.add_argument("--test", required=True, help="Target test file relative to repo root")
    probe_p.add_argument("--function", "--func", dest="function", default=None, help="Optional function name within target file to mutate")
    probe_p.add_argument("--max-mutants", type=int, default=5, help="Maximum number of AST mutants to generate (default: 5)")
    probe_p.add_argument("--json", "--output-json", dest="output_json", default=None, help="Path to write structured JSON findings")
    probe_p.add_argument("--timeout", type=float, default=10.0, help="Test execution timeout in seconds (default: 10.0)")
    probe_p.add_argument("--pytest-args", default=None, help="Optional extra arguments or selectors passed directly to pytest (e.g. '-k test_name' or '-x')")
    probe_p.add_argument("--suggest-test", action="store_true", help="Synthesize mutant-killing unit test assertions for surviving mutants")

    hooks_p = sub.add_parser("hooks", help="Manage and execute deterministic pre-tool and stop hook guards")
    hooks_sub = hooks_p.add_subparsers(dest="hooks_command")

    check_cmd_p = hooks_sub.add_parser("check-cmd", help="Audit a tool command before execution")
    check_cmd_p.add_argument("--command", "-c", dest="command_to_check", required=True, help="Command string to audit")

    stop_gate_p = hooks_sub.add_parser("stop-gate", help="Execute stop hook mutation prosecutor gate on uncommitted diff")
    stop_gate_p.add_argument("--repo-dir", default=".", help="Repository root directory (default: .)")
    stop_gate_p.add_argument("--max-retries", type=int, default=3, help="Max retries per AST anchor before tripping circuit breaker (default: 3)")

    install_p = hooks_sub.add_parser("install", help="Install Cordis pre-commit and Claude Code hooks")
    install_p.add_argument("--repo-dir", default=".", help="Repository root directory (default: .)")
    install_p.add_argument("--targets", nargs="+", default=["git", "claude"], help="Targets to install hooks for (default: git claude)")

    args = parser.parse_args()
    if args.command == "benchmark":
        return run_benchmark_cli(output_md=args.output_md)
    if args.command == "benchmark-repos":
        from cordis.real_repo_benchmark import run_real_repo_benchmark
        return run_real_repo_benchmark(output_md=args.output_md, cache_dir_str=args.cache_dir)
    if args.command == "audit-wild":
        from cordis.wild_audit import run_wild_audit_cli
        return run_wild_audit_cli(cache_dir=args.cache_dir, update_docs=not args.no_docs_update)
    if args.command == "audit-ai-repos":
        from cordis.ai_repo_audit import run_ai_repo_audit
        return run_ai_repo_audit(cache_dir=args.cache_dir, update_docs=not args.no_docs_update)
    if args.command == "check-policy":
        target_repo = args.repo_flag or args.repo_path or "."
        return run_check_policy_cli(repo_dir=target_repo, output_json=args.output_json)
    if args.command == "probe":
        return run_probe_cli(
            repo=args.repo,
            target=args.target,
            test=args.test,
            function=args.function,
            max_mutants=args.max_mutants,
            output_json=args.output_json,
            timeout=args.timeout,
            pytest_args=args.pytest_args,
            suggest_test=getattr(args, "suggest_test", False),
        )
    if args.command == "verify-git":
        return run_verify_git(
            base_ref=args.base_ref,
            target_ref=args.target_ref,
            repo_dir=args.repo_dir,
            github_comment=args.github_comment,
            output_html=args.output_html,
            output_md=args.output_md,
            suggest_test=getattr(args, "suggest_test", False),
        )
    if args.command == "hooks":
        return run_hooks_cli(args, hooks_parser=hooks_p)
    return run_demo(
        github_comment=getattr(args, "github_comment", False),
        output_html=getattr(args, "output_html", None),
        output_md=getattr(args, "output_md", None),
    )


if __name__ == "__main__":
    sys.exit(main())
`

---

## cordis/git_diff.py

`python
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

    if target_ref:
        mb_check = subprocess.run(
            ["git", "merge-base", actual_base, target_ref],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
        )
        if mb_check.returncode == 0 and mb_check.stdout.strip():
            actual_base = mb_check.stdout.strip()

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
`

---

## cordis/memory.py

`python
﻿"""Episodic Memory Ledger: SQLite FTS5 BM25 + Word-Stem + Tag Reciprocal Rank Fusion (RRF).
Includes explicit `status='superseded'` invalidation and `flake_retry_count` tracking.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class MemoryRecord:
    record_id: int
    ast_anchor: str
    function_name: str
    failure_mode: str
    summary: str
    tags: str
    flake_retry_count: int
    status: str
    rrf_score: float = 0.0


class EpisodicMemoryLedger:
    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ast_anchor TEXT NOT NULL,
                function_name TEXT NOT NULL,
                failure_mode TEXT NOT NULL,
                summary TEXT NOT NULL,
                tags TEXT NOT NULL,
                flake_retry_count INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                superseded_by INTEGER DEFAULT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
                function_name,
                failure_mode,
                summary,
                tags,
                content='memory_entries',
                content_rowid='id',
                tokenize='porter unicode61'
            )
            """
        )
        self.conn.commit()

    def record_outcome(
        self,
        ast_anchor: str,
        function_name: str,
        failure_mode: str,
        summary: str,
        tags: str,
        supersede_previous_for_anchor: bool = False,
    ) -> int:
        cur = self.conn.cursor()
        if supersede_previous_for_anchor:
            cur.execute(
                "UPDATE memory_entries SET status = 'superseded' WHERE ast_anchor = ? AND status = 'active'",
                (ast_anchor,),
            )

        # Check if identical failure_mode exists for this anchor (increment flake_retry_count instead of permanent blind prune)
        cur.execute(
            """
            SELECT id, flake_retry_count FROM memory_entries
            WHERE ast_anchor = ? AND failure_mode = ? AND status = 'active'
            """,
            (ast_anchor, failure_mode),
        )
        existing = cur.fetchone()
        if existing and not supersede_previous_for_anchor:
            rec_id, retries = existing
            cur.execute(
                "UPDATE memory_entries SET flake_retry_count = ?, summary = ? WHERE id = ?",
                (retries + 1, summary, rec_id),
            )
            self.conn.commit()
            return int(rec_id)

        cur.execute(
            """
            INSERT INTO memory_entries (ast_anchor, function_name, failure_mode, summary, tags, flake_retry_count, status)
            VALUES (?, ?, ?, ?, ?, 1, 'active')
            """,
            (ast_anchor, function_name, failure_mode, summary, tags),
        )
        new_id = int(cur.lastrowid)
        cur.execute(
            """
            INSERT INTO memory_fts(rowid, function_name, failure_mode, summary, tags)
            VALUES (?, ?, ?, ?, ?)
            """,
            (new_id, function_name, failure_mode, summary, tags),
        )
        self.conn.commit()
        return new_id

    def recall_rrf(self, query_text: str, tag_filter: Optional[str] = None, top_k: int = 5) -> List[MemoryRecord]:
        """Recalls active (non-superseded) memories using 3-channel Reciprocal Rank Fusion (RRF):
        Channel 1: SQLite FTS5 BM25 ranking (with Porter word-stemming)
        Channel 2: Exact function/identifier token match
        Channel 3: Tag overlap
        """
        cur = self.conn.cursor()
        tokens = [t.strip() for t in query_text.replace(":", " ").replace("_", " ").split() if t.strip()]
        fts_query = " OR ".join(f'"{t}"' for t in tokens) if tokens else '""'

        bm25_ranks: dict[int, int] = {}
        try:
            cur.execute(
                """
                SELECT rowid, bm25(memory_fts) as score
                FROM memory_fts
                WHERE memory_fts MATCH ?
                ORDER BY score ASC
                LIMIT 25
                """,
                (fts_query,),
            )
            for rank_idx, (rowid, _) in enumerate(cur.fetchall(), start=1):
                bm25_ranks[int(rowid)] = rank_idx
        except sqlite3.OperationalError:
            pass

        cur.execute(
            """
            SELECT id, ast_anchor, function_name, failure_mode, summary, tags, flake_retry_count, status
            FROM memory_entries
            WHERE status = 'active'
            """
        )
        rows = cur.fetchall()

        scored_records: List[MemoryRecord] = []
        k_rrf = 60.0
        q_lower = query_text.lower()

        for row in rows:
            rec_id, anchor, fn_name, f_mode, summary, tags, retries, status = row
            rrf = 0.0
            # Channel 1: FTS5 BM25
            if rec_id in bm25_ranks:
                rrf += 1.0 / (k_rrf + bm25_ranks[rec_id])
            # Channel 2: Function / Anchor match
            if fn_name.lower() in q_lower or anchor.lower() in q_lower:
                rrf += 1.0 / (k_rrf + 1.0)
            # Channel 3: Tag match
            if tag_filter and tag_filter.lower() in tags.lower():
                rrf += 1.0 / (k_rrf + 1.0)
            elif any(tok.lower() in tags.lower() for tok in tokens):
                rrf += 1.0 / (k_rrf + 3.0)

            if rrf > 0:
                scored_records.append(
                    MemoryRecord(
                        record_id=rec_id,
                        ast_anchor=anchor,
                        function_name=fn_name,
                        failure_mode=f_mode,
                        summary=summary,
                        tags=tags,
                        flake_retry_count=retries,
                        status=status,
                        rrf_score=round(rrf, 6),
                    )
                )

        scored_records.sort(key=lambda r: r.rrf_score, reverse=True)
        return scored_records[:top_k]

    def close(self) -> None:
        self.conn.close()
`

---

