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
            is_mock_call = (
                func_str.startswith("unittest.mock.")
                or func_str.startswith("mock.")
                or func_str.startswith("mocker.")
                or func_str.startswith("monkeypatch.")
                or func_str == "patch"
                or func_str.startswith("patch.")
                or func_str in ("MagicMock", "Mock")
                or func_str.endswith((".MagicMock", ".Mock"))
            )
            if is_mock_call:
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
