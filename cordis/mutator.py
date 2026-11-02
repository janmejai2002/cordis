"""Gate 2: Diff-Scoped In-Place AST Mutation Engine ('Counterfeit Red' & Hollow-Test Killer)."""
from __future__ import annotations

import ast
import copy
import io
import os
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


@dataclass
class MutationGateReport:
    passed: bool
    total_mutants: int
    killed_mutants: int
    survived_mutants: int
    results: List[MutantResult] = field(default_factory=list)
    target_executed: bool = True

    @property
    def kill_rate(self) -> float:
        return (self.killed_mutants / self.total_mutants) if self.total_mutants > 0 else 0.0


class _SingleMutantCandidate:
    def __init__(self, description: str, lineno: int, apply_fn: Callable[[ast.AST], ast.AST]) -> None:
        self.description = description
        self.lineno = lineno
        self.apply_fn = apply_fn


def _find_target_function_node(
    tree: ast.AST, target_function: str
) -> Optional[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Finds FunctionDef or AsyncFunctionDef matching target_function name or Class.name path."""
    parts = target_function.split(".")
    if len(parts) == 2:
        cls_name, fn_name = parts
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == cls_name:
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub.name == fn_name:
                        return sub
    fn_base = parts[-1]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == fn_base:
                return node
    return None


def generate_ast_mutants(
    source_code: str,
    target_function: Optional[str] = None,
    max_mutants: int = 5,
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

    # Collect nodes inside `if __name__ == ...` checks to avoid mutating them
    name_main_nodes: set[ast.AST] = set()
    for node in ast.walk(base_tree):
        if isinstance(node, ast.If):
            if any(isinstance(sub, ast.Name) and sub.id == "__name__" for sub in ast.walk(node.test)):
                for child in ast.walk(node):
                    name_main_nodes.add(child)

    # Identify candidate node positions by (lineno, col_offset, type)
    candidates: List[tuple[int, int, str, str]] = []
    for n in probe_nodes:
        if n in name_main_nodes:
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
                candidates.append((lineno, col, "compare_lt_lte", "Boundary shift `<` to `<=`"))
                candidates.append((lineno, col, "compare_lt", "Flip `<` to `>=`"))
            elif isinstance(op, ast.LtE):
                candidates.append((lineno, col, "compare_lte_lt", "Boundary shift `<=` to `<`"))
                candidates.append((lineno, col, "compare_lte", "Flip `<=` to `>`"))
            elif isinstance(op, ast.Gt):
                candidates.append((lineno, col, "compare_gt_gte", "Boundary shift `>` to `>=`"))
                candidates.append((lineno, col, "compare_gt", "Flip `>` to `<=`"))
            elif isinstance(op, ast.GtE):
                candidates.append((lineno, col, "compare_gte_gt", "Boundary shift `>=` to `>`"))
                candidates.append((lineno, col, "compare_gte", "Flip `>=` to `<`"))
        elif isinstance(n, ast.BinOp):
            if isinstance(n.op, ast.Add):
                candidates.append((lineno, col, "binop_add", "Flip `+` to `-`"))
            elif isinstance(n.op, ast.Sub):
                candidates.append((lineno, col, "binop_sub", "Flip `-` to `+`"))
            elif isinstance(n.op, ast.Mult):
                candidates.append((lineno, col, "binop_mult", "Flip `*` to `/`"))
        elif isinstance(n, ast.Return) and n.value is not None:
            if isinstance(n.value, ast.Constant) and isinstance(n.value.value, (int, float)) and not isinstance(n.value.value, bool):
                candidates.append((lineno, col, "return_const_num", f"Perturb return constant `{n.value.value}`"))
            elif isinstance(n.value, ast.Constant) and isinstance(n.value.value, bool):
                candidates.append((lineno, col, "return_const_bool", f"Flip return boolean `{n.value.value}`"))
            else:
                candidates.append((lineno, col, "return_none", "Replace return expression with `None`"))

    # Deduplicate and prioritize diverse mutations up to max_mutants
    seen = set()
    unique_candidates = []
    for item in candidates:
        key = (item[0], item[1], item[2])
        if key not in seen:
            seen.add(key)
            unique_candidates.append(item)

    for lineno, col, kind, desc in unique_candidates[:max_mutants]:
        tree_copy = copy.deepcopy(base_tree)
        applied = False

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
                elif kind == "return_none" and isinstance(n, ast.Return):
                    n.value = ast.Constant(value=None)
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
) -> MutationGateReport:
    """Executes all assertions in `test_code` against each AST mutant of `source_code`.
    Works 100% in-process (sub-millisecond) with module-level patching and dataclass
    compatibility for Python 3.10-3.13+, guaranteeing zero Windows file-locking issues.
    """
    mutants = generate_ast_mutants(source_code, target_function=target_function, max_mutants=max_mutants)
    if not mutants:
        return MutationGateReport(
            passed=True,
            total_mutants=0,
            killed_mutants=0,
            survived_mutants=0,
            results=[],
        )

    results: List[MutantResult] = []
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
        except Exception:
            # Any AssertionError or runtime exception means the test KILLED the mutant!
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
            )
        )

    survived = len(results) - killed_count
    passed = (survived == 0)
    return MutationGateReport(
        passed=passed,
        total_mutants=len(results),
        killed_mutants=killed_count,
        survived_mutants=survived,
        results=results,
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
        )

    orig_bytes = source_full.read_bytes()
    source_code = orig_bytes.decode("utf-8", errors="replace")

    mutants = generate_ast_mutants(source_code, target_function=target_function, max_mutants=max_mutants)
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

    test_arg = str(Path(test_rel_path))
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        test_arg,
        "-q",
        "-o",
        "asyncio_default_fixture_loop_scope=function",
    ] if has_pytest else [sys.executable, "-m", "unittest", test_arg]

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
            if proc.returncode in (2, 3, 4, 5) or "INTERNALERROR" in out or "ERROR collecting" in out:
                return False, proc.returncode, out

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
            )
            for idx, (desc, lineno, _) in enumerate(mutants, start=1)
        ]
        return MutationGateReport(
            passed=False,
            total_mutants=len(results),
            killed_mutants=0,
            survived_mutants=len(results),
            results=results,
            target_executed=False,
        )

    results: List[MutantResult] = []
    killed_count = 0

    try:
        for idx, (desc, lineno, mutated_src) in enumerate(mutants, start=1):
            killed = False
            try:
                source_full.write_text(mutated_src, encoding="utf-8")
                executed, retcode, _ = _execute_test_cycle()
                if executed and retcode not in (0, 2):
                    killed = True
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
                )
            )
    finally:
        source_full.write_bytes(orig_bytes)

    survived = len(results) - killed_count
    return MutationGateReport(
        passed=(survived == 0),
        total_mutants=len(results),
        killed_mutants=killed_count,
        survived_mutants=survived,
        results=results,
        target_executed=True,
    )
