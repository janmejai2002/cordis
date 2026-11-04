"""Gate 2: Diff-Scoped In-Place AST Mutation Engine ('Counterfeit Red' & Hollow-Test Killer)."""
from __future__ import annotations

import ast
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
                if not _is_boundary_constrained(base_tree, n, "compare_lt_lte"):
                    candidates.append((lineno, col, "compare_lt_lte", "Boundary shift `<` to `<=`"))
                candidates.append((lineno, col, "compare_lt", "Flip `<` to `>=`"))
            elif isinstance(op, ast.LtE):
                if not _is_boundary_constrained(base_tree, n, "compare_lte_lt"):
                    candidates.append((lineno, col, "compare_lte_lt", "Boundary shift `<=` to `<`"))
                candidates.append((lineno, col, "compare_lte", "Flip `<=` to `>`"))
            elif isinstance(op, ast.Gt):
                if not _is_boundary_constrained(base_tree, n, "compare_gt_gte"):
                    candidates.append((lineno, col, "compare_gt_gte", "Boundary shift `>` to `>=`"))
                candidates.append((lineno, col, "compare_gt", "Flip `>` to `<=`"))
            elif isinstance(op, ast.GtE):
                if not _is_boundary_constrained(base_tree, n, "compare_gte_gt"):
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
            elif isinstance(n.value, ast.Constant) and n.value.value is None:
                candidates.append((lineno, col, "return_const_none", "Perturb `return None` to non-None"))
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

        if kind == "unary_not_remove":
            remover = _UnaryNotRemover(lineno, col)
            tree_copy = remover.visit(tree_copy)
            applied = remover.applied
        elif kind == "unary_not_add":
            adder = _UnaryNotAdder(lineno, col)
            tree_copy = adder.visit(tree_copy)
            applied = adder.applied
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

    test_args = shlex.split(test_rel_path) if " " in test_rel_path else [str(Path(test_rel_path))]
    test_arg = test_args[0] if test_args else str(Path(test_rel_path))
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        *test_args,
        "-q",
        "-o",
        "asyncio_default_fixture_loop_scope=function",
    ] if has_pytest else [sys.executable, "-m", "unittest", *test_args]

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
