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
