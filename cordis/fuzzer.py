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
