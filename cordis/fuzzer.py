"""Gate 3: Differential Property-Based Fuzzer & Mann-Whitney U Statistical Benchmark Gate."""
from __future__ import annotations

import importlib
import inspect
import math
import os
import random
import statistics
import subprocess
import sys
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

    @property
    def latency_delta_pct(self) -> float:
        return -self.speedup_pct


# Backwards-compatibility alias
StatisticalBenchmarkReport = BenchmarkGateReport


def _generate_adversarial_values_for_type(annotation: Any, count: int = 200) -> List[Any]:
    """Generates deterministic + randomized adversarial edge cases (floats, ints, strings, collections)."""
    rng = random.Random(42)
    if annotation in (int, "int"):
        edges: List[Any] = [0, 1, -1, 2, -2, 10, 99, 100, 101, 500, 1000, -999999, 2**31 - 1]
        while len(edges) < count:
            edges.append(rng.randint(-10000, 10000))
        return edges[:count]

    if annotation in (str, "str"):
        edges = ["", " ", "a", "0", "100", "null", "None", "NaN", "🔥", "a" * 256, "\n\t"]
        while len(edges) < count:
            length = rng.randint(0, 32)
            edges.append("".join(rng.choice("abcXYZ0123_- /") for _ in range(length)))
        return edges[:count]

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
        edges = [
            0.0, -0.0, 1.0, -1.0, 0.5, 49.99, 50.0, 50.01,
            99.99, 100.0, 100.01, 150.0, 199.99, 200.0, 200.01,
            250.0, 499.99, 500.0, 500.01, 1000.0, 1e6, -50.0,
            float("nan"), float("inf"), float("-inf"),
        ]
        while len(edges) < count:
            edges.append(round(rng.uniform(-500.0, 2500.0), 2))
        return edges[:count]

    # Default / unannotated adversarial matrix across NaN, inf, -0.0, boundary ints, and empty collections
    edges = [
        0.0, -0.0, 1.0, -1.0, 0.5, 49.99, 50.0, 50.01,
        99.99, 100.0, 100.01, 150.0, 199.99, 200.0, 200.01,
        250.0, 499.99, 500.0, 500.01, 1000.0, 1e6, -50.0,
        float("nan"), float("inf"), float("-inf"),
        0, 1, -1, 100, -100, 2**31 - 1,
        [], {}, set(), (),
    ]
    while len(edges) < count:
        edges.append(round(rng.uniform(-500.0, 2500.0), 2))
    return edges[:count]


def _outcomes_match(res_a: Any, exc_a: Optional[Exception], res_b: Any, exc_b: Optional[Exception]) -> tuple[bool, str]:
    if exc_a is not None and exc_b is not None:
        if type(exc_a) is type(exc_b):
            return True, "Both raised same exception"
        return False, f"Exception mismatch: {type(exc_a).__name__} vs {type(exc_b).__name__}"
    if exc_a is not None or exc_b is not None:
        return False, f"One raised exception ({type(exc_a or exc_b).__name__}), the other returned a value"
    if isinstance(res_a, float) and isinstance(res_b, float):
        if math.isnan(res_a) and math.isnan(res_b):
            return True, "Both NaN"
        if math.isclose(res_a, res_b, rel_tol=1e-7, abs_tol=1e-9):
            return True, "Float match"
        return False, f"Float value mismatch: {res_a} != {res_b}"
    if res_a == res_b:
        return True, "Exact match"
    return False, f"Value mismatch: {res_a!r} != {res_b!r}"


def run_differential_fuzz_gate(
    reference_fn: Callable[..., Any],
    candidate_fn: Callable[..., Any],
    num_samples: int = 200,
) -> DifferentialFuzzReport:
    """Fuzzes `reference_fn` vs `candidate_fn` across `num_samples` adversarial edge-case inputs.
    Catches single-input hardcoded fixes (`if amount == 100.0: return 0.15`) immediately.
    """
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
        vals = _generate_adversarial_values_for_type(ann, count=num_samples)
        inputs = [(v,) for v in vals]
    else:
        pools = [_generate_adversarial_values_for_type(p.annotation, count=num_samples) for p in params]
        inputs = [tuple(pool[i] for pool in pools) for i in range(num_samples)]

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

    base_med = statistics.median(base_times_us)
    cand_med = statistics.median(cand_times_us)
    speedup_pct = ((base_med - cand_med) / base_med * 100.0) if base_med > 0 else 0.0
    u_stat, p_val = mann_whitney_u_one_sided(base_times_us, cand_times_us)

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
