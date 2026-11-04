# PR Brief: Add Unit Test Coverage for Exact Duration Unit Values in `duration_in_seconds`

**Repository:** `BerriAI/litellm`  
**Target File:** `litellm/litellm_core_utils/duration_parser.py`  
**Target Function:** `duration_in_seconds`  
**Test File:** `tests/unit/litellm_core_utils/test_duration_parser.py`  
**Patch File:** `findings/litellm_fix.patch`  
**Discovery Engine:** Cordis Verification Engine (Gate 2 Coverage-Verified Mutation Analysis)

---

## 1. Problem Statement

In `litellm/litellm_core_utils/duration_parser.py`, `duration_in_seconds(duration: str) -> int` converts standardized string duration representations into integer seconds for provider budget routing and proxy key/team generation:

```python
def duration_in_seconds(duration: str) -> int:
    value, unit = _extract_from_regex(duration=normalize_duration(duration))

    if unit == "s":
        return value
    elif unit == "m":
        return value * 60
    elif unit == "h":
        return value * 3600
    elif unit == "d":
        return value * 86400
    elif unit == "w":
        return value * 604800
    ...
```

However, upstream tests in `tests/unit/litellm_core_utils/test_duration_parser.py` only verified `duration_in_seconds` for non-month units via:
```python
@pytest.mark.parametrize("duration", ["45s", "30m", "1h", "1d", "7d", "2w", "30d", "daily", "monthly"])
def test_fixed_length_units_do_not_depend_on_the_start(duration):
    assert duration_in_seconds_from(datetime(2026, 2, 10, 12, tzinfo=timezone.utc), duration) == duration_in_seconds(
        duration
    )
```

Because `duration_in_seconds_from` internally forwards directly to `duration_in_seconds` for all non-month units (`if unit != "mo": return duration_in_seconds(duration)`), this test was a structural tautology (`f(x) == f(x)`).

Consequently, AST mutations perturbing:
1. Line 67: `return value` to `None` for seconds (`"s"`)
2. Line 69: `return value * 60` to `None` for minutes (`"m"`)
3. Line 69: `value * 60` operator mutation to `value / 60`

all **survived** upstream test runs undetected.

---

## 2. Invariant Fix

Added explicit unit test `test_duration_in_seconds_units_exact_values()` in `tests/unit/litellm_core_utils/test_duration_parser.py`:

```python
def test_duration_in_seconds_units_exact_values():
    assert duration_in_seconds("45s") == 45
    assert duration_in_seconds("30m") == 1800
    assert duration_in_seconds("1h") == 3600
    assert duration_in_seconds("1d") == 86400
    assert duration_in_seconds("1w") == 604800
    assert duration_in_seconds("7d") == 604800
```

---

## 3. Verification & Mutation Kill Rate

- **Probe Verification:** `report.target_executed == True` (function execution actively verified under test suite).
- **Upstream Mutation Score:** 7/10 killed (3 mutants survived).
- **Post-Patch Mutation Score:** **10/10 killed (100% kill rate, 0 survived)**:
  - Line 67 (`return value` to `None`): **KILLED**
  - Line 69 (`return value * 60` to `None`): **KILLED**
  - Line 69 (`*` to `/`): **KILLED**
- **Pytest Output:** Clean pass (`49 passed in 8.51s`).
