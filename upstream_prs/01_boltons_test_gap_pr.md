# Upstream PR: Fix Missing Boundary & Branch Assertions in `clamp()` and `cardinalize()`

- **Target Repository**: [mahmoud/boltons](https://github.com/mahmoud/boltons)
- **Target Commit**: `d31d821d56c8f7756af9c30a864077f2e5855321` (`d31d821`)
- **Target Files**: `tests/test_mathutils.py`, `tests/test_strutils.py`
- **Discovered By**: Cordis Adversarial AST Mutation Gate (Experiment C: Wild Open-Source Audit)

---

## 1. Upstream GitHub PR Submission Template

### PR Title
`test(mathutils, strutils): add boundary validation tests for clamp() and full branch coverage for cardinalize()`

### PR Description
```markdown
### Summary
This pull request strengthens test coverage for two fundamental utility functions in `boltons`:
1. `boltons.mathutils.clamp`: Adds explicit boundary validation for when `upper == lower` (e.g. `clamp(5, 2, 2) == 2`) and tests that inverted bounds (`upper < lower`) correctly raise `ValueError`.
2. `boltons.strutils.cardinalize`: Adds dedicated unit tests exercising both the singular (`count == 1`) and pluralized (`count != 1`, including zero and multi-item) formatting branches, which currently lack unit tests in `test_strutils.py`.

### Problem & Invariant Verification
During an AST mutation audit using Cordis:
- In `clamp()` (`boltons/mathutils.py:66`), shifting the boundary comparison `upper < lower` to `upper <= lower` survived unit tests because `upper == lower` was never asserted.
- In `cardinalize()` (`boltons/strutils.py:196-198`), mutating return values or flipping `count == 1` to `!=` survived completely (3/3 mutants survived) because `tests/test_strutils.py` contained no test cases calling `cardinalize()`.

### Verification
Ran test suite before and after:
```powershell
pytest tests/test_mathutils.py tests/test_strutils.py -q
```
Result: All existing tests continue to pass; all newly added tests pass cleanly.
```

---

## 2. Unified Git Diff Patch

```diff
diff --git a/tests/test_mathutils.py b/tests/test_mathutils.py
index 39f9e0c..aef2da6 100644
--- a/tests/test_mathutils.py
+++ b/tests/test_mathutils.py
@@ -157,3 +157,16 @@ def test_bits_rshift_past_width():
     assert len(shifted) == 0
     assert shifted.as_bin() == ''
     assert Bits('101') >> 1 == Bits('10')
+
+
+def test_clamp_boundary_and_inverted_bounds():
+    from pytest import raises
+    from boltons.mathutils import clamp
+    # Boundary validation: upper == lower
+    assert clamp(5, 2, 2) == 2
+    assert clamp(1, 2, 2) == 2
+    # Inverted bounds raising ValueError
+    with raises(ValueError):
+        clamp(5, lower=10, upper=2)
+    with raises(ValueError):
+        clamp(0, 5, 4)
diff --git a/tests/test_strutils.py b/tests/test_strutils.py
index 1c7e45a..ce2a8b9 100644
--- a/tests/test_strutils.py
+++ b/tests/test_strutils.py
@@ -443,3 +443,14 @@ def test_args2cmd_sep():
     assert strutils.args2cmd(['aa', 'bb']) == 'aa bb'
     assert strutils.args2cmd(['aa', 'bb'], sep='|') == 'aa|bb'
     assert strutils.args2cmd(['a a', 'bb'], sep='|') == '"a a"|bb'
+
+
+def test_cardinalize_unit_and_plural():
+    from boltons.strutils import cardinalize
+    # Count == 1 branch
+    assert cardinalize("apple", 1) == "apple"
+    assert cardinalize("Day", 1) == "Day"
+    # Count != 1 branch
+    assert cardinalize("apple", 2) == "apples"
+    assert cardinalize("apple", 0) == "apples"
+    assert cardinalize("Wish", 3) == "Wishes"
```

---

## 3. Before vs. After AST Mutation Telemetry

| Target Function | Test Suite | Baseline (Wild `HEAD`) | With Upstream Patch | Status |
| :--- | :--- | :---: | :---: | :---: |
| `boltons.mathutils:clamp()` | `tests/test_mathutils.py` | 2 Killed / 1 Survived (`33.3%` Survival) | **3 Killed / 0 Survived (`100%` Killed)** | 🛡️ **Gap Closed** |
| `boltons.strutils:cardinalize()` | `tests/test_strutils.py` | 0 Killed / 3 Survived (`100.0%` Survival) | **3 Killed / 0 Survived (`100%` Killed)** | 🛡️ **Gap Closed** |

### Specific Mutants Defeated
- `clamp()` Line 66: `Boundary shift < to <=` (Mutant defeated by `clamp(5, 2, 2) == 2`)
- `clamp()` Line 66: `Flip < to >=` (Mutant defeated by `raises(ValueError)`)
- `cardinalize()` Line 196: Flip `==` to `!=` (Defeated by `cardinalize("apple", 1) == "apple"`)
- `cardinalize()` Line 197: `Replace return with None` (Defeated by singular assertions)
- `cardinalize()` Line 198: `Replace return with None` (Defeated by plural assertions)
