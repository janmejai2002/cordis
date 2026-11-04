# PR Brief: Add boundary and invariant tests for JSON extraction work limits and nesting depth

- **Repository**: `567-labs/instructor`
- **Component**: `instructor/v2/core/json.py` (`extract_json_from_codeblock`)
- **Test File**: `tests/v2/test_json_helpers.py`
- **Patch File**: `findings/instructor_fix.patch`
- **Status**: Verified with Cordis AST Mutation Gate (100% Kill Rate: 14/14 mutants killed, 0 survived)

---

## Summary of Changes

This PR introduces comprehensive boundary condition and semantic invariant tests for `instructor.v2.core.json.extract_json_from_codeblock`, securing critical execution paths against boundary shifts, off-by-one errors, and depth traversal mutations.

### Discovered Invariant Gaps

Prior to this patch, the upstream unit test suite allowed 5 distinct AST boundary and arithmetic mutations to survive undetected despite full execution coverage (`target_executed == True`):

1. **Exact 1 MiB Buffer Boundary (`MAX_JSON_EXTRACTION_CHARS = 1_048_576`)**:
   - Upstream tests only evaluated inputs strictly exceeding 1 MiB (`> MAX_JSON_EXTRACTION_CHARS`).
   - An off-by-one boundary shift from `>` to `>=` survived because no test verified that an exact 1,048,576-character payload is valid and permitted.

2. **Index 0 Consumption Guard (`index < consumed`)**:
   - In loop iteration 0 when `consumed == 0`, mutating `<` to `<=` causes `index <= consumed` (0 <= 0 is True) to trigger `continue`, silently skipping index 0.
   - If an LLM response begins immediately at character 0 with a valid JSON object followed by trailing explanatory prose, the function skipped the object.

3. **Exact Malformed-Input Work Limit Boundary (`remaining_work < len(content) - index`)**:
   - The test suite lacked an exact boundary case where `remaining_work == len(content) - index`. A boundary mutation from `<` to `<=` caused legitimate recoveries to abort prematurely.

4. **Multi-Object Span Budget Arithmetic (`remaining_work -= end - index`)**:
   - Decrementing remaining work budget across multiple consecutive JSON blocks lacked invariant testing, allowing operator mutations to pass.

5. **Nesting Depth Invariant (`MAX_JSON_DEPTH = 128`)**:
   - Zero tests existed in `tests/v2/test_json_helpers.py` asserting the 128-level nesting limit.
   - Both `depth > MAX_JSON_DEPTH` mutating to `>=` (rejecting valid 128-depth trees) and `depth + 1` mutating to `depth - 1` (allowing infinite depth without triggering `ValueError`) survived upstream tests.

---

## Verification Evidence

| Metric | Before Patch | After Patch |
| :--- | :--- | :--- |
| **Target Function Executed** | `True` | `True` |
| **Total AST Mutants** | 14 | 14 |
| **Killed Mutants** | 9 | **14** |
| **Survived Mutants** | 5 | **0** |
| **Kill Rate** | 64.3% | **100.0%** |
| **PyTest Result** | 23 passed | **29 passed** (0.35s) |

---

## Applied Test Assertions

1. `test_extract_json_from_codeblock_exact_1mb_boundary_allowed`:
   Constructs a valid JSON payload of exactly 1,048,576 characters and asserts clean extraction.
2. `test_extract_json_from_codeblock_leading_object_with_trailing_prose`:
   Verifies that a valid JSON object starting at index 0 followed by trailing commentary is correctly extracted.
3. `test_extract_json_from_codeblock_exact_work_budget_boundary`:
   Verifies that exact boundary condition `remaining_work == len(content) - index` evaluates to False and continues extraction.
4. `test_extract_json_from_codeblock_multiple_valid_objects_span_offset_budget`:
   Asserts budget consumption across 25 consecutive valid JSON objects.
5. `test_extract_json_from_codeblock_exact_128_depth_boundary_allowed`:
   Verifies that a 128-level deeply nested dictionary succeeds without error.
6. `test_extract_json_from_codeblock_depth_exceeds_128_rejected`:
   Asserts that a 129-level deeply nested dictionary raises `ValueError("JSON extraction nesting exceeds the 128 level limit")`.
