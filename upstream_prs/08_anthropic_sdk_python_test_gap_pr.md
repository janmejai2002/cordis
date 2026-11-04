# PR Brief: Add Unit Test Coverage for Non-Dict JSON Payloads in `_sessions_token_from_secret`

**Repository:** `anthropics/anthropic-sdk-python`  
**Target File:** `src/anthropic/lib/environments/_worker.py`  
**Target Function:** `_sessions_token_from_secret`  
**Patch File:** `findings/anthropic-sdk-python_fix.patch`  
**Discovery Engine:** Cordis Verification Engine (Gate 2 Coverage-Verified Mutation Analysis)

---

## 1. Problem Statement

In `src/anthropic/lib/environments/_worker.py`, `_sessions_token_from_secret(secret: str | None) -> str | None` extracts the per-item sessions bearer token from a work item's URL-safe base64 `secret` payload.

Lines 295–296 guard against payloads that decode to valid JSON that are not JSON objects (dictionaries):
```python
if not isinstance(parsed, dict):
    return None
```

However, upstream tests in `tests/lib/environments/test_worker.py::test_sessions_token_from_secret` only tested invalid base64 and non-JSON plaintext (`b"plain text"`), which raises `json.JSONDecodeError` and exits earlier on line 293. The test suite did **not** test valid base64-encoded JSON that decodes to non-dict JSON primitives (lists, strings, numbers, booleans).

As a result, an AST mutation perturbing line 296 (`return None` to a non-None value or removing the check) **survived** upstream test runs with zero failures.

---

## 2. Invariant Fix

Added explicit unit test assertions in `tests/lib/environments/test_worker.py::test_sessions_token_from_secret` verifying that valid base64-encoded JSON scalars and sequences (`list`, `str`, `int`, `bool`) correctly resolve to `None`:

```python
assert _sessions_token_from_secret(base64.urlsafe_b64encode(b'["sessions-token-abc"]').decode()) is None
assert _sessions_token_from_secret(base64.urlsafe_b64encode(b'"sessions-token-abc"').decode()) is None
assert _sessions_token_from_secret(base64.urlsafe_b64encode(b"12345").decode()) is None
assert _sessions_token_from_secret(base64.urlsafe_b64encode(b"true").decode()) is None
```

---

## 3. Verification & Mutation Kill Rate

- **Probe Verification:** `report.target_executed == True` (function execution actively verified under test suite).
- **Upstream Mutation Score:** 5/6 killed (1 mutant survived).
- **Post-Patch Mutation Score:** **6/6 killed (100% kill rate, 0 survived)**.
- **Pytest Output:** Clean pass (`1 passed, 38 deselected in 0.59s`).
