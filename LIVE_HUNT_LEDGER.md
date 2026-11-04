# CORDIS WILD INVARIANT HUNT — MASTER LEDGER
**Engine:** Cordis Verification Engine (64-bit AST Hasher, Anti-Mock Gate 1, Diff-Scoped In-Place AST Mutator Gate 2)  
**Host:** Windows 11 | Python 3.13 (`C:\Users\Janmejai\cordis_live_lab\.venv`)  
**Corpus:** 5 Tier-1 AI & Developer Infrastructure Repositories (`pydantic-ai`, `instructor`, `anthropic-sdk-python`, `openai-python`, `litellm`)  
**Timestamp:** 2026-11-03T10:30:00+05:30  
**Status:** COMPLETED (All 5 Tier-1 Repositories Audited & Verified)

---

## 1. Executive Master Summary Table

| Repository | Focus / Role | Python Files | AST Funcs Indexed | Test Files | Total Asserts | Weak Asserts (`is not None`) | AST Mocks (`@patch`, etc.) | Mock Density | AI Commits (n=30) | Gate 2 Target Functions Tested | Survived Mutants (`target_executed==True`) | Verified Patch (`.patch`) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`pydantic-ai`** | Pydantic Agent Framework | 2,234 | 62,064 | 1,164 | 64,071 | 2,893 (4.52%) | 2,970 | 0.0464 | 5 / 25 | `_utils.strip_markdown_fences`, `format_prompt.format_as_xml`, `_uuid.uuid7` | **3 survived** in `_uuid.uuid7` (boundary `<` to `<=`, `>` to `>=`, `>` to `<=`) | `findings/pydantic-ai_fix.patch` (**VERIFIED: 100% killed**, 9/9) |
| **`instructor`** | Structured LLM Outputs | 605 | 4,219 | 258 | 5,489 | 177 (3.22%) | 461 | 0.0840 | 4 / 30 | `_get_span`, `is_simple_type`, `extract_json_from_codeblock` | **5 survived** in `extract_json_from_codeblock` (1MB bound, index 0 skip, nesting depth 128 bounds) | `findings/instructor_fix.patch` (**VERIFIED: 100% killed**, 14/14) |
| **`anthropic-sdk-python`** | Official Anthropic SDK | 2,938 | 12,409 | 263 | 14,357 | 116 (0.81%) | 172 | 0.0120 | 30 / 30 | `_calculate_retry_timeout`, `BetaLocalFilesystemMemoryTool.view`, `_sessions_token_from_secret` | **1 survived** in `_sessions_token_from_secret` (non-dict JSON secret return None bypass) | `findings/anthropic-sdk-python_fix.patch` (**VERIFIED: 100% killed**, 6/6) |
| **`openai-python`** | Official OpenAI SDK | 2,519 | 13,597 | 385 | 13,645 | 143 (1.05%) | 783 | 0.0574 | 3 / 25 | `_retry_delay` | **3 survived** in `_retry_delay` (status 500 boundary `< 500` to `<= 500`, standard `retry-after` seconds `return delay`) | `findings/openai-python_fix.patch` (**VERIFIED: 100% killed**, 9/10, 1 equivalent) |
| **`litellm`** | Universal LLM Proxy & Router | 8,730 | 167,064 | 5,452 | 212,122 | 5,947 (2.80%) | 69,011 | **0.3253** | 7 / 25 | `get_budget_window_start`, `duration_in_seconds` | **3 survived** in `duration_in_seconds` (hollow tautological assertions allowed seconds `"s"` and minutes `"m"` return value/operator mutations to survive) | `findings/litellm_fix.patch` (**VERIFIED: 100% killed**, 10/10) |
| **TOTALS** | **Tier-1 AI Infrastructure** | **17,026** | **259,353** | **7,522** | **309,684** | **9,276 (3.00%)** | **73,397** | **0.2370** | **49 / 135 (36.3%)** | **All 5 Repos Complete (10 Functions Audited)** | **14 Survived Upstream** | **5 Patches Verified (100% Kill Rate)** |

---

## 2. Gate 1 Forensics & Git Attribution Breakdown

### 2.1 `pydantic/pydantic-ai`
- **Head SHA:** Shallow clone depth 25
- **AI-Attributed Commits:**
  - `f62e8d6`: David SF: "Stop sending a history container on Anthropic requests..." (Claude)
  - `cf01796`: dependabot[bot]: Update GitHub Actions and `hypothesis` (#12165)
  - `8e6d1bb`: pydantic-docs[bot]: Rebuild the `clai2` web UI bundle (#12248)
- **Gate 1 Metrics:**
  - Total assertions: 64,071 across 1,164 test files.
  - Weak assertions (`assert x is not None`): 2,893 (4.52%).
  - AST Mocks: 2,970 mocks. Skips: 1,293.

### 2.2 `567-labs/instructor`
- **Head SHA:** Shallow clone depth 25
- **AI-Attributed Commits:**
  - `68f4e4e`: Cursor Agent: "test(batch): cover recursive strict schema" (Cursor Agent)
  - `c2aa46b`: Cursor Agent: "fix(batch): guard recursive inlining" (Cursor Agent)
  - `9bcef98`: Cursor Agent: "fix(parallel): guard missing tool_calls in from_response" (Cursor Agent)
- **Gate 1 Metrics:**
  - Total assertions: 5,489 across 258 test files.
  - Weak assertions: 177 (3.22%).
  - AST Mocks: 461 mocks. Skips: 37.

### 2.3 `anthropics/anthropic-sdk-python`
- **Head SHA:** Shallow clone depth 25
- **AI-Attributed Commits:** 100% of scanned commits (30/30) are bot/AI pipeline generated (`anthropic-sdks-writer[bot]`, `Claude`).
  - `5752c13`: anthropic-sdks-writer[bot]: "release: 2.4.0"
  - `62b05ab`: anthropic-sdks-writer[bot]: "feat(api): add named beta types for unified metrics and RBAC"
- **Gate 1 Metrics:**
  - Total assertions: 14,357 across 263 test files.
  - Weak assertions: 116 (0.81%).
  - AST Mocks: 172 mocks (0.012 mock density). Skips: 219.

### 2.4 `openai/openai-python`
- **Head SHA:** Shallow clone depth 25
- **AI-Attributed Commits:**
  - `190dd5a`, `0dcd904`, `b7d440b`: openai-sdks[bot] releases.
- **Gate 1 Metrics:**
  - Total assertions: 13,645 across 385 test files.
  - Weak assertions: 143 (1.05%).
  - AST Mocks: 783 mocks (0.0574 mock density). Skips: 29.

### 2.5 `BerriAI/litellm`
- **Head SHA:** Shallow clone depth 25
- **AI-Attributed Commits:** 7/25 commits AI/Bot-authored:
  - `0bd677af`: devin-ai-integration[bot]: "test(integration): look up streamed Responses spend rows..." (Devin)
  - `6a7a4692`: mgeorgaklis: "fix(vertex_ai): map Anthropic context overflow errors (#3696)" (Claude)
  - `a5fe912e`: Mateo Wang: "fix(proxy): preserve DB settings during config reload (#4973)" (Devin)
- **Gate 1 Metrics:**
  - Total assertions: 212,122 across 5,452 test files.
  - Weak assertions: 5,947 (2.80%).
  - AST Mocks: 69,011 mocks! (Mock density: 32.53% — nearly 1 mock per 3 assertions!). Skips: 290.

---

## 3. Gate 2 Invariant Discovery & Verified Patches

### 3.1 `pydantic/pydantic-ai`
- **Target File:** `pydantic_ai_slim/pydantic_ai/_uuid.py`
- **Target Function:** `uuid7`
- **Test File:** `tests/test_uuid.py`
- **Probe Confirmed (`target_executed==True`):** Yes (`AssertionError: __CORDIS_COVERAGE_PROBE__`)
- **Upstream Survivors:** 3 mutants survived:
  - `<` to `<=` on timestamp millisecond check (allowed duplicate timestamp collisions to skip sequence counter)
  - `>` to `>=` and `>` to `<=` on counter boundary
- **Killer Assertions Added:**
  - `test_uuid7_same_millisecond_timestamp_preserved`
  - `test_uuid7_counter_boundary_no_premature_overflow`
- **Mutation Verification:** 9/9 mutants killed (100% kill rate, 0 survived).
- **Artifacts:** `findings/pydantic-ai_fix.patch` | `findings/pydantic-ai_pr.md`

### 3.2 `567-labs/instructor`
- **Target File:** `instructor/v2/core/json.py`
- **Target Function:** `extract_json_from_codeblock`
- **Test File:** `tests/v2/test_json_helpers.py`
- **Probe Confirmed (`target_executed==True`):** Yes (`AssertionError: __CORDIS_COVERAGE_PROBE__`)
- **Upstream Survivors:** 5 mutants survived:
  - Line 22: Boundary shift `>` to `>=` on `MAX_JSON_EXTRACTION_CHARS` (1 MiB boundary)
  - Line 33: Boundary shift `<` to `<=` on `index < consumed` (silently skips index 0 when consumed == 0)
  - Line 35: Boundary shift `<` to `<=` and `-` to `+` on malformed work budget calculation
  - Line 48: Boundary shift `>` to `>=` on `MAX_JSON_DEPTH` (128)
  - Line 53: Flip `+` to `-` on depth increment during JSON child traversal
- **Killer Assertions Added:**
  - `test_extract_json_from_codeblock_exact_1mb_boundary_allowed`
  - `test_extract_json_from_codeblock_leading_object_with_trailing_prose`
  - `test_extract_json_from_codeblock_exact_work_budget_boundary`
  - `test_extract_json_from_codeblock_multiple_valid_objects_span_offset_budget`
  - `test_extract_json_from_codeblock_exact_128_depth_boundary_allowed`
  - `test_extract_json_from_codeblock_depth_exceeds_128_rejected`
- **Mutation Verification:** 14/14 mutants killed (100% kill rate, 0 survived).
- **Artifacts:** `findings/instructor_fix.patch` | `findings/instructor_pr.md`

### 3.3 `anthropics/anthropic-sdk-python`
- **Target File:** `src/anthropic/lib/environments/_worker.py`
- **Target Function:** `_sessions_token_from_secret`
- **Test File:** `tests/lib/environments/test_worker.py`
- **Probe Confirmed (`target_executed==True`):** Yes (`RuntimeError: __CORDIS_COVERAGE_PROBE__`)
- **Upstream Survivors:** 1 mutant survived:
  - Line 296: Perturb `return None` to non-None on `if not isinstance(parsed, dict)`
  - Upstream tests tested invalid base64 and non-JSON plaintext, but never tested valid base64-encoded JSON primitives/lists (arrays, numbers, strings, booleans).
- **Killer Assertions Added:**
  - Added assertions in `test_sessions_token_from_secret` verifying valid base64-encoded JSON lists, quoted strings, integers, and booleans all safely resolve to `None`.
- **Mutation Verification:** 6/6 mutants killed (100% kill rate, 0 survived).
- **Artifacts:** `findings/anthropic-sdk-python_fix.patch` | `findings/anthropic-sdk-python_pr.md`

### 3.4 `openai/openai-python`
- **Target File:** `src/openai/auth/_x509.py`
- **Target Function:** `_retry_delay`
- **Test File:** `tests/test_x509_workload_identity_hardening.py`
- **Probe Confirmed (`target_executed==True`):** Yes (`RuntimeError: __CORDIS_COVERAGE_PROBE__`)
- **Upstream Survivors:** 3 mutants survived:
  - Line 349: Boundary shift `<` to `<= 500` (silently treats HTTP 500 as non-retryable and returns `None`)
  - Line 375: Perturb `return delay` to `None` on standard RFC 7231 `Retry-After` seconds header
  - Line 376: Boundary shift `>` to `>=` on `delay > MAX_RETRY_AFTER_DELAY`
- **Killer Assertions Added:**
  - `test_sync_x509_retry_delay_boundaries_and_retry_after` testing HTTP 500 backoff return, standard `retry-after: "5"`, exact boundary `MAX_RETRY_AFTER_DELAY` (300.0) allowed, and `MAX_RETRY_AFTER_DELAY + 1` returning `None`.
- **Mutation Verification:** 9/10 mutants killed (100% kill rate of killable mutants; 1 equivalent mutant due to prior short-circuit check).
- **Artifacts:** `findings/openai-python_fix.patch` | `findings/openai-python_pr.md`

### 3.5 `BerriAI/litellm`
- **Target File:** `litellm/litellm_core_utils/duration_parser.py`
- **Target Function:** `duration_in_seconds` (also verified `get_budget_window_start`)
- **Test File:** `tests/unit/litellm_core_utils/test_duration_parser.py`
- **Probe Confirmed (`target_executed==True`):** Yes (`RuntimeError: __CORDIS_COVERAGE_PROBE__`)
- **Upstream Survivors:** 3 mutants survived:
  - Line 67: Perturb `return value` to `None` for seconds duration (`"s"`)
  - Line 69: Perturb `return value * 60` to `None` for minutes duration (`"m"`)
  - Line 69: Operator mutation `*` to `/` for minutes duration (`"m"`)
  - *Root Cause:* Upstream test `test_fixed_length_units_do_not_depend_on_the_start` was a pure tautology (`duration_in_seconds_from(start, d) == duration_in_seconds(d)`), where the former simply calls the latter for all non-month units, resulting in `f(x) == f(x)` which evaluated to `True` for any return value (`None == None`, `0.5 == 0.5`).
- **Killer Assertions Added:**
  - `test_duration_in_seconds_units_exact_values()` asserting exact integer return values for `"45s"`, `"30m"`, `"1h"`, `"1d"`, `"1w"`, and `"7d"`.
- **Mutation Verification:** 10/10 mutants killed (100% kill rate, 0 survived).
- **Artifacts:** `findings/litellm_fix.patch` | `findings/litellm_pr.md`

---
*Maintained continuously by Cordis Wild Invariant Hunt engine inside `C:\Users\Janmejai\cordis_live_lab`.*
