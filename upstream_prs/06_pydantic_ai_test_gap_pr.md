# Pull Request: test(uuid): add boundary invariant assertions for UUIDv7 same-millisecond preservation and counter overflow threshold

## Description
This PR strengthens unit test invariants in `tests/test_uuid.py` for the UUIDv7 generator (`pydantic_ai._uuid.uuid7`).

During AST mutation coverage analysis with Cordis, 3 AST boundary mutants in `_uuid.py` survived the upstream test suite despite the target function being actively executed:
1. **Line 62: `<` shifted to `<=` (`timestamp_ms <= _last_timestamp_v7`)**:
   When consecutive calls occur within the same millisecond (`timestamp_ms == _last_timestamp_v7`), this mutant treated identical timestamps as clock regression, spuriously advancing the timestamp by 1 millisecond (`timestamp_ms = _last_timestamp_v7 + 1`). Upstream tests verified monotonicity (`u2 > u1`), but never verified that consecutive UUIDs within the same millisecond share the exact 48-bit millisecond timestamp prefix (`u1.hex[:12] == u2.hex[:12]`).
2. **Line 66: `>` shifted to `>=` (`counter >= 0x3FF_FFFF_FFFF`)**:
   Prematurely triggered timestamp overflow when the 42-bit sub-millisecond counter reached the maximum valid representation (`0x3FF_FFFF_FFFF`) rather than exceeding it.
3. **Line 66: `>` flipped to `<=` (`counter <= 0x3FF_FFFF_FFFF`)**:
   Prematurely overflowed on all lower counter values.

## Changes Added
- Added `test_uuid7_same_millisecond_timestamp_preserved`: Verifies that consecutive `uuid7()` calls within the same millisecond retain the exact same 48-bit timestamp prefix (`u1.hex[:12] == u2.hex[:12]`), killing the `<` -> `<=` mutation.
- Added `test_uuid7_counter_boundary_no_premature_overflow`: Verifies that when the counter reaches exactly `0x3FF_FFFF_FFFF`, the timestamp is NOT prematurely incremented, killing the `>=` and `<=` overflow boundary mutants.

## Verification
- Pre-mutation test suite: 4 tests passing.
- Post-mutation test suite: 6 tests passing (`pytest tests/test_uuid.py`).
- Cordis Gate 2 Mutation Score: 9/9 mutants killed (100% kill rate, 0 survived).
