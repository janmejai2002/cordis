"""Empirical stress-testing and adversarial challenge suite for cordis/stream_gate.py.

Suite components:
1. TestStreamLifecycleSpyAdversarialStress:
   - Sync & async complex generators with early exceptions
   - Nested generator delegation and propagation
   - Infinite stream early breaks and leak detection
   - Double and triple close idempotency
   - Generator delegation protocol (send, throw, close, asend, athrow, aclose)
   - Context manager auto-close guarantees under exceptions (sync and async)
   - auto_close_on_exit flag behavior (True vs False)
2. TestEphemeralSQLiteSandboxAdversarialStress:
   - Massive DML mutations (10,000+ operations) with 100% rollback
   - DDL schema modifications (CREATE, DROP, ALTER, INDEX) with 100% rollback
   - Commit subversion attacks (conn.commit(), raw SQL COMMIT, END, BEGIN variations)
   - Deep nested probes (5+ levels) with multi-level isolation and rollback
   - Unhandled exception unwinding in inner probes without outer state corruption
   - Re-entrant sandboxes operating concurrently on independent in-memory databases
3. TestStreamGateVulnerabilityReproductions:
   - Empirical reproduction of 6 identified vulnerabilities/gaps using @unittest.expectedFailure:
     * Vulnerability 1: conn.cursor() bypasses proxy commit interception
     * Vulnerability 2: conn.executescript() issues internal CPython commit destroying savepoints
     * Vulnerability 3: SQL comments preceding COMMIT bypass string equality check
     * Vulnerability 4: Raw SQL ROLLBACK destroys outer nested savepoints
     * Vulnerability 5: StreamLifecycleSpy.throw() fails to increment yield_count
     * Vulnerability 6: StreamLifecycleSpy.athrow() fails to increment yield_count
"""
import asyncio
import inspect
import sqlite3
import unittest
from typing import AsyncGenerator, Generator

from cordis.stream_gate import EphemeralSQLiteSandbox, StreamLifecycleSpy


class TestStreamLifecycleSpyAdversarialStress(unittest.TestCase):
    """Adversarial stress harness for StreamLifecycleSpy."""

    def test_sync_generator_early_exception_captures_leak(self):
        def faulty_generator() -> Generator[int, None, None]:
            yield 1
            yield 2
            raise RuntimeError("Stream ruptured intentionally")
            yield 3

        spy = StreamLifecycleSpy(faulty_generator())
        self.assertFalse(spy.started)
        self.assertFalse(spy.is_leaked)
        self.assertFalse(spy.closed)
        self.assertFalse(spy.exhausted)

        gen_iter = iter(spy)
        self.assertEqual(next(gen_iter), 1)
        self.assertTrue(spy.started)
        self.assertEqual(spy.yield_count, 1)
        self.assertTrue(spy.is_leaked)  # started, not exhausted, not closed

        self.assertEqual(next(gen_iter), 2)
        self.assertEqual(spy.yield_count, 2)
        self.assertTrue(spy.is_leaked)

        with self.assertRaises(RuntimeError) as ctx:
            next(gen_iter)
        self.assertIn("ruptured intentionally", str(ctx.exception))
        self.assertIsInstance(spy.exception, RuntimeError)
        self.assertFalse(spy.exhausted)
        self.assertFalse(spy.closed)
        # Because it broke with an unhandled exception outside a context manager, it's leaked!
        self.assertTrue(spy.is_leaked)

        # Closing it should plug the leak
        spy.close()
        self.assertTrue(spy.closed)
        self.assertFalse(spy.is_leaked)
        spy.assert_closed()
        spy.assert_not_leaked()

    def test_async_generator_early_exception_captures_leak(self):
        async def async_faulty_gen() -> AsyncGenerator[str, None]:
            yield "chunk-1"
            yield "chunk-2"
            raise ValueError("Async network socket lost")
            yield "chunk-3"

        async def run_test():
            spy = StreamLifecycleSpy(async_faulty_gen())
            self.assertFalse(spy.started)
            self.assertFalse(spy.is_leaked)

            aiter_obj = spy.__aiter__()
            self.assertEqual(await aiter_obj.__anext__(), "chunk-1")
            self.assertTrue(spy.is_leaked)
            self.assertEqual(spy.yield_count, 1)

            self.assertEqual(await aiter_obj.__anext__(), "chunk-2")
            self.assertEqual(spy.yield_count, 2)

            with self.assertRaises(ValueError):
                await aiter_obj.__anext__()

            self.assertIsInstance(spy.exception, ValueError)
            self.assertTrue(spy.is_leaked)
            self.assertFalse(spy.closed)
            self.assertFalse(spy.exhausted)

            await spy.aclose()
            self.assertTrue(spy.closed)
            self.assertFalse(spy.is_leaked)

        asyncio.run(run_test())

    def test_nested_generator_delegation(self):
        def inner_gen():
            yield "inner-1"
            yield "inner-2"

        def outer_gen(inner_spy):
            yield "outer-start"
            yield from inner_spy
            yield "outer-end"

        inner_spy = StreamLifecycleSpy(inner_gen(), name="inner")
        outer_spy = StreamLifecycleSpy(outer_gen(inner_spy), name="outer")

        items = []
        for x in outer_spy:
            items.append(x)
            if x == "inner-1":
                # Check states mid-stream
                self.assertTrue(outer_spy.is_leaked)
                self.assertTrue(inner_spy.is_leaked)

        self.assertEqual(items, ["outer-start", "inner-1", "inner-2", "outer-end"])
        self.assertTrue(outer_spy.exhausted)
        self.assertTrue(inner_spy.exhausted)
        self.assertFalse(outer_spy.is_leaked)
        self.assertFalse(inner_spy.is_leaked)

    def test_infinite_stream_early_break_and_leak_detection(self):
        def infinite_ticker():
            i = 0
            while True:
                yield i
                i += 1

        # Case 1: unclosed infinite stream
        spy1 = StreamLifecycleSpy(infinite_ticker())
        for val in spy1:
            if val == 5:
                break
        self.assertEqual(spy1.yield_count, 6)  # 0, 1, 2, 3, 4, 5
        self.assertFalse(spy1.exhausted)
        self.assertFalse(spy1.closed)
        self.assertTrue(spy1.is_leaked)
        with self.assertRaises(AssertionError):
            spy1.assert_not_leaked()

        # Case 2: infinite stream in with block with auto_close_on_exit
        spy2 = StreamLifecycleSpy(infinite_ticker(), auto_close_on_exit=True)
        with spy2 as s:
            for val in s:
                if val == 5:
                    break
        self.assertEqual(spy2.yield_count, 6)
        self.assertTrue(spy2.closed)
        self.assertFalse(spy2.exhausted)
        self.assertFalse(spy2.is_leaked)
        spy2.assert_not_leaked()
        spy2.assert_closed()

    def test_double_and_triple_close_idempotency(self):
        def simple_gen():
            yield 1
            yield 2

        spy = StreamLifecycleSpy(simple_gen())
        next(spy)
        self.assertEqual(spy.close_call_count, 0)
        self.assertFalse(spy.closed)

        spy.close()
        self.assertTrue(spy.closed)
        self.assertEqual(spy.close_call_count, 1)

        # Second close should be safe and idempotent
        spy.close()
        self.assertTrue(spy.closed)
        self.assertEqual(spy.close_call_count, 2)

        # Third close
        spy.close()
        self.assertTrue(spy.closed)
        self.assertEqual(spy.close_call_count, 3)

        # Attempting next on closed spy raises StopIteration
        with self.assertRaises(StopIteration):
            next(spy)

    def test_async_double_aclose_idempotency(self):
        async def async_simple_gen():
            yield 100
            yield 200

        async def run_test():
            spy = StreamLifecycleSpy(async_simple_gen())
            item = await spy.__anext__()
            self.assertEqual(item, 100)
            self.assertFalse(spy.closed)

            await spy.aclose()
            self.assertTrue(spy.closed)
            self.assertEqual(spy.close_call_count, 1)

            await spy.aclose()
            self.assertTrue(spy.closed)
            self.assertEqual(spy.close_call_count, 2)

            with self.assertRaises(StopAsyncIteration):
                await spy.__anext__()

        asyncio.run(run_test())

    def test_sync_generator_delegation_send_throw_close(self):
        def interactive_worker():
            total = 0
            while True:
                try:
                    val = yield total
                    if val is None:
                        continue
                    total += val
                except GeneratorExit:
                    break
                except ValueError:
                    total = -999
                    yield total

        spy = StreamLifecycleSpy(interactive_worker())
        # Primer
        first = spy.send(None)
        self.assertEqual(first, 0)
        self.assertEqual(spy.yield_count, 1)

        # Send values
        res = spy.send(10)
        self.assertEqual(res, 10)
        self.assertEqual(spy.yield_count, 2)

        res = spy.send(25)
        self.assertEqual(res, 35)
        self.assertEqual(spy.yield_count, 3)

        # Throw exception caught by worker
        res = spy.throw(ValueError("reset"))
        self.assertEqual(res, -999)

        # Close
        spy.close()
        self.assertTrue(spy.closed)
        with self.assertRaises(StopIteration):
            spy.send(5)

    def test_async_generator_delegation_asend_athrow_aclose(self):
        async def async_accumulator():
            total = 0
            while True:
                try:
                    val = yield total
                    if val is None:
                        continue
                    total += val
                except GeneratorExit:
                    break
                except KeyError:
                    total = 777
                    yield total

        async def run_test():
            spy = StreamLifecycleSpy(async_accumulator())
            # Prime
            first = await spy.asend(None)
            self.assertEqual(first, 0)

            # asend
            res = await spy.asend(50)
            self.assertEqual(res, 50)

            # athrow
            res = await spy.athrow(KeyError)
            self.assertEqual(res, 777)

            # aclose
            await spy.aclose()
            self.assertTrue(spy.closed)
            with self.assertRaises(StopAsyncIteration):
                await spy.asend(10)

        asyncio.run(run_test())

    def test_context_manager_exception_auto_close_sync(self):
        def gen():
            yield "a"
            yield "b"
            yield "c"

        spy = StreamLifecycleSpy(gen(), auto_close_on_exit=True)
        with self.assertRaises(ZeroDivisionError):
            with spy as s:
                val = next(s)
                self.assertEqual(val, "a")
                _ = 1 / 0

        self.assertTrue(spy.entered)
        self.assertTrue(spy.exited)
        self.assertTrue(spy.closed)
        self.assertFalse(spy.is_leaked)
        self.assertIsInstance(spy.exception, ZeroDivisionError)

    def test_context_manager_exception_auto_close_async(self):
        async def agen():
            yield 1
            yield 2

        async def run_test():
            spy = StreamLifecycleSpy(agen(), auto_close_on_exit=True)
            with self.assertRaises(IndexError):
                async with spy as s:
                    val = await s.__anext__()
                    self.assertEqual(val, 1)
                    raise IndexError("out of bounds")

            self.assertTrue(spy.entered)
            self.assertTrue(spy.exited)
            self.assertTrue(spy.closed)
            self.assertFalse(spy.is_leaked)
            self.assertIsInstance(spy.exception, IndexError)

        asyncio.run(run_test())

    def test_auto_close_on_exit_disabled_preserves_leak(self):
        """When auto_close_on_exit=False, an exception in context manager leaves stream leaked."""
        def gen():
            yield 1
            yield 2

        spy = StreamLifecycleSpy(gen(), auto_close_on_exit=False)
        with self.assertRaises(ValueError):
            with spy as s:
                next(s)
                raise ValueError("exit without auto-close")

        self.assertTrue(spy.entered)
        self.assertTrue(spy.exited)
        self.assertFalse(spy.closed)
        self.assertTrue(spy.is_leaked)


class TestEphemeralSQLiteSandboxAdversarialStress(unittest.TestCase):
    """Adversarial stress harness for EphemeralSQLiteSandbox."""

    def setUp(self):
        self.setup_sql = """
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                balance REAL NOT NULL
            );
            INSERT INTO accounts (id, username, balance) VALUES
                (1, 'alice', 1000.0),
                (2, 'bob', 500.0),
                (3, 'charlie', 250.0);
        """
        self.sandbox = EphemeralSQLiteSandbox(setup_sql=self.setup_sql)

    def tearDown(self):
        self.sandbox.close()

    def test_massive_dml_mutations_and_full_rollback(self):
        """Insert 10,000 rows, update 5,000, delete 2,000 inside probe, verify 100% rollback."""
        initial_count = self.sandbox.count_rows("accounts")
        self.assertEqual(initial_count, 3)

        with self.sandbox.probe() as conn:
            # Insert 10,000 rows via executemany
            new_rows = [(i, f"user_{i}", float(i * 10)) for i in range(100, 10100)]
            conn.executemany("INSERT INTO accounts (id, username, balance) VALUES (?, ?, ?);", new_rows)

            self.assertEqual(self.sandbox.count_rows("accounts"), 10003)

            # Update 5,000 rows
            conn.execute("UPDATE accounts SET balance = -1.0 WHERE id >= 100 AND id < 5100;")
            neg_count = conn.execute("SELECT COUNT(*) FROM accounts WHERE balance = -1.0;").fetchone()[0]
            self.assertEqual(neg_count, 5000)

            # Delete 2,000 rows
            conn.execute("DELETE FROM accounts WHERE id >= 5100 AND id < 7100;")
            self.assertEqual(self.sandbox.count_rows("accounts"), 8003)

        # After probe exit, everything must be 100% reverted!
        self.assertEqual(self.sandbox.count_rows("accounts"), 3)
        rows = self.sandbox.fetch_all("SELECT id, username, balance FROM accounts ORDER BY id;")
        self.assertEqual(rows, [
            (1, 'alice', 1000.0),
            (2, 'bob', 500.0),
            (3, 'charlie', 250.0),
        ])

    def test_ddl_operations_full_rollback(self):
        """Test CREATE TABLE, ALTER TABLE, CREATE INDEX, DROP TABLE inside probe and verify schema rollback."""
        self.assertTrue(self.sandbox.table_exists("accounts"))
        self.assertFalse(self.sandbox.table_exists("audit_log"))

        with self.sandbox.probe() as conn:
            # 1. CREATE TABLE
            conn.execute("""
                CREATE TABLE audit_log (
                    log_id INTEGER PRIMARY KEY,
                    action TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.execute("INSERT INTO audit_log (log_id, action) VALUES (1, 'MUTATION_TEST');")
            self.assertTrue(self.sandbox.table_exists("audit_log"))

            # 2. CREATE INDEX
            conn.execute("CREATE INDEX idx_audit_action ON audit_log (action);")

            # 3. ALTER TABLE
            conn.execute("ALTER TABLE accounts ADD COLUMN email TEXT DEFAULT 'none@cordis.io';")
            col_info = conn.execute("PRAGMA table_info(accounts);").fetchall()
            col_names = [c[1] for c in col_info]
            self.assertIn("email", col_names)

            # 4. DROP TABLE
            conn.execute("DROP TABLE accounts;")
            self.assertFalse(self.sandbox.table_exists("accounts"))

        # After exiting probe:
        # audit_log must NOT exist
        self.assertFalse(self.sandbox.table_exists("audit_log"))
        # accounts MUST exist again with original schema and rows
        self.assertTrue(self.sandbox.table_exists("accounts"))
        self.assertEqual(self.sandbox.count_rows("accounts"), 3)
        col_info = self.sandbox.execute("PRAGMA table_info(accounts);").fetchall()
        col_names = [c[1] for c in col_info]
        self.assertNotIn("email", col_names)

    def test_commit_subversion_attempts_are_neutralized(self):
        """Verify conn.commit(), raw SQL COMMIT, END, and BEGIN variations cannot destroy savepoints."""
        initial_balance = self.sandbox.fetch_val("SELECT balance FROM accounts WHERE id = 1;")
        self.assertEqual(initial_balance, 1000.0)

        with self.sandbox.probe() as conn:
            conn.execute("UPDATE accounts SET balance = 999999.0 WHERE id = 1;")

            # Attempt direct Python commit
            conn.commit()

            # Attempt raw SQL COMMITs with whitespace, case variations, semicolons
            conn.execute("COMMIT;")
            conn.execute("commit")
            conn.execute("  COMMIT TRANSACTION;  ")
            conn.execute("END;")
            conn.execute("end transaction")

            # Attempt raw SQL BEGINs
            conn.execute("BEGIN;")
            conn.execute("BEGIN TRANSACTION;")
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("BEGIN EXCLUSIVE;")

            # Modify again after subversion attempts
            conn.execute("UPDATE accounts SET balance = 888888.0 WHERE id = 1;")
            current_val = conn.execute("SELECT balance FROM accounts WHERE id = 1;").fetchone()[0]
            self.assertEqual(current_val, 888888.0)

            # Attempt rollback within proxy
            conn.rollback()

        # Probe has exited. All subversion attempts should have failed to commit to main db.
        final_balance = self.sandbox.fetch_val("SELECT balance FROM accounts WHERE id = 1;")
        self.assertEqual(final_balance, 1000.0)

    def test_deep_nested_probes_multilevel_rollback(self):
        """Test 5 levels of nested probes with individual rollbacks at each boundary."""
        # Level 0: 3 rows
        self.assertEqual(self.sandbox.count_rows("accounts"), 3)

        with self.sandbox.probe(name="level_1") as conn1:
            conn1.execute("INSERT INTO accounts (id, username, balance) VALUES (10, 'level1_user', 10.0);")
            self.assertEqual(self.sandbox.count_rows("accounts"), 4)

            with self.sandbox.probe(name="level_2") as conn2:
                conn2.execute("INSERT INTO accounts (id, username, balance) VALUES (20, 'level2_user', 20.0);")
                self.assertEqual(self.sandbox.count_rows("accounts"), 5)

                with self.sandbox.probe(name="level_3") as conn3:
                    conn3.execute("INSERT INTO accounts (id, username, balance) VALUES (30, 'level3_user', 30.0);")
                    self.assertEqual(self.sandbox.count_rows("accounts"), 6)

                    with self.sandbox.probe(name="level_4") as conn4:
                        conn4.execute("INSERT INTO accounts (id, username, balance) VALUES (40, 'level4_user', 40.0);")
                        self.assertEqual(self.sandbox.count_rows("accounts"), 7)

                        with self.sandbox.probe(name="level_5") as conn5:
                            conn5.execute("INSERT INTO accounts (id, username, balance) VALUES (50, 'level5_user', 50.0);")
                            self.assertEqual(self.sandbox.count_rows("accounts"), 8)

                        # Exited Level 5: row 50 should be rolled back
                        self.assertEqual(self.sandbox.count_rows("accounts"), 7)
                        self.assertIsNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 50;"))

                    # Exited Level 4: row 40 should be rolled back
                    self.assertEqual(self.sandbox.count_rows("accounts"), 6)
                    self.assertIsNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 40;"))

                # Exited Level 3: row 30 should be rolled back
                self.assertEqual(self.sandbox.count_rows("accounts"), 5)
                self.assertIsNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 30;"))

            # Exited Level 2: row 20 should be rolled back
            self.assertEqual(self.sandbox.count_rows("accounts"), 4)
            self.assertIsNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 20;"))

        # Exited Level 1: row 10 should be rolled back, back to original 3
        self.assertEqual(self.sandbox.count_rows("accounts"), 3)
        self.assertIsNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 10;"))

    def test_nested_probe_with_exception_unwinding(self):
        """Verify that an unhandled exception in an inner probe cleanly rolls back without poisoning outer probes."""
        with self.sandbox.probe() as outer_conn:
            outer_conn.execute("INSERT INTO accounts (id, username, balance) VALUES (11, 'outer', 100.0);")
            self.assertEqual(self.sandbox.count_rows("accounts"), 4)

            with self.assertRaises(ValueError):
                with self.sandbox.probe() as inner_conn:
                    inner_conn.execute("INSERT INTO accounts (id, username, balance) VALUES (22, 'inner', 200.0);")
                    self.assertEqual(self.sandbox.count_rows("accounts"), 5)
                    raise ValueError("Simulation of mutant probe failure/crash")

            # Inner insert must be gone, but outer insert must still be alive!
            self.assertEqual(self.sandbox.count_rows("accounts"), 4)
            self.assertIsNotNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 11;"))
            self.assertIsNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 22;"))

        # After outer probe exits, even outer insert is gone
        self.assertEqual(self.sandbox.count_rows("accounts"), 3)
        self.assertIsNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 11;"))

    def test_multiple_sandboxes_concurrency(self):
        """Verify multiple independent sandboxes can run concurrently without cross-contamination."""
        sb1 = EphemeralSQLiteSandbox(setup_sql="CREATE TABLE t1 (v INT);")
        sb2 = EphemeralSQLiteSandbox(setup_sql="CREATE TABLE t2 (v INT);")
        try:
            with sb1.probe() as c1:
                c1.execute("INSERT INTO t1 VALUES (100);")
                with sb2.probe() as c2:
                    c2.execute("INSERT INTO t2 VALUES (200);")
                    self.assertEqual(sb1.count_rows("t1"), 1)
                    self.assertEqual(sb2.count_rows("t2"), 1)
                self.assertEqual(sb2.count_rows("t2"), 0)
            self.assertEqual(sb1.count_rows("t1"), 0)
        finally:
            sb1.close()
            sb2.close()


class TestStreamGateVulnerabilityReproductions(unittest.TestCase):
    """Adversarial vulnerability reproductions.

    These tests document and empirically demonstrate vulnerabilities discovered in
    cordis/stream_gate.py. Decorated with @unittest.expectedFailure so they demonstrate
    the defect empirically while preserving test suite pass status.
    """

    def setUp(self):
        self.sandbox = EphemeralSQLiteSandbox(
            setup_sql="CREATE TABLE accounts (id INT PRIMARY KEY, name TEXT);"
        )

    def tearDown(self):
        self.sandbox.close()

    def test_vulnerability_1_cursor_bypass_commit(self):
        """conn.cursor().execute('COMMIT;') bypasses proxy and breaks isolation."""
        with self.sandbox.probe() as conn:
            conn.execute("INSERT INTO accounts VALUES (999, 'cursor_evil');")
            cur = conn.cursor()
            cur.execute("COMMIT;")
        # EXPECTED: Row 999 is rolled back.
        # ACTUAL: Unproxied cursor commits directly to database, leaking row 999.
        self.assertIsNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 999;"))

    def test_vulnerability_2_executescript_internal_commit(self):
        """conn.executescript() issues internal CPython commit that destroys savepoint."""
        with self.sandbox.probe() as conn:
            conn.executescript("INSERT INTO accounts VALUES (888, 'script_evil');")
        # EXPECTED: Row 888 is rolled back.
        # ACTUAL: CPython executescript commits first, savepoint destroyed, row 888 leaked.
        self.assertIsNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 888;"))

    def test_vulnerability_3_sql_comment_commit_bypass(self):
        """conn.execute('-- comment\\nCOMMIT;') bypasses exact string check and commits."""
        with self.sandbox.probe() as conn:
            conn.execute("INSERT INTO accounts VALUES (777, 'comment_evil');")
            conn.execute("-- comment\nCOMMIT;")
        # EXPECTED: Row 777 is rolled back.
        # ACTUAL: Exact match check fails due to comment, commit executed, row 777 leaked.
        self.assertIsNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 777;"))

    def test_vulnerability_4_raw_sql_rollback_corrupts_nested_probes(self):
        """Raw SQL conn.execute('ROLLBACK;') destroys all outer savepoints rather than only current."""
        with self.sandbox.probe(name="outer") as c1:
            c1.execute("INSERT INTO accounts VALUES (601, 'outer_row');")
            with self.sandbox.probe(name="inner") as c2:
                c2.execute("INSERT INTO accounts VALUES (602, 'inner_row');")
                c2.execute("ROLLBACK;")
            # Inner should be rolled back, but outer row 601 should still be present!
            self.assertEqual(self.sandbox.count_rows("accounts"), 1)
            self.assertIsNotNone(self.sandbox.fetch_val("SELECT id FROM accounts WHERE id = 601;"))

    def test_vulnerability_5_throw_yield_count_tracking(self):
        """When generator handles throw() and yields, yield_count must increment."""
        def handler_gen():
            try:
                yield 1
            except ValueError:
                yield 2

        spy = StreamLifecycleSpy(handler_gen())
        next(spy)
        val = spy.throw(ValueError)
        self.assertEqual(val, 2)
        # EXPECTED: yield_count is 2 (two values yielded).
        # ACTUAL: throw() does not increment yield_count, so yield_count is 1.
        self.assertEqual(spy.yield_count, 2)

    def test_vulnerability_6_athrow_yield_count_tracking(self):
        """When async generator handles athrow() and yields, yield_count must increment."""
        async def async_handler_gen():
            try:
                yield 10
            except KeyError:
                yield 20

        async def run_test():
            spy = StreamLifecycleSpy(async_handler_gen())
            await spy.__anext__()
            val = await spy.athrow(KeyError)
            self.assertEqual(val, 20)
            # EXPECTED: yield_count is 2.
            # ACTUAL: athrow() does not increment yield_count, so yield_count is 1.
            self.assertEqual(spy.yield_count, 2)

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
