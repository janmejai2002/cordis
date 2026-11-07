# Cordis V3 Wave 4 Source Code Implementation Snapshot

## 1. cordis/stream_gate.py
`python
"""Cordis Stream Gate & Ephemeral SQLite Sandbox (Engine 11, Upgrade 11.1).

This module provides:
1. StreamLifecycleSpy: Synchronous and asynchronous stream lifecycle monitor and resource
   leak prosecutor. Tracks iteration start, item yields, natural exhaustion, and explicit
   close/aclose calls to detect abandoned streams across early breaks or exception exits.
2. EphemeralSQLiteSandbox: In-memory SQLite transaction sandbox leveraging SAVEPOINT and
   ROLLBACK mechanics to achieve sub-microsecond stateful SQL mutation isolation with zero
   disk I/O and zero state leakage across differential fuzzing and mutation probes.

100% Python 3.10+ Standard Library with zero external dependencies.
"""
from __future__ import annotations

import inspect
import re
import sqlite3
import sys
from contextlib import contextmanager
from typing import (
    Any,
    AsyncIterable,
    AsyncIterator,
    Callable,
    Generator,
    Generic,
    Iterable,
    Iterator,
    List,
    Optional,
    Tuple,
    TypeVar,
    Union,
)

T = TypeVar("T")


class StreamLifecycleSpy(Generic[T]):
    """Adversarial Stream Lifecycle Spy.

    Wraps synchronous and asynchronous iterables, iterators, and generators to track
    and verify lifecycle states:
    - started: bool — whether iteration was initiated.
    - yield_count / items_yielded: int — number of items successfully yielded.
    - exhausted: bool — whether the stream ran to natural completion (StopIteration / StopAsyncIteration).
    - closed: bool — whether .close() or await .aclose() was explicitly invoked.
    - close_call_count: int — total invocations of close/aclose.
    - entered: bool — whether entered as a context manager.
    - exited: bool — whether exited as a context manager.
    - exception: Optional[BaseException] — caught exception if aborted mid-stream.
    - is_leaked / leaked: bool — True if iteration started but was not exhausted and not closed.
    - active: bool — True if stream is not closed and not exhausted.
    """

    def __init__(
        self,
        iterable: Any,
        auto_close_on_exit: bool = True,
        name: Optional[str] = None,
    ) -> None:
        self.underlying: Any = iterable
        self._wrapped: Any = iterable
        self._iterator: Any = None
        self.name: str = name or getattr(iterable, "__name__", iterable.__class__.__name__)
        self.auto_close_on_exit: bool = auto_close_on_exit

        self.closed: bool = False
        self.exhausted: bool = False
        self.started: bool = False
        self.yield_count: int = 0
        self.close_call_count: int = 0
        self.entered: bool = False
        self.exited: bool = False
        self.exception: Optional[BaseException] = None

        self._is_async: bool = (
            inspect.isasyncgen(iterable)
            or hasattr(iterable, "__aiter__")
            or hasattr(iterable, "__anext__")
        )

    # --- Properties & Aliases ---

    @property
    def is_leaked(self) -> bool:
        """Resource leak theorem: is_leaked <=> started and not exhausted and not closed."""
        if self.closed:
            return False
        if self.exhausted:
            return False
        return self.started or self.yield_count > 0

    @property
    def leaked(self) -> bool:
        """Alias for is_leaked."""
        return self.is_leaked

    @property
    def active(self) -> bool:
        """Active state: neither closed nor exhausted."""
        return (not self.closed) and (not self.exhausted)

    @property
    def items_yielded(self) -> int:
        """Alias for yield_count."""
        return self.yield_count

    @items_yielded.setter
    def items_yielded(self, val: int) -> None:
        self.yield_count = val

    # --- Synchronous Iterator Protocol ---

    def __iter__(self) -> "StreamLifecycleSpy[T]":
        if self._is_async and not hasattr(self.underlying, "__iter__"):
            raise TypeError(f"'{self.name}' is an async stream; use 'async for' or '__aiter__'")
        if self._iterator is None:
            if hasattr(self.underlying, "__iter__"):
                self._iterator = iter(self.underlying)
            elif hasattr(self.underlying, "__next__"):
                self._iterator = self.underlying
            else:
                raise TypeError(f"'{self.name}' object is not iterable")
        return self

    def __next__(self) -> T:
        if self._iterator is None:
            self.__iter__()
        if self.closed:
            raise StopIteration("Stream is closed")
        self.started = True
        try:
            item = next(self._iterator)
            self.yield_count += 1
            return item
        except StopIteration:
            self.exhausted = True
            raise
        except BaseException as exc:
            self.exception = exc
            raise

    def send(self, value: Any) -> T:
        """Delegates value to underlying generator or advances iterator."""
        if self._iterator is None:
            self.__iter__()
        if self.closed:
            raise StopIteration("Stream is closed")
        self.started = True
        try:
            if hasattr(self._iterator, "send"):
                item = self._iterator.send(value)
            else:
                if value is not None:
                    raise TypeError("can't send non-None value to a non-generator")
                item = next(self._iterator)
            self.yield_count += 1
            return item
        except StopIteration:
            self.exhausted = True
            raise
        except BaseException as exc:
            self.exception = exc
            raise

    def throw(self, typ: Any, val: Any = None, tb: Any = None) -> T:
        """Throws exception into underlying generator or raises it directly."""
        if self._iterator is None:
            self.__iter__()
        try:
            if hasattr(self._iterator, "throw"):
                if val is None and tb is None:
                    item = self._iterator.throw(typ)
                else:
                    item = self._iterator.throw(typ, val, tb)
                self.yield_count += 1
                return item
            else:
                if isinstance(typ, BaseException):
                    raise typ
                elif inspect.isclass(typ) and issubclass(typ, BaseException):
                    raise typ(val) if val is not None else typ()
                raise TypeError("exceptions must derive from BaseException")
        except StopIteration:
            self.exhausted = True
            raise
        except BaseException as exc:
            self.exception = exc
            raise

    def close(self) -> None:
        """Explicitly closes underlying stream and updates closed status."""
        self.closed = True
        self.close_call_count += 1
        if self._iterator is not None and hasattr(self._iterator, "close"):
            try:
                self._iterator.close()
            except Exception as exc:
                self.exception = exc
                raise
        elif hasattr(self.underlying, "close"):
            try:
                self.underlying.close()
            except Exception as exc:
                self.exception = exc
                raise

    # --- Asynchronous Iterator Protocol ---

    def __aiter__(self) -> "StreamLifecycleSpy[T]":
        if not self._is_async and not hasattr(self.underlying, "__aiter__"):
            raise TypeError(f"'{self.name}' is a sync stream; use 'for' or '__iter__'")
        if self._iterator is None:
            if hasattr(self.underlying, "__aiter__"):
                self._iterator = self.underlying.__aiter__()
            elif hasattr(self.underlying, "__anext__"):
                self._iterator = self.underlying
            else:
                raise TypeError(f"'{self.name}' object is not an async iterable")
        return self

    async def __anext__(self) -> T:
        if self._iterator is None:
            self.__aiter__()
        if self.closed:
            raise StopAsyncIteration("Async stream is closed")
        self.started = True
        try:
            item = await self._iterator.__anext__()
            self.yield_count += 1
            return item
        except StopAsyncIteration:
            self.exhausted = True
            raise
        except BaseException as exc:
            self.exception = exc
            raise

    async def asend(self, value: Any) -> T:
        """Delegates value to underlying async generator or advances async iterator."""
        if self._iterator is None:
            self.__aiter__()
        if self.closed:
            raise StopAsyncIteration("Async stream is closed")
        self.started = True
        try:
            if hasattr(self._iterator, "asend"):
                item = await self._iterator.asend(value)
            else:
                if value is not None:
                    raise TypeError("can't send non-None value to a non-generator")
                item = await self._iterator.__anext__()
            self.yield_count += 1
            return item
        except StopAsyncIteration:
            self.exhausted = True
            raise
        except BaseException as exc:
            self.exception = exc
            raise

    async def athrow(self, typ: Any, val: Any = None, tb: Any = None) -> T:
        """Throws exception into underlying async generator or raises it."""
        if self._iterator is None:
            self.__aiter__()
        try:
            if hasattr(self._iterator, "athrow"):
                if val is None and tb is None:
                    item = await self._iterator.athrow(typ)
                else:
                    item = await self._iterator.athrow(typ, val, tb)
                self.yield_count += 1
                return item
            else:
                if isinstance(typ, BaseException):
                    raise typ
                elif inspect.isclass(typ) and issubclass(typ, BaseException):
                    raise typ(val) if val is not None else typ()
                raise TypeError("exceptions must derive from BaseException")
        except StopAsyncIteration:
            self.exhausted = True
            raise
        except BaseException as exc:
            self.exception = exc
            raise

    async def aclose(self) -> None:
        """Explicitly closes underlying async stream."""
        self.closed = True
        self.close_call_count += 1
        if self._iterator is not None and hasattr(self._iterator, "aclose"):
            await self._iterator.aclose()
        elif hasattr(self.underlying, "aclose"):
            await self.underlying.aclose()
        elif self._iterator is not None and hasattr(self._iterator, "close"):
            self._iterator.close()
        elif hasattr(self.underlying, "close"):
            self.underlying.close()

    # --- Context Management Protocol ---

    def __enter__(self) -> "StreamLifecycleSpy[T]":
        self.entered = True
        if hasattr(self.underlying, "__enter__"):
            self.underlying.__enter__()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        self.exited = True
        suppressed = False
        if hasattr(self.underlying, "__exit__"):
            suppressed = bool(self.underlying.__exit__(exc_type, exc_val, exc_tb))
        if self.auto_close_on_exit and not self.closed:
            self.close()
        if exc_val is not None and self.exception is None:
            self.exception = exc_val
        return suppressed

    async def __aenter__(self) -> "StreamLifecycleSpy[T]":
        self.entered = True
        if hasattr(self.underlying, "__aenter__"):
            await self.underlying.__aenter__()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        self.exited = True
        suppressed = False
        if hasattr(self.underlying, "__aexit__"):
            suppressed = bool(await self.underlying.__aexit__(exc_type, exc_val, exc_tb))
        if self.auto_close_on_exit and not self.closed:
            await self.aclose()
        if exc_val is not None and self.exception is None:
            self.exception = exc_val
        return suppressed

    # --- Assertion Helpers ---

    def assert_not_leaked(self, msg: Optional[str] = None) -> None:
        """Asserts that stream resource was not leaked."""
        if self.is_leaked:
            raise AssertionError(
                msg
                or f"Stream resource leak detected: stream was iterated ({self.yield_count} items yielded) "
                f"but terminated prematurely without being exhausted or closed. "
                f"(exhausted={self.exhausted}, closed={self.closed})"
            )

    def assert_closed(self, msg: Optional[str] = None) -> None:
        """Asserts that stream was explicitly closed."""
        if not self.closed:
            raise AssertionError(
                msg or f"Stream lifecycle violation: expected stream to be closed, but closed={self.closed}."
            )

    def assert_exhausted(self, msg: Optional[str] = None) -> None:
        """Asserts that stream naturally exhausted all items."""
        if not self.exhausted:
            raise AssertionError(
                msg or f"Stream lifecycle violation: expected stream to be fully exhausted, but exhausted={self.exhausted}."
            )

    # --- Transparent Attribute Proxying ---

    def __getattr__(self, name: str) -> Any:
        return getattr(self.underlying, name)


def _strip_sql_comments(sql: str) -> str:
    """Strips SQL block and line comments to expose core statement tokens."""
    s = re.sub(r"/\*[\s\S]*?\*/", " ", sql)
    s = re.sub(r"--.*$", " ", s, flags=re.MULTILINE)
    return s


def _split_sql_script(script: str) -> List[str]:
    """Splits a multi-statement SQL script into individual statements,
    respecting single quotes, double quotes, and comments."""
    statements: List[str] = []
    current: List[str] = []
    i = 0
    n = len(script)
    in_single_quote = False
    in_double_quote = False
    in_line_comment = False
    in_block_comment = False

    while i < n:
        ch = script[i]
        next_ch = script[i + 1] if i + 1 < n else ""

        if in_line_comment:
            current.append(ch)
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            current.append(ch)
            if ch == "*" and next_ch == "/":
                current.append(next_ch)
                i += 2
                in_block_comment = False
                continue
            i += 1
            continue

        if in_single_quote:
            current.append(ch)
            if ch == "'":
                if next_ch == "'":
                    current.append(next_ch)
                    i += 2
                    continue
                elif i > 0 and script[i - 1] == "\\":
                    pass
                else:
                    in_single_quote = False
            i += 1
            continue

        if in_double_quote:
            current.append(ch)
            if ch == '"':
                if next_ch == '"':
                    current.append(next_ch)
                    i += 2
                    continue
                elif i > 0 and script[i - 1] == "\\":
                    pass
                else:
                    in_double_quote = False
            i += 1
            continue

        if ch == "-" and next_ch == "-":
            in_line_comment = True
            current.append(ch)
            current.append(next_ch)
            i += 2
            continue

        if ch == "/" and next_ch == "*":
            in_block_comment = True
            current.append(ch)
            current.append(next_ch)
            i += 2
            continue

        if ch == "'":
            in_single_quote = True
            current.append(ch)
            i += 1
            continue

        if ch == '"':
            in_double_quote = True
            current.append(ch)
            i += 1
            continue

        if ch == ";":
            stmt = "".join(current).strip()
            if stmt:
                statements.append(stmt)
            current = []
            i += 1
            continue

        current.append(ch)
        i += 1

    last_stmt = "".join(current).strip()
    if last_stmt:
        statements.append(last_stmt)

    return statements


class _SandboxCursorProxy:
    """Transparent proxy over sqlite3.Cursor that enforces transaction neutralization and savepoint isolation."""

    def __init__(self, real_cursor: sqlite3.Cursor, conn_proxy: "_SandboxConnectionProxy") -> None:
        self._real_cursor: sqlite3.Cursor = real_cursor
        self._conn_proxy: "_SandboxConnectionProxy" = conn_proxy

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> "_SandboxCursorProxy":
        res_cur = self._conn_proxy._filter_and_execute(self._real_cursor, sql, *args, **kwargs)
        if isinstance(res_cur, sqlite3.Cursor):
            self._real_cursor = res_cur
        return self

    def executemany(self, sql: str, seq_of_parameters: Any = (), *args: Any, **kwargs: Any) -> "_SandboxCursorProxy":
        cleaned = _strip_sql_comments(sql).strip().rstrip(";").strip()
        cleaned_upper = cleaned.upper()
        if cleaned_upper in ("COMMIT", "COMMIT TRANSACTION", "END", "END TRANSACTION") or cleaned_upper.startswith("RELEASE"):
            return self
        self._real_cursor.executemany(sql, seq_of_parameters, *args, **kwargs)
        return self

    def executescript(self, sql_script: str) -> "_SandboxCursorProxy":
        self._conn_proxy.executescript(sql_script)
        return self

    def fetchone(self) -> Any:
        return self._real_cursor.fetchone()

    def fetchmany(self, size: Optional[int] = None) -> Any:
        if size is None:
            return self._real_cursor.fetchmany()
        return self._real_cursor.fetchmany(size)

    def fetchall(self) -> Any:
        return self._real_cursor.fetchall()

    def close(self) -> None:
        try:
            self._real_cursor.close()
        except Exception:
            pass

    def __iter__(self) -> Any:
        return iter(self._real_cursor)

    def __next__(self) -> Any:
        return next(self._real_cursor)

    def __enter__(self) -> "_SandboxCursorProxy":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real_cursor, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_real_cursor", "_conn_proxy"):
            super().__setattr__(name, value)
        elif hasattr(self, "_real_cursor") and hasattr(self._real_cursor, name):
            setattr(self._real_cursor, name, value)
        else:
            super().__setattr__(name, value)


class _SandboxConnectionProxy:
    """Transparent proxy over sqlite3.Connection that neutralizes commits during probes."""

    def __init__(self, real_conn: sqlite3.Connection, sandbox: "EphemeralSQLiteSandbox") -> None:
        self._real_conn: sqlite3.Connection = real_conn
        self._sandbox: EphemeralSQLiteSandbox = sandbox

    def commit(self) -> None:
        """Intercepted! Inside a probe, commit is a no-op to protect savepoint integrity."""
        pass

    def rollback(self) -> None:
        """Rolls back to the current active savepoint rather than wiping connection state."""
        if self._sandbox._active_savepoints:
            sp = self._sandbox._active_savepoints[-1]
            self._real_conn.execute(f"ROLLBACK TO SAVEPOINT {sp};")
        else:
            self._real_conn.rollback()

    def _filter_and_execute(self, target: Any, sql: str, *args: Any, **kwargs: Any) -> Any:
        cleaned = _strip_sql_comments(sql).strip().rstrip(";").strip()
        cleaned_upper = cleaned.upper()
        if cleaned_upper in ("COMMIT", "COMMIT TRANSACTION", "END", "END TRANSACTION") or cleaned_upper.startswith("RELEASE"):
            return target if isinstance(target, sqlite3.Cursor) else self._real_conn.cursor()
        if cleaned_upper.startswith("BEGIN"):
            sp = f"user_nested_sp_{len(self._sandbox._active_savepoints)}"
            return self._real_conn.execute(f"SAVEPOINT {sp};")
        if cleaned_upper in ("ROLLBACK", "ROLLBACK TRANSACTION"):
            if self._sandbox._active_savepoints:
                active_sp = self._sandbox._active_savepoints[-1]
                return self._real_conn.execute(f"ROLLBACK TO SAVEPOINT {active_sp};")
            return target.execute("ROLLBACK;")
        if "params" in kwargs and not args:
            return target.execute(sql, kwargs["params"])
        return target.execute(sql, *args, **kwargs)

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> _SandboxCursorProxy:
        cur = self._filter_and_execute(self._real_conn, sql, *args, **kwargs)
        if isinstance(cur, _SandboxCursorProxy):
            return cur
        return _SandboxCursorProxy(cur, self)

    def executemany(self, sql: str, seq_of_parameters: Any = (), *args: Any, **kwargs: Any) -> _SandboxCursorProxy:
        cur = self._real_conn.executemany(sql, seq_of_parameters, *args, **kwargs)
        return _SandboxCursorProxy(cur, self)

    def executescript(self, sql_script: str) -> _SandboxCursorProxy:
        statements = _split_sql_script(sql_script)
        cur = self.cursor()
        for stmt in statements:
            cleaned = _strip_sql_comments(stmt).strip()
            if cleaned:
                cur.execute(stmt)
        return cur

    def cursor(self) -> _SandboxCursorProxy:
        return _SandboxCursorProxy(self._real_conn.cursor(), self)

    def close(self) -> None:
        """No-op during active savepoint probe to prevent premature connection disposal."""
        if not self._sandbox._active_savepoints:
            try:
                self._real_conn.close()
            except Exception:
                pass

    def __enter__(self) -> "_SandboxConnectionProxy":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass

    def __getattr__(self, name: str) -> Any:
        if hasattr(self._sandbox, name):
            return getattr(self._sandbox, name)
        return getattr(self._real_conn, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_real_conn", "_sandbox"):
            super().__setattr__(name, value)
        elif hasattr(self, "_real_conn") and hasattr(self._real_conn, name):
            setattr(self._real_conn, name, value)
        else:
            super().__setattr__(name, value)


class EphemeralSQLiteSandbox:
    """Ephemeral In-Memory SQLite Savepoint Sandbox.

    Provides sub-microsecond transaction isolation for mutating and fuzzing
    stateful SQL functions with zero state leakage.
    """

    def __init__(
        self,
        db_path_or_conn: Any = None,
        setup_sql: Optional[str] = None,
        savepoint_name: Optional[str] = None,
        *,
        connection: Optional[sqlite3.Connection] = None,
        db_path: Optional[str] = None,
        uri: Optional[str] = None,
        savepoint_prefix: Optional[str] = None,
    ) -> None:
        real_conn: Optional[sqlite3.Connection] = None
        target_path: str = ":memory:"

        if isinstance(db_path_or_conn, sqlite3.Connection):
            real_conn = db_path_or_conn
        elif isinstance(db_path_or_conn, str):
            target_path = db_path_or_conn
        elif connection is not None:
            real_conn = connection
        elif db_path is not None:
            target_path = db_path
        elif uri is not None:
            target_path = uri

        self.db_path: str = target_path
        self.savepoint_name: str = (
            savepoint_name or savepoint_prefix or "cordis_probe"
        )
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", self.savepoint_name):
            raise ValueError(f"Invalid savepoint name: {self.savepoint_name!r}")
        self.savepoint_prefix: str = self.savepoint_name

        self._own_conn: bool = real_conn is None
        self._depth: int = 0
        self._active_savepoints: List[str] = []

        if real_conn is None:
            self._conn: sqlite3.Connection = sqlite3.connect(self.db_path)
            self._prev_isolation = None
            self._conn.isolation_level = None
        else:
            self._conn = real_conn
            self._prev_isolation = self._conn.isolation_level
            self._conn.isolation_level = None

        if setup_sql:
            self._conn.executescript(setup_sql)

        self.connection: _SandboxConnectionProxy = _SandboxConnectionProxy(self._conn, self)

    def __enter__(self) -> "EphemeralSQLiteSandbox":
        sp_name = f"{self.savepoint_name}_{self._depth}"
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", sp_name):
            raise ValueError(f"Invalid savepoint name: {sp_name!r}")
        self._conn.execute(f"SAVEPOINT {sp_name};")
        self._active_savepoints.append(sp_name)
        self._depth += 1
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._active_savepoints:
            sp_name = self._active_savepoints.pop()
            self._depth -= 1
            try:
                self._conn.execute(f"ROLLBACK TO SAVEPOINT {sp_name};")
            except Exception:
                pass
            try:
                self._conn.execute(f"RELEASE SAVEPOINT {sp_name};")
            except Exception:
                pass

        if not self._active_savepoints and self._prev_isolation is not None:
            try:
                self._conn.isolation_level = self._prev_isolation
            except Exception:
                pass

    @contextmanager
    def probe(self, name: Optional[str] = None) -> Generator[_SandboxConnectionProxy, None, None]:
        """Scoped context manager for isolating an individual mutant probe or fuzz run."""
        sp_name = name or f"{self.savepoint_name}_probe_{self._depth}"
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", sp_name):
            raise ValueError(f"Invalid savepoint name: {sp_name!r}")
        self._conn.execute(f"SAVEPOINT {sp_name};")
        self._active_savepoints.append(sp_name)
        self._depth += 1
        try:
            yield self.connection
        finally:
            self._depth -= 1
            if self._active_savepoints and self._active_savepoints[-1] == sp_name:
                self._active_savepoints.pop()
            try:
                self._conn.execute(f"ROLLBACK TO SAVEPOINT {sp_name};")
            except Exception:
                pass
            try:
                self._conn.execute(f"RELEASE SAVEPOINT {sp_name};")
            except Exception:
                pass

    # --- Connection Operations Proxied to Safe Sandbox Proxy ---

    def execute(self, sql: str, *args: Any, **kwargs: Any) -> _SandboxCursorProxy:
        return self.connection.execute(sql, *args, **kwargs)

    def executemany(self, sql: str, seq_of_parameters: Any = (), *args: Any, **kwargs: Any) -> _SandboxCursorProxy:
        return self.connection.executemany(sql, seq_of_parameters, *args, **kwargs)

    def executescript(self, sql_script: str) -> _SandboxCursorProxy:
        return self.connection.executescript(sql_script)

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()

    def cursor(self) -> _SandboxCursorProxy:
        return self.connection.cursor()

    def close(self) -> None:
        """Closes connection when not inside an active probe."""
        if not self._active_savepoints:
            try:
                self._conn.close()
            except Exception:
                pass

    # --- Convenience Database Query Helpers ---

    def fetch_all(self, sql: str, *args: Any, **kwargs: Any) -> List[Tuple[Any, ...]]:
        return self.execute(sql, *args, **kwargs).fetchall()

    def fetch_one(self, sql: str, *args: Any, **kwargs: Any) -> Optional[Tuple[Any, ...]]:
        return self.execute(sql, *args, **kwargs).fetchone()

    def fetch_val(self, sql: str, *args: Any, **kwargs: Any) -> Any:
        row = self.fetch_one(sql, *args, **kwargs)
        return row[0] if row else None

    def table_exists(self, table_name: str) -> bool:
        row = self.fetch_one(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        return row is not None

    def count_rows(self, table_name: str) -> int:
        return int(self.fetch_val(f"SELECT COUNT(*) FROM {table_name};") or 0)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in (
            "db_path",
            "savepoint_name",
            "savepoint_prefix",
            "_own_conn",
            "_depth",
            "_active_savepoints",
            "_conn",
            "_prev_isolation",
            "connection",
        ):
            super().__setattr__(name, value)
        elif hasattr(self, "_conn") and hasattr(self._conn, name):
            setattr(self._conn, name, value)
        else:
            super().__setattr__(name, value)

    def __del__(self) -> None:
        if getattr(self, "_own_conn", False) and hasattr(self, "_conn"):
            try:
                self._conn.close()
            except Exception:
                pass


__all__ = ["StreamLifecycleSpy", "EphemeralSQLiteSandbox"]

`

## 2. cordis/polyglot_gate.py
`python
"""Gate 1 & Gate 2: Zero-Dependency Polyglot AST Gate (Go & Rust).
Provides 64-bit BLAKE2b AST anchor indexing, test tampering / anti-mock auditing,
and diff-scoped mutant synthesis for Go and Rust using 100% Python 3.10+ standard library.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from cordis.ast_gate import ASTAnchor, TestTamperingReport, compute_node_hash

__all__ = [
    "AnchorDict",
    "mask_go_code",
    "index_go_ast_anchors",
    "audit_go_test_tampering",
    "generate_go_mutants",
    "mask_rust_code",
    "index_rust_ast_anchors",
    "audit_rust_test_tampering",
    "generate_rust_mutants",
]


class AnchorDict(dict):
    """Dictionary mapping qualified names, anchor tags, and hash tags to ASTAnchor."""

    def __getitem__(self, key: str) -> ASTAnchor:
        if super().__contains__(key):
            return super().__getitem__(key)
        for anchor in self.values():
            if anchor.tag == key or anchor.hash_tag == key:
                return anchor
        if "::" in key:
            alt = key.replace("::", ".")
            if super().__contains__(alt):
                return super().__getitem__(alt)
        elif "." in key:
            alt = key.replace(".", "::")
            if super().__contains__(alt):
                return super().__getitem__(alt)
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if super().__contains__(key):
            return True
        if isinstance(key, str):
            if any(anchor.tag == key or anchor.hash_tag == key for anchor in self.values()):
                return True
            if "::" in key:
                alt = key.replace("::", ".")
                if super().__contains__(alt):
                    return True
            elif "." in key:
                alt = key.replace(".", "::")
                if super().__contains__(alt):
                    return True
        return False


def _find_matching_brace(code: str, start_idx: int) -> int:
    """Finds index of matching '}' for '{' at start_idx in masked code."""
    depth = 0
    for i in range(start_idx, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(code) - 1


def _find_matching_paren(code: str, start_idx: int) -> int:
    """Finds index of matching ')' for '(' at start_idx in masked code."""
    depth = 0
    for i in range(start_idx, len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


# ==============================================================================
# GO GATE: LEXICAL SCANNER, AST ANCHOR INDEXER, TAMPERING AUDITOR & MUTATOR
# ==============================================================================


def mask_go_code(code: str, mask_strings: bool = True) -> str:
    """Masks comments and optionally strings/runes in Go code with whitespace,
    preserving exact character offsets and newline positions (\\n).
    """
    n = len(code)
    out: List[str] = []
    i = 0
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""

        # Line comment: // ...
        if c == "/" and nxt == "/":
            out.append("  ")
            i += 2
            while i < n and code[i] != "\n":
                out.append(" ")
                i += 1
            continue

        # Block comment: /* ... */ (non-nestable in Go)
        if c == "/" and nxt == "*":
            out.append("  ")
            i += 2
            while i < n:
                if code[i] == "*" and i + 1 < n and code[i + 1] == "/":
                    out.append("  ")
                    i += 2
                    break
                else:
                    out.append("\n" if code[i] == "\n" else " ")
                    i += 1
            continue

        # Raw string literal: `...`
        if c == "`":
            out.append(" " if mask_strings else "`")
            i += 1
            while i < n:
                if code[i] == "`":
                    out.append(" " if mask_strings else "`")
                    i += 1
                    break
                else:
                    out.append("\n" if code[i] == "\n" else (" " if mask_strings else code[i]))
                    i += 1
            continue

        # Interpreted string literal: "..."
        if c == '"':
            out.append(" " if mask_strings else '"')
            i += 1
            while i < n:
                sc = code[i]
                if sc == "\\":
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(" ")
                            out.append("\n" if snxt == "\n" else " ")
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(" " if mask_strings else sc)
                        i += 1
                elif sc == '"':
                    out.append(" " if mask_strings else '"')
                    i += 1
                    break
                elif sc == "\n":
                    out.append("\n")
                    i += 1
                    break
                else:
                    out.append(" " if mask_strings else sc)
                    i += 1
            continue

        # Rune literal: '...'
        if c == "'":
            out.append(" " if mask_strings else "'")
            i += 1
            while i < n:
                sc = code[i]
                if sc == "\\":
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(" ")
                            out.append("\n" if snxt == "\n" else " ")
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(" " if mask_strings else sc)
                        i += 1
                elif sc == "'":
                    out.append(" " if mask_strings else "'")
                    i += 1
                    break
                elif sc == "\n":
                    out.append("\n")
                    i += 1
                    break
                else:
                    out.append(" " if mask_strings else sc)
                    i += 1
            continue

        out.append(c)
        i += 1

    return "".join(out)


def _extract_go_receiver_type(recv_str: str) -> str:
    """Extracts base receiver struct name from Go receiver parameter string."""
    cleaned = recv_str.strip()
    no_brackets = re.sub(r"\[.*\]", "", cleaned).strip()
    parts = no_brackets.split()
    type_part = parts[-1] if parts else no_brackets
    type_part = type_part.lstrip("*&").strip()
    return type_part


def index_go_ast_anchors(source_code: str, file_path: str = "module.go") -> Dict[str, ASTAnchor]:
    """Indexes functions and receiver methods in Go code into 64-bit BLAKE2b AST anchors."""
    clean_code = source_code.lstrip("\ufeff")
    if not clean_code.strip():
        return AnchorDict()

    masked = mask_go_code(clean_code, mask_strings=True)
    anchors = AnchorDict()

    # Match func declarations:
    # 1. func (r *Receiver) Method(args) ... {
    # 2. func FunctionName(args) ... {
    func_pattern = re.compile(
        r"(?:^|[;\n\s])func\s+(?:\((?P<recv>[^)]+)\)\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    )

    for m in func_pattern.finditer(masked):
        idx = m.start()
        # Find exact start of 'func' keyword
        func_kw_idx = clean_code.find("func", idx, m.end())
        if func_kw_idx == -1:
            continue

        recv_raw = m.group("recv")
        name = m.group("name")

        if recv_raw:
            scope_path = _extract_go_receiver_type(recv_raw)
            qualname = f"{scope_path}.{name}"
            node_type = "MethodDeclaration"
        else:
            scope_path = "<module>"
            qualname = name
            node_type = "FunctionDeclaration"

        # Find opening brace '{'
        decl_end = m.end()
        brace_idx = masked.find("{", decl_end)
        if brace_idx == -1:
            continue

        # Check that there is no semicolon or other func before '{'
        intermediate = masked[decl_end:brace_idx]
        if ";" in intermediate:
            continue

        close_brace_idx = _find_matching_brace(masked, brace_idx)
        lineno = clean_code.count("\n", 0, func_kw_idx) + 1
        end_lineno = clean_code.count("\n", 0, close_brace_idx) + 1

        raw_sig = clean_code[func_kw_idx:brace_idx].strip()
        sig = re.sub(r"\s+", " ", raw_sig)

        raw_body = clean_code[brace_idx + 1 : close_brace_idx]
        norm_body = re.sub(r"\s+", "", raw_body)

        hash_tag = compute_node_hash(
            file_path=file_path,
            scope_path=scope_path,
            node_type=node_type,
            identifier=name,
            signature=sig,
            normalized_body_dump=norm_body,
        )

        anchor = ASTAnchor(
            file_path=file_path,
            scope_path=scope_path,
            node_type=node_type,
            identifier=name,
            signature=sig,
            lineno=lineno,
            end_lineno=end_lineno,
            hash_tag=hash_tag,
        )

        anchors[qualname] = anchor

    return anchors


def _count_go_table_cases(code: str) -> int:
    """Counts test cases inside Go table-driven struct slice literals."""
    masked = mask_go_code(code, mask_strings=True)
    pattern = re.compile(r"\[\]struct\s*\{[^}]*\}\s*\{")
    total_cases = 0
    for m in pattern.finditer(masked):
        body_start = m.end() - 1
        body_end = _find_matching_brace(masked, body_start)
        slice_body = masked[body_start + 1 : body_end]
        depth = 0
        cases = 0
        for ch in slice_body:
            if ch == "{":
                if depth == 0:
                    cases += 1
                depth += 1
            elif ch == "}":
                if depth > 0:
                    depth -= 1
        total_cases += cases
    return total_cases


def audit_go_test_tampering(
    old_go: str,
    new_go: str,
    file_path: str = "module_test.go",
) -> TestTamperingReport:
    """Audits Go tests for tampering, skipping (t.Skip), weakened assertions,
    blank identifier result discarding (_ = got), and table shrinking.
    """
    violations: List[str] = []
    clean_new = new_go.lstrip("\ufeff")
    masked_new = mask_go_code(clean_new, mask_strings=False)

    # 1. Test Skipping: t.Skip / t.Skipf / t.SkipNow
    skip_pattern = re.compile(r"\bt\.(?:Skip|Skipf|SkipNow)\b")
    for m in skip_pattern.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Test decorated with t.Skip / t.SkipNow.")

    # 2. Strong vs Hollow assertions
    strong_re = re.compile(
        r"\b(?:assert\.Equal|require\.Equal|assert\.True|require\.True|assert\.False|require\.False|"
        r"assert\.Contains|cmp\.Diff|cmp\.Equal|reflect\.DeepEqual|t\.Errorf|t\.Fatalf|t\.FailNow)\b"
    )
    hollow_re = re.compile(
        r"\b(?:assert\.NotNil|require\.NotNil|assert\.Nil|require\.Nil|assert\.NotZero|require\.NotZero)\b"
    )

    old_strong = list(strong_re.finditer(old_go))
    new_strong = list(strong_re.finditer(clean_new))
    new_hollow = list(hollow_re.finditer(clean_new))

    if new_hollow and (len(old_strong) > len(new_strong) or len(new_strong) == 0):
        for hm in new_hollow:
            lineno = clean_new.count("\n", 0, hm.start()) + 1
            violations.append(
                f"Line {lineno}: Strong value assertions weakened to hollow checks (assert.NotNil / hollow check without value comparison)."
            )

    # 3. Blank identifier result discarding: _ = got
    blank_re = re.compile(r"(?:^|[;{\n])\s*_\s*=\s*[^;\n]+")
    for m in blank_re.finditer(masked_new):
        u_idx = clean_new.find("_", m.start(), m.end())
        idx = u_idx if u_idx != -1 else m.start()
        lineno = clean_new.count("\n", 0, idx) + 1
        violations.append(
            f"Line {lineno}: Test discards output value via blank identifier '_ = got' without assertion."
        )

    # 4. Table-driven test shrinking
    old_table_cases = _count_go_table_cases(old_go)
    new_table_cases = _count_go_table_cases(clean_new)
    if old_table_cases > 0 and new_table_cases < old_table_cases:
        violations.append(
            f"Line 1: Table-driven test table was shrunk (deleted test cases from {old_table_cases} to {new_table_cases})."
        )

    # 5. Tautological assertions: assert.Equal(t, x, x) or assert.True(t, true)
    tautology_eq = re.compile(r"\bassert\.Equal\s*\(\s*[^,]+,\s*([A-Za-z0-9_]+)\s*,\s*\1\s*\)")
    for m in tautology_eq.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Tautological assertion detected (comparing variable to itself).")

    tautology_true = re.compile(r"\bassert\.True\s*\(\s*[^,]+,\s*true\s*\)")
    for m in tautology_true.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Tautological assertion detected (asserting true).")

    anchors = index_go_ast_anchors(clean_new, file_path=file_path) if clean_new.strip() else AnchorDict()

    return TestTamperingReport(
        passed=len(violations) == 0,
        old_assert_count=len(old_strong),
        new_assert_count=len(new_strong),
        violations=violations,
        anchors=anchors,
    )


def generate_go_mutants(
    go_code: str,
    max_mutants: int = 5,
    target_function: Optional[str] = None,
) -> List[Tuple[str, int, str]]:
    """Synthesizes up to `max_mutants` distinct diff-scoped Go mutants.
    Returns list of (description, lineno, mutated_go_code).
    """
    clean_code = go_code.lstrip("\ufeff")
    if not clean_code.strip():
        return []

    masked = mask_go_code(clean_code, mask_strings=True)
    anchors = index_go_ast_anchors(clean_code)

    start_line = 1
    end_line = clean_code.count("\n") + 1

    if target_function:
        if target_function in anchors:
            start_line = anchors[target_function].lineno
            end_line = anchors[target_function].end_lineno
        else:
            match = next((a for a in anchors.values() if a.identifier == target_function), None)
            if match:
                start_line = match.lineno
                end_line = match.end_lineno
            else:
                return []

    mutants: List[Tuple[str, int, str]] = []
    seen_mutations: Set[str] = set()

    patterns: List[Tuple[str, str, str]] = [
        (r"==", "!=", "Equality inverted (== to !=)"),
        (r"!=", "==", "Inequality inverted (!= to ==)"),
        (r"<=", "<", "Relational boundary adjusted (<= to <)"),
        (r">=", ">", "Relational boundary adjusted (>= to >)"),
        (r"(?<![<=-])<(?![<=-])", ">=", "Relational order inverted (< to >=)"),
        (r"(?<![>=-])>(?![>=-])", "<=", "Relational order inverted (> to <=)"),
        (r"&&", "||", "Logical AND inverted to OR (&& to ||)"),
        (r"\|\|", "&&", "Logical OR inverted to AND (|| to &&)"),
        (r"(?<!\+)\+(?!\+|=)", "-", "Arithmetic addition inverted to subtraction (+ to -)"),
        (r"(?<!-)-(?!-|=|>)", "+", "Arithmetic subtraction inverted to addition (- to +)"),
        (r"\btrue\b", "false", "Boolean literal inverted (true to false)"),
        (r"\bfalse\b", "true", "Boolean literal inverted (false to true)"),
    ]

    for pat, rep, desc in patterns:
        for m in re.finditer(pat, masked):
            idx = m.start()
            end_idx = m.end()
            lineno = clean_code.count("\n", 0, idx) + 1
            if not (start_line <= lineno <= end_line):
                continue
            mutated = clean_code[:idx] + rep + clean_code[end_idx:]
            if mutated not in seen_mutations and mutated != clean_code:
                seen_mutations.add(mutated)
                mutants.append((f"Line {lineno}: {desc}", lineno, mutated))
                if len(mutants) >= max_mutants:
                    return mutants

    # Return nil mutation: return <expr> -> return nil
    ret_re = re.compile(r"\breturn\s+([^;\n]+)")
    for m in ret_re.finditer(masked):
        idx = m.start()
        end_idx = m.end()
        lineno = clean_code.count("\n", 0, idx) + 1
        if not (start_line <= lineno <= end_line):
            continue
        expr = clean_code[m.start(1) : m.end(1)].strip()
        if expr == "nil":
            continue
        mutated = clean_code[: m.start(1)] + "nil" + clean_code[m.end(1) :]
        if mutated not in seen_mutations and mutated != clean_code:
            seen_mutations.add(mutated)
            mutants.append((f"Line {lineno}: Replace return expression with 'nil'", lineno, mutated))
            if len(mutants) >= max_mutants:
                return mutants

    return mutants


# ==============================================================================
# RUST GATE: LEXICAL SCANNER, AST ANCHOR INDEXER, TAMPERING AUDITOR & MUTATOR
# ==============================================================================


def mask_rust_code(code: str, mask_strings: bool = True) -> str:
    """Masks comments and optionally strings/literals in Rust code with whitespace,
    supporting nested block comments (/* /* */ */), raw strings (r#\"...\"#),
    and character literals vs lifetime annotations ('a).
    """
    n = len(code)
    out: List[str] = []
    i = 0
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""

        # Line comment: //, ///, //!
        if c == "/" and nxt == "/":
            out.append("  ")
            i += 2
            while i < n and code[i] != "\n":
                out.append(" ")
                i += 1
            continue

        # Nested block comment: /* ... /* ... */ ... */
        if c == "/" and nxt == "*":
            depth = 1
            out.append("  ")
            i += 2
            while i < n and depth > 0:
                if code[i] == "/" and i + 1 < n and code[i + 1] == "*":
                    depth += 1
                    out.append("  ")
                    i += 2
                elif code[i] == "*" and i + 1 < n and code[i + 1] == "/":
                    depth -= 1
                    out.append("  ")
                    i += 2
                else:
                    out.append("\n" if code[i] == "\n" else " ")
                    i += 1
            continue

        # Raw string literal: r"...", r#"..."#, r##"..."##, br#"..."#
        if (c == "r" and (nxt == '"' or nxt == "#")) or (c == "b" and nxt == "r"):
            raw_match = re.match(r"^(?:b)?r(#*)\"", code[i:])
            if raw_match:
                hashes = raw_match.group(1)
                delim = f'"{hashes}'
                prefix_len = len(raw_match.group(0))
                out.append(" " * prefix_len if mask_strings else code[i : i + prefix_len])
                i += prefix_len
                end_pos = code.find(delim, i)
                if end_pos != -1:
                    inner = code[i:end_pos]
                    for ch in inner:
                        out.append("\n" if ch == "\n" else (" " if mask_strings else ch))
                    out.append(" " * len(delim) if mask_strings else delim)
                    i = end_pos + len(delim)
                    continue

        # Regular string literal: "..."
        if c == '"':
            out.append(" " if mask_strings else '"')
            i += 1
            while i < n:
                sc = code[i]
                if sc == "\\":
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(" ")
                            out.append("\n" if snxt == "\n" else " ")
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(" " if mask_strings else sc)
                        i += 1
                elif sc == '"':
                    out.append(" " if mask_strings else '"')
                    i += 1
                    break
                elif sc == "\n":
                    out.append("\n")
                    i += 1
                    break
                else:
                    out.append(" " if mask_strings else sc)
                    i += 1
            continue

        # Char literal vs Lifetime: 'c' vs 'a
        if c == "'":
            char_match = re.match(r"^'(?:[^'\\]|\\(?:[nrt0\\'\"\\/]|x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}))'", code[i:])
            if char_match:
                c_len = len(char_match.group(0))
                out.append(" " * c_len if mask_strings else char_match.group(0))
                i += c_len
                continue

        out.append(c)
        i += 1

    return "".join(out)


def index_rust_ast_anchors(source_code: str, file_path: str = "lib.rs") -> Dict[str, ASTAnchor]:
    """Indexes functions and impl methods in Rust code into 64-bit BLAKE2b AST anchors."""
    clean_code = source_code.lstrip("\ufeff")
    if not clean_code.strip():
        return AnchorDict()

    masked = mask_rust_code(clean_code, mask_strings=True)
    anchors = AnchorDict()

    # Pass 1: Discover impl blocks to establish scopes
    # impl StructName { ... } or impl Trait for StructName { ... }
    impl_blocks: List[Tuple[int, int, str]] = []
    impl_pattern = re.compile(r"\bimpl\b(?P<hdr>[^{]+)\{")
    for m in impl_pattern.finditer(masked):
        brace_idx = m.end() - 1
        end_brace_idx = _find_matching_brace(masked, brace_idx)
        hdr = m.group("hdr").strip()
        if " for " in hdr:
            target_raw = hdr.split(" for ")[-1].strip()
        else:
            target_raw = hdr
        target_clean = re.sub(r"<[^>]*>", "", target_raw)
        target_clean = target_clean.split("where")[0].strip()
        words = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", target_clean)
        target_type = words[-1] if words else "Unknown"
        impl_blocks.append((brace_idx, end_brace_idx, target_type))

    # Pass 2: Discover fn declarations
    fn_pattern = re.compile(
        r"(?:^|[;\n\s])(?:pub(?:\([^)]+\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern(?:\s+\"[^\"]+\")?\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    )

    for m in fn_pattern.finditer(masked):
        idx = m.start()
        fn_kw_idx = clean_code.find("fn", idx, m.end())
        if fn_kw_idx == -1:
            continue

        name = m.group("name")

        # Determine scope from enclosing impl blocks
        scope_path = "<module>"
        node_type = "FunctionDeclaration"
        for start_b, end_b, t_name in impl_blocks:
            if start_b <= fn_kw_idx <= end_b:
                scope_path = t_name
                node_type = "MethodDeclaration"
                break

        qualname = f"{scope_path}.{name}" if scope_path != "<module>" else name

        decl_end = m.end()
        brace_idx = masked.find("{", decl_end)
        if brace_idx == -1:
            continue

        intermediate = masked[decl_end:brace_idx]
        if ";" in intermediate:
            # Trait method stub without body
            continue

        close_brace_idx = _find_matching_brace(masked, brace_idx)
        lineno = clean_code.count("\n", 0, fn_kw_idx) + 1
        end_lineno = clean_code.count("\n", 0, close_brace_idx) + 1

        raw_sig = clean_code[fn_kw_idx:brace_idx].strip()
        sig = re.sub(r"\s+", " ", raw_sig)

        raw_body = clean_code[brace_idx + 1 : close_brace_idx]
        norm_body = re.sub(r"\s+", "", raw_body)

        hash_tag = compute_node_hash(
            file_path=file_path,
            scope_path=scope_path,
            node_type=node_type,
            identifier=name,
            signature=sig,
            normalized_body_dump=norm_body,
        )

        anchor = ASTAnchor(
            file_path=file_path,
            scope_path=scope_path,
            node_type=node_type,
            identifier=name,
            signature=sig,
            lineno=lineno,
            end_lineno=end_lineno,
            hash_tag=hash_tag,
        )

        anchors[qualname] = anchor

    return anchors


def audit_rust_test_tampering(
    old_rs: str,
    new_rs: str,
    file_path: str = "lib.rs",
    prod_rs_diff: str = "",
) -> TestTamperingReport:
    """Audits Rust tests and production diffs for tampering:
    1. #[ignore] skip attributes on test functions.
    2. Weak assertions (assert!(x.is_ok()) / assert!(x.is_some()) without payload equality).
    3. Production code .unwrap() / .expect() panic injections (grounded in Prusti & Creusot verification).
    4. Tautological assertions.
    """
    violations: List[str] = []
    clean_new = new_rs.lstrip("\ufeff")
    masked_new = mask_rust_code(clean_new, mask_strings=False)

    # 1. #[ignore] attribute detection
    ignore_pattern = re.compile(r"#\[\s*ignore(?:\s*=\s*\"[^\"]*\")?\s*\]")
    for m in ignore_pattern.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Test decorated with #[ignore] attribute.")

    # 2. Weak assertions: assert!(x.is_ok()) / assert!(x.is_some()) without value comparison
    assert_pattern = re.compile(r"\bassert!\s*\(")
    for m in assert_pattern.finditer(masked_new):
        open_paren_idx = m.end() - 1
        close_paren_idx = _find_matching_paren(masked_new, open_paren_idx)
        if close_paren_idx != -1:
            inner = clean_new[open_paren_idx + 1 : close_paren_idx]
            if re.search(r"\.(?:is_ok|is_some|is_err|is_none)\s*\(\s*\)", inner):
                lineno = clean_new.count("\n", 0, m.start()) + 1
                violations.append(
                    f"Line {lineno}: Weak assertion 'assert!(x.is_ok())' used without value equality assertion (violates Prusti/Creusot postcondition invariant)."
                )

    # 3. Production code panic injection via .unwrap() / .expect() in prod_rs_diff
    if prod_rs_diff:
        for line_idx, line in enumerate(prod_rs_diff.splitlines(), start=1):
            if line.startswith("+") and not line.startswith("+++"):
                added_code = line[1:]
                code_without_comments = re.sub(r"//.*$", "", added_code)
                if re.search(r"(?<!\bunwrap_or)(?<!\bunwrap_or_else)(?<!\bunwrap_or_default)\.unwrap\s*\(", code_without_comments):
                    violations.append(
                        f"Line {line_idx}: Production code injects unsafe/panic-prone .unwrap() call (violates Prusti/Creusot panic-freedom invariant)."
                    )
                elif re.search(r"\.expect\s*\(", code_without_comments):
                    violations.append(
                        f"Line {line_idx}: Production code injects unsafe/panic-prone .expect() call (violates Prusti/Creusot panic-freedom invariant)."
                    )

    # 4. Tautological assertions: assert_eq!(x, x) or assert!(true)
    tautology_eq = re.compile(r"\bassert_eq!\s*\(\s*([A-Za-z0-9_]+)\s*,\s*\1\s*\)")
    for m in tautology_eq.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Tautological assertion detected (comparing variable to itself).")

    tautology_true = re.compile(r"\bassert!\s*\(\s*true\s*\)")
    for m in tautology_true.finditer(masked_new):
        lineno = clean_new.count("\n", 0, m.start()) + 1
        violations.append(f"Line {lineno}: Tautological assertion detected (asserting true).")

    anchors = index_rust_ast_anchors(clean_new, file_path=file_path) if clean_new.strip() else AnchorDict()
    old_asserts = len(re.findall(r"\b(?:assert_eq!|assert_ne!|assert!|matches!)\b", old_rs))
    new_asserts = len(re.findall(r"\b(?:assert_eq!|assert_ne!|assert!|matches!)\b", clean_new))

    return TestTamperingReport(
        passed=len(violations) == 0,
        old_assert_count=old_asserts,
        new_assert_count=new_asserts,
        violations=violations,
        anchors=anchors,
    )


def generate_rust_mutants(
    rs_code: str,
    max_mutants: int = 5,
    target_function: Optional[str] = None,
) -> List[Tuple[str, int, str]]:
    """Synthesizes up to `max_mutants` distinct diff-scoped Rust mutants.
    Returns list of (description, lineno, mutated_rs_code).
    """
    clean_code = rs_code.lstrip("\ufeff")
    if not clean_code.strip():
        return []

    masked = mask_rust_code(clean_code, mask_strings=True)
    anchors = index_rust_ast_anchors(clean_code)

    start_line = 1
    end_line = clean_code.count("\n") + 1

    if target_function:
        if target_function in anchors:
            start_line = anchors[target_function].lineno
            end_line = anchors[target_function].end_lineno
        else:
            match = next((a for a in anchors.values() if a.identifier == target_function), None)
            if match:
                start_line = match.lineno
                end_line = match.end_lineno
            else:
                return []

    mutants: List[Tuple[str, int, str]] = []
    seen_mutations: Set[str] = set()

    patterns: List[Tuple[str, str, str]] = [
        (r"==", "!=", "Equality inverted (== to !=)"),
        (r"!=", "==", "Inequality inverted (!= to ==)"),
        (r"<=", "<", "Relational boundary adjusted (<= to <)"),
        (r">=", ">", "Relational boundary adjusted (>= to >)"),
        (r"(?<![<=-])<(?![<=-])", ">=", "Relational order inverted (< to >=)"),
        (r"(?<![>=-])>(?![>=-])", "<=", "Relational order inverted (> to <=)"),
        (r"&&", "||", "Logical AND inverted to OR (&& to ||)"),
        (r"\|\|", "&&", "Logical OR inverted to AND (|| to &&)"),
        (r"(?<!\+)\+(?!\+|=)", "-", "Arithmetic addition inverted to subtraction (+ to -)"),
        (r"(?<!-)-(?!-|=|>)", "+", "Arithmetic subtraction inverted to addition (- to +)"),
        (r"\btrue\b", "false", "Boolean literal inverted (true to false)"),
        (r"\bfalse\b", "true", "Boolean literal inverted (false to true)"),
    ]

    for pat, rep, desc in patterns:
        for m in re.finditer(pat, masked):
            idx = m.start()
            end_idx = m.end()
            lineno = clean_code.count("\n", 0, idx) + 1
            if not (start_line <= lineno <= end_line):
                continue
            mutated = clean_code[:idx] + rep + clean_code[end_idx:]
            if mutated not in seen_mutations and mutated != clean_code:
                seen_mutations.add(mutated)
                mutants.append((f"Line {lineno}: {desc}", lineno, mutated))
                if len(mutants) >= max_mutants:
                    return mutants

    # Return Default::default() mutation: return <expr>; -> return Default::default();
    ret_re = re.compile(r"\breturn\s+([^;]+);")
    for m in ret_re.finditer(masked):
        idx = m.start()
        end_idx = m.end()
        lineno = clean_code.count("\n", 0, idx) + 1
        if not (start_line <= lineno <= end_line):
            continue
        expr = clean_code[m.start(1) : m.end(1)].strip()
        if expr == "Default::default()":
            continue
        mutated = clean_code[: m.start(1)] + "Default::default()" + clean_code[m.end(1) :]
        if mutated not in seen_mutations and mutated != clean_code:
            seen_mutations.add(mutated)
            mutants.append((f"Line {lineno}: Replace return expression with 'Default::default()'", lineno, mutated))
            if len(mutants) >= max_mutants:
                return mutants

    return mutants

`

## 3. cordis/ts_gate.py
`python
"""Gate 1 & Gate 2: Zero-Dependency TypeScript / JavaScript / Jest / Vitest AST Gate.
Provides 64-bit BLAKE2b AST anchor indexing, test tampering / anti-mock auditing,
and diff-scoped mutant synthesis using 100% Python 3.10+ standard library.
"""
from __future__ import annotations
import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from cordis.ast_gate import ASTAnchor, TestTamperingReport, compute_node_hash
__all__ = ['AnchorDict', 'index_ts_ast_anchors', 'audit_ts_test_tampering', 'generate_ts_mutants', 'mask_ts_code', 'strip_ts_comments', 'BOUNDARY_MOCK_TARGETS']

class AnchorDict(dict):
    """Dictionary mapping qualified names and anchor tags to ASTAnchor."""

    def __getitem__(self, key: str) -> ASTAnchor:
        if super().__contains__(key):
            return super().__getitem__(key)
        for anchor in self.values():
            if anchor.tag == key or anchor.hash_tag == key:
                return anchor
        raise KeyError(key)

    def __contains__(self, key: object) -> bool:
        if super().__contains__(key):
            return True
        if isinstance(key, str):
            return any((anchor.tag == key or anchor.hash_tag == key for anchor in self.values()))
        return False

def _is_regex_start(code: str, pos: int) -> bool:
    """Heuristic check whether `/` at `pos` starts a regex literal rather than division."""
    j = pos - 1
    while j >= 0 and code[j] in ' \t\r\n':
        j -= 1
    if j < 0:
        return True
    prev = code[j]
    if prev in '+-':
        if j > 0 and code[j - 1] == prev and (j < 2 or code[j - 2] != prev):
            return False
    if prev in '(=[!&|?:,;~^><+*%-{':
        return True
    if prev.isalnum() or prev in '_$':
        k = j
        while k >= 0 and (code[k].isalnum() or code[k] in '_$'):
            k -= 1
        word = code[k + 1:j + 1]
        if word in ('return', 'yield', 'case', 'default', 'typeof', 'delete', 'void', 'throw', 'await', 'in', 'of', 'instanceof', 'else', 'do'):
            return True
        return False
    return False

def mask_ts_code(code: str, mask_strings: bool=True) -> str:
    """Masks comments and optionally string/template literals with whitespace,
    preserving exact byte offsets and newline positions (\\n).
    """
    n = len(code)
    out: List[str] = []
    i = 0
    stack: List[Any] = []
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ''
        if stack and stack[-1] == 'TEMPLATE':
            if c == '\\':
                if i + 1 < n:
                    if mask_strings:
                        out.append(' ')
                        out.append('\n' if nxt == '\n' else ' ')
                    else:
                        out.append(c)
                        out.append(nxt)
                    i += 2
                else:
                    out.append(' ' if mask_strings else c)
                    i += 1
                continue
            elif c == '`':
                stack.pop()
                out.append(' ' if mask_strings else '`')
                i += 1
                continue
            elif c == '$' and nxt == '{':
                stack.append(['EXPR', 1])
                out.append('  ' if mask_strings else '${')
                i += 2
                continue
            else:
                if mask_strings:
                    out.append('\n' if c == '\n' else ' ')
                else:
                    out.append(c)
                i += 1
                continue
        if stack and isinstance(stack[-1], list) and (stack[-1][0] == 'EXPR'):
            if c == '{':
                stack[-1][1] += 1
                out.append('{')
                i += 1
                continue
            elif c == '}':
                stack[-1][1] -= 1
                if stack[-1][1] == 0:
                    stack.pop()
                    out.append(' ' if mask_strings else '}')
                else:
                    out.append('}')
                i += 1
                continue
        if c == '/' and nxt == '/':
            out.append('  ')
            i += 2
            while i < n and code[i] != '\n':
                out.append(' ')
                i += 1
            continue
        if c == '/' and nxt == '*':
            out.append('  ')
            i += 2
            while i < n:
                if code[i] == '*' and i + 1 < n and (code[i + 1] == '/'):
                    out.append('  ')
                    i += 2
                    break
                else:
                    out.append('\n' if code[i] == '\n' else ' ')
                    i += 1
            continue
        if c == "'":
            out.append(' ' if mask_strings else "'")
            i += 1
            while i < n:
                sc = code[i]
                if sc == '\\':
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(' ')
                            out.append('\n' if snxt == '\n' else ' ')
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(' ' if mask_strings else sc)
                        i += 1
                elif sc == "'":
                    out.append(' ' if mask_strings else "'")
                    i += 1
                    break
                elif sc == '\n':
                    out.append('\n')
                    i += 1
                    break
                else:
                    out.append(' ' if mask_strings else sc)
                    i += 1
            continue
        if c == '"':
            out.append(' ' if mask_strings else '"')
            i += 1
            while i < n:
                sc = code[i]
                if sc == '\\':
                    if i + 1 < n:
                        snxt = code[i + 1]
                        if mask_strings:
                            out.append(' ')
                            out.append('\n' if snxt == '\n' else ' ')
                        else:
                            out.append(sc)
                            out.append(snxt)
                        i += 2
                    else:
                        out.append(' ' if mask_strings else sc)
                        i += 1
                elif sc == '"':
                    out.append(' ' if mask_strings else '"')
                    i += 1
                    break
                elif sc == '\n':
                    out.append('\n')
                    i += 1
                    break
                else:
                    out.append(' ' if mask_strings else sc)
                    i += 1
            continue
        if c == '`':
            stack.append('TEMPLATE')
            out.append(' ' if mask_strings else '`')
            i += 1
            continue
        if c == '/' and _is_regex_start(code, i):
            out.append(' ' if mask_strings else '/')
            i += 1
            in_char_class = False
            while i < n:
                rc = code[i]
                if rc == '\\':
                    if i + 1 < n:
                        rnxt = code[i + 1]
                        if mask_strings:
                            out.append(' ')
                            out.append('\n' if rnxt == '\n' else ' ')
                        else:
                            out.append(rc)
                            out.append(rnxt)
                        i += 2
                    else:
                        out.append(' ' if mask_strings else rc)
                        i += 1
                elif rc == '[':
                    in_char_class = True
                    out.append(' ' if mask_strings else rc)
                    i += 1
                elif rc == ']' and in_char_class:
                    in_char_class = False
                    out.append(' ' if mask_strings else rc)
                    i += 1
                elif rc == '/' and (not in_char_class):
                    out.append(' ' if mask_strings else '/')
                    i += 1
                    while i < n and code[i].isalpha():
                        out.append(' ' if mask_strings else code[i])
                        i += 1
                    break
                elif rc == '\n':
                    out.append('\n')
                    i += 1
                    break
                else:
                    out.append(' ' if mask_strings else rc)
                    i += 1
            continue
        out.append(c)
        i += 1
    return ''.join(out)

def strip_ts_comments(code: str) -> str:
    """Masks only comments with whitespace, keeping string literals and regex intact."""
    return mask_ts_code(code, mask_strings=False)

def _find_matching_brace(code: str, start_idx: int) -> int:
    """Finds index of matching '}' for '{' at start_idx in masked code."""
    depth = 0
    for i in range(start_idx, len(code)):
        if code[i] == '{':
            depth += 1
        elif code[i] == '}':
            depth -= 1
            if depth == 0:
                return i
    return len(code) - 1

def _find_matching_paren(code: str, start_idx: int) -> int:
    """Finds index of matching ')' for '(' at start_idx in masked code."""
    depth = 0
    for i in range(start_idx, len(code)):
        if code[i] == '(':
            depth += 1
        elif code[i] == ')':
            depth -= 1
            if depth == 0:
                return i
    return -1

def _find_toplevel_relational_op(expr: str) -> Optional[Tuple[str, str, str]]:
    """Finds top-level relational operator in expression outside inner parens/brackets/braces.
    Returns (operator, lhs, rhs) or None.
    """
    e = expr.strip()
    while e.startswith('(') and e.endswith(')'):
        d = 0
        enclosed = True
        for idx in range(len(e) - 1):
            if e[idx] == '(':
                d += 1
            elif e[idx] == ')':
                d -= 1
                if d == 0:
                    enclosed = False
                    break
        if enclosed:
            e = e[1:-1].strip()
        else:
            break
    depth = 0
    i = 0
    n = len(e)
    while i < n:
        c = e[i]
        if c in '([{':
            depth += 1
        elif c in ')]}':
            depth -= 1
        elif depth == 0:
            for op in ('===', '!==', '==', '!=', '<=', '>=', '<', '>'):
                if e.startswith(op, i):
                    if op in ('<', '>'):
                        if i + 1 < n and e[i + 1] in ('<', '>', '='):
                            continue
                    left = e[:i].strip()
                    right = e[i + len(op):].strip()
                    return (op, left, right)
        i += 1
    return None

def _extract_signature(params_raw: str) -> str:
    """Extracts normalized argument names from raw parameter declaration."""
    clean = params_raw.strip()
    if not clean:
        return '()'
    parts: List[str] = []
    current: List[str] = []
    depth = 0
    for ch in clean:
        if ch in '([{<':
            depth += 1
            current.append(ch)
        elif ch in ')]}>':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append(''.join(current).strip())
    arg_names: List[str] = []
    for p in parts:
        m = re.match('^([A-Za-z_$][A-Za-z0-9_$]*)', p)
        if m:
            arg_names.append(m.group(1))
        elif p:
            arg_names.append(p.split(':')[0].strip())
    return f"({', '.join(arg_names)})"

def index_ts_ast_anchors(ts_code: str, file_path: str='module.ts') -> Dict[str, ASTAnchor]:
    """Indexes all TypeScript/JavaScript functions, arrow functions, and class methods
    with 64-bit BLAKE2b AST anchors.
    """
    clean_code = ts_code.lstrip('\ufeff')
    if not clean_code.strip():
        return AnchorDict()
    masked = mask_ts_code(clean_code, mask_strings=True)
    no_comments = strip_ts_comments(clean_code)
    anchors = AnchorDict()
    class_re = re.compile('(?:^|[;\\n])\\s*(?:export\\s+(?:default\\s+)?)?(?:abstract\\s+)?class\\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)(?:<[\\s\\S]*?>)?(?:\\s+extends\\s+[A-Za-z0-9_$.<>\\s]+)?(?:\\s+implements\\s+[A-Za-z0-9_$,.<>\\s]+)?\\s*\\{', re.MULTILINE)
    class_spans: List[Tuple[str, int, int]] = []
    for m in class_re.finditer(masked):
        c_name = m.group('name')
        open_brace = m.end() - 1
        close_brace = _find_matching_brace(masked, open_brace)
        class_spans.append((c_name, open_brace, close_brace))

    def get_enclosing_class(idx: int) -> Optional[str]:
        for c_name, ob, cb in class_spans:
            if ob < idx < cb:
                return c_name
        return None
    method_re = re.compile('(?:^|[;\\n}])\\s*(?:(?:public|private|protected|static|async|override|readonly)\\s+)*(?:\\*\\s*)?(?:(?:get|set)\\s+)?(?P<name>\\[[^\\]]+\\]|[A-Za-z_$][A-Za-z0-9_$]*)\\s*(?:<[\\s\\S]*?>)?\\s*\\((?P<params>[^)]*)\\)\\s*(?::\\s*[^{;]+)?\\s*\\{', re.MULTILINE)
    for c_name, ob, cb in class_spans:
        class_body = masked[ob + 1:cb]
        for m in method_re.finditer(class_body):
            abs_name_start = ob + 1 + m.start('name')
            abs_name_end = ob + 1 + m.end('name')
            m_name = clean_code[abs_name_start:abs_name_end].strip()
            if m_name in ('if', 'for', 'while', 'switch', 'catch'):
                continue
            abs_start = ob + 1 + m.start()
            open_b = ob + 1 + m.end() - 1
            close_b = _find_matching_brace(masked, open_b)
            lineno = clean_code.count('\n', 0, abs_start) + 1
            end_lineno = clean_code.count('\n', 0, close_b) + 1
            sig = _extract_signature(m.group('params'))
            body_text = no_comments[open_b:close_b + 1]
            norm_body = re.sub('\\s+', '', body_text)
            qualname = f'{c_name}.{m_name}'
            hash_tag = compute_node_hash(file_path=file_path, scope_path=c_name, node_type='MethodDefinition', identifier=m_name, signature=sig, normalized_body_dump=norm_body)
            anchor = ASTAnchor(file_path=file_path, scope_path=c_name, node_type='MethodDefinition', identifier=m_name, signature=sig, lineno=lineno, end_lineno=end_lineno, hash_tag=hash_tag)
            anchors[qualname] = anchor
    func_decl_re = re.compile('(?:^|[;\\n])\\s*(?:export\\s+(?:default\\s+)?)?(?P<async>async\\s+)?function(?:\\s*\\*\\s*|\\s+)(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\\s*(?:<[\\s\\S]*?>)?\\s*\\((?P<params>[^)]*)\\)\\s*(?::\\s*[^{;]+)?\\s*\\{', re.MULTILINE)
    for m in func_decl_re.finditer(masked):
        idx = m.start()
        if get_enclosing_class(idx) is not None:
            continue
        f_name = m.group('name')
        is_async = bool(m.group('async'))
        node_type = 'AsyncFunctionDeclaration' if is_async else 'FunctionDeclaration'
        open_b = m.end() - 1
        close_b = _find_matching_brace(masked, open_b)
        lineno = clean_code.count('\n', 0, idx) + 1
        end_lineno = clean_code.count('\n', 0, close_b) + 1
        sig = _extract_signature(m.group('params'))
        body_text = no_comments[open_b:close_b + 1]
        norm_body = re.sub('\\s+', '', body_text)
        hash_tag = compute_node_hash(file_path=file_path, scope_path='<module>', node_type=node_type, identifier=f_name, signature=sig, normalized_body_dump=norm_body)
        anchor = ASTAnchor(file_path=file_path, scope_path='<module>', node_type=node_type, identifier=f_name, signature=sig, lineno=lineno, end_lineno=end_lineno, hash_tag=hash_tag)
        anchors[f_name] = anchor
    arrow_assign_re = re.compile('(?:^|[;\\n])\\s*(?:export\\s+)?(?:const|let|var)\\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\\s*(?::\\s*[^=]+)?\\s*=\\s*(?:async\\s+)?(?:<[\\s\\S]*?>\\s*)?(?:\\((?P<params>[^)]*)\\)|(?P<single_param>[A-Za-z_$][A-Za-z0-9_$]*))\\s*(?::\\s*(?:(?!=>).)*)?\\s*=>\\s*', re.MULTILINE)
    for m in arrow_assign_re.finditer(masked):
        idx = m.start()
        if get_enclosing_class(idx) is not None:
            continue
        f_name = m.group('name')
        params_raw = m.group('params') or m.group('single_param') or ''
        sig = _extract_signature(params_raw)
        arrow_end = m.end()
        body_rest = masked[arrow_end:].lstrip()
        leading_spaces = len(masked[arrow_end:]) - len(body_rest)
        body_start_idx = arrow_end + leading_spaces
        if body_start_idx < len(masked) and masked[body_start_idx] == '{':
            close_b = _find_matching_brace(masked, body_start_idx)
            end_idx = close_b
        else:
            end_idx = body_start_idx
            while end_idx < len(masked) and masked[end_idx] not in (';', '\n'):
                end_idx += 1
        lineno = clean_code.count('\n', 0, idx) + 1
        end_lineno = clean_code.count('\n', 0, end_idx) + 1
        body_text = no_comments[arrow_end:end_idx + 1]
        norm_body = re.sub('\\s+', '', body_text)
        hash_tag = compute_node_hash(file_path=file_path, scope_path='<module>', node_type='ArrowFunction', identifier=f_name, signature=sig, normalized_body_dump=norm_body)
        anchor = ASTAnchor(file_path=file_path, scope_path='<module>', node_type='ArrowFunction', identifier=f_name, signature=sig, lineno=lineno, end_lineno=end_lineno, hash_tag=hash_tag)
        anchors[f_name] = anchor
    return anchors
BOUNDARY_MOCK_TARGETS = ('axios', 'fetch', 'http', 'https', 'node:http', 'node:https', 'fs', 'node:fs', 'path', 'node:path', 'child_process', 'node:child_process', 'redis', 'ioredis', 'pg', 'mysql', 'prisma', 'aws-sdk', '@aws-sdk', 'setTimeout', 'setInterval')

def _is_boundary_mock(target_str: str) -> bool:
    clean = target_str.strip('\'"`')
    return any((clean == b or clean.startswith(b + '/') or clean.startswith(b + '.') for b in BOUNDARY_MOCK_TARGETS))
STRONG_MATCHER_RE = re.compile('\\.(?:toBe|toEqual|toStrictEqual|toThrow|toThrowError|toMatchObject|toHaveLength|toContain|toMatch)\\s*\\(')
HOLLOW_MATCHER_RE = re.compile('\\.(?:toBeDefined\\s*\\(\\s*\\)|not\\s*\\.\\s*toBeNull\\s*\\(\\s*\\)|not\\s*\\.\\s*toBeUndefined\\s*\\(\\s*\\)|toBeTruthy\\s*\\(\\s*\\)|toBeFalsy\\s*\\(\\s*\\))')

def audit_ts_test_tampering(old_ts_code: str, new_ts_code: str, target_function_names: Optional[List[str]]=None, file_path: str='test_module.ts') -> TestTamperingReport:
    """Audits old vs new Jest/Vitest test code to catch test tampering."""
    target_set = set(target_function_names or [])
    clean_old = old_ts_code.lstrip('\ufeff')
    clean_new = new_ts_code.lstrip('\ufeff')
    old_no_comments = strip_ts_comments(clean_old)
    new_no_comments = strip_ts_comments(clean_new)
    violations: List[str] = []
    old_assert_matches = list(re.finditer('\\bexpect\\s*\\(', old_no_comments))
    new_assert_matches = list(re.finditer('\\bexpect\\s*\\(', new_no_comments))
    old_assert_count = len(old_assert_matches)
    new_assert_count = len(new_assert_matches)
    if old_assert_count > 0 and new_assert_count < old_assert_count:
        violations.append(f'Assertion count decreased from {old_assert_count} to {new_assert_count} (deleted assertions).')
    if new_assert_count == 0 and len(clean_new.strip()) > 0:
        violations.append('Test file contains zero expect assertions.')
    old_strong = len(STRONG_MATCHER_RE.findall(old_no_comments))
    new_strong = len(STRONG_MATCHER_RE.findall(new_no_comments))
    new_hollow = len(HOLLOW_MATCHER_RE.findall(new_no_comments))
    if old_strong > new_strong:
        violations.append(f'Strong value assertions weakened to hollow checks (strong asserts dropped from {old_strong} to {new_strong}).')
    if new_assert_count > 0 and new_strong == 0 and (new_hollow > 0):
        violations.append('New test is hollow (asserts only weak .toBeDefined()/.not.toBeNull() with zero strong value checks).')
    masked_new = mask_ts_code(new_no_comments, mask_strings=True)
    for m in re.finditer('\\bexpect\\s*\\(', masked_new):
        paren_start = m.end() - 1
        paren_end = _find_matching_paren(masked_new, paren_start)
        if paren_end == -1:
            continue
        actual = new_no_comments[paren_start + 1:paren_end].strip()
        after = new_no_comments[paren_end + 1:]
        m_matcher = re.match('^\\s*\\.\\s*(?P<matcher>toBeTruthy|toBeFalsy|toBe|toEqual|toStrictEqual)\\b', after)
        if not m_matcher:
            continue
        matcher = m_matcher.group('matcher')
        matcher_end_idx = paren_end + 1 + m_matcher.end()
        p_arg_start = masked_new.find('(', matcher_end_idx)
        expected = ''
        call_end = matcher_end_idx
        if p_arg_start != -1 and (not masked_new[matcher_end_idx:p_arg_start].strip()):
            p_arg_end = _find_matching_paren(masked_new, p_arg_start)
            if p_arg_end != -1:
                expected = new_no_comments[p_arg_start + 1:p_arg_end].strip()
                call_end = p_arg_end + 1
            else:
                call_end = p_arg_start + 1
        full_call = new_no_comments[m.start():call_end]
        is_taut = False
        if matcher in ('toBe', 'toEqual', 'toStrictEqual'):
            if actual == expected:
                is_taut = True
            elif actual in ('true', '1') and expected in ('true', '1'):
                is_taut = True
            elif actual in ('false', '0') and expected in ('false', '0'):
                is_taut = True
        rel = _find_toplevel_relational_op(actual)
        if rel:
            op, left, right = rel
            if left == right:
                if op in ('===', '==', '<=', '>=') and (expected in ('true', '1') or matcher == 'toBeTruthy'):
                    is_taut = True
                elif op in ('!==', '!=', '<', '>') and (expected in ('false', '0') or matcher == 'toBeFalsy'):
                    is_taut = True
        if is_taut and full_call not in old_no_comments:
            lineno = clean_new.count('\n', 0, m.start()) + 1
            violations.append(f'Line {lineno}: Tautological assertion in expect(...) ({actual} -> {matcher}({expected})).')
    skip_re = re.compile('\\b(?P<token>(?:it|test|describe)\\s*\\.\\s*(?:skip|todo|only)|(?:xit|xtest|xdescribe))\\s*\\(')
    for m in skip_re.finditer(new_no_comments):
        token = re.sub('\\s+', '', m.group('token'))
        if token not in re.sub('\\s+', '', old_no_comments):
            lineno = clean_new.count('\n', 0, m.start()) + 1
            violations.append(f'Line {lineno}: Test decorated with skip/todo ({token}).')
    mock_re = re.compile('\\b(?P<lib>vi|jest)\\s*\\.\\s*(?P<type>mock|spyOn|fn)\\s*\\(\\s*(?P<target>[^,);]*)')
    total_mocks = 0
    internal_mock_count = 0
    boundary_mock_count = 0
    mock_calls: List[Tuple[int, str, str, str]] = []
    for m in mock_re.finditer(new_no_comments):
        total_mocks += 1
        lineno = clean_new.count('\n', 0, m.start()) + 1
        lib = m.group('lib')
        m_type = m.group('type')
        target_str = m.group('target').strip()
        p_start = masked_new.find('(', m.start())
        p_end = _find_matching_paren(masked_new, p_start) if p_start != -1 else -1
        if p_end != -1:
            semi_idx = new_no_comments.find(';', p_end)
            newline_idx = new_no_comments.find('\n', p_end)
            if semi_idx != -1 and (newline_idx == -1 or semi_idx < newline_idx):
                snippet = new_no_comments[m.start():semi_idx + 1]
            else:
                snippet = new_no_comments[m.start():p_end + 1]
        else:
            newline_idx = new_no_comments.find('\n', m.start())
            snippet = new_no_comments[m.start():newline_idx if newline_idx != -1 else m.end() + 100]
        mock_calls.append((lineno, lib, m_type, snippet))
        if _is_boundary_mock(target_str):
            boundary_mock_count += 1
        else:
            internal_mock_count += 1
    for lineno, lib, m_type, snippet in mock_calls:
        for t_fn in target_set:
            if t_fn in snippet:
                violations.append(f"Line {lineno}: Test mocks out target function '{t_fn}' via {lib}.{m_type}.")
    total_asserts = max(new_assert_count, 1)
    mar = round(total_mocks / total_asserts, 4)
    weighted_mar = round((1.0 * internal_mock_count + 0.25 * boundary_mock_count) / total_asserts, 4)
    if mar < 0.1:
        risk_level = 'LOW'
    elif mar <= 0.25:
        risk_level = 'MODERATE'
    else:
        risk_level = 'HIGH_RISK'
    anchors = index_ts_ast_anchors(clean_new, file_path=file_path)
    passed = len(violations) == 0
    return TestTamperingReport(passed=passed, old_assert_count=old_assert_count, new_assert_count=new_assert_count, violations=violations, anchors=anchors, total_mocks=total_mocks, mar=mar, risk_level=risk_level, internal_mock_count=internal_mock_count, boundary_mock_count=boundary_mock_count, weighted_mar=weighted_mar)

def generate_ts_mutants(source_code: str='', target_function: Optional[str]=None, max_mutants: int=5, *, ts_code: Optional[str]=None) -> List[Tuple[str, int, str]]:
    """Synthesizes up to `max_mutants` distinct diff-scoped TypeScript/JS mutants.
    Returns list of (description, lineno, mutated_ts_code).
    """
    raw_code = ts_code if ts_code is not None else source_code
    clean_code = raw_code.lstrip('\ufeff')
    if not clean_code.strip():
        return None
    masked = mask_ts_code(clean_code, mask_strings=True)
    anchors = index_ts_ast_anchors(clean_code)
    start_line = 1
    end_line = clean_code.count('\n') + 1
    if target_function:
        if target_function in anchors:
            start_line = anchors[target_function].lineno
            end_line = anchors[target_function].end_lineno
        else:
            match = next((a for a in anchors.values() if a.identifier == target_function), None)
            if match:
                start_line = match.lineno
                end_line = match.end_lineno
    mutants: List[Tuple[str, int, str]] = []
    seen_mutations: Set[str] = set()
    patterns: List[Tuple[str, str, str]] = [('===', '!==', 'Strict equality inverted (=== to !==)'), ('!==', '===', 'Strict inequality inverted (!== to ===)'), ('(?<![!=])==(?!=)', '!=', 'Equality inverted (== to !=)'), ('(?<![!=])!=(?!=)', '==', 'Inequality inverted (!= to ==)'), ('<=', '<', 'Relational boundary adjusted (<= to <)'), ('>=', '>', 'Relational boundary adjusted (>= to >)'), ('&&', '||', 'Logical AND inverted to OR (&& to ||)'), ('\\|\\|', '&&', 'Logical OR inverted to AND (|| to &&)'), ('(?<!\\+)\\+(?!\\+|=)', '-', 'Arithmetic addition inverted to subtraction (+ to -)'), ('(?<!-)-(?!-|=)', '+', 'Arithmetic subtraction inverted to addition (- to +)'), ('\\btrue\\b', 'false', 'Boolean literal inverted (true to false)'), ('\\bfalse\\b', 'true', 'Boolean literal inverted (false to true)')]
    for pat, rep, desc in patterns:
        for m in re.finditer(pat, masked):
            idx = m.start()
            end_idx = m.end()
            lineno = clean_code.count('\n', 0, idx) + 1
            if not start_line <= lineno <= end_line:
                continue
            mutated = clean_code[:idx] + rep + clean_code[end_idx:]
            if mutated not in seen_mutations and mutated != clean_code:
                seen_mutations.add(mutated)
                mutants.append((f'Line {lineno}: {desc}', lineno, mutated))
                if len(mutants) >= max_mutants:
                    return mutants
    ret_re = re.compile('\\breturn\\s+([^;]+);')
    for m in ret_re.finditer(masked):
        idx = m.start()
        end_idx = m.end()
        lineno = clean_code.count('\n', 0, idx) + 1
        if not start_line <= lineno <= end_line:
            continue
        expr = clean_code[m.start(1):m.end(1)].strip()
        if expr == 'null':
            continue
        mutated = clean_code[:idx] + 'return null;' + clean_code[end_idx:]
        if mutated not in seen_mutations and mutated != clean_code:
            seen_mutations.add(mutated)
            mutants.append((f"Line {lineno}: Replace return expression with 'null'", lineno, mutated))
            if len(mutants) >= max_mutants:
                return mutants
    return mutants
`
