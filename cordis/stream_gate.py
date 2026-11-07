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
