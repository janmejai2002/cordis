"""Zero-dependency Pytest compatibility shim for pure-stdlib Cordis execution.
Allows real-world repositories with `import pytest` to run tests via standard library unittest.
"""
from __future__ import annotations

_cordis_shim = True

import sys
import unittest
from contextlib import contextmanager
from typing import Any, Callable


class _Mark:
    def parametrize(self, argnames: Any, argvalues: Any, **kwargs: Any) -> Callable:
        def decorator(fn: Callable) -> Callable:
            fn._cordis_parametrized = (argnames, argvalues)
            return fn
        return decorator

    def skip(self, reason: str = "") -> Callable:
        def decorator(fn: Callable) -> Callable:
            return unittest.skip(reason)(fn)
        return decorator

    def xfail(self, *args: Any, **kwargs: Any) -> Callable:
        def decorator(fn: Callable) -> Callable:
            return fn
        return decorator

    def __getattr__(self, name: str) -> Callable:
        def decorator(fn: Callable) -> Callable:
            return fn
        return decorator


mark = _Mark()


@contextmanager
def raises(expected_exception: Any, match: str | None = None):
    try:
        yield
    except expected_exception as exc:
        if match:
            import re
            assert re.search(match, str(exc)), f"Pattern {match!r} not in {str(exc)!r}"
        return
    except Exception as e:
        raise AssertionError(f"Expected {expected_exception.__name__}, got {type(e).__name__}: {e}")
    raise AssertionError(f"DID NOT RAISE {expected_exception.__name__}")


@contextmanager
def warns(expected_warning: Any = None, match: str | None = None):
    yield


@contextmanager
def deprecated_call():
    yield


def approx(val: Any, rel: float | None = None, abs: float | None = None) -> Any:
    return val


def skip(msg: str = "") -> None:
    raise unittest.SkipTest(msg)


def fail(msg: str = "") -> None:
    raise AssertionError(msg)


def fixture(*args: Any, **kwargs: Any) -> Callable:
    def decorator(fn: Callable) -> Callable:
        return fn
    if args and callable(args[0]):
        return args[0]
    return decorator


class MonkeyPatch:
    def setattr(self, target: Any, name: str, value: Any, raising: bool = True) -> None:
        setattr(target, name, value)

    def setenv(self, name: str, value: str) -> None:
        import os
        os.environ[name] = value

    def delenv(self, name: str, raising: bool = True) -> None:
        import os
        os.environ.pop(name, None)
