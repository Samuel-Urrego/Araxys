"""Path pattern matching for per-endpoint rate limits.

Uses :func:`fnmatch.fnmatch` for glob-style wildcard matching
(e.g. ``/api/auth/*``).  No regex — simple and predictable.
"""

from __future__ import annotations

import fnmatch
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping


def match_path(path: str, pattern: str) -> bool:
    """Return ``True`` when *path* matches the glob *pattern*."""
    return fnmatch.fnmatch(path, pattern)


def find_best_match[T](
    path: str,
    patterns: Mapping[str, T],
) -> tuple[str | None, T | None]:
    """Find the most specific pattern that matches *path*.

    *Most specific* is defined as the longest pattern string — exact
    matches are always preferred over wildcards because they have more
    characters.

    Returns ``(pattern, value)`` or ``(None, None)`` when no pattern
    matches.
    """
    matches = [(p, v) for p, v in patterns.items() if fnmatch.fnmatch(path, p)]
    if not matches:
        return None, None
    matches.sort(key=lambda x: len(x[0]), reverse=True)
    return matches[0]
