"""SQL parameterization validation for database security.

Provides ``QueryValidationResult`` (a frozen dataclass) and
``QueryValidator``, which uses sqlparse to detect whether a SQL
template uses parameterized placeholders or inline literals.

Modes
-----
- ``warn`` (default): log a warning and return ``passed=True`` with a
  descriptive ``reason``.
- ``block``: raise :exc:`araxys.core.exceptions.ValidationError`.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import sqlparse

if TYPE_CHECKING:
    from araxys.core.config import QueryValidationConfig

logger = logging.getLogger("araxys.db_security.query_validator")

# Regex matching common SQL placeholder styles:
#   %s       — psycopg2 / most Python DB-APIs
#   ?        — sqlite3 / ODBC
#   :name    — named placeholders (psycopg2, SQLAlchemy)
__all__: list[str] = [
    "QueryValidationResult",
    "QueryValidator",
]

_PLACEHOLDER_RE = re.compile(r"%s|\?|:\w+|\$\d+")


@dataclass(frozen=True)
class QueryValidationResult:
    """Result of a query validation.

    Attributes
    ----------
    passed:
        ``True`` if the query is acceptable under the configured mode.
    reason:
        Human-readable explanation when a query triggers a warn/block
        action, or ``None`` when the query is fully parameterized.
    """

    passed: bool
    reason: str | None


def _has_inline_literals(sql: str) -> bool:
    """Return ``True`` if *sql* contains inline string or number literals.

    Uses ``sqlparse`` to parse the statement and walks the token tree
    looking for ``Literal.String.Single``, ``Literal.Number``, and
    similar token types that indicate values embedded directly in SQL.
    """
    parsed = sqlparse.parse(sql)
    if not parsed:
        return False
    for statement in parsed:
        for token in statement.flatten():  # type: ignore[no-untyped-call]
            if token.ttype is None:
                continue
            ttype_str = str(token.ttype)
            if ttype_str.startswith("Token.Literal"):
                return True
    return False


class QueryValidator:
    """Validates whether SQL templates use parameterized placeholders.

    Parameters
    ----------
    config:
        ``QueryValidationConfig`` controlling the enforcement mode
        (``warn`` or ``block``).
    """

    def __init__(self, config: QueryValidationConfig) -> None:
        self._config = config

    def validate(
        self,
        template: str,
        params: tuple[object, ...] | None = None,
    ) -> QueryValidationResult:
        """Validate *template* for safe vs. interpolated SQL.

        Parameters
        ----------
        template:
            The SQL query string (may contain placeholders like ``%s``).
        params:
            Bound parameters, if any.

        Returns
        -------
        QueryValidationResult
            ``passed=True`` with no ``reason`` for fully parameterized
            queries.  In ``warn`` mode, inline literals produce
            ``passed=True`` with a descriptive ``reason``.  In ``block``
            mode, inline literals cause a :exc:`ValidationError`.

        Raises
        ------
        ValidationError
            In ``block`` mode when inline literals are detected.
        """
        has_placeholders = bool(_PLACEHOLDER_RE.search(template))
        has_params = params is not None and len(params) > 0

        if has_placeholders and has_params:
            # Properly parameterized — the most common and safe case.
            return QueryValidationResult(passed=True, reason=None)

        # No placeholders (or no params supplied) — check for inline
        # literals that suggest values were embedded directly.
        if _has_inline_literals(template):
            reason = (
                "Query contains inline literals but has no parameterized "
                "placeholders — possible SQL injection risk"
            )
            if self._config.mode == "block":
                from araxys.core.exceptions import ValidationError

                raise ValidationError(reason)
            # warn mode
            logger.warning(
                "query_validator.interpolated_query",
                extra={"template": template},
            )
            return QueryValidationResult(passed=True, reason=reason)

        return QueryValidationResult(passed=True, reason=None)
