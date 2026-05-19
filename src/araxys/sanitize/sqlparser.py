"""sqlparse-based SQL injection analyzer.

Provides token-level detection of SQL injection patterns,
eliminating regex false positives on text that merely *contains*
SQL keywords but isn't actual SQL.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:  # noqa: I001
    import sqlparse
    from sqlparse.tokens import (
        Comment as CommentToken,
        Keyword,
        Literal,
        Name,
        Operator,
        Whitespace,
        Wildcard,
    )

    _HAS_SQLPARSE = True
except ImportError:  # pragma: no cover
    _HAS_SQLPARSE = False


@dataclass(frozen=True)
class SqlInjectionFinding:
    """A single SQL injection detection result.

    Attributes:
        type: Machine-readable category (e.g. ``"stacked_query"``).
        description: Human-readable explanation of the finding.
        position: Character offset in the original input where the
            pattern was detected.
    """

    type: str
    description: str
    position: int = 0


# ── time-based keywords ──────────────────────────────────────────────────
# These are recognised as Name tokens by sqlparse — not Keyword.
_TIME_KEYWORDS: frozenset[str] = frozenset({
    "WAITFOR",
    "BENCHMARK",
    "SLEEP",
})


class SqlInjectionAnalyzer:
    """Analyze a string for SQL injection patterns using sqlparse tokenization.

    Usage::

        from araxys.sanitize.sqlparser import SqlInjectionAnalyzer

        analyzer = SqlInjectionAnalyzer()
        findings = analyzer.analyze("SELECT * FROM users; DROP TABLE users;")
    """

    def analyze(self, text: str) -> list[SqlInjectionFinding]:
        """Tokenise *text* and run all detection methods.

        Returns a (possibly empty) list of findings sorted by detection order.
        """
        if not _HAS_SQLPARSE:
            raise ImportError(
                "sqlparse is required for SqlInjectionAnalyzer. "
                "Install it via ``pip install araxys[sqlparser]``."
            )

        findings: list[SqlInjectionFinding] = []

        parsed: Any = sqlparse.parse(text)
        if not parsed:
            return findings

        self._detect_stacked_queries(parsed, text, findings)

        for stmt in parsed:
            flat: list[Any] = list(stmt.flatten())
            self._detect_union_select(flat, findings)
            self._detect_time_based(flat, findings)
            self._detect_comments(flat, findings)
            self._detect_tautologies(flat, findings)

        return findings

    # ── individual detection methods ──────────────────────────────────────

    @staticmethod
    def _detect_stacked_queries(
        parsed: Any,
        text: str,
        findings: list[SqlInjectionFinding],
    ) -> None:
        """Multiple SQL statements separated by ``;``."""
        if len(parsed) > 1:
            pos = text.find(";")
            findings.append(
                SqlInjectionFinding(
                    type="stacked_query",
                    description=(
                        f"Multiple SQL statements detected "
                        f"({len(parsed)} statements)"
                    ),
                    position=pos if pos >= 0 else 0,
                )
            )

    @staticmethod
    def _detect_union_select(
        tokens: list[Any],
        findings: list[SqlInjectionFinding],
    ) -> None:
        """UNION followed by SELECT — only flag when in a real SQL context.

        To distinguish real SQL from plain text that merely *mentions*
        UNION SELECT, we require SQL-structural tokens (``*``, ``FROM``,
        a number literal, or a string literal) after the SELECT keyword.
        """
        union_idx: int | None = None
        for idx, token in enumerate(tokens):
            if token.ttype is Keyword and token.value.upper() == "UNION":
                union_idx = idx
                break

        if union_idx is None:
            return

        select_idx: int | None = None
        for j in range(union_idx + 1, min(union_idx + 8, len(tokens))):
            t = tokens[j]
            if t.ttype in Keyword.DML and t.value.upper() == "SELECT":
                select_idx = j
                break

        if select_idx is None:
            return

        for k in range(select_idx + 1, min(select_idx + 8, len(tokens))):
            tk = tokens[k]
            if tk.ttype is Whitespace:
                continue
            if tk.ttype in (
                Wildcard,
                Literal.Number.Integer,
                Literal.String.Single,
            ):
                findings.append(
                    SqlInjectionFinding(
                        type="union_select",
                        description="UNION SELECT injection detected",
                        position=0,
                    )
                )
                return
            if tk.ttype is Keyword and tk.value.upper() == "FROM":
                findings.append(
                    SqlInjectionFinding(
                        type="union_select",
                        description="UNION SELECT injection detected",
                        position=0,
                    )
                )
                return

    @staticmethod
    def _detect_tautologies(
        tokens: list[Any],
        findings: list[SqlInjectionFinding],
    ) -> None:
        """Always-true comparisons such as ``1=1`` or ``'a'='a'``.

        Looks for ``<literal> = <literal>`` where both sides have the same
        token type and the same value.
        """
        for idx in range(len(tokens) - 2):
            left = tokens[idx]
            op = tokens[idx + 1]
            right = tokens[idx + 2]

            if op.ttype is Whitespace:
                if idx + 3 < len(tokens):
                    op = tokens[idx + 2]
                    right = tokens[idx + 3]
                else:
                    continue

            if op.ttype is not Operator.Comparison:
                continue

            if (
                left.ttype is Literal.Number.Integer
                and right.ttype is Literal.Number.Integer
                and left.value == right.value
            ):
                findings.append(
                    SqlInjectionFinding(
                        type="tautology",
                        description=(
                            "Boolean tautology detected "
                            "(always-true comparison)"
                        ),
                        position=0,
                    )
                )
                return

            if (
                left.ttype is Literal.String.Single
                and right.ttype is Literal.String.Single
                and left.value == right.value
            ):
                findings.append(
                    SqlInjectionFinding(
                        type="tautology",
                        description=(
                            "Boolean tautology detected "
                            "(always-true comparison)"
                        ),
                        position=0,
                    )
                )
                return

    @staticmethod
    def _detect_time_based(
        tokens: list[Any],
        findings: list[SqlInjectionFinding],
    ) -> None:
        """Time-based injection keywords: WAITFOR, BENCHMARK, SLEEP."""
        for token in tokens:
            if (
                token.ttype is Name
                and token.value.upper() in _TIME_KEYWORDS
            ):
                findings.append(
                    SqlInjectionFinding(
                        type="time_based",
                        description=(
                            f"Time-based injection detected ({token.value})"
                        ),
                        position=0,
                    )
                )
                return

    @staticmethod
    def _detect_comments(
        tokens: list[Any],
        findings: list[SqlInjectionFinding],
    ) -> None:
        """SQL comment syntax: ``--``, ``/* */``, ``#``."""
        for token in tokens:
            if token.ttype in CommentToken:
                findings.append(
                    SqlInjectionFinding(
                        type="comment_injection",
                        description="SQL comment injection detected",
                        position=0,
                    )
                )
                return
