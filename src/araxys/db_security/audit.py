"""Query auditing for database security.

Provides a :class:`QueryEvent` dataclass and a :class:`QueryAuditor` that
emits :class:`AuditEntry` records via an ``on_audit`` callback, optionally
flagging slow queries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from araxys.db_security.query_validator import QueryValidationResult

import structlog

from araxys.core.types import AuditEntry, AuditEventType

logger = structlog.get_logger("araxys.db_security.audit")


@dataclass(frozen=True, slots=True)
class QueryEvent:
    """Immutable record of a single query execution.

    Attributes
    ----------
    query_text:
        The SQL query string.
    query_params:
        Optional bound parameters.
    connection_id:
        Optional identifier of the connection that executed the query.
    timestamp:
        When the event was created (default: UTC now).
    duration_ms:
        Optional execution duration in milliseconds.
    validation:
        Optional result from :class:`QueryValidator.validate`.
    """

    query_text: str
    query_params: dict[str, Any] | None = None
    connection_id: str | None = None
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(UTC),
    )
    duration_ms: float | None = None
    validation: QueryValidationResult | None = None


class QueryAuditor:
    """Audits database queries by emitting ``AuditEntry`` records.

    Parameters
    ----------
    enabled:
        When ``False``, :meth:`emit` is a no-op.
    slow_query_threshold_ms:
        Queries with ``duration_ms`` exceeding this threshold are marked
        with ``detail="slow_query"`` and logged at warning level.
    on_audit:
        Async callback receiving the :class:`AuditEntry`.  When ``None``,
        :meth:`emit` is a no-op.
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        slow_query_threshold_ms: int = 100,
        on_audit: Callable[[AuditEntry], Awaitable[None]] | None = None,
    ) -> None:
        self._enabled = enabled
        self._slow_query_threshold_ms = slow_query_threshold_ms
        self._on_audit = on_audit

    async def emit(self, event: QueryEvent) -> None:
        """Emit an audit entry for *event*.

        The entry is passed to the ``on_audit`` callback.  Slow queries
        (``duration_ms > slow_query_threshold_ms``) are flagged with
        ``detail="slow_query"`` and logged at warning level.
        """
        if not self._enabled or self._on_audit is None:
            return

        detail: str | None = None
        if (
            event.duration_ms is not None
            and event.duration_ms > self._slow_query_threshold_ms
        ):
            detail = "slow_query"
            logger.warning(
                "db_audit.slow_query",
                query=event.query_text,
                duration_ms=event.duration_ms,
                threshold=self._slow_query_threshold_ms,
            )

        metadata: dict[str, Any] = {
            "query_text": event.query_text,
            "query_params": event.query_params,
            "duration_ms": event.duration_ms,
            "connection_id": event.connection_id,
        }
        if event.validation is not None:
            metadata["validation"] = {
                "passed": event.validation.passed,
                "reason": event.validation.reason,
            }

        entry = AuditEntry(
            event_type=AuditEventType.QUERY_EXECUTED,
            detail=detail,
            metadata=metadata,
        )

        await self._on_audit(entry)
