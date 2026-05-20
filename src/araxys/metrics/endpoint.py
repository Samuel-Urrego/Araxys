"""Prometheus /metrics endpoint as a Starlette request handler.

Provides a request handler that serves Prometheus metrics in plain-text
format, and a helper to mount it on a FastAPI app.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from starlette.responses import PlainTextResponse

if TYPE_CHECKING:
    from fastapi import FastAPI
    from starlette.requests import Request
    from starlette.responses import Response

    from araxys.core.config import MetricsConfig
    from araxys.metrics.collector import MetricsRegistry


async def _not_found_handler(request: Request) -> Response:
    """Request handler that returns 404."""
    return PlainTextResponse(status_code=404, content="Not Found")


async def _unauthorized_handler(request: Request) -> Response:
    """Request handler that returns 401."""
    return PlainTextResponse(status_code=401, content="Unauthorized")


def _build_handler(registry: MetricsRegistry, config: MetricsConfig) -> Any:
    """Build a request handler that serves /metrics.

    Returns a 404 handler if metrics are disabled or unavailable.
    When an ``auth_token`` is configured, the handler requires a
    matching query parameter (``?token=...``) or ``Authorization``
    header.
    """
    if not registry._enabled:
        return _not_found_handler

    from araxys.metrics.collector import _prometheus as _pc  # noqa: PLC0415

    if _pc is None:
        return _not_found_handler

    auth_token = config.auth_token

    async def _metrics_handler(request: Request) -> Response:
        """Return Prometheus metrics (auth-protected when configured)."""
        if auth_token:
            token = request.query_params.get("token")
            if not token:
                auth = request.headers.get("authorization", "")
                if auth.startswith("Bearer "):
                    token = auth.removeprefix("Bearer ")
            if not token or token != auth_token:
                return PlainTextResponse(
                    status_code=401,
                    content="Unauthorized\n",
                    headers={"content-type": "text/plain"},
                )

        data = _pc.generate_latest()
        return PlainTextResponse(
            content=data.decode("utf-8"),
            status_code=200,
            headers={"content-type": "text/plain; version=0.0.4; charset=utf-8"},
        )

    return _metrics_handler


def metrics_endpoint(registry: MetricsRegistry, config: MetricsConfig) -> Any:
    """Return a Starlette request handler that serves /metrics.

    Parameters
    ----------
    registry:
        The ``MetricsRegistry`` instance with counters and histograms.
    config:
        Metrics configuration (used for auth_token).

    Returns
    -------
    A request handler (``async (Request) -> Response``) that returns
    Prometheus plain-text format on GET, or 404 when disabled.
    """
    return _build_handler(registry, config)


def mount_metrics(
    app: FastAPI,
    config: MetricsConfig,
    registry: MetricsRegistry,
) -> None:
    """Mount the /metrics endpoint on a FastAPI application.

    The endpoint is only mounted when ``config.enabled`` is ``True``.
    It is registered at ``config.path`` (default ``/metrics``).

    Parameters
    ----------
    app:
        The FastAPI application.
    config:
        Metrics configuration.
    registry:
        The ``MetricsRegistry`` instance.
    """
    if not config.enabled:
        return
    handler = metrics_endpoint(registry, config)
    app.add_route(config.path, route=handler, methods=["GET"])
