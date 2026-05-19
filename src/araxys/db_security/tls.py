"""TLS context factory for database connections.

Provides ``build_ssl_context()`` to build an ``ssl.SSLContext`` from a
``TLSConfig`` model, with CA certificate loading and minimum TLS version
enforcement.
"""

from __future__ import annotations

import os
import ssl
from typing import TYPE_CHECKING

from araxys.core.exceptions import TLSConfigurationError

if TYPE_CHECKING:
    from araxys.core.config import TLSConfig

_TLS_VERSION_MAP: dict[str, ssl.TLSVersion] = {
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def build_ssl_context(config: TLSConfig) -> ssl.SSLContext | None:
    """Build an ``ssl.SSLContext`` from *config*.

    Returns ``None`` when *config* has ``enabled=False``.

    Parameters
    ----------
    config:
        TLS configuration from database security settings.

    Returns
    -------
    An :class:`ssl.SSLContext` configured for TLS client connections, or
    ``None`` if TLS is disabled.

    Raises
    ------
    TLSConfigurationError:
        - If *config* specifies a ``ca_cert_path`` that does not exist.
        - If the system's OpenSSL does not support the requested minimum
          TLS version.
    """
    if not config.enabled:
        return None

    min_version = _TLS_VERSION_MAP.get(config.min_tls_version)
    if min_version is None:
        raise TLSConfigurationError(
            f"Unsupported TLS version: {config.min_tls_version}",
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = min_version

    if config.ca_cert_path:
        if not os.path.isfile(config.ca_cert_path):
            raise TLSConfigurationError(
                f"CA cert file not found: {config.ca_cert_path}",
            )
        context.load_verify_locations(cafile=config.ca_cert_path)

    # Verify that the version we set was actually applied by the system.
    if context.minimum_version != min_version:
        raise TLSConfigurationError(
            f"System does not support {config.min_tls_version}",
        )

    return context
