"""Content-Security-Policy header builder.

Builds RFC-compliant CSP header strings from structured ``CSPDirectiveConfig``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from araxys.core.config import CSPDirectiveConfig

# Directives that appear as bare flags (no value).
_FLAG_DIRECTIVES = frozenset({
    "upgrade-insecure-requests",
    "block-all-mixed-content",
})

# Mapping of CSPDirectiveConfig attribute names to CSP header directive names.
_DIRECTIVE_MAP: dict[str, str] = {
    "default_src": "default-src",
    "script_src": "script-src",
    "style_src": "style-src",
    "img_src": "img-src",
    "font_src": "font-src",
    "connect_src": "connect-src",
    "media_src": "media-src",
    "object_src": "object-src",
    "frame_src": "frame-src",
    "base_uri": "base-uri",
    "form_action": "form-action",
    "report_uri": "report-uri",
}


def build_csp_header(config: CSPDirectiveConfig) -> str:
    """Build an RFC-compliant CSP header string from *config*.

    Parameters
    ----------
    config:
        Structured CSP directive configuration.

    Returns
    -------
    str
        The ``Content-Security-Policy`` header value, with directives joined
        by ``"; `` (semicolon-space).
    """
    directives: list[str] = []

    # Iterate through directive fields that are list[str]
    for attr, directive_name in _DIRECTIVE_MAP.items():
        values = getattr(config, attr, None)
        if values is None:
            continue
        if isinstance(values, list):
            if not values:
                continue
            directives.append(f"{directive_name} {' '.join(values)}")
        else:
            # str values (e.g. report_uri)
            directives.append(f"{directive_name} {values}")

    # Flag directives (bool fields)
    if config.upgrade_insecure_requests:
        directives.append("upgrade-insecure-requests")

    return "; ".join(directives)
