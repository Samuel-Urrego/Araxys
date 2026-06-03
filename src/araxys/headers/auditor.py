"""Security headers auditor — checks response headers against OWASP recommendations.

Pure functions for auditing HTTP response headers. Each function checks
a specific header and returns an :class:`AuditFinding` dataclass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class AuditFinding:
    """Result of auditing a single security header.

    Attributes
    ----------
    header_name:
        The HTTP header being audited (e.g. ``Strict-Transport-Security``).
    status:
        Audit result: ``pass``, ``warn``, or ``fail``.
    found_value:
        The actual header value found in the response, or ``None`` if missing.
    recommended_value:
        The recommended minimum value for this header.
    severity:
        How critical the finding is: ``info``, ``low``, ``medium``, ``high``.
    detail:
        Optional human-readable explanation of the finding.
    """

    header_name: str
    status: str  # "pass" | "warn" | "fail"
    found_value: str | None = None
    recommended_value: str | None = None
    severity: str = "info"  # "info" | "low" | "medium" | "high"
    detail: str = ""


def audit_headers(response_headers: dict[str, str]) -> list[AuditFinding]:
    """Audit HTTP response headers against OWASP recommendations.

    Checks the following headers:
    - ``Strict-Transport-Security`` (HSTS)
    - ``X-Content-Type-Options``
    - ``X-Frame-Options``
    - ``Content-Security-Policy``
    - ``X-XSS-Protection``
    - ``Referrer-Policy``
    - ``Cross-Origin-Opener-Policy`` (COOP)
    - ``Cross-Origin-Resource-Policy`` (CORP)
    - ``Permissions-Policy``

    Parameters
    ----------
    response_headers:
        Dict of header name → header value from the response.

    Returns
    -------
    list[AuditFinding]
        Findings for each audited header. An empty list means all checks passed
        (all findings have status ``pass``).
    """
    findings: list[AuditFinding] = []

    findings.append(_audit_hsts(response_headers))
    findings.append(_audit_content_type_options(response_headers))
    findings.append(_audit_frame_options(response_headers))
    findings.append(_audit_csp(response_headers))
    findings.append(_audit_xss_protection(response_headers))
    findings.append(_audit_referrer_policy(response_headers))
    findings.append(_audit_coop(response_headers))
    findings.append(_audit_corp(response_headers))
    findings.append(_audit_permissions_policy(response_headers))

    return findings


def _audit_hsts(headers: dict[str, str]) -> AuditFinding:
    value = headers.get("Strict-Transport-Security")
    if value is None:
        return AuditFinding(
            header_name="Strict-Transport-Security",
            status="fail",
            severity="high",
            detail="HSTS header is missing. This allows downgrade attacks.",
            recommended_value="max-age=31536000; includeSubDomains",
        )
    has_max_age = "max-age=" in value.lower()
    if not has_max_age:
        return AuditFinding(
            header_name="Strict-Transport-Security",
            status="fail",
            found_value=value,
            severity="high",
            detail="HSTS header is missing max-age directive.",
            recommended_value="max-age=31536000; includeSubDomains",
        )
    # Check max-age value
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    if match:
        max_age = int(match.group(1))
        if max_age < 31536000:
            return AuditFinding(
                header_name="Strict-Transport-Security",
                status="warn",
                found_value=value,
                severity="medium",
                detail=(
                    f"HSTS max-age is {max_age}s (less than 1 year). "
                    "Consider increasing to 31536000."
                ),
                recommended_value="max-age=31536000; includeSubDomains",
            )
        if "includesubdomains" not in value.lower():
            return AuditFinding(
                header_name="Strict-Transport-Security",
                status="warn",
                found_value=value,
                severity="low",
                detail="HSTS does not include subdomains.",
                recommended_value="max-age=31536000; includeSubDomains",
            )
    return AuditFinding(
        header_name="Strict-Transport-Security",
        status="pass",
        found_value=value,
    )


def _audit_content_type_options(headers: dict[str, str]) -> AuditFinding:
    value = headers.get("X-Content-Type-Options")
    if value is None:
        return AuditFinding(
            header_name="X-Content-Type-Options",
            status="fail",
            severity="medium",
            detail="Missing X-Content-Type-Options header. This allows MIME sniffing.",
            recommended_value="nosniff",
        )
    if value.lower() != "nosniff":
        return AuditFinding(
            header_name="X-Content-Type-Options",
            status="fail",
            found_value=value,
            severity="medium",
            detail=f"Expected 'nosniff', got '{value}'.",
            recommended_value="nosniff",
        )
    return AuditFinding(
        header_name="X-Content-Type-Options",
        status="pass",
        found_value=value,
    )


def _audit_frame_options(headers: dict[str, str]) -> AuditFinding:
    value = headers.get("X-Frame-Options")
    csp = headers.get("Content-Security-Policy", "")
    if value is None and "frame-ancestors" not in csp.lower():
        return AuditFinding(
            header_name="X-Frame-Options",
            status="warn",
            severity="medium",
            detail=(
                "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                "This allows clickjacking."
            ),
            recommended_value="DENY or CSP frame-ancestors 'none'",
        )
    if value is not None and value not in ("DENY", "SAMEORIGIN"):
        return AuditFinding(
            header_name="X-Frame-Options",
            status="warn",
            found_value=value,
            severity="low",
            detail=f"X-Frame-Options is '{value}'. Consider 'DENY' or CSP.",
            recommended_value="DENY",
        )
    return AuditFinding(
        header_name="X-Frame-Options",
        status="pass",
        found_value=value or "(via CSP frame-ancestors)",
    )


def _audit_csp(headers: dict[str, str]) -> AuditFinding:
    value = headers.get("Content-Security-Policy")
    if value is None:
        return AuditFinding(
            header_name="Content-Security-Policy",
            status="warn",
            severity="medium",
            detail="CSP header is not set. This weakens XSS protection.",
            recommended_value="default-src 'self'",
        )
    if "unsafe-inline" in value.lower() and "nonce-" not in value.lower():
        return AuditFinding(
            header_name="Content-Security-Policy",
            status="warn",
            found_value=value,
            severity="low",
            detail="CSP has 'unsafe-inline' without nonce. Consider using nonces.",
        )
    if "unsafe-eval" in value.lower():
        return AuditFinding(
            header_name="Content-Security-Policy",
            status="warn",
            found_value=value,
            severity="medium",
            detail="CSP has 'unsafe-eval'. This enables code injection.",
        )
    return AuditFinding(
        header_name="Content-Security-Policy",
        status="pass",
        found_value=value,
    )


def _audit_xss_protection(headers: dict[str, str]) -> AuditFinding:
    value = headers.get("X-XSS-Protection")
    if value is None:
        # Modern browsers ignore this; CSP is the real protection
        return AuditFinding(
            header_name="X-XSS-Protection",
            status="info",
            severity="info",
            detail="X-XSS-Protection header is not set. CSP is the modern replacement.",
        )
    if value.strip() == "0":
        return AuditFinding(
            header_name="X-XSS-Protection",
            status="pass",
            found_value=value,
            detail="Explicitly disabled — modern practice (rely on CSP).",
        )
    return AuditFinding(
        header_name="X-XSS-Protection",
        status="warn",
        found_value=value,
        severity="low",
        detail="X-XSS-Protection is enabled. Consider disabling (0) and relying on CSP.",  # noqa: E501  # noqa: E501
        recommended_value="0",
    )


def _audit_referrer_policy(headers: dict[str, str]) -> AuditFinding:
    value = headers.get("Referrer-Policy")
    if value is None:
        return AuditFinding(
            header_name="Referrer-Policy",
            status="warn",
            severity="low",
            detail="Referrer-Policy header is missing. This may leak URL info.",
            recommended_value="strict-origin-when-cross-origin",
        )
    if "unsafe-url" in value.lower() or value.lower() == "no-referrer-when-downgrade":
        return AuditFinding(
            header_name="Referrer-Policy",
            status="warn",
            found_value=value,
            severity="low",
            detail=(
                f"Referrer-Policy is '{value}'. "
                "Consider stricter policy."
            ),
            recommended_value="strict-origin-when-cross-origin",
        )
    return AuditFinding(
        header_name="Referrer-Policy",
        status="pass",
        found_value=value,
    )


def _audit_coop(headers: dict[str, str]) -> AuditFinding:
    value = headers.get("Cross-Origin-Opener-Policy")
    if value is None:
        return AuditFinding(
            header_name="Cross-Origin-Opener-Policy",
            status="warn",
            severity="low",
            detail="COOP header is missing. This allows cross-origin attacks.",
            recommended_value="same-origin",
        )
    if value.lower() == "unsafe-none":
        return AuditFinding(
            header_name="Cross-Origin-Opener-Policy",
            status="warn",
            found_value=value,
            severity="low",
            detail="COOP is set to 'unsafe-none' — disables process isolation.",
            recommended_value="same-origin",
        )
    return AuditFinding(
        header_name="Cross-Origin-Opener-Policy",
        status="pass",
        found_value=value,
    )


def _audit_corp(headers: dict[str, str]) -> AuditFinding:
    value = headers.get("Cross-Origin-Resource-Policy")
    if value is None:
        return AuditFinding(
            header_name="Cross-Origin-Resource-Policy",
            status="warn",
            severity="low",
            detail="CORP header is missing. This allows cross-origin resource loading.",
            recommended_value="same-origin",
        )
    if value.lower() == "cross-origin":
        return AuditFinding(
            header_name="Cross-Origin-Resource-Policy",
            status="warn",
            found_value=value,
            severity="low",
            detail="CORP is 'cross-origin' — very permissive.",
            recommended_value="same-origin",
        )
    return AuditFinding(
        header_name="Cross-Origin-Resource-Policy",
        status="pass",
        found_value=value,
    )


def _audit_permissions_policy(headers: dict[str, str]) -> AuditFinding:
    value = headers.get("Permissions-Policy")
    if value is None:
        return AuditFinding(
            header_name="Permissions-Policy",
            status="info",
            severity="info",
            detail="Permissions-Policy header is not set. Consider adding it.",
            recommended_value="camera=(), microphone=(), geolocation=()",
        )
    # Check for permissive directives
    if "*" in value:
        return AuditFinding(
            header_name="Permissions-Policy",
            status="warn",
            found_value=value,
            severity="low",
            detail="Permissions-Policy uses wildcard '*'. Consider restricting.",
        )
    return AuditFinding(
        header_name="Permissions-Policy",
        status="pass",
        found_value=value,
    )
