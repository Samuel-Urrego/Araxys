"""SQL injection detection patterns.

Conservative pattern set designed to minimize false positives while
catching the most common attack vectors.
"""


from __future__ import annotations

import re

# Compiled patterns for SQL injection detection
# Each tuple: (pattern, description)
SQLI_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"(\b(UNION\s+(ALL\s+)?SELECT)\b)",
            re.IGNORECASE,
        ),
        "UNION SELECT injection",
    ),
    (
        re.compile(
            r"(\b(SELECT\s+.+\s+FROM\s+\w+)\b)",
            re.IGNORECASE,
        ),
        "SELECT FROM statement",
    ),
    (
        re.compile(
            r"(\b(INSERT\s+INTO\s+\w+)\b)",
            re.IGNORECASE,
        ),
        "INSERT INTO statement",
    ),
    (
        re.compile(
            r"(\b(UPDATE\s+\w+\s+SET)\b)",
            re.IGNORECASE,
        ),
        "UPDATE SET statement",
    ),
    (
        re.compile(
            r"(\b(DELETE\s+FROM\s+\w+)\b)",
            re.IGNORECASE,
        ),
        "DELETE FROM statement",
    ),
    (
        re.compile(
            r"(\b(DROP\s+(TABLE|DATABASE|INDEX)\s+\w+)\b)",
            re.IGNORECASE,
        ),
        "DROP statement",
    ),
    (
        re.compile(
            r"(\b(ALTER\s+TABLE\s+\w+)\b)",
            re.IGNORECASE,
        ),
        "ALTER TABLE statement",
    ),
    (
        re.compile(
            r"(\b(EXEC(UTE)?)\s*\()",
            re.IGNORECASE,
        ),
        "EXECUTE statement",
    ),
    (
        re.compile(
            r"(;\s*(DROP|DELETE|INSERT|UPDATE|ALTER|EXEC))",
            re.IGNORECASE,
        ),
        "Chained SQL statement",
    ),
    (
        re.compile(
            r"('?\s*(OR|AND)\s+\d+\s*=\s*\d+)",
            re.IGNORECASE,
        ),
        "Boolean-based blind injection",
    ),
    (
        re.compile(
            r"('?\s*(OR|AND)\s+'[^']*'\s*=\s*'[^']*')",
            re.IGNORECASE,
        ),
        "String-based blind injection",
    ),
    (
        re.compile(
            r"(--\s|/\*|\*/|#\s)",
        ),
        "SQL comment injection",
    ),
    (
        re.compile(
            r"(\bxp_\w+\b)",
            re.IGNORECASE,
        ),
        "SQL Server extended procedure",
    ),
    (
        re.compile(
            r"(\bWAITFOR\s+DELAY\b)",
            re.IGNORECASE,
        ),
        "Time-based blind injection",
    ),
    (
        re.compile(
            r"(\bBENCHMARK\s*\()",
            re.IGNORECASE,
        ),
        "MySQL time-based injection",
    ),
    (
        re.compile(
            r"(\bSLEEP\s*\(\d+\))",
            re.IGNORECASE,
        ),
        "Sleep-based injection",
    ),
]


# XSS: tags and attributes that are ALWAYS dangerous
XSS_DANGEROUS_TAGS = frozenset(
    {
        "script",
        "iframe",
        "object",
        "embed",
        "form",
        "input",
        "textarea",
        "button",
        "applet",
        "base",
        "link",
        "meta",
        "style",
    }
)

XSS_DANGEROUS_ATTRIBUTES = frozenset(
    {
        "onload",
        "onerror",
        "onclick",
        "onmouseover",
        "onfocus",
        "onblur",
        "onsubmit",
        "onkeydown",
        "onkeyup",
        "onkeypress",
        "onchange",
        "oninput",
        "onmousedown",
        "onmouseup",
        "ondblclick",
        "oncontextmenu",
        "onwheel",
        "onscroll",
        "ontouchstart",
        "ontouchend",
        "ontouchmove",
        "onanimationstart",
        "onanimationend",
        "ontransitionend",
    }
)

# Patterns for detecting XSS in string values (beyond HTML tags)
XSS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"<script[\s>]", re.IGNORECASE),
        "Script tag",
    ),
    (
        re.compile(r"javascript\s*:", re.IGNORECASE),
        "JavaScript URI",
    ),
    (
        re.compile(r"vbscript\s*:", re.IGNORECASE),
        "VBScript URI",
    ),
    (
        re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
        "Data URI with HTML",
    ),
    (
        re.compile(r"on\w+\s*=", re.IGNORECASE),
        "Event handler attribute",
    ),
    (
        re.compile(r"<iframe[\s>]", re.IGNORECASE),
        "Iframe injection",
    ),
    (
        re.compile(r"<object[\s>]", re.IGNORECASE),
        "Object tag injection",
    ),
    (
        re.compile(r"<embed[\s>]", re.IGNORECASE),
        "Embed tag injection",
    ),
    (
        re.compile(r"expression\s*\(", re.IGNORECASE),
        "CSS expression",
    ),
]
