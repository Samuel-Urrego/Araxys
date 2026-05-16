"""Pure-function detectors for injection attacks.

Each detector is a pure function ``(value: str) -> str | None`` that
returns a threat description if the input matches an attack pattern,
or ``None`` if the input appears safe.

Detectors operate on URL-decoded strings — callers are responsible for
decoding before invoking these functions.
"""

from __future__ import annotations

import re
from typing import Final

# ---------------------------------------------------------------------------
# NoSQL Injection Patterns
# ---------------------------------------------------------------------------

# MongoDB operators with $ prefix — the most common NoSQL injection vector
_NOSQL_DOLLAR_OPERATORS: Final[re.Pattern[str]] = re.compile(
    r"""[$](?:
        where  | regex  | gt   | ne   | eq    |
        nin    | or     | and  | nor  | exists |
        mod    | all    | elemMatch | text | search
    )\b""",
    re.IGNORECASE | re.VERBOSE,
)

# NoSQL operators WITHOUT $ prefix (some dialects / REST APIs)
_NOSQL_PREFIXLESS_OPERATORS: Final[re.Pattern[str]] = re.compile(
    r"""(?:
        (?:^|[?&])[a-zA-Z_]\w*\[(?:
            gt | ne | regex | nin | eq | gte | lte | lt | where | exists | mod
        )\]
        |
        ["'](?:
            gt | ne | regex | nin | eq | gte | lte | lt | where | exists | mod
        )["']\s*:
    )""",
    re.IGNORECASE | re.VERBOSE,
)


def detect_nosql_injection(value: str) -> str | None:
    """Check a string for NoSQL injection patterns.

    Detects MongoDB operators (``$where``, ``$gt``, ``$ne``, etc.) and
    prefixless variants (``gt``, ``ne``, ``regex``) used in REST APIs.

    Returns the threat description, or ``None`` if the value is clean.
    """
    if _NOSQL_DOLLAR_OPERATORS.search(value):
        return "NoSQL $operator injection"

    if _NOSQL_PREFIXLESS_OPERATORS.search(value):
        return "NoSQL prefixless operator injection"

    return None


# ---------------------------------------------------------------------------
# Command Injection Patterns
# ---------------------------------------------------------------------------

# Shell metacharacters — single chars that break out of commands
_SHELL_METACHARS: Final[re.Pattern[str]] = re.compile(
    r"""(?<!\w)(?:  # not preceded by a word char
        ;      \s*  # command separator
        |
        \|     \s*  # pipe (single)
        |
        \|\|        # OR-ify
        |
        &&          # AND-ify
        |
        (?:`| \$\( | \( \) | \{ \})  # command substitution
    )""",
    re.VERBOSE,
)

# Common command names used in injection attacks
_COMMAND_NAMES: Final[re.Pattern[str]] = re.compile(
    r"""(?:
        \b(?:cat|ls|wget|curl|nc|ncat|bash|sh|zsh|dash|fish|cmd|powershell)\b
        |
        /(?:bin|usr/bin|sbin|usr/sbin)/[a-z]
        |
        [A-Za-z]:\\   # Windows drive letter
        |
        \\{2,}        # UNC path start
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# URL-encoded metacharacters
_URL_ENCODED_COMMAND: Final[re.Pattern[str]] = re.compile(
    r"""(?i:%             # %-encoded chars
        (?:3[BCDEbcde]    # %3B = ;, %3C = <, %3D = =, %3E = >
        |7[Cc]            # %7C = |
        |2[678]           # %26 = &, %27 = ', %28 = (
        |29               # %29 = )
        |00               # %00 = null
        )
        |
        %252e%252e       # double-encoded .. 
    )""",
    re.VERBOSE,
)


def detect_command_injection(value: str) -> str | None:
    """Check a string for OS command injection patterns.

    Scans for shell metacharacters (``;``, ``|``, ``&&``, backtick),
    common command names (``cat``, ``wget``, ``bash``), and URL-encoded
    variants (``%3B``, ``%7C``).

    Returns the threat description, or ``None`` if the value is clean.
    """
    if _SHELL_METACHARS.search(value):
        return "Shell metacharacter injection"

    if _COMMAND_NAMES.search(value):
        return "Command name injection"

    if _URL_ENCODED_COMMAND.search(value):
        return "URL-encoded command injection"

    # Null byte (\x00) in raw form
    if "\x00" in value:
        return "Null byte injection"

    return None


# ---------------------------------------------------------------------------
# Path Traversal Patterns
# ---------------------------------------------------------------------------

# Unix directory traversal
_UNIX_TRAVERSAL: Final[re.Pattern[str]] = re.compile(
    r"""(?:
        \.\.[/\\]           # ../ or ..\ (basic)
        |
        %2e%2e%2f           # URL-encoded ../
        |
        %2e%2e/             # Partial URL-encoded ../
        |
        \.\.%2f             # Mixed encoding ../ -> ..%2f
        |
        %252e%252e%252f     # Double-encoded ../
        |
        %252e%252e\/        # Partial double-encoded ../
        |
        (?:^|[\s"'])/etc/   # /etc/ paths
        |
        (?:^|[\s"'])/var/   # /var/ paths
        |
        (?:^|[\s"'])/usr/   # /usr/ paths
        |
        (?:^|[\s"'])/bin/   # /bin/ paths
        |
        (?:^|[\s"'])/proc/  # /proc/ paths
        |
        (?:^|[\s"'])/root   # /root
        |
        (?:^|[\s"'])/home/  # /home/
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# Windows directory traversal (drive letters, UNC paths)
_WINDOWS_TRAVERSAL: Final[re.Pattern[str]] = re.compile(
    r"""(?:
        \b[A-Za-z]:\\    # Drive letter (C:\, D:\, etc.)
        |
        \\{2,}[A-Za-z]   # UNC path (\\server\...)
    )""",
    re.VERBOSE,
)

# Null byte in path context (critical for path traversal bypass)
_PATH_NULL_BYTE: Final[re.Pattern[str]] = re.compile(r"%00|\\x00")

# Encoded absolute path detection (for query params that might contain %2f)
_ENCODED_PATH_TRAVERSAL: Final[re.Pattern[str]] = re.compile(
    r"(?:%2e%2e%2f|%2e%2e%5c)",
    re.IGNORECASE,
)


def detect_path_traversal(value: str) -> str | None:
    """Check a string for path traversal / directory traversal attempts.

    Detects:
    - ``../`` and ``..\\`` directory traversal
    - URL-encoded variants (``%2e%2e%2f``, ``..%2f``)
    - Double-encoded variants (``%252e%252e%252f``)
    - Unix absolute paths (``/etc/``, ``/var/``)
    - Windows drive letters (``C:\\``) and UNC paths
    - Null byte injection in path context

    Returns the threat description, or ``None`` if the value is clean.
    """
    if _ENCODED_PATH_TRAVERSAL.search(value):
        return "URL-encoded path traversal"

    if _UNIX_TRAVERSAL.search(value):
        return "Path traversal detected"

    if _WINDOWS_TRAVERSAL.search(value):
        return "Windows path traversal detected"

    if _PATH_NULL_BYTE.search(value):
        return "Null byte path injection"

    return None
