"""Tests for OIDC discovery dependency requirements (Task 1.1).

Ensures httpx is available as a core dependency, not just an optional one.
"""

import tomllib
from pathlib import Path


def test_httpx_in_core_dependencies() -> None:
    """httpx>=0.27 must be in [project] dependencies for OIDC discovery."""
    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)

    deps: list[str] = data["project"]["dependencies"]
    assert any(
        d.strip() == "httpx>=0.27" for d in deps
    ), "httpx>=0.27 must be in [project] dependencies (core)"
