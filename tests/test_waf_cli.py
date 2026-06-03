"""Tests for the `araxys waf generate` and `araxys waf apply` CLI commands.

Phase 2, task 2.3 — waf generate
Phase 4, task 4.3 — waf apply
Phase 5, task 5.6 — CLI tests
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from araxys.cli import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Sample OpenAPI fixture
# ---------------------------------------------------------------------------

SAMPLE_OPENAPI_JSON = """{
  "openapi": "3.0.2",
  "info": {"title": "Test API", "version": "1.0.0"},
  "paths": {
    "/users": {
      "get": {"responses": {"200": {"description": "OK"}}},
      "post": {"responses": {"201": {"description": "Created"}}}
    },
    "/health": {
      "get": {"responses": {"200": {"description": "OK"}}}
    }
  }
}"""


# ---------------------------------------------------------------------------
# Task 2.3 — waf sub-app exists and waf generate command
# ---------------------------------------------------------------------------


class TestWafSubAppExists:
    """The `waf` sub-app must be registered on the main CLI app."""

    def test_waf_command_is_registered(self) -> None:
        """`araxys waf` must be a registered command group."""
        result = runner.invoke(app, ["waf", "--help"])
        assert result.exit_code == 0
        assert "generate" in result.stdout.lower()


class TestWafGenerateCommand:
    """The `araxys waf generate` command must produce valid WAF JSON."""

    @staticmethod
    def _strip_ansi(text: str) -> str:
        """Remove ANSI escape sequences from text (Rich formatting)."""
        import re
        return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)

    def test_generate_help_shows_options(self) -> None:
        """`araxys waf generate --help` shows --input, --output, --pretty."""
        result = runner.invoke(app, ["waf", "generate", "--help"])
        assert result.exit_code == 0
        clean = self._strip_ansi(result.stdout)
        assert "--input" in clean
        assert "--output" in clean
        assert "--pretty" in clean

    def test_generate_with_input_file(self, tmp_path: str) -> None:
        """Given an OpenAPI JSON file, generate WAF rules to a file."""
        import json
        from pathlib import Path

        # Write a sample OpenAPI file
        input_path = Path(tmp_path) / "openapi.json"
        input_path.write_text(SAMPLE_OPENAPI_JSON)

        output_path = Path(tmp_path) / "waf-rules.json"

        result = runner.invoke(app, [
            "waf", "generate",
            "--input", str(input_path),
            "--output", str(output_path),
        ])

        assert result.exit_code == 0, f"CLI failed: {result.stdout}\n{result.stderr}"
        # Output file should exist
        assert output_path.exists()

        # Read and verify output is valid JSON
        raw = output_path.read_text(encoding="utf-8")
        # Strip drift comment
        json_body = raw.split("\n", 1)[1] if raw.startswith("//") else raw
        parsed = json.loads(json_body)
        assert "WebACL" in parsed
        assert "IPSet" in parsed

    def test_generate_drift_warning_on_stdout(self, tmp_path: str) -> None:
        """The drift-warning comment must appear in stdout output."""
        from pathlib import Path

        input_path = Path(tmp_path) / "openapi.json"
        input_path.write_text(SAMPLE_OPENAPI_JSON)

        result = runner.invoke(app, [
            "waf", "generate",
            "--input", str(input_path),
        ])

        assert result.exit_code == 0
        assert "snapshot" in result.stdout.lower()

    def test_generate_pretty_output(self, tmp_path: str) -> None:
        """--pretty (default) must produce 2-space indented output."""
        from pathlib import Path

        input_path = Path(tmp_path) / "openapi.json"
        input_path.write_text(SAMPLE_OPENAPI_JSON)

        result = runner.invoke(app, [
            "waf", "generate",
            "--input", str(input_path),
            "--pretty",
        ])

        assert result.exit_code == 0
        # Pretty-printed JSON uses indentation
        assert "  " in result.stdout
        assert "WebACL" in result.stdout

    def test_generate_without_input_fails(self) -> None:
        """`araxys waf generate` without --input should show an error or help."""
        result = runner.invoke(app, ["waf", "generate"])
        # Should fail because --input is required
        assert result.exit_code != 0 or "required" in result.stderr.lower()

    def test_generate_with_nonexistent_file_fails(self) -> None:
        """Passing a nonexistent file path should fail with a clear error."""
        result = runner.invoke(app, [
            "waf", "generate",
            "--input", "nonexistent_file.json",
        ])
        assert result.exit_code != 0

    def test_generate_with_invalid_json_fails(self, tmp_path: str) -> None:
        """Passing invalid JSON should fail with a clear error."""
        from pathlib import Path

        bad_path = Path(tmp_path) / "bad.json"
        bad_path.write_text("not valid json")

        result = runner.invoke(app, [
            "waf", "generate",
            "--input", str(bad_path),
        ])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Task 4.3 & 5.6 — waf apply command
# ---------------------------------------------------------------------------


class TestWafApplyCommand:
    """The `araxys waf apply` command must add IPs to an AWS WAF IP set."""

    def test_apply_help_shows_options(self) -> None:
        """`araxys waf apply --help` shows --ip-set-id, --ip, --region, --dry-run."""
        result = runner.invoke(app, ["waf", "apply", "--help"])
        assert result.exit_code == 0
        clean = TestWafGenerateCommand._strip_ansi(result.stdout)
        assert "--ip-set-id" in clean
        assert "--ip" in clean
        assert "--region" in clean
        assert "--dry-run" in clean

    def test_apply_help_mentions_boto3_requirement(self) -> None:
        """`araxys waf apply --help` must mention boto3 requirement."""
        result = runner.invoke(app, ["waf", "apply", "--help"])
        assert result.exit_code == 0
        assert "boto3" in result.stdout.lower()

    def test_apply_dry_run_with_mocked_boto3(self) -> None:
        """In dry-run mode with valid args, log the action without calling AWS."""
        mock_client = MagicMock()
        mock_client.get_ip_set = MagicMock(return_value={
            "IPSet": {
                "Name": "TestIPSet",
                "Id": "abc-123",
                "Addresses": [],
                "LockToken": "lock-1",
            },
        })
        mock_client.update_ip_set = MagicMock()

        mock_boto3 = MagicMock()
        mock_boto3.client.return_value = mock_client

        with patch.dict(sys.modules, {"boto3": mock_boto3}):
            result = runner.invoke(app, [
                "waf", "apply",
                "--ip-set-id", "abc-123",
                "--ip", "1.2.3.4",
                "--dry-run",
            ])
            assert result.exit_code == 0
            assert (
                "DRY RUN" in result.stdout.upper()
                or "dry run" in result.stdout.lower()
            )

        # In dry-run mode, update_ip_set should NOT be called
        mock_client.update_ip_set.assert_not_called()

    def test_apply_missing_ip_shows_error(self) -> None:
        """`araxys waf apply` without --ip should show an error or help."""
        result = runner.invoke(app, [
            "waf", "apply",
            "--ip-set-id", "abc-123",
        ])
        # Should fail because --ip is required
        assert result.exit_code != 0
