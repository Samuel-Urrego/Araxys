"""Araxys Security CLI — Manage your security assets from the terminal."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from araxys.api_keys.manager import APIKeyManager
from araxys.api_keys.storage import RedisAPIKeyStorage
from araxys.core.types import Scope
from araxys.headers.auditor import audit_headers
from araxys.threat_intel.cli import (
    _ti_feeds,
    _ti_purge,
    _ti_refresh,
    _ti_stats,
)
from araxys.waf.rule_generator import WafRuleGenerator
from araxys.waf.schema_reader import SchemaReader

if TYPE_CHECKING:
    from araxys.api_keys.models import APIKeyRecord, APIKeyResponse

app = typer.Typer(
    help="🛡️ Araxys Security CLI — Enterprise-grade security management.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
keys_app = typer.Typer(help="🔑 Manage API Keys", no_args_is_help=True)
app.add_typer(keys_app, name="keys")

waf_app = typer.Typer(
    help="🛡️ AWS WAF Bridge — Generate and apply WAF rules from OpenAPI schemas.",
    no_args_is_help=True,
)
app.add_typer(waf_app, name="waf")

threat_intel_app = typer.Typer(
    help="🛡️ Threat Intelligence — Fetch and manage threat intel feeds.",
    no_args_is_help=True,
)
app.add_typer(threat_intel_app, name="threat-intel")

console = Console()


def get_manager() -> APIKeyManager:
    """Initialize the APIKeyManager using environment variables."""
    redis_url = os.getenv("ARAXYS_REDIS_URL")
    if not redis_url:
        console.print(
            "[bold red]Error:[/bold red] ARAXYS_REDIS_URL environment variable not set."
        )
        console.print("The CLI requires a persistent Redis backend to manage keys.")
        raise typer.Exit(code=1)

    storage = RedisAPIKeyStorage(redis_url)
    return APIKeyManager(storage=storage)


@keys_app.command("create")
def create_key(
    owner: str = typer.Option(..., "--owner", "-o", help="Owner identifier"),
    scopes: str | None = typer.Option(
        None, "--scopes", "-s", help="Comma-separated scopes (e.g. read,write)"
    ),
    ttl: int | None = typer.Option(
        None, "--ttl", "-t", help="Days until expiration"
    ),
    label: str | None = typer.Option(None, "--label", "-l", help="Optional label"),
) -> None:
    """Create a new API key securely."""
    manager = get_manager()

    parsed_scopes = None
    if scopes:
        parsed_scopes = [Scope(s.strip()) for s in scopes.split(",")]

    async def _run() -> APIKeyResponse:
        return await manager.create_key(
            owner=owner,
            scopes=parsed_scopes,
            ttl_days=ttl,
            label=label,
        )

    result = asyncio.run(_run())

    console.print(
        Panel.fit(
            f"[bold green]API Key successfully created for {owner}![/bold green]\n\n"
            f"[bold cyan]Raw Key:[/bold cyan] [white]{result.raw_key}[/white]\n"
            f"[bold cyan]Prefix:[/bold cyan] {result.prefix}\n"
            f"[bold cyan]Expires:[/bold cyan] {result.expires_at or 'Never'}",
            title="Success",
            border_style="green",
        )
    )
    console.print(
        "[bold yellow]⚠️  IMPORTANT:[/bold yellow] This key is [italic]never[/italic] "
        "stored in plain text. Copy it now; you won't see it again!"
    )


@keys_app.command("list")
def list_keys(
    owner: str | None = typer.Option(None, "--owner", "-o", help="Filter by owner"),
) -> None:
    """List all active API keys."""
    manager = get_manager()

    async def _run() -> list[APIKeyRecord]:
        return await manager.list_keys(owner=owner)

    records = asyncio.run(_run())

    if not records:
        console.print("[yellow]No active API keys found.[/yellow]")
        return

    table = Table(title="Araxys Active API Keys", header_style="bold magenta")
    table.add_column("Prefix", style="cyan")
    table.add_column("Owner", style="green")
    table.add_column("Label")
    table.add_column("Scopes", style="dim")
    table.add_column("Expires", style="yellow")
    table.add_column("Created", style="dim")

    for r in records:
        table.add_row(
            r.prefix,
            r.owner,
            r.label or "-",
            ", ".join([s.value for s in r.scopes]),
            str(r.expires_at.date()) if r.expires_at else "Never",
            str(r.created_at.date()),
        )

    console.print(table)


@keys_app.command("revoke")
def revoke_key(
    prefix: str = typer.Argument(..., help="The 8-character prefix of the key"),
) -> None:
    """Immediately revoke an API key."""
    manager = get_manager()

    async def _run() -> bool:
        return await manager.revoke_key(prefix)

    success = asyncio.run(_run())

    if success:
        console.print(f"[bold green]✅ Key {prefix} has been revoked.[/bold green]")
    else:
        console.print(f"[bold red]❌ Key {prefix} not found.[/bold red]")


# ---------------------------------------------------------------------------
# Headers Audit CLI
# ---------------------------------------------------------------------------

audit_headers_app = typer.Typer(help="Audit HTTP response security headers")
app.add_typer(audit_headers_app, name="audit-headers")


@audit_headers_app.command("check")
def audit_headers_command(
    url: str = typer.Argument(..., help="URL to audit (e.g. https://example.com)"),
    fail_on: str = typer.Option(
        "fail",
        "--fail-on",
        help="Minimum severity to fail on: warn or fail",
    ),
) -> None:
    """Audit security headers of a remote URL.

    Fetches the URL, extracts response headers, and checks them against
    OWASP security header recommendations.
    """
    import httpx

    console.print(f"[bold]Auditing headers for:[/bold] {url}")
    try:
        with httpx.Client(follow_redirects=True, timeout=10) as client:
            response = client.get(url)
    except httpx.RequestError as e:
        console.print(f"[bold red]Error fetching {url}:[/bold red] {e}")
        raise typer.Exit(code=1) from e

    headers_dict = dict(response.headers)
    findings = audit_headers(headers_dict)

    table = Table(title=f"Security Headers Audit — {url}")
    table.add_column("Header", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Found Value", style="dim")
    table.add_column("Detail", style="yellow")

    has_issues = False
    for f in findings:
        status_color = "green" if f.status == "pass" else (
            "yellow" if f.status == "warn" else "red"
        )
        status_text = f"[{status_color}]{f.status.upper()}[/{status_color}]"
        table.add_row(
            f.header_name,
            status_text,
            f.found_value or "\u2014",
            f.detail or "",
        )

        if f.status == "fail" or f.status == "warn" and fail_on == "warn":
            has_issues = True

    console.print(table)

    if has_issues:
        console.print(
            "[bold red]Issues found![/bold red] "
            "Review the findings above."
        )
        raise typer.Exit(code=1)
    else:
        console.print("[bold green]All checks passed![/bold green]")


# ── v0.14 — Secrets Rotation CLI ────────────────────────────────────────────

secrets_app = typer.Typer(
    help="Manage dynamic secrets rotation",
    no_args_is_help=True,
)
app.add_typer(secrets_app, name="secrets")


def _get_secrets_client() -> tuple[str, str]:
    """Get API key and base URL from environment variables."""
    api_key = os.getenv("ARAXYS_API_KEY")
    if not api_key:
        console.print(
            "[bold red]Error:[/bold red] ARAXYS_API_KEY environment variable not set."
        )
        raise typer.Exit(code=1)
    base_url = os.getenv("ARAXYS_BASE_URL", "http://localhost:8000")
    return (api_key, base_url)


@secrets_app.command("rotate")
def secrets_rotate(
    target: str | None = typer.Option(
        None, "--target", "-t",
        help="Specific target to rotate (e.g. redis, postgres). "
             "If not set, all configured targets are rotated.",
    ),
) -> None:
    """Manually trigger secrets rotation for one or all targets."""
    import httpx

    api_key, base_url = _get_secrets_client()

    body: dict[str, list[str]] = {"targets": [target] if target else []}

    async def _run() -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=base_url, timeout=30.0,
        ) as client:
            resp = await client.post(
                "/admin/secrets/rotate",
                json=body,
                headers={"X-API-Key": api_key},
            )
            resp.raise_for_status()
            return resp.json()

    try:
        result = asyncio.run(_run())
    except Exception as e:
        console.print(f"[bold red]Rotation failed:[/bold red] {e}")
        raise typer.Exit(code=1) from e

    console.print("[bold green]Rotation triggered successfully[/bold green]")
    for tgt, status in result.get("results", {}).items():
        color = "green" if status == "ok" else "red"
        icon = "\u2705" if status == "ok" else "\u274c"
        console.print(f"  {icon} [{color}]{tgt}: {status}[/{color}]")


@secrets_app.command("status")
def secrets_status() -> None:
    """Show secrets rotation configuration and per-target stats."""
    import httpx

    api_key, base_url = _get_secrets_client()

    async def _run() -> dict[str, Any]:
        async with httpx.AsyncClient(
            base_url=base_url, timeout=30.0,
        ) as client:
            resp = await client.get(
                "/admin/secrets/status",
                headers={"X-API-Key": api_key},
            )
            resp.raise_for_status()
            return resp.json()

    try:
        data = asyncio.run(_run())
    except Exception as e:
        console.print(f"[bold red]Failed to fetch status:[/bold red] {e}")
        raise typer.Exit(code=1) from e

    # Configuration panel
    enabled_text = (
        "[green]Yes[/green]" if data["enabled"]
        else "[red]No[/red]"
    )
    console.print(
        Panel.fit(
            f"[bold]Enabled:[/bold] {enabled_text}\n"
            f"[bold]Interval:[/bold] {data['interval_seconds']}s\n"
            f"[bold]Targets:[/bold] {', '.join(data['targets'])}",
            title="Secrets Rotation Config",
            border_style="blue",
        )
    )

    # Per-target stats table
    table = Table(title="Per-Target Rotation Stats", header_style="bold magenta")
    table.add_column("Target", style="cyan")
    table.add_column("Rotations", justify="right")
    table.add_column("Failures", justify="right", style="red")
    table.add_column("Last Success", style="green")
    table.add_column("Last Error", style="yellow")

    per_target: dict[str, dict[str, Any]] = data.get("per_target", {})
    for tgt, stats in per_target.items():
        last_success = (
            f"{stats['last_success']:.2f}s" if stats["last_success"] else "\u2014"
        )
        last_error = (
            f"{stats['last_error']:.2f}s" if stats["last_error"] else "\u2014"
        )
        table.add_row(
            tgt,
            str(stats.get("rotations", 0)),
            str(stats.get("failures", 0)),
            last_success,
            last_error,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# AWS WAF Bridge commands
# ---------------------------------------------------------------------------


@waf_app.command("generate")
def waf_generate(
    input_file: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to an OpenAPI JSON file.",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (default: stdout).",
    ),
    pretty: bool = typer.Option(
        True,
        "--pretty / --no-pretty",
        help="Pretty-print the JSON output with 2-space indentation.",
    ),
) -> None:
    """Generate AWS WAF v2 rules from an OpenAPI schema.

    Reads an OpenAPI JSON file (e.g. the output of ``app.openapi()``)
    and produces IP sets, regex pattern sets, rule groups, and a Web
    ACL ready for AWS WAF v2.

    WAF rules are a snapshot of your OpenAPI schema.
    Regenerate after API changes.
    """
    reader = SchemaReader(file_path=input_file)
    generator = WafRuleGenerator(reader)
    output_text = generator.to_json(pretty=pretty)

    if output:
        Path(output).write_text(output_text, encoding="utf-8")
        console.print(f"[green]WAF rules written to {output}[/green]")
    else:
        sys.stdout.write(output_text)


@waf_app.command("apply")
def waf_apply(
    ip_set_id: str = typer.Option(
        ...,
        "--ip-set-id",
        "-s",
        help="AWS WAF IP set UUID (returned by create_ip_set or the console).",
    ),
    ip_set_name: str = typer.Option(
        "AraxysBlockedIPs",
        "--ip-set-name",
        "-n",
        help="Friendly name of the IP set (default: AraxysBlockedIPs).",
    ),
    ip: str = typer.Option(
        ...,
        "--ip",
        "-i",
        help="IP address to add (CIDR /32 suffix auto-appended).",
    ),
    region: str = typer.Option(
        "us-east-1",
        "--region",
        "-r",
        help="AWS region (default: us-east-1).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Log the action without calling AWS.",
    ),
) -> None:
    """Apply a blocked IP to an AWS WAF IP set.

    Adds an IP address (auto-suffixed as /32) to an existing AWS WAF
    IP set using optimistic locking via boto3.

    Requires the IP set UUID (--ip-set-id) and optionally the name
    (--ip-set-name, defaults to "AraxysBlockedIPs").

    Requires boto3 to be installed:
        pip install araxys[aws_waf]
    """
    try:
        import boto3  # noqa: F401
    except ImportError:
        console.print(
            "[bold red]Error:[/bold red] boto3 not installed. "
            "Install with: pip install araxys[aws_waf]"
        )
        raise typer.Exit(code=1) from None

    from araxys.waf.aws_client import WafClient

    cidr = f"{ip}/32"

    async def _apply() -> None:
        client = WafClient(region_name=region)

        # Read current state (optimistic locking)
        current = await client.get_ip_set(
            ip_set_id=ip_set_id, ip_set_name=ip_set_name,
        )
        lock_token = current.get("IPSet", {}).get("LockToken")
        if not lock_token:
            console.print(
                "[bold red]Error:[/bold red] No LockToken returned. "
                "Is the IP set ID correct?"
            )
            raise typer.Exit(code=1) from None

        current_addrs: list[str] = current.get("IPSet", {}).get("Addresses", [])
        if cidr in current_addrs:
            console.print(
                f"[yellow]IP {cidr} is already in IP set {ip_set_id}.[/yellow]"
            )
            return

        if dry_run:
            console.print(
                f"[yellow]DRY RUN:[/yellow] would add {cidr} to IP set {ip_set_id}"
            )
            return

        new_addrs = [*current_addrs, cidr]
        await client.update_ip_set(
            ip_set_id=ip_set_id,
            ip_set_name=ip_set_name,
            ip_addresses=new_addrs,
            lock_token=lock_token,
        )
        console.print(
            f"[green]Added {cidr} to IP set {ip_set_id} "
            f"({len(new_addrs)} total addresses)[/green]"
        )

    asyncio.run(_apply())


if __name__ == "__main__":
    app()

# ── Security Headers Audit Command ────────────────────────────────────────


def _audit_headers_command(
    url: str,
    output_format: str = "table",
    fail_on: str | None = None,
) -> bool:
    """Audit HTTP security headers for a URL.

    Fetches headers from *url*, runs the audit, and prints results
    as JSON or a Rich table.

    Returns ``True`` if the audit passed the *fail_on* threshold,
    ``False`` otherwise.
    """
    import httpx

    try:
        client = httpx.Client(timeout=10, follow_redirects=True)
        response = client.get(url)
        if response.status_code >= 400:
            console.print(
                f"[bold red]Error fetching {url}:[/bold red] "
                f"HTTP {response.status_code}"
            )
            return False
    except httpx.HTTPError as exc:
        console.print(f"[bold red]Error fetching {url}:[/bold red] {exc}")
        return False

    findings = audit_headers(dict(response.headers))

    if output_format == "json":
        import json

        result = {
            "url": url,
            "status_code": response.status_code,
            "findings": [
                {
                    "header": f.header,
                    "status": f.status,
                    "severity": f.severity,
                    "message": f.message,
                    "recommendation": f.recommendation,
                    "current_value": f.current_value,
                    "expected": f.expected,
                }
                for f in findings
            ],
        }
        console.print(json.dumps(result, indent=2))
    else:
        # Rich table output
        table = Table(
            title=f"Security Headers Audit — [bold]{url}[/bold]",
            header_style="bold magenta",
        )
        table.add_column("Header", style="cyan")
        table.add_column("Status")
        table.add_column("Severity")
        table.add_column("Message")
        table.add_column("Recommendation", style="dim")

        for f in findings:
            status_color = {
                "pass": "green",
                "warn": "yellow",
                "fail": "red",
            }.get(f.status, "white")

            severity_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "WARNING": "yellow",
                "INFO": "dim",
            }.get(f.severity, "white")

            table.add_row(
                f.header,
                f"[{status_color}]{f.status}[/{status_color}]",
                f"[{severity_color}]{f.severity}[/{severity_color}]",
                f.message,
                f.recommendation or "-",
            )

        console.print(table)

    # Check fail-on threshold
    if fail_on:
        _severity_rank = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2, "INFO": 3}
        threshold = _severity_rank.get(fail_on.upper(), 99)
        for f in findings:
            if _severity_rank.get(f.severity, 99) <= threshold and f.status != "pass":
                return False

    return True


@app.command("audit-headers")
def audit_headers_cli(
    url: str = typer.Argument(..., help="URL to audit HTTP security headers for."),
    output_format: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: 'table' or 'json'.",
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit with non-zero if findings at or above this severity "
        "(CRITICAL, HIGH, WARNING, INFO).",
    ),
) -> None:
    """Audit HTTP security headers for a given URL.

    Fetches the URL, runs security header checks against OWASP best
    practices, and displays findings as a table or JSON.

    Use --fail-on to make CI/CD pipelines fail on insecure headers:
        araxys audit-headers https://example.com --fail-on HIGH
    """
    success = _audit_headers_command(
        url=url,
        output_format=output_format,
        fail_on=fail_on,
    )
    if not success:
        raise typer.Exit(code=1)


# ── Threat Intel commands (registered on threat_intel_app) ──────────────────

threat_intel_app.command("refresh")(_ti_refresh)
threat_intel_app.command("feeds")(_ti_feeds)
threat_intel_app.command("stats")(_ti_stats)
threat_intel_app.command("purge")(_ti_purge)
