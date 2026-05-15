"""Araxys Security CLI — Manage your security assets from the terminal."""

from __future__ import annotations

import asyncio
import os

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from araxys.api_keys.manager import APIKeyManager
from araxys.api_keys.storage import RedisAPIKeyStorage
from araxys.core.types import Scope

app = typer.Typer(
    help="🛡️ Araxys Security CLI — Enterprise-grade security management.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
keys_app = typer.Typer(help="🔑 Manage API Keys", no_args_is_help=True)
app.add_typer(keys_app, name="keys")

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
):
    """Create a new API key securely."""
    manager = get_manager()

    parsed_scopes = None
    if scopes:
        parsed_scopes = [Scope(s.strip()) for s in scopes.split(",")]

    async def _run():
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
):
    """List all active API keys."""
    manager = get_manager()

    async def _run():
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
):
    """Immediately revoke an API key."""
    manager = get_manager()

    async def _run():
        return await manager.revoke_key(prefix)

    success = asyncio.run(_run())

    if success:
        console.print(f"[bold green]✅ Key {prefix} has been revoked.[/bold green]")
    else:
        console.print(f"[bold red]❌ Key {prefix} not found.[/bold red]")


if __name__ == "__main__":
    app()
