"""Threat intel CLI commands — wired by ``araxys.cli`` to the ``threat-intel``
Typer sub-app.

Commands delegate to the running :class:`ThreatIntelScheduler` obtained
via :func:`_get_threat_intel_scheduler`.
"""

from __future__ import annotations

import asyncio
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

if hasattr(typer, "Option"):
    Option = typer.Option
else:
    from typing import Annotated as _Annotated

    Option = _Annotated[Any, typer.Option()]  # type: ignore[misc]

console = Console()


def _get_threat_intel_scheduler() -> Any:
    """Return the running :class:`ThreatIntelScheduler`, or ``None``.

    This is replaced at runtime by :class:`AraxysShield` and patched
    in tests.  The default returns ``None``.
    """
    return None


# ── refresh ──────────────────────────────────────────────────────────────


def _ti_refresh(
    feed: str | None = Option(  # type: ignore[assignment]
        None,
        "--feed",
        "-f",
        help="Feed name to refresh (omit to refresh all).",
    ),
) -> None:
    """Fetch threat intel feeds and update the blocklist."""
    sched = _get_threat_intel_scheduler()
    if sched is None:
        console.print("[bold red]Threat intel is not enabled in config.[/bold red]")
        raise typer.Exit(code=1)

    result = asyncio.run(sched.refresh(feed))

    if isinstance(result, list):
        # All feeds — show summary table
        table = Table(title="Threat Intel Refresh Results")
        table.add_column("Feed", style="cyan")
        table.add_column("IPs Added")
        table.add_column("IPs Evicted")
        for entry in result:
            if "error" in entry:
                console.print(
                    f"[red]Error refreshing {entry['feed']}: "
                    f"{entry['error']}[/red]"
                )
            else:
                table.add_row(
                    str(entry["feed"]),
                    str(entry.get("ips_added", 0)),
                    str(entry.get("ips_evicted", 0)),
                )
                console.print(
                    f"[green]✅ Refreshed {entry['feed']}: "
                    f"+{entry.get('ips_added', 0)} IPs, "
                    f"-{entry.get('ips_evicted', 0)} evicted[/green]"
                )
    else:
        # Single feed
        if "error" in result:
            console.print(
                f"[red]Error refreshing {result.get('feed', feed)}: "
                f"{result['error']}[/red]"
            )
        else:
            console.print(
                f"[green]✅ Refreshed {result['feed']}: "
                f"+{result.get('ips_added', 0)} IPs added[/green]"
            )


# ── feeds ────────────────────────────────────────────────────────────────


def _ti_feeds() -> None:
    """List configured threat intel feeds."""
    sched = _get_threat_intel_scheduler()
    if sched is None:
        console.print("[bold red]Threat intel is not enabled in config.[/bold red]")
        raise typer.Exit(code=1)

    stats = sched.stats()

    table = Table(title="Threat Intel Feeds")
    table.add_column("Feed", style="cyan")
    table.add_column("Status")
    table.add_column("Tracked IPs")

    feed_names = [
        "firehol_level1", "firehol_level2", "firehol_level3",
        "spamhaus_drop", "spamhaus_edrop", "blocklist_de",
        "abuseipdb", "alienvault_otx",
    ]
    for name in feed_names:
        feed_cfg = getattr(sched._config, name, None)
        status = (
            "[green]enabled[/green]"
            if feed_cfg is not None and feed_cfg.enabled
            else "[dim]disabled[/dim]"
        )
        ip_count = stats.get("feeds", {}).get(name, {}).get("ip_count", 0)
        table.add_row(name, status, str(ip_count))

    console.print(table)
    console.print(
        f"[bold]Total tracked IPs:[/bold] {stats.get('total_ips', 0)}"
    )


# ── stats ────────────────────────────────────────────────────────────────


def _ti_stats() -> None:
    """Show threat intel statistics."""
    sched = _get_threat_intel_scheduler()
    if sched is None:
        console.print("[bold red]Threat intel is not enabled in config.[/bold red]")
        raise typer.Exit(code=1)

    stats = sched.stats()

    console.print(
        f"[bold cyan]Tracked IPs[/bold cyan]: {stats.get('total_ips', 0)}"
    )

    feeds = stats.get("feeds", {})
    if feeds:
        table = Table(title="Per-Feed Breakdown")
        table.add_column("Feed", style="cyan")
        table.add_column("IP Count")
        table.add_column("Last Fetch")
        for fn, info in sorted(feeds.items()):
            table.add_row(
                fn,
                str(info.get("ip_count", 0)),
                str(info.get("last_fetch") or "-"),
            )
        console.print(table)


# ── purge ────────────────────────────────────────────────────────────────


def _ti_purge() -> None:
    """Purge all threat intel IPs from the blocklist."""
    sched = _get_threat_intel_scheduler()
    if sched is None:
        console.print("[bold red]Threat intel is not enabled in config.[/bold red]")
        raise typer.Exit(code=1)

    count = asyncio.run(sched.purge())
    console.print(
        f"[green]✅ Purged {count} threat-intel IPs from the blocklist.[/green]"
    )
