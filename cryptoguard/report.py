"""Terminal report formatter using Rich.

Produces clear, color-coded security reports for terminal output.
Also supports plain-text and JSON output modes.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from .analyzer import AnalysisResult, Finding, RiskLevel, Severity

# Try rich for beautiful output, fall back to plain text
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

RISK_LEVEL_EMOJI = {
    # Using ASCII art instead of emoji per user preference
    "CRITICAL": "[!!!]",
    "HIGH": "[!!]",
    "MEDIUM": "[!]",
    "LOW": "[~]",
    "SAFE": "[OK]",
}

RISK_LEVEL_COLORS = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "SAFE": "bold green",
}


def print_report(result: AnalysisResult, output: str = "rich", file: TextIO = sys.stderr) -> None:
    """Print analysis report to terminal.

    Args:
        result: Analysis result to display
        output: Output format - "rich", "plain", or "json"
        file: Output stream (default stderr for hook compatibility)
    """
    if output == "json":
        print(json.dumps(result.to_dict(), indent=2), file=file)
        return

    if output == "rich" and HAS_RICH:
        _print_rich(result, file)
    else:
        _print_plain(result, file)


def format_hook_message(result: AnalysisResult) -> str:
    """Format a concise message for AI agent hook output (stderr).

    This is what the AI agent sees when a transaction is blocked or warned.
    Must be clear and actionable.
    """
    lines = []
    level = result.risk_level.value
    marker = RISK_LEVEL_EMOJI.get(level, "")

    lines.append(f"\n{'='*60}")
    lines.append(f" CRYPTOGUARD {marker} {level} RISK DETECTED")
    lines.append(f"{'='*60}")
    lines.append(f" Token: {result.token_info.name or 'Unknown'} ({result.token_info.symbol or '???'})")
    lines.append(f" Address: {result.address}")
    lines.append(f" Chain: {result.chain}")
    lines.append(f" Risk Score: {result.risk_score}/100")
    lines.append(f" Risk Level: {level}")
    lines.append("")

    # Critical and high findings only for hook (keep it concise)
    critical = result.critical_findings + result.high_findings
    if critical:
        lines.append(" FINDINGS:")
        for i, f in enumerate(critical[:8], 1):
            lines.append(f"  {i}. [{f.severity.value}] {f.title}")
            lines.append(f"     {f.description[:120]}")
        if len(critical) > 8:
            lines.append(f"  ... and {len(critical) - 8} more findings")
    else:
        medium = [f for f in result.findings if f.severity == Severity.MEDIUM]
        if medium:
            lines.append(" FINDINGS:")
            for i, f in enumerate(medium[:5], 1):
                lines.append(f"  {i}. [{f.severity.value}] {f.title}")

    lines.append("")
    if result.should_block:
        lines.append(" RECOMMENDATION: BLOCK this transaction. High risk of fund loss.")
    elif result.risk_level == RiskLevel.MEDIUM:
        lines.append(" RECOMMENDATION: CAUTION. Review findings before proceeding.")
    else:
        lines.append(" RECOMMENDATION: Low risk detected. Proceed with normal caution.")

    lines.append(f"{'='*60}\n")
    return "\n".join(lines)


def _print_rich(result: AnalysisResult, file: TextIO) -> None:
    """Rich (colored) terminal output."""
    console = Console(file=file)

    # Header
    level = result.risk_level.value
    color = RISK_LEVEL_COLORS.get(level, "white")
    marker = RISK_LEVEL_EMOJI.get(level, "")

    header = Text()
    header.append(f" {marker} ", style=color)
    header.append(f"RISK LEVEL: {level}", style=color)
    header.append(f"  (Score: {result.risk_score}/100)", style="dim")

    console.print()
    console.print(Panel(header, title="CryptoGuard Analysis", border_style=color))

    # Token info table
    info_table = Table(show_header=False, box=None, padding=(0, 2))
    info_table.add_column("Key", style="bold")
    info_table.add_column("Value")

    info_table.add_row("Token", f"{result.token_info.name} ({result.token_info.symbol})")
    info_table.add_row("Address", result.address)
    info_table.add_row("Chain", result.chain)
    info_table.add_row("Holders", str(result.token_info.holder_count))
    info_table.add_row("Open Source", "Yes" if result.token_info.is_open_source else "No")
    info_table.add_row("Owner", result.token_info.owner or "N/A")
    info_table.add_row("DEX Listed", "Yes" if result.token_info.is_in_dex else "No")

    console.print(info_table)
    console.print()

    # Findings table
    if result.findings:
        findings_table = Table(title="Security Findings", expand=True)
        findings_table.add_column("Severity", width=10, justify="center")
        findings_table.add_column("Category", width=12)
        findings_table.add_column("Finding", ratio=2)
        findings_table.add_column("Details", ratio=3)

        # Sort by severity
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 5))

        for f in sorted_findings:
            sev_style = SEVERITY_COLORS.get(f.severity.value, "white")
            findings_table.add_row(
                Text(f.severity.value, style=sev_style),
                f.category,
                f.title,
                f.description[:150] + ("..." if len(f.description) > 150 else ""),
            )

        console.print(findings_table)
    else:
        console.print("[green]No security findings detected.[/green]")

    # Reputation sources
    if result.reputation and result.reputation.sources:
        console.print()
        rep_table = Table(title="Reputation Sources")
        rep_table.add_column("Source", width=18)
        rep_table.add_column("Status", width=12)
        rep_table.add_column("Risk", width=8, justify="center")
        rep_table.add_column("Details", ratio=2)

        for src in result.reputation.sources:
            if src.available:
                status_text = Text("FLAGGED", style="bold red") if src.is_flagged else Text("OK", style="green")
                risk_text = str(src.risk_score)
                detail_parts = []
                for k, v in list(src.details.items())[:3]:
                    if k not in ("risk_indicators",) and v:
                        detail_parts.append(f"{k}={v}")
                detail_str = ", ".join(detail_parts)[:100]
            else:
                status_text = Text("N/A", style="dim")
                risk_text = "-"
                detail_str = src.error or "unavailable"

            rep_table.add_row(src.source, status_text, risk_text, detail_str)

        console.print(rep_table)

    # Summary
    console.print()
    summary = _build_summary(result)
    summary_style = color
    console.print(Panel(summary, title="Recommendation", border_style=summary_style))
    console.print()


def _print_plain(result: AnalysisResult, file: TextIO) -> None:
    """Plain text output (no ANSI colors)."""
    level = result.risk_level.value
    marker = RISK_LEVEL_EMOJI.get(level, "")

    lines = [
        "",
        "=" * 60,
        f"  CryptoGuard Analysis - {marker} {level} RISK (Score: {result.risk_score}/100)",
        "=" * 60,
        "",
        f"  Token:       {result.token_info.name} ({result.token_info.symbol})",
        f"  Address:     {result.address}",
        f"  Chain:       {result.chain}",
        f"  Holders:     {result.token_info.holder_count}",
        f"  Open Source: {'Yes' if result.token_info.is_open_source else 'No'}",
        f"  Owner:       {result.token_info.owner or 'N/A'}",
        "",
        "-" * 60,
        "  FINDINGS:",
        "-" * 60,
    ]

    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 5))

    for i, f in enumerate(sorted_findings, 1):
        lines.append(f"  {i:2d}. [{f.severity.value:8s}] {f.title}")
        lines.append(f"      {f.description[:120]}")

    if not result.findings:
        lines.append("  No findings.")

    # Reputation
    if result.reputation and result.reputation.sources:
        lines.append("")
        lines.append("-" * 60)
        lines.append("  REPUTATION SOURCES:")
        lines.append("-" * 60)
        for src in result.reputation.sources:
            status = "FLAGGED" if src.is_flagged else ("OK" if src.available else "N/A")
            lines.append(f"  {src.source:18s}  {status:8s}  risk={src.risk_score}")

    lines.append("")
    lines.append("-" * 60)
    lines.append(f"  {_build_summary(result)}")
    lines.append("=" * 60)
    lines.append("")

    print("\n".join(lines), file=file)


def _build_summary(result: AnalysisResult) -> str:
    """Build recommendation summary text."""
    level = result.risk_level

    if level == RiskLevel.CRITICAL:
        return (
            "DO NOT PROCEED. This token has critical security issues. "
            "You are very likely to lose all funds. "
            f"({len(result.critical_findings)} critical finding(s))"
        )
    elif level == RiskLevel.HIGH:
        return (
            "HIGH RISK - Transaction should be blocked. "
            "Significant probability of fund loss. "
            "Review all findings carefully before any interaction."
        )
    elif level == RiskLevel.MEDIUM:
        return (
            "MEDIUM RISK - Proceed with caution. "
            "Some concerning indicators found. "
            "Only invest what you can afford to lose."
        )
    elif level == RiskLevel.LOW:
        return (
            "LOW RISK - Minor concerns detected. "
            "Standard precautions apply. DYOR."
        )
    else:
        return (
            "SAFE - No significant risks detected. "
            "Standard precautions still apply. This is not financial advice."
        )
