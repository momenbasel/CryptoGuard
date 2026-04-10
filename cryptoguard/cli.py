"""CLI interface for CryptoGuard.

Commands:
  cryptoguard check <address> --chain <chain>   - Analyze a token
  cryptoguard install-hook                       - Install Claude Code hook
  cryptoguard uninstall-hook                     - Remove Claude Code hook
  cryptoguard serve                              - Start MCP server
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click

from .analyzer import analyze
from .report import print_report


@click.group()
@click.version_option()
def cli() -> None:
    """CryptoGuard - AI agent safety layer for crypto transactions.

    Analyzes smart contracts for honeypots, blacklists, rug pulls,
    and other scam patterns before you interact with them.
    """


@cli.command()
@click.argument("address")
@click.option(
    "--chain", "-c",
    default="ethereum",
    help="Target blockchain (ethereum, bsc, polygon, arbitrum, base, optimism, etc.)",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["rich", "plain", "json"]),
    default="rich",
    help="Output format",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    help="Only output risk level (for scripting)",
)
def check(address: str, chain: str, output: str, quiet: bool) -> None:
    """Analyze a token contract for security risks.

    ADDRESS is the contract address (0x...).

    Examples:

      cryptoguard check 0xdAC17F958D2ee523a2206206994597C13D831ec7 --chain ethereum

      cryptoguard check 0x... --chain bsc --output json

      cryptoguard check 0x... -c polygon -q
    """
    try:
        result = analyze(address, chain)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if quiet:
        click.echo(result.risk_level.value)
        sys.exit(2 if result.should_block else 0)

    print_report(result, output=output, file=sys.stdout)

    # Exit code reflects risk level
    if result.should_block:
        sys.exit(2)
    elif result.risk_level.value == "MEDIUM":
        sys.exit(1)
    else:
        sys.exit(0)


@cli.command("install-hook")
@click.option(
    "--settings-path",
    type=click.Path(),
    default=None,
    help="Path to Claude Code settings.json (auto-detected if omitted)",
)
@click.option(
    "--threshold",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM"]),
    default="HIGH",
    help="Minimum risk level to block transactions (default: HIGH)",
)
def install_hook(settings_path: str | None, threshold: str) -> None:
    """Install CryptoGuard as a Claude Code pre-transaction hook.

    This adds a PreToolUse hook to your Claude Code settings that
    automatically analyzes crypto contracts before any transaction.
    """
    if settings_path is None:
        settings_path = _find_claude_settings()

    if not settings_path:
        click.echo("Error: Could not find Claude Code settings.json", err=True)
        click.echo("Searched: ~/.claude/settings.json", err=True)
        click.echo("Use --settings-path to specify the location.", err=True)
        sys.exit(1)

    settings_file = Path(settings_path)

    # Read existing settings
    if settings_file.exists():
        with open(settings_file) as f:
            settings = json.load(f)
    else:
        settings_file.parent.mkdir(parents=True, exist_ok=True)
        settings = {}

    # Build hook command
    hook_cmd = f"python -m cryptoguard.hook"
    if threshold != "HIGH":
        hook_cmd = f"CRYPTOGUARD_THRESHOLD={threshold} {hook_cmd}"

    hook_entry = {
        "matcher": "Bash",
        "hook": hook_cmd,
    }

    # Add to hooks.PreToolUse
    if "hooks" not in settings:
        settings["hooks"] = {}
    if "PreToolUse" not in settings["hooks"]:
        settings["hooks"]["PreToolUse"] = []

    # Check if already installed
    existing = settings["hooks"]["PreToolUse"]
    for entry in existing:
        if "cryptoguard" in entry.get("hook", ""):
            click.echo("CryptoGuard hook is already installed.")
            click.echo(f"Current config: {json.dumps(entry)}")
            return

    existing.append(hook_entry)

    # Write back
    with open(settings_file, "w") as f:
        json.dump(settings, f, indent=2)

    click.echo(f"CryptoGuard hook installed at {settings_file}")
    click.echo(f"Threshold: {threshold} (blocks {threshold} and above)")
    click.echo("")
    click.echo("The hook will now automatically analyze contracts before")
    click.echo("any crypto transaction executed via Claude Code.")
    click.echo("")
    click.echo("To disable temporarily: export CRYPTOGUARD_DISABLE=1")
    click.echo("To uninstall: cryptoguard uninstall-hook")


@cli.command("uninstall-hook")
@click.option(
    "--settings-path",
    type=click.Path(),
    default=None,
    help="Path to Claude Code settings.json",
)
def uninstall_hook(settings_path: str | None) -> None:
    """Remove CryptoGuard hook from Claude Code settings."""
    if settings_path is None:
        settings_path = _find_claude_settings()

    if not settings_path:
        click.echo("Error: Could not find Claude Code settings.json", err=True)
        sys.exit(1)

    settings_file = Path(settings_path)
    if not settings_file.exists():
        click.echo("Settings file does not exist. Nothing to uninstall.")
        return

    with open(settings_file) as f:
        settings = json.load(f)

    hooks = settings.get("hooks", {}).get("PreToolUse", [])
    original_count = len(hooks)
    hooks = [h for h in hooks if "cryptoguard" not in h.get("hook", "")]
    settings.setdefault("hooks", {})["PreToolUse"] = hooks

    if len(hooks) == original_count:
        click.echo("CryptoGuard hook was not found in settings.")
        return

    with open(settings_file, "w") as f:
        json.dump(settings, f, indent=2)

    click.echo("CryptoGuard hook removed successfully.")


@cli.command("serve")
@click.option("--port", "-p", default=3847, help="MCP server port")
@click.option("--host", default="127.0.0.1", help="MCP server host")
def serve(port: int, host: str) -> None:
    """Start CryptoGuard MCP server (for IDE/agent integration)."""
    try:
        from .mcp_server import start_server
        start_server(host=host, port=port)
    except ImportError as exc:
        click.echo(f"MCP server requires additional dependencies: {exc}", err=True)
        click.echo("Install with: pip install cryptoguard[mcp]", err=True)
        sys.exit(1)


def _find_claude_settings() -> str | None:
    """Auto-detect Claude Code settings.json location."""
    home = Path.home()
    candidates = [
        home / ".claude" / "settings.json",
        home / ".config" / "claude" / "settings.json",
    ]
    for path in candidates:
        if path.exists():
            return str(path)
    # Return default even if it doesn't exist yet
    default = home / ".claude" / "settings.json"
    return str(default) if default.parent.exists() else None


def main() -> None:
    """Entry point for console_scripts."""
    cli()


if __name__ == "__main__":
    main()
