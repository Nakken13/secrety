"""Command-line interface for secrety."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape

from secrety import __version__
from secrety.config import (
    DEFAULT_BASE64_THRESHOLD,
    DEFAULT_HEX_THRESHOLD,
    DEFAULT_MIN_LENGTH,
    EntropyConfig,
)
from secrety.detectors import EntropyDetector, RegexDetector
from secrety.models import Finding
from secrety.rules import load_rules
from secrety.scanner import scan as run_scan
from secrety.sources import FilesystemSource, ScanStats
from secrety.sources.filesystem import DEFAULT_MAX_FILE_SIZE

EXIT_FINDINGS = 1
EXIT_ERROR = 2

app = typer.Typer(
    name="secrety",
    help="Scan source code and Git history for exposed secrets.",
    no_args_is_help=True,
    add_completion=False,
)
# emoji=False: a location such as "a.py:100:3" would print ":100:" as an emoji.
console = Console(highlight=False, soft_wrap=True, emoji=False)


def _version_callback(value: bool) -> None:
    """Print the version and exit when ``--version`` is passed."""
    if value:
        console.print(f"secrety {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Scan source code and Git history for exposed secrets."""


def _print_findings(findings: list[Finding]) -> None:
    """Print one line per finding, with the secret masked.

    Paths and secrets come from the scanned (untrusted) files, so they are
    escaped: a file named ``[link=...]x`` must not be read as Rich markup.
    """
    for f in findings:
        # Rule ids may come from a custom rules file: escaped like the rest.
        also = ", ".join(rule_id for rule_id, _ in f.also_matched)
        console.print(
            f"{escape(f.location)}  [bold]{escape(f.rule_id)}[/bold]  {escape(f.masked())}  "
            f"[dim](confidence {f.confidence:.2f}"
            f"{f'; also: {escape(also)}' if also else ''})[/dim]"
        )


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=True, help="File or folder to scan."),
    ] = Path("."),
    rules: Annotated[
        Path | None,
        typer.Option(exists=True, dir_okay=False, help="Custom rules file (YAML)."),
    ] = None,
    max_file_size: Annotated[
        int, typer.Option(min=1, help="Skip files larger than this many bytes.")
    ] = DEFAULT_MAX_FILE_SIZE,
    # Ranges are checked once, by EntropyConfig, not duplicated as typer bounds.
    entropy_base64_threshold: Annotated[
        float, typer.Option(help="Minimum entropy (bits/char, max 6) to flag a base64 token.")
    ] = DEFAULT_BASE64_THRESHOLD,
    entropy_hex_threshold: Annotated[
        float, typer.Option(help="Minimum entropy (bits/char, max 4) to flag a hex token.")
    ] = DEFAULT_HEX_THRESHOLD,
    entropy_min_length: Annotated[
        int, typer.Option(help="Shortest token checked for entropy.")
    ] = DEFAULT_MIN_LENGTH,
) -> None:
    """Scan PATH for exposed secrets.

    Exit code: 0 if nothing is found, 1 if secrets are found, 2 on error.
    """
    try:  # RuleError is a ValueError: one error path for rules and settings
        loaded_rules = load_rules(rules)
        entropy = EntropyConfig(
            base64_threshold=entropy_base64_threshold,
            hex_threshold=entropy_hex_threshold,
            min_length=entropy_min_length,
        )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_ERROR) from exc
    detectors = [RegexDetector(loaded_rules), EntropyDetector(entropy)]
    result = run_scan(FilesystemSource(path, max_file_size=max_file_size), detectors)
    _print_findings(result.findings)

    console.print(_summary(result.stats))
    if result.findings:
        console.print(f"[red bold]{len(result.findings)} potential secret(s) found.[/red bold]")
        raise typer.Exit(EXIT_FINDINGS)
    console.print("[green]No secret found.[/green]")


def _summary(stats: ScanStats) -> str:
    """Describe what was scanned and everything that was skipped."""
    summary = (
        f"\n{stats.scanned} file(s) scanned, {stats.skipped_binary} binary and "
        f"{stats.skipped_large} large file(s) skipped."
    )
    if stats.unreadable:
        summary += f" [yellow]{stats.unreadable} path(s) could not be read.[/yellow]"
    return summary
