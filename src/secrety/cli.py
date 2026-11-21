"""Command-line interface for secrety."""

import re
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Annotated, NoReturn

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
from secrety.detectors import Detector, EntropyDetector, RegexDetector
from secrety.models import Finding
from secrety.rules import load_rules
from secrety.scanner import scan as run_scan
from secrety.sources import FilesystemSource, ScanStats
from secrety.sources.filesystem import DEFAULT_MAX_FILE_SIZE

EXIT_FINDINGS = 1
EXIT_ERROR = 2
# C0 controls, DEL and C1 controls: ESC or CSI could drive the terminal.
_CONTROL_CHARS = re.compile("[\x00-\x1f\x7f-\x9f]")
_DATE_FORMATS = ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]

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


def _safe(text: str) -> str:
    """Make untrusted text (paths, authors, rule ids) safe to print.

    Control characters (ESC, CSI...) are shown as hex escapes so they cannot
    drive the terminal, then Rich markup is escaped (a file named
    ``[link=...]x`` stays literal).
    """
    return escape(_CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", text))


def _print_findings(findings: list[Finding]) -> None:
    """Print one line per finding, with the secret masked.

    Paths and secrets come from the scanned (untrusted) files, so they are
    escaped: a file named ``[link=...]x`` must not be read as Rich markup.
    """
    for f in findings:
        # Rule ids may come from a custom rules file: escaped like the rest.
        details = [f"confidence {f.confidence:.2f}"]
        if f.also_matched:
            details.append("also: " + ", ".join(rule_id for rule_id, _ in f.also_matched))
        if f.author:
            details.append(f"by {f.author}" + (f" on {f.date[:10]}" if f.date else ""))
        if f.removed_later:
            details.append("removed from HEAD, still in history")
        console.print(
            f"{_safe(f.location)}  [bold]{_safe(f.rule_id)}[/bold]  {_safe(f.masked())}  "
            f"[dim]({_safe('; '.join(details))})[/dim]"
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
    git_history: Annotated[
        bool,
        typer.Option(
            "--git",
            help="Scan the lines added by every commit reachable from HEAD in the "
            "repository at PATH, instead of the files on disk (other branches and "
            "uncommitted changes are not scanned).",
        ),
    ] = False,
    max_commits: Annotated[
        int | None, typer.Option(min=1, help="With --git: scan only the N newest commits.")
    ] = None,
    since: Annotated[
        datetime | None,
        typer.Option(
            formats=_DATE_FORMATS, help="With --git: scan only commits committed after this date."
        ),
    ] = None,
) -> None:
    """Scan PATH for exposed secrets.

    Exit code: 0 if nothing is found, 1 if secrets are found, 2 on error.
    """
    if not git_history and (max_commits is not None or since is not None):
        _fail("--max-commits and --since need --git.")
    try:  # RuleError is a ValueError: one error path for rules and settings
        loaded_rules = load_rules(rules)
        entropy = EntropyConfig(
            base64_threshold=entropy_base64_threshold,
            hex_threshold=entropy_hex_threshold,
            min_length=entropy_min_length,
        )
    except ValueError as exc:
        _fail(str(exc), exc)
    detectors = [RegexDetector(loaded_rules), EntropyDetector(entropy)]
    if git_history:
        findings, stats = _scan_history(path, detectors, max_file_size, max_commits, since)
    else:
        result = run_scan(FilesystemSource(path, max_file_size=max_file_size), detectors)
        findings, stats = result.findings, result.stats
    _print_findings(findings)

    console.print(_summary(stats))
    if findings:
        console.print(f"[red bold]{len(findings)} potential secret(s) found.[/red bold]")
        raise typer.Exit(EXIT_FINDINGS)
    console.print("[green]No secret found.[/green]")


def _fail(message: str, cause: BaseException | None = None) -> NoReturn:
    """Print ``message`` as an error and exit with :data:`EXIT_ERROR`."""
    console.print(f"[red]Error:[/red] {escape(message)}")
    raise typer.Exit(EXIT_ERROR) from cause


def _scan_history(
    path: Path,
    detectors: Sequence[Detector],
    max_file_size: int,
    max_commits: int | None,
    since: datetime | None,
) -> tuple[list[Finding], ScanStats]:
    """Scan the Git history at ``path``, marking secrets no longer in ``HEAD``."""
    # Imported here: GitPython fails at import time when git is not installed,
    # which must not break a plain folder scan.
    try:
        import git

        from secrety.sources.git import GitSource
    except ImportError as exc:
        _fail(f"--git needs GitPython and the git executable: {exc}", exc)
    source = GitSource(path, max_commits=max_commits, since=since, max_file_size=max_file_size)
    try:
        findings = source.mark_removed(run_scan(source, detectors).findings)
        shallow = source.is_shallow()
    except (ValueError, git.GitError) as exc:
        _fail(str(exc), exc)
    if shallow:
        console.print(
            "[yellow]Warning: shallow clone. Older history is missing, and the oldest "
            "commit is reported as adding every file it contains.[/yellow]"
        )
    return findings, source.stats


def _summary(stats: ScanStats) -> str:
    """Describe what was scanned and everything that was skipped."""
    scanned = (
        f"{stats.scanned} file change(s) in {stats.commits} commit(s)"
        if stats.commits
        else f"{stats.scanned} file(s)"
    )
    summary = (
        f"\n{scanned} scanned, {stats.skipped_binary} binary and "
        f"{stats.skipped_large} large file(s) skipped."
    )
    if stats.unreadable:
        summary += f" [yellow]{stats.unreadable} path(s) could not be read.[/yellow]"
    return summary
