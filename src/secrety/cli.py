"""Command-line interface for secrety."""

import io
import sys
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer
from rich.console import Console

from secrety import __version__
from secrety.allowlist import FilterResult
from secrety.classifier import load_classifier
from secrety.config import (
    DEFAULT_BASE64_THRESHOLD,
    DEFAULT_HEX_THRESHOLD,
    DEFAULT_MIN_LENGTH,
    EntropyConfig,
    load_file_config,
)
from secrety.detectors import Detector, EntropyDetector, RegexDetector
from secrety.models import Finding
from secrety.reporters import render_json, render_sarif, render_text, safe
from secrety.rules import load_rules, unbounded_rule_warnings
from secrety.scanner import scan as run_scan
from secrety.sources import FilesystemSource, ScanStats
from secrety.sources.filesystem import DEFAULT_MAX_FILE_SIZE

EXIT_FINDINGS = 1
EXIT_ERROR = 2
_DATE_FORMATS = ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"]


class OutputFormat(StrEnum):
    """Report formats accepted by ``--format``."""

    TEXT = "text"
    JSON = "json"
    SARIF = "sarif"


app = typer.Typer(
    name="secrety",
    help="Scan source code and Git history for exposed secrets.",
    no_args_is_help=True,
    add_completion=False,
)
# emoji=False: a location such as "a.py:100:3" would print ":100:" as an emoji.
console = Console(highlight=False, soft_wrap=True, emoji=False)
# Status lines of a json/sarif run: stdout must hold the report alone.
_stderr_console = Console(stderr=True, highlight=False, soft_wrap=True, emoji=False)


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
    config: Annotated[
        Path | None,
        typer.Option(
            exists=True,
            dir_okay=False,
            help="Settings file (TOML). Default: .secrety.toml at the scanned folder, if any.",
        ),
    ] = None,
    classifier: Annotated[
        bool,
        typer.Option(
            "--classifier",
            help="Rescore findings with the packaged model and drop those below its threshold.",
        ),
    ] = False,
    classifier_threshold: Annotated[
        float | None,
        typer.Option(help="With --classifier: minimum probability (0-1) to keep a finding."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Report format. json and sarif keep stdout for the report alone "
            "(status lines go to stderr). Secrets are always masked.",
        ),
    ] = OutputFormat.TEXT,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", dir_okay=False, help="Write the report to this file."),
    ] = None,
) -> None:
    """Scan PATH for exposed secrets.

    Exit code: 0 if nothing is found, 1 if secrets are found, 2 on error.
    """
    # Chosen first: nothing but the report may reach stdout in a json/sarif run.
    info = console if output_format is OutputFormat.TEXT and output is None else _stderr_console
    if not git_history and (max_commits is not None or since is not None):
        _fail("--max-commits and --since need --git.")
    if classifier_threshold is not None and not classifier:
        _fail("--classifier-threshold needs --classifier.")
    try:  # RuleError is a ValueError: one error path for rules and settings
        loaded_rules = load_rules(rules)
        entropy = EntropyConfig(
            base64_threshold=entropy_base64_threshold,
            hex_threshold=entropy_hex_threshold,
            min_length=entropy_min_length,
        )
        file_config = load_file_config(config, path)
        model = load_classifier(threshold=classifier_threshold) if classifier else None
    except ValueError as exc:
        _fail(str(exc), exc)
    if rules is not None:  # bundled rules are bounded, and tested to stay so
        for warning in unbounded_rule_warnings(loaded_rules):
            info.print(f"[yellow]Warning: {safe(warning)}[/yellow]")
    detectors = [RegexDetector(loaded_rules), EntropyDetector(entropy)]
    if git_history:
        findings, stats = _scan_history(path, detectors, max_file_size, max_commits, since, info)
    else:
        result = run_scan(FilesystemSource(path, max_file_size=max_file_size), detectors)
        findings, stats = result.findings, result.stats
    filtered = file_config.allowlist.apply(findings)
    findings = filtered.kept
    rescored = None
    if model is not None:
        rescored = model.rescore(findings)
        findings = rescored.kept
    _write_report(findings, output_format, output)

    if file_config.source is not None:
        info.print(f"\nConfig: {safe(str(file_config.source))}")
    info.print(_summary(stats) + _suppressed(filtered))
    if model is not None and rescored is not None:
        info.print(
            f"{rescored.dropped} finding(s) below the classifier threshold "
            f"{model.threshold:.2f} dropped."
        )
        if model.stub:
            info.print(
                "[yellow]Warning: the packaged classifier is an untrained stub "
                "(hand-set weights); its scores are rough.[/yellow]"
            )
    if findings:
        info.print(f"[red bold]{len(findings)} potential secret(s) found.[/red bold]")
        raise typer.Exit(EXIT_FINDINGS)
    info.print("[green]No secret found.[/green]")


def _write_report(findings: list[Finding], fmt: OutputFormat, output: Path | None) -> None:
    """Render ``findings`` in ``fmt`` to ``output``, or to stdout when it is ``None``."""
    if fmt is OutputFormat.TEXT:
        if output is None:
            render_text(console, findings)
            return
        buffer = io.StringIO()
        # No colour codes in a file, and a wide line must not be wrapped.
        render_text(Console(file=buffer, highlight=False, emoji=False, width=10_000), findings)
        document = buffer.getvalue()
    else:
        document = (render_json if fmt is OutputFormat.JSON else render_sarif)(findings)
    if output is None:
        sys.stdout.write(document)
        return
    try:
        output.write_text(document, encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write {output}: {exc}", exc)


def _fail(message: str, cause: BaseException | None = None) -> NoReturn:
    """Print ``message`` as an error and exit with :data:`EXIT_ERROR`."""
    _stderr_console.print(f"[red]Error:[/red] {safe(message)}")
    raise typer.Exit(EXIT_ERROR) from cause


def _scan_history(
    path: Path,
    detectors: Sequence[Detector],
    max_file_size: int,
    max_commits: int | None,
    since: datetime | None,
    info: Console,
) -> tuple[list[Finding], ScanStats]:
    """Scan the Git history at ``path``, marking secrets no longer in ``HEAD``."""
    # Imported here: GitPython fails at import time when git is not installed,
    # which must not break a plain folder scan.
    try:
        from secrety.sources.git import scan_history
    except ImportError as exc:
        _fail(f"--git needs GitPython and the git executable: {exc}", exc)
    try:
        result = scan_history(
            path, detectors, max_commits=max_commits, since=since, max_file_size=max_file_size
        )
    except ValueError as exc:
        _fail(str(exc), exc)
    if result.shallow:
        info.print(
            "[yellow]Warning: shallow clone. Older history is missing, and the oldest "
            "commit is reported as adding every file it contains.[/yellow]"
        )
    return result.findings, result.stats


def _suppressed(filtered: FilterResult) -> str:
    """Say how many findings the allowlist and inline markers removed."""
    if not (filtered.suppressed_by_path or filtered.suppressed_inline):
        return ""
    return (
        f"\n{filtered.suppressed_by_path} finding(s) suppressed by the path allowlist, "
        f"{filtered.suppressed_inline} by inline secrety:ignore."
    )


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
    if stats.skipped_links:
        summary += f" {stats.skipped_links} link(s) not followed."
    if stats.unreadable:
        summary += f" [yellow]{stats.unreadable} path(s) could not be read.[/yellow]"
    return summary
