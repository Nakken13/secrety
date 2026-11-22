"""Menu flow: mode -> path -> options -> scan -> results -> report. All I/O is injected."""

import io
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NamedTuple

from rich.console import Console

from secrety.config import (
    CONFIG_FILE_NAME,
    EntropyConfig,
    FileConfig,
    load_file_config,
    parse_file_config,
)
from secrety.detectors import EntropyDetector, RegexDetector
from secrety.models import Finding
from secrety.reporters import render_json, render_sarif, render_text, safe
from secrety.rules import load_rules
from secrety.scanner import scan as run_scan
from secrety.sources import FilesystemSource, ScanStats
from secrety.sources.staged import StagedSource, repo_root, staged_file_text
from secrety.tui.banner import banner
from secrety.tui.prompts import InputFn, PrintFn, ask, choose
from secrety.tui.visual import render_cards, render_info

MODES = ("Folder or file", "Git history", "Staged changes")
_REPORT_FORMATS = ("Text", "JSON", "SARIF")

_ABOUT = (
    "Secrety scans source code and Git history for exposed secrets, with a confidence score.",
    "Pick a mode, give it a path, and get findings grouped by file.",
    "Secrets are always masked: the raw value is never printed or saved.",
    "Same engine as `secrety scan`; use that command for fine-tuning and CI.",
)

_CLEAR_SCREEN = "\x1b[2J\x1b[3J\x1b[H"


class _Results(NamedTuple):
    findings: list[Finding]
    stats: ScanStats


def _load_config(path: Path, staged: bool) -> FileConfig:
    if staged:
        root = repo_root(path)
        text = staged_file_text(root, CONFIG_FILE_NAME)
        return FileConfig() if text is None else parse_file_config(text, root / CONFIG_FILE_NAME)
    return load_file_config(None, path)


def _scan(mode: int, path: Path, max_commits: int | None) -> _Results:
    """Run the same pipeline as `secrety scan` with default settings; ValueError on failure."""
    detectors = [RegexDetector(load_rules(None)), EntropyDetector(EntropyConfig())]
    config = _load_config(path, staged=mode == 2)
    if mode == 1:
        # Imported here: GitPython fails at import time when git is not installed.
        from secrety.sources.git import scan_history

        history = scan_history(path, detectors, max_commits=max_commits)
        findings, stats = history.findings, history.stats
    else:
        source = StagedSource(path) if mode == 2 else FilesystemSource(path)
        result = run_scan(source, detectors)
        findings, stats = result.findings, result.stats
    return _Results(config.allowlist.apply(findings).kept, stats)


def _summary(stats: ScanStats) -> str:
    scanned = (
        f"{stats.scanned} file change(s) in {stats.commits} commit(s)"
        if stats.commits
        else f"{stats.scanned} file(s)"
    )
    return (
        f"{scanned} scanned, {stats.skipped_binary} binary and "
        f"{stats.skipped_large} large file(s) skipped."
    )


def _ask_scan(mode: int, input_fn: InputFn, print_fn: PrintFn) -> _Results | None:
    """Asks the mode's questions and scans; returns None if an error was shown."""
    path = Path(ask("Path", default=".", input_fn=input_fn, print_fn=print_fn))
    max_commits: int | None = None
    if mode == 1:
        raw = ask("Newest commits to scan", input_fn=input_fn, print_fn=print_fn)
        if raw:
            if not raw.isdigit() or int(raw) < 1:
                print_fn("Error: enter a whole number >= 1, or ENTER for the whole history.")
                return None
            max_commits = int(raw)
    if not path.exists():
        print_fn(f"Error: '{safe(str(path))}' does not exist.")
        return None
    try:
        results = _scan(mode, path, max_commits)
    except ValueError as error:
        print_fn(f"Error: {safe(str(error))}")
        return None
    color = sys.stdout.isatty()
    if results.findings:
        print_fn("\n" + render_cards(results.findings, color=color))
        print_fn(f"\n{len(results.findings)} potential secret(s) found. {_summary(results.stats)}")
    else:
        print_fn(f"\nNo secret found. {_summary(results.stats)}")
    return results


def _document(findings: Sequence[Finding], fmt: int) -> str:
    if fmt == 1:
        return render_json(findings)
    if fmt == 2:
        return render_sarif(findings)
    buffer = io.StringIO()
    render_text(Console(file=buffer, highlight=False, emoji=False, width=10_000), findings)
    return buffer.getvalue()


def _save_report(results: _Results, input_fn: InputFn, print_fn: PrintFn) -> None:
    fmt = choose(
        "Report format", _REPORT_FORMATS, back="Cancel", input_fn=input_fn, print_fn=print_fn
    )
    if fmt is None:
        return
    target = Path(ask("Output file", optional=False, input_fn=input_fn, print_fn=print_fn))
    try:
        with target.open("x", encoding="utf-8") as handle:  # never overwrites
            handle.write(_document(results.findings, fmt))
    except FileExistsError:
        print_fn(f"Error: '{safe(str(target))}' already exists.")
    except OSError as error:
        print_fn(f"Error: cannot write '{safe(str(target))}': {safe(str(error))}")
    else:
        print_fn(f"Report saved to '{safe(str(target))}'.")


def _after_results(results: _Results, mode: int, input_fn: InputFn, print_fn: PrintFn) -> bool:
    """Results submenu; True = run another scan in the same mode."""
    while True:
        choice = choose(
            "What now?",
            ["Save a report (text, JSON or SARIF)", f"New scan ({MODES[mode]})"],
            back="Main menu",
            input_fn=input_fn,
            print_fn=print_fn,
        )
        if choice is None:
            return False
        if choice == 1:
            return True
        _save_report(results, input_fn, print_fn)


def show_banner(print_fn: PrintFn) -> None:
    """Clear the screen and print the banner."""
    print_fn(
        _CLEAR_SCREEN + "\n" + banner(color=sys.stdout.isatty()).rstrip("\n")
    )  # the menu adds its own leading blank line


def run(input_fn: InputFn = input, print_fn: PrintFn = print) -> None:
    """Main loop: scan mode -> scan -> results submenu, until the user quits."""

    def show_about() -> None:
        print_fn("\n" + render_info("About secrety", _ABOUT, color=sys.stdout.isatty()))

    show_banner(print_fn)
    while (
        mode := choose(
            "Scan mode",
            MODES,
            back="Quit",
            on_info=show_about,
            input_fn=input_fn,
            print_fn=print_fn,
        )
    ) is not None:
        while (results := _ask_scan(mode, input_fn, print_fn)) is not None:
            if not _after_results(results, mode, input_fn, print_fn):
                break
        show_banner(print_fn)
