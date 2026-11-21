"""Run gitleaks and trufflehog on a corpus and normalise what they report.

Both tools are used as released, with default configuration and, for
trufflehog, ``--no-verification`` (verification calls the services, which
fake credentials cannot and must not do). Their reports are reduced to
``(path, line)`` locations so :mod:`evaluation.metrics` scores every tool the
same way. Versions are read from the binaries and recorded with the results.
"""

from __future__ import annotations

import json
import statistics
import subprocess
import tempfile
import time
from collections.abc import Callable
from pathlib import Path, PurePosixPath, PureWindowsPath

from evaluation.metrics import Location

TOOLS_DIR = Path(__file__).parent / "tools"
GITLEAKS_VERSION = "8.30.1"
TRUFFLEHOG_VERSION = "3.100.0"
PINNED_VERSIONS = {"gitleaks": GITLEAKS_VERSION, "trufflehog": TRUFFLEHOG_VERSION}


def _relative(raw: str, root: Path) -> str:
    """Return ``raw`` (any separator, absolute or relative to the cwd) relative to ``root``."""
    resolved = Path.cwd().joinpath(PureWindowsPath(raw).as_posix()).resolve()
    return PurePosixPath(resolved.relative_to(root.resolve())).as_posix()


def parse_gitleaks(report: str, root: Path) -> set[Location]:
    """Locations of a gitleaks JSON report; a multi-line finding covers each of its lines."""
    if not report.strip():
        return set()
    found: set[Location] = set()
    for item in json.loads(report):
        path = _relative(item["File"], root)
        found.update((path, n) for n in range(item["StartLine"], item["EndLine"] + 1))
    return found


def parse_trufflehog(output: str, root: Path) -> set[Location]:
    """Locations of trufflehog's JSON-lines output; log lines are ignored."""
    found: set[Location] = set()
    for line in output.splitlines():
        if not line.strip():
            continue
        data = json.loads(line)
        meta = data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem")
        if meta:
            found.add((_relative(meta["file"], root), int(meta["line"])))
    return found


def median_seconds(run: Callable[[], object], runs: int = 3) -> float:
    """Wall-clock seconds of ``run()``, median over ``runs`` calls."""
    if runs < 1:
        raise ValueError(f"runs must be >= 1, got {runs}")
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        run()
        times.append(time.perf_counter() - start)
    return statistics.median(times)


def _exe(tool: str) -> Path:
    for name in (f"{tool}.exe", tool):
        path = TOOLS_DIR / tool / name
        if path.exists():
            return path
    raise FileNotFoundError(
        f"{tool} not found under {TOOLS_DIR / tool}; see docs/results/README.md"
    )


def gitleaks_command(files_dir: Path, report: Path) -> list[str]:
    """Command line that scans ``files_dir`` and writes a JSON report."""
    return [
        str(_exe("gitleaks")), "dir", str(files_dir), "--no-banner", "--exit-code", "0",
        "--log-level", "error", "-f", "json", "-r", str(report),
    ]  # fmt: skip


def trufflehog_command(files_dir: Path) -> list[str]:
    """Command line that scans ``files_dir`` and prints JSON lines on stdout."""
    return [
        str(_exe("trufflehog")), "filesystem", str(files_dir), "--json",
        "--no-verification", "--no-update",
    ]  # fmt: skip


def run_gitleaks(files_dir: Path) -> tuple[set[Location], str]:
    """Scan with gitleaks; return the locations and the raw report text."""
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        subprocess.run(gitleaks_command(files_dir, report), check=True, capture_output=True)
        text = report.read_text(encoding="utf-8") if report.exists() else ""
    return parse_gitleaks(text, files_dir), text


def run_trufflehog(files_dir: Path) -> tuple[set[Location], str]:
    """Scan with trufflehog; return the locations and the raw output."""
    done = subprocess.run(
        trufflehog_command(files_dir), check=True, capture_output=True, text=True, encoding="utf-8"
    )
    return parse_trufflehog(done.stdout, files_dir), done.stdout


def tool_version(tool: str) -> str:
    """Version string the binary reports about itself."""
    args = ["version"] if tool == "gitleaks" else ["--version"]
    done = subprocess.run([str(_exe(tool)), *args], capture_output=True, text=True, check=True)
    return (done.stdout + done.stderr).strip().splitlines()[0]
