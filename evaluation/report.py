"""Run the whole evaluation and write ``docs/results/`` (table, JSON, plots).

Reproducible command (from the repository root, with the benchmark tools
installed under ``evaluation/tools/``, see ``docs/results/README.md``)::

    python -m evaluation.report --out docs/results

The corpora are generated at runtime into ``evaluation/corpora/`` and the tools'
raw reports are kept in ``evaluation/results/raw/``; both are gitignored.
"""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

from evaluation import benchmark
from evaluation.corpus import (
    DECOY_FAMILIES,
    DEFAULT_FILES,
    FILES_DIR,
    POSITIVE_FAMILIES,
    TEST_SEED,
    TRAIN_SEED,
    generate_corpus,
)
from evaluation.detect import VARIANTS, run_variant
from evaluation.metrics import Row, Scores, family_report, score, score_locations
from evaluation.plots import plot_comparison, plot_family_rates
from secrety.classifier import load_classifier

TIMING_SEED = 4
RAW_DIR = Path(__file__).parent / "results" / "raw"


def format_table(rows: list[Row]) -> str:
    """Markdown table of precision, recall, F1 and the raw counts."""
    lines = [
        "| Configuration | Precision | Recall | F1 | TP | FP | FN |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in rows:
        s = r.scores
        lines.append(
            f"| {r.name} | {s.precision:.3f} | {s.recall:.3f} | {s.f1:.3f} "
            f"| {s.tp} | {s.fp} | {s.fn} |"
        )
    return "\n".join(lines)


def family_table(
    before: dict[str, tuple[int, int]],
    after: dict[str, tuple[int, int]],
    verb: str = "Flagged",
) -> str:
    """Markdown table ``family | before | after`` (hits/total); ``verb`` names the hits."""
    lines = [
        f"| Family | {verb} without classifier | {verb} with classifier |",
        "| --- | ---: | ---: |",
    ]
    for name, (hits, total) in before.items():
        lines.append(f"| {name} | {hits}/{total} | {after[name][0]}/{after[name][1]} |")
    return "\n".join(lines)


def _time_tools(files_dir: Path, runs: int) -> dict[str, float]:
    """Median wall-clock seconds of each tool scanning ``files_dir`` as a subprocess."""
    with tempfile.TemporaryDirectory() as tmp:
        config = Path(tmp) / "secrety.toml"
        config.write_text("[allowlist]\nuse_defaults = false\n", encoding="utf-8")
        secrety_cmd = [
            sys.executable, "-m", "secrety", "scan", str(files_dir), "--config", str(config),
            "--format", "json", "--output", str(Path(tmp) / "report.json"),
        ]  # fmt: skip

        def secrety() -> None:
            done = subprocess.run(secrety_cmd, capture_output=True, check=False)
            # exit 1 means "secrets found"; anything else is a crash, not a fast scan
            if done.returncode not in (0, 1) or not (Path(tmp) / "report.json").exists():
                raise RuntimeError(f"secrety failed: {done.stderr.decode(errors='replace')[:300]}")

        def gitleaks() -> None:
            cmd = benchmark.gitleaks_command(files_dir, Path(tmp) / "gl.json")
            subprocess.run(cmd, capture_output=True, check=True)

        def trufflehog() -> None:
            subprocess.run(benchmark.trufflehog_command(files_dir), capture_output=True, check=True)

        return {
            "secrety (combined)": benchmark.median_seconds(secrety, runs),
            "gitleaks": benchmark.median_seconds(gitleaks, runs),
            "trufflehog": benchmark.median_seconds(trufflehog, runs),
        }


def _as_dict(scores: Scores) -> dict[str, float]:
    return {
        "tp": scores.tp,
        "fp": scores.fp,
        "fn": scores.fn,
        "precision": round(scores.precision, 4),
        "recall": round(scores.recall, 4),
        "f1": round(scores.f1, 4),
    }


def main(argv: list[str] | None = None) -> None:
    """Generate corpora, score every configuration and write the results folder."""
    parser = argparse.ArgumentParser(description="Run the secrety evaluation.")
    parser.add_argument("--out", type=Path, default=Path("docs/results"))
    parser.add_argument("--files", type=int, default=DEFAULT_FILES)
    parser.add_argument("--timing-files", type=int, default=1500)
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args(argv)

    corpus_root = Path(__file__).parent / "corpora"
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    args.out.mkdir(parents=True, exist_ok=True)
    model = load_classifier()

    splits = {}
    for split, seed in (("train", TRAIN_SEED), ("test", TEST_SEED)):
        root = corpus_root / split
        splits[split] = (root, generate_corpus(root, seed, split, args.files))
    test_dir, test_truth = splits["test"]
    train_truth = splits["train"][1]

    findings = {
        (split, v): run_variant(root / FILES_DIR, v, model if "classifier" in v else None)
        for split, (root, _) in splits.items()
        for v in VARIANTS
    }
    secrety_rows = {
        split: [Row(v, score(findings[(split, v)], truth)) for v in VARIANTS]
        for split, (_, truth) in splits.items()
    }

    files = test_dir / FILES_DIR
    gl_locations, gl_raw = benchmark.run_gitleaks(files)
    th_locations, th_raw = benchmark.run_trufflehog(files)
    (RAW_DIR / "gitleaks.json").write_text(gl_raw, encoding="utf-8")
    (RAW_DIR / "trufflehog.jsonl").write_text(th_raw, encoding="utf-8")
    test_rows = secrety_rows["test"] + [
        Row("gitleaks", score_locations(gl_locations, test_truth)),
        Row("trufflehog", score_locations(th_locations, test_truth)),
    ]

    decoys = [f.name for f in DECOY_FAMILIES]
    before = family_report(findings[("test", "combined")], test_truth)
    after = family_report(findings[("test", "combined+classifier")], test_truth)
    secrets = [f.name for f in POSITIVE_FAMILIES]
    secret_before = {n: before[n] for n in secrets}
    secret_after = {n: after[n] for n in secrets}
    decoy_before = {n: before[n] for n in decoys}
    decoy_after = {n: after[n] for n in decoys}

    timing_root = corpus_root / "timing"
    generate_corpus(timing_root, TIMING_SEED, "test", args.timing_files)
    seconds = _time_tools(timing_root / FILES_DIR, args.runs)
    n_files = sum(1 for p in (timing_root / FILES_DIR).rglob("*") if p.is_file())
    versions = {t: benchmark.tool_version(t) for t in benchmark.PINNED_VERSIONS}
    for tool, pinned in benchmark.PINNED_VERSIONS.items():
        if pinned not in versions[tool]:
            raise RuntimeError(f"{tool} reports {versions[tool]!r}, the results pin {pinned}")

    results = {
        "model": {"threshold": model.threshold, "stub": model.stub},
        "seeds": {"train": TRAIN_SEED, "test": TEST_SEED, "timing": TIMING_SEED},
        "corpus": {
            "test_files": args.files,
            "test_secrets": sum(c.label == "secret" for c in test_truth),
            "test_decoys": sum(c.label == "decoy" for c in test_truth),
            "train_secrets": sum(c.label == "secret" for c in train_truth),
            "train_decoys": sum(c.label == "decoy" for c in train_truth),
        },
        "test": {r.name: _as_dict(r.scores) for r in test_rows},
        "train": {r.name: _as_dict(r.scores) for r in secrety_rows["train"]},
        "timing_seconds": {k: round(v, 3) for k, v in seconds.items()},
        "timing_files": n_files,
        "versions": versions,
        "machine": f"{platform.system()} {platform.release()}, Python {platform.python_version()}",
    }
    (args.out / "results.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    plot_comparison(test_rows, args.out / "comparison.png")
    plot_family_rates(decoy_before, decoy_after, args.out / "false-positives-by-family.png")
    timing = "\n".join(f"| {k} | {v:.2f} |" for k, v in seconds.items())
    (args.out / "results.md").write_text(
        "# Results (generated, do not edit)\n\n"
        "## Held-out test corpus\n\n" + format_table(test_rows) + "\n\n"
        "## Train corpus (secrety only)\n\n" + format_table(secrety_rows["train"]) + "\n\n"
        "## Decoy families on the test corpus\n\n"
        + family_table(decoy_before, decoy_after)
        + "\n\n"
        "## Secret families on the test corpus\n\n"
        + family_table(secret_before, secret_after, verb="Found")
        + "\n\n"
        f"## Time on {n_files} files (median of {args.runs} runs, whole process)\n\n"
        "| Tool | Seconds |\n| --- | ---: |\n" + timing + "\n\n"
        f"Versions: gitleaks {versions['gitleaks']}, {versions['trufflehog']} "
        "(trufflehog with `--no-verification`).\n",
        encoding="utf-8",
    )
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
