"""The synthetic corpus: determinism, ground truth, held-out families, no label leak."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

import pytest
from evaluation.corpus import (
    DECOY_FAMILIES,
    FILES_DIR,
    HEADER_TEXT,
    POSITIVE_FAMILIES,
    Candidate,
    generate_corpus,
    load_ground_truth,
)

N_FILES = 40


def snapshot(root: Path) -> dict[str, bytes]:
    return {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def test_same_seed_gives_identical_bytes(tmp_path: Path) -> None:
    generate_corpus(tmp_path / "a", seed=7, split="train", n_files=N_FILES)
    generate_corpus(tmp_path / "b", seed=7, split="train", n_files=N_FILES)
    assert snapshot(tmp_path / "a") == snapshot(tmp_path / "b")


def test_different_seed_gives_different_corpus(tmp_path: Path) -> None:
    generate_corpus(tmp_path / "a", seed=7, split="train", n_files=N_FILES)
    generate_corpus(tmp_path / "b", seed=8, split="train", n_files=N_FILES)
    assert snapshot(tmp_path / "a") != snapshot(tmp_path / "b")


def test_ground_truth_is_written_and_loadable(tmp_path: Path) -> None:
    written = generate_corpus(tmp_path, seed=1, split="train", n_files=N_FILES)
    assert (tmp_path / "ground_truth.json").is_file()
    data = json.loads((tmp_path / "ground_truth.json").read_text(encoding="utf-8"))
    assert data["seed"] == 1
    assert data["split"] == "train"
    assert load_ground_truth(tmp_path) == written


def test_ground_truth_points_at_the_value(tmp_path: Path) -> None:
    candidates = generate_corpus(tmp_path, seed=1, split="train", n_files=N_FILES)
    assert candidates
    for c in candidates:
        lines = (tmp_path / FILES_DIR / c.path).read_text(encoding="utf-8").split("\n")
        assert c.value.split("\n")[0] in lines[c.line - 1]
        assert c.line <= c.end_line <= len(lines)


def test_both_labels_and_every_family_are_present(tmp_path: Path) -> None:
    candidates = generate_corpus(tmp_path, seed=1, split="test", n_files=200)
    assert {c.label for c in candidates} == {"secret", "decoy"}
    families = {c.family for c in candidates}
    assert families == {f.name for f in POSITIVE_FAMILIES + DECOY_FAMILIES}


def test_held_out_decoy_families_are_only_in_test(tmp_path: Path) -> None:
    held_out = {f.name for f in DECOY_FAMILIES if f.held_out}
    assert held_out
    train = generate_corpus(tmp_path / "train", seed=1, split="train", n_files=200)
    test = generate_corpus(tmp_path / "test", seed=2, split="test", n_files=200)
    assert not held_out & {c.family for c in train}
    assert held_out <= {c.family for c in test}


def test_candidates_never_share_a_line(tmp_path: Path) -> None:
    candidates = generate_corpus(tmp_path, seed=3, split="test", n_files=N_FILES)
    taken: set[tuple[str, int]] = set()
    for c in candidates:
        lines = {(c.path, n) for n in range(c.line, c.end_line + 1)}
        assert not lines & taken
        taken |= lines


def test_values_carry_no_marker_word(tmp_path: Path) -> None:
    candidates = generate_corpus(tmp_path, seed=1, split="test", n_files=200)
    for c in candidates:
        for word in ("fake", "example", "test"):
            # decoy families may be about test data on purpose; secrets never are
            if c.label == "secret":
                assert word not in c.value.lower(), (c.family, word)


def test_marker_is_a_header_identical_for_both_labels(tmp_path: Path) -> None:
    candidates = generate_corpus(tmp_path, seed=1, split="test", n_files=200)
    labels_by_file: dict[str, set[str]] = defaultdict(set)
    for c in candidates:
        labels_by_file[c.path].add(c.label)
    headed = 0
    for path in labels_by_file:
        first = (tmp_path / FILES_DIR / path).read_text(encoding="utf-8").split("\n", 1)[0]
        if HEADER_TEXT in first:
            headed += 1
    assert headed
    # the header depends on the file type only, so it cannot tell the labels apart:
    # each file type holds both labels
    kinds_by_label: dict[str, set[str]] = defaultdict(set)
    for c in candidates:
        kinds_by_label[c.label].add(Path(c.path).suffix)
    assert kinds_by_label["secret"] == kinds_by_label["decoy"]


def test_file_types_are_spread_alike_for_both_labels(tmp_path: Path) -> None:
    candidates = generate_corpus(tmp_path, seed=1, split="test", n_files=300)
    count: Counter[tuple[str, str]] = Counter((c.label, Path(c.path).suffix) for c in candidates)
    for suffix in {Path(c.path).suffix for c in candidates}:
        secret, decoy = count[("secret", suffix)], count[("decoy", suffix)]
        assert secret and decoy, suffix
        assert 0.25 < secret / (secret + decoy) < 0.85, (suffix, secret, decoy)


def test_candidate_dataclass_round_trip() -> None:
    c = Candidate("a.py", 2, 2, "secret", "github_token", "v")
    assert Candidate(**c.__dict__) == c


@pytest.mark.parametrize("split", ["train", "test"])
def test_split_is_recorded_and_validated(tmp_path: Path, split: str) -> None:
    generate_corpus(tmp_path, seed=1, split=split, n_files=5)
    assert json.loads((tmp_path / "ground_truth.json").read_text("utf-8"))["split"] == split


def test_unknown_split_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="split"):
        generate_corpus(tmp_path, seed=1, split="dev", n_files=5)


def test_ground_truth_is_outside_the_scanned_files(tmp_path: Path) -> None:
    generate_corpus(tmp_path, seed=1, split="train", n_files=5)
    assert not list((tmp_path / FILES_DIR).rglob("ground_truth.json"))
