import os
from pathlib import Path

import pytest

from secrety.sources import FilesystemSource, SourceFile


def write(root: Path, rel: str, content: str | bytes) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8", newline="")
    return path


def paths(source: FilesystemSource) -> list[str]:
    return [f.path for f in source]


def test_yields_text_files_with_posix_relative_paths(tmp_path: Path) -> None:
    write(tmp_path, "a.py", "x = 1\n")
    write(tmp_path, "pkg/sub/b.txt", "hello\n")
    files = list(FilesystemSource(tmp_path))
    assert files == [
        SourceFile(path="a.py", text="x = 1\n"),
        SourceFile(path="pkg/sub/b.txt", text="hello\n"),
    ]


def test_skips_binary_files(tmp_path: Path) -> None:
    write(tmp_path, "image.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00")
    write(tmp_path, "ok.txt", "text")
    source = FilesystemSource(tmp_path)
    assert paths(source) == ["ok.txt"]
    assert source.stats.skipped_binary == 1


def test_skips_files_over_size_limit(tmp_path: Path) -> None:
    write(tmp_path, "big.txt", "a" * 101)
    write(tmp_path, "small.txt", "a" * 100)
    source = FilesystemSource(tmp_path, max_file_size=100)
    assert paths(source) == ["small.txt"]
    assert source.stats.skipped_large == 1


def test_prunes_excluded_directories(tmp_path: Path) -> None:
    write(tmp_path, ".git/config", "x")
    write(tmp_path, "node_modules/lib/index.js", "x")
    write(tmp_path, "src/node_modules_helper.py", "x")
    assert paths(FilesystemSource(tmp_path)) == ["src/node_modules_helper.py"]


def test_custom_excluded_dirs(tmp_path: Path) -> None:
    write(tmp_path, "vendor/x.py", "x")
    write(tmp_path, "keep/x.py", "x")
    assert paths(FilesystemSource(tmp_path, excluded_dirs={"vendor"})) == ["keep/x.py"]


def test_invalid_utf8_is_replaced_not_fatal(tmp_path: Path) -> None:
    write(tmp_path, "latin1.txt", "caf\xe9".encode("latin-1"))
    (file,) = FilesystemSource(tmp_path)
    assert file.text.startswith("caf")


def test_single_file_root(tmp_path: Path) -> None:
    target = write(tmp_path, "dir/one.env", "A=1")
    assert list(FilesystemSource(target)) == [SourceFile(path="one.env", text="A=1")]


def test_counts_scanned_files(tmp_path: Path) -> None:
    write(tmp_path, "a.txt", "a")
    write(tmp_path, "b.txt", "b")
    source = FilesystemSource(tmp_path)
    list(source)
    assert source.stats.scanned == 2


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlink support")
def test_does_not_follow_symlinks(tmp_path: Path) -> None:
    outside = write(tmp_path, "outside/secret.txt", "x")
    root = tmp_path / "root"
    root.mkdir()
    try:
        (root / "link.txt").symlink_to(outside)
        (root / "linkdir").symlink_to(outside.parent, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation not permitted")
    assert paths(FilesystemSource(root)) == []


def test_missing_root_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        list(FilesystemSource(tmp_path / "nope"))
