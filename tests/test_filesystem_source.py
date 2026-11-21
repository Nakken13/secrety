import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from secrety.sources import FilesystemSource, Source, SourceFile
from secrety.sources.filesystem import _is_link


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


@pytest.mark.skipif(sys.platform != "win32", reason="NTFS junctions are Windows-only")
def test_does_not_follow_windows_junctions(tmp_path: Path) -> None:
    # Junctions need no admin privilege, unlike symlinks, and Python 3.11's
    # os.walk(followlinks=False) / is_symlink() do not recognise them.
    write(tmp_path, "outside/secret.txt", "x")
    root = tmp_path / "root"
    write(root, "inside.txt", "y")
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(root / "j"), str(tmp_path / "outside")],
        check=True,
        capture_output=True,
    )
    source = FilesystemSource(root)
    assert paths(source) == ["inside.txt"]
    assert source.stats.skipped_links == 1


def test_unreadable_file_is_counted_and_scan_continues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path, "a.txt", "a")
    write(tmp_path, "locked.txt", "b")
    write(tmp_path, "z.txt", "z")
    real_open = Path.open

    def fake_open(self: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        if self.name == "locked.txt":
            raise PermissionError("denied")
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", fake_open)
    source = FilesystemSource(tmp_path)
    assert paths(source) == ["a.txt", "z.txt"]
    assert source.stats.unreadable == 1


def test_unreadable_directory_is_counted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(tmp_path, "a.txt", "a")
    real_walk = os.walk

    def walk_with_error(top: object, **kwargs: object):  # type: ignore[no-untyped-def]
        onerror = kwargs.get("onerror")
        assert callable(onerror), "os.walk must be given an onerror callback"
        onerror(PermissionError("denied"))
        yield from real_walk(top, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(os, "walk", walk_with_error)
    source = FilesystemSource(tmp_path)
    assert paths(source) == ["a.txt"]
    assert source.stats.unreadable == 1


def test_utf16_file_with_bom_is_text_not_binary(tmp_path: Path) -> None:
    write(tmp_path, "ps.txt", "token = abc\n".encode("utf-16"))
    (file,) = FilesystemSource(tmp_path)
    assert file.text == "token = abc\n"


def test_stats_are_reset_on_each_iteration(tmp_path: Path) -> None:
    write(tmp_path, "a.txt", "a")
    source = FilesystemSource(tmp_path)
    list(source)
    list(source)
    assert source.stats.scanned == 1


def test_explicit_symlink_root_is_followed(tmp_path: Path) -> None:
    target = write(tmp_path, "real.env", "A=1")
    link = tmp_path / "link.env"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation not permitted")
    assert paths(FilesystemSource(link)) == ["link.env"]


def test_source_file_commit_defaults_to_none() -> None:
    assert SourceFile(path="a", text="b").commit is None


def test_filesystem_source_satisfies_source_protocol(tmp_path: Path) -> None:
    assert isinstance(FilesystemSource(tmp_path), Source)


def fake_stat(mode: int, attributes: int = 0, tag: int = 0) -> os.stat_result:
    return SimpleNamespace(  # type: ignore[return-value]
        st_mode=mode, st_file_attributes=attributes, st_reparse_tag=tag
    )


_REPARSE = 0x400  # FILE_ATTRIBUTE_REPARSE_POINT


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        (fake_stat(stat.S_IFREG), False),
        (fake_stat(stat.S_IFLNK), True),
        (fake_stat(stat.S_IFDIR, _REPARSE, 0xA0000003), True),  # junction (mount point)
        (fake_stat(stat.S_IFREG, _REPARSE, 0xA000000C), True),  # symlink
        # OneDrive / cloud placeholder: a real file stored elsewhere, not a link.
        (fake_stat(stat.S_IFREG, _REPARSE, 0x9000001A), False),
        # Deduplicated file (Windows Server data deduplication).
        (fake_stat(stat.S_IFREG, _REPARSE, 0x80000013), False),
    ],
)
def test_only_name_surrogate_reparse_points_are_links(info: os.stat_result, expected: bool) -> None:
    assert _is_link(info) is expected


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlink support")
def test_skipped_symlinks_are_counted(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    try:
        (root / "link.txt").symlink_to(outside)
        (root / "linkdir").symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation not permitted")
    source = FilesystemSource(root)
    assert paths(source) == []
    assert source.stats.skipped_links == 2
