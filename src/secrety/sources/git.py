"""Read the lines added by each commit of a Git repository.

Only what a commit *adds* is scanned, not the full tree at every commit: a
secret is reported once, at the commit that introduced it, and the cost is
proportional to the size of the history's diffs, not to tree x commits.

Imported only when ``--git`` is used, so a missing ``git`` executable never
breaks a plain folder scan.
"""

from __future__ import annotations

import codecs
import re
import subprocess
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path

import git

from secrety.models import Finding
from secrety.sources.base import ScanStats, SourceFile
from secrety.sources.filesystem import DEFAULT_MAX_FILE_SIZE, decode, is_binary

# Start of each commit in the log output. \x01 cannot start a patch line,
# which always begins with "+", "-", " ", "@", "\\", "diff" or a header word.
_COMMIT_MARK = b"\x01"
_LOG_FORMAT = "%x01%H%x00%an <%ae>%x00%aI"
# "@@ -a,b +c,d @@" (one parent) or "@@@ -a,b -c,d +e,f @@@" (merge).
_HUNK = re.compile(rb"^(@{2,}) (?:-\d+(?:,\d+)? )+\+(\d+)(?:,\d+)? @{2,}")


def _new_path(header: bytes) -> str:
    """Path from a ``+++ b/<path>`` header, without its ``b/`` prefix.

    Git C-style quotes a path with unusual bytes (octal escapes for UTF-8,
    backslash escapes for quotes) and appends a tab to a path containing a space.
    """
    header = header.removesuffix(b"\t")
    if header.startswith(b'"') and header.endswith(b'"'):
        header = codecs.escape_decode(header[1:-1])[0]
    return header.removeprefix(b"b/").decode("utf-8", errors="replace")


@dataclass
class _Pending:
    """The added lines of one file in one commit, collected while parsing."""

    path: str | None = None
    lines: list[tuple[int, str]] = field(default_factory=list)
    size: int = 0  # bytes of added lines, to enforce max_file_size
    binary: bool = False
    too_large: bool = False

    def add(self, number: int, raw: bytes, max_size: int) -> None:
        """Record one added line.

        Everything is dropped once ``max_size`` is passed, or when a line holds
        a NUL byte (binary content, detected here because ``git log --text``
        ignores the repository's own, untrusted, binary attributes).
        """
        if self.too_large or self.binary:
            return
        if is_binary(raw):
            self.binary = True
            self.lines.clear()
            return
        self.size += len(raw) + 1
        if self.size > max_size:
            self.too_large = True
            self.lines.clear()
        else:
            self.lines.append((number, decode(raw)))

    def text(self) -> str:
        """Added lines at their line number in the new file, blank lines between.

        Detectors number lines from the text they get, so padding keeps every
        finding at the line it has in ``git show <sha>:<path>``.
        """
        parts: list[str] = []
        current = 1
        for number, line in self.lines:
            parts.append("\n" * (number - current))
            parts.append(line)
            current = number
        return "".join(parts)


@dataclass
class _Commit:
    sha: str
    author: str
    date: str


@dataclass
class GitSource:
    """Iterate over the lines added by every commit reachable from ``HEAD``.

    Other branches and tags are not scanned unless merged into ``HEAD``.

    Yields one :class:`SourceFile` per (commit, file), newest commit first.

    Attributes:
        root: The repository, or a folder inside it (the history is then
            limited to that folder). Paths are relative to the repository root.
        max_commits: Scan only this many commits, newest first.
        since: Scan only commits more recent than this date (committer date,
            as ``git log --since``).
        max_file_size: Skip a file version whose added lines exceed this size.
    """

    root: Path
    max_commits: int | None = None
    since: datetime | None = None
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    stats: ScanStats = field(default_factory=ScanStats)

    def __iter__(self) -> Iterator[SourceFile]:
        """Yield the added lines of each file changed by each commit."""
        self.stats = ScanStats()
        with self._open() as repo:
            if not repo.head.is_valid():
                raise ValueError(f"{self.root}: the repository has no commits")
            process = repo.git.log(*self._log_args(repo), as_process=True)
            finished = False
            try:
                yield from self._parse(process.proc.stdout)  # type: ignore[arg-type]
                finished = True
            finally:
                if finished:
                    process.wait()  # raises GitCommandError on a git failure
                else:  # consumer stopped early or failed: do not mask its error
                    process.proc.kill()
                    process.proc.communicate()

    def mark_removed(self, findings: Sequence[Finding]) -> list[Finding]:
        """Set :attr:`~secrety.models.Finding.removed_later` on history findings.

        A secret is "removed later" when it appears in no text file of
        ``HEAD``, at any path: one moved to another file is still exposed.
        Multi-line secrets are looked up by their longest line. Findings
        without a commit (from a folder scan) are returned unchanged.
        """
        probes = {f.secret: max(f.secret.split("\n"), key=len) for f in findings if f.commit}
        if not probes:
            return list(findings)
        with self._open() as repo:
            lines = self._grep_head(repo, sorted(set(probes.values())))
        present = {secret for secret, probe in probes.items() if any(probe in x for x in lines)}
        return [
            replace(f, removed_later=f.secret not in present) if f.commit else f for f in findings
        ]

    @staticmethod
    def _grep_head(repo: git.Repo, patterns: list[str]) -> list[str]:
        """Return the lines of ``HEAD`` containing one of ``patterns`` (fixed strings).

        Patterns go through stdin, never the command line, where other local
        users could read the secrets in the process list. ``-a`` searches
        every file, whatever the repository's attributes say is binary.
        """
        process = repo.git.grep(
            "-a",
            "-F",
            "-h",
            "--no-color",
            "--no-textconv",
            "-f",
            "-",
            "HEAD",
            "--",
            as_process=True,
            istream=subprocess.PIPE,
        )
        data = "\n".join(patterns).encode("utf-8") + b"\n"
        out, err = process.proc.communicate(data)
        if process.proc.returncode not in (0, 1):  # 1 means "no match"
            raise git.GitCommandError(["git", "grep"], process.proc.returncode, err)
        return decode(out).split("\n")

    def _open(self) -> git.Repo:
        try:
            start = self.root if self.root.is_dir() else self.root.parent
            return git.Repo(start, search_parent_directories=True)
        except (git.InvalidGitRepositoryError, git.NoSuchPathError) as exc:
            raise ValueError(f"{self.root}: not a Git repository") from exc

    def is_shallow(self) -> bool:
        """True for a shallow clone, whose history is truncated.

        The oldest commit of a shallow clone looks like it adds every file, so
        findings there may in fact be older.
        """
        with self._open() as repo:
            return repo.git.rev_parse("--is-shallow-repository") == "true"

    def _log_args(self, repo: git.Repo) -> list[str]:
        # The repository is untrusted input: external diff drivers and
        # textconv filters it configures must never run; prefixes, colors and
        # rename detection are forced whatever the user's config says.
        args = [
            "--patch",
            "--cc",  # merges: only lines that are new compared with every parent
            "--root",  # the first commit's diff, even with log.showRoot=false
            "--full-history",  # a path filter must not drop merged side branches
            "--text",  # repository attributes must not hide files as binary
            "--encoding=UTF-8",  # ignore i18n.logOutputEncoding
            "--unified=0",
            "--find-renames",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--no-show-signature",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            f"--format={_LOG_FORMAT}",
        ]
        if self.max_commits is not None:
            args.append(f"--max-count={self.max_commits}")
        if self.since is not None:
            args.append(f"--since={self.since.isoformat()}")
        args += ["HEAD", "--"]
        top = Path(repo.working_tree_dir or self.root).resolve()
        here = self.root.resolve()
        if here != top:
            # :(literal) so a folder named like a pathspec magic is taken as is.
            args.append(f":(literal){here.relative_to(top).as_posix()}")
        return args

    def _parse(self, stream: Iterable[bytes]) -> Iterator[SourceFile]:
        """Turn ``git log --patch --cc`` output into one file per (commit, path).

        In a hunk, each line starts with one marker column per parent (one for
        a normal commit, two or more for a merge). A ``-`` in any column means
        the line is not in the new file; ``+`` in every column means it is new
        compared with all parents, the only case reported. A line from a
        merged branch shows ``+`` in some columns only: it was already
        reported at the branch commit that added it.
        """
        commit: _Commit | None = None
        pending = _Pending()
        in_hunk = False
        parents = 1
        new_line = 0

        def flush() -> Iterator[SourceFile]:
            if pending.binary:
                self.stats.skipped_binary += 1
            elif pending.too_large:
                self.stats.skipped_large += 1
            elif commit and pending.path and pending.lines:
                self.stats.scanned += 1
                yield SourceFile(
                    path=pending.path,
                    text=pending.text(),
                    commit=commit.sha,
                    author=commit.author,
                    date=commit.date,
                )

        for raw in stream:
            line = raw.rstrip(b"\n").removesuffix(b"\r")
            if line.startswith(_COMMIT_MARK):
                yield from flush()
                sha, author, date = line[1:].split(b"\x00")
                commit = _Commit(sha.decode(), decode(author), date.decode())
                self.stats.commits += 1
                pending, in_hunk = _Pending(), False
            elif line.startswith(b"diff "):
                if commit is None:  # a config changed the header format
                    raise ValueError(f"{self.root}: unexpected `git log` output")
                yield from flush()
                pending, in_hunk = _Pending(), False
            elif in_hunk and line[:1] in (b"+", b"-", b" "):
                markers = line[:parents]
                if b"-" in markers:
                    continue  # removed line: not in the new file
                if markers == b"+" * parents:
                    pending.add(new_line, line[parents:], self.max_file_size)
                new_line += 1
            elif match := _HUNK.match(line):
                in_hunk = True
                parents = len(match.group(1)) - 1
                new_line = int(match.group(2))
            elif line.startswith(b"+++ ") and line != b"+++ /dev/null":
                pending.path = _new_path(line[len(b"+++ ") :])
        yield from flush()
