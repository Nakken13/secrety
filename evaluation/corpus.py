"""Synthetic labelled corpus: files with fake secrets and look-alike decoys.

Everything is generated at runtime from a seed and written to a directory that
is gitignored, so no secret-shaped string is ever committed (see ``AGENTS.md``).
The generator source holds recipes, never literal credentials.

Design notes, kept next to the code because they decide what the numbers mean:

* **Markers.** The fake-value marker is a one-line header (``HEADER_TEXT``) at
  the top of every file whose format allows a comment, never part of a value
  and never near one line only. The header depends on the file type, and each
  file type holds both labels, so it cannot tell the classes apart. Secret
  values never contain ``fake``/``example``/``test``: a marker inside the
  value would hand the classifier the answer (and gitleaks / trufflehog treat
  such values as allowlisted, which would flatter them or us, see
  ``docs/results/``).
* **Held-out families.** Some decoy families exist only in the ``test`` split,
  so the test score measures behaviour on look-alikes the classifier never saw.
* **One candidate per line**, so a finding is matched to the ground truth by
  ``(path, line)`` alone, whatever span the tool reports.
"""

from __future__ import annotations

import json
import random
import string
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

TRAIN_SEED = 1
TEST_SEED = 2
DEFAULT_FILES = 150
SPLITS = ("train", "test")
GROUND_TRUTH_FILE = "ground_truth.json"
FILES_DIR = "files"  # what the scanners are pointed at; the ground truth stays outside it
HEADER_TEXT = "synthetic corpus: FAKE TEST DATA, no real credential"

_UPPER_NO_ONE = string.ascii_uppercase + "234567"
_ALNUM = string.ascii_letters + string.digits
_B64URL = _ALNUM + "-_"
_B64 = _ALNUM + "+/"
_HEX = "0123456789abcdef"
_PASSWORD_SYMBOLS = "!@#^*-_+=."  # secrety:ignore[generic-password-assignment]
_FORBIDDEN_IN_SECRETS = ("fake", "example", "test", "dummy", "sample")
_WORDS = ("Summer", "Dragon", "Winter", "Falcon", "Sunset", "Harbor", "Marble", "Tiger")


@dataclass(frozen=True)
class Candidate:
    """One labelled line (or block of lines) of the corpus.

    Attributes:
        path: File path relative to the corpus root, ``/`` separated.
        line: 1-based first line.
        end_line: 1-based last line (equals ``line`` except for key blocks).
        label: ``secret`` or ``decoy``.
        family: Name of the generator family.
        value: The value (first line of it is on ``line``).
    """

    path: str
    line: int
    end_line: int
    label: str
    family: str
    value: str


@dataclass(frozen=True)
class Family:
    """A recipe for one kind of candidate."""

    name: str
    label: str
    names: tuple[tuple[str, ...], ...]
    make: Callable[[random.Random], str]
    held_out: bool = False
    block: bool = False


def _rand(rng: random.Random, alphabet: str, n: int) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def _aws_key(rng: random.Random) -> str:
    return rng.choice(("AKIA", "ASIA")) + _rand(rng, _UPPER_NO_ONE, 16)


def _github_token(rng: random.Random) -> str:
    return rng.choice(("ghp_", "gho_", "ghs_")) + _rand(rng, _ALNUM, 36)


def _stripe_key(rng: random.Random) -> str:
    return rng.choice(("sk_live_", "rk_live_")) + _rand(rng, _ALNUM, 24)


def _google_key(rng: random.Random) -> str:
    return "AIza" + _rand(rng, _B64URL, 35)


def _slack_token(rng: random.Random) -> str:
    digits = string.digits
    return f"xoxb-{_rand(rng, digits, 12)}-{_rand(rng, digits, 12)}-{_rand(rng, _ALNUM, 24)}"


def _jwt(rng: random.Random) -> str:
    parts = (30, 40, 43)
    return ".".join(("eyJ" if i < 2 else "") + _rand(rng, _B64URL, n) for i, n in enumerate(parts))


def _password(rng: random.Random) -> str:
    if rng.random() < 0.5:  # a human-looking password: low entropy, hard for the entropy method
        return (
            rng.choice(_WORDS) + _rand(rng, string.digits, rng.randint(2, 4)) + rng.choice("!#^*")
        )
    return rng.choice(_ALNUM) + _rand(rng, _ALNUM + _PASSWORD_SYMBOLS, rng.randint(11, 17))


def _url_credentials(rng: random.Random) -> str:
    user = rng.choice(("admin", "svc", "deploy", "app", "reader"))
    host = rng.choice(("db.internal", "cache.internal", "mq.internal"))
    return f"postgres://{user}:{_rand(rng, _ALNUM, rng.randint(12, 20))}@{host}:5432/main"


def _private_key(rng: random.Random) -> str:
    kind = rng.choice(("RSA ", "EC ", "OPENSSH ", ""))
    body = [_rand(rng, _B64, 64) for _ in range(rng.randint(4, 8))]
    return "\n".join(
        [f"-----BEGIN {kind}PRIVATE KEY-----", *body, f"-----END {kind}PRIVATE KEY-----"]
    )


def _aws_secret(rng: random.Random) -> str:
    return _rand(rng, _B64, 40)


def _entropy_token(rng: random.Random) -> str:
    if rng.random() < 0.5:
        return _rand(rng, _HEX, rng.choice((32, 40, 64)))
    return _rand(rng, _B64URL, rng.randint(32, 48))


def _git_sha(rng: random.Random) -> str:
    return _rand(rng, _HEX, 40)


def _uuid(rng: random.Random) -> str:
    return "-".join(_rand(rng, _HEX, n) for n in (8, 4, 4, 4, 12))


def _checksum(rng: random.Random) -> str:
    return _rand(rng, _HEX, rng.choice((32, 64)))


def _placeholder_password(rng: random.Random) -> str:
    return rng.choice(
        (
            "changeme",
            "your-password-here",
            "xxxxxxxxxxxx",
            "password123",
            "ChangeMe123",
            "todo-set-me",
        )
    )


def _dotted_reference(rng: random.Random) -> str:
    a = rng.choice(("app", "auth", "vault", "settings"))
    b = rng.choice(("security", "crypto", "session", "db"))
    c = rng.choice(("password_policy", "secret_ref", "token_ttl", "key_name"))
    return f"{a}.{b}.{c}"


def _data_uri_chunk(rng: random.Random) -> str:
    return _rand(rng, _B64, rng.randint(40, 90))


def _public_identifier(rng: random.Random) -> str:
    return _rand(rng, _ALNUM, rng.randint(20, 28))


def _env_var_name(rng: random.Random) -> str:
    return (
        rng.choice(("PAYMENT", "SMTP", "DB", "STORAGE"))
        + "_"
        + rng.choice(("API_SECRET", "PASSWORD", "TOKEN_VALUE"))
    )


def _integrity_hash(rng: random.Random) -> str:
    return "sha512-" + _rand(rng, _B64, 86) + "=="


def _docker_digest(rng: random.Random) -> str:
    return "sha256:" + _rand(rng, _HEX, 64)


def _ssh_public_key(rng: random.Random) -> str:
    return "ssh-rsa AAAAB3NzaC1yc2E" + _rand(rng, _B64, rng.randint(90, 140))


def _asset_name(rng: random.Random) -> str:
    return "bundle." + _rand(rng, _ALNUM, 28) + ".js"


POSITIVE_FAMILIES: tuple[Family, ...] = (
    Family(
        "aws_access_key", "secret", (("aws", "access", "key", "id"), ("access", "key")), _aws_key
    ),
    Family(
        "github_token",
        "secret",
        (("github", "token"), ("gh", "token"), ("ci", "token")),
        _github_token,
    ),
    Family("stripe_key", "secret", (("stripe", "key"), ("payment", "key")), _stripe_key),
    Family("google_api_key", "secret", (("google", "api", "key"), ("maps", "key")), _google_key),
    Family("slack_token", "secret", (("slack", "token"), ("bot", "token")), _slack_token),
    Family("jwt", "secret", (("auth", "token"), ("session", "token"), ("bearer",)), _jwt),
    Family(
        "password",
        "secret",
        (("db", "password"), ("admin", "password"), ("password",), ("mail", "passwd")),
        _password,
    ),
    Family(
        "url_credentials",
        "secret",
        (("database", "url"), ("broker", "url"), ("dsn",)),
        _url_credentials,
    ),
    Family("private_key", "secret", ((),), _private_key, block=True),
    Family(
        "aws_secret_key",
        "secret",
        (("aws", "secret", "access", "key"), ("secret", "key")),
        _aws_secret,
    ),
    Family(
        "entropy_token",
        "secret",
        (("session", "blob"), ("svc", "cred"), ("signing", "material"), ("webhook", "auth")),
        _entropy_token,
    ),
)

DECOY_FAMILIES: tuple[Family, ...] = (
    Family(
        "git_sha", "decoy", (("commit",), ("git", "sha"), ("revision",), ("base", "ref")), _git_sha
    ),
    Family("uuid", "decoy", (("request", "id"), ("trace", "id"), ("tenant", "id")), _uuid),
    Family("checksum", "decoy", (("checksum",), ("file", "hash"), ("digest",)), _checksum),
    Family(
        "placeholder_password",
        "decoy",
        (("db", "password"), ("password",), ("admin", "password"), ("secret",)),
        _placeholder_password,
    ),
    Family(
        "dotted_reference",
        "decoy",
        (("password", "key"), ("secret", "ref"), ("token", "path")),
        _dotted_reference,
    ),
    Family(
        "data_uri_chunk", "decoy", (("logo",), ("icon", "data"), ("image", "blob")), _data_uri_chunk
    ),
    Family(
        "public_identifier",
        "decoy",
        (("site", "key"), ("client", "id"), ("cache", "key"), ("public", "key", "id")),
        _public_identifier,
    ),
    Family(
        "env_var_name",
        "decoy",
        (("password", "var"), ("secret", "name"), ("token", "env")),
        _env_var_name,
    ),
    Family(
        "integrity_hash",
        "decoy",
        (("integrity",), ("lock", "hash")),
        _integrity_hash,
        held_out=True,
    ),
    Family(
        "docker_digest",
        "decoy",
        (("image", "digest"), ("base", "image")),
        _docker_digest,
        held_out=True,
    ),
    Family(
        "ssh_public_key",
        "decoy",
        (("authorized", "key"), ("public", "key")),
        _ssh_public_key,
        held_out=True,
    ),
    Family(
        "asset_name", "decoy", (("main", "bundle"), ("entry", "file")), _asset_name, held_out=True
    ),
)

# extension -> (comment template, filler pool); an empty template means no comment is allowed
_EXTENSIONS: dict[str, tuple[str, str]] = {
    ".py": ("# {}", "#"),
    ".sh": ("# {}", "#"),
    ".env": ("# {}", "#"),
    ".yaml": ("# {}", "#"),
    ".yml": ("# {}", "#"),
    ".toml": ("# {}", "#"),
    ".tf": ("# {}", "#"),
    ".ini": ("; {}", "#"),
    ".js": ("// {}", "//"),
    ".ts": ("// {}", "//"),
    ".go": ("// {}", "//"),
    ".java": ("// {}", "//"),
    ".md": ("<!-- {} -->", ""),
    ".json": ("", ""),
}
_DIRS = ("src", "app", "config", "lib", "tests", "docs", "scripts", "deploy", "services/api")
_STEMS = ("settings", "client", "main", "deploy", "service", "helpers", "loader", "setup")
_TEST_PREFIXES = ("test", "mock", "sample")
_FILLERS: dict[str, tuple[str, ...]] = {
    "#": (
        "import os",
        "retries = 3",
        "# TODO tidy this up",
        "log.info('starting')",
        "timeout = 30",
    ),
    "//": (
        "import fs from 'fs';",
        "// helper below",
        "const retries = 3;",
        "log.info('starting');",
        "return items;",
    ),
    "": ('version = "1.2.3"', "debug = false", '"retries": 3,', 'name = "service"', "port = 8080"),
}


def _is_clean(value: str) -> bool:
    lowered = value.lower()
    return not any(word in lowered for word in _FORBIDDEN_IN_SECRETS)


def _value(rng: random.Random, family: Family) -> str:
    """Draw a value; secrets are redrawn until they hold no marker word."""
    while True:
        value = family.make(rng)
        if family.label == "decoy" or _is_clean(value):
            return value


def _style_name(tokens: tuple[str, ...], ext: str, rng: random.Random) -> str:
    if rng.random() < 0.12:  # same chance for both labels: a test-ish name says nothing
        tokens = (rng.choice(_TEST_PREFIXES), *tokens)
    if ext in (".js", ".ts", ".go"):
        return tokens[0] + "".join(t.capitalize() for t in tokens[1:])
    if ext in (".java", ".env", ".sh", ".md"):
        return "_".join(tokens).upper()
    return "_".join(tokens)


def _render(name: str, value: str, ext: str, rng: random.Random) -> str:
    if ext in (".js", ".ts"):
        return f'const {name} = "{value}";'
    if ext == ".go":
        return f'{name} := "{value}"'
    if ext == ".java":
        return f'private static final String {name} = "{value}";'
    if ext in (".yaml", ".yml"):
        return f'{name}: "{value}"' if rng.random() < 0.6 else f"{name}: {value}"
    if ext == ".env":
        return f"{name}={value}"
    if ext == ".json":
        return f'"{name}": "{value}",'
    if ext == ".md":
        return f'    {name}="{value}"'
    if ext == ".sh":
        return f'export {name}="{value}"'
    return f'{name} = "{value}"'


def _header(ext: str) -> str | None:
    template = _EXTENSIONS[ext][0]
    return template.format(HEADER_TEXT) if template else None


def _filler(ext: str, rng: random.Random) -> str:
    return rng.choice(_FILLERS[_EXTENSIONS[ext][1]])


def _pick_family(rng: random.Random, split: str, ext: str) -> Family:
    held_in = [f for f in DECOY_FAMILIES if split == "test" or not f.held_out]
    pool = POSITIVE_FAMILIES if rng.random() < 0.5 else tuple(held_in)
    while True:
        family = rng.choice(pool)
        if not (family.block and ext == ".json"):
            return family


def generate_corpus(
    out_dir: Path, seed: int, split: str = "train", n_files: int = 120
) -> list[Candidate]:
    """Write a corpus to ``out_dir/files`` and ``out_dir/ground_truth.json``; return the candidates.

    The same ``(seed, split, n_files)`` always gives the same bytes. The
    ``train`` split uses the shared families only; ``test`` adds the held-out
    decoy families.
    """
    if split not in SPLITS:
        raise ValueError(f"split must be one of {SPLITS}, got {split!r}")
    rng = random.Random(f"{split}:{seed}")
    out_dir.mkdir(parents=True, exist_ok=True)
    candidates: list[Candidate] = []
    extensions = sorted(_EXTENSIONS)
    for index in range(n_files):
        ext = rng.choice(extensions)
        rel = f"{rng.choice(_DIRS)}/{rng.choice(_STEMS)}_{index:03d}{ext}"
        lines: list[str] = []
        header = _header(ext)
        if header:
            lines.append(header)
        for _ in range(rng.randint(4, 10)):
            lines.extend(_filler(ext, rng) for _ in range(rng.randint(1, 4)))
            family = _pick_family(rng, split, ext)
            value = _value(rng, family)
            if family.block:
                start = len(lines) + 1
                lines.extend(value.split("\n"))
                end = len(lines)
            else:
                name = _style_name(rng.choice(family.names), ext, rng)
                lines.append(_render(name, value, ext, rng))
                start = end = len(lines)
            candidates.append(Candidate(rel, start, end, family.label, family.name, value))
        path = out_dir / FILES_DIR / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    payload = {"seed": seed, "split": split, "candidates": [asdict(c) for c in candidates]}
    (out_dir / GROUND_TRUTH_FILE).write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")
    return candidates


def load_ground_truth(corpus_dir: Path) -> list[Candidate]:
    """Read the candidates back from ``ground_truth.json``."""
    data = json.loads((corpus_dir / GROUND_TRUTH_FILE).read_text(encoding="utf-8"))
    return [Candidate(**c) for c in data["candidates"]]
