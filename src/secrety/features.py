"""Turn a finding into the numeric features the classifier scores.

:func:`extract` is the single feature function: the CLI calls it at scan
time and the training code (``evaluation/``) must call it too, so the model
always sees features computed the same way. Every value is a finite float;
categories (charset, file type) are fixed one-hot columns, and an unknown
category is all zeros.

Changing :data:`FEATURE_NAMES` (adding, removing, reordering) means retraining
and re-exporting the model: the loader refuses a model whose feature list
differs (see ``docs/decisions/0001-classifier-format.md``).
"""

from __future__ import annotations

import math
import re
import string
from pathlib import PurePosixPath

from secrety.detectors.entropy import shannon_entropy
from secrety.models import DetectionMethod, Finding

FEATURE_NAMES: tuple[str, ...] = (
    "entropy",
    "log_length",
    "digit_ratio",
    "mixed_case",
    "charset_hex",
    "charset_alnum",
    "charset_base64",
    "charset_other",
    "has_name",
    "name_secret_word",
    "name_test_word",
    "value_placeholder",
    "value_dotted_name",
    "ext_config",
    "ext_code",
    "ext_doc",
    "method_regex",
    "prior_confidence",
)

_HEX = frozenset(string.hexdigits)
_ALNUM = frozenset(string.ascii_letters + string.digits)
_BASE64 = _ALNUM | frozenset("+/=-_")

_SECRET_WORDS = frozenset(
    {"password", "passwd", "pwd", "pass", "secret", "token", "key", "apikey", "auth"}
    | {"credential", "credentials", "private", "access"}
)
_TEST_WORDS = frozenset(
    {"test", "tests", "mock", "fake", "dummy", "example", "sample", "stub", "fixture", "demo"}
)
# Lowercase substrings of values people paste in docs and templates. FAKE is
# included: test suites, this one too, mark their fake values with it.
_PLACEHOLDERS = (
    "example",
    "sample",
    "dummy",
    "fake",
    "changeme",
    "placeholder",
    "your",
    "xxxx",
    "redacted",
    "todo",
)

_CONFIG_EXTS = frozenset(
    {".env", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".properties", ".toml", ".json", ".xml"}
)
_CODE_EXTS = frozenset(
    {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".kt", ".rb", ".php", ".cs"}
    | {".c", ".cpp", ".h", ".rs", ".swift", ".scala", ".sh", ".ps1", ".tf"}
)
_DOC_EXTS = frozenset({".md", ".rst", ".txt", ".adoc", ".html"})

# Only the end of the text before the secret is searched: the name sits right
# before it, and a bounded window keeps a huge minified line cheap.
_NAME_WINDOW = 200
_ASSIGNED_NAME = re.compile(r"([A-Za-z_$@][\w.\-$@]*)[\"']?\s*(?::=|=>|[:=])\s*[\"']?$")
_WORD = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")
_DOTTED_NAME = re.compile(r"[a-z_][a-z0-9_]*(?:[.:][a-z_][a-z0-9_]*)+")


def name_before(line: str, index: int) -> str:
    """Return the variable or key the value at ``index`` is assigned to, or ``""``.

    Recognises ``name = v``, ``name: v``, ``name := v``, ``name => v`` with
    optional quotes around the name and the value.
    """
    match = _ASSIGNED_NAME.search(line[max(0, index - _NAME_WINDOW) : index])
    return match.group(1) if match else ""


def name_tokens(name: str) -> tuple[str, ...]:
    """Split ``name`` into lowercase words: snake_case, kebab-case, dots and camelCase."""
    return tuple(word.lower() for word in _WORD.findall(name))


def _charset(secret: str) -> str:
    """Return the narrowest alphabet ``secret`` is drawn from."""
    chars = set(secret)
    if chars <= _HEX:
        return "hex"
    if chars <= _ALNUM:
        return "alnum"
    if chars <= _BASE64:
        return "base64"
    return "other"


def _file_kind(path: str) -> str:
    """Return ``config``, ``code``, ``doc`` or ``""`` from the file name."""
    name = PurePosixPath(path).name.lower()
    if name.startswith(".env"):
        return "config"
    suffix = PurePosixPath(name).suffix
    if suffix in _CONFIG_EXTS:
        return "config"
    if suffix in _CODE_EXTS:
        return "code"
    if suffix in _DOC_EXTS:
        return "doc"
    return ""


def extract(finding: Finding) -> tuple[float, ...]:
    """Return the features of ``finding``, in the order of :data:`FEATURE_NAMES`."""
    secret = finding.secret
    n = len(secret) or 1
    lowered = secret.lower()
    charset = _charset(secret)
    name = name_before(finding.line_content, finding.column - 1)
    words = set(name_tokens(name))
    kind = _file_kind(finding.path)
    values = {
        "entropy": shannon_entropy(secret),
        "log_length": math.log(n),
        "digit_ratio": sum(c.isdigit() for c in secret) / n,
        "mixed_case": float(secret != secret.lower() and secret != secret.upper()),
        "charset_hex": float(charset == "hex"),
        "charset_alnum": float(charset == "alnum"),
        "charset_base64": float(charset == "base64"),
        "charset_other": float(charset == "other"),
        "has_name": float(bool(name)),
        "name_secret_word": float(bool(words & _SECRET_WORDS)),
        "name_test_word": float(bool(words & _TEST_WORDS)),
        "value_placeholder": float(any(p in lowered for p in _PLACEHOLDERS)),
        "value_dotted_name": float(_DOTTED_NAME.fullmatch(secret) is not None),
        "ext_config": float(kind == "config"),
        "ext_code": float(kind == "code"),
        "ext_doc": float(kind == "doc"),
        "method_regex": float(finding.method is DetectionMethod.REGEX),
        "prior_confidence": float(finding.confidence),
    }
    return tuple(values[key] for key in FEATURE_NAMES)
