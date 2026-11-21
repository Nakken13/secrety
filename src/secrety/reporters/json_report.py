"""JSON reporter with a stable, versioned schema."""

import json
from collections.abc import Sequence

from secrety import __version__
from secrety.models import Finding

SCHEMA_VERSION = 1


def _finding_dict(f: Finding) -> dict[str, object]:
    return {
        "rule_id": f.rule_id,
        "description": f.description,
        "path": f.path,
        "line": f.line,
        "column": f.column,
        "secret": f.masked(),
        "method": f.method.value,
        "also_matched": [{"rule_id": r, "method": m.value} for r, m in f.also_matched],
        "confidence": round(f.confidence, 4),
        "fingerprint": f.fingerprint,
        "commit": f.commit,
        "author": f.author,
        "date": f.date,
        "removed_later": f.removed_later,
    }


def render_json(findings: Sequence[Finding]) -> str:
    """Return the findings as a JSON document (secrets masked)."""
    document = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "secrety", "version": __version__},
        "findings": [_finding_dict(f) for f in findings],
    }
    return json.dumps(document, indent=2) + "\n"
