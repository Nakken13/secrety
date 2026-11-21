"""SARIF 2.1.0 reporter, for GitHub code scanning and other SARIF viewers."""

import json
from collections.abc import Sequence
from urllib.parse import quote

from secrety import __version__
from secrety.models import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_HIGH_CONFIDENCE = 0.8
_INFORMATION_URI = "https://github.com/Nakken13/secrety"


def _result(f: Finding, rule_index: int) -> dict[str, object]:
    # No `snippet` in the region: it would carry the raw secret.
    properties: dict[str, object] = {
        "confidence": round(f.confidence, 4),
        "method": f.method.value,
        "maskedSecret": f.masked(),
    }
    for key, value in (
        ("commit", f.commit),
        ("author", f.author),
        ("date", f.date),
        ("removedLater", f.removed_later),
    ):
        if value is not None:
            properties[key] = value
    return {
        "ruleId": f.rule_id,
        "ruleIndex": rule_index,
        "level": "error" if f.confidence >= _HIGH_CONFIDENCE else "warning",
        "message": {"text": f"{f.description}: {f.masked()}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(f.path)},
                    "region": {"startLine": f.line, "startColumn": f.column},
                }
            }
        ],
        "partialFingerprints": {"secretyFingerprint/v1": f.fingerprint},
        "properties": properties,
    }


def render_sarif(findings: Sequence[Finding]) -> str:
    """Return the findings as a SARIF 2.1.0 log (secrets masked)."""
    rules: dict[str, dict[str, object]] = {}
    for f in findings:
        rules.setdefault(
            f.rule_id,
            {"id": f.rule_id, "name": f.rule_id, "shortDescription": {"text": f.description}},
        )
    index = {rule_id: i for i, rule_id in enumerate(rules)}
    log = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secrety",
                        "version": __version__,
                        "informationUri": _INFORMATION_URI,
                        "rules": list(rules.values()),
                    }
                },
                "results": [_result(f, index[f.rule_id]) for f in findings],
            }
        ],
    }
    return json.dumps(log, indent=2) + "\n"
