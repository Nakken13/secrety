"""Output formats: terminal text, JSON and SARIF.

Every reporter masks secrets: the raw value never leaves the process.
"""

from secrety.reporters.json_report import render_json
from secrety.reporters.sarif import render_sarif
from secrety.reporters.text import render_text, safe

__all__ = ["render_json", "render_sarif", "render_text", "safe"]
