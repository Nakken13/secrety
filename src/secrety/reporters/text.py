"""Terminal reporter: one line per finding, secret masked."""

import re
from collections.abc import Sequence

from rich.console import Console
from rich.markup import escape

from secrety.models import Finding

# C0 controls, DEL and C1 controls: ESC or CSI could drive the terminal.
_CONTROL_CHARS = re.compile("[\x00-\x1f\x7f-\x9f]")


def safe(text: str) -> str:
    """Make untrusted text (paths, authors, rule ids) safe to print.

    Control characters (ESC, CSI...) are shown as hex escapes so they cannot
    drive the terminal, then Rich markup is escaped (a file named
    ``[link=...]x`` stays literal).
    """
    return escape(_CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", text))


def render_text(console: Console, findings: Sequence[Finding]) -> None:
    """Print one line per finding on ``console``, with the secret masked.

    Paths and secrets come from the scanned (untrusted) files, so they are
    escaped: a file named ``[link=...]x`` must not be read as Rich markup.
    """
    for f in findings:
        # Rule ids may come from a custom rules file: escaped like the rest.
        details = [f"confidence {f.confidence:.2f}"]
        if f.also_matched:
            details.append("also: " + ", ".join(rule_id for rule_id, _ in f.also_matched))
        if f.author:
            details.append(f"by {f.author}" + (f" on {f.date[:10]}" if f.date else ""))
        if f.removed_later:
            details.append("removed from HEAD, still in history")
        console.print(
            f"{safe(f.location)}  [bold]{safe(f.rule_id)}[/bold]  {safe(f.masked())}  "
            f"[dim]({safe('; '.join(details))})[/dim]"
        )
