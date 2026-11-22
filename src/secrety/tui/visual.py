"""Menu panels, info panels and per-file result cards (Rich), with an ASCII fallback."""

import shutil
import sys
from collections.abc import Iterable, Sequence
from io import StringIO

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from secrety.models import Finding
from secrety.reporters import safe

_PANEL_WIDTH = 64


def _unicode_printable() -> bool:
    """False when stdout's encoding cannot show box drawing (e.g. cp1252): ASCII fallback."""
    try:
        "╭▸❯".encode(sys.stdout.encoding or "ascii")  # noqa: RUF001
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _console(buffer: StringIO, width: int, color: bool) -> Console:
    return Console(
        file=buffer,
        width=width,
        force_terminal=color,
        color_system="256" if color else None,
        highlight=False,
        emoji=False,
    )


def _terminal_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def _strip(buffer: StringIO) -> str:
    return "\n".join(line.rstrip() for line in buffer.getvalue().splitlines())


def render_menu(
    title: str,
    options: Sequence[str],
    *,
    back: str = "Back",
    info: bool = False,
    color: bool = False,
) -> str:
    """Numbered menu in a panel; the info and back keys sit below a rule."""
    terminal = _terminal_width()
    buffer = StringIO()
    console = _console(buffer, terminal, color)
    unicode_ok = _unicode_printable()
    rows = Table.grid(padding=(0, 2))
    rows.add_column(justify="right")
    rows.add_column(no_wrap=True)
    for number, option in enumerate(options, start=1):
        rows.add_row(Text(f"[{number}]", style="bold color(208)"), Text(option, style="bold"))
    keys = Text()
    if info:
        keys.append("[0]", style="bold color(208)").append("  Info", style="dim").append("        ")
    keys.append("[q]", style="bold color(208)").append(f"  {back}", style="dim")
    panel = Panel(
        Group(
            rows,
            Rule(style="color(94)", characters="─" if unicode_ok else "-"),
            Align.center(keys),
        ),
        title=Text(title, style="bold"),
        title_align="left",
        box=box.ROUNDED if unicode_ok else box.ASCII,
        border_style="color(166)",
        padding=(0, 2),
        width=min(terminal, _PANEL_WIDTH),
    )
    console.print(Align.center(panel))
    return _strip(buffer)


def render_info(title: str, lines: Iterable[str], *, color: bool = False) -> str:
    """Centered panel (same width as the menu) with one wrapped paragraph per line."""
    terminal = _terminal_width()
    buffer = StringIO()
    console = _console(buffer, terminal, color)
    panel = Panel(
        Group(*(Text(line) for line in lines)),
        title=Text(title, style="bold"),
        title_align="left",
        box=box.ROUNDED if _unicode_printable() else box.ASCII,
        border_style="color(166)",
        padding=(0, 2),
        width=min(terminal, _PANEL_WIDTH),
    )
    console.print(Align.center(panel))
    return _strip(buffer)


def render_cards(findings: Sequence[Finding], *, color: bool = False) -> str:
    """One panel per file (or commit:file); one line per finding, the secret masked."""
    if not findings:
        return ""
    width = min(_terminal_width(), 100)
    buffer = StringIO()
    console = _console(buffer, width, color)
    unicode_ok = _unicode_printable()
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.path, []).append(finding)
    for path, items in groups.items():
        body = Group(*(_finding_line(f, unicode_ok) for f in items))
        console.print(
            Panel(
                body,
                title=Text.from_markup(f"{safe(path)} ({len(items)})"),
                title_align="left",
                box=box.ROUNDED if unicode_ok else box.ASCII,
            )
        )
    return _strip(buffer)


def _finding_line(f: Finding, unicode_ok: bool) -> Text:
    where = f"{f.commit[:7]}:" if f.commit else ""
    line = Text.from_markup(
        f"{'▸ ' if unicode_ok else '- '}[color(208)]{where}{f.line}:{f.column}[/color(208)]  "
        f"[bold]{safe(f.rule_id)}[/bold]  {safe(f.masked())}  [dim]{f.confidence:.2f}[/dim]"
    )
    if f.removed_later:
        line.append("  (removed from HEAD, still in history)", style="yellow")
    return line


def menu_prompt(*, color: bool = False) -> str:
    """Input prompt for the menus (fancy arrow, ASCII fallback)."""
    arrow = "❯" if _unicode_printable() else ">"  # noqa: RUF001
    return f"\x1b[1msecrety {arrow}\x1b[0m " if color else f"secrety {arrow} "
