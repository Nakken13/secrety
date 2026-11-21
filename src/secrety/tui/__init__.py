"""Interactive numbered menu, opened by `secrety` with no arguments."""

import sys

from secrety.tui.flow import run


def main() -> None:
    """Run the menu on the real terminal (undisplayable characters replaced, never a crash)."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    try:
        run()
    except (KeyboardInterrupt, EOFError):
        print()


__all__ = ["main", "run"]
