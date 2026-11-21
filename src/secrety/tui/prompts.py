"""Only menu module that touches `input()`; I/O is injectable for tests."""

import sys
from collections.abc import Callable, Sequence

from secrety.tui.visual import menu_prompt, render_menu

InputFn = Callable[[str], str]
PrintFn = Callable[[str], None]


def choose(
    title: str,
    options: Sequence[str],
    *,
    back: str = "Back",
    on_info: Callable[[], None] | None = None,
    input_fn: InputFn = input,
    print_fn: PrintFn = print,
) -> int | None:
    """Numbered menu; returns the 0-based index of the option, or None for `q` (back).

    With `on_info`, an extra `0` entry calls it, then the menu is shown again.
    """
    color = sys.stdout.isatty()
    shown = render_menu(title, options, back=back, info=on_info is not None, color=color)
    print_fn("\n" + shown)
    while True:
        try:
            entry = input_fn(menu_prompt(color=color)).strip()
        except EOFError:
            return None
        if entry.lower() == "q":
            return None
        if entry == "0" and on_info is not None:
            on_info()
            print_fn("\n" + shown)
            continue
        if entry.isdigit() and 1 <= int(entry) <= len(options):
            return int(entry) - 1
        print_fn(f"Invalid choice: enter a number between 1 and {len(options)}, or q.")


def ask(
    label: str,
    *,
    default: str | None = None,
    optional: bool = True,
    input_fn: InputFn = input,
    print_fn: PrintFn = print,
) -> str:
    """Free input. ENTER returns `default` if given, "" if `optional`, else asks again."""
    if default is not None:
        prompt_text = f"{label} (ENTER = {default}) : "
    elif optional:
        prompt_text = f"{label} (ENTER to skip) : "
    else:
        prompt_text = f"{label} : "
    while True:
        entry = input_fn(prompt_text).strip()
        if entry:
            return entry
        if default is not None:
            return default
        if optional:
            return ""
        print_fn("A value is required.")
