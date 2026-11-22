"""Banner (a braille emblem and the name `Secrety`) shown when the menu opens."""

import shutil

from secrety import __version__

_LOCK = (
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣤⣤⣤⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⡶⠿⠋⠛⠉⠁⠀⠉⠉⠛⠿⣶⣀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⣠⣾⠟⠁⠀⠀⢀⣄⣤⣤⣤⣀⠀⠀⠀⠈⠻⣧⡀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⣠⣼⠟⠀⠀⣠⣴⠟⠟⠉⠉⠈⠉⠻⣷⣄⠀⠀⠀⠹⣷⡀⠀⠀⠀⠀",
    "⠀⠀⠀⣠⡿⠁⠀⢀⣾⠟⠁⠀⣠⣤⡶⣤⣤⣀⠈⢻⣦⠀⠀⠀⡿⡇⠀⠀⠀⠀",
    "⠀⠀⢀⣿⠀⠀⢀⣾⠋⠀⠀⣾⠏⠀⣠⣄⠉⢻⣆⠈⣿⡄⠀⠀⢸⡧⠀⠀⠀⠀",
    "⠀⠀⣸⡏⠀⠀⢸⡏⠀⠀⣸⡇⠀⢼⡏⠻⠂⢸⡯⠀⣸⡇⠀⠀⣸⠇⠀⠀⠀⠀",
    "⠀⠀⢸⣇⠀⠀⢿⡇⠀⠀⠪⣷⠀⠈⠻⣷⡾⠟⠁⢠⡿⠁⠀⢰⡿⠁⠀⠀⠀⠀",
    "⠀⠀⠀⢿⣆⠀⠈⣿⡄⠀⠀⠻⣷⣄⣀⣀⣀⣠⣴⠿⠁⠀⣴⠿⠁⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠈⢻⣧⠀⠘⠿⣶⣄⠀⠈⠈⠛⠛⠛⠋⠀⠀⣤⡾⠋⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠋⠀⠀⠀⠈⠹⠷⣦⣤⣤⣤⣤⡴⠾⠟⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀",
    "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
)

_TITLE = (
    r" ___                 _         ",
    r"/ __| ___ __ _ _ ___| |_ _  _ ",
    r"\__ \/ -_) _| '_/ -_)  _| || |",
    r"|___/\___\__|_| \___|\__|\_, |",
    r"                          |__/ ",
)


# 256-color fire ramp, flame tip (yellow) down to the embers (dark red).
_FIRE = (226, 220, 214, 208, 202, 196, 160, 124)


def _fire(index: int, total: int) -> int:
    return _FIRE[index * len(_FIRE) // total]


def banner(*, color: bool = False) -> str:
    """Padlock, `Secrety`, then version and author, centered; `color` adds a fire gradient."""
    terminal = shutil.get_terminal_size((80, 24)).columns
    lock = [line.center(terminal).rstrip() for line in _LOCK]
    if color:
        lock = [f"[38;5;{_fire(n, len(lock))}m{line}[0m" for n, line in enumerate(lock)]
    # same width for every title line, or center() shifts each one differently
    width = max(len(line) for line in _TITLE)
    title = [line.ljust(width).center(terminal).rstrip() for line in _TITLE]
    lines = [*lock, *title, ""]
    lines.append(f"v{__version__}".center(terminal).rstrip())
    lines.append("Made by Nakken".center(terminal).rstrip())
    return "\n".join(lines) + "\n"
