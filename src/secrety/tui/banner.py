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


def banner() -> str:
    """Padlock, `Secrety`, then version and author, each centered on the terminal."""
    terminal = shutil.get_terminal_size((80, 24)).columns
    lines = [line.center(terminal).rstrip() for line in _LOCK]
    lines += [line.center(terminal).rstrip() for line in _TITLE]
    lines.append("")
    lines.append(f"v{__version__}".center(terminal).rstrip())
    lines.append("Made by Nakken".center(terminal).rstrip())
    return "\n".join(lines) + "\n"
