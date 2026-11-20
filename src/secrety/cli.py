"""Command-line interface for secrety."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from secrety import __version__

app = typer.Typer(
    name="secrety",
    help="Scan source code and Git history for exposed secrets.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _version_callback(value: bool) -> None:
    """Print the version and exit when ``--version`` is passed."""
    if value:
        console.print(f"secrety {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Scan source code and Git history for exposed secrets."""


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=True, help="File or folder to scan."),
    ] = Path("."),
) -> None:
    """Scan PATH for exposed secrets."""
    console.print(f"Scanning [bold]{path}[/bold]... (no detector yet)")
