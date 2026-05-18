"""Shared output-mode state for the CLI.

Set once by the root callback in tool.py before any command runs.
All command functions read these to decide how to render output.
"""

from __future__ import annotations

output_json: bool = False
output_simple: bool = False


def configure(json_out: bool, simple: bool) -> None:
    global output_json, output_simple
    output_json = json_out
    output_simple = simple


def get_console():
    """Return a Rich Console appropriate for the current output mode."""
    from rich.console import Console

    plain = output_simple or output_json
    return Console(no_color=plain, markup=not plain, highlight=not plain, emoji=False)
