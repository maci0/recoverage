"""Shared status colors, owned by relumea-brand and copied with provenance.

TERMINAL balances black and white grounds. Keep verdicts, origin, activity and
warnings semantically separate.
"""

TERMINAL: dict[str, str] = {
    "exact": "#1e864f",
    "reloc": "#02828b",
    "proven": "#547f67",
    "library": "#a65d89",
    "thunk": "#7c68be",
    "near": "#6173ac",
    "stub": "#717581",
    "live": "#397ba8",
    "fail": "#bf544c",
    "warn": "#9a6d20",
}

RICH_STYLES: dict[str, str] = {
    "green": TERMINAL["exact"],
    "cyan": TERMINAL["live"],
    "blue": TERMINAL["near"],
    "magenta": TERMINAL["thunk"],
    "yellow": TERMINAL["warn"],
    "red": TERMINAL["fail"],
    "bold green": f"bold {TERMINAL['exact']}",
    "green bold": f"bold {TERMINAL['exact']}",
    "bold cyan": f"bold {TERMINAL['live']}",
    "cyan bold": f"bold {TERMINAL['live']}",
    "bold blue": f"bold {TERMINAL['near']}",
    "blue bold": f"bold {TERMINAL['near']}",
    "bold magenta": f"bold {TERMINAL['thunk']}",
    "magenta bold": f"bold {TERMINAL['thunk']}",
    "bold yellow": f"bold {TERMINAL['warn']}",
    "yellow bold": f"bold {TERMINAL['warn']}",
    "bold red": f"bold {TERMINAL['fail']}",
    "red bold": f"bold {TERMINAL['fail']}",
}
