"""Shared status colors, owned by relumea-brand and copied with provenance.

TERMINAL balances black and white grounds. Keep verdicts, origin, activity and
warnings semantically separate.
"""

TERMINAL: dict[str, str] = {
    "exact": "#1e864f",
    "live": "#397ba8",
    "near": "#6173ac",
    "thunk": "#7c68be",
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
    "bold cyan": f"bold {TERMINAL['live']}",
}
