"""clispec 0.3 document for the recoverage CLI. No config, credentials, or network."""

from __future__ import annotations

lazy from typing import Any

lazy from recoverage import __version__

_RETRY = (
    " No idempotency key is accepted, so a retry is not a safe substitute for"
    " knowing whether the first run finished."
)

_ITEMS = [
    {"name": "items", "type": "array", "items": {"type": "object"}},
    {"name": "total", "type": "integer"},
]


def _command(
    name: str,
    description: str,
    effects: str,
    *,
    collection: bool = False,
) -> dict[str, Any]:
    text = description
    if effects == "non_idempotent":
        text += _RETRY
    spec: dict[str, Any] = {
        "name": name,
        "description": text,
        "effects": effects,
        "output_kind": "data",
    }
    if collection:
        spec["cardinality"] = "bounded"
        spec["output_fields"] = _ITEMS
    else:
        spec["cardinality"] = "single"
        spec["stdout_schema"] = {}
    return spec


# Invocable commands only. `recoverage` with no command is `serve`.
_COMMANDS: tuple[dict[str, Any], ...] = (
    _command(
        "serve",
        "Start the coverage dashboard and serve it until the process is stopped.",
        "non_idempotent",
    ),
    _command(
        "stats",
        "Print coverage stats for each target.",
        "read_only",
        collection=True,
    ),
    _command(
        "export",
        "Export coverage rows. JSON is the items envelope; csv and md are text artifacts.",
        "read_only",
        collection=True,
    ),
    _command(
        "check",
        "Compare coverage with a threshold. Exit 1 prints the verdict document"
        " and is the same failure code as a missing target, not a separate outcome.",
        "read_only",
    ),
    _command(
        "regen",
        "Refresh the live project view without writing coverage files.",
        "non_idempotent",
    ),
    _command(
        "backup",
        "Copy portable coverage documents into one new archive.",
        "non_idempotent",
    ),
    _command(
        "restore",
        "Put a verified backup back into the coverage directory.",
        "non_idempotent",
    ),
    _command(
        "open",
        "Open the running dashboard in a browser.",
        "non_idempotent",
    ),
    _command(
        "config",
        "Print the configuration serve would start with, without binding a port.",
        "read_only",
    ),
    _command(
        "schema",
        "Print the clispec 0.3 JSON document for this CLI.",
        "read_only",
    ),
)


def build_schema(path: str | None = None) -> dict[str, Any]:
    """The clispec 0.3 document, optionally filtered to one command path."""
    commands = list(_COMMANDS)
    if path:
        commands = [
            command
            for command in commands
            if command["name"] == path or command["name"].startswith(path + " ")
        ]
    return {
        "clispec": "0.3",
        "name": "recoverage",
        "version": __version__,
        "description": "Coverage dashboard for binary-matching decompilation projects.",
        "output": {"tty": "text", "piped": "text"},
        "global_args": [
            {
                "name": "--output",
                "short": "-o",
                "type": "string",
                "enum": ["auto", "text", "json"],
                "default": "auto",
                "description": (
                    "Format before the subcommand. auto stays text."
                    " --json remains a synonym for json."
                ),
            },
            {
                "name": "--json",
                "type": "boolean",
                "description": "Write results to stdout as JSON. Same as -o json.",
            },
            {
                "name": "--version",
                "short": "-V",
                "type": "boolean",
                "description": "Show version and exit.",
            },
            {
                "name": "--no-color",
                "type": "boolean",
                "description": "Disable colored output. Honors NO_COLOR and TERM=dumb.",
            },
        ],
        "commands": commands,
        "errors": [
            {
                "kind": "usage",
                "exit_code": 2,
                "retryable": False,
                "description": "The arguments or RECOVERAGE_* values are not a valid invocation.",
            },
            {
                "kind": "failure",
                "exit_code": 1,
                "retryable": False,
                "description": (
                    "The command could not finish. A check that finds coverage"
                    " below the threshold uses this same code and prints the"
                    " verdict document on stdout."
                ),
            },
        ],
    }
