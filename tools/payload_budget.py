#!/usr/bin/env python3
"""Print the inlined SPA shell's compressed size at each static encoding.

docs/DESIGN.md quotes these three numbers to justify smallest-wins static
compression, and they move every time the bundle does, so the document points
here rather than at a hand-copied figure nobody can re-derive.  The encoding
that wins is the one `ui.select_static_variant` serves to a client accepting
all three; the budget it is checked against is `ui._TCP_CWND_BUDGET`.

Run it from the repository root through the locked interpreter:

    uv run --locked --extra dev python tools/payload_budget.py
"""

from __future__ import annotations

import gzip
import sys

import brotli
import zstandard

from recoverage import ui


def main() -> int:
    """Print one row per static encoding, plus the smallest and the budget."""
    payload = ui._build_index_payload()
    sizes = {
        "br": len(brotli.compress(payload, quality=ui.BROTLI_STATIC_QUALITY)),
        "zstd": len(zstandard.ZstdCompressor(level=ui.ZSTD_STATIC_LEVEL).compress(payload)),
        "gzip": len(gzip.compress(payload, compresslevel=ui.GZIP_STATIC_LEVEL)),
    }
    winner = min(sizes, key=lambda name: sizes[name])
    print(f"inlined shell: {len(payload)} B uncompressed")
    for name in sorted(sizes, key=lambda key: sizes[key]):
        print(f"  {name:<5} {sizes[name]:>8,} B")
    print(f"smallest: {winner} ({sizes[winner]:,} B)")
    print(f"budget:   ui._TCP_CWND_BUDGET = {ui._TCP_CWND_BUDGET:,} B")
    if sizes[winner] > ui._TCP_CWND_BUDGET:
        print(f"OVER by {sizes[winner] - ui._TCP_CWND_BUDGET:,} B", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
