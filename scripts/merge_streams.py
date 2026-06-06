#!/usr/bin/env python3
"""Merge a run's *-findings.jsonl streams into one summary.json.

Each `<key>-findings.jsonl` becomes `summary[<key>] = [records...]`, where <key>
is the filename minus the `-findings.jsonl` suffix (e.g. entra, azure-org, aws,
google). The result is written as summary.json in the same directory as the
streams. Invoked by the audit actions at the end of a run when stream-merging is
enabled. Best-effort, stdlib only — never fails the audit.

Run:
  python3 scripts/merge_streams.py <streams-dir>
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

SUFFIX = "-findings.jsonl"


def merge(streams_dir: Path) -> dict:
    merged: dict[str, list] = {}
    for jf in sorted(streams_dir.rglob("*" + SUFFIX)):
        key = jf.name[: -len(SUFFIX)]
        for line in jf.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                merged.setdefault(key, []).append(json.loads(line))
            except json.JSONDecodeError:
                print(f"::warning::skipping malformed line in {jf.name}")
    return merged


def main() -> int:
    streams_dir = Path(
        (sys.argv[1] if len(sys.argv) > 1 else "")
        or os.environ.get("STACKQL_STREAM_DIR")
        or "."
    )
    if not streams_dir.is_dir():
        print(f"::warning::streams dir not found: {streams_dir}; nothing to merge")
        return 0

    merged = merge(streams_dir)
    total = sum(len(v) for v in merged.values())
    out = streams_dir / "summary.json"
    try:
        out.write_text(json.dumps(merged, default=str, indent=2))
        print(f"::notice::wrote {out} ({len(merged)} stream(s), {total} record(s))")
    except OSError as e:
        print(f"::warning::could not write summary.json: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
