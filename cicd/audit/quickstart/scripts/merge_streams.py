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

import datetime
import json
import os
import sys
from pathlib import Path

SUFFIX = "-findings.jsonl"


ASSAYED_SUFFIX = "-assayed.jsonl"
ROWS_SUFFIX = "-rows.jsonl"
SKIPPED_SUFFIX = "-skipped.jsonl"

# Every stream key (a findings base like "gcp-org" or an assayed/skipped dirname
# like "google") maps to one cloud bucket for the executive roll-up.
_CLOUD = {
    "s3": "AWS", "aws-regions": "AWS", "aws": "AWS",
    "finops-aws": "AWS", "finops-aws-rightsizing": "AWS",
    "gcp-org": "GCP", "google": "GCP", "finops-gcp": "GCP",
    "azure-org": "Azure", "azure": "Azure", "finops-azure": "Azure",
    "entra": "Entra", "entra_id": "Entra",
}
_CLOUD_ORDER = ["AWS", "GCP", "Azure", "Entra"]
_REAL_SEV = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_SEV_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦"}


def _cloud_of(key: str) -> str:
    return _CLOUD.get(key, key)


def _read_jsonl(path: Path) -> list:
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            print(f"::warning::skipping malformed line in {path.name}")
    return out


def merge(streams_dir: Path) -> dict:
    merged: dict[str, list] = {}
    assayed: dict[str, list] = {}
    for jf in sorted(streams_dir.rglob("*.jsonl")):
        if jf.name.endswith(ASSAYED_SUFFIX):
            # per-check tally (incl. clean/0) so absent resources are explicit
            assayed.setdefault(jf.name[: -len(ASSAYED_SUFFIX)], []).extend(_read_jsonl(jf))
        elif jf.name.endswith(SUFFIX):
            merged.setdefault(jf.name[: -len(SUFFIX)], []).extend(_read_jsonl(jf))
    if assayed:
        merged["assayed"] = assayed
    return merged


def _run_time(streams_dir: Path) -> str:
    """UTC 'YYYY-MM-DD HH:MM' from the run stamp (the stream dir's name / RUN_STAMP
    epoch), falling back to now."""
    stamp = streams_dir.name
    epoch = None
    if stamp.isdigit():
        epoch = int(stamp)
    elif os.environ.get("RUN_STAMP", "").strip().isdigit():
        epoch = int(os.environ["RUN_STAMP"].strip())
    when = (datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc) if epoch
            else datetime.datetime.now(datetime.timezone.utc))
    return when.strftime("%Y-%m-%d %H:%M UTC")


def _rollup_md(streams_dir: Path, merged: dict) -> str:
    """Executive cross-cloud roll-up: a dated total line + a per-cloud table
    (severity breakdown · population scanned · skipped checks). Built purely from
    the merged findings/assayed streams + the *-skipped.jsonl records — no
    fabricated numbers. UNKNOWN enum-error records are excluded from the tally."""
    per: dict[str, dict[str, int]] = {}   # cloud -> {severity: finding count}
    for key, recs in merged.items():
        if key == "assayed" or not isinstance(recs, list):
            continue
        d = per.setdefault(_cloud_of(key), {s: 0 for s in _REAL_SEV})
        for r in recs:
            sev = (r.get("severity") or "").upper()
            if sev in d:
                d[sev] += 1

    scanned_by: dict[str, int] = {}   # cloud -> largest population any check scanned
    checks_by: dict[str, int] = {}
    for key, recs in (merged.get("assayed") or {}).items():
        cloud = _cloud_of(key)
        checks_by[cloud] = checks_by.get(cloud, 0) + len(recs)
        for r in recs:
            sc = r.get("scanned")
            if isinstance(sc, int):
                scanned_by[cloud] = max(scanned_by.get(cloud, 0), sc)

    skipped_by: dict[str, set] = {}
    for jf in sorted(streams_dir.rglob("*" + SKIPPED_SUFFIX)):
        cloud = _cloud_of(jf.name[: -len(SKIPPED_SUFFIX)])
        for r in _read_jsonl(jf):
            base = str(r.get("check") or r.get("name") or "?")
            skipped_by.setdefault(cloud, set()).add(Path(base).name.rsplit(".", 1)[0])

    present = set(per) | set(scanned_by) | set(checks_by) | set(skipped_by)
    clouds = [c for c in _CLOUD_ORDER if c in present] + sorted(present - set(_CLOUD_ORDER))

    tot_sev = {s: sum(per.get(c, {}).get(s, 0) for c in clouds) for s in _REAL_SEV}
    total = sum(tot_sev.values())
    meta = f"{len(clouds)} clouds · {sum(checks_by.values())} checks"
    total_skipped = sum(len(v) for v in skipped_by.values())
    if total_skipped:
        meta += f" · {total_skipped} skipped"

    head_bits = " · ".join(f"{_SEV_ICON[s]} {tot_sev[s]} {s}" for s in _REAL_SEV)
    lines = [
        f"# Cloud Audit — {_run_time(streams_dir)}",
        f"**{total} findings** · {head_bits}   ·   {meta}",
        "",
        "| Cloud | 🟥 | 🟧 | 🟨 | 🟦 | Findings | Scanned | Skipped |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for c in clouds:
        d = per.get(c, {s: 0 for s in _REAL_SEV})
        f = sum(d[s] for s in _REAL_SEV)
        sc = scanned_by.get(c)
        sc_str = f"{sc:,}" if isinstance(sc, int) else "—"
        sk = skipped_by.get(c)
        sk_str = ", ".join(sorted(sk)) if sk else "—"
        lines.append(
            f"| {c} | {d['CRITICAL']} | {d['HIGH']} | {d['MEDIUM']} | {d['LOW']} | {f} | {sc_str} | {sk_str} |")
    return "\n".join(lines)


def _prepend_rollup(streams_dir: Path, merged: dict) -> None:
    """Prepend the executive roll-up to report.md (GITHUB_STEP_SUMMARY, else a
    report.md in the stream dir). Best-effort — never fails the merge."""
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    report = Path(summary) if summary else (streams_dir / "report.md")
    try:
        existing = report.read_text() if report.exists() else ""
        if existing.lstrip().startswith("# Cloud Audit —"):
            return  # already prepended (e.g. a merge re-run) — don't stack roll-ups
        report.write_text(_rollup_md(streams_dir, merged) + "\n\n---\n\n" + existing)
        print(f"::notice::prepended executive roll-up to {report}")
    except OSError as e:
        print(f"::warning::could not write roll-up to report.md: {e}")


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
    total = sum(len(v) for v in merged.values() if isinstance(v, list))
    out = streams_dir / "summary.json"
    try:
        out.write_text(json.dumps(merged, default=str, indent=2))
        print(f"::notice::wrote {out} ({len(merged)} stream(s), {total} record(s))")
    except OSError as e:
        print(f"::warning::could not write summary.json: {e}")

    # findings.json — flat, fully-traceable result rows (every row + its
    # originating check/query + full fields) for downstream/agent consumption.
    # Written alongside summary.json (same folder => same uploaded artifact);
    # summary.json is untouched.
    rows: list = []
    for jf in sorted(streams_dir.rglob("*" + ROWS_SUFFIX)):
        rows.extend(_read_jsonl(jf))
    findings_out = streams_dir / "findings.json"
    try:
        findings_out.write_text(json.dumps({"findings": rows}, default=str, indent=2))
        print(f"::notice::wrote {findings_out} ({len(rows)} traceable row(s))")
    except OSError as e:
        print(f"::warning::could not write findings.json: {e}")

    # Executive cross-cloud roll-up, prepended to report.md. Best-effort: a
    # roll-up failure must never fail the audit, so swallow anything unexpected.
    try:
        _prepend_rollup(streams_dir, merged)
    except Exception as e:  # noqa: BLE001 — merge is documented as never-fatal
        print(f"::warning::roll-up skipped: {e}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
