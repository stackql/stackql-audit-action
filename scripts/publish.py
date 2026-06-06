#!/usr/bin/env python3
"""Publish audit findings to a reporting/observability backend.

Disjoint from audit.py / discover.py — this consumes the artifacts they already
produce (the per-run `*-findings.jsonl` streams) and does NOT change how an audit
runs. It is only invoked by the separate `actions/publish` action.

Two outputs from one canonical schema:
  * batch  — a single {run, summary, findings[]} JSON document (run-report.json),
             optionally POSTed to STACKQL_AUDIT_REPORT_URL.
  * stream — the NDJSON files are left as-is for a log collector to tail; S3 sync
             is handled by the action (`aws s3 cp`), not here.

Best-effort by design: a backend being down degrades to "wrote the local file",
never a non-zero exit. Stdlib only.

Run:
  PUBLISH_FINDINGS_DIR=path/to/logs python3 scripts/publish.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _run_id() -> str:
    return (os.environ.get("GITHUB_RUN_ID")
            or os.environ.get("RUN_STAMP")
            or time.strftime("%Y%m%d-%H%M%S"))


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _target_from_name(path: Path) -> str:
    # e.g. entra-findings.jsonl -> entra ; aws-regions-findings.jsonl -> aws-regions
    return path.name[: -len("-findings.jsonl")] if path.name.endswith("-findings.jsonl") else path.stem


def _canonical(raw: dict, target: str, rid: str) -> dict:
    """Lift the stable dimensions out of a raw stream line; keep the full line
    under `fields` so nothing is lost."""
    return {
        "run_id": rid,
        "ts": _now_iso(),
        "tool": "stackql-audit",
        "target": target,
        "severity": (raw.get("severity") or "MEDIUM").upper(),
        "check_id": raw.get("check"),
        "check_name": raw.get("name"),
        "fields": raw,
    }


def collect(findings_dir: Path, rid: str) -> list[dict]:
    findings: list[dict] = []
    for jf in sorted(findings_dir.rglob("*-findings.jsonl")):
        target = _target_from_name(jf)
        for line in jf.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                print(f"::warning::skipping malformed line in {jf.name}")
                continue
            findings.append(_canonical(raw, target, rid))
    return findings


def summarize(findings: list[dict]) -> dict:
    by_sev = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        if sev in by_sev:
            by_sev[sev] += 1
    highest = next((s for s in SEVERITIES if by_sev[s]), "NONE")
    return {"by_severity": by_sev, "total": len(findings), "highest": highest}


def post_report(url: str, payload: bytes) -> None:
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json"},
    )
    token = os.environ.get("STACKQL_AUDIT_REPORT_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    timeout = float(os.environ.get("STACKQL_AUDIT_REPORT_TIMEOUT", "10"))
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (operator-supplied URL)
        resp.read()


def main() -> int:
    findings_dir = Path(
        (sys.argv[1] if len(sys.argv) > 1 else "")
        or os.environ.get("PUBLISH_FINDINGS_DIR")
        or "cicd/log"
    )
    if not findings_dir.is_dir():
        print(f"::warning::findings dir not found: {findings_dir}; nothing to publish")
        return 0

    rid = _run_id()
    findings = collect(findings_dir, rid)
    report = {
        "run_id": rid,
        "generated_at": _now_iso(),
        "tool": "stackql-audit",
        "summary": summarize(findings),
        "findings": findings,
    }

    out = findings_dir / "run-report.json"
    payload = json.dumps(report, default=str).encode()
    try:
        out.write_bytes(payload)
        print(f"::notice::wrote {out} ({report['summary']['total']} findings)")
    except OSError as e:
        print(f"::warning::could not write run report: {e}")

    url = os.environ.get("STACKQL_AUDIT_REPORT_URL", "").strip()
    if url:
        try:
            post_report(url, payload)
            print(f"::notice::posted run report ({report['summary']['total']} findings) to reporting backend")
        except (urllib.error.URLError, OSError, ValueError) as e:
            print(f"::warning::run report POST failed (kept local file {out}): {e}")
    else:
        print("::notice::STACKQL_AUDIT_REPORT_URL not set — wrote run-report.json only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
