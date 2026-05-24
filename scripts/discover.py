#!/usr/bin/env python3
"""Next-gen enumerated audit orchestrator — disjoint from the published audit.py.

Implemented target: `s3` — the AWS S3 full audit. Lists every bucket (one cheap
call), then fetches each bucket's detail under bounded, throttle-aware
parallelism, and evaluates the filter-only checks in queries/s3/ against that
detail row. One detail fetch per bucket; all checks run against it.

Reuses audit.py for auth, stackql execution, filters, and rendering — so checks
aren't duplicated and the published single-scope action is untouched.

Run:
  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=us-east-1 \
  ACTION_PATH="$(pwd)" python3 scripts/discover.py s3

Tuning: STACKQL_S3_PARALLEL (default 8) bounds concurrent detail fetches.
"""

from __future__ import annotations

import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

import audit

# Detail columns the S3 filters read; kept narrow to limit payload per bucket.
S3_DETAIL_COLS = [
    "bucket_name",
    "region",
    "public_access_block_configuration",
    "bucket_encryption",
    "versioning_configuration",
    "ownership_controls",
]
THROTTLE_MARKERS = ("slowdown", "throttl", "requestlimitexceeded", "rate exceeded", "503")


def _is_throttle(err: str | None) -> bool:
    e = (err or "").lower()
    return any(m in e for m in THROTTLE_MARKERS)


def _setup_log_dir() -> Path:
    action_path = Path(os.environ.get("ACTION_PATH", "."))
    run_stamp = os.environ.get("RUN_STAMP") or time.strftime("%Y%m%d-%H%M%S")
    root = Path(os.environ.get("STACKQL_AUDIT_LOG_DIR") or (action_path / "cicd" / "log"))
    d = root / run_stamp
    d.mkdir(parents=True, exist_ok=True)
    return d


def list_bucket_names(region: str, auth: str, log_dir: Path) -> list[str]:
    q = f"SELECT bucket_name, region FROM aws.s3.buckets_list_only WHERE region = '{region}';"
    rows, err, _ = audit.run_stackql(q, auth, log_dir / "s3__list.log")
    if err:
        print(f"::error::S3 bucket listing failed: {err.splitlines()[0]}")
        return []
    return [r["bucket_name"] for r in (rows or []) if r.get("bucket_name")]


def fetch_bucket_detail(bucket: str, region: str, auth: str, log_dir: Path,
                        retries: int = 4, base_delay: float = 0.5):
    """Fetch one bucket's detail row, retrying with backoff on throttling."""
    cols = ", ".join(S3_DETAIL_COLS)
    q = (f"SELECT {cols} FROM aws.s3.buckets "
         f"WHERE region = '{region}' AND data__Identifier = '{bucket}';")
    safe = bucket.replace("/", "_")
    for attempt in range(retries + 1):
        rows, err, _ = audit.run_stackql(q, auth, log_dir / f"s3__{safe}.log")
        if err and _is_throttle(err) and attempt < retries:
            time.sleep(base_delay * (2 ** attempt) + random.random() * base_delay)
            continue
        if err:
            return None, err
        return (rows[0] if rows else None), None
    return None, "exhausted retries (throttled)"


def load_s3_checks(action_path: Path) -> list[dict]:
    checks: list[dict] = []
    qdir = action_path / "queries" / "s3"
    for cf in sorted(list(qdir.glob("*.yaml")) + list(qdir.glob("*.yml"))):
        c = yaml.safe_load(cf.open())
        c["_file"] = f"s3/{cf.name}"
        c["_provider"] = "aws"
        checks.append(c)
    return checks


def run_s3() -> int:
    region = os.environ.get("AWS_REGION", "").strip()
    if not region:
        print("::error::AWS_REGION is required for the S3 audit")
        return 2
    parallel = max(1, int(os.environ.get("STACKQL_S3_PARALLEL", "8")))
    fail_on = os.environ.get("FAIL_ON_SEVERITY", "HIGH").upper()
    fail_threshold = audit.SEVERITY_ORDER.get(fail_on, 3)

    auth, enabled = audit.build_auth()
    if "aws" not in enabled:
        print("::error::no AWS credentials supplied")
        return 2

    action_path = Path(os.environ.get("ACTION_PATH", "."))
    filters_mod = audit.load_filters_module(action_path)
    log_dir = _setup_log_dir()
    checks = load_s3_checks(action_path)
    if not checks:
        print("::warning::no S3 checks found in queries/s3/")
        return 0

    buckets = list_bucket_names(region, auth, log_dir)
    print(f"::notice::S3: {len(buckets)} bucket(s); fetching detail with {parallel} worker(s)")

    findings: dict[str, list[dict]] = {c["_file"]: [] for c in checks}
    fetch_errors: list[tuple[str, str]] = []

    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futs = {pool.submit(fetch_bucket_detail, b, region, auth, log_dir): b for b in buckets}
        for fut in as_completed(futs):
            bucket = futs[fut]
            detail, err = fut.result()
            if err:
                fetch_errors.append((bucket, err))
                print(f"::warning::S3 detail failed for {bucket}: {err.splitlines()[0]}")
                continue
            if not detail:
                continue
            for c in checks:
                try:
                    hits = audit.apply_filter(filters_mod, c["filter"], [detail], c.get("filter_args"))
                except Exception as e:
                    print(f"::warning::filter {c['filter']} errored on {bucket}: {e}")
                    continue
                findings[c["_file"]].extend(hits)

    by_sev = {k: 0 for k in audit.SEVERITY_ORDER}
    total = 0
    highest = "NONE"
    sections: list[str] = []
    for c in checks:
        rows = findings[c["_file"]]
        if not rows:
            sections.append(audit.render_pass(c))
            continue
        sev = c.get("severity", "MEDIUM").upper()
        by_sev[sev] += len(rows)
        total += len(rows)
        if audit.SEVERITY_ORDER[sev] > audit.SEVERITY_ORDER[highest]:
            highest = sev
        sections.append(audit.render_findings(c, rows))

    out = [
        "# StackQL S3 Audit",
        (f"**Region:** `{region}`  ·  **Buckets:** {len(buckets)}  ·  "
         f"**Checks:** {len(checks)}  ·  **Fetch errors:** {len(fetch_errors)}"),
        "", "## Summary", "| Severity | Findings |", "| --- | --- |",
    ]
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        out.append(f"| {audit.SEVERITY_BADGE[s]} | {by_sev[s]} |")
    out.append(f"| **Total** | **{total}** |\n")
    out.append("## Checks\n")
    out.extend(sections)
    rendered = "\n".join(out)
    print(rendered)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(rendered + "\n")
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as f:
            f.write(f"findings-count={total}\n")
            f.write(f"highest-severity={highest}\n")

    print(f"::notice::stackql logs in {log_dir}")
    if total > 0 and fail_threshold > 0 and audit.SEVERITY_ORDER[highest] >= fail_threshold:
        print(f"::error::S3 audit found {highest} findings (fail-on-severity={fail_on})")
        return 1
    return 0


# Extension point: add "aws-regions" and "gcp-org" targets here.
COMMANDS = {"s3": run_s3}


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DISCOVER_TARGET", "s3")
    fn = COMMANDS.get(target)
    if fn is None:
        print(f"::error::unknown target '{target}'; available: {', '.join(COMMANDS)}")
        return 2
    return fn()


if __name__ == "__main__":
    sys.exit(main())
