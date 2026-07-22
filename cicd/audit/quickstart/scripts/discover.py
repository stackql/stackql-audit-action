#!/usr/bin/env python3
"""Next-gen enumerated ("deep") audit orchestrator — disjoint from audit.py.

Targets (positional arg, or DISCOVER_TARGET):
  s3          — AWS S3 full audit: list every bucket, fetch each bucket's detail
                under bounded, throttle-aware parallelism, evaluate queries/s3/.
  aws-regions — enumerate enabled regions, run queries/aws/ per region.
  gcp-org     — descend an org's folders to ACTIVE projects, run queries/google/.
  azure-org   — descend a management group's subscriptions, run queries/azure/.
  entra       — Entra ID is tenant-global: run queries/entra_id/ once, flat (no
                enumeration/descent).

All deep targets share one path: enumerate scopes -> run the existing checks per
scope under a Budget (org-nodes / queries / wall-clock; -1 = unlimited), with
findings streamed to JSONL as they arrive. audit.py and the published action are
untouched — this only adds a parallel deep path.

Run:
  ACTION_PATH="$(pwd)" AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
  AWS_REGION=us-east-1 python3 scripts/discover.py s3

Tuning: STACKQL_{S3,AWS,GCP,AZURE}_PARALLEL bound concurrency; STACKQL_DEEP_MAX_NODES
/ _MAX_QUERIES / _TIMEOUT cap the run; STACKQL_AUDIT_STREAM overrides the JSONL path.
"""

from __future__ import annotations

import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

import audit
from budget import Budget

# Detail columns the S3 filters read; kept narrow to limit payload per bucket.
S3_DETAIL_COLS = [
    "bucket_name",
    "region",
    "regional_domain_name",
    "public_access_block_configuration",
    "bucket_encryption",
    "versioning_configuration",
    "ownership_controls",
]
# Per-attempt backoff for throttled per-resource detail fetches (indexed by
# attempt 0..2). ~2s, 5s, 12s before ±25% jitter — ≈20s worst case per resource.
RETRY_DELAYS = (2.0, 5.0, 12.0)


_BUCKET_REGION_RE = re.compile(r"\.s3[.-]([a-z0-9-]+)\.amazonaws\.com$", re.IGNORECASE)


def _bucket_region(detail: dict, fallback: str) -> str:
    """Derive a bucket's home region from regional_domain_name.

    The `region` column only echoes the caller's endpoint region, not where the
    bucket lives; e.g. 'b.s3.us-west-2.amazonaws.com' -> 'us-west-2', and the
    legacy 'b.s3.amazonaws.com' form -> 'us-east-1'.
    """
    rdn = detail.get("regional_domain_name") or ""
    m = _BUCKET_REGION_RE.search(rdn)
    if m:
        return m.group(1)
    return "us-east-1" if ".s3.amazonaws.com" in rdn else fallback


def _setup_log_dir() -> Path:
    action_path = Path(os.environ.get("ACTION_PATH", "."))
    run_stamp = os.environ.get("RUN_STAMP") or time.strftime("%Y%m%d-%H%M%S")
    root = Path(os.environ.get("STACKQL_AUDIT_LOG_DIR") or (action_path / "cicd" / "log"))
    d = root / run_stamp
    d.mkdir(parents=True, exist_ok=True)
    return d


def _setup_stream_dir() -> Path:
    """Run-stamped directory for the *-findings.jsonl streams, kept separate from
    the per-invocation .log files. Falls back to STACKQL_AUDIT_LOG_DIR (then
    cicd/log) when STACKQL_AUDIT_STREAM_DIR is unset, so local runs are unchanged;
    the deep/oidc actions point it at deep-audit-data-streams/."""
    action_path = Path(os.environ.get("ACTION_PATH", "."))
    run_stamp = os.environ.get("RUN_STAMP") or time.strftime("%Y%m%d-%H%M%S")
    root = Path(os.environ.get("STACKQL_AUDIT_STREAM_DIR")
                or os.environ.get("STACKQL_AUDIT_LOG_DIR")
                or (action_path / "cicd" / "log"))
    d = root / run_stamp
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_checks(action_path: Path, dirname: str, provider_tag: str) -> list[dict]:
    checks: list[dict] = []
    qdir = action_path / "queries" / dirname
    for cf in sorted(list(qdir.glob("*.yaml")) + list(qdir.glob("*.yml"))):
        c = yaml.safe_load(cf.open())
        c["_file"] = f"{dirname}/{cf.name}"
        c["_provider"] = provider_tag
        if audit.check_skipped(c):
            print(f"skipping {c['_file']}: matched STACKQL_AUDIT_SKIP")
            # Record it so the merge roll-up can name what was skipped, rather than
            # the check silently vanishing from the report.
            try:
                with open(_setup_stream_dir() / f"{dirname}-skipped.jsonl", "a", buffering=1) as sf:
                    sf.write(json.dumps({
                        "check": c["_file"],
                        "name": c.get("name"),
                        "severity": (c.get("severity") or "MEDIUM").upper(),
                        "reason": "STACKQL_AUDIT_SKIP",
                    }) + "\n")
            except OSError:
                pass
            continue
        checks.append(c)
    return checks


# --- shared report + scope-fanout core -------------------------------------

def _budget_line(budget: Budget, stopped_reason: str | None, skipped: int) -> str:
    snap = budget.snapshot()
    line = (f"**Budget:** {budget.describe_limits()}  ·  **Visited:** {snap['nodes']} nodes / "
            f"{snap['queries']} queries / {snap['elapsed_s']}s")
    if stopped_reason:
        line += f"  ·  ⚠️ **Stopped early:** {stopped_reason} ({skipped} skipped) — partial results"
    return line


def _finalize_report(title: str, header_lines: list[str], checks: list[dict],
                     findings: dict[str, list[dict]], label: str | None,
                     log_dir: Path, fail_on: str, fail_threshold: int,
                     target: str = "", scanned: dict | None = None) -> int:
    """Render the markdown summary + sections, emit outputs, return the exit code.

    If `label` is set, it's prepended as a column to each finding (e.g. which
    project/region/subscription the finding came from). If `target` is set, an
    assayed-tally is written so absent/clean resources are reported plainly in the
    data output (not just silently missing): one row per check with its count and
    status (clean / findings). `scanned` is {check_file: population} so each check
    reports its findings *out of how many* (None = no denominator)."""
    scanned = scanned or {}
    by_sev = {k: 0 for k in audit.SEVERITY_ORDER}
    total = 0
    highest = "NONE"
    sections: list[str] = []
    for c in checks:
        rows = findings.get(c["_file"], [])
        sc = scanned.get(c["_file"])
        if not rows:
            sections.append(audit.render_pass(c, sc))
            continue
        sev = c.get("severity", "MEDIUM").upper()
        by_sev[sev] += len(rows)
        total += len(rows)
        if audit.SEVERITY_ORDER[sev] > audit.SEVERITY_ORDER[highest]:
            highest = sev
        if label:
            base = c.get("columns") or [k for k in rows[0].keys() if k != label]
            rc = {**c, "columns": [label] + base}
        else:
            rc = c
        sections.append(audit.render_findings(rc, rows, sc))

    out = [title, *header_lines, "", "## Summary", "| Severity | Findings |", "| --- | --- |"]
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        out.append(f"| {audit.SEVERITY_BADGE[s]} | {by_sev[s]} |")
    out.append(f"| **Total** | **{total}** |\n")
    out.append("## Checks\n")
    out.extend(sections)
    rendered = "\n".join(out)
    print(rendered)

    # Assayed tally: one row per check, including the clean ones, so a resource
    # absent from the client's space is told plainly in the data — not omitted.
    if target:
        try:
            with open(_setup_stream_dir() / f"{target}-assayed.jsonl", "a", buffering=1) as af:
                for c in checks:
                    n = len(findings.get(c["_file"], []))
                    af.write(json.dumps({
                        "check": c["_file"],
                        "name": c.get("name"),
                        "severity": (c.get("severity") or "MEDIUM").upper(),
                        "count": n,
                        "scanned": scanned.get(c["_file"]),
                        "status": "findings" if n else "clean",
                    }) + "\n")
        except OSError as e:
            print(f"warning: could not write assayed tally for {target}: {e}")

        # Rich, fully-traceable rows for downstream/recommendation agents: every
        # result row + the check/query that produced it + the full field set,
        # independent of severity (so an agent can act on e.g. all kind=compute).
        rid = os.environ.get("GITHUB_RUN_ID") or os.environ.get("RUN_STAMP") or ""
        try:
            with open(_setup_stream_dir() / f"{target}-rows.jsonl", "a", buffering=1) as rf:
                for c in checks:
                    for row in findings.get(c["_file"], []):
                        rf.write(json.dumps({
                            "run_id": rid,
                            "target": target,
                            "provider": c.get("_provider"),
                            "check_id": c.get("id"),
                            "check_file": c.get("_file"),
                            "check_name": c.get("name"),
                            "query": (c.get("query") or "").strip(),
                            "severity": (c.get("severity") or "MEDIUM").upper(),
                            "category": row.get("category"),
                            "kind": row.get("kind"),
                            "region": row.get("region"),
                            "fields": row,
                        }, default=str) + "\n")
        except OSError as e:
            print(f"warning: could not write rows for {target}: {e}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(rendered + "\n")
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as f:
            f.write(f"findings-count={total}\n")
            f.write(f"highest-severity={highest}\n")

    print(f"stackql logs in {log_dir}")
    if total > 0 and fail_threshold > 0 and audit.SEVERITY_ORDER[highest] >= fail_threshold:
        print(f"error: deep audit found {highest} findings (fail-on-severity={fail_on})")
        return 1
    return 0


def audit_scope(label: str, scope_var: str, scope_value: str, checks: list[dict],
                auth: str, filters_mod, log_dir: Path, budget: Budget):
    """Run every query-check for one scope (region / project / subscription),
    substituting ${scope_var}. Returns (findings, errors, scanned) — findings is
    {check_file: rows} (rows tagged with `label`=scope_value); errors is a list
    of {failed_check, error} for queries that errored (e.g. throttled), so the
    caller can surface them as UNKNOWN instead of dropping them; scanned is
    {check_file: pre_filter_row_count} for filter checks (the population for this
    one scope, summed across scopes by the caller). Returns None if the budget was
    exhausted (scope skipped)."""
    if budget.should_stop():
        return None
    budget.add_node()
    safe = scope_value.replace("/", "_")
    out: dict[str, list[dict]] = {}
    errors: list[dict] = []
    scanned: dict[str, int] = {}
    for c in checks:
        query = c["query"].replace("${" + scope_var + "}", scope_value)
        budget.add_query()
        log = log_dir / f"{label}__{safe}__{c['_file'].replace('/', '_')}.log"
        rows, err, _ = audit.run_stackql(query, auth, log)
        if err:
            errors.append({"failed_check": c["_file"], "error": err.splitlines()[0] if err else ""})
            continue
        if c.get("filter"):
            scanned[c["_file"]] = len(rows or [])  # population before the filter narrows it
            try:
                rows = audit.apply_filter(filters_mod, c["filter"], rows or [], c.get("filter_args"))
            except Exception as e:
                print(f"warning: filter {c['filter']} errored on {scope_value}: {e}")
                continue
        if rows:
            for r in rows:
                r[label] = scope_value
            out[c["_file"]] = rows
    return out, errors, scanned


def _scope_fanout(label: str, scope_var: str, scope_values: list[str], descent_stop: str | None,
                  checks: list[dict], auth: str, filters_mod, log_dir: Path, budget: Budget,
                  parallel: int, stream_name: str):
    """Audit each scope in parallel; stream findings; return (findings, stopped_reason,
    skipped, audited, scanned) — scanned is {check_file: total population scanned across
    all scopes} for filter checks (None for WHERE-clause checks, which have no denominator)."""
    stream_path = Path(os.environ.get("STACKQL_AUDIT_STREAM") or (_setup_stream_dir() / stream_name))
    print(f"streaming findings to {stream_path}")
    findings: dict[str, list[dict]] = {c["_file"]: [] for c in checks}
    scanned_totals: dict[str, int | None] = {c["_file"]: (0 if c.get("filter") else None) for c in checks}
    skipped = 0
    audited = 0
    stopped_reason = descent_stop
    with open(stream_path, "a", buffering=1) as stream, \
            ThreadPoolExecutor(max_workers=parallel) as pool:
        futs = {pool.submit(audit_scope, label, scope_var, v, checks, auth, filters_mod, log_dir, budget): v
                for v in scope_values}
        for fut in as_completed(futs):
            v = futs[fut]
            res = fut.result()
            if res is None:
                skipped += 1
                if stopped_reason is None:
                    stopped_reason = budget.should_stop()
                    print(f"warning: deep audit stopping early — {stopped_reason}; analyzing partial results")
                continue
            out_map, errors, scanned_map = res
            audited += 1
            for cfile, n in scanned_map.items():
                scanned_totals[cfile] = (scanned_totals.get(cfile) or 0) + n
            for cfile, rows in out_map.items():
                findings[cfile].extend(rows)
                c = next(x for x in checks if x["_file"] == cfile)
                sev = c.get("severity", "MEDIUM").upper()
                for r in rows:
                    _keep = {
                        k: r[k] for k in (
                            "estimated_monthly_usd",
                            "volumeId", "publicIp", "address", "name", "size", "size_gb", "sizeGb",
                        ) if k in r
                    }
                    stream.write(json.dumps({**_keep, label: v, "check": cfile, "name": c["name"], "severity": sev}) + "\n")
            # Surface errored (e.g. throttled) checks as UNKNOWN rather than dropping them.
            for e in errors:
                stream.write(json.dumps({
                    label: v,
                    "check": "_meta/enum-error",
                    "name": "scope detail enumeration failed",
                    "severity": "UNKNOWN",
                    "failed_check": e["failed_check"],
                    "error": e["error"],
                }) + "\n")
    return findings, stopped_reason, skipped, audited, scanned_totals


# --- target: AWS S3 full audit ---------------------------------------------

def list_bucket_names(region: str, auth: str, log_dir: Path, budget: Budget) -> list[str]:
    q = f"SELECT bucket_name, region FROM aws.s3.buckets_list_only WHERE region = '{region}';"
    budget.add_query()
    rows, err, _ = audit.run_stackql(q, auth, log_dir / "s3__list.log")
    if err:
        print(f"error: S3 bucket listing failed: {err.splitlines()[0]}")
        return []
    return [r["bucket_name"] for r in (rows or []) if r.get("bucket_name")]


def fetch_bucket_detail(bucket: str, region: str, auth: str, log_dir: Path, budget: Budget,
                        retries: int = 3):
    """Fetch one bucket's detail row, retrying throttles on the RETRY_DELAYS
    schedule (2s, 5s, 12s ±25% jitter — ≈20s worst case per bucket).

    Returns (detail, error, stop_reason). If the budget is exhausted the bucket
    is skipped (no query issued) and stop_reason explains why."""
    stop = budget.should_stop()
    if stop:
        return None, None, stop
    budget.add_node()
    cols = ", ".join(S3_DETAIL_COLS)
    q = (f"SELECT {cols} FROM aws.s3.buckets "
         f"WHERE region = '{region}' AND data__Identifier = '{bucket}';")
    safe = bucket.replace("/", "_")
    for attempt in range(retries + 1):
        budget.add_query()
        rows, err, _ = audit.run_stackql(q, auth, log_dir / f"s3__{safe}.log")
        if err and audit._is_throttle(err) and attempt < retries:
            time.sleep(RETRY_DELAYS[attempt] * (0.75 + random.random() * 0.5))
            continue
        if err:
            return None, err, None
        return (rows[0] if rows else None), None, None
    return None, "exhausted retries (throttled)", None


def run_s3() -> int:
    if not audit.provider_allowed("aws"):
        print("skipping s3: aws not in STACKQL_AUDIT_PROVIDERS")
        return 0
    region = os.environ.get("AWS_REGION", "").strip()
    if not region:
        print("error: AWS_REGION is required for the S3 audit")
        return 2
    parallel = max(1, int(os.environ.get("STACKQL_S3_PARALLEL", "8")))
    fail_on = os.environ.get("FAIL_ON_SEVERITY", "HIGH").upper()
    fail_threshold = audit.SEVERITY_ORDER.get(fail_on, 3)

    auth, _ = audit.build_auth()

    action_path = Path(os.environ.get("ACTION_PATH", "."))
    filters_mod = audit.load_filters_module(action_path)
    log_dir = _setup_log_dir()
    checks = load_checks(action_path, "s3", "aws")
    if not checks:
        print("warning: no S3 checks found in queries/s3/")
        return 0

    budget = Budget.from_env(os.environ)
    print(f"deep audit budget: {budget.describe_limits()}")

    buckets = list_bucket_names(region, auth, log_dir, budget)
    print(f"S3: {len(buckets)} bucket(s); fetching detail with {parallel} worker(s)")

    stream_path = Path(os.environ.get("STACKQL_AUDIT_STREAM") or (_setup_stream_dir() / "s3-findings.jsonl"))
    print(f"streaming findings to {stream_path}")

    findings: dict[str, list[dict]] = {c["_file"]: [] for c in checks}
    fetch_errors: list[tuple[str, str]] = []
    skipped = 0
    stopped_reason: str | None = None

    # buffering=1 = line-buffered: every finding is flushed to the OS on write,
    # so partial results survive an abrupt exit mid-run.
    with open(stream_path, "a", buffering=1) as stream, \
            ThreadPoolExecutor(max_workers=parallel) as pool:
        futs = {pool.submit(fetch_bucket_detail, b, region, auth, log_dir, budget): b for b in buckets}
        for fut in as_completed(futs):
            bucket = futs[fut]
            detail, err, stop_reason = fut.result()
            if stop_reason:
                skipped += 1
                if stopped_reason is None:
                    stopped_reason = stop_reason
                    print(f"warning: deep audit stopping early — {stop_reason}; analyzing partial results")
                continue
            if err:
                fetch_errors.append((bucket, err))
                first = err.splitlines()[0] if err else ""
                print(f"warning: S3 detail failed for {bucket}: {first}")
                # Surface the unresolved bucket as one UNKNOWN finding rather than
                # dropping it silently — one per bucket, not per check.
                stream.write(json.dumps({
                    "bucket": bucket,
                    "region": region,
                    "check": "_meta/enum-error",
                    "name": "S3 bucket detail enumeration failed",
                    "severity": "UNKNOWN",
                    "error": first,
                }) + "\n")
                continue
            if not detail:
                continue
            detail["region"] = _bucket_region(detail, region)  # true home region, not the endpoint
            for c in checks:
                try:
                    hits = audit.apply_filter(filters_mod, c["filter"], [detail], c.get("filter_args"))
                except Exception as e:
                    print(f"warning: filter {c['filter']} errored on {bucket}: {e}")
                    continue
                if not hits:
                    continue
                findings[c["_file"]].extend(hits)
                sev = c.get("severity", "MEDIUM").upper()
                for h in hits:
                    stream.write(json.dumps({
                        "bucket": h.get("bucket_name", bucket),
                        "region": h.get("region", region),
                        "check": c["_file"],
                        "name": c["name"],
                        "severity": sev,
                    }) + "\n")

    header = [
        (f"**Endpoint:** `{region}` (buckets are account-wide)  ·  **Buckets:** {len(buckets)}  ·  "
         f"**Checks:** {len(checks)}  ·  **Fetch errors:** {len(fetch_errors)}"),
        _budget_line(budget, stopped_reason, skipped),
    ]
    # Every S3 check is evaluated against the same fetched bucket population.
    scanned = {c["_file"]: len(buckets) for c in checks}
    return _finalize_report("# StackQL S3 Audit", header, checks, findings, None,
                            log_dir, fail_on, fail_threshold, target="s3", scanned=scanned)


# --- target: AWS all-regions sweep -----------------------------------------

def enumerate_regions(seed_region: str, auth: str, log_dir: Path, budget: Budget) -> list[str]:
    """Enabled region names via DescribeRegions (one call, account-wide)."""
    budget.add_query()
    q = ("SELECT region_name, opt_in_status FROM aws.ec2.regions "
         f"WHERE region = '{seed_region}';")
    rows, err, _ = audit.run_stackql(q, auth, log_dir / "aws__regions.log")
    if err:
        print(f"error: region enumeration failed: {err.splitlines()[0]}")
        return []
    return [r["region_name"] for r in (rows or [])
            if r.get("region_name") and (r.get("opt_in_status") or "") in ("opt-in-not-required", "opted-in")]


def run_aws_regions(dirname: str = "aws", title: str = "# StackQL AWS All-Regions Audit",
                    stream: str = "aws-regions-findings.jsonl") -> int:
    if not audit.provider_allowed("aws"):
        print(f"skipping {dirname}: aws not in STACKQL_AUDIT_PROVIDERS")
        return 0
    seed = os.environ.get("AWS_REGION", "").strip()
    if not seed:
        print("error: AWS_REGION (a seed region to call DescribeRegions from) is required")
        return 2
    parallel = max(1, int(os.environ.get("STACKQL_AWS_PARALLEL", "8")))
    fail_on = os.environ.get("FAIL_ON_SEVERITY", "HIGH").upper()
    fail_threshold = audit.SEVERITY_ORDER.get(fail_on, 3)

    auth, _ = audit.build_auth()

    action_path = Path(os.environ.get("ACTION_PATH", "."))
    filters_mod = audit.load_filters_module(action_path)
    log_dir = _setup_log_dir()
    checks = load_checks(action_path, dirname, "aws")
    if not checks:
        print(f"warning: no checks found in queries/{dirname}/")
        return 0

    budget = Budget.from_env(os.environ)
    print(f"deep audit budget: {budget.describe_limits()}")

    regions = enumerate_regions(seed, auth, log_dir, budget)
    print(f"{len(regions)} enabled region(s); auditing with {parallel} worker(s)")

    findings, stopped_reason, skipped, audited, scanned = _scope_fanout(
        "region", "AWS_REGION", regions, None, checks, auth,
        filters_mod, log_dir, budget, parallel, stream)
    header = [
        f"**Regions audited:** {audited} / {len(regions)} enabled  ·  **Checks:** {len(checks)}",
        _budget_line(budget, stopped_reason, skipped),
    ]
    return _finalize_report(title, header, checks, findings, "region",
                            log_dir, fail_on, fail_threshold, target=dirname, scanned=scanned)


# --- target: GCP org descent ------------------------------------------------

def _gcp_list_children(parent: str, resource: str, cols: str,
                       auth: str, log_dir: Path, budget: Budget) -> list[dict]:
    """List cloudresourcemanager <resource> that are direct children of parent."""
    budget.add_query()
    safe = parent.replace("/", "_")
    q = (f"SELECT {cols} FROM google.cloudresourcemanager.{resource} "
         f"WHERE parent = '{parent}';")
    rows, err, _ = audit.run_stackql(q, auth, log_dir / f"gcp__{resource}__{safe}.log")
    if err:
        print(f"warning: list {resource} under {parent} failed: {err.splitlines()[0]}")
        return []
    return rows or []


def descend_org(org_id: str, auth: str, log_dir: Path, budget: Budget) -> tuple[list[str], str | None]:
    """BFS from organizations/<org_id> through folders to ACTIVE project IDs."""
    queue = [f"organizations/{org_id}"]
    seen_folders: set[str] = set()
    project_ids: list[str] = []
    stop_reason: str | None = None
    while queue:
        stop_reason = budget.should_stop()
        if stop_reason:
            break
        parent = queue.pop(0)
        for f in _gcp_list_children(parent, "folders", "name, parent, state", auth, log_dir, budget):
            name = f.get("name")
            if f.get("state") == "ACTIVE" and name and name not in seen_folders:
                seen_folders.add(name)
                queue.append(name)
        for p in _gcp_list_children(parent, "projects", "projectId, parent, state", auth, log_dir, budget):
            if p.get("state") == "ACTIVE" and p.get("projectId"):
                project_ids.append(p["projectId"])
    return project_ids, stop_reason


def run_gcp_org(dirname: str = "google", title: str = "# StackQL GCP Org Audit",
                stream: str = "gcp-org-findings.jsonl") -> int:
    if not audit.provider_allowed("google"):
        print(f"skipping {dirname}: google not in STACKQL_AUDIT_PROVIDERS")
        return 0
    org_id = os.environ.get("GOOGLE_ORG_ID", "").strip()
    if not org_id:
        print("error: GOOGLE_ORG_ID is required for the gcp org descent")
        return 2
    parallel = max(1, int(os.environ.get("STACKQL_GCP_PARALLEL", "8")))
    fail_on = os.environ.get("FAIL_ON_SEVERITY", "HIGH").upper()
    fail_threshold = audit.SEVERITY_ORDER.get(fail_on, 3)

    auth, _ = audit.build_auth()

    action_path = Path(os.environ.get("ACTION_PATH", "."))
    filters_mod = audit.load_filters_module(action_path)
    log_dir = _setup_log_dir()
    checks = load_checks(action_path, dirname, "google")
    if not checks:
        print(f"warning: no checks found in queries/{dirname}/")
        return 0

    budget = Budget.from_env(os.environ)
    print(f"deep audit budget: {budget.describe_limits()}")

    project_ids, descent_stop = descend_org(org_id, auth, log_dir, budget)
    print(f"descended organizations/{org_id}: {len(project_ids)} ACTIVE project(s)")

    findings, stopped_reason, skipped, audited, scanned = _scope_fanout(
        "project", "PROJECT_ID", project_ids, descent_stop, checks, auth,
        filters_mod, log_dir, budget, parallel, stream)
    header = [
        (f"**Org:** `organizations/{org_id}`  ·  **Projects audited:** {audited} / "
         f"{len(project_ids)} discovered  ·  **Checks:** {len(checks)}"),
        _budget_line(budget, stopped_reason, skipped),
    ]
    return _finalize_report(title, header, checks, findings, "project",
                            log_dir, fail_on, fail_threshold, target=dirname, scanned=scanned)


# --- target: Azure management-group descent ---------------------------------

def descend_mgmt_group(group_id: str, auth: str, log_dir: Path, budget: Budget) -> tuple[list[str], str | None]:
    """Subscription IDs under a management group via the recursive descendants
    call (one query). Subscriptions are descendants whose id has '/subscriptions/'."""
    budget.add_query()
    safe = group_id.replace("/", "_")
    q = ("SELECT id, name, type FROM azure.management_groups.descendants "
         f"WHERE groupId = '{group_id}';")
    rows, err, _ = audit.run_stackql(q, auth, log_dir / f"azure__descendants__{safe}.log")
    if err:
        print(f"error: management-group descent failed: {err.splitlines()[0]}")
        return [], None
    subs: list[str] = []
    for r in rows or []:
        rid = r.get("id") or ""
        if "/subscriptions/" in rid:
            subs.append(rid.split("/subscriptions/", 1)[1].split("/", 1)[0])
    return subs, budget.should_stop()


def list_all_subscriptions(auth: str, log_dir: Path, budget: Budget) -> tuple[list[str], str | None]:
    """Flat tenant-wide subscription list (fallback when no management group given)."""
    budget.add_query()
    q = "SELECT subscription_id, state FROM azure.resource.subscriptions;"
    rows, err, _ = audit.run_stackql(q, auth, log_dir / "azure__subscriptions.log")
    if err:
        print(f"error: subscription listing failed: {err.splitlines()[0]}")
        return [], None
    subs = [r["subscription_id"] for r in (rows or [])
            if r.get("subscription_id") and r.get("state") in (None, "Enabled")]
    return subs, budget.should_stop()


def run_azure_org(dirname: str = "azure", title: str = "# StackQL Azure Org Audit",
                  stream: str = "azure-org-findings.jsonl") -> int:
    if not audit.provider_allowed("azure"):
        print(f"skipping {dirname}: azure not in STACKQL_AUDIT_PROVIDERS")
        return 0
    group_id = os.environ.get("AZURE_MGMT_GROUP", "").strip()
    parallel = max(1, int(os.environ.get("STACKQL_AZURE_PARALLEL", "8")))
    fail_on = os.environ.get("FAIL_ON_SEVERITY", "HIGH").upper()
    fail_threshold = audit.SEVERITY_ORDER.get(fail_on, 3)

    auth, _ = audit.build_auth()

    action_path = Path(os.environ.get("ACTION_PATH", "."))
    filters_mod = audit.load_filters_module(action_path)
    log_dir = _setup_log_dir()
    checks = load_checks(action_path, dirname, "azure")
    if not checks:
        print(f"warning: no checks found in queries/{dirname}/")
        return 0

    budget = Budget.from_env(os.environ)
    print(f"deep audit budget: {budget.describe_limits()}")

    if group_id:
        subs, descent_stop = descend_mgmt_group(group_id, auth, log_dir, budget)
        scope_label = f"management group `{group_id}`"
    else:
        subs, descent_stop = list_all_subscriptions(auth, log_dir, budget)
        scope_label = "tenant (all subscriptions)"
    print(f"Azure {scope_label}: {len(subs)} subscription(s); auditing with {parallel} worker(s)")

    findings, stopped_reason, skipped, audited, scanned = _scope_fanout(
        "subscription", "SUBSCRIPTION_ID", subs, descent_stop, checks, auth,
        filters_mod, log_dir, budget, parallel, stream)
    header = [
        (f"**Scope:** {scope_label}  ·  **Subscriptions audited:** {audited} / "
         f"{len(subs)} discovered  ·  **Checks:** {len(checks)}"),
        _budget_line(budget, stopped_reason, skipped),
    ]
    return _finalize_report(title, header, checks, findings, "subscription",
                            log_dir, fail_on, fail_threshold, target=dirname, scanned=scanned)


# --- target: FinOps (orphan/unattached resources, costed from the snapshot) --

def run_finops_aws() -> int:
    return run_aws_regions("finops-aws", "# StackQL AWS FinOps Audit", "finops-aws-findings.jsonl")


# --- target: AWS rightsizing via Compute Optimizer (AWS CLI) -----------------
# stackql has no Compute Optimizer provider, so we shell out to the AWS CLI
# (already authed in the action). FinOps is the black box; stackql is just one
# tool inside it. Reads finished vendor verdicts — no metrics math on our side.

def _aws_cli_json(args: list[str], log_dir: Path, tag: str):
    """Run `aws <args> --output json`; return (parsed, error). Logs stderr."""
    out = subprocess.run(["aws", *args, "--output", "json"], capture_output=True, text=True, check=False)
    try:
        (log_dir / f"awscli__{tag}.log").write_text(
            f"args: {' '.join(args)}\nexit: {out.returncode}\n--- stderr ---\n{out.stderr.strip() or '(empty)'}\n")
    except OSError:
        pass
    if out.returncode != 0:
        first = (out.stderr.strip().splitlines() or [f"exit {out.returncode}"])[0]
        return None, first
    try:
        return json.loads(out.stdout or "{}"), None
    except json.JSONDecodeError as e:
        return None, f"bad json: {e}"


def run_finops_aws_rightsizing() -> int:
    if not audit.provider_allowed("aws"):
        print("skipping finops-aws-rightsizing: aws not in STACKQL_AUDIT_PROVIDERS")
        return 0
    if not shutil.which("aws"):
        print("warning: aws CLI not found — skipping AWS rightsizing")
        return 0
    log_dir = _setup_log_dir()
    stream_path = Path(os.environ.get("STACKQL_AUDIT_STREAM")
                       or (_setup_stream_dir() / "finops-aws-rightsizing-findings.jsonl"))
    seed = (os.environ.get("AWS_REGION", "") or "us-east-1").strip()

    # Region list (CLI — keep it self-contained). Fall back to the seed region.
    regions = [seed]
    doc, err = _aws_cli_json(
        ["ec2", "describe-regions", "--region", seed, "--query", "Regions[].RegionName"], log_dir, "regions")
    if not err and isinstance(doc, list) and doc:
        regions = doc

    print(f"AWS Compute Optimizer across {len(regions)} region(s); streaming to {stream_path}")
    findings = 0
    errors = 0
    with open(stream_path, "a", buffering=1) as stream:
        for region in regions:
            doc, err = _aws_cli_json(
                ["compute-optimizer", "get-ec2-instance-recommendations", "--region", region],
                log_dir, f"co_{region}")
            if err:  # not enrolled / throttled / no access — surface, don't drop
                errors += 1
                stream.write(json.dumps({
                    "region": region, "check": "_meta/enum-error",
                    "name": "Compute Optimizer query failed", "severity": "UNKNOWN", "error": err}) + "\n")
                print(f"warning: compute-optimizer {region}: {err}")
                continue
            for rec in (doc or {}).get("instanceRecommendations", []):
                if "over" not in (rec.get("finding") or "").lower():
                    continue  # only over-provisioned yields savings
                opts = rec.get("recommendationOptions") or []
                savings = target_type = None
                if opts:
                    em = (opts[0].get("savingsOpportunity") or {}).get("estimatedMonthlySavings") or {}
                    savings = em.get("value")
                    target_type = opts[0].get("instanceType")
                stream.write(json.dumps({
                    "region": region,
                    "resource": rec.get("instanceArn"),
                    "instance_name": rec.get("instanceName"),
                    "current_type": rec.get("currentInstanceType"),
                    "recommended_type": target_type,
                    "finding": rec.get("finding"),
                    "category": "suspected",
                    "source": "aws-compute-optimizer",
                    "estimated_savings_usd": round(float(savings), 2) if savings not in (None, "") else None,
                    "check": "compute-optimizer/ec2",
                    "name": "Over-provisioned EC2 instance",
                    "severity": "LOW",
                }) + "\n")
                findings += 1

    try:
        with open(_setup_stream_dir() / "finops-aws-rightsizing-assayed.jsonl", "a", buffering=1) as af:
            af.write(json.dumps({
                "check": "compute-optimizer/ec2", "name": "Over-provisioned EC2 instance",
                "severity": "LOW", "count": findings, "status": "findings" if findings else "clean"}) + "\n")
    except OSError:
        pass

    summary = (f"# StackQL AWS Rightsizing (Compute Optimizer)\n\n"
               f"**Regions:** {len(regions)}  ·  **Over-provisioned instances:** {findings}  ·  "
               f"**Region errors:** {errors}\n")
    print(summary)
    gh = os.environ.get("GITHUB_STEP_SUMMARY")
    if gh:
        with open(gh, "a") as f:
            f.write(summary + "\n")
    return 0


def run_finops_gcp() -> int:
    return run_gcp_org("finops-gcp", "# StackQL GCP FinOps Audit", "finops-gcp-findings.jsonl")


def run_finops_azure() -> int:
    return run_azure_org("finops-azure", "# StackQL Azure FinOps Audit", "finops-azure-findings.jsonl")


# --- target: Entra ID (tenant-global, no enumeration) -----------------------

def run_entra() -> int:
    """Run queries/entra_id/ once against the tenant. Entra is tenant-global —
    there are no scopes to enumerate/descend — so this is a flat sweep, not a
    fan-out. Shares the same report/stream/budget machinery as the other targets."""
    if not audit.provider_allowed("entra_id"):
        print("skipping entra: entra_id not in STACKQL_AUDIT_PROVIDERS")
        return 0
    fail_on = os.environ.get("FAIL_ON_SEVERITY", "HIGH").upper()
    fail_threshold = audit.SEVERITY_ORDER.get(fail_on, 3)

    auth, _ = audit.build_auth()

    action_path = Path(os.environ.get("ACTION_PATH", "."))
    filters_mod = audit.load_filters_module(action_path)
    log_dir = _setup_log_dir()
    checks = load_checks(action_path, "entra_id", "entra_id")
    if not checks:
        print("warning: no entra checks found in queries/entra_id/")
        return 0

    budget = Budget.from_env(os.environ)
    print(f"deep audit budget: {budget.describe_limits()}")

    findings: dict[str, list[dict]] = {c["_file"]: [] for c in checks}
    scanned: dict[str, int | None] = {c["_file"]: (0 if c.get("filter") else None) for c in checks}
    stream_path = Path(os.environ.get("STACKQL_AUDIT_STREAM") or (_setup_stream_dir() / "entra-findings.jsonl"))
    print(f"streaming findings to {stream_path}")
    stopped_reason: str | None = None
    with open(stream_path, "a", buffering=1) as stream:
        for c in checks:
            stopped_reason = budget.should_stop()
            if stopped_reason:
                print(f"warning: deep audit stopping early — {stopped_reason}; analyzing partial results")
                break
            budget.add_query()
            log = log_dir / f"entra__{c['_file'].replace('/', '_')}.log"
            rows, err, _ = audit.run_stackql(c["query"], auth, log)
            if err:
                first = err.splitlines()[0] if err else ""
                print(f"warning: entra check {c['_file']} errored: {first}")
                # Surface the errored (e.g. throttled) check as UNKNOWN, not a silent drop.
                stream.write(json.dumps({
                    "check": "_meta/enum-error",
                    "name": "entra check enumeration failed",
                    "severity": "UNKNOWN",
                    "failed_check": c["_file"],
                    "error": first,
                }) + "\n")
                continue
            if c.get("filter"):
                scanned[c["_file"]] = len(rows or [])  # directory population before the filter
                try:
                    rows = audit.apply_filter(filters_mod, c["filter"], rows or [], c.get("filter_args"))
                except Exception as e:
                    print(f"warning: filter {c['filter']} errored: {e}")
                    continue
            if rows:
                findings[c["_file"]] = rows
                sev = c.get("severity", "MEDIUM").upper()
                for r in rows:
                    stream.write(json.dumps({"check": c["_file"], "name": c["name"], "severity": sev}) + "\n")

    header = [
        f"**Scope:** tenant-global  ·  **Checks:** {len(checks)}",
        _budget_line(budget, stopped_reason, 0),
    ]
    return _finalize_report("# StackQL Entra ID Audit", header, checks, findings, None,
                            log_dir, fail_on, fail_threshold, target="entra", scanned=scanned)


COMMANDS = {
    "s3": run_s3,
    "aws-regions": run_aws_regions,
    "gcp-org": run_gcp_org,
    "azure-org": run_azure_org,
    "entra": run_entra,
    "finops-aws": run_finops_aws,
    "finops-aws-rightsizing": run_finops_aws_rightsizing,
    "finops-gcp": run_finops_gcp,
    "finops-azure": run_finops_azure,
}


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DISCOVER_TARGET", "s3")
    fn = COMMANDS.get(target)
    if fn is None:
        print(f"error: unknown target '{target}'; available: {', '.join(COMMANDS)}")
        return 2
    return fn()


if __name__ == "__main__":
    sys.exit(main())
