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
THROTTLE_MARKERS = ("slowdown", "throttl", "requestlimitexceeded", "rate exceeded", "503")


def _is_throttle(err: str | None) -> bool:
    e = (err or "").lower()
    return any(m in e for m in THROTTLE_MARKERS)


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


def load_checks(action_path: Path, dirname: str, provider_tag: str) -> list[dict]:
    checks: list[dict] = []
    qdir = action_path / "queries" / dirname
    for cf in sorted(list(qdir.glob("*.yaml")) + list(qdir.glob("*.yml"))):
        c = yaml.safe_load(cf.open())
        c["_file"] = f"{dirname}/{cf.name}"
        c["_provider"] = provider_tag
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
                     log_dir: Path, fail_on: str, fail_threshold: int) -> int:
    """Render the markdown summary + sections, emit outputs, return the exit code.

    If `label` is set, it's prepended as a column to each finding (e.g. which
    project/region/subscription the finding came from)."""
    by_sev = {k: 0 for k in audit.SEVERITY_ORDER}
    total = 0
    highest = "NONE"
    sections: list[str] = []
    for c in checks:
        rows = findings.get(c["_file"], [])
        if not rows:
            sections.append(audit.render_pass(c))
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
        sections.append(audit.render_findings(rc, rows))

    out = [title, *header_lines, "", "## Summary", "| Severity | Findings |", "| --- | --- |"]
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
        print(f"::error::deep audit found {highest} findings (fail-on-severity={fail_on})")
        return 1
    return 0


def audit_scope(label: str, scope_var: str, scope_value: str, checks: list[dict],
                auth: str, filters_mod, log_dir: Path, budget: Budget) -> dict[str, list[dict]] | None:
    """Run every query-check for one scope (region / project / subscription),
    substituting ${scope_var}. Returns {check_file: rows} (rows tagged with
    `label`=scope_value), or None if the budget was exhausted (scope skipped)."""
    if budget.should_stop():
        return None
    budget.add_node()
    safe = scope_value.replace("/", "_")
    out: dict[str, list[dict]] = {}
    for c in checks:
        query = c["query"].replace("${" + scope_var + "}", scope_value)
        budget.add_query()
        log = log_dir / f"{label}__{safe}__{c['_file'].replace('/', '_')}.log"
        rows, err, _ = audit.run_stackql(query, auth, log)
        if err:
            continue
        if c.get("filter"):
            try:
                rows = audit.apply_filter(filters_mod, c["filter"], rows or [], c.get("filter_args"))
            except Exception as e:
                print(f"::warning::filter {c['filter']} errored on {scope_value}: {e}")
                continue
        if rows:
            for r in rows:
                r[label] = scope_value
            out[c["_file"]] = rows
    return out


def _scope_fanout(label: str, scope_var: str, scope_values: list[str], descent_stop: str | None,
                  checks: list[dict], auth: str, filters_mod, log_dir: Path, budget: Budget,
                  parallel: int, stream_name: str):
    """Audit each scope in parallel; stream findings; return (findings, stopped_reason,
    skipped, audited)."""
    stream_path = Path(os.environ.get("STACKQL_AUDIT_STREAM") or (log_dir / stream_name))
    print(f"::notice::streaming findings to {stream_path}")
    findings: dict[str, list[dict]] = {c["_file"]: [] for c in checks}
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
                    print(f"::warning::deep audit stopping early — {stopped_reason}; analyzing partial results")
                continue
            audited += 1
            for cfile, rows in res.items():
                findings[cfile].extend(rows)
                c = next(x for x in checks if x["_file"] == cfile)
                sev = c.get("severity", "MEDIUM").upper()
                for r in rows:
                    stream.write(json.dumps({label: v, "check": cfile, "name": c["name"], "severity": sev}) + "\n")
    return findings, stopped_reason, skipped, audited


# --- target: AWS S3 full audit ---------------------------------------------

def list_bucket_names(region: str, auth: str, log_dir: Path, budget: Budget) -> list[str]:
    q = f"SELECT bucket_name, region FROM aws.s3.buckets_list_only WHERE region = '{region}';"
    budget.add_query()
    rows, err, _ = audit.run_stackql(q, auth, log_dir / "s3__list.log")
    if err:
        print(f"::error::S3 bucket listing failed: {err.splitlines()[0]}")
        return []
    return [r["bucket_name"] for r in (rows or []) if r.get("bucket_name")]


def fetch_bucket_detail(bucket: str, region: str, auth: str, log_dir: Path, budget: Budget,
                        retries: int = 4, base_delay: float = 0.5):
    """Fetch one bucket's detail row, retrying with backoff on throttling.

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
        if err and _is_throttle(err) and attempt < retries:
            time.sleep(base_delay * (2 ** attempt) + random.random() * base_delay)
            continue
        if err:
            return None, err, None
        return (rows[0] if rows else None), None, None
    return None, "exhausted retries (throttled)", None


def run_s3() -> int:
    if not audit.provider_allowed("aws"):
        print("::notice::skipping s3: aws not in STACKQL_AUDIT_PROVIDERS")
        return 0
    region = os.environ.get("AWS_REGION", "").strip()
    if not region:
        print("::error::AWS_REGION is required for the S3 audit")
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
        print("::warning::no S3 checks found in queries/s3/")
        return 0

    budget = Budget.from_env(os.environ)
    print(f"::notice::deep audit budget: {budget.describe_limits()}")

    buckets = list_bucket_names(region, auth, log_dir, budget)
    print(f"::notice::S3: {len(buckets)} bucket(s); fetching detail with {parallel} worker(s)")

    stream_path = Path(os.environ.get("STACKQL_AUDIT_STREAM") or (log_dir / "s3-findings.jsonl"))
    print(f"::notice::streaming findings to {stream_path}")

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
                    print(f"::warning::deep audit stopping early — {stop_reason}; analyzing partial results")
                continue
            if err:
                fetch_errors.append((bucket, err))
                print(f"::warning::S3 detail failed for {bucket}: {err.splitlines()[0]}")
                continue
            if not detail:
                continue
            detail["region"] = _bucket_region(detail, region)  # true home region, not the endpoint
            for c in checks:
                try:
                    hits = audit.apply_filter(filters_mod, c["filter"], [detail], c.get("filter_args"))
                except Exception as e:
                    print(f"::warning::filter {c['filter']} errored on {bucket}: {e}")
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
    return _finalize_report("# StackQL S3 Audit", header, checks, findings, None,
                            log_dir, fail_on, fail_threshold)


# --- target: AWS all-regions sweep -----------------------------------------

def enumerate_regions(seed_region: str, auth: str, log_dir: Path, budget: Budget) -> list[str]:
    """Enabled region names via DescribeRegions (one call, account-wide)."""
    budget.add_query()
    q = ("SELECT regionName, optInStatus FROM aws.ec2_native.regions "
         f"WHERE region = '{seed_region}';")
    rows, err, _ = audit.run_stackql(q, auth, log_dir / "aws__regions.log")
    if err:
        print(f"::error::region enumeration failed: {err.splitlines()[0]}")
        return []
    return [r["regionName"] for r in (rows or [])
            if r.get("regionName") and (r.get("optInStatus") or "") in ("opt-in-not-required", "opted-in")]


def run_aws_regions() -> int:
    if not audit.provider_allowed("aws"):
        print("::notice::skipping aws-regions: aws not in STACKQL_AUDIT_PROVIDERS")
        return 0
    seed = os.environ.get("AWS_REGION", "").strip()
    if not seed:
        print("::error::AWS_REGION (a seed region to call DescribeRegions from) is required")
        return 2
    parallel = max(1, int(os.environ.get("STACKQL_AWS_PARALLEL", "8")))
    fail_on = os.environ.get("FAIL_ON_SEVERITY", "HIGH").upper()
    fail_threshold = audit.SEVERITY_ORDER.get(fail_on, 3)

    auth, _ = audit.build_auth()

    action_path = Path(os.environ.get("ACTION_PATH", "."))
    filters_mod = audit.load_filters_module(action_path)
    log_dir = _setup_log_dir()
    checks = load_checks(action_path, "aws", "aws")
    if not checks:
        print("::warning::no aws checks found in queries/aws/")
        return 0

    budget = Budget.from_env(os.environ)
    print(f"::notice::deep audit budget: {budget.describe_limits()}")

    regions = enumerate_regions(seed, auth, log_dir, budget)
    print(f"::notice::{len(regions)} enabled region(s); auditing with {parallel} worker(s)")

    findings, stopped_reason, skipped, audited = _scope_fanout(
        "region", "AWS_REGION", regions, None, checks, auth,
        filters_mod, log_dir, budget, parallel, "aws-regions-findings.jsonl")
    header = [
        f"**Regions audited:** {audited} / {len(regions)} enabled  ·  **Checks:** {len(checks)}",
        _budget_line(budget, stopped_reason, skipped),
    ]
    return _finalize_report("# StackQL AWS All-Regions Audit", header, checks, findings, "region",
                            log_dir, fail_on, fail_threshold)


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
        print(f"::warning::list {resource} under {parent} failed: {err.splitlines()[0]}")
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


def run_gcp_org() -> int:
    if not audit.provider_allowed("google"):
        print("::notice::skipping gcp-org: google not in STACKQL_AUDIT_PROVIDERS")
        return 0
    org_id = os.environ.get("GOOGLE_ORG_ID", "").strip()
    if not org_id:
        print("::error::GOOGLE_ORG_ID is required for the gcp-org audit")
        return 2
    parallel = max(1, int(os.environ.get("STACKQL_GCP_PARALLEL", "8")))
    fail_on = os.environ.get("FAIL_ON_SEVERITY", "HIGH").upper()
    fail_threshold = audit.SEVERITY_ORDER.get(fail_on, 3)

    auth, _ = audit.build_auth()

    action_path = Path(os.environ.get("ACTION_PATH", "."))
    filters_mod = audit.load_filters_module(action_path)
    log_dir = _setup_log_dir()
    checks = load_checks(action_path, "google", "google")
    if not checks:
        print("::warning::no google checks found in queries/google/")
        return 0

    budget = Budget.from_env(os.environ)
    print(f"::notice::deep audit budget: {budget.describe_limits()}")

    project_ids, descent_stop = descend_org(org_id, auth, log_dir, budget)
    print(f"::notice::descended organizations/{org_id}: {len(project_ids)} ACTIVE project(s)")

    findings, stopped_reason, skipped, audited = _scope_fanout(
        "project", "PROJECT_ID", project_ids, descent_stop, checks, auth,
        filters_mod, log_dir, budget, parallel, "gcp-org-findings.jsonl")
    header = [
        (f"**Org:** `organizations/{org_id}`  ·  **Projects audited:** {audited} / "
         f"{len(project_ids)} discovered  ·  **Checks:** {len(checks)}"),
        _budget_line(budget, stopped_reason, skipped),
    ]
    return _finalize_report("# StackQL GCP Org Audit", header, checks, findings, "project",
                            log_dir, fail_on, fail_threshold)


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
        print(f"::error::management-group descent failed: {err.splitlines()[0]}")
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
    q = "SELECT subscriptionId, state FROM azure.subscription.subscriptions;"
    rows, err, _ = audit.run_stackql(q, auth, log_dir / "azure__subscriptions.log")
    if err:
        print(f"::error::subscription listing failed: {err.splitlines()[0]}")
        return [], None
    subs = [r["subscriptionId"] for r in (rows or [])
            if r.get("subscriptionId") and r.get("state") in (None, "Enabled")]
    return subs, budget.should_stop()


def run_azure_org() -> int:
    if not audit.provider_allowed("azure"):
        print("::notice::skipping azure-org: azure not in STACKQL_AUDIT_PROVIDERS")
        return 0
    group_id = os.environ.get("AZURE_MGMT_GROUP", "").strip()
    parallel = max(1, int(os.environ.get("STACKQL_AZURE_PARALLEL", "8")))
    fail_on = os.environ.get("FAIL_ON_SEVERITY", "HIGH").upper()
    fail_threshold = audit.SEVERITY_ORDER.get(fail_on, 3)

    auth, _ = audit.build_auth()

    action_path = Path(os.environ.get("ACTION_PATH", "."))
    filters_mod = audit.load_filters_module(action_path)
    log_dir = _setup_log_dir()
    checks = load_checks(action_path, "azure", "azure")
    if not checks:
        print("::warning::no azure checks found in queries/azure/")
        return 0

    budget = Budget.from_env(os.environ)
    print(f"::notice::deep audit budget: {budget.describe_limits()}")

    if group_id:
        subs, descent_stop = descend_mgmt_group(group_id, auth, log_dir, budget)
        scope_label = f"management group `{group_id}`"
    else:
        subs, descent_stop = list_all_subscriptions(auth, log_dir, budget)
        scope_label = "tenant (all subscriptions)"
    print(f"::notice::Azure {scope_label}: {len(subs)} subscription(s); auditing with {parallel} worker(s)")

    findings, stopped_reason, skipped, audited = _scope_fanout(
        "subscription", "SUBSCRIPTION_ID", subs, descent_stop, checks, auth,
        filters_mod, log_dir, budget, parallel, "azure-org-findings.jsonl")
    header = [
        (f"**Scope:** {scope_label}  ·  **Subscriptions audited:** {audited} / "
         f"{len(subs)} discovered  ·  **Checks:** {len(checks)}"),
        _budget_line(budget, stopped_reason, skipped),
    ]
    return _finalize_report("# StackQL Azure Org Audit", header, checks, findings, "subscription",
                            log_dir, fail_on, fail_threshold)


# --- target: Entra ID (tenant-global, no enumeration) -----------------------

def run_entra() -> int:
    """Run queries/entra_id/ once against the tenant. Entra is tenant-global —
    there are no scopes to enumerate/descend — so this is a flat sweep, not a
    fan-out. Shares the same report/stream/budget machinery as the other targets."""
    if not audit.provider_allowed("entra_id"):
        print("::notice::skipping entra: entra_id not in STACKQL_AUDIT_PROVIDERS")
        return 0
    fail_on = os.environ.get("FAIL_ON_SEVERITY", "HIGH").upper()
    fail_threshold = audit.SEVERITY_ORDER.get(fail_on, 3)

    auth, _ = audit.build_auth()

    action_path = Path(os.environ.get("ACTION_PATH", "."))
    filters_mod = audit.load_filters_module(action_path)
    log_dir = _setup_log_dir()
    checks = load_checks(action_path, "entra_id", "entra_id")
    if not checks:
        print("::warning::no entra checks found in queries/entra_id/")
        return 0

    budget = Budget.from_env(os.environ)
    print(f"::notice::deep audit budget: {budget.describe_limits()}")

    findings: dict[str, list[dict]] = {c["_file"]: [] for c in checks}
    stream_path = Path(os.environ.get("STACKQL_AUDIT_STREAM") or (log_dir / "entra-findings.jsonl"))
    print(f"::notice::streaming findings to {stream_path}")
    stopped_reason: str | None = None
    with open(stream_path, "a", buffering=1) as stream:
        for c in checks:
            stopped_reason = budget.should_stop()
            if stopped_reason:
                print(f"::warning::deep audit stopping early — {stopped_reason}; analyzing partial results")
                break
            budget.add_query()
            log = log_dir / f"entra__{c['_file'].replace('/', '_')}.log"
            rows, err, _ = audit.run_stackql(c["query"], auth, log)
            if err:
                print(f"::warning::entra check {c['_file']} errored: {err.splitlines()[0]}")
                continue
            if c.get("filter"):
                try:
                    rows = audit.apply_filter(filters_mod, c["filter"], rows or [], c.get("filter_args"))
                except Exception as e:
                    print(f"::warning::filter {c['filter']} errored: {e}")
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
                            log_dir, fail_on, fail_threshold)


COMMANDS = {
    "s3": run_s3,
    "aws-regions": run_aws_regions,
    "gcp-org": run_gcp_org,
    "azure-org": run_azure_org,
    "entra": run_entra,
}


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DISCOVER_TARGET", "s3")
    fn = COMMANDS.get(target)
    if fn is None:
        print(f"::error::unknown target '{target}'; available: {', '.join(COMMANDS)}")
        return 2
    return fn()


if __name__ == "__main__":
    sys.exit(main())
