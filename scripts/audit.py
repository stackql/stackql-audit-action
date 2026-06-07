#!/usr/bin/env python3
"""StackQL audit runner.

Discovers check definitions (YAML) under a queries directory, runs each one via
its own `stackql exec` subprocess (in parallel), optionally pipes the rows
through a Python filter function, and writes a markdown summary into
$GITHUB_STEP_SUMMARY.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml

# UNKNOWN = -1 sorts below NONE so synthetic enumeration-error findings never
# trip FAIL_ON_SEVERITY (the gate is `>= fail_threshold`, fail_threshold >= 0).
SEVERITY_ORDER = {"UNKNOWN": -1, "NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_BADGE = {
    "CRITICAL": "🟥 CRITICAL",
    "HIGH": "🟧 HIGH",
    "MEDIUM": "🟨 MEDIUM",
    "LOW": "🟦 LOW",
    "NONE": "⬜ NONE",
    "UNKNOWN": "❔ UNKNOWN",
}
MAX_PARALLEL = int(os.environ.get("STACKQL_AUDIT_PARALLEL", "8"))

# AWS Cloud Control (and similar cloud APIs) answer HTTP 400 throttle responses
# on which `stackql exec` writes the error to stderr but still exits 0. Without
# detection that reads as "succeeded, no rows" and the resource silently vanishes
# from the output. run_stackql treats throttled-empty results as errors so every
# caller's retry/error path engages.
THROTTLE_MARKERS = ("slowdown", "throttl", "requestlimitexceeded", "rate exceeded", "503")


def _is_throttle(err: str | None) -> bool:
    e = (err or "").lower()
    return any(m in e for m in THROTTLE_MARKERS)


def build_auth() -> tuple[str, set[str]]:
    """Return a stackql `--auth` payload, or empty string to use stackql's defaults.

    If STACKQL_AUDIT_AUTH (raw JSON) or STACKQL_AUDIT_AUTH_FILE (path) is set,
    that payload is used verbatim and its top-level keys are the enabled
    providers. Otherwise no `--auth` is passed.
    """
    override = os.environ.get("STACKQL_AUDIT_AUTH")
    if not override and os.environ.get("STACKQL_AUDIT_AUTH_FILE"):
        try:
            with open(os.environ["STACKQL_AUDIT_AUTH_FILE"]) as f:
                override = f.read()
        except OSError as e:
            print(f"::error::STACKQL_AUDIT_AUTH_FILE could not be read: {e}")
            return "", set()
    if override:
        try:
            parsed = json.loads(override)
        except json.JSONDecodeError as e:
            print(f"::error::STACKQL_AUDIT_AUTH is not valid JSON: {e}")
            return "", set()
        if not isinstance(parsed, dict):
            print("::error::STACKQL_AUDIT_AUTH must be a JSON object keyed by provider")
            return "", set()
        return json.dumps(parsed), set(parsed.keys())
    return "", set()


def provider_allowed(provider: str) -> bool:
    """Honour STACKQL_AUDIT_PROVIDERS (space/comma separated). Empty/unset = no filter.

    The caller (action/wrapper) is in the best position to know which providers
    successfully authenticated; it sets this env so the script doesn't have to
    guess from auth shapes."""
    raw = os.environ.get("STACKQL_AUDIT_PROVIDERS", "").strip()
    if not raw:
        return True
    return provider in set(raw.replace(",", " ").split())


def scope_vars(provider: str) -> dict[str, str]:
    """Per-provider placeholder substitutions applied to a check's query."""
    if provider == "google":
        return {"PROJECT_ID": os.environ.get("PROJECT_ID", "")}
    if provider == "aws":
        return {"AWS_REGION": os.environ.get("AWS_REGION", "")}
    if provider == "azure":
        return {"SUBSCRIPTION_ID": os.environ.get("AZURE_SUBSCRIPTION_ID", "")}
    return {}


def run_stackql(query: str, auth: str, log_path: Path) -> tuple[list[dict] | None, str | None, int]:
    argv = ["stackql", "exec"]
    if auth:
        argv += ["--auth", auth]
    argv += ["--output", "json", query]
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    rc = result.returncode
    stderr = result.stderr.strip()
    # Always write the per-invocation log, even on exit 0: a query that returns
    # no rows can still emit warnings/errors on stderr, and that's invisible
    # from the result alone — which is exactly what we want to surface.
    try:
        log_path.write_text(
            f"exit: {rc}\n"
            f"--- query ---\n{query}\n"
            f"--- stderr ---\n{stderr or '(empty)'}\n"
        )
    except OSError:
        pass
    if rc != 0:
        err = stderr or result.stdout.strip() or f"exit {rc}"
        return None, err, rc
    out = result.stdout.strip()
    if not out or out == "[]":
        # stackql exits 0 on AWS throttle responses with no rows — surface it as
        # an error so callers retry instead of recording a false "no findings".
        if _is_throttle(stderr):
            return None, stderr, rc
        return [], None, rc
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        return None, f"failed to parse stackql JSON: {e}\n--- raw (first 1KB) ---\n{out[:1024]}", rc
    if isinstance(data, dict):
        data = [data]
    return data, None, rc


def load_filters_module(action_path: Path):
    filters_path = action_path / "scripts" / "filters.py"
    spec = importlib.util.spec_from_file_location("audit_filters", filters_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def apply_filter(filters_mod: Any, name: str, rows: list[dict], args: dict | None) -> list[dict]:
    fn = getattr(filters_mod, name, None)
    if fn is None:
        raise RuntimeError(f"unknown filter function: {name}")
    return fn(rows, **(args or {}))


def execute_check(check: dict, auth: str, filters_mod: Any, log_dir: Path) -> dict:
    """Run a single check and return a result dict."""
    query = check["query"]
    for var, val in scope_vars(check["_provider"]).items():
        query = query.replace(f"${{{var}}}", val)
    slug = check["_file"].replace("/", "__").rsplit(".", 1)[0]
    rows, err, rc = run_stackql(query, auth, log_dir / f"{slug}.log")
    if err:
        return {"check": check, "status": "error", "error": err, "rows": [], "exit_code": rc}
    if check.get("filter"):
        try:
            rows = apply_filter(filters_mod, check["filter"], rows or [], check.get("filter_args"))
        except Exception as e:
            return {"check": check, "status": "error", "error": f"filter error: {e}", "rows": [], "exit_code": rc}
    if not rows:
        return {"check": check, "status": "pass", "rows": [], "exit_code": rc}
    return {"check": check, "status": "findings", "rows": rows, "exit_code": rc}


def render_findings(check: dict, rows: list[dict]) -> str:
    sev = check.get("severity", "MEDIUM").upper()
    badge = SEVERITY_BADGE.get(sev, sev)
    prov = check.get("_provider", "").upper()
    lines: list[str] = []
    lines.append(f"### {badge} — `{prov}` {check['name']}  ·  {len(rows)} finding(s)")
    if check.get("description"):
        lines.append(f"_{check['description'].strip()}_\n")
    columns = check.get("columns") or list(rows[0].keys())
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("| " + " | ".join("---" for _ in columns) + " |")
    for row in rows:
        cells = []
        for col in columns:
            val = row.get(col, "")
            if isinstance(val, (dict, list)):
                val = json.dumps(val)
            cells.append(str(val).replace("|", "\\|").replace("\n", " "))
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    if check.get("remediation"):
        lines.append(f"**Remediation:** {check['remediation'].strip()}\n")
    return "\n".join(lines)


def render_pass(check: dict) -> str:
    prov = check.get("_provider", "").upper()
    name = check["name"]
    desc = (check.get("description") or "").strip()
    return f"### ✅ `{prov}` {name}\n_{desc}_\n\nNo findings.\n"


def render_error(check: dict, err: str) -> str:
    prov = check.get("_provider", "").upper()
    name = check["name"]
    return (
        f"### ⚠️ `{prov}` {name} — query error\n"
        "<details><summary>Error</summary>\n\n"
        f"```\n{err}\n```\n\n</details>\n"
    )


def main() -> int:
    fail_on = os.environ.get("FAIL_ON_SEVERITY", "HIGH").upper()
    fail_threshold = SEVERITY_ORDER.get(fail_on, 3)
    auth, _ = build_auth()

    action_path = Path(os.environ["ACTION_PATH"])
    qp = os.environ.get("QUERIES_PATH", "").strip()
    queries_root = Path(qp) if qp else action_path / "queries"
    if not queries_root.is_dir():
        print(f"::error::queries path not found: {queries_root}")
        return 2

    filters_mod = load_filters_module(action_path)

    # Per-run log dir; each stackql invocation drops a <provider__check>.log here.
    run_stamp = os.environ.get("RUN_STAMP") or time.strftime("%Y%m%d-%H%M%S")
    log_root = Path(os.environ.get("STACKQL_AUDIT_LOG_DIR") or (action_path / "cicd" / "log"))
    log_dir = log_root / run_stamp
    log_dir.mkdir(parents=True, exist_ok=True)

    # Per-run data-stream dir for *-findings.jsonl, kept separate from the .log
    # files. Falls back to the log dir when STACKQL_AUDIT_STREAM_DIR is unset so
    # local runs are unchanged; the actions point it at a dedicated folder.
    stream_root = Path(os.environ.get("STACKQL_AUDIT_STREAM_DIR")
                       or os.environ.get("STACKQL_AUDIT_LOG_DIR")
                       or (action_path / "cicd" / "log"))
    stream_dir = stream_root / run_stamp
    stream_dir.mkdir(parents=True, exist_ok=True)

    # Walk every queries/<provider>/ that exists; stackql defaults / the auth
    # override decide what actually authenticates.
    checks: list[dict] = []
    for pdir in sorted(p for p in queries_root.iterdir() if p.is_dir()):
        provider = pdir.name
        if not provider_allowed(provider):
            print(f"::notice::skipping {provider}: not in STACKQL_AUDIT_PROVIDERS")
            continue
        for cf in sorted(list(pdir.glob("*.yaml")) + list(pdir.glob("*.yml"))):
            with cf.open() as f:
                check = yaml.safe_load(f)
            check["_file"] = f"{provider}/{cf.name}"
            check["_provider"] = provider
            checks.append(check)

    if not checks:
        print(f"::warning::no checks found in {queries_root}")
        return 0

    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=MAX_PARALLEL) as pool:
        futures = {
            pool.submit(execute_check, c, auth, filters_mod, log_dir): c["_file"]
            for c in checks
        }
        for fut in as_completed(futures):
            file_key = futures[fut]
            try:
                results[file_key] = fut.result()
            except Exception as e:
                results[file_key] = {
                    "check": next(c for c in checks if c["_file"] == file_key),
                    "status": "error",
                    "error": f"unexpected error: {e}",
                    "rows": [],
                    "exit_code": None,
                }

    # Track stackql exit codes across the run: write an index and flag non-zero.
    nonzero: list[tuple[str, Any]] = []
    manifest = ["exit\tcheck"]
    for c in checks:
        code = results[c["_file"]].get("exit_code")
        manifest.append(f"{code}\t{c['_file']}")
        if code != 0:
            nonzero.append((c["_file"], code))
    try:
        (log_dir / "index.log").write_text("\n".join(manifest) + "\n")
    except OSError:
        pass
    for file_key, code in nonzero:
        print(f"::warning::stackql non-zero exit ({code}) for {file_key}")
    print(f"::notice::stackql logs in {log_dir}")

    findings_by_severity = {k: 0 for k in SEVERITY_ORDER}
    total_findings = 0
    highest_severity = "NONE"
    error_count = 0
    sections: list[str] = []
    streams: dict[str, list[dict]] = {}  # provider -> finding records (JSONL)

    for c in checks:
        r = results[c["_file"]]
        check = r["check"]
        if r["status"] == "error":
            error_count += 1
            sections.append(render_error(check, r["error"]))
            print(f"::warning::{check['name']}: {r['error'].splitlines()[0]}")
            continue
        if r["status"] == "pass":
            sections.append(render_pass(check))
            continue
        rows = r["rows"]
        sev = check.get("severity", "MEDIUM").upper()
        findings_by_severity[sev] += len(rows)
        total_findings += len(rows)
        if SEVERITY_ORDER[sev] > SEVERITY_ORDER[highest_severity]:
            highest_severity = sev
        for row in rows:
            streams.setdefault(check["_provider"], []).append({
                "provider": check["_provider"],
                "check": check["_file"],
                "name": check.get("name"),
                "severity": sev,
                "fields": row,
            })
        sections.append(render_findings(check, rows))

    # Stream findings as per-provider NDJSON (one file per provider), separate
    # from the .log files — the actions upload/merge this folder on its own.
    for prov, recs in streams.items():
        try:
            with open(stream_dir / f"{prov}-findings.jsonl", "a", buffering=1) as sf:
                for rec in recs:
                    sf.write(json.dumps(rec, default=str) + "\n")
        except OSError as e:
            print(f"::warning::could not write {prov} stream: {e}")

    out_lines: list[str] = []
    out_lines.append("# StackQL Cloud Audit")
    out_lines.append(
        f"**Providers:** {', '.join(sorted({c['_provider'] for c in checks}))}  ·  **Checks run:** {len(checks)}"
        f"  ·  **Errors:** {error_count}  ·  **Non-zero exits:** {len(nonzero)}"
    )
    out_lines.append("")
    out_lines.append("## Summary")
    out_lines.append("| Severity | Findings |")
    out_lines.append("| --- | --- |")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        out_lines.append(f"| {SEVERITY_BADGE[sev]} | {findings_by_severity[sev]} |")
    out_lines.append(f"| **Total** | **{total_findings}** |\n")
    out_lines.append("## Checks\n")
    out_lines.extend(sections)
    rendered = "\n".join(out_lines)

    print(rendered)
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write(rendered + "\n")

    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a") as f:
            f.write(f"findings-count={total_findings}\n")
            f.write(f"highest-severity={highest_severity}\n")

    should_fail = (
        total_findings > 0
        and fail_threshold > 0
        and SEVERITY_ORDER[highest_severity] >= fail_threshold
    )
    if should_fail:
        print(f"\n::error::Audit found {highest_severity} findings (fail-on-severity={fail_on})")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
