#!/usr/bin/env python3
"""Run .sql files for the preflight / apply composite actions.

mode=preflight : read-only re-verification. Rejects any file containing a
                 destructive keyword (DELETE/UPDATE/INSERT/DROP/ALTER) without
                 executing it. pass = every file exit 0 and rows>=1 (or ==0 when
                 expect-empty).
mode=apply     : execute mutating remediation SQL. dry-run logs without mutating.
                 When require-preflight-pass, refuses to mutate a file lacking an
                 adjacent passing preflight.sql (fail-closed). Serial per file.

Throttle-aware retry per statement reuses audit.run_stackql + audit._is_throttle
and discover.RETRY_DELAYS — identical schedule to the deep audit. Always writes
results-json, even on failure.

Configured via env (set by the action); see the action.yml files. Outputs
(results-json path, summary-md path, pass, mutations-applied) are appended to
GITHUB_OUTPUT.
"""

from __future__ import annotations

import glob as globmod
import json
import os
import re
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit  # noqa: E402
from discover import RETRY_DELAYS  # reuse the exact deep-audit backoff schedule  # noqa: E402

DESTRUCTIVE = re.compile(r"(?i)\b(DELETE|UPDATE|INSERT|DROP|ALTER|TRUNCATE)\b")


class _FileTimeout(Exception):
    pass


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _bool(name: str, default: bool) -> bool:
    v = _env(name)
    if not v:
        return default
    return v.lower() in ("1", "true", "yes", "on")


def split_statements(text: str) -> list[str]:
    """Split a .sql file into statements on `;`, dropping comments/blanks."""
    no_comments = "\n".join(
        ln for ln in text.splitlines() if not ln.strip().startswith("--"))
    return [s.strip() for s in no_comments.split(";") if s.strip()]


def _run_statement(stmt: str, auth: str, log_path: Path, retries: int):
    """run_stackql one statement with throttle retry. Returns (rows, err, rc).
    Prints the query + stdout(rows) + stderr to the job log every run."""
    rows = err = None
    rc = 1
    for attempt in range(retries + 1):
        rows, err, rc = audit.run_stackql(stmt, auth, log_path)
        if err and audit._is_throttle(err) and attempt < retries:
            delay = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
            time.sleep(delay * (0.75 + 0.5 * ((attempt + 1) / (retries + 1))))
            continue
        break
    # Print inline (NOT in a ::group::, which GitHub collapses and hides).
    print("─── stackql statement ───────────────────────────────")
    print(f"QUERY : {stmt}")
    print(f"EXIT  : {rc}")
    print(f"STDOUT: {json.dumps(rows, default=str)[:4000] if rows is not None else '(none)'}")
    print(f"STDERR: {err or '(empty)'}")
    print("─────────────────────────────────────────────────────")
    return rows, err, rc


def _preflight_pass(file_obj: dict, expect_empty: bool) -> bool:
    if file_obj["exit_code"] != 0:
        return False
    total_rows = sum(len(s.get("rows") or []) for s in file_obj["statements"])
    return total_rows == 0 if expect_empty else total_rows >= 1


def run_preflight(files: list[Path], auth: str, retries: int, file_timeout: int,
                  expect_empty: bool, tmp: Path) -> tuple[list[dict], bool]:
    results: list[dict] = []
    overall = True
    for f in files:
        obj = {"file": str(f), "mode": "preflight", "exit_code": 0,
               "duration_ms": 0, "statements": [], "errors": None}
        text = f.read_text()
        bad = DESTRUCTIVE.search(text)
        if bad:
            obj["exit_code"] = 2
            obj["errors"] = f"destructive keyword '{bad.group(1).upper()}' in a preflight file — refused"
            results.append(obj)
            overall = False
            continue
        start = time.time()
        try:
            _arm_timeout(file_timeout)
            for stmt in split_statements(text):
                rows, err, rc = _run_statement(stmt, auth, tmp / "stmt.log", retries)
                obj["statements"].append({"statement": stmt, "rows": rows, "errors": err})
                if rc != 0 or err:
                    obj["exit_code"] = rc or 1
                    obj["errors"] = err
        except _FileTimeout:
            obj["exit_code"] = 124
            obj["errors"] = f"per-file timeout after {file_timeout}s"
        finally:
            _disarm_timeout()
        obj["duration_ms"] = int((time.time() - start) * 1000)
        if not _preflight_pass(obj, expect_empty):
            overall = False
        results.append(obj)
    return results, overall


def _preflight_passed_for(apply_file: Path, preflight_results: list[dict],
                          expect_empty: bool) -> tuple[bool, str]:
    """Fail-closed: an apply file may run only if an adjacent preflight.sql exists
    AND its entry in the supplied preflight-results passed."""
    adjacent = apply_file.parent / "preflight.sql"
    if not adjacent.exists():
        return False, f"no adjacent preflight.sql next to {apply_file}"
    parent = str(apply_file.parent)
    for entry in preflight_results:
        if str(Path(entry.get("file", "")).parent) == parent:
            if _preflight_pass(entry, expect_empty):
                return True, ""
            return False, f"preflight for {parent} did not pass (exit {entry.get('exit_code')})"
    return False, f"no preflight result entry for {parent}"


def run_apply(files: list[Path], auth: str, retries: int, file_timeout: int,
              dry_run: bool, require_preflight: bool, preflight_results: list[dict],
              tmp: Path) -> tuple[list[dict], bool, int]:
    results: list[dict] = []
    overall = True
    mutations = 0
    for f in files:
        obj = {"file": str(f), "mode": "apply", "exit_code": 0, "duration_ms": 0,
               "statements": [], "statements_executed": 0, "errors": None}
        text = f.read_text()
        statements = split_statements(text)

        if dry_run:
            for stmt in statements:
                obj["statements"].append({"statement": stmt, "rows": None,
                                          "errors": None, "executed": False})
            results.append(obj)
            continue

        if require_preflight:
            ok, why = _preflight_passed_for(f, preflight_results, expect_empty=False)
            if not ok:
                obj["exit_code"] = 3
                obj["errors"] = f"fail-closed: {why}"
                results.append(obj)
                overall = False
                continue

        start = time.time()
        try:
            _arm_timeout(file_timeout)
            for stmt in statements:
                rows, err, rc = _run_statement(stmt, auth, tmp / "stmt.log", retries)
                executed = err is None and rc == 0
                obj["statements"].append({"statement": stmt, "rows": None,
                                          "errors": err, "executed": executed})
                if executed:
                    obj["statements_executed"] += 1
                    mutations += 1
                else:
                    obj["exit_code"] = rc or 1
                    obj["errors"] = err
                    break  # no rollback; stop this file, surface partial state
        except _FileTimeout:
            obj["exit_code"] = 124
            obj["errors"] = f"per-file timeout after {file_timeout}s"
        finally:
            _disarm_timeout()
        obj["duration_ms"] = int((time.time() - start) * 1000)
        if obj["exit_code"] != 0:
            overall = False
        results.append(obj)
    return results, overall, mutations


def _arm_timeout(seconds: int) -> None:
    def _raise(signum, frame):  # noqa: ARG001
        raise _FileTimeout()
    try:
        signal.signal(signal.SIGALRM, _raise)
        signal.alarm(max(1, seconds))
    except (ValueError, AttributeError):
        pass  # not on the main thread / not POSIX — skip hard timeout


def _disarm_timeout() -> None:
    try:
        signal.alarm(0)
    except (ValueError, AttributeError):
        pass


def _log_result(obj: dict, ok: bool, expect_empty: bool = False) -> None:
    """Per-file line to the job log — so a failure is visible, not buried in JSON."""
    rows = sum(len(s.get("rows") or []) for s in obj["statements"])
    lvl = "notice" if ok else "warning"
    msg = (f"::{lvl}::{obj['mode']} {'PASS' if ok else 'FAIL'}: {obj['file']} "
           f"— exit {obj['exit_code']}, {len(obj['statements'])} stmt, {rows} row(s)")
    if "statements_executed" in obj:
        msg += f", {obj['statements_executed']} executed"
    print(msg)
    if not ok and obj["mode"] == "preflight" and obj["exit_code"] == 0:
        print(f"::warning::  preflight criterion not met: expected "
              f"{'0' if expect_empty else '>=1'} row(s), got {rows}")
    if obj.get("errors"):
        print(f"::error::  {str(obj['errors']).splitlines()[0]}")
    for s in obj["statements"]:
        if s.get("errors"):
            print(f"::error::  statement failed: {str(s['errors']).splitlines()[0]}")


def _summary_md(mode: str, results: list[dict], passed: bool, mutations: int) -> str:
    lines = [f"# StackQL {mode} — {'PASS' if passed else 'FAIL'}", ""]
    if mode == "apply":
        lines.append(f"**Mutations applied:** {mutations}\n")
    lines += ["| file | exit | statements | error |", "| --- | --- | --- | --- |"]
    for r in results:
        err = (r.get("errors") or "").splitlines()[0] if r.get("errors") else ""
        lines.append(f"| {r['file']} | {r['exit_code']} | {len(r['statements'])} | {err} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    mode = _env("RUN_SQL_MODE", "preflight")
    workdir = Path(_env("RUN_SQL_WORKDIR") or os.getcwd())
    pattern = _env("RUN_SQL_GLOB")
    retries = int(_env("RUN_SQL_RETRIES", "3") or "3")
    file_timeout = int(_env("RUN_SQL_FILE_TIMEOUT", "60") or "60")
    tmp = Path(os.environ.get("RUNNER_TEMP") or "/tmp")

    if not pattern:
        print("::error::glob is required")
        return 2
    resolved = str(workdir / pattern)
    print(f"::notice::{mode}: workdir={workdir} exists={workdir.is_dir()}  glob={pattern}  -> {resolved}")
    files = sorted(Path(p) for p in globmod.glob(resolved, recursive=True)
                   if p.endswith(".sql") and Path(p).is_file())
    if not files:
        print(f"::error::no .sql files matched '{pattern}' under {workdir} "
              f"— check working-directory/glob (this is why preflight does nothing)")
        cwd = Path(os.getcwd())
        print(f"::group::path debug (cwd={cwd}, workdir={workdir})")
        print(f"-- entries in cwd ({cwd}):")
        for p in sorted(cwd.iterdir())[:40]:
            print(f"   {'d' if p.is_dir() else 'f'} {p.name}")
        print(f"-- entries in workdir ({workdir}):")
        if workdir.is_dir():
            for p in sorted(workdir.iterdir())[:40]:
                print(f"   {'d' if p.is_dir() else 'f'} {p.name}")
        else:
            print("   (workdir does not exist)")
        print("-- every *.sql under workdir (recursive, first 40):")
        for p in sorted(workdir.rglob("*.sql"))[:40]:
            print(f"   {p}")
        print("::endgroup::")
        return 2
    print(f"::notice::{mode}: matched {len(files)} file(s):")
    for p in files:
        print(f"::notice::  - {p}")

    auth, payload_keys = audit.build_auth()
    print(f"::notice::{mode}: stackql auth providers = {sorted(payload_keys) or '(stackql env defaults)'}")
    mutations = 0
    if mode == "preflight":
        results, passed = run_preflight(
            files, auth, retries, file_timeout, _bool("RUN_SQL_EXPECT_EMPTY", False), tmp)
    elif mode == "apply":
        dry_run = _bool("RUN_SQL_DRY_RUN", True)
        require_preflight = _bool("RUN_SQL_REQUIRE_PREFLIGHT", True)
        pf_path = _env("RUN_SQL_PREFLIGHT_RESULTS")
        pf_results: list[dict] = []
        if pf_path and Path(pf_path).is_file():
            try:
                pf_results = json.loads(Path(pf_path).read_text())
            except (OSError, json.JSONDecodeError) as e:
                print(f"::warning::could not read preflight-results: {e}")
        if not dry_run and require_preflight and not pf_results:
            print("::error::dry-run=false with require-preflight-pass=true but no usable preflight-results")
        results, passed, mutations = run_apply(
            files, auth, retries, file_timeout, dry_run, require_preflight, pf_results, tmp)
    else:
        print(f"::error::unknown mode '{mode}'")
        return 2

    # Per-file outcome to the log so failures are visible (not just in JSON).
    expect_empty = _bool("RUN_SQL_EXPECT_EMPTY", False)
    for obj in results:
        ok = _preflight_pass(obj, expect_empty) if mode == "preflight" else obj["exit_code"] == 0
        _log_result(obj, ok, expect_empty)

    results_path = tmp / f"{mode}-results.json"
    summary_path = tmp / f"{mode}-summary.md"
    results_path.write_text(json.dumps(results, indent=2))
    summary_path.write_text(_summary_md(mode, results, passed, mutations))
    print(_summary_md(mode, results, passed, mutations))  # also to stdout

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as f:
            f.write(f"results-json={results_path}\n")
            f.write(f"summary-md={summary_path}\n")
            f.write(f"pass={'true' if passed else 'false'}\n")
            if mode == "apply":
                f.write(f"mutations-applied={mutations}\n")
    print(f"::notice::{mode}: pass={passed} files={len(results)}"
          + (f" mutations={mutations}" if mode == "apply" else ""))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
