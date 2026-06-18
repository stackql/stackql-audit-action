#!/usr/bin/env python3
"""Generate remediation proposals from a findings.json.

For every finding whose originating check defines a `remediation_sql` block
(preflight + apply, with ${field} placeholders), write a proposal pair:

  remediations/proposed/<run>/<slug>/preflight.sql   (read-only re-verify)
  remediations/proposed/<run>/<slug>/apply.sql       (the mutation)

These are exactly what actions/preflight* and actions/apply* consume. Only
`category == "waste"` findings (proven, deterministic) get a proposal — never
`watch`/`suspected`. Deterministic string substitution from the finding's fields;
no LLM. Placeholders that can't be resolved cause that finding to be skipped with
a warning (never emit a half-templated mutation).

Run:  python3 scripts/gen_proposals.py <findings.json> [out-dir]
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import yaml

_PLACEHOLDER = re.compile(r"\$\{([a-zA-Z0-9_.]+)\}")
_SLUG = re.compile(r"[^a-zA-Z0-9._-]+")


def _slug(s: str) -> str:
    return _SLUG.sub("-", str(s)).strip("-")[:80] or "x"


def _resolve(template: str, ctx: dict) -> str | None:
    """Substitute ${k}/${a.b} from ctx; return None if any placeholder is unresolved."""
    missing: list[str] = []

    def sub(m: re.Match) -> str:
        cur = ctx
        for part in m.group(1).split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
            if cur is None:
                break
        if cur is None or isinstance(cur, (dict, list)):
            missing.append(m.group(1))
            return ""
        return str(cur)

    out = _PLACEHOLDER.sub(sub, template)
    if missing:
        return None
    return out


def _rationale(f: dict, preflight: str) -> str:
    fields = f.get("fields") or {}
    saving = fields.get("estimated_monthly_usd")
    saving_s = f"${saving}/mo" if saving not in (None, "") else "unpriced"
    return (
        f"# Remediate {f.get('resource')}\n\n"
        f"**What:** {f.get('check_name')} — `{f.get('resource')}` in "
        f"{f.get('region')} ({f.get('provider')}).\n\n"
        f"**Why safe:** matched the deterministic waste check `{f.get('check_id')}` "
        f"({f.get('check_file')}). The remediation deletes only this resource; "
        f"preflight.sql re-verifies it still meets the check criteria immediately "
        f"before any mutation, so a resource that changed state in the meantime is "
        f"not touched.\n\n"
        f"**Estimated monthly saving:** {saving_s}.\n\n"
        f"**Preflight:** `{preflight.strip().splitlines()[0]}`\n"
    )


def _load_remediation_sql(action_path: Path) -> dict[str, dict]:
    """Map check_file -> {'preflight':..., 'apply':...} for checks that define it."""
    out: dict[str, dict] = {}
    for cf in (action_path / "queries").rglob("*.yaml"):
        try:
            c = yaml.safe_load(cf.open())
        except yaml.YAMLError:
            continue
        rsql = (c or {}).get("remediation_sql")
        if isinstance(rsql, dict) and rsql.get("preflight") and rsql.get("apply"):
            rel = str(cf.relative_to(action_path / "queries"))
            out[rel] = {"preflight": rsql["preflight"], "apply": rsql["apply"]}
    return out


def main() -> int:
    findings_path = Path(sys.argv[1] if len(sys.argv) > 1 else (os.environ.get("FINDINGS_JSON") or ""))
    if not findings_path.is_file():
        print(f"::error::findings file not found: {findings_path}")
        return 2
    action_path = Path(os.environ.get("ACTION_PATH", "."))
    run_stamp = os.environ.get("RUN_STAMP") or os.environ.get("GITHUB_RUN_ID") or "run"
    out_root = Path(sys.argv[2] if len(sys.argv) > 2 else
                    (os.environ.get("PROPOSALS_DIR") or "remediations/proposed")) / run_stamp

    rsql_by_check = _load_remediation_sql(action_path)
    doc = json.loads(findings_path.read_text())
    findings = doc.get("findings", doc) if isinstance(doc, dict) else doc

    written = 0
    skipped = 0
    for i, f in enumerate(findings):  # 0-based index, per the consumer layout
        if f.get("category") != "waste":
            continue
        tmpl = rsql_by_check.get(f.get("check_file"))
        if not tmpl:
            continue
        fields = f.get("fields") or {}
        ctx = dict(fields)
        ctx.update({"region": f.get("region"), "resource": f.get("resource")})
        preflight = _resolve(tmpl["preflight"], ctx)
        apply_sql = _resolve(tmpl["apply"], ctx)
        if preflight is None or apply_sql is None:
            print(f"::warning::skipping proposal for {f.get('check_file')} "
                  f"({f.get('resource')}): unresolved placeholder")
            skipped += 1
            continue
        # <resource_id> = most specific id present in fields
        rid = next((fields[k] for k in ("volumeId", "publicIp", "address", "name") if fields.get(k)),
                   f.get("resource") or i)
        d = out_root / f"{i}-{_slug(f.get('check_id') or 'check')}-{_slug(rid)}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "finding.json").write_text(json.dumps(f, indent=2) + "\n")
        (d / "preflight.sql").write_text(preflight.rstrip() + "\n")
        (d / "remediation.sql").write_text(apply_sql.rstrip() + "\n")
        (d / "rationale.md").write_text(_rationale(f, preflight))
        written += 1

    print(f"::notice::generated {written} proposal(s) under {out_root} ({skipped} skipped)")
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a") as fh:
            fh.write(f"proposals-dir={out_root}\n")
            fh.write(f"proposals-count={written}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
