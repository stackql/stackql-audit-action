# StackQL GCP Audit Action

> **Live-audit your GCP project with SQL — no agents, no pipelines, no ingestion.**

A GitHub Action that runs an opinionated set of security checks against your
Google Cloud project using [stackql](https://stackql.io). Findings render as a
markdown table on the workflow run page. Copy-paste setup, first results in
under two minutes.

![sample summary](/docs/img/google-screenshot-summary.png)

## What it finds (v1)

| Check | Severity |
| --- | --- |
| SSH (22/tcp) open to the internet | HIGH |
| RDP (3389/tcp) open to the internet | HIGH |
| Cloud SQL instances with a public IP | HIGH |
| Compute instances with public IPs | MEDIUM |
| Compute instances using the default service account | MEDIUM |
| Storage buckets without uniform bucket-level access | MEDIUM |
| Default VPC network exists | MEDIUM |

Every check is a single YAML file in [`queries/`](queries/) — fork, extend, or
replace at will.

## Quickstart

1. Create a GCP service account with read-only audit permissions on the
   target project (see [Required permissions](#required-permissions)).
2. Add its JSON key as a repo secret named `GCP_SA_JSON`.
3. Copy one of the ready-to-use workflows from **[`docs/examples/`](docs/examples/)** into your repo's `.github/workflows/`:

   - **[`audit-workflow-dispatch.yml`](docs/examples/audit-workflow-dispatch.yml)** — manual trigger from the Actions tab; enter the project ID at run time.
   - **[`audit-pull-request.yml`](docs/examples/audit-pull-request.yml)** — audit on every PR against `main`; reads the project ID from a repo variable.

Open the workflow run → the audit summary renders inline on the run page.

## Inputs

| Name | Required | Default | Description |
| --- | --- | --- | --- |
| `project-id` | yes | — | GCP project ID to audit. |
| `gcp-credentials` | yes | — | Full contents of a GCP service account JSON key. |
| `queries-path` | no | *(built-in)* | Path to a custom queries directory. |
| `fail-on-severity` | no | `HIGH` | Fail the workflow on findings at this severity or above. Use `NONE` to never fail. |
| `stackql-version` | no | `latest` | stackql release to install. |

## Outputs

| Name | Description |
| --- | --- |
| `findings-count` | Total findings across all checks. |
| `highest-severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `NONE`. |

## Required permissions

Minimum read-only roles on the target project:

- `roles/compute.viewer`
- `roles/cloudsql.viewer`
- `roles/storage.objectViewer`  *(or `roles/storage.admin` for IAM-config inspection)*
- `roles/iam.securityReviewer`  *(recommended for full coverage)*

## Custom checks

Point `queries-path` at your own directory of YAML files. Each file is a check:

```yaml
id: my-org-firewall-check
name: Allow only known source ranges
severity: HIGH
description: Catch firewall rules with sourceRanges outside our corp CIDRs.
remediation: Restrict to known CIDRs or migrate to IAP.
query: |
  SELECT name, network, sourceRanges
  FROM google.compute.firewalls
  WHERE project = '${PROJECT_ID}'
    AND direction = 'INGRESS'
columns: [name, network, sourceRanges]
```

A query returning **zero rows = no findings**. Any rows returned become
finding rows. For checks where SQL alone can't express the audit logic (e.g.
filtering by structure inside a JSON array column), reference a function in
[`scripts/filters.py`](scripts/filters.py):

```yaml
filter: firewall_allows_port
filter_args:
  port: 22
  protocol: tcp
```

## How it works

```
   ┌───────────────────────────┐
   │  queries/*.yaml           │   (one file per check)
   └────────────┬──────────────┘
                │
                ▼
   ┌───────────────────────────┐
   │  audit.py                 │   fans out N parallel
   │  └─ ThreadPoolExecutor    │   `stackql exec` subprocesses
   └────────────┬──────────────┘
                │
                ▼
   ┌───────────────────────────┐
   │  stackql exec --output json
   │     SELECT ... FROM google.*   <─── live API calls to GCP
   └────────────┬──────────────┘
                │
                ▼
   ┌───────────────────────────┐
   │  optional filter (Python) │   for checks SQL can't express
   └────────────┬──────────────┘
                │
                ▼
   ┌───────────────────────────┐
   │  $GITHUB_STEP_SUMMARY     │   markdown tables, severity badges
   └───────────────────────────┘
```

Each check runs in its own short-lived stackql process — cleanup is automatic
and checks run concurrently (8 at a time by default; override with
`STACKQL_AUDIT_PARALLEL`).

## Why stackql

stackql queries cloud control planes **live**. No resource crawl, no
inventory database, no daily sync — every `SELECT` hits the cloud API at
query time. You see what GCP sees right now.

## License

MIT
