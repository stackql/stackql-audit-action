# StackQL Cloud Audit Action

> **Live-audit GCP, AWS, and Azure with SQL — no agents, no pipelines, no ingestion.**

A GitHub Action that runs an opinionated set of security checks against your
cloud accounts using [stackql](https://stackql.io). Findings render as a
markdown table on the workflow run page. Copy-paste setup, first results in
under two minutes.

**A provider is audited only if its credentials are supplied** — start with one
cloud, add the others later just by adding their secrets.

![sample summary](/docs/img/google-screenshot-summary.png)

## What it finds

| Provider | Check | Severity |
| --- | --- | --- |
| GCP | SSH (22/tcp) open to the internet | HIGH |
| GCP | RDP (3389/tcp) open to the internet | HIGH |
| GCP | Cloud SQL instances reachable on a public IP | HIGH |
| GCP | Compute instances with public IPs | MEDIUM |
| GCP | Compute instances using the default service account | MEDIUM |
| GCP | Storage buckets without uniform bucket-level access | MEDIUM |
| GCP | Default VPC network exists | MEDIUM |
| AWS | SSH (22/tcp) open to the internet (security groups) | HIGH |
| AWS | RDP (3389/tcp) open to the internet (security groups) | HIGH |
| AWS | RDS instances publicly accessible | HIGH |
| AWS | EC2 instances with a public IP | MEDIUM |
| AWS | Default VPC exists | LOW |
| Azure | SSH (22/tcp) open to the internet (NSG) | HIGH |
| Azure | RDP (3389/tcp) open to the internet (NSG) | HIGH |
| Azure | SQL servers with public network access | HIGH |
| Azure | Storage accounts allowing public blob access | MEDIUM |

Every check is a single YAML file under [`queries/<provider>/`](queries/) —
fork, extend, or replace at will.

## Quickstart

1. Set the credentials for the cloud(s) you want to audit (see
   [Credentials & configuration](#credentials--configuration)).
2. Copy a ready-to-use workflow from **[`docs/examples/`](docs/examples/)** into
   your repo's `.github/workflows/`:

   | Example | Audits |
   | --- | --- |
   | [`all-clouds-audit-workflow-dispatch.yml`](docs/examples/all-clouds-audit-workflow-dispatch.yml) | GCP + AWS + Azure in one run |
   | [`google-only-audit-workflow-dispatch.yml`](docs/examples/google-only-audit-workflow-dispatch.yml) | GCP, manual trigger |
   | [`google-only-audit-pull-request.yml`](docs/examples/google-only-audit-pull-request.yml) | GCP, on every PR to `main` |
   | [`aws-only-audit-workflow-dispatch.yml`](docs/examples/aws-only-audit-workflow-dispatch.yml) | AWS, manual trigger |
   | [`azure-only-audit-workflow-dispatch.yml`](docs/examples/azure-only-audit-workflow-dispatch.yml) | Azure, manual trigger |

Open the workflow run → the audit summary renders inline on the run page.

## Credentials & configuration

Store **sensitive** values as repo **secrets** (Settings → Secrets and variables
→ Actions → *Secrets*). Non-sensitive identifiers (project ID, region,
subscription ID) can be **variables**, or just typed in at run time.

### GCP

| Action input | Suggested GitHub home | Sensitive |
| --- | --- | --- |
| `gcp-credentials` | secret `GCP_SA_JSON` (service account JSON key) | **yes** |
| `gcp-project-id` | variable / run-time input | no |

### AWS

| Action input | Suggested GitHub home | Sensitive |
| --- | --- | --- |
| `aws-access-key-id` | secret `AWS_ACCESS_KEY_ID` | **yes** |
| `aws-secret-access-key` | secret `AWS_SECRET_ACCESS_KEY` | **yes** |
| `aws-region` | variable / run-time input | no |

### Azure

| Action input | Suggested GitHub home | Sensitive |
| --- | --- | --- |
| `azure-client-secret` | secret `AZURE_CLIENT_SECRET` | **yes** |
| `azure-tenant-id` | secret / variable `AZURE_TENANT_ID` | identifier |
| `azure-client-id` | secret / variable `AZURE_CLIENT_ID` | identifier |
| `azure-subscription-id` | variable / run-time input | no |

Azure auth uses a service principal (the tenant/client/secret triplet) via
stackql's `azure_default`.

## Inputs

| Name | Required | Default | Description |
| --- | --- | --- | --- |
| `gcp-project-id` | for GCP | — | GCP project ID; substituted as `${PROJECT_ID}` in google checks. |
| `gcp-credentials` | for GCP | — | Full contents of a GCP service account JSON key. |
| `google-provider-version` | no | pinned | stackql Google provider version (blank = latest). |
| `aws-access-key-id` | for AWS | — | AWS access key ID. |
| `aws-secret-access-key` | for AWS | — | AWS secret access key. |
| `aws-region` | for AWS | — | AWS region; substituted as `${AWS_REGION}` in aws checks. |
| `aws-provider-version` | no | latest | stackql AWS provider version. |
| `azure-subscription-id` | for Azure | — | Azure subscription ID; substituted as `${SUBSCRIPTION_ID}` in azure checks. |
| `azure-tenant-id` / `azure-client-id` / `azure-client-secret` | for Azure | — | Service principal credentials. |
| `azure-provider-version` | no | latest | stackql Azure provider version. |
| `queries-path` | no | *(built-in)* | Custom queries dir (must contain per-provider subdirs `google/` `aws/` `azure/`). |
| `fail-on-severity` | no | `HIGH` | Fail the workflow on findings at this severity or above. `NONE` never fails. |
| `stackql-version` | no | `latest` | stackql release to install. |
| `upload-logs` | no | `false` | Upload per-invocation stackql logs as the `stackql-audit-logs` artifact. |
| `log-retention-days` | no | `0` | Retention (days) for that artifact. `0` = repo default; integer in `[0, 90]`. |

A provider's checks run **iff** its credentials are present, so unused
provider inputs can be left unset.

## Outputs

| Name | Description |
| --- | --- |
| `findings-count` | Total findings across all checks. |
| `highest-severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `NONE`. |

## Required permissions

Read-only, on the audited scope:

- **GCP** — `roles/compute.viewer`, `roles/cloudsql.viewer`,
  `roles/storage.objectViewer`, `roles/iam.securityReviewer` (recommended).
- **AWS** — the managed `SecurityAudit` policy (or `ReadOnlyAccess`) covers the
  EC2/RDS describe calls the checks make.
- **Azure** — the `Reader` role on the subscription.

## Custom checks

Point `queries-path` at your own directory of per-provider subdirs. Each file
is one check:

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

A query returning **zero rows = no findings**. Any rows returned become finding
rows. For checks where SQL alone can't express the audit logic (e.g. filtering
by structure inside a nested column), reference a function in
[`scripts/filters.py`](scripts/filters.py):

```yaml
filter: firewall_allows_port
filter_args:
  port: 22
  protocol: tcp
```

## Logs & debugging

Set `upload-logs: true` to capture a per-invocation log for every `stackql exec`
(the query, exit code, and stderr) and upload it as the `stackql-audit-logs`
artifact. This is the fastest way to diagnose a check that returns nothing
unexpectedly — stderr is recorded even when the query exits 0. Tune retention
with `log-retention-days` (`0` = repo default, max `90`).

## How it works

```
   ┌───────────────────────────┐
   │  queries/<provider>/*.yaml │   (one file per check, per cloud)
   └────────────┬──────────────┘
                │
                ▼
   ┌───────────────────────────┐
   │  audit.py                 │   fans out N parallel
   │  └─ ThreadPoolExecutor    │   `stackql exec` subprocesses
   └────────────┬──────────────┘
                │
                ▼
   ┌────────────────────────────────────┐
   │  stackql exec --output json         │
   │   SELECT ... FROM google.*/aws.*/   │ <─── live API calls
   │                       azure.*       │
   └────────────┬────────────────────────┘
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

One combined `--auth` object carries every supplied provider, so a single fan-out
covers all three clouds. Each check runs in its own short-lived stackql process —
cleanup is automatic and checks run concurrently (8 at a time by default;
override with `STACKQL_AUDIT_PARALLEL`).

## Why stackql

stackql queries cloud control planes **live**. No resource crawl, no inventory
database, no daily sync — every `SELECT` hits the cloud API at query time. You
see what the cloud sees right now.

## License

MIT
