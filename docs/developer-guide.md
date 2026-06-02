## Running locally

The audit reads provider credentials from the environment and audits a provider
**only if its credentials are present** — so set just the cloud(s) you want to
exercise. Run everything from the repo root.

### One-time setup

```bash
export ACTION_PATH="$(pwd)"
export FAIL_ON_SEVERITY=NONE              # don't exit 1 while iterating
export RUN_STAMP="$(date '+%s')"          # names the per-run log dir
export GITHUB_STEP_SUMMARY="$(pwd)/cicd/tmp/${RUN_STAMP}-summary.txt"  # optional — also prints to stdout

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r cicd/requirements.txt
```

### Per provider

Pull the provider registry, then export its credentials and scope. Set any
combination — unset providers are skipped.

```bash
# GCP
stackql exec 'registry pull google v25.12.00357;'
export PROJECT_ID='<project>'
export STACKQL_AUDIT_GCP_CREDS="$(pwd)/cicd/vendor-secrets/google-sa.json"   # put a SA key here

# AWS
stackql exec 'registry pull aws v26.03.00379;'
export AWS_ACCESS_KEY_ID='...' AWS_SECRET_ACCESS_KEY='...' AWS_REGION='us-east-1'

# Azure (service principal)
stackql exec 'registry pull azure v24.10.00267;'
export AZURE_SUBSCRIPTION_ID='...' AZURE_TENANT_ID='...' AZURE_CLIENT_ID='...' AZURE_CLIENT_SECRET='...'
```

### Run

```bash
python3 scripts/audit.py
cat "${GITHUB_STEP_SUMMARY}"
```

[`scripts/local-test.sh`](../scripts/local-test.sh) wraps all of the above:
it enables GCP only if the SA key exists, sources AWS/Azure creds from
`cicd/vendor-secrets/secrets.sh` if present, pulls the providers, and runs the
audit.

### Logs

Every `stackql exec` writes a per-invocation log to
`cicd/log/<RUN_STAMP>/<provider>__<check>.log` (the query, exit code, and
stderr), plus an `index.log` listing each check's exit code. stderr is recorded
even on exit 0 — the fastest way to spot a query that returns nothing
unexpectedly. Override the location with `STACKQL_AUDIT_LOG_DIR`.

## IAM 

### entraid

These are useful basis queries:

```sql

select id, appId, displayName from entraid.applications.applications;

select id, userPrincipalName from entraid.users.users;

select id, displayName, servicePrincipalType from entraid.service_principals.service_principals; -- horrid slow rendering on select *

```

