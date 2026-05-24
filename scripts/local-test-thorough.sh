#!/usr/bin/env bash
# Local runner for the DEEP (enumerated) audits in scripts/discover.py:
#   s3, aws-regions, gcp-org, azure-org.
# Run from the repo root. Each target runs only if its creds + scope are present.
#
# Put creds/scope in cicd/vendor-secrets/secrets.sh, e.g.:
#   export AWS_ACCESS_KEY_ID=...  AWS_SECRET_ACCESS_KEY=...
#   export AZURE_TENANT_ID=...    AZURE_CLIENT_ID=...    AZURE_CLIENT_SECRET=...
#   export AZURE_MGMT_GROUP=...           # optional; omit -> all tenant subscriptions
#   export GOOGLE_ORG_ID=123456789012
# and a GCP service-account key at cicd/vendor-secrets/google-sa.json.

set -uo pipefail

export AWS_REGION="${AWS_REGION:-ap-southeast-2}"   # s3 endpoint + region-sweep seed

if [ -f "$(pwd)/cicd/vendor-secrets/google-sa.json" ]; then
  export STACKQL_AUDIT_GCP_CREDS="$(pwd)/cicd/vendor-secrets/google-sa.json"
fi

if [ -f "$(pwd)/cicd/vendor-secrets/secrets.sh" ]; then
  source "$(pwd)/cicd/vendor-secrets/secrets.sh"
fi

export ACTION_PATH="$(pwd)"
export FAIL_ON_SEVERITY=NONE              # don't exit 1 while iterating
export RUN_STAMP="$(date '+%s')"
export GITHUB_STEP_SUMMARY="$(pwd)/cicd/tmp/${RUN_STAMP}-thorough-summary.md"  # all targets append here

# Safety caps for local runs so a big org / thousands of buckets can't run away.
# Each target gets its own budget; set any to -1 for an unlimited (full) run.
export STACKQL_DEEP_MAX_NODES="${STACKQL_DEEP_MAX_NODES:-50}"
export STACKQL_DEEP_MAX_QUERIES="${STACKQL_DEEP_MAX_QUERIES:--1}"
export STACKQL_DEEP_TIMEOUT="${STACKQL_DEEP_TIMEOUT:-600}"

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -q -r cicd/requirements.txt

run_target () {
  echo ""
  echo "=================== deep: $1 ==================="
  python3 scripts/discover.py "$1" || echo "::warning::$1 exited non-zero"
}

# --- AWS: S3 full audit + all-regions sweep ---
if [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]; then
  stackql exec 'registry pull aws v26.05.00395;'
  run_target s3
  run_target aws-regions
else
  echo "skip aws (s3, aws-regions): set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
fi

# --- GCP: org folder/project descent ---
if [ -n "${STACKQL_AUDIT_GCP_CREDS:-}" ] && [ -n "${GOOGLE_ORG_ID:-}" ]; then
  stackql exec 'registry pull google v25.12.00357;'
  run_target gcp-org
else
  echo "skip gcp-org: need cicd/vendor-secrets/google-sa.json and GOOGLE_ORG_ID"
fi

# --- Azure: management-group subscription descent ---
if [ -n "${AZURE_TENANT_ID:-}" ] || [ -n "${AZURE_CLIENT_ID:-}" ]; then
  stackql exec 'registry pull azure v24.10.00267;'
  run_target azure-org
else
  echo "skip azure-org: set AZURE_TENANT_ID / AZURE_CLIENT_ID / AZURE_CLIENT_SECRET"
fi

echo ""
echo "=== summary:           ${GITHUB_STEP_SUMMARY}"
echo "=== logs + findings:   $(pwd)/cicd/log/${RUN_STAMP}/  (per-bucket logs + *-findings.jsonl)"
