#!/usr/bin/env bash

export PROJECT_ID="${PROJECT_ID:-"stackql-demo"}"

export AWS_REGION="${AWS_REGION:-"ap-southeast-2"}"

if [ -f "$(pwd)/cicd/vendor-secrets/google-sa.json" ]; then
  export STACKQL_AUDIT_GCP_CREDS="$(pwd)/cicd/vendor-secrets/google-sa.json"
fi

if [ -f "$(pwd)/cicd/vendor-secrets/secrets.sh" ]; then
  source "$(pwd)/cicd/vendor-secrets/secrets.sh"
fi

export ACTION_PATH="$(pwd)"
export FAIL_ON_SEVERITY=NONE              # don't exit 1 while iterating

export RUN_STAMP="$(date '+%s')"

export GITHUB_STEP_SUMMARY="$(pwd)/cicd/tmp/${RUN_STAMP}-summary.txt"  # optional — also prints to stdout

python3 -m venv .venv
source .venv/bin/activate


stackql exec 'registry pull aws v26.05.00395;'
stackql exec 'registry pull azure v24.10.00267;'
stackql exec 'registry pull google v25.12.00357;'


python3 -m pip install -r cicd/requirements.txt
python3 scripts/audit.py
cat "${GITHUB_STEP_SUMMARY}"


