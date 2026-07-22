#!/usr/bin/env bash
# Docker audit run logic. Lives beside queries/ and scripts/ in the audit repo
# at cicd/audit/quickstart/. The stackql-devel bootstrap downloads this whole
# directory (pinned by AUDIT_ENGINE_REF) and execs this file.
#
# Talks to the stackql/stackql server over the Postgres wire (STACKQL_DSN, set
# by the quickstart's docker compose). A cloud with no credentials is skipped.
#
# Env contract provided by the caller (compose / .env.audit):
#   STACKQL_DSN                         wire endpoint of the stackql server
#   AWS_ACCESS_KEY_ID / _SECRET / AWS_REGION
#   GCP_SA_JSON / GOOGLE_ORG_ID
#   AZURE_TENANT_ID / _CLIENT_ID / _CLIENT_SECRET / AZURE_MGMT_GROUP
#   AUDIT_OUTPUT_DIR (default /audit/output), FAIL_ON_SEVERITY, STACKQL_DEEP_TIMEOUT
set -uo pipefail

ACTION_PATH="$(cd "$(dirname "$0")" && pwd)"      # this dir holds queries/ + scripts/
export ACTION_PATH
OUT="${AUDIT_OUTPUT_DIR:-/audit/output}"
export RUN_STAMP="$(date +%s)"
export STACKQL_AUDIT_LOG_DIR="$OUT/log"
export STACKQL_AUDIT_STREAM_DIR="$OUT/streams"
export FAIL_ON_SEVERITY="${FAIL_ON_SEVERITY:-NONE}"
export STACKQL_DEEP_TIMEOUT="${STACKQL_DEEP_TIMEOUT:-300}"   # per-target wall-clock cap (s)
export GITHUB_STEP_SUMMARY="$OUT/report.md"                 # consolidated report
mkdir -p "$STACKQL_AUDIT_LOG_DIR" "$STACKQL_AUDIT_STREAM_DIR"
exec > >(tee "$OUT/run.log") 2>&1
: > "$GITHUB_STEP_SUMMARY"

# python deps for the engine (talks to the stackql server via psycopg2)
python3 -m pip install --quiet --root-user-action=ignore psycopg2-binary pyyaml boto3

# which clouds have credentials -> providers + deep targets
providers=""; targets=""
if [ -n "${AWS_ACCESS_KEY_ID:-}" ] && [ -n "${AWS_SECRET_ACCESS_KEY:-}" ]; then
  providers="$providers aws"; targets="$targets s3 aws-regions"; echo "aws: credentials found"
else echo "aws: skipped (no credentials)"; fi
if [ -n "${GCP_SA_JSON:-}" ]; then
  providers="$providers google"; targets="$targets gcp-org"; echo "gcp: credentials found"
else echo "gcp: skipped (no credentials)"; fi
if [ -n "${AZURE_TENANT_ID:-}" ] && [ -n "${AZURE_CLIENT_ID:-}" ] && [ -n "${AZURE_CLIENT_SECRET:-}" ]; then
  providers="$providers azure entra_id"; targets="$targets azure-org entra"; echo "azure/entra: credentials found"
else echo "azure/entra: skipped (no credentials)"; fi

if [ -z "${providers// }" ]; then
  echo "No cloud credentials configured — nothing to audit. Edit .env.audit."
  exit 0
fi
export STACKQL_AUDIT_PROVIDERS="${providers# }"

echo "→ auditing:${targets}"
for t in ${AUDIT_TARGET:-$targets}; do
  echo "==== $t ===="
  python3 "$ACTION_PATH/scripts/discover.py" "$t" || echo "target '$t' exited non-zero"
done

python3 "$ACTION_PATH/scripts/merge_streams.py" "$STACKQL_AUDIT_STREAM_DIR/$RUN_STAMP" || true
cp "$STACKQL_AUDIT_STREAM_DIR/$RUN_STAMP/findings.json" "$OUT/findings.json" 2>/dev/null \
  && echo "✅ findings: $OUT/findings.json  ·  report: $OUT/report.md" \
  || echo "no findings.json produced (see $OUT/run.log)"
