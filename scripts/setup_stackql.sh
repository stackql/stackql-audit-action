#!/usr/bin/env bash
# Shared stackql install + provider-pull for the preflight/apply actions.
# (actions/oidc, actions/deep, actions/publish are intentionally NOT migrated
# onto this yet — see cicd/tmp/change-actions.md.)
#
# Usage: setup_stackql.sh <stackql-version|latest> [provider[:version] ...]
#   e.g. setup_stackql.sh latest aws:v26.05.00395 google: azure:v24.10.00267
#   A bare "provider:" (empty version) pulls the registry default.
set -euo pipefail

ver="${1:-latest}"; shift || true

cd "${RUNNER_TEMP}"
if [ "$ver" = "latest" ]; then
  url="https://releases.stackql.io/stackql/latest/stackql_linux_amd64.zip"
else
  url="https://releases.stackql.io/stackql/${ver}/stackql_linux_amd64.zip"
fi
curl -fsSL "$url" -o stackql.zip
unzip -q stackql.zip && chmod +x stackql
echo "${RUNNER_TEMP}" >> "$GITHUB_PATH"
export PATH="${RUNNER_TEMP}:${PATH}"

for spec in "$@"; do
  [ -z "$spec" ] && continue
  p="${spec%%:*}"
  v="${spec#*:}"
  [ "$v" = "$p" ] && v=""
  if [ -n "$v" ]; then
    stackql exec "registry pull ${p} ${v};"
  else
    stackql exec "registry pull ${p};"
  fi
done
