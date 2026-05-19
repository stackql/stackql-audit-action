
## Running locally

From the root of this repository:

```bash

export PROJECT_ID='<your project name>'
export STACKQL_AUDIT_GCP_CREDS="$(pwd)/cicd/vendor-secrets/google-sa.json" # you will need put a sa key here
export ACTION_PATH="$(pwd)"
export FAIL_ON_SEVERITY=NONE              # don't exit 1 while iterating

export RUN_STAMP="$(date '+%s')"

export GITHUB_STEP_SUMMARY="$(pwd)/cicd/tmp/${RUN_STAMP}-summary.txt"  # optional — also prints to stdout

python3 -m venv .venv
source .venv/bin/activate


stackql exec 'registry pull google v25.12.00357;'


python3 -m pip install -r cicd/requirements.txt
python3 scripts/audit.py
cat "${GITHUB_STEP_SUMMARY}"


```
