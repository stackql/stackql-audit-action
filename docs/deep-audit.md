# Deep (org-wide) audits

The shallow action audits a **single scope** — one GCP project, one AWS region,
one Azure subscription. The **deep** audits enumerate an entire org and run the
same checks across every scope they find.

Deep is a separate sub-action ([/deep/action.yml](/deep/action.yml)) and
entrypoint ([/scripts/discover.py](/scripts/discover.py)); the published shallow
action is unchanged.

## Targets

| Target | Enumerates | Runs per scope | Node |
| --- | --- | --- | --- |
| `s3` | every bucket (account-wide `ListBuckets`), then each bucket's detail | [/queries/s3/](/queries/s3/) — public access block, encryption, versioning, ACLs | bucket |
| `aws-regions` | enabled regions (`DescribeRegions`, opt-in filtered) | [/queries/aws/](/queries/aws/) | region |
| `gcp-org` | organization → folders → ACTIVE projects | [/queries/google/](/queries/google/) | project |
| `azure-org` | a management group's subscriptions (recursive `descendants`; or all tenant subscriptions) | [/queries/azure/](/queries/azure/) | subscription |

Each scope's id is substituted into the check query (`${AWS_REGION}` /
`${PROJECT_ID}` / `${SUBSCRIPTION_ID}`), and every finding is tagged with the
scope it came from.

## Running it

### As an action

```yaml
- uses: stackql/stackql-audit-action/deep@v0.3
  with:
    target: s3 aws-regions gcp-org azure-org
    gcp-credentials: ${{ secrets.GCP_SA_JSON }}
    google-org-id: '123456789012'
    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    aws-region: us-east-1
    azure-tenant-id: ${{ secrets.AZURE_TENANT_ID }}
    azure-client-id: ${{ secrets.AZURE_CLIENT_ID }}
    azure-client-secret: ${{ secrets.AZURE_CLIENT_SECRET }}
    azure-mgmt-group: ''        # blank = all tenant subscriptions
    max-nodes: '-1'             # budget; see below
```

It's a **sub-action**: `uses: <repo>/deep@<ref>` runs the action in the repo's
`deep/` folder, while `<repo>@<ref>` (no `/deep`) is the shallow root action.
One repo, two actions, one tag. Full example:
[/docs/examples/deep-audit-workflow-dispatch.yml](/docs/examples/deep-audit-workflow-dispatch.yml).

### Locally

```bash
export ACTION_PATH="$(pwd)" FAIL_ON_SEVERITY=NONE
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=us-east-1
python3 scripts/discover.py s3          # or aws-regions / gcp-org / azure-org
```

Or run every target whose creds resolve with
[/scripts/local-test-thorough.sh](/scripts/local-test-thorough.sh) (reads creds
from `cicd/vendor-secrets/secrets.sh`).

Scope inputs: `GOOGLE_ORG_ID` (gcp-org), `AWS_REGION` (s3 endpoint + region-sweep
seed), `AZURE_MGMT_GROUP` (azure-org; blank = whole tenant). Per-target
concurrency: `STACKQL_{S3,AWS,GCP,AZURE}_PARALLEL` (default 8).

## Budget

Cap a run so a large org or thousands of buckets can't run away. All default
`-1` (unlimited):

| Env / action input | Caps |
| --- | --- |
| `STACKQL_DEEP_MAX_NODES` / `max-nodes` | scopes visited |
| `STACKQL_DEEP_MAX_QUERIES` / `max-queries` | stackql queries issued |
| `STACKQL_DEEP_TIMEOUT` / `timeout-seconds` | wall-clock seconds |

On breach the run stops dispatching new scopes and analyzes the **partial**
result set already collected — the summary flags `⚠️ Stopped early`. Caps are
soft within the concurrency window (a few in-flight queries may finish past the
limit), and the timeout stops *new* work rather than killing an in-flight query.

## Output

- **Step summary** — rendered markdown per target (also printed to stdout
  locally), tagged with the scope each finding came from.
- **Per-invocation logs** — `cicd/log/<run>/<scope>__<check>.log` (the query,
  exit code, and stderr). Uploaded as the `deep-audit-logs` artifact when
  `upload-logs: true`.
- **Findings stream** — `<target>-findings.jsonl`, one JSON line per finding,
  written and flushed as each scope completes — so a killed run still leaves a
  partial result set on disk.

## Required privileges

Read-only, granted **one scope up** so it inherits, plus enumeration rights:

- **GCP** — `roles/viewer` + `roles/resourcemanager.folderViewer` at the
  **organization** node.
- **AWS** — `SecurityAudit` (or `ReadOnlyAccess`) on the principal; the S3 scan
  also needs `s3:GetBucket*` and, if it routes via Cloud Control,
  `cloudcontrol:GetResource` / `cloudcontrol:ListResources`.
- **Azure** — `Reader` at the **management-group** (or tenant root) scope, which
  inherits to every child subscription.

## Notes

- `azure-org` builds `azure_default` from the service-principal env itself
  (rather than the shallow `build_auth`, which gates on a single subscription) —
  the whole point is to span subscriptions.
- GCP descent is sequential (folder levels depend on each other); only the
  per-project audit runs in parallel.
- Subscriptions are identified from `descendants` rows by `/subscriptions/` in
  the resource `id`.
