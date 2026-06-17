# actions/preflight (static creds)

Read-only re-verification of findings immediately before any mutation. Runs the
`.sql` files matched by `glob`, each statement against your cloud, and reports
`pass`/`results-json`/`summary-md`. **Rejects** any file containing a destructive
keyword (`DELETE`/`UPDATE`/`INSERT`/`DROP`/`ALTER`) without executing it.

```yaml
- uses: stackql/stackql-audit-action/actions/preflight@v0.11
  id: pf
  with:
    glob: 'remediations/proposed/**/preflight.sql'
    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    aws-region: us-east-1
# steps.pf.outputs.pass / results-json / summary-md
```

Inputs mirror `actions/deep` (static creds) plus the shared `glob`,
`working-directory`, `expect-empty`, `per-file-timeout-seconds`, `retries`,
`stackql-version`, provider versions.

`expect-empty: true` flips the criterion — pass iff every file returns **zero**
rows (for "verify nothing matches" checks).

Permissions: `contents: read`; use a **read-only** cloud role (e.g. AWS
`SecurityAudit`, Azure `Reader`, GCP `roles/iam.securityReviewer`).
