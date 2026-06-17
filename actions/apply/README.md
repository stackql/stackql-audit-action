# actions/apply (static creds)

Execute **mutating** remediation `.sql` once a proposal is approved. Dry-run by
default; **fail-closed** — refuses to mutate unless a passing preflight result is
supplied. Serial per file (mutation order matters). No rollback — partial
application is surfaced per-statement in `results-json`.

```yaml
- uses: stackql/stackql-audit-action/actions/apply@v0.11
  id: apply
  with:
    glob: 'remediations/approved/**/apply.sql'
    dry-run: 'false'
    require-preflight-pass: 'true'
    preflight-results: ${{ steps.pf.outputs.results-json }}   # from a prior preflight step
    aws-access-key-id: ${{ secrets.AWS_APPLY_KEY_ID }}
    aws-secret-access-key: ${{ secrets.AWS_APPLY_SECRET }}
    aws-region: us-east-1
# steps.apply.outputs.mutations-applied / pass / results-json
```

Fail-closed contract: with `dry-run=false` + `require-preflight-pass=true`, each
`apply.sql` must have an **adjacent `preflight.sql`** whose entry in
`preflight-results` passed; otherwise that file errors and nothing is mutated.

## Least-privilege policy (current `queries/finops-*` remediations)

Grant only the mutations the current checks can produce.

**AWS** (IAM policy):
```json
{ "Version": "2012-10-17", "Statement": [{
  "Effect": "Allow",
  "Action": ["ec2:DeleteVolume", "ec2:ReleaseAddress", "ec2:DeleteSnapshot"],
  "Resource": "*"
}] }
```

**Azure** (custom role actions):
```
Microsoft.Compute/disks/delete
Microsoft.Network/publicIPAddresses/delete
```

**GCP** (custom role permissions):
```
compute.disks.delete
compute.addresses.delete
compute.snapshots.delete
```

Add the corresponding action only when you add a remediation that needs it. Keep
this role separate from the read-only audit/preflight role.

> `max-parallel` is accepted but execution is currently **serial** regardless
> (safe default; parallel mutation is reserved).
