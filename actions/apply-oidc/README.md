# actions/apply-oidc (federated / OIDC)

Same as [`actions/apply`](../apply/) but with federated (OIDC) auth — no
long-lived secrets. Inputs mirror `actions/oidc` for auth, plus the apply-only
`dry-run`, `require-preflight-pass`, `preflight-results`, `max-parallel`.

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: stackql/stackql-audit-action/actions/apply-oidc@v0.11
    with:
      glob: 'remediations/approved/**/apply.sql'
      dry-run: 'false'
      preflight-results: ${{ steps.pf.outputs.results-json }}
      aws-role-arn: ${{ secrets.AWS_APPLY_ROLE_ARN }}   # narrow mutate role
      aws-region: us-east-1
```

The federated role/SA needs the **same least-privilege mutate permissions** as
[`actions/apply`](../apply/#least-privilege-policy-current-queriesfinops-remediations)
— and nothing more. Keep it distinct from the read-only preflight role.
