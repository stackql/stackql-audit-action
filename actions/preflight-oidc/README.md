# actions/preflight-oidc (federated / OIDC)

Same as [`actions/preflight`](../preflight/) but with federated (OIDC) auth — no
long-lived secrets. Inputs mirror `actions/oidc` (`aws-role-arn`, `aws-region`,
`gcp-workload-identity-provider`, `gcp-sa-email`, `azure-tenant-id`,
`azure-client-id`, `azure-subscription-id`).

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: stackql/stackql-audit-action/actions/preflight-oidc@v0.11
    id: pf
    with:
      glob: 'remediations/proposed/**/preflight.sql'
      aws-role-arn: ${{ secrets.AWS_OIDC_ROLE_ARN }}   # read-only
      aws-region: us-east-1
```

Read-only: the federated role should carry no write actions.
