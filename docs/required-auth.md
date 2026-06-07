# Required auth & privileges

All audits are **read-only**. Each provider runs only when its credentials are
supplied. Grant the minimum below; prefer scoping **one level up** so child
scopes inherit.

## Privileges per provider

| Provider | Principal | Minimum role / permissions |
| --- | --- | --- |
| **AWS** | access key or assumed role | `SecurityAudit` (or `ReadOnlyAccess`). S3 deep scan also needs `s3:GetBucket*` and, via Cloud Control, `cloudcontrol:GetResource` / `cloudcontrol:ListResources`. |
| **GCP** | service account or WIF SA | `roles/viewer` + `roles/iam.securityReviewer`. Org descent (`gcp-org`) also needs `roles/resourcemanager.folderViewer` at the **organization** node. |
| **Azure** | service principal | `Reader` at the **subscription**, or at the **management-group / tenant root** for `azure-org` (inherits to all child subscriptions). |
| **Entra ID** | same service principal (Microsoft Graph) | Graph **application** permissions, admin-consented: `Directory.Read.All`, `Policy.Read.All`, `Application.Read.All`, `AuditLog.Read.All`. Tenant-global — no subscription required. |

## OIDC (federated) auth

The `actions/oidc` action uses GitHub OIDC — no long-lived secrets.

- **AWS** — IAM role with a trust policy federating
  `token.actions.githubusercontent.com` for your repo subject; attach `SecurityAudit`.
- **GCP** — Workload Identity Federation pool bound to the repo, impersonating an
  SA holding the roles above.
- **Azure / Entra** — app registration with a **federated credential** whose
  subject matches the run, e.g.
  `repo:<owner>/<repo>:ref:refs/heads/<branch>`
  (issuer `https://token.actions.githubusercontent.com`, audience
  `api://AzureADTokenExchange`). Assign `Reader` for `azure-org` and the Graph
  permissions above for `entra`. The federated login needs only client-id +
  tenant-id (subscription is optional).

> **Entra under OIDC:** the `entra` target authenticates with a Microsoft Graph
> bearer token minted from the federated `az` CLI session — no client secret. It
> only runs if the Azure federated login succeeds.

## Notes

- Scope an audit narrowly by supplying a single subscription/project; omit it to
  span all (org/management-group descent).
- No write/DML permissions are ever required.
