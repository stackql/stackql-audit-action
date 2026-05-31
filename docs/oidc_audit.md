# OIDC-based Audit

This action performs cross-cloud deep audit using federated identity / OIDC authentication rather than long-lived cloud credentials.

Supported providers:

- AWS — GitHub OIDC → `sts:AssumeRoleWithWebIdentity`
- GCP — Workload Identity Federation → service account impersonation
- Azure — federated identity credentials

No static access keys, client secrets, or service-account keys are required for the audited cloud estates.

This action is intended for:
- org-wide audit
- foreign account / tenant / org audit
- scheduled continuous reporting
- deep inventory traversal (`s3`, region descent, org descent, etc.)

A copy/paste-able workflow example is available at:

[`oidc-audit-workflow-dispatch.yml`](/docs/examples/oidc-audit-workflow-dispatch.yml)

