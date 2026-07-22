# StackQL Cross-Cloud Audit — Quickstart

The audit gives you a single view of security and cost risk across a broad cloud estate — AWS, GCP, Azure, and Entra ID — in one run. It enumerates the
full footprint (every enabled AWS region, every ACTIVE project under a GCP org, every
subscription in an Azure tenant, and the Entra directory), runs a pack of checks
against each scope — internet-exposed compute and databases, management ports (SSH/RDP)
open to the world, over-broad IAM and identity/credential hygiene, and orphaned or
oversized resources that waste spend — and rolls the results into one report: an
executive per-cloud summary (findings by severity, how large a population each check
scanned, and anything skipped) on top of full per-check detail with remediation, plus a
machine-readable `findings.json` / `summary.json` for downstream automation.
