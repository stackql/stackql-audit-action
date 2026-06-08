# Pricing estimation — run locally

Gathers vendor pricing into `pricing/snapshot.json` (the normalized rate table
the FinOps audit reads). Each provider gathers only if its auth is present;
Azure is anonymous.

## Setup

```bash
export PRICING_OUT_DIR="$(pwd)/cicd/out/pricing"
python3 -m pip install -r cicd/requirements.txt

## you will need this for authenticated pricing, or you can do the drill manually
# source cicd/vendor-secrets/secrets.sh
```

## Per source

```bash
# Azure — no auth
python3 scripts/pricing.py azure

# AWS — needs creds with pricing:GetProducts
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
python3 scripts/pricing.py aws

# GCP — needs the provider pulled + SA auth
stackql exec 'registry pull google v25.12.00357;'
export STACKQL_AUDIT_AUTH='{"google":{"type":"service_account","credentialsfilepath":"'"$(pwd)/cicd/vendor-secrets/google-sa.json"'"}}'
python3 scripts/pricing.py gcp
```

## All at once

```bash
python3 scripts/pricing.py all      # or: aws azure gcp
cat pricing/snapshot.json
```

Empty `rates` → fix the per-class selectors in `CLASS_SPECS` at the top of
[`scripts/pricing.py`](../scripts/pricing.py).
