#!/usr/bin/env python3
"""Gather vendor pricing into one normalized rate-table snapshot.

Disjoint from the audit: this runs on a schedule/event and writes a pricing
snapshot the on-demand FinOps audit reads (it never fetches pricing per run, so
audit runs stay fast, deterministic, and reproducible). One normalized schema
across providers, so the audit's costing logic is provider-agnostic.

Sources (per the brief):
  * AWS   — Price List Query API (boto3 pricing.get_products; needs AWS creds)
  * Azure — Retail Prices API (anonymous HTTP)
  * GCP   — Cloud Billing Catalog (cloudbilling.skus, via stackql; needs GCP auth)

Output: pricing/snapshot.json
  {
    "version": "<iso>", "currency": "USD",
    "sources": {"aws": "...", ...},
    "rates": [ {provider, resource_class, region, unit, price, sku}, ... ]
  }

`resource_class` / `unit` are the NORMALIZED keys the audit filters map a live
resource to (e.g. block-storage @ GB-month, public-ip @ hour). Add a class by
editing CLASS_SPECS — the per-vendor selectors there are the only thing to
validate against live catalog output on first run.

Run:  python3 scripts/pricing.py [aws|azure|gcp|all]   (default: all)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

# --- normalized taxonomy -----------------------------------------------------
# unit is what the audit multiplies by: "GB-month" -> price * size_gb;
# "hour" -> price * HOURS_PER_MONTH (idle IP / NAT etc.).
HOURS_PER_MONTH = 730

# Per-class vendor selectors. THESE are the validate-on-first-run knobs:
#   azure: an OData $filter against the Retail Prices API
#   aws:   (ServiceCode, [(Field, Value), ...]) filters for pricing.get_products
#   gcp:   substrings matched (case-insensitive) against cloudbilling sku.description
CLASS_SPECS = {
    "block-storage": {
        "unit": "GB-month",
        "azure": "serviceName eq 'Storage' and priceType eq 'Consumption' and contains(meterName, 'Disk')",
        "aws": ("AmazonEC2", [("productFamily", "Storage"), ("volumeApiName", "gp3")]),
        "gcp": ["SSD backed PD Capacity", "Storage PD Capacity"],
    },
    "snapshot-storage": {
        "unit": "GB-month",
        "azure": "serviceName eq 'Storage' and priceType eq 'Consumption' and contains(meterName, 'Snapshot')",
        "aws": ("AmazonEC2", [("productFamily", "Storage Snapshot")]),
        "gcp": ["Storage PD Snapshot"],
    },
    "public-ip": {
        "unit": "hour",
        "azure": "serviceName eq 'Virtual Network' and priceType eq 'Consumption' and contains(meterName, 'IP Address')",
        "aws": ("AmazonEC2", [("productFamily", "IP Address"), ("group", "ElasticIP:Address")]),
        "gcp": ["Static Ip Charge", "External IP Charge"],
    },
    "nat-gateway": {
        "unit": "hour",
        "azure": "serviceName eq 'NAT Gateway' and priceType eq 'Consumption' and contains(meterName, 'Gateway')",
        "aws": ("AmazonEC2", [("productFamily", "NAT Gateway")]),
        "gcp": ["Cloud NAT Gateway"],
    },
}

CURRENCY = "USD"


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _rate(provider, resource_class, region, unit, price, sku) -> dict:
    return {
        "provider": provider,
        "resource_class": resource_class,
        "region": region,
        "unit": unit,
        "price": float(price),
        "sku": sku,
    }


# --- Azure: Retail Prices API (anonymous) ------------------------------------

def gather_azure() -> list[dict]:
    rates: list[dict] = []
    base = "https://prices.azure.com/api/retail/prices"
    for klass, spec in CLASS_SPECS.items():
        flt = spec.get("azure")
        if not flt:
            continue
        url = f"{base}?$filter={urllib.parse.quote(flt)}&currencyCode={CURRENCY}"
        pages = 0
        while url and pages < 20:  # cap paging defensively
            try:
                with urllib.request.urlopen(url, timeout=30) as r:
                    doc = json.loads(r.read())
            except Exception as e:  # noqa: BLE001 - best-effort gather
                print(f"::warning::azure {klass} fetch failed: {e}")
                break
            for it in doc.get("Items", []):
                if it.get("type") != "Consumption":
                    continue
                rates.append(_rate(
                    "azure", klass, it.get("armRegionName") or "global",
                    spec["unit"], it.get("retailPrice", 0.0),
                    it.get("meterId") or it.get("skuId") or it.get("meterName"),
                ))
            url = doc.get("NextPageLink")
            pages += 1
    return rates


# --- AWS: Price List Query API (boto3) ---------------------------------------

def gather_aws() -> list[dict]:
    try:
        import boto3  # provided by the action step (pip install)
    except ImportError:
        print("::warning::boto3 not available — skipping AWS pricing")
        return []
    # The pricing API only lives in these regions; data is global regardless.
    client = boto3.client("pricing", region_name="us-east-1")
    rates: list[dict] = []
    for klass, spec in CLASS_SPECS.items():
        sel = spec.get("aws")
        if not sel:
            continue
        service_code, filters = sel
        flt = [{"Type": "TERM_MATCH", "Field": f, "Value": v} for f, v in filters]
        try:
            paginator = client.get_paginator("get_products")
            for page in paginator.paginate(ServiceCode=service_code, Filters=flt):
                for raw in page.get("PriceList", []):
                    prod = json.loads(raw)
                    region = prod.get("product", {}).get("attributes", {}).get("regionCode", "global")
                    sku = prod.get("product", {}).get("sku")
                    # on-demand USD price-per-unit
                    for term in prod.get("terms", {}).get("OnDemand", {}).values():
                        for dim in term.get("priceDimensions", {}).values():
                            usd = dim.get("pricePerUnit", {}).get("USD")
                            if usd is None:
                                continue
                            rates.append(_rate("aws", klass, region, spec["unit"], usd, sku))
        except Exception as e:  # noqa: BLE001
            print(f"::warning::aws {klass} fetch failed: {e}")
    return rates


# --- GCP: Cloud Billing Catalog via stackql ----------------------------------
# Compute Engine service id in the Cloud Billing Catalog (bare id; the stackql
# resource takes it as the `servicesId` path param).
GCP_COMPUTE_SERVICE = "6F81-5844-456A"


def _stackql_json(query: str) -> list[dict]:
    argv = ["stackql", "exec"]
    auth = os.environ.get("STACKQL_AUDIT_AUTH")  # e.g. the WIF bearer set by the action
    if auth:
        argv += ["--auth", auth]
    argv += ["--output", "json", query]
    out = subprocess.run(argv, capture_output=True, text=True, check=False)
    if out.returncode != 0 or not out.stdout.strip():
        print(f"::warning::gcp pricing query failed: {(out.stderr or '').splitlines()[:1]}")
        return []
    try:
        data = json.loads(out.stdout)
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else [data]


def gather_gcp() -> list[dict]:
    rows = _stackql_json(
        f"SELECT skuId, description, category, serviceRegions, pricingInfo "
        f"FROM google.cloudbilling.skus WHERE servicesId = '{GCP_COMPUTE_SERVICE}';")
    rates: list[dict] = []
    for klass, spec in CLASS_SPECS.items():
        needles = [n.lower() for n in spec.get("gcp", [])]
        if not needles:
            continue
        for sku in rows:
            desc = (sku.get("description") or "").lower()
            if not any(n in desc for n in needles):
                continue
            price = _gcp_unit_price(sku.get("pricingInfo"))
            if price is None:
                continue
            for region in (sku.get("serviceRegions") or ["global"]):
                rates.append(_rate("gcp", klass, region, spec["unit"], price, sku.get("skuId")))
    return rates


def _gcp_unit_price(pricing_info) -> float | None:
    """First tiered rate from a cloudbilling sku's pricingInfo (units + nanos)."""
    if isinstance(pricing_info, str):
        try:
            pricing_info = json.loads(pricing_info)
        except json.JSONDecodeError:
            return None
    try:
        expr = pricing_info[0]["pricingExpression"]
        tier = expr["tieredRates"][-1]["unitPrice"]
        return int(tier.get("units", 0)) + int(tier.get("nanos", 0)) / 1e9
    except (KeyError, IndexError, TypeError, ValueError):
        return None


GATHERERS = {"aws": gather_aws, "azure": gather_azure, "gcp": gather_gcp}


def main() -> int:
    args = sys.argv[1:] or ["all"]
    providers = list(GATHERERS) if "all" in args else args
    rates: list[dict] = []
    sources: dict[str, str] = {}
    for p in providers:
        fn = GATHERERS.get(p)
        if not fn:
            print(f"::error::unknown provider '{p}'")
            return 2
        got = fn()
        rates.extend(got)
        sources[p] = f"{len(got)} rates @ {_now_iso()}"
        print(f"::notice::{p}: {len(got)} rate(s)")

    snapshot = {
        "version": _now_iso(),
        "currency": CURRENCY,
        "sources": sources,
        "rates": rates,
    }
    out_dir = Path(os.environ.get("PRICING_OUT_DIR") or (Path(os.environ.get("ACTION_PATH", ".")) / "pricing"))
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "snapshot.json"
    out.write_text(json.dumps(snapshot, indent=2))
    print(f"::notice::wrote {out} ({len(rates)} total rates across {len(providers)} provider(s))")
    if not rates:
        print("::warning::pricing snapshot is empty — validate CLASS_SPECS selectors against live catalog output")
    return 0


if __name__ == "__main__":
    sys.exit(main())
