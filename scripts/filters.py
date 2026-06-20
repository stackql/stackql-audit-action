"""Python helpers for audit checks where SQL alone isn't enough.

Each function takes the rows returned by stackql plus named kwargs (sourced
from `filter_args` in the YAML) and returns the subset that should be
reported as findings.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _coerce_list(val: Any) -> list:
    if val is None:
        return []
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            return [val]
    return [val]


def _coerce_dict(val: Any) -> dict:
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _port_matches(port: int, spec: str) -> bool:
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        try:
            return int(lo) <= port <= int(hi)
        except ValueError:
            return False
    return spec == str(port)


def firewall_allows_port(
    rows: list[dict],
    *,
    port: int,
    protocol: str = "tcp",
    source: str = "0.0.0.0/0",
) -> list[dict]:
    """Keep rows where the firewall allows `protocol`/`port` from `source`."""
    matches: list[dict] = []
    for row in rows:
        ranges = _coerce_list(row.get("sourceRanges"))
        if source not in ranges:
            continue
        for entry in _coerce_list(row.get("allowed")):
            if not isinstance(entry, dict):
                continue
            if (entry.get("IPProtocol") or "").lower() != protocol.lower():
                continue
            ports = entry.get("ports") or []
            if not ports:  # absent = all ports
                matches.append(row)
                break
            if any(_port_matches(port, str(p)) for p in ports):
                matches.append(row)
                break
    return matches


def _aws_list(val: Any) -> list:
    """Normalize the AWS Query-API polymorphic `{"item": ...}` wrapper to a flat list.

    The EC2 describe output collapses lists by cardinality: one element renders
    as ``{"item": {...}}``, many as ``{"item": [...]}``, empty as ``""``, and the
    whole field may be ``null``. stackql may also hand us the column as a JSON
    string. This flattens all of those to a plain list of dicts.
    """
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return []
        try:
            val = json.loads(s)
        except json.JSONDecodeError:
            return []
    if not val:  # None, "", {}, []
        return []
    if isinstance(val, dict):
        return _aws_list(val["item"]) if "item" in val else [val]
    if isinstance(val, list):
        return val
    return []


def sg_allows_port(
    rows: list[dict],
    *,
    port: int,
    protocol: str = "tcp",
    source: str = "0.0.0.0/0",
) -> list[dict]:
    """Keep AWS security groups whose ip_permissions allow `protocol`/`port` from `source`.

    Each permission is {ipProtocol, fromPort, toPort, ipRanges, ...}; ipProtocol
    '-1' means all protocols/all ports. ipRanges/ip_permissions arrive in the
    polymorphic `{"item": ...}` form handled by _aws_list.
    """
    matches: list[dict] = []
    for row in rows:
        for perm in _aws_list(row.get("ip_permissions")):
            if not isinstance(perm, dict):
                continue
            proto = str(perm.get("ipProtocol", "")).lower()
            if proto not in (protocol.lower(), "-1"):
                continue
            cidrs = [r.get("cidrIp") for r in _aws_list(perm.get("ipRanges")) if isinstance(r, dict)]
            if source not in cidrs:
                continue
            frm, to = perm.get("fromPort"), perm.get("toPort")
            if proto == "-1" or frm is None or to is None:
                matches.append(row)
                break
            try:
                if int(frm) <= port <= int(to):
                    matches.append(row)
                    break
            except (TypeError, ValueError):
                continue
    return matches


def instance_has_external_ip(rows: list[dict]) -> list[dict]:
    matches: list[dict] = []
    for row in rows:
        found = False
        for nic in _coerce_list(row.get("networkInterfaces")):
            if not isinstance(nic, dict):
                continue
            for ac in _coerce_list(nic.get("accessConfigs")):
                if isinstance(ac, dict) and ac.get("natIP"):
                    found = True
                    break
            if found:
                break
        if found:
            matches.append(row)
    return matches


def instance_uses_default_sa(rows: list[dict]) -> list[dict]:
    matches: list[dict] = []
    for row in rows:
        for sa in _coerce_list(row.get("serviceAccounts")):
            email = sa.get("email", "") if isinstance(sa, dict) else ""
            if email.endswith("-compute@developer.gserviceaccount.com"):
                matches.append(row)
                break
    return matches


def bucket_no_uniform_access(rows: list[dict]) -> list[dict]:
    matches: list[dict] = []
    for row in rows:
        cfg = _coerce_dict(row.get("iamConfiguration"))
        ubla = cfg.get("uniformBucketLevelAccess") or {}
        if not ubla.get("enabled"):
            matches.append(row)
    return matches


def cloudsql_has_public_ip(rows: list[dict]) -> list[dict]:
    matches: list[dict] = []
    for row in rows:
        for addr in _coerce_list(row.get("ipAddresses")):
            if isinstance(addr, dict) and addr.get("type") == "PRIMARY":
                matches.append(row)
                break
    return matches


# --- Azure helpers -------------------------------------------------------
# Azure resources surface their ARM body under a `properties` object (camelCase
# keys). These walk that structure; first-cut, refine against live output.

_AZURE_ANY_SOURCE = {"*", "internet", "0.0.0.0/0"}


def _port_in_range(port: int, spec: Any) -> bool:
    spec = str(spec).strip()
    if spec in ("*", ""):
        return True
    return _port_matches(port, spec)


def nsg_allows_port(rows: list[dict], *, port: int, protocol: str = "tcp") -> list[dict]:
    """Keep NSGs with an inbound Allow rule for `protocol`/`port` from any source."""
    matches: list[dict] = []
    for row in rows:
        props = _coerce_dict(row.get("properties"))
        for rule in _coerce_list(props.get("securityRules")):
            rp = _coerce_dict(rule).get("properties")
            rp = _coerce_dict(rp) if rp is not None else _coerce_dict(rule)
            if (rp.get("access") or "").lower() != "allow":
                continue
            if (rp.get("direction") or "").lower() != "inbound":
                continue
            proto = (rp.get("protocol") or "").lower()
            if proto not in (protocol.lower(), "*"):
                continue
            sources = {s.lower() for s in _coerce_list(rp.get("sourceAddressPrefix")) + _coerce_list(rp.get("sourceAddressPrefixes"))}
            if not (sources & _AZURE_ANY_SOURCE):
                continue
            ports = _coerce_list(rp.get("destinationPortRange")) + _coerce_list(rp.get("destinationPortRanges"))
            if any(_port_in_range(port, p) for p in ports):
                matches.append(row)
                break
    return matches


def azure_sql_public(rows: list[dict]) -> list[dict]:
    matches: list[dict] = []
    for row in rows:
        props = _coerce_dict(row.get("properties"))
        if (props.get("publicNetworkAccess") or "").lower() == "enabled":
            matches.append(row)
    return matches


def azure_storage_public_blob(rows: list[dict]) -> list[dict]:
    matches: list[dict] = []
    for row in rows:
        props = _coerce_dict(row.get("properties"))
        if props.get("allowBlobPublicAccess") is True:
            matches.append(row)
    return matches


# --- AWS S3 (Cloud Control detail rows) ----------------------------------
# Each filter evaluates a single aws.s3.buckets detail row. Columns are JSON
# (PascalCase keys), handed back by stackql as objects or JSON strings — the
# _coerce_* helpers absorb either.

_S3_PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


def s3_public_access_block_incomplete(rows: list[dict]) -> list[dict]:
    """Flag buckets where Public Access Block is absent or not all four enabled."""
    matches: list[dict] = []
    for row in rows:
        pab = _coerce_dict(row.get("public_access_block_configuration"))
        if not all(pab.get(k) is True for k in _S3_PAB_KEYS):
            matches.append(row)
    return matches


def s3_no_kms_encryption(rows: list[dict]) -> list[dict]:
    """Flag buckets whose default encryption is not SSE-KMS (i.e. SSE-S3/AES256 or none)."""
    matches: list[dict] = []
    for row in rows:
        enc = _coerce_dict(row.get("bucket_encryption"))
        rules = _coerce_list(enc.get("ServerSideEncryptionConfiguration"))
        uses_kms = any(
            _coerce_dict(_coerce_dict(r).get("ServerSideEncryptionByDefault")).get("SSEAlgorithm") == "aws:kms"
            for r in rules
        )
        if not uses_kms:
            matches.append(row)
    return matches


def s3_versioning_disabled(rows: list[dict]) -> list[dict]:
    """Flag buckets whose versioning status is not Enabled."""
    matches: list[dict] = []
    for row in rows:
        if _coerce_dict(row.get("versioning_configuration")).get("Status") != "Enabled":
            matches.append(row)
    return matches


def s3_acls_enabled(rows: list[dict]) -> list[dict]:
    """Flag buckets whose Object Ownership is not BucketOwnerEnforced (ACLs still active)."""
    matches: list[dict] = []
    for row in rows:
        rules = _coerce_list(_coerce_dict(row.get("ownership_controls")).get("Rules"))
        ownerships = [_coerce_dict(r).get("ObjectOwnership") for r in rules]
        if not ownerships or any(o != "BucketOwnerEnforced" for o in ownerships):
            matches.append(row)
    return matches


# --- Entra ID (Microsoft Graph) ------------------------------------------
# Graph returns ISO8601 timestamps (e.g. "2025-01-02T03:04:05Z", sometimes with
# 7-digit fractional seconds Python's fromisoformat won't accept). _parse_graph_dt
# normalises both. "now" is the audit run time — good enough for age/expiry checks.

def _parse_graph_dt(val: Any) -> datetime | None:
    if not isinstance(val, str) or not val.strip():
        return None
    s = re.sub(r"\.\d+", "", val.strip().replace("Z", "+00:00"))
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def entra_credential_hygiene(
    rows: list[dict], *, expiry_window_days: int = 30, max_lifetime_days: int = 365
) -> list[dict]:
    """Flag applications / service principals whose password or key credentials are
    expired, expiring within expiry_window_days, or longer-lived than max_lifetime_days.

    Reused by both the app and service-principal checks — both expose
    passwordCredentials / keyCredentials arrays of the same shape. Each match gains a
    `credential_issues` column summarising the offending credentials."""
    now = _now()
    soon = now + timedelta(days=expiry_window_days)
    matches: list[dict] = []
    for row in rows:
        issues: list[str] = []
        for kind, col in (("password", "passwordCredentials"), ("key", "keyCredentials")):
            for raw in _coerce_list(row.get(col)):
                cred = _coerce_dict(raw)
                end = _parse_graph_dt(cred.get("endDateTime"))
                if end is None:
                    continue
                label = cred.get("displayName") or cred.get("keyId") or "(unnamed)"
                if end < now:
                    issues.append(f"{kind}:{label}:expired")
                elif end < soon:
                    issues.append(f"{kind}:{label}:expiring<{expiry_window_days}d")
                else:
                    start = _parse_graph_dt(cred.get("startDateTime"))
                    if start and (end - start).days > max_lifetime_days:
                        issues.append(f"{kind}:{label}:lifetime>{max_lifetime_days}d")
        if issues:
            matches.append({**row, "credential_issues": "; ".join(issues)})
    return matches


def entra_external_audience(rows: list[dict]) -> list[dict]:
    """Flag app registrations whose sign-in audience extends beyond the home tenant
    (anything other than AzureADMyOrg — i.e. multi-tenant or personal Microsoft accounts)."""
    return [r for r in rows if (r.get("signInAudience") or "") not in ("", "AzureADMyOrg")]


# Delegated Graph scopes broad enough that a tenant-wide (AllPrincipals) grant is
# worth surfacing. Override per-check via filter_args.sensitive_scopes.
_ENTRA_SENSITIVE_SCOPES = (
    "Directory.Read.All", "Directory.ReadWrite.All",
    "User.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.ReadWrite.All",
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.ReadWrite.All", "Sites.ReadWrite.All",
    "Application.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
    "full_access_as_user",
)


def entra_oauth_tenant_wide_grants(
    rows: list[dict], *, sensitive_scopes: list[str] | None = None
) -> list[dict]:
    """Flag OAuth2 delegated permission grants consented for ALL users
    (consentType=AllPrincipals) that include a sensitive scope. Each match gains a
    `sensitive_scopes` column listing the scopes that tripped it."""
    sens = set(sensitive_scopes) if sensitive_scopes else set(_ENTRA_SENSITIVE_SCOPES)
    matches: list[dict] = []
    for row in rows:
        if (row.get("consentType") or "") != "AllPrincipals":
            continue
        hit = [s for s in (row.get("scope") or "").split() if s in sens]
        if hit:
            matches.append({**row, "sensitive_scopes": " ".join(hit)})
    return matches


def entra_guest_users(rows: list[dict]) -> list[dict]:
    """Flag external (guest) directory accounts."""
    return [r for r in rows if (r.get("userType") or "") == "Guest"]


def entra_stale_users(
    rows: list[dict], *, max_age_days: int = 90, include_never: bool = True
) -> list[dict]:
    """Flag enabled accounts that haven't signed in within max_age_days (and, when
    include_never is set, accounts with no recorded interactive sign-in). Each match
    gains a `last_sign_in` column ('never' or a date)."""
    now = _now()
    matches: list[dict] = []
    for row in rows:
        if row.get("accountEnabled") is False:
            continue
        last = _parse_graph_dt(_coerce_dict(row.get("signInActivity")).get("lastSignInDateTime"))
        if last is None:
            if include_never:
                matches.append({**row, "last_sign_in": "never"})
            continue
        if (now - last).days > max_age_days:
            matches.append({**row, "last_sign_in": last.date().isoformat()})
    return matches


# --- FinOps: pricing lookup + orphan/unattached cost estimates ---------------
# Reads the committed pricing snapshot (scripts/pricing.py output) and annotates
# orphan findings with estimated_monthly_usd. Estimate, not an invoice: where a
# class has many SKUs/regions we use the median rate for the resource's region.

_PRICING_CACHE: tuple[dict, dict] | None = None


def _pricing_path() -> Path:
    return Path(os.environ.get("STACKQL_PRICING_SNAPSHOT")
                or (Path(os.environ.get("ACTION_PATH", "."))
                    / "cicd" / "reference" / "pricing" / "snapshot.json"))


def _load_pricing() -> tuple[dict, dict]:
    """Return (index, units). index keys: (provider, class, region) and
    (provider, class, None) -> [prices]; units: class -> unit string."""
    global _PRICING_CACHE
    if _PRICING_CACHE is not None:
        return _PRICING_CACHE
    try:
        data = json.loads(_pricing_path().read_text())
        rates = data.get("rates", [])
    except (OSError, json.JSONDecodeError):
        rates = []
    idx: dict = {}
    units: dict = {}
    for r in rates:
        p, k, region = r.get("provider"), r.get("resource_class"), r.get("region")
        price = r.get("price")
        if price is None:
            continue
        idx.setdefault((p, k, region), []).append(price)
        idx.setdefault((p, k, None), []).append(price)
        units[k] = r.get("unit")
    _PRICING_CACHE = (idx, units)
    return _PRICING_CACHE


def _median(xs: list[float]) -> float:
    xs = sorted(xs)
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def _monthly_cost(provider: str, klass: str, region: str | None, size_gb: Any = None) -> float | None:
    idx, units = _load_pricing()
    prices = idx.get((provider, klass, region)) or idx.get((provider, klass, None))
    if not prices:
        return None
    price = _median(prices)
    unit = units.get(klass)
    if unit == "GB-month":
        try:
            return round(price * float(size_gb or 0), 2)
        except (TypeError, ValueError):
            return None
    if unit == "hour":
        return round(price * 730, 2)
    return round(price, 2)


def _gcp_region(row: dict) -> str | None:
    region = row.get("region")
    if region:
        return region.rsplit("/", 1)[-1]
    zone = (row.get("zone") or "").rsplit("/", 1)[-1]
    return zone.rsplit("-", 1)[0] if zone else None


def gcp_unattached_disk(rows: list[dict]) -> list[dict]:
    """Persistent disks with no attached instances (users == [])."""
    out: list[dict] = []
    for r in rows:
        if _coerce_list(r.get("users")):
            continue
        region = _gcp_region(r)
        zone_name = (r.get("zone") or "").rsplit("/", 1)[-1]  # bare zone for gcloud --zone
        out.append({**r, "region": region, "zone_name": zone_name,
                    "category": "waste", "estimated_monthly_usd": _monthly_cost("gcp", "block-storage", region, r.get("sizeGb"))})
    return out


def gcp_unused_address(rows: list[dict]) -> list[dict]:
    """Reserved static IPs not in use (status RESERVED, no users)."""
    out: list[dict] = []
    for r in rows:
        if (r.get("status") or "") != "RESERVED" or _coerce_list(r.get("users")):
            continue
        region = _gcp_region(r)
        out.append({**r, "region": region,
                    "category": "waste", "estimated_monthly_usd": _monthly_cost("gcp", "public-ip", region)})
    return out


_AZURE_ID = re.compile(r"/subscriptions/([^/]+)/resourceGroups/([^/]+)/.*/([^/]+)$", re.IGNORECASE)


def _azure_id_parts(resource_id: Any) -> dict:
    """Pull the delete-identity (subscriptionId, resourceGroupName, name) out of an
    ARM resource id, so the suggested_remediation template can address it."""
    m = _AZURE_ID.match(resource_id or "")
    if not m:
        return {}
    return {"subscriptionId": m.group(1), "resourceGroupName": m.group(2), "name": m.group(3)}


def azure_unattached_disk(rows: list[dict]) -> list[dict]:
    """Managed disks not attached to anything (managedBy is null/empty)."""
    out: list[dict] = []
    for r in rows:
        if r.get("managedBy"):
            continue
        props = _coerce_dict(r.get("properties"))
        size = props.get("diskSizeGB")
        region = r.get("location")
        out.append({**r, **_azure_id_parts(r.get("id")), "region": region, "size_gb": size,
                    "category": "waste", "estimated_monthly_usd": _monthly_cost("azure", "block-storage", region, size)})
    return out


def azure_unassociated_public_ip(rows: list[dict]) -> list[dict]:
    """Public IPs not bound to any IP configuration (idle, still billed)."""
    out: list[dict] = []
    for r in rows:
        if _coerce_dict(r.get("properties")).get("ipConfiguration"):
            continue
        region = r.get("location")
        out.append({**r, **_azure_id_parts(r.get("id")), "region": region,
                    "category": "waste", "estimated_monthly_usd": _monthly_cost("azure", "public-ip", region)})
    return out


def _aws_region_from_az(az: str | None) -> str | None:
    """us-east-1a -> us-east-1 (strip the trailing AZ letter)."""
    if not az:
        return None
    return az[:-1] if az[-1].isalpha() else az


def aws_unattached_volume(rows: list[dict]) -> list[dict]:
    """EBS volumes in 'available' state (not attached to any instance)."""
    out: list[dict] = []
    for r in rows:
        if (r.get("status") or "").lower() != "available":
            continue
        region = _aws_region_from_az(r.get("AvailabilityZone"))
        out.append({**r, "region": region,
                    "category": "waste", "estimated_monthly_usd": _monthly_cost("aws", "block-storage", region, r.get("size"))})
    return out


def aws_unassociated_eip(rows: list[dict]) -> list[dict]:
    """Elastic IPs not associated with an instance/ENI (idle, still billed).

    The address row carries no region; EIP pricing is effectively flat, so cost
    uses the global median (region=None). The fanout tags the row's region for display."""
    out: list[dict] = []
    for r in rows:
        if r.get("associationId") or r.get("instanceId") or r.get("networkInterfaceId"):
            continue
        out.append({**r, "category": "waste", "estimated_monthly_usd": _monthly_cost("aws", "public-ip", None)})
    return out


def _advisor_monthly_savings(ext: dict) -> float | None:
    """Azure Advisor cost recs carry a vendor savings figure in extendedProperties
    (annualSavingsAmount, or savingsAmount). Normalize to monthly USD-ish."""
    for key, div in (("annualSavingsAmount", 12), ("savingsAmount", 1)):
        v = ext.get(key)
        if v not in (None, ""):
            try:
                return round(float(v) / div, 2)
            except (TypeError, ValueError):
                pass
    return None


def azure_advisor_cost(rows: list[dict]) -> list[dict]:
    """Azure Advisor cost recommendations (vendor-computed right-size / shutdown of
    underutilized resources). Tagged `suspected` — it's the vendor's signal, not our
    proof — with their savings estimate."""
    out: list[dict] = []
    for r in rows:
        p = _coerce_dict(r.get("properties"))
        if (p.get("category") or "") != "Cost":
            continue
        sd = _coerce_dict(p.get("shortDescription"))
        out.append({
            "id": r.get("id"),
            "resource": p.get("impactedValue"),
            "impacted_field": p.get("impactedField"),
            "impact": p.get("impact"),
            "recommendation": sd.get("solution") or sd.get("problem"),
            "category": "suspected",
            "source": "azure-advisor",
            "estimated_savings_usd": _advisor_monthly_savings(_coerce_dict(p.get("extendedProperties"))),
        })
    return out


# --- FinOps: watch — expensive running resources flagged for notice ----------
# Inventory + type, tagged `watch` (spend, not proven waste). monthly_run_rate_usd
# is null until the compute/db pricing classes land (GCP prices by vCPU+RAM, not
# machine-type — a separate pricing effort); the type is captured so it's costable.

def aws_compute_watch(rows: list[dict]) -> list[dict]:
    """Running EC2 instances."""
    out: list[dict] = []
    for r in rows:
        if (_coerce_dict(r.get("instanceState")).get("name") or "").lower() != "running":
            continue
        region = _aws_region_from_az(_coerce_dict(r.get("placement")).get("availabilityZone"))
        out.append({"category": "watch", "kind": "compute", "resource": r.get("instanceId"),
                    "type": r.get("instanceType"), "region": region, "monthly_run_rate_usd": None})
    return out


def gcp_compute_watch(rows: list[dict]) -> list[dict]:
    """Running Compute Engine instances."""
    out: list[dict] = []
    for r in rows:
        if (r.get("status") or "") != "RUNNING":
            continue
        out.append({"category": "watch", "kind": "compute", "resource": r.get("name"),
                    "type": (r.get("machineType") or "").rsplit("/", 1)[-1],
                    "region": _gcp_region(r), "monthly_run_rate_usd": None})
    return out


def azure_compute_watch(rows: list[dict]) -> list[dict]:
    """Azure VMs (the list API doesn't carry power state, so all are flagged)."""
    out: list[dict] = []
    for r in rows:
        props = _coerce_dict(r.get("properties"))
        out.append({"category": "watch", "kind": "compute", "resource": r.get("id"),
                    "type": _coerce_dict(props.get("hardwareProfile")).get("vmSize"),
                    "region": r.get("location"), "monthly_run_rate_usd": None})
    return out


def aws_rds_watch(rows: list[dict]) -> list[dict]:
    """RDS instances (managed DB) flagged for cost review."""
    return [{"category": "watch", "kind": "db",
             "resource": r.get("db_instance_identifier") or r.get("db_instance_arn"),
             "type": r.get("db_instance_class"), "engine": r.get("engine"),
             "region": r.get("region"), "monthly_run_rate_usd": None} for r in rows]


def gcp_cloudsql_watch(rows: list[dict]) -> list[dict]:
    """Cloud SQL instances flagged for cost review."""
    return [{"category": "watch", "kind": "db", "resource": r.get("name"),
             "type": _coerce_dict(r.get("settings")).get("tier"),
             "engine": r.get("databaseVersion"), "region": r.get("region"),
             "monthly_run_rate_usd": None} for r in rows]


def aws_eks_watch(rows: list[dict]) -> list[dict]:
    """EKS cluster control planes (nodes are covered by compute watch)."""
    return [{"category": "watch", "kind": "cluster", "resource": r.get("id") or r.get("arn"),
             "type": "eks", "region": r.get("region"), "monthly_run_rate_usd": None} for r in rows]


def gcp_gke_watch(rows: list[dict]) -> list[dict]:
    """GKE clusters (nodes are covered by compute watch)."""
    return [{"category": "watch", "kind": "cluster", "resource": r.get("name"),
             "type": "gke", "region": r.get("location"),
             "node_count": r.get("currentNodeCount"), "monthly_run_rate_usd": None} for r in rows]


def azure_aks_watch(rows: list[dict]) -> list[dict]:
    """AKS managed clusters (nodes are covered by compute watch)."""
    return [{"category": "watch", "kind": "cluster", "resource": r.get("id"),
             "type": "aks", "region": r.get("location"), "monthly_run_rate_usd": None} for r in rows]


# --- zero-VMs policy: every active VM is a finding to kill ----------------
# Hard policy, severity HIGH. Distinct from *_compute_watch (LOW, advisory).
# Output keeps the raw row plus a kill-friendly handle so the remediation
# agent has enough to author the DELETE statement.


def aws_zero_vms_policy(rows: list[dict]) -> list[dict]:
    """EC2 instances not yet terminated. ('terminated' is the only kill end-state.)"""
    out: list[dict] = []
    for r in rows:
        state = (_coerce_dict(r.get("instanceState")).get("name") or "").lower()
        if state == "terminated":
            continue
        region = _aws_region_from_az(_coerce_dict(r.get("placement")).get("availabilityZone"))
        out.append({**r, "region": region, "instanceState": state})
    return out


def gcp_zero_vms_policy(rows: list[dict]) -> list[dict]:
    """GCE instances not yet terminated. (TERMINATED here means stopped, not deleted.)"""
    out: list[dict] = []
    for r in rows:
        status = (r.get("status") or "").upper()
        if status == "TERMINATED":
            continue
        zone = (r.get("zone") or "").rsplit("/", 1)[-1]
        machine_type = (r.get("machineType") or "").rsplit("/", 1)[-1]
        out.append({**r, "zone": zone, "machineType": machine_type,
                    "region": _gcp_region(r), "status": status})
    return out


def azure_zero_vms_policy(rows: list[dict]) -> list[dict]:
    """All Azure VMs from the list API. Power state is unavailable here;
    the remediation preflight must re-check via instanceView before kill."""
    out: list[dict] = []
    for r in rows:
        props = _coerce_dict(r.get("properties"))
        vm_size = _coerce_dict(props.get("hardwareProfile")).get("vmSize")
        out.append({**r, "region": r.get("location"), "vmSize": vm_size})
    return out
