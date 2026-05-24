"""Python helpers for audit checks where SQL alone isn't enough.

Each function takes the rows returned by stackql plus named kwargs (sourced
from `filter_args` in the YAML) and returns the subset that should be
reported as findings.
"""

from __future__ import annotations

import json
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
