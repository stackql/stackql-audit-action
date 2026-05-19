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
