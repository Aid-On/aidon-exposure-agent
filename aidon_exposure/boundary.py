"""Deterministic security boundary. All input is data, never instructions.

The manifest is an operator-approved local trust root, NOT proof of ownership.
Hashes detect corruption, not malicious forgery; no signing is implemented.
"""
from __future__ import annotations
import copy
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 2 * 1024 * 1024
MAX_NODES, MAX_EDGES, MAX_EVIDENCE, MAX_PATHS = 100, 200, 1000, 256
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}\Z")
PREDICATES = {"public_visibility", "unauthenticated_invocation", "orphaned", "active",
              "user_input_drives_connector", "excessive_privilege", "sensitive", "known_vulnerability"}

class InputError(ValueError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def digest(record):
    return hashlib.sha256(canonical({k: v for k, v in record.items() if k != "sha256"})).hexdigest()

def timestamp(value):
    if not isinstance(value, str):
        raise InputError("Timestamp must be an ISO-8601 string with timezone")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InputError(f"Invalid timestamp: {value}") from exc
    if result.tzinfo is None:
        raise InputError("Timezone required")
    return result.astimezone(timezone.utc)

def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def no_duplicate_keys(pairs):
    out = {}
    for key, val in pairs:
        if key in out:
            raise InputError(f"Duplicate JSON key: {key}")
        out[key] = val
    return out

def load(path):
    path = Path(path)
    if path.stat().st_size > MAX_BYTES:
        raise InputError("Input exceeds 2 MiB budget")
    try:
        value = json.loads(path.read_text(), object_pairs_hook=no_duplicate_keys)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise InputError("Invalid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise InputError("Input root must be an object")
    return value

def require_id(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise InputError(f"Invalid identifier: {value!r}")
    return value

def bounded_records(root, key, maximum):
    records = root.get(key)
    if not isinstance(records, list) or len(records) > maximum:
        raise InputError(f"{key} must be a list with at most {maximum} records")
    ids = set()
    for record in records:
        if not isinstance(record, dict):
            raise InputError(f"{key} entries must be objects")
        ident = require_id(record.get("id"))
        if ident in ids:
            raise InputError(f"Duplicate {key} id: {ident}")
        ids.add(ident)
    return records

def hostname(raw):
    if not isinstance(raw, str) or raw != raw.strip() or not raw:
        raise InputError("Invalid host")
    if any(c in raw for c in "/:@*\\%?#"):
        raise InputError("Host must be a name without URL, wildcard, port or userinfo")
    raw = raw.removesuffix(".")
    try:
        host = raw.encode("idna").decode().lower()
    except UnicodeError as exc:
        raise InputError("Invalid IDNA host") from exc
    if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
        raise InputError("Invalid DNS host")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise InputError("IP literal must use explicit IP authorization")

class Scope:
    def __init__(self, manifest):
        if manifest.get("schema_version") != 1 or manifest.get("mode") != "fixture_only":
            raise InputError("Only schema 1 fixture_only manifests are supported")
        if manifest.get("revoked") is not False:
            raise InputError("Scope must explicitly be unrevoked")
        self.valid_from = timestamp(manifest.get("valid_from"))
        self.valid_until = timestamp(manifest.get("valid_until"))
        if self.valid_until <= self.valid_from:
            raise InputError("Invalid scope validity interval")
        self.organization = require_id(manifest.get("organization_id"))
        self.tenant = require_id(manifest.get("tenant_id"))
        self.hosts = [(hostname(x["name"]), x.get("include_subdomains") is True) for x in manifest.get("hosts", [])]
        self.excluded = [hostname(x) for x in manifest.get("excluded_hosts", [])]
        self.ips = set()
        for raw in manifest.get("ips", []):
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError as exc:
                raise InputError("IP grants require exact addresses, not CIDR") from exc
            if not ip.is_global:
                raise InputError("Private, reserved and special IP ranges are disallowed")
            self.ips.add(str(ip))
        self.grants = set(require_id(x) for x in manifest.get("asset_ids", []))
        self.ownership = manifest.get("ownership_records", {})
        if not isinstance(self.ownership, dict) or not manifest.get("approval_ref"):
            raise InputError("Manifest needs ownership records and an approval reference")
        if manifest.get("allowed_operations") != ["fixture_read"]:
            raise InputError("The only available operation is fixture_read")
        sources = bounded_records(manifest, "sources", 25)
        self.sources = {x["id"]: x for x in sources}
        for source in sources:
            if source.get("type") not in {"customer_config", "public_observation"}:
                raise InputError("Unsupported source type")
            if source.get("tenant_id") != self.tenant:
                raise InputError("Source tenant must match manifest")
            ttl = source.get("max_age_seconds", 86400)
            if type(ttl) is not int or not 1 <= ttl <= 604800:
                raise InputError("Source max_age_seconds must be 1..604800")

    def assert_current(self, at):
        if not self.valid_from <= at < self.valid_until:
            raise InputError("Scope approval is not valid at the assessment clock")

    def host_allowed(self, raw):
        try:
            name = hostname(raw)
        except InputError:
            return False
        if any(name == e or name.endswith("." + e) for e in self.excluded):
            return False
        return any(name == h or (sub and name.endswith("." + h)) for h, sub in self.hosts)

    def admit(self, node):
        owner = self.ownership.get(node["id"], {})
        observed_owner = node.get("owner", {})
        if not isinstance(owner, dict) or not isinstance(observed_owner, dict):
            return False, "Malformed ownership record"
        if node["id"] not in self.grants:
            return False, "Asset has no explicit grant; attribution is not authorization"
        if owner.get("status") != "verified" or owner.get("organization_id") != self.organization or not owner.get("verification_ref") or observed_owner != owner:
            return False, "Ownership not verified in operator-approved manifest inventory"
        if node.get("tenant_id") != self.tenant:
            return False, "Tenant mismatch"
        if node.get("kind") == "ai_app" and not node.get("hostname"):
            return False, "Public entry node needs an explicitly allowed hostname"
        names = ([node["hostname"]] if node.get("hostname") else []) + node.get("cname_chain", [])
        if any(not self.host_allowed(name) for name in names):
            return False, "Hostname or CNAME crosses scope; scope does not follow aliases"
        for raw in node.get("resolved_ips", []):
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                return False, "Invalid IP"
            if not ip.is_global or str(ip) not in self.ips:
                return False, "Resolved IP lacks an exact public-IP grant; shared IP is not ownership"
        return True, "Explicit fixture_read grant and ownership assertion accepted"

def normalize(manifest, snapshot, at):
    scope = Scope(manifest)
    at = timestamp(at) if isinstance(at, str) else at
    scope.assert_current(at)
    if snapshot.get("schema_version") != 1 or snapshot.get("tenant_id") != scope.tenant:
        raise InputError("Snapshot schema or tenant mismatch")
    revision = snapshot.get("revision")
    if type(revision) is not int or revision < 1:
        raise InputError("Snapshot revision must be a positive integer")
    snapshot_time = timestamp(snapshot.get("captured_at"))
    if snapshot_time > at:
        raise InputError("Snapshot is in the future relative to assessment clock")
    nodes = copy.deepcopy(bounded_records(snapshot, "nodes", MAX_NODES))
    edges = copy.deepcopy(bounded_records(snapshot, "edges", MAX_EDGES))
    evidence = copy.deepcopy(bounded_records(snapshot, "evidence", MAX_EVIDENCE))
    node_map = {n["id"]: n for n in nodes}
    edge_map = {e["id"]: e for e in edges}
    if node_map.keys() & edge_map.keys():
        raise InputError("Node and edge identifiers must be disjoint")
    issues = []
    for node in nodes:
        if node.get("kind") not in {"ai_app", "connector", "business_asset"}:
            raise InputError("Unsupported node kind")
        if node.get("state") not in {"confirmed", "inferred", "unknown"}:
            raise InputError("Node state must be confirmed/inferred/unknown")
        allowed, reason = scope.admit(node)
        node["authorized"] = allowed and node.get("state") == "confirmed"
        node["admission_reason"] = reason if node.get("state") == "confirmed" else "Node identity is not confirmed"
        if not node["authorized"]:
            issues.append({"subject": node["id"], "status": "excluded", "reason": node["admission_reason"]})
    for edge in edges:
        if edge.get("kind") not in {"invokes", "can_read"} or edge.get("state") not in {"confirmed", "inferred", "unknown"}:
            raise InputError("Unsupported edge kind/state")
        if edge.get("from") not in node_map or edge.get("to") not in node_map:
            raise InputError("Dangling edge endpoint")
        edge["authorized"] = node_map[edge["from"]]["authorized"] and node_map[edge["to"]]["authorized"]
    paths = sum(sum(1 for e2 in edges if e2["from"] == e1["to"] and e2["kind"] == "can_read") for e1 in edges if e1["kind"] == "invokes")
    if paths > MAX_PATHS:
        raise InputError("Candidate path budget exceeded")
    fingerprints = set()
    for e in evidence:
        if e.get("predicate") not in PREDICATES or type(e.get("value")) is not bool:
            raise InputError("Evidence predicate/value is invalid")
        if e.get("subject") not in node_map and e.get("subject") not in edge_map:
            raise InputError("Evidence refers to unknown subject")
        e["integrity_status"] = "valid" if e.get("sha256") == digest(e) else "invalid"
        reason = "eligible"
        source = scope.sources.get(e.get("source_id"))
        subject = node_map.get(e["subject"], edge_map.get(e["subject"]))
        if e["integrity_status"] != "valid":
            reason = "integrity_failed"
        elif not source or e.get("source_type") != source["type"]:
            reason = "unregistered_source"
        elif not subject["authorized"]:
            reason = "out_of_scope"
        elif e.get("tenant_id") != scope.tenant or e.get("deployment_id") != subject.get("deployment_id"):
            reason = "context_mismatch"
        elif e["subject"] in edge_map and e.get("principal_id") != subject.get("principal_id"):
            reason = "principal_mismatch"
        elif type(e.get("revision")) is not int or e["revision"] < 1:
            reason = "invalid_revision"
        elif not isinstance(e.get("provenance"), str) or not e["provenance"].startswith("fixture://"):
            reason = "invalid_fixture_provenance"
        else:
            observed, expires = timestamp(e.get("observed_at")), timestamp(e.get("expires_at"))
            if observed > at or observed > snapshot_time:
                reason = "future_evidence"
            elif expires <= observed:
                reason = "invalid_expiry"
            elif expires <= at or (at - observed).total_seconds() > source.get("max_age_seconds", 86400):
                reason = "stale"
        e["eligibility"] = reason
        # Exact semantic duplicates are retained for audit but cannot add votes.
        fingerprint = hashlib.sha256(canonical({k: v for k, v in e.items() if k not in {"id", "sha256", "integrity_status", "eligibility"}})).hexdigest()
        if fingerprint in fingerprints and reason == "eligible":
            e["eligibility"] = "duplicate"
        if e["eligibility"] == "eligible":
            fingerprints.add(fingerprint)
    # Only newer records in the SAME source+subject+predicate stream supersede.
    # Disagreement between independent streams remains a conflict in the engine.
    for e in evidence:
        if e["eligibility"] != "eligible":
            continue
        stream = (e.get("source_id"), e["subject"], e["predicate"])
        newer = [x for x in evidence if x["eligibility"] in {"eligible", "stale", "superseded"} and
                 (x.get("source_id"), x["subject"], x["predicate"]) == stream and x["revision"] > e["revision"]]
        if newer:
            if any(timestamp(x["observed_at"]) < timestamp(e["observed_at"]) for x in newer):
                raise InputError("Evidence revision/time rollback within a source stream")
            e["eligibility"] = "superseded"
    return {"schema_version": 1, "tenant_id": scope.tenant, "revision": revision,
            "captured_at": snapshot["captured_at"], "assessed_at": iso(at),
            "nodes": nodes, "edges": edges, "evidence": evidence, "admission_issues": issues}
