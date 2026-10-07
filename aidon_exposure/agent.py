"""Bounded deterministic inspection loop: no network and no change application."""
from __future__ import annotations
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from .boundary import InputError, canonical, normalize, timestamp

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENGINE = ROOT / "bin" / "aidon-engine"
RULE = "orphan-ai-connector-sensitive-v1"


def assess(manifest, snapshot, at, engine=DEFAULT_ENGINE):
    normalized = normalize(manifest, snapshot, at)
    engine = Path(engine).resolve()
    if not engine.is_file():
        raise InputError("Almide engine not built; run ./build.sh with ALMIDE pointing to the compiler")
    with tempfile.TemporaryDirectory(prefix="aidon-fixture-") as tmp:
        path = Path(tmp) / "normalized.json"
        path.write_bytes(canonical(normalized))
        try:
            run = subprocess.run([str(engine), str(path)], capture_output=True, text=True,
                                 timeout=10, check=False, cwd=tmp)
        except subprocess.TimeoutExpired as exc:
            raise InputError("Engine budget exceeded; assessment is inconclusive") from exc
    if run.returncode or len(run.stdout) > 10 * 1024 * 1024:
        raise InputError(f"Engine failed or output budget exceeded (exit {run.returncode})")
    try:
        result = json.loads(run.stdout)
    except json.JSONDecodeError as exc:
        raise InputError("Invalid engine response") from exc
    findings = result["findings"]
    nodes = {n["id"]: n for n in normalized["nodes"]}
    edges = {e["id"]: e for e in normalized["edges"]}
    for f in findings:
        f["path_context"] = {
            "nodes": [{k: nodes[ident].get(k) for k in ("id", "kind", "tenant_id", "deployment_id")} for ident in f["path"]],
            "edges": [{k: edges[ident].get(k) for k in ("id", "kind", "from", "to", "deployment_id", "principal_id")} for ident in f["edges"]],
        }
        key = [f["rule_id"], f["tenant_id"], f["path"], f["edges"], f["path_context"]]
        f["id"] = "aidon-" + hashlib.sha256(canonical(key)).hexdigest()[:20]
        f["priority"] = "review_now" if f["status"] == "configuration_supported_candidate" and f["business_impact"] == "high" else "investigate" if f["status"] == "not_established" else "review_snapshot"
        f["priority_basis"] = {"business_impact": f["business_impact"], "status": f["status"], "method": "ordinal policy; no CVSS or invented probability"}
        f["remediation"] = {
            "status": "proposal_only", "approval_required": True,
            "options": [
                {"target": f["path"][0], "proposal": "Retire the unused PoC or require intended-user authentication"},
                {"target": f["edges"][1], "proposal": "Reduce the connector to approved business resources and permissions"},
                {"target": f["edges"][0], "proposal": "Constrain how untrusted user input can select connector operations"},
            ],
            "verification": "Supply a later independent config snapshot; do not edit this report as evidence",
        }
    findings.sort(key=lambda f: ({"review_now": 0, "investigate": 1, "review_snapshot": 2}[f["priority"]], f["id"]))
    return {
        "schema_version": 1, "product": "Aid-On Exposure Agent prototype", "engine": result["engine"],
        "engine_version": result["engine_version"], "mode": "fixture_only", "rule_id": RULE,
        "snapshot": {"id": snapshot.get("id"), "revision": normalized["revision"], "captured_at": normalized["captured_at"], "assessed_at": normalized["assessed_at"], "sha256": hashlib.sha256(canonical(snapshot)).hexdigest()},
        "trust": {"manifest": "local operator-approved assertion; ownership was not independently verified", "evidence_integrity": "unsigned SHA-256 detects corruption, not authenticity", "source_authority": "configured allowlist; fixture assertions were not authenticated against live providers"},
        "limitations": ["No live access, exploitation, authentication or remediation was attempted", "Configuration-supported candidates are not proven exploits or current runtime reachability", "One bounded rule and synthetic scenario; no claim of superiority over commercial EASM", "A blocked path does not establish that all alternative paths are safe"],
        "loop": [
            {"step": "collect", "tool": "fixture_read", "status": "completed"},
            {"step": "normalize", "tool": "deterministic_boundary", "status": "completed"},
            {"step": "reconcile", "tool": "revision_and_conflict_rules", "status": "completed"},
            {"step": "assess", "tool": "almide_prerequisite_engine", "status": "completed"},
            {"step": "report", "tool": "local_json_and_text", "status": "completed"},
            {"step": "remediate", "tool": "none", "status": "human_approval_required_and_not_implemented"},
            {"step": "recheck", "tool": "fixture_read", "status": "awaiting_new_snapshot"},
        ],
        "findings": findings, "admission_issues": normalized["admission_issues"],
        "graph": {"nodes": normalized["nodes"], "edges": normalized["edges"]},
        "evidence": normalized["evidence"],
    }


def recheck(before, after):
    # This comparison consumes reports freshly produced by assess(), not a fix plan.
    old, new = before["snapshot"], after["snapshot"]
    valid_revision = new["revision"] > old["revision"] and new["sha256"] != old["sha256"]
    valid_time = timestamp(new["captured_at"]) > timestamp(old["assessed_at"])
    results = []
    new_findings = {f["id"]: f for f in after["findings"]}
    evidence = {e["id"]: e for e in after["evidence"]}
    old_evidence = {e["id"]: e for e in before["evidence"]}
    def stream_key(e):
        return tuple(e.get(k) for k in ("source_id", "subject", "predicate", "tenant_id", "deployment_id", "principal_id"))
    def continuity_error(previous):
        for check in previous["prerequisites"]:
            for ident in check["evidence_ids"]:
                prior = old_evidence[ident]
                available = [e for e in evidence.values() if stream_key(e) == stream_key(prior) and e["eligibility"] in {"eligible", "superseded", "duplicate", "stale"}]
                if not available:
                    return "Previously supporting source stream is missing or unusable in the later snapshot"
                newest = max(e["revision"] for e in available)
                if newest < prior["revision"]:
                    return "Source-stream revision rolled back across snapshots"
                latest = [e for e in available if e["revision"] == newest]
                if any(timestamp(e["observed_at"]) < timestamp(prior["observed_at"]) for e in latest):
                    return "Source-stream observation time rolled back across snapshots"
                if newest == prior["revision"] and any(e["value"] != prior["value"] for e in latest):
                    return "Source-stream revision was reused with a conflicting value"
        return None
    for previous in before["findings"]:
        if previous["status"] != "configuration_supported_candidate":
            continue
        current = new_findings.get(previous["id"])
        state, reason, closing = "inconclusive", "Missing or insufficient later evidence", []
        reclassified = []
        context_changed = any(f["path"] == previous["path"] and f["edges"] == previous["edges"] and f["path_context"] != previous["path_context"] for f in after["findings"])
        continuity = continuity_error(previous)
        if context_changed:
            reason = "Path context changed; a different deployment or principal cannot close the original path"
        elif continuity:
            reason = continuity
        elif not valid_revision or not valid_time:
            reason = "A distinct later snapshot revision captured after the original assessment is required"
        elif current and current["status"] == "configuration_supported_candidate":
            state, reason = "still_supported", "The same prerequisite chain is supported in the later snapshot"
        elif current and current["status"] == "blocked_in_snapshot":
            for check in current["prerequisites"]:
                if check["status"] == "contradicted":
                    later = [ident for ident in check["evidence_ids"] if evidence[ident]["eligibility"] == "eligible" and timestamp(evidence[ident]["observed_at"]) > timestamp(old["assessed_at"])]
                    if later and check["predicate"] in {"public_visibility", "unauthenticated_invocation", "active", "user_input_drives_connector"}:
                        closing += later
                    elif later:
                        reclassified += later
            if closing:
                state, reason = "closed_in_fixture", "Later allowed-source evidence contradicts a causal entry/transition condition of this exact path"
            elif reclassified:
                state, reason = "scenario_reclassified", "A lifecycle, sensitivity or privilege label changed; this does not prove the access path was blocked"
        results.append({"finding_id": previous["id"], "state": state, "reason": reason,
                        "closing_evidence_ids": sorted(set(closing)), "reclassification_evidence_ids": sorted(set(reclassified)), "before_revision": old["revision"],
                        "after_revision": new["revision"], "runtime_verification": "not_performed"})
    return {"mode": "fixture_only", "results": results,
            "limitation": "Closure applies only to this path and supplied snapshots; no universal or live security guarantee"}


def comparison(report, oracle):
    # The oracle is a separate explicit input only to evaluation. assess never reads it.
    labels = oracle["labels"]
    universe = set(labels)
    expected = {k for k, v in labels.items() if v is True}
    predicted = {f["path"][0] for f in report["findings"] if f["status"] == "configuration_supported_candidate"} & universe
    exposed = {e["subject"] for e in report["evidence"] if e["eligibility"] == "eligible" and e["predicate"] == "public_visibility" and e["value"]}
    baseline = {e["subject"] for e in report["evidence"] if e["eligibility"] == "eligible" and e["predicate"] == "known_vulnerability" and e["value"]} & exposed & universe
    def metrics(values):
        tp, fp, fn = len(values & expected), len(values - expected), len(expected - values)
        return {"predicted_entry_assets": sorted(values), "tp": tp, "fp": fp, "fn": fn,
                "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None}
    return {"task": "Identify entry assets with a supported synthetic orphan-AI-to-sensitive-asset path", "unit": "entry_asset", "oracle": oracle["description"], "baseline_definition": "Inventory + known-vulnerability list; flag an entry only when both public visibility and a known vulnerability are present", "baseline": metrics(baseline), "prerequisite_engine": metrics(predicted), "warning": "Small hand-authored fixture for reproducibility, not a representative EASM benchmark or product superiority claim"}


def render(report):
    lines = ["Aid-On Exposure Agent 0.1.0 | offline fixture report", "",
             f"Snapshot {report['snapshot']['id']} revision {report['snapshot']['revision']}",
             f"Assessed at {report['snapshot']['assessed_at']}",
             "Candidates describe configuration support. Exploitability and live reachability were NOT tested.", ""]
    for f in report["findings"]:
        lines += [f"{f['id']} | {f['status']} | priority={f['priority']}", "  " + " -> ".join(f["path"])]
        for p in f["prerequisites"]:
            refs = ",".join(p["evidence_ids"]) or "none"
            lines.append(f"  {p['status']:13} {p['subject']}:{p['predicate']} evidence={refs}")
        lines.append("  Remediation: proposal only; human approval and a new snapshot required")
        lines.append("")
    for issue in report["admission_issues"]:
        lines.append(f"EXCLUDED {issue['subject']}: {issue['reason']}")
    lines += ["", "Trust: unsigned hashes are integrity checks, not proof of source authenticity.", "No network, credentials, exploit or mutation tools exist in this prototype."]
    return "\n".join(lines) + "\n"
