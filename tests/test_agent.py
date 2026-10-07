from __future__ import annotations
import copy
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from aidon_exposure.agent import ROOT, assess, comparison, recheck
from aidon_exposure.boundary import InputError, Scope, digest, hostname, load, normalize

AT = "2026-10-07T09:30:00Z"
LATER = "2026-10-07T10:30:00Z"

class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.manifest = load(ROOT / "fixtures/manifest.json")
        self.snapshot = load(ROOT / "fixtures/before.json")
        self.after = load(ROOT / "fixtures/after.json")

    def run_agent(self, snapshot=None, at=AT):
        return assess(self.manifest, snapshot or self.snapshot, at)

    def finding(self, report, app="app:poc"):
        return next(f for f in report["findings"] if f["path"][0] == app)

    def change_evidence(self, subject, predicate, **changes):
        record = next(e for e in self.snapshot["evidence"] if e["subject"] == subject and e["predicate"] == predicate)
        record.update(changes)
        record["sha256"] = digest(record)
        return record

    def test_end_to_end_candidate(self):
        report = self.run_agent()
        supported = [f for f in report["findings"] if f["status"] == "configuration_supported_candidate"]
        self.assertEqual([f["path"][0] for f in supported], ["app:poc"])
        self.assertTrue(all(p["status"] == "supported" for p in supported[0]["prerequisites"]))
        self.assertEqual(supported[0]["runtime_reachability"], "not_tested")

    def test_public_only_does_not_establish_internal_permissions(self):
        found = self.finding(self.run_agent(), "app:public-only")
        self.assertEqual(found["status"], "not_established")
        self.assertEqual(next(p for p in found["prerequisites"] if p["predicate"] == "excessive_privilege")["status"], "unknown")

    def test_scope_lookalike_and_unknown_owner_excluded(self):
        report = self.run_agent()
        excluded = {i["subject"] for i in report["admission_issues"]}
        self.assertTrue({"app:vendor", "app:unknown-owner"} <= excluded)
        self.assertFalse(any(f["path"][0] in excluded for f in report["findings"]))

    def test_stale_evidence_is_unknown_not_false(self):
        f = self.finding(self.run_agent(), "app:stale")
        self.assertEqual(f["status"], "not_established")
        self.assertTrue(any(p["status"] == "unknown" for p in f["prerequisites"]))

    def test_inactive_edge_blocks(self):
        self.assertEqual(self.finding(self.run_agent(), "app:inactive")["status"], "blocked_in_snapshot")

    def test_duplicates_are_not_votes(self):
        report = self.run_agent()
        self.assertEqual(sum(e["eligibility"] == "duplicate" for e in report["evidence"]), 1)
        p = next(p for p in self.finding(report)["prerequisites"] if p["predicate"] == "public_visibility")
        self.assertEqual(len(p["evidence_ids"]), 1)

    def test_integrity_tamper_rejected_as_support(self):
        e = next(e for e in self.snapshot["evidence"] if e["subject"] == "app:poc" and e["predicate"] == "unauthenticated_invocation")
        e["value"] = False  # Deliberately do not update digest.
        report = self.run_agent()
        self.assertEqual(self.finding(report)["status"], "not_established")
        self.assertEqual(next(x for x in report["evidence"] if x["id"] == e["id"])["eligibility"], "integrity_failed")

    def test_independent_current_conflict_retained(self):
        e = copy.deepcopy(self.change_evidence("app:poc", "unauthenticated_invocation"))
        e.update(id="ev:independent-deny", source_id="config-b", value=False)
        e["sha256"] = digest(e); self.snapshot["evidence"].append(e)
        f = self.finding(self.run_agent())
        self.assertEqual(f["status"], "not_established")
        self.assertEqual(next(p for p in f["prerequisites"] if p["predicate"] == "unauthenticated_invocation")["status"], "conflicted")

    def test_public_visibility_conflict_with_private_config(self):
        e = copy.deepcopy(self.snapshot["evidence"][0])
        e.update(id="ev:private-only", source_type="customer_config", source_id="config-a", value=False)
        e["sha256"] = digest(e); self.snapshot["evidence"].append(e)
        self.assertEqual(self.finding(self.run_agent())["status"], "not_established")

    def test_invalid_duplicate_cannot_hide_valid_negative(self):
        negative = copy.deepcopy(next(e for e in self.snapshot["evidence"] if e["subject"] == "app:poc" and e["predicate"] == "unauthenticated_invocation"))
        negative.update(id="ev:invalid-negative", source_id="config-b", value=False, sha256="invalid")
        valid = copy.deepcopy(negative); valid["id"] = "ev:valid-negative"; valid["sha256"] = digest(valid)
        self.snapshot["evidence"] += [negative, valid]
        report = self.run_agent()
        self.assertEqual(self.finding(report)["status"], "not_established")
        self.assertEqual(next(e for e in report["evidence"] if e["id"] == valid["id"])["eligibility"], "eligible")
        self.assertEqual(next(p for p in self.finding(report)["prerequisites"] if p["predicate"] == "unauthenticated_invocation")["status"], "conflicted")

    def test_same_stream_new_revision_supersedes_without_erasure(self):
        report = self.run_agent(self.after, LATER)
        old = next(e for e in report["evidence"] if e["id"] == "ev:app:poc:unauthenticated_invocation")
        self.assertEqual(old["eligibility"], "superseded")
        self.assertEqual(self.finding(report)["status"], "blocked_in_snapshot")

    def test_expired_new_revision_does_not_revive_old_support(self):
        e = copy.deepcopy(self.change_evidence("app:poc", "unauthenticated_invocation"))
        e.update(id="ev:expired-new", revision=2, observed_at="2026-10-07T09:01:00Z", expires_at="2026-10-07T09:02:00Z", value=False)
        e["sha256"] = digest(e); self.snapshot["evidence"].append(e)
        self.assertEqual(self.finding(self.run_agent())["status"], "not_established")

    def test_missing_transition_cannot_be_invented(self):
        self.snapshot["edges"] = [e for e in self.snapshot["edges"] if e["id"] != "call:poc"]
        self.snapshot["evidence"] = [e for e in self.snapshot["evidence"] if e["subject"] != "call:poc"]
        self.assertFalse(any(f["path"][0] == "app:poc" for f in self.run_agent()["findings"]))

    def test_incompatible_principals_rejected(self):
        next(e for e in self.snapshot["edges"] if e["id"] == "read:poc")["principal_id"] = "principal:unrelated"
        f = self.finding(self.run_agent())
        self.assertNotEqual(f["status"], "configuration_supported_candidate")
        self.assertEqual(next(p for p in f["prerequisites"] if p["predicate"] == "principal_binding")["status"], "contradicted")

    def test_incompatible_deployments_rejected(self):
        next(e for e in self.snapshot["edges"] if e["id"] == "read:poc")["deployment_id"] = "production-unrelated"
        self.assertNotEqual(self.finding(self.run_agent())["status"], "configuration_supported_candidate")

    def test_unknown_principal_is_not_false(self):
        next(e for e in self.snapshot["edges"] if e["id"] == "read:poc")["principal_id"] = ""
        self.assertEqual(self.finding(self.run_agent())["status"], "not_established")

    def test_inferred_edge_does_not_count_as_confirmed(self):
        next(e for e in self.snapshot["edges"] if e["id"] == "read:poc")["state"] = "inferred"
        self.assertEqual(self.finding(self.run_agent())["status"], "not_established")

    def test_cname_and_shared_ip_do_not_expand_scope(self):
        node = next(n for n in self.snapshot["nodes"] if n["id"] == "app:poc")
        node["cname_chain"] = ["shared.cdn.invalid"]
        self.assertFalse(any(f["path"][0] == "app:poc" for f in self.run_agent()["findings"]))
        node["cname_chain"] = []; node["resolved_ips"] = ["8.8.8.8"]
        self.assertFalse(any(f["path"][0] == "app:poc" for f in self.run_agent()["findings"]))

    def test_ownership_spoof_does_not_override_manifest(self):
        node = next(n for n in self.snapshot["nodes"] if n["id"] == "app:unknown-owner")
        node["owner"]["status"] = "verified"
        self.assertFalse(any(f["path"][0] == node["id"] for f in self.run_agent()["findings"]))

    def test_scope_exact_subdomain_and_exclusion_rules(self):
        scope = Scope(self.manifest)
        self.assertTrue(scope.host_allowed("POC.AIDON.EXAMPLE."))
        self.assertFalse(scope.host_allowed("aidon.example.evil.invalid"))
        self.assertFalse(scope.host_allowed("evil-aidon.example"))
        self.assertFalse(scope.host_allowed("nested.excluded.aidon.example"))
        self.manifest["hosts"][0]["include_subdomains"] = False
        self.assertFalse(Scope(self.manifest).host_allowed("poc.aidon.example"))

    def test_private_and_cidr_ip_grants_rejected(self):
        for ip in ["127.0.0.1", "169.254.169.254", "10.0.0.1", "::1", "8.8.8.0/24"]:
            self.manifest["ips"] = [ip]
            with self.assertRaises(InputError): Scope(self.manifest)

    def test_url_and_ambiguous_host_rejected(self):
        for host in ["https://aidon.example", "aidon.example:443", "*.aidon.example", "a..example", "user@aidon.example", "127.0.0.1"]:
            with self.assertRaises(InputError): hostname(host)

    def test_recheck_requires_later_revision_and_closes_exact_path(self):
        before, after = self.run_agent(), self.run_agent(self.after, LATER)
        results = recheck(before, after)["results"]
        self.assertEqual(results[0]["state"], "closed_in_fixture")
        self.assertEqual(results[0]["closing_evidence_ids"], ["ev:poc:auth-enabled-v2"])
        self.assertEqual(self.finding(before)["id"], self.finding(after)["id"])

    def test_lifecycle_change_reclassifies_but_does_not_close_access(self):
        before = self.run_agent()
        e = self.after["evidence"][-1]; e.update(id="ev:lifecycle-v2", predicate="orphaned"); e["sha256"] = digest(e)
        result = recheck(before, self.run_agent(self.after, LATER))["results"][0]
        self.assertEqual(result["state"], "scenario_reclassified")
        self.assertEqual(result["closing_evidence_ids"], [])
        self.assertEqual(result["reclassification_evidence_ids"], ["ev:lifecycle-v2"])

    def test_sensitivity_change_reclassifies_but_does_not_close_access(self):
        before = self.run_agent()
        e = self.after["evidence"][-1]; e.update(id="ev:sensitivity-v2", subject="data:customer-records", predicate="sensitive"); e["sha256"] = digest(e)
        result = recheck(before, self.run_agent(self.after, LATER))["results"][0]
        self.assertEqual(result["state"], "scenario_reclassified")
        self.assertEqual(result["closing_evidence_ids"], [])

    def test_replacement_deployment_does_not_close_original(self):
        before = self.run_agent()
        for group in ("nodes", "edges", "evidence"):
            for record in self.after[group]:
                record["deployment_id"] = "deployment-replacement"
                if group == "evidence": record["sha256"] = digest(record)
        result = recheck(before, self.run_agent(self.after, LATER))["results"][0]
        self.assertEqual(result["state"], "inconclusive")
        self.assertIn("context changed", result["reason"])

    def test_source_revision_rollback_across_snapshots(self):
        self.change_evidence("app:poc", "unauthenticated_invocation", revision=100)
        before = self.run_agent()
        self.after["evidence"] = [e for e in self.after["evidence"] if e["id"] != "ev:app:poc:unauthenticated_invocation"]
        e = self.after["evidence"][-1]; e["revision"] = 1; e["sha256"] = digest(e)
        result = recheck(before, self.run_agent(self.after, LATER))["results"][0]
        self.assertEqual(result["state"], "inconclusive")
        self.assertIn("revision rolled back", result["reason"])

    def test_same_source_revision_cannot_change_value_across_snapshots(self):
        before = self.run_agent()
        self.after["evidence"] = [e for e in self.after["evidence"] if e["id"] != "ev:app:poc:unauthenticated_invocation"]
        e = self.after["evidence"][-1]; e["revision"] = 1; e["sha256"] = digest(e)
        result = recheck(before, self.run_agent(self.after, LATER))["results"][0]
        self.assertEqual(result["state"], "inconclusive")
        self.assertIn("revision was reused", result["reason"])

    def test_replaced_supporting_source_is_not_silent_closure(self):
        before = self.run_agent()
        self.after["evidence"] = [e for e in self.after["evidence"] if e["id"] != "ev:app:poc:unauthenticated_invocation"]
        e = self.after["evidence"][-1]; e["source_id"] = "config-b"; e["sha256"] = digest(e)
        result = recheck(before, self.run_agent(self.after, LATER))["results"][0]
        self.assertEqual(result["state"], "inconclusive")
        self.assertIn("source stream is missing", result["reason"])

    def test_engine_timeout_is_inconclusive_failure_not_safe_report(self):
        with patch("aidon_exposure.agent.subprocess.run", side_effect=subprocess.TimeoutExpired("aidon-engine", 10)):
            with self.assertRaisesRegex(InputError, "inconclusive"):
                self.run_agent()

    def test_unchanged_later_snapshot_remains_supported(self):
        before = self.run_agent()
        self.after["evidence"] = [e for e in self.after["evidence"] if e["id"] != "ev:poc:auth-enabled-v2"]
        self.assertEqual(recheck(before, self.run_agent(self.after, LATER))["results"][0]["state"], "still_supported")

    def test_same_snapshot_and_proposal_do_not_close(self):
        before = self.run_agent()
        before["findings"][0]["remediation"]["status"] = "approved"
        self.assertEqual(recheck(before, before)["results"][0]["state"], "inconclusive")

    def test_disappearance_is_not_remediation(self):
        before = self.run_agent()
        self.after["edges"] = [e for e in self.after["edges"] if e["id"] != "call:poc"]
        self.after["evidence"] = [e for e in self.after["evidence"] if e["subject"] != "call:poc"]
        self.assertEqual(recheck(before, self.run_agent(self.after, LATER))["results"][0]["state"], "inconclusive")

    def test_old_negative_and_new_snapshot_does_not_close(self):
        before = self.run_agent()
        self.after["evidence"][-1].update(observed_at="2026-10-07T09:10:00Z")
        self.after["evidence"][-1]["sha256"] = digest(self.after["evidence"][-1])
        self.assertEqual(recheck(before, self.run_agent(self.after, LATER))["results"][0]["state"], "inconclusive")

    def test_missing_data_is_not_closed(self):
        before = self.run_agent()
        self.after["evidence"] = [e for e in self.after["evidence"] if not (e["subject"] == "app:poc" and e["predicate"] == "unauthenticated_invocation")]
        self.assertEqual(recheck(before, self.run_agent(self.after, LATER))["results"][0]["state"], "inconclusive")

    def test_injection_text_is_inert_and_no_external_tools(self):
        report = self.run_agent()
        self.assertEqual(self.finding(report)["status"], "configuration_supported_candidate")
        self.assertTrue(any("untrusted_text" in e for e in report["evidence"]))
        self.assertNotIn("network", {step["tool"] for step in report["loop"]})
        self.assertEqual(next(s for s in report["loop"] if s["step"] == "remediate")["tool"], "none")

    def test_fixture_metrics_are_explicit_and_reproducible(self):
        result = comparison(self.run_agent(), load(ROOT / "fixtures/ground_truth.json"))
        self.assertEqual((result["baseline"]["tp"], result["baseline"]["fp"], result["baseline"]["fn"]), (0, 1, 1))
        self.assertEqual((result["prerequisite_engine"]["tp"], result["prerequisite_engine"]["fp"], result["prerequisite_engine"]["fn"]), (1, 0, 0))
        self.assertIn("not a representative", result["warning"])

    def test_evidence_from_another_deployment_cannot_transfer(self):
        self.change_evidence("app:poc", "unauthenticated_invocation", deployment_id="different-deployment")
        self.assertEqual(self.finding(self.run_agent())["status"], "not_established")

    def test_evidence_from_another_principal_cannot_transfer(self):
        self.change_evidence("read:poc", "excessive_privilege", principal_id="different-principal")
        self.assertEqual(self.finding(self.run_agent())["status"], "not_established")

    def test_unknown_source_rejected(self):
        self.change_evidence("app:poc", "unauthenticated_invocation", source_id="not-registered")
        self.assertEqual(self.finding(self.run_agent())["status"], "not_established")

    def test_future_and_invalid_time_rejected(self):
        self.snapshot["captured_at"] = "2099-01-01T00:00:00Z"
        with self.assertRaises(InputError): self.run_agent()
        self.snapshot["captured_at"] = "2026-10-07T09:05:00"
        with self.assertRaises(InputError): self.run_agent()

    def test_duplicate_ids_and_dangling_edges_fail_closed(self):
        self.snapshot["nodes"].append(copy.deepcopy(self.snapshot["nodes"][0]))
        with self.assertRaises(InputError): self.run_agent()
        self.snapshot["nodes"].pop(); self.snapshot["edges"][0]["to"] = "missing"
        with self.assertRaises(InputError): self.run_agent()

    def test_evidence_revision_time_rollback_rejected(self):
        e = copy.deepcopy(self.change_evidence("app:poc", "unauthenticated_invocation"))
        e.update(id="ev:rollback", revision=2, observed_at="2026-10-07T08:00:00Z")
        e["sha256"] = digest(e); self.snapshot["evidence"].append(e)
        with self.assertRaises(InputError): self.run_agent()

    def test_expired_scope_fails_closed(self):
        self.manifest["valid_until"] = "2026-10-07T09:30:00Z"
        with self.assertRaisesRegex(InputError, "not valid"):
            self.run_agent()

    def test_revoked_scope_fails_closed(self):
        self.manifest["revoked"] = True
        with self.assertRaises(InputError):
            self.run_agent()

    def test_no_extra_operation_can_be_authorized(self):
        self.manifest["allowed_operations"].append("http_request")
        with self.assertRaises(InputError): self.run_agent()

    def test_budget_is_bounded(self):
        self.snapshot["evidence"] = [{"id": f"many:{i}"} for i in range(1001)]
        with self.assertRaises(InputError): self.run_agent()

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"; path.write_text('{"x": 1, "x": 2}')
            with self.assertRaises(InputError): load(path)

    def test_cli_unknown_command_fails(self):
        run = subprocess.run(["python3", "-m", "aidon_exposure", "scan", "https://example.com"], cwd=ROOT, capture_output=True)
        self.assertEqual(run.returncode, 2)

if __name__ == "__main__":
    unittest.main()
