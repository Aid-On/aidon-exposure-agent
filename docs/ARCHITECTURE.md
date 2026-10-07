# Architecture and input contract

## Executed flow

`local fixture → Python admission/normalization → Almide prerequisite engine → local JSON/text report → separately supplied later fixture → exact-path recheck`

The loop is a deterministic agent workflow, not an LLM service. The only collector is local fixture reading. No shell command, URL, tool name or natural-language directive in observations is interpreted as an action. Python invokes exactly the explicitly selected local engine binary with one temporary file argument, without a shell and with a 10-second timeout. The engine never invokes other tools.

## Trust boundaries

1. The local operator-approved manifest is the trust root. It registers exact asset IDs, ownership records and approved source types. Source authorization is separate from evidence integrity and from source assertions.
2. Snapshot inventory claims must agree with the ownership registry. Brand/name association and inferred attribution cannot authorize an asset.
3. A DNS name grant is exact unless include_subdomains is explicitly true. Exclusions apply first, including their descendants. Every supplied CNAME hop needs its own applicable name grant. Supplied resolved addresses need exact public-IP grants. Reserved/private/special addresses and CIDR grants are rejected. No actual DNS or redirects are followed.
4. Absence of DNS/IP facts means those controls were not exercised; it does not prove the real host’s DNS destination is allowed. This collector cannot make a request, so it cannot cross that boundary. A future network adapter must independently resolve and validate every request/hop at use time.
5. SHA-256 covers canonical JSON of each evidence record except its sha256 field. It catches corruption; a writer able to replace evidence and hash can forge it. No source signature or signed manifest is implemented.
6. Engine input is an internal normalized protocol. Calling the binary directly bypasses the Python validation boundary. Its output alone is not an authorization decision. No live executor should consume it as permission.

## Manifest

- schema_version=1, mode=fixture_only
- organization_id, tenant_id, approval_ref; valid_from/valid_until and revoked=false (enforced at the assessment clock)
- asset_ids: explicit fixture_read authorization, separate from ownership_records
- ownership_records: asset ID → status, organization_id, verification_ref; an operator assertion, not independent verification
- hosts: name and include_subdomains; excluded_hosts; ips: exact publicly routable addresses only
- sources: ID, type=public_observation/customer_config, tenant_id, max_age_seconds
- allowed_operations must equal [fixture_read]

## Snapshot

- schema_version, id, tenant_id, positive revision, captured_at with timezone
- nodes: unique ID, ai_app/connector/business_asset kind, confirmed/inferred/unknown state, tenant_id, deployment_id, owner record; public entry hostname; optional CNAME/IP facts; business impact on business assets
- edges: unique ID, invokes/can_read kind, from/to existing node IDs, state, principal_id, deployment_id
- evidence: ID, subject node/edge, predicate, boolean value, registered source_id and matching source_type, fixture:// provenance, tenant_id/deployment_id/principal_id bindings, observed_at, expires_at, positive source-stream revision, sha256
- optional text is data only. It is retained in JSON for audit and never used as instructions

The fixtures are examples of the contract; no formal JSON Schema or signed source adapter is included in v0.1.

## Evidence reconciliation

A record is usable only if its digest, source, asset/edge authorization, context binding, timestamp and freshness are valid. public_observation can support only public_visibility in the path rule. Internal facts require customer_config. Both accepted and rejected evidence survive in the report with an eligibility status.

Repeated semantically identical observations are marked duplicate, not treated as independent votes. New revisions supersede only the same source+subject+predicate stream. A newer expired revision cannot revive an old positive claim. Other currently eligible sources may disagree: the predicate becomes conflicted. Old and conflicting records remain visible. Missing, stale, inferred or unsuitable-source information is unknown, never silently false. There is no weighted-confidence vote.

The current run checks revision/time consistency in the supplied snapshot, and recheck also compares continuity across the two supplied snapshots. It has no persistent anti-rollback ledger and cannot prove that the caller supplied the latest real-world snapshot.

## One explicit rule

The structural template is an AI application invoking a connector that can read a business asset. Both transitions need the same principal and compatible deployment; node tenants must match. An unrelated login page and privileged identity cannot be joined by adjacency.

Required conditions:

1. Compatible tenant/deployment context
2. Same nonempty connector principal on both transitions
3. Confirmed call edge
4. Confirmed read edge
5. Public entry visibility
6. Unauthenticated invocation
7. Orphaned lifecycle
8. Active call edge
9. Untrusted user input can drive this connector operation
10. Active read edge
11. Excessive privilege for this read relation
12. Sensitive destination

Every condition reports supported, contradicted, unknown or conflicted, its evidence references and reason. All must be supported to emit configuration_supported_candidate. A fully known contradicted chain becomes blocked_in_snapshot. Any unknown/conflicted condition keeps the overall chain not_established, even if another condition is contradicted. Admission-excluded assets do not enter a path.

These are configuration assertions. They do not prove prompt injection, a usable token, authorization bypass, data exfiltration, the absence of other runtime controls or an actual exploit.

## Identity, priority and remediation

Finding identity is a SHA-256-derived stable key over rule ID, tenant, ordered nodes and edges, and their tenant/deployment/principal context. Evidence revision/time is not in the identity. A replacement deployment or principal is a different finding and cannot close the original. Business-impact labels come from the supplied inventory. Priority is an auditable ordinal policy: supported+high-impact → review_now; uncertain → investigate; otherwise review_snapshot. It is neither CVSS nor a probability estimate.

Every finding includes human-review remediation options. There is no apply endpoint, mutation tool, automatic policy change or claim that a proposed change happened. A real deployment should separate proposal approval, authorized execution and independent verification.

## Recheck contract

Recheck assesses two raw snapshots through the same boundary and engine. For an originally supported finding:

- Requires a different snapshot hash, higher revision and captured_at after the original assessment
- Same supported chain → still_supported
- Same fully known chain blocked by fresh later contradictory entry/transition evidence (public_visibility, unauthenticated_invocation, active, user_input_drives_connector) → closed_in_fixture, citing that evidence
- Only lifecycle, sensitivity or excessive-privilege label changes → scenario_reclassified; this does not establish that access was blocked
- Previously supporting source streams must remain usable; across-pair revision/time rollback or conflicting values under a reused revision → inconclusive
- Missing path, missing evidence, unknown/conflicted facts, structural mismatch without new condition evidence, reused revision, old denial or invalid clocks → inconclusive

Changing a proposal, deleting an asset from input, changing a graph label, or an engine timeout cannot prove remediation. The demo later snapshot is separately stored synthetic evidence, not a performed remediation or independently measured live result. Closure is scoped to the same rule/path and snapshots.

## Budgets

2 MiB per JSON input; at most 100 nodes, 200 edges, 1,000 evidence records, 25 sources and 256 structural candidate paths; 10 seconds per engine invocation; at most 10 MiB accepted stdout. No retry loop, recursive graph walk, network discovery or unbounded autonomous execution exists. Exceeding a budget fails the assessment, never yields an empty “safe” report. This is resource bounding, not a hardened OS sandbox.

## Proposed next architecture, not implemented

- Read-only, explicitly authorized adapters for public observations and customer-owned configuration
- Immutable authenticated evidence store and source-specific collectors, versioned schema and anti-rollback ledger
- A proposed-check planner, optionally LLM assisted; deterministic scope/action authorization remains outside the model
- Additional explicit path rules with independent adversarial fixtures and evaluation sets
- Permission-limited verification in customer-approved test environments, with target/method/time/stop conditions
- Human-approved remediation executor and separate verification worker
- Potential static-code evidence from teastia and runtime permission/control evidence from Porta, once real interfaces and guarantees are verified

The next acceptance milestone should be one authorized, read-only customer test environment with independently curated true/false paths. Real-world precision/recall, analyst review time and verified closure should be measured before any “beyond EASM” effectiveness claim.
