# Threat model and acceptance scope

## Assets and adversaries

Protect the operator's allowed target boundary, local machine, confidentiality of any future customer evidence, assessment integrity and honest closure reporting. Current fixtures contain only invented assets and data. Assume observations may contain misleading attribution, malicious instructions, stale or contradictory facts, duplicated records, incompatible identities and malformed input.

The operator and local manifest/engine are trusted in this MVP. A malicious local operator, malicious replacement binary, compromised Python/Almide toolchain or attacker able to rewrite all approved fixture files is outside its protection. There is no OS sandbox, source authentication, signature trust, secret vault, live source connector or persistent evidence database.

## Controls and residual risks

| Threat | Current control | Residual limitation |
|---|---|---|
| CNAME, shared-IP, subdomain or lookalike scope expansion | Explicit asset grants, separate ownership records, exact-boundary name policy, all supplied aliases/IPs checked | No actual DNS/rebinding/redirect collector exists; future adapters must enforce at request time |
| Ownership implied by a brand or observation | Manifest ownership must be verified and match inventory | “Verified” is an operator assertion, not an automated validation |
| Public page invents internal permissions | Per-predicate source gate; internal facts require customer_config | Config source authority is configured, not cryptographically authenticated |
| Stale/replayed or future evidence | Expiry/max-age, time consistency, intra-snapshot and across-pair revision reconciliation | No persistent anti-rollback state or proof latest data was supplied |
| Accidental corruption or forged content | Canonical SHA-256 integrity check | Unsigned hashes do not stop intentional forgery |
| Unrelated true facts compose a false path | Explicit transitions; identity, tenant and deployment bindings; each prerequisite evaluated | One rule only; supplied bindings are assertions |
| Instruction injection in observations | Data never selects code/tools; no LLM/action executor | JSON consumers must continue treating text as untrusted data |
| Duplicate records inflate confidence | Only eligible records can become dedupe representatives; no majority voting | Source independence is not independently verified |
| Conflicting facts collapse to certainty | Current cross-source disagreement retained as conflicted | No automated truth arbitration |
| Proposed fix/missing observation treated as closure | Same deployment/principal, source continuity and new snapshot/revision/time plus later causal contradiction required | Closure is in fixture only, not tested in production |
| High impact hidden by a score | Explicit business impact and uncertainty; no invented CVSS/probability | Business impact is supplied by operator |
| Resource exhaustion | File/entity/path/time/output budgets | JSON nesting, OS memory/CPU and trusted binary are not sandbox-hardened |
| Sensitive evidence disclosure | Local output only; synthetic fixtures; no external tools | Real data is not encrypted at rest; do not use production secrets |

## Acceptance coverage

The unittest suite exercises supported path, public-only internal claims, stale/inactive cases, unknown ownership, spoofed ownership, CNAME/shared IP and lookalike scope escape, exact/subdomain/exclusion policy, special/private/CIDR IPs, host ambiguity, hashes, duplicates, source conflicts, revision supersession, expired newest record, missing links, incompatible principals/deployments, evidence context binding, inferred edges, missing identity, successful fixture closure, repeated snapshot, proposal-only state, disappearing edge, missing evidence, old negative facts, inert injected text, unknown source, future/naive clocks, malformed IDs/references, revision rollback, unauthorized tool modes, budgets and CLI rejection of scanning.

Run tests from a fresh build. Passing these cases establishes only this implementation's behavior on tested cases, not a production security certification. The comparison fixture is illustrative and intentionally tiny.
