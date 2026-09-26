# GCAT_BCAT_ENGINE_ORG_BOUNDARY_MIRROR_HANDOFF.md

Status: ACTIVE
Updated: 2026-08-31

## Goal
Establish GCAT-BCAT-Engine/.github as the canonical organizational ingress/egress definition for GCAT-BCAT-Engine.

## Current task authority
1. This handoff is the source of truth for org-boundary/* in this repository.
2. Cross-organization traffic is represented as governed InTr envelopes at this boundary.
3. Individual repositories expose application/runtime profiles and must not independently redefine organization-level transport semantics.
4. HB or HB-derived carriers provide synchronization/carrier capability only; they grant no admission, execution, credential, routing, transition, receiving, publication, or release authority.
5. GitHub Actions may validate source/evidence, but GitHub runtime is not execution authority.

## Canonical layering
HB or HB-derived carrier -> InTr org boundary -> ingestion/normalization -> core-lite registry/routing -> repository/runtime profile.
Return path: endpoint result -> evidence binding -> org egress -> InTr -> carrier.

## Organization repositories currently registered for boundary profiling
- GCAT-BCAT-Engine/Documentation
- GCAT-BCAT-Engine/core-master
- GCAT-BCAT-Engine/Triage
- GCAT-BCAT-Engine/core-addons
- GCAT-BCAT-Engine/workflows
- GCAT-BCAT-Engine/Publisher
- GCAT-BCAT-Engine/core-full
- GCAT-BCAT-Engine/Gemstone_IV
- GCAT-BCAT-Engine/core-lite-prod
- GCAT-BCAT-Engine/WZ
- GCAT-BCAT-Engine/core-lite
- GCAT-BCAT-Engine/Marketplace
- GCAT-BCAT-Engine/StegSim
- GCAT-BCAT-Engine/telemetry

## Immediate implementation
- org-boundary/README.md
- org-boundary/schemas/intr-envelope.schema.json
- org-boundary/evidence/receipt-chain.schema.json
- org-boundary/registry/services.json
- stegverse.architecture.json

## Evidence semantics
Source presence, CI success, merge, deployment, activation, ingress receipt, dispatch, consumption, observation, egress, and same-execution reconstruction are distinct states.

## Next
Replace generic INTERNAL_ENDPOINT entries with tighter endpoint-specific profiles as each repository's own handoff and runtime contract are reconciled.


## Canonical resident-runtime activation rule — 2026-08-31
- Every GCAT-BCAT-Engine resident runtime activation surface MUST be kept in `GCAT-BCAT-Engine/.github`.
- No application repository is the organization resident-runtime activation authority.
- Application repositories expose capabilities/endpoints to the organizational boundary; the organization `.github` owns activation, ingress, egress, and organization-crossing transport behavior.
- All communication crossing the GCAT-BCAT-Engine organizational boundary MUST be generated through this `.github` boundary using Interlock/InTr semantics.
- Ingress responsibilities: carrier observation, InTr envelope validation, provenance binding, transition-context binding, destination/profile resolution, dispatch evidence.
- Egress responsibilities: result/evidence validation, destination-org resolution, InTr envelope generation, egress evidence, reconstruction linkage.
- HB/HB-derived carrier presence remains non-authorizing. Authority is determined by applicable transition elements.
- GitHub Actions may validate or transport evidence, but GitHub-hosted workflow execution is not required as sovereign runtime authority.
- Canonical implementation paths: `org-boundary/runtime/`, `org-boundary/registry/`, `org-boundary/schemas/`, `org-boundary/evidence/`, `resident-runtime/`.
- Any legacy resident activation implementation outside `GCAT-BCAT-Engine/.github` becomes an endpoint/provider to this boundary or must be migrated here; it must not remain a competing organizational activation point.

## 2026-09-25 — separate open-source root-license census (source-only)

Existing central goal `ECOSYSTEM-OPEN-SOURCE-STRATEGY-001` / COSV `20010010100000`. New source-owned internal `docs/OPEN_SOURCE_ORGANIZATION_INVENTORY_20260925.json` records 15 visible repositories (7 public, 7 private, 1 internal). All 15 default-branch root LICENSE paths were checked: five found (one MIT text, one Apache 2.0 text, three custom/restrictive texts), ten not found. These are root-path observations only; file-level permissions, prior grants, imported code, holder authority and release approval remain unverified. Distinguish GCAT's own `core-lite` MIT text from the independently audited, currently unlicensed-at-root SDK-pinned `Data-Continuation/core-lite`. Never publish nonpublic repository details in central public summaries. This additional evidence does not alter the organization boundary, grant open-source rights or establish runtime/Publisher release authority. Retain all existing obligations above.
