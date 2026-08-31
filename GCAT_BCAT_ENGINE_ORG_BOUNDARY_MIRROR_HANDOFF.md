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
