# Organization Transition Ledger Mirror Handoff

Organization: `GCAT-BCAT-Engine`

Repository-level transitions remain owned and replayable in their originating repositories. This `.github` layer verifies a source transition receipt, records only the organization-level state consequence, and links the exact source receipt hash.

Every state transition occurring within the organization emits an organization receipt (`organization_scope_rule`), so admission follows the contract's `consumes` list rather than a single hard-coded schema:

- `stegverse.repo-transition-receipt/v1` — a repository transition, verified against its own self-hash and required to name a repository inside this organization. Recorded with `source_repository`, `repo_receipt_sha256` and `repo_transition_id`.
- `stegverse.canonical-state-transition-receipt/v1` — a canonical state transition manifested through Interlock/InTr. Bound by its own canonical digest as `canonical_state_transition_receipt_sha256`, keeping its own schema and transition id. It must carry exact inline canonical evidence bytes, each entry bound to its own `transition_id`, so organization replay terminates on this chain alone.

Both land on one chain. The source receipt's own schema, transition id and digest are preserved in the organization receipt rather than replaced (`preserves_source_transition_receipt`). Admission is decided before the append lock is taken, so an inadmissible source receipt never contends for the ledger.

Contract: `.stegverse/transition-ledger/org-contract.json`  
Rollup: `resident-runtime/aggregate_repo_transition.py`  
Readback: `resident-runtime/organization_ledger_readback.py`

The designated ref is `refs/stegverse/organization-ledger` in `GCAT-BCAT-Engine/.github`. The materializer supplies it as `STEGVERSE_ORG_LEDGER_ROOT=git+<checkout>#refs/stegverse/organization-ledger`. There is no host-derived default.

Organization replay must terminate using verified source receipts plus this org chain; it must not depend on Master Records ecosystem replay.

Only the organization receipt and evidence required for ecosystem reconstruction propagate to `master-records/.github`. A recorded disposition is transition evidence only. Authority and time remain constraint variables.

The organization ledger ref is this organization's runtime-reality locus (`data/organization-role-runtime-reality-deployment.json`, `ORGANIZATION-ROLE-RUNTIME-REALITY-DEPLOYMENT-001`).
