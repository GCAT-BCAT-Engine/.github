# Transition Ledger Mirror Handoff

Repository: `GCAT-BCAT-Engine/.github`

Every durable transition owned here is recorded first in this repository ledger. Repo replay must terminate without org or ecosystem replay.

Contract: `.stegverse/transition-ledger/contract.json`  
Emitter: `.stegverse/transition-ledger/emit.py`  
Store: `resident-runtime/ledger_store.py`  
Durable root: supplied by the materializer as `STEGVERSE_REPO_LEDGER_ROOT`. There is no host-derived default: without it the emitter refuses with `ledger_location_required_from_materializer`.

Where the durable root is (`contract.json` `repository_ledger_location`): a subtree, `repository-ledger/GCAT-BCAT-Engine/.github/`, of the designated organization ledger ref `refs/stegverse/organization-ledger` in this repository, addressed as `git+<checkout>#refs/stegverse/organization-ledger:repository-ledger/GCAT-BCAT-Engine/.github`. The repository chain and the organization chain share that ref: one commit history, one compare-and-swap, one fast-forward push under `ORGANIZATION_LEDGER_LOCK`. Repository replay walks `repository-ledger/<repository>/HEAD.json` back through repository receipts alone. The push-only `organization-ledger-merge-transfer.yml` binds both roots from the contracts and reads both chains back from a fresh fetch (the self-closure `organization-ledger-transition.yml` is retired under Rigel's rule, 2026-10-25: no InTr hop inside one organization). The durable chain opens at its own genesis on the first append.

`resident-runtime/dual_ledger.py` is the in-process wrapper egress and ingress call. It appends through the emitter and the aggregator above.

Receipts are append-only and hash-linked. Only evidence needed for organization reconstruction propagates upward. A recorded disposition is transition evidence only. Authority and time remain constraint variables.
