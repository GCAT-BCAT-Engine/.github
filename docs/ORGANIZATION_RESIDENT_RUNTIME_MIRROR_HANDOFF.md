# Organization Resident Runtime / Interlock-InTr Handoff

Organization: **GCAT-BCAT-Engine**  
Runtime owner: **GCAT-BCAT-Engine/.github**

All GCAT-BCAT-Engine resident-runtime activation declarations and all organization-boundary
ingress/egress mechanisms are owned by this `.github` repository.

Sibling repositories may supply application payloads or local handlers, but they
may not become an alternate organization runtime owner or bypass the organization
Interlock/InTr boundary.

```text
GCAT-BCAT-Engine application/work repo
  -> GCAT-BCAT-Engine/.github
  -> Interlock
  -> governed InTr packet
  -> HB / deterministic HB-derived carrier when available
  -> receiving Interlock
```

Machine surfaces:
- `control/organization-runtime.json`
- `runtime/organization_runtime.py`
- `runtime/activations/`
- `runtime/egress/`
- `runtime/ingress/`

HB, derived carriers, and InTr grant no execution, credential, routing,
transition, publication, or receiving authority. Credential authority remains
TV/TVC. GitHub Actions may validate this source but is not the resident runtime.
