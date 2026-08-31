# Organization Resident Runtime + Interlock/InTr Boundary Mirror Handoff

Status: ACTIVE
Updated: 2026-08-31
Organization: `GCAT-BCAT-Engine`
Repository: `GCAT-BCAT-Engine/.github`

## Canonical ownership
This `.github` owns organization resident-runtime activation source and the mechanism generating all organization ingress/egress communication.

Application repositories expose endpoint/runtime profiles only. They do not create a second organization communication boundary.

## Runtime
`org-runtime/activation.json` and `org-runtime/runtime_boundary.py` are the organization-local activation surfaces. Authentic execution remains a sovereign resident process. GitHub Actions is validation/evidence only.

## Communication
All cross-organization communication crosses this boundary as Interlock/InTr. HB/HB-derived carriers provide synchronization/carrier capability but no authority.

Action admission, authority transfer, capability realization, and authority effect are distinct. Standing/effects are `DERIVED_FROM_APPLICABLE_TRANSITION_ELEMENTS`.

Machine surfaces:
- `org-runtime/activation.json`
- `org-runtime/interlock-intr.json`
- `org-runtime/runtime_boundary.py`

The tool validates the contract and emits activation requests plus ingress/egress envelopes. It cannot self-grant authority.
