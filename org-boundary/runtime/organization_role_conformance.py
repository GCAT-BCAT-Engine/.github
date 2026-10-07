#!/usr/bin/env python3
import json

CURRENT_VERSION = "org-role-2026-10-07"

def evaluate(payload):
    declared = payload.get("declared_version")
    if not declared:
        return {"disposition":"FAIL_CLOSED","failed_predicate":"DECLARED_ORGANIZATION_ROLE_VERSION_PRESENT","repair":"Supply the owning Organization's declared Organization Role version in the manifest-bound payload.","retry_entrypoint":"MANIFEST_BOUND_CONFORMANCE_RETRY","next_attempt":"Retry through the same org-boundary service with a declared_version.","runtime_migration":"UNOBSERVED"}
    if declared != CURRENT_VERSION:
        return {"disposition":"DENY","failed_predicate":"DECLARED_ORGANIZATION_ROLE_VERSION_EQUALS_CANONICAL_VERSION","declared_version":declared,"canonical_version":CURRENT_VERSION,"repair":"Migrate through an Organization-owned manifest-bound transition; repository mutation alone is insufficient.","retry_entrypoint":"MANIFEST_BOUND_CONFORMANCE_RETRY","next_attempt":"Retry only after Organization-owned migration evidence exists.","runtime_migration":"UNOBSERVED"}
    return {"disposition":"ALLOW","predicate":"DECLARED_ORGANIZATION_ROLE_VERSION_EQUALS_CANONICAL_VERSION","declared_version":declared,"canonical_version":CURRENT_VERSION,"authority_effect":"NONE_CONFORMANCE_RESULT_ONLY","runtime_migration":"UNOBSERVED","note":"ALLOW confirms source/version conformance only; it does not establish runtime migration."}

if __name__ == "__main__":
    import sys
    print(json.dumps(evaluate(json.load(sys.stdin)),sort_keys=True))
