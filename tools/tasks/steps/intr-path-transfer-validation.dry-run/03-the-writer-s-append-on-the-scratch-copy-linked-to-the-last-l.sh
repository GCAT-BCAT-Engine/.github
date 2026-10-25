python3 resident-runtime/intr_path_ledger.py which
set -euo pipefail
# a main merge whose main-merge transfer receipt is on the ledger (pinned in the expected real state)
base=$(python3 -c 'import json; print(json.load(open("tests/fixtures/intr-path-transfer/expected-real-state.json"))["verified_transfer_commit"])')
# an organization with no main-merge transfer receipt yet: append the pinned merges to the scratch copy first
for c in $(python3 -c 'import json; print(" ".join(json.load(open("tests/fixtures/intr-path-transfer/expected-real-state.json")).get("temp_merge_transfers") or []))'); do
  python3 resident-runtime/intr_path_ledger.py append-merge-transfer --commit "$c" > /dev/null
done
python3 resident-runtime/intr_path_transfer.py append --transfer-commit "$base" --out "$RUNNER_TEMP/results/append.json" > /dev/null
python3 resident-runtime/intr_path_transfer.py verify --expect-source ALLOW --out "$RUNNER_TEMP/results/verify.json" > /dev/null
tip=$(git --git-dir="$SCRATCH" rev-parse "$LEDGER_REF")
python3 resident-runtime/intr_path_transfer.py append --transfer-commit "$base" --out "$RUNNER_TEMP/results/replay.json" > /dev/null
test "$(git --git-dir="$SCRATCH" rev-parse "$LEDGER_REF")" = "$tip"
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert all(x.get("replayed") is True for x in r), r' "$RUNNER_TEMP/results/replay.json"
# A previously ledgered path replays without moving the scratch tip (the source receipts may already be
# ledgered). The workspace ref is unchanged by this read-only dry run. The writer (intr-path-transfer.yml,
# after a push to main) may append to the published ref while this runs, so the published-ref guard is
# append-only growth from the copied tip and no scratch commit on the published ref, not an unchanged tip.
test "$(git rev-parse "$LEDGER_REF")" = "$PUBLISHED_TIP"
git fetch --no-tags origin "+$LEDGER_REF:refs/dry-run/published-now"
git merge-base --is-ancestor "$PUBLISHED_TIP" refs/dry-run/published-now
scratch_tip=$(git --git-dir="$SCRATCH" rev-parse "$LEDGER_REF")
if [ "$scratch_tip" != "$PUBLISHED_TIP" ] && git rev-list refs/dry-run/published-now | grep -qx "$scratch_tip"; then
  echo '{"disposition":"DENY","failure_code":"DRY_RUN_SCRATCH_APPEND_PUBLISHED","failed_predicate":"SCRATCH_APPEND_NOT_ON_PUBLISHED_REF","required_evidence_or_repair":"the read-only dry run must not publish its scratch append","retry_entrypoint":".github/workflows/intr-path-transfer-validation.yml","owning_existing_goal":"StegVerse-org/.github#162","next_attempt":"remove any push from the dry-run job"}'
  exit 1
fi
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print("INTR_PATH_DRY_RUN", json.dumps(r["counts"]))' "$RUNNER_TEMP/results/verify.json"
