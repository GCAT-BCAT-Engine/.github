set -euo pipefail
python3 resident-runtime/intr_path_transfer.py verify --out "$RUNNER_TEMP/results/real-state.json" > /dev/null
python3 - <<'PY'
import json, os, subprocess
from pathlib import Path
git = ["git", "--git-dir=" + os.environ["SCRATCH"]]
ref = os.environ["LEDGER_REF"]
me = "GCAT-BCAT-Engine"
names = subprocess.run(git + ["ls-tree", "-r", "--name-only", ref, "receipts/"], check=True,
                       capture_output=True, text=True).stdout.split()
ledgered = set()
for name in names:
    receipt = json.loads(subprocess.run(git + ["cat-file", "blob", ref + ":" + name], check=True,
                                        capture_output=True, text=True).stdout)
    b = receipt.get("boundary_evidence") or {}
    if b.get("operation") == "INTR_MESH_PATH_TRANSFER" and b.get("disposition") == "ALLOW" \
            and b.get("repository") == me + "/.github" and b.get("path_id"):
        ledgered.add(b["path_id"])
state = json.loads((Path(os.environ["RUNNER_TEMP"]) / "results/real-state.json").read_text())
paths = state["paths"]
assert sum(state["counts"].values()) == len(paths) and len(paths) > 0, state["counts"]
own = [p for p in paths if p["path_id"].startswith(me + "->")]
assert own, "no path sourced here was examined"
mismatch = [(p["path_id"], p["halves"]["source"], p["path_id"] in ledgered) for p in own
            if p["halves"]["source"] != ("ALLOW" if p["path_id"] in ledgered else "FAIL_CLOSED")]
assert not mismatch, ("source half does not match the ledgered state", mismatch)
stray = sorted(ledgered - {p["path_id"] for p in own})
assert not stray, ("ledgered path receipt for an undeclared path", stray)
assert all(p["disposition"] == "ALLOW" or (p.get("failure_code") and p.get("failed_predicate"))
           for p in paths), state["counts"]
assert all(p["disposition"] != "ALLOW" or set(p["halves"].values()) == {"ALLOW"} for p in paths)
print("INTR_PATH_REAL_STATE", json.dumps(state["counts"]), "sourced_here", len(own),
      "source_ALLOW_ledgered", len(ledgered))
PY
