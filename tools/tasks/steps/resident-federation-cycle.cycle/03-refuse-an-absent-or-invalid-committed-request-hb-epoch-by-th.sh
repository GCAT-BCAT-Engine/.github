python - <<'PY'
import importlib.util, json, os, sys
spec = importlib.util.spec_from_file_location("kernel", "org-kernel/kernel.py")
kernel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kernel)
refusal = kernel.writer_epoch_refusal(
    os.environ.get("HB_EPOCH") or None,
    retry_entrypoint=".github/workflows/resident-federation-cycle.yml (.stegverse/resident-federation/cycle-request.json hb_epoch)")
if refusal is not None:
    print(json.dumps(refusal, sort_keys=True))
    sys.exit(1)
print("COMMITTED_REQUEST_HB_EPOCH=SUPPLIED")
PY
