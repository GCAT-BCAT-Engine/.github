# The fold of .github/workflows/resident-federation-cycle.yml (on: push, branches [main],
# paths: the committed cycle request). The stable dispatcher runs this group on every
# pull_request and push, so the group selects its own run: a push to main whose
# before..after diff touches the request. Every other event exports false and nothing
# below runs. A push whose diff cannot be computed fails closed: nothing runs.
request=.stegverse/resident-federation/cycle-request.json
committed=false
if [ "$GITHUB_EVENT_NAME" = "push" ] && [ "$GITHUB_REF" = "refs/heads/main" ] && [ -n "$CATALOG_EVENT_AFTER" ]; then
  if [ -z "$CATALOG_EVENT_BEFORE" ] || [ "$CATALOG_EVENT_BEFORE" = "0000000000000000000000000000000000000000" ]; then
    if git cat-file -e "$CATALOG_EVENT_AFTER:$request" 2>/dev/null; then committed=true; fi
  else
    set +e
    git diff --quiet "$CATALOG_EVENT_BEFORE" "$CATALOG_EVENT_AFTER" -- "$request"
    rc=$?
    set -e
    case "$rc" in
      0) ;;
      1) committed=true ;;
      *) echo "CYCLE_REQUEST_PUSH_NOT_COMPARABLE: git diff $CATALOG_EVENT_BEFORE $CATALOG_EVENT_AFTER exited $rc" >&2; exit 1 ;;
    esac
  fi
fi
echo "CYCLE_REQUEST_COMMITTED=$committed" >> "$GITHUB_ENV"
echo "CYCLE_REQUEST_COMMITTED=$committed"
