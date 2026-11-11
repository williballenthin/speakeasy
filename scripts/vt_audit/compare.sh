#!/usr/bin/env bash
# Re-emulate the samples of a finished batch with a second speakeasy checkout (usually
# mandiant/speakeasy master), and print the outcome of both side by side. Use it before triage:
# a stop that the second checkout no longer shows is already fixed there and needs no new issue.
#
# usage: compare.sh <second speakeasy checkout> <work dir of run_audit.sh>
# Outputs in <work dir>: venv-cmp/, out-cmp/ (same layout as out/), analyze-cmp.txt, compare.txt
set -euo pipefail

SE=$(realpath "$1")
WORK=$(realpath "$2")
TOOLS=$(dirname "$(realpath "$0")")
echo "[*] compare with $(git -C "$SE" rev-parse --short HEAD) in $WORK"

git -C "$SE" submodule update --init --depth 1 deps/win32json deps/phnt >/dev/null
uv venv -q --allow-existing "$WORK/venv-cmp"
uv pip install -q --python "$WORK/venv-cmp/bin/python" -e "$SE"
PY="$WORK/venv-cmp/bin/python"

mkdir -p "$WORK/out-cmp"
ls "$WORK/data/samples" | xargs -P4 -I{} sh -c '
    start=$(date +%s)
    timeout -k 10 300 "$0" -I "$1/run_one.py" "$2/data/samples/{}" "$2/out-cmp/{}" > "$2/out-cmp/{}.log" 2>&1
    echo "$? $(( $(date +%s) - start ))" > "$2/out-cmp/{}.rc"' "$PY" "$TOOLS" "$WORK"

"$PY" -I "$TOOLS/analyze.py" "$WORK/data/manifest.json" "$WORK/data/samples" "$WORK/out-cmp" > "$WORK/analyze-cmp.txt" 2> "$WORK/analyze-cmp.err" || true
python3 -I - "$WORK/out/summary.json" "$WORK/out-cmp/summary.json" > "$WORK/compare.txt" <<'PYEOF'
import json, sys

def first_error(x):
    v = x.get("first_error") or {}
    return " ".join(str(v[k]) for k in ("error", "pc", "instruction", "last_api") if v.get(k))[:55]

a = {x["sha256"]: x for x in json.load(open(sys.argv[1]))}
b = {x["sha256"]: x for x in json.load(open(sys.argv[2]))}
print("sha      family       outcome   apis first error                                              | second checkout")
for sha, x in a.items():
    y = b.get(sha, {})
    mark = "*" if (x["outcome"], first_error(x)) != (y.get("outcome"), first_error(y)) else " "
    print(mark + sha[:8], x["family"][:12].ljust(12), x["outcome"][:7].ljust(7), str(x["n_api_total"]).rjust(6),
          first_error(x).ljust(55), "|", y.get("outcome", "?")[:7].ljust(7), str(y.get("n_api_total")).rjust(6), first_error(y))
PYEOF
tail -1 "$WORK/analyze-cmp.txt"
echo "[*] done: $WORK/compare.txt (* = differs)"
