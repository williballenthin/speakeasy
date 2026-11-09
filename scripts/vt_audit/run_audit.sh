#!/usr/bin/env bash
# Run one VT audit batch end to end: install speakeasy, select and download samples, enrich them,
# emulate them, then score and triage the runs.
#
# usage: run_audit.sh <speakeasy checkout under test> <work dir> [since YYYY-MM-DD] [until YYYY-MM-DD] [target]
#   defaults: until = today (UTC), since = until - 7 days, target = 60
#
# Outputs in <work dir>:
#   data/manifest.json   selected samples with VT metadata (strata, labels, configs)
#   data/samples/<sha>   the samples (mode 0400) - never commit these
#   data/behaviour/      VT sandbox behaviour summaries;  data/payloads/  sandbox-extracted payload metadata
#   out/<sha>/           report.json, harness.json, regions/ (full memory dump)
#   out/summary.json     per-sample outcome, oracles, errors;  analyze.txt  table
#   triage.md            runs grouped by stop signature, out-of-scope stops marked
#
# Requires: VT_API_KEY, curl, uv, python3. Samples are only ever loaded into speakeasy, never executed.
set -euo pipefail

SE=$(realpath "$1")
WORK=$(realpath -m "$2")
UNTIL=${4:-$(date -u +%F)}
SINCE=${3:-$(date -u -d "$UNTIL - 7 days" +%F)}
TARGET=${5:-60}
TOOLS=$(dirname "$(realpath "$0")")
mkdir -p "$WORK"
echo "[*] speakeasy $(git -C "$SE" rev-parse --short HEAD) window $SINCE..$UNTIL target $TARGET work $WORK"

# 1. install the speakeasy under test into its own venv
git -C "$SE" submodule update --init --depth 1 deps/win32json deps/phnt >/dev/null
uv venv -q --allow-existing "$WORK/venv"
uv pip install -q --python "$WORK/venv/bin/python" -e "$SE"
PY="$WORK/venv/bin/python"
"$PY" -c 'import speakeasy, sys; print("[*] installed", speakeasy.__file__)'

# 2. select + download
python3 -I "$TOOLS/collect.py" --since "$SINCE" --until "$UNTIL" --target "$TARGET" \
    --seen "$TOOLS/seen.txt" --out "$WORK/data" --download

# 3. sandbox ground truth (plain API calls)
python3 -I "$TOOLS/enrich.py" "$WORK/data/manifest.json" "$WORK/data"

# 4. emulate, 4 at a time, each bounded by a hard timeout
mkdir -p "$WORK/out"
ls "$WORK/data/samples" | xargs -P4 -I{} sh -c '
    start=$(date +%s)
    timeout -k 10 300 "$0" -I "$1/run_one.py" "$2/data/samples/{}" "$2/out/{}" > "$2/out/{}.log" 2>&1
    echo "$? $(( $(date +%s) - start ))" > "$2/out/{}.rc"' "$PY" "$TOOLS" "$WORK"

# 5. score + triage
"$PY" -I "$TOOLS/analyze.py" "$WORK/data/manifest.json" "$WORK/data/samples" "$WORK/out" > "$WORK/analyze.txt" 2> "$WORK/analyze.err" || true
python3 -I "$TOOLS/triage.py" "$WORK/out/summary.json" "$SE" > "$WORK/triage.md"
tail -1 "$WORK/analyze.txt"
echo "[*] done: $WORK/triage.md"
