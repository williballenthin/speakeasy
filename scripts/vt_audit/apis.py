import json, sys
# usage: apis.py report.json [run_index] [tail_n]
r = json.load(open(sys.argv[1]))
idx = int(sys.argv[2]) if len(sys.argv) > 2 else 0
n = int(sys.argv[3]) if len(sys.argv) > 3 else 60
evs = r["entry_points"][idx]["events"]
for v in evs[-n:]:
    if v["event"] == "api":
        args = " | ".join(f"{a.get('name', '')}={str(a.get('display'))[:80]}" for a in v.get("args") or [])
        print(" ", v["api_name"], args[:300], "->", v.get("ret_val"))
    else:
        print("  *", v["event"], json.dumps({k: v[k] for k in v if k not in ("pos", "event")})[:240])
