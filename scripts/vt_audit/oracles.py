import collections
import json
import sys

rows = json.load(open(sys.argv[1]))
for r in rows:
    o = r["oracles"]
    print(
        f"{r['stratum'][:11]:11} {r['family'][:20]:20} {r['outcome']:14} bs={int(o['backscatter'])} "
        f"sbIOC={int(o['sandbox_ioc'])}/{len(r['sandbox_hidden'])} sbPay={int(o['sandbox_payload'])}/{r['sandbox_payloads']} "
        f"intr={int(o['intrinsic'])}",
        list(r["sandbox_hits"])[:2],
        [m["kind"] for m in r["sandbox_payload_matches"]][:2],
    )
print(collections.Counter(tuple(k for k, v in r["oracles"].items() if v) for r in rows))
print(collections.Counter(r["outcome"] for r in rows))
