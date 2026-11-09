#!/usr/bin/env python3
"""
Fetch sandbox ground truth that does not come from Mandiant Backscatter, for each sample of a manifest.
Uses plain API calls only (no search or download quota).

  data/behaviour/<sha>.json  : behaviour_summary + sandbox names
  data/payloads/<sha>.json   : VT metadata of each CAPE/sandbox extracted payload (pe_info sections etc.)

usage: enrich.py <manifest.json> <data dir>
"""

import json
import os
import subprocess
import sys

VT = "https://www.virustotal.com/api/v3"


def get(path):
    r = subprocess.run(
        ["curl", "-sS", "-H", f"x-apikey: {os.environ['VT_API_KEY']}", f"{VT}/{path}"], capture_output=True, check=False
    )
    try:
        return json.loads(r.stdout)
    except Exception:
        return {}


def main():
    manifest, ddir = sys.argv[1:3]
    os.makedirs(os.path.join(ddir, "behaviour"), exist_ok=True)
    os.makedirs(os.path.join(ddir, "payloads"), exist_ok=True)
    for s in json.load(open(manifest))["samples"]:
        sha = s["sha256"]
        bpath = os.path.join(ddir, "behaviour", f"{sha}.json")
        if not os.path.exists(bpath):
            bs = get(f"files/{sha}/behaviour_summary").get("data", {})
            bl = get(f"files/{sha}/behaviours?limit=40").get("data", [])
            json.dump({"summary": bs, "sandboxes": sorted({x["attributes"].get("sandbox_name") for x in bl})}, open(bpath, "w"))
        bs = json.load(open(bpath))["summary"]
        ppath = os.path.join(ddir, "payloads", f"{sha}.json")
        if os.path.exists(ppath):
            continue
        out = []
        seen = set()
        for p in (bs.get("payloads_extracted") or [])[:25]:
            h = p.get("sha256")
            if not h or h in seen:
                continue
            seen.add(h)
            a = get(f"files/{h}").get("data", {}).get("attributes")
            entry = {k: p.get(k) for k in ("sha256", "size", "payload_type", "process_name")}
            if a:
                pe = a.get("pe_info") or {}
                entry.update(
                    {
                        "on_vt": True,
                        "type_tag": a.get("type_tag"),
                        "imphash": pe.get("imphash"),
                        "sections": [
                            {k: x.get(k) for k in ("name", "virtual_address", "raw_size", "virtual_size", "md5", "entropy")}
                            for x in pe.get("sections", [])
                        ],
                        "label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label"),
                        "yara": sorted({y.get("rule_name") for y in a.get("crowdsourced_yara_results") or []}),
                    }
                )
            else:
                entry["on_vt"] = False
            out.append(entry)
        json.dump(out, open(ppath, "w"), indent=1)
        print(sha[:12], len(out), "payloads", sum(1 for e in out if e.get("sections")), "with PE sections", file=sys.stderr)


if __name__ == "__main__":
    main()
