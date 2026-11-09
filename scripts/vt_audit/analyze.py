#!/usr/bin/env python3
"""
Score each emulated sample against VT ground truth and triage how the emulation ended.

Oracle:
  * config indicators (C2 hosts, mutexes, campaign ids, ...) that VT/Backscatter extracted from a sandbox
    memory dump; only the ones that are NOT in the file bytes count ("hidden"), and a hit in emulated
    memory or API arguments means the inner payload was reached.
  * PE images carved from memory that are neither the sample's own headers nor stored in plain form in the file.
  * the sample image after emulation differs from the mapped file (in-place unpacking, e.g. UPX).

usage: analyze.py <manifest.json> <samples dir> <out dir>  -> writes <out dir>/summary.json and prints a table
"""

import base64
import collections
import hashlib
import json
import os
import re
import struct
import sys
import zlib

import pefile

SKIP_KEYS = {"tool", "description", "categories", "protocol_tags", "family", "version", "port", "file_type"}
SKIP_TAG = ("emu.struct", "emu.gdt", "emu.segment", "emu.kernel", "emu.KUSER")


def indicators(cfg):
    out = set()

    def walk(x, key=None):
        if isinstance(x, dict):
            for k, v in x.items():
                if k not in SKIP_KEYS:
                    walk(v, k)
        elif isinstance(x, list):
            for v in x:
                walk(v, key)
        elif isinstance(x, str):
            s = x.strip()
            if re.fullmatch(r"[A-Z0-9_]+", s) or s.lower() in ("payload", "127.0.0.1"):
                return  # schema enums (PLAINTEXT, HKEY_CURRENT_USER, ...) and placeholders, not IOCs
            if len(s) >= 6 and not re.fullmatch(r"[\d.:]+", s) or re.fullmatch(r"\d+\.\d+\.\d+\.\d+", s):
                out.add(s)

    for fam in (cfg or {}).get("families", []):
        for c in fam.get("configs", []):
            walk(c)
    return sorted(out)


def needles(s):
    b = s.encode("utf-8", "ignore")
    return [b.lower(), s.encode("utf-16le", "ignore").lower()]


def contains(hay_lower, s):
    return any(n in hay_lower for n in needles(s))


def carve_pes(data):
    found = []
    for m in re.finditer(rb"MZ", data):
        off = m.start()
        if off + 0x40 > len(data):
            break
        e_lfanew = struct.unpack_from("<I", data, off + 0x3C)[0]
        if not 0x40 <= e_lfanew < 0x1000 or off + e_lfanew + 0x18 > len(data):
            continue
        if data[off + e_lfanew : off + e_lfanew + 4] != b"PE\0\0":
            continue
        machine = struct.unpack_from("<H", data, off + e_lfanew + 4)[0]
        found.append((off, machine))
    return found


def image_rewritten(sample_path, regions_dir, regions, image_base):
    """Fraction of the sample's section bytes that differ after emulation, and the sections touched."""
    try:
        pe = pefile.PE(sample_path, fast_load=True)
        mapped = pe.get_memory_mapped_image()
    except Exception:
        return None, []
    touched, diff_total, size_total = [], 0, 0
    img = [r for r in regions if r["tag"].startswith("emu.module.") and int(r["base"], 16) == image_base]
    if not img:
        return None, []
    data = open(os.path.join(regions_dir, img[0]["file"]), "rb").read()
    for s in pe.sections:
        va, vs = s.VirtualAddress, max(s.Misc_VirtualSize, s.SizeOfRawData)
        a, b = mapped[va : va + vs], data[va : va + vs]
        n = min(len(a), len(b))
        if n == 0:
            continue
        d = sum(1 for i in range(0, n, 16) if a[i : i + 16] != b[i : i + 16]) * 16
        diff_total += d
        size_total += n
        if d > 0.05 * n:
            name = s.Name.rstrip(b"\0").decode(errors="replace")
            touched.append(f"{name}:{100 * d // n}%")
    return (diff_total / size_total if size_total else None), touched


STATIC_GENERIC = re.compile(
    r"(^|\.)(microsoft\.com|windows\.com|windowsupdate\.com|msftncsi\.com|msftconnecttest\.com|digicert\.com|"
    r"verisign\.com|symcd\.com|symcb\.com|globalsign\.(com|net)|sectigo\.com|usertrust\.com|comodoca\.com|"
    r"letsencrypt\.org|lencr\.org|bing\.com|live\.com|office\.com|office365\.com|azureedge\.net|akamai(edge)?\.net|"
    r"gstatic\.com|googleapis\.com|wpad\..*)$|^(local\\|global\\)?(smo:|sm0:|ctf\.|msctf|zonescache|zoneslocked|"
    r"rasp?bfile|dbwinmutex|__clr|.net clr|syncrootmanager|wininet_|c:!users|_shmem|wilstaging|wilerror|"
    r"inventorysynchronization|^127\.0\.0\.1|^localhost)",
    re.I,
)
GENERIC_SANDBOX: set = set()


def sandbox_indicators(bs):
    out = set()
    for k in ("mutexes_created", "memory_pattern_domains", "memory_pattern_urls", "memory_pattern_ips"):
        for v in bs.get(k) or []:
            if k == "memory_pattern_ips" and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+(:\d+)?", v or ""):
                continue
            if isinstance(v, str) and len(v) >= 6:
                out.add(v)
    for d in bs.get("dns_lookups") or []:
        if d.get("hostname"):
            out.add(d["hostname"])
    for h in bs.get("http_conversations") or []:
        if h.get("url"):
            out.add(h["url"])
    def norm(i):
        return re.sub(r"^(\\Sessions\\\d+)?\\BaseNamedObjects\\", "", i)

    return {
        i
        for i in out
        if not STATIC_GENERIC.search(i.split("://")[-1].split("/")[0]) and not STATIC_GENERIC.search(norm(i))
    }


def match_payloads(payloads, blobs, image_base, raw=b""):
    """Exact matches between sandbox-extracted payloads and emulated memory: whole-buffer sha256, or the md5 of
    a mapped PE section at a candidate image start (carved MZ, region start)."""
    want_sha = {p["sha256"] for p in payloads}
    secs = [
        (p["sha256"][:12], x)
        for p in payloads
        for x in p.get("sections") or []
        if x.get("md5") and (x.get("raw_size") or 0) >= 0x400
    ]
    matches = []
    for meta, data in blobs:
        trimmed = data.rstrip(b"\0")
        for cand in (data, trimmed):
            if cand and cand not in raw and hashlib.sha256(cand).hexdigest() in want_sha:
                matches.append({"region": meta["tag"], "kind": "buffer-sha256"})
        if not secs:
            continue
        starts = {0} | {off for off, _m in carve_pes(data)}
        for st in starts:
            for psha, x in secs:
                chunk = data[st + x["virtual_address"] : st + x["virtual_address"] + x["raw_size"]]
                if (
                    len(chunk) == x["raw_size"]
                    and chunk.strip(b"\0")
                    and hashlib.md5(chunk).hexdigest() == x["md5"]
                    and chunk not in raw  # a section the packer never touched is not evidence
                ):
                    matches.append({"region": meta["tag"], "kind": f"section {x['name']} of {psha}"})
    uniq = {(m["region"], m["kind"]): m for m in matches}
    return list(uniq.values())[:8]


def build_generic(samples, sdir):
    """Sandbox indicators shared by samples of 3+ different families are environment noise."""
    seen = collections.defaultdict(set)
    for s in samples:
        p = os.path.join(os.path.dirname(sdir), "behaviour", s["sha256"] + ".json")
        if os.path.exists(p):
            for i in sandbox_indicators(json.load(open(p))["summary"]):
                seen[i.lower()].add(s["family"])
    GENERIC_SANDBOX.update(i for i, fams in seen.items() if len(fams) >= 3)


def main():
    manifest, sdir, odir = sys.argv[1:4]
    samples = json.load(open(manifest))["samples"]
    build_generic(samples, sdir)
    rows = []
    for s in samples:
        sha = s["sha256"]
        o = os.path.join(odir, sha)
        raw = open(os.path.join(sdir, sha), "rb").read()
        raw_l = raw.lower()
        row = {k: s[k] for k in ("sha256", "stratum", "family", "packer", "arch", "type", "size")}
        rc = open(os.path.join(odir, sha + ".rc")).read().split() if os.path.exists(os.path.join(odir, sha + ".rc")) else ["?", "?"]
        row["exit"], row["secs"] = rc[0], rc[1]
        hpath, rpath = os.path.join(o, "harness.json"), os.path.join(o, "report.json")
        if not os.path.exists(hpath):
            row["outcome"] = "HARNESS-CRASH"
            log = open(os.path.join(odir, sha + ".log"), errors="replace").read()[-800:] if os.path.exists(os.path.join(odir, sha + ".log")) else ""
            row["log_tail"] = log
            # rc 124/137 = killed by the hard timeout in run_audit.sh: speakeasy's own limits did not stop it
            kind = "harness_timeout" if row["exit"] in ("124", "137") else "harness_crash"
            row["first_error"] = {"error": kind, "secs": row["secs"]}
            rows.append(row)
            continue
        h = json.load(open(hpath))
        r = json.load(open(rpath)) if os.path.exists(rpath) else {"entry_points": []}
        row["harness_error"] = h.get("harness_error")
        row["no_handler"] = h.get("no_handler", {})
        row["unsupported"] = h.get("unsupported", {})

        # --- how the runs ended
        eps = []
        api_names = collections.Counter()
        events_text = []
        inj = collections.Counter()
        for ep in r.get("entry_points", []):
            err = ep.get("error") or {}
            e = {"type": ep.get("type"), "name": ep.get("name"), "error": err.get("type")}
            for k in (
                "message",
                "pc",
                "instruction",
                "address",
                "api_name",
                "pc_module",
                "pc_offset",
                "context_summary",
                "last_api",
                "count",
            ):
                if err.get(k) is not None:
                    e[k] = err[k]
            for k in ():
                if err.get(k):
                    e[k] = err[k]
            if err.get("traceback"):
                e["traceback_tail"] = err["traceback"].strip().splitlines()[-3:]
            e["dyn_code"] = len(ep.get("dynamic_code_segments") or [])
            evs = ep.get("events") or []
            e["n_api"] = sum(1 for ev in evs if ev.get("event") == "api")
            for ev in evs:
                if ev.get("event") == "api":
                    api_names[ev.get("api_name")] += 1
                    events_text.append(" ".join(str(a.get("display", "")) for a in ev.get("args") or []))
                elif ev.get("event") in ("process_create", "thread_inject", "net_dns", "net_http", "net_traffic"):
                    inj[ev["event"]] += 1
                    events_text.append(json.dumps(ev))
                elif ev.get("event") == "mem_write" and ev.get("pid"):
                    inj["remote_mem_write"] += 1
            if evs:
                last = [ev for ev in evs if ev.get("event") == "api"][-1:]
                e["last_api"] = last[0].get("api_name") if last else None
            eps.append(e)
        row["runs"] = eps
        row["n_api_total"] = sum(api_names.values())
        row["n_api_unique"] = len(api_names)
        row["notable_events"] = dict(inj)
        dropped = []
        for ep in r.get("entry_points", []):
            for df in ep.get("dropped_files") or []:
                dropped.append(df.get("path"))
        row["dropped"] = dropped

        # --- memory: indicators + carved PEs
        rdir = os.path.join(o, "regions")
        regions = [x for x in h.get("regions", []) if not x["tag"].startswith(SKIP_TAG)]
        blobs = []
        for x in regions:
            blobs.append((x, open(os.path.join(rdir, x["file"]), "rb").read()))
        for ref, art in (r.get("data") or {}).items():
            try:
                blobs.append(({"tag": "report.data", "file": ref, "base": "0x0"}, zlib.decompress(base64.b64decode(art["data"]))))
            except Exception:
                pass

        inds = indicators(s.get("malware_config"))
        hidden = [i for i in inds if not contains(raw_l, i)]
        row["indicators"] = len(inds)
        row["hidden_indicators"] = hidden[:12]
        mem_lower = [(x, b.lower()) for x, b in blobs]
        api_lower = "\n".join(events_text).lower().encode()
        hits = {}
        for i in hidden:
            where = [x["tag"] for x, bl in mem_lower if contains(bl, i)]
            if contains(api_lower, i):
                where.append("api-args")
            if where:
                hits[i] = sorted(set(where))[:4]
        row["hidden_hits"] = hits

        image_base = int(h.get("image_base", "0x0"), 16)
        carved = []
        for x, b in blobs:
            for off, machine in carve_pes(b):
                base = int(x.get("base", "0x0"), 16)
                if base + off == image_base:
                    continue  # the sample's own headers
                if x["tag"].startswith("emu.module.") and off == 0:
                    continue
                head = b[off : off + 0x400]
                plain = head in raw
                carved.append(
                    {
                        "tag": x["tag"],
                        "off": hex(off),
                        "machine": {0x14C: "x86", 0x8664: "x64"}.get(machine, hex(machine)),
                        "plain_in_file": plain,
                        "sha256_head": hashlib.sha256(head).hexdigest()[:16],
                    }
                )
        # dedupe identical heads
        uniq = {}
        for c in carved:
            uniq.setdefault((c["sha256_head"], c["plain_in_file"]), c)
        row["carved_pe"] = list(uniq.values())
        frac, touched = image_rewritten(os.path.join(sdir, sha), rdir, h.get("regions", []), image_base)
        row["image_rewritten"] = None if frac is None else round(frac, 3)
        row["image_sections_touched"] = touched

        # --- sandbox oracle (CAPE/Zenbox/VMRay/... via VT behaviour_summary), independent of Backscatter
        bpath = os.path.join(os.path.dirname(sdir), "behaviour", sha + ".json")
        ppath = os.path.join(os.path.dirname(sdir), "payloads", sha + ".json")
        sb_inds = sandbox_indicators(json.load(open(bpath))["summary"]) if os.path.exists(bpath) else set()
        sb_inds = {i for i in sb_inds if i.lower() not in GENERIC_SANDBOX}
        sb_hidden = sorted(i for i in sb_inds if not contains(raw_l, i))
        sb_hits = {}
        for i in sb_hidden:
            where = [x["tag"] for x, bl in mem_lower if contains(bl, i)]
            if contains(api_lower, i):
                where.append("api-args")
            if where:
                sb_hits[i] = sorted(set(where))[:4]
        row["sandbox_hidden"] = sb_hidden[:15]
        row["sandbox_hits"] = sb_hits
        payloads = json.load(open(ppath)) if os.path.exists(ppath) else []
        row["sandbox_payloads"] = len(payloads)
        row["sandbox_payload_matches"] = match_payloads(payloads, blobs, image_base, raw)

        # --- outcome
        decrypted_pe = [c for c in row["carved_pe"] if not c["plain_in_file"]]
        dyn = sum(e["dyn_code"] for e in eps)
        errors = [e["error"] for e in eps if e.get("error")]
        row["oracles"] = {
            "backscatter": bool(hits),
            "sandbox_ioc": bool(sb_hits),
            "sandbox_payload": bool(row["sandbox_payload_matches"]),
            "intrinsic": bool(decrypted_pe) or (s["stratum"] == "packer" and (frac or 0) > 0.5),
        }
        if any(row["oracles"].values()):
            outcome = "PAYLOAD"
        elif dyn or (frac or 0) > 0.2 or inj.get("remote_mem_write") or inj.get("thread_inject"):
            outcome = "PARTIAL"
        elif errors:
            outcome = "STOPPED"
        else:
            outcome = "RAN-NO-PAYLOAD"
        row["outcome"] = outcome
        row["first_error"] = next((e for e in eps if e.get("error")), None)
        rows.append(row)

    with open(os.path.join(odir, "summary.json"), "w") as f:
        json.dump(rows, f, indent=1)

    print(f"{'stratum':12} {'family':22} {'arch':4} {'outcome':15} {'apis':>6} {'hid':>3} {'hit':>3} {'pe':>3} {'img%':>5}  first error")
    for row in rows:
        fe = row.get("first_error") or {}
        err = fe.get("error") or ""
        if fe.get("api_name"):
            err += f" {fe['api_name']}"
        elif fe.get("message"):
            err += f" {fe['message'][:60]}"
        elif fe.get("instruction"):
            err += f" @{fe.get('pc')} {fe['instruction']}"
        ir = row.get("image_rewritten")
        print(
            f"{row['stratum'][:12]:12} {row['family'][:22]:22} {row.get('arch') or '?':4} {row['outcome']:15} "
            f"{row.get('n_api_total', 0):6} {len(row.get('hidden_indicators', [])):3} {len(row.get('hidden_hits', {})):3} "
            f"{len([c for c in row.get('carved_pe', []) if not c['plain_in_file']]):3} "
            f"{'' if ir is None else int(ir * 100):>5}  {err[:90]}"
        )
    print(collections.Counter(r["outcome"] for r in rows))


if __name__ == "__main__":
    main()
