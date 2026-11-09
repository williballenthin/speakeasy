#!/usr/bin/env python3
"""
Select a varied set of native Windows loaders and packed samples from VirusTotal for a first-seen
window, and download them.

The strata come from independent signals, so that no single labeller (in particular Mandiant
Backscatter configs, which share technology with speakeasy) decides what we test:

  config      VT malware_config (Backscatter) - capped share
  packer      classic compressors (in-place unpacking)
  protector   commercial protectors
  sbx-inject  sandbox-observed injection / hollowing
  yara        crowdsourced YARA loader/shellcode rules
  comment     community comments (loader, crypter, injector, shellcode)
  evasion     sandbox anti-analysis tags
  unlabeled   high-detection files that look packed (least biased)

In each result page the candidates are ranked by an interest score from free attributes. Each pick is
then checked against the VT sandbox behaviour summary (plain API calls). Interpreters, self-extracting
archives and other out-of-scope files are dropped, and evidence of memory manipulation raises the score.

usage:
  collect.py --since 2026-11-01 --until 2026-11-08 --target 60 --out WORK/data \
             --seen scripts/vt_audit/seen.txt --download
"""

import argparse
import collections
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse

VT = "https://www.virustotal.com/api/v3"

BASE = "fs:{since}+ fs:{until}- p:5+ NOT tag:assembly size:3MB-"
INJ_TARGETS = "explorer.exe svchost.exe regasm.exe msbuild.exe notepad.exe rundll32.exe dllhost.exe applaunch.exe"
CLASSIC_PACKERS = "upx mpress aspack pecompact petite fsg nspack mew kkrunchy upack yoda"
PROTECTORS = "themida vmprotect enigma obsidium asprotect pelock"


def _or(prefix, words):
    return "(" + " OR ".join(f"{prefix}:{w}" for w in words.split()) + ")"


# name, query (without BASE), share of the target, result order
STRATA = [
    ("config-exe-x86", "type:peexe NOT tag:64bits have:malware_config", 0.12, "unique_sources-"),
    ("config-exe-x64", "type:peexe tag:64bits have:malware_config", 0.08, ""),
    ("config-dll", "type:pedll have:malware_config", 0.05, ""),
    ("packer", "type:peexe " + _or("detectiteasy", CLASSIC_PACKERS) + " NOT have:malware_config", 0.10, "unique_sources-"),
    ("protector", "type:peexe " + _or("detectiteasy", PROTECTORS) + " NOT have:malware_config", 0.05, "unique_sources-"),
    (
        "sbx-inject",
        "type:pe (attack_technique:T1055.012 OR "
        + " OR ".join(f"behaviour_injected_processes:{t}" for t in INJ_TARGETS.split())
        + ") NOT have:malware_config",
        0.15,
        "",
    ),
    ("yara", "type:pe (crowdsourced_yara_rule:*loader* OR crowdsourced_yara_rule:*shellcode*) NOT have:malware_config", 0.12, ""),
    ("comment", "type:pe (comment:loader OR comment:crypter OR comment:injector OR comment:shellcode) NOT have:malware_config", 0.10, ""),
    ("evasion", "type:peexe (tag:detect-debug-environment OR tag:long-sleeps OR tag:checks-user-input) NOT have:malware_config", 0.10, ""),
    ("unlabeled", "(type:peexe OR type:pedll) p:15+ NOT have:malware_config", 0.13, "unique_sources-"),
]

# --- scope: what speakeasy could reasonably support -------------------------------------------------
# Interpreters, installers, managed code and big runtimes are not emulation targets.
REJECT_DIE = re.compile(
    r"nsis|nullsoft|inno ?setup|autoit|autohotkey|pyinstaller|py2exe|nuitka|\.net|installshield|wise installer|"
    r"setup factory|smart install|advanced installer|7-zip|winrar|sfx|electron|^go$|golang|java|nodejs|"
    r"squirrel|msi|visual basic",
    re.I,
)
# File infectors: the "payload" is a legitimate host program, and they flood every query.
NOISE_LABEL = re.compile(r"^virus\.|virut|sality|neshta|expiro|floxif|jadtre|parite|mandaph|ramnit|induc|madang|jeefo", re.I)
# Imports that mean "needs a third-party runtime" - speakeasy will never model these.
THIRD_PARTY_DLL = re.compile(
    r"^(qt\d|python\d|libpython|libcrypto|libssl|libcurl|sqlite3|node|jvm|java|msvbvm|vb40|mono|libgcc|libstdc|"
    r"libwinpthread|cygwin|msys|wx|gtk|glib|libglib|sdl|opengl32sw|d3dcompiler|libeay32|ssleay32|zlib1|"
    r"boost_|tbb|icu|av(codec|format|util)|nvcuda|cudart|steam_api|unity|mfc\d+u?d?\.dll$)",
    re.I,
)
CLR_IMPORT = re.compile(r"^mscoree\.dll$", re.I)
# Sandbox artefacts that reveal an interpreter or SFX the static packer detector (DIE) missed.
INTERPRETER_SIGNS = re.compile(
    r"AHK Keybd|autohotkey|RarSFX|\\7zS|\\_MEI\d|\\is-[A-Z0-9]{5}\.tmp|\\ns[a-z0-9]{3,5}\.tmp|python3?\d*\.dll|"
    r"AutoIt|\.au3",
    re.I,
)
INTEREST_TAGS = {"detect-debug-environment", "long-sleeps", "checks-user-input", "runtime-modules", "direct-cpu-clock-access"}
MEM_CALLS = re.compile(
    r"virtualalloc|virtualprotect|writeprocessmemory|ntwritevirtualmemory|mapviewofsection|createremotethread|"
    r"queueuserapc|setthreadcontext|resumethread|ntunmapviewofsection|ntallocatevirtualmemory",
    re.I,
)


def vt_get(path, params=None, retries=4):
    url = f"{VT}/{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    err = b""
    for attempt in range(retries):
        r = subprocess.run(
            ["curl", "-sS", "--max-time", "120", "-H", f"x-apikey: {os.environ['VT_API_KEY']}", url],
            capture_output=True,
            check=False,
        )
        if r.returncode == 0:
            try:
                return json.loads(r.stdout)
            except json.JSONDecodeError:
                err = r.stdout[:200]
        else:
            err = r.stderr
        time.sleep(2**attempt)
    raise RuntimeError(f"VT request failed: {path}: {err!r}")


def search(query, order="", limit=300):
    params = {"query": query, "limit": limit}
    if order:
        params["order"] = order
    d = vt_get("intelligence/search", params)
    if "error" in d:
        raise RuntimeError(f"{query}: {d['error']}")
    return d.get("data", []), d.get("meta", {})


def die_values(a):
    return a.get("detectiteasy", {}).get("values", [])


def config_families(a):
    mc = a.get("malware_config") or {}
    return sorted({f.get("family") for f in mc.get("families", []) if f.get("family")})


def family_key(a):
    fams = config_families(a)
    if fams:
        return "+".join(fams)
    for y in a.get("crowdsourced_yara_results") or []:
        m = re.search(
            r"Win(?:dows)?_?(?:Trojan|Backdoor|Loader|Ransomware|Infostealer|Hacktool)?_?([A-Za-z0-9]+)", y.get("rule_name", "")
        )
        if m and len(m.group(1)) > 3 and m.group(1).lower() not in ("generic", "trojan", "shellcode", "loader", "packer"):
            return m.group(1).lower()
    ptc = a.get("popular_threat_classification") or {}
    names = ptc.get("popular_threat_name") or []
    if names:
        return names[0]["value"].lower()
    return (ptc.get("suggested_threat_label") or "unknown").split("/")[-1]


def packer_key(a):
    names = [v["name"] for v in die_values(a) if v.get("type") in ("Packer", "Protector", "Cryptor", "Joiner")]
    return ",".join(sorted(set(names))) or "-"


def imported_dlls(a):
    return [x.get("library_name", "") for x in (a.get("pe_info") or {}).get("import_list", [])]


def looks_packed(a):
    pe = a.get("pe_info") or {}
    secs = pe.get("sections") or []
    imps = sum(len(x.get("imported_functions", [])) for x in pe.get("import_list", []))
    max_ent = max((x.get("entropy", 0) for x in secs), default=0)
    std = r"\.(text|rdata|data|pdata|rsrc|reloc|tls|idata|edata|bss|CRT|didat|gfids|00cfg|xdata)"
    odd = any(x.get("name") and not re.fullmatch(std, x.get("name", "")) for x in secs)
    return max_ent >= 7.2 or imps <= 15 or odd


def reject_reason(a, stratum):
    if a.get("type_tag") not in ("peexe", "pedll"):
        return f"type:{a.get('type_tag')}"
    mt = (a.get("pe_info") or {}).get("machine_type")
    if mt not in (332, 34404):
        return f"machine:{mt}"
    for v in die_values(a):
        if v.get("type") in ("Installer", "Sfx", "SFX"):
            return f"installer:{v.get('name')}"
        if REJECT_DIE.search(v.get("name", "")):
            return f"die:{v.get('name')}"
    label = (a.get("popular_threat_classification") or {}).get("suggested_threat_label") or ""
    if NOISE_LABEL.search(label) or NOISE_LABEL.search(json.dumps(a.get("popular_threat_classification") or {})):
        if not config_families(a):
            return "file-infector"
    for dll in imported_dlls(a):
        if CLR_IMPORT.search(dll):
            return "clr-host"
        if THIRD_PARTY_DLL.search(dll):
            return f"third-party:{dll}"
    if stratum == "unlabeled" and not looks_packed(a):
        return "not-packed"
    return None


def interest(a):
    score = min(2, len(set(a.get("tags", [])) & INTEREST_TAGS))
    score += 1 if a.get("crowdsourced_yara_results") else 0
    score += 1 if (a.get("threat_severity") or {}).get("threat_severity_level") == "SEVERITY_HIGH" else 0
    score += 1 if len(a.get("sandbox_verdicts") or {}) >= 2 else 0
    score += 1 if (a.get("unique_sources") or 0) >= 2 else 0
    score += 1 if looks_packed(a) else 0
    return score


def behaviour_check(sha):
    """Return (bonus, reason). bonus is None when the sample must be dropped."""
    bs = vt_get(f"files/{sha}/behaviour_summary").get("data", {})
    blob = json.dumps(bs)
    if INTERPRETER_SIGNS.search(blob):
        return None, "sandbox:interpreter-or-sfx"
    bonus = 0
    bonus += 2 if bs.get("processes_injected") else 0
    bonus += 2 if bs.get("payloads_extracted") else 0
    bonus += 1 if any(MEM_CALLS.search(c) for c in bs.get("calls_highlighted") or []) else 0
    bonus += 1 if (bs.get("memory_pattern_domains") or bs.get("memory_pattern_urls") or bs.get("mutexes_created")) else 0
    return bonus, None


def summarize(o, stratum, score):
    a = o["attributes"]
    pe = a.get("pe_info") or {}
    return {
        "sha256": o["id"],
        "stratum": stratum,
        "family": family_key(a),
        "config_families": config_families(a),
        "packer": packer_key(a),
        "die": [f"{v.get('type')}:{v.get('name')}" for v in die_values(a)],
        "type": a.get("type_tag"),
        "arch": {332: "x86", 34404: "x64"}.get(pe.get("machine_type")),
        "size": a.get("size"),
        "imphash": pe.get("imphash"),
        "vhash": a.get("vhash"),
        "positives": (a.get("last_analysis_stats") or {}).get("malicious"),
        "label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label"),
        "yara": sorted({y.get("rule_name") for y in a.get("crowdsourced_yara_results") or []})[:8],
        "severity": (a.get("threat_severity") or {}).get("threat_severity_level"),
        "first_seen": a.get("first_submission_date"),
        "unique_sources": a.get("unique_sources"),
        "tags": a.get("tags", []),
        "imports": imported_dlls(a),
        "interest": score,
        "malware_config": a.get("malware_config"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", required=True, help="first-seen lower bound, YYYY-MM-DD")
    ap.add_argument("--until", required=True, help="first-seen upper bound, YYYY-MM-DD")
    ap.add_argument("--target", type=int, default=60)
    ap.add_argument("--seen", help="file with sha256s assessed in earlier runs")
    ap.add_argument("--out", required=True)
    ap.add_argument("--download", action="store_true")
    args = ap.parse_args()

    seen = set()
    if args.seen and os.path.exists(args.seen):
        seen = {x.strip() for x in open(args.seen) if x.strip() and not x.startswith("#")}
    base = BASE.format(since=args.since, until=args.until)

    picked, rejects = [], collections.Counter()
    fam_seen, imphash_seen, vhash_seen = set(), set(), set()
    for name, q, share, order in STRATA:
        quota = max(1, round(share * args.target))
        cands = []
        data, meta = search(f"{q} {base}", order)
        print(f"[{name}] hits~{meta.get('total_hits')} page={len(data)}", file=sys.stderr)
        for o in data:
            r = reject_reason(o["attributes"], name)
            if r:
                rejects[r.split(":")[0]] += 1
                continue
            cands.append((interest(o["attributes"]), o))
        cands.sort(key=lambda t: -t[0])
        n = 0
        for score, o in cands:
            if n >= quota:
                break
            a = o["attributes"]
            fam = family_key(a).lower()
            imph = (a.get("pe_info") or {}).get("imphash")
            vh = a.get("vhash")
            if o["id"] in seen or any(p["sha256"] == o["id"] for p in picked):
                rejects["seen"] += 1
                continue
            if fam in fam_seen or (imph and imph in imphash_seen) or (vh and vh in vhash_seen):
                rejects["duplicate"] += 1
                continue
            bonus, why = behaviour_check(o["id"])
            if bonus is None:
                rejects[why] += 1
                continue
            picked.append(summarize(o, name, score + bonus))
            fam_seen.add(fam)
            if imph:
                imphash_seen.add(imph)
            if vh:
                vhash_seen.add(vh)
            n += 1

    os.makedirs(args.out, exist_ok=True)
    manifest = {"window": [args.since, args.until], "rejects": dict(rejects), "samples": picked}
    json.dump(manifest, open(os.path.join(args.out, "manifest.json"), "w"), indent=1)
    print(
        json.dumps({"picked": len(picked), "by_stratum": collections.Counter(p["stratum"] for p in picked), "rejects": rejects}),
        file=sys.stderr,
    )

    if args.download:
        sdir = os.path.join(args.out, "samples")
        os.makedirs(sdir, exist_ok=True)
        for s in picked:
            dst = os.path.join(sdir, s["sha256"])
            if os.path.exists(dst):
                continue
            subprocess.run(
                ["curl", "-sS", "-L", "--max-time", "300", "-o", dst, "-H", f"x-apikey: {os.environ['VT_API_KEY']}",
                 f"{VT}/files/{s['sha256']}/download"],
                check=True,
            )
            os.chmod(dst, 0o400)


if __name__ == "__main__":
    main()
