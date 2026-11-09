#!/usr/bin/env python3
"""
Group the runs of a batch by how they stopped, mark out-of-scope stops, and write a Markdown digest that
the auditor uses to choose what to investigate.

usage: triage.py <summary.json> <speakeasy checkout> > triage.md

Scope rules (see README.md):
  * out-of-scope: unsupported API in a third-party / non-Windows DLL, .NET hosting (mscoree), AVX/VEX
    instructions (Unicorn backend limitation, tracked upstream of speakeasy), interpreters.
  * in-scope candidates: every other stop before the payload, in particular invalid_* faults inside the
    sample, internal_error, unsupported_api in Windows DLLs, max_api_count / timeout loops, and runs that
    exit cleanly while the sandbox/config ground truth says a payload exists.
"""

import collections
import glob
import json
import os
import re
import sys

WINDOWS_DLL_RE = re.compile(r"^(api-ms-win-|ext-ms-win-|msvcr|msvcp|vcruntime|ucrtbase|mfc)", re.I)


def windows_dlls(checkout):
    names = set()
    for arch in ("x86", "x64"):
        for f in glob.glob(os.path.join(checkout, "speakeasy", "resources", "win32", "exports", arch, "*.json")):
            names.add(os.path.splitext(os.path.basename(f))[0].lower())
    # common Windows DLLs that have no export manifest yet; extend when you meet one
    names |= {"shfolder", "icmp", "security", "dfshim", "psapi", "version", "winmm", "wtsapi32", "netapi32", "dnsapi",
              "iphlpapi", "secur32", "userenv", "dbghelp", "imagehlp", "wintrust", "crypt32", "bcrypt", "ncrypt", "winhttp",
              "wininet", "urlmon", "ole32", "oleaut32", "shell32", "shlwapi", "comctl32", "comdlg32", "gdiplus", "msimg32",
              "setupapi", "cfgmgr32", "rpcrt4", "mpr", "netutils", "srvcli", "wkscli", "powrprof", "uxtheme", "dwmapi",
              "imm32", "msctf", "rasapi32", "sensapi", "ntdll", "kernelbase", "kernel32", "user32", "gdi32", "advapi32"}
    return names


def classify(row, windlls):
    fe = row.get("first_error") or {}
    err = fe.get("error")
    api = (fe.get("api_name") or "").lower()
    instr = (fe.get("instruction") or "").lower()
    if row.get("outcome") == "HARNESS-CRASH":
        return "in-scope", "harness/emulator crash (no report)"
    if err == "unsupported_api" and api:
        dll = api.split(".", 1)[0]
        if dll == "mscoree":
            return "out-of-scope", "CLR hosting"
        if dll not in windlls and not WINDOWS_DLL_RE.search(dll):
            return "out-of-scope", f"third-party DLL {dll}"
    if err == "invalid_instruction" and instr.startswith("v"):
        return "out-of-scope", "AVX/VEX instruction (Unicorn limitation; known: speakeasy issue about AVX stop reason)"
    if err == "internal_error":
        return "in-scope", "speakeasy internal_error"
    return "in-scope", ""


def signature(row):
    fe = row.get("first_error") or {}
    err = fe.get("error") or ("clean-exit" if row.get("outcome") != "PAYLOAD" else "payload")
    detail = fe.get("api_name") or (fe.get("instruction") if fe.get("instruction") not in (None, "disasm_failed") else "")
    if err in ("max_api_count", "timeout"):
        detail = f"last={fe.get('last_api')}"
    return f"{err} {detail}".strip()


def main():
    rows = json.load(open(sys.argv[1]))
    windlls = windows_dlls(sys.argv[2])
    groups = collections.defaultdict(list)
    for r in rows:
        scope, why = classify(r, windlls)
        r["_scope"], r["_why"] = scope, why
        groups[(scope, signature(r))].append(r)

    out = collections.Counter(r["outcome"] for r in rows)
    print(f"# Triage digest\n\n{len(rows)} samples: {dict(out)}\n")
    print("Outcome legend: PAYLOAD = an oracle confirmed the inner payload; PARTIAL = dynamic code or rewrite seen; "
          "STOPPED = error before payload; RAN-NO-PAYLOAD = clean exit, no payload evidence.\n")
    for (scope, sig), rs in sorted(groups.items(), key=lambda kv: (kv[0][0] != "in-scope", -len(kv[1]), kv[0][1])):
        print(f"## [{scope}] {sig}  ({len(rs)} samples)")
        if rs[0]["_why"]:
            print(f"_{rs[0]['_why']}_\n")
        for r in rs:
            fe = r.get("first_error") or {}
            o = r.get("oracles") or {}
            fired = ",".join(k for k, v in o.items() if v) or "-"
            print(f"- `{r['sha256']}` {r['stratum']} {r['family']} {r.get('arch')} {r.get('type')}: outcome {r['outcome']} "
                  f"(oracles: {fired}); apis {r.get('n_api_total')}; pc {fe.get('pc')} {fe.get('pc_module') or ''}"
                  f"; last_api {fe.get('last_api')}")
            ctx = fe.get("context_summary")
            if ctx:
                print(f"  - context: {ctx[:200]}")
            if r.get("no_handler"):
                print(f"  - signature-fallback APIs: {', '.join(list(r['no_handler'])[:12])}")
            if r.get("unsupported"):
                print(f"  - unsupported: {r['unsupported']}")
            hid = [i for i in r.get("hidden_indicators") or [] if i not in (r.get("hidden_hits") or {})]
            sbh = [i for i in r.get("sandbox_hidden") or [] if i not in (r.get("sandbox_hits") or {})]
            if hid or sbh:
                print(f"  - hidden ground truth not found in emulation: config {hid[:4]} sandbox {sbh[:4]}")
            if r.get("notable_events"):
                print(f"  - events: {r['notable_events']}")
        print()


if __name__ == "__main__":
    main()
