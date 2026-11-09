#!/usr/bin/env python3
"""
Emulate one sample with speakeasy and save: report.json, memory regions that are not system DLLs
(heap and stack included, which --snapshot-memory-regions leaves out), and the API fallback log.

usage: run_one.py <sample> <outdir>      (SE_CHILDREN=0 disables child-process emulation)
"""

import json
import logging
import os
import re
import sys
import traceback

import speakeasy

MAX_REGION = 64 * 1024 * 1024

CONFIG = {
    "max_run_time": 30,
    "max_total_time": 120,
    "max_api_calls": 20000,
    "keep_memory_on_free": True,
    "analysis": {"strings": False, "memory_tracing": False, "coverage": False},
}


class FallbackLog(logging.Handler):
    """Record the calls that ran from a signature (no handler) and the unsupported APIs."""

    PAT = re.compile(r"no handler for (\S+?);|Unsupported API: (\S+)")

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.no_handler = {}
        self.unsupported = {}

    def emit(self, record):
        try:
            msg = record.getMessage()
        except Exception:
            return
        m = self.PAT.search(msg)
        if not m:
            return
        if m.group(1):
            self.no_handler[m.group(1)] = self.no_handler.get(m.group(1), 0) + 1
        else:
            self.unsupported[m.group(2)] = self.unsupported.get(m.group(2), 0) + 1


def main():
    sample, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(os.path.join(outdir, "regions"), exist_ok=True)
    fb = FallbackLog()
    root = logging.getLogger("speakeasy")
    root.setLevel(logging.DEBUG)
    root.addHandler(fb)
    root.propagate = False

    status = {"sample": sample, "harness_error": None}
    dyn = []
    image_base = None
    se = speakeasy.Speakeasy(config=CONFIG)
    try:
        se.add_dyn_code_hook(lambda emu, region: dyn.append(getattr(region, "tag", str(region))))
        module = se.load_module(sample)
        image_base = module.base
        status["image_base"] = hex(module.base)
        se.run_module(module, all_entrypoints=True, emulate_children=os.environ.get("SE_CHILDREN", "1") == "1")
    except Exception as e:
        status["harness_error"] = f"{type(e).__name__}: {e}"
        status["harness_traceback"] = traceback.format_exc()[-3000:]

    try:
        with open(os.path.join(outdir, "report.json"), "w") as f:
            f.write(se.get_json_report())
    except Exception as e:
        status["report_error"] = f"{type(e).__name__}: {e}"

    regions = []
    try:
        for tag, base, size, is_free, _proc, data in se.get_memory_dumps():
            tag = tag or "untagged"
            # system DLLs are speakeasy's own decoys; the sample image itself is kept
            if tag.startswith("emu.module.") and base != image_base:
                continue
            if size > MAX_REGION or not data.strip(b"\x00"):
                continue
            fn = f"{base:016x}_{re.sub(r'[^A-Za-z0-9_.-]', '_', tag)[:80]}.bin"
            with open(os.path.join(outdir, "regions", fn), "wb") as f:
                f.write(data)
            regions.append({"file": fn, "tag": tag, "base": hex(base), "size": size, "free": is_free})
    except Exception as e:
        status["dump_error"] = f"{type(e).__name__}: {e}"

    status["regions"] = regions
    status["dyn_code_hooks"] = dyn
    status["no_handler"] = fb.no_handler
    status["unsupported"] = fb.unsupported
    with open(os.path.join(outdir, "harness.json"), "w") as f:
        json.dump(status, f, indent=1)
    try:
        se.shutdown()
    except Exception:
        pass


if __name__ == "__main__":
    main()
