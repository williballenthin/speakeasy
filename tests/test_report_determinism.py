"""Determinism of handle/object-id allocation across emulator instances (issue #3).

Handle/object-id counters were class attributes shared across every emulator in
a process, so the same sample emulated twice produced different pid/tid/handle
values. Each fresh emulator now reseeds them.
"""

from speakeasy import Speakeasy
from speakeasy.windows.objman import KernelObject


def _run(data):
    se = Speakeasy()
    module = se.load_module(data=data)
    se.run_module(module, all_entrypoints=True)
    report = se.get_report()
    result = [(ep.pid, ep.tid) for ep in report.entry_points]
    se.shutdown()
    return result


def test_pid_tid_deterministic_across_instances(load_test_bin):
    data = load_test_bin("dll_test_x86.dll.xz")
    first = _run(data)
    second = _run(data)
    assert first == second
    # Sanity: the sample actually produced multiple runs with ids.
    assert len(first) >= 2


def test_construction_reseeds_object_id_counter(load_test_bin):
    # Pollute the shared class counter, then construct a fresh emulator.
    KernelObject.curr_id = 0xABCDE
    se = Speakeasy()
    se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
    # The counter was reseeded to its base (0x400), not left polluted.
    assert KernelObject.curr_id < 0xABCDE
    se.shutdown()
