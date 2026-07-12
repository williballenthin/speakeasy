"""Tests for Unicorn engine lifecycle on shutdown (issue #4).

shutdown() previously kept the native Unicorn engine alive on purpose, leaking a
full engine (and its mapped memory) per emulation. On the required Unicorn
(>=2.1.4) the engine can be released safely.
"""

import gc
import weakref

import unicorn

from speakeasy import Speakeasy


def _live_uc_count():
    gc.collect()
    return sum(1 for o in gc.get_objects() if isinstance(o, unicorn.Uc))


def test_engine_released_after_shutdown(load_test_bin):
    se = Speakeasy()
    module = se.load_module(data=load_test_bin("argv_test_x86.exe.xz"))
    se.run_module(module)

    ref = weakref.ref(se.emu.emu_eng.emu)
    se.shutdown()
    gc.collect()

    assert ref() is None  # the Uc engine was reclaimed


def test_second_emulator_works_after_first_shutdown(load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")

    first = Speakeasy()
    first.run_module(first.load_module(data=data))
    first.shutdown()

    second = Speakeasy()
    second.run_module(second.load_module(data=data))
    assert second.get_report() is not None
    second.shutdown()


def test_no_engine_leak_across_runs(load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")
    base = _live_uc_count()
    for _ in range(6):
        se = Speakeasy()
        se.run_module(se.load_module(data=data))
        se.shutdown()
        del se
    assert _live_uc_count() <= base + 1
