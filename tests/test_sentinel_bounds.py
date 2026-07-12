"""Tests for import sentinel address-space bounds (issue #8).

Sentinels must stay inside the reserved hook window so a fetch always faults and
traps into the import dispatcher. Running out must raise, not silently hand back
an address outside the window (which could be backed by real memory and cause a
silent mis-dispatch).
"""

import pytest

import speakeasy.windows.common as winemu
from speakeasy import Speakeasy
from speakeasy.errors import WindowsEmuError


def test_sentinels_stay_in_reserved_window_then_raise(load_test_bin):
    se = Speakeasy()
    module = se.load_module(data=load_test_bin("argv_test_x86.exe.xz"))
    se.run_module(module)
    emu = se.emu

    seen = set()
    count = 0
    with pytest.raises(WindowsEmuError):
        for i in range(1_000_000):
            sentinel = emu.get_proc(f"mod{i}", f"func{i}")
            assert winemu.IMPORT_HOOK_ADDR <= sentinel < winemu.EMU_RESERVED_END
            assert sentinel not in seen
            seen.add(sentinel)
            count += 1

    assert count > 0  # allocation worked up to the boundary
    se.shutdown()
