"""Regression tests for per-run CPU/stack reset (issues #9 and #10).

Run-to-run transitions reuse the same Unicorn instance, so without an explicit
reset the next run inherits the previous run's registers, EFLAGS (notably the
direction flag), and stack contents.
"""

import speakeasy.winenv.arch as arch
from speakeasy import Speakeasy


def test_registers_and_eflags_do_not_bleed_between_runs(load_test_bin):
    se = Speakeasy()
    module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
    emu = se.emu

    export_addrs = {e.address for e in module.get_exports() if e.address}
    observed = []
    seen = set()

    def code_hook(_emu, addr, size, ctx=None):
        if addr in export_addrs and addr not in seen:
            seen.add(addr)
            esi = emu.reg_read(arch.X86_REG_ESI)
            eflags = emu.reg_read(arch.X86_REG_EFLAGS)
            observed.append((esi, eflags))
            # Dirty state that a later run would (previously) inherit.
            emu.reg_write(arch.X86_REG_ESI, 0xDEAD1234)
            emu.reg_write(arch.X86_REG_EFLAGS, eflags | 0x400)  # set DF
        return True

    se.add_code_hook(code_hook)
    se.run_module(module, all_entrypoints=True)

    # At least two export runs, and every one starts from a clean context.
    assert len(observed) >= 2
    for esi, eflags in observed:
        assert esi == 0, f"ESI bled across runs: {esi:#x}"
        assert eflags & 0x400 == 0, "direction flag bled across runs"

    se.shutdown()


def test_clear_run_stack_zeroes_stack_region(load_test_bin):
    se = Speakeasy()
    module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
    se.run_module(module)
    emu = se.emu

    mm = emu.get_address_map(emu.stack_base - 1)
    assert mm is not None and mm.tag.startswith("emu.stack")

    marker = b"\x41" * 64
    emu.mem_write(mm.base + mm.size // 2, marker)
    assert emu.mem_read(mm.base + mm.size // 2, len(marker)) == marker

    emu._clear_run_stack()

    assert emu.mem_read(mm.base + mm.size // 2, len(marker)) == b"\x00" * len(marker)

    se.shutdown()
