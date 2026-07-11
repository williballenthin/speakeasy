"""Regression test for curr_mod being refreshed per run (issue #11).

Run-to-run transitions normally happen inside a single Unicorn emu_start (via
PC rewrite in the code hook), so curr_mod was not refreshed at the boundary. A
run starting in a different module than the previous one would leave a stale
curr_mod, and handle_import_func consults curr_mod.import_table first.
"""

from speakeasy import Speakeasy
from speakeasy.profiler import Run


def test_prepare_run_context_refreshes_curr_mod(load_test_bin):
    se = Speakeasy()
    module = se.load_module(data=load_test_bin("dll_test_x86.dll.xz"))
    se.run_module(module)
    emu = se.emu

    ep = module.base + module.ep

    # Simulate the stale-module condition: some *other* loaded module (whose
    # range does not contain the new run's entry) is left in curr_mod.
    stale = next(m for m in emu.modules if not (m.base <= ep < m.base + m.image_size))
    emu.curr_mod = stale

    run = Run()
    run.type = "probe"
    run.start_addr = ep
    run.args = []
    emu._prepare_run_context(run)

    # curr_mod must now reflect the module containing the run's entry point.
    assert emu.curr_mod is not stale
    assert emu.curr_mod.base == module.base

    se.shutdown()
