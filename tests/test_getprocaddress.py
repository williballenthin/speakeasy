"""Tests for GetProcAddress resolution (issue #7).

- lpProcName with a zero high word is an ordinal (MAKEINTRESOURCE), checked
  before any attempt to read it as a string pointer;
- the module handle is resolved against any loaded module, not only an exact
  PEB base match;
- an unknown handle returns NULL.
"""

import copy

from speakeasy import Speakeasy


def _emu(config, load_test_bin):
    cfg = copy.deepcopy(config)
    cfg["modules"]["functions_always_exist"] = True
    se = Speakeasy(config=cfg)
    module = se.load_module(data=load_test_bin("argv_test_x86.exe.xz"))
    se.run_module(module)
    return se


def test_getprocaddress_by_name(config, load_test_bin):
    se = _emu(config, load_test_bin)
    try:
        emu = se.emu
        k32 = emu.get_mod_by_name("kernel32")
        handler = emu.api.load_api_handler("kernel32")

        # Place the proc name well above 0xFFFF so it is not mistaken for an ordinal.
        name_ptr = emu.mem_map(64, base=0x30000000, tag="test.scratch")
        emu.write_mem_string("VirtualAlloc", name_ptr, 1)

        rv = handler.GetProcAddress(emu, [k32.base, name_ptr], {})
        assert rv != 0
        assert emu.import_table[rv] == ("kernel32", "VirtualAlloc")
    finally:
        se.shutdown()


def test_getprocaddress_by_ordinal_does_not_read_memory(config, load_test_bin):
    se = _emu(config, load_test_bin)
    try:
        emu = se.emu
        k32 = emu.get_mod_by_name("kernel32")
        handler = emu.api.load_api_handler("kernel32")

        # A small integer (high word zero) is an ordinal, handled without a read.
        rv = handler.GetProcAddress(emu, [k32.base, 7], {})
        assert rv != 0
        assert emu.import_table[rv] == ("kernel32", "ordinal_7")
    finally:
        se.shutdown()


def test_getprocaddress_unknown_handle_returns_null(config, load_test_bin):
    se = _emu(config, load_test_bin)
    try:
        emu = se.emu
        name_ptr = emu.mem_map(64, base=0x30000000, tag="test.scratch")
        emu.write_mem_string("VirtualAlloc", name_ptr, 1)
        handler = emu.api.load_api_handler("kernel32")

        rv = handler.GetProcAddress(emu, [0x999999, name_ptr], {})
        assert rv == 0
    finally:
        se.shutdown()
