"""Round-trip tests for calling-convention argument marshalling (issue #1).

set_func_args (used to call into emulated code) must lay arguments out exactly
where get_func_argv reads them, for every convention and arg count -- including
x86 fastcall (first two args in ECX/EDX) and x64 with more than four args
(overflow args above the 32-byte shadow space).
"""

import pytest

import speakeasy.winenv.arch as arch
from speakeasy import Speakeasy

X86_CONVS = [arch.CALL_CONV_CDECL, arch.CALL_CONV_STDCALL, arch.CALL_CONV_FASTCALL]
ARG_COUNTS = [0, 1, 2, 3, 4, 5, 8]


def _emu(load_test_bin, bin_name):
    se = Speakeasy()
    module = se.load_module(data=load_test_bin(bin_name))
    se.run_module(module)
    return se


def _roundtrip(se, conv, argc):
    emu = se.emu
    args = [(i + 1) * 0x11 for i in range(argc)]
    sp = emu.get_stack_ptr()
    emu.set_func_args(sp, 0xDEADBEEF, *args, conv=conv)
    return args, emu.get_func_argv(conv, argc)


@pytest.mark.parametrize("conv", X86_CONVS)
@pytest.mark.parametrize("argc", ARG_COUNTS)
def test_x86_arg_roundtrip(load_test_bin, conv, argc):
    se = _emu(load_test_bin, "argv_test_x86.exe.xz")
    try:
        args, got = _roundtrip(se, conv, argc)
        assert got == args
    finally:
        se.shutdown()


@pytest.mark.parametrize("argc", ARG_COUNTS)
def test_x64_arg_roundtrip(load_test_bin, argc):
    se = _emu(load_test_bin, "argv_test_x64.exe.xz")
    try:
        args, got = _roundtrip(se, arch.CALL_CONV_STDCALL, argc)
        assert got == args
    finally:
        se.shutdown()
