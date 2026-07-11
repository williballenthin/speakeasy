"""Regression tests for composed import folding (issues #5 and #6).

normalize_import_miss must compose its folding rules: an import that needs both
DLL-name normalization (api-ms-win-*/CRT/winsock umbrella names) AND
function-name folding (A/W suffix, Zw/Nt) must still resolve to the shared
handler. Data-export lookups must fold the DLL name the same way.
"""

import pytest

from speakeasy import Speakeasy


@pytest.fixture
def emu(load_test_bin):
    se = Speakeasy()
    module = se.load_module(data=load_test_bin("argv_test_x86.exe.xz"))
    se.run_module(module)
    yield se.emu
    se.shutdown()


def resolve(emu, dll, name):
    """Mirror handle_import_func: direct lookup, then the miss/fold path."""
    _mod, attrs = emu.api.get_export_func_handler(dll, name)
    if attrs:
        return attrs[0]
    _mod, attrs = emu.normalize_import_miss(dll, name)
    return attrs[0] if attrs else None


# Every entry must resolve to the same handler as the canonical kernel32 name.
@pytest.mark.parametrize(
    "dll,name,expected",
    [
        ("kernel32", "CreateProcessA", "CreateProcess"),
        ("kernel32", "CreateProcessW", "CreateProcess"),
        # apiset umbrella + A/W suffix (the regression: previously UNRESOLVED)
        ("api-ms-win-core-processthreads-l1-1-1", "CreateProcess", "CreateProcess"),
        ("api-ms-win-core-processthreads-l1-1-1", "CreateProcessA", "CreateProcess"),
        ("api-ms-win-core-processthreads-l1-1-1", "CreateProcessW", "CreateProcess"),
        ("api-ms-win-core-libraryloader-l1-2-0", "LoadLibraryExW", "LoadLibraryEx"),
        # CRT umbrella name folds to msvcrt
        ("api-ms-win-crt-string-l1-1-0", "strlen", "strlen"),
        # Zw/Nt folding still works via ntdll -> ntoskrnl bridge
        ("ntdll", "NtCreateFile", "ZwCreateFile"),
    ],
)
def test_import_folding_composes(emu, dll, name, expected):
    assert resolve(emu, dll, name) == expected


def test_data_handler_folds_dll_name(emu):
    # msvcrt exposes the _acmdln data export; CRT apiset names must fold to it.
    canonical = "msvcrt"
    apiset = "api-ms-win-crt-runtime-l1-1-0"
    sym = "_acmdln"

    # Sanity: the raw apiset name has no direct data handler ...
    assert emu.api.get_data_export_handler(apiset, sym)[1] is None
    # ... but the folding lookup resolves it, same as the canonical name.
    assert emu.lookup_data_handler(canonical, sym)[1] is not None
    assert emu.lookup_data_handler(apiset, sym)[1] is not None
