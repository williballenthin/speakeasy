"""Regression tests for deferred IN/SYSCALL instruction-hook registration.

Hooks registered before the emulator engine is instantiated must be queued in
their own deferred lists and later installed as instruction hooks -- not folded
into the memory-write hook list (see issue #2).
"""

from speakeasy import Speakeasy


def _cb(*args, **kwargs):
    return None


def test_deferred_in_syscall_hooks_use_dedicated_lists():
    se = Speakeasy()

    # No engine yet -> hooks are deferred.
    assert se.emu is None

    se.add_IN_instruction_hook(_cb)
    se.add_SYSCALL_instruction_hook(_cb)

    # They must land in their own queues, not in mem_write_hooks.
    assert len(se.in_insn_hooks) == 1
    assert len(se.syscall_insn_hooks) == 1
    assert len(se.mem_write_hooks) == 0


def test_deferred_insn_hooks_installed_as_instruction_hooks(config):
    """After load, the deferred queues are drained via the instruction-hook path."""
    se = Speakeasy(config=config)
    se.add_IN_instruction_hook(_cb)
    se.add_SYSCALL_instruction_hook(_cb)

    # Loading shellcode instantiates the engine and _init_hooks drains the queues.
    sc = b"\x90\xc3"  # nop; ret
    addr = se.load_shellcode(data=sc, arch="x86")
    se._init_hooks()

    # Deferred queues drained; nothing leaked into mem_write_hooks.
    assert len(se.in_insn_hooks) == 0
    assert len(se.syscall_insn_hooks) == 0
    assert len(se.mem_write_hooks) == 0
    assert addr is not None
    se.shutdown()
