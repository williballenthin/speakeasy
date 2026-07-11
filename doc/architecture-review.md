# Architecture review: correctness and library use

Speakeasy's API coverage is driven by real-world malware and is battle-tested; this review is
deliberately *not* about adding more handlers. It focuses on two things the sample-driven CLI
path exercises poorly:

1. **Correctness bugs** in the emulation primitives, and
2. **Using Speakeasy as a library** — driving it programmatically (`call()`, hooks, memory,
   batch loops, custom harnesses) rather than "load a PE, dump a report."

Every bug below was found by driving the *library* API in ways the CLI never does, and each is
reproducible from a few lines of Python. That is the theme: the emulator core is solid on the
one path the sample suite covers, and under-specified/under-tested everywhere else.

## Confirmed correctness bugs

### 1. `set_func_args` marshals x86 fastcall and x64 >4-arg calls incorrectly

`binemu.py:set_func_args` is the primitive used to *call into* emulated code (`Speakeasy.call`,
API callbacks, `setup_callback`). It disagrees with the emulator's own argument *reader*,
`get_func_argv`, so a call and its callee see different arguments.

- **x86 fastcall:** `set_func_args` has no fastcall branch — it pushes *all* arguments onto the
  stack. But `get_func_argv(FASTCALL)` and `do_call_return(FASTCALL)` both expect the first two
  in ECX/EDX. Round-trip:
  ```
  x86 fastcall  in =[0x11,0x22,0x33,0x44,0x55,0x66]
                out=[0x10b, 0x1300000, 0x11, 0x22, 0x33, 0x44]   # ECX/EDX garbage, args shifted
  ```
- **x64, >4 args:** `set_func_args` reserves the 32-byte shadow space and then writes stack
  args 5+ *immediately above the return address* — i.e. inside the shadow region — instead of
  above it. `get_func_argv` reads them at `RSP+0x28`/`RSP+0x30` per the Windows x64 ABI, so they
  don't match:
  ```
  x64 stdcall   in =[0x11,0x22,0x33,0x44,0x55,0x66]
                out=[0x11,0x22,0x33,0x44, 0x0, 0x8970]           # args 5,6 read from wrong slots
  ```

Root cause is ordering: the function reserves shadow space *before* writing the overflow args,
placing the shadow gap above the args rather than between the return address and the args. Both
cases are latent in the CLI because standard entry points and callbacks (DllMain=3, thread
proc=1, TLS=3) stay within register args — but they are live bugs for any library-driven call
with overflow/fastcall arguments, and they make the three cooperating routines
(`set_func_args` / `get_func_argv` / `do_call_return`) mutually inconsistent on fastcall.

### 2. Deferred `IN` / `SYSCALL` instruction hooks are registered as memory-write hooks

`Speakeasy.add_IN_instruction_hook` and `add_SYSCALL_instruction_hook` (`speakeasy.py:494-524`)
support the documented "register hooks before loading a module" pattern by queuing into a
pending list until the engine exists. Their pre-init branch is a copy-paste of the mem-write
hook and appends to `self.mem_write_hooks`:

```python
def add_IN_instruction_hook(self, cb, begin=1, end=0):
    if not self.emu:
        self.mem_write_hooks.append((cb, begin, end))   # wrong list
        return
    return self.emu.add_instruction_hook(cb, ..., insn=218)
```

`_init_hooks` then drains `mem_write_hooks` through `add_mem_write_hook`, so the callback is
installed as a memory-write hook (different event, different callback signature) and the
`IN`/`SYSCALL` hook never fires. Only the deferred path is affected; registering after load
works. Confirmed: after two deferred registrations, `mem_write_hooks` has 2 entries and there is
no instruction hook.

### 3. Object id / handle counters are class-global, so reports are non-deterministic

Handle and object-id counters are **class attributes**, shared across every emulator instance in
a process: `KernelObject.curr_handle`/`curr_id` (`objman.py:78-79`) plus eight more
(`Console`, `sessman`, `netman`, three in `fileman`, `regman`, `cryptman`). Running the *same*
sample twice in one process yields different identifiers:

```
run #1: tid=1076
run #2: tid=1312
```

Since `pid`/`tid` are emitted into the JSON report (`entry_points[*].pid/tid`), and handles feed
object lookups, batch/library use produces non-reproducible reports and defeats result caching or
golden comparison. The test suite already works around this with an autouse
`_reset_handle_counters` fixture (`tests/conftest.py:34`) that resets these class attributes
between every test — direct evidence the state should be per-instance.

### 4. `shutdown()` never releases the Unicorn engine

`Speakeasy.shutdown` (`speakeasy.py:403`) removes hooks but deliberately leaves the `Uc` object
alive, because `uc_close` "has process-global side effects that can corrupt other live engine
instances." The engine (and all its mapped memory) therefore leaks on every run:

```
Unicorn engine still ALIVE after shutdown()+gc -> leaked
```

For a long-lived service that emulates many samples in-process this is an unbounded leak. It is
also *why* the CLI defaults to forking a child process per sample (`--no-mp` to opt out): the
in-process lifecycle isn't clean, so the CLI sidesteps it. Now that `unicorn>=2.1.4` is required,
per-instance close should be re-evaluated so the library has a real teardown path.

## Exercising Speakeasy as a library

The sample suite asserts *behavioral* facts ("these APIs were called, these IOCs appeared") over
the one path the CLI drives. It does not test the emulator as a set of composable primitives,
which is how library users actually consume it — and that untested surface is where the bugs
above live. The following harnesses target that surface directly; each maps to a bug class it
would have caught.

1. **Determinism / idempotency.** Run one sample N times in a single process and byte-diff the
   JSON reports (modulo timestamp/runtime). Same input + config must give an identical report.
   Catches bug #3 and any other global-state leakage immediately.

2. **Instance isolation.** Instantiate two `Speakeasy` objects, interleave loads/runs, and assert
   no cross-talk in handles, object ids, or memory. Makes class-global state a test failure rather
   than a fixture workaround.

3. **Calling-convention round-trip (property-based).** For every convention and arch, assert
   `set_func_args(args)` followed by `get_func_argv(conv, len(args))` returns `args`, for
   arg counts spanning register-only, boundary, and overflow. Pure primitive, no sample needed.
   Directly catches bug #1. Extend to `do_call_return` stack-pointer accounting.

4. **Memory-primitive invariants (property-based, e.g. Hypothesis).**
   - `mem_write`/`mem_read` round-trip across page boundaries and protections.
   - alloc/free: freed addresses become invalid; live allocations never overlap; `mem_alloc(n)`
     returns a page-aligned region ≥ n; randomized alloc/free stress against the sub-page block
     allocator and `get_valid_ranges`.
   - `read/write_mem_string` round-trip for width 1/2, `max_chars`, embedded nulls.
   - `push_stack`/`pop_stack` symmetry; `EmuStruct` pack/cast round-trip for x86 and x64 pointer
     sizes.

5. **Hook-contract tests.** For every `add_*_hook`, register it both *before* and *after* engine
   init and assert it actually fires with the correct callback signature and that the two paths are
   equivalent. Catches bug #2 and pins the deferred-vs-immediate contract.

6. **Lifecycle / leak bounds.** Emulate K samples in a loop in one process and assert live
   Unicorn engine count and RSS stay bounded. Catches bug #4 and defines what `shutdown()`
   guarantees.

7. **Reuse semantics.** Specify and test what `load_module` twice on one instance, `call()` after
   a run, and `resume()` do — today these are underspecified. Either cleanly reset state or reject
   the operation; test whichever contract is chosen.

8. **Robustness / fuzzing through the API.** Feed malformed PEs and random shellcode through
   `load_module`/`load_shellcode` and assert a typed `SpeakeasyError` (never a host crash or hang)
   within the configured timeout. A library must not take down its host; the CLI's child-process
   watchdog currently provides this guarantee that the in-process library does not.

9. **Snapshot / restore as a first-class capability.** Expose save/restore of emulator state
   (registers + memory maps + manager state). This is both a feature (branch execution, resume
   from a decrypt point) and a powerful test oracle (drive to a point, snapshot, run two ways,
   diff). It also forces the per-instance-state cleanup that bugs #3 and #4 need.

Items 1, 2, 3, 5, and 6 are cheap to stand up, run without any sample binary, and would have
caught four of the four bugs above. They are the highest-leverage next step for "make it more
correct" — a small property/contract test layer under the existing pytest suite, plus a
determinism gate in CI.
