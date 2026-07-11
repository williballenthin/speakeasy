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

## Import resolution correctness

Import resolution runs through several folding rules in `normalize_import_miss`
(`winemu.py:1572`): strip an `A`/`W` suffix, fold `Zw*`/`Nt*` together, bridge `ntdll`→
`ntoskrnl`, and normalize the DLL name (`normalize_dll_name`, `common.py:158`) so that
CRT variants, `winsock`/`wsock32`, and `api-ms-win-crt`/`api-ms-win-core` umbrella names funnel
into `msvcrt`/`ws2_32`/`kernel32`. These rules are individually correct but do not compose.

### 1. A DLL that needs normalization *and* a folded function name fails to resolve

The suffix and DLL-name rules are mutually exclusive, and the suffix retry uses the *original*
(un-normalized) DLL name:

```python
if alt_imp_api:                                          # A/W (or Zw/Nt) produced an alt name
    mod, func_attrs = self.api.get_export_func_handler(dll, alt_imp_api)          # original dll
elif alt_imp_dll:                                        # only reached when there is NO alt name
    mod, func_attrs = self.api.get_export_func_handler(alt_imp_dll, name)
```

So when an import arrives through an apiset/CRT/winsock DLL name *and* carries an `A`/`W`
suffix, neither `(normalized_dll, base_name)` nor `(normalized_dll, original_name)` is ever
tried, and the run dies with `unsupported_api` even though the handler exists. Reproduced
(`get_export_func_handler` used directly to show the handler is present):

```
kernel32.CreateProcessA                                 -> folds to CreateProcess (OK)
api-ms-win-core-processthreads-l1-1-1.CreateProcess     -> folds to CreateProcess (OK)
api-ms-win-core-processthreads-l1-1-1.CreateProcessA    -> UNRESOLVED (run dies)
api-ms-win-core-libraryloader-l1-2-0.LoadLibraryExW     -> UNRESOLVED (run dies)
```

This hits exactly the most common modern case: 64-bit binaries that import ubiquitous `…W`
functions (`CreateFileW`, `LoadLibraryExW`, `GetModuleFileNameW`, …) through `api-ms-win-*`
umbrella names. `import_table` stores the raw DLL name (`_normalize_mod_name` only strips the
extension and lowercases — it does not apply `normalize_dll_name`), so `handle_import_func`
reaches this branch with the umbrella name intact. `functions_always_exist` does not save it:
it returns a stdcall/argc=4 stub instead of the real handler, so the call is still wrong.

*Fix:* make the rules compose — try `{original_dll, normalize_dll_name(dll)}` ×
`{name, suffix-stripped name}` and return the first hit, instead of `if suffix / elif dll`.

### 2. Data imports inherit the same normalization gap (by inspection)

`handle_import_data` (`winemu.py:1383`) and the load-time data-import loop (`winemu.py:1122`)
look up `get_data_export_handler(imp.dll_name, …)` with the raw DLL name and never fall back
through `normalize_dll_name`, so a data export (e.g. imported via an `api-ms-win-*` name) is
not initialized. Separately, `load_image` first patches every import slot — data imports
included — with a fresh sentinel (`winemu.py:1054`), then overwrites the data slots with the
real pointer (`winemu.py:1129`); the sentinel and its `import_table` entry are left allocated
but orphaned. Harmless per call, but it burns sentinel address space (see #4).

### 3. `GetProcAddress` only resolves modules found in the PEB, by exact base match

`kernel32.GetProcAddress` (`kernel32.py:1980`) iterates `get_peb_modules()` and acts only when
`mod.base == hmod`; any other handle yields `rv = 0` (NULL) and no fallback. It also probes for
an ordinal by trying `read_mem_string(lpProcName)` *first* and only treating the value as an
ordinal in the exception path, which inverts the documented HIWORD-zero convention and is
fragile when the low address happens to be mapped.

### 4. Sentinel address space is finite and unguarded

Sentinels are handed out linearly from `IMPORT_HOOK_ADDR` (0xFEEDFACE) with no bound check
(`_alloc_sentinel`, `winemu.py:871`). Every static import, every `get_proc`/`GetProcAddress`
resolution, and every orphaned data-import sentinel (#2) consumes slots. There is no check that
the growing sentinel range stays unmapped and clear of real allocations, so a sample with a
very large or repeatedly-resolved import surface can eventually collide sentinels with mapped
memory — at which point the fetch no longer faults and the call is silently mis-dispatched.

Findings #1 and #2 share one root cause (folding rules that don't compose) and one fix; a table
test over `(dll, func)` → expected-handler pairs covering apiset/CRT/winsock × A/W/ordinal/base
would lock it down and belongs in the contract-test layer above.
