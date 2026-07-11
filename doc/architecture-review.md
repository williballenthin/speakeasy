# Architecture review

A review of Speakeasy's Windows emulation architecture: how it is put together, where it
is strong, where it is weak, and a prioritized list of enhancements that fit the project's
current goals (faithful, fast malware triage with an easy-to-extend API surface and a
structured, analyst-friendly report) and its established style (Unicorn CPU, decorator API
handlers, Pydantic config/report models, config-driven environment).

## Architecture at a glance

Speakeasy models a Windows userland/kernel runtime around a Unicorn CPU rather than a full
VM. The layering, from the metal up:

- **CPU engine** — `engines/unicorn_eng.py` wraps Unicorn (registers, memory, hooks). The
  engine is abstracted behind an `EMU_ENGINES` table (`winenv/api/api.py:22`), but Unicorn
  is the only implementation and `config.emu_engine` is a `Literal["unicorn"]`. Only x86 and
  AMD64 are defined (`winenv/arch.py`).
- **Memory manager** — `memmgr.py`. A linear `self.maps` list of `MemMap` objects; blocks
  sub-page allocations into pages; tags every region.
- **Binary emulator** — `binemu.py` (`BinaryEmulator`). Register/stack/calling-convention
  helpers, argument marshalling, string readers, and the full hook-registration API
  (code/mem/API/interrupt/insn/dyn-code hooks).
- **Windows emulator** — `windows/winemu.py` (`WindowsEmulator`, ~2830 lines). The core:
  PE/loader integration, IAT sentinel dispatch, import forwarding, SEH/VEH, invalid-memory
  fault handling, the run queue, tracing/coverage hooks, PEB/TEB, KUSER_SHARED_DATA.
- **Mode specializations** — `windows/win32.py` (`Win32Emulator`) and `windows/kernel.py`
  (`WinKernelEmulator`, with an SSDT).
- **OS resource managers** — `fileman`, `regman`, `netman`, `driveman`, `cryptman`,
  `objman`, `sessman`, `ioman`, `com`. Each models one Windows subsystem behind a small API.
- **API handlers** — `winenv/api/usermode/` (40 modules, ~804 `@apihook` handlers) and
  `winenv/api/kernelmode/` (7 modules, ~234 handlers), autoloaded by reflection
  (`winapi.py:13`). Struct/const definitions live in `winenv/defs/`.
- **Config & report** — `config.py`/`cli_config.py` (Pydantic v2, single inline default
  profile) and `profiler.py`/`profiler_events.py`/`report.py` (Pydantic report schema
  v3.0.0 with a deduplicated blob store).

**API dispatch mechanism.** At load time each IAT slot is patched with a unique sentinel
address inside a reserved, unmapped region. When the sample calls an import, the fetch
faults; the invalid-fetch handler resolves the sentinel to `module.function`, looks up the
handler, marshals arguments per the declared calling convention, invokes the Python handler,
logs the call, and returns. This is robust and even covers hollowed/injected PEs whose IATs
are patched in memory (`doc/speakeasy2-walkthrough.md`).

**Concurrency model.** Threads, TLS callbacks, exports, APCs, and callbacks are all modeled
as *runs* on a queue (`run_queue`, `_exec_next_run`, `winemu.py:403`). Each run executes to
completion, then the next is popped. There is no scheduler, no preemption, and no
interleaving — cooperative, one run at a time.

## Strengths

1. **Extensibility is excellent.** Adding an API is a decorated method
   (`@apihook("CreateFileW", argc=7)`); handlers are discovered by reflection with no
   registration boilerplate. The same decorator carries argc/calling-convention/ordinal, so
   the dispatcher can marshal correctly. This is the project's best asset and the reason its
   coverage has grown to ~1000 handlers.
2. **Sentinel import dispatch is elegant and resilient.** It decouples interception from the
   loader, works uniformly across PE/shellcode/decoy/injected images, and gives per-call
   argument and return-value visibility for free.
3. **Clean subsystem separation.** File/registry/network/crypto/object/drive managers keep
   OS state out of the CPU core and make the emulated environment fully config-driven
   (planted files, seeded registry keys, canned DNS/HTTP responses, NIC adapters).
4. **Modern, well-modeled config and report.** Pydantic v2 config (`extra="forbid"`,
   `frozen=True`, legacy-field migration) and a schema-versioned Pydantic report with
   discriminated event unions, hex serializers, and a SHA-256-keyed zlib blob store that
   deduplicates dropped files and memory dumps.
5. **Strong analyst ergonomics.** Runtime-decoded strings are separated from static strings
   (`strings.in_memory` vs `strings.static`), dropped files are recoverable with hashes, network
   IOCs (DNS/HTTP/socket) are first-class events with captured bytes, and each run carries an
   `apihash` for behavioral clustering.
6. **Breadth: user *and* kernel mode.** WDM/WDF driver emulation, IRP dispatch, an SSDT, and
   a decent `ntoskrnl` surface — rare among lightweight emulators.
7. **Recent modernization (Speakeasy 2).** A unified `Loader`/`LoadedImage`/`RuntimeModule`
   model, `--volume` host mounts, auto-mount of sibling files, a udbserver GDB stub, full
   AMD64 thread-context get/set, and per-section protections/access tracking.
8. **Graceful degradation.** An unsupported API stops only the current run; other queued
   entry points still execute, so one gap doesn't zero out the report.
9. **A real regression backbone.** The PMA golden suite (`tests/pma_*`) asserts expected
   APIs and IOCs against real Practical-Malware-Analysis samples.

## Weaknesses

1. **API-coverage gaps are the number-one practical limiter.** When no handler exists and no
   user hook/`functions_always_exist` fallback applies, the run terminates
   (`winemu.py:1755`). Thin or stub-only modules include `crypt32`, `dnsapi`, `iphlpapi`,
   `secur32`, `rpcrt4`, COM (`ole32`/`com_api`), and `mscoree` (a single stub — managed/.NET
   payloads are effectively unsupported). `ws2_32` has no IPv6 (`AF_INET6` unimplemented).
   Whole modules are absent (`setupapi`, `version`, `comdlg32`, `dbghelp`, `wsock32`).
   Kernel mode has a block of seven consecutive unimplemented `ntoskrnl` handlers
   (`ntoskrnl.py:~1993–2080`) and thin WFP/NDIS/USB.
2. **The `functions_always_exist` fallback risks stack corruption.** It assumes stdcall,
   `argc=4`, and returns 1 (`winemu.py:1742`). For an unknown API with a different argument
   count or convention, the stack cleanup is wrong, silently corrupting downstream state and
   producing misleading reports — the exact failure mode the "stop on unknown API" design was
   meant to avoid.
3. **No true threading/scheduler.** Run-to-completion sequential runs cannot faithfully model
   thread synchronization, producer/consumer handoffs, races, APC delivery, or thread-based
   anti-analysis. Sleeps/timing loops and cross-thread signalling don't resolve the way a
   real scheduler would, so multithreaded modern malware often stalls or diverges.
4. **Performance won't scale to long or allocation-heavy runs.** `MemoryManager` uses O(n)
   linear scans (`get_address_map`, `get_address_tag`), and `get_valid_ranges`
   (`memmgr.py:287`) rematerializes the page set of *every* mapped region on *every*
   allocation — roughly O(allocations x total_pages). Tracing/coverage run as per-instruction
   Python callbacks (`_hook_code_tracing`, `_hook_code_coverage`), and symbol resolution runs
   on a per-read hook. These are fine for small samples but throttle large unpackers.
5. **`winemu.py` is a ~2830-line god class.** Loader glue, import dispatch, SEH/VEH, fault
   handling, run scheduling, and three tracing hooks all live in one class. This raises the
   cost of every change and makes the concurrency and performance work above harder than it
   should be.
6. **Correctness is validated only behaviorally.** Tests assert that certain APIs were called
   with certain args and that indicators appeared; there is no instruction/register golden
   comparison against a reference CPU, and most of the ~1000 API handlers are exercised only
   if some PMA sample happens to call them. Managers (`netman`, `cryptman`, `sessman`,
   `driveman`, `com`, `ioman`, `memmgr`) have no direct unit tests. CI runs a single Python
   (3.13) on Linux only, does not run mypy, and measures no coverage; the `capa-testfiles`
   submodule isn't checked out locally, so sample tests skip by default.
7. **Environmental fidelity and evasion resistance are dated.** The only default profile is
   Windows 7 SP1 (`os_ver` 6.1.7601, `config.py:19`) with a hardcoded fake process list,
   fixed SID, and one Intel NIC — all easy to fingerprint, and modern samples gate on Win10/11
   build numbers. There are no named OS presets.
8. **Reporting has no consolidated IOC view, and captures are truncated.** Network endpoints,
   dropped-file hashes, mutexes, and registry persistence are scattered across every run's
   event stream with no top-level `iocs` rollup. File/registry data previews cap at 1024
   bytes and network bodies at 0x3000 (`profiler.py`), so full payloads can be lost. The
   richest telemetry (`memory_tracing`, `coverage`, `snapshot_memory_regions`) is off by
   default, and without `memory_tracing` the per-event `tick` ordering degrades.
9. **Robustness rough edges.** Broad `except Exception` blocks wrap dispatch and every code
   hook, converting real handler bugs into generic recorded errors. `do_str_format`
   (`api.py:413`) is self-described as "very brittle." These quietly reduce report
   trustworthiness.

## Prioritized enhancements

Ordered by (usefulness + correctness gained) / effort. Each is scoped to fit the existing
patterns — Pydantic models, decorator handlers, config-driven behavior, doc-verified changes.

### P0 — highest leverage

1. **Prototype-driven unknown-API handling (correctness + coverage).**
   Replace the `argc=4` guess in `functions_always_exist` with a prototype database keyed by
   `module.export` (argument count + calling convention), derived from the same metadata used
   to define handlers. When an unknown API has a known prototype, skip it with the *correct*
   stack cleanup and a neutral return, and record it as `stubbed` rather than killing the run.
   This directly fixes weakness #2 and softens #1 without writing hundreds of handlers.
   *Effort: medium. Style fit: extends the existing `@apihook`/dispatch model.*

2. **Coverage-gap telemetry + a "continue-on-unknown" triage mode.**
   Add an opt-in mode that, instead of stopping, logs each unsupported API (module, export,
   caller, argc guess) into a dedicated report section and continues via the P0.1 stubber.
   Aggregated across a sample corpus this produces a ranked worklist of the highest-impact
   missing handlers — turning coverage growth from anecdote into data.
   *Effort: low. Style fit: a new Pydantic report section + a config flag.*

3. **Consolidated top-level `iocs` report section.**
   Roll up files written/dropped (with hashes), registry persistence keys, network endpoints
   (domains, IPs, URLs, ports), mutexes/named objects, and child processes into one
   `report.iocs` block, deduplicated across runs. Pure additive value for triage and
   downstream tooling; no behavior change.
   *Effort: low. Style fit: a new `extra="forbid"` sub-model populated from existing events.*

### P1 — foundational fidelity

4. **Named OS environment profiles (Win10/Win11) + less-fingerprintable defaults.**
   Ship selectable presets (build numbers, KUSER_SHARED_DATA fields, realistic process list,
   adapters) chosen by config/CLI. Improves correctness for build-gated samples and raises the
   bar for anti-emulation. Keep Win7 as a preset for back-compat.
   *Effort: medium. Style fit: additional Pydantic profiles + a `--profile` flag.*

5. **Memory-manager performance rework.**
   Back the map set with a sorted/interval structure for O(log n) `get_address_map`/tag
   lookups, and maintain the free/used page set incrementally instead of rebuilding it per
   allocation in `get_valid_ranges`. This unblocks large unpackers and long runs within the
   timeout, and is a prerequisite for heavier tracing.
   *Effort: medium. Style fit: internal to `memmgr.py`, no API change.*

6. **Cooperative thread scheduler.**
   Introduce quantum-based switching across runnable threads with real semantics for the
   common synchronization primitives (events, mutexes, critical sections, `WaitForSingle/
   MultipleObjects`), APC delivery, and `Sleep` advancing a virtual clock. This is the single
   biggest correctness gain for modern multithreaded malware. Land it incrementally on top of
   the existing run queue (make a run yield and re-enqueue rather than always run-to-completion).
   *Effort: high. Style fit: evolves the existing `run_queue`/`objman` thread objects.*

### P2 — maintainability and trust

7. **Decompose `WindowsEmulator`.**
   Extract import dispatch, SEH/VEH, invalid-memory handling, run scheduling, and the tracing
   hooks into focused collaborators. Lowers the cost of P0/P1 and makes the core reviewable.
   *Effort: medium-high. Style fit: internal refactor, behavior-preserving.*

8. **Correctness test + CI hardening.**
   Add per-handler and per-manager unit tests (especially the untested managers), a small
   differential CPU-state harness for critical flows, and check the `capa-testfiles` submodule
   in CI so sample tests actually run. Wire mypy and coverage into the gate and expand the CI
   matrix to Python 3.10–3.13. Converts behavioral confidence into enforced guarantees.
   *Effort: medium. Style fit: extends the existing pytest/PMA structure and `justfile`.*

9. **Dispatch robustness.**
   Narrow the broad `except Exception` blocks to record structured, attributable handler
   errors (which handler, which arg) instead of generic run failures; harden or replace the
   brittle `do_str_format`; implement IPv6/`getaddrinfo` in `ws2_32`. Small, targeted fixes
   that raise report trustworthiness.
   *Effort: low-medium.*

### P3 — reach

10. **Configurable capture limits + string provenance.**
    Make the 1024-byte / 0x3000 truncation caps configurable so full exfil/payload bytes can
    be retained on demand, and attach address/region provenance to decoded strings so analysts
    can trace them back to memory.
    *Effort: low.*

11. **Managed/.NET and scripting awareness.**
    Even without full CLR emulation, detect managed payloads (via `mscoree`/COR headers) and
    report them explicitly rather than dying, and consider surfacing script-host
    (`wscript`/`mshta`) intent. A longer-term reach item that widens the sample types Speakeasy
    can say something useful about.
    *Effort: high.*

### Quick wins (days, not weeks)

- The IOC rollup (P0.3), coverage-gap telemetry (P0.2), configurable capture limits (P3.10),
  IPv6 in `ws2_32`, mypy/coverage/multi-Python CI (part of P2.8), and checking out the
  `capa-testfiles` submodule in CI are all low-effort, high-signal, and independently landable.

## How these map to project goals

- *More samples run further* → P0.1/P0.2 (unknown-API handling), P1.6 (scheduler), P1.5
  (performance).
- *More faithful/correct* → P0.1, P1.4 (OS profiles), P1.6, P2.8/P2.9 (tests + robustness).
- *More useful to analysts* → P0.3 (IOC rollup), P3.10 (capture/provenance), P3.11 (managed
  payloads).
- *Easier to maintain and extend* → P2.7 (decompose the god class), P2.8 (enforced quality
  gates).
