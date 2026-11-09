# Speakeasy × VirusTotal loader audit: research notes

This is the research log of the first audit (batches of 2026-11-08). The weekly procedure is in `README.md`, and this file explains why the tooling looks the way it does. Statements about "monkeypatch" results refer to scratch patches, not to code in the repo.

Goal: a periodic, varied corpus of native Windows loaders/packed samples from VT, to find speakeasy correctness bugs and raise the rate at which the inner payload is recovered — without over-specifying the API surface.

## 1. VT access

- The key is on the `hex_rays` group: Intelligence search (90-day lookback), downloads, retrohunt, livehunt.
- The quota is not a constraint for this audit: millions of lookups and downloads per day. One result page (≤300 files with full attributes) is one search. Plain API calls (file objects, `behaviour_summary`, comments, lookups of extracted payloads) are cheap.
- `threat_severity`, `behaviour_calls:` and `have:payloads_extracted` are **not** usable as search modifiers. `behaviour_injected_processes:*` matches everything, so name the processes.

## 2. Selection signals (verified against the API)

| signal | how | notes |
|---|---|---|
| sandbox injection | `behaviour_injected_processes:<exe>` (exact name, e.g. explorer.exe, svchost.exe, regasm.exe, msbuild.exe); `attack_technique:T1055.012` (hollowing) | `behaviour_injected_processes:*` matches everything (useless); per-target names are small but high value (82/week); T1055.012 ≈2.2k/week. `attack_technique:T1055` alone is noisy: CAPA static signatures also emit it (70k/week) |
| sigma | `sigma_rule:*process_injection*` | ≈2.8k/week |
| crowdsourced YARA | `crowdsourced_yara_rule:*loader*`, `*shellcode*` (case-sensitive wildcard) | rule names also give a family label that does not come from AV labels or Backscatter |
| comments | `comment:loader OR comment:crypter OR comment:injector OR comment:shellcode` | VMRay posts "Threat Name: …" comments, which are another independent family label (`/files/{id}/comments`, free) |
| sandbox tags | `tag:detect-debug-environment`, `tag:long-sleeps`, `tag:checks-user-input` | anti-analysis: these are the samples most likely to expose emulator tells |
| malware config | `have:malware_config`, `malware_config:<family>` | Backscatter (Mandiant), see bias below; **cap at ≤25% of a run** |
| packers | `detectiteasy:<name>`, `packer:<name>` | classic compressors, protectors |
| score | `p:`, plus client-side `threat_severity.threat_severity_level`, `sandbox_verdicts`, `unique_sources` | `threat_severity:` and `threat_severity_level:` are **not** search prefixes, so rank pages client side |
| not usable | `behaviour_calls:` (invalid prefix), `have:payloads_extracted` (not allowed), `threat_severity*:` | — |

`collect.py` implements this (it was `collect2.py` in the first audit):
- Strata: `sbx-inject` 25%, `yara-loader` 20%, `comment` 15%, `evasion` 15%, `unlabeled-packed` 25%. All of them use `NOT have:malware_config`. `unlabeled-packed` is `p:15+` plus a client-side "looks packed" check (section entropy ≥7.2, ≤15 imports, or non-standard section names). It is the least labeler-biased population.
- In each page, candidates are ranked by an **interest score** built from free attributes: anti-analysis tags, YARA hits, HIGH severity, ≥2 sandbox verdicts, prevalence, and packed look.
- The shortlist is then checked against `behaviour_summary` (free):
  - +2 if the sandbox saw injection or extracted payloads;
  - +1 if `calls_highlighted` has memory-manipulation APIs (VirtualAlloc/Protect, WriteProcessMemory, NtMapViewOfSection, SetThreadContext, QueueUserAPC, …);
  - +1 if the sandbox recorded IOCs that the oracle can check;
  - **rejected** when the sandbox reveals an interpreter or SFX that DIE missed (mutex `AHK Keybd`, `RarSFX`, `_MEI`, `is-*.tmp`, `ns*.tmp`, AutoIt).
- The merged `collect.py` caps config strata at 25% and gives 15% to classic packers and protectors together; the rest goes to the independent strata.

### Dedup lessons

- AV labels are unreliable family keys. `dfjp`, `bypassuac` and `phantomdriver` are one builder: identical decrypted stub+UPX payload in the heap, and two of them share an imphash. Cap per **imphash** and per VT **vhash** as well as per family, and prefer YARA/config/VMRay names over AV labels.
- Filter `virus.*` labels (Jeefo slipped through), and native CLR hosts (`mscoree.CLRCreateInstance`): those are .NET payloads, which are out of scope.

## 3. Oracle: three independent sources + emulator-internal evidence

The emulator dumps every non-system region (heap and stack included). A sample counts as **PAYLOAD** if any of these fire:

1. **backscatter**: a Backscatter config indicator (C2, mutex, campaign id, …) that is *not* in the file bytes appears in emulated memory or API arguments. Schema tokens (`PLAINTEXT`, `HKEY_*`) are ignored.
2. **sandbox_ioc** (independent of Mandiant): hidden sandbox IOCs from `behaviour_summary`: `mutexes_created`, `memory_pattern_domains/urls/ips`, `dns_lookups`, `http_conversations`. Generic noise is removed with a static list (OS/CA/CDN domains, CTF/MSCTF/ZonesCache mutexes, …) plus any indicator seen in ≥3 different families of the batch.
3. **sandbox_payload** (independent of Mandiant): `payloads_extracted` sha256 values (mostly CAPE) are looked up on VT (free). A match is an exact sha256 of a memory buffer, or the md5 of a payload section found at a candidate image base in emulated memory. Sections that are also in the file bytes don't count: Themida/VMProtect leave `.rsrc` untouched, which gave false matches before this filter.
4. **intrinsic** (no labeler at all): a carved PE that is not in the file in plain form, or, for classic packers, the image rebuilt in place (>50% of section bytes changed).

### Bias check (Backscatter vs the rest)

| run | strata | PAYLOAD | oracles that fired | Backscatter-only |
|---|---|---|---|---|
| 1 | config-heavy (40) | 17 (43%) | backscatter 8, intrinsic 10, sandbox_ioc 6, sandbox_payload 2 | 4 |
| 2 | no Backscatter (29) | 11 (38%; 9 distinct builders) | intrinsic 6, sandbox_ioc 4, sandbox_payload 2 | 0 |

How the runs ended:
- Run 1: clean 15, timeout 8, max_api_count 6, invalid fetch/read 8.
- Run 2: **max_api_count 9**, invalid_read 5, unsupported_api 3, timeout 3.

The non-Backscatter population fails differently: more loops and junk-API hammering, more CRT gaps. A Backscatter-only corpus would under-sample exactly these failures.

## 4. Speakeasy behaviours that surprised us: needed options / fixes

1. **`snapshot_memory_regions` always skips heap and stack.** `EXCLUDED_TAG_PREFIXES = ("emu.stack", "api.heap", "emu.process_heap")` at `speakeasy/windows/win32.py:696`, with no option. Crypters often decrypt into `HeapAlloc` buffers. In these runs the decrypted PEs of prochijack, Trik/Xylonite, dfjp/bypassuac/phantomdriver and `foreign` were **only** in the heap, so the stock CLI output would not show them. → Option: `snapshot_memory_regions: {none, non_heap, all}`, or coalesce heap blocks into one region per heap.
2. **The in-memory string scan skips the sample's own image.** `get_mem_strings` scans only `emu.stack*` and `api*` tags (`speakeasy/binemu.py:785`). Strings that in-place unpackers write into the image are missing from `strings.in_memory`. Found only in the rewritten image:
- Padodor and Darkmoss C2s;
- Spectre's `rainmeter.co`;
- the UPX-packed Draftor's ESET-named mutex and `bbs.vc52.cn`. → Scan image regions whose bytes changed since load, or add an option for it.
3. **Snapshots exist only at the end of a run.** There is no capture when dynamic code first executes, so sleep-obfuscation (Havoc/Ekko-style re-encryption), `VirtualFree`, or overwrites hide the payload. `keep_memory_on_free` helps only with frees. → Option: `dynamic_code_segments[*].data_ref` = region bytes at first execution.
4. **Child-process emulation covers only `CreateProcess*`.** `child=True` is passed only at `kernel32.py:1131`, so `WinExec`, `ShellExecute(Ex)` and `CreateProcessAsUser` processes never run with `--emulate-children`. Separately, **ShellExecute joins `lpDirectory` onto an absolute `lpFile`** (`shell32.py:208`), giving `C:\Windows\temp\\C:\Windows\temp\hasfj.exe`; the command line also drops the program path. With both fixed (monkeypatch), Upatre's dropped second stage ran. No option is needed, these are bugs.
5. **Signature-fallback calls are not marked in the report.** You only see them with `--verbose` ("no handler for"). To decide which handlers are worth adding without over-specifying, the report should carry a per-event flag (e.g. `handler: "signature"`). Then a batch can rank fallback APIs by how often they come right before a crash or loop.
6. **Exports run with fake arguments under `all_entrypoints`.** For reflective-loader DLLs (Cobalt Strike, Gandcrab `ReflectiveLoader` exports), this produces garbage crashes inside API traps (`invalid_read` at the trap address 0xf000ed00). → Skip known loader exports, or record export runs as "synthetic" so triage can ignore them.
7. **Cross-process `mem_write` events keep only the first 1 KB** (`profiler.py:541`). The target process memory is in the dumps, so this matters only for report-only consumers.
8. **Unicorn 2.1.4 has no AVX** (CPUID does not advertise it, and `vmovups ymm` is invalid). Binaries built with `/arch:AVX*` die at the first AVX instruction (the `stealer` DLL). Nothing to fix in speakeasy beyond reporting it as a distinct stop reason, but count it per batch.

## 5. Harness

See `README.md`. `collect.py` merges the first two collectors (config/packer/protector, and behaviour/YARA/comment/evasion/unlabeled). `run_audit.sh` runs the whole batch, and `triage.py` groups the stops.

## 6. Root causes found so far (each fix tested by monkeypatch; the repo is unchanged)

Scripts are in `investigate/api/`.

| sample | stop | root cause | class | fix tested → result |
|---|---|---|---|---|
| Lumma crypter `edfd278e` | `invalid_fetch` @0 | `RegEnumValueA` runs from its signature. Its out-param zero-fill trusts the guest's `*lpcchValueName` = 0x8488840 (capped at `MAX_OUT_ZERO_FILL`=0x10000, `winemu.py:2846-2870`) and zeroes 0x40a028–0x41a028. That range includes the **read-only IAT**, because `mem_write` ignores page protection. Also, the NULL `hKey` should fail with ERROR_INVALID_HANDLE, but the fallback returns success, which flips an opaque predicate. | **bug** (signature fallback) | zero-fill only inside guest-writable pages, cap 0x1000, and NULL required handle → type's error value: real path taken, then a CPU-bound decrypt loop (30 s limit) |
| Metasploit x64 `81bc054d` | clean exit, no payload | shellcode is decrypted (BCryptDecrypt) into a section view and started via `CreateTimerQueueTimer` + `SleepEx(INFINITE, TRUE)`. The timer runs from its signature, so the callback never runs | missing execution primitive | queue the callback as a run → payload runs: ws2_32, `connect 192.168.126.131:4444`, `CreateProcessA("cmd")` |
| DarkComet `630a568a` | `unsupported_api shfolder.SHGetFolderPathA` | no shfolder export manifest and no `DLL_HOSTS` alias, although forwarders work when a manifest declares them | module alias gap | `shfolder→shell32` alias → RAT main logic: mutex, C2 `kfwrflcknt.localto.net:3147`, threads, message loop |
| ScreenConnect launcher `a24904e7` | `invalid_fetch` @0 | `LoadLibraryA("dfshim")` returns 0 (a DLL with no manifest fails unless `modules_always_exist`), and the sample doesn't check for NULL | environment | `modules_always_exist` + `functions_always_exist` → `ShOpenVerbApplicationW` called with the ClickOnce payload URL, clean exit |
| Vidar x64 `343b4ff8` | `invalid_read` | the TLS callback maps `C:\Windows\system32\ntdll.dll` from disk to parse its exports, but configured module files have **empty content** (`fileman.py:526`), so the view is zeros. Also, user-mode `NtProtectVirtualMemory` resolves to the kernel `ZwProtectVirtualMemory` handler, which **does nothing** (no protection change, no OldProtect). Next: direct `syscall`s with SSNs extracted from the decoy stubs (which have no `mov eax, SSN`), and speakeasy treats `syscall` as a no-op | bugs + missing model | decoy image as file content + real Nt* virtual-memory calls → TLS callback completes; stops next on direct syscalls |

### Callback-execution primitives (survey)

- **Run the callback:** CreateThread/RemoteThread/NtCreateThreadEx, QueueUserAPC, EnumWindows, CallWindowProc, CreateWindowEx, DialogBoxParam, EnumResource*, InitOnceExecuteOnce, StartServiceCtrlDispatcher, qsort.
- **Only through the message loop:** SetTimer.
- **Handler exists but never calls the callback:** SetWaitableTimer, EnumDisplayMonitors, SetWindowsHookEx.
- **Signature only, callback never runs (~60 APIs):** the timer queue, the thread pool (Tp*/Rtl*), RegisterWaitForSingleObject, QueueUserWorkItem, NtQueueApcThread, fibers, EnumSystemLocales/CodePages/Calendar/Date/UILanguages/Geo, EnumChildWindows/ThreadWindows/Desktops, CertEnumSystemStore, CryptEnumOIDInfo, EnumFonts*, EnumObjects, LineDDA, GrayString, CopyFileEx/progress routines, ReadFileEx/WriteFileEx, SymEnum*, timeSetEvent, …
- **Unsupported:** EtwpCreateEtwThread, RtlUserFiberStart, shell32.SHCreateThread.

**Proposal (avoids over-specifying):** one declarative table, `(dll, name) → (callback arg index, arg template, sync|queued)`, applied in the signature fallback. Synchronous enumerators call the callback once; asynchronous primitives queue a run. An alertable or infinite wait should also yield to queued runs, not only ExitProcess.

### Fixes ranked by leverage

1. **Harden the signature fallback:**
   - never zero-fill non-writable pages, and use a small cap;
   - a NULL required handle fails with the type's error value.
2. **Callback table** in the signature fallback.
3. **User-mode `Nt{Protect,Query,Allocate}VirtualMemory`** backed by the kernel32 memory core; fix the no-op `ZwProtectVirtualMemory`.
4. **Forwarder-only manifests for shim DLLs** (shfolder→shell32, icmp→iphlpapi, security→secur32, …), plus a list of known System32 DLLs so that `LoadLibrary` of a common DLL succeeds.
5. **Decoy system-DLL file bytes, plus syscall stubs with real SSNs** (`mov r10,rcx; mov eax,SSN; syscall`), with the `syscall` instruction routed by SSN to the handler. This covers Hell's Gate, SysWhispers and VMProtect.

### Loader / memory-protection cases (`investigate/loader/`)

| sample | stop | root cause | class | fix tested → result |
|---|---|---|---|---|
| VMProtect x64 `e3b0ce16` | `invalid_protect_write` | VMProtect calls `ZwProtectVirtualMemory(RWX)` on each packed section, but user-mode Zw* calls route to the **kernel stub** (`api_resolution.py:116` → `kernelmode/ntoskrnl.py:1280`), which returns success and changes nothing. The decompression write faults, and its handler is still-packed code, so it faults again; that second fault is the reported error | **bug** (core memory API) | protect through a shared VirtualProtect helper → decompression runs. The next stop is `ZwQuerySystemInformation(SystemBasicInformation)` = 0xC0000003, then VMProtect's `ExitProcess(0xdeadc0de)`. With both fixed: 343 APIs, the run reaches the original entry point, then the payload deletes its own file |
| VMProtect x64 `9b02b8a6` | timeout | its file integrity check maps and checksums its own file, which takes ~23 s; the 30 s/run limit expires (not a hang). Next comes the same ZwProtect gap | time budget + same bug | 120 s budget → passes the check |
| "MPRESS" Upatre `8ea868d0` | `invalid_protect_write` | the file is a broken **unpacked dump**: the merged section has no write flag and the entry point is the original WinMain. Windows would crash the same way | bad input | forcing rwx → 21 APIs and its window is created. Separate gap: **`PostMessage` is a no-op** (`user32.py:835`), so BM_CLICK never reaches the window procedure where the payload is |
| Cobalt Strike DLL `b02ae11e` | `invalid_fetch` 0x5b000000 | the file contents are shifted 0xC00 from the section table, so the import, export and load-config directories land on garbage. Windows would refuse to load it; speakeasy skips the bad import descriptors with only a warning (`loaders.py:386`) and runs DllMain anyway | bad input / triage gap | none; record skipped descriptors as `invalid_image` problems so triage can drop these files |

Two of these four are bad inputs, not emulator bugs. Corpus triage should mark them: entry point == original WinMain in an "MPRESS" section, or descriptors that don't parse. The collector could also look for VT `tag:invalid-rich-pe-linker-version`-style signals or a large mismatch between section table and content, but the cheapest place to catch them is a speakeasy `invalid_image` problem.

### Loops / early exits (`investigate/loops/`)

Each case pairs a deliberate anti-emulation trick with a speakeasy bug or a missing model that stops it from getting past the trick.

| sample | stop | root cause | fixes tested → result |
|---|---|---|---|
| SmokeLoader crypter `f519e814` | max_api_count | fixed-count junk loops: 5M, 8M and 404M iterations, plus about 21k junk API calls. The idle deferred-work **code hook is only flagged off, never removed** (`windows/winemu.py:499-508`, `common.py:100-103`), so every instruction still pays a Python callback. After that, stage 2 needs **PostMessage → GetMessage** (PostMessage is a stub, `user32.py:835`) | api_hammering + hook removal + a message queue → **full process hollowing** (CreateProcess suspended, VirtualAllocEx, NtWriteVirtualMemory, Set/GetThreadContext, ResumeThread), and the injected stage runs until `CreateFileMappingW(SEC_IMAGE)` on ntdll |
| Pony `d78223eb` | max_api_count | `GetTickCount() % 10 == 5` timing loop: the tick advances by a **fixed +20** from 86,400,000, so the remainder is always 0 (`kernel32.py:2796`). Then 19M GetTickCount calls of API hammering through `call rel32` → `jmp [IAT]` thunks, which **`hammer.py` cannot patch** (only `call [mem]`/`call reg`), plus one log line per call | 64 Hz tick granularity + an `E8` patch in hammer.py → Pony main in 3 s; the next stop is CreateStreamOnHGlobal returning S_OK with no IStream |
| Remus x64 `0d82bc8e` | 3 APIs, then exit | **Hell's Gate**: no `4C 8B D1 B8 <SSN>` in the decoy ntdll stubs (`api_image.py:41`), and guest `syscall` is a no-op. Then a "cancel the run" `NtRaiseHardError` prompt, then **CPUID anti-VM**: Unicorn sets the hypervisor bit (CPUID.1:ECX bit 31) and leaf 0x40000000 is all zeros | syscall stubs with SSNs + SSN dispatch, NtRaiseHardError → OK, NtCreateSemaphore, a CPUID hook that clears bit 31 → 3 → 71 APIs: WMI queries, host recon, then NtOpenKeyEx returns handle 0 |
| Havoc demon DLL `0a7df3f6` | timeout in DllMain | its SSN/gadget scanner has no length limit and spins through the decoy ntdll. Then SharedSleep busy-waits on **KUSER_SHARED_DATA.SystemTime, which is never updated** (`winemu.py:956-985`) | syscall stubs + KUSER_SHARED_DATA kept in sync → 13 → 12,923 APIs: indirect syscalls, recon, **WinHTTP check-in POST to https://146.70.113.188:443/** (the Backscatter C2), then sleep/retry cycles |
| Raccoon/RecordBreaker Delphi `2a2853d5` | max_api_count | 64M×2 junk DeleteDC(0)/GetDlgCtrlID(0) loops through `E8` thunks (hammer gap). Then: WM_CREATE goes to the **stale class wndproc** after VCL subclasses during WM_NCCREATE (`user32.py:588`, same in UpdateWindow); no GetClassInfoA handler; **FindResource matches the type case-sensitively** (`kernel32.py:384`); **GetDlgCtrlID always returns 1** (`user32.py:1702`), and that value feeds the payload decryption key | all fixed → resource GGGR decrypted into RWX memory, shellcode maps **Raccoon v2 over its own image** (stealer strings "Login Data", "wallet.dat", …), then a crash entering the remapped image |

## 7. Merged fix list, by leverage

Every item below was tested by monkeypatch on at least one real sample.

1. **Direct and indirect syscalls.** ntdll Nt*/Zw* decoy stubs should carry a real prologue (`4C 8B D1 B8 <SSN> … 0F 05 C3`), and the `syscall` instruction should dispatch by SSN to the Nt handler. Also serve decoy DLL bytes as the file content of `C:\Windows\system32\*.dll`. *(Remus, Havoc, Vidar, VMProtect; Hell's Gate/SysWhispers-style loaders in general.)*
2. **Real user-mode `Nt/Zw{Protect,Query,Allocate}VirtualMemory`** through one helper shared with VirtualProtect/VirtualAlloc; the current Zw kernel stub does nothing. Add `SystemBasicInformation`. *(VMProtect ×2, Vidar.)*
3. **Harden the signature fallback:** zero-fill only writable pages, a small cap, and a NULL required handle fails. *(Lumma.)*
4. **Callback table in the signature fallback** (~60 APIs: timer queues, thread pool, APC, fibers, Enum*), and alertable/infinite waits yield to queued runs. *(Metasploit x64.)*
5. **Clock realism:** GetTickCount with 15.6 ms granularity tied to the emulated clock; KUSER_SHARED_DATA InterruptTime/SystemTime/TickCount kept in sync. *(Pony, Havoc.)*
6. **API hammering and speed:**
   - `hammer.py` should patch `call rel32` (E8) and x64 call sites and log once per site;
   - remove the idle deferred-work code hook from Unicorn instead of flagging it off.
   *(SmokeLoader, Pony, Raccoon.)*
7. **CPUID:** a default hook that clears the hypervisor bit, so the CPU looks like bare metal; report AVX as a distinct stop reason. *(Remus; AVX-built stealer.)*
8. **User32 message and window model:**
   - PostMessage/PostThreadMessage/PostQuitMessage queue messages, and GetMessage delivers them;
   - WM_CREATE and UpdateWindow use the current wndproc;
   - add GetClassInfo;
   - GetDlgCtrlID(NULL) = 0.
   *(SmokeLoader, Raccoon, Upatre/MPRESS dump.)*
9. **Process creation:** `child=True` for WinExec/ShellExecute(Ex)/CreateProcessAsUser, and the ShellExecute path join. *(Upatre.)*
10. **Module resolution:** forwarder-only manifests for shim DLLs (shfolder→shell32, …), and a list of known System32 DLLs. *(DarkComet, ScreenConnect.)*
11. **Small models:**
    - NtRaiseHardError (answer OK), NtCreateSemaphore, NtOpenKeyEx;
    - CreateStreamOnHGlobal/IStream;
    - case-insensitive FindResource types;
    - `CreateFileMapping(SEC_IMAGE)` on system DLLs.
12. **Report/triage options:**
    - heap in snapshots, and the image in the in-memory string scan;
    - a snapshot of dynamic code at first execution;
    - a per-event signature-fallback flag;
    - `invalid_image` for skipped descriptors;
    - mark synthetic export runs.

Items 1, 5 and 7 are the anti-emulation "tells" that recur across unrelated families. Items 2–4 are correctness bugs. None of them needs per-family handlers, which fits the goal of not over-specifying the API surface.

## 8. Periodic assessment

See `README.md`. Decision (2026-11-09): no regression re-runs for now. Each week tests only new files seen in the wild, and `seen.txt` prevents repeats.

## 9. Filed issues (williballenthin/speakeasy, label `vt-audit`; mirrored upstream as mandiant/speakeasy #565–#594)

- #21 — snapshot_memory_regions never captures heap memory, so payloads that loaders unpack into HeapAlloc buffers are missing from the report
- #22 — strings.in_memory does not scan the sample's own image, so strings that in-place unpackers write are missing
- #23 — Dynamic code regions are only captured at the end of the run, after multi-stage unpackers have overwritten them
- #24 — The report does not show which API calls ran from a signature instead of a handler
- #25 — all_entrypoints runs a ReflectiveLoader export on the mapped image, which always crashes; running it from raw file bytes works
- #26 — AVX instructions end the run as a generic invalid_instruction; report unsupported CPU features as their own stop reason
- #27 — --emulate-children ignores processes started with ShellExecute(Ex), WinExec and CreateProcessAsUser
- #28 — ShellExecute prepends lpDirectory to an absolute lpFile, giving paths like C:\Windows\temp\\C:\Windows\temp\x.exe
- #29 — Runs stop on unsupported CRT and PSAPI imports: _create_locale, _Thrd_detach, EnumDeviceDrivers
- #30 — Signature fallback zero-fills an Out buffer with a guest-supplied size of up to 64 KiB, writes through read-only pages and wipes the IAT
- #31 — A signature-only API called with a NULL required handle returns success, so opaque predicates that rely on the failure take the wrong branch
- #32 — CreateTimerQueueTimer and about 60 other callback APIs run from a signature and never call the callback, so callback-launched shellcode never runs
- #33 — Imports from forwarder-only shim DLLs such as shfolder.dll are "unsupported" even though the target handler exists (shfolder!SHGetFolderPathA -> shell32)
- #34 — Enhancement: LoadLibrary returns NULL for standard System32 DLLs that Speakeasy does not model (dfshim.dll), so launchers call a NULL function pointer
- #35 — Configured system DLL files are empty on the emulated disk, so mapping C:\Windows\system32\ntdll.dll from disk yields zeros
- #36 — ntdll Nt/ZwProtectVirtualMemory in user mode resolves to the ntoskrnl stub, which returns STATUS_SUCCESS but changes no page protection
- #37 — ZwQuerySystemInformation returns STATUS_INVALID_INFO_CLASS for SystemBasicInformation (class 0), so VMProtect stops with a hard error and ExitProcess(0xdeadc0de)
- #38 — Malformed import descriptors are only logged, not reported as invalid_image, so speakeasy runs DllMain of a DLL that Windows would refuse to load
- #39 — Enhancement (low priority): add an optional analysis mode that maps the input image RWX, for unpacked memory dumps whose section headers lost the write bit
- #40 — Direct and indirect syscalls fail: the decoy ntdll stubs have no `mov r10, rcx; mov eax, SSN` prologue, and a guest `syscall` instruction does nothing
- #41 — KUSER_SHARED_DATA time fields never advance, so busy-waits on SystemTime spin forever
- #42 — GetTickCount always advances by exactly 20 ms, so `GetTickCount() % 10` never changes and a modulo wait loop never ends
- #43 — CPUID reports "hypervisor present" (leaf 1 ECX bit 31) but leaf 0x40000000 returns zeros, which trips VM checks
- #44 — API hammering mitigation cannot patch `call rel32` sites (calls through `jmp [IAT]` thunks), and it logs on every call after the threshold
- #45 — The deferred-work code hook stays registered in Unicorn after it is disabled, so every guest instruction can pay for a Python callback
- #46 — PostMessage and PostThreadMessage do not queue the message, so GetMessage never returns it
- #47 — WM_CREATE and UpdateWindow use the class window procedure captured before WM_NCCREATE, which ignores a window subclassed with SetWindowLong(GWL_WNDPROC)
- #48 — GetDlgCtrlID always returns 1, also for a NULL window
- #49 — FindResource compares string resource types case-sensitively, so a "gggr" lookup misses a "GGGR" resource
- #50 — Missing API models that report success but leave the out-parameter zero: NtRaiseHardError, NtCreateSemaphore, NtOpenKeyEx, CreateStreamOnHGlobal

## 10. Run 2026-11-09 (master `588cb575`)

Fork #21–#50 were moved upstream on 2026-11-09 (open there as mandiant/speakeasy #565–#594, fork #N = upstream #N+544); the fork copies are closed "not planned", which does not mean fixed. Treat them as open upstream issues.

This run's issues could **not be filed**: the session had no GitHub MCP tools and no push/API access to the fork (git proxy 403). The drafts were left with the run's results; until they are filed, treat these as known root causes (all confirmed by monkeypatch):

| sample | root cause |
|---|---|
| xworm `f28f53b5` | waits on a thread handle return WAIT_OBJECT_0 before the thread runs; the worker runs after ExitProcess |
| respawner `b99b85e7` | the child loop in `run_module` ignores `max_total_time` (harness 300 s kill) |
| dacic `bd058498` | VirtualAlloc(Ex) with lpAddress returns another address; PEB.ImageBaseAddress 0 for file-backed children |
| BlackMatter `60b94ca5` | KUSER_SHARED_DATA.NtSystemRoot empty; FindFirstFile does not list configured modules |
| Cobalt Strike `d522cbbd` | named-pipe client is the `\\.\pipe*` stager.bin file; ReadFile never blocks |
| tedy `2e8c63ab` | ExitProcess does not close the process's handles; named mutexes outlive it |
| Donut .cpl `8507f3fa` | CPlApplet export run gets placeholder args instead of CPL_INIT |
| Snowhush `ec806791` | SHGetKnownFolderPath knows 16 GUIDs; combase has no ole32 alias (#577 class) |
| blackmoon `d56f664c` | input path without extension → no '.' in GetModuleFileName (MFC crash); child: VirtualProtect size 0 → UC_ERR_ARG |
| injector `62c31f3e` | run at a synthetic decoy child's MZ header; `get_module_from_addr` inclusive end |

Corrections: the VMProtect "time budget" cases (9b02b8a6 here, e3136233/cddb73e9 this run) are upstream #589 overhead, not a slow check. New #594-class members: CryptBinaryToString, BCryptCreateHash, EnumDisplaySettings. #585 also breaks string keys derived from InterruptTime deltas (StoneDrill). FreshyCalls-style resolvers jump to `Zw* stub + 8` (#584 fix must keep +8 valid).

Tooling: `analyze.py` needed Python 3.12 for an f-string (the venv is 3.11); fixed. A hard-timeout kill is now `first_error: harness_timeout`. The report collapses identical consecutive API events, so "41 APIs + max_api_count" can be ~20k calls of one API.
