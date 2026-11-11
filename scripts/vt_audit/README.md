# VT audit of speakeasy

A weekly audit that tests speakeasy `master` against native Windows loaders and packed samples first seen on VirusTotal in the past week. It finds correctness bugs and missing models that stop speakeasy from reaching the inner payload, and it files them as issues on this fork.

The tooling lives on the `vt-audit` branch of williballenthin/speakeasy under `scripts/vt_audit/`. `NOTES.md` has the research behind it, and `ISSUE_TEMPLATE.md` has the issue format.

## Files

| file | what |
|---|---|
| `run_audit.sh` | one batch end to end: install the checkout under test, collect, download, enrich, emulate, analyze, triage |
| `collect.py` | VT selection: 10 strata from independent signals, scope filters, ranking, dedup, `--download` |
| `enrich.py` | VT sandbox ground truth: behaviour summaries and the metadata of extracted payloads |
| `compare.sh` | re-emulates a finished batch with a second checkout (mandiant/speakeasy master) and prints both outcomes side by side → `compare.txt` |
| `run_one.py` | emulates one sample with the library, dumps all memory (heap and stack included), logs signature-fallback and unsupported APIs; children on by default |
| `analyze.py` | oracles (config IOCs, sandbox IOCs, sandbox payloads, emulator-internal evidence), how each run ended → `summary.json` |
| `triage.py` | groups runs by stop signature and marks out-of-scope stops → `triage.md` |
| `oracles.py`, `apis.py` | small viewers: oracle matrix; API trace tail of a report |
| `SCHEDULED_PROMPT.md` | the prompt of the weekly scheduled task (Wednesdays 00:00 UTC); keep it in sync when you change the procedure |
| `seen.txt` | sha256s assessed in earlier runs; never re-tested |
| `runs/<date>.tsv` | per-run sample list: sha256, stratum, family, outcome, first error |

## Weekly procedure

1. Check out `master` of williballenthin/speakeasy (the code under test), and this branch for the tooling, in separate worktrees.
2. Run `scripts/vt_audit/run_audit.sh <master checkout> <work dir>`. The window defaults to the past 7 days and the target to 60 samples. It takes about an hour.
3. Run `scripts/vt_audit/compare.sh <mandiant/speakeasy master checkout> <work dir>` (about 20 minutes). The fork's `master` can lag upstream, where many earlier findings are already fixed. A stop that upstream no longer shows is not a new finding: list it in the summary as "fixed upstream, not yet in the fork". Triage the rest on the fork's `master`, and check whether the root cause still holds upstream.
4. Read `<work dir>/triage.md`. For each **in-scope** stop group, pick a representative sample and find the root cause:
   - read the report events (`apis.py <report.json> <run> 60`), the error's `pc`, `instruction` and `context_summary`, and the signature-fallback list in `harness.json`;
   - disassemble the guest code around the stop with capstone, using `out/<sha>/regions/*.bin` for memory as it was at the end of the run;
   - read the speakeasy code that handled the relevant API or event;
   - confirm with a monkeypatch in a scratch script (never edit the checkout under test), and record the before/after: APIs reached, payload evidence.
   - Only a root cause that is confirmed this way may become a new issue. Hypotheses go into the summary as "unconfirmed leads", or are dropped.
5. Check for duplicates before filing:
   - Fork: `gh api -X GET search/issues -f q='repo:williballenthin/speakeasy is:issue <keywords>'`. Also list the `vt-audit` label, open and closed.
   - Upstream: `gh api -X GET search/issues -f q='repo:mandiant/speakeasy is:issue <keywords>'`.
   - Fork issues closed as "not planned" may have been **moved upstream**, not fixed. For example, fork #21–#50 were moved to mandiant/speakeasy #565–#594 (same titles, same order). Before treating a closed fork issue as fixed or regressed, look for an upstream copy with the same title. If the upstream copy is open, the finding is a re-observation: list it in the summary with a link to the upstream issue. Never comment on mandiant/speakeasy.
   - Search by API name, file and function, and the sample's sha256.
   - If an open issue covers the root cause and the new sample adds evidence (a new family, a new variant, a better reproducer), add **one** comment to that issue with the sample, its context and a link to the run summary. Then list it in the summary under "Re-observed".
   - If a closed issue covers it, the fix may have regressed. Treat it as a new finding and reference the closed issue.
6. File:
   - one **summary issue** per run, only if the run produced at least one new issue or added evidence to an existing one; otherwise file nothing;
   - one **issue per confirmed root cause**, in the `ISSUE_TEMPLATE.md` format, labelled `vt-audit`, and added as a sub-issue of the summary (`sub_issue_write` with the new issue's id).
7. Housekeeping on this branch:
   - append the run's sha256s to `seen.txt`;
   - add `runs/<date>.tsv`;
   - commit any tooling fixes, then commit and push. Never commit samples, memory dumps, reports, or raw sandbox IOCs.

## Scope: what to report

Report what speakeasy could reasonably fix, based on what is seen in the wild:
- emulator correctness: CPU state, memory and protection, exceptions/SEH, loader, threads and runs, children;
- core Windows API semantics: memory, process/thread, file, registry, synchronization, time, module loading, user32 message basics;
- generic mechanisms: signature fallback, callback dispatch, syscalls, forwarders and API sets, KUSER_SHARED_DATA, CPUID;
- report and analysis features that hide payloads (snapshots, strings, dynamic code).

Do not report:
- third-party DLLs and runtimes (Qt, Python, OpenSSL, game SDKs, …); speakeasy will never model them;
- .NET/CLR hosting, interpreters (AutoIt, AutoHotkey, PyInstaller, …), installers and self-extractors;
- AVX/VEX instructions (Unicorn limitation; already tracked);
- network-dependent stages (a payload that is only downloaded), unless speakeasy mishandles the network API itself;
- one-off API handlers that only one family needs and that do not change behaviour beyond that call; prefer the generic mechanism (see `NOTES.md` §7);
- malformed inputs that Windows would also refuse, unless the triage/reporting itself is wrong.

## Summary issue format

Title: `VT audit <YYYY-MM-DD>: <n> new findings` (master `<sha>`).

Body:
- **Window and commit:** first-seen window, speakeasy commit, and how many samples were selected per stratum.
- **Outcome table:** PAYLOAD / PARTIAL / STOPPED / RAN-NO-PAYLOAD counts, and which oracle fired.
- **New findings:** one line per sub-issue.
- **Re-observed:** existing issues (fork or upstream) with new samples; link the comment you added.
- **Out-of-scope stops:** counts by reason.
- **Unconfirmed leads:** stops with no confirmed root cause yet, each with its sample sha256.
- **Sample list:** sha256, stratum, family, outcome and first error for every sample; this is also `runs/<date>.tsv`.
- The attribution footer.

## Safety

- Samples are only loaded into speakeasy or parsed with pefile/capstone; they are never executed.
- Keep scripts outside the samples directory, run Python with `-I`, and pass sample paths as arguments.
- Samples have mode 0400 and live only in the work directory; never commit them.
- Never post to mandiant/speakeasy; only read it for duplicate checks.
