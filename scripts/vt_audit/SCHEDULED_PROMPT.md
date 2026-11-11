Weekly VT audit of speakeasy. Run it unattended from start to finish; nobody will answer questions during the run.

## Context
speakeasy (https://github.com/williballenthin/speakeasy, a fork of mandiant/speakeasy) is a Windows malware emulator. Every week we test its `master` branch against native Windows loaders and packed samples first seen on VirusTotal in the past 7 days. The goal is to find correctness bugs and missing models that stop speakeasy from reaching the inner payload, and to report the confirmed ones that speakeasy could reasonably fix.

The tooling, the playbook and the issue format live on the `vt-audit` branch of the fork, under `scripts/vt_audit/`. Read `README.md` (procedure and reporting policy), `ISSUE_TEMPLATE.md` (issue format) and `NOTES.md` (research and earlier root causes) in full before you triage anything. They are authoritative; this prompt summarizes them. The model issue for depth and format is https://github.com/williballenthin/speakeasy/issues/21.

`VT_API_KEY` is set in the environment. Never print it.

## Steps

1. **Setup.**
   - Get the fork. Use `/home/user/speakeasy` if it exists, otherwise `git clone https://github.com/williballenthin/speakeasy`. If git or the GitHub tools cannot reach the repo, call `add_repo` (owner `williballenthin`, repo `speakeasy`, access `push`).
   - `git fetch origin master vt-audit`. Create two worktrees under a scratch directory `$W`:
     - `$W/master` at `origin/master`: the code under test. Never edit it.
     - `$W/tools` on a local branch `vt-audit` that tracks `origin/vt-audit`.
   - Record the master commit.
2. **Run the batch** with `$W/tools/scripts/vt_audit/run_audit.sh $W/master $W/work`. It uses a 7-day window and 60 samples by default, and takes about an hour. Run it in the background and wait for it to finish. If it fails, fix the tooling on the `vt-audit` worktree and re-run. Tooling fixes are allowed and should be committed.
   Then fetch mandiant/speakeasy `master` into a third worktree `$W/upstream` and run `$W/tools/scripts/vt_audit/compare.sh $W/upstream $W/work` (about 20 minutes). Stops that upstream no longer shows are "fixed upstream, not yet in the fork": list them in the summary, do not file them.
3. **Triage.** Read `$W/work/triage.md`, `$W/work/compare.txt` and `$W/work/analyze.txt`. For each in-scope stop group, find the root cause on a representative sample. Parallel subagents are fine for independent groups. For each one:
   - read the report events, the error's `pc`/`instruction`/`context_summary`, and the signature-fallback list in `harness.json`;
   - disassemble the guest code with capstone, using `out/<sha>/regions/*.bin`;
   - read the speakeasy code that handled the relevant API or event;
   - confirm with a monkeypatch in a scratch script outside the checkout, and record the before/after: APIs reached, payload evidence.

   A root cause is confirmed only when the evidence or a working monkeypatch shows it. Everything else is an "unconfirmed lead".
4. **Scope.** Report only what speakeasy could reasonably fix, based on what is seen in the wild:
   - emulator correctness;
   - core Windows API semantics;
   - generic mechanisms: the signature fallback, callbacks, syscalls, forwarders, the clock, CPUID;
   - report features that hide payloads.

   Never report:
   - third-party DLLs or runtimes, .NET/CLR, interpreters, installers;
   - AVX (a Unicorn limitation);
   - stages that are only downloaded;
   - one-off per-family handlers;
   - malformed inputs that Windows also rejects.
5. **Duplicates.** Before you file anything, search both repos, open and closed:
   - Fork: `gh api -X GET search/issues -f q='repo:williballenthin/speakeasy is:issue <keywords>'`, and the `vt-audit` label.
   - Upstream: `gh api -X GET search/issues -f q='repo:mandiant/speakeasy is:issue <keywords>'`.
   - Search by API name, code location, and sample sha256.
   - If an open issue already covers the root cause and the new sample adds real evidence, add **one** comment to that issue, with the sample (sha256, VT link, family, how it was selected, how it stopped) and a link to this run's summary issue. Use `gh` only for search; post with the GitHub MCP tools.
   - Fork issues closed as "not planned" were usually moved upstream, not fixed: fork #21–#50 are open upstream as mandiant/speakeasy #565–#594 (same titles, same order). If a finding matches an open upstream copy, list it in the summary as re-observed with the upstream link; do not comment upstream.
   - If an issue was closed as fixed, report the finding as a possible regression and reference that issue.
6. **File on williballenthin/speakeasy only.** Never post to mandiant/speakeasy.
   - If the run found no new confirmed root cause and added no evidence to an existing issue, file **nothing**.
   - Otherwise:
     - create one summary issue, titled `VT audit <YYYY-MM-DD>: <n> new findings`, in the format in README.md "Summary issue format", labelled `vt-audit`;
     - create one issue per confirmed root cause, in the `ISSUE_TEMPLATE.md` format, with full sample context so it can be reproduced later: full sha256, VT link, stratum and selection signal, master commit, reproduce command, disassembly, API trace, code references, impact, suggested fix and test case;
     - label each with `vt-audit`, and add each as a sub-issue of the summary with `sub_issue_write` (using the id from the create response);
     - list re-observed existing issues (fork or upstream) in the summary, with links;
     - defang network IOCs; never attach samples;
     - end every issue and comment body with the line `---` and then `_Generated by [Claude Code](https://claude.ai/code)_`.
7. **Housekeeping on the `vt-audit` branch** (the repo owner has authorized pushing to this branch; do not push anywhere else, do not touch master, do not open pull requests):
   - append this run's sample sha256s to `scripts/vt_audit/seen.txt`;
   - write `scripts/vt_audit/runs/<YYYY-MM-DD>.tsv` (sha256, stratum, family, arch, type, outcome, first error);
   - commit tooling improvements, then commit and push with `git push origin vt-audit`, retrying up to 4 times with backoff on network errors.
   - Never commit samples, memory dumps, reports or raw sandbox IOCs.
8. **Final message:** the master commit, samples per stratum, the outcome counts, the links to the issues you filed or commented on, the unconfirmed leads, and anything that went wrong.

## Safety
- Samples are only loaded into speakeasy or parsed with pefile/capstone; never execute them natively.
- Run Python with `-I`, keep scripts outside the samples directory, and pass sample paths as arguments.
- When unsure whether a finding is confirmed and in scope, list it as an unconfirmed lead in the summary instead of filing it. Nothing filed is better than noise.
