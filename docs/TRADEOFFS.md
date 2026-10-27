# Hardening and loosening: the trade-offs behind the guards

Every guard here sits between "stops a leak" and "gets in the way of real work".
This page records where each guard was tightened and where it was loosened,
with the pull request, the version it first shipped in, the reason, and what it
cost. It exists so that the next change starts from the evidence rather than
repeating a mistake.

PR numbers are this repository's (`gramatr/claude-plugin-guards`). Scanner
changes are made in
[guards-unified](https://github.com/gramatr/guards-unified) and copied into the
vendored `scan.sh` here by a sync PR; the sync PR is the number given. "Version"
is the first release tag that contains the change; plugin installs track `main`,
so a change is live as soon as it is merged and the plugin updates. Tags that
exist are in the repository's tag list; there are no plugin tags for v0.1.5 to
v0.2.1, and "Unreleased" marks a change that no tag contains yet.

Anything described as "verified live" comes from the PR descriptions; it was
not re-run for this page.

## Hardening

| PR | Version | What | Why | Cost or residual |
|---|---|---|---|---|
| #5 | v0.1.0 | `SendMessage` guard: scan outgoing agent-to-agent text | A message leaves the session for another agent and possibly other places | First version denied; see #6 and #21 |
| #36 | v0.1.3 | A truncated or error-shaped service response is treated as "service down", not "clean" | An empty `jq` result looked identical to "scanned, nothing found" | None known |
| #42 | v0.1.3 | stderr scanned as well as stdout | A token logged to stderr got no coverage at all | One more scan per call |
| #43 | v0.1.4 | Output passed through files (`--rawfile`) instead of arguments; scan cap with disclosure | A roughly 128 KB value crashed the final `jq` and silently dropped the redaction, because Claude Code then uses the original output | The 24 KB cap left later secrets unscanned; replaced by #58 and #59 for secrets |
| #51 | v0.2.2 | `credfile-guard`: deny reads of credential files before content exists, including any file with a private-key header | Read and Grep output cannot be rewritten, so a pre-tool deny is the only reliable control there | False positives on documents that quote a key header (see below); indirect reads not caught |
| #52, #53 | v0.2.2 | Scanner sync: redaction pattern quoted; a deterministic private-key pass that works without gitleaks (including truncated keys); one gitleaks retry; fail-closed verification that withholds the whole output if a confirmed secret survives | A detection that did not redact: unquoted pattern treated as a glob, so a key inside JSON came back unchanged; gitleaks occasionally returned nothing on a detectable key | An output can be withheld entirely when verification fails |
| #54 | v0.2.2 | `publish-guard`: block credentials in `gh` publishes, `gh api` bodies, `git commit` and GitHub MCP writes | A live key was once quoted in the body of a public issue; nothing looked at outbound text | Occasional block next to a secret-ish key name; does not cover `git push` |
| #55 | v0.2.2 | Scanner sync: context rules (value after a key name, URL passwords, headers, CLI flags, `.netrc`, Azure/gcloud/bcrypt shapes); exact-match redaction of secret-named environment variable values in the publish guard and the fallback | gitleaks keys on value shape and real credentials often do not have one | **Stated bias: over-redact.** More false positives; fixes for those are below |
| #56 | v0.2.2 | `mcp-output-guard`: redact secrets in MCP results | MCP results are the third path into the session | Rewrites recognised shapes only; skips grāmatr's own server by default |
| #57 | v0.2.2 | Scanner sync: linear-time redaction, no per-rule match cap, Unicode-safe matching (zero-width characters, fullwidth delimiters) | Speed bugs were leak bugs: a quadratic split took longer than the service timeout, which then returned the text unredacted; a cap of 200 matches left 100 of 300 secrets | Thousands of matches are still slow |
| #58 | v0.2.2 | Secret-only route (about 55 ms) with local fallback for the publish and MCP guards | Make the secret path fast without making protection depend on the service | Two code paths to keep consistent |
| #59 | v0.2.2 | Bash hook fast path: secrets scanned up to 256 KB without waiting for the models | The old hook took 10 s on 24 KB and did not redact a secret later in a large output | See the PII and injection loosening below |
| #61 | v0.2.2 | Scanner sync: decode long base64 tokens and scan the decoded text | A secret wrapped in base64 had no key name to match | Up to 25 candidates per scan; no other encodings |
| #62 | v0.2.2 | Publish guard denies instead of asking when no person can answer (modes `auto`, `bypassPermissions`, `dontAsk`, unknown) | An `ask` in `auto` mode was seen to let a command carrying a fake password run through | An ambiguous match in an unattended session blocks work until a person intervenes |
| #101, #102 | v0.2.10 | `outbound-guard`: deny a Bash command that sends a credential file, the whole environment or a literal credential to a remote host, and teach the safe form | A credential leaves the machine in one command and no other guard looked at a network client; the spike found 74 candidates in 95,879 Bash commands of one machine's history, 71 of them uncaught by the earlier guards | About 3 ms on a command that names no client, about 190 to 230 ms on one that does (about 2 percent of Bash calls); best effort, see LIMITS.md |
| #101 | v0.2.10 | The outbound override is read from the environment only, and the guard fails closed for a command that names a client | The caller is usually an AI agent, so the override must be something it cannot type; sent text cannot be recalled | A hung service or a bug blocks curl until the switch is set |
| #101 | v0.2.10 | A file named through a variable or a substitution that builds the path is allowed with a note | The agent cannot fix a command it wrote correctly, and a deny there would teach it to split commands | A credential file named through a variable is not seen |
| #94, #98 | v0.2.10 | The bash deadline watchdog no longer reports a timeout that did not happen, and its work-directory cleanup no longer deletes the hook's answer | Without `timeout` (stock macOS) a hook that finished in time was denied at random, and under load a deny could come out as nothing | None known; only the path without `timeout` changed |
| #95 | v0.2.10 | Path resolution works without GNU `realpath -m` | On macOS a symlink to a credentials file was not recognised | About 4 ms per call on a Mac; none on Linux |
| #100, guards-unified#43 | v0.2.10 | `scan.sh` uses no bash 4 syntax; a static check and a macOS CI job guard it | The bash 4 lowercase expansion made every context rule fail on stock macOS bash 3.2, so `KEY=value` was not redacted by the local scan | `scan.sh` is slow on bash 3.2 for a very long unbroken run followed by a key (tracked in #71) |
| #141 | v0.2.12 | The scan image patches the same six gitleaks Go modules as the server image, and a CI check (`dockerfile-go-drift`) fails if the two lists differ | The plugin's image patched three and still carried findings the server image had already fixed | One more list to keep in step; the check fails the build when the server changes its list before the plugin does |
| #143, coordination #100 | v0.2.12 | Every deny, ask and withhold message carries a `Fix:` clause; a withhold notice says the command ran and only its output was withheld; `docs/AGENTS-GUIDE.md` and `guards_status` tell a guards message from another hook's | A block with no fix costs a retry loop, and a withheld output that read like a failure made the model rerun a command that had already run; 93 of 749 `kubectl` results in the replay were blocked by a hook that was not a guard | Anything that matches the old wording of a message needs updating; `credfile-diff` compares messages without the label and without letter case |

## Loosening and walk-backs

| PR | Version | What | Why | Cost or residual |
|---|---|---|---|---|
| #6 | v0.1.0 | `SendMessage`: redact and send instead of deny | The other guards redact exact spans; all-or-nothing denial was inconsistent | A message goes out with redaction markers |
| #19 | v0.1.0 | `UserPromptSubmit`: from blocking to a note only | Claude Code lets this event block the whole prompt or add a note, nothing in between; blocking was judged too costly | **Real loss of protection:** a secret in your own prompt reaches the model. Only a platform-side control can close it |
| #20 | v0.1.0 | PII flagged, not redacted, in the Bash hook (`PII_GUARD_MODE=flag`) | The PII model tagged a git remote as an email address, an epoch timestamp as a phone number, a tool name as a person; redaction destroyed output | PII reaches the model unredacted, only the types are noted |
| #35 | v0.1.3 | Same for `SendMessage` | Messages go between your own agents; redaction destroyed operational content | Same |
| #21 | v0.1.0 | `SendMessage` when the service is down: degrade (local secret scan, allow, disclose) instead of deny | Denying blocked all cross-agent coordination on one dependency | PII is not scanned during an outage, only disclosed |
| #27 | v0.1.2 | Injection warning needs a 0.95 confidence floor (`INJECTION_MIN_SCORE`) | Benign security-themed text scored 0.86 to 0.91 as malicious; real attacks 0.977 and up | Text that discusses override phrasing can still score above it; recall on indirect injection is about 6% |
| #38 | v0.1.3 | Self-heal removes only a container it can prove is its own stale instance | A copy running in a sandbox once removed the production container | An unmanaged container holding port 8700 needs manual cleanup |
| coordination #55 | v0.2.10 | Self-heal installs the patched gitleaks that guards-unified publishes with its release, checked against SHA-256 values this plugin carries; it falls back to the upstream binary with a warning if that fails. | A host without Docker ran upstream gitleaks, which bundles Go modules with known HIGH CVEs that the image no longer has. Hashes carried in the plugin (and kept equal to the server's by a CI check) mean a tampered release page cannot pass, which a checksum served beside the download cannot promise. | Another file to keep in step with the server's. A failed patched install silently (a warning in the log) leaves the weaker binary in place. Proven end to end only at the first release that carries the assets. |
| #57 | v0.2.2 | A scan that times out keeps the original text; withholding on timeout was tried and dropped | A timeout was withholding a user's whole result to protect against a rare case; a policy choice made inside a bug fix was backed out | A scan that runs out of time leaks rather than blocks |
| #59 | v0.2.2 | PII and injection flags only on the first 2 KB (`FLAG_MAX_BYTES`), abandoned after a budget | The models cost about 0.25 s per KB (the server's figure) and parallel requests did not help; the hook runs on every Bash call | **PII and injection beyond 2 KB are never flagged;** the hook is still not always under one second |
| #60 | v0.2.2 | Credential-file and publish guards ask the person for ambiguous cases instead of denying | Blocking every match stopped ordinary work (a `.env` being debugged, an issue documenting flag syntax) | A distracted person can approve a real leak; the original incident (a punctuation-heavy key after "secret key") is now an ask. Sure things still deny |
| #62, #63 | v0.2.2 | Scanner sync: a value that is an existing path is never a password; `PWD` and `OLDPWD` are skipped | The `PWD` environment variable matched a password alias, so every mention of the working directory was redacted and the publish guard blocked a commit that only contained it | A password that is also a real path on the scanning host is not redacted |
| #65 | v0.2.3 | Scanner sync: the key-name rules' delimiter is a space or tab only, no longer a newline | A heading that ended in "token:" or "secret:" followed by an indented line had that line's first word redacted | **Removed real protection:** a value on the line after its key (a YAML scalar) was no longer caught |
| #66 | v0.2.3 | Scanner sync: YAML next-line rule restored narrowly (key line is only the key and a colon, next line a single bare token) | Restore the YAML scalar case without the heading false positive | A heading ending in a keyword and a colon, followed by exactly one word, still redacts that word |
| #15, #16, #92 | v0.1.0; narrowed in v0.2.10 | Metrics directory made `chmod 777`, then private when it can be | The container's non-root user (uid 1000) could not write to a root-owned bind mount | v0.1.0 made it world-writable (verdicts only, never scanned text, but any local user could read, fill or replace the log). Now mode 0700 for a host user with uid 1000, 0700 plus an ACL entry for uid 1000 where `setfacl` exists, and `0777` with a warning only otherwise (not warned on macOS, where Docker Desktop maps the owner) |
| #50 (decision pending) | Unreleased | A guard that scans content written with `Write`, `Edit`, `MultiEdit` and `NotebookEdit` is **not built** (declined for now). | The commit guard already scans the staged diff, so a committed file is caught at `git commit`. A replay of a fixed random sample of 1,500 real writes (from 21,887 distinct writes in one maintainer's sessions) through the scanner changed 95 of them (6.3%: 3.0% of edits, 14.2% of whole-file writes), and 93 of the 95 were the ambiguous key-name rule, not a vendor token shape. A guard that denied or asked would have interrupted about 1 write in 16, and 1 whole-file write in 7. | An uncommitted file with a credential in it, a file shared another way, and a value from your own prompt that is written out are not scanned, so the value lands on disk and in the transcript. The 95 were not reviewed one by one (their content was not read), so some may be real secrets; the replay measures how often a guard would fire, not how often it would be right. Revisit when a path-aware rule (test and fixture directories, `*.example` files) can bring the rate under 1% on the same sample. |
| guards-unified#55 (server change) | v0.2.10 | The server's default PII types are narrowed to six structured kinds (email, phone, SSN, passport, card, IBAN); `IP_ADDRESS`, `PERSON` and `LOCATION` are off unless `PII_ENTITIES` adds them. The plugin sees it as fewer notes with no plugin change | The server changelog gives the reason: addresses, host or city-like names and tool names are routine in operator output, and on one set of real transcripts these three were 96% of all PII notices (a figure from the changelog, not re-run here). With no `PERSON` or `LOCATION` the model is also not run, so a scan is faster | A name, place or IP address in output is no longer noted unless the server opts in. PII is still never redacted by default, so nothing changes for the text itself |
| #132 | Unreleased | A PII type is named once per session (`GUARDS_PII_NOTE_ONCE=1`, state kept per session), and `GUARDS_PII_IGNORE_ENTITIES` filters the note, set from the launch environment only so an agent cannot loosen it | After the default change a person on an older server default, or who re-enables a type, still got one note per command (coordination issue #97) | A second finding of the same type in the same session raises no note, so a new PII value of a type already named goes unannounced for the rest of the session. Secret redaction is untouched. Without a session id, or if the state file cannot be written, the note is shown |
| #137, coordination #98 | v0.2.11 | `credfile-guard` drops the body of a heredoc that only writes data (`cat > f <<EOF`, `tee f <<EOF`) before looking for reader words and sensitive paths | 8 of the 13 credfile blocks in the replay that were not reads only named a path in text being written | A path in text that a data-writing heredoc writes is no longer checked (the file that text creates is checked when read). A heredoc fed to an interpreter, a shell or a pipe, an unterminated heredoc, and a path on the command line still deny. Off: `GUARDS_CRED_HEREDOC_STRIP=0` |
| #138, coordination #99 | v0.2.11 | `publish-guard` judges a `git commit` on its message and staged diff; a heredoc that only writes a file is dropped from the scanned command text | 62 of the 73 publish-guard blocks in the replay were `git commit` commands, many because of an unrelated command chained on the same line | A credential in a file that a heredoc writes and the commit does not stage is not checked. `git add`, `-a` and a pathspec on the line turn it off for that command. Off: `GUARDS_PUBLISH_COMMIT_SCOPE=0` |
| #144, coordination #86 | v0.2.12 | The key-header content sniff reads a file as a key only when it looks like one (a header that starts or ends its line, a key inside JSON, or a header plus a base64 body); a document that names the header in a sentence reads | A design note or runbook that quoted the header could not be read by the agent | A header alone on a line inside a code fence still denies. A header named mid-sentence followed by a key body wrapped to lines under 40 characters is not caught by the sniff (output redaction is the backstop). Off: `GUARDS_CRED_SNIFF_STRICT=1` |

Not a plugin change but a deliberate non-hardening: access-key and client IDs
are not redacted by default (the scanner switch is `SECRET_GUARD_REDACT_KEY_IDS`),
because an ID is a semi-public identifier and the secret half is the boundary.
It arrived with #55.

Not hardening and not loosening, but worth knowing: #47 (v0.1.4) lengthened the
image pull timeout to 240 s inside a 270 s hook timeout, because a 15 s timeout
meant nobody ever picked up a fixed image; the cost is up to several minutes
the first time a cold pull happens. #49 (v0.2.2) added Watchtower so a fixed
image reaches you within minutes; the cost is a Docker-socket mount and a
floating tag (see [`LIMITS.md`](LIMITS.md)). #22 (v0.1.0) raised the
service's memory limit from 2 GB to 4 GB because kernel out-of-memory kills
looked like an intermittent outage.

The description of #59 says a 1 KB prefix and a 0.5 s budget. The shipped values
are 2 KB and `0.25 + 0.3 s per KB` (0.85 s for 2 KB); the code and the README are
authoritative.

## The open inconsistency: ask in `auto` mode

The two guards that use Claude Code's `ask` decision now behave the same in
unattended sessions. This was an open inconsistency; it is closed by #71
(coordination issue #35, private repo).

- The **publish guard** reads the permission mode. In `auto`, `bypassPermissions`
  and `dontAsk` (or an unrecognised mode) it denies an ambiguous match, because
  an `ask` was seen to run with no person answering and a publish cannot be
  undone (#62).
- The **credential-file guard** used to ask regardless of mode. In `auto` mode
  its `ask` for a `.env` or kubeconfig was answered by Claude Code itself, and
  the read went through (observed live), so it was not a gate. It now applies
  the same rule: ask in `default`, `acceptEdits` and `plan`, deny elsewhere.

Decision (#71): ask only where a person can answer. The cost: in `auto`,
`bypassPermissions` and `dontAsk` an agent that legitimately needs a `.env` or
kubeconfig is denied and cannot be approved in-session; the person must read it
themselves, or start Claude Code with `GUARDS_CRED_ASK` set to `force` (ask in every mode,
only if a person is attached) or `GUARDS_ALLOW_CRED_READ=1`.

Another open item: `FLAG_MAX_BYTES`. With flags on the hook waits for the models
at about 0.25 s per KB of the prefix. Earlier timings were taken before v0.2.10
changed the default PII setup and were removed instead of re-measured.
A 2 KB prefix covers roughly 80% of outputs completely (measured over 120
sessions), 3 KB roughly 90%. A real fix needs an asynchronous tier on the
platform side; the hook cannot get there by chunking.

## Knobs and their direction

| Setting | Direction | Effect |
|---|---|---|
| `GUARDS_CRED_ASK=0` | Harden | `.env`, kubeconfig, `.npmrc`/`.pypirc`, terraform state become hard denies in every mode, including `default`, `acceptEdits` and `plan` |
| `GUARDS_CRED_ASK` set to `force` | Loosen in unattended modes | Ask in every mode, including those where no person answers. Only for an operator who knows a person is attached |
| `GUARDS_CRED_IDENTITY_USE=0` | Harden | Turns the use-only registry off: any reader word plus a sensitive path on one line is a deny again, even when the credential is only the `-i` of `age` or `ssh`, the `--kubeconfig` of `kubectl` and so on. | The default (`1`) exempts a credential handed to a tool in `cred-use-registry.tsv`, because those tools use it without printing it (each row is run against a real throwaway credential in CI, and the forbidden forms are shown to print it), and a command such as `SECRET=$(cat a) T=$(age -d -i KEY f)` or `ssh -i KEY host \| head` was denied only because a reader word and the key shared a line. Of 20 realistic shapes, 8 were false positives and are now allowed; the 20-shape battery pins every outcome. | The exemption protects the credential, not what the tool prints: `age -d` prints the decrypted payload (output redaction covers it), and `ssh-keygen -p`/`-t … -f` can rewrite or overwrite a key (integrity, accepted; pinned as intentionally allowed in `credfile-battery.test.sh`). A row is a trust decision: a tool version that starts printing a credential would make the exemption a hole until a canary fails. Anything else on the line that names the credential still denies. Still denied although nothing prints a credential: `ls ~/.ssh \| head` (needs a rule for pipes into `xargs`, coordination#89) and tools with no row (`sops`, `op`, `gpg`). |
| `GUARDS_PUBLISH_ASK=force` | Loosen in unattended modes | Ask in every mode, including those where no person answers. Only for an operator who knows a person is attached |
| `GUARDS_PUBLISH_ASK=0` | Harden | Every match is a hard deny |
| `GUARDS_ALLOW_CRED_READ=1`, `GUARDS_ALLOW_PUBLISH_SECRETS=1`, `GUARDS_MCP_SCAN=0` | Loosen | Turn a guard off for the session |
| `FLAG_MAX_BYTES` larger | Harden (PII, injection), slower | More of the output is flagged; each KB costs about 0.25 s |
| `FLAG_MAX_BYTES=0` | Loosen (PII, injection), faster | No PII or injection notes |
| `GUARDS_FAST_BASH=0` or `PII_GUARD_MODE=redact` | Mixed | Older path: scans only the first 24 KB for secrets, but redacts PII |
| `GUARDS_MCP_SKIP` | Either | A narrower pattern scans more tools; the default skips grāmatr's own server |
| `INJECTION_MIN_SCORE` | Either | Lower shows more injection warnings, with more false positives |
| `SECRET_GUARD_REDACT_KEY_IDS=1` (scanner) | Harden | Also redacts access-key and client IDs |
| `SECRET_GUARD_B64=0` (scanner) | Loosen | Turns off the base64 pass |
| `SECRET_GUARD_REFERENCE_VALUES=0` (scanner) | Harden | Turns off the reference-value exemptions, so a value that only points at a credential is redacted again (and the publish guard denies it again) |
| `GUARDS_CRED_HEREDOC_STRIP=0` | Harden | A heredoc that only writes data is scanned again for reader words and sensitive paths |
| `GUARDS_PUBLISH_COMMIT_SCOPE=0` | Harden | The whole command text of a `git commit` is scanned again, including unrelated heredocs on the same line |
| `GUARDS_CRED_SNIFF_STRICT=1` | Harden | Any file that holds a private-key header is a key again |

## Design lessons

These recur across the history above. Lessons that are about the scanner apply
here because the plugin vendors it.

1. **One hard rule: no secrets.** It is the one control that must be fast and
   synchronous. PII and injection are best-effort notices on a prefix, because
   their models cost about 0.25 s per KB and cannot be sped up by parallelism.
   Policy, asynchronous delivery and audit belong to a platform behind
   `GUARDS_ENDPOINT`, not to this open-source plugin.
2. **Context beats shape.** gitleaks keys on value shape; real credentials often
   lack one. The rules key on what a value is next to. The cost is false
   positives, so every context rule needs benign lookalike tests and a skip list.
3. **Bias toward over-redaction for secrets, toward flag-only for PII.** A leaked
   credential is permanent; a redacted harmless value is recoverable. For PII on
   engineering text the reverse holds.
4. **Every false-positive fix removes some protection; state what.** #65 removed
   the YAML next-line case and #66 restored it narrowly; #62 and #63 declared an
   existing path is never a password. Write the residual down and keep a
   "must stay unchanged" test beside every "must redact" test.
5. **Judge the value as well as the key.** Both `PWD` bugs came from trusting the
   name alone.
6. **A detection that does not redact is worse than none.** "Found" with
   unchanged text gave a false sense of safety (the unquoted pattern, caps, a
   quadratic timeout, an argument-length crash, an empty field skipping the
   others). Assert that "found" implies changed text, and fail closed inside the
   scanner on survivors.
7. **Fail open versus fail closed is per surface, and must be explicit.** Closed:
   the publish guard (irreversible). Open: tool-output redaction, MCP results,
   the prompt note (a safety net must not become a single point of failure).
   `SendMessage` was denied-when-down at first and now degrades with disclosure.
   Never decide fail-closed inside a bug fix; ask.
8. **An `ask` protects only if a person answers.** In `auto`, `bypassPermissions`
   and `dontAsk` Claude Code resolves it. Irreversible actions must deny where no
   person is present. Any bypass the agent can type for itself (a marker in the
   command) defeats the guard; only a human decision or a variable set before
   launch counts as an override.
9. **Deny before, redact after.** Where the output schema is undocumented (Read,
   Grep) a rewrite is silently ignored, so a pre-tool deny is the only reliable
   control. Where the schema is not validated (MCP), rewrite only recognised
   shapes and never guess. A second `PreToolUse` hook on the same event silently
   drops `updatedInput`, so `SendMessage` keeps a single one.
10. **Hot path rule.** No change to the Bash hook without before and after
    numbers from the real service, an off switch (`GUARDS_FAST_BASH=0`,
    `FLAG_MAX_BYTES=0`), and a fallback to the previous behavior on any error.
    Avoid leading-`*` globs and bounded large regex repeats on large text in
    bash; the first base64 pass cost 2.9 s per scan.
11. **Speed bugs are leak bugs.** Timeouts and caps return the original text.
    Never cap matches; keep the scan cap above realistic output; disclose what
    was not scanned.
12. **Test against reality.** Live runs found what unit tests could not: `PWD`,
    ask-in-auto, the MCP result shape. `guards/tests/run-all.sh` mirrors CI
    (gitleaks hidden from `PATH`, the scanner image, no host paths) because
    tests passed on a laptop and failed in CI twice.
13. **Vendored copy parity.** The vendored `scan.sh` is a copy of guards-unified's
    `app/scan.sh`. Every scanner change needs a paired sync PR here, and a PR
    should be opened only after every commit is pushed: a fix once merged
    without its later commits (#52 reached `main` without its second commit,
    which landed as #53).
14. **Version and tag discipline.** A tag push on guards-unified is the only
    publish; versions move in lockstep; a burned number is skipped, never deleted
    or reused.
15. **Writing about secrets trips the guards.** Pass commit messages and PR bodies
    as files, use fabricated values built at run time, describe shapes, and mark
    deliberately fake fixture lines `guards:synthetic`. Never use a rotated value
    or a lookalike of a real one.
16. **Protocol limits shape policy.** `UserPromptSubmit` can only add a note or
    block the whole prompt; that, not preference, is why the prompt guard is
    advisory. Document such limits as limits and route the real fix to the
    platform.
17. **Self-healing can destroy.** Port reconciliation once removed a production
    container from a sandbox copy. The fix proves staleness (this project's image
    and a compose file under the plugin cache) before removing anything, at the
    cost of manual cleanup in edge cases.
