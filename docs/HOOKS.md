# Hooks reference

The plugin registers eight hooks (`guards/hooks/hooks.json`) and starts one MCP
server (`guards/.mcp.json`). This page lists each one and, more importantly,
what each does **when things go wrong**.

For why the hooks are arranged this way (one rewriter per tool), see the
"Architecture" section of [`guards/README.md`](../guards/README.md).

## Hook table

| Event | Matcher | Script | Timeout | What it does |
|---|---|---|---|---|
| `SessionStart` | `*` | `bin/guards-selfheal.sh` | 270 s | Installs gitleaks if missing, checks for a plugin update, starts and updates the guards-unified container. Always exits 0. |
| `PostToolUse` | `Bash` | `hooks/combined-hook.sh` | 15 s | Scans stdout and stderr. Redacts secrets; prepends a note for PII and for likely injection. Rewrites the Bash output shape only. |
| `PostToolUse` | `mcp__.*` | `hooks/mcp-output-guard.sh` | 30 s | Redacts secrets in MCP tool results of recognised shapes. Skips `^mcp__plugin_gramatr_` by default. |
| `PreToolUse` | `SendMessage` | `hooks/sendmessage-guard.sh` | 15 s | Redacts secrets in `message`, `summary`, `content` before the message is sent; flags PII. Must stay the only `PreToolUse` hook on `SendMessage`. |
| `PreToolUse` | `Read\|Grep\|Bash` | `hooks/credfile-guard.sh` | 10 s | Denies reads of credential files and of any file containing a private-key header; for `.env`, kubeconfig, `.npmrc`/`.pypirc` and terraform state it asks where a person can answer and denies otherwise. |
| `PreToolUse` | `Bash\|mcp__.*github.*` | `hooks/publish-guard.sh` | 40 s | Denies (or asks about) `gh` publishes, `gh api` with a body, `git commit` and GitHub MCP writes that carry credentials. |
| `PreToolUse` | `Bash` | `hooks/outbound-guard.sh` | 15 s | Denies (or asks about) a Bash command that would send credential material to a remote host: a credential file, or the whole environment, given to `curl`, `wget`, HTTPie, `nc`, `scp`/`rsync`/`sftp` or `ssh`, or a literal credential in the command text. A deny teaches the safe forms. See [`OUTBOUND-SAFE-FORMS.md`](OUTBOUND-SAFE-FORMS.md). |
| `UserPromptSubmit` | none (all prompts) | `hooks/userpromptsubmit-guard.sh` | 15 s | Adds a note if the prompt contains a secret. Cannot redact or block. |

MCP server: `mcp/server.py`, with the tools `scan(text)` and
`check_before_publish(text_or_command, cwd, kind)`, four `guards://guide/...`
resources and server `instructions` (see "Working with the guards as a coding
agent" below). `scan` calls the service's
`POST /v1/scan` with a 15 s client timeout. Anything that is not a real scan
result comes back as `{"error": ...}`, never as a clean-looking result:

| Outcome | Result |
|---|---|
| 2xx with a `findings` list | the service's JSON, unchanged |
| 413 (text over the service limit, 64 KiB by default) | error naming the status, the byte count, the limit and the server setting (`SCAN_FULL_MAX_BYTES`); nothing was scanned |
| any other non-2xx | error naming the HTTP status and the start of the body |
| 2xx without a `findings` list | error: answered HTTP 2xx without scan findings |
| timeout or connection error | error starting "guards backend unreachable at ..." |

Two constraints worth knowing when you edit `hooks.json`:

- Exactly one `PostToolUse` hook may rewrite a given tool's output; the Bash and
  MCP matchers are disjoint for that reason.
- `sendmessage-guard.sh` must stay the only `PreToolUse` hook matching
  `SendMessage`. With a second hook registered, `updatedInput` was observed to
  be silently dropped. `credfile-guard.sh`, `publish-guard.sh` and `outbound-guard.sh` match `Bash`
  but never return `updatedInput`.

How Claude Code combines two `PreToolUse` decisions on the same Bash call (for
example `ask` from the credential-file guard and `deny` from the publish guard)
is Claude Code's behavior and has not been confirmed from this repository.

## Failure-mode matrix

"Service" means the guards-unified container on `GUARDS_ENDPOINT`. "Local
fallback" means the vendored `scan.sh`, which covers **secrets only**. PII and
injection have no local fallback, because they need the loaded models.

Legend: **open** = the text or action goes through unchecked; **closed** =
the action is denied; **degrade** = a weaker check runs and the hook says so.

| Hook | Service down | Service slow (timeout) | No scanner available |
|---|---|---|---|
| **Bash output** (`combined-hook.sh`), fast path | Secret scan - **local fallback**, full `scan.sh` with gitleaks, bounded to 6 s inside the hook's 10 s internal deadline (see below). PII and injection notes: absent, with no message. | Secret route times out after 2 s, then the full local scan runs. Flag scan is dropped silently when its budget (0.85 s for 2 KB) passes. | `scan.sh` missing and service down: the hook falls through to the older path, which prints a message to stderr and passes the output through unchanged (**open**). `jq` missing: the built-in scan (private keys, key-name context, session environment values) runs on the whole payload; a result with a finding is **withheld** with a reason that says to install `jq`, a clean one passes with a note that the check was partial (vendor-token formats, PII and injection are not checked). |
| **Bash output**, older path (`GUARDS_FAST_BASH=0` or `PII_GUARD_MODE=redact`) | **Local fallback** for secrets only; stderr message "falling back to local scan.sh". | The 6 s request limit applies; on timeout it behaves as down. | `scan.sh` missing or not executable: pass-through with a stderr message (**open**). |
| **MCP result** (`mcp-output-guard.sh`) | **Local fallback** (full `scan.sh`), per text block. | Secret route times out after 2 s, then local scan. Many large blocks in one result run into the 20 s internal deadline, at which the result is **withheld** (see below). | `scan.sh` missing: nothing is scanned (**open**). `jq` missing: as for the Bash hook, a result with a finding is **withheld** (replaced by one text block naming `jq`), a clean one passes with a note. A text block over 512 KB is skipped silently (**open**). A failed scan leaves the block untouched (**open**). |
| **SendMessage** (`sendmessage-guard.sh`) | **Degrade**: each field gets a local secret-only scan; the hook returns `allow` with the updated input and a note that PII scanning was unavailable. It returns `allow` even if nothing was found. | The hook decides reachability from the `message` field and then treats the service as down for all three fields. The three fields share a 4 s budget for the service; a field the service did not answer in time gets the local secret-only scan. Everything is bounded by the 10 s internal deadline, at which the message is **denied**. | `scan.sh` not executable and service down: the fields pass through unchanged while the note still says a local scan ran (**open**). `jq` missing: the built-in scan runs on the whole payload; a message with a finding is **denied** (it cannot be redacted without `jq`) with a reason that says to install `jq`, a clean one is allowed with a note. |
| **Credential-file guard** (`credfile-guard.sh`) | Does not use the service. Unaffected. | Does not use the service. Internal deadline 6 s: **closed** (deny) if the check does not finish. | `jq` missing: the guard still decides, reading the few fields it needs with awk (**closed** for credential files as usual); if even that cannot find the tool name, the call is denied with a reason that says to install `jq`. A payload `jq` cannot parse is passed (**open**). |
| **Publish guard** (`publish-guard.sh`) | Service route skipped; the full local scan runs. Still enforces. | Secret route times out after 2 s, then the full local scan. | No scanner can run (service unusable **and** `scan.sh` missing, crashed, or over its 15 s limit), or the whole hook passes 25 s: **closed**, the publish is denied. `jq` missing: the hook still decides, reading the few fields it needs with awk (`json-lib.sh`) and scanning without gitleaks, with a notice that vendor-token formats were not checked; a payload it cannot read is denied with a reason that says to install `jq`. gitleaks missing only: the built-in passes still run, with a notice (vendor-token formats are not checked). |
| **Outbound guard** (`outbound-guard.sh`) | The file and environment checks never use the service. For a literal credential in the command text it runs the full local `scan.sh`; still enforces. | The secret route times out after 2 s, then the local scan (4 s) and the environment pass (2 s) run. Internal deadline 9 s: **closed** (deny) for a command that names a client. | No awk, or the parser crashes: **closed** (deny). No scanner (service unreachable **and** `scan.sh` missing): a command that names a client is **denied** with "no secret scanner could run"; a by-reference deny still names its own reason and skips the scan. `jq` missing: the prefilter reads the raw payload and the fields are read with awk; an unreadable payload that names a client is denied with an install-`jq` reason. A command that names no client exits at the prefilter (about 3 ms, **open**, as it is not a network command). A parser limit (unbalanced quoting, a command over 8 KB, nesting deeper than 3) is a note plus the checks that could run, not a deny. |
| **UserPromptSubmit** (`userpromptsubmit-guard.sh`) | No note (**open**). There is no local fallback. | The request carries `curl -m 8`; a prompt that needs longer gets no note (**open**). | `jq` missing: no note and one line on stderr (**open**; advisory by design, it never blocks or rewrites). A malformed or error answer (no `findings` list, HTTP error, non-JSON) is treated like down: no note. |
| **MCP `scan` tool** | Returns `{"error": "guards backend unreachable ..."}`, never a false "clean". | 15 s client timeout, then the same "unreachable" error. A non-2xx answer (including 413) returns an error naming the real status. | n/a |
| **Self-heal** (`SessionStart`) | n/a (it starts the service) | A pull is limited to 240 s and the health poll to 30 s (15 polls, 2 s apart). A pull timeout warns and carries on with the cached image; a service that never answers warns. Exit status is 0 in every case. | No Docker, or the daemon down: logs that PII and injection are unavailable, touches nothing; secrets still work through the local fallback. A missing compose file makes `up -d` fail: warning, no health poll. A failed gitleaks download or missing `jq` is a warning. |

Notes on the matrix:

- "Open" for the Bash and MCP hooks means the **pre-existing** behavior of Claude
  Code applies: the original tool output reaches the model. A safety net that
  can break the tool is worse than none for these two surfaces.
- The publish guard is the one place that fails **closed**, because a publish
  cannot be undone.
- **A hook that exceeds its `timeout` fails open.** Verified by experiment
  (Claude Code 2.1.304, 2026-10-20, repeated twice): Claude Code kills the hook,
  records its outcome as `cancelled`, and proceeds as if the hook were not
  there. The tool call goes through the normal permission flow and the model sees
  no timeout message. This holds even for a hook that would have returned a
  deny. Any exit status other than 0 or 2 is also a non-blocking error (the tool
  runs). Only exit 2 or a JSON deny blocks. Every hook therefore
  enforces its own deadline below its configured timeout and decides for itself
  what happens at expiry, and a crash gets the same deliberate outcome (next
  section).
- **An `ask` with no person attached is a deny.** Verified in headless
  `claude -p` in every permission mode (default, acceptEdits, plan, auto,
  bypassPermissions, dontAsk): the tool call does not run, the model receives the
  hook's reason text, and the run records a permission denial. An `ask` even
  overrides an allow rule and bypassPermissions. Not tested: the prompt in a
  session with a person attached. Interactive `auto` mode is different: there
  an ask was observed to be answered by Claude Code itself with no person, which
  is why the guards deny rather than ask where no person can answer.
- **Conflicting PreToolUse decisions: deny beats ask beats allow, in any
  order.** Verified with two hooks on the same Bash call, in either order, in
  one matcher group or two, and with the first hook the slower one. An `allow`
  from one hook never overrides another hook's `ask` or `deny`. Hooks with the
  same matcher run concurrently, so configuration order is not a tiebreaker.
  A guard with nothing to say should return no decision rather than `allow`, so
  that it never masks the user's own permission flow.
- When a scan is cut by a size cap rather than a failure (Bash output past
  256 KB, the older path past 24 KB, SendMessage fields past 24 KB, MCP blocks
  past 512 KB), see [`LIMITS.md`](LIMITS.md). The Bash and SendMessage hooks
  disclose it; the MCP guard does not.

## Internal deadline versus configured timeout

`hooks/deadline-lib.sh` re-runs each hook under its own deadline and maps what
happens to a deliberate outcome. The deadline is at most 70 % of the timeout in
`hooks.json`, so no timeout needed raising. `guards/tests/hook-deadlines.test.sh`
hangs the scanner of every hook, runs it under a kill at the configured timeout
and asserts it answers at least 3 s earlier; the same test against the previous
hooks fails (they are killed, which is the fail-open).

| Hook | `hooks.json` timeout | Internal deadline | Outcome at expiry or crash |
|---|---|---|---|
| Publish guard | 40 s | 25 s | **Deny**, with a reason that says the scan did not finish and what to do. Inner bounds: service 2 s, local scan 15 s. |
| Credential-file guard | 10 s | 6 s | **Deny**, same shape. |
| Outbound guard | 15 s | 9 s | **Deny**, with the reason and the override. Inner bounds: service 2 s, local scan 4 s, environment pass 2 s. A command that names no client never reaches the wrapper. |
| Bash output (`combined-hook.sh`) | 15 s | 10 s | **Withhold**: stdout is replaced by a notice that the output was not checked and should be produced again; stderr is emptied. Inner bounds: service 6 s, local scan 6 s. |
| MCP result (`mcp-output-guard.sh`) | 30 s | 20 s | **Withhold**, in the shape of the result (content array, string, or object with `content`). Shapes the hook never scans are left alone, as always. Inner bound: local scan 8 s per block. |
| SendMessage | 15 s | 10 s | The service gets 4 s across all fields, then the local secret-only scan (the documented degrade); if even that does not finish by 9 s, or the hook crashes, **deny**. |
| UserPromptSubmit | 15 s | 10 s | No note, nothing else (advisory, as documented). Inner bound: service 8 s. |
| Self-heal (`SessionStart`) | 270 s | none | Not a guard and makes no decision; unchanged. |

Notes: a hook with nothing to say returns no decision, never an explicit allow.
The SendMessage degrade path still returns `allow` with the updated input, as
before, because it must carry the rewritten message. Without `timeout` on the
machine (stock macOS) the lib falls back to a bash watchdog.

## Ask versus deny by permission mode

Three guards use Claude Code's `ask` decision, and they treat modes the same way.
Details and the reasoning are in [`TRADEOFFS.md`](TRADEOFFS.md).

| Guard | `default`, `acceptEdits`, `plan` | `auto`, `bypassPermissions`, `dontAsk`, unknown |
|---|---|---|
| Publish guard, ambiguous match | ask | **deny** (no person to answer) |
| Publish guard, sure thing | deny | deny |
| Credential-file guard, ask-class file (`.env`, kubeconfig, ...) | ask | **deny** (no person to answer); `GUARDS_CRED_ASK` set to `force` asks in every mode, `0` denies in every mode |
| Credential-file guard, deny-class file or private-key content | deny | deny |
| Outbound guard, ask-class file (`.env`, kubeconfig, ...) or a filtered environment dump | ask | **deny** (no person to answer); `GUARDS_OUTBOUND_ASK` set to `force` asks in every mode, `0` denies in every mode |
| Outbound guard, ambiguous literal (`-u user:pw`, an `X-Api-Key` or `Authorization` value, URL userinfo, `password=` in a body, `--password`) | ask | **deny** |
| Outbound guard, sure thing (a credential store or the whole environment sent, a vendor-shaped token, a private-key header, a value from the session's own environment) | deny | deny |

## Behavior pinned by the tests

Each hook below has a test in `guards/tests/` that runs in `run-all.sh` and in
CI, against a stub service (no real credential, container or network). The
tests are the specification for the points listed.

**SendMessage guard** (`sendmessage-guard.test.sh`)

- Clean input: no output, input untouched. Other tools and all-empty fields are ignored.
- A secret is redacted and the hook answers `allow` with `updatedInput` and a note; it never denies.
- `message`, `summary` and `content` are each scanned from their own text. An empty `message` does not stop `content` from being scanned.
- `summary` is cut to 200 characters on the redaction path. A clean 300-character summary with nothing else to report produces no output, so it is not cut.
- PII is flagged and left intact by default; `PII_GUARD_MODE=redact` replaces it.
- A field past `SCAN_MAX_BYTES` (default 24576): only that many bytes are sent, the rest is reattached unchanged, and the note says so. This applies even when nothing else was found.
- Service down, or answering 200 without a `findings` list: local secret-only scan of every field, `allow`, and a note that PII scanning could not run. With no executable `scan.sh` as well, the text passes unchanged but the hook still answers `allow` (**open**).

**UserPromptSubmit guard** (`userpromptsubmit-guard.test.sh`)

- Clean prompt: no output, exit 0. Empty prompt: nothing is sent.
- A secret adds one `additionalContext` note (`hookEventName: UserPromptSubmit`, nothing else) that does not repeat the value. The hook never blocks and never rewrites.
- PII and injection findings in the prompt add nothing.
- Service down, error answer, malformed answer, curl timeout, `jq` missing: no note, exit 0.
- Length: the hook sends the prompt to the secret-only route (`/v1/scan/secret`), never the full route, and passes it to `jq` on stdin, so the operating system's per-argument limit (about 128 KB) does not apply. A 200 KB prompt is sent whole and a credential at its very end gets the note. A prompt past 900000 bytes is cut to that length so the route's 1 MiB cap is never hit; a credential in the first 900000 bytes still gets the note, one after that is not seen (**open**). A service refusal (413) or an outage gives no note (**open**).
- Latency, measured 2026-10-20 against the live service (guards-unified 0.2.4, `http://127.0.0.1:8700`, one host, CPU image): the whole hook, from process start to exit, six runs each with small fabricated prompts. A 70-byte clean prompt: 199 to 231 ms (median about 209 ms). A 70-byte prompt holding a fabricated token: 210 to 220 ms (median about 214 ms). This is one machine on one day, with prompts far below the sizes where the model cost grows (about 0.25 s per KB per the service docs); larger prompts were not measured and will be slower, up to the 8 s request limit.

**Outbound guard** (`outbound-guard.test.sh`, a throwaway HOME with fabricated credential files and ssh-keygen keys, a stub service)

- Every by-reference row of the #49 probe table in each permission mode: a credential file sent as a body, upload, form field, header file, stdin redirect, pipe or `$(...)` denies; `.env`, kubeconfig and a filtered environment dump ask where a person can answer and deny elsewhere; the whole environment denies.
- The safe forms stay silent (variable reference, `-K`, `--netrc`, `-H @file`, a payload file, stdin, `--data-raw @x`, `-o file`, `--cert/--key`), and so do commands that merely mention a client word.
- A path built by a variable or substitution is allowed with a note; a credential path written inside a substitution is still caught.
- Literal credentials: a vendor-shaped token, a private-key header, an AWS access key id and a value from the session's own environment deny in every mode; `-u user:pw`, an `X-Api-Key` value, URL userinfo, `password=` and `--password` ask or deny by mode; a sandbox placeholder, an opaque request id and a variable reference stay silent.
- `GUARDS_ALLOW_OUTBOUND_SECRETS=1` in the environment silences the guard; in front of a command, or after `export` in the same command, it changes nothing.
- A deny never holds a path, a file name, file content, a value or the first 4 characters of one; it names the class and the flag, locates the match as the scanner redacts it, and names the safe forms. Every form it names has a case in `outbound-safeforms.test.sh`.
- The prefilter: a stub `mktemp` proves a command that names no client never reaches the deadline wrapper; the service is called once for a client command, never for a by-reference deny or for `echo curl`.
- A hung parser is denied inside the 9 s deadline and 6 s before the 15 s timeout; a crashing parser is denied; with no scanner at all a client command is denied and a by-reference deny keeps its own reason.
- `hooks.json` registers the hook on `Bash` with a 15 s timeout and an internal deadline of at most 70 percent of it.

**Publish guard** (`publish-guard.test.sh`, throwaway git repositories, local scanner)

- A deny names the rule(s) and a "Where" list: for each of up to 5 matches, the
  source (the command text, a file the command names, or "the staged diff, file F, line N")
  and the line as the scanner redacts it. The raw value never appears in the
  message (checked for a context match, a private key and an environment value).
- `guards:synthetic` on the same line drops an added line of the staged diff. It
  does not excuse a `-m` message or a file named by `-F`/`--body-file`/`cat`.
  `GUARDS_ALLOW_PUBLISH_SECRETS=1` in front of the command does not change the
  answer; set in the hook's environment it does.
- The repository is found through `git -C`, `cd`, quoted and relative paths,
  `pushd`, subshells, `--git-dir`/`--work-tree` and `GIT_DIR`/`GIT_WORK_TREE`,
  so another repository's staged lines are not scanned instead.
- `git add ... && git commit` in one command scans what the add will stage
  (a marker added since the last `git add` counts; a new unmarked file is seen),
  without touching the real index.
- `git -c k=v commit` and `git --no-pager commit` are inspected like `git commit`.
- A marked line is still checked for a private-key header, an AWS access key id, a GitHub, Slack, Stripe or OpenAI-style live key and denied (naming the family, never the value); the documented EXAMPLE ids, values containing EXAMPLE or FAKE, JWT-shaped strings and ordinary fixtures are accepted.
- A diff over `PUBLISH_GUARD_MAX_BYTES` is cut, and the hook says so.

**MCP server** (`mcp-server.test.py`)

- The instructions are at most 150 words and carry the rules and the four resource URIs; a client over stdio receives them with the resources and both tools.
- The guides state the marker scope and the defaults, and pass the scanner unchanged.
- `check_before_publish` denies text and commits with the located, value-free explanation, allows a marked staged line, ignores an inline override, reports `inspected: false` for a command that is not a publish, and returns `{"error": ...}`, never an allow, when the hook is missing, crashes or answers garbage.

**Self-heal** (`guards-selfheal.test.sh`, `docker`, `curl`, `git`, `timeout`, `sleep` stubbed)

- Service already healthy: the script still runs `docker compose pull` and `up -d` (both idempotent) and removes nothing; with an unchanged version it prints nothing on stdout.
- Service missing: `up -d` starts it and the health poll then succeeds.
- A version change across the pull, or a plugin commit behind upstream, produces one `SessionStart` `additionalContext` note.
- Containers on the old ports 8730-8732 are removed. A container on `:8700` is removed only if it is a `guards-unified` image whose compose file sits under this user's plugin cache; anything else is left alone with a warning.
- The env file is created empty with mode 600 if absent, and set back to 600 if loosened.

## Working with the guards as a coding agent

The longer version of this section is [`docs/AGENTS-GUIDE.md`](AGENTS-GUIDE.md).

The guards are meant to be worked with, not around. What an agent needs to know:

1. **Never put a real credential** in a commit message, PR or issue body,
   comment or file: not a prefix, a partial, or a rotated one. Describe the
   shape (length, character classes, which tool produced it).
2. **Put long messages and bodies in a file** (`git commit -F`, `gh ... --body-file`),
   and check the text first with the `check_before_publish` tool of the plugin's
   MCP server. It runs the real publish guard offline and returns allow or deny
   with the located, value-free explanation.
3. **`guards:synthetic` on the same line** marks a deliberately fake fixture line.
   It covers only the added lines of the staged diff of a `git commit`, and not
   a real vendor credential or key (a private-key header, an AWS access key id,
   a GitHub, Slack, Stripe or OpenAI-style live key is still denied on a marked
   line; documented EXAMPLE ids and values containing EXAMPLE or FAKE are fine).
   It does not cover the command text (so not a `-m` message), `gh issue`/`gh pr`
   bodies, or files named by `--body-file`, `-F` or `cat`.
4. **`GUARDS_ALLOW_PUBLISH_SECRETS=1` does nothing when typed in front of a
   command.** The hook reads its own environment, which is the one Claude Code
   was started from. It is the user's switch, for a reviewed false positive.
5. **Never disable the guards and never ask the user to.** Report a false
   positive (which key, which rule) and let the user decide.
6. **A block says where.** The message lists up to 5 places (the command text, a
   named file, the staged diff with file and line), each line shown as the
   scanner redacts it. A key name that only names an identifier of a secret
   (`secret_vault_id`, `client_secret_bws_id`, `token_store_ref`) is a false
   positive: rename or reword it if you can, and report it.

The plugin's MCP server carries this so the agent has it without anyone
pasting it: the rules are in the server `instructions` (they reach the agent's
system prompt), four resources hold the detail (`guards://guide/publishing`,
`guards://guide/false-positives`, `guards://guide/hooks`,
`guards://guide/diagnosing-a-block`), and `check_before_publish` is the tool.
For projects that want the rules in their own agent instructions, this snippet
for `CLAUDE.md` or `AGENTS.md` is self-contained:

```markdown
## Secret guards

This session runs gramatr-guards. It redacts secrets in command and MCP output,
denies reads of credential files, and blocks commits, PRs, issues and comments
that look like they contain a credential. Rules:

- Never put a real credential in a commit message, PR or issue body, comment or
  file. Describe its shape (length, character classes, source), not its value.
- Put long messages and bodies in a file and check them first with the
  `check_before_publish` tool of the `guards` MCP server.
- Mark a deliberately fake fixture line of a commit with `guards:synthetic` on
  the same line. It covers added lines of a git commit's staged diff only: not
  the commit message, not PR or issue bodies, not files named by `--body-file`.
- `GUARDS_ALLOW_PUBLISH_SECRETS=1` typed in front of a command does nothing.
- Never disable the guards or ask the user to. A block shows the matching line
  with the value redacted; if it is a false positive (for example a key named
  `secret_vault_id`), rename or reword it, or report it.
```

## Agent tools that exercise the publish guard

`guards/mcp/guards_tools.py` (registered by `mcp/server.py`) adds tools around the publish guard (see also [AGENTS-GUIDE.md](AGENTS-GUIDE.md)):

- `check_before_publish` (in `mcp/server.py`) runs `hooks/publish-guard.sh` itself in the strict `auto` mode and returns its located, value-free explanation.
- `prepare_publication` and `mark_synthetic` produce the two forms the hook
  accepts: text in a file named by `--body-file` or `-F`, and fixture lines in a
  commit's staged diff carrying `guards:synthetic`. The marker is honoured only
  in the staged diff, never for command text, bodies or named files.
- `explain_block`, `guards_status` and `report_false_positive` only read or write
  local files; no tool sets, clears or suggests a bypass.

Tests: `guards/tests/mcp-tools.test.py` compares `check_before_publish` with the
hook's decision on the same input across a matrix (clean text, fixture line unmarked and
marked, command text with a fake credential, `-F` file).
