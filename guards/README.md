# gramatr-guards — Claude Code plugin

Secret, PII and prompt-injection guards for Claude Code. The plugin wires
seven hooks and one MCP server into a session. They catch credentials in
tool output, agent-to-agent messages, MCP results, credential files and
outbound publishes (issues, PRs, commits).

The detection logic lives in the
[guards-unified](https://github.com/gramatr/guards-unified) service, one
container that bundles the secret, PII and injection detectors behind
`POST /v1/scan` and `POST /v1/scan/secret`. This repository is the thin
Claude Code side: hooks, an MCP `scan` tool, and a self-heal script that
keeps the container running. For what changed between versions, read
guards-unified's
[CHANGELOG.md](https://github.com/gramatr/guards-unified/blob/main/CHANGELOG.md).
For the service's API and the secret-detection rules, read its
[docs](https://github.com/gramatr/guards-unified/tree/main/docs) and README.

**One hard rule, everything else best effort.** The only control that must be
fast, synchronous and strict is "no secrets": secrets are redacted or blocked.
PII and prompt-injection findings are best-effort notices; they never change
the text. Read [`docs/LIMITS.md`](../docs/LIMITS.md) before relying on this.

## Documentation map

| Doc | What it covers |
|---|---|
| This file | Overview, install, what each guard does |
| [`docs/AGENTS-GUIDE.md`](../docs/AGENTS-GUIDE.md) | One page for coding agents and for people who write CLAUDE.md/AGENTS.md: tools, prompts, skill, rules |
| [`docs/HOOKS.md`](../docs/HOOKS.md) | Per-hook table (matcher, timeout) and the failure-mode matrix |
| [`docs/CONFIGURATION.md`](../docs/CONFIGURATION.md) | Every environment variable the plugin reads |
| [`docs/LIMITS.md`](../docs/LIMITS.md) | What the guards do not catch |
| [`docs/TRADEOFFS.md`](../docs/TRADEOFFS.md) | Where the guards were tightened or loosened, and why |
| [Threat model](https://github.com/gramatr/guards-unified/blob/main/docs/THREAT-MODEL.md) | Assets, actors, trust boundaries, and what is and is not defended (in guards-unified) |
| [`SECURITY.md`](../SECURITY.md) | How to report a vulnerability privately |

## The seven hooks

| # | Event and matcher | Script | What it does |
|---|---|---|---|
| 1 | `SessionStart` | `bin/guards-selfheal.sh` | Starts and updates the guards-unified container; installs gitleaks if missing |
| 2 | `PostToolUse` on `Bash` | `hooks/combined-hook.sh` | Redacts secrets in stdout and stderr; notes PII and injection |
| 3 | `PostToolUse` on `mcp__.*` | `hooks/mcp-output-guard.sh` | Redacts secrets in MCP tool results |
| 4 | `PreToolUse` on `SendMessage` | `hooks/sendmessage-guard.sh` | Redacts secrets in outgoing agent-to-agent messages; notes PII |
| 5 | `PreToolUse` on `Read\|Grep\|Bash` | `hooks/credfile-guard.sh` | Denies (or asks about) reads of credential files before any content exists |
| 6 | `PreToolUse` on `Bash\|mcp__.*github.*` | `hooks/publish-guard.sh` | Denies (or asks about) publishes that carry credentials |
| 7 | `UserPromptSubmit` | `hooks/userpromptsubmit-guard.sh` | Adds a note when your own prompt contains a secret. Advisory only |

Plus an MCP server (`mcp/server.py`, started with `uv run --script`) that
exposes one tool, `scan`.

Matchers, timeouts and what each hook does when the service is down are in
[`docs/HOOKS.md`](../docs/HOOKS.md).

What you will see: a redacted secret is replaced by the literal marker
`***REDACTED:SECRET***`. A PII note starts with "pii-guard flagged possible
PII"; an injection warning starts with "injection-guard flagged this content".
Both are prepended to the Bash output. A rewritten MCP result comes with a
"guards mcp-output-guard: redacted credential material" note naming the
detector rules, never a value.

## Install

Prerequisites:

- Claude Code with plugin support.
- `docker` with `docker compose`, for PII and injection detection and for the
  fast secret path. Without Docker, secret detection still works through the
  local `scan.sh` fallback; PII and injection do not (see
  [`docs/HOOKS.md`](../docs/HOOKS.md)).
- `jq` and `curl`. Every hook needs `jq`; the credential-file and publish
  guards **fail open** without it.
- `uv`, for the MCP `scan` tool (`.mcp.json` runs it with `uv run --script`).
- `gitleaks` is optional. If it is missing, the self-heal script downloads
  v8.30.1 for Linux or macOS (x64 or arm64), checks its SHA-256 against the
  release checksum file, and installs it to `~/.local/bin`. Other platforms get
  a warning and the built-in passes only.
- For the injection finding only: a Hugging Face token whose account has
  accepted the Llama Prompt Guard 2 license (below).

```
claude plugin marketplace add gramatr/claude-plugin-guards
claude plugin install guards
```

Then start (or restart) a Claude Code session; the `SessionStart` hook runs the
self-heal automatically. To confirm the hooks are registered, use `/hooks`.

### The HF_TOKEN requirement

The injection finding needs a Hugging Face token that has accepted Llama
Prompt Guard 2's gated license. Accepting someone else's license is a manual,
per-user step, so it cannot be automated. Put `HF_TOKEN=<your token>` in
`~/.config/gramatr-guards/injection-guard.env`. The self-heal script creates
that file empty (mode 0600) if it is missing and warns. Without a token the
secret and PII findings work normally and the injection finding does not
(the model cannot load).

### Stopping and uninstalling

Remove the plugin from Claude Code's `/plugin` menu, then stop the containers
it started:

```
docker compose -f <plugin dir>/docker/docker-compose.yml down   # stops guards-unified and watchtower
```

Optional cleanup: `~/.config/gramatr-guards/`, `~/.local/share/gramatr-guards/`
(metrics and the self-heal lock), and the downloaded `~/.local/bin/gitleaks`.
Environment variables that disable single guards are listed in
[`docs/CONFIGURATION.md`](../docs/CONFIGURATION.md).

## Architecture

### Where the work happens

- **Secrets** are scanned in two places. The warm service answers
  `POST /v1/scan/secret` (about 55 ms). The vendored `scan.sh` then runs
  locally for the passes that need this process's environment. If the service
  is down, too slow (2 s), too old to have the route, or returns an error, the
  full local `scan.sh` runs instead (with gitleaks if installed). Protection
  never depends on the service being up. The shared code is
  `hooks/secret-scan-lib.sh`; the Bash hook (fast path), the MCP result guard
  and the publish guard all use it.
- **PII and injection** need the loaded models, so they exist only in the
  service (`POST /v1/scan`). There is no local fallback for them.
- `guards/vendor/secret-guard-core/scan.sh` is a copy of
  `app/scan.sh` in guards-unified. Every change to the scanner needs a paired
  sync commit here, and CI enforces it: the `scan-sh-drift` job
  (`guards/tests/scan-sh-drift.sh`) fetches guards-unified's `app/scan.sh` from
  `main` (on a tag build, the same tag when guards-unified has it) and fails if
  this copy differs by even one character, apart from its two-line header.
  Merge the guards-unified change first, then re-run the check here. To run it
  locally: `SERVER_REF=<branch> bash guards/tests/scan-sh-drift.sh`.

### One rewriter per tool

Claude Code runs several hooks matched on the same event in parallel, and its
documentation leaves the winner undefined when more than one returns
`updatedToolOutput`. So exactly one `PostToolUse` hook rewrites each tool's
output: `combined-hook.sh` for `Bash`, `mcp-output-guard.sh` for `mcp__.*`. The
matchers are disjoint. The same problem was observed for `PreToolUse`:
`sendmessage-guard.sh` must stay the only `PreToolUse` hook that matches
`SendMessage`, because with a second one registered `updatedInput` was silently
dropped. `credfile-guard.sh` and `publish-guard.sh` match `Bash` but never
return `updatedInput`.

### Why Read, Grep and WebFetch output is not rewritten

Claude Code publishes the `updatedToolOutput` shape for `Bash` only, and a
value that does not match a tool's schema is silently ignored. A rewrite hook
there would look protected and leak. The credential-file guard denies the read
up front instead; other content those tools return is unscanned.

### The Docker stack

`docker/docker-compose.yml` runs two services:

- `guards-unified`: image `ghcr.io/gramatr/guards-unified:cpu`, published on
  `127.0.0.1:8700` only, 4 GB memory limit, 16 CPUs ceiling, metrics volume at
  `~/.local/share/gramatr-guards/metrics`, `HF_TOKEN` from the env file above.
- `watchtower` (pinned `nickfedor/watchtower:1.23.1`): polls the registry every
  5 minutes and swaps in a newer `guards-unified` image without a Claude Code
  restart. It is scoped by label to the `guards-unified` container. It needs
  `/var/run/docker.sock`, which is root-equivalent on the host; the trust
  boundary is "this pinned image is maintained". The floating `:cpu` tag means
  a published image reaches your machine within minutes. To pin a version,
  change the tag and remove the watchtower service.

The loopback-only publish line is deliberate; read
[`docker/SERVER-SIDE.md`](docker/SERVER-SIDE.md) before changing it. The
service has no authentication and receives raw tool output, so never expose it.

The metrics volume holds one JSON line per finding (timestamp, type, verdict,
reason code), never the scanned text, and is never transmitted. The writer is
the server, not the hooks.

`vendor/secret-guard-core/{Dockerfile,server.py}` is a standalone gitleaks
wrapper image. It is **not** part of the running stack; CI builds it only to run
the redaction regression test inside it and to scan it.

### What the self-heal does on every session start

`bin/guards-selfheal.sh` is idempotent and always exits 0. It installs gitleaks
if missing; compares the installed plugin commit with `main` (a note appears in
the session if it is behind); and, if Docker is usable, takes a lock, creates
the env file and the metrics directory (`chmod 777`, so the container's
non-root user can write), removes only provably stale containers holding port
8700 (an image of this project whose compose file lives under the plugin
cache), pulls the image (240 s limit), runs `docker compose up -d` and polls
`/health` for up to 30 s. A version change of the running image is reported to
the session. The hook's own timeout is 270 s. An unmanaged container that
holds port 8700 is deliberately not removed; clean it up by hand.

## What each guard does

### Bash output (PostToolUse): `combined-hook.sh`

Runs after every Bash call. stdout and stderr are scanned separately. Secrets
are redacted. PII and injection are noted without changing the text. Only the
Bash output shape `{stdout, stderr, interrupted, isImage}` is rewritten.

The default path (`GUARDS_FAST_BASH=1`) does two things at once:

1. **Secrets, always and fast.** Up to `SECRET_MAX_BYTES` (256 KB) go through
   the secret-scan library. Bytes past the cap are not scanned; a warning is
   prepended and the remainder is returned unchanged.
2. **PII and injection flags, best effort.** Only the first `FLAG_MAX_BYTES`
   (2 KB) are sent to the full `POST /v1/scan`, in parallel with the secret
   scan. The wait budget is `FLAG_BUDGET` seconds, by default
   `0.25 + 0.3 * KB` (0.85 s for 2 KB). A late or failed answer is dropped
   without notice. An injection warning is shown only for a "malicious" verdict
   scoring at least `INJECTION_MIN_SCORE` (0.95).

The models cost roughly 0.3 s per KB and are not made faster by parallel
requests, which is why they see a prefix only. Measured end to end, with flags
on the hook is not always under one second (see [`docs/LIMITS.md`](../docs/LIMITS.md)).
`FLAG_MAX_BYTES` and `FLAG_BUDGET` are read by this hook, not by the server.

`GUARDS_FAST_BASH=0` and `PII_GUARD_MODE=redact` select the older single-call
path: the first `SCAN_MAX_BYTES` (24 KB) go to `/v1/scan`, and PII is replaced
too (`redact`). The old path is also the fallback if the library or every
scanner is unavailable.

PII is flagged, not redacted, by default because the PII model produced false
positives on engineering output (a tool name tagged as a person, a git remote
tagged as an email address, a timestamp tagged as a phone number). Secrets are
always redacted.

### MCP result guard (PostToolUse): `mcp-output-guard.sh`

Redacts secrets in an MCP tool's result before the model sees it. Claude Code
passes MCP replacement output through with no schema validation, so the hook is
deliberately conservative. It rewrites only recognised shapes and returns the
same shape: an array of `{"type":"text","text":...}` blocks, an object with
such a `content` array (other fields preserved), or a bare string. Images,
resources and unknown wrappers pass through untouched. Each text block is
scanned on its own, using the same secret-scan library as the Bash hook
(service first, local `scan.sh` otherwise). It fails open on any error.

- A text block larger than `MCP_GUARD_MAX_BYTES` (512 KB) is skipped silently
  and arrives unredacted.
- Tools whose name matches `GUARDS_MCP_SKIP` (default `^mcp__plugin_gramatr_`)
  are not scanned: grāmatr's own server returns session tokens by design.
  The plugin's own `scan` tool is scanned like any other.
- `GUARDS_MCP_SCAN=0` disables the hook.

**Verified status:** verified live on 2026-10-19 (the plugin's own `scan` tool
echoes its input, which made a convenient seed). The payload shape was
originally taken from a session transcript rather than from a documented
example, so re-verify after a Claude Code upgrade that changes MCP result
handling. Tests: `guards/tests/mcp-output-guard.test.sh`.

### Outbound messages (PreToolUse): `sendmessage-guard.sh`

Scans an agent-to-agent `SendMessage` **before** it is sent. A message goes to a
different agent, possibly a different user, possibly logged elsewhere, so this
protects what leaves the session.

- `message`, `summary` and `content` are each scanned independently (they are
  not copies of each other; `content` is a truncated preview and `summary` is
  limited to 200 characters). Each scan covers the first `SCAN_MAX_BYTES`
  (24 KB) of a field, and the hook says so when it truncated what it scanned.
  After redaction, `summary` is cut to 200 characters.
- Secrets are redacted. PII is flagged in `additionalContext` and left in place
  by default; `PII_GUARD_MODE=redact` replaces it. Injection findings are
  ignored on purpose: the sending agent wrote the message.
- It returns `permissionDecision: "allow"` together with `updatedInput` and
  `additionalContext` only when something changed (a secret, PII, or a
  truncated summary); otherwise it exits silently.
- **When the service is unreachable it degrades, it does not block.** Each field
  gets a local secret-only scan, and the hook returns `allow` with the updated
  input and a note that PII scanning was unavailable. In this branch the hook
  returns `allow` even when nothing was found.
- It has no automated test. To check the redaction path without sending
  anything, build a fake value at run time and pipe a crafted payload in:

```bash
FAKE="$(printf 'A%.0s' {1..40})"
jq -n --arg m "password: $FAKE" \
  '{tool_name:"SendMessage", tool_input:{to:"test", message:$m}}' \
  | bash guards/hooks/sendmessage-guard.sh
```

`updatedInput.message` in the output is what Claude Code would use for the
call. If it still shows the value, the redaction path is broken.

### Your own prompt (UserPromptSubmit): `userpromptsubmit-guard.sh`

**Advisory only. It protects nothing.** If your prompt contains a secret, the
hook adds an `additionalContext` note next to the prompt. The prompt is
submitted exactly as typed and the secret reaches the model and the API. If it
is a real credential, treat it as exposed the moment you typed it and rotate it.

This is a limit of the hook protocol, not a choice of effort: `UserPromptSubmit`
cannot rewrite or remove part of a prompt. The only options are to block the
whole prompt or to add a note. An earlier version blocked; that was reversed
because blocking every prompt that tripped a detector was judged too costly.
The note is written as a statement of fact rather than an instruction, so it
does not look like injected text.

Only the secret finding is used. PII and injection are ignored (it is your own
data and your own instruction). The hook sends the prompt to the secret-only
route (`/v1/scan/secret`, 8 s limit, no models), cut at 900000 bytes, so a
credential anywhere in a long prompt is found. With the service down, or for a
prompt the service refuses, no note appears. It has no local fallback.

### Credential-file guard (PreToolUse): `credfile-guard.sh`

Denies reads of credential material **before** any content is produced, for the
`Read`, `Grep` and `Bash` tools.

**Always denied:** SSH private keys under `~/.ssh` (not `*.pub`, `known_hosts`,
`config`, `authorized_keys`), `~/.aws/credentials`, gcloud credential files,
`~/.docker/config.json`, GPG private keyrings, `.netrc`, `.pgpass`,
`.git-credentials`, `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519`, keystores
(`*.p12`, `*.pfx`, `*.jks`, `*.keystore`, `*.kdbx`), service-account and
client-secret JSON files, whole credential directories, and **any readable
regular file whose content has a PEM/OpenSSH private-key header, whatever its
name** (see "False positives" below).

**Ask (only where a person can answer; see "Permission modes" below)** for files that merely contain
credentials but are often needed for debugging: `.env` and `.env.*` (not
`.env.example`, `.sample`, `.template`, `.dist`), kubeconfig, `.npmrc`,
`.pypirc`, and terraform state. These go to the human through Claude Code's
permission prompt in `default`, `acceptEdits` and `plan` modes, and are hard
denies in `auto`, `bypassPermissions`, `dontAsk` or any mode the hook does not
recognise. A deny-class match in the same call still wins.

For `Bash`, only commands that print file content (`cat`, `head`, `tail`,
`sed`, `awk`, `grep`, `base64`, `xxd`, `strings`, `python`, ...) and name a
sensitive path are checked. Globs are expanded (20 matches per glob, 60 tokens
per command). `ssh -i key host`, `ssh-keygen -l -f key`, `test -f key` and
`ls ~/.ssh` use or inspect a key without printing it and are allowed.

**Permission modes.** An `ask` is only a gate if a person answers it. In `auto`
mode Claude Code answers it with its own approval logic: a `.env` read went
through without a prompt (verified live). So this guard follows the rule the
publish guard already uses: ask in `default`, `acceptEdits` and `plan`, deny in
`auto`, `bypassPermissions`, `dontAsk` or an unknown mode. `GUARDS_CRED_ASK` set to `force`
asks in every mode (for an operator who knows a person is attached);
`GUARDS_CRED_ASK=0` denies in every mode. See
[`docs/TRADEOFFS.md`](../docs/TRADEOFFS.md).

**False positives from the private-key content sniff.** The sniff reads the
first `CREDFILE_SNIFF_MAX_BYTES` (10 MiB) of every readable regular file a
command names, whatever the file's name. A document that merely quotes a
private-key header, such as a design note, a test fixture or this kind of
documentation, is therefore denied as "file contains a private key". This hits
Bash commands too, because glob arguments are expanded before the check: a
command like `grep -r pattern docs/*` or `cat *.md` is denied if any one
expanded file contains such a header, even though you did not name it.

How to deal with it:

1. Name the files you mean instead of a glob, and leave the offending file out.
2. Do not write a literal key header into documents. Describe the shape ("a PEM
   private-key header line") or build fixture text at run time in the test.
3. As a last resort, `GUARDS_ALLOW_CRED_READ=1` in the environment Claude Code
   starts from turns the whole guard off for that session. There is no per-call
   bypass, by design: anything the agent could type for itself would also work
   for a prompt-injected agent.

Other limits: a `Grep` over a whole directory is checked by directory and glob
name only; a Bash command that reads a key indirectly (a script that cats it, a
path in a variable, `eval`) is not caught; the hook fails open if `jq` is
missing or the payload cannot be parsed. Tests:
`guards/tests/credfile-guard.test.sh` (throwaway keys generated at run time).

### Pre-publish guard (PreToolUse): `publish-guard.sh`

Blocks commands that would publish credential material. Redaction after the
fact cannot help once something is public, and GitHub push protection knows
only vendor token formats and does not scan issue bodies.

**What it covers**

- `gh issue|pr|release|gist` with `create`, `comment`, `edit` or `review`.
- `gh api ...` when the call carries a body flag (`-f`, `-F`, `--field`,
  `--raw-field`, `--input`).
- `git commit`, including `git -C <dir> commit`, `git -c k=v commit` and a
  commit after `cd <dir>`: the command text (the message) **and** the added
  lines of the staged diff (`--cached`; the working tree against `HEAD` when
  `-a`/`--all` is used), minus lines containing `guards:synthetic`. The
  repository is found by following `cd`, `pushd` and `git -C` in order (quotes
  and `~` understood, relative paths resolved against the session's directory),
  and `--git-dir`/`--work-tree`/`GIT_DIR`/`GIT_WORK_TREE`. With `git add ... &&
  git commit` in one command the add has not run yet, so it is replayed against
  a throwaway copy of the index (plain pathspecs and `-A`, `-u`, `-f` only;
  anything else falls back to the tracked changes against `HEAD`). Each file or
  diff is capped at `PUBLISH_GUARD_MAX_BYTES` (512 KB); the hook says when a
  diff was cut.
- GitHub MCP write tools: tools whose name matches `mcp__.*github.*` **and**
  contains one of `create`, `update`, `add_`, `comment`, `push`, `merge`,
  `review`, `edit`, `post`, `send`, `write`. The whole `tool_input` is scanned.

The scanned text is the full command (heredoc bodies included) plus the
contents of any file the command names (`--body-file`, `--notes-file`,
`--input`, `-F`/`-f` file arguments, `cat FILE`, gist files), so a body file is
not a bypass.

**What it does not cover.** `git push` itself is not inspected: only the commit
is. A secret that is already committed is not caught at push time. Also not
covered: `curl` or other posters, scripts that publish indirectly, non-GitHub
MCP tools (GitLab, Jira, Slack, ...), and the GitHub web UI. See
[`docs/LIMITS.md`](../docs/LIMITS.md).

**Decision.** On a finding it never rewrites the text and never echoes a
value. The message names the detector rules, says **where** the match is (up to
5 places: the command text, a file the command names, or the staged diff with
file and line; each line is shown as the scanner redacts it, so the key and its
context are visible and the value is not), and says what to do: describe the
*shape* only, how far `guards:synthetic` reaches, and that the override is the
user's. Example:

```
Where (first 2 of 2; each line is shown as the scanner redacts it, the value itself is never printed):
  1. the staged diff, file src/cfg.ts, line 3: db_password: "***REDACTED:SECRET***"
  2. the staged diff, file src/cfg.ts, line 5: api_secret = "***REDACTED:SECRET***"
```

| Finding | `default`, `acceptEdits`, `plan` | `auto`, `bypassPermissions`, `dontAsk`, or unknown mode |
|---|---|---|
| Sure thing: a private key, a vendor token format gitleaks recognises, a value from this session's own environment, a base64-wrapped secret | deny | deny |
| Ambiguous match from a key name or URL shape (secret-word lead-in, URL password, auth or cookie header, CLI password flag, `.netrc`/`.pgpass`, k8s or JSON name/value pair, Azure/gcloud/bcrypt shapes, generic API key) | **ask** (rule names, no value) | **deny** |
| No scanner could run (service unreachable and `scan.sh` missing or failed) | deny | deny |

Why deny where no person is present: in `auto` mode Claude Code resolves an
`ask` without a person, and an `ask` was seen to let a command carrying a fake
password run straight through. A publish cannot be undone, so the hook reads
`permission_mode` from its input and denies instead. The deny message says that
the mode has no person to answer.

`GUARDS_PUBLISH_ASK=force` asks regardless of mode (for an operator who knows a
person is attached); `GUARDS_PUBLISH_ASK=0` makes every match a hard deny.
`GUARDS_ALLOW_PUBLISH_SECRETS=1` in the environment Claude Code starts from
bypasses the guard for a reviewed false positive. A line carrying
`guards:synthetic` is dropped from the staged diff for deliberately fake
fixtures; it does not apply to command text (a `-m` message), issue or PR
bodies, or named files (`--body-file`, `-F`, `cat`). Typing
`GUARDS_ALLOW_PUBLISH_SECRETS=1` in front of a command does nothing: the hook
reads its own environment. If only gitleaks is missing, the built-in passes still run and the
hook adds a notice. The hook fails open only if `jq` is missing.

Because this hook runs in the session's own environment it also turns on
`SECRET_GUARD_ENV_VALUES=1` for the scanner: the values of environment
variables whose names look secret (`*TOKEN*`, `*PASSWORD*`, ...) are
exact-match redacted. That is the only way to catch a bare value with no key
name or prefix. Values shorter than 8 characters, placeholders, existing file
paths, and names ending in `_FILE`, `_PATH`, `_DIR`, `_URL`, `_NAME`, `_ID`
and similar are skipped.

Writing about secrets trips the guard too. Pass commit messages and PR bodies
through files, describe shapes rather than values, and mark deliberately fake
fixture lines `guards:synthetic`. Tests: `guards/tests/publish-guard.test.sh`.

### The MCP server: `mcp/server.py`

The server is named `guards`. It exposes:

- **`scan(text)`**, for any MCP-capable caller. It posts to
  `POST {GUARDS_ENDPOINT}/v1/scan` (15 s limit) and returns the service's JSON:
  a finding each for `secret`, `pii` and `injection`, plus `redacted_text`
  (secrets and then PII redacted; injection never alters text). If the service
  is unreachable it returns `{"error": ...}` instead of a false "clean": a
  caller that explicitly asked for a scan should not be told something is clean
  when it was never checked. Scanning a secret with this tool returns the secret
  inside the finding's `detail`; the MCP result guard redacts that on the way
  back because the tool is not in the default skip list.
- **`check_before_publish(text_or_command, cwd="", kind="auto")`**, which runs
  `hooks/publish-guard.sh` itself, offline, on a would-be command, body or
  message (permission mode `auto`, so the answer is the strict one) and returns
  `{"decision": "allow"|"deny", "inspected": bool, "explanation": str}`. On a
  deny the explanation is the hook's located, value-free message. A command
  the guard does not inspect (not a publish) is `allow` with `inspected: false`.
  If the check cannot run (hook missing, crashed, timed out) the result is
  `{"error": ...}`, never an allow. `GUARDS_ALLOW_PUBLISH_SECRETS` in the
  server's environment is ignored (and mentioned). The tool talks to the
  service only through the hook, which falls back to the local scanner.
- **Instructions** (about 135 words): what the guards do, the three rules an
  agent must follow, and where to look. MCP clients add server instructions to
  the agent's system prompt, so this is the channel that reaches the agent.
- **Resources** `guards://guide/publishing`, `guards://guide/false-positives`,
  `guards://guide/hooks` and `guards://guide/diagnosing-a-block`.

Tests: `guards/tests/mcp-server.test.py` (HTTP client stubbed for `scan`; the
`check_before_publish` tests run the real hook in throwaway repositories; one
test starts the server over stdio and reads the instructions and resources as a
client would).

## Working with the guards as a coding agent

The guards are meant to be worked with, not around. What an agent needs to know:

1. **Never put a real credential** in a commit message, PR or issue body,
   comment or file: not a prefix, a partial, or a rotated one. Describe the
   shape (length, character classes, which tool produced it).
2. **Put long messages and bodies in a file** (`git commit -F`, `gh ... --body-file`),
   and check the text first with the `check_before_publish` tool of the plugin's
   MCP server. It runs the real publish guard offline and returns allow or deny
   with the located, value-free explanation.
3. **`guards:synthetic` on the same line** marks a deliberately fake fixture line.
   It covers only the added lines of the staged diff of a `git commit`. It does
   not cover the command text (so not a `-m` message), `gh issue`/`gh pr`
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

### Agent tools, prompts and skill: `mcp/guards_tools.py`

Alongside `check_before_publish` (above), the same MCP server gives a coding agent
what it needs to work with the guards instead of against them. The one-page
reference for agents and for people writing `CLAUDE.md`/`AGENTS.md` is
[`docs/AGENTS-GUIDE.md`](../docs/AGENTS-GUIDE.md). Every tool is value-free: no result contains a
raw matched credential value (each string is shape-scrubbed and re-scanned
before it is returned). None of them disables, bypasses or weakens a guard; the
`GUARDS_ALLOW_*` overrides stay with the person who starts Claude Code.

| Tool | What it does |
|---|---|
| `explain_block(message)` | Diagnosis and next steps for a guard deny or ask message (or decision JSON): guard, rules, and each located source (command text, named file, staged diff with file and line), with the remedy that fits the source. |
| `prepare_publication(kind, title, body)` | Writes commit-message, pr-body or issue-body text to a 0600 file under the state directory, scans it, lists the lines the scanner would redact (shown redacted), and returns the command (`git commit -F`, `gh pr create --body-file`, `gh issue create --body-file`). A file with findings holds the redacted text only. |
| `guards_status()` | Registered hooks, plugin and service versions, whether the service answers, the permission-mode rules, environment overrides that switch a guard off, and degraded modes (no `jq`, no `gitleaks`, service down). |
| `mark_synthetic(path, lines, reason)` | Appends `guards:synthetic` with the right comment syntax for the file type. Refuses lines shaped like a real credential (PEM header, AKIA/ASIA id, `ghp_`/`gho_`/`github_pat_`, `xox*-`, `sk-`, JWT, 40+ character base64), an empty reason, paths outside the cwd's git repo, and file types with no comment syntax. |
| `report_false_positive(rule, redacted_line, context)` | Writes a value-free JSON report under the state directory and returns its path and a line for the user to forward (the public repos have Issues disabled). Refuses input that does not look redacted. |

Prompts: `fix_a_block`, `safe_pr_body`, `fake_fixture_checklist`. The plugin
skill `skills/guards-for-agents/SKILL.md` carries the same rules and triggers
when an agent hits a block, writes fixtures, or writes commit, PR or issue text.
Files written by the tools live in `$GUARDS_STATE_DIR` (default
`~/.local/share/gramatr-guards`). Tests: `guards/tests/mcp-tools.test.py`.

## Verified live

Two sessions checked the real behaviour instead of assuming it.

Secret redaction across every hooked surface (2026-10-19), with the service up
and with the container stopped to force each fallback:

| Surface | Service up | Service stopped |
|---|---|---|
| `PostToolUse:Bash` | Redacted | Still redacted, through the local `scan.sh` |
| `PreToolUse:SendMessage` | Redacted | Still redacted, the reason names the local-only fallback |
| `UserPromptSubmit` | **Not redacted: reaches the model as typed, by design** | No note at all |

The marketplace install flow (`claude plugin marketplace add ...`,
`claude plugin install guards`) was run end to end: the hook ran with
`${CLAUDE_PLUGIN_ROOT}` resolved, the self-heal started the container, and the
`scan` tool returned a secret finding and a PII finding for a crafted string.
The self-heal's measured run time when the container was already up was about
0.5 s.

The credential-file guard, the publish guard (including the `auto`-mode deny)
and the MCP result guard were each verified live as well. Nothing here is a
substitute for running the test suites; see the next section.

## Tests

```bash
bash guards/tests/run-all.sh
```

This runs every suite twice, once with gitleaks hidden from `PATH` (what CI
sees) and once with it visible, and once inside the built scanner image if
Docker is usable. Suites cover the credential-file guard, the publish guard,
the fast secret path, the Bash hook, the MCP result guard and `scan.sh`
redaction. There are **no** tests for `sendmessage-guard.sh`,
`userpromptsubmit-guard.sh`, `guards-selfheal.sh` or the `scan` tool in `mcp/server.py`
(the agent tools in `mcp/guards_tools.py` have `mcp-tools.test.py`).

## Server-side or hosted deployment

**Not enabled by anything in this repo.** If you consider running the service
reachable over a network, even inside your own boundary, read
[`docker/SERVER-SIDE.md`](docker/SERVER-SIDE.md) first. Setting
`GUARDS_ENDPOINT` to a remote URL sends raw tool output, which can contain the
secrets you are trying to protect, to that host.

## Versioning

This plugin and the guards-unified service are one product shipped as two
packages, so **they carry the same version and the same tag**, cut together:
`vX.Y.Z` on both repositories. The version is in the `VERSION` file at the root
of this repository. Plugin installs track `main` and are identified by commit
(that is what `/plugin` shows), so the tag here is a label; a CI check
(`.github/workflows/tag-check.yml`) fails if a pushed tag does not equal
`VERSION`. Before tagging a release, confirm `VERSION` is the same in both
repositories. The release recipe is in guards-unified's
[`docs/RELEASING.md`](https://github.com/gramatr/guards-unified/blob/main/docs/RELEASING.md).

## Why this exists

Built after a real session-long pattern: secrets and PII surfacing in raw Bash
tool output. The guards redact and classify, rather than only logging, and are
bundled so they are one plugin install away.

## License

MIT for this repository's own code; see `LICENSE`. This repository never
bundles or ships model weights; it is a thin hook and MCP client for the
guards-unified API on port 8700.

**guards-unified** (the backend these hooks call) loads
`meta-llama/Llama-Prompt-Guard-2-86M` for the injection axis, which carries its
own redistribution obligations under Meta's Llama 4 Community License ("Built
with Llama" attribution, a NOTICE file, a bundled copy of the license text).
That obligation belongs to, and is satisfied in, guards-unified's repository
(`LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES/`, and its runtime `GET /about`
endpoint), not duplicated here. If you redistribute a build of this plugin
together with a pre-pulled guards-unified image, you inherit that obligation
directly; see guards-unified's README for what is required.
