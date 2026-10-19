# gramatr-guards — Claude Code plugin

Wires [secret-guard](https://github.com/gramatr/secret-guard),
[injection-guard](https://github.com/gramatr/injection-guard), and
[pii-guard](https://github.com/gramatr/pii-guard) into Claude Code's
`PostToolUse` hook for Bash, plus a self-healing `SessionStart` hook
that keeps the backend running — **and** an MCP server (`mcp/server.py`)
exposing one `scan` tool, backed by
[guards-unified](https://github.com/gramatr/guards-unified), for any
MCP-capable caller.

## Three independent axes, one call

secret-guard, pii-guard, and injection-guard protect against three
unrelated things — credential leaks, personal-data leaks, and
jailbreak/override attempts — and none of them depends on or needs
input from the others. `combined-hook.sh` sequences all three
internally, but that's a workaround for one specific Claude Code
limitation (`PostToolUse` hooks matched on the same event run in
parallel with *undefined* resolution order when more than one tries to
rewrite the same output — see that script's own comments), not a
statement that the three guards are coupled.

The MCP server (`mcp/server.py`) exposes exactly **one** tool, `scan`,
backed by `guards-unified`'s single `POST /v1/scan` endpoint — which
already runs all three detectors unconditionally on the same text and
returns a per-finding result for each, in one response. An earlier
version of this file exposed `scan_secrets`/`scan_pii`/
`classify_injection` as three separate tools against three separate
daemons; that made sense when the backend *was* three separate
daemons, and stopped making sense once the backend became one call
that already answers all three questions at once — splitting it back
into three client-side calls would only add round trips a caller never
wanted (a caller asking about injection risk also wants to know about
leaked secrets in the same content; there's no real use case for only
checking one axis). This also closes out injection-guard's own README
roadmap item, "MCP server front-end for explicit tool-call access (vs.
automatic hook-based gating only)."

Same scope caveats apply as the hook path: the injection finding is
jailbreak/override detection, not a reliable control for indirect
injection (6% recall on real tool-output injections — see
injection-guard's `RESEARCH-SPIKE-classification.md`). The PII finding
covers Presidio's entity set only, not all PII. The tool returns an
explicit `{"error": ...}` rather than a false "clean" result if the
backend is unreachable — unlike the hooks, which fail open by design,
a caller that explicitly asked for a scan result should not be told
something is clean when it was never actually checked.

## Outbound protection: redacting agent-to-agent message leaks

`hooks/sendmessage-guard.sh` is a `PreToolUse` hook matched on
`SendMessage` — it scans an outgoing agent-to-agent message **before**
it's sent and, if it contains a secret or PII finding, **redacts and
allows** the call rather than blocking it outright — the same posture
secret-guard/pii-guard already use for incoming content (exact-span
redaction), now applied on the way out, because `guards-unified`'s
`redacted_text` gives the same exact-span guarantee for an outgoing
message that it already gives for tool output. This is a different
trust boundary than the `PostToolUse` hooks above: those protect
content coming *into* this session's context; this one protects
content this session is about to send *out*, to a different agent,
possibly a different user, possibly logged or relayed elsewhere.

- Redacts **every** text-bearing copy of the message, not just the
  field named `message` — confirmed by harvesting a real `SendMessage`
  `PreToolUse` payload: `tool_input` also carries `summary` (documented
  as "not transmitted" to the recipient, but it can still land in
  local logs/transcripts) and `content` (an undocumented field that
  turned out to be a **truncated preview** of the same text). Patching
  only `message` while leaving a secret sitting in `content` would be
  an incomplete fix with false confidence — worse than doing nothing,
  because it would look safe. All three are overwritten with the same
  redacted text.
- Uses `hookSpecificOutput.updatedInput` + `permissionDecision: "allow"`
  + `additionalContext` together — confirmed working by actually
  triggering a real `SendMessage` call and checking the `PostToolUse`
  capture of what was actually executed, not assumed from docs (this
  exact combination was explicitly unconfirmed in Claude Code's own
  hooks reference at the time of writing).
- **Must remain the only `PreToolUse` hook matched on `SendMessage`
  (or on a broad `*` that also matches it).** Confirmed by testing,
  not assumed: with a second `PreToolUse` hook also registered on the
  same event — even one that emitted no output at all — `updatedInput`
  was silently dropped and the original, unredacted message went
  through unchanged. Same "undefined resolution order across multiple
  hooks on one event" problem Claude Code's docs already warn about
  for `PostToolUse`'s `updatedToolOutput`, now confirmed to apply here
  too. If this ever needs to coexist with another `PreToolUse` hook on
  `SendMessage`, they must be combined into one script — the same
  reason `combined-hook.sh` exists for the Bash `PostToolUse` case.
- Both the `secret` and `pii` findings are redacted here — a different
  policy than a user's own prompt to their own agent (where PII isn't
  acted on, because it's the user's own data in their own
  conversation). The recipient of a `SendMessage` call is a different
  agent, possibly a different party entirely.
- The `injection` finding is deliberately ignored for this decision —
  the message is authored by the sending agent itself, not forwarded
  untrusted content, so "is this an injection attempt" isn't the
  relevant question for an outbound send.
- **Degrades, does not block, when the backend is unreachable** (changed
  in `1411d2b`, from an earlier version that denied outright in this
  case — this section previously described that older, now-incorrect
  behavior; corrected 2026-10-19). Falls back to the same vendored
  local `scan.sh`/gitleaks secret-only scan `combined-hook.sh` uses for
  its own backend-unreachable case: secrets still get real, local
  redaction via `updatedInput`; only PII scanning (which needs
  `guards-unified`'s loaded Presidio model) is unavailable until the
  backend is back. Verified live, 2026-10-19 — see "Verified live:
  secret redaction across every surface" below.

## Inbound awareness: flagging a secret in your own prompt — NOT prevention

`hooks/userpromptsubmit-guard.sh` is a `UserPromptSubmit` hook. **Read
this section before assuming it protects anything** — it is advisory
only, by deliberate choice, not the blocking control an earlier
version of this hook was.

- **The secret still reaches the model and gets sent to the API,
  exactly as typed.** If it contains a secret, this hook adds an
  `additionalContext` note alongside the unchanged prompt — it does
  not stop, redact, or undo the submission. If the value is a real,
  live credential, treat it as exposed the moment it was typed and
  rotate it; the note arriving afterward changes nothing about that.
- **Why there's no middle ground: confirmed directly against Claude
  Code's own hooks docs, not assumed.** `UserPromptSubmit` has no way
  to rewrite or remove part of a prompt — "can't replace the prompt;
  it only injects `additionalContext` alongside it." So the real
  choice for this event was always binary: block the whole prompt
  outright, or let it through unchanged with a note. This hook does
  the latter, on purpose — it is not a failed attempt at redaction.
  An earlier version of this hook blocked instead; that tradeoff was
  deliberately reversed with explicit confirmation of what it gives
  up (see this repo's PR history for both decisions).
- **Secret findings only.** PII is explicitly out of scope — it's the
  user's own data in their own conversation. The injection finding is
  out of scope too: this is the user's own direct instruction to their
  own agent, not forwarded untrusted content.
- **`additionalContext` is written as a factual statement, not an
  imperative instruction** — the same discipline `sendmessage-guard.sh`
  already follows, since imperative phrasing in a field that feeds
  back into the model's own context is exactly the shape a
  prompt-injection defense watches for.
- Fails open on backend-unreachable, same as before — simpler to
  reason about now, since this hook never blocks anything regardless:
  unreachable just means no note gets added.

## Verified live: secret redaction across every surface (2026-10-19)

Prompted by a direct question — "prove secrets never go through
unredacted, across every surface, not just one" — rather than answer
from the code or from memory, each hooked surface was tested live
against a real, synthetic GitHub-PAT-shaped value
(`ghp_16C7e42F292c6912E7710c838347Ae178B4a` — fake, never a real
credential, never needs rotation), both with `guards-unified` running
normally and with it killed outright (`docker stop
docker-guards-unified-1`) to force each hook's backend-unreachable
fallback path for real, not assumed from a comment.

| Surface | Backend up | Backend killed |
|---|---|---|
| `PostToolUse:Bash` (tool output) | Redacted — real `echo` of the fake secret came back as `***REDACTED:SECRET***` | Still redacted — same result, via local `scan.sh`/gitleaks fallback |
| `PreToolUse:SendMessage` (agent-to-agent) | Redacted — `updatedInput.message` came back with `***REDACTED:SECRET***`, confirmed via a crafted `PreToolUse` payload piped directly into `sendmessage-guard.sh` | Still redacted — same result, `permissionDecisionReason` explicitly named the local-only fallback path |
| `UserPromptSubmit` (the user's own prompt) | **Not redacted — reaches the model exactly as typed, by design.** See the section above: this is architecturally impossible to fix at this hook, not a gap in effort. | N/A — this hook never scans the backend at all for this decision |

Reproduce the `PostToolUse` case yourself: run a Bash command whose
output contains a secret-shaped string and read back what actually
came through. Reproduce the `PreToolUse:SendMessage` case without
sending anything real:

```bash
jq -n '{
  tool_name: "SendMessage",
  tool_input: { to: "test", message: "secret: ghp_16C7e42F292c6912E7710c838347Ae178B4a" }
}' | bash guards/hooks/sendmessage-guard.sh
```

The `updatedInput.message` field in the output is what Claude Code
would actually use for the tool call — if it shows the raw value, the
redaction path is broken; if it shows `***REDACTED:SECRET***`, it
isn't. This is the whole mechanism, reduced to one command — no live
backend, no real recipient, no side effects, required to check it.

## Architecture

### One combined hook, not three

`hooks/combined-hook.sh` is the **only** `PostToolUse` hook this plugin
registers — confirmed directly against
[Claude Code's hooks docs](https://code.claude.com/docs/en/hooks)
before building this: multiple hooks matched on the same event run **in
parallel**, each receiving the same original (unmodified) tool output,
and the resolution order when more than one hook returns
`updatedToolOutput` for the same call is **explicitly undefined** by
the docs ("it doesn't say which one wins"). The docs' own
recommendation: "use one hook that performs the rewrite." Confirmed
this same constraint applies to `PreToolUse`'s `updatedInput` too, not
just `PostToolUse` — see `sendmessage-guard.sh`'s own comments for how
that was found.

This script makes **one** call to `guards-unified`'s single
`POST /v1/scan` — which already runs secret, PII, and injection
detection unconditionally on the same original text and returns all
three results in one response — applies the redaction, prepends the
injection warning banner if flagged, and emits exactly one final
result. It used to make three separate sequential calls to three
separate daemons; that collapsed into one call once `guards-unified`
shipped (see
`docs/scope/ship-private-marketplace-plugin-2026-10-18.md`, Unit U1).

### Bash-only for v1

The `updatedToolOutput` schema is **per tool**, and only Bash's shape
is confirmed from the docs — a structured object, not a bare string:

```json
{"stdout": "...", "stderr": "...", "interrupted": false, "isImage": false}
```

"A value that doesn't match the tool's output schema is ignored and the
original output is used" — each sibling repo's own standalone
`adapters/claude-code/hook.sh` returns a bare string for
`updatedToolOutput`, which means **those standalone adapters would have
silently no-op'd the whole time** if ever wired into a real
`settings.json`, before this was found. This plugin's `combined-hook.sh`
emits the correct structured shape and exits 0 (pass through) for any
non-Bash tool, rather than guess at Read/Grep/WebFetch's exact shapes
and ship something that silently no-ops the same way. See "Known
limitations."

### One Docker Compose stack, not three manual installs

`docker/docker-compose.yml` runs all three guards as containers —
`secret-guard` now ships a thin HTTP wrapper (`vendor/secret-guard-core/
server.py` + `Dockerfile`) around its own `scan.sh` purely for interface
consistency with its siblings (no model to keep resident, so no
performance reason to containerize it — this is about one stack, one
shape, not three different setups). `pii-guard` and `injection-guard`
already shipped their own Dockerfiles; `injection-guard`'s lean `:cpu`
ghcr.io image is the default here (see that repo's README — the ~5x
GPU latency win doesn't matter for a synchronous hook, and it avoids a
~4.7GB pull of unused CUDA runtime).

**Every port-publish in that compose file is `127.0.0.1:PORT:PORT`,
never bare `PORT:PORT`** — this is the one line that must never be
"simplified" without reading `docker/SERVER-SIDE.md` first; secret-guard
and pii-guard's own READMEs are explicit that neither may ever be
network-reachable, even inside our own boundary.

### Self-heal, not a one-shot installer

`bin/guards-selfheal.sh` runs on every `SessionStart` — same idempotent
"check state, fix if needed" pattern as grāmatr's own
`statusline-selfheal.js`. Docker-first: if `docker` + `docker compose`
are usable, it builds/starts the Compose stack above and verifies each
service answers its own `/health` on `127.0.0.1`, not just that the
container is "Up" — found by testing, not assumed: a container can be
reported running with its port-publish silently missing if it was
created during an earlier failed bind (see the migration note below).

**Migrating off previous architectures**: the self-heal script does a
one-time migration from either state a machine could be in before this
consolidation — the original `uv tool install` + `systemd --user`
bare-metal daemons (disabled, same as before), and now also the old
three-container Docker stack (`secret-guard`/`pii-guard`/
`injection-guard` on `8732`/`8731`/`8730`), torn down in favor of the
single `guards-unified` container on `:8700`. Found by testing, not
assumed: the old stack's ports don't conflict with `:8700`, so without
this migration a machine that already ran it would end up with four
containers across two architectures, not a clean upgrade.

**Non-Docker fallback is now secret-detection only.** The old bare-metal
path ran `injection-guard-daemon`/`pii-guard-daemon` as standalone
`systemd --user` services so combined-hook.sh could still reach them on
a non-Docker machine. That path is retired: combined-hook.sh now talks
to `guards-unified` as one service, which has no non-Docker equivalent
(it's one process bundling all three models/tools, not three
independently-installable daemons). On a machine without Docker, secret
detection still works via combined-hook.sh's own local `scan.sh`
fallback (no daemon, no network dependency); PII and injection detection
require Docker. See `docs/scope/ship-private-marketplace-plugin-2026-10-18.md`,
Units U1/U2, for why PII/injection don't get an equivalent fallback —
both need actual loaded models to produce a result, so there's no cheap
local path for them the way gitleaks gives secrets.

### The HF_TOKEN problem

`guards-unified`'s injection finding needs a Hugging Face token that has
accepted Llama Prompt Guard 2's gated license. This **cannot be
automated** — accepting someone else's license is inherently a manual,
per-user step. `guards-selfheal.sh` checks for
`~/.config/gramatr-guards/injection-guard.env` (must contain
`HF_TOKEN=...`) and warns clearly if it's missing, rather than silently
starting a container whose injection finding will never successfully
load the model (the secret and PII findings don't need it and work
regardless).

## Install

```
claude plugin marketplace add gramatr/claude-plugin-guards
claude plugin install guards
```

Then start (or restart) a Claude Code session — the `SessionStart` hook
runs the self-heal automatically.

### Verified for real — this exact install flow, not just the scripts standalone

This was never actually run end to end until it was — confirmed from
real, literal output, not assumed to work because the pieces worked
individually (see `docs/scope/ship-private-marketplace-plugin-2026-10-18.md`,
Unit U3):

```
$ claude plugin marketplace add gramatr/claude-plugin-guards
✔ Successfully added marketplace: gramatr-guards (declared in user settings)

$ claude plugin install guards
✔ Successfully installed plugin: guards@gramatr-guards (scope: user)
```

`${CLAUDE_PLUGIN_ROOT}` resolved to a real cache path in both the hook
and the MCP server — confirmed from the session's own debug log, not a
literal `${CLAUDE_PLUGIN_ROOT}` string surviving into what actually
ran:

```
[DEBUG] Hooks: SessionStart:startup [bash /home/research3/.claude/plugins/cache/gramatr-guards/guards/90f9d4c0d597/bin/guards-selfheal.sh] (plugin guards@gramatr-guards) finished with status 0 (489ms)
```

`guards-selfheal.sh` ran successfully on `SessionStart` and auto-started
`guards-unified` itself. The `scan` MCP tool, called from inside that
real installed session (not a standalone `uv run`), against a crafted
string containing both a secret and PII, returned:

```json
{
  "findings": [
    {"type": "secret", "verdict": "found", "reason_code": ["SECRET_GITHUB-PAT"], "...": "..."},
    {"type": "pii", "verdict": "found", "reason_code": ["PII_EMAIL_ADDRESS"], "...": "..."},
    {"type": "injection", "verdict": "clean", "reason_code": null, "...": "..."}
  ],
  "redacted_text": "contact <EMAIL_ADDRESS> and here is a token ***REDACTED:SECRET***"
}
```

`combined-hook.sh` was also confirmed firing automatically in that same
fresh session — a real `Bash` command containing a test secret came
back redacted with no manual intervention.

## Server-side / hosted deployment

**Not enabled by anything in this repo.** If you're considering running
any of these guards reachable over a network — even inside our own
infrastructure boundary — read `docker/SERVER-SIDE.md` first. The short
version: it's architecturally fine for `injection-guard`, and explicitly
not fine for `secret-guard`/`pii-guard` per their own READMEs, for
reasons that don't go away just because the network boundary is ours.

## Credential-file guard (PreToolUse)

`hooks/credfile-guard.sh` denies reads of credential material *before any
content is produced*, for the `Read`, `Grep` and `Bash` tools. Redaction
after the fact is only a backstop: it sees Bash output only, and can miss
keys in odd shapes (escaped newlines, truncated PEM).

Denied: SSH private keys (not `*.pub`, `known_hosts`, `config`),
`~/.aws/credentials`, kubeconfigs, gcloud and docker credential files,
`.netrc`, `.pgpass`, `.git-credentials`, `.npmrc`, `.pypirc`, `.env` and
`.env.*` (not `.env.example`/`.sample`/`.template`), keystores,
`*.tfstate`, service-account / client-secret JSON, and **any readable file
whose content has a PEM/OpenSSH private-key header, whatever its name**
(sniffed with `grep -q`, never printed). For Bash, only commands that
print file content (`cat`, `head`, `sed`, `grep`, `base64`, `python`, ...)
that name a sensitive path are denied; `ssh -i key host` and
`ssh-keygen -l -f key` use a key without printing it and are allowed.

Limits: a `Grep` over a whole directory is checked by directory and glob
name only; a Bash command that reads a key indirectly is not caught; the
hook fails open if `jq` is missing. Override with
`GUARDS_ALLOW_CRED_READ=1` in the environment Claude Code starts from.
Tests: `guards/tests/credfile-guard.test.sh` (throwaway keys generated at
run time, run in CI).

## Known limitations

- **Docker is the only path to PII/injection detection now.** Its only
  hard requirement is a working `docker` + `docker compose` on the
  host. Without it, only secret detection works (via combined-hook.sh's
  local `scan.sh` fallback) — see "Non-Docker fallback" above.
- **Windows not supported at all for `guards-unified`** — secret
  detection still works there (no daemon needed), PII/injection stages
  fail open.
- **Output redaction covers Bash tool calls only.** Read/Grep/WebFetch's `updatedToolOutput` shapes aren't documented, and a wrong shape is silently ignored, so those results are never rewritten. Credential files are instead blocked *before* they are read by `credfile-guard.sh` (see "Credential-file guard" below); everything else those tools return is unscanned.
- **Vendored hook scripts** (`hooks/*.sh`, `vendor/secret-guard-core/scan.sh`) must be manually synced if their source repos change — no automated sync exists yet.
- **secret-guard's `gitleaks`/`jq` dependencies are checked, never auto-installed** — a system package manager assumption felt too risky to make silently; the self-heal script warns and fails open instead.

## Why this exists

Built after a real session-long pattern: secrets and PII surfacing in
raw Bash tool output, caught (in shadow-mode, logging-only) by an
existing grāmatr hook (`bash-output-scan.js`) during this very build.
secret-guard, injection-guard, and pii-guard are the dedicated,
purpose-built versions of that same idea — redaction and
classification, not just logging — bundled here so they're one
plugin install away rather than three separate manual setups.

## License

MIT for this repository's own code — see `LICENSE`. This repo never
bundles or ships model weights itself; it's a thin hook/MCP client
that talks to `guards-unified`'s `:8700` API.

**guards-unified** (the backend these hooks call) directly loads
`meta-llama/Llama-Prompt-Guard-2-86M` for the injection-detection axis,
which carries its own redistribution obligations under Meta's Llama 4
Community License — "Built with Llama" attribution, a required NOTICE
file, and a bundled copy of the license text. That obligation belongs
to, and is satisfied in, `guards-unified`'s own repo (`LICENSE`,
`NOTICE`, `THIRD_PARTY_LICENSES/`, and its runtime `GET /about`
endpoint) and `injection-guard`'s (same pattern, original source) —
not duplicated here, since this repo doesn't distribute the weights or
the loading code, only an `HTTP` client to a service that does. If
you're redistributing a build of this plugin together with a
pre-pulled `guards-unified` image (rather than letting users `docker
pull` it themselves per the install instructions above), you inherit
that obligation directly — see `guards-unified`'s README for what's
required.
