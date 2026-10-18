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
- **Still fails CLOSED on one case: the backend being unreachable.**
  There's nothing to safely redact against without a scan result, and
  an unsent message is recoverable while a sent one is not — so that
  one path still denies outright, unlike every other hook in this
  stack, which fails open. This is the only remaining deny path; a
  detected secret/PII no longer denies, it redacts.

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
recommendation: "use one hook that performs the rewrite." So this
script runs secret-guard → pii-guard → injection-guard in sequence,
each stage operating on the previous stage's already-redacted text, and
emits exactly one final result.

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

**Migrating off the old bare-metal daemons**: if this machine previously
ran `injection-guard-daemon`/`pii-guard-daemon` via `uv tool install` +
`systemd --user` (the old v1 install path), the self-heal script
disables those units before starting the Docker stack — both bind the
same ports the containers publish, so leaving them running makes the
`docker compose up` bind fail. This migration runs once; once the
systemd units are disabled they stay disabled.

**Non-Docker fallback**: if Docker isn't usable on this machine, the
original `uv tool install` + `systemd --user` (Linux) / launchd (macOS,
templates only, self-heal not implemented) path is still there and
still works, unchanged from v1. Windows remains explicitly out of scope
for any daemon self-heal — the script logs why and exits 0 rather than
failing the session.

### The HF_TOKEN problem

`injection-guard-daemon` needs a Hugging Face token that has accepted
Llama Prompt Guard 2's gated license. This **cannot be automated** —
accepting someone else's license is inherently a manual, per-user step.
`guards-selfheal.sh` checks for `~/.config/gramatr-guards/injection-guard.env`
(must contain `HF_TOKEN=...`) and warns clearly if it's missing, rather
than silently installing a daemon that will never successfully load the
model.

## Install

```
claude plugin marketplace add gramatr/claude-plugin-guards
claude plugin install guards
```

Then start (or restart) a Claude Code session — the `SessionStart` hook
runs the self-heal automatically.

## Server-side / hosted deployment

**Not enabled by anything in this repo.** If you're considering running
any of these guards reachable over a network — even inside our own
infrastructure boundary — read `docker/SERVER-SIDE.md` first. The short
version: it's architecturally fine for `injection-guard`, and explicitly
not fine for `secret-guard`/`pii-guard` per their own READMEs, for
reasons that don't go away just because the network boundary is ours.

## Known limitations

- **Docker is now the primary deployment path**; its only hard
  requirement is a working `docker` + `docker compose` on the host.
  Without it, self-heal falls back to the original bare-metal path
  below, unchanged.
- **macOS self-heal not implemented** for either path — manual launchd
  install only, see `launchd/`.
- **Windows not supported at all for the daemon services** — secret-guard's hook stage still works there (no daemon needed), injection-guard/pii-guard stages fail open.
- **Only Bash tool calls are guarded** — Read/Grep/WebFetch's `updatedToolOutput` shapes aren't confirmed from the docs; rather than guess, those tool calls pass through unguarded for v1.
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
