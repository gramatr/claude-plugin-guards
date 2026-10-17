# gramatr-guards — Claude Code plugin

Wires [secret-guard](https://github.com/gramatr/secret-guard),
[injection-guard](https://github.com/gramatr/injection-guard), and
[pii-guard](https://github.com/gramatr/pii-guard) into Claude Code's
`PostToolUse` hook for Bash, plus a self-healing `SessionStart` hook
that keeps the two daemons installed and running.

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

### Self-heal, not a one-shot installer

`bin/guards-selfheal.sh` runs on every `SessionStart` — same idempotent
"check state, fix if needed" pattern as grāmatr's own
`statusline-selfheal.js`. It checks whether `injection-guard-daemon` and
`pii-guard-daemon` are installed (`uv tool install`) and running
(`systemctl --user` on Linux), and fixes anything missing — rather than
a setup step the user has to remember to run once and never revisit.

**Linux**: fully implemented and verified end to end this session —
real `uv tool install git+https://...`, real `systemd --user` unit
registration and startup, confirmed via `systemctl status` and a real
`curl` to each daemon's `/health` endpoint.

**macOS**: launchd plist templates exist in `launchd/`, but
`guards-selfheal.sh`'s macOS branch is **not yet implemented** — it
logs a message pointing at the templates for manual install. This
session had no Mac to test launchd behavior on; the plists are
syntax-valid XML (verified with Python's `plistlib`) but otherwise
unverified. See "Known limitations."

**Windows**: explicitly out of scope for v1. The self-heal script logs
why and exits 0 rather than failing the session.

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

## Known limitations

- **macOS self-heal not implemented** — manual launchd install only, see `launchd/`.
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
