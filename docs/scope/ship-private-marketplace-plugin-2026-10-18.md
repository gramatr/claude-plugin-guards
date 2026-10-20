# Scope: Ship claude-plugin-guards to a private marketplace — 2026-10-18

> **Historical, superseded.** This is a dated scoping pass from 2026-10-18. Its units (U1 to U6) are done and several of its designs are not what
> shipped: the `UserPromptSubmit` hook described in U4 was built as an **advisory note, not a blocking hook**, and the repository stays public. For the
> current behavior read [`guards/README.md`](../../guards/README.md), [`docs/HOOKS.md`](../HOOKS.md), [`docs/LIMITS.md`](../LIMITS.md) and
> [`docs/TRADEOFFS.md`](../TRADEOFFS.md). It is kept for the reasoning only; some commands and paths in it no longer apply.

## Goal

`claude-plugin-guards` ("guards") is meant to be one `/plugin install` away from protecting a Claude Code session against secret/PII/injection leaks in tool output and agent-to-agent messages. Today it would ship broken: two of its four integration points (`combined-hook.sh`, `guards-selfheal.sh`) still talk to the old three-daemon architecture (ports 8732/8731/8730) that `guards-unified` replaced, while the other two (`sendmessage-guard.sh`, `guards/mcp/server.py`) correctly call `guards-unified`'s single `:8700 /v1/scan` endpoint. A fresh install right now stands up the wrong backend for the hooks that need it, and the MCP tool has nothing to talk to unless someone manually starts `guards-unified`. Separately, the plugin manifest wiring (`.mcp.json` + `${CLAUDE_PLUGIN_ROOT}`) has never been exercised via a real `claude plugin marketplace add` + `claude plugin install` — only the underlying script was tested standalone.

"Done" for this scope means: (1) every hook and the MCP server point at the same `guards-unified` backend, consistently; (2) the marketplace/install flow has been run for real at least once and confirmed working; and (3) the known-but-deferred follow-up work (UserPromptSubmit secret-blocking hook, a licensing audit across all five repos, and the repo-visibility decision for a "private marketplace") is each turned into one filed, independently closeable issue — not left as session notes that evaporate when this conversation ends.

This is a read-only scoping pass. No code was changed, no Docker builds were run, no GitHub issues were filed to produce this document.

## Units

Repo for all units unless noted: `gramatr/claude-plugin-guards`.

### TRUE BLOCKERS — plugin is non-functional today without these

**U1 — Repoint `combined-hook.sh` at `guards-unified`'s single `/v1/scan` endpoint**
Owner artifact: one PR touching `guards/hooks/combined-hook.sh` only.
Rewrite the three sequential calls (`SECRET_GUARD_ENDPOINT`/`:8732/scan`, `PII_GUARD_ENDPOINT`/`:8731/analyze`, `INJECTION_GUARD_ENDPOINT`/`:8730/classify`) into one call to `GUARDS_ENDPOINT` (default `http://127.0.0.1:8700`) `/v1/scan`, and build `updatedToolOutput.stdout` from the response's `redacted_text` plus the existing injection-warning-banner behavior when `findings[].type=="injection" && verdict=="malicious"`. Preserve the existing bare-metal fallback behavior (see Risks) and the existing fail-open-on-unreachable behavior.

**U2 — Consolidate the Docker stack and self-heal script onto `guards-unified`**
Owner artifact: one PR touching `guards/docker/docker-compose.yml` and `guards/bin/guards-selfheal.sh`.
Replace the three-container compose file (`secret-guard`/`pii-guard`/`injection-guard` on 8732/8731/8730) with a single `guards-unified` service bound `127.0.0.1:8700:8700`, pulling `ghcr.io/gramatr/guards-unified:cpu` by default (see Open Questions). Update `guards-selfheal.sh`'s health-check loop to poll only `:8700/health`, and extend its existing `migrate_off_systemd`-style one-time migration logic to also stop/remove any leftover old three-container stack from a prior install, so an upgrading machine doesn't leave three stale containers bound to 8730-32 alongside the new one on 8700. Keep the `HF_TOKEN` env-file wiring (`~/.config/gramatr-guards/injection-guard.env`) passed through to the single container.

**U3 — Verify the marketplace install + MCP wiring end-to-end, for real**
Owner artifact: one PR/commit adding a recorded verification transcript (e.g. to `guards/README.md`'s "Known limitations" or a new `docs/verification/` note) plus any fixes the run surfaces. Depends on U1 and U2 landing first.
From a clean Claude Code environment, run `claude plugin marketplace add gramatr/claude-plugin-guards` then `claude plugin install guards`, start a session, and confirm: (a) `guards-selfheal.sh` actually executes on `SessionStart` (visible in session logs); (b) the `guards` MCP server resolves `${CLAUDE_PLUGIN_ROOT}` to a real path (no literal `${CLAUDE_PLUGIN_ROOT}` string in the resolved command) and registers; (c) invoking the MCP `scan` tool with a crafted string containing a known test secret returns a real `findings` array with a `secret` verdict of `"found"`, not `{"error": ...}`. This has never been done — only the standalone script was run via direct `uv run`.

### FOLLOW-UP / POLISH — matter, but don't block basic functionality

**U4 — Build the UserPromptSubmit secret-blocking hook**
Owner artifact: one PR adding `guards/hooks/userpromptsubmit-guard.sh` + a `hooks.json` entry.
Implement the hook exactly as designed in conversation: on a secret finding (PII explicitly out of scope — it's the user's own data in their own conversation), return `{"decision":"block","reason":"...","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}`, with a documented, explicit override path. Document the confirmed caveat that `suppressOriginalPrompt:true` does not remove the blocked text from the on-disk session transcript/prompt history. Fail OPEN on backend-unreachable (resolved — see Open Questions #4): unlike `sendmessage-guard.sh`'s fail-closed stance, blocking every prompt during a `guards-unified` outage would turn this safety net into a single point of failure for using Claude Code at all.

**U5 — Licensing/documentation audit across all five repos**
Owner artifact: one issue per repo with a concrete, named gap (not one umbrella issue) — see Epic-completeness audit below for the first confirmed finding (`guards-unified` has no `LICENSE` file despite its README claiming "MIT for this repository's own code").

**U6 — Decide and document claude-plugin-guards' repo visibility for the "private marketplace" plan**
Owner artifact: one issue (decision record), not a code change.
Lay out the two live options — (a) keep the repo PUBLIC and make "private marketplace" mean an access-controlled marketplace *listing* with a world-readable source repo, or (b) flip the repo PRIVATE (as was done for a separate, internal operational tool) and have "private marketplace" mean a private source repo too — with the concrete tradeoff for each (discoverability control vs. source control), and get an explicit human decision rather than assuming either default.

## Acceptance criteria per unit

**U1**
- `grep -E 'SECRET_GUARD_ENDPOINT|PII_GUARD_ENDPOINT|INJECTION_GUARD_ENDPOINT' guards/hooks/combined-hook.sh` returns zero matches after the change.
- Given a stubbed `:8700/v1/scan` endpoint, running `combined-hook.sh` against a crafted `PostToolUse` JSON payload (`tool_name: "Bash"`, `tool_response.stdout` containing a known gitleaks test-fixture secret and a fake PII email) results in exactly **one** HTTP request to the stub (not three), and `updatedToolOutput.stdout` exactly matches the stub's `redacted_text`, prefixed with the injection-warning banner when the stub's `injection` finding is `malicious`.
- With `GUARDS_ENDPOINT` pointed at a closed port, running the same payload exits 0 with no `hookSpecificOutput` key emitted (fail-open preserved) — captured as literal command output in the PR description, not described in prose.

**U2**
- `guards/docker/docker-compose.yml` defines exactly one service built from or pulling `ghcr.io/gramatr/guards-unified`, published only as `127.0.0.1:8700:8700` (`grep -c '127.0.0.1:8700:8700'` returns 1; `grep -E '8730|8731|8732'` returns zero matches in the new compose file).
- `grep -E '8730|8731|8732' guards/bin/guards-selfheal.sh` returns zero matches; the health-check loop polls only `127.0.0.1:8700/health`.
- Simulating a machine with the old three containers already running, then running `guards-selfheal.sh`, results in those three containers stopped/removed and the single new container `Up` and answering `/health` — captured via `docker compose ps` output before/after in the closing PR.
- The `HF_TOKEN` env-file line (`env_file: - ${HOME}/.config/gramatr-guards/injection-guard.env`) is present on the single consolidated service.

**U3**
- Literal terminal output from running `claude plugin marketplace add gramatr/claude-plugin-guards` and `claude plugin install guards` in a clean environment, pasted into the closing PR/issue, with no manual workaround steps added in between.
- `SessionStart` hook execution visible in the session's own logs (cite the log line).
- The MCP `scan` tool invoked against a known test-secret string returns `findings[].type=="secret"` with `verdict=="found"` — the actual JSON response pasted into the closing artifact, not paraphrased.

**U4**
- `guards/hooks/userpromptsubmit-guard.sh` exists, is registered under `hooks.UserPromptSubmit` in `guards/hooks/hooks.json`, and contains no code path that acts on a PII finding (grep/code-read confirms only `type=="secret"` is checked).
- Triggering the hook directly with a crafted `UserPromptSubmit` payload containing a known test secret returns exactly the JSON shape `{"decision":"block","reason":"...","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}` (diffed against this literal shape in the PR).
- README documents, in the caveat's own words, where the blocked prompt can still land on disk despite `suppressOriginalPrompt:true` (cite the specific file/mechanism, confirmed by testing in this unit, not assumed).
- The chosen fail-open/fail-closed behavior for backend-unreachable is stated explicitly in the PR body with a one-line rationale.

**U5**
- One `gh issue create` per repo, each citing a specific, confirmed gap. First confirmed finding to seed this: `guards-unified`'s README (`## License`) states "MIT for this repository's own code," but a listing of the repo root showed no `LICENSE` or `NOTICE` file in the repo root — that repo also vendors Llama-licensed code transitively (via `injection_guard`) but has no `THIRD_PARTY_LICENSES/` directory or "Built with Llama" attribution anywhere, unlike `injection-guard` itself which has both (`injg/NOTICE`, `injg/THIRD_PARTY_LICENSES/LLAMA4_COMMUNITY_LICENSE.txt`).
- Each issue's AC is binary and checkable by a human reviewer without re-deriving the audit (e.g. "LICENSE file exists at repo root and matches the license named in README").

**U6**
- The issue states both options with their concrete consequences, names that precedent explicitly, asks the one open question ("does the same bar apply here, and why/why not"), and tags the human decision-maker rather than defaulting to either option.

## Dependency graph

```
U1 (combined-hook.sh -> guards-unified)  ─┐
U2 (compose + selfheal -> guards-unified) ─┼─> U3 (end-to-end install verification)
                                           │
U4 (UserPromptSubmit hook)  — independent of U1-U3; soft dependency on guards-unified
                                being reachable the same way, for its own testing
U5 (licensing audit)        — fully independent
U6 (visibility decision)    — fully independent; blocks nothing technical, but blocks
                                the stated end goal ("private marketplace") if left open
```

External blockers: none identified — all five repos are local checkouts the agent(s) can modify directly; no cross-team or cross-repo approval is required for U1-U5. U6 requires a human decision, not an external team.

## Risks the tracker doesn't already name

- **Single point of failure regression.** Today, if the secret-guard daemon is down, `combined-hook.sh` falls back to invoking `vendor/secret-guard-core/scan.sh` directly — secret redaction still works even with the daemon dead. Collapsing all three stages into one `guards-unified` call (U1) means if that one container is down, *all three* axes fail open simultaneously, where secret detection alone used to have an independent fallback. Mitigation: U1 should keep the existing `SECRET_SCAN` local-script fallback as a second-tier fallback specifically for the secret axis when `:8700` is unreachable, not drop it for symmetry.
- **GPU/CPU image default mismatch.** If U2's consolidated compose file defaults to `:gpu` instead of `:cpu`, a dev laptop with no GPU pulls ~4.7GB of unused CUDA runtime and gets no latency benefit for a synchronous hook — the exact problem the current `docker-compose.yml` comment already calls out for standalone `injection-guard`. Mitigation: default to `:cpu` in U2, consistent with existing documented reasoning; accepted risk otherwise.
- **Never-tested manifest wiring surfaces something only at install time.** `.mcp.json`'s `${CLAUDE_PLUGIN_ROOT}` substitution for `uv run --script` has never been confirmed working end-to-end; the task description for this scope flags it explicitly as unverified. Accepted; this is precisely what U3 exists to detect before any real user relies on it — not something to pre-fix speculatively.
- **Migration leaves stale containers/ports behind.** A machine that already ran the old three-container compose stack (ports 8730-32) will have both the old containers *and* attempt to bind the new 8700 one unless U2's migration logic explicitly tears down the old stack, not just the old bare-metal systemd units (which `guards-selfheal.sh` already handles) — the existing migration code only migrates *off systemd*, not off the old *Docker* stack. Mitigation: named explicitly in U2's AC.
- **Shipping "private marketplace" without resolving visibility is the default outcome.** If U6 is left open, the plugin ships exactly as it is today — a PUBLIC source repo — regardless of what "private marketplace" was intended to mean. Accepted; flagged as an explicit open question rather than silently deciding either way.

## Verification plan

Prod/real-session positive evidence, not absence-of-errors:
- A fresh Claude Code session with `guards` installed via the marketplace actually redacts a planted test secret in real Bash tool output — the model-visible `tool_response.stdout` contains `guards-unified`'s redaction marker, not the raw secret value, captured as a literal transcript excerpt.
- `docker compose ps` (post-U2) shows exactly one `guards-unified` container `Up`, bound `127.0.0.1:8700`, with no leftover `secret-guard`/`pii-guard`/`injection-guard` containers from the old stack on 8730-32 (unless `guards-stack` is intentionally running separately for an unrelated reason).
- The MCP `scan` tool, invoked from inside a real installed session (not a standalone `uv run`), returns a real `findings` array for a crafted test string — the literal JSON response is the evidence, not "the tool exists."
- A session-log line confirming `guards-selfheal.sh` ran and every service it checks answered `/health` on the expected port, captured from an actual `SessionStart` run, not inferred from reading the script.

## Epic-completeness audit

Load-bearing items named in this session's scoping conversation that do **not** yet have a tracked issue with testable AC:

| Requirement (source: this session's problem statement) | Tracked issue? | Recommended `gh issue create` |
|---|---|---|
| `combined-hook.sh` still points at the dead 3-daemon ports | No | `gh issue create --repo gramatr/claude-plugin-guards --title "combined-hook.sh still calls the old 3-daemon endpoints, not guards-unified :8700" --body "See docs/scope/ship-private-marketplace-plugin-2026-10-18.md, Unit U1 for AC."` |
| `guards-selfheal.sh` + `docker-compose.yml` still stand up the old 3-container stack | No | `gh issue create --repo gramatr/claude-plugin-guards --title "guards-selfheal.sh / docker-compose.yml still deploy the old 3-container stack, not guards-unified" --body "See docs/scope/ship-private-marketplace-plugin-2026-10-18.md, Unit U2 for AC."` |
| Marketplace install + `.mcp.json` `${CLAUDE_PLUGIN_ROOT}` wiring has never been tested end-to-end | No | `gh issue create --repo gramatr/claude-plugin-guards --title "Verify claude plugin marketplace add + install end-to-end (never tested)" --body "See docs/scope/ship-private-marketplace-plugin-2026-10-18.md, Unit U3 for AC."` |
| UserPromptSubmit secret-blocking hook was fully designed but never built | No | `gh issue create --repo gramatr/claude-plugin-guards --title "Build UserPromptSubmit secret-blocking hook (designed, not yet implemented)" --body "See docs/scope/ship-private-marketplace-plugin-2026-10-18.md, Unit U4 for AC."` |
| No discrete licensing/documentation audit has been done across the five guard repos | No | `gh issue create --repo gramatr/guards-unified --title "guards-unified has no LICENSE file or Llama attribution despite bundling Llama-licensed code transitively" --body "See docs/scope/ship-private-marketplace-plugin-2026-10-18.md, Unit U5 for AC. README claims MIT but no LICENSE/NOTICE/THIRD_PARTY_LICENSES exists in this repo."` (plus four sibling issues, one per remaining repo, per U5) |
| claude-plugin-guards' repo visibility vs. the "private marketplace" goal is an open, undecided question | No | `gh issue create --repo gramatr/claude-plugin-guards --title "Decide: does claude-plugin-guards need to go PRIVATE for the private-marketplace plan, or does 'private' only mean the marketplace listing?" --body "See docs/scope/ship-private-marketplace-plugin-2026-10-18.md, Unit U6 for the two options and the bws-toolkit precedent."` |

## Open questions — all four resolved

1. **U2 image default: `:cpu`.** Matches the existing documented rationale for standalone `injection-guard`.
2. **`claude-plugin-guards` stays PUBLIC.** It doubles as the public reference implementation; `claude-plugin-guards` is the example other platforms/harnesses can build on, which is why it stays public while internal operational tools do not.
3. **U1 keeps the bare-metal `scan.sh` fallback, secret axis only.** PII and injection don't get an equivalent fallback: both need their actual loaded models (Presidio, and especially injection-guard's Llama Prompt Guard 2) to produce a result at all, so there's no cheap local path for them the way gitleaks gives secrets — not a design choice, just what's physically available.
4. **U4 (`UserPromptSubmit`) fails OPEN on backend-unreachable** — deliberately the opposite of `sendmessage-guard.sh`'s precedent. Fail-closed there costs one occasional agent-to-agent send during an outage; fail-closed here would block every single prompt the user types for as long as `guards-unified` is down, turning a safety net into a single point of failure for using Claude Code at all.
