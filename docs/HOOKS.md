# Hooks reference

The plugin registers seven hooks (`guards/hooks/hooks.json`) and starts one MCP
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
| `UserPromptSubmit` | none (all prompts) | `hooks/userpromptsubmit-guard.sh` | 15 s | Adds a note if the prompt contains a secret. Cannot redact or block. |

MCP server: `mcp/server.py`, one tool `scan(text)`. It calls the service's
`POST /v1/scan` with a 15 s client timeout.

Two constraints worth knowing when you edit `hooks.json`:

- Exactly one `PostToolUse` hook may rewrite a given tool's output; the Bash and
  MCP matchers are disjoint for that reason.
- `sendmessage-guard.sh` must stay the only `PreToolUse` hook matching
  `SendMessage`. With a second hook registered, `updatedInput` was observed to
  be silently dropped. `credfile-guard.sh` and `publish-guard.sh` match `Bash`
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
| **Bash output** (`combined-hook.sh`), fast path | Secrets: **local fallback**, full `scan.sh` with gitleaks, 30 s limit inside a 15 s hook timeout. PII and injection notes: absent, with no message. | Secret route times out after 2 s, then the full local scan runs. Flag scan is dropped silently when its budget (0.85 s for 2 KB) passes. | `scan.sh` missing and service down: the hook falls through to the older path, which prints a message to stderr and passes the output through unchanged (**open**). `jq` missing: the hook does nothing (**open**). |
| **Bash output**, older path (`GUARDS_FAST_BASH=0` or `PII_GUARD_MODE=redact`) | **Local fallback** for secrets only; stderr message "falling back to local scan.sh". | The 10 s request limit applies; on timeout it behaves as down. | `scan.sh` missing or not executable: pass-through with a stderr message (**open**). |
| **MCP result** (`mcp-output-guard.sh`) | **Local fallback** (full `scan.sh`), per text block. | Secret route times out after 2 s, then local scan. Many large blocks in one result can exceed the hook's 30 s timeout. | `scan.sh` missing or `jq` missing: nothing is scanned (**open**). A text block over 512 KB is skipped silently (**open**). A failed scan leaves the block untouched (**open**). |
| **SendMessage** (`sendmessage-guard.sh`) | **Degrade**: each field gets a local secret-only scan; the hook returns `allow` with the updated input and a note that PII scanning was unavailable. It returns `allow` even if nothing was found. | A 10 s request limit applies per field; the hook decides reachability from the `message` field and then treats the service as down for all three fields. Up to three sequential requests against a 15 s hook timeout: not measured. | `scan.sh` not executable and service down: the fields pass through unchanged while the note still says a local scan ran (**open**). `jq` missing: the hook does nothing (**open**). |
| **Credential-file guard** (`credfile-guard.sh`) | Does not use the service. Unaffected. | Does not use the service. | `jq` missing or payload unparseable: **open**. |
| **Publish guard** (`publish-guard.sh`) | Service route skipped; the full local scan runs. Still enforces. | Secret route times out after 2 s, then the full local scan. | No scanner can run (service unusable **and** `scan.sh` missing, crashed, or over its 30 s limit): **closed**, the publish is denied. `jq` missing: **open**. gitleaks missing only: the built-in passes still run, with a notice (vendor-token formats are not checked). |
| **UserPromptSubmit** (`userpromptsubmit-guard.sh`) | No note (**open**). There is no local fallback. | The 10 s request limit applies; a long prompt that needs longer gets no note (**open**). | `jq` missing: no note (**open**). |
| **MCP `scan` tool** | Returns `{"error": ...}`, never a false "clean". | 15 s client timeout, then the same error. | n/a |
| **Self-heal** (`SessionStart`) | n/a (it starts the service) | A pull is limited to 240 s and the health poll to 30 s. | No Docker: logs that PII and injection are unavailable; secrets still work through the local fallback. A failed gitleaks download or missing `jq` is a warning. |

Notes on the matrix:

- "Open" for the Bash and MCP hooks means the **pre-existing** behavior of Claude
  Code applies: the original tool output reaches the model. A safety net that
  can break the tool is worse than none for these two surfaces.
- The publish guard is the one place that fails **closed**, because a publish
  cannot be undone.
- What Claude Code does when a hook exceeds its own timeout is not verified here.
  The hook comments assume it falls back to the original output or input,
  meaning unredacted; plan on that.
- When a scan is cut by a size cap rather than a failure (Bash output past
  256 KB, the older path past 24 KB, SendMessage fields past 24 KB, MCP blocks
  past 512 KB), see [`LIMITS.md`](LIMITS.md). The Bash and SendMessage hooks
  disclose it; the MCP guard does not.

## Ask versus deny by permission mode

Two guards use Claude Code's `ask` decision, and they treat modes the same way.
Details and the reasoning are in [`TRADEOFFS.md`](TRADEOFFS.md).

| Guard | `default`, `acceptEdits`, `plan` | `auto`, `bypassPermissions`, `dontAsk`, unknown |
|---|---|---|
| Publish guard, ambiguous match | ask | **deny** (no person to answer) |
| Publish guard, sure thing | deny | deny |
| Credential-file guard, ask-class file (`.env`, kubeconfig, ...) | ask | **deny** (no person to answer); `GUARDS_CRED_ASK` set to `force` asks in every mode, `0` denies in every mode |
| Credential-file guard, deny-class file or private-key content | deny | deny |
