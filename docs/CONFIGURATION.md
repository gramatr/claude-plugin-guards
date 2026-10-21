# Configuration reference

Every environment variable the plugin's hooks, MCP server and self-heal script
read, with its default. Values here come from the scripts under `guards/`; if
the README and this page disagree, the scripts win.

## Where to set them

The hooks are processes started by Claude Code, so they inherit **the
environment Claude Code itself was started from**. Export a variable in your
shell before you launch `claude`, and restart the session to change it. The
override switches (`GUARDS_ALLOW_*`) work only this way on purpose: there is no
per-call bypass the agent could type for itself.

Variables for the **container** (the guards-unified service, such as `HF_TOKEN`
or `METRICS_PATH`) are a different thing: they are set in the container's
environment (for the plugin's compose file, in
`~/.config/gramatr-guards/injection-guard.env`) and are documented in
guards-unified's README. They have no effect on the hooks.

## Which side reads it

| Setting | Read by |
|---|---|
| `FLAG_MAX_BYTES`, `FLAG_BUDGET`, `SECRET_MAX_BYTES`, `INJECTION_MIN_SCORE`, `GUARDS_FAST_BASH` | The **Bash hook** (`hooks/combined-hook.sh`) |
| `SCAN_MAX_BYTES` | The Bash hook's older single-call path, and `sendmessage-guard.sh` (per field) |
| `PII_GUARD_MODE` | The Bash hook and `sendmessage-guard.sh` |
| `GUARDS_ENDPOINT` | All hooks that call the service, and `mcp/server.py` |

`FLAG_MAX_BYTES` and `FLAG_BUDGET` live in the plugin hook, **not in the
server**. Setting them in the container's environment does nothing. The server
scans whatever text it is sent; the hook decides how much to send.

## Service connection

| Variable | Default | Meaning |
|---|---|---|
| `GUARDS_ENDPOINT` | `http://127.0.0.1:8700` | Base URL of the guards-unified service. Used by the Bash hook, the secret-scan library (so also the publish guard and the MCP result guard), `sendmessage-guard.sh`, `userpromptsubmit-guard.sh` and `mcp/server.py`. Pointing it at a remote host sends raw tool output, which may contain secrets, to that host; read `guards/docker/SERVER-SIDE.md` first. |
| `SS_SERVICE_TIMEOUT` | `2` | Seconds to wait for the secret-only route (`POST /v1/scan/secret`) before the hook runs the full local scan. Read by `hooks/secret-scan-lib.sh`. |
| `GUARDS_SECRET_SCAN` | `<plugin>/vendor/secret-guard-core/scan.sh` | Path of the local scanner. Honoured by the publish guard, the outbound guard and the MCP result guard only; the Bash hook and `sendmessage-guard.sh` always use the vendored copy. Mainly used by tests to simulate a missing or broken scanner. |

## Bash output hook (`combined-hook.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `GUARDS_FAST_BASH` | `1` | `1` uses the fast path (secrets always and fast, PII and injection on a prefix). `0` restores the older single `/v1/scan` call. |
| `SECRET_MAX_BYTES` | `262144` (256 KB) | Bytes of each stream (stdout, stderr) scanned for secrets on the fast path. Bytes beyond it are not scanned; a warning is prepended and the remainder is returned unchanged. |
| `FLAG_MAX_BYTES` | `2048` | Bytes (the leading prefix) sent for PII and injection flags. `0` skips the flag scan entirely. PII and injection past this prefix are never flagged. |
| `FLAG_BUDGET` | unset | Seconds to wait for the flag scan. Unset means `0.25 + 0.3 * KB` for the bytes actually sent (0.85 s for 2 KB). A late or failed answer is dropped without notice. |
| `INJECTION_MIN_SCORE` | `0.95` | The injection warning is shown only for a "malicious" verdict scoring at least this. Benign security-themed text scored 0.86 to 0.91; real attacks 0.977 and up. |
| `PII_GUARD_MODE` | `flag` | `flag` notes PII types and leaves the values. `redact` replaces PII and also selects the older single-call path in the Bash hook. |
| `SCAN_MAX_BYTES` | `24576` (24 KB) | Older single-call path only: bytes sent to the full `/v1/scan`; the rest is returned unscanned with a warning. |

## Outbound messages (`sendmessage-guard.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `PII_GUARD_MODE` | `flag` | As above: `flag` leaves PII in place and notes it; `redact` replaces it. |
| `SCAN_MAX_BYTES` | `24576` | Bytes of each field (`message`, `summary`, `content`) that are scanned; the hook discloses when it truncated what it scanned. |

## Credential-file guard (`credfile-guard.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `GUARDS_ALLOW_CRED_READ` | `0` | `1` disables the guard. Set it in the environment Claude Code starts from; there is no per-call bypass. |
| `GUARDS_CRED_ASK` | `1` | `1`: `.env`, kubeconfig, `.npmrc`/`.pypirc` and terraform state ask the person in `default`, `acceptEdits` and `plan` modes and deny in every other mode. `force`: ask in every mode. `0`: hard deny in every mode. Private keys and credential stores are always hard denies. |
| `GUARDS_CRED_IDENTITY_USE` | `1` | `1`: a credential handed to a tool that only uses it is not treated as a read, so a reader word elsewhere on the same line (a `cat` of another file, a trailing `\| head`) no longer makes the use look like one. The tools and forms are the rows of `guards/hooks/cred-use-registry.tsv` (`age`/`rage` `-i` and `--identity`; `ssh`/`scp`/`sftp` `-i` and `-o IdentityFile=`; `ssh-keygen -f`; `ssh-add KEY`; `openssl` signing flags and `pkey`/`rsa`/`ec -in KEY -pubout`; `kubectl --kubeconfig` and `KUBECONFIG=`; `curl --key`; `docker --config`). Each row is proven by a canary test that runs the real tool against a throwaway credential. Any other mention of the credential on the line still counts, and a forbidden form (`openssl pkey` without `-pubout`, `-text`, `kubectl config view --raw`) is never exempted. `0` restores the old behavior: any reader word plus a sensitive path on the line is a deny. A missing or unparsable registry behaves as `0`. **What it does not protect:** the exemption is about the credential handed to the tool, not what the tool outputs. `age -d -i KEY file` prints the decrypted secret to the transcript (output redaction is what covers that, and it has gaps for bare high-entropy values, see `docs/LIMITS.md`), and `ssh-keygen -p -f KEY` or `ssh-keygen -t … -f KEY` can rewrite or overwrite the key: an integrity risk, not a confidentiality one. |
| `CREDFILE_SNIFF_MAX_BYTES` | `10485760` (10 MiB) | Bytes of each readable regular file checked for a private-key header. This is what denies an unrelated document that quotes a key header. |

## Publish guard (`publish-guard.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `GUARDS_ALLOW_PUBLISH_SECRETS` | `0` | `1` disables the guard, for a reviewed false positive. |
| `GUARDS_PUBLISH_ASK` | `1` | `1`: an ambiguous match asks the person in `default`, `acceptEdits` and `plan` modes and denies in every other mode. `force`: ask in every mode. `0`: every match is a hard deny. Sure things (a private key, a vendor token format, a value from the session environment) always deny. |
| `PUBLISH_GUARD_MAX_BYTES` | `524288` (512 KB) | Cap per appended file, and for the staged diff. |

## Outbound command guard (`outbound-guard.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `GUARDS_ALLOW_OUTBOUND_SECRETS` | `0` | `1` disables the guard. Set it in the environment Claude Code starts from; typed in front of a command, or exported in the same command, it changes nothing, because the caller is usually an AI agent and the override must be something it cannot type. |
| `GUARDS_OUTBOUND_ASK` | `1` | `1`: an ask-class file (`.env`, kubeconfig, `.npmrc`/`.pypirc`, terraform state), a filtered environment dump or an ambiguous literal asks the person in `default`, `acceptEdits` and `plan` modes and denies in every other mode. `force`: ask in every mode. `0`: deny in every mode. Sure things deny in every mode. |
| `GUARDS_OUTBOUND_SENTINEL_RE` | `SANDBOX_MASKED_[A-Za-z0-9]+` | Extended regular expression for the placeholder Claude Code's sandbox puts where it masks a credential. Matches are removed from the command before it is read. The real format is not verified. |
| `CREDFILE_SNIFF_MAX_BYTES` | `10485760` (10 MiB) | Shared with the credential-file guard: bytes of each file checked for a private-key header. |

The guard also reads `GUARDS_ENDPOINT` and `SS_SERVICE_TIMEOUT` (the secret-only route) and `GUARDS_SECRET_SCAN` (the local scanner), described above.

## MCP result guard (`mcp-output-guard.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `GUARDS_MCP_SCAN` | `1` | `0` disables the guard. |
| `GUARDS_MCP_SKIP` | `^mcp__plugin_gramatr_` | Extended regular expression on the tool name. Matching tools are not scanned. The default skips grāmatr's own MCP server, which returns session tokens by design. |
| `MCP_GUARD_MAX_BYTES` | `524288` (512 KB) | A text block larger than this is skipped silently and arrives unredacted. |

## Variables the hooks set for the scanner (rarely set by hand)

The vendored `scan.sh` has its own switches. The hooks set them as needed; they
are listed so you know what a hook is doing.

| Variable | Default in `scan.sh` | Set by the hooks | Meaning |
|---|---|---|---|
| `SECRET_GUARD_ENV_VALUES` | off | `1` in the publish guard, MCP guard, secret-scan library and Bash fallback | Exact-match redaction of values of environment variables with secret-looking names. Skips values under 8 characters, placeholders, existing paths, and names ending in `_FILE`, `_PATH`, `_DIR`, `_URL`, `_URI`, `_NAME`, `_ID`, `_TYPE`, `_HOST`, `_PORT`, `_USER`. Not available inside the container, which cannot see your session's environment. |
| `SECRET_GUARD_SKIP_GITLEAKS` | off | `1` after the service has already run gitleaks | Stops after the built-in passes. |
| `SECRET_GUARD_B64` | on | not set | `0` disables the base64 pass. |
| `SECRET_GUARD_REDACT_KEY_IDS` | off | not set | `1` also redacts access-key and client IDs, which are not redacted by default. |
| `SECRET_GUARD_FINDINGS_JSON` | unset | a temp file | Where rule IDs (never values) are written. |

## Fixed paths used by the self-heal script

| Path | Purpose |
|---|---|
| `~/.config/gramatr-guards/injection-guard.env` | Container env file; put `HF_TOKEN=...` here. Created empty with mode 0600 if missing. |
| `~/.local/share/gramatr-guards/metrics/` | Metrics volume, mounted at `/app/metrics` in the container. Created `chmod 777`. |
| `~/.local/share/gramatr-guards/selfheal.lock` | Lock so two session starts do not reconcile the stack at once. |
| `~/.local/bin/gitleaks` | Where a missing gitleaks (v8.30.1) is installed. |

## Compose file settings

`guards/docker/docker-compose.yml` is edited, not configured by variables. The
values worth knowing: the image tag (`:cpu`; `:gpu` only if you have a GPU and
measured a need), `mem_limit: 4g` (2 GB was killed by the kernel while loading
both models), `cpus: 16` (a ceiling, not a reservation; on a small machine the
scan latency numbers in `docs/LIMITS.md` will be worse), and the Watchtower poll
interval (300 s).
