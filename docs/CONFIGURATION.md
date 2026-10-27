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

## Server settings that change what you are told about PII

These are **container** variables: they are read by the guards-unified service, not by the hooks. Put
them in the container's env file, `~/.config/gramatr-guards/injection-guard.env` for the plugin's
compose file, one `NAME=value` per line. Docker Compose recreates the container when that file
changes, so run `docker compose -f <the plugin's guards/docker/docker-compose.yml> up -d`, or just
restart Claude Code (the self-heal script runs the same command at session start). A recreated
container downloads the injection model again; see [DATA-FLOW.md](DATA-FLOW.md).

| Variable | Default (server v0.2.10) | What it does |
|---|---|---|
| `PII_ENTITIES` | `EMAIL_ADDRESS,PHONE_NUMBER,US_SSN,US_PASSPORT,CREDIT_CARD,IBAN_CODE` | The entity types the PII axis looks for. The default is the structured kinds a validator can confirm. `IP_ADDRESS`, `LOCATION` and `PERSON` are off: addresses, hosts and tool names are routine in operator and infrastructure output. With no `PERSON` or `LOCATION` the language model is not run at all. |
| `PII_MIN_SCORE` | `0.4` | Lowest score a `PERSON` or `LOCATION` match needs to be reported. Only matters if you turn those back on. |
| `PII_IGNORE_NAMES` | empty | Names (comma-separated, matched whole and case-insensitively) that are never reported as a `PERSON`, added to a built-in list of tool and product names. Only matters if `PERSON` is on. |

The PII notes are advisory: they leave the text as it is. Secret redaction does not depend on any of
these.

**Recorded run** (the v0.2.10 image, 2026-10-22, the PII engine on one fabricated sentence containing a
name, a place, an IP address, an email address and an SSN):

| `PII_ENTITIES` | Entity types reported |
|---|---|
| not set (the default) | `EMAIL_ADDRESS`, `US_SSN` |
| the default plus `IP_ADDRESS` | `EMAIL_ADDRESS`, `IP_ADDRESS`, `US_SSN` |
| `PERSON,LOCATION,EMAIL_ADDRESS,PHONE_NUMBER,US_SSN,US_PASSPORT,CREDIT_CARD,IBAN_CODE,IP_ADDRESS` (the previous default) | `EMAIL_ADDRESS`, `IP_ADDRESS`, `LOCATION`, `PERSON`, `US_SSN` |

**To get no PII or injection notes at all**, and the wait for them, set `FLAG_MAX_BYTES=0` in the
environment Claude Code starts from (a **hook** setting, see above). The Bash output hook then skips the
flag scan entirely; secret redaction is unaffected.

## Service connection

| Variable | Default | Meaning |
|---|---|---|
| `GUARDS_ENDPOINT` | `http://127.0.0.1:8700` | Base URL of the guards-unified service. Used by the Bash hook, the secret-scan library (so also the publish guard and the MCP result guard), `sendmessage-guard.sh`, `userpromptsubmit-guard.sh` and `mcp/server.py`. Pointing it at a remote host sends raw tool output, which may contain secrets, to that host; read `guards/docker/SERVER-SIDE.md` first. When it is anything other than `http://127.0.0.1:8700`, self-heal does not start or update the local container; it only checks the endpoint's `/health` and warns if it does not answer. |
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
| `GUARDS_PII_IGNORE_ENTITIES` | unset | Comma-separated PII types the **note** never names, for example `IP_ADDRESS,LOCATION`. Case and spaces do not matter. Set it in the environment Claude Code starts from (a variable typed in a command has no effect). It filters the note only, in `flag` mode: it does not change what the service reports or what `redact` mode replaces, and it never touches secret redaction. Also read by `sendmessage-guard.sh`. |
| `GUARDS_PII_NOTE_ONCE` | `1` | `1`: a PII type is named once per session, the first time it is seen, and not again for that session. `0` restores a note on every command. Needs the session id in the hook payload; without one, or if the state file cannot be written, the note is shown. Also read by `sendmessage-guard.sh`. |
| `GUARDS_STATE_DIR` | `${XDG_STATE_HOME:-~/.local/state}/gramatr-guards` | Where the once-per-session state lives: one small file per session under `pii-notes/` holding the type names already shown (no text). Files older than two days are removed when a new one is started. Setting the variable moves this state and the files the MCP tools write; the MCP tools alone default to `${XDG_DATA_HOME:-~/.local/share}/gramatr-guards` (`guards/mcp/guards_tools.py`). |

## Outbound messages (`sendmessage-guard.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `PII_GUARD_MODE` | `flag` | As above: `flag` leaves PII in place and notes it; `redact` replaces it. |
| `SCAN_MAX_BYTES` | `24576` | Bytes of each field (`message`, `summary`, `content`) that are scanned; the hook discloses when it truncated what it scanned. |

## Credential-file guard (`credfile-guard.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `GUARDS_ALLOW_CRED_READ` | `0` | `1` disables the guard. Set it in the environment Claude Code starts from; there is no per-call bypass. |
| `GUARDS_ALLOW_CRED_PATHS` | unset | A colon-separated list of exact absolute file paths the guard lets through, for any class including private keys. The narrow alternative to `GUARDS_ALLOW_CRED_READ=1`. Set it in the environment Claude Code starts from; a variable typed in front of a command does not count. Each entry is compared by realpath (a listed symlink and a read through one both match), applies to `Read`, `Grep path=` and `Bash` alike in every permission mode, and allows only that file: not its siblings, and a directory entry does not allow the files in it. An empty, relative, glob (`* ? [`), backslash or `..` entry is ignored, so a malformed list denies more, never less. Unset changes nothing. `GUARDS_ALLOW_CRED_READ=1` still wins. |
| `GUARDS_CRED_ASK` | `1` | `1`: `.env`, kubeconfig, `.npmrc`/`.pypirc` and terraform state ask the person in `default`, `acceptEdits` and `plan` modes and deny in every other mode. `force`: ask in every mode. `0`: hard deny in every mode. Private keys and credential stores are always hard denies. |
| `GUARDS_CRED_IDENTITY_USE` | `1` | `1`: a credential handed to a tool that only uses it is not treated as a read, so a reader word elsewhere on the same line (a `cat` of another file, a trailing `\| head`) no longer makes the use look like one. The tools and forms are the rows of `guards/hooks/cred-use-registry.tsv` (`age`/`rage` `-i` and `--identity`; `ssh`/`scp`/`sftp` `-i` and `-o IdentityFile=`; `ssh-keygen -f`; `ssh-add KEY`; `openssl` signing flags and `pkey`/`rsa`/`ec -in KEY -pubout`; `kubectl --kubeconfig` and `KUBECONFIG=`; `curl --key`; `docker --config`). Each row is proven by a canary test that runs the real tool against a throwaway credential. Any other mention of the credential on the line still counts, and a forbidden form (`openssl pkey` without `-pubout`, `-text`, `kubectl config view --raw`) is never exempted. `0` restores the old behavior: any reader word plus a sensitive path on the line is a deny. A missing or unparsable registry behaves as `0`. **What it does not protect:** the exemption is about the credential handed to the tool, not what the tool outputs. `age -d -i KEY file` prints the decrypted secret to the transcript (output redaction is what covers that, and it has gaps for bare high-entropy values, see `docs/LIMITS.md`), and `ssh-keygen -p -f KEY` or `ssh-keygen -t … -f KEY` can rewrite or overwrite the key: an integrity risk, not a confidentiality one. |
| `GUARDS_CRED_SNIFF_STRICT` | `0` | `0`: a file that holds a private-key header is read as a key only when it looks like one: a header that starts its line (after blanks and a markdown quote or list prefix), ends its line, is followed by a literal `\n` (a key inside JSON) or by base64 with no space, or a header anywhere plus a line of 40 or more base64 characters standing alone. A document that only names the header in a sentence (a design note, a runbook) reads. `1`: any header makes the file a key, as before. An awk that cannot run treats the file as a key. **Accepted limits:** a header alone on a line inside a code fence is still denied, and a header named mid-sentence followed by a key body that is wrapped to lines shorter than 40 characters is not caught by this sniff (the existing output redaction is the backstop). The same sniff serves the outbound guard. |
| `GUARDS_CRED_HEREDOC_STRIP` | `1` | `1`: the body of a heredoc that only writes data (`cat > file <<EOF`, `cat >> file <<'EOF'`, `tee file <<EOF`) is dropped before the credential-file guard looks for reader words and sensitive paths, so a key path named in text being written is not treated as a read. A heredoc fed to an interpreter or a shell (`python3 - <<EOF`, `bash <<EOF`, `sed`, `awk`), a heredoc on a line with a pipe, an unterminated heredoc and a path on the command line itself all keep being scanned. `0` scans every heredoc body again. A missing `guards/hooks/heredoc-strip.awk` or an awk failure behaves as `0`. |
| `GUARDS_PUBLISH_COMMIT_SCOPE` | `1` | `1`: a `git commit` command is judged on its message and its staged diff, not on unrelated commands chained on the same line. A heredoc that only writes a file (`cat > f <<EOF`, `tee f <<EOF`) is dropped from the command text, because that text is either committed (then the staged diff carries it) or not published at all. Only when nothing on the line can pull that file into the commit: no `git add`, `git stage`, `git update-index` or `git apply`, no `-a`/`--all` and no pathspec. A credential in the `-m` message or in the staged diff still denies or asks. `0` scans the whole command text again. A missing `guards/hooks/heredoc-strip.awk` or an awk failure behaves as `0`. |
| `CREDFILE_SNIFF_MAX_BYTES` | `10485760` (10 MiB) | Bytes of each readable regular file checked for a private-key header. This is what denies an unrelated document that quotes a key header. |

## Publish guard (`publish-guard.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `GUARDS_ALLOW_PUBLISH_SECRETS` | `0` | `1` disables the guard, for a reviewed false positive. |
| `GUARDS_PUBLISH_ASK` | `1` | `1`: an ambiguous match asks the person in `default`, `acceptEdits` and `plan` modes and denies in every other mode. `force`: ask in every mode. `0`: every match is a hard deny. Sure things (a private key, a vendor token format, a value from the session environment) always deny. |
| `GUARDS_PUBLISH_APPROVE` | `1` | `1`: where an ambiguous match is denied because no person can answer (auto, bypassPermissions, dontAsk), the deny names an id and a command the person runs themselves (`! bash <plugin>/bin/guards-approve.sh <id>`) to approve that exact text once. `0`: a plain deny. Not offered for sure things, and not when `GUARDS_PUBLISH_ASK=0`. |
| `GUARDS_APPROVE_TTL` | `600` | Seconds an approval stays valid after the person runs the approve command. One use only. |
| `GUARDS_APPROVE_DIR` | `$GUARDS_STATE_DIR`, else `~/.local/share/gramatr-guards` | Where the approve-once store (`approvals/`, `pending/`, `approvals.log`) lives. publish-guard refuses an agent command that names the default location or the approve script; a custom location is not recognised by that text check. |
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
| `SECRET_GUARD_REFERENCE_VALUES` | on | not set | `0` turns off the reference-value exemptions: a value that only points at a credential (a name written in capitals, a Terraform reference, a forwarded keyword argument, a manifest field that names a Secret) is redacted like any other value again. The server's `docs/TRADEOFFS.md` lists the cases and what they give up. |
| `SECRET_GUARD_REDACT_KEY_IDS` | off | not set | `1` also redacts access-key and client IDs, which are not redacted by default. |
| `SECRET_GUARD_FINDINGS_JSON` | unset | a temp file | Where rule IDs (never values) are written. |

## Fixed paths used by the self-heal script

| Path | Purpose |
|---|---|
| `~/.config/gramatr-guards/injection-guard.env` | Container env file; put `HF_TOKEN=...` here. Created empty with mode 0600 if missing. |
| `~/.local/share/gramatr-guards/metrics/` | Metrics volume, mounted at `/app/metrics` in the container. Mode 0700 when your uid is 1000 (the container's uid), 0700 plus an ACL entry for uid 1000 when `setfacl` is installed, otherwise 0777 with a warning (none on macOS). An older install's 0777 directory is tightened on the next session start; its files are kept. |
| `~/.local/share/gramatr-guards/selfheal.lock` | Lock so two session starts do not reconcile the stack at once. |
| `~/.local/bin/gitleaks` | Where a missing gitleaks (v8.30.1) is installed. |

## Compose file settings

`guards/docker/docker-compose.yml` is edited, not configured by variables. The
values worth knowing: the image tag (`:cpu`; `:gpu` only if you have a GPU and
measured a need), `mem_limit: 4g` (2 GB was killed by the kernel while loading
both models), `cpus: 16` (a ceiling, not a reservation; on a small machine the
scan latency numbers in `docs/LIMITS.md` will be worse), and the Watchtower poll
interval (300 s).
