# What the guards do not catch

This plugin reduces the chance that a credential, personal data or an injected
instruction reaches the model, a teammate or a public repository. It is not a
guarantee. This page lists the known gaps so you can decide what else you need.
Each item says whether a setting changes it.

The design rule behind most of these: **secrets are the one hard rule**, kept
fast and strict. PII and prompt-injection are best-effort notices that never
change the text. See [`TRADEOFFS.md`](TRADEOFFS.md) for the history.

## Coverage gaps (what is never looked at)

- **Read, Grep and WebFetch output is not scanned.** Claude Code publishes the
  output shape for `Bash` only, and a wrong shape is silently ignored. The
  credential-file guard denies reads of credential files up front; everything
  else those tools return reaches the model unchecked.
- **Tool inputs are mostly not scanned.** Only `SendMessage` input, the publish
  verbs and, for a command that names a network client, the outbound guard (see
  [Outbound commands](#outbound-commands)) are checked. A secret written with
  `Write`, `Edit`, `MultiEdit` or `NotebookEdit`, or passed to a tool the guards do
  not name, is not looked at. A file that is then committed is caught by the
  publish guard's scan of the staged diff. A write guard was considered and
  declined for now: a replay of 1,500 real writes through the scanner changed 6.3% of
  them, nearly all on the ambiguous key-name rule (see [TRADEOFFS.md](TRADEOFFS.md)).
- **A secret typed in your own prompt cannot be removed by a hook.**
  `UserPromptSubmit` can only block the whole prompt or add a note, and this
  plugin adds a note. The prompt reaches the model and the API as typed. If the
  value is real, rotate it.
- **The publish guard does not cover `git push`.** It inspects `git commit`
  (message and staged diff) but not what is pushed, so a secret that is already
  in a commit is not caught at push time. It also does not cover scripts that
  publish indirectly, non-GitHub MCP tools (GitLab, Jira, Slack, mail and
  similar), or the GitHub web UI. Commands that send data with `curl`, `wget`
  and similar clients belong to the outbound guard. It inspects only commands
  that name `gh issue|pr|release|gist` with `create|comment|edit|review`, a
  `gh api` call with a body flag, `git commit`, and MCP tools whose name
  contains `github` and a write verb.
- **Only recognised MCP result shapes are rewritten**: an array of
  `{"type":"text","text":...}` blocks, an object with such a `content` array, or
  a bare string. Images, resources and unknown wrappers pass through unscanned,
  by design (a wrong guess could corrupt a result).
- **grāmatr's own MCP tools are skipped by default**
  (`GUARDS_MCP_SKIP=^mcp__plugin_gramatr_`) because they return session tokens
  by design. Change the variable to scan them; you will then see those tokens
  redacted.
- **Indirect reads of credential files.** The credential-file guard checks the
  paths a command or tool names. A script that reads a key, a path held in a
  variable, or `eval` is not caught. A `Grep` over a whole directory is checked
  by directory and glob name only.
- **Only the first 60 path-like words of a Bash command are checked.** The credential-file guard looks at
  the words of a command that could be paths, up to a cap of 60, to keep the hook fast (about 2.4 ms per
  word). A credential path after the 60th word is not seen: a reader word, 60 other arguments and then a key
  path is allowed. Words the use-only registry removes (a credential handed to `ssh -i` and so on) do not
  count towards the cap, so a long command is looked at slightly deeper than before. Pinned as an expected
  miss in `credfile-battery.test.sh`; tracked, with a design to cover long commands at the same cost, as
  gramatr/guards-coordination#91.
- **The use-only registry exempts the credential, not the tool's output or its side effects.** `age -d -i KEY file`
  keeps the key out of the transcript but prints the decrypted secret (covered only by output redaction, which has
  the gaps listed below), and `ssh-keygen -p -f KEY` or `ssh-keygen -t ... -f KEY` can rewrite or overwrite the key:
  an integrity risk the guard does not claim to prevent. Both are pinned as intentionally allowed in
  `credfile-battery.test.sh` (shapes 15 to 17), so a later change is a conscious one.
- **A tool with no row in the use-only registry is still denied beside a reader word.** The credential-file
  guard drops a credential handed to a tool in `guards/hooks/cred-use-registry.tsv` before it looks for sensitive
  paths; for any other tool (`sops`, `op`, `gpg`, a script) a reader word and a sensitive path on the same line
  is a deny, and a listing such as `ls ~/.ssh | head` is too. Each row exists only where the tool was run against
  a throwaway credential and did not print it. Rows can be added with a canary; see the header of that file.
- **Only Claude Code sessions with the plugin installed** are covered, not a
  terminal outside Claude Code.

## Outbound commands

The outbound guard (`hooks/outbound-guard.sh`) stops a Bash command from sending
credential material to a remote host. It is best effort, not a sandbox.

**What it covers.** Commands whose command word is `curl`, `wget`, HTTPie
(`http`, `https`, `xh`), `nc`/`ncat`/`netcat`, `scp`/`rsync`/`sftp` (a local
source with a remote destination) or `ssh` (standard input only), including
behind `sudo`, `env`, `timeout`, `xargs`, `bash -c` and `eval`:

- a **file** the client would send (`-d @file`, `-F f=@file`, `-T file`,
  `-H @file`, `--post-file`, `field@file`, a source operand, `< file`,
  `cat file |`, `$(cat file)`), classified like `credfile-guard` does: a
  credential store denies, `.env` and similar ask or deny by mode;
- the **whole environment** (`env`, `printenv`, `set`, `export -p`) piped in;
- a **literal credential in the command text**: a vendor-shaped token or key id,
  a private-key header, a value from the session's own environment (deny), or
  an ambiguous literal such as `-u user:pw`, an `X-Api-Key` or `Authorization`
  value, URL userinfo or `password=` in a body (ask or deny by mode).

**What it does not see.** These go through unchecked:

- a file or value named through a **variable** or a **command substitution that
  builds the path** (`curl -d @$F`): allowed with a note that says so;
- **aliases and functions**, **scripts** (`bash ./upload.sh`) and **other
  interpreters** (a python `requests.post`, a node `fetch`);
- **state across commands**: a file created or copied by an earlier command, a
  `cd` earlier in the same command, `tee >(client) < file`, a named fifo;
- **other clients**: `ftp`, `telnet`, `socat`, `openssl s_client`, `aria2c`,
  `lftp`, `git push` and `git remote` URLs, `docker run <client image>`, and
  cloud CLIs (`aws s3 cp`, `gsutil`, `rclone`, `kubectl cp`, `gh api -F @file`);
- the **content** of a file sent as a body: it is judged by its name and a
  private-key sniff of its first 10 MB, not scanned for vendor tokens, and the
  file can change between the check and the client running;
- a command over **8 KB**, unbalanced quoting, or nesting deeper than 3: the
  guard says it could not check fully and runs the checks that could run.

**Safe forms are not all equally safe.** A variable reference keeps a credential
out of the command text but not out of the process list (`ps`). `curl -v`,
`wget -d` and `http --verbose` print a credential carried in a header or
cookie back. Whether `curl --oauth2-bearer` and `-u` show the value in `ps`
depends on the curl version (visible on 7.81, hidden on 8.5.0). See
[`OUTBOUND-SAFE-FORMS.md`](OUTBOUND-SAFE-FORMS.md) for each form, measured.

**Cost.** A command that names no client costs about 3 ms. A command that
names one costs about 190 to 230 ms with the service (measured on a busy
machine), because the command text is scanned; a file-reference deny skips the
scan and costs about 45 ms.

**A sandbox placeholder** (`SANDBOX_MASKED_<id>`) is removed before the text is
read. The real placeholder format of Claude Code's sandbox credential masking is
not verified; set `GUARDS_OUTBOUND_SENTINEL_RE` if it differs. For a hard
boundary, use Claude Code's sandbox (a network allowlist and credential
masking), which this guard complements and does not replace.

## Size and position limits

- **PII and injection are flagged on the first 2 KB of a Bash output only**
  (`FLAG_MAX_BYTES`). Personal data or an injected instruction later in a long
  output is never flagged. This is the price of keeping the hook fast: the
  models cost roughly 0.3 s per KB, and splitting the work in parallel made
  them slower, not faster. `FLAG_MAX_BYTES` is read by the hook, not the
  server. Raising it costs latency; `0` turns the flags off.
- **Secrets are scanned in the first 256 KB of each Bash stream only**
  (`SECRET_MAX_BYTES`). The rest is returned unscanned, with a warning
  prepended.
- **The older single-call path scans only the first 24 KB** (`SCAN_MAX_BYTES`)
  and says so. `SendMessage` has the same 24 KB cap per field.
- **MCP text blocks over 512 KB are skipped silently** (`MCP_GUARD_MAX_BYTES`)
  and arrive unredacted, with no note.
- **The plugin's own `scan` MCP tool posts the whole text to the server's
  `/v1/scan`**, which refuses bodies over 64 KiB with HTTP 413 (guards-unified
  #17, released after 0.2.3). The tool then returns its `{"error": ...}` shape,
  never a "clean" result, but its wording says the backend is unreachable,
  which is misleading for a 413.
- **The publish guard reads at most 512 KB** per named file and of the staged
  diff (`PUBLISH_GUARD_MAX_BYTES`); it says so when it cuts a diff, and nothing
  past the cut is scanned.
- **A very long unbroken run of name characters used to make the local scan
  slow; the publish guard denied at its 15 s limit.** The cause was a base64
  blob, a hash or a bundle without spaces: the context pass took far more than
  linear time on one such run (a 20 KB run took about 10 s). The shared
  `scan.sh` now masks runs of 256 or more name characters for the context rules
  (20 KB: 0.06 s), and a secret after one, or a long run as a key's value, is
  still redacted. Other pathological shapes may remain; a scan that still runs
  out of time is denied, not allowed.
- **The `guards:synthetic` marker is not checked beyond a few vendor shapes.**
  Before this was fixed the hook dropped every marked added line before scanning,
  so a fabricated vendor-token-shaped string and the lines of a throwaway private
  key, each marked, were allowed (verified). Now marked lines are still held
  against: private-key headers, AWS access key ids (`AKIA`/`ASIA` plus 16),
  GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), Slack
  tokens (`xox[abprs]-`), and Stripe and OpenAI-style live keys (`sk_live_`,
  `rk_live_`, `sk-proj-`), and the commit is denied. A matched token containing
  EXAMPLE or FAKE (the documented AWS example ids) is accepted. Not in the set,
  on purpose: JWT-shaped, generic high-entropy and base64 values. So a real
  credential of another shape on a marked line still passes unchecked.
- **`git commit` forms the publish guard does not follow:** a pathspec commit
  (`git commit src/a.ts -m x`, which commits the working-tree state of the
  listed paths whatever is staged), `--amend` (only the newly staged changes are
  scanned, not what the amended commit already holds), and `git add` with a glob,
  quoted or `$`-expanded argument in the same command (falls back to the tracked
  changes against `HEAD`; a new untracked file is not seen). Untracked files that
  nothing stages are never scanned.
- **Very large inputs with thousands of matches are slow.** A timeout in the
  scanner keeps the original text rather than withholding it, so a scan that
  runs out of time is a leak, not a block. This was a deliberate choice; see
  [`TRADEOFFS.md`](TRADEOFFS.md).
- **The credential-file content sniff reads only the first 10 MiB** of a file
  (`CREDFILE_SNIFF_MAX_BYTES`).

## What the detectors can and cannot recognise

- **A bare high-entropy value with no key name, prefix or context** is not
  detectable by any rule. The only defence is `SECRET_GUARD_ENV_VALUES=1`, which
  the hooks turn on for the scanner they run locally: it redacts the exact
  values of environment variables with secret-looking names. That does not see
  values that are not in the session environment, values under 8 characters,
  placeholders, or values that are existing file paths. The container cannot see
  your environment at all.
- **Access-key and client IDs are not redacted by default**
  (`SECRET_GUARD_REDACT_KEY_IDS=1` changes that). They are semi-public
  identifiers; the secret half is the boundary.
- **Encodings:** the scanner has a base64 decoding pass (up to 25 candidate
  tokens per scan). Other encodings, such as hex, URL encoding or compression,
  are not decoded. A secret split across several tool calls or messages is not
  reassembled.
- **Context rules trade precision for recall.** They key on what a value is
  next to (a key name, URL password, header, command-line flag). That produces
  false positives on text that documents such things, and each false-positive
  fix removes a little protection: a value that is an existing path is never
  treated as a password, and a heading that ends in a keyword plus a colon,
  followed by exactly one word, still has that word redacted because it cannot
  be told from a YAML scalar.
- **Prompt injection:** the injection finding is jailbreak and override
  detection. Measured recall on indirect injection (malicious instructions
  embedded in data with no override language) is about 6% on real tool-output
  attacks (InjecAgent, n=200). A "clean" verdict is not a safety guarantee. The
  warning is also shown only above a 0.95 confidence floor, because benign
  security-themed text scored 0.86 to 0.91.
- **PII:** only the entity types the PII model is configured for are found, and
  the model produces false positives on engineering text. PII is flagged,
  never removed, by default (`PII_GUARD_MODE=redact` changes that for the Bash
  hook and outgoing messages).

## False positives you will meet

- **The credential-file guard denies any file that contains a private-key
  header, whatever its name,** including documents that only quote one, and it
  checks glob-expanded Bash arguments, so an innocent `grep ... docs/*` can be
  denied. See "False positives from the private-key content sniff" in
  [`guards/README.md`](../guards/README.md).
- **The publish guard occasionally blocks a post that sits next to a
  secret-ish key name.** In `default`, `acceptEdits` and `plan` modes it asks;
  elsewhere it denies. The credential-file guard does the same for a `.env`,
  kubeconfig, `.npmrc`/`.pypirc` or terraform state: it asks only where a person
  can answer, so in `auto` an agent that needs one is denied, not prompted.
- **PII notes on ordinary developer output** (a tool name tagged as a person,
  a git remote as an email address). They are notes only.

## Operational limits

- **Latency is not always under one second with the flags on.** Measured by the
  maintainers on a development machine (not re-measured for this page): about
  0.6 s at 1 KB of output, 1.0 s at 3 KB and above, worst case 1.4 s, against
  0.3 to 0.8 s with `FLAG_MAX_BYTES=0`. The Bash hook runs after every Bash
  call, so you feel this on all work. `FLAG_MAX_BYTES=0` removes it at the cost
  of no PII or injection notes.
- **Scan latency scales with your CPU.** The compose file allows 16 CPUs and 4 GB
  of memory for the service; a small machine will be slower, and a container
  killed for exceeding memory looks like an intermittent outage.
- **A hook that exceeds its timeout fails open in Claude Code** (verified, Claude Code 2.1.304, see [`HOOKS.md`](HOOKS.md)): the hook is
  killed and the tool call or output goes through unchecked. Each hook
  therefore has its own shorter deadline and a deliberate outcome at expiry
  (deny for the publish and credential-file guards, withhold for the Bash and
  MCP output hooks), listed in [`HOOKS.md`](HOOKS.md). The cost is that a hung
  scanner now blocks a publish or hides one command's output until you retry.
- **A missing `jq` degrades every hook, visibly.** The publish and
  credential-file guards still decide (awk reads the payload) but the publish
  guard skips the gitleaks pass, so vendor-token formats are not checked. The
  Bash, MCP-result and SendMessage hooks cannot redact without `jq`: a result or
  message with credential material is withheld or denied with a reason that says
  to install it, and anything else passes with a note that only the built-in
  checks ran (no PII or injection notes). The prompt hook is advisory and stays
  silent. The `check_before_publish` tool answers `unknown`, never allow, when it
  could not inspect.
- **Docker is required for PII and injection.** Without it only secret
  detection runs. The service stack is not supported on Windows; Windows is not
  tested.
- **The service has no authentication** and sees raw tool output. It is bound
  to loopback on purpose. Do not expose it, and be careful what you set
  `GUARDS_ENDPOINT` to.
- **Auto-update trust.** Watchtower, with access to the Docker socket, pulls
  the floating `:cpu` tag every five minutes, so a published image reaches your
  machine within minutes. Pin the tag and remove Watchtower if that is not
  acceptable.

## Maintenance gaps

- **Hook tests use stubs.** `sendmessage-guard.sh`, `userpromptsubmit-guard.sh`,
  `guards-selfheal.sh` and `mcp/server.py` have automated tests, but against a
  stub service and stubbed `docker`, `curl` and HTTP client, not the real
  models. What a real Claude Code session does with their output was verified
  by hand (see [`HOOKS.md`](HOOKS.md)).
- **The vendored `scan.sh` is copied by hand** from `app/scan.sh` in
  [guards-unified](https://github.com/gramatr/guards-unified). This repository's
  CI (`scan-sh-drift`) fails when the copy differs from guards-unified's `main`
  (or the same tag on a tag build) apart from the two-line header, so a drift
  cannot go unnoticed. The check still needs the copy to be made: a scanner fix
  that lands only in guards-unified reaches the local fallback after the paired
  sync commit here, and until guards-unified's change is merged this check
  compares against the old file.
- **Versions move in lockstep,** but each repository's CI cannot see the other,
  so equal `VERSION` files are a release-checklist step.
- **gitleaks versions** are pinned in two places (the self-heal script and the
  vendored Dockerfile) and kept equal by hand.
- **Known CVEs** in the Go modules bundled with the pinned gitleaks release
  are not suppressed. The scan image builds gitleaks from its tag with fixed
  `klauspost/compress`, `x/crypto` and `x/text` and a current Go toolchain, and
  `.trivyignore` is empty. For a machine without Docker, the self-heal script
  downloads the patched gitleaks that guards-unified publishes with each release
  (from the first release that carries it) and checks it against SHA-256 values
  this plugin carries, `guards/vendor/secret-guard-core/gitleaks-assets.sha256`.
  If that fails (no asset yet, a hash mismatch, an unsupported platform) it falls
  back to the unpatched upstream release and says so in its log; that warning is
  the only signal, and the host then runs the weaker binary.
