# Guards for coding agents

One page for coding agents working in a session that runs the guards plugin, and for
people who write `CLAUDE.md` or `AGENTS.md` for such sessions. The same rules are in
the MCP server's `instructions` and `guards://guide/*` resources, the prompts, and the
`guards-for-agents` skill; this page is the reference.

## The three rules

1. **Never put a real credential** in a commit message, PR or issue body, comment or
   file: not a prefix, a partial, or a rotated one. Describe the shape (length,
   character classes, which tool produced it).
2. **`guards:synthetic` on the same line** marks a deliberately fake fixture line. It
   covers only the added lines of the staged diff of a `git commit`, and not a real
   vendor credential or key (a private-key header, an AWS access key id, a GitHub,
   Slack, Stripe or OpenAI-style live key is still denied on a marked line;
   documented EXAMPLE ids and values containing EXAMPLE or FAKE are fine). It does
   not cover the command text (so not a `-m` message), `gh issue`/`gh pr` bodies, or files named
   by `--body-file`, `-F` or `cat`.
3. **Never disable or bypass the guards, and never ask the user to.** Report a false
   positive and let the user decide. The `GUARDS_ALLOW_*` switches
   (`GUARDS_ALLOW_PUBLISH_SECRETS`, `GUARDS_ALLOW_OUTBOUND_SECRETS`) are read from the
   environment Claude Code was started from; typing one in front of a command does
   nothing.

## Tools

All tools are value-free: no result contains a raw matched credential value. None of
them disables, bypasses or weakens a guard.

| Tool | Example | Use it to |
|---|---|---|
| `check_before_publish(text_or_command, cwd, kind)` | `check_before_publish("git commit -m wip", "/repo")` | Run the real publish guard offline (strict "auto" mode) and get allow or deny with where each match is. Nothing is published. |
| `explain_block(message)` | `explain_block(<deny message>)` | Turn a deny or ask message into a diagnosis: guard, rules, each located source (command text, named file, staged diff with file and line) and the remedy that fits it. |
| `prepare_publication(kind, title, body)` | `prepare_publication("pr-body", "Fix login", body)` | Write commit, PR or issue text to a file, scan it, and get the exact command (`git commit -F`, `gh pr create --body-file`, `gh issue create --body-file`). Lines the scanner would redact are listed redacted; a file with findings holds the redacted text only. |
| `guards_status()` | `guards_status()` | See the registered hooks, plugin and service versions, whether the service answers, the permission-mode rules, any environment override that switches a guard off, and degraded modes (no `jq`, no `gitleaks`, service down). |
| `mark_synthetic(path, lines, reason)` | `mark_synthetic("tests/test_login.py", [12], "fake password")` | Add `guards:synthetic` to fixture lines with the right comment syntax for the file type. Refuses lines shaped like a real credential, an empty reason, and paths outside the repository. |
| `report_false_positive(rule, redacted_line, context)` | `report_false_positive("secret-lead-in", <redacted line>, "config key name")` | Write a value-free report to a local file and return its path for the user to forward. Refuses input that does not look redacted. |
| `scan(text)` | `scan("...")` | Scan text for secrets, PII and injection (see the README). |

`check_before_publish` lives in `mcp/server.py`; the others in `mcp/guards_tools.py`.
Files the tools write go under `$GUARDS_STATE_DIR` (default `~/.local/share/gramatr-guards`).

## Prompts and skill

- MCP prompts: `fix_a_block` (steps after a block), `safe_pr_body` (how to write
  publishable text), `fake_fixture_checklist` (writing fixtures).
- Skill `guards-for-agents` (`guards/skills/guards-for-agents/SKILL.md`): triggers when
  a guard blocks something, when you write fixtures, or when you write commit, PR or
  issue text.
- Resources: `guards://guide/publishing`, `guards://guide/false-positives`,
  `guards://guide/hooks`, `guards://guide/diagnosing-a-block`.

## Sending data over the network

The outbound guard checks a Bash command whose command word is `curl`, `wget`, HTTPie,
`nc`, `scp`, `rsync`, `sftp` or `ssh`. It denies (or asks about) a command that would send:

- a credential file (`curl -d @~/.aws/credentials`, `nc host 9 < ~/.ssh/id_ed25519`,
  `scp ~/.ssh/id_ed25519 host:`), or the whole environment (`env | curl -d @- ...`);
- a literal credential in the command text (a token in a header, `-u user:password`,
  a password in a URL or a body).

The `@` is not the problem: `curl -H @headers.txt` and `curl -d @payload.json` are fine.
What matters is what the file is. If you need to send a credential, do not put it in the
command line. Use one of these:

1. A config file only you can read: `curl -K <file>` (with a `header = "..."` line in it) or `wget --config=<file>`.
2. The client's netrc support: `curl --netrc-file <file>` or `~/.netrc`.
3. A header file: `curl -H @headers.txt`.
4. A body from a file or standard input: `curl -d @payload.json` or `curl -d @-`.

A variable reference (`-H "X-Api-Key: $KEY"`) keeps the value out of the command text and the transcript but not out of the process list: `ps` shows it to other users of the machine. A header or cookie that carries a credential is printed back by `curl -v`, `wget -d` and `http --verbose`, so avoid those options when one is involved. Each form is proven against the real clients in [`OUTBOUND-SAFE-FORMS.md`](OUTBOUND-SAFE-FORMS.md).

If a command is denied, read the "Where" and "What to do" parts, switch to one of the
forms above and run it again. An ask-class file (`.env`, kubeconfig) or an ambiguous
literal is an ask for a person in default, acceptEdits and plan modes and a deny in every
other mode. A command that names its file through a variable (`-d @$F`) is allowed with a
note, because the guard cannot see the path; that is a limit, not permission. Do not split,
encode or rename a value to get past the guard.

## Whose message is it?

A call can be stopped by something other than the guards: another PreToolUse hook (yours,
the project's or another plugin's), a permission rule, or Claude Code itself. In one replay,
93 of 749 `kubectl` results were blocked by a hook that was not a guard. The prefix tells
them apart, and `guards_status` returns the same table in its `message_prefixes` field.

| The message starts with | Who sent it | What it means |
|---|---|---|
| `Blocked by guards <hook>:` | a guards hook | The call did not run. The message ends with a `Fix:` clause: the exact thing to do instead. |
| `guards <hook>:` | a guards hook | An ask (a person is prompted and the call has not run yet), a note, or a withheld output. For a withheld output the command or tool **already ran**; only its output was replaced by a notice, so do not assume it failed. |
| anything else | not a guard | Look at the hook, rule or tool that wrote it. The guards cannot change it. |

`<hook>` is one of `credfile-guard`, `publish-guard`, `outbound-guard`, `sendmessage-guard`,
`userpromptsubmit-guard`, `combined-hook` (Bash output) or `mcp-output-guard` (MCP output).

## Diagnosing a block

1. Call `explain_block` with the message. A publish-guard message has the detector
   rules, a "Where" list (up to 5 entries) and what to do. Each entry names the source:
   the command text, a file the command names, or the staged diff with file and line.
2. Fix the source it names:
   - **Command text, issue or PR body, file named by `--body-file` or `-F`:** rewrite
     to describe the shape. The marker does not apply. Put long text in a file with
     `prepare_publication`.
   - **Staged diff of a commit:** a deliberately fake fixture line takes the marker on
     the same line (`mark_synthetic`), then stage the file again.
   - **A key name that only names an identifier** (`secret_vault_id`, `token_store_ref`):
     a false positive. Rename or reword it if you can, and `report_false_positive`.
   - **A false positive you cannot reword** (a manifest field that names a Secret, code
     that forwards a variable), in a mode with no person to ask: the block message ends
     with an `Approval:` paragraph, an id and a command. Show the person the lines above
     it and ask them to run the command in their own session with the `!` prefix; it
     approves that exact text once, for ten minutes. Then retry the **identical**
     command. Never run that command, or read or write the approve-once store, yourself:
     it is refused, and an approval you made would not be the person's. A sure-thing
     match (a private key, a vendor token format) never carries one.
3. Re-run `check_before_publish` on the same command or text. (It only reports; it does
   not use up the person's approval.)
4. Other messages: "did not finish in time" means the input was very large or held thousands of
   matches (long lines and long unbroken runs are no longer slow; split the text or commit a
   large generated file separately); "no secret scanner could run" means the
   install needs repair (`guards_status`, tell the user). Neither is a finding.

An ambiguous match is an ask for a person in default, acceptEdits and plan modes, and a
deny in every other mode. You cannot answer an ask yourself.

## What is already not a false positive

The scanner does not flag, by design: a key that names an identifier or
reference of a secret (`secret_name`, `client_secret_bws_id`,
`secret_vault_id`, `token_store_ref`, `credential_provider_arn`), a setting
about a credential (`..._TIMEOUT`, `..._MODE`), placeholders (`${VAR}`,
`<token>`, `***`), and ordinary source code where an unquoted value is a call, a variable, a member chain or a type name (a declaration assigned the result of a function, an object property whose value is a variable, a field typed as a primitive). It does flag
any string literal assigned to a credential-named variable, and unquoted values
in env files, shell, YAML and INI.

## Fixtures

Deliberately fake fixtures in a commit are fine with the marker on every
matching line, in the file's comment syntax:

```ts
const sample = { client_secret: "not-a-real-value" }; // guards:synthetic
```

A marked line is still checked against vendor-key shapes, so build a fake
vendor-shaped value at run time or give it an obviously fake form (EXAMPLE, FAKE).
Rules of thumb: build values at run time when you can; never paste a real token
"just to see"; never use the marker on a line that could hold a real value. The
marker removes the line from the scan, so it is a statement by you that the line
is fake.

## When the block is wrong

1. Rename or reword if you can (the key, the prose: say "the token (24
   characters)" rather than writing a credential word, a colon and a word).
2. Otherwise tell the user: the rule, the redacted line, the source. They decide
   whether to set the override in the environment Claude Code starts from.
3. Do not split, encode or otherwise disguise a value to get past the scan.

## What the marker covers

Only added lines of a `git commit`'s staged diff, and only the line that carries it.
A marked line is dropped from the key-name and context rules, but the commit is
still denied if it matches a sure-thing vendor shape: a private-key header, an AWS
access key id (`AKIA`/`ASIA`), a GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`,
`ghr_`, `github_pat_`), a Slack token (`xox[abprs]-`), or a Stripe or OpenAI-style
live key (`sk_live_`, `rk_live_`, `sk-proj-`). The deny names the family and the
place, never the value. Accepted on a marked line: a matched token that contains
EXAMPLE or FAKE (the documented AWS example ids), JWT-shaped strings and ordinary
fake values. Build vendor-shaped fakes at run time (a prefix plus filler) so the
source holds no literal. `mark_synthetic` is stricter still and refuses these
shapes and JWTs, so the marker cannot hide a real credential.

## What never to do

- Do not include a real credential anywhere, not even a dead one.
- Do not split, encode or otherwise disguise a value to get past a scan.
- Do not look for another way to publish text the guard blocked.
- Do not ask the user to set `GUARDS_ALLOW_*` or to switch the guards off.
- Do not approve an ask on your own behalf.

## For `CLAUDE.md` / `AGENTS.md`

The snippet in [`HOOKS.md`](HOOKS.md#working-with-the-guards-as-a-coding-agent) is
self-contained. This one-line pointer is enough when the plugin's MCP server is
connected: "This session runs gramatr-guards; read its `guards-for-agents` skill and
use its `check_before_publish` and `prepare_publication` tools before publishing."
