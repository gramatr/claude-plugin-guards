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
   positive and let the user decide. `GUARDS_ALLOW_PUBLISH_SECRETS=1` is read from the
   environment Claude Code was started from; typing it in front of a command does
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
3. Re-run `check_before_publish` on the same command or text.
4. Other messages: "did not finish in time" means a very long single line was slow to
   scan (leave minified or generated files out); "no secret scanner could run" means the
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
Vendor-shaped fakes (AWS ids, `ghp_`, `xoxb-`, `sk-`, JWTs, PEM headers) should be built
at run time (a prefix plus filler) so the source holds no literal; `mark_synthetic`
refuses them so the marker cannot hide a real credential.

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
