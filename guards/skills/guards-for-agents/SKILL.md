---
name: guards-for-agents
description: Use when a guard (publish-guard, credfile-guard, sendmessage-guard) blocks or redacts something, when writing test fixtures that look like credentials, or when writing commit, PR or issue text. Explains how to fix the text instead of fighting the guard, using the guards MCP tools.
---

# Working with the guards
The guards stop credentials from reaching public places. A block is about the
TEXT you wrote, not about you. Fix the text; never look for a way around the
guard. The overrides (`GUARDS_ALLOW_*`) belong to the person running the
session; do not ask for them to get past a fixture or a long message.

The guards MCP tools (all value-free: none returns a raw matched value):

| Need | Tool |
|---|---|
| Understand a deny message | `explain_block(message)` |
| Ask the publish guard before you try | `check_before_publish(text_or_command, cwd)` |
| Write commit/PR/issue text | `prepare_publication(kind, title, body)` |
| Mark a fake fixture line in source | `mark_synthetic(path, lines, reason)` |
| Is anything degraded or switched off | `guards_status()` |
| Wrong match on a real non-secret | `report_false_positive(rule, redacted_line, context)` |

Prompts with the same steps: `fix_a_block`, `safe_pr_body`, `fake_fixture_checklist`.
Full reference: `docs/AGENTS-GUIDE.md`.

## When something is blocked

1. `explain_block` with the message. It names the source (command text, a file the
   command names, or the staged diff of a commit) and the rule.
2. Fix that source. The remedy depends on it:
   - Command text, issue/PR body, file named by `--body-file` or `-F`: rewrite the
     text to describe the SHAPE (length, character classes, the tool that made
     it). `guards:synthetic` does NOT apply here.
   - A commit's staged diff: a deliberately fake fixture line takes the marker
     `guards:synthetic` on the same line (`mark_synthetic` writes it with the
     right comment syntax).
3. Re-check with `check_before_publish`, then run the command.

## Writing commit, PR and issue text

- Never pass long text inline. `prepare_publication` writes it to a file, scans it
  and returns the exact command: `git commit -F FILE`,
  `gh pr create --body-file FILE`, `gh issue create --body-file FILE`.
- Name rules, files and line numbers, never a value, prefix or partial.

## Writing fixtures

- Prefer building the fake at run time (`"x" * 32`, a prefix plus a counter) so
  the source holds no literal.
- Vendor-shaped literals (AWS ids, `ghp_`, `xoxb-`, `sk-`, JWTs, PEM headers) cannot
  be marked: `mark_synthetic` refuses them so the marker cannot hide a real one.
- A generic fake (a password assignment in a test) may stay literal with the
  marker on the same line. Never paste a real one, even a dead one.

## If you think the guard is wrong

`report_false_positive` with the rule and the REDACTED line. It writes a local
file; tell the user its path so they can forward it. Do not retry variations of
the text to find one that slips through.
