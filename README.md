# gramatr-guards

A Claude Code plugin marketplace with one plugin, **guards**: secret, PII and
prompt-injection guards for Claude Code sessions.

- Secrets in Bash output, MCP results and outgoing agent-to-agent messages are
  redacted.
- Reads of credential files are denied before any content exists.
- A commit, pull request, issue or comment that carries a credential is blocked,
  and the block names the matching line with the value redacted.
- A command that would send a credential file, the whole environment or a literal
  credential to a remote host is blocked.
- PII and likely prompt injection are noted, never redacted. By default each PII type is named once
  per session and the note can be filtered (see [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)).
  They never change the text.

The detection logic runs in the
[guards-unified](https://github.com/gramatr/guards-unified) service, one container
behind `POST /v1/scan` and `POST /v1/scan/secret`. This repository is the Claude Code
side: hooks, an MCP server (seven tools, three prompts, four resources), and a self-heal script that keeps the container running.

**One hard rule, everything else best effort.** The only control that must be fast,
synchronous and strict is "no secrets". PII and injection findings are notices.
Read [`docs/LIMITS.md`](docs/LIMITS.md) before relying on this.

## Install

In Claude Code 2.1.275 or later, one step:

```
/plugin install guards --marketplace gramatr/claude-plugin-guards
```

Or in two steps, from a terminal:

```
claude plugin marketplace add gramatr/claude-plugin-guards
claude plugin install guards
```

Then restart Claude Code (or run `/reload-plugins`). Updates: `/plugin`, then
`/reload-plugins`. Plugin installs track `main` and are identified by commit.

Requirements: `jq` and `curl`; `docker` with `docker compose` for PII and injection
detection and the fast secret path. Without Docker, secret detection still works
through a local fallback; PII and injection do not. Details, the eight hooks and
what each does when the service is down are in
[`guards/README.md`](guards/README.md) and [`docs/HOOKS.md`](docs/HOOKS.md).

## Documentation

| Doc | What it covers |
|---|---|
| [`guards/README.md`](guards/README.md) | The full plugin guide: install, each hook, configuration |
| [`docs/AGENTS-GUIDE.md`](docs/AGENTS-GUIDE.md) | One page for coding agents and for people who write CLAUDE.md or AGENTS.md |
| [`docs/HOOKS.md`](docs/HOOKS.md) | Per-hook matcher, timeout and failure modes |
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Every environment variable the plugin reads |
| [`docs/LIMITS.md`](docs/LIMITS.md) | What the guards do not catch |
| [`docs/TRADEOFFS.md`](docs/TRADEOFFS.md) | Where the guards were tightened or loosened, and why |
| [`SECURITY.md`](SECURITY.md) | How to report a vulnerability privately |

## Versions

This plugin and guards-unified are one product in two packages. They carry the same
version and the same tag (`vX.Y.Z`), in the `VERSION` file here. The changelog covers
both and lives in guards-unified:
[CHANGELOG.md](https://github.com/gramatr/guards-unified/blob/main/CHANGELOG.md).
Releases of the service are on its
[releases page](https://github.com/gramatr/guards-unified/releases).

## License

MIT, see [`LICENSE`](LICENSE). The vendored scanner files carry their own header
comments, and their origin is described in [`NOTICE`](NOTICE).
