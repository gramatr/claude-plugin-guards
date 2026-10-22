# Security policy

## Reporting a vulnerability

Please report security problems privately, through GitHub's private
vulnerability reporting: open the **Security** tab of this repository and choose
**Report a vulnerability**. Issues are disabled on this repository, and please
do not describe a vulnerability in any public place (a pull request, a
discussion, a social post): a public report discloses it to everyone at once.

This is a small open-source project. Replies are best effort and no response
time is promised. A report that is clear, reproducible and about something in
scope is the most likely to be acted on quickly.

## Supported versions

Only the latest release is supported. This repository and
[guards-unified](https://github.com/gramatr/guards-unified) (the server image
the plugin talks to) move in lockstep (the same version number and tag; see
[`RELEASING.md`](https://github.com/gramatr/guards-unified/blob/main/docs/RELEASING.md)),
and the current number is in the [`VERSION`](VERSION) file. Fixes are made on `main` and shipped in a new release; older releases
are not patched.

## Past advisories

- [GHSA-h5rq-hrxc-f3vm](https://github.com/gramatr/claude-plugin-guards/security/advisories/GHSA-h5rq-hrxc-f3vm) (published 2026-10-22): in v0.2.9 and every earlier release, the plugin's local fallback scanner could return a vendor-shaped token unredacted, about 1 scan in 125, with no error. Fixed in v0.2.10. The same flaw in the server image is [GHSA-5g92-g3j3-2g22](https://github.com/gramatr/guards-unified/security/advisories/GHSA-5g92-g3j3-2g22).

## What to send

Describe the **shape** of the finding and the steps to reproduce it. **Never
include a real credential, token, key or personal data**, not even a rotated or
expired one. Use a fabricated value that has the same shape (for example a
made-up string with the right prefix and length), and say which rule or
behaviour it exercises. Useful details:

- the plugin version (the `VERSION` file in the installed copy), the server
  version (`GET /about` on the service) and your Claude Code permission mode;
- the exact request or input shape, with fabricated values;
- what you expected and what happened (for example "the value came back
  unchanged with verdict `clean`");
- the impact you see, and whether it needs a particular setting.

This repository's own scanner redacts credential-shaped text in tool output, so
describing a shape in words is also the safest way to get it past your own
tooling.

## What is in scope

- A secret that survives redaction when the input is of a kind the documentation
  says is covered: the scanner returns it unchanged, or reports `found` without
  removing it. The scanner lives in
  [guards-unified](https://github.com/gramatr/guards-unified); if you are
  unsure which repository a finding belongs in, report it here.
- A bypass of a guard that the documentation says holds, for example a way to
  make a hook stay silent for a case it claims to block (a credential-file read
  or a publish that goes through), or to make the scanner skip text it should
  scan.
- Problems in the plugin or the service it installs: command injection through
  a hook payload, unsafe handling of files or paths, the self-heal and update
  logic, leaking scanned text into logs or error output, or a flaw in the
  container image, the compose file or the release pipeline.
- A vulnerable dependency or a supply-chain weakness that is reachable here.

## What is not in scope

These are documented limits, not vulnerabilities. They are listed in
[`docs/LIMITS.md`](docs/LIMITS.md) and in
[`THREAT-MODEL.md`](https://github.com/gramatr/guards-unified/blob/main/docs/THREAT-MODEL.md#out-of-scope-and-not-defended)
in guards-unified:

- Anything the documentation already says is not covered: `git push`, Read,
  Grep and WebFetch output, tool inputs other than the publish verbs and
  `SendMessage`, a secret typed in your own prompt (a hook cannot remove it)
  and similar. Also anything it says is not detected (short values, a bare
  high-entropy value with no context, encodings other than base64, text split
  across calls, and similar).
- Prompt-injection recall: indirect injection is mostly missed by design (6%
  measured), and a `clean` verdict is never a safety guarantee.
- The service has no authentication, no TLS and no rate limit; it is meant to
  be reachable on loopback only, and `GUARDS_ENDPOINT` sends raw output wherever
  it points. Exposing it to a network and then reporting
  that anyone can reach it is a deployment mistake, not a flaw.
- A scan that times out returns the text unscanned, deliberately.
- Findings that need an attacker who already controls the machine, the
  container runtime or the user's account.

If you are unsure whether something is in scope, report it privately and say so.
