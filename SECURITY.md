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

- [GHSA-h5rq-hrxc-f3vm](https://github.com/gramatr/claude-plugin-guards/security/advisories/GHSA-h5rq-hrxc-f3vm) (published 2026-10-22): in v0.2.9 and every earlier release, the plugin's local fallback scanner could return a vendor-shaped token unredacted, about 1 scan in 155, with no error. Fixed in v0.2.10. The same flaw in the server image is [GHSA-5g92-g3j3-2g22](https://github.com/gramatr/guards-unified/security/advisories/GHSA-5g92-g3j3-2g22).

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
  Grep and WebFetch output, tool inputs other than the publish verbs,
  `SendMessage` and the network-client commands the outbound guard inspects, a secret typed in your own prompt (a hook cannot remove it)
  and similar. Also anything it says is not detected (short values, a bare
  high-entropy value with no context, encodings other than base64, text split
  across calls, and similar).
- Prompt-injection recall: indirect injection is mostly missed by design (6%
  measured), and a `clean` verdict is never a safety guarantee.
- The service has no authentication, no TLS and no rate limit; it is meant to
  be reachable on loopback only, and `GUARDS_ENDPOINT` sends raw output wherever
  it points. Exposing it to a network and then reporting
  that anyone can reach it is a deployment mistake, not a flaw.
- A scan by the service that times out is not the whole story: each hook has its
  own shorter deadline, at which it denies (publish, credential-file, outbound
  and SendMessage guards) or withholds (Bash and MCP output) instead of letting
  the text through, and the prompt note stays silent (see
  [`docs/HOOKS.md`](docs/HOOKS.md)). A late PII or injection answer is dropped
  without a note, deliberately.
- Findings that need an attacker who already controls the machine, the
  container runtime or the user's account.

If you are unsure whether something is in scope, report it privately and say so.

## How we rate severity

We rate a defect with the CVSS v3.1 Base metrics and use the standard bands: Low 0.1 to 3.9, Medium 4.0 to 6.9, High 7.0 to 8.9, Critical 9.0 to 10.0. CVSS has no field for some of what a small local tool gets wrong, so we apply these conventions and say so on each advisory:

- **Chance.** Attack complexity is High when the defect depends on chance (below about 5 percent of events) or on an uncommon environment the user chose, and Low when it happens every time for a kind of input or an attacker can cause it.
- **Where it runs.** Attack vector is Local for anything that runs on the user's machine (the hooks and the loopback service), scope is Unchanged, and user interaction is Required for a path that runs inside a session a person has open.
- **Confidentiality.** Low when the loss is bounded: one value, or a small fraction of events, and the recipient is inside the session's own trust boundary (the model and the transcript). High when a whole class of credential is exposed, a credential store is read, or the exposure is outside that boundary (a public repository, a world-readable file). None when the user is told (a warning, a deny, withheld output).
- **Not a vulnerability.** A documented limit (listed above), a failure that is loud and fails closed with nothing leaked, and a finding in a third-party dependency. For the last we point to the upstream advisory.

Each advisory states its CVSS vector and a short reason for the confidentiality and complexity choices.

## When we publish an advisory

Every in-scope defect that shipped in a release and rates Low or above gets a repository security advisory, on this repository's Security tab, with the affected and patched versions. This rule applies from 2026-10-22. Defects fixed in earlier releases are described in the changelog and the release notes, not in advisories. We do not request CVE identifiers by default. If one is ever requested, the maintainer decides, case by case, after seeing the exact request.
