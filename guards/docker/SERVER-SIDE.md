# Preparing this stack to run server-side

> **Superseded design, kept as history.** Everything below the "Historical
> notes" line was written when the stack ran three separately hostable guards
> (secret, PII, injection) as three containers. That is no longer the
> architecture. The stack is now **one** bundled `guards-unified` container
> serving secret, PII and injection findings from the same process, so you
> cannot host one axis and keep the others local.
>
> **Current guidance**
>
> - The bundle inherits the strictest posture of its parts: treat the whole
>   service as **loopback-only**. `docker-compose.yml` publishes it as
>   `127.0.0.1:8700:8700`; that prefix is load-bearing. Never publish it on
>   `0.0.0.0` from this compose file. A shared instance for several machines is
>   a separate deployment with its own requirements, listed below.
> - The service has no authentication and receives raw tool output, which can
>   contain the credentials and personal data it exists to catch.
> - `GUARDS_ENDPOINT` can point at another host, and the hooks will send raw
>   output there. Do that only for a service you operate under the same
>   assumptions as a local one. Hosting an implementation of the same endpoint
>   contract (`POST /v1/scan`, `POST /v1/scan/secret`) elsewhere is a separate
>   architecture and privacy decision, not something this repository enables.
>   When the endpoint is not the local stack (loopback, port 8700), the
>   SessionStart self-heal does not pull, start or update a local container; it
>   only checks the endpoint's `/health` and warns if it does not answer. If the
>   endpoint is unreachable the hooks fall back to the local secret scan only.
> - If you do run one shared instance for several machines, treat these as
>   requirements, not suggestions:
>   - **Private network only.** No public route, tunnel or public DNS name. The
>     service has no authentication, so the network is the only boundary.
>   - **TLS from a certificate the clients already trust**, so `curl` in the
>     hooks verifies it and nothing is sent in the clear.
>   - **No body capture anywhere on the path.** Do not enable request or
>     response body logging or tracing at the ingress, proxy, mesh or sidecar.
>     Scanned text must never reach a log, trace or metric.
>   - **Pin the image by digest** and update it by change request, not through a
>     floating tag and an auto-updater, and run at least two replicas with a
>     disruption budget so an update does not drop the service.
>   - Treat it as temporary until it sits behind real authentication.
> - Logs: a live test of v0.2.12 (unique marker strings and an email address sent
>   through both scan routes, including malformed, oversized and
>   error-triggering requests) found no scanned text in the service's logs or in
>   an ingress controller's. The service's own log calls write fixed strings
>   only, the scan script's stderr is never logged, and the metrics file stores
>   verdicts only. One residual: tracebacks print exception messages, and this
>   was not shown to hold for every error a dependency can raise. Memory
>   handling after a request is still an open item.
> - Current behavior is documented in [`../README.md`](../README.md),
>   [`../../docs/HOOKS.md`](../../docs/HOOKS.md) and
>   [`../../docs/LIMITS.md`](../../docs/LIMITS.md).

## Historical notes (three-container design)

This file exists so a future agent (or you) can modify this Docker
Compose stack toward a hosted/multi-tenant deployment **deliberately**,
not by discovering a half-wired path and guessing the rest. Nothing in
`docker-compose.yml` enables server-side behavior today — every
port-publish is `127.0.0.1:PORT:PORT`, and that is load-bearing, not a
default left lying around.

Read this in full before changing any bind address, adding an
`0.0.0.0` publish, or removing a `127.0.0.1:` prefix anywhere in this
stack.

## The constraint is per-tool, not one setting

The three guards do **not** have the same hosting posture. Confirmed
from each repo's own README (not inferred):

| Tool | Hosted tier allowed? | Why |
|---|---|---|
| `injection-guard` | **Yes** — already architected for it | Classifies the *shape* of text (malicious: true/false). The judgment isn't itself sensitive data, so sending text to a remote classifier is a normal network call, not a leak by definition. |
| `pii-guard` | **No — not even inside our own boundary** | Its job is to locate literal personal data. Shipping the raw text to *any* remote endpoint, including one we operate, defeats the point — and separately pulls grāmatr's own infra into GDPR Art. 4(2) "processing" scope for customer PII, with no materiality floor. |
| `secret-guard` | **No — not even inside our own boundary** | Same reasoning as pii-guard, for credential values instead of PII. The README is explicit: "sending a live credential value to any remote endpoint, even your own, defeats the tool's purpose." |

So "make this server-side" is really two different, independent
changes:

1. **injection-guard**: turning on its existing hosted-tier config
   (`INJECTION_GUARD_AUTH_TOKEN`, binding behind a real load balancer
   instead of loopback) is architecturally sound today. Its own
   `DATA_HANDLING.md` describes the zero-retention design — but that
   file says, in its own words, it is an *engineering design
   commitment, not yet a legal/compliance-reviewed policy*. Get that
   review before this is customer-facing, not after.

2. **secret-guard / pii-guard**: there is no compliant "just expose it"
   path. If this is seriously proposed later, the closest compliant
   shape consistent with both READMEs' own reasoning is **not a
   network-reachable service at all** — e.g. an in-process library call
   or a same-pod loopback-only sidecar per tenant, so raw text never
   crosses a network boundary even internally, and is never persisted.
   That is a different architecture from "add auth and expose the
   port," and it still needs a legal/DPA review before shipping,
   exactly as pii-guard's README says. Do not reuse injection-guard's
   hosted-tier pattern for these two and assume the reasoning carries
   over — it explicitly does not (see the README comparison above).

## What's still unconfirmed even for the injection-guard path

None of the three repos currently document (confirmed by reading all
three READMEs, not assumed):

- Whether request logging is disabled on the daemons.
- Whether scanned/classified text can leak into metrics or error
  traces (stack traces on a 500, access logs, etc.).
- Memory handling after a request completes (no explicit zeroing is
  implemented anywhere in the code read for this stack).

Treat these as open items to verify, not as already-guaranteed, before
any hosted deployment — including injection-guard's.

## If you do extend this file

- Add a `docker-compose.server.yml` **override** (not a change to the
  base file) so the default `docker compose up` here stays
  loopback-only, and server-side behavior is only ever opt-in via
  `docker compose -f docker-compose.yml -f docker-compose.server.yml up`.
- Scope any such override to `injection-guard` only, per the table
  above, unless a legal/DPA review has explicitly cleared a different
  architecture for secret-guard/pii-guard.
- Update the audit wiring too: a hosted tier changes who and what can
  trigger a secret, PII or injection audit event; the audit event contract
  belongs to whoever owns your audit trail, not to this repository.
