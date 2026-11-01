# Degraded-service baseline: what each failure costs a hook today (2026-11-01)

Unit M0 of `docs/scope/service-degradation-2026-11-01.md` in guards-coordination (issues #93, #126, #127,
#128). It measures the release as it stands (plugin `4aed0a5`, VERSION 0.2.18) before any change to how the
hooks treat a failing service, so that each later change has a number to be compared with, and so that the
breaker (#127) is built only as far as the numbers justify. Nothing here touches a real service: every
cell runs against a loopback stub or an address that cannot answer. Shape only: no host, address, token or
account appears in this file.

## Method

`guards/tests/degrade-bench.sh` runs one hook from two plugin trees, **A** and **B**, interleaved ABAB (the
order flips every round), 100 rounds per cell, and reports the median and 95th percentile of wall time in
milliseconds. For this baseline A and B are **the same tree**, so the difference between the two columns is the
measurement noise of the machine, not an effect. Stubs are `guards/tests/degrade-stub.py`:

| Cell | What the hook talks to |
|---|---|
| up | a stub that answers every route with all axes clean |
| refused | a closed loopback port (`connection refused`, over in a fraction of a millisecond) |
| blackhole | the documentation address `192.0.2.1` (packets are dropped; only the connect timeout ends the wait) |
| slow | a stub that sleeps 3 s before answering |
| axiserr | a stub whose PII and injection axes answer `verdict: error` (no reason code) |
| secerr | a stub whose secret axis answers `verdict: error` (`SECRET_SCAN_TIMEOUT`) |

Inputs are ordinary build-log text built at run time (about 8 KB for the Bash and MCP hooks, 400 characters for
the message and prompt hooks), not keyword-dense, as the epic's process rule asks. The hooks ran with a throwaway
`HOME` and state directory. One session id per tree, so these are steady-state numbers, not first-call numbers.
The four hooks were measured concurrently (four processes) on a shared 28-core WSL2 machine with a load average
of 4 to 7, so the absolute numbers are higher than an idle machine would give; the A/A columns show how much that
matters.

Reproduce: `bash guards/tests/degrade-bench.sh -n 100 -H bash -s up,refused,blackhole,slow,axiserr,secerr`
(with `-a ROOT_A -b ROOT_B` to compare two trees, `-E "VAR=val"` to set an off switch for B only, `-c` to
compare the output of A and B byte for byte).

## Hook wall time, current release (ms; median, then 95th percentile)

Columns are the first copy of the tree (A) and the second copy (A'), which are identical.

| Hook | Cell | A median | A p95 | A' median | A' p95 |
|---|---|---:|---:|---:|---:|
| Bash output | up | 236.1 | 246.5 | 235.0 | 250.7 |
| | refused | 480.6 | 540.1 | 481.8 | 569.2 |
| | blackhole | 1458.6 | 1719.6 | 1459.9 | 1613.6 |
| | slow | 2445.4 | 2483.8 | 2443.8 | 2473.0 |
| | axiserr | 211.5 | 219.5 | 211.5 | 221.0 |
| | secerr | 497.8 | 520.6 | 497.8 | 533.5 |
| MCP result | up | 206.3 | 220.3 | 206.7 | 217.8 |
| | refused | 483.2 | 538.7 | 483.5 | 558.1 |
| | blackhole | 1462.0 | 1719.9 | 1460.7 | 1637.0 |
| | slow | 2441.2 | 2484.1 | 2446.2 | 2476.0 |
| | axiserr | 185.0 | 191.0 | 184.5 | 189.0 |
| | secerr | 468.0 | 489.7 | 467.5 | 492.2 |
| SendMessage | up | 314.8 | 334.3 | 313.0 | 336.0 |
| | refused | 1141.3 | 1336.9 | 1142.2 | 1328.8 |
| | blackhole | 3094.9 | 3224.4 | 3092.5 | 3535.1 |
| | slow | 4840.4 | 4923.5 | 4848.7 | 4959.6 |
| | axiserr | 288.0 | 294.9 | 287.6 | 294.9 |
| | secerr | 1084.8 | 1139.7 | 1088.3 | 1169.9 |
| Prompt | up | 61.3 | 65.4 | 61.3 | 64.9 |
| | refused | 40.2 | 94.6 | 40.3 | 126.9 |
| | blackhole | 3040.8 | 3051.1 | 3040.6 | 3052.6 |
| | slow | 3060.7 | 3065.6 | 3060.8 | 3068.0 |
| | axiserr | 57.8 | 60.5 | 57.5 | 61.7 |
| | secerr | 57.2 | 96.9 | 57.2 | 100.0 |

**Noise floor.** Across the 24 cells the medians of two identical trees differ by at most 5 ms (the largest:
MCP `slow`, 4.9 ms); the 95th percentiles by up to 32 ms on the cells where the hook returns in tens of
milliseconds and by up to 310 ms on the cells where it waits for seconds (one stalled run moves a p95). A later
change counts as a difference only where it exceeds these.

## What the numbers say

1. **A refused connection costs nothing in itself.** Every `refused` and `secerr` cell is the cost of the local
   scan that replaces the service (the vendored `scan.sh` with gitleaks: about 0.25 s plus start-up), not of the
   failed connection. The up path is 0.2 s because the service's secret route is faster than the local scan.
   Nothing a breaker could skip is left in these cells; skipping the connection attempt would save well under a
   millisecond.
2. **A blackholed address costs the whole connect timeout, on every call.** Bash and MCP: 1459 ms against 481
   for a refused port, so 978 ms is waiting (the 1 s connect timeout of the secret route). SendMessage: 3093 ms
   against 1142, so 1951 ms (its 2 s connect timeout). Prompt: 3041 ms against 40, so 3000 ms (its 3 s connect
   timeout), for a hook that then does nothing with the answer because it has no local fallback. This is the
   whole of what a breaker can save: 1, 2 and 3 seconds per call respectively.
3. **The SendMessage hook runs the local scan once per field.** With the service refused it takes 1.14 s for a
   message with three fields, against 0.48 s for the Bash hook: three local scans in series. This is not part of
   this work; it is recorded because it is the dominant cost of that hook whenever the service is not answering,
   whatever the failure.
4. **A slow service costs the full time limit, then the local scan.** Bash 2445 ms (the 2 s limit of the secret
   route plus 0.4 s), MCP 2441 ms, SendMessage 4840 ms (its 4 s budget plus local scans). The prompt hook, whose
   limit is 8 s, simply waited out the stub's 3 s and got its answer (3061 ms). A breaker must not trip on these:
   the service is there and answering, and a slow answer is not an outage.
5. **An axis that answers `error` costs the same as a healthy service** (axiserr is at or below `up`: 211, 185,
   288, 58 ms). Nothing in any hook looks at it today: the PII and injection verdicts `error` are read as clean,
   with no message.

## What the transcripts say (counts, no text)

Local Claude Code transcripts on one development machine (51 project directories), counting hook-notice
attachments by day and the number of distinct sessions each came from (in brackets). Only attachments of the
hook types were counted, and only the exact notice wordings of the hooks, so text in a transcript that merely
quotes a notice does not count. The script is in the pull request description; it prints counts and nothing
else.

| Day | Bash hook: fell back to local scan | Bash hook: secret axis did not answer / malformed | SendMessage: service "unreachable" | SendMessage: a field ran out of time | Output withheld (deadline) |
|---|---|---|---|---|---|
| 2026-10-18 | 1969 (145) | - | 36 (7) | - | - |
| 2026-10-19 | 394 (18) | 1 (1) | 40 (2) | - | - |
| 2026-10-20 | 43 (18) | 2 (2) | 8 (6) | 1 (1) | - |
| 2026-10-21 | 1 (1) | 1 (1) | 6 (2) | - | - |
| 2026-10-22 | - | - | 2 (1) | - | - |
| 2026-10-23 | - | - | 2 (1) | 2 (1) | - |
| 2026-10-25 | 1 (1) | - | 84 (28) | 62 (23) | - |
| 2026-10-26 | - | - | 46 (13) | 44 (11) | - |
| 2026-10-27 | - | - | 174 (26) | 92 (20) | - |
| 2026-10-28 | 1 (1) | 1 (1) | 187 (25) | 82 (13) | 6 (2) |
| 2026-10-29 | - | - | 154 (16) | 64 (11) | - |
| 2026-10-30 | - | - | 166 (17) | 142 (21) | 3 (1) |
| 2026-10-31 | - | - | 84 (13) | 38 (8) | - |
| Total | 2409 | 5 | 989 | 527 | 9 |

How to read it, and what it cannot say:

- 2026-10-18 to 10-20 are the days the fallback was being developed and tested; the Bash counts there are
  test runs, not outages. The Bash hook's default path (since then) falls back **silently**, with no line on
  stderr, so its absence from the later days says nothing about outages.
- From 2026-10-25 the SendMessage notices are daily: 46 to 187 per day in 13 to 28 sessions, with a "field ran out
  of time" notice for roughly every two of them. A field running out of time means the service **answered
  the first field**, so for those sessions it was up and slow (the hook's 4 s budget is shared by three fields,
  and the full scan costs about 0.25 s per KB). The notices worded "unreachable" are not necessarily
  outages: the hook words every failure of its first field that way, and a field that outran the 4 s budget
  looks exactly like a connection that failed. This is the conflation named in #128 and #127, and it is why
  those two issues cannot be separated from each other by reading the transcripts. **The transcripts cannot say
  how often the service is blackholed.** Nothing in them records the failure class.
- The 9 "withheld" lines are the 10 s deadline firing (three sessions, 2026-10-28 and 10-30), not a service state.

## Consequence for the breaker (#127, unit B1)

The breaker saves nothing for refused connections and unresolvable names, and 1 to 3 seconds per call for a
blackholed or half-open address (table above, point 2). It must not trip on a slow answer (point 4), an error
status or a malformed body. Whether a blackholed address ever happens in the field is not known and cannot be
learned from these transcripts. The design therefore builds the breaker narrowly: it records a failure as
`slow` only when the attempt itself took half a second or more at the connection stage, and trips only on that.
A refused port, which is the common outage, never trips it, so the common case gains no code path and no risk;
the blackholed case, when it comes, stops costing 1 to 3 seconds per call. The measured effect of the built
breaker is in its own pull request.
