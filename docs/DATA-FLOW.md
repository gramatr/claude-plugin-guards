# What the guards read, send, keep and download

For someone deciding whether to install the guards: what leaves your machine, what is
kept, and what is downloaded. Every statement below names where it comes from, and what
was **not** verified is listed at the end. Checked on 2026-10-22 against plugin v0.2.10 and
guards-unified v0.2.10.

**Short answer.** The hooks send the text they scan to one address, `GUARDS_ENDPOINT`, which
is `http://127.0.0.1:8700` (your own machine) unless you change it. The service keeps a
log of verdicts, never the text. Things that do reach the internet are downloads and update
checks (container images, a model, the patched gitleaks, a plugin-update check), listed in
the first table. What this page cannot claim is that nothing else ever leaves the machine:
see [What was checked and what was not](#what-was-checked-and-what-was-not).

## What reaches the internet

| Destination | When | What goes out | Where it is set |
|---|---|---|---|
| `github.com`, a Git ref lookup of `gramatr/claude-plugin-guards` | At session start | An ordinary `git ls-remote` request, to tell you if the plugin is out of date. None of your text. | `guards/bin/guards-selfheal.sh` (plugin-update check) |
| `ghcr.io` (the guards-unified image) and Docker Hub (the Watchtower image) | At session start (`docker compose pull`), and by Watchtower every 5 minutes for the guards-unified tag | A registry pull request | `guards/bin/guards-selfheal.sh`, `guards/docker/docker-compose.yml` |
| `github.com` releases, the patched gitleaks | Only on a host with no Docker and no gitleaks | A file download. If the patched build is unavailable or fails its hash check, the upstream gitleaks release is downloaded instead, with a warning. | `guards/bin/guards-selfheal.sh` |
| Hugging Face, the injection model | When the container starts, using **your own** `HF_TOKEN` | Your token and requests for the model files, at a pinned revision | guards-unified `app/injection_guard/model.py`, `Dockerfile.cpu` (`HF_HOME`) |

Nothing in the table sends text from your session. The spaCy model for PII detection is
baked into the image at build time, not downloaded at run time (`Dockerfile.cpu`).

## What each hook reads, when it runs, and what it sends

The default address in every case is `GUARDS_ENDPOINT`, `http://127.0.0.1:8700`. If the
service is unreachable, each hook falls back to a local copy of the scanner and sends
nothing.

| Hook | Runs | Reads | Sends to the endpoint | Source |
|---|---|---|---|---|
| credfile-guard | Before `Read`, `Grep`, `Bash` | The tool's input; the first bytes of a readable file, to look for a private-key header (up to `CREDFILE_SNIFF_MAX_BYTES`, 10 MiB) | **Nothing.** It calls no network tool. | `hooks/credfile-guard.sh`; observed below |
| publish-guard | Before `Bash` commands that publish (`gh`, `git commit`, ...) | The command, files the command names, the staged diff | The text to scan, up to `PUBLISH_GUARD_MAX_BYTES` (512 KiB), as a secret-only request | `hooks/publish-guard.sh`, `hooks/secret-scan-lib.sh` |
| outbound-guard | Before `Bash` commands that run `curl`, `wget`, `ssh` and similar | The command text | The command text, as a secret-only request | `hooks/outbound-guard.sh` |
| sendmessage-guard | Before `SendMessage` | The `message`, `summary` and `content` fields | Each field up to `SCAN_MAX_BYTES` (24 KiB) | `hooks/sendmessage-guard.sh` |
| combined-hook | After `Bash` | The command's output (stdout and stderr) | The first `SECRET_MAX_BYTES` (256 KiB) as a secret-only request, and the first `FLAG_MAX_BYTES` (2 KiB) for the PII and injection notes | `hooks/combined-hook.sh` |
| mcp-output-guard | After an MCP tool call | The tool's result text | Up to `MCP_GUARD_MAX_BYTES` (512 KiB) | `hooks/mcp-output-guard.sh` |
| userpromptsubmit-guard | When you submit a prompt | Your prompt | Up to 900,000 bytes, as a secret-only request. It adds a note; it never blocks. | `hooks/userpromptsubmit-guard.sh` |
| MCP server (`guards_status`, `scan`, ...) | When the agent calls it | What the tool is given | The text of a scan call, to the endpoint; `guards_status` reads the endpoint's `/about` | `guards/mcp/server.py`, `guards/mcp/guards_tools.py` |
| self-heal | At session start | Docker state, the plugin cache, the endpoint's `/health` and `/about` on `127.0.0.1:8700` | See the first table | `guards/bin/guards-selfheal.sh` |

**Changing `GUARDS_ENDPOINT` moves where your text goes.** Observed: with it set to another
host, the output hook sent its request there. Point it only at a service you control.

## What the service keeps

- **A metrics log** on the bind mount `~/.local/share/gramatr-guards/metrics`: one JSON line
  per finding with a timestamp, the finding type, the verdict and a reason code. Never the
  scanned text (`app/main.py`, `_log_metric`). The directory is private to your user when your
  user id is 1000 (see `docs/CONFIGURATION.md`).
- **Container logs** (Python logging at INFO, plus the web server's request lines). None of the
  service's own log statements formats the scanned text: there are eleven, and they log startup
  messages, a model-override warning, a scan timing out or failing, an output being withheld, and
  the metrics write failing (`app/main.py`,
  `app/pii_guard/engine.py`, `app/injection_guard/model.py`).
- **The model cache** is inside the container (`HF_HOME=/app/.cache/huggingface`), not on a
  volume, so a recreated container, for example after an image update, downloads the model
  again.

## What the service and the image download

- The injection model (a gated Hugging Face model), at the revision `GET /about` reports, with
  your token, when the container starts.
- Nothing else at run time was observed. The Python packages, the spaCy model and gitleaks are
  fixed in the image at build time.

## What was checked and what was not

**Checked**
1. **The hooks, with the network tools replaced by recorders** (on 2026-10-22, one fabricated
   payload each, no real value): combined-hook, mcp-output-guard, sendmessage-guard,
   userpromptsubmit-guard, publish-guard and outbound-guard each tried to reach
   `http://127.0.0.1:8700` and nothing else; credfile-guard called no network tool. The tools
   replaced were `curl`, `wget`, `nc`, `ncat`, `ssh`, `scp`, `rsync`, `gh`, `docker` and the
   network commands of `git`. With `GUARDS_ENDPOINT` set to another host, the output hook sent
   its request to that host.
2. **The running v0.2.10 service, while it handled scans.** Twelve snapshots of its TCP
   connections over about 24 seconds, taken from inside the container while scans ran, showed only
   loopback and private-network (Docker bridge) peers, plus one connection to a public HTTPS
   address (behind Amazon CloudFront) that had already been closed by the far end
   (`CLOSE_WAIT`), was present in every snapshot including idle ones, and did not change
   while scans ran. It is consistent with a connection left over from loading the model at
   startup, which is the one thing the service is expected to download. No new public
   connection appeared during scanning.
3. **The metrics log record** is built from four fields, none of them text (`_log_metric`).

**Not verified, so not claimed**
- That **nothing else** leaves the machine. The service check is a set of connection
  snapshots, not a packet capture or a deny-by-default network. It cannot see UDP (so, DNS
  lookups) or a connection that opens and closes between snapshots.
- That the `huggingface_hub` library sends no usage telemetry. The image does not set
  `HF_HUB_DISABLE_TELEMETRY` or `HF_HUB_OFFLINE`. The model download request itself carries
  library versions in its user agent; I have not captured it.
- That no library error message ever echoes part of the scanned text into the container log.
  The service's own log statements do not format the text; a traceback from inside Presidio,
  spaCy or transformers has not been reviewed.
- Network behaviour of the plugin's MCP server (`guards/mcp`) beyond reading its code: it
  posts to and reads from `GUARDS_ENDPOINT` (`httpx`), and was not run under the recorders.
- Anything about a host where `GUARDS_ENDPOINT` points elsewhere, or where Docker, Watchtower
  or a proxy is configured differently from the plugin's compose file.

**To close the gap yourself**, run the service on a Docker network with no route out, or under
a packet capture, for a full session, and look at what leaves. A result from that would
replace the snapshot in item 2.

Related: [HOOKS.md](HOOKS.md), [CONFIGURATION.md](CONFIGURATION.md), and the server's
[THREAT-MODEL.md](https://github.com/gramatr/guards-unified/blob/main/docs/THREAT-MODEL.md) and
[VERIFY.md](https://github.com/gramatr/guards-unified/blob/main/docs/VERIFY.md).
