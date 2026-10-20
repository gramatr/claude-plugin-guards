# Safe forms for passing a credential to curl, wget and HTTPie

When a command has to send a credential, the safest place for the value is a
file, standard input or an environment variable, not the command text. This page
records, per form, what a real client does with it. Every row is proven by a case
in [`guards/tests/outbound-safeforms.test.sh`](../guards/tests/outbound-safeforms.test.sh),
which runs the real client against a localhost listener with a fabricated value
and asserts the result. The test fails if a row here stops being true, and it
fails if this table and the test's case ids drift apart.

Three things are checked for every form:

- **Arrives**: the value reached the listener, in the header or body named.
- **In argv**: whether the value is visible in the client's argument list while
  it runs (read from `/proc/<pid>/cmdline`). Anything in argv is visible to every
  process on the machine, so "yes" means the form keeps the value out of the
  *command text* but not out of the process list.
- **Verbose echo**: whether the client's own debug output (`curl -v`, `wget -d`,
  `http --verbose`) prints the value. A "yes" means do not run the command with
  that flag where its output is logged or shown.

In the command column, `$TOKEN` and `$USERPW` (`user:token`) are environment
variables the caller already has; `FILE` is a file with owner-only permissions.

## Verified forms

| Case id | Client | Form | Arrives | In argv | Verbose echo | Verdict |
|---|---|---|---|---|---|---|
| `curl-var-header` | curl | `-H "Authorization: Bearer $TOKEN"` | header | yes | yes | works; value visible in argv and with `-v` |
| `curl-oauth2-bearer` | curl | `--oauth2-bearer "$TOKEN"` | header | varies by curl version | yes | works; curl 7.81 leaves the value in argv, curl 8.5 blanks it after startup; visible with `-v` either way |
| `curl-u-userpw` | curl | `-u "$USERPW"` | header (Basic) | varies by curl version | yes | works; curl 7.81 leaves the value in argv, curl 8.5 blanks it after startup; visible with `-v` either way |
| `curl-K-file` | curl | `-K FILE` with `header = "Authorization: Bearer ..."` in it | header | no | yes | safe form |
| `curl-K-stdin` | curl | `-K - < FILE` | header | no | yes | safe form |
| `curl-curlrc` | curl | `CURL_HOME=DIR curl ...` with `DIR/.curlrc` | header | no | yes | safe form |
| `curl-netrc-file` | curl | `--netrc-file FILE` | header (Basic) | no | yes | safe form |
| `curl-H-at-file` | curl | `-H @FILE` (header lines from a file) | header | no | yes | safe form |
| `curl-cookie-file` | curl | `-b FILE` (cookie file) | header (Cookie) | no | yes | safe form |
| `curl-d-at-file` | curl | `-d @FILE` | body | no | no | safe form |
| `curl-stdin-body` | curl | `--data-binary @- < FILE` | body | no | no | safe form |
| `curl-T-file` | curl | `-T FILE` | body | no | no | safe form |
| `curl-F-file` | curl | `-F name=@FILE` | body | no | no | safe form |
| `curl-cmdsubst-header` | curl | `-H "Authorization: Bearer $(cat FILE)"` | header | yes | yes | NOT safe: the shell expands it before curl runs, so the value is in argv |
| `curl-data-raw-at` | curl | `--data-raw @FILE` | nowhere | no | no | does not read the file: it sends the literal text `@FILE` |
| `curl-8.3-unverified` | curl | `--json`, `--variable`, `--expand-*` | not verified here | not verified here | not verified here | curl 8.3 and later only; the test client is older, so these are skipped, not claimed |
| `wget-var-header` | wget | `--header="Authorization: Bearer $TOKEN"` | header | yes | yes | works; value visible in argv and with `-d` |
| `wget-user-password` | wget | `--user=NAME --password="$TOKEN"` | header (Basic, after a 401) | yes | yes | works; value visible in argv and with `-d` |
| `wget-config` | wget | `--config=FILE` with `header = Authorization: Bearer ...` | header | no | yes | safe form |
| `wget-wgetrc-env` | wget | `WGETRC=FILE wget ...` | header | no | yes | safe form |
| `wget-netrc` | wget | `.netrc` in `HOME` | header (Basic, after a 401) | no | yes | safe form; wget sends netrc credentials only after the server challenges |
| `wget-askpass` | wget | `--use-askpass=PROGRAM`, no `--user` | header (Basic, after a 401) | no | yes | safe form, if the program answers by prompt |
| `wget-askpass-single-secret` | wget | `--use-askpass=PROGRAM` where the program prints one answer | the secret is sent as the username | no | not asserted | NOT safe: fails (see below) |
| `wget-post-file` | wget | `--post-file=FILE` | body | no | no | safe form |
| `wget-body-file-stdin` | wget | `--method=POST --body-file=/dev/stdin < FILE` | body | no | no | safe form |
| `wget-load-cookies` | wget | `--load-cookies=FILE` | header (Cookie) | no | yes | safe form |
| `http-auth-header` | HTTPie | `http GET URL "Authorization:Bearer $TOKEN"` | header | yes | yes | works; value visible in argv and with `--verbose` |
| `http-a-userpw` | HTTPie | `http -a "$USERPW" GET URL` | header (Basic) | yes | yes | works; value visible in argv and with `--verbose` |
| `http-field-at-file` | HTTPie | `http POST URL name=@FILE` | body | no | yes | safe from argv; `--verbose` prints the request body |
| `http-stdin-file` | HTTPie | `http POST URL < FILE` | body | no | yes | safe from argv; `--verbose` prints the request body |
| `http-netrc` | HTTPie | `.netrc` in `HOME` | header (Basic) | no | yes | safe form |

## The wget askpass program must branch on the prompt

`wget --use-askpass=PROGRAM` runs `PROGRAM` once per question and passes the
prompt text as its first argument. With no `--user`, wget asks for the username
first and the password second. A program that prints the same single answer to
both, as `wget-askpass-single-secret` does, sends the secret as the username too
and the request never carries `user:secret`. `wget-askpass` uses a program that
answers a prompt containing `sername` with the user name and anything else with
the secret, and that one authenticates.

## Notes

- Verbose output echoes a credential placed in a header or cookie and, for
  curl and wget, does not echo a body read from a file. HTTPie's `--verbose`
  prints the request body too.
- The test records the client versions it ran against at the top of its output.
  A client that is not installed is reported as `SKIP`, never as a pass. HTTPie
  is optional.
- Where argv visibility is "varies by curl version", the test reports what it
  saw and asserts nothing: a client that blanks its own argv after startup still
  exposes the value for a moment, and the shell variable still has to hold it.
- The argv check reads `/proc` and runs on Linux only; elsewhere that single
  assertion is reported as `SKIP`.
- The test uses a throwaway `HOME` and fabricated values built at run time; no
  real credential file is read.
