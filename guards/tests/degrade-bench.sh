#!/usr/bin/env bash
# guards/tests/degrade-bench.sh — hook wall time and output under a degraded service.
#
# A measurement tool, not a test: it is not part of run-all.sh. It runs one hook from two plugin trees,
# A (the baseline) and B (the change), interleaved ABAB (the order flips each round so neither tree
# always goes first), N rounds per cell, against loopback stubs only (degrade-stub.py), and prints the
# median and 95th percentile of wall time in milliseconds per tree.
#
#   bash guards/tests/degrade-bench.sh [-n N] [-a ROOT_A] [-b ROOT_B] [-H HOOKS] [-s SCENARIOS]
#                                      [-E "VAR=val ..."] [-F] [-c]
#
#   -n N          rounds per cell (default 100)
#   -a ROOT_A     plugin root of the baseline, the directory holding hooks/ (default: this tree's guards/)
#   -b ROOT_B     plugin root of the change (default: the same as A, which measures the noise floor)
#   -H HOOKS      comma list from: bash message prompt mcp   (default: all four)
#   -s SCENARIOS  comma list from: up refused blackhole slow axiserr unavailable secerr http500 malformed
#                 (default: up,refused,blackhole,slow,axiserr)
#   -E "V=v ..."  extra environment for B only (an off switch, say)
#   -F            a fresh session id every round (measures first-call cost); default keeps one per tree
#   -M            before each cell, put a session-mode record of ANOTHER session in both state directories (the
#                 state of a machine where some session was told something in the last two days)
#   -c            also compare the stdout of A and B byte for byte, once per cell, with -E applied to B
#
# Cells: up = a stub that answers; refused = a closed loopback port; blackhole = the documentation address
# 192.0.2.1 (packets dropped, so only the connect timeout ends the wait); slow = a stub that sleeps 3 s;
# axiserr/unavailable/secerr/http500/malformed = a stub failing that way (see degrade-stub.py).
# Inputs are ordinary build-log text (not keyword dense), built at run time: nothing here is a credential.
# Needs: bash 5 (EPOCHREALTIME), jq, python3, curl.

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
N=100 ROOT_A="$HERE/.." ROOT_B="" HOOKS="bash,message,prompt,mcp" SCEN="up,refused,blackhole,slow,axiserr" EXTRA="" FRESH=0 CMP=0 SEED=0
while getopts "n:a:b:H:s:E:FcM" o; do
  case "$o" in
    n) N="$OPTARG" ;; a) ROOT_A="$OPTARG" ;; b) ROOT_B="$OPTARG" ;; H) HOOKS="$OPTARG" ;;
    s) SCEN="$OPTARG" ;; E) EXTRA="$OPTARG" ;; F) FRESH=1 ;; c) CMP=1 ;; M) SEED=1 ;;
    *) exit 2 ;;
  esac
done
[ -n "$ROOT_B" ] || ROOT_B="$ROOT_A"
[ -n "${EPOCHREALTIME:-}" ] || { echo "degrade-bench: needs bash 5 (EPOCHREALTIME)" >&2; exit 2; }

T="$(mktemp -d)"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null; rm -rf "$T"' EXIT
mkdir -p "$T/home"

# Ordinary text: 200 lines of build output, about 8 KB.
python3 -I - > "$T/ordinary.txt" <<'PY'
for i in range(200):
    print(f"[{i:03d}] compiled module core_{i % 17} in {0.1 + (i % 9) / 10:.2f}s, 0 warnings, cache hit")
PY
SMALL="$(head -c 400 "$T/ordinary.txt")"

start_stub() { # start_stub NAME MODE [DELAY]
  mkdir -p "$T/$1"
  python3 -I "$HERE/degrade-stub.py" "$T/$1" "$2" "${3:-0}" >/dev/null 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 50); do [ -s "$T/$1/port" ] && break; sleep 0.1; done
  echo "http://127.0.0.1:$(cat "$T/$1/port")"
}

endpoint_for() { # endpoint_for SCENARIO -> URL
  case "$1" in
    refused) echo "http://127.0.0.1:1" ;;
    blackhole) echo "http://192.0.2.1:8700" ;;
    up) start_stub up up ;;
    slow) start_stub slow slow 3 ;;
    axiserr|unavailable|secerr|http500|malformed) start_stub "$1" "$1" ;;
    *) echo "unknown scenario $1" >&2; exit 2 ;;
  esac
}

payload() { # payload HOOK SID
  case "$1" in
    bash) jq -nc --rawfile o "$T/ordinary.txt" --arg sid "$2" '{session_id:$sid, tool_name:"Bash", tool_input:{command:"make"}, tool_response:{stdout:$o, stderr:"", interrupted:false, isImage:false}}' ;;
    message) jq -nc --arg m "$SMALL" --arg sid "$2" '{session_id:$sid, tool_name:"SendMessage", tool_input:{to:"peer", message:$m, summary:"build status", content:"all modules compiled"}}' ;;
    prompt) jq -nc --arg p "$SMALL" --arg sid "$2" '{session_id:$sid, prompt:$p}' ;;
    mcp) jq -nc --rawfile o "$T/ordinary.txt" --arg sid "$2" '{session_id:$sid, tool_name:"mcp__bench__tool", tool_input:{}, tool_response:[{type:"text", text:$o}]}' ;;
  esac
}
script_for() {
  case "$1" in
    bash) echo combined-hook.sh ;; message) echo sendmessage-guard.sh ;;
    prompt) echo userpromptsubmit-guard.sh ;; mcp) echo mcp-output-guard.sh ;;
  esac
}

# run_one ROOT HOOK ENDPOINT SID STATEDIR [EXTRA_ENV] -> stdout of the hook; elapsed ms in $T/ms
run_one() {
  local root="$1" hook="$2" ep="$3" sid="$4" st="$5" extra="${6:-}" s e out
  s=$EPOCHREALTIME
  # shellcheck disable=SC2086  # EXTRA is a space-separated list of VAR=val words on purpose
  out="$(payload "$hook" "$sid" | env HOME="$T/home" GUARDS_STATE_DIR="$st" GUARDS_ENDPOINT="$ep" $extra bash "$root/hooks/$(script_for "$hook")" 2>/dev/null)"
  e=$EPOCHREALTIME
  awk -v s="$s" -v e="$e" 'BEGIN { printf "%.1f\n", (e - s) * 1000 }' > "$T/ms"
  printf '%s' "$out"
}

stats() { # stats FILE -> "median p95"
  python3 -I -c '
import sys
v = sorted(float(x) for x in open(sys.argv[1]) if x.strip())
if not v:
    print("n/a n/a")
else:
    print(f"{v[len(v) // 2]:7.1f} {v[min(len(v) - 1, int(len(v) * 0.95))]:7.1f}")
' "$1"
}

printf 'rounds=%s  A=%s  B=%s%s%s\n' "$N" "$ROOT_A" "$ROOT_B" "${EXTRA:+  B env: $EXTRA}" "$([ "$FRESH" = 1 ] && echo '  fresh session id each round')"
printf '%-8s %-12s %9s %9s %9s %9s  %s\n' hook scenario "A med" "A p95" "B med" "B p95" "stdout A vs B"
IFS=',' read -r -a HL <<< "$HOOKS"
IFS=',' read -r -a SL <<< "$SCEN"
for sc in "${SL[@]}"; do
  ep="$(endpoint_for "$sc")"
  for h in "${HL[@]}"; do
    : > "$T/a.ms"; : > "$T/b.ms"
    mkdir -p "$T/sta" "$T/stb"; rm -rf "${T:?}/sta/"* "${T:?}/stb/"*
    if [ "$SEED" = 1 ]; then
      for d in sta stb; do mkdir -p "$T/$d/mode"; printf 'full %s 1 0 0 0\n' "$(date +%s)" > "$T/$d/mode/some-other-session"; done
    fi
    # one unmeasured warm-up per tree (file cache, first fork)
    run_one "$ROOT_A" "$h" "$ep" warm "$T/sta" > /dev/null
    run_one "$ROOT_B" "$h" "$ep" warm "$T/stb" "$EXTRA" > /dev/null
    i=0
    while [ "$i" -lt "$N" ]; do
      sa="bench-a"; sb="bench-b"
      [ "$FRESH" = 1 ] && { sa="a$i"; sb="b$i"; }
      if [ $((i % 2)) -eq 0 ]; then
        run_one "$ROOT_A" "$h" "$ep" "$sa" "$T/sta" > /dev/null; cat "$T/ms" >> "$T/a.ms"
        run_one "$ROOT_B" "$h" "$ep" "$sb" "$T/stb" "$EXTRA" > /dev/null; cat "$T/ms" >> "$T/b.ms"
      else
        run_one "$ROOT_B" "$h" "$ep" "$sb" "$T/stb" "$EXTRA" > /dev/null; cat "$T/ms" >> "$T/b.ms"
        run_one "$ROOT_A" "$h" "$ep" "$sa" "$T/sta" > /dev/null; cat "$T/ms" >> "$T/a.ms"
      fi
      i=$((i + 1))
    done
    same="-"
    if [ "$CMP" = 1 ]; then
      rm -rf "${T:?}/sta/"* "${T:?}/stb/"*
      oa="$(run_one "$ROOT_A" "$h" "$ep" cmp "$T/sta")"; ob="$(run_one "$ROOT_B" "$h" "$ep" cmp "$T/stb" "$EXTRA")"
      [ "$oa" = "$ob" ] && same="identical" || same="DIFFERENT"
    fi
    # shellcheck disable=SC2046  # two words, split on purpose
    printf '%-8s %-12s %s %s  %s\n' "$h" "$sc" "$(stats "$T/a.ms")" "$(stats "$T/b.ms")" "$same"
  done
done
