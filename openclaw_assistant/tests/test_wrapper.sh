#!/usr/bin/env bash
# Shell tests for the add-on (not copied into the image):
#   1. openclaw-wrapper.sh: the allow/deny matrix (update refusal, writing
#      doctor refusal, HOLD allow-list, OC_ADDON_UNSAFE escape), run against a
#      fake `node` that echoes the argv it was exec'd with.
#   2. run.sh's migration-gate wait/trap pattern (early_stop, run_migration_gate
#      and enter_hold, extracted verbatim from run.sh) against a fake
#      `oc-upgrade` that sleeps, records a forwarded SIGTERM and exits with a
#      chosen status.
#   3. run.sh's `gate --plan` block (timeout -> HOLD, plan lines handed to the
#      gate run so they are not printed twice; contract addendum 2 item 11).
#   4. run.sh's shutdown(): the one-time "still stopping after 60 s" warning and
#      the SIGKILL at 270 s (addendum 2 item 12), with `sleep 1` sped up.
#
# Usage: bash openclaw_assistant/tests/test_wrapper.sh     (exit 0 = all passed)
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADDON_DIR="$(cd "${HERE}/.." && pwd)"
WRAPPER_SRC="${ADDON_DIR}/openclaw-wrapper.sh"
RUN_SH="${ADDON_DIR}/run.sh"

T="$(mktemp -d "${TMPDIR:-/tmp}/oc-shell-test.XXXXXX")"
trap 'rm -rf "$T"' EXIT

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); }
fail() { FAIL=$((FAIL + 1)); echo "FAIL: $*" >&2; }
# check DESCRIPTION COMMAND...: pass when the command succeeds.
check() {
  local desc="$1"
  shift
  if "$@"; then pass; else fail "$desc"; fi
}

# ------------------------------------------------------------------------------
# 1. Wrapper
# ------------------------------------------------------------------------------
mkdir -p "$T/oc-addon" "$T/pkg" "$T/bin" "$T/fakebin" "$T/brewbin" "$T/upg"
cp "$WRAPPER_SRC" "$T/oc-addon/openclaw"
chmod +x "$T/oc-addon/openclaw"
ENTRY="$T/pkg/openclaw.mjs"
: > "$ENTRY"
printf '%s\n' "$ENTRY" > "$T/oc-addon/openclaw-entry"
printf '2026.9.9\n' > "$T/oc-addon/openclaw-pinned-version"
# Called through a symlink, like /usr/bin/openclaw in the image.
ln -s "$T/oc-addon/openclaw" "$T/bin/openclaw"
cat > "$T/fakebin/node" <<'EOF'
#!/bin/sh
# Fake node: print the argv it was exec'd with, one [arg] per argument.
printf 'EXEC'
for a in "$@"; do printf ' [%s]' "$a"; done
printf '\n'
exit 0
EOF
chmod +x "$T/fakebin/node"
# The image's Node, recorded at build time (Dockerfile: openclaw-node).
printf '%s\n' "$T/fakebin/node" > "$T/oc-addon/openclaw-node"
# A Homebrew node that comes first on PATH (run.sh puts linuxbrew/bin early).
printf '#!/bin/sh\necho BREW-NODE "$@"\n' > "$T/brewbin/node"
chmod +x "$T/brewbin/node"

OC="$T/bin/openclaw"
HOLD_FILE="$T/upg/hold.txt"
EXTRA_ENV=()

# Run the wrapper with a controlled environment; sets OUT, ERR, RC and
# DIR_WARNED (the OC_UPGRADE_DIR override warning, which is not part of ERR:
# every test points OC_UPGRADE_DIR at its own HOLD directory).
DIR_WARNING="— add-on safety checks bypassed (HOLD marker not read from /config/.openclaw-upgrade)"
invoke() {
  OUT="$(env -u OC_ADDON_UNSAFE PATH="$T/brewbin:/usr/bin:/bin" OC_UPGRADE_DIR="$T/upg" \
           ${EXTRA_ENV[@]+"${EXTRA_ENV[@]}"} "$OC" "$@" 2>"$T/stderr")"
  RC=$?
  ERR="$(grep -vF -- "$DIR_WARNING" "$T/stderr" || true)"
  if grep -qF -- "$DIR_WARNING" "$T/stderr"; then DIR_WARNED=true; else DIR_WARNED=false; fi
}

expected_exec() {
  local line="EXEC [${ENTRY}]" a
  for a in "$@"; do line="${line} [${a}]"; done
  printf '%s' "$line"
}

describe() { printf '%s openclaw %s' "${EXTRA_ENV[*]:-}" "$*"; }

# The command is exec'd unchanged (argv preserved), with no wrapper output.
allow() {
  invoke "$@"
  if [ "$RC" -eq 0 ] && [ "$OUT" = "$(expected_exec "$@")" ] && [ -z "$ERR" ]; then
    pass
  else
    fail "expected allow: $(describe "$@") -> rc=$RC out='$OUT' err='$ERR'"
  fi
}

# Allowed through OC_ADDON_UNSAFE=1: exec'd unchanged, with the bypass warning.
allow_unsafe() {
  invoke "$@"
  if [ "$RC" -eq 0 ] && [ "$OUT" = "$(expected_exec "$@")" ] && \
     [[ "$ERR" == *"OC_ADDON_UNSAFE=1"*"bypassed"* ]]; then
    pass
  else
    fail "expected unsafe allow: $(describe "$@") -> rc=$RC out='$OUT' err='$ERR'"
  fi
}

# Refused with exit 2, nothing exec'd, and stderr containing $1.
deny() {
  local needle="$1"
  shift
  invoke "$@"
  if [ "$RC" -eq 2 ] && [ -z "$OUT" ] && [[ "$ERR" == *"$needle"* ]]; then
    pass
  else
    fail "expected deny ($needle): $(describe "$@") -> rc=$RC out='$OUT' err='$ERR'"
  fi
}
DOCTOR_MSG="oc-upgrade retry --doctor"
HOLD_MSG="the add-on is holding OpenClaw"
UPDATE_MSG="openclaw update is disabled"

# --- normal operation (no hold.txt), pinned 2026.9.9 --------------------------
rm -f "$HOLD_FILE"
allow --version
allow -V
allow status
allow gateway run
allow plugins install "npm:@openclaw/brave-plugin@2026.9.9" --pin --force --accept-capabilities
allow config set gateway.port 18790
allow config get "a b" "c'd"
allow agents add work --non-interactive
allow doctor --lint
allow doctor --lint --json
allow doctor --lint --json --all --severity-min info
allow doctor --json
allow doctor --post-upgrade
allow doctor --help
allow doctor -h
allow --dev doctor --lint
allow --profile p doctor --lint
allow --log-level debug doctor --json
allow -- doctor --lint
allow help doctor
deny "$DOCTOR_MSG" doctor
deny "$DOCTOR_MSG" doctor --non-interactive
deny "$DOCTOR_MSG" doctor --fix
deny "$DOCTOR_MSG" doctor --fix --non-interactive
deny "$DOCTOR_MSG" doctor --repair
deny "$DOCTOR_MSG" doctor --lint --fix
deny "$DOCTOR_MSG" doctor --json --yes
deny "$DOCTOR_MSG" doctor --help --force
deny "$DOCTOR_MSG" doctor --lint --generate-gateway-token
deny "$DOCTOR_MSG" doctor --lint --allow-exec
deny "$DOCTOR_MSG" doctor --lint --state-sqlite
deny "$DOCTOR_MSG" doctor --lint --state-sqlite=/tmp/x.sqlite
deny "$DOCTOR_MSG" doctor --json --session-sqlite
deny "$DOCTOR_MSG" doctor --json --session-sqlite-store=x
deny "$DOCTOR_MSG" doctor --json --session-sqlite-agent main
deny "$DOCTOR_MSG" doctor --json --session-sqlite-all-agents
deny "$DOCTOR_MSG" doctor -- --lint
deny "$DOCTOR_MSG" --profile p doctor
deny "$DOCTOR_MSG" -- doctor
deny "$DOCTOR_MSG" --dev doctor --non-interactive
deny "$UPDATE_MSG" update
deny "$UPDATE_MSG" update --help
deny "$UPDATE_MSG" --update
deny "$UPDATE_MSG" --dev --update
# OpenClaw rewrites `--update` only in the root-option position; after a command
# word it is that command's (unknown) option, not the update command.
allow gateway --update
EXTRA_ENV=(OC_ADDON_UNSAFE=1)
allow_unsafe doctor --help
allow_unsafe doctor --fix --non-interactive
allow_unsafe agents add work --non-interactive
deny "$UPDATE_MSG" update
EXTRA_ENV=(OC_ADDON_UNSAFE=0)
deny "$DOCTOR_MSG" doctor
EXTRA_ENV=()

# --- HOLD (hold.txt present in OC_UPGRADE_DIR) ---------------------------------
printf 'OpenClaw is held (test)\n' > "$HOLD_FILE"
allow --version
allow -V
allow -v
allow --help
allow --no-color --version
allow help
allow help doctor
allow doctor --lint
allow doctor --lint --json
allow doctor --json
allow doctor --post-upgrade
allow doctor --help
allow config validate
allow config validate --json
allow config get gateway.port
allow config file
allow config schema
allow config --help
allow database preflight
allow database preflight-agent main
allow database --help
allow logs
allow logs --follow
deny "$HOLD_MSG"
deny "$HOLD_MSG" --dev
deny "$HOLD_MSG" status
deny "$HOLD_MSG" gateway run
deny "$HOLD_MSG" node run --host h --port 1
deny "$HOLD_MSG" plugins install x
deny "$HOLD_MSG" plugins list
deny "$HOLD_MSG" agents add work --non-interactive
deny "$HOLD_MSG" onboard
deny "$HOLD_MSG" configure
deny "$HOLD_MSG" config
deny "$HOLD_MSG" config set gateway.port 1
deny "$HOLD_MSG" config unset gateway.port
deny "$HOLD_MSG" database
deny "$HOLD_MSG" database migrate
deny "$HOLD_MSG" doctor
deny "$HOLD_MSG" doctor --fix
deny "$HOLD_MSG" doctor --lint --fix
deny "$HOLD_MSG" doctor -- --lint
deny "$UPDATE_MSG" update
EXTRA_ENV=(OC_ADDON_UNSAFE=1)
allow_unsafe status
allow_unsafe doctor --fix
allow_unsafe agents add work --non-interactive
deny "$UPDATE_MSG" update
EXTRA_ENV=()
# The HOLD marker location follows OC_UPGRADE_DIR: another dir has no hold.
EXTRA_ENV=(OC_UPGRADE_DIR="$T/other-upg")
allow status
EXTRA_ENV=()

# --- OpenClaw 2026.7.x pinned: old doctor behaviour, HOLD still applies -------
printf '2026.7.1-2\n' > "$T/oc-addon/openclaw-pinned-version"
rm -f "$HOLD_FILE"
allow doctor --fix --non-interactive
allow doctor
printf 'held\n' > "$HOLD_FILE"
deny "$HOLD_MSG" doctor --fix
deny "$HOLD_MSG" status
allow doctor --lint
rm -f "$HOLD_FILE"

# --- unknown pinned version: fail closed (doctor rule applies) ----------------
rm -f "$T/oc-addon/openclaw-pinned-version"
deny "$DOCTOR_MSG" doctor --fix
printf 'garbage\n' > "$T/oc-addon/openclaw-pinned-version"
deny "$DOCTOR_MSG" doctor --fix
printf '2026.9.9\n' > "$T/oc-addon/openclaw-pinned-version"

# --- the image's Node, never a Homebrew node first on PATH (F8) ---------------
# invoke puts $T/brewbin first on PATH: every allow() above already proved that
# the recorded node ran. Without a usable record, PATH is the fallback.
invoke status
check "node: recorded image node not used (out='$OUT')" [ "$OUT" = "$(expected_exec status)" ]
printf '%s\n' "$T/missing/node" > "$T/oc-addon/openclaw-node"
invoke status
check "node: stale record did not fall back to PATH (out='$OUT')" [ "$OUT" = "BREW-NODE $ENTRY status" ]
rm -f "$T/oc-addon/openclaw-node"
EXTRA_ENV=(PATH="$T/fakebin:/usr/bin:/bin")
allow status
EXTRA_ENV=()
printf '%s\n' "$T/fakebin/node" > "$T/oc-addon/openclaw-node"

# --- OC_UPGRADE_DIR override: warned like OC_ADDON_UNSAFE (F14) ---------------
invoke status
check "upgrade dir: override not warned (err='$(cat "$T/stderr")')" [ "$DIR_WARNED" = "true" ]
check "upgrade dir: warning lacks the directory" grep -qF "openclaw: OC_UPGRADE_DIR=$T/upg $DIR_WARNING" "$T/stderr"
for d in /config/.openclaw-upgrade /config/.openclaw-upgrade/; do
  EXTRA_ENV=(OC_UPGRADE_DIR="$d")
  allow status
  check "upgrade dir: default $d warned" [ "$DIR_WARNED" = "false" ]
done
EXTRA_ENV=(OC_UPGRADE_DIR=)
allow status
check "upgrade dir: empty value warned" [ "$DIR_WARNED" = "false" ]
EXTRA_ENV=(OC_ADDON_UNSAFE=1)
allow_unsafe status
check "upgrade dir: warned twice with OC_ADDON_UNSAFE=1" [ "$DIR_WARNED" = "false" ]
EXTRA_ENV=()
printf 'held\n' > "$HOLD_FILE"
deny "$HOLD_MSG" status
check "upgrade dir: no warning in HOLD" [ "$DIR_WARNED" = "true" ]
rm -f "$HOLD_FILE"

# --- broken install: entry missing -> 127 -------------------------------------
mv "$ENTRY" "$ENTRY.away"
invoke --version
if [ "$RC" -eq 127 ] && [[ "$ERR" == *"package entry not found"* ]]; then pass; else
  fail "missing entry: rc=$RC err='$ERR'"; fi
mv "$ENTRY.away" "$ENTRY"

WRAPPER_PASS=$PASS
WRAPPER_FAIL=$FAIL

# ------------------------------------------------------------------------------
# 2. run.sh migration-gate wait/trap pattern (R-6, critique B16/B17)
# ------------------------------------------------------------------------------
extract_function() {  # $1 = function name; prints its definition from run.sh
  awk -v name="$1" '
    $0 ~ "^" name "\\(\\) \\{$" { on = 1 }
    on { print }
    on && /^}$/ { exit }
  ' "$RUN_SH"
}
for fn in early_stop enter_hold run_migration_gate; do
  if [ -z "$(extract_function "$fn")" ]; then
    fail "run.sh has no top-level function ${fn}()"
  fi
done

mkdir -p "$T/gate/bin"
{
  cat <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
UPG_DIR="$1"
OPENCLAW_RUNTIME_VERSION="2026.9.9"
GATE_PID=""
GATE_WAIT_INTERRUPTED=false
SHUTTING_DOWN="false"
STATE_HOLD=false
STATE_HOLD_REASON=""
GATE_PLAN_OUT="${TEST_GATE_PLAN_OUT:-}"
EOF
  extract_function early_stop
  echo 'trap early_stop INT TERM'
  extract_function enter_hold
  extract_function run_migration_gate
  cat <<'EOF'
run_migration_gate
echo "RESULT STATE_HOLD=${STATE_HOLD} SHUTTING_DOWN=${SHUTTING_DOWN}"
if [ "$SHUTTING_DOWN" = "true" ]; then echo "INFO: Stop requested during startup; exiting."; exit 0; fi
EOF
} > "$T/gate/runner.sh"

# Fake `oc-upgrade gate`: records its start, env and a forwarded SIGTERM, then
# exits FAKE_RC after FAKE_SLEEP seconds (or at once on TERM with
# FAKE_EXIT_ON_TERM=1). FAKE_WRITE_HOLD=1 writes hold.txt first.
cat > "$T/gate/bin/oc-upgrade" <<'EOF'
#!/usr/bin/env bash
d="$FAKE_DIR"
echo "$$ $* FROM_RUNSH=${OC_GATE_FROM_RUNSH:-}" > "$d/started"
printf '%s' "${OC_GATE_PLAN_SHOWN:-}" > "$d/plan_shown"
on_term() {
  echo TERM >> "$d/got_term"
  if [ "${FAKE_EXIT_ON_TERM:-0}" = "1" ]; then exit "${FAKE_RC:-7}"; fi
}
trap on_term TERM
end=$((SECONDS + ${FAKE_SLEEP:-2}))
while [ "$SECONDS" -lt "$end" ]; do sleep 0.1; done
if [ "${FAKE_WRITE_HOLD:-0}" = "1" ]; then
  printf 'OpenClaw is held — migration gate run test, phase doctor1\nReason [doctor-failed]: fake\n' > "$OC_UPGRADE_DIR_FOR_FAKE/hold.txt"
fi
exit "${FAKE_RC:-7}"
EOF
chmod +x "$T/gate/bin/oc-upgrade"

# gate_case NAME SIGNALS(n TERMs to send) EXPECT_LOG_SUBSTRING [VAR=VALUE ...]
gate_case() {
  local name="$1" signals="$2" expect="$3" i pid rc
  shift 3
  local d="$T/gate/$name"
  rm -rf "$d"
  mkdir -p "$d/upg"
  if [ -n "${STALE_HOLD:-}" ]; then printf 'stale reason from an earlier run\n' > "$d/upg/hold.txt"; fi
  env PATH="$T/gate/bin:$PATH" FAKE_DIR="$d" OC_UPGRADE_DIR_FOR_FAKE="$d/upg" "$@" \
    bash "$T/gate/runner.sh" "$d/upg" > "$d/log" 2>&1 &
  pid=$!
  for _ in $(seq 1 100); do [ -s "$d/started" ] && break; sleep 0.05; done
  if [ ! -s "$d/started" ]; then
    fail "gate[$name]: fake gate did not start"
  fi
  for ((i = 0; i < signals; i++)); do
    sleep 0.3
    kill -TERM "$pid" 2>/dev/null || true
  done
  rc=0
  wait "$pid" || rc=$?
  if [ "$rc" -ne 0 ]; then fail "gate[$name]: runner exited $rc"; fi
  if ! grep -q "^[0-9]* gate FROM_RUNSH=1$" "$d/started" 2>/dev/null; then
    fail "gate[$name]: not started as 'OC_GATE_FROM_RUNSH=1 oc-upgrade gate': $(cat "$d/started" 2>/dev/null)"
  fi
  if [ "$signals" -gt 0 ]; then
    if [ "$(grep -c TERM "$d/got_term" 2>/dev/null || echo 0)" -lt 1 ]; then
      fail "gate[$name]: SIGTERM was not forwarded to the gate"
    fi
  elif [ -e "$d/got_term" ]; then
    fail "gate[$name]: gate got an unexpected SIGTERM"
  fi
  if grep -qF -- "$expect" "$d/log"; then
    pass
  else
    fail "gate[$name]: log lacks '$expect':"
    sed 's/^/    | /' "$d/log" >&2
  fi
  if grep -q "not a child" "$d/log"; then
    fail "gate[$name]: wait reported 'not a child'"
  fi
  GATE_CASE_DIR="$d"
}

# TERM mid-run: forwarded, the gate finishes on its own and exits 7; the real
# status (not the 143 of the interrupted wait) is observed.
gate_case term-then-7 1 "stopped (exit 7)" FAKE_SLEEP=2 FAKE_RC=7
check "term-then-7: unexpected result" grep -q "RESULT STATE_HOLD=false SHUTTING_DOWN=true" "$GATE_CASE_DIR/log"
check "term-then-7: no early exit" grep -q "Stop requested during startup; exiting." "$GATE_CASE_DIR/log"
# Two TERMs while the gate is still running: both forwarded, real status kept.
gate_case two-terms 2 "stopped (exit 7)" FAKE_SLEEP=2 FAKE_RC=7
check "two-terms: expected 2 forwarded TERMs" [ "$(grep -c TERM "$GATE_CASE_DIR/got_term")" -eq 2 ]
# The gate exits at once on TERM (status collected right after the trap).
gate_case exit-on-term 1 "stopped (exit 7)" FAKE_SLEEP=5 FAKE_RC=7 FAKE_EXIT_ON_TERM=1
# The gate's own interrupted status 143 is kept (not replaced by 127).
gate_case exit-143 1 "stopped (exit 143)" FAKE_SLEEP=5 FAKE_RC=143 FAKE_EXIT_ON_TERM=1
# No signal, success: no HOLD.
gate_case ok 0 "RESULT STATE_HOLD=false SHUTTING_DOWN=false" FAKE_SLEEP=0 FAKE_RC=0
check "ok: OC_GATE_PLAN_SHOWN set without a plan" [ ! -s "$GATE_CASE_DIR/plan_shown" ]
# The plan lines run.sh printed are handed to the gate run (it does not repeat them).
gate_case plan-shown 0 "RESULT STATE_HOLD=false" FAKE_SLEEP=0 FAKE_RC=0 \
  TEST_GATE_PLAN_OUT=$'[gate] plan: runtime=2026.9.9 -> gate run mode=from-7x\nWARN [gate] w'
check "plan-shown: plan line not passed to the gate" \
  grep -qxF "[gate] plan: runtime=2026.9.9 -> gate run mode=from-7x" "$GATE_CASE_DIR/plan_shown"
check "plan-shown: WARN line not passed to the gate" grep -qxF "WARN [gate] w" "$GATE_CASE_DIR/plan_shown"
# No signal, gate HOLD (exit 20 with hold.txt): enter_hold keeps the gate's text.
gate_case hold-20 0 "ERROR: Reason [doctor-failed]: fake" FAKE_SLEEP=0 FAKE_RC=20 FAKE_WRITE_HOLD=1
check "hold-20: STATE_HOLD not set" grep -q "RESULT STATE_HOLD=true" "$GATE_CASE_DIR/log"
check "hold-20: hold.txt overwritten" grep -q "Reason \[doctor-failed\]: fake" "$GATE_CASE_DIR/upg/hold.txt"
# A stale hold.txt is removed before the gate starts (B16): an internal error
# without a fresh hold.txt gets run.sh's own reason, never the stale one.
STALE_HOLD=1 gate_case stale-hold 0 "failed unexpectedly (exit 1)" FAKE_SLEEP=0 FAKE_RC=1
if grep -q "stale reason" "$GATE_CASE_DIR/log" "$GATE_CASE_DIR/upg/hold.txt"; then
  fail "stale-hold: stale hold.txt reused"
else
  pass
fi
check "stale-hold: run.sh did not write hold.txt" grep -q "failed unexpectedly (exit 1)" "$GATE_CASE_DIR/upg/hold.txt"

# ------------------------------------------------------------------------------
# 3. run.sh `gate --plan` block: timeout -> HOLD, plan output kept for the gate
# ------------------------------------------------------------------------------
plan_block="$(awk '/^GATE_NEEDED=false$/ { on = 1 } on { print } on && /^fi$/ { exit }' "$RUN_SH")"
if ! printf '%s\n' "$plan_block" | grep -q 'timeout --kill-after=30 600 oc-upgrade gate --plan'; then
  fail "run.sh: gate --plan is not wrapped in 'timeout --kill-after=30 600'"
fi
mkdir -p "$T/plan/bin"
{
  cat <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
UPG_DIR="$1"
OPENCLAW_RUNTIME_VERSION="2026.9.9"
STATE_HOLD=false
STATE_HOLD_REASON=""
STATE_NEWER=false
SHUTTING_DOWN=false
GATE_PID=""
runtime_at_least() { return 0; }
EOF
  extract_function early_stop
  echo 'trap early_stop INT TERM'
  extract_function enter_hold
  # the real 600 s / 30 s budget, shortened for the test (PLAN_TIMEOUT, default 1 s)
  printf '%s\n' "$plan_block" | sed 's/timeout --kill-after=30 600 /timeout --kill-after=1 "${PLAN_TIMEOUT:-1}" /'
  echo 'echo "RESULT STATE_HOLD=${STATE_HOLD} GATE_NEEDED=${GATE_NEEDED} PLAN_OUT=${GATE_PLAN_OUT}"'
} > "$T/plan/runner.sh"
cat > "$T/plan/bin/oc-upgrade" <<'EOF'
#!/usr/bin/env bash
if [ "${FAKE_IGNORE_TERM:-0}" = "1" ]; then trap '' TERM; fi
end=$((SECONDS + ${FAKE_SLEEP:-0}))
while [ "$SECONDS" -lt "$end" ]; do sleep 0.1; done
echo "[gate] plan: fake $* -> gate run"
exit "${FAKE_RC:-0}"
EOF
chmod +x "$T/plan/bin/oc-upgrade"

plan_case() {  # plan_case NAME EXPECT_LOG_SUBSTRING [VAR=VALUE ...]
  local name="$1" expect="$2"
  shift 2
  local d="$T/plan/$name"
  rm -rf "$d"
  mkdir -p "$d/upg"
  env PATH="$T/plan/bin:$PATH" "$@" bash "$T/plan/runner.sh" "$d/upg" > "$d/log" 2>&1 || true
  if grep -qF -- "$expect" "$d/log"; then
    pass
  else
    fail "plan[$name]: log lacks '$expect':"
    sed 's/^/    | /' "$d/log" >&2
  fi
  PLAN_CASE_DIR="$d"
}
plan_case timeout "planning timed out" FAKE_SLEEP=5
check "plan timeout: no HOLD" grep -q "RESULT STATE_HOLD=true GATE_NEEDED=false" "$PLAN_CASE_DIR/log"
check "plan timeout: hold.txt" grep -q "planning timed out" "$PLAN_CASE_DIR/upg/hold.txt"
plan_case timeout-kill "planning timed out" FAKE_SLEEP=5 FAKE_IGNORE_TERM=1
plan_case gate-needed "RESULT STATE_HOLD=false GATE_NEEDED=true PLAN_OUT=[gate] plan: fake gate --plan -> gate run" \
  FAKE_RC=10
check "plan 10: plan line not printed exactly once" [ "$(grep -c '^\[gate\] plan:' "$PLAN_CASE_DIR/log")" -eq 1 ]
plan_case no-gate "RESULT STATE_HOLD=false GATE_NEEDED=false PLAN_OUT=" FAKE_RC=0
# A stop during a slow plan is honoured at once (PID 1 must not sit in a foreground command).
d="$T/plan/term"; rm -rf "$d"; mkdir -p "$d/upg"
env PATH="$T/plan/bin:$PATH" FAKE_SLEEP=30 PLAN_TIMEOUT=60 bash "$T/plan/runner.sh" "$d/upg" > "$d/log" 2>&1 &
runner=$!
sleep 1
start=$SECONDS
kill -TERM "$runner"
wait "$runner" 2>/dev/null || true
check "plan TERM: runner exits within 5 s" [ $((SECONDS - start)) -le 5 ]
check "plan TERM: stop reported" grep -q "Stop requested during migration planning" "$d/log"
check "plan TERM: TERM forwarded to the planner" grep -q "forwarding SIGTERM" "$d/log"
check "plan TERM: no HOLD" bash -c '! grep -q "RESULT STATE_HOLD=true" "$1"' _ "$d/log"

# ------------------------------------------------------------------------------
# 4. run.sh shutdown(): one WARN after 60 s, SIGKILL at 270 s (sleep sped up)
# ------------------------------------------------------------------------------
if [ -z "$(extract_function shutdown)" ]; then
  fail "run.sh has no top-level function shutdown()"
fi
mkdir -p "$T/stop"
{
  cat <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
HEALTH_PID=""
NGINX_PID=""
TTYD_PID=""
CLEAN_LOCKS_ON_EXIT=false
STATE_HOLD=false
SHUTTING_DOWN=false
find_gateway_daemon_pid() { return 1; }
stop_gw_relay() { :; }
cleanup_session_locks() { :; }
if [ "${STUBBORN:-0}" = "1" ]; then
  bash -c 'trap "" TERM; while :; do sleep 0.05; done' &
else
  bash -c 'trap "exit 0" TERM; while :; do sleep 0.05; done' &
fi
GW_PID=$!
sleep 0.2
EOF
  extract_function shutdown | sed 's/^\([[:space:]]*\)sleep 1$/\1sleep 0.01/'
  echo 'shutdown'
  echo 'echo "RESULT stopped"'
} > "$T/stop/runner.sh"
env STUBBORN=1 bash "$T/stop/runner.sh" > "$T/stop/stubborn.log" 2>&1 || true
check "shutdown: 60 s warning missing" \
  grep -qxF "WARN: gateway still stopping after 60 s (OpenClaw 2026.9+ waits for plugin cleanup; up to 270 s)" "$T/stop/stubborn.log"
check "shutdown: 60 s warning not printed exactly once" \
  [ "$(grep -c 'still stopping after 60 s' "$T/stop/stubborn.log")" -eq 1 ]
check "shutdown: no SIGKILL at 270 s" grep -q "did not stop within 270 s; sending SIGKILL" "$T/stop/stubborn.log"
check "shutdown: stubborn run did not finish" grep -q "RESULT stopped" "$T/stop/stubborn.log"
env STUBBORN=0 bash "$T/stop/runner.sh" > "$T/stop/quick.log" 2>&1 || true
check "shutdown: quick stop warned" bash -c "! grep -q 'still stopping' '$T/stop/quick.log'"
check "shutdown: quick stop did not finish" grep -q "RESULT stopped" "$T/stop/quick.log"

# ------------------------------------------------------------------------------
# 5. run.sh main loop: a stop request during the crash-restart window (daemon
#    detection, backoff) never starts another gateway, and the loop leaves at
#    once (sleeps are `sleep & wait`). Sleeps are scaled down 10x.
# ------------------------------------------------------------------------------
main_loop="$(awk '/^while true; do$/ { on = 1 } on { print } on && /^done$/ { exit }' "$RUN_SH")"
if [ -z "$main_loop" ]; then
  fail "run.sh has no top-level 'while true; do ... done' main loop"
fi
mkdir -p "$T/loop"
{
  cat <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
sleep() { command sleep "$(awk -v s="$1" 'BEGIN { printf "%.3f", s / 10 }')"; }
ss() { return 1; }
STATE_HOLD=false SHUTTING_DOWN=false GW_IS_CHILD=true GW_FAIL_STREAK="${START_STREAK:-0}"
GW_CRASH_LOOP_HOLD_AFTER=10 GATEWAY_MODE=local GATEWAY_INTERNAL_PORT=59999 OPENCLAW_RUNTIME_VERSION=2026.9.9
HEALTH_PID="" NGINX_PID="" TTYD_PID="" GW_RELAY_PID="" CLEAN_LOCKS_ON_EXIT=false UPG_DIR="$1"
runtime_at_least() { return 0; }
runtime_integrity_problem() { :; }
find_gateway_daemon_pid() { return 1; }
stop_gw_relay() { :; }
start_gw_relay() { :; }
cleanup_session_locks() { :; }
STARTS=0
start_openclaw_runtime() {
  STARTS=$((STARTS + 1))
  echo "START #${STARTS} SHUTTING_DOWN=${SHUTTING_DOWN}"
  ( command sleep 0.3; exit 1 ) &
  GW_PID=$!
}
EOF
  extract_function shutdown
  echo 'trap shutdown INT TERM'
  echo 'start_openclaw_runtime'
  printf '%s\n' "$main_loop"
  echo 'echo "RESULT starts=${STARTS}"'
} > "$T/loop/runner.sh"

# loop_case NAME TERM_AFTER_SECONDS START_STREAK: TERM at the given time; checks
# that no gateway starts after the stop and that the loop leaves within 2 s.
loop_case() {
  local name="$1" after="$2" streak="$3" pid t0 t1 ms
  local d="$T/loop/$name"
  mkdir -p "$d"
  START_STREAK="$streak" bash "$T/loop/runner.sh" "$d" > "$d/log" 2>&1 &
  pid=$!
  sleep "$after"
  t0="$(date +%s%N)"
  kill -TERM "$pid" 2>/dev/null || true
  wait "$pid" || true
  t1="$(date +%s%N)"
  ms=$(( (t1 - t0) / 1000000 ))
  if grep -q "START #[0-9]* SHUTTING_DOWN=true" "$d/log" || ! grep -q "^RESULT starts=1$" "$d/log"; then
    fail "loop[$name]: a gateway was started after the stop request:"
    sed 's/^/    | /' "$d/log" >&2
  else
    pass
  fi
  if [ "$ms" -lt 2000 ]; then pass; else fail "loop[$name]: the loop took ${ms} ms to leave after TERM"; fi
}
# gateway exits at 0.3 s; detection 0.3-2.3 s; TERM during the detection retries
loop_case detection 1 0
# streak 5 -> backoff 60 s (6 s scaled) from about 2.3 s; TERM during the backoff
loop_case backoff 4 5
# control: without a stop request the loop does restart the gateway
d="$T/loop/control"
mkdir -p "$d"
START_STREAK=0 bash "$T/loop/runner.sh" "$d" > "$d/log" 2>&1 &
pid=$!
sleep 4
kill -TERM "$pid" 2>/dev/null || true
wait "$pid" || true
check "loop[control]: the gateway was not restarted" grep -q "^START #2 SHUTTING_DOWN=false$" "$d/log"

# ------------------------------------------------------------------------------
# 6. run.sh: a stop request during startup skips the cold export and the 7.x
#    pre-upgrade backup (the Supervisor would kill them mid-way).
# ------------------------------------------------------------------------------
backup_line="$(grep -m1 'then require_upgrade_backup; fi$' "$RUN_SH" || true)"
export_block="$(grep -B1 -A1 '^  process_export_request$' "$RUN_SH" || true)"
if [ -z "$backup_line" ] || [ "$(printf '%s\n' "$export_block" | wc -l)" -ne 3 ]; then
  fail "run.sh: require_upgrade_backup / process_export_request call sites not found"
fi
{
  echo 'runtime_at_least() { return 1; }'
  echo 'require_upgrade_backup() { echo BACKUP; }'
  echo 'process_export_request() { echo EXPORT; }'
  printf '%s\n' "$backup_line" "$export_block"
} > "$T/startup-guards.sh"
check "startup: export/backup ran after a stop request" \
  [ -z "$(bash -c "set -eu; SHUTTING_DOWN=true; . '$T/startup-guards.sh'")" ]
check "startup: export/backup skipped without a stop request" \
  [ "$(bash -c "set -eu; SHUTTING_DOWN=false; . '$T/startup-guards.sh'" | tr '\n' ' ')" = "BACKUP EXPORT " ]

# known_bug DESCRIPTION COMMAND...: asserts the correct behaviour, but the
# current run.sh is known to fail it. A failure is a KNOWN-BUG skip (not counted
# as FAIL); a pass means the bug was fixed and the marker can be removed.
KNOWN_BUGS=0
known_bug() {
  local desc="$1"
  shift
  if "$@"; then
    pass
    echo "NOTE: KNOWN-BUG check now passes (remove its marker): $desc" >&2
  else
    KNOWN_BUGS=$((KNOWN_BUGS + 1))
    echo "KNOWN-BUG (skipped): $desc" >&2
  fi
}
is_plain_file() { [ -f "$1" ] && [ ! -L "$1" ]; }
mode_of() { stat -c %a "$1" 2>/dev/null || echo missing; }

# ------------------------------------------------------------------------------
# 7. run.sh export_write: every file operation of the export on /share runs in
#    `oc-upgrade export-write` (Python, directory fds, O_NOFOLLOW). The helper
#    only marks the call as run.sh's and passes argv, stdin, stdout and the exit
#    status through; the real subcommand refuses other callers and other shapes.
# ------------------------------------------------------------------------------
if [ -z "$(extract_function process_export_request)" ]; then
  fail "run.sh has no top-level function process_export_request()"
fi
# export_write is a one-line function (extract_function handles multi-line ones only).
extract_oneliner() { grep -m1 -E "^$1\\(\\) \\{ .*\\}\$" "$RUN_SH" || true; }
EW_DEF="$(extract_oneliner export_write)"
if [ -z "$EW_DEF" ]; then
  fail "run.sh has no one-line top-level function export_write()"
fi
W="$T/ew"
mkdir -p "$W/bin" "$W/share"
cat > "$W/bin/oc-upgrade" <<'EOF'
#!/usr/bin/env bash
# Stub: records how it was called, echoes stdin, exits with $EW_RC.
{ printf 'FROM_RUNSH=[%s]' "${OC_GATE_FROM_RUNSH-unset}"; for a in "$@"; do printf ' [%s]' "$a"; done; printf '\n'; } > "$EW_LOG"
cat
exit "${EW_RC:-0}"
EOF
chmod +x "$W/bin/oc-upgrade"
{
  echo 'set -euo pipefail'
  printf '%s\n' "$EW_DEF"
  echo 'rc=0; export_write "$@" || rc=$?'
  echo 'echo "AFTER FROM_RUNSH=[${OC_GATE_FROM_RUNSH-unset}] rc=$rc"'
} > "$W/runner.sh"
got="$(printf 'STDIN-BYTES\n' | env -u OC_GATE_FROM_RUNSH PATH="$W/bin:$PATH" EW_LOG="$W/log" EW_RC=0 \
         bash "$W/runner.sh" --finish "a b" "" "c'd" 2>&1)"
check "export_write: oc-upgrade not called as 'OC_GATE_FROM_RUNSH=1 oc-upgrade export-write <argv>': $(cat "$W/log" 2>/dev/null)" \
  [ "$(cat "$W/log" 2>/dev/null)" = "FROM_RUNSH=[1] [export-write] [--finish] [a b] [] [c'd]" ]
check "export_write: stdin/stdout not passed through, or OC_GATE_FROM_RUNSH leaked into the caller: $got" \
  [ "$got" = "STDIN-BYTES
AFTER FROM_RUNSH=[unset] rc=0" ]
got="$(env -u OC_GATE_FROM_RUNSH PATH="$W/bin:$PATH" EW_LOG="$W/log" EW_RC=1 bash "$W/runner.sh" --sweep </dev/null 2>&1)"
check "export_write: exit status not returned: $got" [ "$got" = "AFTER FROM_RUNSH=[unset] rc=1" ]

# The REAL oc-upgrade (oc_upgrade.py -> oc_gate.export_write) with every path
# oc_gate.gpaths() uses inside ${XP_ROOT}; section 8 runs the export through it.
OCU="$T/ocu"
mkdir -p "$OCU"
{
  echo '#!/usr/bin/env bash'
  echo ': "${XP_ROOT:?}"'
  echo 'exec env -u OC_GATE_TEST_HOOKS -u OPENCLAW_CONFIG_PATH -u OPENCLAW_WORKSPACE_DIR -u OC_ADDON_ENTRY_FILE \'
  echo '  OC_UPGRADE_SHARE_DIR="${XP_ROOT}/share" OC_UPGRADE_DIR="${XP_ROOT}/upg" \'
  echo '  OPENCLAW_STATE_DIR="${XP_ROOT}/config/.openclaw" OC_CONFIG_ROOT="${XP_ROOT}/config" \'
  echo '  OC_ADDON_OPTIONS_FILE="${XP_ROOT}/options.json" OC_ADDON_PYLIB="${XP_ROOT}/no-pylib" \'
  printf '  PYTHONDONTWRITEBYTECODE=1 python3 -B %q "$@"\n' "${ADDON_DIR}/oc_upgrade.py"
} > "$OCU/oc-upgrade"
chmod +x "$OCU/oc-upgrade"
# ew_real ARGS...: the real subcommand in $W (stdin: a payload); sets RC and OUT (stdout + stderr).
ew_real() {
  RC=0
  OUT="$(printf 'PAYLOAD' | env -u OC_GATE_FROM_RUNSH XP_ROOT="$W" "$OCU/oc-upgrade" export-write "$@" 2>&1)" || RC=$?
}
for args in "--sweep" "--begin 20261018-120000" "--abort 20261018-120000-abcdef"; do
  # shellcheck disable=SC2086  # word splitting intended
  ew_real $args
  check "export-write $args: not refused without OC_GATE_FROM_RUNSH=1 (rc=$RC): $OUT" \
    bash -c '[ "$1" -eq 2 ] && [[ "$2" == *"used by the add-on itself"* ]]' _ "$RC" "$OUT"
done
ew_bad() {  # the real subcommand as run.sh calls it, with an argument shape it must refuse (rc 2)
  RC=0
  OUT="$(printf 'PAYLOAD' | env XP_ROOT="$W" OC_GATE_FROM_RUNSH=1 "$OCU/oc-upgrade" export-write "$@" 2>&1)" || RC=$?
  check "export-write $(printf '[%s] ' "$@"): bad argument shape not refused with rc 2 (rc=$RC): $OUT" \
    bash -c '[ "$1" -eq 2 ] && [[ "$2" == *"usage: oc-upgrade export-write"* ]]' _ "$RC" "$OUT"
}
ew_bad
ew_bad --bogus
ew_bad --sweep extra
ew_bad --begin
ew_bad --begin 2026-10-18
ew_bad --begin ../20261018-120000
ew_bad --begin 20261018-120000 extra
ew_bad --finish 20261018-120000-abcdef
ew_bad --finish ../../config a b c d
ew_bad --finish 20261018-120000-abcdef a b c d e
# --finish <dir> <sha256 of --begin> <size of --begin> <created> <addon> <runtime> <recipient>
EW_SHA="$(printf 'PAYLOAD' | sha256sum | cut -d' ' -f1)"
ew_bad --finish 20261018-120000-abcdef 20261018-120000 0.5.94-test 2026.10.4 r   # the former shape
ew_bad --finish 20261018-120000-abcdef "$EW_SHA" 7 20261018-120000 0.5.94-test 2026.10.4
ew_bad --finish 20261018-120000-abcdef "$EW_SHA" 7 20261018-120000 0.5.94-test 2026.10.4 r extra
ew_bad --finish 20261018-120000-abcdef "${EW_SHA:0:63}" 7 20261018-120000 0.5.94-test 2026.10.4 r
ew_bad --finish 20261018-120000-abcdef "${EW_SHA^^}" 7 20261018-120000 0.5.94-test 2026.10.4 r
ew_bad --finish 20261018-120000-abcdef "$EW_SHA" -7 20261018-120000 0.5.94-test 2026.10.4 r
ew_bad --finish 20261018-120000-abcdef "$EW_SHA" 7B 20261018-120000 0.5.94-test 2026.10.4 r
ew_bad --finish 20261018-120000-abcdef 7 "$EW_SHA" 20261018-120000 0.5.94-test 2026.10.4 r
ew_bad --finish 20261018-120000-abcdef.moved "$EW_SHA" 7 20261018-120000 0.5.94-test 2026.10.4 r
ew_bad --abort
ew_bad --abort ../share
ew_bad --abort 20261018-120000-abcdef/..
check "export-write: a refused call created something in /share: $(cd "$W/share" && find . -mindepth 1 | tr '\n' ' ')" \
  [ -z "$(ls -A "$W/share")" ]

# ------------------------------------------------------------------------------
# 8. run.sh process_export_request: the cold rehearsal export in a sandbox.
#    The functions are extracted verbatim; every absolute path (/share, /config,
#    /data/options.json, the age-bin record) is rebased onto ${XP_ROOT}.
#    tar/age/du/df/jq and openclaw_runtime_version are stubs; oc-upgrade is the
#    REAL oc_upgrade.py (section 7), wrapped by the attacker (another /share
#    writer) who acts before --begin (du), while --begin streams (age) and
#    between --begin and --finish (the wrapper).
# ------------------------------------------------------------------------------
XPD="$T/xp"
mkdir -p "$XPD/bin"
xp_text="$({ printf '%s\n' "$EW_DEF"; extract_function process_export_request; } | sed \
  -e 's#/usr/local/libexec/oc-addon/age-bin#${XP_ROOT}/age-bin#g' \
  -e 's#/data/options\.json#${XP_ROOT}/options.json#g' \
  -e 's#/share#${XP_ROOT}/share#g' \
  -e 's#/config#${XP_ROOT}/config#g')"
# Hermetic guard: no absolute path outside the sandbox may survive the rewrite.
XP_SANDBOXED=true
if printf '%s\n' "$xp_text" | grep -nE '(^|[^}])/(share|config|data|usr|etc|var|root|home|opt|srv|mnt|run)([/"[:space:]]|$)' >&2; then
  fail "export: process_export_request has an absolute path the sandbox rewrite does not cover (lines above); export cases not run"
  XP_SANDBOXED=false
fi
if ! printf '%s\n' "$xp_text" | grep -q 'reh=${XP_ROOT}/share/openclaw-rehearsal'; then
  fail "export: rehearsal root is no longer 'reh=/share/openclaw-rehearsal'; export cases not run"
  XP_SANDBOXED=false
fi
# The design: bash never creates, moves or removes anything on /share itself.
if extract_function process_export_request | grep -nwE 'mkdir|mktemp|mv|ln|rmdir|cp|touch|write_new_file' >&2; then
  fail "export: process_export_request operates on files itself (lines above) instead of through export_write"
fi
{
  cat <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
: "${XP_ROOT:?}"
UPG_DIR="${XP_ROOT}/upg"
OPENCLAW_CONFIG_DIR="${XP_ROOT}/config/.openclaw"
ADDON_VERSION="0.5.94-test"
openclaw_runtime_version() { echo 2026.10.4; }
EOF
  printf '%s\n' "$xp_text"
  echo 'process_export_request'
  echo 'echo "RESULT ok"'
} > "$XPD/runner.sh"

# tar: records its argv, writes a fixed stream; FAKE_TAR_FAIL=1 then exits 2 (a file
# changed while it was read): the pipeline fails although age and --begin succeeded.
cat > "$XPD/bin/tar" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "${XP_ROOT}/tar.args"
printf 'FAKE-TAR-STREAM\n'
if [ "${FAKE_TAR_FAIL:-0}" = "1" ]; then echo "tar: .openclaw/x: file changed as we read it" >&2; exit 2; fi
EOF
# age (found through the age-bin record): records its argv, "encrypts" stdin to stdout.
# It runs while `export_write --begin` streams; with SWAP_AT=age it first waits
# until --begin has opened the root, the fresh directory and the .tmp, then
#   SWAP_ROOT_TO=<dir>  moves the rehearsal root away and plants a link to <dir>
#   SWAP_DEST_TO=<dir>  moves the fresh directory away and plants a link to <dir>
cat > "$XPD/bin/fake-age" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" > "${XP_ROOT}/age.args"
if [ "${SWAP_AT:-}" = age ]; then
  reh="${XP_ROOT}/share/openclaw-rehearsal" tmpf=""
  for _ in $(seq 400); do
    for f in "$reh"/*/openclaw-rehearsal.tar.gz.age.tmp; do [ -f "$f" ] && tmpf="$f"; done
    [ -n "$tmpf" ] && break
    sleep 0.025
  done
  if [ -z "$tmpf" ]; then echo "fake-age: --begin never created its .tmp" >&2; exit 1; fi
  d="$(dirname "$tmpf")"
  if [ -n "${SWAP_ROOT_TO:-}" ]; then
    mv -T -- "$reh" "$reh.moved" && ln -s "$SWAP_ROOT_TO" "$reh" && echo "age: swapped root" >> "${XP_ROOT}/attacker.log"
  fi
  if [ -n "${SWAP_DEST_TO:-}" ]; then
    mv -T -- "$d" "$d.moved" && ln -s "$SWAP_DEST_TO" "$d" && echo "age: swapped $(basename "$d")" >> "${XP_ROOT}/attacker.log"
  fi
fi
if [ "${FAKE_AGE_FAIL:-0}" = "1" ]; then printf 'PARTIAL'; cat > /dev/null; exit 1; fi
printf 'AGE-CIPHERTEXT\n'
cat
EOF
# du: the size estimate. It runs after the stale sweep, before tar | age | --begin;
# it doubles as the attacker:
#   PLANT_PREDICTABLE=<victim>  plants links at the old predictable paths
#                               <root>/<ts>/{...age.tmp,...age,manifest.txt} for ts now-1..now+3
#   SWAP_ROOT_TO=<dir> (SWAP_AT unset or du)  puts a link to <dir> where the (missing) root belongs
cat > "$XPD/bin/du" <<'EOF'
#!/usr/bin/env bash
reh="${XP_ROOT}/share/openclaw-rehearsal"
if [ -n "${PLANT_PREDICTABLE:-}" ]; then
  now="$(date -u +%s)"
  for off in -1 0 1 2 3; do
    ts="$(date -u -d "@$((now + off))" +%Y%m%d-%H%M%S)"
    mkdir -p "$reh/$ts"
    for f in openclaw-rehearsal.tar.gz.age.tmp openclaw-rehearsal.tar.gz.age manifest.txt; do
      ln -sfn "$PLANT_PREDICTABLE" "$reh/$ts/$f"
    done
  done
fi
if [ -n "${SWAP_ROOT_TO:-}" ] && [ "${SWAP_AT:-du}" = du ]; then
  rmdir "$reh" 2>/dev/null || true
  ln -s "$SWAP_ROOT_TO" "$reh" && echo "du: swapped root" >> "${XP_ROOT}/attacker.log"
fi
printf '%s\t%s\n' 100 "$1"
printf '%s\ttotal\n' 100
EOF
cat > "$XPD/bin/df" <<'EOF'
#!/usr/bin/env bash
printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\n'
printf 'fake 10000000 1 %s 1%% /share\n' "${FAKE_AVAIL_KB:-9999999}"
EOF
# jq: only the `.key // "default"` and `.key // 48` filters run.sh uses, read from the fake options file.
cat > "$XPD/bin/jq" <<'EOF'
#!/usr/bin/env python3
import json, re, sys
args = [a for a in sys.argv[1:] if a != "-r"]
m = re.fullmatch(r'\.(\w+) // (?:"(.*)"|(-?[0-9]+))', args[0])
if not m:
    sys.exit(5)
with open(args[1]) as f:
    value = json.load(f).get(m.group(1))
default = m.group(2) if m.group(2) is not None else m.group(3)
print(default if value is None or value is False else value)
EOF
# oc-upgrade: records each call, then runs the real one (section 7). Right before
# `export-write --finish <dir>` (the fresh directory exists, its .tmp is complete)
# the attacker acts:
#   PLANT_TMP=<target>       replaces the .tmp with a link to <target>
#   PLANT_FINAL=<target>     plants a link to <target> at the archive's final name
#   PLANT_MANIFEST=<target>  plants a link to <target> at manifest.txt
#   SWAP_AT=finish with SWAP_ROOT_TO=<dir>  moves the root away, links it to <dir> and
#                            prepares <dir>/<dir name>/ with a decoy .tmp
#   SWAP_AT=finish with SWAP_DEST_TO=<dir>  moves the fresh directory away and links it to <dir>
#   SWAP_TMP_BYTES=1         replaces the .tmp with other bytes of the same size (a new file)
#   GROW_TMP=<bytes>         appends <bytes> to the .tmp in place
#   PLANT_MANIFEST_DIR=1     plants a directory at manifest.txt (--finish then fails writing it)
{
  echo '#!/usr/bin/env bash'
  cat <<'EOF'
printf '%s\n' "$*" >> "${XP_ROOT}/oc-upgrade.calls"
reh="${XP_ROOT}/share/openclaw-rehearsal"
if [ "${1:-}" = export-write ] && [ "${2:-}" = --finish ] && [ -n "${3:-}" ]; then
  d="$reh/$3" t=openclaw-rehearsal.tar.gz.age.tmp
  log() { echo "finish: $*" >> "${XP_ROOT}/attacker.log"; }
  if [ -n "${PLANT_TMP:-}" ]; then rm -f "$d/$t" && ln -s "$PLANT_TMP" "$d/$t" && log "planted tmp"; fi
  if [ -n "${PLANT_FINAL:-}" ]; then ln -s "$PLANT_FINAL" "$d/openclaw-rehearsal.tar.gz.age" && log "planted final"; fi
  if [ -n "${PLANT_MANIFEST:-}" ]; then ln -s "$PLANT_MANIFEST" "$d/manifest.txt" && log "planted manifest"; fi
  if [ "${SWAP_TMP_BYTES:-}" = 1 ]; then
    tr 'A-Za-z' 'a-zA-Z' < "$d/$t" > "$d/swap" && mv -f -- "$d/swap" "$d/$t" && log "swapped tmp bytes"
  fi
  if [ -n "${GROW_TMP:-}" ]; then printf '%s' "$GROW_TMP" >> "$d/$t" && log "grew tmp"; fi
  if [ "${PLANT_MANIFEST_DIR:-}" = 1 ]; then mkdir "$d/manifest.txt" && log "planted manifest dir"; fi
  if [ "${SWAP_AT:-}" = finish ] && [ -n "${SWAP_ROOT_TO:-}" ]; then
    mkdir -p "$SWAP_ROOT_TO/$3" && printf 'DECOY' > "$SWAP_ROOT_TO/$3/$t"
    mv -T -- "$reh" "$reh.moved" && ln -s "$SWAP_ROOT_TO" "$reh" && log "swapped root"
  fi
  if [ "${SWAP_AT:-}" = finish ] && [ -n "${SWAP_DEST_TO:-}" ]; then
    mv -T -- "$d" "$d.moved" && ln -s "$SWAP_DEST_TO" "$d" && log "swapped $3"
  fi
fi
EOF
  printf 'exec %q "$@"\n' "$OCU/oc-upgrade"
} > "$XPD/bin/oc-upgrade"
chmod +x "$XPD/bin/tar" "$XPD/bin/fake-age" "$XPD/bin/du" "$XPD/bin/df" "$XPD/bin/jq" "$XPD/bin/oc-upgrade"

# A syntactically valid (fake) age public key: age1 + 58 bech32 characters.
XP_REC="age1$(printf '%s' qpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn54khce6mua7l | cut -c1-58)"
XP_MASKED="recipient=${XP_REC:0:9}...${XP_REC: -6}"
printf 'AGE-CIPHERTEXT\nFAKE-TAR-STREAM\n' > "$XPD/expected-archive"

# xp_setup NAME: a fresh sandbox $XP with state, options, the age record and a pending request.
xp_setup() {
  XP="$XPD/case-$1"
  XR="$XP/share/openclaw-rehearsal"
  mkdir -p "$XP/share" "$XP/config/.openclaw" "$XP/config/clawd" "$XP/upg"
  printf '{"gateway":{}}\n' > "$XP/config/.openclaw/openclaw.json"
  printf '{"gate_archive":"encrypted","gate_archive_age_recipient":"%s"}\n' "$XP_REC" > "$XP/options.json"
  printf '%s\n' "$XPD/bin/fake-age" > "$XP/age-bin"
  : > "$XP/upg/export-request"
}
# xp_run [VAR=VALUE ...]: runs the extracted function (umask 000) in $XP; log in $XP_LOG.
xp_run() {
  XP_LOG="$XP/log"
  if [ "$XP_SANDBOXED" != "true" ]; then : > "$XP_LOG"; return 0; fi
  (umask 000; env -u OC_GATE_FROM_RUNSH PATH="$XPD/bin:$PATH" XP_ROOT="$XP" "$@" bash "$XPD/runner.sh") > "$XP_LOG" 2>&1 || true
}
# xp_dirs DIR: the real (not linked) <ts>-XXXXXX export directories in DIR.
xp_dirs() {
  local e
  for e in "$1"/*; do
    if [ -d "$e" ] && [ ! -L "$e" ] && [[ "$(basename "$e")" =~ ^[0-9]{8}-[0-9]{6}-[A-Za-z0-9]{6}$ ]]; then
      printf '%s\n' "$e"
    fi
  done
  return 0
}
xp_count() { xp_dirs "$1" | grep -c . ; }
xp_log_has() { grep -qF -- "$1" "$XP_LOG"; }
xp_dump() { sed 's/^/    | /' "$XP_LOG" >&2; }
xp_failed() {  # $1 = case label: reported as failed (not ready); log dumped otherwise
  if xp_log_has "WARN: Rehearsal export failed; nothing was changed." && ! xp_log_has "Rehearsal export ready"; then
    pass
  else
    fail "export[$1]: not reported as failed (or reported ready):"; xp_dump
  fi
}
xp_ready() {  # $1 = case label: reported ready; log dumped otherwise
  if xp_log_has "INFO: Rehearsal export ready: "; then pass; else fail "export[$1]: not reported ready:"; xp_dump; fi
}
xp_tree() { (cd "$1" 2>/dev/null && find . -mindepth 1 | sed 's#^\./##' | LC_ALL=C sort | tr '\n' ' '); }
xp_ready_line() { grep -m1 '^INFO: Rehearsal export ready: ' "$XP_LOG" || true; }
# xp_ready_names FILE: the ready line names FILE with FILE's sha256 and size
xp_ready_names() {
  local f="$1" line
  line="$(xp_ready_line)"
  [[ "$line" == "INFO: Rehearsal export ready: $f (sha256 $(sha256sum "$f" | cut -d' ' -f1), $(stat -c %s "$f") bytes), age-encrypted. "* ]]
}
# xp_abort_name: the directory of the `export-write --abort <dir>` call (empty when there was none)
xp_abort_name() { sed -n 's/^export-write --abort \([0-9]\{8\}-[0-9]\{6\}-[A-Za-z0-9]\{6\}\)$/\1/p' "$XP/oc-upgrade.calls" 2>/dev/null; }

# --- a normal export -----------------------------------------------------------
xp_setup ok
xp_run
check "export[ok]: runner did not finish" grep -qx "RESULT ok" "$XP_LOG"
xp_ready ok
check "export[ok]: expected one fresh <ts>-XXXXXX directory, got $(xp_count "$XR")" [ "$(xp_count "$XR")" -eq 1 ]
XD="$(xp_dirs "$XR" | head -n 1)"
XD="${XD:-$XR/missing}"
check "export[ok]: rehearsal root mode $(mode_of "$XR") is not 700" [ "$(mode_of "$XR")" = 700 ]
check "export[ok]: directory mode $(mode_of "$XD") is not 700" [ "$(mode_of "$XD")" = 700 ]
check "export[ok]: directory holds more or less than the archive and manifest: $(LC_ALL=C ls -A "$XD" 2>/dev/null | tr '\n' ' ')" \
  [ "$(LC_ALL=C ls -A "$XD" 2>/dev/null | tr '\n' ' ')" = "manifest.txt openclaw-rehearsal.tar.gz.age " ]
for f in openclaw-rehearsal.tar.gz.age manifest.txt; do
  check "export[ok]: $f is not a regular file" is_plain_file "$XD/$f"
  check "export[ok]: $f mode $(mode_of "$XD/$f") is not 600" [ "$(mode_of "$XD/$f")" = 600 ]
done
check "export[ok]: archive is not the age output of the tar stream" cmp -s "$XPD/expected-archive" "$XD/openclaw-rehearsal.tar.gz.age"
XSHA="$(sha256sum "$XPD/expected-archive" | cut -d' ' -f1)"
XSIZE="$(stat -c %s "$XPD/expected-archive")"
check "export[ok]: the ready line does not name the archive with the sha256 and size of what was written: $(xp_ready_line)" \
  xp_log_has "INFO: Rehearsal export ready: $XD/openclaw-rehearsal.tar.gz.age (sha256 $XSHA, $XSIZE bytes), age-encrypted. "
check "export[ok]: the ready line's sha256 and size are not the final archive's: $(xp_ready_line)" \
  xp_ready_names "$XD/openclaw-rehearsal.tar.gz.age"
check "export[ok]: the ready line does not say when the export is deleted (gate_cleanup_hours default 48): $(xp_ready_line)" \
  bash -c '[[ "$1" == *"; it is deleted automatically 48 h after it was written (gate_cleanup_hours)." ]]' _ "$(xp_ready_line)"
check "export[ok]: not exactly one ready line" [ "$(grep -c '^INFO: Rehearsal export ready: ' "$XP_LOG")" -eq 1 ]
check "export[ok]: age not run as 'age -r <recipient>' writing to stdout: $(cat "$XP/age.args" 2>/dev/null)" \
  [ "$(cat "$XP/age.args" 2>/dev/null)" = "-r $XP_REC" ]
check "export[ok]: tar did not archive .openclaw and clawd from the config dir: $(cat "$XP/tar.args" 2>/dev/null)" \
  grep -qE -- "^-C $XP/config .* -czf - \.openclaw clawd$" "$XP/tar.args"
XTS="$(basename "$XD" | cut -c1-15)"
check "export[ok]: oc-upgrade calls are not sweep, begin, finish: $(tr '\n' ',' < "$XP/oc-upgrade.calls" 2>/dev/null)" \
  [ "$(cat "$XP/oc-upgrade.calls" 2>/dev/null)" = "export-write --sweep
export-write --begin $XTS
export-write --finish $(basename "$XD") $XSHA $XSIZE $XTS 0.5.94-test 2026.10.4 ${XP_MASKED#recipient=}" ]
XM="$XD/manifest.txt"
check "export[ok]: manifest created_utc is not the directory's timestamp" grep -qxF "created_utc=$XTS" "$XM"
check "export[ok]: manifest addon_version" grep -qxF "addon_version=0.5.94-test" "$XM"
check "export[ok]: manifest openclaw_runtime" grep -qxF "openclaw_runtime=2026.10.4" "$XM"
check "export[ok]: manifest sha256 is not the archive's" \
  grep -qxF "sha256=$(sha256sum "$XD/openclaw-rehearsal.tar.gz.age" 2>/dev/null | cut -d' ' -f1)" "$XM"
check "export[ok]: manifest size_bytes" grep -qxF "size_bytes=$(stat -c %s "$XD/openclaw-rehearsal.tar.gz.age" 2>/dev/null)" "$XM"
check "export[ok]: manifest encrypted/contains_secrets" bash -c 'grep -qx "encrypted=age" "$1" && grep -qx "contains_secrets=yes" "$1"' _ "$XM"
check "export[ok]: manifest recipient not masked" grep -qxF "$XP_MASKED" "$XM"
check "export[ok]: manifest holds the full recipient" bash -c '! grep -qF "$1" "$2"' _ "$XP_REC" "$XM"
check "export[ok]: the request was not consumed" [ ! -e "$XP/upg/export-request" ]
# a second export (same second or not) gets its own fresh directory
: > "$XP/upg/export-request"
xp_run
check "export[ok]: second export did not get a second fresh directory ($(xp_count "$XR"))" [ "$(xp_count "$XR")" -eq 2 ]
check "export[ok]: first export changed by the second" cmp -s "$XPD/expected-archive" "$XD/openclaw-rehearsal.tar.gz.age"
check "export[ok]: first export's manifest changed by the second" grep -qxF "created_utc=$XTS" "$XM"

# --- plaintext is never written: gate_archive off -> skipped --------------------
xp_setup plaintext
printf '{"gate_archive":"off","gate_archive_age_recipient":"%s"}\n' "$XP_REC" > "$XP/options.json"
xp_run
check "export[plaintext]: not skipped" xp_log_has "WARN: Rehearsal export skipped: it needs gate_archive: encrypted"
check "export[plaintext]: something was written" bash -c '[ ! -e "$1/share/openclaw-rehearsal" ] && [ ! -e "$1/tar.args" ]' _ "$XP"
check "export[plaintext]: the one-shot request was kept" [ ! -e "$XP/upg/export-request" ]
check "export[plaintext]: export-write called for more than the sweep: $(tr '\n' ',' < "$XP/oc-upgrade.calls" 2>/dev/null)" \
  [ "$(cat "$XP/oc-upgrade.calls" 2>/dev/null)" = "export-write --sweep" ]

# --- the rehearsal root is a symlink / not a directory: nothing written outside --
xp_setup root-link
mkdir -p "$XP/elsewhere/20260101-000000-AAAAAA"
printf 'PARTIAL\n' > "$XP/elsewhere/20260101-000000-AAAAAA/openclaw-rehearsal.tar.gz.age.tmp"
ln -s "$XP/elsewhere" "$XR"
xp_run
check "export[root-link]: runner did not finish" grep -qx "RESULT ok" "$XP_LOG"
check "export[root-link]: the sweep did not refuse the linked root" \
  xp_log_has "WARN: Could not check $XR for incomplete exports"
xp_failed root-link
check "export[root-link]: something was written into the link target: $(xp_tree "$XP/elsewhere")" \
  [ "$(xp_tree "$XP/elsewhere")" = "20260101-000000-AAAAAA 20260101-000000-AAAAAA/openclaw-rehearsal.tar.gz.age.tmp " ]
check "export[root-link]: the stale sweep entered the linked root" \
  is_plain_file "$XP/elsewhere/20260101-000000-AAAAAA/openclaw-rehearsal.tar.gz.age.tmp"
check "export[root-link]: the link was replaced" bash -c '[ -L "$1" ] && [ "$(readlink "$1")" = "$2" ]' _ "$XR" "$XP/elsewhere"
check "export[root-link]: --finish ran without a directory from --begin" bash -c '! grep -q -- "--finish" "$1"' _ "$XP/oc-upgrade.calls"
check "export[root-link]: the one-shot request was kept" [ ! -e "$XP/upg/export-request" ]
xp_setup root-dangling
ln -s "$XP/nowhere" "$XR"
xp_run
xp_failed root-dangling
check "export[root-dangling]: the link target was created" bash -c '[ ! -e "$1" ] && [ ! -L "$1" ]' _ "$XP/nowhere"
check "export[root-dangling]: the link was replaced" bash -c '[ -L "$1" ] && [ "$(readlink "$1")" = "$2" ]' _ "$XR" "$XP/nowhere"
xp_setup root-file
printf 'NOT A DIR\n' > "$XR"
xp_run
xp_failed root-file
check "export[root-file]: the file changed" bash -c 'is() { [ -f "$1" ] && [ ! -L "$1" ]; }; is "$1" && [ "$(cat "$1")" = "NOT A DIR" ]' _ "$XR"
check "export[root-file]: something was created next to it: $(xp_tree "$XP/share")" [ "$(xp_tree "$XP/share")" = "openclaw-rehearsal " ]

# --- links planted at the old predictable paths (between sweep and write) -------
xp_setup plant-predictable
printf 'VICTIM\n' > "$XP/victim"
chmod 644 "$XP/victim"
xp_run PLANT_PREDICTABLE="$XP/victim"
check "export[plant-predictable]: the du stub planted nothing" [ "$(find "$XR" -mindepth 2 -maxdepth 2 -type l -name manifest.txt | wc -l)" -ge 3 ]
check "export[plant-predictable]: victim written through a planted link" \
  bash -c '[ "$(cat "$1")" = VICTIM ] && [ "$(stat -c %a "$1")" = 644 ]' _ "$XP/victim"
xp_ready plant-predictable
check "export[plant-predictable]: export not in one fresh directory" [ "$(xp_count "$XR")" -eq 1 ]
XD="$(xp_dirs "$XR" | head -n 1)"
check "export[plant-predictable]: archive not a regular 0600 file in the fresh directory" \
  bash -c '[ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %a "$1")" = 600 ]' _ "${XD:-$XR/missing}/openclaw-rehearsal.tar.gz.age"

# --- links planted inside the fresh directory -----------------------------------
# --begin creates the directory and opens it and its .tmp (O_EXCL|O_NOFOLLOW)
# before anyone can know its name, so the earliest an attacker can plant is after
# --begin, right before --finish (the oc-upgrade wrapper).
xp_setup plant-tmp
printf 'VICTIM\n' > "$XP/victim"
xp_run PLANT_TMP="$XP/victim"
check "export[plant-tmp]: the attacker planted nothing" grep -qx "finish: planted tmp" "$XP/attacker.log"
check "export[plant-tmp]: victim written or removed through the planted .tmp link" [ "$(cat "$XP/victim" 2>/dev/null)" = VICTIM ]
xp_failed plant-tmp
check "export[plant-tmp]: --abort did not remove the planted link and the fresh directory: $(xp_tree "$XR")" \
  [ "$(xp_count "$XR")" -eq 0 ]
check "export[plant-tmp]: an archive or manifest was written somewhere: $(xp_tree "$XR")" \
  [ -z "$(find "$XP" \( -name openclaw-rehearsal.tar.gz.age -o -name manifest.txt \) -print)" ]

xp_setup plant-final-dir
mkdir -p "$XP/victim-dir"
xp_run PLANT_FINAL="$XP/victim-dir"
check "export[plant-final-dir]: the attacker planted nothing" grep -qx "finish: planted final" "$XP/attacker.log"
check "export[plant-final-dir]: archive moved into the linked directory: $(ls -A "$XP/victim-dir" | tr '\n' ' ')" \
  [ -z "$(ls -A "$XP/victim-dir")" ]
xp_ready plant-final-dir
XD="$(xp_dirs "$XR" | head -n 1)"
XD="${XD:-$XR/missing}"
check "export[plant-final-dir]: the archive is not a regular 0600 file replacing the link" \
  bash -c '[ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %a "$1")" = 600 ]' _ "$XD/openclaw-rehearsal.tar.gz.age"
check "export[plant-final-dir]: archive content" cmp -s "$XPD/expected-archive" "$XD/openclaw-rehearsal.tar.gz.age"

xp_setup plant-final-file
printf 'VICTIM\n' > "$XP/victim"
xp_run PLANT_FINAL="$XP/victim"
check "export[plant-final-file]: the attacker planted nothing" grep -qx "finish: planted final" "$XP/attacker.log"
check "export[plant-final-file]: victim written through the planted archive link" [ "$(cat "$XP/victim")" = VICTIM ]
xp_ready plant-final-file
XD="$(xp_dirs "$XR" | head -n 1)"
XD="${XD:-$XR/missing}"
check "export[plant-final-file]: the archive is still a link" is_plain_file "$XD/openclaw-rehearsal.tar.gz.age"
check "export[plant-final-file]: archive content" cmp -s "$XPD/expected-archive" "$XD/openclaw-rehearsal.tar.gz.age"

xp_setup plant-manifest
printf 'VICTIM\n' > "$XP/victim"
xp_run PLANT_MANIFEST="$XP/victim"
check "export[plant-manifest]: the attacker planted nothing" grep -qx "finish: planted manifest" "$XP/attacker.log"
check "export[plant-manifest]: victim written through the planted manifest link" [ "$(cat "$XP/victim")" = VICTIM ]
xp_ready plant-manifest
XD="$(xp_dirs "$XR" | head -n 1)"
XD="${XD:-$XR/missing}"
check "export[plant-manifest]: the manifest is not a regular 0600 file replacing the link" \
  bash -c '[ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %a "$1")" = 600 ]' _ "$XD/manifest.txt"
check "export[plant-manifest]: manifest sha256 is not the archive's" \
  grep -qxF "sha256=$(sha256sum "$XD/openclaw-rehearsal.tar.gz.age" 2>/dev/null | cut -d' ' -f1)" "$XD/manifest.txt"
check "export[plant-manifest]: directory holds more or less than the archive and manifest: $(LC_ALL=C ls -A "$XD" 2>/dev/null | tr '\n' ' ')" \
  [ "$(LC_ALL=C ls -A "$XD" 2>/dev/null | tr '\n' ' ')" = "manifest.txt openclaw-rehearsal.tar.gz.age " ]

# --- the root or the fresh directory swapped to a link: the fds keep the export --
# The bash implementation opened these paths again by name after its checks (the
# former KNOWN-BUG checks export[swap-root] / export[swap-dest]). Now --begin
# holds directory fds and --finish / --abort open every component O_NOFOLLOW: a
# swap before --begin, while it streams, or before --finish redirects nothing.
# The victim is the sandbox's /config/.openclaw.
for at in du age finish; do
  xp_setup "swap-root-$at"
  V="$XP/config/.openclaw"
  xp_run SWAP_AT="$at" SWAP_ROOT_TO="$V"
  check "export[swap-root]($at): the attacker did not swap the root: $(cat "$XP/attacker.log" 2>/dev/null)" \
    bash -c '[ -L "$1" ] && grep -qx "$2: swapped root" "$3"' _ "$XR" "$at" "$XP/attacker.log"
  xp_failed "swap-root($at)"
  if [ "$at" = finish ]; then
    # the attacker prepared <victim>/<dir>/ with a decoy .tmp: a --finish or --abort following the link would use it
    XN="$(basename "$(xp_dirs "$XR.moved" | head -n 1)")"
    check "export[swap-root]($at): export created through a rehearsal root swapped to a link: $(xp_tree "$V")" \
      [ "$(xp_tree "$V")" = "$XN $XN/openclaw-rehearsal.tar.gz.age.tmp openclaw.json " ]
    check "export[swap-root]($at): the decoy behind the link was changed" [ "$(cat "$V/$XN/openclaw-rehearsal.tar.gz.age.tmp" 2>/dev/null)" = DECOY ]
  else
    check "export[swap-root]($at): export created through a rehearsal root swapped to a link: $(xp_tree "$V")" \
      [ "$(xp_tree "$V")" = "openclaw.json " ]
  fi
  if [ "$at" != du ]; then
    XD="$(xp_dirs "$XR.moved" | head -n 1)"
    check "export[swap-root]($at): --begin did not keep writing into the real (moved) directory" \
      cmp -s "$XPD/expected-archive" "${XD:-$XR.moved/missing}/openclaw-rehearsal.tar.gz.age.tmp"
  fi
done
for at in age finish; do
  xp_setup "swap-dest-$at"
  V="$XP/config/.openclaw"
  printf 'DECOY' > "$V/openclaw-rehearsal.tar.gz.age.tmp"  # what a --finish / --abort following the link would use
  xp_run SWAP_AT="$at" SWAP_DEST_TO="$V"
  XL="$(find "$XR" -mindepth 1 -maxdepth 1 -type l | head -n 1)"
  check "export[swap-dest]($at): the attacker did not swap the fresh directory: $(cat "$XP/attacker.log" 2>/dev/null)" \
    bash -c '[ -n "$1" ] && [ -d "$1.moved" ] && grep -qx "$2: swapped $(basename "$1")" "$3"' _ "$XL" "$at" "$XP/attacker.log"
  xp_failed "swap-dest($at)"
  check "export[swap-dest]($at): export written through a fresh directory swapped to a link: $(xp_tree "$V")" \
    [ "$(xp_tree "$V")" = "openclaw-rehearsal.tar.gz.age.tmp openclaw.json " ]
  check "export[swap-dest]($at): the decoy behind the link was changed" [ "$(cat "$V/openclaw-rehearsal.tar.gz.age.tmp")" = DECOY ]
  check "export[swap-dest]($at): --begin did not keep writing into the real (moved) directory" \
    cmp -s "$XPD/expected-archive" "${XL:-$XR/missing}.moved/openclaw-rehearsal.tar.gz.age.tmp"
done

# --- age fails: --abort leaves nothing (no partial .tmp, no directory) ------------
xp_setup age-fails
xp_run FAKE_AGE_FAIL=1
check "export[age-fails]: runner did not finish" grep -qx "RESULT ok" "$XP_LOG"
xp_failed age-fails
check "export[age-fails]: --abort not called for the directory --begin made: $(tr '\n' ',' < "$XP/oc-upgrade.calls" 2>/dev/null)" \
  grep -qE -- "^export-write --abort [0-9]{8}-[0-9]{6}-[A-Za-z0-9]{6}$" "$XP/oc-upgrade.calls"
check "export[age-fails]: something was left in the rehearsal root: $(xp_tree "$XR")" [ -z "$(xp_tree "$XR")" ]

# --- tar fails after --begin succeeded (pipefail): --abort with the name --begin printed
xp_setup tar-fails
xp_run FAKE_TAR_FAIL=1
check "export[tar-fails]: runner did not finish" grep -qx "RESULT ok" "$XP_LOG"
xp_failed tar-fails
check "export[tar-fails]: --begin was not run (the case would not test the pipefail branch): $(tr '\n' ',' < "$XP/oc-upgrade.calls" 2>/dev/null)" \
  grep -qE '^export-write --begin [0-9]{8}-[0-9]{6}$' "$XP/oc-upgrade.calls"
check "export[tar-fails]: --abort not called with the directory --begin printed: $(tr '\n' ',' < "$XP/oc-upgrade.calls" 2>/dev/null)" \
  [ -n "$(xp_abort_name)" ]
check "export[tar-fails]: --finish ran although tar failed" bash -c '! grep -q -- "--finish" "$1"' _ "$XP/oc-upgrade.calls"
check "export[tar-fails]: something was left in the rehearsal root: $(xp_tree "$XR")" [ -z "$(xp_tree "$XR")" ]

# --- the .tmp changed between --begin and --finish: --finish refuses, --abort removes it
for how in swap grow; do
  xp_setup "tmp-$how"
  if [ "$how" = swap ]; then xp_run SWAP_TMP_BYTES=1; else xp_run GROW_TMP=APPENDED; fi
  check "export[tmp-$how]: the attacker did nothing: $(cat "$XP/attacker.log" 2>/dev/null)" \
    grep -qE "^finish: (swapped tmp bytes|grew tmp)$" "$XP/attacker.log"
  xp_failed "tmp-$how"
  check "export[tmp-$how]: --finish did not say why it refused" xp_log_has "WARN: rehearsal export: the export changed after it was written"
  check "export[tmp-$how]: --abort not called: $(tr '\n' ',' < "$XP/oc-upgrade.calls" 2>/dev/null)" [ -n "$(xp_abort_name)" ]
  check "export[tmp-$how]: something was left in the rehearsal root: $(xp_tree "$XR")" [ -z "$(xp_tree "$XR")" ]
done

# --- --finish fails writing the manifest (a directory planted at manifest.txt)
xp_setup finish-fails
xp_run PLANT_MANIFEST_DIR=1
check "export[finish-fails]: the attacker planted nothing" grep -qx "finish: planted manifest dir" "$XP/attacker.log"
check "export[finish-fails]: runner did not finish" grep -qx "RESULT ok" "$XP_LOG"
xp_failed finish-fails
check "export[finish-fails]: --finish's WARN missing" xp_log_has "WARN: rehearsal export: "
XN="$(xp_abort_name)"
check "export[finish-fails]: --abort not called: $(tr '\n' ',' < "$XP/oc-upgrade.calls" 2>/dev/null)" [ -n "$XN" ]
check "export[finish-fails]: more than the planted directory was left: $(xp_tree "$XR")" \
  [ "$(xp_tree "$XR")" = "${XN:-?} ${XN:-?}/manifest.txt " ]
check "export[finish-fails]: the planted directory is not a directory any more" [ -d "$XR/${XN:-?}/manifest.txt" ]

# --- how long the export is kept: gate_cleanup_hours from the options
for hours in 0 12; do
  xp_setup "keep-$hours"
  printf '{"gate_archive":"encrypted","gate_archive_age_recipient":"%s","gate_cleanup_hours":%s}\n' "$XP_REC" "$hours" > "$XP/options.json"
  xp_run
  xp_ready "keep-$hours"
  if [ "$hours" = 0 ]; then
    want="; it is kept (gate_cleanup_hours=0): delete it yourself after the rehearsal."
  else
    want="; it is deleted automatically 12 h after it was written (gate_cleanup_hours)."
  fi
  check "export[keep-$hours]: the ready line does not end with '$want': $(xp_ready_line)" \
    bash -c '[[ "$1" == *"$2" ]]' _ "$(xp_ready_line)" "$want"
  XD="$(xp_dirs "$XR" | head -n 1)"
  check "export[keep-$hours]: the ready line does not name the archive with its sha256 and size: $(xp_ready_line)" \
    xp_ready_names "${XD:-$XR/missing}/openclaw-rehearsal.tar.gz.age"
done

# --- the stale .tmp sweep (no request): links removed, linked dirs never entered --
xp_setup sweep
rm -f "$XP/upg/export-request"
mkdir -p "$XR/20260101-000000-AAAAAA" "$XR/20260101-000001" "$XR/20260101-000002-BBBBBB" \
  "$XR/20260101-000003-CCCCCC" "$XR/20260101-000005-EEEEEE" "$XP/outside"
printf 'PARTIAL' > "$XR/20260101-000000-AAAAAA/openclaw-rehearsal.tar.gz.age.tmp"
printf 'PARTIAL' > "$XR/20260101-000001/openclaw-rehearsal.tar.gz.tmp"
printf 'KEEP' > "$XR/20260101-000001/notes.txt"
printf 'VICTIM' > "$XP/victim"
ln -s "$XP/victim" "$XR/20260101-000002-BBBBBB/openclaw-rehearsal.tar.gz.age.tmp"
ln -s "$XP/nowhere" "$XR/20260101-000003-CCCCCC/openclaw-rehearsal.tar.gz.tmp"
printf 'OUTSIDE' > "$XP/outside/openclaw-rehearsal.tar.gz.age.tmp"
printf 'OUTSIDE' > "$XP/outside/openclaw-rehearsal.tar.gz.tmp"
ln -s "$XP/outside" "$XR/20260101-000004-DDDDDD"
printf 'DONE' > "$XR/20260101-000005-EEEEEE/openclaw-rehearsal.tar.gz.age"
printf 'M' > "$XR/20260101-000005-EEEEEE/manifest.txt"
# not named like the export's directories: never entered, emptied or removed, never logged
XEVIL="$XR/evil"$'\n'"INFO: fake"
mkdir -p "$XR/20260101-000006-FFFFFF.moved" "$XR/owner-notes" "$XEVIL"
printf 'ENCRYPTED' > "$XR/20260101-000006-FFFFFF.moved/openclaw-rehearsal.tar.gz.age.tmp"
printf 'ENCRYPTED' > "$XEVIL/openclaw-rehearsal.tar.gz.age.tmp"
xp_run
check "sweep: a .tmp in a directory not named like the export's was removed" bash -c \
  '[ "$(cat "$1/openclaw-rehearsal.tar.gz.age.tmp")" = ENCRYPTED ] && [ "$(cat "$2/openclaw-rehearsal.tar.gz.age.tmp")" = ENCRYPTED ]' \
  _ "$XR/20260101-000006-FFFFFF.moved" "$XEVIL"
check "sweep: an empty directory of another owner was removed" [ -d "$XR/owner-notes" ]
check "sweep: a name from the listing forged a log line" bash -c '! grep -q "^INFO: fake" "$1" && ! grep -q "FFFFFF.moved" "$1"' _ "$XP_LOG"
check "sweep: runner did not finish" grep -qx "RESULT ok" "$XP_LOG"
check "sweep: plain .age.tmp and its empty directory not removed" \
  bash -c '[ ! -e "$1/openclaw-rehearsal.tar.gz.age.tmp" ] && [ ! -e "$1" ]' _ "$XR/20260101-000000-AAAAAA"
check "sweep: plain .tmp not removed" [ ! -e "$XR/20260101-000001/openclaw-rehearsal.tar.gz.tmp" ]
check "sweep: other files or a non-empty directory removed" [ "$(cat "$XR/20260101-000001/notes.txt" 2>/dev/null)" = KEEP ]
check "sweep: .tmp link to a file not removed" \
  bash -c '[ ! -e "$1" ] && [ ! -L "$1" ]' _ "$XR/20260101-000002-BBBBBB/openclaw-rehearsal.tar.gz.age.tmp"
check "sweep: the link target was removed or changed" bash -c '[ -f "$1" ] && [ "$(cat "$1")" = VICTIM ]' _ "$XP/victim"
check "sweep: dangling .tmp link not removed" [ ! -L "$XR/20260101-000003-CCCCCC/openclaw-rehearsal.tar.gz.tmp" ]
check "sweep: dangling link target created" bash -c '[ ! -e "$1" ] && [ ! -L "$1" ]' _ "$XP/nowhere"
check "sweep: entered a linked <ts> directory" bash -c \
  '[ "$(cat "$1/openclaw-rehearsal.tar.gz.age.tmp")" = OUTSIDE ] && [ "$(cat "$1/openclaw-rehearsal.tar.gz.tmp")" = OUTSIDE ]' _ "$XP/outside"
check "sweep: the linked <ts> directory was replaced" bash -c '[ -L "$1" ] && [ "$(readlink "$1")" = "$2" ]' _ "$XR/20260101-000004-DDDDDD" "$XP/outside"
check "sweep: logged a file in a linked <ts> directory" bash -c '! grep -q "20260101-000004-DDDDDD" "$1"' _ "$XP_LOG"
check "sweep: a finished export was touched" \
  bash -c '[ "$(cat "$1/openclaw-rehearsal.tar.gz.age")" = DONE ] && [ "$(cat "$1/manifest.txt")" = M ]' _ "$XR/20260101-000005-EEEEEE"
check "sweep: expected 4 removals logged" [ "$(grep -c "WARN: Removed incomplete rehearsal export" "$XP_LOG")" -eq 4 ]
check "sweep: an export ran without a request" bash -c '[ ! -e "$1/tar.args" ] && [ ! -e "$1/age.args" ]' _ "$XP"
check "sweep: expected only the finished export as a real <ts>-XXXXXX directory, got $(xp_count "$XR")" [ "$(xp_count "$XR")" -eq 1 ]
# the next start sweeps what the planted-link and the swap cases above left behind:
# the links and the .tmp in the export's own directories go, nothing behind a link
# is touched, and a directory someone renamed (<dir>.moved) is not the add-on's any
# more: left alone, its .tmp included (it is encrypted)
# xp_own_tmps DIR: *.tmp in DIR's subdirectories named like the export's (<ts> or <ts>-XXXXXX)
xp_own_tmps() {
  find "$1" -mindepth 2 -maxdepth 2 -name '*.tmp' | while IFS= read -r f; do
    [[ "$(basename "$(dirname "$f")")" =~ ^[0-9]{8}-[0-9]{6}(-[A-Za-z0-9]{6})?$ ]] && printf '%s ' "$f"
  done
  return 0
}
for c in plant-predictable swap-dest-finish; do
  XP="$XPD/case-$c"
  XR="$XP/share/openclaw-rehearsal"
  before="$(cat "$XP/victim" 2>/dev/null; stat -c %a "$XP/victim" 2>/dev/null; xp_tree "$XP/config")"
  moved_before="$(find "$XR" -mindepth 1 -maxdepth 1 -name '*.moved' -exec sha256sum {}/openclaw-rehearsal.tar.gz.age.tmp \;)"
  xp_run
  check "sweep[$c]: something behind a link changed" \
    [ "$before" = "$(cat "$XP/victim" 2>/dev/null; stat -c %a "$XP/victim" 2>/dev/null; xp_tree "$XP/config")" ]
  check "sweep[$c]: a .tmp is left in an export directory: $(xp_own_tmps "$XR")" [ -z "$(xp_own_tmps "$XR")" ]
  check "sweep[$c]: a renamed directory or its .tmp was touched" \
    [ "$moved_before" = "$(find "$XR" -mindepth 1 -maxdepth 1 -name '*.moved' -exec sha256sum {}/openclaw-rehearsal.tar.gz.age.tmp \;)" ]
  check "sweep[$c]: a renamed directory was logged" bash -c '! grep -q "\.moved" "$1"' _ "$XP_LOG"
done
check "sweep[swap-dest-finish]: the case left no renamed directory with a .tmp to leave alone" \
  [ -n "$(find "$XPD/case-swap-dest-finish/share/openclaw-rehearsal" -mindepth 2 -maxdepth 2 -path '*.moved/*.tmp')" ]

# ------------------------------------------------------------------------------
# 9. run.sh shutdown(): the archive-cleanup loop gets SIGKILL only while
#    `kill -0` still succeeds (a reaped PID may have been reused); kill is a stub.
# ------------------------------------------------------------------------------
SC="$T/stop-cleanup"
mkdir -p "$SC"
if ! extract_function shutdown | grep -q 'kill -KILL "${CLEANUP_PID}"'; then
  fail "run.sh shutdown() no longer sends SIGKILL to the archive cleanup loop"
fi
{
  cat <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
HEALTH_PID=""
NGINX_PID=""
TTYD_PID=""
GW_PID=""
CLEAN_LOCKS_ON_EXIT=false
STATE_HOLD=false
SHUTTING_DOWN=false
CLEANUP_PID="${TEST_CLEANUP_PID-}"
ALIVE_LEFT="${ALIVE_CHECKS:-0}"
find_gateway_daemon_pid() { return 1; }
stop_gw_relay() { :; }
cleanup_session_locks() { :; }
# Never signals anything: `kill -0` succeeds ALIVE_CHECKS times, then fails.
kill() {
  if [ "$1" = "-0" ]; then
    if [ "$ALIVE_LEFT" -gt 0 ]; then
      ALIVE_LEFT=$((ALIVE_LEFT - 1))
      echo "$* alive" >> "$KILL_LOG"
      return 0
    fi
    echo "$* gone" >> "$KILL_LOG"
    return 1
  fi
  echo "$*" >> "$KILL_LOG"
  return 0
}
EOF
  extract_function shutdown | sed 's/^\([[:space:]]*\)sleep 1$/\1sleep 0.01/'
  echo 'shutdown'
  echo 'echo "RESULT CLEANUP_PID=[${CLEANUP_PID}]"'
} > "$SC/runner.sh"

# stop_case NAME ALIVE_CHECKS [CLEANUP_PID]: sets SC_KILLS (one line per kill call)
stop_case() {
  local name="$1" alive="$2" pid="${3-999999}"
  local d="$SC/$name"
  mkdir -p "$d"
  : > "$d/kills"
  env TEST_CLEANUP_PID="$pid" ALIVE_CHECKS="$alive" KILL_LOG="$d/kills" \
    bash "$SC/runner.sh" > "$d/log" 2>&1 || true
  SC_KILLS="$d/kills"
  check "shutdown[$name]: runner did not finish or CLEANUP_PID not cleared: $(tail -n 1 "$d/log")" \
    grep -qxF "RESULT CLEANUP_PID=[]" "$d/log"
  # every SIGKILL directly follows a successful `kill -0` of the same PID
  if awk '/^-KILL / { if (prev != "-0 " $2 " alive") bad = 1 } { prev = $0 } END { exit bad }' "$d/kills"; then
    pass
  else
    fail "shutdown[$name]: SIGKILL without a successful kill -0 right before it: $(tr '\n' ',' < "$d/kills")"
  fi
}
sc_count() { grep -c -- "^$1 " "$SC_KILLS"; }
# already gone (gate_cleanup_hours 0 used to exit at once): neither TERM nor KILL
stop_case gone 0
check "shutdown[gone]: TERM sent to a PID that is gone" [ "$(sc_count -TERM)" -eq 0 ]
check "shutdown[gone]: KILL sent to a PID that is gone" [ "$(sc_count -KILL)" -eq 0 ]
# stops on TERM before the first poll
stop_case quick 1
check "shutdown[quick]: TERM not sent once" [ "$(sc_count -TERM)" -eq 1 ]
check "shutdown[quick]: KILL sent after the loop stopped" [ "$(sc_count -KILL)" -eq 0 ]
# stops after a few polls
stop_case polls 4
check "shutdown[polls]: TERM not sent once" [ "$(sc_count -TERM)" -eq 1 ]
check "shutdown[polls]: KILL sent after the loop stopped" [ "$(sc_count -KILL)" -eq 0 ]
# stops right after the last poll of the 10 s budget: the old unconditional KILL case
stop_case last-moment 11
check "shutdown[last-moment]: the 10 s poll budget was not used" [ "$(grep -c '^-0 999999 alive$' "$SC_KILLS")" -eq 11 ]
check "shutdown[last-moment]: KILL sent although kill -0 failed" [ "$(sc_count -KILL)" -eq 0 ]
# never stops: exactly one KILL, as the last call
stop_case stubborn 1000
check "shutdown[stubborn]: KILL not sent exactly once" [ "$(sc_count -KILL)" -eq 1 ]
check "shutdown[stubborn]: KILL is not the last kill call" [ "$(tail -n 1 "$SC_KILLS")" = "-KILL 999999" ]
# no cleanup loop started (no oc-upgrade): no kill call at all
stop_case none 1000 ""
check "shutdown[none]: kill called without a cleanup PID: $(tr '\n' ',' < "$SC_KILLS")" [ ! -s "$SC_KILLS" ]

if [ "$KNOWN_BUGS" -gt 0 ]; then
  echo "known bugs (skipped, see KNOWN-BUG lines): $KNOWN_BUGS"
fi
echo "wrapper: $WRAPPER_PASS passed, $WRAPPER_FAIL failed; total: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
