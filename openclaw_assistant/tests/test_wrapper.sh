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
mkdir -p "$T/oc-addon" "$T/pkg" "$T/bin" "$T/fakebin" "$T/upg"
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

OC="$T/bin/openclaw"
HOLD_FILE="$T/upg/hold.txt"
EXTRA_ENV=()

# Run the wrapper with a controlled environment; sets OUT, ERR, RC.
invoke() {
  OUT="$(env -u OC_ADDON_UNSAFE PATH="$T/fakebin:/usr/bin:/bin" OC_UPGRADE_DIR="$T/upg" \
           ${EXTRA_ENV[@]+"${EXTRA_ENV[@]}"} "$OC" "$@" 2>"$T/stderr")"
  RC=$?
  ERR="$(cat "$T/stderr")"
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
runtime_at_least() { return 0; }
EOF
  extract_function enter_hold
  # the real 600 s / 30 s budget, shortened for the test
  printf '%s\n' "$plan_block" | sed 's/timeout --kill-after=30 600 /timeout --kill-after=1 1 /'
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
  grep -qxF "WARN: gateway still stopping after 60 s (9.9 waits for plugin cleanup; up to 270 s)" "$T/stop/stubborn.log"
check "shutdown: 60 s warning not printed exactly once" \
  [ "$(grep -c 'still stopping after 60 s' "$T/stop/stubborn.log")" -eq 1 ]
check "shutdown: no SIGKILL at 270 s" grep -q "did not stop within 270 s; sending SIGKILL" "$T/stop/stubborn.log"
check "shutdown: stubborn run did not finish" grep -q "RESULT stopped" "$T/stop/stubborn.log"
env STUBBORN=0 bash "$T/stop/runner.sh" > "$T/stop/quick.log" 2>&1 || true
check "shutdown: quick stop warned" bash -c "! grep -q 'still stopping' '$T/stop/quick.log'"
check "shutdown: quick stop did not finish" grep -q "RESULT stopped" "$T/stop/quick.log"

echo "wrapper: $WRAPPER_PASS passed, $WRAPPER_FAIL failed; total: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
