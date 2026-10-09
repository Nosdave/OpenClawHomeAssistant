#!/usr/bin/env bash
# Add-on wrapper for the `openclaw` CLI.
#
# At image build time every `openclaw` executable on PATH is replaced by a
# symlink to this script, and the path of the pinned package entry
# (<npm root -g>/openclaw/openclaw.mjs) is recorded next to it. So whoever
# runs `openclaw` — run.sh, the web terminal, or a tool the agent executes with
# its own PATH — gets this wrapper.
#
# The image pins the OpenClaw version, and upgrades between OpenClaw release
# lines run one-way state migrations that need the add-on's backup and migration
# steps. So the wrapper refuses:
#   - `openclaw update` (also spelled `openclaw --update ...`): it would bypass
#     the image pin and every add-on safety step. Always refused.
#   - a writing `openclaw doctor` (anything but --lint/--json/--post-upgrade/
#     --help) on OpenClaw 2026.8+: doctor migrates config and state without an
#     archive. The add-on's migration gate runs it (`oc-upgrade retry --doctor`).
#   - while the add-on holds OpenClaw (hold.txt present), every command except
#     a small read-only allow-list.
# OC_ADDON_UNSAFE=1 bypasses the doctor and HOLD checks (support-guided
# recovery only). Everything that is allowed is exec'd unchanged — no extra
# process is left behind for run.sh's gateway detection to see. The migration
# gate calls the package entry with node directly and never comes through here.
set -u

# The directory this wrapper was installed into (the image installs it as
# /usr/local/libexec/oc-addon/openclaw, next to the files it reads).
self="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || true)"
OC_ADDON_DIR="$(dirname "${self:-/usr/local/libexec/oc-addon/openclaw}")"
UPG_DIR="${OC_UPGRADE_DIR:-/config/.openclaw-upgrade}"

entry="$(head -n 1 "${OC_ADDON_DIR}/openclaw-entry" 2>/dev/null || true)"
if [ -z "$entry" ] || [ ! -f "$entry" ]; then
  echo "openclaw: package entry not found (expected path in ${OC_ADDON_DIR}/openclaw-entry)" >&2
  exit 127
fi
node_bin="$(command -v node 2>/dev/null || true)"
if [ -z "$node_bin" ]; then
  echo "openclaw: node not found on PATH" >&2
  exit 127
fi

# Find the command word the way OpenClaw does: skip root options
# (--dev, --no-color, --profile/--log-level/--container [value]); OpenClaw also
# rewrites the first `--update` anywhere in argv to the `update` command.
args=("$@")
for j in "${!args[@]}"; do
  if [ "${args[$j]}" = "--update" ]; then
    args[j]="update"
    break
  fi
done
cmd=""
cmd_index=-1
i=0
while [ "$i" -lt "${#args[@]}" ]; do
  a="${args[$i]}"
  case "$a" in
    --)
      if [ $((i + 1)) -lt "${#args[@]}" ]; then
        cmd="${args[$((i + 1))]}"
        cmd_index=$((i + 1))
      fi
      break
      ;;
    --profile|--log-level|--container)
      next="${args[$((i + 1))]:-}"
      if [ -n "$next" ] && [ "${next#-}" = "$next" ]; then
        i=$((i + 1))
      fi
      ;;
    -*)
      ;;
    *)
      cmd="$a"
      cmd_index=$i
      break
      ;;
  esac
  i=$((i + 1))
done

# Arguments after the command word.
rest=()
if [ "$cmd_index" -ge 0 ]; then
  rest=("${args[@]:$((cmd_index + 1))}")
fi

if [ "$cmd" = "update" ]; then
  cat >&2 <<'EOF'
openclaw update is disabled in this Home Assistant add-on.

The add-on image pins the OpenClaw version. Moving to a newer OpenClaw line runs
one-way database migrations, which the add-on performs itself with a verified
backup first. Update the add-on in Home Assistant instead
(Settings -> Add-ons -> OpenClaw Assistant), after creating a backup.

Read-only upgrade check:  oc-upgrade check
EOF
  exit 2
fi

if [ "${OC_ADDON_UNSAFE:-}" = "1" ]; then
  echo "openclaw: OC_ADDON_UNSAFE=1 — add-on safety checks bypassed" >&2
  exec "$node_bin" "$entry" "$@"
fi

# True when `rest` contains one of the given flags (also as --flag=value).
# Flags after a bare `--` are positional arguments and do not count.
rest_has_flag() {
  local r f
  for r in ${rest[@]+"${rest[@]}"}; do
    [ "$r" = "--" ] && return 1
    for f in "$@"; do
      if [ "$r" = "$f" ] || [ "${r%%=*}" = "$f" ]; then
        return 0
      fi
    done
  done
  return 1
}

# A doctor run that only reads: it asks for lint/JSON/post-upgrade output or
# help, and carries no flag that writes or repairs.
doctor_is_read_only() {
  local r f
  # Write flags count anywhere (also after `--`), so scan them first.
  for r in ${rest[@]+"${rest[@]}"}; do
    for f in --fix --repair --yes --force --generate-gateway-token --allow-exec \
             --state-sqlite --session-sqlite --session-sqlite-store \
             --session-sqlite-agent --session-sqlite-all-agents; do
      if [ "$r" = "$f" ] || [ "${r%%=*}" = "$f" ]; then
        return 1
      fi
    done
  done
  rest_has_flag --lint --json --post-upgrade -h --help
}

# First non-option word after the command (the subcommand).
subcommand() {
  local r
  for r in ${rest[@]+"${rest[@]}"}; do
    case "$r" in
      --) return 0 ;;
      -*) ;;
      *) printf '%s' "$r"; return 0 ;;
    esac
  done
  return 0
}

hold_allows() {
  local sub
  case "$cmd" in
    "")
      # Bare `openclaw` may start an interactive flow; only version/help.
      local a
      for a in "$@"; do
        case "$a" in
          --version|-V|-v|--help|-h) return 0 ;;
        esac
      done
      return 1
      ;;
    help|logs)
      return 0
      ;;
    doctor)
      doctor_is_read_only
      return
      ;;
    config)
      sub="$(subcommand)"
      case "$sub" in
        validate|get|file|schema) return 0 ;;
        "") rest_has_flag -h --help; return ;;
      esac
      return 1
      ;;
    database)
      sub="$(subcommand)"
      case "$sub" in
        preflight|preflight-agent) return 0 ;;
        "") rest_has_flag -h --help; return ;;
      esac
      return 1
      ;;
  esac
  return 1
}

if [ -e "${UPG_DIR}/hold.txt" ] && ! hold_allows "$@"; then
  cat >&2 <<'EOF'
openclaw: the add-on is holding OpenClaw (see: oc-upgrade status). Only read-only commands are allowed.
After fixing the cause: oc-upgrade retry   (then restart the add-on)
EOF
  exit 2
fi

# The writing doctor is refused on the OpenClaw lines the migration gate runs
# (2026.8+; an unknown pinned version counts as such). 2026.7.x keeps the old
# behaviour.
pinned="$(head -n 1 "${OC_ADDON_DIR}/openclaw-pinned-version" 2>/dev/null || true)"
pinned="${pinned%%-*}"
doctor_guarded=true
if [ -n "$pinned" ] && [ "$(printf '%s\n%s\n' "2026.8.0" "$pinned" | sort -V | head -n 1)" != "2026.8.0" ]; then
  doctor_guarded=false
fi

if [ "$cmd" = "doctor" ] && [ "$doctor_guarded" = "true" ] && ! doctor_is_read_only; then
  cat >&2 <<'EOF'
openclaw doctor (without --lint/--json/--post-upgrade) migrates config and state and is not run by hand in this add-on.
Run: oc-upgrade retry --doctor   and restart the add-on — it archives the state first, then runs doctor --fix twice with checks.
Read-only check: openclaw doctor --lint
EOF
  exit 2
fi

exec "$node_bin" "$entry" "$@"
