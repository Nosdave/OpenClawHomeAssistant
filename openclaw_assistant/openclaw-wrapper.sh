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
# steps. `openclaw update` (also spelled `openclaw --update ...`) would bypass all
# of that, so it is refused. Everything else is exec'd unchanged — no extra
# process is left behind for run.sh's gateway detection to see.
set -u

OC_ADDON_DIR="/usr/local/libexec/oc-addon"

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
i=0
while [ "$i" -lt "${#args[@]}" ]; do
  a="${args[$i]}"
  case "$a" in
    --)
      cmd="${args[$((i + 1))]:-}"
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
      break
      ;;
  esac
  i=$((i + 1))
done

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

exec "$node_bin" "$entry" "$@"
