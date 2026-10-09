#!/usr/bin/env bash
# Add-on wrapper for the `openclaw` CLI (installed first in PATH by run.sh).
#
# The add-on image pins the OpenClaw version, and upgrades between OpenClaw
# release lines run one-way state migrations that need the add-on's backup and
# migration steps. `openclaw update` would bypass all of that (and install into
# the container layer, where the next image update silently replaces it again),
# so it is refused here. Everything else is passed through unchanged via `exec`,
# so no extra process is left behind for run.sh's gateway detection to see.
set -u

self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Resolve the real CLI: the next `openclaw` on PATH that is not this wrapper.
real=""
IFS=: read -r -a path_dirs <<< "${PATH:-}"
for d in "${path_dirs[@]}"; do
  [ -n "$d" ] || continue
  resolved="$(cd "$d" 2>/dev/null && pwd -P)" || continue
  [ "$resolved" = "$self_dir" ] && continue
  if [ -f "$d/openclaw" ] && [ -x "$d/openclaw" ]; then
    real="$d/openclaw"
    break
  fi
done
if [ -z "$real" ]; then
  echo "openclaw: CLI not found on PATH" >&2
  exit 127
fi

# Find the command word, skipping OpenClaw's root options
# (--dev, --no-color, --profile/--log-level/--container [value]).
args=("$@")
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

exec "$real" "$@"
