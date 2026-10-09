#!/usr/bin/env bash
set -euo pipefail

# Ensure Homebrew and brew-installed binaries are in PATH
# This is needed for OpenClaw skills that depend on CLI tools (gemini, aider, etc.)
export PATH="/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:${PATH}"

# Home Assistant add-on options are usually rendered to /data/options.json
OPTIONS_FILE="/data/options.json"

if [ ! -f "$OPTIONS_FILE" ]; then
  echo "Missing $OPTIONS_FILE (add-on options)."
  exit 1
fi

read_json_bool() {
  local key="$1"
  local default_bool="$2"
  jq -r --arg key "$key" --argjson default_bool "$default_bool" '
    if .[$key] == null then $default_bool else .[$key] end
  ' "$OPTIONS_FILE"
}

# ------------------------------------------------------------------------------
# Read add-on options (only add-on-specific knobs; OpenClaw is configured via onboarding)
# ------------------------------------------------------------------------------

TZNAME=$(jq -r '.timezone // "Europe/Sofia"' "$OPTIONS_FILE")
GW_PUBLIC_URL=$(jq -r '.gateway_public_url // empty' "$OPTIONS_FILE")
HA_TOKEN=$(jq -r '.homeassistant_token // empty' "$OPTIONS_FILE")
ADDON_HTTP_PROXY=$(jq -r '.http_proxy // empty' "$OPTIONS_FILE")
ENABLE_TERMINAL=$(read_json_bool enable_terminal true)
TERMINAL_PORT_RAW=$(jq -r '.terminal_port // 7681' "$OPTIONS_FILE")

# SECURITY: Validate TERMINAL_PORT to prevent nginx config injection
# Only allow numeric values in valid port range (1024-65535)
if [[ "$TERMINAL_PORT_RAW" =~ ^[0-9]+$ ]] && [ "$TERMINAL_PORT_RAW" -ge 1024 ] && [ "$TERMINAL_PORT_RAW" -le 65535 ]; then
  TERMINAL_PORT="$TERMINAL_PORT_RAW"
else
  echo "ERROR: Invalid terminal_port '$TERMINAL_PORT_RAW'. Must be numeric 1024-65535. Using default 7681."
  TERMINAL_PORT="7681"
fi

echo "DEBUG: enable_terminal config value: '$ENABLE_TERMINAL'"
echo "DEBUG: terminal_port config value: '$TERMINAL_PORT' (validated)"

# Generic router SSH settings
ROUTER_HOST=$(jq -r '.router_ssh_host // empty' "$OPTIONS_FILE")
ROUTER_USER=$(jq -r '.router_ssh_user // empty' "$OPTIONS_FILE")
ROUTER_KEY=$(jq -r '.router_ssh_key_path // "/data/keys/router_ssh"' "$OPTIONS_FILE")

# Optional: allow disabling lock cleanup if you ever need to debug
CLEAN_LOCKS_ON_START=$(read_json_bool clean_session_locks_on_start true)
CLEAN_LOCKS_ON_EXIT=$(read_json_bool clean_session_locks_on_exit true)
PERSIST_NODE_GLOBAL=$(read_json_bool persist_node_global false)
PERSIST_BREW_TOOLS=$(read_json_bool persist_brew_tools false)

# Gateway configuration
GATEWAY_MODE=$(jq -r '.gateway_mode // "local"' "$OPTIONS_FILE")
GATEWAY_REMOTE_URL=$(jq -r '.gateway_remote_url // empty' "$OPTIONS_FILE")
GATEWAY_BIND_MODE=$(jq -r '.gateway_bind_mode // "loopback"' "$OPTIONS_FILE")
GATEWAY_PORT=$(jq -r '.gateway_port // 18789' "$OPTIONS_FILE")
ENABLE_OPENAI_API=$(read_json_bool enable_openai_api false)
GATEWAY_AUTH_MODE=$(jq -r '.gateway_auth_mode // "token"' "$OPTIONS_FILE")
GATEWAY_TRUSTED_PROXIES=$(jq -r '.gateway_trusted_proxies // empty' "$OPTIONS_FILE")
GATEWAY_ADDITIONAL_ALLOWED_ORIGINS=$(jq -r '.gateway_additional_allowed_origins // empty' "$OPTIONS_FILE")
CONTROLUI_DISABLE_DEVICE_AUTH=$(read_json_bool controlui_disable_device_auth true)
FORCE_IPV4_DNS=$(read_json_bool force_ipv4_dns true)
ACCESS_MODE=$(jq -r '.access_mode // "custom"' "$OPTIONS_FILE")
NGINX_LOG_LEVEL=$(jq -r '.nginx_log_level // "minimal"' "$OPTIONS_FILE")
AUTO_CONFIGURE_MCP=$(read_json_bool auto_configure_mcp false)
RESOURCE_PROFILE=$(jq -r '.resource_profile // "auto"' "$OPTIONS_FILE")
HA_HEALTH_SENSORS=$(read_json_bool ha_health_sensors false)
HA_HEALTH_INTERVAL_RAW=$(jq -r '.ha_health_interval // 60' "$OPTIONS_FILE")
HA_BASE_URL=$(jq -r '.ha_base_url // empty' "$OPTIONS_FILE")
CONFIG_BACKUP_KEEP_RAW=$(jq -r '.config_backup_keep // 10' "$OPTIONS_FILE")
GW_ENV_VARS_TYPE=$(jq -r 'if .gateway_env_vars == null then "null" else (.gateway_env_vars | type) end' "$OPTIONS_FILE")
GW_ENV_VARS_RAW=$(jq -r '.gateway_env_vars // empty' "$OPTIONS_FILE")
GW_ENV_VARS_JSON=$(jq -c '.gateway_env_vars // []' "$OPTIONS_FILE")

export TZ="$TZNAME"

# SECURITY/SANITY: validate numeric options before they reach loops or Python.
if [[ "$HA_HEALTH_INTERVAL_RAW" =~ ^[0-9]+$ ]] && [ "$HA_HEALTH_INTERVAL_RAW" -ge 15 ] && [ "$HA_HEALTH_INTERVAL_RAW" -le 3600 ]; then
  HA_HEALTH_INTERVAL="$HA_HEALTH_INTERVAL_RAW"
else
  echo "WARN: Invalid ha_health_interval '$HA_HEALTH_INTERVAL_RAW'. Must be 15-3600. Using default 60."
  HA_HEALTH_INTERVAL="60"
fi

if [[ "$CONFIG_BACKUP_KEEP_RAW" =~ ^[0-9]+$ ]] && [ "$CONFIG_BACKUP_KEEP_RAW" -le 100 ]; then
  CONFIG_BACKUP_KEEP="$CONFIG_BACKUP_KEEP_RAW"
else
  echo "WARN: Invalid config_backup_keep '$CONFIG_BACKUP_KEEP_RAW'. Must be 0-100. Using default 10."
  CONFIG_BACKUP_KEEP="10"
fi
export CONFIG_BACKUP_KEEP

# ------------------------------------------------------------------------------
# Resource profile — keep the add-on well-behaved on low-power Home Assistant
# hardware (Raspberry Pi, low-RAM VMs).
#
# Node sizes its heap against TOTAL HOST memory, which on HAOS is the whole
# machine. Without a cap the gateway happily grows until the OOM killer takes
# it (or Home Assistant itself) down. We give it an explicit, logged budget.
#
# `auto` (default) only ever touches add-on process settings — it never writes
# to openclaw.json, so upgrades cannot silently change agent behavior. An
# explicitly selected `low` additionally applies conservative OpenClaw defaults
# for keys the user has not set (see apply-resource-profile in the helper).
# ------------------------------------------------------------------------------
MEM_TOTAL_MB=$(awk '/^MemTotal:/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
CPU_COUNT=$(nproc 2>/dev/null || echo 1)
HOST_ARCH=$(uname -m 2>/dev/null || echo unknown)

case "$RESOURCE_PROFILE" in
  low|balanced|high) ;;
  auto|"") RESOURCE_PROFILE="auto" ;;
  *)
    echo "WARN: Invalid resource_profile '$RESOURCE_PROFILE'; falling back to auto."
    RESOURCE_PROFILE="auto"
    ;;
esac

RESOURCE_PROFILE_SOURCE="option"
EFFECTIVE_PROFILE="$RESOURCE_PROFILE"

if [ "$RESOURCE_PROFILE" = "auto" ]; then
  RESOURCE_PROFILE_SOURCE="auto-detected"
  case "$HOST_ARCH" in
    armv6*|armv7*)
      # 32-bit ARM is Pi 3 / Pi Zero class hardware regardless of reported RAM.
      EFFECTIVE_PROFILE="low"
      ;;
    *)
      if [ "$MEM_TOTAL_MB" -gt 0 ] && [ "$MEM_TOTAL_MB" -lt 2048 ]; then
        EFFECTIVE_PROFILE="low"
      elif [ "$MEM_TOTAL_MB" -gt 0 ] && [ "$MEM_TOTAL_MB" -lt 6144 ]; then
        EFFECTIVE_PROFILE="balanced"
      elif [ "$MEM_TOTAL_MB" -eq 0 ]; then
        # Unreadable /proc/meminfo — assume the conservative middle ground.
        EFFECTIVE_PROFILE="balanced"
      else
        EFFECTIVE_PROFILE="high"
      fi
      ;;
  esac
fi

# Heap budget as a share of total RAM, clamped to a sane band per profile.
# `high` intentionally sets no cap so large machines keep Node's own default.
NODE_HEAP_MB=""
case "$EFFECTIVE_PROFILE" in
  low)      HEAP_PCT=35; HEAP_MIN=256; HEAP_MAX=768 ;;
  balanced) HEAP_PCT=45; HEAP_MIN=768; HEAP_MAX=2048 ;;
  high)     HEAP_PCT=0;  HEAP_MIN=0;   HEAP_MAX=0 ;;
esac

if [ "$HEAP_PCT" -gt 0 ]; then
  NODE_HEAP_MB=$(( MEM_TOTAL_MB * HEAP_PCT / 100 ))
  if [ "$NODE_HEAP_MB" -lt "$HEAP_MIN" ]; then
    NODE_HEAP_MB="$HEAP_MIN"
  fi
  if [ "$NODE_HEAP_MB" -gt "$HEAP_MAX" ]; then
    NODE_HEAP_MB="$HEAP_MAX"
  fi
  if [ -n "${NODE_OPTIONS:-}" ]; then
    export NODE_OPTIONS="${NODE_OPTIONS} --max-old-space-size=${NODE_HEAP_MB}"
  else
    export NODE_OPTIONS="--max-old-space-size=${NODE_HEAP_MB}"
  fi
fi

echo "INFO: Resource profile: ${EFFECTIVE_PROFILE} (${RESOURCE_PROFILE_SOURCE}); host: ${MEM_TOTAL_MB} MB RAM, ${CPU_COUNT} CPU, ${HOST_ARCH}"
if [ -n "$NODE_HEAP_MB" ]; then
  echo "INFO: Node heap limit for OpenClaw: ${NODE_HEAP_MB} MB (--max-old-space-size)"
else
  echo "INFO: Node heap limit: unset (profile 'high' leaves Node's own default in place)"
fi

if [ "$EFFECTIVE_PROFILE" = "low" ]; then
  echo "NOTICE: Low-resource profile active. The heaviest optional components are"
  echo "NOTICE: Chromium (browser automation) and node-llama-cpp (local embeddings)."
  if [ "$RESOURCE_PROFILE" != "low" ]; then
    echo "NOTICE: Set resource_profile=low explicitly to also disable browser automation"
    echo "NOTICE: in OpenClaw, or disable it yourself with: openclaw config set browser.enabled false"
  fi
fi

export RESOURCE_PROFILE EFFECTIVE_PROFILE NODE_HEAP_MB

# ------------------------------------------------------------------------------
# Access mode presets — override individual gateway settings for common scenarios
# ------------------------------------------------------------------------------
ENABLE_HTTPS_PROXY=false
GATEWAY_INTERNAL_PORT="$GATEWAY_PORT"

case "$ACCESS_MODE" in
  local_only)
    GATEWAY_BIND_MODE="loopback"
    GATEWAY_AUTH_MODE="token"
    echo "INFO: Access mode: local_only (loopback + token, Ingress/terminal only)"
    ;;
  lan_https)
    # Gateway binds loopback on internal port; nginx terminates TLS on the external port.
    GATEWAY_BIND_MODE="loopback"
    GATEWAY_AUTH_MODE="token"
    ENABLE_HTTPS_PROXY=true
    GATEWAY_INTERNAL_PORT=$((GATEWAY_PORT + 1))
    # OpenClaw 2026.8.2+ refuses requests that carry forwarded identity headers
    # from a source it does not trust ("proxy_attribution_required"). The
    # built-in HTTPS proxy is our own nginx on loopback and it sets
    # X-Forwarded-For / X-Real-IP / X-Forwarded-Proto, so loopback must be a
    # trusted proxy or every gateway request is rejected. Trusting loopback also
    # lets the gateway attribute the real LAN client IP for rate limiting
    # instead of seeing every request as 127.0.0.1.
    if [ -n "$GATEWAY_TRUSTED_PROXIES" ]; then
      GATEWAY_TRUSTED_PROXIES="127.0.0.1,::1,${GATEWAY_TRUSTED_PROXIES}"
    else
      GATEWAY_TRUSTED_PROXIES="127.0.0.1,::1"
    fi
    echo "INFO: Access mode: lan_https (built-in HTTPS proxy on 0.0.0.0:${GATEWAY_PORT})"
    echo "INFO: Trusting loopback as a proxy so the gateway can attribute LAN clients."
    ;;
  lan_reverse_proxy)
    GATEWAY_BIND_MODE="lan"
    GATEWAY_AUTH_MODE="trusted-proxy"
    if [ -z "$GATEWAY_TRUSTED_PROXIES" ]; then
      echo "ERROR: access_mode=lan_reverse_proxy requires gateway_trusted_proxies to be set."
      echo "ERROR: Set it to your reverse proxy's IP/CIDR (e.g. 127.0.0.1,192.168.88.0/24)."
    fi
    echo "INFO: Access mode: lan_reverse_proxy (LAN bind + trusted-proxy auth)"
    ;;
  tailnet_https)
    GATEWAY_BIND_MODE="tailnet"
    GATEWAY_AUTH_MODE="token"
    echo "INFO: Access mode: tailnet_https (Tailscale bind + token auth)"
    ;;
  custom|*)
    echo "INFO: Access mode: custom (using individual gateway_bind_mode/auth_mode settings)"
    ;;
esac

# Reduce risk of secrets ending up in logs
set +x

# Optional outbound proxy from add-on settings.
# If set, apply it to both HTTP and HTTPS for Node/undici/OpenClaw tooling.
if [ -n "$ADDON_HTTP_PROXY" ]; then
  if [[ "$ADDON_HTTP_PROXY" =~ ^https?://[^[:space:]]+$ ]]; then
    # Keep local traffic direct to avoid accidental proxying of loopback/LAN services.
    DEFAULT_NO_PROXY="localhost,127.0.0.1,::1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,.local"

    export HTTP_PROXY="$ADDON_HTTP_PROXY"
    export HTTPS_PROXY="$ADDON_HTTP_PROXY"
    export http_proxy="$ADDON_HTTP_PROXY"
    export https_proxy="$ADDON_HTTP_PROXY"
    export NO_PROXY="${NO_PROXY:+${NO_PROXY},}${DEFAULT_NO_PROXY}"
    export no_proxy="${no_proxy:+${no_proxy},}${DEFAULT_NO_PROXY}"
    echo "INFO: Outbound HTTP/HTTPS proxy enabled from add-on configuration."
    echo "INFO: Applied NO_PROXY defaults for localhost/private network ranges."
  else
    echo "WARN: Invalid http_proxy value in add-on options; expected URL like http://host:port"
  fi
fi

# Optional network hardening/workaround: force IPv4-first DNS ordering for Node.js.
# Helps in environments where IPv6 resolves but has no working egress.
if [ "$FORCE_IPV4_DNS" = "true" ] || [ "$FORCE_IPV4_DNS" = "1" ]; then
  if [ -n "${NODE_OPTIONS:-}" ]; then
    export NODE_OPTIONS="${NODE_OPTIONS} --dns-result-order=ipv4first"
  else
    export NODE_OPTIONS="--dns-result-order=ipv4first"
  fi
  echo "INFO: Enabled IPv4-first DNS ordering (NODE_OPTIONS=--dns-result-order=ipv4first)"
fi

# HA add-ons mount persistent storage at /config (maps to /addon_configs/<slug> on the host).
export HOME=/config

# Explicitly set OpenClaw directories to ensure they persist across add-on updates
# This prevents loss of installed skills, configuration, and workspace state
export OPENCLAW_CONFIG_DIR=/config/.openclaw
export OPENCLAW_WORKSPACE_DIR=/config/clawd
export XDG_CONFIG_HOME=/config

mkdir -p /config/.openclaw /config/.openclaw/identity /config/clawd /config/keys /config/secrets

warn_legacy_persistent_dir() {
  local path="$1"
  local label="$2"
  if [ -e "$path" ]; then
    echo "WARN: Found legacy persistent ${label} at ${path}, but persistence is disabled."
    case "$path" in
      */.linuxbrew)
        # Fork: .linuxbrew is not in backup_exclude (persist_brew_tools defaults to true).
        echo "WARN: It is still included in Home Assistant backups and uses disk space."
        ;;
      *)
        echo "WARN: It is excluded from Home Assistant backups, but still uses disk space."
        ;;
    esac
    echo "WARN: Remove it with: rm -rf ${path}"
  fi
}

# ------------------------------------------------------------------------------
# Sync built-in OpenClaw skills from image to persistent storage
# On each startup, copy new/updated built-in skills so they survive rebuilds.
# We sync them to /config/.openclaw/skills and symlink back.
# NOTE: We cannot use `npm root -g` here because HOME=/config may contain a
# persisted .npmrc with a custom prefix from a previous run. Instead, we
# resolve the real image path by temporarily overriding HOME.
# ------------------------------------------------------------------------------
IMAGE_SKILLS_DIR="$(HOME=/root npm root -g 2>/dev/null)/openclaw/skills"
PERSISTENT_SKILLS_DIR="/config/.openclaw/skills"

if [ -d "$IMAGE_SKILLS_DIR" ] && [ ! -L "$IMAGE_SKILLS_DIR" ]; then
  mkdir -p "$PERSISTENT_SKILLS_DIR"
  # Sync skills: --update replaces older files so upgrades propagate,
  # but doesn't delete user-added files in persistent storage.
  if command -v rsync >/dev/null 2>&1; then
    rsync -a --update "$IMAGE_SKILLS_DIR/" "$PERSISTENT_SKILLS_DIR/" 2>/dev/null || true
  else
    cp -ru "$IMAGE_SKILLS_DIR/"* "$PERSISTENT_SKILLS_DIR/" 2>/dev/null || true
  fi
  # Replace image skills dir with symlink to persistent copy
  rm -rf "$IMAGE_SKILLS_DIR"
  ln -sf "$PERSISTENT_SKILLS_DIR" "$IMAGE_SKILLS_DIR"
  echo "INFO: Synced built-in skills to persistent storage at $PERSISTENT_SKILLS_DIR"
elif [ -L "$IMAGE_SKILLS_DIR" ]; then
  echo "INFO: Built-in skills already linked to persistent storage"
else
  echo "WARN: Built-in skills directory not found at $IMAGE_SKILLS_DIR"
fi

# ------------------------------------------------------------------------------
# Optional persistence for user-installed node skills across Docker image rebuilds.
# When enabled, redirect npm/pnpm global installs to /config/.node_global so
# dashboard-installed skills survive image updates. Disabled by default to keep
# Home Assistant backups smaller.
# NOTE: This MUST come after the skills sync above (which needs the original npm root -g).
# ------------------------------------------------------------------------------
PERSISTENT_NODE_GLOBAL="/config/.node_global"
if [ "$PERSIST_NODE_GLOBAL" = "true" ] || [ "$PERSIST_NODE_GLOBAL" = "1" ]; then
  mkdir -p "$PERSISTENT_NODE_GLOBAL"
  npm config set prefix "$PERSISTENT_NODE_GLOBAL" 2>/dev/null || true
  export PATH="${PERSISTENT_NODE_GLOBAL}/bin:${PATH}"
  export NODE_PATH="${PERSISTENT_NODE_GLOBAL}/lib/node_modules:${NODE_PATH:-}"

  # Also configure pnpm global dir to persistent storage
  export PNPM_HOME="${PERSISTENT_NODE_GLOBAL}/pnpm"
  mkdir -p "$PNPM_HOME"
  export PATH="${PNPM_HOME}:${PATH}"
  echo "INFO: persist_node_global=true; user-installed npm skills will survive add-on rebuilds."
else
  npm config delete prefix 2>/dev/null || true
  export npm_config_prefix="/usr/local"
  export PNPM_HOME="/tmp/.pnpm-home"
  mkdir -p "$PNPM_HOME"
  export PATH="${PNPM_HOME}:${PATH}"
  warn_legacy_persistent_dir "$PERSISTENT_NODE_GLOBAL" "node global tool/skill data"
  echo "INFO: persist_node_global=false; npm/pnpm global installs are ephemeral and excluded from HA backups."
fi

# The add-on's `openclaw` wrapper goes first on PATH (for run.sh and the web
# terminal it spawns): it refuses `openclaw update` — the image pins the
# OpenClaw version and line upgrades need the add-on's backup/migration steps —
# and execs the real CLI for everything else.
OC_ADDON_BIN="/usr/local/libexec/oc-addon"
if [ -x "${OC_ADDON_BIN}/openclaw" ]; then
  export PATH="${OC_ADDON_BIN}:${PATH}"
fi

# Protect critical runtime variables from accidental override via gateway_env_vars.
is_reserved_gateway_env_var() {
  case "$1" in
    # Critical runtime paths/process vars.
    HOME|PATH|PWD|OLDPWD|SHLVL|TZ|XDG_CONFIG_HOME|PNPM_HOME|NODE_PATH|NODE_OPTIONS|NODE_NO_WARNINGS)
      return 0
      ;;
    # Low-level injection vectors that can alter process/linker/shell behavior.
    LD_*|DYLD_*|BASH_ENV|ENV|BASH_FUNC_*)
      return 0
      ;;
    # Proxy vars managed by add-on options.
    HTTP_PROXY|HTTPS_PROXY|NO_PROXY|http_proxy|https_proxy|no_proxy)
      return 0
      ;;
    # Add-on internal control vars (OC_GATE_* holds the migration gate's test
    # hooks, OC_ADDON_UNSAFE the wrapper escape, OC_UPGRADE_DIR the HOLD
    # marker location the wrapper checks).
    OPENCLAW_*|OC_GATE_*|OC_ADDON_*|OC_UPGRADE_*|OC_CONFIG_ROOT)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

try_export_gateway_env_var() {
  local key="$1"
  local value="$2"

  if [ -z "$key" ]; then
    return 0
  fi

  # Validate variable name format
  if ! [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "WARN: Invalid environment variable name: '$key' (must start with letter/underscore, skip)"
    return 0
  fi

  # Protect critical runtime variables from accidental override.
  if is_reserved_gateway_env_var "$key"; then
    echo "WARN: Reserved environment variable '$key' cannot be overridden via gateway_env_vars (skip)"
    return 0
  fi

  # Enforce max variable name length
  if [ ${#key} -gt $max_var_name_size ]; then
    echo "WARN: Environment variable name too long: '$key' (max $max_var_name_size chars, skip)"
    return 0
  fi

  # Enforce max variable value length
  if [ ${#value} -gt $max_var_value_size ]; then
    echo "WARN: Environment variable value too long for '$key' (max $max_var_value_size chars, skip)"
    return 0
  fi

  # Enforce limit on number of variables
  if [ $env_count -ge $max_env_vars ]; then
    echo "WARN: Maximum environment variables limit ($max_env_vars) reached (skip)"
    return 0
  fi

  export "$key=$value"
  env_count=$((env_count + 1))
  echo "INFO: Exported gateway env var: $key"
}

# Export gateway environment variables from add-on config
# These are user-defined variables that should be available to the gateway process.
# Primary format: array of {name, value} objects.
if [ "$GW_ENV_VARS_TYPE" = "array" ] || [ "$GW_ENV_VARS_TYPE" = "object" ] || { [ "$GW_ENV_VARS_TYPE" = "string" ] && [ -n "$GW_ENV_VARS_RAW" ]; }; then
  env_count=0
  max_env_vars=50
  max_var_name_size=255
  max_var_value_size=10000

  if [ "$GW_ENV_VARS_TYPE" = "array" ] && [ "$GW_ENV_VARS_JSON" != "[]" ]; then
    echo "INFO: Setting gateway environment variables from list config..."

    invalid_entries_count=$(printf '%s' "$GW_ENV_VARS_JSON" | jq '[.[] | select((type != "object") or ((.name | type) != "string") or (has("value") | not))] | length')
    if [ "$invalid_entries_count" -gt 0 ]; then
      echo "WARN: Found $invalid_entries_count invalid gateway_env_vars entries; expected objects with 'name' and 'value' keys (skip)"
    fi

    while IFS= read -r -d '' key && IFS= read -r -d '' value; do
      try_export_gateway_env_var "$key" "$value"
    done < <(printf '%s' "$GW_ENV_VARS_JSON" | jq -j '.[] | select((type == "object") and ((.name | type) == "string") and (has("value"))) | .name, "\u0000", (.value | tostring), "\u0000"')
  elif [ "$GW_ENV_VARS_TYPE" = "object" ] && [ "$GW_ENV_VARS_JSON" != "{}" ]; then
    # Backward compatibility for old map/object configuration.
    echo "INFO: Setting gateway environment variables from object config (legacy format)..."
    while IFS= read -r -d '' key && IFS= read -r -d '' value; do
      try_export_gateway_env_var "$key" "$value"
    done < <(printf '%s' "$GW_ENV_VARS_JSON" | jq -j 'to_entries[] | .key, "\u0000", (.value | tostring), "\u0000"')
  elif [ "$GW_ENV_VARS_TYPE" = "string" ] && [ -n "$GW_ENV_VARS_RAW" ]; then
    # Preferred for complex values: JSON object string in one line.
    if printf '%s' "$GW_ENV_VARS_RAW" | jq -e 'type == "object"' >/dev/null 2>&1; then
      echo "INFO: Setting gateway environment variables from JSON string config..."
      while IFS= read -r -d '' key && IFS= read -r -d '' value; do
        try_export_gateway_env_var "$key" "$value"
      done < <(printf '%s' "$GW_ENV_VARS_RAW" | jq -j 'to_entries[] | .key, "\u0000", (.value | tostring), "\u0000"')
    else
      # Supported simple format: KEY=VALUE pairs separated by ';' or newlines.
      echo "INFO: Setting gateway environment variables from KEY=VALUE string config..."
      while IFS= read -r entry; do
        entry="${entry%$'\r'}"
        trimmed="$(printf '%s' "$entry" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"

        # Skip empty lines and comments.
        if [ -z "$trimmed" ] || [[ "$trimmed" == \#* ]]; then
          continue
        fi

        if [[ "$trimmed" != *"="* ]]; then
          echo "WARN: Invalid gateway_env_vars entry '$trimmed' (expected KEY=VALUE, skip)"
          continue
        fi

        key="${trimmed%%=*}"
        value="${trimmed#*=}"
        key="$(printf '%s' "$key" | sed -E 's/^[[:space:]]+//;s/[[:space:]]+$//')"

        try_export_gateway_env_var "$key" "$value"
      done < <(printf '%s' "$GW_ENV_VARS_RAW" | tr ';' '\n')
    fi
  fi

  if [ $env_count -gt 0 ]; then
    echo "INFO: Successfully exported $env_count gateway environment variable(s)"
  fi
elif [ "$GW_ENV_VARS_TYPE" != "null" ]; then
  echo "WARN: Invalid gateway_env_vars format in add-on options (expected list, string or object), skipping"
fi

# ------------------------------------------------------------------------------
# Optional persistence for Linuxbrew/Homebrew across Docker image rebuilds.
# When enabled, sync /home/linuxbrew/.linuxbrew to /config/.linuxbrew so
# brew-installed CLI tools survive image updates. Disabled by default to keep
# Home Assistant backups smaller.
# ------------------------------------------------------------------------------
IMAGE_BREW_DIR="/home/linuxbrew/.linuxbrew"
PERSISTENT_BREW_DIR="/config/.linuxbrew"

if [ "$PERSIST_BREW_TOOLS" = "true" ] || [ "$PERSIST_BREW_TOOLS" = "1" ]; then
  if [ -d "$IMAGE_BREW_DIR" ] && [ ! -L "$IMAGE_BREW_DIR" ]; then
    # Image has a real Homebrew install — sync to persistent storage
    if [ -d "$PERSISTENT_BREW_DIR" ]; then
      # Persistent copy exists: sync new/updated files from image (upgrades),
      # but preserve user-installed packages already in persistent storage.
      if command -v rsync >/dev/null 2>&1; then
        rsync -a --update "$IMAGE_BREW_DIR/" "$PERSISTENT_BREW_DIR/" 2>/dev/null || true
      else
        cp -ru "$IMAGE_BREW_DIR/"* "$PERSISTENT_BREW_DIR/" 2>/dev/null || true
      fi
      echo "INFO: Synced Homebrew updates to persistent storage"
    else
      # First time: copy entire Homebrew install to persistent storage
      cp -a "$IMAGE_BREW_DIR" "$PERSISTENT_BREW_DIR" 2>/dev/null || true
      echo "INFO: Copied Homebrew to persistent storage at $PERSISTENT_BREW_DIR"
    fi
    # Replace image dir with symlink to persistent copy
    rm -rf "$IMAGE_BREW_DIR"
    ln -sf "$PERSISTENT_BREW_DIR" "$IMAGE_BREW_DIR"
  elif [ -L "$IMAGE_BREW_DIR" ]; then
    echo "INFO: Homebrew already linked to persistent storage"
  elif [ -d "$PERSISTENT_BREW_DIR" ]; then
    # Image doesn't have Homebrew (failed install?) but persistent copy exists
    mkdir -p "$(dirname "$IMAGE_BREW_DIR")"
    ln -sf "$PERSISTENT_BREW_DIR" "$IMAGE_BREW_DIR"
    echo "INFO: Restored Homebrew symlink from persistent storage"
  else
    echo "INFO: Homebrew not available (install may have failed during image build)"
  fi
  echo "INFO: persist_brew_tools=true; brew-installed tools will survive add-on rebuilds."
else
  warn_legacy_persistent_dir "$PERSISTENT_BREW_DIR" "Homebrew data"
  echo "INFO: persist_brew_tools=false; Homebrew installs stay ephemeral and excluded from HA backups."
fi

# Back-compat: some docs/scripts assume /data; point it at /config.
if [ ! -e /data ]; then
  ln -s /config /data || true
fi

# Ensure the agents base directory exists so cleanup scans work even before first run.
# Do NOT pre-create agent-specific directories; OpenClaw creates them as needed.
mkdir -p /config/.openclaw/agents || true

# ------------------------------------------------------------------------------
# SINGLE-INSTANCE GUARD (prevents multiple gateway runs racing each other)
# ------------------------------------------------------------------------------
STARTUP_LOCK="/config/.openclaw/gateway.start.lock"
exec 9>"$STARTUP_LOCK"
if ! flock -n 9; then
  echo "ERROR: Another instance appears to be running (could not acquire $STARTUP_LOCK)."
  echo "If this is wrong, check for stuck processes or remove the lock file."
  exit 1
fi

# ------------------------------------------------------------------------------
# Early stop handling. `init: false` makes this script PID 1, and PID 1 ignores
# a SIGTERM it has no handler for. Until the full `shutdown` trap is installed
# further down, a stop request is remembered (and forwarded to the migration
# gate, which runs in the background so this trap can fire while it works).
# ------------------------------------------------------------------------------
GATE_PID=""
GATE_WAIT_INTERRUPTED=false
SHUTTING_DOWN="false"
early_stop() {
  SHUTTING_DOWN="true"
  GATE_WAIT_INTERRUPTED=true
  if [ -n "${GATE_PID}" ] && kill -0 "${GATE_PID}" 2>/dev/null; then
    echo "INFO: Stop requested; forwarding SIGTERM to the migration gate (PID ${GATE_PID})."
    kill -TERM "${GATE_PID}" 2>/dev/null || true
  fi
}
trap early_stop INT TERM

# ------------------------------------------------------------------------------
# Upgrade-state backup (OpenClaw 2026.7.x runtimes only)
#
# OpenClaw 2026.8+ migrates the persistent databases one-way (2026.9.9: state
# schema 19, agent schema 24); older OpenClaw builds cannot open them. For those
# runtimes the migration gate (`oc-upgrade gate`, below) owns the pre-migration
# archive: it writes a verified archive to /share/openclaw-upgrade/<run>/ and
# only then runs `openclaw doctor --fix`. The local archive below is kept for
# 2026.7.x runtimes, which perform no schema migration: before the gateway
# starts a version we have not started before, archive the state while the old
# gateway is down. It excludes regenerable/bulky content (skills, media, npm,
# logs and previous archives), but retains the config, SQLite databases
# (including WAL/SHM files), agents, pairing and channel state.
#
# The version marker is written only after a complete archive. A failed backup
# puts the add-on in HOLD (page and terminal stay up) instead of exiting.
# ------------------------------------------------------------------------------
OPENCLAW_UPGRADE_BACKUP_DIR="${OPENCLAW_CONFIG_DIR}/upgrade-backups"
OPENCLAW_UPGRADE_BACKUP_KEEP=3

openclaw_runtime_version() {
  openclaw --version 2>/dev/null | sed -n 's/^OpenClaw \([0-9][0-9.]*\).*/\1/p' | head -n1
}

has_upgrade_sensitive_state() {
  [ -f "${OPENCLAW_CONFIG_DIR}/openclaw.json" ] || \
    [ -d "${OPENCLAW_CONFIG_DIR}/state" ] || \
    { [ -d "${OPENCLAW_CONFIG_DIR}/agents" ] && \
      [ -n "$(find "${OPENCLAW_CONFIG_DIR}/agents" -mindepth 1 -print -quit 2>/dev/null)" ]; }
}

prune_upgrade_backups() {
  local stale
  mapfile -t stale < <(find "$OPENCLAW_UPGRADE_BACKUP_DIR" -maxdepth 1 -type f -name 'openclaw-state-*.tar.gz' -printf '%f\n' 2>/dev/null | sort -r | tail -n +$((OPENCLAW_UPGRADE_BACKUP_KEEP + 1)))
  for stale in "${stale[@]}"; do
    rm -f "${OPENCLAW_UPGRADE_BACKUP_DIR}/${stale}" || \
      echo "WARN: Could not prune old upgrade backup ${stale}."
  done
}

backup_state_before_upgrade() {
  local version marker stamp archive temporary
  version="$(openclaw_runtime_version)"
  if [ -z "$version" ]; then
    echo "ERROR: Could not determine the bundled OpenClaw version; refusing an unprotected startup."
    return 1
  fi

  if ! has_upgrade_sensitive_state; then
    echo "INFO: No existing OpenClaw state; no upgrade-state backup needed."
    return 0
  fi

  if ! mkdir -p "$OPENCLAW_UPGRADE_BACKUP_DIR"; then
    echo "ERROR: Could not create the upgrade-backup directory."
    return 1
  fi
  marker="${OPENCLAW_UPGRADE_BACKUP_DIR}/started-${version}"
  if [ -f "$marker" ]; then
    # The marker holds the archive path. Pruning keeps only the newest archives,
    # so after a rollback to an older version its archive may be gone: take a
    # fresh one instead of trusting a marker that points at nothing.
    local recorded
    recorded="$(head -n 1 "$marker" 2>/dev/null || true)"
    if [ -n "$recorded" ] && [ -f "$recorded" ]; then
      echo "INFO: Upgrade-state backup already recorded for OpenClaw ${version}."
      return 0
    fi
    echo "INFO: Upgrade-state backup for OpenClaw ${version} was pruned; taking a new one."
    rm -f "$marker"
  fi

  stamp="$(date -u +%Y%m%d-%H%M%S)"
  archive="${OPENCLAW_UPGRADE_BACKUP_DIR}/openclaw-state-${stamp}-before-${version}.tar.gz"
  temporary="${archive}.tmp"
  rm -f "$temporary"

  echo "INFO: Creating pre-upgrade state backup for OpenClaw ${version}..."
  if ! tar -C "$OPENCLAW_CONFIG_DIR" \
      --exclude='./upgrade-backups' \
      --exclude='./media' \
      --exclude='./npm' \
      --exclude='./skills' \
      --exclude='./logs' \
      --exclude='./.cache' \
      --exclude='./tmp' \
      -czf "$temporary" .; then
    rm -f "$temporary"
    echo "ERROR: Could not create pre-upgrade state backup."
    return 1
  fi

  if ! mv "$temporary" "$archive"; then
    rm -f "$temporary"
    echo "ERROR: Could not finalize the pre-upgrade state backup."
    return 1
  fi
  chmod 600 "$archive" 2>/dev/null || true
  if ! printf '%s\n' "$archive" > "$marker"; then
    echo "ERROR: Could not record the completed pre-upgrade state backup."
    return 1
  fi
  chmod 600 "$marker" 2>/dev/null || true
  prune_upgrade_backups
  echo "INFO: Saved pre-upgrade state backup: ${archive}."
  return 0
}

# Fork: only refuse to start when the runtime that is about to run can actually
# migrate state (the 2026.8+ lines). The 2026.7.x runtime performs no schema
# migration, so a failed archive there must not take the add-on page and
# terminal down with it. run.sh calls this only for runtimes below 2026.8 (the
# migration gate owns the archive from 2026.8 on); the HOLD branch is a
# fail-closed fallback for an undeterminable runtime version.
require_upgrade_backup() {
  local bundled_version
  if backup_state_before_upgrade; then
    return 0
  fi
  bundled_version="$(openclaw_runtime_version)"
  if [ -n "$bundled_version" ] && \
     [ "$(printf '%s\n%s\n' "2026.8.0" "$bundled_version" | sort -V | head -n 1)" != "2026.8.0" ]; then
    echo "WARN: Pre-upgrade state backup failed; continuing because OpenClaw ${bundled_version} performs no state migration."
    echo "WARN: Free disk space before the next OpenClaw upgrade — that upgrade will refuse to start without this backup."
    return 0
  fi
  enter_hold "Pre-upgrade state backup failed; OpenClaw was not started, so its persistent state remains unchanged.
Free disk space or repair permissions, then restart the add-on."
  return 0
}

# ------------------------------------------------------------------------------
# Runtime environment hardening. Variables that would make OpenClaw believe it
# runs under systemd/launchd, inside an update, or as another host's container
# are dropped for this script and every child (gateway, terminal CLI, migration
# gate). With OPENCLAW_UPDATE_IN_PROGRESS set, for example, doctor exits 0
# having done nothing ("Doctor maintenance deferred").
# ------------------------------------------------------------------------------
unset INVOCATION_ID JOURNAL_STREAM SYSTEMD_EXEC_PID OPENCLAW_SYSTEMD_UNIT OPENCLAW_SERVICE_MARKER \
      OPENCLAW_SERVICE_KIND OPENCLAW_LAUNCHD_LABEL OPENCLAW_CONTAINER NODE_COMPILE_CACHE \
      OPENCLAW_COMPATIBILITY_HOST_VERSION
while IFS= read -r _v; do
  [ -n "$_v" ] && unset "$_v"
done < <(compgen -e | grep '^OPENCLAW_UPDATE_' || true)
unset _v

# Bundled OpenClaw version (keeps a -N patch suffix such as 2026.7.1-2), for
# the state guard and version-dependent config handling in the helpers.
get_openclaw_version() {
  local raw
  raw="$(openclaw --version 2>/dev/null | head -n 1 || true)"
  printf '%s\n' "$raw" | grep -oE '[0-9]{4}\.[0-9]+\.[0-9]+(-[0-9]+)?' | head -n 1 || true
}
OPENCLAW_RUNTIME_VERSION="$(get_openclaw_version)"
export OPENCLAW_RUNTIME_VERSION

# True when the bundled runtime is at least $1 (x.y.z; a -N patch suffix of the
# runtime is ignored). False when the runtime version is unknown.
runtime_at_least() {
  [ -n "${OPENCLAW_RUNTIME_VERSION:-}" ] &&
  [ "$(printf '%s\n%s\n' "$1" "${OPENCLAW_RUNTIME_VERSION%%-*}" | sort -V | head -n1)" = "$1" ]
}

# The image pins the OpenClaw version; never let the gateway apply an update on
# its own (would bypass the image pin and any pre-upgrade backup).
export OPENCLAW_NO_AUTO_UPDATE=1
if runtime_at_least 2026.8.0; then
  # run.sh supervises the gateway: restarts stay in-process (the gateway PID
  # stays our child, and doctor never detaches), and OpenClaw performs no
  # service lifecycle, self-update or AI triage of its own. SUPERVISOR_MODE
  # must never be set without NO_RESPAWN (every restart would then hand off
  # and exit 0).
  export OPENCLAW_NO_RESPAWN=1
  export OPENCLAW_SUPERVISOR_MODE=external
  export OPENCLAW_SERVICE_REPAIR_POLICY=external
  # A stray SIGUSR1 must not open the Node inspector on the host's loopback
  # port 9229 (host_network); OpenClaw 2026.9.6+ restarts on SIGUSR2.
  export NODE_OPTIONS="${NODE_OPTIONS:+${NODE_OPTIONS} }--disable-sigusr1 --disable-warning=ExperimentalWarning"
fi
echo "INFO: OpenClaw runtime version: ${OPENCLAW_RUNTIME_VERSION:-unknown}"

# ------------------------------------------------------------------------------
# Proxy shim for undici/OpenClaw startup
# Keep official OpenClaw npm release while enabling HTTP(S)_PROXY support.
# Set up before anything runs OpenClaw, so the migration gate's doctor (npm and
# OAuth traffic) goes through the configured proxy as well.
# ------------------------------------------------------------------------------
OPENCLAW_GLOBAL_NODE_MODULES="$(HOME=/root npm root -g 2>/dev/null || true)"
if [ -f /usr/local/lib/openclaw-proxy-shim.cjs ]; then
  if [ -n "${NODE_OPTIONS:-}" ]; then
    export NODE_OPTIONS="--require /usr/local/lib/openclaw-proxy-shim.cjs ${NODE_OPTIONS}"
  else
    export NODE_OPTIONS="--require /usr/local/lib/openclaw-proxy-shim.cjs"
  fi
  export OPENCLAW_GLOBAL_NODE_MODULES
fi

# The image routes every `openclaw` executable through the add-on wrapper and
# records the pinned package version. If something inside the container swapped
# the runtime (e.g. an `npm install -g openclaw@...` run by an agent), the
# swapped runtime could migrate the state without the add-on's backup steps.
runtime_integrity_problem() {
  local wrapper="/usr/local/libexec/oc-addon/openclaw" wrapper_real pinned entry pkg_dir actual d candidate
  [ -f /usr/local/libexec/oc-addon/openclaw-pinned-version ] || return 0
  wrapper_real="$(readlink -f "$wrapper" 2>/dev/null || true)"
  pinned="$(head -n 1 /usr/local/libexec/oc-addon/openclaw-pinned-version 2>/dev/null || true)"
  entry="$(head -n 1 /usr/local/libexec/oc-addon/openclaw-entry 2>/dev/null || true)"
  if [ -z "$entry" ]; then
    echo "the add-on's record of the pinned OpenClaw package is missing (broken image?)"
    return 0
  fi
  pkg_dir="$(dirname "$entry")"
  actual="$(jq -r '.version // empty' "${pkg_dir}/package.json" 2>/dev/null || true)"
  if [ -n "$pinned" ] && [ "$actual" != "$pinned" ]; then
    echo "the OpenClaw package in the container is ${actual:-missing}, but this image pins ${pinned} (changed by npm inside the container?)"
    return 0
  fi
  # Every place an agent's shell or npm could put another `openclaw`: the
  # standard bin directories (login PATH), the runtime npm/pnpm prefixes, and the
  # persistent node-global prefix when it is enabled. Checked explicitly instead
  # of via run.sh's PATH, where the wrapper always comes first.
  for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin \
           "${npm_config_prefix:+${npm_config_prefix}/bin}" "${PNPM_HOME:-}" \
           "$( [ "$PERSIST_NODE_GLOBAL" = "true" ] || [ "$PERSIST_NODE_GLOBAL" = "1" ] && echo "${PERSISTENT_NODE_GLOBAL}/bin" )"; do
    [ -n "$d" ] && [ -e "${d}/openclaw" ] || continue
    if [ "$(readlink -f "${d}/openclaw" 2>/dev/null || true)" != "$wrapper_real" ]; then
      echo "${d}/openclaw is not the add-on wrapper (another OpenClaw installed inside the container?)"
      return 0
    fi
  done
  for candidate in /usr/local/lib/node_modules/openclaw \
                   "${npm_config_prefix:+${npm_config_prefix}/lib/node_modules/openclaw}" \
                   "$( [ "$PERSIST_NODE_GLOBAL" = "true" ] || [ "$PERSIST_NODE_GLOBAL" = "1" ] && echo "${PERSISTENT_NODE_GLOBAL}/lib/node_modules/openclaw" )"; do
    [ -n "$candidate" ] && [ -f "${candidate}/package.json" ] || continue
    if [ "$(readlink -f "$candidate")" != "$(readlink -f "$pkg_dir")" ]; then
      echo "a second OpenClaw package exists at ${candidate} (installed inside the container?)"
      return 0
    fi
  done
  return 0
}

# ------------------------------------------------------------------------------
# State guard (HOLD)
#
# If the persistent state was written by a newer OpenClaw than this image ships
# (e.g. a Home Assistant restore brought back the old image but not the old
# data, or the reverse), starting the bundled runtime on it can corrupt it: a
# 2026.7.x runtime cannot open databases migrated by 2026.8+. Earlier add-on
# versions "repaired" this by silently npm-installing the newer runtime. Now the
# add-on holds instead: nothing touches the state, OpenClaw is not started, and
# the add-on page and terminal stay up so a backup can be restored. From
# OpenClaw 2026.8 on, the migration gate also decides whether the state has to
# be migrated first (see below); every failure there is a HOLD as well.
# ------------------------------------------------------------------------------
UPG_DIR="${OC_UPGRADE_DIR:-/config/.openclaw-upgrade}"
mkdir -p "$UPG_DIR"
chmod 700 "$UPG_DIR" 2>/dev/null || true
STATE_HOLD=false
STATE_HOLD_REASON=""

# Put the add-on in HOLD: OpenClaw is not started, nginx and the terminal still
# come up, and the supervisor loop only waits for the stop request.
#   $1 = reason (may span several lines)
#   $2 = "keep": hold.txt was already written by oc-upgrade; leave it as is.
# The `openclaw` wrapper allows only read-only commands while hold.txt exists.
enter_hold() {
  STATE_HOLD=true
  STATE_HOLD_REASON="$1"
  if [ "${2:-}" != "keep" ]; then
    { echo "OpenClaw is held (bundled runtime ${OPENCLAW_RUNTIME_VERSION:-unknown}):"
      printf '%s\n' "$1"
      echo "The add-on page and terminal stay available. Details: oc-upgrade status"
    } > "${UPG_DIR}/hold.txt" 2>/dev/null || true
  fi
  echo "ERROR: ================================================================"
  echo "ERROR: HOLD — OpenClaw will NOT be started."
  printf '%s\n' "$1" | sed 's/^/ERROR: /'
  echo "ERROR: The add-on page and terminal stay available. Details: oc-upgrade status"
  echo "ERROR: ================================================================"
}

# Idle until the Supervisor stops the add-on (the shutdown trap sets
# SHUTTING_DOWN); `wait` on a background sleep keeps the trap responsive.
hold_wait_loop() {
  while [ "$SHUTTING_DOWN" != "true" ]; do
    sleep 30 &
    wait "$!" || true
  done
}

STATE_NEWER=false
OC_UPGRADE_MISSING=false
if command -v oc-upgrade >/dev/null 2>&1; then
  if guard_out="$(oc-upgrade state-guard 2>&1)"; then
    if [ -n "$guard_out" ]; then echo "$guard_out"; fi
  else
    guard_rc=$?
    if [ "$guard_rc" -eq 3 ]; then
      STATE_NEWER=true
      STATE_HOLD_REASON="$guard_out"
    else
      echo "WARN: oc-upgrade state-guard failed (exit ${guard_rc}); continuing without the state guard."
      if [ -n "$guard_out" ]; then echo "$guard_out"; fi
    fi
  fi
elif runtime_at_least 2026.8.0; then
  # OpenClaw 2026.8+ migrates state one-way; without the gate it must not start.
  OC_UPGRADE_MISSING=true
  STATE_HOLD_REASON="oc-upgrade missing: cannot run the migration gate (broken image?)."
else
  echo "WARN: oc-upgrade is missing from the add-on image; state guard skipped."
fi
RUNTIME_PROBLEM="$(runtime_integrity_problem)"
if [ -n "$RUNTIME_PROBLEM" ]; then
  STATE_HOLD_REASON="${STATE_HOLD_REASON:+${STATE_HOLD_REASON}
}${RUNTIME_PROBLEM}."
fi

if [ "$STATE_NEWER" = "true" ] || [ "$OC_UPGRADE_MISSING" = "true" ] || [ -n "$RUNTIME_PROBLEM" ]; then
  hold_text="$(
    printf '%s\n' "$STATE_HOLD_REASON"
    if [ "$STATE_NEWER" = "true" ]; then
      echo "Restore the Home Assistant backup that matches this add-on version (or update to the add-on"
      echo "version that wrote the state)."
    fi
    if [ -n "$RUNTIME_PROBLEM" ] || [ "$OC_UPGRADE_MISSING" = "true" ]; then
      echo "Reinstall or rebuild the add-on in Home Assistant to restore the pinned OpenClaw runtime."
    fi
    echo "OpenClaw is not started, and its config, databases, sessions and plugins are not modified"
    echo "(built-in skill files are still refreshed from the image)."
  )"
  enter_hold "$hold_text"
fi

# ------------------------------------------------------------------------------
# Migration gate planning (OpenClaw 2026.8+). `oc-upgrade gate --plan` is
# read-only (it may only write its marker for an adopted state or a sticky
# hold.txt). Exit codes: 0 no gate, 10 gate needed, 11 sticky HOLD (hold.txt
# written), 3 state newer than this runtime, anything else an error (fail
# closed). It reads every SQLite database, so it is bounded by `timeout 600`
# (124/137 = timed out -> HOLD). The gate itself runs further down, right
# before the session-lock cleanup, in the background so a stop request can be
# forwarded to it; it does not repeat the plan lines printed here.
# ------------------------------------------------------------------------------
GATE_NEEDED=false
GATE_PLAN_OUT=""
if [ "$STATE_HOLD" != "true" ] && runtime_at_least 2026.8.0; then
  if plan_out="$(timeout --kill-after=30 600 oc-upgrade gate --plan 2>&1)"; then plan_rc=0; else plan_rc=$?; fi
  if [ -n "$plan_out" ]; then printf '%s\n' "$plan_out"; fi
  case "$plan_rc" in
    0)  ;;
    10) GATE_NEEDED=true; GATE_PLAN_OUT="$plan_out" ;;
    124|137)
      enter_hold "The migration gate planning timed out (oc-upgrade gate --plan did not finish within 600 s); OpenClaw was not started.
Check the disk (slow or failing storage?), then restart the add-on. Details: oc-upgrade status."
      ;;
    11)
      if [ -s "${UPG_DIR}/hold.txt" ]; then
        enter_hold "$(cat "${UPG_DIR}/hold.txt")" keep
      else
        enter_hold "${plan_out:-The migration gate is on hold.}
Details: oc-upgrade status. After fixing the cause: oc-upgrade retry (then restart the add-on)."
      fi
      ;;
    3)
      STATE_NEWER=true
      enter_hold "${plan_out}
Restore the Home Assistant backup that matches this add-on version."
      ;;
    *)
      enter_hold "oc-upgrade gate --plan failed (exit ${plan_rc}): ${plan_out}"
      ;;
  esac
fi
if [ "$STATE_HOLD" != "true" ]; then
  # A HOLD from an earlier boot no longer applies. Before a gate run the gate
  # (and run_migration_gate) delete it themselves.
  if [ "$GATE_NEEDED" != "true" ]; then rm -f "${UPG_DIR}/hold.txt"; fi
  # From 2026.8 on the migration gate owns the pre-migration archive. Not
  # started when a stop request arrived meanwhile (the Supervisor would kill it).
  if ! runtime_at_least 2026.8.0 && [ "$SHUTTING_DOWN" != "true" ]; then require_upgrade_backup; fi
fi

# ------------------------------------------------------------------------------
# Cold export for an offline upgrade rehearsal (requested via `oc-upgrade export`)
# Runs before anything starts or writes, so the copy is consistent.
# ------------------------------------------------------------------------------
process_export_request() {
  local request="${UPG_DIR}/export-request" ts dest need_kb avail_kb archive stale
  # An interrupted export (power loss, SIGKILL) leaves a secret-bearing .tmp
  # behind; remove those on every start, whether or not a new export is due.
  for stale in /share/openclaw-rehearsal/*/openclaw-rehearsal.tar.gz.tmp; do
    [ -e "$stale" ] || continue
    echo "WARN: Removing incomplete rehearsal export ${stale}."
    rm -f "$stale" 2>/dev/null || echo "WARN: Could not remove ${stale}; delete it manually (it contains secrets)."
    rmdir "$(dirname "$stale")" 2>/dev/null || true
  done
  [ -f "$request" ] || return 0
  # One-shot: never retry on every boot, even after a failure.
  rm -f "$request"
  if [ ! -d /share ]; then
    echo "WARN: Rehearsal export skipped: /share is not available."
    return 0
  fi
  ts="$(date -u +%Y%m%d-%H%M%S)"
  dest="/share/openclaw-rehearsal/${ts}"
  # Estimate with the same exclusions as the archive below (uncompressed size,
  # so a safe upper bound for the compressed export).
  need_kb="$(du -skc \
      --exclude='.openclaw/upgrade-backups' --exclude='.openclaw/media' \
      --exclude='.openclaw/logs' --exclude='.openclaw/.cache' --exclude='.openclaw/tmp' \
      --exclude='clawd/node_modules' --exclude='clawd/*/node_modules' \
      "$OPENCLAW_CONFIG_DIR" /config/clawd 2>/dev/null | tail -n 1 | cut -f1)" || need_kb=""
  avail_kb="$(df -Pk /share 2>/dev/null | awk 'NR==2 {print $4}')" || avail_kb=""
  if [ -z "$need_kb" ] || [ -z "$avail_kb" ] || [ "$avail_kb" -lt "$need_kb" ]; then
    echo "WARN: Rehearsal export skipped: not enough free space in /share (need ~${need_kb:-?} KiB, have ${avail_kb:-?} KiB)."
    return 0
  fi
  echo "INFO: Creating cold rehearsal export in ${dest} (gateway not started yet)..."
  if ! (umask 077 && mkdir -p "$dest"); then
    echo "WARN: Rehearsal export skipped: cannot create ${dest}."
    return 0
  fi
  archive="${dest}/openclaw-rehearsal.tar.gz"
  local members=(.openclaw)
  [ -d /config/clawd ] && members+=(clawd)
  # Plugin packages under .openclaw (npm/, extensions/) stay in the copy; only
  # dependency trees inside the workspace are left out.
  if (umask 077 && tar -C /config \
      --exclude='.openclaw/upgrade-backups' \
      --exclude='.openclaw/media' \
      --exclude='.openclaw/logs' \
      --exclude='.openclaw/.cache' \
      --exclude='.openclaw/tmp' \
      --exclude='clawd/node_modules' \
      --exclude='clawd/*/node_modules' \
      -czf "${archive}.tmp" "${members[@]}") \
     && mv "${archive}.tmp" "$archive"; then
    chmod 600 "$archive" 2>/dev/null || true
    if (umask 077 && {
          echo "created_utc=${ts}"
          echo "addon_version=${ADDON_VERSION:-unknown}"
          echo "openclaw_runtime=$(openclaw_runtime_version || true)"
          echo "sha256=$(sha256sum "$archive" | cut -d' ' -f1)"
          echo "size_bytes=$(stat -c %s "$archive")"
          echo "contains_secrets=yes"
        } > "${dest}/manifest.txt") 2>/dev/null; then
      echo "INFO: Rehearsal export ready: ${archive} ($(du -h "$archive" 2>/dev/null | cut -f1)). It contains secrets — delete it after the rehearsal."
    else
      rm -f "${dest}/manifest.txt" 2>/dev/null || true
      echo "WARN: Rehearsal export written to ${archive}, but its manifest could not be written (disk full?). Startup continues."
    fi
  else
    rm -f "${archive}.tmp"
    echo "WARN: Rehearsal export failed; nothing was changed. Startup continues."
  fi
  return 0
}
# A stop request that arrived during the state guard or `gate --plan` must not
# start a multi-GB export the Supervisor kills (its one-shot request would be lost).
if [ "$SHUTTING_DOWN" != "true" ]; then
  process_export_request
fi

# ------------------------------------------------------------------------------
# Session lock cleanup helpers
# ------------------------------------------------------------------------------

gateway_running() {
  pgrep -f "openclaw-gateway" >/dev/null 2>&1
}

cleanup_session_locks() {
  local agents_dir="/config/.openclaw/agents"
  local total_locks=0
  local cleaned_dirs=()

  # Scan all agent session directories, not just 'main'.
  # This is needed for users who have gateway.forcedAgentId set to a non-default agent.
  shopt -s nullglob
  local all_locks=()
  for agent_sessions_dir in "${agents_dir}"/*/sessions; do
    local agent_locks=( "${agent_sessions_dir}"/*.jsonl.lock )
    if [ ${#agent_locks[@]} -gt 0 ]; then
      all_locks+=( "${agent_locks[@]}" )
      cleaned_dirs+=( "$agent_sessions_dir" )
      total_locks=$(( total_locks + ${#agent_locks[@]} ))
    fi
  done
  shopt -u nullglob

  if [ "$total_locks" -eq 0 ]; then
    return 0
  fi

  # If gateway is running, do NOT remove locks automatically (could be real).
  if gateway_running; then
    echo "INFO: Gateway appears to be running; leaving session lock files untouched."
    echo "INFO: Locks present: $total_locks"
    return 0
  fi

  echo "INFO: Removing stale session lock files ($total_locks) across agents: ${cleaned_dirs[*]}"
  for agent_sessions_dir in "${cleaned_dirs[@]}"; do
    rm -f "${agent_sessions_dir}"/*.jsonl.lock || true
  done
}

# ------------------------------------------------------------------------------
# Self-heal: reclaim orphaned Telegram ingress-spool claims.
# OpenClaw's isolated-polling spool leaves an inbound update as
# <id>.json.processing if the gateway is interrupted mid-claim (e.g. a restart
# while a message is being handled). Because the container gateway runs as PID 1,
# OC's own recovery (processExists(1)) false-positives and skips the orphan for
# ~6h, blocking that Telegram lane -> bot appears unreachable.
# We run this BEFORE each gateway (re)start (gateway not yet running => race-free),
# mirroring OC's recoverStaleTelegramSpooledUpdateClaims:
#   - sibling <id>.json.failed (dead-letter) -> delete .processing (never resurrect)
#   - sibling <id>.json already exists        -> delete .processing (don't clobber)
#   - otherwise                               -> rename .processing -> .json (requeue)
# MUST be fail-safe: never abort run.sh under `set -euo pipefail`.
# Upstream bug, open as of OC 2026.6.6: openclaw/openclaw#84674 / #85168.
# ------------------------------------------------------------------------------
heal_telegram_ingress_spool() {
  # OpenClaw 2026.8+ keeps Telegram ingress in its state database and never
  # reads these spool files; the migration gate only reports leftovers.
  if runtime_at_least 2026.8.0; then return 0; fi
  local base="/config/.openclaw/telegram"
  local healed=0 dropped=0 spool_dir f pending failed
  shopt -s nullglob
  for spool_dir in "${base}"/ingress-spool-*/; do
    [ -d "$spool_dir" ] || continue
    for f in "${spool_dir}"*.json.processing; do
      [ -f "$f" ] || continue
      pending="${f%.processing}"
      failed="${pending}.failed"
      if [ -e "$failed" ]; then
        rm -f -- "$f" && dropped=$((dropped + 1)) || true
      elif [ -e "$pending" ]; then
        rm -f -- "$f" && dropped=$((dropped + 1)) || true
      elif mv -f -- "$f" "$pending" 2>/dev/null; then
        healed=$((healed + 1))
      else
        echo "WARN: could not reclaim orphaned spool file: $f"
      fi
    done
  done
  shopt -u nullglob
  if [ "$healed" -gt 0 ] || [ "$dropped" -gt 0 ]; then
    echo "INFO: Telegram ingress-spool self-heal: requeued $healed, dropped $dropped orphan(s)."
  fi
}

# ------------------------------------------------------------------------------
# Ensure the Brave web-search provider plugin is installed (idempotent).
# Brave is an EXTERNAL official plugin (@openclaw/brave-plugin), NOT bundled in
# core openclaw. It installs into the persistent config dir
# (/config/.openclaw/extensions), so once present it survives image rebuilds --
# but a fresh state or a migration has no Brave, and our oc_config_helper would
# then strip a persisted tools.web.search.provider=brave as "unavailable".
# We (re)ensure it here, BEFORE the config-helper repair runs, so a user's Brave
# selection stays intact across rebuilds/fresh states.
# The plugin version MUST match the baked openclaw (CalVer lockstep; plugin
# peerDependencies.openclaw>=X). The image records the version it was built
# with (Dockerfile ARG BRAVE_PLUGIN_VERSION, checked against npm at build time).
# Best-effort: never blocks startup (guarded, non-fatal). Runs after the
# migration gate, so never against unmigrated state.
# ------------------------------------------------------------------------------
BRAVE_PLUGIN_VERSION="$(head -n 1 /usr/local/libexec/oc-addon/brave-plugin-version 2>/dev/null || true)"
if [ -z "$BRAVE_PLUGIN_VERSION" ]; then
  # Older image without the record: CalVer lockstep with the bundled runtime.
  BRAVE_PLUGIN_VERSION="${OPENCLAW_RUNTIME_VERSION:-2026.9.9}"
fi
ensure_brave_plugin() {
  local marker="/config/.openclaw/.brave_plugin_${BRAVE_PLUGIN_VERSION}"
  if [ -f "$marker" ]; then
    return 0
  fi
  # Install or CONVERGE to the pinned version. --force upgrades any older Brave
  # install (e.g. left over from a previous OpenClaw version) to match the host
  # CalVer, instead of adopting a stale version. Guarded by the per-version
  # marker so it runs at most once per version. Runs before gateway start
  # (gateway down => safe). (Replaces the old adopt-without-version path that
  # wrote a new-version marker for a stale install -> version drift on bumps.)
  echo "INFO: Ensuring Brave web-search plugin @openclaw/brave-plugin@${BRAVE_PLUGIN_VERSION}..."
  # OpenClaw 2026.8+ asks to accept a plugin's declared capabilities (the
  # Brave manifest declares none); 2026.7.x does not know the flag.
  local accept_flag=()
  if runtime_at_least 2026.8.0; then accept_flag=(--accept-capabilities); fi
  if timeout 180 openclaw plugins install "npm:@openclaw/brave-plugin@${BRAVE_PLUGIN_VERSION}" --pin --force "${accept_flag[@]}" >/dev/null 2>&1; then
    touch "$marker" 2>/dev/null || true
    echo "INFO: Brave web-search plugin ensured (@${BRAVE_PLUGIN_VERSION})."
  else
    echo "WARN: Brave plugin install failed or timed out (non-fatal); web search may use a bundled provider (e.g. duckduckgo)."
  fi
  return 0
}

# ------------------------------------------------------------------------------
# Migration gate (OpenClaw 2026.8+, when `gate --plan` asked for it above).
# `oc-upgrade gate` archives the state to /share, cleans up, pre-migrates the
# config, runs `openclaw doctor --fix --non-interactive` twice and checks the
# result; any failure leaves a HOLD with hold.txt (exit 20, or 1 for an internal
# error). It runs in the background so the early stop trap can forward SIGTERM
# (exit 130/143, the next start resumes once).
# ------------------------------------------------------------------------------
run_migration_gate() {
  local rc=0 r rc_known=false
  # A hold.txt from an earlier run must never be mistaken for this run's reason.
  rm -f "${UPG_DIR}/hold.txt"
  echo "INFO: Starting the OpenClaw migration gate (OpenClaw ${OPENCLAW_RUNTIME_VERSION}); nginx and the terminal start after it."
  # Unbuffered, so the gate's progress lines reach the add-on log as they happen.
  # OC_GATE_PLAN_SHOWN: plan lines already printed above (the gate re-plans silently).
  OC_GATE_PLAN_SHOWN="${GATE_PLAN_OUT:-}" OC_GATE_FROM_RUNSH=1 PYTHONUNBUFFERED=1 oc-upgrade gate &
  GATE_PID=$!
  # One wait loop. A trapped signal makes `wait` return early (>128) after
  # early_stop ran (which sets GATE_WAIT_INTERRUPTED), so wait again for the
  # real exit status. A repeated wait for an already collected status answers
  # 127 ("not a child"); keep the status collected before in that case.
  GATE_WAIT_INTERRUPTED=true
  while [ "$GATE_WAIT_INTERRUPTED" = "true" ]; do
    GATE_WAIT_INTERRUPTED=false
    if wait "$GATE_PID" 2>/dev/null; then r=0; else r=$?; fi
    if [ "$r" -eq 127 ] && [ "$rc_known" = "true" ]; then
      break
    fi
    rc=$r
    rc_known=true
  done
  GATE_PID=""
  if [ "$rc" -eq 0 ]; then
    return 0
  fi
  if [ "$SHUTTING_DOWN" = "true" ]; then
    echo "INFO: The migration gate stopped (exit ${rc}) on the stop request; the next start resumes it."
    return 0
  fi
  if [ -s "${UPG_DIR}/hold.txt" ]; then
    enter_hold "$(cat "${UPG_DIR}/hold.txt")" keep
  else
    enter_hold "The migration gate failed unexpectedly (exit ${rc}); see the log above. Retry: oc-upgrade retry (then restart the add-on)."
  fi
  return 0
}

if [ "$STATE_HOLD" != "true" ] && [ "$GATE_NEEDED" = "true" ] && [ "$SHUTTING_DOWN" != "true" ]; then
  run_migration_gate
fi
if [ "$SHUTTING_DOWN" = "true" ]; then
  echo "INFO: Stop requested during startup; exiting."
  exit 0
fi

if [ "$STATE_HOLD" = "true" ]; then
  echo "INFO: HOLD: skipping session lock cleanup."
elif [ "$CLEAN_LOCKS_ON_START" = "true" ]; then
  cleanup_session_locks
else
  echo "INFO: clean_session_locks_on_start=false; skipping session lock cleanup."
fi

# ------------------------------------------------------------------------------
# Store tokens / export env vars (optional)
# ------------------------------------------------------------------------------

if [ -n "$HA_TOKEN" ]; then
  umask 077
  printf '%s' "$HA_TOKEN" > /config/secrets/homeassistant.token
fi


# ------------------------------------------------------------------------------
# OpenClaw config is managed by OpenClaw itself (onboarding / configure).
# This add-on intentionally does NOT create/patch /config/.openclaw/openclaw.json.
# ------------------------------------------------------------------------------

# Convenience info for later (router SSH access path & HA token file)
cat > /config/CONNECTION_NOTES.txt <<EOF
Home Assistant token (if set): /config/secrets/homeassistant.token
Router SSH (generic):
  host=${ROUTER_HOST}
  user=${ROUTER_USER}
  key=${ROUTER_KEY}
EOF


# ------------------------------------------------------------------------------
# Graceful shutdown handling (PID 1 trap) to reduce stale locks
# ------------------------------------------------------------------------------
GW_PID=""
GW_RELAY_PID=""
NGINX_PID=""
TTYD_PID=""
HEALTH_PID=""
# Keep a stop request that arrived before this point (early_stop trap).
SHUTTING_DOWN="${SHUTTING_DOWN:-false}"

shutdown() {
  SHUTTING_DOWN="true"
  echo "Shutdown requested; stopping services..."

  if [ -n "${HEALTH_PID}" ] && kill -0 "${HEALTH_PID}" >/dev/null 2>&1; then
    kill -TERM "${HEALTH_PID}" >/dev/null 2>&1 || true
    wait "${HEALTH_PID}" 2>/dev/null || true
  fi

  if [ -n "${NGINX_PID}" ] && kill -0 "${NGINX_PID}" >/dev/null 2>&1; then
    kill -TERM "${NGINX_PID}" >/dev/null 2>&1 || true
    wait "${NGINX_PID}" || true
  fi

  if [ -n "${TTYD_PID}" ] && kill -0 "${TTYD_PID}" >/dev/null 2>&1; then
    kill -TERM "${TTYD_PID}" >/dev/null 2>&1 || true
    wait "${TTYD_PID}" || true
  fi

  # Stop the gateway and give it time to drain and flush its SQLite state.
  # After an in-process self-restart the tracked PID can be a wrapper that has
  # already exited while the daemon lives on, so also signal whatever holds the
  # gateway port. The poll stays below config.yaml `timeout: 300`, after which
  # the Supervisor sends SIGKILL.
  local _gw_pids="" _p _i _alive
  if [ -n "${GW_PID}" ] && kill -0 "${GW_PID}" >/dev/null 2>&1; then
    _gw_pids="${GW_PID}"
  fi
  _p="$(find_gateway_daemon_pid 2>/dev/null || true)"
  if [ -n "$_p" ] && [ "$_p" != "${GW_PID}" ] && kill -0 "$_p" >/dev/null 2>&1; then
    _gw_pids="${_gw_pids} ${_p}"
  fi
  if [ -n "$_gw_pids" ]; then
    for _p in $_gw_pids; do
      kill -TERM "$_p" >/dev/null 2>&1 || true
    done
    for _i in $(seq 1 270); do
      _alive=false
      for _p in $_gw_pids; do
        if kill -0 "$_p" 2>/dev/null; then _alive=true; fi
      done
      [ "$_alive" = "true" ] || break
      if [ "$_i" -eq 60 ]; then
        echo "WARN: gateway still stopping after 60 s (9.9 waits for plugin cleanup; up to 270 s)"
      fi
      if [ $((_i % 15)) -eq 0 ]; then
        echo "Waiting for the gateway to stop (${_i}s)..."
      fi
      sleep 1
    done
    # The Supervisor kills the whole add-on 300 s after the stop request, while
    # OpenClaw 2026.9's own stop budget is 325 s: end it here, logged.
    for _p in $_gw_pids; do
      if kill -0 "$_p" 2>/dev/null; then
        echo "WARN: gateway PID ${_p} did not stop within 270 s; sending SIGKILL."
        kill -KILL "$_p" >/dev/null 2>&1 || true
      fi
    done
    # Reap our own child so it does not linger as a zombie.
    wait "${GW_PID}" 2>/dev/null || true
  fi

  stop_gw_relay

  if [ "$CLEAN_LOCKS_ON_EXIT" = "true" ] && [ "${STATE_HOLD:-false}" != "true" ]; then
    cleanup_session_locks || true
  fi
}

trap shutdown INT TERM
# A stop request that arrived between the migration gate and this trap.
if [ "$SHUTTING_DOWN" = "true" ]; then
  echo "INFO: Stop requested during startup; exiting."
  exit 0
fi

if ! command -v openclaw >/dev/null 2>&1; then
  enter_hold "openclaw is not installed in the add-on image (broken image?). Reinstall or rebuild the add-on."
fi

# Bootstrap minimal OpenClaw config ONLY if missing.
# We do not overwrite or patch existing configs; onboarding owns everything else.
OPENCLAW_CONFIG_PATH="/config/.openclaw/openclaw.json"
if [ ! -f "$OPENCLAW_CONFIG_PATH" ] && [ "$STATE_HOLD" != "true" ]; then
  echo "INFO: OpenClaw config missing; bootstrapping minimal config at $OPENCLAW_CONFIG_PATH"
  python3 - <<'PY'
import json
import secrets
from pathlib import Path

cfg_path = Path('/config/.openclaw/openclaw.json')
cfg_path.parent.mkdir(parents=True, exist_ok=True)

cfg = {
  "gateway": {
    "mode": "local",
    "port": 18789,
    "bind": "loopback",
    "auth": {
      "mode": "token",
      "token": secrets.token_urlsafe(24)
    }
  },
  "agents": {
    "defaults": {
      "workspace": "/config/clawd"
    }
  }
}

cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding='utf-8')
print("INFO: Wrote minimal OpenClaw config (gateway.mode=local, auth.token generated)")
PY
fi

# ------------------------------------------------------------------------------
# Apply gateway LAN mode settings safely using helper script
# This updates gateway.bind and gateway.port without touching other settings
# ------------------------------------------------------------------------------
export OPENCLAW_CONFIG_PATH="/config/.openclaw/openclaw.json"

# Find the helper script (copied to root in Dockerfile, or fallback to add-on dir)
HELPER_PATH="/oc_config_helper.py"
if [ ! -f "$HELPER_PATH" ] && [ -f "$(dirname "$0")/oc_config_helper.py" ]; then
  HELPER_PATH="$(dirname "$0")/oc_config_helper.py"
fi

CONFIG_UNREADABLE=false
if [ "$STATE_HOLD" = "true" ]; then
  # Nothing may write to state that is newer than this runtime.
  CONFIG_UNREADABLE=true
  echo "INFO: HOLD: skipping plugin and config repair steps."
elif [ -f "$OPENCLAW_CONFIG_PATH" ]; then
  # Ensure Brave is present BEFORE repair-known-invalid-settings, so a persisted
  # tools.web.search.provider=brave is not stripped as "unavailable".
  ensure_brave_plugin || true
  if [ -f "$HELPER_PATH" ]; then
    # Snapshot BEFORE the first mutation of this boot so `oc-config restore`
    # can always undo whatever the repair/apply steps below decide to change.
    # A failed backup must never block startup — the helper reports and returns 0.
    python3 "$HELPER_PATH" snapshot "$CONFIG_BACKUP_KEEP" startup || \
      echo "WARN: Could not snapshot openclaw.json; continuing startup."

    if python3 "$HELPER_PATH" repair-known-invalid-settings; then
      :
    else
      rc=$?
      if [ "$rc" -eq 2 ]; then
        # openclaw.json exists but is not valid JSON. The helper refuses to touch
        # it (it would otherwise rebuild it from scratch and drop every agent,
        # channel and credential). Keep booting so the add-on page and terminal
        # stay reachable for a repair / `oc-config restore`.
        CONFIG_UNREADABLE=true
        echo "ERROR: $OPENCLAW_CONFIG_PATH is not valid JSON; the add-on will not modify it."
        echo "ERROR: Fix it in the add-on terminal ('oc-config list' / 'oc-config restore <n>') and restart."
      else
        # Never exit PID 1 here: that would take the add-on page and terminal
        # down with it. Hold instead, so the config can be inspected and fixed.
        echo "ERROR: Failed to repair known invalid OpenClaw config settings via oc_config_helper.py (exit code ${rc})."
        CONFIG_UNREADABLE=true
        enter_hold "The add-on could not check/repair openclaw.json (oc_config_helper.py repair-known-invalid-settings, exit ${rc}); the gateway configuration may be invalid.
Inspect it in the terminal (openclaw config validate, oc-config list / oc-config restore <n>), fix it, then restart the add-on."
      fi
    fi

    # In lan_https mode the gateway uses an internal port; nginx owns the external one.
    EFFECTIVE_GW_PORT="$GATEWAY_INTERNAL_PORT"
    if [ "$CONFIG_UNREADABLE" = "true" ]; then
      echo "WARN: Skipping gateway settings: openclaw.json is unreadable or the add-on is in HOLD."
    elif python3 "$HELPER_PATH" apply-gateway-settings "$GATEWAY_MODE" "$GATEWAY_REMOTE_URL" "$GATEWAY_BIND_MODE" "$EFFECTIVE_GW_PORT" "$ENABLE_OPENAI_API" "$GATEWAY_AUTH_MODE" "$GATEWAY_TRUSTED_PROXIES"; then
      :
    else
      rc=$?
      echo "ERROR: Failed to apply gateway settings via oc_config_helper.py (exit code ${rc})."
      CONFIG_UNREADABLE=true
      enter_hold "The add-on could not apply its gateway settings to openclaw.json (oc_config_helper.py apply-gateway-settings, exit ${rc}); the gateway configuration may be incorrect.
Inspect it in the terminal (openclaw config validate, oc-config list / oc-config restore <n>), fix it, then restart the add-on."
    fi

    # Conservative OpenClaw defaults for explicitly selected low-resource setups.
    # Only writes keys the user has not set, and never runs for auto-detection.
    if [ "$RESOURCE_PROFILE" = "low" ] && [ "$CONFIG_UNREADABLE" != "true" ]; then
      python3 "$HELPER_PATH" apply-resource-profile low || \
        echo "WARN: Could not apply low-profile OpenClaw defaults; continuing."
    fi
  else
    echo "WARN: oc_config_helper.py not found, cannot apply gateway settings"
    echo "INFO: Ensure the add-on image includes oc_config_helper.py and restart"
  fi
else
  echo "WARN: OpenClaw config not found at $OPENCLAW_CONFIG_PATH, cannot apply gateway settings"
  echo "INFO: Run 'openclaw onboard' first, then restart the add-on"
fi

if [ "$GATEWAY_AUTH_MODE" = "trusted-proxy" ]; then
  echo "NOTICE: gateway_auth_mode=trusted-proxy is enabled."
  echo "NOTICE: Direct local CLI calls to the gateway may return unauthorized (trusted_proxy_user_missing) unless identity headers are injected by your reverse proxy."
  echo "NOTICE: For local terminal CLI workflows, temporarily switch to token auth or use commands that don't require direct gateway WS auth."
fi

# ------------------------------------------------------------------------------
# TLS certificate generation for built-in HTTPS proxy (lan_https mode)
# Generates a local CA + server cert so phones/tablets get proper HTTPS.
# The CA cert can be installed once on a device for trusted access.
# ------------------------------------------------------------------------------
LAN_IP=""
if [ "$ENABLE_HTTPS_PROXY" = "true" ]; then
  CERT_DIR="/config/certs"
  mkdir -p "$CERT_DIR"

  cert_ext_contains() {
    local cert_path="$1"
    local extension_name="$2"
    local expected="$3"
    openssl x509 -in "$cert_path" -noout -ext "$extension_name" 2>/dev/null | grep -Fq "$expected"
  }

  local_ca_cert_is_valid() {
    local cert_path="$1"
    [ -f "$cert_path" ] && \
      cert_ext_contains "$cert_path" basicConstraints "CA:TRUE" && \
      cert_ext_contains "$cert_path" keyUsage "Certificate Sign, CRL Sign"
  }

  gateway_server_cert_is_valid() {
    local cert_path="$1"
    [ -f "$cert_path" ] && \
      cert_ext_contains "$cert_path" extendedKeyUsage "TLS Web Server Authentication" && \
      cert_ext_contains "$cert_path" subjectAltName "DNS:localhost"
  }

  generate_local_ca_cert() {
    cat > "$CERT_DIR/_ca.ext" <<'CAEOF'
[v3_ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
CAEOF

    openssl genrsa -out "$CERT_DIR/ca.key" 2048 2>/dev/null
    openssl req -new -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.csr" \
      -subj "/CN=OpenClaw Local CA" 2>/dev/null
    openssl x509 -req -in "$CERT_DIR/ca.csr" -signkey "$CERT_DIR/ca.key" \
      -out "$CERT_DIR/ca.crt" -days 3650 \
      -extfile "$CERT_DIR/_ca.ext" -extensions v3_ca 2>/dev/null

    rm -f "$CERT_DIR/ca.csr" "$CERT_DIR/_ca.ext"
    chmod 600 "$CERT_DIR/ca.key"
  }

  generate_gateway_server_cert() {
    openssl genrsa -out "$CERT_DIR/gateway.key" 2048 2>/dev/null
    openssl req -new -key "$CERT_DIR/gateway.key" -out "$CERT_DIR/gateway.csr" \
      -subj "/CN=OpenClaw Gateway" 2>/dev/null

    cat > "$CERT_DIR/_server.ext" <<SERVER_EOF
[v3_server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:${LAN_IP:-127.0.0.1},IP:127.0.0.1,DNS:localhost,DNS:homeassistant,DNS:homeassistant.local${EXTRA_SANS:+,${EXTRA_SANS}}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
SERVER_EOF

    openssl x509 -req -in "$CERT_DIR/gateway.csr" \
      -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
      -out "$CERT_DIR/gateway.crt" -days 3650 \
      -extfile "$CERT_DIR/_server.ext" -extensions v3_server 2>/dev/null

    rm -f "$CERT_DIR/gateway.csr" "$CERT_DIR/_server.ext" "$CERT_DIR/ca.srl"
    chmod 600 "$CERT_DIR/gateway.key"
  }

  # Detect primary LAN IP
  LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  STORED_IP=$(cat "$CERT_DIR/.cert_ip" 2>/dev/null || echo "")

  # --- Local CA (generated once, persists across restarts) ---
  if [ ! -f "$CERT_DIR/ca.key" ] || [ ! -f "$CERT_DIR/ca.crt" ]; then
    echo "INFO: Generating local CA certificate (one-time)..."
    generate_local_ca_cert
    STORED_IP=""  # force server cert regeneration
    echo "INFO: Local CA created at $CERT_DIR/ca.crt"
  elif ! local_ca_cert_is_valid "$CERT_DIR/ca.crt"; then
    echo "WARN: Existing local CA certificate is missing required X.509 CA extensions."
    echo "WARN: Regenerating CA/server certificates for OpenSSL and Python strict verification compatibility."
    echo "WARN: Devices that trusted the old CA need the new /cert/ca.crt installed again."
    rm -f "$CERT_DIR/ca.key" "$CERT_DIR/ca.crt" "$CERT_DIR/gateway.key" "$CERT_DIR/gateway.crt"
    generate_local_ca_cert
    STORED_IP=""
    echo "INFO: Local CA rotated at $CERT_DIR/ca.crt"
  fi

  # --- Extra SANs from gateway_additional_allowed_origins + gateway_public_url ---
  EXTRA_SANS=""
  EXTRA_SAN_SOURCES="${GATEWAY_ADDITIONAL_ALLOWED_ORIGINS},${GW_PUBLIC_URL}"
  if [ "$EXTRA_SAN_SOURCES" != "," ]; then
    EXTRA_SANS="$(python3 - "$EXTRA_SAN_SOURCES" "${LAN_IP:-}" <<'PY'
import sys, re
from urllib.parse import urlparse
raw = sys.argv[1] if len(sys.argv) > 1 else ""
lan_ip = sys.argv[2] if len(sys.argv) > 2 else ""
entries = [e.strip() for e in raw.split(",") if e.strip()]
sans = []
seen = {"127.0.0.1", "localhost", "homeassistant", "homeassistant.local"}
if lan_ip:
    seen.add(lan_ip)
for entry in entries:
    if "://" not in entry:
        entry = "https://" + entry
    host = urlparse(entry).hostname or ""
    if host and host not in seen:
        seen.add(host)
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            sans.append(f"IP:{host}")
        else:
            sans.append(f"DNS:{host}")
print(",".join(sans), end="")
PY
)"
  fi
  STORED_EXTRA_SANS=$(cat "$CERT_DIR/.cert_extra_sans" 2>/dev/null || echo "")

  # --- Server cert (regenerated when LAN IP or SANs change) ---
  if [ ! -f "$CERT_DIR/gateway.crt" ] || [ ! -f "$CERT_DIR/gateway.key" ] || [ "$LAN_IP" != "$STORED_IP" ] || [ "$EXTRA_SANS" != "$STORED_EXTRA_SANS" ] || ! gateway_server_cert_is_valid "$CERT_DIR/gateway.crt"; then
    echo "INFO: Generating server TLS certificate for IP: ${LAN_IP:-unknown}..."
    generate_gateway_server_cert
    printf '%s' "$LAN_IP" > "$CERT_DIR/.cert_ip"
    printf '%s' "$EXTRA_SANS" > "$CERT_DIR/.cert_extra_sans"
    echo "INFO: Server TLS certificate generated (SAN: IP:${LAN_IP:-127.0.0.1}${EXTRA_SANS:+,${EXTRA_SANS}})"
  else
    echo "INFO: Reusing existing TLS certificate (IP: $STORED_IP)"
  fi

  # Make CA cert available for download via nginx
  mkdir -p /etc/nginx/html
  cp "$CERT_DIR/ca.crt" /etc/nginx/html/openclaw-ca.crt 2>/dev/null || true
  echo "INFO: CA certificate available for download at /cert/ca.crt on the HTTPS port"

fi

# ------------------------------------------------------------------
# Configure gateway.controlUi.allowedOrigins:
# - In lan_https: include HTTPS proxy defaults (LAN IP + common hostnames)
# - In all modes: also include origin from gateway_public_url when present
# - Helper merges with existing origins + user extras and deduplicates
# ------------------------------------------------------------------
if [ -f "$HELPER_PATH" ] && [ -f "$OPENCLAW_CONFIG_PATH" ] && [ "$CONFIG_UNREADABLE" != "true" ]; then
  ALLOWED_ORIGINS=""

  if [ "$ENABLE_HTTPS_PROXY" = "true" ] && [ -n "$LAN_IP" ]; then
    ALLOWED_ORIGINS="https://${LAN_IP}:${GATEWAY_PORT}"
    ALLOWED_ORIGINS="${ALLOWED_ORIGINS},https://homeassistant.local:${GATEWAY_PORT}"
    ALLOWED_ORIGINS="${ALLOWED_ORIGINS},https://homeassistant:${GATEWAY_PORT}"
  fi

  if [ -n "$GW_PUBLIC_URL" ]; then
    GW_PUBLIC_ORIGIN="$(python3 - "$GW_PUBLIC_URL" <<'PY'
import sys
from urllib.parse import urlparse
u = (sys.argv[1] or '').strip()
p = urlparse(u)
if p.scheme in ('http', 'https') and p.netloc:
    print(f"{p.scheme}://{p.netloc}", end='')
PY
)"
    if [ -n "$GW_PUBLIC_ORIGIN" ]; then
      if [ -n "$ALLOWED_ORIGINS" ]; then
        ALLOWED_ORIGINS="${ALLOWED_ORIGINS},${GW_PUBLIC_ORIGIN}"
      else
        ALLOWED_ORIGINS="$GW_PUBLIC_ORIGIN"
      fi
    fi
  fi

  python3 "$HELPER_PATH" set-control-ui-origins "$ALLOWED_ORIGINS" "$GATEWAY_ADDITIONAL_ALLOWED_ORIGINS" "$CONTROLUI_DISABLE_DEVICE_AUTH" || \
    echo "WARN: Could not set controlUi settings — gateway may reject the Control UI"
fi

# (The proxy shim for undici/OpenClaw is set up next to the runtime environment
# hardening near the top, before the migration gate.)

# ------------------------------------------------------------------------------
# Auto-configure MCP (Model Context Protocol) for Home Assistant
# Registers HA as an MCP server so OpenClaw can control HA entities/services.
# Requires: homeassistant_token set in add-on options + mcporter CLI available.
# Runs once; re-runs when the token or the Home Assistant URL changes.
# Auto-detects HA API URL: supervisor proxy if available, else localhost:8123.
# ------------------------------------------------------------------------------
if [ "$STATE_HOLD" = "true" ]; then
  echo "INFO: HOLD: skipping MCP auto-configuration."
elif [ "$AUTO_CONFIGURE_MCP" = "true" ] && [ -n "$HA_TOKEN" ]; then
  if command -v mcporter >/dev/null 2>&1; then
    # Detect HA API URL. This add-on runs with host_network: true, so the
    # container is not on the Supervisor bridge network and the `supervisor`
    # hostname normally does not resolve — registering that URL would silently
    # produce a dead MCP server. Prefer the host's Home Assistant on localhost
    # and only use the Supervisor proxy when it actually resolves.
    if [ -n "$HA_BASE_URL" ]; then
      MCP_HA_URL="${HA_BASE_URL%/}/api/mcp"
    elif [ -n "${SUPERVISOR_TOKEN:-}" ] && getent hosts supervisor >/dev/null 2>&1; then
      MCP_HA_URL="http://supervisor/core/api/mcp"
    else
      MCP_HA_URL="http://localhost:8123/api/mcp"
    fi
    MCP_FLAG="/config/.openclaw/.mcp_ha_configured"
    # Fingerprint covers token AND URL, so changing ha_base_url (or the URL
    # detection above) re-registers the server. Older markers held a token-only
    # hash and trigger one re-registration; add-on versions before 0.5.90
    # registered the unreachable http://supervisor/... URL.
    MCP_TOKEN_HASH=$(printf '%s\n%s' "$HA_TOKEN" "$MCP_HA_URL" | sha256sum | cut -d' ' -f1)

    if [ -f "$MCP_FLAG" ] && [ "$(cat "$MCP_FLAG" 2>/dev/null)" = "$MCP_TOKEN_HASH" ]; then
      echo "INFO: MCP Home Assistant server already configured (token and URL unchanged)"
    else
      echo "INFO: Configuring MCP for Home Assistant at $MCP_HA_URL ..."
      # Remove stale entry if present (token may have changed)
      mcporter config remove HA 2>/dev/null || true

      if mcporter config add HA "$MCP_HA_URL" \
          --header "Authorization=Bearer $HA_TOKEN" \
          --scope home 2>&1; then
        printf '%s' "$MCP_TOKEN_HASH" > "$MCP_FLAG"
        echo "INFO: MCP server 'HA' registered — OpenClaw can now control Home Assistant"
      else
        echo "WARN: MCP auto-configuration failed. Configure manually in the terminal:"
        echo "WARN:   mcporter config add HA \"$MCP_HA_URL\" --header \"Authorization=Bearer YOUR_TOKEN\" --scope home"
      fi
    fi
  else
    echo "WARN: mcporter is missing from the add-on image; skipping MCP auto-configuration"
  fi
elif [ "$AUTO_CONFIGURE_MCP" = "true" ] && [ -z "$HA_TOKEN" ]; then
  echo "INFO: MCP auto-configure enabled but homeassistant_token not set — skipping"
  echo "INFO: To auto-configure, set homeassistant_token in add-on Configuration, then restart"
fi

start_openclaw_runtime() {
  echo "Starting OpenClaw Assistant runtime (openclaw)..."
  # Reclaim orphaned Telegram ingress-spool claims before (re)starting the gateway.
  heal_telegram_ingress_spool || true
  if [ "$GATEWAY_MODE" = "remote" ]; then
    # Remote mode: do NOT start a local gateway service.
    # Start a node/client host that connects to the configured remote gateway URL.
    # Use $GATEWAY_REMOTE_URL directly from add-on options — do NOT read back via
    # 'openclaw config get' which can time out at startup or return redacted values.
    REMOTE_URL="$GATEWAY_REMOTE_URL"
    if [ -z "$REMOTE_URL" ]; then
      echo "ERROR: gateway_mode=remote but gateway_remote_url is not set in add-on options"
      echo "ERROR: Set gateway_remote_url in add-on Configuration (e.g. ws://192.168.1.10:18789), then restart"
      return 1
    fi

    NODE_HOST=""
    NODE_PORT=""
    NODE_TLS_FLAG=""
    if ! eval "$(python3 - "$REMOTE_URL" <<'PY'
import sys
from urllib.parse import urlparse
url = (sys.argv[1] or '').strip()
p = urlparse(url)
if p.scheme not in ('ws', 'wss') or not p.hostname:
    print('echo "ERROR: Invalid gateway.remote.url (expected ws:// or wss://): %s"' % url.replace('"', '\\"'))
    print('return 1')
    raise SystemExit(0)
port = p.port or (443 if p.scheme == 'wss' else 80)
print(f'NODE_HOST={p.hostname}')
print(f'NODE_PORT={port}')
print(f'NODE_TLS_FLAG={"--tls" if p.scheme == "wss" else ""}')
PY
)"; then
      echo "ERROR: Failed to parse gateway.remote.url: $REMOTE_URL"
      return 1
    fi

    echo "INFO: gateway_mode=remote detected; starting node host to $NODE_HOST:$NODE_PORT ${NODE_TLS_FLAG}"
    # shellcheck disable=SC2086
    openclaw node run --host "$NODE_HOST" --port "$NODE_PORT" $NODE_TLS_FLAG &
  else
    openclaw gateway run &
  fi
  GW_PID=$!
  return 0
}

# --- Loopback relay helpers for tailnet bind mode (issue #90) ---
# When gateway.bind=tailnet the gateway only listens on the Tailscale IP.
# The local CLI always tries ws://127.0.0.1:PORT and fails with
# "Gateway not running" even though the gateway is healthy.
# These functions start/stop a lightweight Node.js TCP relay on
# 127.0.0.1:PORT -> TAILSCALE_IP:PORT so terminal CLI commands work.
# IMPORTANT: stop_gw_relay must be called before restarting the gateway;
# otherwise the relay holds the loopback port and the new gateway instance
# detects it as "already listening" and exits with code 1.
start_gw_relay() {
  if [ "$GATEWAY_BIND_MODE" != "tailnet" ]; then
    return 0
  fi
  local ts_ip
  ts_ip=$(ip -4 addr show tailscale0 2>/dev/null \
    | awk '/inet /{gsub(/\/.*/,"",$2); print $2; exit}' || true)
  if [[ "${ts_ip:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "INFO: Starting loopback relay for tailnet gateway (127.0.0.1:${GATEWAY_PORT} -> ${ts_ip}:${GATEWAY_PORT})"
    node -e "
const net = require('net');
const TARGET_HOST = '${ts_ip}';
const TARGET_PORT = ${GATEWAY_PORT};
const server = net.createServer(function(c) {
  const t = net.createConnection(TARGET_PORT, TARGET_HOST);
  c.pipe(t); t.pipe(c);
  c.on('error', function() { t.destroy(); });
  t.on('error', function() { c.destroy(); });
});
server.listen(TARGET_PORT, '127.0.0.1');" &
    GW_RELAY_PID=$!
    echo "INFO: Loopback relay started (PID ${GW_RELAY_PID})"
  else
    echo "WARN: tailnet bind mode active but Tailscale IP not found on tailscale0 interface."
    echo "WARN: Terminal CLI may show gateway as unreachable. Ensure Tailscale is running and restart."
  fi
}

stop_gw_relay() {
  if [ -n "${GW_RELAY_PID}" ] && kill -0 "${GW_RELAY_PID}" >/dev/null 2>&1; then
    kill -TERM "${GW_RELAY_PID}" >/dev/null 2>&1 || true
    wait "${GW_RELAY_PID}" 2>/dev/null || true
    GW_RELAY_PID=""
  fi
}

# Find a running gateway daemon's PID using multiple detection methods.
# Used by the supervisor loop to detect self-restarts (SIGUSR1) without
# spawning duplicate gateway instances that collide on the port.
#
# Three tiers, tried in order of reliability:
#   1. Port ownership via `ss -tlnp` — authoritative, but only works once
#      the daemon has bound the port (can take 20+ s on Pi hardware).
#   2. Process title via `pgrep -f openclaw-gateway` — works after Node.js
#      sets process.title, which also happens late during init.
#   3. /proc cmdline scan — catches the daemon IMMEDIATELY after fork,
#      before title or port bind, by matching "openclaw" in the cmdline.
#      Excludes known PIDs (nginx, ttyd, relay, our shell, old GW_PID).
#
# Returns the PID on stdout and exit 0, or exits with code 1 if nothing found.
find_gateway_daemon_pid() {
  local pid=""

  # Tier 1: port ownership (authoritative once port is bound)
  pid=$(ss -tlnp 2>/dev/null \
    | grep ":${GATEWAY_INTERNAL_PORT} " \
    | sed -n 's/.*pid=\([0-9]*\).*/\1/p' \
    | head -1)
  [ -n "$pid" ] && { echo "$pid"; return 0; }

  # Tier 2: process title (after Node sets process.title)
  pid=$(pgrep -f "openclaw-gateway" 2>/dev/null | head -1)
  [ -n "$pid" ] && { echo "$pid"; return 0; }

  # Tier 3: scan /proc for any openclaw process we don't already know about.
  # The daemon's cmdline (e.g. node /usr/.../openclaw/...) contains "openclaw"
  # from the moment it is forked, even before process.title is set.
  # Not with OPENCLAW_NO_RESPAWN=1 (2026.8+): restarts stay in-process, so the
  # gateway PID stays our child, and the scan could adopt an unrelated
  # `openclaw` CLI process (hiding exit codes, or signalling it on shutdown).
  if [ "${OPENCLAW_NO_RESPAWN:-}" != "1" ]; then
    local known=" ${NGINX_PID:-0} ${TTYD_PID:-0} ${GW_RELAY_PID:-0} ${GW_PID:-0} $$ "
    local f cand
    for f in /proc/[0-9]*/cmdline; do
      [ -r "$f" ] || continue
      if tr '\0' ' ' < "$f" 2>/dev/null | grep -q "openclaw"; then
        cand="${f#/proc/}"
        cand="${cand%%/*}"
        case "$known" in *" $cand "*) continue ;; esac
        echo "$cand"
        return 0
      fi
    done
  fi

  return 1
}

if [ "$STATE_HOLD" = "true" ]; then
  echo "ERROR: HOLD: OpenClaw runtime not started (see above / oc-upgrade status)."
elif [ "$SHUTTING_DOWN" = "true" ]; then
  echo "INFO: Stop requested during startup; exiting."
  exit 0
elif start_openclaw_runtime; then
  start_gw_relay
else
  # Keep the add-on page and terminal up instead of exiting PID 1.
  enter_hold "OpenClaw could not be started (see the error above). Fix the add-on configuration, then restart the add-on."
fi

# Start web terminal (optional)
TTYD_PID_FILE="/var/run/openclaw-ttyd.pid"

# Clean up stale ttyd process from previous run using PID file
if [ -f "$TTYD_PID_FILE" ]; then
  OLD_PID=$(cat "$TTYD_PID_FILE" 2>/dev/null || echo "")
  if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "Stopping previous ttyd process (PID $OLD_PID)..."
    kill "$OLD_PID" 2>/dev/null || true
    sleep 1
    # Force kill if still running
    kill -9 "$OLD_PID" 2>/dev/null || true
  fi
  rm -f "$TTYD_PID_FILE"
fi

if [ "$ENABLE_TERMINAL" = "true" ] || [ "$ENABLE_TERMINAL" = "1" ]; then
  # Check if the terminal port is already in use before starting ttyd
  if command -v ss >/dev/null 2>&1 && ss -tlnp 2>/dev/null | grep -q ":${TERMINAL_PORT} "; then
    echo ""
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "!!  WARNING: terminal_port ${TERMINAL_PORT} IS ALREADY IN USE  !!"
    echo "!!                                                             !!"
    echo "!!  The web terminal (ttyd) may FAIL to start because port     !!"
    echo "!!  ${TERMINAL_PORT} appears to be in use by another process.  !!"
    echo "!!                                                             !!"
    echo "!!  ACTION REQUIRED: If the terminal does not work, go to      !!"
    echo "!!  Add-on Configuration and change 'terminal_port' to a free  !!"
    echo "!!  port, then restart the add-on.                             !!"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo ""
  fi
  echo "Starting web terminal (ttyd) on 127.0.0.1:${TERMINAL_PORT} ..."
  ttyd -W -i 127.0.0.1 -p "${TERMINAL_PORT}" -b /terminal bash &
  TTYD_PID=$!
  echo "$TTYD_PID" > "$TTYD_PID_FILE"
  echo "ttyd started with PID $TTYD_PID"
else
  echo "Terminal disabled (enable_terminal=$ENABLE_TERMINAL)"
fi

# Start ingress reverse proxy (nginx). This provides the add-on UI inside HA.
# Token is injected server-side; never put it in the browser URL.
NGINX_PID_FILE="/var/run/openclaw-nginx.pid"

# Clean up stale nginx process from previous run (e.g., after crash/unclean restart)
if [ -f "$NGINX_PID_FILE" ]; then
  OLD_NGINX_PID=$(cat "$NGINX_PID_FILE" 2>/dev/null || echo "")
  if [ -n "$OLD_NGINX_PID" ] && kill -0 "$OLD_NGINX_PID" 2>/dev/null; then
    echo "Stopping previous nginx process (PID $OLD_NGINX_PID)..."
    kill "$OLD_NGINX_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$OLD_NGINX_PID" 2>/dev/null || true
  fi
  rm -f "$NGINX_PID_FILE"
fi
# Also kill any orphaned nginx workers that might hold port 48099
if command -v pkill >/dev/null 2>&1; then
  pkill -f "nginx.*-c /etc/nginx/nginx.conf" 2>/dev/null || true
  sleep 1
fi
# Verify port 48099 is actually free before proceeding
if command -v ss >/dev/null 2>&1 && ss -tlnp 2>/dev/null | grep -q ':48099 '; then
  echo "WARN: Port 48099 still in use after cleanup; nginx may fail to start"
fi

# ------------------------------------------------------------------------------
# render_landing: (re-)render the nginx config + landing page HTML.
#
# Called once before nginx starts (token may be empty on first boot/pre-onboard)
# and again in the background after the gateway comes up so a freshly-generated
# token is immediately reflected in the "Open Gateway Web UI" button.
# nginx is sent SIGHUP to reload the updated config without restarting.
# ------------------------------------------------------------------------------
render_landing() {
  local label="${1:-startup}"
  # Read gateway token directly from openclaw.json (CLI redacts secrets v2026.2.22+)
  local token
  token="$(python3 -c "
import json, os
p = os.environ.get('OPENCLAW_CONFIG_PATH', '/config/.openclaw/openclaw.json')
print(json.load(open(p)).get('gateway',{}).get('auth',{}).get('token',''), end='')
" 2>/dev/null || true)"

  local disk_total="" disk_used="" disk_avail="" disk_pct=""
  if df -h /config >/dev/null 2>&1; then
    disk_total=$(df -h /config | awk 'NR==2{print $2}')
    disk_used=$(df -h /config  | awk 'NR==2{print $3}')
    disk_avail=$(df -h /config | awk 'NR==2{print $4}')
    disk_pct=$(df -h /config   | awk 'NR==2{print $5}')
    if [ "$label" = "startup" ]; then
      echo "INFO: Disk usage: ${disk_used}/${disk_total} (${disk_pct} used, ${disk_avail} free)"
      local pct_num=${disk_pct//%/}
      if [ "$pct_num" -ge 90 ] 2>/dev/null; then
        echo "WARNING: Disk is ${disk_pct} full! Add-on updates may fail. Run 'oc-cleanup' in the terminal."
      elif [ "$pct_num" -ge 75 ] 2>/dev/null; then
        echo "NOTICE: Disk is ${disk_pct} full. Consider running 'oc-cleanup' in the terminal."
      fi
    fi
  fi

  GW_PUBLIC_URL="$GW_PUBLIC_URL" GW_TOKEN="$token" TERMINAL_PORT="$TERMINAL_PORT" \
    ENABLE_HTTPS_PROXY="$ENABLE_HTTPS_PROXY" HTTPS_PROXY_PORT="$GATEWAY_PORT" \
    GATEWAY_INTERNAL_PORT="$GATEWAY_INTERNAL_PORT" ACCESS_MODE="$ACCESS_MODE" \
    DISK_TOTAL="$disk_total" DISK_USED="$disk_used" DISK_AVAIL="$disk_avail" DISK_PCT="$disk_pct" \
    NGINX_LOG_LEVEL="$NGINX_LOG_LEVEL" \
    RESOURCE_PROFILE="$EFFECTIVE_PROFILE" NODE_HEAP_MB="$NODE_HEAP_MB" \
    python3 /render_nginx.py

  if [ "$label" != "startup" ]; then
    # Signal nginx to reload config/landing HTML without dropping connections.
    local nginx_pid
    nginx_pid=$(cat "${NGINX_PID_FILE:-/var/run/openclaw-nginx.pid}" 2>/dev/null || true)
    if [ -n "$nginx_pid" ] && kill -0 "$nginx_pid" 2>/dev/null; then
      kill -HUP "$nginx_pid" 2>/dev/null || true
      echo "INFO: Landing page re-rendered with gateway token (nginx reloaded)."
    fi
  fi
}

# Initial render (token may be absent if openclaw.json does not exist yet)
render_landing startup

echo "Starting ingress proxy (nginx) on :48099 ..."
nginx -g 'daemon off;' &
NGINX_PID=$!
sleep 1
if kill -0 "$NGINX_PID" 2>/dev/null; then
  echo "$NGINX_PID" > "$NGINX_PID_FILE"
  echo "nginx started with PID $NGINX_PID"
else
  echo "WARN: nginx failed to start (PID $NGINX_PID exited); ingress UI may be unavailable"
fi

# If the token was not available at startup (first boot / pre-onboard), schedule
# a background re-render so the "Open Gateway Web UI" button gets the real token
# once openclaw onboard writes openclaw.json (typically within 30-90 s).
(
  CONFIG_PATH="${OPENCLAW_CONFIG_PATH:-/config/.openclaw/openclaw.json}"
  for _i in $(seq 1 24); do
    sleep 5
    token=$(python3 -c "
import json, os
p='$CONFIG_PATH'
try:
    print(json.load(open(p)).get('gateway',{}).get('auth',{}).get('token',''), end='')
except Exception:
    pass
" 2>/dev/null || true)
    if [ -n "$token" ]; then
      render_landing post-onboard
      break
    fi
  done
) &

# ------------------------------------------------------------------------------
# Home Assistant health sensors (optional)
# Publishes gateway status / version / memory / disk / cert expiry as HA states
# so users can alert on them. One curl per interval; no resident daemon.
# ------------------------------------------------------------------------------
if [ "$HA_HEALTH_SENSORS" = "true" ] || [ "$HA_HEALTH_SENSORS" = "1" ]; then
  # Gate on the current option value, not the token file: clearing
  # homeassistant_token leaves the previously written file behind.
  if [ -z "${SUPERVISOR_TOKEN:-}" ] && [ -z "$HA_TOKEN" ]; then
    echo "WARN: ha_health_sensors=true but no Home Assistant token is available."
    echo "WARN: Set 'homeassistant_token' in the add-on Configuration and restart."
    echo "WARN: Preview the sensors without publishing by running 'oc-health show'."
  elif command -v oc-health >/dev/null 2>&1; then
    HA_HEALTH_INTERVAL="$HA_HEALTH_INTERVAL" \
    HA_BASE_URL="$HA_BASE_URL" \
    ADDON_VERSION="${ADDON_VERSION:-unknown}" \
    ACCESS_MODE="$ACCESS_MODE" \
    GATEWAY_BIND_MODE="$GATEWAY_BIND_MODE" \
    GATEWAY_INTERNAL_PORT="$GATEWAY_INTERNAL_PORT" \
    RESOURCE_PROFILE="$EFFECTIVE_PROFILE" \
    NODE_HEAP_MB="$NODE_HEAP_MB" \
    ENABLE_HTTPS_PROXY="$ENABLE_HTTPS_PROXY" \
      oc-health loop &
    HEALTH_PID=$!
    echo "INFO: Home Assistant health sensors enabled (PID ${HEALTH_PID}, every ${HA_HEALTH_INTERVAL}s)"
  else
    echo "WARN: oc-health is missing from the add-on image; skipping health sensors."
  fi
else
  echo "INFO: ha_health_sensors=false; not publishing Home Assistant sensor entities."
fi

# Keep add-on alive even if gateway/node runtime restarts itself (e.g. during onboarding).
# If runtime exits unexpectedly, restart it while nginx/ttyd stay up.
#
# OpenClaw 2026.8+ (OPENCLAW_NO_RESPAWN=1): restarts stay in-process, so the
# gateway PID stays our child and `wait` returns its real exit code. Exit 78
# means the gateway refused to start (invalid config, unmigrated or newer state,
# lock, gateway.mode): that is a HOLD at once, never a restart loop and never an
# automatic doctor run. Ten failed starts in a row are a HOLD as well. Both stay
# until `oc-upgrade retry` (sticky across restarts). 2026.7.x keeps the
# behaviour described below.
#
# Design notes (issue #95, OpenClaw 2026.7.x):
#   `openclaw gateway run` is a thin wrapper that spawns `openclaw-gateway` as a
#   long-running daemon and then exits. When the gateway self-restarts (SIGUSR1 /
#   `openclaw gateway restart`), the old daemon exits and a NEW daemon is forked —
#   the new PID is NOT a child of this shell so `wait` cannot block on it.
#
#   The new daemon can take 20-30 seconds to initialise on low-power hardware
#   (Pi / eMMC). During that time its process.title and port binding are not yet
#   visible, but the process itself exists in /proc with "openclaw" in its cmdline.
#
#   Strategy:
#     1. `wait` for our child (the wrapper). After it exits, use
#        `find_gateway_daemon_pid` (port → pgrep → /proc scan) with retries
#        to find the daemon. If found → re-track and poll with `kill -0`.
#     2. When the re-tracked daemon eventually exits (crash or another restart),
#        `kill -0` fails, we check again for a live daemon to re-track.
#     3. Before any supervisor-initiated restart, do a final port-occupancy
#        guard to prevent launching a duplicate.
GW_IS_CHILD=true   # true only when GW_PID was started by us (can use `wait`)

# Consecutive failed starts, used for restart backoff (reset once a boot sticks).
GW_FAIL_STREAK=0
# Fork policy: the add-on never runs `openclaw doctor --fix` on its own after
# startup. Upstream retries a crash-looping gateway with an automatic
# `openclaw doctor --fix --non-interactive --yes`. On this deployment that would
# run OpenClaw's config/state migrations (e.g. the openai-codex -> openai route
# migration) unattended and without a pre-migration backup. Doctor runs only in
# the migration gate at startup (archive first, checks after), also when
# requested with `oc-upgrade retry --doctor`. A crash loop backs off and
# reports; on OpenClaw 2026.8+ it ends in a HOLD.
GW_CRASH_LOOP_HOLD_AFTER=10

if [ "$STATE_HOLD" = "true" ]; then
  # Keep nginx/ttyd (and the health sensors) running so the user can inspect
  # and restore; wait until the Supervisor stops the add-on.
  hold_wait_loop
  exit 0
fi

while true; do
  GW_START_SECONDS=$SECONDS
  if [ "$GW_IS_CHILD" = "true" ]; then
    # Efficient blocking wait on our child process.
    GW_EXIT_CODE=0
    wait "${GW_PID}" 2>/dev/null || GW_EXIT_CODE=$?
  else
    # GW_PID is NOT our child (re-tracked after a self-restart).
    # Poll with kill -0 until it exits.
    while kill -0 "$GW_PID" 2>/dev/null; do
      if [ "$SHUTTING_DOWN" = "true" ]; then break 2; fi
      sleep 5 &
      wait "$!" || true
    done
    GW_EXIT_CODE=0
  fi

  # Capture how long the runtime actually lived BEFORE the daemon-detection
  # retries below, otherwise their sleeps count as gateway uptime.
  GW_UPTIME=$((SECONDS - GW_START_SECONDS))

  if [ "$SHUTTING_DOWN" = "true" ]; then
    break
  fi

  # OpenClaw 2026.8+ exit 78: the gateway refused to start. Record a sticky
  # HOLD (oc-upgrade classifies the state and writes hold.txt) and wait.
  if [ "$GW_IS_CHILD" = "true" ] && [ "${GW_EXIT_CODE:-0}" -eq 78 ] && runtime_at_least 2026.8.0; then
    stop_gw_relay
    hold_out="$(oc-upgrade gate --hold-exit78 2>&1 || true)"
    if [ -s "${UPG_DIR}/hold.txt" ]; then hold_keep=keep; else hold_keep=""; fi
    enter_hold "OpenClaw exited with code 78 (it refused to start: configuration or state needs attention).
${hold_out}" "$hold_keep"
    hold_wait_loop
    exit 0
  fi

  # A runtime swapped inside the container (e.g. `npm install -g openclaw@...`)
  # must not be (re)started or adopted after a self-restart: check before the
  # daemon detection below, stop a daemon that may already run the swapped
  # code, and hold here without counting it as a crash.
  RUNTIME_PROBLEM="$(runtime_integrity_problem)"
  if [ -n "$RUNTIME_PROBLEM" ]; then
    if [ "$RUNTIME_PROBLEM" != "${LAST_RUNTIME_PROBLEM:-}" ]; then
      {
        echo "OpenClaw is held (bundled runtime ${OPENCLAW_RUNTIME_VERSION:-unknown}):"
        echo "${RUNTIME_PROBLEM}."
        echo "Reinstall or rebuild the add-on in Home Assistant to restore the pinned OpenClaw runtime."
      } > "${UPG_DIR}/hold.txt" 2>/dev/null || true
      echo "ERROR: HOLD — not restarting OpenClaw: ${RUNTIME_PROBLEM}."
      echo "ERROR: Reinstall or rebuild the add-on in Home Assistant. Details: oc-upgrade status"
      LAST_RUNTIME_PROBLEM="$RUNTIME_PROBLEM"
    fi
    _swapped_pid="$(ss -tlnp 2>/dev/null | grep ":${GATEWAY_INTERNAL_PORT} " \
      | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | head -1 || true)"
    [ -n "$_swapped_pid" ] || _swapped_pid="$(pgrep -f "openclaw-gateway" 2>/dev/null | head -1 || true)"
    if [ -n "$_swapped_pid" ] && kill -0 "$_swapped_pid" 2>/dev/null; then
      echo "ERROR: Stopping gateway PID ${_swapped_pid} (it may run the swapped OpenClaw)."
      kill -TERM "$_swapped_pid" 2>/dev/null || true
    fi
    stop_gw_relay
    sleep 60 &
    wait "$!" || true
    if [ "$SHUTTING_DOWN" = "true" ]; then
      break
    fi
    GW_IS_CHILD=true
    GW_PID=""
    continue
  fi
  LAST_RUNTIME_PROBLEM=""

  # --- Detect self-restart ---------------------------------------------------
  # Try up to 10 times (≈ 20 s) using all 3 tiers of find_gateway_daemon_pid.
  # Tier 3 (/proc scan) usually finds the daemon on the very first attempt
  # because the process exists immediately after fork, even before port bind
  # or process.title. The retries cover edge cases on extremely slow I/O.
  # Every sleep in this crash-restart window is `sleep & wait`, so a stop
  # request runs the shutdown trap at once, and SHUTTING_DOWN is checked again
  # after the detection, after the backoff and right before a restart: a
  # gateway started after shutdown() would never be stopped.
  RESTARTED_PID=""
  if [ "$GATEWAY_MODE" != "remote" ]; then
    for _attempt in 1 2 3 4 5 6 7 8 9 10; do
      RESTARTED_PID=$(find_gateway_daemon_pid 2>/dev/null || true)
      [ -n "$RESTARTED_PID" ] && break
      [ "$SHUTTING_DOWN" = "true" ] && break
      sleep 2 &
      wait "$!" || true
    done
  else
    sleep 2 &
    wait "$!" || true
    RESTARTED_PID=$(pgrep -f "openclaw.*node.*run" 2>/dev/null | head -1 || true)
  fi
  if [ "$SHUTTING_DOWN" = "true" ]; then
    break
  fi

  if [ -n "$RESTARTED_PID" ]; then
    echo "INFO: OpenClaw runtime active (PID $RESTARTED_PID); monitoring."
    GW_FAIL_STREAK=0
    GW_PID="$RESTARTED_PID"
    GW_IS_CHILD=false
    continue
  fi

  # --- Final port guard ------------------------------------------------------
  # Even if all detection methods missed the daemon during the loop above,
  # the port may now be bound (the daemon finished initialising while we slept).
  # Never launch a duplicate if the port is occupied.
  if [ "$GATEWAY_MODE" != "remote" ] && \
     ss -tlnp 2>/dev/null | grep -q ":${GATEWAY_INTERNAL_PORT} "; then
    PORT_PID=$(ss -tlnp 2>/dev/null \
      | grep ":${GATEWAY_INTERNAL_PORT} " \
      | sed -n 's/.*pid=\([0-9]*\).*/\1/p' \
      | head -1 || true)
    echo "INFO: Gateway port ${GATEWAY_INTERNAL_PORT} occupied by PID ${PORT_PID:-unknown}; monitoring."
    GW_FAIL_STREAK=0
    GW_PID="${PORT_PID:-$GW_PID}"
    GW_IS_CHILD=false
    continue
  fi

  # Exponential backoff so a persistently broken gateway cannot hammer the CPU
  # or fill the disk with stability bundles. Reset whenever a start sticks.
  # A runtime that stayed up for a while is not part of a crash loop.
  # The threshold is well above a normal cold start (~45s on this image) so a
  # gateway that only ever survives its own startup still counts as looping.
  if [ "$GW_UPTIME" -ge 120 ]; then
    GW_FAIL_STREAK=0
  fi

  GW_FAIL_STREAK=$((GW_FAIL_STREAK + 1))
  GW_BACKOFF=$((2 ** (GW_FAIL_STREAK < 6 ? GW_FAIL_STREAK : 6)))
  if [ "$GW_BACKOFF" -gt 60 ]; then
    GW_BACKOFF=60
  fi

  if [ "$GW_FAIL_STREAK" -ge "$GW_CRASH_LOOP_HOLD_AFTER" ] && runtime_at_least 2026.8.0; then
    # Crash loop: stop restarting and hold (sticky until `oc-upgrade retry`).
    stop_gw_relay
    hold_out="$(oc-upgrade gate --hold-crash-loop "${GW_EXIT_CODE}" 2>&1 || true)"
    if [ -s "${UPG_DIR}/hold.txt" ]; then hold_keep=keep; else hold_keep=""; fi
    enter_hold "OpenClaw failed to start ${GW_FAIL_STREAK} times in a row (last exit code ${GW_EXIT_CODE}).
${hold_out}" "$hold_keep"
    hold_wait_loop
    exit 0
  fi

  if [ "$GW_FAIL_STREAK" -ge 5 ]; then
    echo "ERROR: OpenClaw runtime has failed ${GW_FAIL_STREAK} times in a row."
    echo "ERROR: The terminal and add-on page stay available — open the terminal and run:"
    echo "ERROR:   oc-gateway status"
    echo "ERROR:   openclaw config validate"
    if runtime_at_least 2026.8.0; then
      echo "ERROR:   openclaw doctor --lint   (read-only)"
      echo "ERROR: Do not run 'openclaw doctor --fix' by hand (blocked). Use 'oc-upgrade retry --doctor',"
      echo "ERROR: which archives the state first; then restart the add-on."
    else
      echo "ERROR: Take a Home Assistant backup of the add-on before running 'openclaw doctor --fix':"
      echo "ERROR: it migrates configuration and state and cannot be undone without that backup."
    fi
    echo "ERROR: Recent failures are detailed in /config/.openclaw/logs/stability/."
  fi

  echo "WARN: OpenClaw runtime exited with code ${GW_EXIT_CODE}. Restarting in ${GW_BACKOFF}s..."
  sleep "$GW_BACKOFF" &
  wait "$!" || true
  if [ "$SHUTTING_DOWN" = "true" ]; then
    break
  fi

  # Stop the loopback relay BEFORE restarting the gateway (tailnet mode only).
  # The relay holds 127.0.0.1:GATEWAY_PORT — leaving it up causes the new gateway
  # to detect the port as occupied and exit with code 1, re-entering the loop.
  stop_gw_relay

  if [ "$SHUTTING_DOWN" = "true" ]; then
    break
  fi
  if ! start_openclaw_runtime; then
    echo "ERROR: Failed to restart OpenClaw runtime; retrying in 5s..."
    sleep 5 &
    wait "$!" || true
  else
    GW_IS_CHILD=true
    start_gw_relay
  fi
done
