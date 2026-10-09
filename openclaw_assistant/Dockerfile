ARG BUILD_FROM
FROM ${BUILD_FROM}

# Base image is Debian Bookworm (glibc). This avoids musl-related native module issues
# that occur on Alpine (e.g. clipboard, node-llama-cpp).

# Install base packages (without nodejs/npm - we'll get Node 24 from NodeSource)
# build-essential provides gcc/cc needed by Homebrew for OpenClaw's brew-managed dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    git \
    openssh-client \
    ca-certificates \
    tzdata \
    jq \
    curl \
    tar \
    xz-utils \
    file \
    python3 \
    cmake \
    nginx \
    gnupg \
    build-essential \
    sudo \
    vim \
    nano \
    fd-find \
    ripgrep \
    rsync \
    bat \
    less \
    openssl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 24 LTS from NodeSource.
# OpenClaw 2026.9.9 requires Node >=24.16.0 <25 || >=26.1.0 (package.json
# engines); on an older Node it refuses to run or tries to install another Node.
# Use explicit keyring + apt source instead of setup_24.x pipe script for deterministic builds.
RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
    | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && chmod 644 /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_24.x nodistro main" \
    > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && NODE_VERSION="$(node -v)" \
    && echo "$NODE_VERSION" \
    && node -e 'const[a,b]=process.versions.node.split(".").map(Number);if(!((a===24&&b>=16)||(a===26&&b>=1)||a>26)){console.error("Node "+process.versions.node+" does not satisfy >=24.16.0 <25 || >=26.1.0");process.exit(1)}' \
    && rm -f /etc/apt/sources.list.d/nodesource.list /etc/apt/keyrings/nodesource.gpg \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install ttyd (web terminal) - not in Debian repos, download binary
# Docker TARGETARCH: amd64, arm64, arm/v7 → ttyd filenames: x86_64, aarch64, armhf
ARG TARGETARCH
RUN ARCH=$(echo ${TARGETARCH:-$(dpkg --print-architecture)} | sed 's|arm64|aarch64|;s|arm/v7|armhf|;s|armv7|armhf|;s|amd64|x86_64|') \
    && echo "Downloading ttyd for arch: ${ARCH}" \
    && curl -fsSL "https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.${ARCH}" -o /usr/local/bin/ttyd \
    && chmod +x /usr/local/bin/ttyd

RUN node -v && npm -v

# Install pnpm globally (required by some OpenClaw skills like clawhub)
RUN npm install -g pnpm && pnpm -v

# Install Chromium for website automation tasks
# Includes necessary dependencies for headless browser operation
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Homebrew (Linuxbrew) for OpenClaw skill dependencies
# Homebrew is optional - some skills need CLI tools like gemini, aider, etc.
# NOTE: Homebrew requires CPU with SSSE3 support (Intel Core 2 or newer, ~2006+)
# If installation fails (e.g., older CPUs), the add-on will still work but some skills may not install
ENV HOMEBREW_NO_AUTO_UPDATE=1 \
    HOMEBREW_NO_INSTALL_CLEANUP=1 \
    HOMEBREW_NO_ANALYTICS=1

RUN useradd -m -s /bin/bash linuxbrew \
    && mkdir -p /home/linuxbrew/.linuxbrew \
    && chown -R linuxbrew:linuxbrew /home/linuxbrew

USER linuxbrew
RUN /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || \
    (echo "WARNING: Homebrew installation failed (likely unsupported CPU - requires SSSE3). Some skills may not work." && exit 0)
RUN if [ -d /home/linuxbrew/.linuxbrew/Homebrew ]; then \
    cd /home/linuxbrew/.linuxbrew/Homebrew && \
    git config --global --add safe.directory /home/linuxbrew/.linuxbrew/Homebrew && \
    /home/linuxbrew/.linuxbrew/bin/brew update --force || true; \
    fi
USER root

# Add Homebrew to PATH for all users (wrapper comes first to intercept root calls)
# PATH is set even if brew failed - wrapper will handle missing brew gracefully
ENV PATH="/usr/local/bin:/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:${PATH}"

# Copy brew wrapper that allows root to run brew by delegating to linuxbrew user
COPY brew-wrapper.sh /usr/local/bin/brew
RUN chmod +x /usr/local/bin/brew

# Verify brew is available and install gcc (needed for compiling some brew packages)
# Skip if brew installation failed
USER linuxbrew
RUN if [ -x /home/linuxbrew/.linuxbrew/bin/brew ]; then \
    /home/linuxbrew/.linuxbrew/bin/brew --version && \
    /home/linuxbrew/.linuxbrew/bin/brew install gcc || true; \
    else \
    echo "Skipping gcc installation - Homebrew not available"; \
    fi
USER root

# Install OpenClaw globally.
# Bundle node-llama-cpp so the default local memory/embeddings provider works
# in HAOS without requiring manual npm installs in /usr/lib.
# Bundle mcporter so Home Assistant MCP auto-configuration works out of the box.
# The image now ships Node 24, so use the current mcporter line.
#
# Version pins — bump all three together (and re-verify the migration gate's
# assumptions against the new dist, see the Stage B notes):
#   OPENCLAW_VERSION      the bundled OpenClaw (the migration gate migrates the
#                         persistent state to it, one-way).
#   BRAVE_PLUGIN_VERSION  @openclaw/brave-plugin, CalVer lockstep with OpenClaw;
#                         recorded in the image for run.sh (installed at runtime
#                         into the persistent state, so it cannot be baked in).
#   NPM_BEFORE            npm resolves every dependency as of this UTC time.
#                         openclaw ships no npm-shrinkwrap.json, so this limits
#                         dependency drift between rebuilds. Must be after the
#                         publish times of the pins (openclaw@2026.9.9
#                         2026-10-08T09:38:01Z, @openclaw/brave-plugin@2026.9.9
#                         2026-10-08T09:11:35Z).
ARG OPENCLAW_VERSION=2026.9.9
ARG BRAVE_PLUGIN_VERSION=2026.9.9
ARG NPM_BEFORE=2026-10-08T12:00:00Z
# Repeated here (cheap) so this part of the build also checks the Node range
# when it is built on top of another base.
RUN node -e 'const[a,b]=process.versions.node.split(".").map(Number);if(!((a===24&&b>=16)||(a===26&&b>=1)||a>26)){console.error("Node "+process.versions.node+" does not satisfy >=24.16.0 <25 || >=26.1.0");process.exit(1)}'
# Never use --ignore-scripts: the package lifecycle marker would make the first
# CLI run replay the install scripts (or exit 1). The checks below fail the build
# when the installed package is not the pinned, fully installed version, when it
# lacks the schema targets the migration gate reads, when Node's bundled SQLite
# fails OpenClaw's own capability probe, when Node rejects the NODE_OPTIONS
# flags run.sh sets, or when the pinned Brave plugin version does not exist.
RUN npm config set fund false && npm config set audit false \
    && npm install -g --before="${NPM_BEFORE}" "openclaw@${OPENCLAW_VERSION}" node-llama-cpp@3.18.1 mcporter@0.12.3 \
    && pkg="$(npm root -g)/openclaw" \
    && test "$(jq -r .version "$pkg/package.json")" = "${OPENCLAW_VERSION}" \
    && test ! -e "$pkg/.openclaw-lifecycle-pending" \
    && test ! -e "$pkg/dist/openclaw-install-guard" \
    && jq -e '.openclaw.schemaVersions.state and .openclaw.schemaVersions.agent' "$pkg/package.json" >/dev/null \
    && OCQ_PKG="$pkg" node --input-type=module -e "const m=await import(process.env.OCQ_PKG+'/node-sqlite.mjs');const p=await m.detectCurrentSqliteCapabilities();const f=m.nodeRuntimeFailure(process.versions.node,p);if(f){console.error(f);process.exit(1)}console.log('node',process.versions.node,'sqlite',p.version)" \
    && NODE_OPTIONS="--disable-sigusr1 --disable-warning=ExperimentalWarning" node -e 0 \
    && test "$(npm view "@openclaw/brave-plugin@${BRAVE_PLUGIN_VERSION}" version)" = "${BRAVE_PLUGIN_VERSION}"

# ACP / ACPX harness: lets OpenClaw drive external coding agents (Codex, Claude Code)
# via the Agent Client Protocol. Volt authenticates Anthropic + OpenAI via OAuth
# (not API keys), so the harness must ship in the image. Codex is NOT bundled in
# OpenClaw (2026.7.35 or 2026.9.9): it is the external @openclaw/codex plugin, and
# Brave and acpx are external plugins too; plugins live in the persistent state
# (/config/.openclaw/npm/projects). acpx + the Claude Code CLI cover the
# OAuth/ACP path. acpx auto-downloads the codex-acp / claude-agent-acp adapters
# via npx on first use.
# Pinned (not floating) so an image rebuild cannot silently change the harness.
RUN npm install -g acpx@0.19.3 @anthropic-ai/claude-code@2.1.283

# Shell aliases and color options for interactive use
RUN tee -a /etc/bash.bashrc <<'EOF'

# Aliases
alias bat="batcat"
alias fd="fdfind"

# Enable colors
alias ls="ls --color=auto"
alias grep="grep --color=auto"
alias egrep="grep -E --color=auto"
alias fgrep="grep -F --color=auto"
alias diff="diff --color=auto"
alias ip="ip --color=auto"
if [ -z "${LS_COLORS+x}" ]; then
  export LS_COLORS="di=1;34:ln=1;36:so=1;pi=33:ex=1;32:bd=1;33:cd=1;33:su=1;31:sg=1;31:tw=1;34:ow=1;34"
fi
EOF
# Expose the add-on version to the runtime (Home Assistant's builder passes
# BUILD_VERSION); used by the optional Home Assistant health sensors.
ARG BUILD_VERSION
ENV ADDON_VERSION=${BUILD_VERSION}

COPY run.sh /run.sh
COPY oc_config_helper.py /oc_config_helper.py
COPY render_nginx.py /render_nginx.py
COPY oc-cleanup.sh /usr/local/bin/oc-cleanup
COPY oc-gateway /usr/local/bin/oc-gateway
COPY oc-health.sh /usr/local/bin/oc-health
COPY oc-config.sh /usr/local/bin/oc-config
COPY oc_upgrade.py /usr/local/bin/oc-upgrade
# Migration gate modules (imported by oc-upgrade from OC_ADDON_PYLIB).
COPY oc_common.py oc_migrate.py oc_gate.py /usr/local/lib/oc-addon/python/
COPY openclaw-wrapper.sh /usr/local/libexec/oc-addon/openclaw
COPY openclaw-proxy-shim.cjs /usr/local/lib/openclaw-proxy-shim.cjs
COPY nginx.conf.tpl /etc/nginx/nginx.conf.tpl
COPY landing.html.tpl /etc/nginx/landing.html.tpl
RUN chmod +x /run.sh /oc_config_helper.py /render_nginx.py /usr/local/bin/oc-cleanup /usr/local/bin/oc-gateway \
    /usr/local/bin/oc-health /usr/local/bin/oc-config /usr/local/bin/oc-upgrade \
    /usr/local/libexec/oc-addon/openclaw \
    && mkdir -p /run/nginx \
    && python3 -c "import sys;[compile(open(p,encoding='utf-8').read(),p,'exec') for p in sys.argv[1:]]" \
       /usr/local/bin/oc-upgrade /usr/local/lib/oc-addon/python/*.py \
    && PYTHONDONTWRITEBYTECODE=1 python3 -c "import sys;sys.path.insert(0,'/usr/local/lib/oc-addon/python');import oc_common,oc_migrate,oc_gate" \
    && PYTHONDONTWRITEBYTECODE=1 /usr/local/bin/oc-upgrade --help >/dev/null \
    && test ! -e /usr/local/bin/__pycache__ && test ! -e /usr/local/lib/oc-addon/python/__pycache__

# Route every `openclaw` executable through the add-on wrapper (refuses
# `openclaw update` and a writing `openclaw doctor`, restricts commands while the
# add-on holds OpenClaw, independent of the caller's PATH order) and record the
# pinned package entry and version it runs, plus the Brave plugin version run.sh
# installs. The wrapper is also placed in every standard bin directory, so a
# later `npm install -g openclaw@...` (runtime npm prefix /usr/local) collides
# with it (EEXIST) instead of silently shadowing it. Then check the launcher's
# version, the doctor flags the migration gate relies on (in a throwaway HOME),
# and the wrapper's doctor rule.
RUN set -eu; \
    W=/usr/local/libexec/oc-addon/openclaw; \
    pkg="$(npm root -g)/openclaw"; \
    test -f "$pkg/openclaw.mjs"; \
    printf '%s\n' "$pkg/openclaw.mjs" > /usr/local/libexec/oc-addon/openclaw-entry; \
    jq -r .version "$pkg/package.json" > /usr/local/libexec/oc-addon/openclaw-pinned-version; \
    printf '%s\n' "${BRAVE_PLUGIN_VERSION}" > /usr/local/libexec/oc-addon/brave-plugin-version; \
    for bin in $(IFS=:; for d in $PATH; do [ -e "$d/openclaw" ] && echo "$d/openclaw"; done | sort -u); do \
      if [ "$(readlink -f "$bin")" != "$(readlink -f "$W")" ]; then ln -sf "$W" "$bin"; fi; \
    done; \
    for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin; do \
      mkdir -p "$d"; \
      if [ "$(readlink -f "$d/openclaw" 2>/dev/null || true)" != "$(readlink -f "$W")" ]; then ln -sf "$W" "$d/openclaw"; fi; \
    done; \
    test "$(readlink -f "$(command -v openclaw)")" = "$(readlink -f "$W")"; \
    openclaw --version; \
    test "$(openclaw --version | sed -n 's/^OpenClaw \([0-9][0-9.]*\).*/\1/p')" = "${OPENCLAW_VERSION}"; \
    if openclaw update --help >/dev/null 2>&1; then echo "wrapper does not block update" >&2; exit 1; fi; \
    h="$(mktemp -d)"; \
    HOME="$h" node "$pkg/openclaw.mjs" doctor --help > "$h/doctor-help.txt" 2>&1; \
    for flag in --fix --non-interactive --lint; do \
      grep -q -- "$flag" "$h/doctor-help.txt" || { echo "openclaw doctor --help lacks $flag" >&2; exit 1; }; \
    done; \
    rc=0; HOME="$h" openclaw doctor --fix >/dev/null 2>&1 || rc=$?; \
    if [ "$rc" -ne 2 ]; then echo "wrapper does not block a writing doctor (exit $rc)" >&2; exit 1; fi; \
    HOME="$h" openclaw doctor --lint --help >/dev/null; \
    rm -rf "$h"

CMD [ "/run.sh" ]
