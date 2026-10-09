# Changelog

All notable changes to the OpenClaw Assistant Home Assistant Add-on will be documented in this file.

> **Private fork** (`Nosdave/OpenClawHomeAssistant`): `-ghcrN` / `-fullN` suffixes are fork build iterations on top of the upstream `techartdev` base version. The image is pre-built on GitHub Actions (native `aarch64`) and pulled from GHCR. `-fullN` marks the un-stripped "full" build line (see `0.5.80-full1`).


## [0.5.94-full1] - 2026-10-10

**OpenClaw `2026.7.35` → `2026.9.9`. One-way state migration.** Merges upstream `techartdev` 0.5.94 (which only bumps OpenClaw). Since OpenClaw 2026.9.7 the gateway no longer migrates 2026.7.x state on its own: it exits with code 78 until `openclaw doctor --fix` has run, and doctor's model-route repair can damage a 2026.7 config. The add-on therefore runs a **migration gate** once, before the first 9.9 gateway start.

**Before updating:** set auto-update off, stop the add-on, create a Home Assistant backup of the add-on and download it. Plan 1–3 hours. Do not stop the add-on while the log shows `[gate] … doctor pass … running`. Rollback is only through that backup (or the `/share` archive below) together with 0.5.93-full2: a 9.9 state cannot be opened by 7.35.

### Added
- **Migration gate** (`oc-upgrade gate`, run by the add-on at startup; every line starts with `[gate]`):
  1. **precheck** (read-only): bundled runtime and schema targets, Node/SQLite capability, no other OpenClaw process, readable `openclaw.json`, state not newer than the image, clean 2026.7 state, no legacy `/config/.clawdbot` dir, model preflight, legacy files, sessions, free space, SQLite `quick_check`, npm reachable (doctor updates official plugins).
  2. **archive**: `/config/.openclaw` and the workspace are written to `/share/openclaw-upgrade/<run>/openclaw-state-<ts>-before-2026.9.9.tar.gz` with `manifest.json` and `SHA256SUMS`, verified by re-reading the archive and comparing the sha256 of every SQLite file. **It contains secrets** (tokens, logins); delete it once you no longer need the rollback.
  3. **cleanup**: memory-search transient SQLite sidecars (e.g. `openclaw-agent.sqlite.reindex-lock.sqlite`) and legacy Telegram caches are moved to `/config/.openclaw-upgrade/gate/quarantine/<run>/` (logged per file, kept).
  4. **pre-migration** (only for legacy `openai-codex/…` refs): `openai-codex/*` wildcards become explicit model entries, and legacy Codex refs keep the OpenClaw runtime they used on 2026.7 (otherwise doctor replaces the primary model with a default or switches it to the Codex harness).
  5. **doctor** `--fix --non-interactive`, twice (a third pass only if the second still changes the config), with a time limit and a progress line every minute.
  6. **fixups** limited to migrated legacy refs; canonical `openai/*` refs keep their runtime (the Codex app-server by default, as on 2026.7). Retired model ids that doctor replaces are accepted and listed (`[gate] info: doctor replaced retired model X with Y`).
  7. **postconditions**: database schema, `config validate`, `doctor --lint`, no legacy refs, runtime of migrated refs, `models status`, sessions.
  8. **behaviour pins** (below), only where you have not set the key yourself, recorded in a ledger and never re-applied.
- **HOLD instead of a restart loop.** Any gate failure — and, after the migration, a gateway exit 78 or 10 failed starts in a row — stops OpenClaw while the add-on page and terminal stay up. `oc-upgrade status` shows the reason and the next step.
- **New commands:** `oc-upgrade retry [--doctor] [--accept CODE]` (continue on the next start; `--accept` passes an acceptable HOLD; `--doctor` re-runs doctor with a new archive), `oc-upgrade log` (redacted doctor log), `oc-upgrade gate --dry-run` (read-only preview). `oc-upgrade check` gains a "migration gate readiness" section.
- A `WARN` after 60 s when the gateway is still stopping (see "Changed").

### Changed
- **`openclaw doctor` is refused in the terminal unless read-only** (`--lint`, `--json`, `--post-upgrade`, `--help`): plain `doctor` migrates without a backup. Use `oc-upgrade retry --doctor` and restart the add-on. In HOLD only read-only commands are allowed (`--version`, `config validate|get|file|schema`, `doctor --lint`, `logs`). `OC_ADDON_UNSAFE=1 openclaw …` bypasses this for guided recovery.
- **Behaviour pins** that keep 2026.7 defaults (only where unset): `agents.defaults.maxConcurrent` 4; subagents `maxSpawnDepth` 1 and `delegationMode` `suggest`; gateway terminal and CLI agents off; session visibility `tree`; agent-to-agent and cross-provider messages off; code mode, tool search and swarm off; skill workshop `pending` / autonomous `off`; dreaming off (only if not set — an explicit `true` stays), transcripts off, no utility model, no cross-conversation memory; Telegram `streaming.mode` `partial`, raw command preview, no join intro; groups may stay silent; daily session reset at 04:00; **heartbeat target `none`** (9.9's default `owner` would send every heartbeat to your DM); session maintenance 500 entries, no new-session notice; Control UI session observer and favicon fetching off; geolocation and GitHub plugins off; no automatic model failover on cyber refusals.
- Environment for 9.x: `OPENCLAW_NO_RESPAWN=1`, `OPENCLAW_SUPERVISOR_MODE=external`, `OPENCLAW_SERVICE_REPAIR_POLICY=external`, Node `--disable-sigusr1` (a stray SIGUSR1 no longer opens the Node inspector). `oc-gateway restart` uses SIGUSR2.
- Brave web-search plugin `2026.9.9`; image requires Node ≥ 24.16 and checks the OpenClaw package, the doctor flags and the wrapper at build time.
- Add-on helper failures and a failed gateway start now HOLD instead of stopping the add-on.
- `oc-cleanup` keeps OpenClaw's `/tmp/openclaw*` logs.

### Unavoidable changes in OpenClaw 2026.9 (not reverted by the add-on)
- **Every browser must be paired once** for the Control UI; `controlui_disable_device_auth` is inert (`openclaw devices list` / `openclaw devices approve <id>`).
- Model names show as `openai/<model>`; retired ids are upgraded by doctor (e.g. `claude-opus-4-5` → `4-7`, `claude-sonnet-4-5` → `4-6`, `gpt-5.1-codex` → `gpt-5.3-codex`, aliases kept).
- `agents.list` becomes `agents.entries`; `imageGenerationModel` becomes `mediaModels.image`.
- Doctor disables skills whose binaries or credentials are missing (`openclaw skills check`), creates a heartbeat job and a disabled weekly skill-review job per agent (`openclaw cron list --all`), archives an untouched `TOOLS.md` and moves `HEARTBEAT.md` into the heartbeat job.
- Plaintext API keys in the config are additionally copied into the agent database.
- Stopping can take up to ~4.5 minutes when the Telegram plugin's cleanup hangs (the add-on stops waiting after 270 s, within Home Assistant's 300 s limit).
- Undelivered messages in the 2026.7 Telegram file spool are not processed by 9.9 (their number is logged).

## [0.5.93-full2] - 2026-10-09

Preparation release ("stage A") for the later jump to OpenClaw 2026.9.x. No OpenClaw change compared with `0.5.93-full1` (still `2026.7.35`).

**Coming from `0.5.88-full1` (this deployment), this update also brings everything from `0.5.88-full2` and `0.5.93-full1`, neither of which was installed here:**
- OpenClaw `2026.7.1-2` → `2026.7.35`. Same database schema; reversible by restoring the Home Assistant backup.
- One-time Brave plugin reinstall `2026.7.1` → `2026.7.35` on the first start. Needs network; non-fatal.
- The LAN lockdown of port 48099, the upstream 0.5.93 merge, atomic config writes and the pre-upgrade state archive.

On the first start the archive captures the 7.1-2 state (`…-before-2026.7.35.tar.gz`). The rollback baseline for the 9.x upgrade is the separate `…-before-2026.9.x` archive that the 9.x release takes before its first start. Stop the add-on and create a Home Assistant backup before updating.

### Added
- **`oc-upgrade`** helper:
  - `oc-upgrade check` — read-only inventory before an OpenClaw upgrade. Prints names, sizes and versions only, never secret values. Exit code 0 / 4 notes / 2 possible bridge case / 3 state newer than this image. SQLite files are read without creating or changing any file next to them: immutable when there is no WAL content, a read-only `-shm` otherwise, or a private copy. It covers:
    - versions and database schema versions;
    - pre-June-2026 leftovers: old task/flow/plugin databases and whether they were imported, legacy Telegram/Active Memory files, `credentials/oauth.json`;
    - memory sidecar databases;
    - model wildcards;
    - free space.
  - `oc-upgrade export` — on the next start, before the gateway starts, writes a cold copy to `/share/openclaw-rehearsal/<timestamp>/` for an offline upgrade rehearsal.
    - Contents: `/config/.openclaw` including installed plugins, plus the workspace.
    - Left out: logs, media, caches, earlier archives and workspace `node_modules`.
    - The copy contains secrets. It is `0600`, comes with a manifest (sha256, versions), and an interrupted export is removed on the next start.
  - `oc-upgrade status` — hold reason, upgrade archives, pending export.

### Changed
- **State newer than the image → HOLD instead of a silent runtime install.**
  - **Trigger:** `/config/.openclaw` was written by a newer OpenClaw than the bundled one — a newer `meta.lastTouchedVersion`, or, on a 2026.7.x runtime, a state/agent database with a schema version above 1.
  - **Before:** the add-on `npm install -g`ed that newer OpenClaw at boot. `repair_runtime_version_mismatch` is removed.
  - **Now:** OpenClaw is not started and its config, databases, sessions and plugins are not modified: no archive, plugin install, config repair, MCP re-registration or session-lock cleanup, at start or at stop. The add-on page and terminal stay up, and the reason is logged and shown by `oc-upgrade status`.
  - **Fail-safe:** the guard holds if it cannot complete, including when a database's WAL cannot be read; it never falls back to a possibly stale header.
  - **Why:** a Home Assistant restore after the 9.x upgrade becomes safe, because a mismatched image/data pair can no longer corrupt the data.
- **`openclaw update` is refused.**
  - At image build time every `openclaw` executable is replaced by a wrapper that refuses `openclaw update` and `openclaw --update …`. Everything else is exec'd unchanged. The wrapper is also placed in every standard bin directory, so it applies whatever the caller's PATH, including tools the agent runs, and a plain `npm install -g openclaw@…` fails with `EEXIST` instead of shadowing it.
  - If another OpenClaw is forced into the container anyway, the add-on holds instead of (re)starting OpenClaw. It checks at start and whenever the gateway process exits or self-restarts, before adopting a new daemon, for an extra `openclaw` in a bin directory, a second package, or a pinned package whose version changed. A gateway that may already run the swapped code is stopped. Until the next check, such a CLI can still be run by hand or by an agent.
- **GHCR version tags are not rebuilt.**
  - The build workflow skips a version tag that is already published: a push without a version bump builds nothing and leaves a warning.
  - Publishing runs are serialized (job-level concurrency), and only `main` publishes.
  - Why: Home Assistant's backup restore re-pulls the add-on image by its version tag, so a rebuilt tag would silently change what a rollback restores.

## [0.5.93-full1] - 2026-09-27

Merge of upstream `techartdev` **0.5.88 → 0.5.93** onto the fork. **No OpenClaw bump** — the pin stays **`2026.7.35`** (extended-stable); upstream's `2026.9.6` is not taken (see "Not included" below).

### Added (from upstream)
- **Config snapshots and rollback** (`config_backup_keep`, `oc-config list|diff|restore|snapshot`): `openclaw.json` is snapshotted before the add-on's first write of each start.
- **Pre-upgrade state archive**: before an OpenClaw version starts for the first time, the migration-sensitive state is archived to `/config/.openclaw/upgrade-backups/` (newest 3 kept). **The first start of this release writes one archive for `2026.7.35`**, which becomes the rollback baseline for the later 9.x upgrade. Fork changes: `tmp/` is excluded from the archive, and on 2026.7.x runtimes a failed archive (e.g. full disk) only warns instead of refusing to start — 7.x performs no state migration, so there is nothing to protect yet. From 2026.8 on the upstream behaviour applies: no archive, no start.
- **Resource profiles** (`resource_profile`, default `auto`). On this 10 GB VM `auto` resolves to `high`, which sets no Node heap cap — no change in behaviour.
- **Home Assistant health sensors** (`ha_health_sensors`, `ha_health_interval`, `ha_base_url`, `oc-health`) — off by default.
- `backup_exclude` for regenerable caches (`.node_global`, `.npm`, `.cache`, `__pycache__`, stale `*.jsonl.lock`).
- `lan_https`: nginx rebuilds forwarded-identity headers instead of appending client-supplied ones, and loopback is trusted as the local proxy hop.
- Crash-loop restart backoff (2 s doubling to 60 s) with a correct uptime measurement.

### Fixed (fork)
- **A damaged `openclaw.json` could be silently wiped on startup.** If the file existed but was not valid JSON, `oc_config_helper.py` treated it as missing and wrote back a config containing only the gateway block — agents, channels (incl. the Telegram bot token) and model settings were gone, and the helper still exited successfully. The helper now refuses to write (exit 2), startup continues with the add-on page and terminal available, and the log points at `oc-config restore`. Config writes are now atomic (temp file + fsync + rename, file mode preserved), so an interrupted write can no longer truncate the file.
- **Clean shutdown**: stopping the add-on now waits up to 270 s for the gateway to drain (previously 5 s), also signals the gateway daemon when the tracked PID is a finished wrapper after an in-process restart, and `config.yaml` sets `timeout: 300` so the Supervisor no longer SIGKILLs the gateway after 10 s mid-write.
- `repair_runtime_version_mismatch` only installs a plain stable release number read from `openclaw.json` (`YYYY.M.P` or `YYYY.M.P-N`); tags, prereleases, URLs and git/file specs are refused instead of being passed to a root `npm install -g`.
- **Pre-upgrade archive follows the runtime that actually starts**: if `repair_runtime_version_mismatch` swaps in a newer OpenClaw, the archive and its "no archive, no start (2026.8+)" rule are re-evaluated for that runtime. A version marker whose archive was pruned no longer suppresses a new archive.
- **Health sensors (`oc-health`)**: TLS verification is only skipped for loopback (`127.0.0.1`, `localhost`); `ha_base_url` and LAN names (`homeassistant`, `homeassistant.local`) must present a valid certificate before the long-lived token is sent. SIGTERM now ends `oc-health loop` immediately, so it no longer stalls add-on shutdown.
- **HA MCP re-registers when the Home Assistant URL changes** (not just the token). Existing installs re-register once — add-on versions before 0.5.90 had registered the unreachable `http://supervisor/core/api/mcp` URL under `host_network`.
- `oc-config snapshot` / `restore`: a failed snapshot now reports failure, `restore` refuses to proceed without its pre-restore safety copy, and restores are written atomically.
- The GHCR build passes `BUILD_VERSION`, so the add-on version is known inside the image (health sensor `addon_version`).
- DOCS: Control UI secure-context guidance is now version-specific — on the bundled 2026.7.35 plain-HTTP LAN access still needs HTTPS or the device-auth bypass.
- `oc-gateway restart` picks the restart signal from the installed OpenClaw: `SIGUSR1` up to 2026.9.5, `SIGUSR2` from 2026.9.6 (where `SIGUSR1` would open a Node debugger on port 9229 instead of restarting). No change on the current 7.35.

### Changed vs. upstream (fork decisions)
- **No automatic `openclaw doctor --fix`.** Upstream runs it unattended after repeated failed starts; here that would run the `openai-codex/*` → `openai/*` route migration without a backup. The crash loop only backs off and reports. A controlled, backup-guarded migration step comes with the OpenClaw 2026.9 upgrade.
- **`controlui_disable_device_auth` keeps working on 7.x.** Upstream strips `gateway.controlUi.dangerouslyDisableDeviceAuth` unconditionally (it is inert from OpenClaw 2026.8). The fork only strips it once the bundled runtime is ≥ 2026.8.0; on 7.35 the option still skips browser pairing as before. Option texts updated in all six locales.
- **No Supervisor `watchdog`** (upstream probes `tcp://[HOST]:48099`): a Supervisor restart during startup could later interrupt the pre-upgrade archive or a state migration.
- **`.linuxbrew` is kept in HA backups** — the fork defaults `persist_brew_tools` to `true`, so brew tools are part of the add-on and must survive a restore.
- `OPENCLAW_NO_AUTO_UPDATE=1` is exported so the gateway never applies an OpenClaw update on its own, bypassing the image pin.
- `acpx@0.19.3` and `@anthropic-ai/claude-code@2.1.283` are pinned instead of floating.

### Not included: OpenClaw 2026.9.6
Upstream 0.5.93 bundles OpenClaw `2026.9.6`. Not taken: 9.6 leaks ~77 MB per agent turn in the catalog worker (openclaw/openclaw#157842, fixed in the upcoming 2026.9.7), and the 7.x → 9.x jump runs one-way state migrations plus the `openai-codex` route migration. Target is `2026.9.7` with a backup-guarded migration step in a later release.

## [0.5.88-full2] - 2026-09-26

### Security
- **The web terminal is no longer reachable from the LAN without Home Assistant login.** Because the add-on runs with `host_network: true`, nginx's Ingress backend on port `48099` listened on every host interface without any access restriction — anyone on the network could open `http://<ha-ip>:48099/terminal/` and get a writable ttyd shell inside the add-on (with access to `/config`, tokens and the OpenClaw state), bypassing Ingress authentication entirely. Port `48099` now only accepts loopback and the Supervisor Ingress proxy (`172.30.32.2`); everything else gets `403`. Opening the add-on through the Home Assistant sidebar/add-on page is unaffected. Same fix as upstream `techartdev` (`security: restrict ingress backend to Supervisor`).

### Changed
- **OpenClaw `2026.7.1-2` → `2026.7.35` (npm `extended-stable`).** Extended-stable is the July maintenance line: it sits directly on `2026.7.1-2` and backports the security and reliability fixes from the full `v2026.7.1-2..` audit — no 8.x/9.x migrations. Highlights: hardened command parsing (escaped-newline shell words now need approval), exact-origin browser checks, plugin git-install option injection blocked, backup archives written `0600`, rotated OpenAI OAuth credentials no longer reverted by auth bookkeeping, Telegram/Discord/WhatsApp delivery and transcript-recovery fixes, bounded provider/history/media waits, and new model catalogs (Claude Opus 5, GPT-6 Astra, Gemini 3.6/3.7 Flash, …).
- `2026.7.34` is deliberately skipped: its Doctor wrote a partial plugin registry (Browser, Canvas, pairing, … missing after restart), which `2026.7.35` repairs.
- **Brave plugin pin `2026.7.1` → `2026.7.35`** (plugin `peerDependencies.openclaw>=2026.7.35`). The per-version marker makes `ensure_brave_plugin()` converge the persisted install once on the first start.

### Still deliberately NOT included: OpenClaw 2026.8.x / 2026.9.x
Unchanged reasoning from `0.5.88-full1`: `2026.8.1` requires `openclaw doctor --fix` for the `openai-codex/*` → `openai/*` route migration and the OpenProse removal, and turns on dreaming, self-learning, conversation recall and (from 9.2/9.3) Swarm, recursive delegation and CLI agents by default. `2026.9.3` additionally requires Node ≥ 24.16 and migrates Workshop skills; `2026.9.6` still has open upgrade/performance regression reports. Plan that jump as a separate maintenance window with a state backup.

## [0.5.88-full1] - 2026-09-01

Merge of upstream `techartdev` **0.5.86 → 0.5.88** onto the fork. **No OpenClaw bump** — the pin stays `2026.7.1-2`, identical to upstream's.

### Fixed
- **Explicit `false` add-on options are no longer silently flipped back to their defaults** (upstream #175). `run.sh` read booleans as `jq -r '.opt // true'`, and jq's `//` operator falls back on **`false`** just as it does on `null` — so every option deliberately set to `false` came back as the default on each start. Reads now go through a `read_json_bool()` helper. Affects `enable_terminal`, `controlui_disable_device_auth`, `force_ipv4_dns`, `clean_session_locks_on_start`/`_on_exit`, `enable_openai_api` and the `persist_*` pair. On this deployment the only explicit `false` is `persist_node_global`, whose default is also `false`, so nothing was actually mis-set — this closes a latent trap rather than fixing live damage.
- Upstream `0.5.87` repaired a broken `0.5.86` image build that requested the nonexistent `openclaw@2026.7.1-2-2`. This fork skipped both releases and was never affected.

### Fork deltas retained over upstream
- `config.yaml`: `app_config:rw` map, GHCR `image:` pull, `aarch64`-only `arch`, fork `url:`.
- ACP/ACPX harness (`acpx`, `@anthropic-ai/claude-code`), full image (Chromium + `node-llama-cpp`), `mcporter@0.12.3`.
- `ensure_brave_plugin()` bake + version convergence, `heal_telegram_ingress_spool()` self-heal.

### Deliberately NOT included: OpenClaw 2026.8.1
npm `latest` moved to **`2026.8.1`** on 2026-08-31 (the `2026.7.2` line never shipped stable and was superseded). It is not taken here, because it carries two **breaking** migrations that both mandate `openclaw doctor --fix` — a command this deployment bans — namely the OpenProse/`/prose` removal and the `codex/*` + `openai-codex/*` → `openai/*` route migration, which directly touches this install's `openai-codex` provider and OAuth profile. It also replaces `agents.defaults.models` with `modelPolicy.allow` (the structure this fork's wildcards live in) and switches several behaviours on by default: grounded dreaming, automatic self-learning, personal conversation recall, and CPU-scaled 8–16 concurrent runs. That belongs in a planned window with a dry run against a copy of the state.
## [0.5.85-full1] - 2026-07-21

Merge of upstream `techartdev` **0.5.83 → 0.5.85** onto the fork.

### Fixed
- **`mcporter@0.12.3` is now baked into the image — HA MCP auto-configuration actually runs.** Symptom on this deployment: with `auto_configure_mcp: true` and a valid `homeassistant_token`, startup logged `mcporter MISSING -> auto_configure_mcp silently skipped` / `mcporter not available; skipping MCP auto-configuration`, no `/config/.mcporter` was ever created, and **no Home Assistant MCP server was registered** — i.e. Volt could not drive HA entities/services over MCP at all. Upstream fix for issue #163 (`fix(addon): bundle mcporter for HA MCP auto-config`); the misleading "run `openclaw onboard`" hint was also replaced.
- **Runtime-downgrade repair on startup**: if the bundled OpenClaw CLI is older than the persisted `/config/.openclaw/openclaw.json` format version, the add-on restores the newer runtime instead of silently coming up broken after a HAOS update or add-on rebuild (upstream 0.5.82).
- **`lan_https` certificate regeneration** with proper X.509 extensions (`basicConstraints`, `keyUsage`, `extendedKeyUsage`) so strict Python/OpenSSL verification accepts the built-in HTTPS proxy certs (upstream 0.5.82).

### Changed
- **Track upstream**: bump OpenClaw `2026.7.1` → **`2026.7.1-2`** — a patch on the same 7.1 line we already run, welcome after the 7.1 migration crash-loop experience.
- Add-on runtime base bumped to **Node 24** (upstream `chore(build): bump add-on runtime to Node 24`); the Dockerfile's `node -v` gate now asserts `v24.*`.
- Brave plugin pin stays at **`2026.7.1`** — `-2` is a core-only patch and satisfies `peerDependencies.openclaw>=2026.7.1`; no plugin rebuild needed.

### Fork deltas retained over upstream
- `config.yaml` map `app_config:rw` (upstream still emits the legacy `addon_config`, which trips a Supervisor deprecation warning).
- GHCR pre-built `image:` (pull, don't build on-device), `aarch64`-only `arch`.
- ACP/ACPX harness (`acpx`, `@anthropic-ai/claude-code`), full image (Chromium + `node-llama-cpp`).
- `ensure_brave_plugin()` bake + version convergence, `heal_telegram_ingress_spool()` self-heal.

## [0.5.82-full1] - 2026-07-13

### Changed
- **Track upstream**: bump OpenClaw to **2026.7.1** (`npm install -g openclaw@2026.7.1`), the newest npm stable. Upstream `techartdev` add-on base is still `0.5.80`/`2026.6.10`; this fork stays ahead.
- **Brave plugin pinned to 2026.7.1** (CalVer lockstep with the host; plugin `peerDependencies.openclaw>=2026.7.1`).
- **Telegram spool self-heal retained (belt-and-suspenders)**: the 2026.7.1 line carries the upstream ingress-orphan fix (openclaw/openclaw#84674 → PR #97118), which first shipped in the `2026.7.1-beta` series and is now stable. `heal_telegram_ingress_spool()` is kept as a safety net pending real-world observation of the upstream fix, then a candidate for removal in a later release.

### Fixed
- **`ensure_brave_plugin()` now converges Brave to the pinned version on OpenClaw bumps.** The previous adopt-without-version path wrote the new per-version marker for a *stale* Brave install (observed on 0.5.81-full1: host openclaw 2026.6.11 but Brave adopted at 2026.6.6), so a bump would not auto-upgrade the plugin. It now runs `openclaw plugins install …@<ver> --pin --force` when the target-version marker is absent, upgrading any older install to match the host. Still guarded by the marker (runs once per version) and non-fatal.

## [0.5.81-full1] - 2026-07-10

### Changed
- **Track upstream**: bump OpenClaw to **2026.6.11** (`npm install -g openclaw@2026.6.11`). Upstream `techartdev` add-on base is still `0.5.80`/`2026.6.10`; this fork moves ahead to the newest npm stable for its security fixes (patched DOMPurify in the Control UI, trusted package-source path hardening, no reasoning-leak into Telegram/WhatsApp replies) and continued auth-profiles→SQLite migration work.
- **Telegram spool self-heal retained**: the upstream PID-1 ingress-orphan fix (openclaw/openclaw#84674 → PR #97118) landed only in the `2026.7.1-beta` line, **not** in stable `2026.6.10`/`2026.6.11`. `heal_telegram_ingress_spool()` therefore stays. Revisit removing it once `2026.7.1` ships stable.

### Added
- **Brave web-search plugin baked in via idempotent runtime install**: `ensure_brave_plugin()` in `run.sh` installs `@openclaw/brave-plugin@2026.6.11` (`npm:` source, `--pin`) before the config-helper runs, guarded by a version marker (`/config/.openclaw/.brave_plugin_<ver>`) and an "adopt existing install" fast-path. Brave is an **external** official plugin (not bundled in core openclaw) that installs into the persistent config dir, so this ends the recurring need to re-add it manually. Version is CalVer-locked to the baked openclaw (plugin `peerDependencies.openclaw>=2026.6.11`). Best-effort/non-fatal — a failed install never blocks startup. **DuckDuckGo** needs no install (bundled, key-free) and can be selected via `openclaw configure --section web`.

### Fixed
- **`oc_config_helper.py` no longer strips a valid Brave selection**: `repair-known-invalid-settings` previously deleted `tools.web.search.provider=brave` on *every* start (boot-loop guard from the stripped-image era), silently disabling web search even when the plugin was installed. It now strips only when Brave is genuinely absent (checks `plugins.entries.brave` + the `extensions/` dir), preserving the boot-loop protection for the truly-missing case.

## [0.5.80-full1] - 2026-07-01

### Changed
- **Track upstream**: bump OpenClaw to **2026.6.10** (upstream add-on base `0.5.80`).
- **Un-stripped "full" image** — the add-on now runs on a roomy DGX Spark HAOS VM (not the 4 GB Green), so the lean-image constraints no longer apply. Re-added **Chromium + chromium-driver** and **`node-llama-cpp@3.18.1`** (the local embeddings/memory-search provider is available again). Reverses the `0.5.77-ghcr1` strip.

### Added
- **ACP / ACPX harness baked into the image**: `npm install -g acpx @anthropic-ai/claude-code`. Lets OpenClaw drive external coding agents (Codex, Claude Code) over the Agent Client Protocol — required because Anthropic + OpenAI are authenticated via **OAuth** (not API keys). Codex itself is bundled in OpenClaw; `acpx` + the Claude Code CLI cover the OAuth/ACP path (the `codex-acp` / `claude-agent-acp` adapters auto-download via npx on first use).
- Tag suffix `-ghcrN` → `-fullN` to mark the un-stripped build line.

## [0.5.78-ghcr2] - 2026-06-17

### Changed
- **Track upstream**: bump OpenClaw to **2026.6.6** (upstream add-on base `0.5.78`), `npm install -g openclaw@2026.6.6`. The fork's self-heal and the GHCR pre-built-image approach are retained.
- Note: upstream's PID-1-namespace Telegram-spool recovery bug (openclaw/openclaw#84674, #85168) is **still open in 2026.6.6**, so the self-heal below remains necessary.

## [0.5.78-ghcr1] - 2026-06-15

### Added
- **Telegram ingress-spool self-heal**: `heal_telegram_ingress_spool()` in `run.sh` runs at the top of `start_openclaw_runtime` — i.e. before every gateway (re)start, while the gateway is down (race-free). It reclaims orphaned `<id>.json.processing` claims (requeue `→ .json`), skips dead-letters (`.failed` sibling), and never clobbers an existing `.json`. Fail-safe under `set -euo pipefail` (`nullglob` + `|| true`). Works around OpenClaw's PID-1-namespace recovery false-positive that otherwise blocks a Telegram lane for ~6h after a restart interrupting an in-flight message — making a plain add-on restart a reliable recovery. (OpenClaw pin unchanged: 2026.5.28.)

## [0.5.77-ghcr1] - 2026-06-05

### Changed
- **Private GHCR build**: the add-on image is built on GitHub Actions (native `aarch64`) and **pulled from private GHCR** via the `image:` field instead of being built on-device — avoids Supervisor build-OOM on the 4 GB HA Green. `arch` limited to `aarch64`.
- Stripped Chromium/`chromium-driver` and `node-llama-cpp` from the image (cloud embeddings only) to keep the image lean.

---

> Upstream `techartdev` release history below.
## [0.5.91 – 0.5.93] - 2026-09-24

> Upstream released these as `0.5.91`–`0.5.93` (OpenClaw `2026.9.3`–`2026.9.6`); the notes were kept under "Unreleased" upstream.

### Added

- **Safe OpenClaw database upgrades**: before the add-on starts an OpenClaw
  version for the first time, it archives the migration-sensitive persistent
  state (configuration, SQLite agent/session databases with WAL files, pairing
  and delivery state) in `/config/.openclaw/upgrade-backups/`. If that archive
  cannot be created, startup stops before an irreversible schema migration can
  occur. The three newest archives are retained; media, skills, npm projects and
  logs are excluded because they are not required to roll back database state.

### Changed

- Bundle OpenClaw `2026.9.6` (add-on version `0.5.93`) for the next release.

### Fixed

- Restrict the Home Assistant Ingress backend on port `48099` to loopback and
  the Supervisor proxy, preventing direct LAN access from bypassing Ingress
  authentication and exposing the terminal.
- In `lan_https` mode, rebuild forwarded identity at nginx and omit it for
  same-host loopback clients, avoiding ambiguous proxy attribution while not
  trusting client-supplied forwarding chains.

## [0.5.90] - 2026-09-02

### Added
- **Resource profiles** (`resource_profile`): the add-on now gives the gateway an explicit Node.js heap budget instead of letting it size against total host memory. `auto` (default) picks `low` / `balanced` / `high` from CPU architecture and RAM, and never writes to `openclaw.json`. Selecting `low` explicitly also applies conservative OpenClaw defaults (currently `browser.enabled: false`) for keys you have not set yourself. The resolved profile and heap limit are logged at startup and shown on the landing page.
- **Home Assistant health sensors** (`ha_health_sensors`, `ha_health_interval`): optionally publish `sensor.openclaw_gateway`, `sensor.openclaw_version`, `sensor.openclaw_gateway_memory`, `sensor.openclaw_disk_used` and `sensor.openclaw_certificate_expiry` so you can alert on gateway health, disk usage and certificate expiry from automations. Requires `homeassistant_token`. New `oc-health` helper (`show` / `once` / `loop`) for previewing and debugging.
- **Config snapshots and rollback** (`config_backup_keep`): `openclaw.json` is now snapshotted to `/config/.openclaw/backups` before the add-on's first configuration write of each start, so an unwanted change can be undone. New `oc-config` helper: `list`, `diff`, `restore`, `snapshot`. Restoring always backs up the config it replaces first. Identical configs are not re-snapshotted, and only the newest `config_backup_keep` (default 10) are kept.
- New `ha_base_url` option to point the health sensors at a Home Assistant on a non-default port or host (empty = auto-detect).
- `oc-health check`: diagnoses credentials and API connectivity in one command — which endpoint was chosen, whether a token is present, whether the Supervisor host resolves, and the result of a live probe.
- Supervisor watchdog on the ingress port, so Home Assistant restarts the add-on if the ingress proxy stops answering. Can be turned off with the Watchdog toggle on the add-on page.
- **Smaller Home Assistant backups**: the add-on now declares `backup_exclude`, so regenerable caches and tooling (`.linuxbrew`, `.node_global`, `.npm`, `.cache`, `__pycache__`, stale `*.jsonl.lock` files) are skipped when Home Assistant backs the add-on up. Excluded directories are pruned without being walked, so backups are both smaller and faster. All user state — `openclaw.json`, config snapshots, skills, agent sessions, the `clawd` workspace, keys, secrets and certificates — is still backed up. Note that a restore replaces `/config` wholesale, so excluded tooling must be reinstalled rather than restored.

### Changed
- **Documentation reviewed against OpenClaw `2026.8.2`.** Added a *Device pairing (first connection)* walkthrough — the gateway host is the add-on container, so `openclaw devices list` / `openclaw devices approve <requestId>` in the add-on terminal is all that is needed, and the `ssh -N -L` hint printed by `openclaw dashboard` does not apply here. Corrected the long-standing claim that the Control UI requires HTTPS or localhost: upstream removed that restriction (device identity is signed with pure-JS Ed25519 on any origin), so the guidance now recommends HTTPS for token confidentiality rather than presenting it as mandatory. Rewrote the two error-1008 troubleshooting entries around pairing, and marked `controlui_disable_device_auth` as deprecated and inert in all six locales.
- Startup warnings about legacy `/config/.node_global` and `/config/.linuxbrew` directories no longer claim they inflate Home Assistant backups (they are now excluded). The warning explains they only use disk space and gives the exact removal command.

### Fixed
- **Stopped writing a retired OpenClaw key.** The add-on set `gateway.controlUi.dangerouslyDisableDeviceAuth` on every start to skip Control UI device pairing. OpenClaw retired that flag in the `2026.8.x` line: it is inert, the security audit reports it as a dangerous key, and `openclaw doctor --fix` deletes it — so the add-on was re-adding it every boot and fighting Doctor. The add-on now removes the key instead, which also clears the "dangerous config flags enabled" startup warning. Browsers pair once via `openclaw devices approve <requestId>`.
- **Health sensors could not reach a Home Assistant that serves HTTPS**: endpoint detection only ever tried plain `http://`, which a TLS listener answers by closing the connection — surfacing as `HTTP 000` (curl: *Empty reply from server*). Detection now probes `https` and `http` across `127.0.0.1`, `localhost`, `homeassistant` and `homeassistant.local`, and uses the first endpoint that answers. TLS verification is skipped for these local endpoints because Home Assistant's certificate is normally issued for its external hostname and never matches a loopback address; the connection stays on the local host/LAN.
- Detection is retried on later cycles instead of only at startup, so sensors still come up when the add-on starts before Home Assistant is listening.
- **Health sensors could not reach Home Assistant (`HTTP 000`)**: `oc-health` preferred the Supervisor proxy whenever `SUPERVISOR_TOKEN` was present, but this add-on runs with `host_network: true`, so the container is not on the Supervisor bridge network and the `supervisor` hostname does not resolve. Every sensor update failed at the connection level. It now prefers the user's long-lived token against the host's Home Assistant on `localhost:8123`, and only uses the Supervisor proxy when that hostname actually resolves.
- The same endpoint-selection bug in the MCP auto-configuration would have registered an unreachable `http://supervisor/core/api/mcp` URL; it now applies the same reachability check.
- Health sensor failures are logged once per status change instead of one line per entity per interval, so an outage can no longer fill the add-on log (previously ~7000 lines a day).
- Failures now explain themselves: `HTTP 000` reports that Home Assistant is unreachable at the resolved endpoint, `401`/`403` points at the token, rather than printing a bare status code.

- **`proxy_attribution_required` in `lan_https` mode**: OpenClaw `2026.8.2` began rejecting requests that carry forwarded identity headers from an untrusted source. The add-on's built-in HTTPS proxy runs on loopback and sets `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Proto`, but loopback was never added to `gateway.trustedProxies`, so the gateway refused every request with `proxy_attribution_required`. `lan_https` now trusts `127.0.0.1` and `::1` (merged with any `gateway_trusted_proxies` you set, and deduplicated). As a side benefit the gateway can now attribute the real LAN client IP for rate limiting instead of seeing every request as loopback.
- **Gateway restart loop was not actually recovering** (follow-up to `0.5.104`): the automatic repair ran `openclaw doctor --fix` without `--non-interactive`. With no TTY, Doctor printed advisory notices and skipped the migration, so the loop continued. It now runs `openclaw doctor --fix --non-interactive --yes`, the documented automation form, and reports clearly when Doctor exits non-zero because a legacy source or interrupted `.doctor-importing` claim remains.
- **Restart backoff never escalated**: gateway uptime was measured after the daemon-detection retry loop, so its sleeps counted as uptime. A gateway that died ~45s into startup measured ~65s, tripped the 60s "healthy" reset, and pinned the retry interval at 2s forever. Uptime is now captured the moment the runtime exits, and the healthy threshold is 120s — comfortably above a normal ~45s cold start. The repair is also attempted after 2 consecutive failures instead of 3, since each failed boot costs about a minute.
- **Gateway restart loop after an OpenClaw upgrade**: releases that gate startup behind a data migration (such as the legacy workspace state check in `2026.8.2`) made the supervisor restart the gateway forever, writing a stability bundle on every attempt. The add-on now runs the documented `openclaw doctor --fix` repair once per start after repeated failures — snapshotting `openclaw.json` first so it is reversible — and backs off between restarts (2s doubling to a 60s cap) instead of retrying every 2 seconds. After five consecutive failures it logs the exact diagnostic commands to run. The terminal and add-on page stay available throughout.
- Documentation listed Node.js 22 in the bundled tools table; the image has shipped Node.js 24 since `0.5.83`.

## [0.5.89] - 2026-09-02

### Changed
- Bump OpenClaw to `2026.8.2`.

## [0.5.88] - 2026-08-25

### Fixed
- Preserve explicit `false` values for boolean add-on options instead of replacing them with `true` defaults during startup. This restores settings such as strict Control UI device authentication, disabled terminal access, and IPv6-capable DNS behavior after an add-on restart or rebuild.

## [0.5.87] - 2026-08-10

### Fixed
- Correct the bundled OpenClaw npm package version in the Docker image build for add-on `0.5.86`, fixing failed installs that requested the nonexistent `openclaw@2026.7.1-2-2`.

## [0.5.85] - 2026-07-21

### Changed
- Bump OpenClaw to `2026.7.1-2`.

## [0.5.84] - 2026-07-17

### Changed
- Bundle `mcporter@0.12.3` in the add-on image so `auto_configure_mcp` can register Home Assistant out of the box on fresh installs without a manual global install workaround.
- Replace the misleading startup hint that told users to run `openclaw onboard` when `mcporter` was missing. The message now correctly points to a broken image state instead.

## [0.5.82] - 2026-07-15

### Fixed
- Repair add-on startup automatically when the bundled OpenClaw CLI is older than the persisted `/config/.openclaw/openclaw.json` format version. On mismatch, the add-on now restores the newer runtime before launching the gateway instead of silently coming up broken after a Home Assistant OS update or add-on rebuild.
- Regenerate malformed `lan_https` CA/server certificates with proper X.509 extensions (`basicConstraints`, `keyUsage`, `extendedKeyUsage`) so Python/OpenSSL strict verification accepts the built-in HTTPS proxy certificates.

## [0.5.81] - 2026-07-14

### Changed
- Bump OpenClaw to `2026.7.1`.

## [0.5.80] - 2026-06-26

### Changed
- Bump OpenClaw to `2026.6.10`.

## [0.5.78] - 2026-06-16

### Changed
- Bump OpenClaw through the `2026.5.28` and `2026.6.6` upstream releases.

## [0.5.76] - 2026-05-29

### Changed
- Bump OpenClaw to `2026.5.27`.

## [0.5.75] - 2026-05-28

### Changed
- **Backup-friendly persistence defaults**: new add-on options `persist_node_global` and `persist_brew_tools`, both defaulting to `false` so large optional toolchains are no longer persisted into Home Assistant backups unless users explicitly opt in.
- `run.sh` now keeps npm global installs and Homebrew ephemeral by default, while preserving the old rebuild-survival behavior when the new toggles are enabled.

### Added
- Migration notes and documentation for older installs that already have legacy `/config/.node_global/` or `/config/.linuxbrew/` directories contributing to backup size.

## [0.5.74] - 2026-05-27

### Fixed
- Bundle `node-llama-cpp` inside the add-on image so the default local memory/embeddings provider works in HAOS without manual package installs.
- Add `cmake` to the image so `node-llama-cpp` can fall back to a source build when a prebuilt binary is unavailable for the target architecture.

## [0.5.73] - 2026-05-26

### Added
- New add-on-native `oc-gateway` helper for container-supervised runtime management:
  - `oc-gateway status` shows gateway state in the HA add-on model (`run.sh` supervisor, not systemd)
  - `oc-gateway restart` requests gateway self-restart via `SIGUSR1` without full add-on restart

### Changed
- Troubleshooting and setup docs now use `oc-gateway status` / `oc-gateway restart` in add-on contexts to avoid confusing systemd-related CLI output.

## [0.5.72] - 2026-05-04

### Fixed
- Repair startup when a persisted OpenClaw config still selects the unavailable `tools.web.search.provider=brave` provider. The add-on now clears that provider before launching the gateway so OpenClaw can start; users can reinstall/enable the Brave provider later if they want web search through Brave.

## [0.5.71] - 2026-05-03

### Changed
- Bump OpenClaw through the 2026.4.29 and 2026.5.2 upstream releases.

## [0.5.70] - 2026-04-30

### Changed
- Bump OpenClaw to 2026.4.27.

## [0.5.69] - 2026-04-27

### Changed
- Bump OpenClaw through the 2026.4.23 and 2026.4.24 upstream releases.

## [0.5.68] - 2026-04-25

### Changed
- Bump OpenClaw through the 2026.4.14, 2026.4.15, 2026.4.21, and 2026.4.22 upstream releases.

## [0.5.67] - 2026-04-25

### Changed
- Bump OpenClaw through the 2026.4.5, 2026.4.8, 2026.4.9, 2026.4.10, 2026.4.11, and 2026.4.12 upstream releases.

## [0.5.66] - 2026-04-04

### Fixed
- **"Open Gateway Web UI" button missing token on first boot / post-onboard** (issue #102): the gateway token was read once at startup, before `openclaw onboard` had a chance to write `openclaw.json`. The landing page now re-renders automatically in the background (up to ~2 min after startup) once the token appears in `openclaw.json`, and nginx is reloaded with SIGHUP — no add-on restart required. Existing installs with a token already present are unaffected.

## [0.5.65] - 2026-04-04

### Changed
- Bump OpenClaw to 2026.4.2.

## [0.5.63] - 2026-03-14

### Changed
- Bump OpenClaw to 2026.3.13.

## [0.5.62] - 2026-03-10

### Fixed
- **Gateway restart loop** (issue #95): `openclaw gateway run` is a thin wrapper that spawns `openclaw-gateway` as a long-running daemon then exits immediately. On self-restart (SIGUSR1 / `openclaw gateway restart`), the old daemon forks a new one and exits — the new PID is not a child of run.sh. The supervisor now uses a 3-tier daemon detection function (`find_gateway_daemon_pid`): (1) port ownership via `ss -tlnp`, (2) process title via `pgrep -f "openclaw-gateway"`, (3) `/proc/*/cmdline` scan for "openclaw" (catches the daemon immediately after fork, even before process.title or port bind — critical on Pi/eMMC where initialization takes 20-30 s). Detection retries up to 10 times with a final port-occupancy guard before any supervisor-initiated restart. Non-child PIDs are monitored with `kill -0` polling instead of `wait`. The loopback relay (tailnet mode) is stopped/restarted around gateway restarts to prevent port conflicts.

## [0.5.61] - 2026-03-10

### Fixed
- **Gateway restart loop** (issue #95): stop the tailnet loopback relay before supervisor-initiated gateway restarts and start it again after the new daemon is launched, preventing the relay from holding the local port and trapping the add-on in an `already listening` restart loop.

## [0.5.60] - 2026-03-10

### Fixed
- **Session lock cleanup ignored non-default agents**: `cleanup_session_locks` was hardcoded to `agents/main/sessions`, skipping stale locks for any agent with a custom `forcedAgentId`. Stale locks could block the gateway from opening sessions for those agents, causing silent fallback to `main`. Cleanup now scans all `agents/*/sessions/` directories.

## [0.5.59] - 2026-03-10

- **Remote mode URL not propagated** (issue #93): `start_openclaw_runtime` was reading `gateway.remote.url` back via `openclaw config get`, which can time out (2 s limit at startup) or return an empty/redacted result. The function now uses `$GATEWAY_REMOTE_URL` directly from the already-parsed add-on options, which is the same value the config helper writes to `openclaw.json`.
- **Terminal CLI unreachable in tailnet mode** (issue #90): when `gateway_bind_mode=tailnet` (or `access_mode=tailnet_https`), the gateway binds only to the Tailscale IP. The local CLI always connects via `ws://127.0.0.1:PORT`, causing "Gateway not running" inside the add-on terminal. A lightweight loopback relay (Node.js) is now started automatically to forward `127.0.0.1:PORT → TAILSCALE_IP:PORT`, making all terminal CLI commands work normally. Token auth is still enforced end-to-end by the gateway.
- **Session lock cleanup ignored non-default agents**: `cleanup_session_locks` was hardcoded to `agents/main/sessions`, skipping stale locks for any agent with a custom `forcedAgentId`. Stale locks could block the gateway from opening sessions for those agents, causing silent fallback to `main`. Cleanup now scans all `agents/*/sessions/` directories.

### Added
- **MCP auto-configuration for Home Assistant**: new option `auto_configure_mcp` (default: `false`). When enabled and `homeassistant_token` is set, the add-on automatically registers Home Assistant as an MCP server (`mcporter config add HA ...`) on startup. Auto-detects the HA API URL (supervisor proxy or localhost:8123). Re-configures only when the token changes.
- Landing page: new collapsible **MCP setup** section with automatic and manual setup instructions, post-upgrade refresh command, and model tips.
- DOCS: new **MCP Integration** guide covering automatic/manual setup, verification, model requirements, and troubleshooting.

### Changed
- Bump OpenClaw to 2026.3.9.

## [0.5.58] - 2026-03-08

### Changed
- Bump OpenClaw to 2026.3.7.

## [0.5.57] - 2026-03-07

### Added
- New add-on option `controlui_disable_device_auth` (default: `true`) to control whether `gateway.controlUi.dangerouslyDisableDeviceAuth` is enabled in `lan_https` mode.

### Changed
- `set-control-ui-origins` helper now accepts an explicit device-auth toggle and applies `dangerouslyDisableDeviceAuth` accordingly instead of forcing it on.
- `run.sh` now forwards the add-on option to the config helper.
- Control UI guidance text and docs were updated to explain when device-pairing bypass should be ON vs OFF.

### Fixed
- Docker build stability: replaced NodeSource `setup_22.x | bash` installer with explicit keyring + apt source configuration for Node.js 22, avoiding intermittent `apt-get install nodejs` exit code 100 failures.

### Translations
- Added `controlui_disable_device_auth` labels/descriptions to: `en`, `bg`, `de`, `es`, `pl`, `pt-BR`.

## [0.5.55] - 2026-03-04

### Changed
- Bump OpenClaw to 2026.3.2.

## [0.5.54] - 2026-02-25

### Changed
- Added startup guidance when `gateway_auth_mode=trusted-proxy` is enabled to clarify why direct local CLI gateway calls can show `trusted_proxy_user_missing`/unauthorized.
- Bump OpenClaw to 2026.2.24.

### Added
- New add-on option `gateway_additional_allowed_origins` for extra Control UI origins in `lan_https` mode.
- **Custom SANs in TLS certificate** (`lan_https` mode): hostnames and IPs from `gateway_additional_allowed_origins` and `gateway_public_url` are now included in the server certificate's Subject Alternative Name. The certificate auto-regenerates when SANs change.

### Fixed
- **Gateway token on landing page**: read token directly from `openclaw.json` instead of via `openclaw config get` which redacts secrets since OpenClaw v2026.2.22+ (fixes "Open Gateway Web UI" button sending `openclaw_redacted` as the token).
- **Token retrieval instructions**: all "get your token" references in the landing page and DOCS now use `jq -r '.gateway.auth.token' /config/.openclaw/openclaw.json` with a note explaining why the old `openclaw config get` command no longer works.
- `lan_https` startup no longer overwrites `gateway.controlUi.allowedOrigins` with defaults only.
- Control UI origins are now merged as: built-in defaults + existing config values + `gateway_additional_allowed_origins` (deduplicated).
- In `lan_reverse_proxy` and other non-`lan_https` setups, Control UI origins now also include the origin derived from `gateway_public_url`.
- `gateway.controlUi.allowedOrigins` configuration is now consistently applied via merge logic (defaults + existing values + user extras), reducing manual `openclaw.json` edits after upgrades.
- Add-on no longer exits/restarts when OpenClaw runtime process is restarted during onboarding or config changes.
- `run.sh` now supervises the OpenClaw runtime (`openclaw gateway run` / `openclaw node run`) and auto-restarts it while keeping nginx + terminal alive.

## [0.5.53] - 2026-02-24
- Bump OpenClaw to 2026.2.23.

## [0.5.52] - 2026-02-23

### Added
- New add-on option `gateway_env_vars` that accepts a list of `{name, value}` objects from Home Assistant UI and safely injects values into the gateway process at startup (max 50 vars, key <=255 chars, value <=10000 chars).
- Guard `gateway_env_vars` from overriding reserved runtime/proxy/`OPENCLAW_*` keys.
- Keep legacy string/object input formats for backward compatibility.

## [0.5.51] - 2026-02-23

### Fixed
- **`web_fetch failed: fetch failed`**: changed `force_ipv4_dns` default to **true**. Node 22 tries IPv6 first; most HAOS VMs lack IPv6 egress, causing outbound `web_fetch` / HTTP tool calls to time out.

### Added
- **`nginx_log_level` option** (`minimal` / `full`, default `minimal`): suppresses repetitive Home Assistant health-check and polling requests (`GET /`, `GET /v1/models`, `POST /tools/invoke`) from the nginx access log.

## [0.5.50] - 2026-02-23

**[!WARNING!]**
This update contains lots of changes. It is adviced to backup before installing!

### Changed
- **Upgraded OpenClaw to v2026.2.22-2** — includes major gateway/auth/pairing fixes and security hardening.
- Precreate `$OPENCLAW_CONFIG_DIR/identity` on startup to prevent `EACCES` errors on CLI commands that need device identity.
- Gateway token is auto-constructed from detected LAN IP when `lan_https` is active and `gateway_public_url` is empty.
- Config helper now receives the effective internal port (gateway_port + 1 in lan_https mode).

### Notes — v2026.2.22 impact on this add-on
- **Pairing fixes (loopback)**: v2026.2.22 auto-approves loopback scope-upgrade pairing requests, includes `operator.read`/`operator.write` in default scope bundles, and treats `operator.admin` as satisfying other scopes. This greatly improves `local_only` mode reliability.
- **`dangerouslyDisableDeviceAuth` security warning**: v2026.2.22 now emits a startup warning when this flag is active. The warning is **expected and harmless** for `lan_https` mode — the flag is still required because LAN browser connections through the HTTPS proxy are not considered loopback by the gateway. Token auth remains enforced.
- **Gateway lock improvements**: stale-lock detection now uses port reachability, reducing false "already running" errors after unclean restarts.
- **Log file size cap**: new `logging.maxFileBytes` default (500 MB) prevents disk exhaustion from log storms.
- **`wss://` default for remote onboarding**: validates our HTTPS proxy approach as the correct direction.

### Added
- **Disk-space monitoring on the landing page** — shows total / used / available with colour-coded indicator (🟢 / 🟡 / 🔴).
- **Low-disk warning banner** appears automatically when usage exceeds 90 %.
- **`oc-cleanup` terminal command** — interactive helper that shows cache sizes (npm, pnpm, OpenClaw, Homebrew, pycache, tmp) and lets users reclaim space with a menu-driven cleanup.
- Startup disk-space check with log warnings when the overlay is above 75 % or 90 %.
- **`access_mode` preset option** — simplifies secure access configuration with one setting:
  - `custom` (default, backward-compatible): use individual gateway settings
  - `local_only`: loopback + token (Ingress/terminal only)
  - `lan_https`: **built-in HTTPS reverse proxy for LAN access** (recommended for phones/tablets)
  - `lan_reverse_proxy`: LAN bind + trusted-proxy for external reverse proxy (NPM, Caddy, Traefik)
  - `tailnet_https`: Tailscale interface bind + token auth
- **Built-in TLS certificate generation** (`lan_https` mode):
  - Auto-generates a local CA + server certificate on first startup
  - Server cert is regenerated automatically when LAN IP changes
  - CA certificate downloadable from the landing page for one-tap phone trust
  - nginx HTTPS server block terminates TLS and proxies to the loopback gateway
- **Overhauled landing page** with:
  - Real-time status cards (gateway health, secure context, access mode)
  - Access wizard with step-by-step guidance per mode
  - Error translation — maps raw errors like `1008: requires device identity` to friendly messages with fixes
  - CA certificate download button (lan_https mode)
  - Migration banner for users on `custom` mode recommending a preset
  - Collapsible reverse-proxy recipes (NPM / Caddy / Traefik / Tailscale)
- Added `openssl` to Docker image for TLS certificate generation.
- Translations for `access_mode` in all 6 languages (EN, BG, DE, ES, PL, PT-BR).

### Fixed
- **`lan_https` — error 1008 "pairing required"**: auto-set `gateway.controlUi.dangerouslyDisableDeviceAuth: true` to skip interactive device pairing (token auth remains enforced). Replaces the invalid `pairingMode` key that caused `Unrecognized key` config errors.
- Config helper now removes stale/invalid keys (e.g. `pairingMode`) from `controlUi` on startup.
- Landing page error translation now covers "pairing required" and "origin not allowed" errors with correct fix guidance.
- Dropdown translations for `access_mode`, `gateway_mode`, `gateway_bind_mode`, and `gateway_auth_mode` now show human-readable labels in all 6 languages.
- **`lan_https` — error 1008 "origin not allowed"**: auto-configure `gateway.controlUi.allowedOrigins` with the HTTPS proxy origins (LAN IP, `homeassistant.local`, `homeassistant`) so the Control UI WebSocket is accepted.

## [0.5.49] - 2026-02-22

### Added
- New add-on option `http_proxy` for configuring outbound HTTP/HTTPS proxy from Home Assistant settings.

### Changed
- Export `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, and `https_proxy` from add-on config at startup.
- Add translations for the new `http_proxy` option.
- Document proxy configuration in README and DOCS.

## [0.5.48] - 2026-02-22

### Changed
- Bump OpenClaw to 2026.2.21-2.
- Add Home Assistant `share` and `media` mounts to the add-on (`map: share:rw, media:rw`).
- Keep official OpenClaw npm release and add startup proxy shim for `HTTP_PROXY/HTTPS_PROXY` support in undici fetch.

## [0.5.47] - 2026-02-21

### Added
- Add new `gateway_bind_mode` values: `auto` and `tailnet`.

### Changed
- Update startup helper validation and CLI usage to support `auto|loopback|lan|tailnet` bind modes.
- Update add-on translations and docs for the expanded gateway bind mode options.

## [0.5.46] - 2026-02-18

### Added
- New add-on option `force_ipv4_dns` to enable IPv4-first DNS ordering for Node network calls (`NODE_OPTIONS=--dns-result-order=ipv4first`), helping Telegram connectivity on IPv6-broken networks.

### Changed
- Added translations for `force_ipv4_dns` option.
- Updated docs with `force_ipv4_dns` configuration and Telegram network troubleshooting note.
- Bump OpenClaw to 2026.2.17

## [0.5.45] - 2026-02-16

### Changed
- Bump OpenClaw to 2026.2.15

## [0.5.44] - 2026-02-14

### Changed
- Bump OpenClaw to 2026.2.13

## [0.5.43] - 2026-02-13

### Changed
- Bump OpenClaw to 2026.2.12

### Added
- Portuguese (Brazil) translation (`pt-BR.yaml`) by medeirosiago

## [0.5.42] - 2026-02-12

### Changed
- Change nginx ingress port from 8099 to 48099 to avoid conflicts with NextCloud and other services
- Persist Homebrew and brew-installed packages across container rebuilds (symlink to `/config/.linuxbrew/`)

### Added
- SECURITY.md with risk documentation and disclaimer

### Improved
- Comprehensive DOCS.md overhaul (architecture, use cases, persistence, troubleshooting, FAQ)
- README.md rewritten as concise landing page with quick start guide
- New branding assets (icon.png, logo.png)
- Added Discord server link to README

## [0.5.41] - 2026-02-11

### Changed
- Update Dockerfile, config.yaml, and run.sh for enhancements
- Update icon and logo images for improved quality

## [0.5.40] - 2026-02-11

### Added
- Additional tools in Dockerfile

### Changed
- Improved nginx process management in run.sh

## [0.5.39] - 2026-02-10

### Fixed
- Fix OpenClaw installation command in Dockerfile

## [0.5.38] - 2026-02-10

### Changed
- Bump OpenClaw to 2026.2.9

## [0.5.37] - 2026-02-09

### Added
- OpenAI API integration for Home Assistant Assist pipeline
- Updated translations

## [0.5.36] - 2026-02-08

### Changed
- Documentation updates

## [0.5.35] - 2026-02-08

### Changed
- Update Dockerfile for Homebrew installation improvements

## [0.5.34] - 2026-02-08

### Added
- Install pnpm globally

### Changed
- Upgrade OpenClaw version to 2026.2.6-3

## [0.5.33] - 2026-02-06

### Changed
- Enhanced README with images and updated setup instructions

---

For the full commit history, see [GitHub commits](https://github.com/techartdev/OpenClawHomeAssistant/commits/main).
