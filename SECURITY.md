# Security Risks & Disclaimer

This document outlines the security risks associated with running the OpenClaw Assistant Home Assistant add-on and provides best practices for safe usage.

**By installing and using this add-on, you acknowledge and accept the risks described below.**

---

## Disclaimer

This add-on is provided **"AS IS"**, without warranty of any kind, under the [MIT License](LICENSE).

The authors and contributors of this add-on are **not responsible** for any damage, data loss, security breach, unauthorized access, financial loss, or any other harm that may occur as a result of installing, configuring, or using this add-on. This includes but is not limited to:

- Unintended actions performed by the AI agent
- Exposure of sensitive data (tokens, credentials, personal information)
- Unauthorized access to your Home Assistant instance or network
- Damage to smart home devices or connected systems
- Actions taken by third-party skills or integrations

**You use this add-on entirely at your own risk.**

---

## Understanding the Risks

### 1. Autonomous AI Agent

OpenClaw is an **agentic AI assistant** — it can plan, reason, and execute actions autonomously. Unlike a simple chatbot, it can:

- Execute shell commands on the add-on container
- Control smart home devices (if integrated with Assist pipeline or HA long-lived access token)
- Read and write files
- Make HTTP requests to external services
- Install and run third-party skills

**Risk**: If the agent is manipulated (e.g., via prompt injection from a malicious webpage or document), it could perform unintended actions within its permissions.

**Mitigation**: Review what entities you expose to the Assist pipeline. Only expose devices you're comfortable with the AI controlling.

**Changes to OpenClaw itself (GHSA-pw3x-g8v8-fvj2).** Through its `openclaw` tool an agent can ask for persistent changes to OpenClaw: configuration set/unset, plugin installs, gateway restarts. OpenClaw `>= 2026.9.2 < 2026.10.33` and `>= 2026.11.1 < 2026.11.4` applied them without approval whenever the run's exec defaults were full access, even for an agent whose tool policy denied exec. That covers `0.5.94-full1` … `0.5.94-full4` (OpenClaw 2026.10.4) and `0.5.94-full5` (2026.11.3, not to be installed). `0.5.94-full6` (2026.11.4) and `0.5.94-full7` (2026.11.11, the same approval rules) are not affected: an agent whose exec tool is denied or restricted now gets an approval request. Without approval OpenClaw still applies such changes in an explicit Full Access session (chosen by an admin operator) and for an agent that may run exec on the gateway host unrestricted (security full, ask off, no sandbox: OpenClaw's defaults, which the add-on keeps), because that agent could make them through a shell command anyway. To require approval for every such change, set `tools.openclaw.autoApproveChanges` to `false` (global or per agent).
- Until you update, deny the tool: add `"openclaw"` to `tools.deny` (keep the entries already there). Do not set `tools.openclaw.autoApproveChanges` on 2026.10.4 or 2026.11.3: they do not know the key, the configuration becomes invalid and the add-on holds. After the update the entry can stay; if you remove it, agents with the exec tool get such changes applied automatically again unless `autoApproveChanges` is `false`.
- `tools.openclaw.autoApproveChanges: true` (global or per agent) deliberately reopens the advisory's path: OpenClaw then applies every permitted change without asking anyone, also for an agent whose exec tools are denied. The migration gate warns about it (precheck, end of the run, `oc-upgrade status`); leave the key out, or set it to `false` to require approval even with Full Access.
- **Accepted gap in 2026.11.11.** 2026.11.4 and 2026.11.8 also tie the containment check of a delegated change (sandbox, workspace-only file policy) to the policy the run was admitted with ("preserve admitted delegation policy"). 2026.11.11 lacks that follow-up; OpenClaw's main line has it only from openclaw/openclaw#203901. Its check compares against the configuration read when the tool was built, so a policy change during a run can count differently. The approval rules above are unchanged, and with `tools.openclaw.autoApproveChanges: false` every delegated change still waits for a human approval. The add-on accepts this and carries no patch.

### 2. Network Exposure

When `gateway_bind_mode` is set to `lan`, the gateway is accessible to **all devices on your local network**. When exposed to the internet (via port forwarding or reverse proxy), it becomes accessible to **anyone**.

When `gateway_bind_mode` is set to `tailnet`, the gateway is exposed only on your Tailscale network. This significantly reduces exposure compared with `lan`, but all authenticated tailnet peers can still reach it.

**Risks**:
- Unauthorized users could interact with your AI agent
- API tokens could be intercepted over plain HTTP
- The gateway endpoint could be discovered by network scanners

**Mitigations**:
- Use HTTPS whenever possible (reverse proxy with TLS)
- Never expose the gateway port directly to the internet without authentication and encryption
- Use `gateway_bind_mode: loopback` if you only need local access
- Prefer `gateway_bind_mode: tailnet` over `lan` when you need remote/private-network access
- Keep your gateway auth token secret
- Keep the landing page and web terminal behind Home Assistant Ingress. The add-on restricts port `48099` to loopback and the Supervisor's internal proxy address so direct LAN clients cannot bypass Home Assistant authentication.

**Capability-scoped gateway paths (openclaw/openclaw#190863).** OpenClaw 2026.11.4 and the bundled 2026.11.11 refuse a capability-scoped request path (`/__openclaw__/cap/<cap>/<rest>`) whose `<rest>` starts with a second slash or an encoded slash or backslash (`//`, `%2f`, `%5c`), so that the gateway's route checks and the handler cannot interpret different paths. Both answer such a request with 400. 2026.11.11 has the fix itself (d4c687ac8c97), so the add-on carries no patch for it; `tests/oc_patches/gateway_capability_path_2026.11.11.test.mjs` checks the stock function.

**New commands of the OpenClaw 2026.11.10 line (bundled: 2026.11.11) that the add-on lets through.** Outside a HOLD the wrapper passes them; during a HOLD it refuses them, like every command outside its read-only allow-list.
- `openclaw pair <code>` approves a browser that shows a pairing code. Approving gives that browser administrator control of the gateway. Approve only a page you opened yourself that shows this code; if someone sent you the code or the command, answer no. `openclaw devices list` shows paired browsers, and `openclaw devices remove <id>` ends one's access.
- `openclaw id status|rebind|publish` manages OpenClaw ID remote access to this gateway: a tunnel through a relay for devices you admitted. It is off by default (`gateway.openclawId.enabled: false`); while off, the gateway starts no tunnel and contacts no OpenClaw ID service. Turning it on exposes the gateway beyond your network.
- `openclaw node join <link>` enrolls this machine as a node host with an OpenClaw ID invitation; `--service` installs it as an OS service.
The add-on refuses three other new commands; see section 10.

### 3. Plain HTTP Authentication (`allow_insecure_auth`)

Enabling `allow_insecure_auth` transmits authentication tokens over **unencrypted HTTP**. On a trusted home network this is generally acceptable, but:

**Risks**:
- Anyone on your network can intercept the token
- If your Wi-Fi is compromised, the token is exposed
- The token grants full access to the gateway

**Mitigations**:
- Only enable on trusted networks
- Never enable when the gateway is exposed to the internet
- Rotate your gateway token periodically: `openclaw config set gateway.auth.token <new-token>`

### 4. Home Assistant Token

The `homeassistant_token` option stores a **long-lived access token** that grants broad access to your Home Assistant instance. This is extremely powerful — it can control devices, read state, trigger automations, and more.

**Risks**:
- If the container is compromised, the attacker gains full HA access
- Skills or scripts running inside the add-on have access to this token
- The token does not expire unless manually revoked

**Mitigations**:
- Only provide this token if skills specifically require it
- Create a dedicated HA user with limited permissions for this token
- Revoke and regenerate the token if you suspect compromise
- Monitor your HA logs for unexpected API activity

### 5. Third-Party Skills & Supply Chain

OpenClaw supports installing skills from the community (ClawHub) and via npm. These are **third-party code** running inside the add-on container.

**Risks**:
- Malicious skills could exfiltrate data, install backdoors, or perform harmful actions
- Skills have access to the same permissions as the OpenClaw process
- Compromised npm packages could affect your installation
- [Security researchers have already found malicious skills](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html) published to ClawHub

**Mitigations**:
- Only install skills from trusted sources
- Review skill code before installing when possible
- Monitor the add-on logs for unexpected activity
- Keep the add-on updated to get security patches

**Plugins downloaded while the add-on runs.** OpenClaw and the image's other npm packages are installed when the image is built, resolved as of a fixed date (`npm install --before`). Three steps fetch from the npm registry while the add-on runs instead, always with the gateway stopped:
- OpenClaw's own doctor, in the migration gate's doctor passes (`openclaw doctor --fix`; on every gate run, also `oc-upgrade retry --doctor`): it brings every **enabled** official plugin of OpenClaw's catalog (for example `@openclaw/codex`, `@openclaw/acpx`, `@openclaw/brave-plugin`) to exactly the bundled OpenClaw's version (a recorded pin newer than that is kept), the same plugin update `openclaw update` makes. It skips disabled plugins, and a failed fetch is only a warning in the doctor log. This is OpenClaw's behaviour (also with OpenClaw 2026.10.4); the add-on does not change it.
- at start, after the gate, never during a HOLD and once per OpenClaw version: the Brave web-search plugin, `@openclaw/brave-plugin` in the bundled OpenClaw's version;
- likewise, since the OpenClaw 2026.11 line (from `0.5.94-full6`, OpenClaw 2026.11.4; `0.5.94-full7` bundles 2026.11.11; it came with `0.5.94-full5`, which is not to be installed): every **enabled** official plugin (`@openclaw/…`) that is still older than the bundled OpenClaw after the gate is updated to exactly that version (`openclaw plugins update <package>@<version>`, run by `oc-upgrade plugins-sync`). It first asks the registry for that version (`npm view`, at most 30 s, with OpenClaw's npm settings); without an answer it updates nothing and the gateway starts at once. It never downgrades and leaves disabled plugins, bundled plugins, plugins not installed from npm and other npm scopes alone.

**Risk**: these packages are not part of the image build and not limited by its date: what the npm registry serves for that name and version at that moment is installed, and it runs inside the gateway with its permissions. They come from OpenClaw's own npm scope, in the version OpenClaw released together with the bundled runtime (the image build checks that `@openclaw/brave-plugin`, `@openclaw/codex` and `@openclaw/acpx` exist in that version). A failed or blocked download leaves the installed version in place (a doctor warning in the gate, a `WARN` at start; the add-on's step retries at the next start).

**Mitigation**: disable official plugins you do not use (`openclaw plugins disable <id>`); then neither doctor nor the add-on updates them (the Brave plugin is installed by the add-on with each new OpenClaw version either way).

### 6. Router SSH Access

The `router_ssh_*` options allow the add-on to SSH into your router or network devices. This grants **direct access to your network infrastructure**.

**Risks**:
- A compromised add-on could reconfigure your router
- Firewall rules could be modified
- Network traffic could be intercepted or redirected

**Mitigations**:
- Use a dedicated SSH key with minimal permissions
- Restrict the SSH user's capabilities on the router (read-only if possible)
- Only enable if you have a specific use case that requires it, and only if you understand the risks very well

### 7. Browser Automation (Chromium)

The bundled Chromium runs with `noSandbox` (required in Docker). This reduces browser-level security isolation.

**Risks**:
- A malicious webpage could potentially escape the browser sandbox
- Automated browsing could expose session cookies or credentials
- Browser automation skills could visit unintended websites

**Mitigations**:
- Only use browser automation with trusted skills
- Do not use it to log into sensitive accounts
- The container itself provides some isolation from the host

### 8. Prompt Injection

AI agents that process external content (web pages, documents, emails) are vulnerable to **prompt injection** — hidden instructions that manipulate the agent's behavior.

**Risks**:
- A webpage or document could contain hidden instructions that cause the agent to perform unintended actions
- Data exfiltration through crafted prompts
- Actions performed on behalf of an attacker

**Mitigations**:
- Be cautious about what content you ask the agent to process
- Review agent actions in the logs
- Limit the entities and services exposed to the agent

### 9. Supervisor API Access (`hassio_api`)

Since `0.5.94-full2` the add-on declares `hassio_api: true` with `hassio_role: default`. The migration gate needs it for one read-only check before it changes the OpenClaw state: is there a recent, encrypted Home Assistant backup that contains this add-on? Restoring that backup is the only rollback point after a one-way OpenClaw migration.

**What the add-on reads** (and nothing else):
- `GET /addons/self/info`: only this add-on's slug and version are used. The response also contains this add-on's options in clear (for example `homeassistant_token`); it is never logged or stored.
- `GET /backups/info`: the backup list (name, date, type, contained add-ons, encryption per storage location).
- `GET /backups/<slug>/info`: for up to 50 candidate backups (the most recent first), the version of this add-on inside them.

Nothing is created, changed, restored or downloaded. The gate journal records only the chosen backup's slug, name, date, type, locations and add-on version.

**Why `default` and not `backup`**: the `default` role allows only `GET` on the Supervisor's `…/info` endpoints. The `backup` role would also allow creating, deleting, restoring and downloading backups.

**How the token is handled**:
- It is read from s6's container environment (`/run/s6/container_environment/SUPERVISOR_TOKEN`), with the process environment as fallback.
- It is sent only to the Supervisor's fixed address `172.30.32.2:80` (with `Host: supervisor`), using Python's `http.client`: no proxy (the `http_proxy` option does not apply), no redirects, and never to whatever the name `supervisor` resolves to on the host network.
- It is never logged; error messages contain neither the token nor a response body. A token with characters that do not belong in an HTTP header, or a malformed, oversized or too slow answer, leads to `ha-backup-unverified`, and the text and traceback of an unexpected gate error (`internal-error`) pass through the log redaction.
- It is removed from the environment of every OpenClaw process that the migration gate and `oc-upgrade` start (doctor, CLI checks), and `gateway_env_vars` refuses `SUPERVISOR_TOKEN`, `SUPERVISOR_API` and `HASSIO_TOKEN`.

**Accepted risk: everything in the container can use the token.** The gate needs the token for a few seconds of its precheck, but the Supervisor issues one token at every add-on start, valid as long as the add-on runs, and it cannot be limited to the gate:
- The token is readable by every process in the add-on container: the OpenClaw gateway, the agent and its shell tools, skills, the web terminal. s6 keeps it in `/run/s6/container_environment/SUPERVISOR_TOKEN`. Removing it from the environment of the gate's child processes does not change that; a prompt-injected agent or a malicious skill can read the file.
- With `hassio_api: true` and the role `default`, whoever holds the token can `GET` every `/<something>/info` endpoint of the Supervisor: the backup list and each backup's info (names, dates, type, contained add-ons and folders, encryption, sizes), host, network, OS, Supervisor, Core and hardware information (versions, host name, network interfaces and addresses, disks and devices), the list of installed add-ons and other add-ons' info.
- Other add-ons' options (which can hold their passwords and tokens): current Supervisor versions return them empty (`{}`) to an add-on with the role `default`; they are given only to Home Assistant Core, to the add-on itself, or to add-ons with the role `manager` or `admin`. Older Supervisor versions returned them in clear. Keep Home Assistant's Supervisor up to date.
- Before `0.5.94-full2`, without `hassio_api`, the token already reached what every add-on token reaches, such as this add-on's own `/addons/self/…` endpoints (its info and options in clear, `homeassistant_token` included, restart, stop) and `/info`.
- `hassio_api` with the role `default` adds no write access: the token still cannot create, restore, delete or download backups, read backup contents, or change or control other add-ons, the host or Home Assistant Core.

### 10. Backups and Leftover Copies

The add-on's data contains secrets: tokens, OAuth logins, API keys. Rule: **no plaintext secrets in archives or backups. Home Assistant backups stay inside the Home Assistant backup system and are encrypted.**

- **No copies outside the Home Assistant backup system**: the add-on writes no copy of the OpenClaw state outside the Home Assistant backup system. Since `0.5.94-full3` the migration gate writes no archive of its own and there is no export; the add-on writes nothing to `/share` (it only deletes leftovers there, see below). The only transient exception: reading a database whose WAL has no `-shm` index uses a private copy in the container's `/tmp`, deleted right after the read. The rollback after a one-way migration is restoring the encrypted Home Assistant backup that the gate requires.
- **Home Assistant backups**: create them encrypted, in **Settings → System → Backups**; do not download them, copy them to other machines or create unencrypted ones. The gate requires a recent encrypted backup before a migration and names unencrypted backups that contain this add-on in a `WARN` (up to three, the rest counted).
- **Automatic deletion** (`gate_cleanup_hours`, default 48; `0` keeps everything except a `.upgrade-*` folder without a swap plan, see the next point): the add-on deletes the doctor captures of a gate run (plaintext database copies that OpenClaw 2026.10 doctor leaves in `/config/.openclaw.update-captures/`, including what OpenClaw keeps of a capture that failed, which doctor names only as `evidence retained at …` or `Database backup files retained at …`; from OpenClaw 2026.11.5 doctor names its sealed captures only at debug level, so a gate run also records the `doctor-<uuid>` directories that appear during its doctor passes; a capture that no gate run names or recorded, for example from a doctor you ran yourself while no gate run was open, is kept and named in `oc-upgrade status`, while a doctor you run by hand while a gate run is held counts as part of that run; the captures of a gate run that never finished, for example one the next start closed as abandoned, are kept as well) and the SQLite copies its doctor passes saved beside the databases (`*.pre-startup-migration-*.bak`, from OpenClaw 2026.10.10 also `.scoped.bak`, and doctor's pre-repair cron backups of the state database, `/config/.openclaw/state/openclaw.sqlite.doctor-cron-<ms>-<uuid>.bak`, full plaintext copies with its device keys, tokens and other stored secrets that doctor writes before each cron repair it commits, from OpenClaw 2026.11.2 also when it records the cron jobs' inference accounts, and doctor's pre-repair recovery directories `<database directory>/openclaw-<repair>-recovery-<6 characters>/` with a full plaintext copy of that database, `database.sqlite`, that doctor writes before an index, media, transcript, session-window or orphan task delivery repair it commits (the last also with `orphan-rows.jsonl` and `manifest.json`; only directories that hold nothing else, unlinked file by file through a directory handle that never follows a link), and doctor's verified pre-repair snapshots of whole databases, `*.auth-profile-migration-<uuid>.bak` (the auth profile store: API keys and OAuth tokens), `*.pre-acp-key-migration-<uuid>.bak`, `*.pre-acp-metadata-migration-<uuid>.bak`, `*.pre-exec-approvals-migration-<uuid>.bak` and `*.doctor-gateway-token.<uuid>.bak` (before doctor moves the gateway token into its secret store), by their modification time; with OpenClaw 2026.11.11 also doctor's copy of an agent's `models.json` before it removes provider blocks that only copy a plugin's generated catalog, `agents/<id>/agent/models.json.bak-<ms>` (the whole previous file, literal provider keys included), by the time in its name or doctor's "backup:" line; with OpenClaw 2026.11.11 also its pre-repair cron backup, which is then a pre-migration copy `state/openclaw.sqlite.pre-startup-migration-<uuid>.bak`, and its cold-chat navigation recovery directories `openclaw-cold-navigation-recovery-*/`; OpenClaw itself keeps them, and copies from the runs of earlier add-on versions go at the first check after the update; only below `/config/.openclaw`: a copy beside an agent database registered outside it, elsewhere in `/config` or in `/share`, is never deleted by the add-on, which names it in a `WARN` after the doctor pass and at the end of the run and in `oc-upgrade status`: delete it yourself) that many hours after the run ended, or after a hold that followed the run was cleared, whichever is later. At the same time it deletes the gate's own plaintext copies of `openclaw.json` in the run directory (`/config/.openclaw-upgrade/gate/runs/<run>/config.*.json`: gateway token, literal provider and channel keys) and its saved output of `openclaw models status` and `models auth list` (`pc-models-status.json`, `pc-probe.json`, `pc-auth-list.json`, `pc-auth-order.json`: OpenClaw's masked key fragments, profile ids with e-mail addresses), also those of the runs of earlier add-on versions; only regular files with these names in a real run directory, through a directory handle that never follows a link. Captures that OpenClaw would keep (marked with `outcome.json`) go too: the rule against plaintext secrets takes precedence over OpenClaw's own retention. Copies that earlier add-on versions left are deleted the same way: the gate archives in `/share/openclaw-upgrade/` (plaintext from `0.5.94-full1`, encrypted from `0.5.94-full2`) and orphaned archive directories there, rehearsal exports in `/share/openclaw-rehearsal/` (encrypted and unencrypted), and the plaintext 2026.7 archives in `/config/.openclaw/upgrade-backups/`, counted from the later of their modification time and the completion of the 2026.8+ migration.
- **OpenClaw's own state upgrade at a gateway start (OpenClaw 2026.11.11)**: when a database is below the bundled schema, `openclaw gateway run` upgrades the state by copy and swap before it opens it (a `.upgrade-*` folder an earlier start left only makes it finish that folder's swap plan, if any, and delete the folder). It writes a full plaintext copy of the state to `/config/.openclaw/.upgrade-<version>-<pid>-<ms>/`, stages each other file it changes beside the live one (`.openclaw.json.upgrade-<version>-<pid>-<ms>`, the migrated config with the gateway token, which OpenClaw removes only when the upgrade fails with an error), runs its own doctor there (not through the add-on's wrapper), and keeps every file it replaced as `<file>.pre-<version>`: `state/openclaw.sqlite.pre-<version>` holds the auth profiles (keys and OAuth tokens), `openclaw.json.pre-<version>` the gateway token. The copy's doctor log stays as `logs/state-upgrade-<version>.log`. These copies would exist outside the gate's control, so the gate keeps that upgrade from running: its doctor migrates in place first, the postconditions hold (`pc-startup-upgrade`) when the first start would still upgrade, and every add-on start without a gate run holds instead of starting OpenClaw when it would (`startup-upgrade-pending`, `startup-upgrade-unfinished`; a gateway restart after a crash within a running add-on is not checked again). If such a start ran anyway, `oc-upgrade status` lists what it left, and the add-on deletes it `gate_cleanup_hours` after the newest of it was made (for a `<file>.pre-<version>`, a hard link that keeps the old file's time, the time of the swap), but only after a healthy gateway start (up 2 minutes, nothing left to upgrade): `.upgrade-*` folders without a swap plan, the `<file>.pre-<version>` files (regular files only, through directory handles that never follow a link), the state-upgrade logs and the staged copies `.<file>.upgrade-*` in `/config/.openclaw` (not those beside `$include` files elsewhere). A `.upgrade-*` folder with `plan.json` is never deleted, nor are the staged copies with its suffix: it is an interrupted swap that the next start finishes. With `gate_cleanup_hours: 0` they are only listed, except that a gate run's precheck deletes a `.upgrade-*` folder without a swap plan, and the staged copies of the same attempt, at once (the gate cannot pass while it exists, and OpenClaw's next start would delete the folder anyway).
- **Database copy and restore commands refused**: OpenClaw 2026.11.11's `openclaw database migration-capture create` writes a plaintext archive of the state, its database images and `openclaw.json`; `migration-capture restore` unpacks one, and `database restore-session-dependencies` rewrites the live state database. The wrapper refuses these three forms, also outside a HOLD (exit code 2), unless `OC_ADDON_UNSAFE=1`. `openclaw database migration-capture capabilities` only prints JSON and passes. Older database commands (`database port`, `database restore-migration-backup`, `database ownership claim`, already in 2026.11.4) pass outside a HOLD as before.
- **OpenClaw's own backup commands are not refused**: `openclaw backup create` (into the current directory, `--output` or a storage location with `--to`), `openclaw backup enable` (scheduled backups by a gateway automation, `--include-secrets`), `openclaw backup sqlite create` and `openclaw backup git create` (without `--exclude-secrets`) write archives or snapshots of the config, credentials and state database, that is the gateway token, API keys and OAuth tokens, outside the encrypted Home Assistant backup; local archives are not encrypted. These commands already exist in OpenClaw 2026.11.4. The wrapper lets them through outside a HOLD (during a HOLD it refuses them like every other command). Do not use them: back up with encrypted Home Assistant backups. Doctor's hint "No successful backup is recorded. Create one now with `openclaw backup create`" does not apply to this add-on. A refusal like the one for the database commands above protects only against accidental runs: an agent with shell access can copy the state in other ways.
- **The gate only reads OpenClaw's databases**: the migration itself is done by OpenClaw's doctor. The gate's own checks (`quick_check`, the foreign-key check, the Skill Workshop inventory and export, the cron job report, the session sizes) open the databases read-only, and the gate never writes into OpenClaw's databases, auth stores or cron jobs (from OpenClaw 2026.11.2 OpenClaw's doctor itself records the cron jobs' inference accounts in the state database during the migration). With OpenClaw 2026.11.3+ the precheck also reads the memory search settings and the model rows of `openclaw.json` and prints only agent ids, field names, provider/model ids and token limits, never a key or header value. For the cron report the gate also reads the provider keys in `openclaw.json` and in the agents' model catalogs (`models.json`, generated plugin catalogs) in memory, only to tell whether OpenClaw's doctor copies them; it prints and keeps provider ids and config paths, never a key. Before its cron config fixup, and for the provider lines of the cron report, it also compares, in memory, the stored API-key logins of such a provider with its literal key, as written and as OpenClaw substitutes `${NAME}` placeholders in it from the environment (a stored login that is not that same key keeps the gate from changing the provider); nothing of it is kept, printed or journaled. OpenClaw's doctor itself copies every literal provider key (also a placeholder such as `EMPTY`) from these files into its auth store (SQLite, plaintext like the other stored logins); an env SecretRef keeps the key out of both (it is then in the add-on options, `gateway_env_vars`). What the gate writes itself: `openclaw.json` (pre-migration, the scoped fixups between doctor passes, pins, and with OpenClaw 2026.10.10+ the one cron config fixup before doctor pass 1: `models.providers.<p>.auth = "api-key"` for a provider whose literal key doctor stores as a login and that a cron job uses, an atomic replace that keeps the file's mode and owner and leaves no copy beside it; not with `$include`) and, coming from 2026.7, the JSON session stores (pre-migration); it moves files into its quarantine, keeps its own records under `/config/.openclaw-upgrade/gate/`, and deletes what is listed under automatic deletion.
- **`/share` is shared with other add-ons**: any add-on with `/share` access can write there and plant symbolic links. The add-on only deletes there (the leftovers above), and those deletes never follow a symbolic link: they go through directory handles opened component by component with `O_NOFOLLOW`, an archive directory is renamed to `.oc-addon-deleting-<name>` before it is removed (a rehearsal export's files are unlinked one by one), and listings never follow links, so a planted link is removed as a link or the delete is refused, and a delete is never redirected into `/config` or elsewhere. Only entries whose names match what earlier add-on versions wrote are touched. Names read from `/share` are escaped before they are logged, so a crafted file name cannot add lines to the add-on log.
- **Still plaintext, inside `/config` only** (and so only in your encrypted Home Assistant backups): `openclaw.json` and its snapshots in `/config/.openclaw/backups/`, `/config/secrets/`, the gate's run records and quarantine under `/config/.openclaw-upgrade/gate/` (its copies of `openclaw.json` and saved `models status` output there only until they are deleted, see above), the gate's Skill Workshop exports in `/config/.openclaw-upgrade/gate/runs/<run>/skill-workshop/` (OpenClaw 2026.10.10+: every proposal before doctor drops them; secrets replaced with the add-on's log redaction rules, see the next point; in `proposals.json` a JSON value under a key that names a secret is hidden whole, whatever it holds, and no hash that could confirm a guess of a redacted value is kept; kept until you delete them), doctor captures and doctor's SQLite copies, including its pre-repair cron backups of the state database, its pre-repair recovery directories and its pre-repair snapshots, until they are deleted (copies no gate run made, and those of a gate run that never finished, stay until you delete them; `oc-upgrade status` lists them), the credential archives OpenClaw keeps after importing credential files (`credentials/oauth.json.migrated-<time>-<uuid>`, `credentials/auth-profiles/*.migrated-*`, `agents/<id>/agent/auth-profiles.json.migrated-*`, `*.sqlite-import.*.bak` and older `*.migrated` files; plaintext keys and OAuth tokens in several of them; neither OpenClaw nor the add-on deletes them, `oc-upgrade status` lists them: delete them yourself once the logins work), databases OpenClaw set aside as `<database>.corrupt-<time>` (for example doctor's renamed copy of another agent's database; complete databases with their secrets; neither OpenClaw nor the add-on deletes them, `oc-upgrade status` lists them: delete them yourself once you are satisfied), the chat cold archives `agents/<id>/sessions/cold/*.jsonl.zst` (OpenClaw 2026.11.11, on by default: chats inactive for 30 days, compressed, not encrypted; required history, which the add-on never deletes and which every backup of the add-on includes), and the 2026.7 pre-upgrade archives in `/config/.openclaw/upgrade-backups/` until they are deleted (`gate_cleanup_hours` after the 2026.8+ migration; never with `0`). Do not copy these paths out of Home Assistant.
- **Log redaction** (what the add-on replaces by `***` in the gate's lines of the add-on log, including cron job names, its HOLD texts and journal, the `[doctor]` lines of the add-on log, `oc-upgrade log`, error messages, and the Skill Workshop export; with every OpenClaw version). It works on text patterns and can miss a secret written in a form it does not know. The `[doctor]` lines and `oc-upgrade log` are read line by line; the rules that span lines still apply there: a PEM block hides every line up to its END line (at most 200 lines when the END line is missing), a YAML block scalar its deeper-indented lines, and a key at the end of a line the value on the next line. What a HOLD text quotes from doctor's output is redacted before it is cut.
  - **Hidden:** the value after a key that names a secret and `:` or `=` (also `"key": value`, `'key': value`, `**Key:** value`, `` `key`: value ``, `key = value`, or the value alone on the next line; a YAML block scalar `key: |` or `key: >-` with all the lines indented below it). Such a key ends in `token`, `secret`, `password`, `passwd`, `passphrase`, `passcode`, `API key` (`api-key`, `apiKey`), `Passwort`, `Kennwort`, `Schlüssel` (`API-Schlüssel`, `WLAN-Schlüssel`, `Netzwerkschlüssel`), `Zugang`, `Zugangscode`, `Zugangsdaten`, `wachtwoord`, `contraseña`, or a private, secret, access, signing, encryption, master or client key (`private_key`, `AWS_SECRET_ACCESS_KEY`, `PrivateKey`), also after a prefix (`botToken`, `db_password`, `WLAN-Passwort`, `Routerkennwort`); or in `key` after `_` or `-` (`wifi_key`, `wlan-key`); or it is `pwd`, `pw`, `pass`, `senha`, `hasło`, `парола`, `пароль` or `mot de passe` as a word of its own, after `_`, `.` or `-`, or in camelCase (`MYSQL_PWD`, `SMTP_PASS`, `smtp.pass`, `smtpPass`, `smtp pass: …`, `user=bob pass=…`); a `PIN`, `PIN-Code`, `SIM-PIN` or `PUK` counts when its value is 3 to 12 digits. In the export's `proposals.json` a JSON key counts by its last words too (`WLAN Passwort`, `SIM PIN`). A value in quotes (`"…"`, `'…'`, `` `…` ``; YAML's `''` inside single quotes) is hidden up to its closing quote. Any other value is hidden to the end of its line, but it ends before a comma or semicolon followed by a blank or a quote, a `)`, `]` or `}` that closes a bracket opened before it, a sentence-final `.`, a blank followed by `#` (comment) or `|` (table cell), a blank followed by the next `name=`, `Name: ` or `--flag` field, and `&name=` in a URL; the value of a command-line flag (`--token=…`, `--passwort=…`) is one word. So `password: "correct horse battery"`, `Passwort: correct horse battery` and `(password: 4711).` become `password: "***"`, `Passwort: ***` and `(password: ***).`.
  - **Also hidden:** one of the password words (password, passwd, Passwort, Kennwort, passphrase, passcode, wachtwoord, contraseña, senha, hasło, парола, пароль, mot de passe) followed by `is`, `was`, `to`, `ist`, `war`, `lautet`, `heißt`, `auf`, `est`, `es`, `é`, `jest` or `е` and a value in quotes or one word that contains a digit (`Das Passwort ist 4711.`, `set the password to hunter2`), or the whole value when a colon follows the verb (`Das Passwort lautet: Sommer 2024`); one of these password words followed directly by a value in quotes or one word that contains a digit (`Passwort 4711 für den Router`); `PIN`, `PIN-Code`, `SIM-PIN` or `PUK` followed by 3 to 12 digits without a colon (`PIN 1234`); `key=value` (URL query, env, logfmt) for a key that contains `token`, `secret`, `password` or `apikey` or ends in `key` (one word); the argument of `--token`, `--password`, `--secret`, `--api-key`; the password in `scheme://user:password@host`, also with an empty user (`redis://:password@host`); `Bearer`/`Basic` credentials and the credentials of any other scheme after `Authorization:` (`Token …`, `Bot …`); PEM private keys (the whole block); age secret keys; Google (`AIza…`), Slack (`xox…-`), GitHub (`ghp_…`, `github_pat_…`) and `sk-…` keys (also `csk-…` and `hsk-…`, and after an escape such as `\n`, `\x22` or `%3D`; not the `sk-` after a letter or digit, as in `task-delivery` or `ask-…`); Telegram bot tokens; JWTs; any standalone run of 40 or more letters, digits, `_` and `-` (not in a path or file name, and not OpenClaw's own directory names `doctor-<uuid>` and `openclaw-<repair>-recovery-<6 characters>`).
  - **Not hidden:** a secret with no such key or format (a bare `4711`, `PIN ist 1234`, `Passwort ist geheim` without a digit or colon, a password in a table under a `Password` heading, a key word not listed here such as `clave:` or `lösenord:`); words between the key word and the colon (`Passwort für das WLAN: …`, `Passwort (WLAN): …`); a PIN written in groups (`PIN: 1234 5678` keeps `5678`); the rest of an unquoted value after one of the delimiters above (`password: correct, horse` keeps `horse`); a bare `true`, `false`, `null`, `undefined` or `none` as the value (`apiKey: undefined`); a token shorter than 40 characters in no known format. Words that only contain a keyword stay readable (`maxTokens`, `passed`, `bypass`, `pinned`, `password_hint`), and so do OpenClaw's own uses of them (`first pass: …`, `one more pass: …`, `convergence pass: …`, `dependency pin: name@2026.11.1`, `pin=true`, `password is configured`).

---

## Best Practices Summary

| Practice | Priority |
|---|---|
| Use HTTPS for remote access | High |
| Keep `gateway_bind_mode: loopback` unless network access is needed | High |
| Prefer `gateway_bind_mode: tailnet` over `lan` for remote/private access | High |
| Only install skills from trusted sources | High |
| Review exposed entities in Assist pipeline | High |
| Keep the add-on updated | High |
| Use only encrypted Home Assistant backups; never download or copy them elsewhere | High |
| Approve a pairing code (`openclaw pair`, `openclaw devices approve`) only for a browser you opened yourself | High |
| Use a dedicated HA user for the `homeassistant_token` | Medium |
| Disable OpenClaw plugins you do not use (OpenClaw's doctor and the add-on update enabled official plugins from npm) | Medium |
| Keep the Home Assistant Supervisor up to date (older versions show other add-ons' options to this add-on's token) | Medium |
| Monitor add-on logs regularly | Medium |
| Rotate gateway tokens periodically | Medium |
| Restrict router SSH user permissions | Medium |
| Back up your configuration regularly (encrypted Home Assistant backups) | Low |

---

## Reporting Security Issues

If you discover a security vulnerability in this add-on, please report it responsibly by opening a private security advisory on GitHub rather than a public issue.

---

*This document does not constitute legal advice. Consult a qualified professional for legal guidance specific to your situation.*
