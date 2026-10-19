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
- `GET /backups/<slug>/info`: for up to five candidate backups, the version of this add-on inside them.

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
- **Automatic deletion** (`gate_cleanup_hours`, default 48; `0` keeps everything): the add-on deletes the doctor captures of a gate run (plaintext database copies that OpenClaw 2026.10 doctor leaves in `/config/.openclaw.update-captures/`) that many hours after the run ended, or after a hold that followed the run was cleared, whichever is later. Captures that OpenClaw would keep (marked with `outcome.json`) go too: the rule against plaintext secrets takes precedence over OpenClaw's own retention. Copies that earlier add-on versions left are deleted the same way: the gate archives in `/share/openclaw-upgrade/` (plaintext from `0.5.94-full1`, encrypted from `0.5.94-full2`) and orphaned archive directories there, rehearsal exports in `/share/openclaw-rehearsal/` (encrypted and unencrypted), and the plaintext 2026.7 archives in `/config/.openclaw/upgrade-backups/`, counted from the later of their modification time and the completion of the 2026.8+ migration.
- **`/share` is shared with other add-ons**: any add-on with `/share` access can write there and plant symbolic links. The add-on only deletes there (the leftovers above), and those deletes never follow a symbolic link: they go through directory handles opened component by component with `O_NOFOLLOW`, an archive directory is renamed to `.oc-addon-deleting-<name>` before it is removed (a rehearsal export's files are unlinked one by one), and listings never follow links, so a planted link is removed as a link or the delete is refused, and a delete is never redirected into `/config` or elsewhere. Only entries whose names match what earlier add-on versions wrote are touched. Names read from `/share` are escaped before they are logged, so a crafted file name cannot add lines to the add-on log.
- **Still plaintext, inside `/config` only** (and so only in your encrypted Home Assistant backups): `openclaw.json` and its snapshots in `/config/.openclaw/backups/`, `/config/secrets/`, the gate's run records and quarantine under `/config/.openclaw-upgrade/gate/`, doctor captures until they are deleted, and the 2026.7 pre-upgrade archives in `/config/.openclaw/upgrade-backups/` until they are deleted (`gate_cleanup_hours` after the 2026.8+ migration; never with `0`). Do not copy these paths out of Home Assistant.

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
| Use a dedicated HA user for the `homeassistant_token` | Medium |
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
