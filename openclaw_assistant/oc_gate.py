"""
Migration gate for the bundled OpenClaw runtime (2026.7.x -> 2026.9+/2026.10.x, later bumps).

Phases (spec §7): 1 precheck, 2 archive (/share, age-encrypted or off), 3 cleanup/quarantine, 4 pre-migrate
(R1-R5, from-7x), 5 doctor pass 1, 6 fixups (F1-F4, from-7x), 7 doctor pass 2 (+3),
8 postconditions, 9 pins (from-7x), finalize (marker).

Entry points used by oc-upgrade:
  plan(apply=False)            `oc-upgrade gate --plan`      rc 0 / 10 / 11 / 3 / 1
  run_gate()                   `OC_GATE_FROM_RUNSH=1 oc-upgrade gate`  rc 0 / 20 / 130 / 143 / 1
  dry_run(network=False)       `oc-upgrade gate --dry-run`   rc 0 / 20 / 1
  hold_after_start(code, rc)   `oc-upgrade gate --hold-exit78|--hold-crash-loop <rc>`  rc 0
  retry_cmd(args), log_cmd(args), cleanup_cmd(args), status_lines(), readiness_lines()

Every line printed starts with "[gate]" (warnings: "WARN [gate]"); doctor output is mirrored
as "[doctor] ..." (redacted). Secrets are never printed.
"""

import errno
import gzip
import hashlib
import json
import math
import os
import re
import select
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import oc_common as C

_MIG = None


def mig():
    """oc_migrate (contract §4), imported on first use so `gate --plan` never depends on it."""
    global _MIG
    if _MIG is None:
        import oc_migrate  # noqa: PLC0415
        _MIG = oc_migrate
    return _MIG


# --- constants -----------------------------------------------------------------------------

PHASES = ("precheck", "archive", "cleanup", "premigrate", "doctor1", "fixups", "doctor2",
          "postconditions", "pins", "finalize")
PHASE_NO = {"precheck": 1, "archive": 2, "cleanup": 3, "premigrate": 4, "doctor1": 5, "fixups": 6,
            "doctor2": 7, "postconditions": 8, "pins": 9, "finalize": 9}
# Fixups run in every mode: F1b (contract addendum 2 rule 4) also applies to bump/maintenance runs.
FROM7X_ONLY = frozenset({"premigrate", "pins"})
DOCTOR_PHASES = ("doctor1", "fixups", "doctor2")

ACCEPTABLE = frozenset({
    "checkpoint-not-735", "legacy-db-unimported", "active-memory-optouts", "telegram-bindings-nonempty",
    "oauth-json-only", "legacy-memory-sidecar", "models-platform-only", "canonical-openai-refs",
    "models-route-collision",
    "sqlite-check-timeout", "no-network", "orphan-agent-db",
    "doctor-not-idempotent", "doctor-warnings",
    "pc-schema-meta", "pc-legacy-files", "pc-lint-errors", "pc-lint-failed", "pc-legacy-refs",
    "pc-codex-runtime", "pc-runtime-pin", "pc-models-status", "pc-sessions-runtime", "pc-auth-order",
    "pc-probe", "pc-legacy-state", "pins-invalid",
    # retired pre-July-2026 state that OpenClaw 2026.10 refuses (oc_migrate.classify_retired_state)
    "cron-json-unimported", "oauth-sidecar-referenced", "plugin-index-unimported", "plugins-installs-unindexed",
    "device-pair-subscribers", "voice-call-log", "telegram-spool-invalid", "dreaming-json-unmigrated",
    "doctor-held-back",  # acceptable only on rc 0 (2026.10 reports held stores without failing doctor)
    # no recent encrypted Home Assistant backup with this add-on / the backup list could not be read
    "ha-backup-missing", "ha-backup-unverified",
})
NO_RETRY = frozenset({"newer-state", "runtime-integrity"})
POST_RUN_HOLDS = frozenset({"exit78", "crash-loop"})
HOOK_KEYS = ("raise_in_phase", "doctor_cmd", "skip_network_check", "accept", "skip_cleanup_kinds",
             "doctor_timeout_s", "skip_space_check", "skip_backup_check", "supervisor_url",
             "supervisor_token_file", "cleanup_interval_s", "cleanup_clock_offset_s")

STATE_EXCLUDES = ("upgrade-backups", "logs", "tmp", "cache", ".cache")
WORKSPACE_FULL_LIMIT = 2 * C.GIB
DOCTOR_MIRROR_CAP = 3000
HEARTBEAT_S = 60
DOCTOR_KILL_AFTER = 600
DOCTOR_STOP_GRACE = 240
ARCHIVE_TIMEOUT = 6 * 3600
AGE_MAGIC = b"age-encryption.org/v1\n"
AGE_CHUNK = 64 * 1024
BACKUP_SKEW_S = 600
CLEANUP_INTERVAL_S = 3600
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}$")
SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")  # one path component, never ".."
# OpenClaw 2026.10 doctor: "Pre-repair state retained for manual recovery at <dir>/manifest.json."
CAPTURE_RE = re.compile(r"Pre-repair state retained for manual recovery at (\S+)/manifest\.json")
CAPTURE_NAME_RE = re.compile(r"^doctor-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
QUICK_CHECK_COPY_LIMIT = 512 * C.MIB
CHECKPOINT_735 = "2026.7.35"
ATTESTATION_HEADER = b"openclaw-workspace-attestation:v1\n"
CONTENT_VERSION_KEY = "state.schema.contentVersion"

NODE_CAPABILITY_JS = (
    "const m=await import(process.env.OCQ_PKG+'/node-sqlite.mjs');"
    "const p=await m.detectCurrentSqliteCapabilities();"
    "const f=m.nodeRuntimeFailure(process.versions.node,p);"
    "if(f){console.error(f);process.exit(1)}"
    "console.log(process.versions.node+' '+p.version)"
)

ADVICE = {
    "runtime-schema-unknown": "the add-on image is broken (OpenClaw package lacks schema targets): reinstall or rebuild the add-on",
    "node-runtime": "the bundled Node.js cannot run this OpenClaw: reinstall or rebuild the add-on",
    "openclaw-running": "another OpenClaw process is running: stop it (restart the add-on), then oc-upgrade retry",
    "gate-busy": "another migration gate is running: wait for it, or restart the add-on",
    "config-missing": "restore openclaw.json from the Home Assistant backup, then oc-upgrade retry",
    "config-unreadable": "fix openclaw.json (strict JSON required; JSON5 comments are unsupported), then oc-upgrade retry",
    "config-includes": "inline the $include files into openclaw.json, then oc-upgrade retry",
    "state-symlink": "replace the symlink by the real directory (or bind-mount it), then oc-upgrade retry",
    "newer-state": "restore the Home Assistant backup that matches this add-on version",
    "not-pre-journal": "restore the 0.5.93 backup (the state is not a clean 2026.7.x state)",
    "archive-missing": "put the archive back (same path, unchanged; sha256sum -c SHA256SUMS in its directory must pass) "
                       "and oc-upgrade retry, or restore the encrypted Home Assistant backup and start over",
    "archive-key-missing": "set gate_archive_age_recipient in the add-on Configuration to your age public key (age1..., "
                           "from age-keygen on a trusted device; keep the private key off this host), or set "
                           "gate_archive: off (no archive; rollback only through the encrypted Home Assistant backup), "
                           "then oc-upgrade retry",
    "archive-key-invalid": "put exactly one age public key (age1..., 62 characters) into gate_archive_age_recipient, never "
                           "the AGE-SECRET-KEY private key (if it was pasted anywhere, create a new key pair), or set "
                           "gate_archive: off, then oc-upgrade retry",
    "archive-age-missing": "the add-on image has no working age tool: reinstall or rebuild the add-on",
    "ha-backup-missing": "create an encrypted Home Assistant backup that includes this add-on before updating (Settings > "
                         "System > Backups, add-on stopped, stored locally or on a network mount: cloud-only copies are "
                         "not visible to the add-on), then oc-upgrade retry",
    "ha-backup-unverified": "the Supervisor backup list could not be read (see the reason): make sure an encrypted backup "
                            "with this add-on exists (Settings > System > Backups), then oc-upgrade retry",
    "legacy-state-dir": "move /config/.clawdbot out of /config (or merge it manually), then oc-upgrade retry",
    "custom-session-store": "remove session.store from openclaw.json (custom session stores are not migrated), then oc-upgrade retry",
    "sessions-unreadable": "repair or move the unreadable sessions.json files, then oc-upgrade retry",
    "models-codex-provider": "replace codex/... or codex-cli/... model refs and the models.providers.codex block, then oc-upgrade retry",
    "models-codex-runtime": "remove the Codex agentRuntime pins from the openai-codex/... (or codex/...) entries in openclaw.json "
                            "(a Codex pin on an openai/... entry is kept), then oc-upgrade retry",
    "models-route-collision": "use one form per model on 0.5.93 (openai-codex/<model> or openai/<model>, not both), "
                              "then oc-upgrade retry",
    "models-provider-merge": "merge models.providers[\"openai-codex\"].models into models.providers.openai by hand, then oc-upgrade retry",
    "models-wildcard-pinned": "remove the agentRuntime pin from the openai-codex/* wildcard entry, then oc-upgrade retry",
    "low-disk-config": "free space on the /config disk, then oc-upgrade retry",
    "low-disk-share": "free space on /share, then oc-upgrade retry",
    "low-disk-tmp": "free space for SQLite temporary files (/tmp, /var/tmp), then oc-upgrade retry",
    "sqlite-corrupt": "restore the database from a backup (quick_check failed), then oc-upgrade retry",
    "archive-failed": "check free space and permissions on /share (the reason names tar or age), then oc-upgrade retry",
    "archive-verify-failed": "check the /share disk, then oc-upgrade retry (nothing was changed; a new archive is written)",
    "archive-timeout": "check /share performance, then oc-upgrade retry",
    "cleanup-failed": "check permissions under /config/.openclaw-upgrade, then oc-upgrade retry",
    "premigrate-failed": "check free space and permissions, then oc-upgrade retry",
    "config-retired-keys": "remove the listed settings from openclaw.json on 0.5.93 (OpenClaw 2026.7.35 does not use "
                           "them), then oc-upgrade retry",
    "retired-state-outside": "move the listed pre-July-2026 files away by hand (they are in your backup), then oc-upgrade retry",
    "retired-state-uninspectable": "fix or remove the listed paths (they must be directories or absent), then oc-upgrade retry",
    "retired-memory-index": "on 0.5.93 run `openclaw memory index --agent <id>` for each listed agent (2026.7.35 converts "
                            "the index), then oc-upgrade retry",
    "pre-july-schema": "restore a backup taken after a clean 0.5.93 start (pre-July-2026 databases are not migrated by "
                       "OpenClaw 2026.10)",
    "telegram-spool-unsupported": "rename or move the listed telegram/ingress-spool-* entries, then oc-upgrade retry",
    "doctor-retired-format": "doctor refused pre-July-2026 settings or files (see the reason): remove or move them "
                             "(they are in your encrypted Home Assistant backup, and in the gate archive unless gate_archive is off), "
                             "then oc-upgrade retry; a plain retry repeats the refusal",
    "doctor-held-back": "doctor held back agent databases: re-register the agent (OC_ADDON_UNSAFE=1 openclaw agents add <id> --workspace <ws> --agent-dir <dir> --non-interactive) or restore the backup, then oc-upgrade retry",
    "doctor-migration-refused": "fix the item doctor reported (oc-upgrade log), then oc-upgrade retry",
    "doctor-maintenance-refused": "oc-upgrade retry (doctor resumes from its last committed step); if the reason mentions "
                                  "a different PID namespace, wait 90 s after the previous stop first",
    "doctor-plugin-load": "make sure the network is available, then oc-upgrade retry",
    "doctor-config-write": "oc-upgrade retry",
    "doctor-backup-unverifiable": "data at risk: restoring the backup is recommended; oc-upgrade retry is allowed",
    "doctor-incomplete": "oc-upgrade retry (doctor resumes from its last committed step)",
    "doctor-failed": "see oc-upgrade log, fix the reported check, then oc-upgrade retry",
    "doctor-timeout": "oc-upgrade retry (doctor resumes; it is not re-run automatically in the same start)",
    "doctor-interrupted": "oc-upgrade retry",
    "doctor-crashed": "doctor was killed (out of memory?): free memory (stop other add-ons), then oc-upgrade retry",
    "doctor-invocation": "the doctor command line was refused (broken image?): reinstall the add-on, then oc-upgrade retry",
    "interrupted-twice": "the gate was interrupted twice: make sure nothing stops the add-on during the migration, then oc-upgrade retry",
    "fixups-invalid": "the post-doctor fixups produced an invalid config (restored): see oc-upgrade status, then oc-upgrade retry",
    "pc-schema": "the databases are not at the target schema: oc-upgrade retry --doctor",
    "pc-config": "fix the configuration (openclaw config validate), then oc-upgrade retry",
    "internal-error": "see the traceback in the gate events.log (oc-upgrade status), then oc-upgrade retry",
    "bump-repeat": "the gate already ran for this runtime but the state still needs migration: check oc-upgrade check, then oc-upgrade retry",
    "exit78": "see the reason above, fix it, then oc-upgrade retry",
    "crash-loop": "see the gateway log, fix the cause, then oc-upgrade retry",
}

# Doctor output classification (spec §7.5 with critique B3/B8)
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
BOX_RE = re.compile("[─-╿■-◿]")
# 2026.10 refusals of pre-July-2026 settings/files/schemas (a retry cannot pass them; checked first).
RETIRED_FORMAT_MARKERS = (
    "retired pre-July-2026 settings", "retired pre-June keys", "predates July 1, 2026",
    "retired pre-July 2026 format", "predates the July 2026 upgrade support window",
    "pre-July-2026 state are no longer migrated", "Retired memory index format detected", "predates July 2026",
    "upgrades from pre-July-2026",
    "unreleased session schema", "unsupported agent database registry schema",
    "Unsupported Telegram spool directory", "Telegram state must be a directory",
    "Cannot inspect potentially retired state",
)
# Held agent stores: 9.9 failed doctor on them; 2026.10 only warns and exits 0 (doctor-health-BmFjJGcU.mjs:185-187).
# "Held agent <id> database ... (retained-by-deletion)" is an agent deleted with its files kept: not a problem
# (docs/cli/doctor/state-migrations.md:171-174), so that line is ignored on rc 0.
HELD_BACK_MARKERS = ("held back", "remain held")
_HELD_AGENT_RE = re.compile(r"Held agent (?:(?!\(retained-by-deletion\)).){1,300}?(?:deletion history needs repair|"
                            r"deletion journal|unverified)", re.I)
FATAL_MARKERS = (
    ("doctor-retired-format", RETIRED_FORMAT_MARKERS, None),
    # a race doctor reports when the journal changed while it quarantined: a retry passes
    ("doctor-incomplete", ("Agent deletion journal changed before quarantine",), None),
    ("doctor-migration-refused", ("Doctor stopped because",), None),
    # specific failures before "Doctor could not complete ...", which 2026.10 prints as a wrapper around them
    ("doctor-plugin-load", ("plugin load errors",), None),
    ("doctor-config-write", ("config fixes were not applied",), None),
    ("doctor-backup-unverifiable", ("Cannot verify pre-migration SQLite backup", "backup group is missing"), None),
    ("doctor-maintenance-refused", ("Doctor could not enter maintenance", "Doctor could not complete",
                                    "Doctor could not acquire", "Doctor could not reacquire",
                                    "Doctor could not promote"), None),
    # after the specific failures: 2026.10 prints held-back warnings on otherwise normal runs
    ("doctor-held-back", HELD_BACK_MARKERS + ("Held agent ", "unverified-agent-databases", "Agent deletion journal"),
     None),
    ("doctor-incomplete", ("schema migration required",), re.compile(r"SQLite .{0,200}?timed out after", re.I)),
    ("doctor-failed", ("Failing check ",), None),
)
SUSPICIOUS_MARKERS = ("Preserved retired", "may contain unmigrated data", "Pre-June OAuth credentials")
# Only in the last doctor pass: pass 1 reports plugins pinned to the 7.x package as unfinished until doctor
# has updated them (deferred-plugin-migrations-DtqETF3J.mjs:220; gone in pass 2 in every rehearsal).
# The same for auth profile renames: pass 1 always prints "Kept auth profile openai-codex:... unchanged" before
# the alias step renames it (repair-sequencing-DFs-UYNz.mjs:408-413); in the last pass it is a real deferral.
# 2026.10.4 turns a failed dreaming cron inventory into a recoverable warning with rc 0 (memory-core
# doctor-contract-api.js:119); 2026.10.3 refused the step ("Doctor stopped because"), so it must not pass silently.
FINAL_PASS_SUSPICIOUS = ("data/settings upgrade is unfinished", "Deferred auth profile alias",
                         "Deferred stale auth profile alias", "Kept auth profile ",
                         "Dreaming cron inspection remains pending")

STOP = threading.Event()
_STOP_SIG = [None]
NODE_FALLBACKS = []


class GateStopped(Exception):
    pass


class HoldError(Exception):
    def __init__(self, findings, phase, resume_after=False):
        super().__init__(", ".join(f["code"] for f in findings))
        self.findings = findings
        self.phase = phase
        self.resume_after = resume_after


def finding(code, cls, message, phase=""):
    return {"code": code, "cls": cls, "message": message, "phase": phase}


# --- paths, hooks, small io ------------------------------------------------------------------

def gpaths():
    p = C.paths()
    g = p["UPG_DIR"] / "gate"
    p.update({
        "GATE": g, "JOURNAL": g / "journal.json", "MARKER": g / "migrated.json",
        "LEDGER": g / "pins-ledger.json", "RETRY": g / "retry-request.json", "RUNS": g / "runs",
        "QUAR": g / "quarantine", "LOCK": g / ".lock", "HOOKS": g / "test-hooks.json",
        "HOLD": p["UPG_DIR"] / "hold.txt", "ARCHIVES": p["SHARE"] / "openclaw-upgrade",
    })
    return p


def ensure_dirs(gp=None):
    gp = gp or gpaths()
    for d in (gp["UPG_DIR"], gp["GATE"], gp["RUNS"], gp["QUAR"]):
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass


def load_hooks():
    """Test hooks: honoured only with OC_GATE_TEST_HOOKS=1 (spec §8.6)."""
    if os.environ.get("OC_GATE_TEST_HOOKS") != "1":
        return {}
    data = C.load_json_or_none(gpaths()["HOOKS"])
    if not isinstance(data, dict):
        return {}
    return {k: data[k] for k in HOOK_KEYS if k in data}


def addon_version():
    return os.environ.get("ADDON_VERSION") or os.environ.get("BUILD_VERSION") or "unknown"


def new_run_id():
    return C.utc_now().strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]


def load_journal():
    path = gpaths()["JOURNAL"]
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("gate journal.json is not a JSON object")
    return data


def load_marker():
    m = C.load_json_or_none(gpaths()["MARKER"])
    return m if isinstance(m, dict) else None


def load_retry():
    r = C.load_json_or_none(gpaths()["RETRY"])
    return r if isinstance(r, dict) else None


def has_upgrade_sensitive_state():
    """Mirror of run.sh has_upgrade_sensitive_state (no gate on a fresh install)."""
    p = C.paths()
    if p["CONFIG_PATH"].is_file() or (p["STATE"] / "state").is_dir():
        return True
    agents = p["STATE"] / "agents"
    try:
        with os.scandir(agents) as it:
            return any(True for _ in it)
    except OSError:
        return False


def out(line):
    print(line, flush=True)


# --- read-only DB access with node fallback (B11) ------------------------------------------

def q(path, sql, params=()):
    try:
        return C.query_ro(path, sql, params)
    except sqlite3.DatabaseError as exc:
        try:
            rows = C.node_query(path, sql, params=params, stop_event=STOP)
        except C.NodeQueryError as nexc:
            raise sqlite3.DatabaseError(f"{exc} (node fallback: {nexc})") from exc
        NODE_FALLBACKS.append(str(path))
        return [tuple(r.values()) if isinstance(r, dict) else tuple(r) for r in rows]


def _mq(path, sql):
    """Reader handed to oc_migrate.classify_state_files (read-only, node fallback)."""
    return q(path, sql)


def table_names(path):
    return {r[0] for r in q(path, "SELECT name FROM sqlite_master WHERE type='table'")}


def db_uv(path):
    try:
        return C.user_version(path)
    except C.SchemaUnknown:
        try:
            rows = C.node_query(path, "PRAGMA user_version", stop_event=STOP)
        except C.NodeQueryError:
            raise
        NODE_FALLBACKS.append(str(path))
        if rows and isinstance(rows[0], dict):
            return int(list(rows[0].values())[0])
        raise


def schema_meta_primary(path, tables=None):
    tables = table_names(path) if tables is None else tables
    if "schema_meta" not in tables:
        return None
    rows = q(path, "SELECT role, schema_version, agent_id, app_version FROM schema_meta WHERE meta_key='primary'")
    return dict(zip(("role", "schema_version", "agent_id", "app_version"), rows[0])) if rows else None


def startup_checkpoint(state_db):
    try:
        if not state_db.exists() or "schema_meta" not in table_names(state_db):
            return None
        rows = q(state_db, "SELECT app_version FROM schema_meta WHERE meta_key='startup-migrations'")
        return rows[0][0] if rows else None
    except sqlite3.Error:
        return None


def agent_db_version(path):
    """user_version of an agent DB; None for a fresh, unowned DB (ignored by 9.9)."""
    uv = db_uv(path)
    if uv is None:
        return None
    if uv == 0:
        tables = table_names(path)
        app = [t for t in tables if not t.startswith("sqlite_")]
        if not app and schema_meta_primary(path, tables) is None:
            return None
    return uv


# --- workspaces ------------------------------------------------------------------------------

def _cfg_get(cfg, *keys):
    cur = cfg
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur


def _expand_ws(value, root):
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    if v == "~" or v.startswith("~/"):
        v = str(root) + v[1:]
    p = Path(v)
    if not p.is_absolute():
        p = Path(root) / p
    return Path(os.path.normpath(str(p)))


def workspaces(cfg):
    """Every configured workspace (§6.2), default first, de-duplicated."""
    p = C.paths()
    found = [Path(os.path.normpath(str(p["WORKSPACE"])))]
    agents = cfg.get("agents") if isinstance(cfg, dict) else None
    cands = [_cfg_get(agents, "defaults", "workspace")]
    lst = agents.get("list") if isinstance(agents, dict) else None
    for e in lst if isinstance(lst, list) else []:
        if isinstance(e, dict):
            cands.append(e.get("workspace"))
    ent = agents.get("entries") if isinstance(agents, dict) else None
    for e in ent.values() if isinstance(ent, dict) else []:
        if isinstance(e, dict):
            cands.append(e.get("workspace"))
    for c in cands:
        w = _expand_ws(c, p["CONFIG_ROOT"])
        if w is not None and w not in found:
            found.append(w)
    return found


# --- classification (§6.2 + B4/B5) -----------------------------------------------------------

def configured_agent_ids(cfg):
    ids = []
    agents = cfg.get("agents") if isinstance(cfg, dict) else None
    lst = agents.get("list") if isinstance(agents, dict) else None
    for e in lst if isinstance(lst, list) else []:
        if isinstance(e, dict) and isinstance(e.get("id"), str) and e["id"].strip():
            ids.append(e["id"].strip())
    ent = agents.get("entries") if isinstance(agents, dict) else None
    for k in ent.keys() if isinstance(ent, dict) else []:
        if isinstance(k, str) and k.strip():
            ids.append(k.strip())
    if not ids:
        ids = ["main"]
    out_ids = []
    for i in ids:
        for c in (i, i.lower()):
            if c not in out_ids:
                out_ids.append(c)
    return out_ids


def agent_databases(state_dir, cfg, state_tables):
    """(targets, orphans): targets = configured ∪ registered agent DBs [(id, Path)], orphans = other globbed DBs."""
    state_dir = Path(state_dir)
    targets = {}
    for aid in configured_agent_ids(cfg):
        pth = state_dir / "agents" / aid / "agent" / "openclaw-agent.sqlite"
        if pth.is_file():
            targets.setdefault(os.path.realpath(pth), (aid, pth))
    state_db = state_dir / "state" / "openclaw.sqlite"
    if state_db.exists() and "agent_databases" in state_tables:
        for aid, rp in q(state_db, "SELECT agent_id, path FROM agent_databases"):
            if not isinstance(rp, str) or not rp:
                continue
            pth = Path(rp)
            if not pth.is_absolute():
                pth = state_dir / pth
            if pth.is_file():
                targets.setdefault(os.path.realpath(pth), (str(aid), pth))
    orphans = []
    for pth in sorted(state_dir.glob("agents/*/agent/openclaw-agent.sqlite")):
        if os.path.realpath(pth) not in targets:
            orphans.append((pth.parent.parent.name, pth))
    return sorted(targets.values(), key=lambda t: str(t[1])), orphans


def legacy_files(state_dir, cfg, state_tables):
    """§6.2 files verdict sources (+ B5: attestations under the legacy .clawdbot state dir)."""
    import hashlib as _h
    state_dir = Path(state_dir)
    p = C.paths()
    found = []
    state_db = state_dir / "state" / "openclaw.sqlite"
    has_row = False
    if state_db.exists() and "device_identities" in state_tables:
        has_row = bool(q(state_db, "SELECT 1 FROM device_identities WHERE identity_key='primary'"))
    if not has_row:
        dev = state_dir / "identity" / "device.json"
        for c in (dev, Path(f"{dev}.doctor-importing"), Path(f"{dev}.native-importing")):
            if os.path.lexists(c):
                found.append(str(c))
    att_dirs = [state_dir / "workspace-attestations", p["CONFIG_ROOT"] / ".clawdbot" / "workspace-attestations"]
    for ws in workspaces(cfg):
        # <ws>/.openclaw/workspace-state.json (last written by 2026.6.8) is ignored by 2026.10 doctor
        # (docs/cli/doctor/state-migrations.md:318-323), so it no longer counts as unmigrated state.
        for f in (ws / "openclaw-workspace-state.json",):
            for c in (f, Path(f"{f}.doctor-importing")):
                if os.path.lexists(c):
                    found.append(str(c))
        for c in (Path(f"{ws}.attested"), Path(f"{ws}.attested.doctor-importing")):
            try:
                st = os.lstat(c)
            except FileNotFoundError:
                continue
            except OSError:
                found.append(str(c))
                continue
            if stat.S_ISREG(st.st_mode):
                try:
                    with open(c, "rb") as fh:
                        if fh.read(len(ATTESTATION_HEADER)) == ATTESTATION_HEADER:
                            found.append(str(c))
                except OSError:
                    found.append(str(c))
        for wp in {str(ws), os.path.realpath(ws)}:
            key = _h.sha256(wp.encode()).hexdigest()
            for ad in att_dirs:
                base = ad / f"{key}.attested"
                for c in (base, Path(f"{base}.doctor-importing")):
                    if os.path.lexists(c) and str(c) not in found:
                        found.append(str(c))
    return found


def classify(state_dir, cfg, s_target, a_target, runtime):
    """Predicate (§6.2). Returns a JSON-able dict; verdict newer|gate|ok."""
    state_dir = Path(state_dir)
    cfg = cfg if isinstance(cfg, dict) else {}
    res = {"verdict": "ok", "schema_verdict": "ok", "files_verdict": "ok", "newer": [], "gate": [], "files": [],
           "state": None, "state_uv": None, "agents": {}, "agent_paths": {}, "orphans": [],
           "targets": {"state": s_target, "agent": a_target}}
    state_db = state_dir / "state" / "openclaw.sqlite"
    tables = set()
    if state_db.exists():
        uv = db_uv(state_db)
        uv = 0 if uv is None else uv
        tables = table_names(state_db)
        eff = uv
        if "config_machine_state" in tables:
            rows = q(state_db, "SELECT value_json FROM config_machine_state WHERE state_key=?", (CONTENT_VERSION_KEY,))
            if rows:
                v = json.loads(rows[0][0]) if isinstance(rows[0][0], str) else rows[0][0]
                if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                    raise ValueError("invalid state.schema.contentVersion in config_machine_state")
                eff = max(uv, v)
        res["state"] = {"path": C.rel(state_db, state_dir), "uv": uv, "eff": eff}
        res["state_uv"] = uv
        if eff > s_target:
            res["newer"].append(f"state schema {eff} > {s_target}")
        elif eff < s_target:
            res["gate"].append(f"state schema {eff} < {s_target}")
        if eff >= s_target and "cron_run_logs" in tables:
            res["gate"].append("legacy cron_run_logs table present")
    targets, orphans = agent_databases(state_dir, cfg, tables)
    for aid, pth in targets:
        v = agent_db_version(pth)
        if v is None:
            continue
        key = aid if aid not in res["agents"] else C.rel(pth, state_dir)
        res["agents"][key] = v
        res["agent_paths"][key] = C.rel(pth, state_dir)
        if v > a_target:
            res["newer"].append(f"{C.rel(pth, state_dir)}: agent schema {v} > {a_target}")
        elif v < a_target:
            res["gate"].append(f"{C.rel(pth, state_dir)}: agent schema {v} < {a_target}")
    for aid, pth in orphans:
        try:
            v = agent_db_version(pth)
        except (sqlite3.Error, C.SchemaUnknown, C.NodeQueryError, OSError) as exc:
            res["orphans"].append({"id": aid, "path": C.rel(pth, state_dir), "uv": None, "error": str(exc)})
            continue
        if v is None or v == a_target:
            continue
        if v > a_target:
            res["newer"].append(f"{C.rel(pth, state_dir)} (unconfigured agent): agent schema {v} > {a_target}")
        res["orphans"].append({"id": aid, "path": C.rel(pth, state_dir), "uv": v})
    lt = _cfg_get(cfg, "meta", "lastTouchedVersion")
    if C.version_tuple(lt) and C.version_tuple(runtime) and C.version_tuple(lt) > C.version_tuple(runtime):
        res["newer"].append(f"openclaw.json was last written by OpenClaw {lt}, but this image ships {runtime}")
    res["files"] = legacy_files(state_dir, cfg, tables)
    if res["files"]:
        res["files_verdict"] = "gate"
    if res["newer"]:
        res["schema_verdict"] = "newer"
        res["verdict"] = "newer"
    elif res["gate"]:
        res["schema_verdict"] = "gate"
        res["verdict"] = "gate"
    elif res["files"]:
        res["verdict"] = "gate"
    return res


def infer_mode(cls, cfg):
    """from-7x when the state DB or any target agent DB is at schema 1, or openclaw.json was last
    written by OpenClaw < 2026.8 (whatever the state DB says); else bump."""
    if cls.get("state_uv") == 1 or any(v == 1 for v in (cls.get("agents") or {}).values()):
        return "from-7x"
    lt = C.version_tuple(_cfg_get(cfg, "meta", "lastTouchedVersion"))
    if lt and lt < (2026, 8, 0, 0):
        return "from-7x"
    return "bump"


def current_binding(state_dir, cls):
    state_dir = Path(state_dir)
    b = {"state_db": None, "agents": []}
    sdb = state_dir / "state" / "openclaw.sqlite"
    try:
        st = os.stat(sdb)
        app = None
        try:
            prim = schema_meta_primary(sdb)
            app = prim.get("app_version") if prim else None
        except (sqlite3.Error, C.NodeQueryError):
            app = None
        b["state_db"] = {"path": "state/openclaw.sqlite", "dev": st.st_dev, "ino": st.st_ino,
                         "user_version": (cls.get("state") or {}).get("uv"), "app_version": app}
    except OSError:
        pass
    for aid, relp in sorted(cls.get("agent_paths", {}).items()):
        try:
            st = os.stat(state_dir / relp)
        except OSError:
            continue
        b["agents"].append({"path": relp, "dev": st.st_dev, "ino": st.st_ino,
                            "user_version": cls.get("agents", {}).get(aid)})
    return b


def binding_equal(a, b):
    if not isinstance(a, dict) or not isinstance(b, dict):
        return False

    def ident(x):
        sdb = x.get("state_db") or {}
        ags = tuple(sorted((g.get("path"), g.get("dev"), g.get("ino")) for g in x.get("agents") or []
                           if isinstance(g, dict)))
        return (sdb.get("dev"), sdb.get("ino"), ags)
    return ident(a) == ident(b)


# --- plan decision table (§6.3 + B1/B2/B4/B11) ------------------------------------------------

def decide(ctx):
    """Pure decision table. ctx: fresh, runtime, cls, journal, marker, retry, cfg, binding.

    Returns {"rc","action","reason","mode","resume_phase","new_run","hold","marker","warnings","bk"}.
    bk (bookkeeping the gate run applies; `--plan` never writes the journal):
      consume_retry, auto_resumes, accept, journal_status, redo_doctor.
    """
    warnings = []
    bk = {"consume_retry": False, "auto_resumes": None, "accept": [], "journal_status": None, "redo_doctor": False}

    def R(rc, action, reason, **kw):
        d = {"rc": rc, "action": action, "reason": reason, "mode": None, "resume_phase": None, "new_run": False,
             "hold": None, "marker": None, "warnings": warnings, "bk": bk}
        d.update(kw)
        return d

    j = ctx.get("journal") or {}
    marker, retry, cfg = ctx.get("marker"), ctx.get("retry"), ctx.get("cfg") or {}
    has_retry = isinstance(retry, dict)
    status = j.get("status")
    if ctx.get("fresh"):
        if status in ("hold", "running", "interrupted") or has_retry:
            bk["journal_status"] = "abandoned" if status in ("hold", "running", "interrupted") else None
            bk["consume_retry"] = has_retry
            return R(0, "none", "fresh install (no OpenClaw state); closing the stale gate journal / retry request")
        return R(0, "none", "fresh install (no OpenClaw state)")
    cls, runtime = ctx["cls"], ctx["runtime"]
    if cls["verdict"] == "newer":
        return R(3, "newer", "state is newer than the bundled runtime: " + "; ".join(cls["newer"]))
    run_id = j.get("run_id")
    marker_rt = isinstance(marker, dict) and marker.get("runtime") == runtime
    gate_needed = cls["schema_verdict"] == "gate" or (cls["files_verdict"] == "gate" and not marker_rt)
    mode_new = infer_mode(cls, cfg)

    def consume(accept=True):
        bk["consume_retry"] = True
        bk["auto_resumes"] = 0
        if accept:
            bk["accept"] = [str(c) for c in (retry.get("accept") or [])]

    if status == "hold" and (j.get("hold") or {}).get("code") in NO_RETRY:
        # The state is no longer newer (checked above): the matching backup was restored.
        bk["journal_status"] = "done"
        warnings.append(f"previous HOLD {(j.get('hold') or {}).get('code')} no longer applies; closing it")
        status = "done"
    if status == "hold":
        hold = j.get("hold") or {}
        code = hold.get("code") or "unknown"
        if not has_retry:
            return R(11, "hold", f"HOLD {code} (sticky until oc-upgrade retry)",
                     hold={"code": code, "phase": hold.get("phase") or j.get("phase"), "from_journal": True})
        consume()
        if code in POST_RUN_HOLDS:
            if gate_needed or retry.get("doctor"):
                # a 2026.7.x state (rollback) needs the full from-7x run, never a maintenance doctor
                m = "from-7x" if mode_new == "from-7x" else "maintenance"
                return R(10, "run", f"retry after {code}: {m} gate (archive per gate_archive, doctor)", mode=m, new_run=True)
            bk["journal_status"] = "done"
            status = "done"
        elif j.get("first_write_at") is None and j.get("mode") != "maintenance":
            if gate_needed:
                return R(10, "resume", f"retry of run {run_id}: nothing written yet, re-running from precheck",
                         mode=mode_new, resume_phase="precheck")
            bk["journal_status"] = "done"
            warnings.append(f"run {run_id} wrote nothing and the predicate no longer needs a gate; closing it")
            status = "done"
        elif j.get("first_write_at") is None:
            return R(10, "resume", f"retry of run {run_id} from precheck", mode="maintenance", resume_phase="precheck")
        else:
            bk["redo_doctor"] = bool(retry.get("doctor")) and bool(j.get("doctor_started"))
            phase = hold.get("phase") or j.get("phase") or "precheck"
            return R(10, "resume", f"retry of run {run_id} at {phase}", mode=j.get("mode"), resume_phase=phase)
    elif status in ("running", "interrupted"):
        phase = j.get("phase") or "precheck"
        if has_retry:
            consume()
            return R(10, "resume", f"retry of interrupted run {run_id} at {phase}", mode=j.get("mode"),
                     resume_phase=phase)
        if int(j.get("auto_resumes") or 0) == 0:
            bk["auto_resumes"] = 1
            return R(10, "resume", f"resuming interrupted run {run_id} at {phase} (1/1)", mode=j.get("mode"),
                     resume_phase=phase)
        return R(11, "hold", f"run {run_id} was interrupted twice",
                 hold={"code": "interrupted-twice", "phase": phase,
                       "message": f"the migration gate (run {run_id}) was interrupted twice (last phase {phase})"})

    if gate_needed:
        if (mode_new != "from-7x" and marker_rt and binding_equal(marker.get("binding"), ctx.get("binding"))
                and not has_retry):
            why = "; ".join((cls["gate"] + [f"legacy file {f}" for f in cls["files"]])[:5])
            return R(11, "hold", "bump-repeat",
                     hold={"code": "bump-repeat", "phase": "plan",
                           "message": f"a {marker.get('mode')} gate for {runtime} already completed on this state, "
                                      f"but the predicate still says gate ({why})"})
        if has_retry and not bk["consume_retry"]:
            consume()
        return R(10, "run", "migration needed: " + "; ".join((cls["gate"] + cls["files"])[:4]), mode=mode_new,
                 new_run=True)
    if has_retry and retry.get("doctor") and status in ("done", "abandoned", None) and not bk["consume_retry"]:
        consume()
        return R(10, "run", "maintenance doctor run requested (oc-upgrade retry --doctor)", mode="maintenance",
                 new_run=True)
    if has_retry and not bk["consume_retry"]:
        bk["consume_retry"] = True
        warnings.append("discarding a pending retry request: there is nothing to retry")
    if marker_rt:
        mk = None
        if not binding_equal(marker.get("binding"), ctx.get("binding")):
            warnings.append("state identity changed since migration (restore?); predicate ok — marker rebound")
            mk = "rebind"
        if cls["files_verdict"] == "gate":
            warnings.append("legacy files still present after migration (ignored): " + ", ".join(cls["files"][:5]))
        return R(0, "none", f"migrated ({marker.get('mode')}, run {marker.get('run_id')})", marker=mk)
    if isinstance(marker, dict):
        return R(10, "run", f"marker is for {marker.get('runtime')}; version bump to {runtime}", mode=mode_new,
                 new_run=True)
    lt = _cfg_get(cfg, "meta", "lastTouchedVersion")
    if not lt and _has_legacy_codex_refs(cfg):
        # Every config OpenClaw wrote carries meta.lastTouchedVersion; an unversioned one with legacy
        # routes was written by hand. Do not record it as migrated (no marker), so it is re-checked on
        # every start, and say why the gate cannot help (no 2026.7 state to migrate).
        warnings.append("openclaw.json has no meta.lastTouchedVersion but still uses openai-codex/codex model "
                        "refs; 2026.9 does not run them. Change them to openai/<model> (or restore a 2026.7 "
                        "state and let the gate migrate it). Not recorded as migrated.")
        return R(0, "none", "unversioned config with legacy Codex refs; not adopted")
    if not lt or C.version_tuple(lt) == C.version_tuple(runtime):
        return R(0, "none", "no marker; state matches the runtime -> adopted", marker="adopt")
    return R(10, "run", f"openclaw.json last written by {lt}; version bump to {runtime}", mode=mode_new, new_run=True)


_LEGACY_CODEX_REF = re.compile(r'"\s*(?:openai-codex|codex|codex-cli)\s*/', re.I)


def _has_legacy_codex_refs(cfg):
    """Cheap scan (plan must not import oc_migrate): any legacy Codex model ref or key in the config."""
    try:
        return bool(_LEGACY_CODEX_REF.search(json.dumps(cfg or {})))
    except (TypeError, ValueError):
        return False


def _read_cfg_lenient():
    try:
        return C.read_json_strict(C.paths()["CONFIG_PATH"])
    except C.ConfigReadError:
        return {}


def _summary_bits(pkg, cls):
    st = cls.get("state") or {}
    ags = ",".join(f"{k}:{v}" for k, v in sorted(cls.get("agents", {}).items())) or "none"
    return (f"runtime={pkg['version']} targets={pkg['schema_state']}/{pkg['schema_agent']} "
            f"state={st.get('eff', 'none')} agents={ags} verdict={cls['verdict']}")


def plan(apply=False, emit=out):
    """`gate --plan` (apply=False) and the gate's own planning (apply=True). Returns the decision dict."""
    gp = gpaths()
    if not has_upgrade_sensitive_state():
        try:
            journal = load_journal()
        except (OSError, ValueError):
            journal = None
        d = decide({"fresh": True, "journal": journal, "retry": load_retry()})
        d["journal"] = journal
        if (d["bk"].get("consume_retry") or d["bk"].get("journal_status")) and not apply:
            d["rc"], d["action"] = 10, "housekeeping"
            emit(f"[gate] plan: {d['reason']} -> gate housekeeping")
        else:
            emit(f"[gate] plan: {d['reason']} -> no gate")
        if apply:
            apply_bookkeeping(d)
        return d
    marker = load_marker()
    pkg = None
    try:
        pkg = C.runtime_package()
        cfg = _read_cfg_lenient()
        journal = load_journal()
        retry = load_retry()
        cls = classify(gp["STATE"], cfg, pkg["schema_state"], pkg["schema_agent"], pkg["version"])
        binding = current_binding(gp["STATE"], cls)
        d = decide({"fresh": False, "runtime": pkg["version"], "cls": cls, "journal": journal, "marker": marker,
                    "retry": retry, "cfg": cfg, "binding": binding})
    except C.Stopped:
        raise
    except Exception as exc:  # B11: a planning bug must not brick a migrated install
        # ... but must not bypass a gate run that is still open (sticky HOLD, interrupted run)
        try:
            jst = load_journal()
            settled = jst is None or jst.get("status") in ("done", "abandoned")
        except (OSError, ValueError):
            settled = False
        if marker and pkg and marker.get("runtime") == pkg["version"] and settled:
            emit(f"WARN [gate] planning failed ({type(exc).__name__}: {exc}); a migration marker for "
                 f"{pkg['version']} exists -> starting OpenClaw (exit 78 would still HOLD)")
            emit(f"[gate] plan: runtime={pkg['version']} planning error ignored (marker {marker.get('mode')}) -> no gate")
            return {"rc": 0, "action": "none", "reason": "plan-error-with-marker", "warnings": [], "bk": {},
                    "mode": None}
        emit(f"[gate] plan: error: {type(exc).__name__}: {exc}")
        return {"rc": 1, "action": "error", "reason": str(exc), "warnings": [], "bk": {}, "mode": None,
                "error": exc}
    d["pkg"], d["cls"], d["cfg"], d["journal"], d["retry"], d["binding"] = pkg, cls, cfg, journal, retry, binding
    for w in d["warnings"]:
        emit(f"WARN [gate] {w}")
    if NODE_FALLBACKS:
        emit(f"WARN [gate] Python's SQLite could not read {len(set(NODE_FALLBACKS))} database(s); used the node:sqlite fallback")
    try:
        if d.get("marker") == "adopt":
            write_marker(mode="adopted", run_id=None, binding=binding, runtime=pkg["version"], archive=None,
                         accepted=[], orphans=cls.get("orphans", []))
        elif d.get("marker") == "rebind":
            m = dict(marker)
            m["binding"] = binding
            m["rebound_at"] = C.utc_iso()
            C.atomic_write_json(gp["MARKER"], m)
    except OSError as exc:
        emit(f"WARN [gate] could not write the migration marker: {exc}")
    pending = d["bk"].get("consume_retry") or d["bk"].get("journal_status")
    if d["rc"] == 0 and pending and not apply:
        d["rc"], d["action"] = 10, "housekeeping"
        d["reason"] += "; retry bookkeeping pending"
    bits = _summary_bits(pkg, cls)
    if d["rc"] == 11:
        write_sticky_hold_txt(d, pkg)
        emit(f"[gate] plan: {bits} -> HOLD {d['hold']['code']} ({d['reason']})")
    elif d["rc"] == 3:
        emit(f"[gate] plan: {bits} -> newer state, HOLD ({d['reason']})")
    elif d["rc"] == 10:
        run = (journal or {}).get("run_id") if d["action"] == "resume" else "new"
        emit(f"[gate] plan: {bits} -> gate {d['action']} mode={d.get('mode') or '-'} run={run} ({d['reason']})")
    else:
        emit(f"[gate] plan: {bits} -> no gate ({d['reason']})")
    if apply:
        apply_bookkeeping(d)
    return d


def apply_bookkeeping(d):
    gp = gpaths()
    bk = d.get("bk") or {}
    j = d.get("journal")
    if bk.get("consume_retry") and gp["RETRY"].exists():
        ensure_dirs(gp)
        os.replace(gp["RETRY"], gp["GATE"] / f"retry-request.consumed-{C.utc_now().strftime('%Y%m%dT%H%M%SZ')}.json")
    if j is not None:
        changed = False
        if bk.get("auto_resumes") is not None:
            j["auto_resumes"] = bk["auto_resumes"]
            changed = True
        if bk.get("journal_status"):
            j["status"] = bk["journal_status"]
            j.setdefault("history", []).append({"at": C.utc_iso(),
                                                "event": f"journal {bk['journal_status']}: {d['reason']}"})
            j["hold"] = None
            changed = True
        if changed:
            ensure_dirs(gp)
            C.atomic_write_json(gp["JOURNAL"], j)


def write_marker(*, mode, run_id, binding, runtime, archive, accepted, orphans, archive_mode=None):
    gp = gpaths()
    ensure_dirs(gp)
    C.atomic_write_json(gp["MARKER"], {
        "schema": 1, "runtime": runtime, "mode": mode, "run_id": run_id, "completed_at": C.utc_iso(),
        "binding": binding, "archive": archive, "archive_mode": archive_mode, "accepted": sorted(set(accepted or [])),
        "orphans": orphans or [], "addon_version": addon_version()})


# --- hold.txt ---------------------------------------------------------------------------------

def advice_for(codes, findings=None):
    codes = list(codes)
    acc = [c for c in codes if c in ACCEPTABLE or any(f.get("code") == c and f.get("cls") == "acceptable"
                                                      for f in findings or [])]
    hard = [c for c in codes if c not in acc]
    if hard:
        return ADVICE.get(hard[0], "fix the cause, then oc-upgrade retry") + " (then restart the add-on)"
    first = ADVICE.get(acc[0]) if len(acc) == 1 and acc[0] in ADVICE else None
    base = first or "fix the causes, then oc-upgrade retry"
    return f"{base}, or accept: oc-upgrade retry --accept {','.join(acc)} (then restart the add-on)"


def hold_text(runtime, run_id, phase, findings, state_line, next_line):
    lines = [f"OpenClaw is held (bundled runtime {runtime}) — migration gate run {run_id or 'n/a'}, phase {phase}"]
    for f in findings:
        lines.append(f"Reason [{f['code']}]: {f['message']}")
    lines.append(f"State: {state_line}")
    lines.append(f"Next: {next_line}")
    acc = [f["code"] for f in findings if f.get("cls") == "acceptable"]
    if acc:
        lines.append(f"Accept (only if you understand the consequence): oc-upgrade retry --accept {','.join(dict.fromkeys(acc))}")
    lines.append("Details: oc-upgrade status | oc-upgrade log")
    return "\n".join(lines) + "\n"


def state_line_for(j, post_run=False):
    if post_run:
        return "migrated (gateway refused to start)"
    if not j or not j.get("first_write_at"):
        return "unchanged (nothing written yet)"
    if j.get("doctor_started"):
        return "partially migrated (doctor started)"
    return "partially changed (files quarantined / config pre-transformed; doctor not started)"


def write_sticky_hold_txt(d, pkg):
    gp = gpaths()
    j = d.get("journal") or {}
    h = d.get("hold") or {}
    if h.get("from_journal"):
        jh = j.get("hold") or {}
        findings = jh.get("findings") or [finding(jh.get("code", "unknown"),
                                                  "acceptable" if jh.get("acceptable") else "hard",
                                                  jh.get("message", ""))]
        text = hold_text(pkg["version"], j.get("run_id"), jh.get("phase") or j.get("phase"), findings,
                         jh.get("state_line") or state_line_for(j, jh.get("code") in POST_RUN_HOLDS),
                         jh.get("next") or advice_for([f["code"] for f in findings], findings))
    else:
        findings = [finding(h["code"], "hard", h.get("message", ""))]
        text = hold_text(pkg["version"], j.get("run_id"), h.get("phase"), findings, state_line_for(j),
                         advice_for([h["code"]]))
    try:
        gp["UPG_DIR"].mkdir(parents=True, exist_ok=True)
        C.atomic_write_text(gp["HOLD"], text)
    except OSError as exc:
        out(f"WARN [gate] could not write hold.txt: {exc}")


# --- space (B6) -------------------------------------------------------------------------------

def sqlite_tmpdir():
    for cand in (os.environ.get("SQLITE_TMPDIR"), os.environ.get("TMPDIR"), "/var/tmp", "/tmp"):
        if cand and os.path.isdir(cand):
            return cand
    return "/tmp"


def existing_parent(path):
    p = Path(path)
    while not p.exists() and p != p.parent:
        p = p.parent
    return p


def read_mountinfo(path="/proc/self/mountinfo"):
    mounts = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.split()
                if " - " not in line or len(parts) < 7:
                    continue
                left, right = line.split(" - ", 1)
                lf, rf = left.split(), right.split()
                mp = lf[4].encode().decode("unicode_escape") if "\\" in lf[4] else lf[4]
                mounts.append({"mm": lf[2], "mountpoint": mp, "fstype": rf[0] if rf else ""})
    except OSError:
        pass
    return mounts


def fs_identity(path, mounts=None):
    p = existing_parent(path)
    try:
        dev = os.stat(p).st_dev
    except OSError:
        return None
    real = os.path.realpath(p)
    best = None
    for m in mounts if mounts is not None else read_mountinfo():
        mp = m["mountpoint"]
        if real == mp or real.startswith(mp.rstrip("/") + "/") or mp == "/":
            if best is None or len(mp) > len(best["mountpoint"]):
                best = m
    return {"dev": dev, "mm": best["mm"] if best else None, "fstype": best["fstype"] if best else None}


def proven_distinct(a, b):
    """True only when two paths are certainly on different filesystems (B6)."""
    if not a or not b or a["dev"] == b["dev"]:
        return False
    if not a.get("mm") or not b.get("mm"):
        return False
    ram = ("tmpfs", "ramfs")
    if a.get("fstype") in ram or b.get("fstype") in ram:
        return a["mm"] != b["mm"]
    if a["mm"].startswith("0:") or b["mm"].startswith("0:"):  # overlay, btrfs subvolume, network fs: unknown backing
        return False
    return a["mm"] != b["mm"]


def space_check(needs, disk_usage=shutil.disk_usage, fsinfo=fs_identity):
    """needs: [(label, path, need_bytes, code)]. Groups not proven distinct must fit SUM(need) <= MIN(free)."""
    items = []
    for label, path, need, code in needs:
        p = existing_parent(path)
        try:
            free = disk_usage(str(p)).free
        except OSError:
            free = None
        items.append({"label": label, "path": str(path), "need": int(need), "code": code, "free": free,
                      "fs": fsinfo(str(path))})
    n = len(items)
    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    for i in range(n):
        for k in range(i + 1, n):
            if not proven_distinct(items[i]["fs"], items[k]["fs"]):
                parent[find(i)] = find(k)
    groups = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(items[i])
    findings, parts = [], []
    for members in groups.values():
        need = sum(m["need"] for m in members)
        frees = [m["free"] for m in members if m["free"] is not None]
        have = min(frees) if frees else None
        label = "+".join(m["label"] for m in members)
        parts.append(f"{label} need {C.human(need)} have {C.human(have)}")
        if have is None or need > have:
            code = max(members, key=lambda m: m["need"])["code"]
            findings.append(finding(code, "hard", f"not enough free space on {label}: need {C.human(need)}, "
                                                  f"have {C.human(have)}", "precheck"))
    return findings, "; ".join(parts)


# --- process scan ----------------------------------------------------------------------------


def _parse_backup_date(v):
    if not isinstance(v, str) or not v:
        return None
    try:
        dt = datetime.fromisoformat(v.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def backup_protected(b):
    """A Supervisor backup counts as encrypted only if every stored copy is protected. location_attributes
    (per location) wins; an empty or malformed one is unverifiable; without it the top-level flag decides."""
    la = b.get("location_attributes")
    if la is None:
        return b.get("protected") is True
    if not isinstance(la, dict) or not la:
        return False
    return all(isinstance(v, dict) and v.get("protected") is True for v in la.values())


def backup_locations(b):
    la = b.get("location_attributes")
    if isinstance(la, dict) and la:
        return ",".join(str(k or ".local") for k in la)
    locs = b.get("locations") or [b.get("location")]
    return ",".join(str(x or ".local") for x in locs if x is not None or len(locs) == 1) or ".local"


def evaluate_ha_backups(backups, self_slug, now, max_age_s, skew_s=BACKUP_SKEW_S):
    """Pure: the newest encrypted full/partial Home Assistant backup that contains this add-on and is at most
    max_age_s old (a few minutes in the future are tolerated). Unencrypted ones are reported separately."""
    out = {"candidates": [], "total": 0, "with_slug": 0, "unprotected": [], "bad_dates": 0, "newest_with_slug": None}
    for b in backups if isinstance(backups, list) else []:
        if not isinstance(b, dict):
            continue
        out["total"] += 1
        content = b.get("content") if isinstance(b.get("content"), dict) else {}
        slugs = content.get("addons") or content.get("apps") or []
        if not isinstance(slugs, list) or self_slug not in [x for x in slugs if isinstance(x, str)]:
            continue
        out["with_slug"] += 1
        dt = _parse_backup_date(b.get("date"))
        if dt is None:
            out["bad_dates"] += 1
            continue
        prot = backup_protected(b)
        entry = {"slug": b.get("slug"), "name": C.redact_text(str(b.get("name") or ""))[:80], "date": C.utc_iso(dt),
                 "dt": dt, "type": b.get("type"), "protected": prot, "locations": backup_locations(b)}
        if out["newest_with_slug"] is None or dt > out["newest_with_slug"]["dt"]:
            out["newest_with_slug"] = entry
        if not prot:
            out["unprotected"].append(entry)
            continue
        if b.get("type") not in ("full", "partial"):
            continue
        age = (now - dt).total_seconds()
        if -skew_s <= age <= max_age_s:
            out["candidates"].append(entry)
    out["candidates"].sort(key=lambda e: e["dt"], reverse=True)
    return out


def backup_addon_version(info, self_slug):
    """The add-on version recorded in a backup (GET /backups/<slug>/info: addons|apps [{slug, version}])."""
    for key in ("addons", "apps"):
        for a in info.get(key) or []:
            if isinstance(a, dict) and a.get("slug") == self_slug:
                return a.get("version")
    return None

def find_openclaw_processes(entry, proc_dir="/proc", self_pid=None):
    self_pid = os.getpid() if self_pid is None else self_pid
    exclude = {self_pid}
    try:
        exclude.add(os.getppid())
    except OSError:
        pass
    procs = {}
    try:
        names = os.listdir(proc_dir)
    except OSError:
        return []
    for name in names:
        if not name.isdigit():
            continue
        pid = int(name)
        try:
            with open(os.path.join(proc_dir, name, "cmdline"), "rb") as f:
                raw = f.read()
            with open(os.path.join(proc_dir, name, "stat"), encoding="utf-8", errors="replace") as f:
                st = f.read()
            ppid = int(st.rsplit(")", 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        procs[pid] = (raw, ppid)
    for pid, (_raw, ppid) in procs.items():
        if ppid == self_pid:
            exclude.add(pid)
    found = []
    for pid, (raw, _ppid) in sorted(procs.items()):
        if pid in exclude:
            continue
        args = [a.decode("utf-8", "replace") for a in raw.split(b"\0") if a]
        if not args:
            continue
        first = args[0].strip()
        hit = (entry and entry in args) or any(a.endswith("/openclaw.mjs") for a in args) \
            or first.split(" ")[0] == "openclaw-gateway" or os.path.basename(first.split(" ")[0]) == "openclaw"
        if hit:
            # argv[0..2] only, redacted: the rest may carry secrets (--token ...) into hold.txt and the journal
            found.append({"pid": pid, "cmd": C.redact_text(" ".join(args[:3]))[:120]})
    return found


# --- doctor output ----------------------------------------------------------------------------

def normalize_doctor_text(text):
    text = ANSI_RE.sub("", text or "")
    text = BOX_RE.sub(" ", text)
    return " ".join(text.split())


def _snippet(norm, idx, width=160):
    s = norm[max(0, idx - 40): idx + width]
    return C.redact_text(s)


def evaluate_doctor(rc, text, *, timed_out=False, stopping=False, final=False):
    """Classify one doctor pass (B3: markers only when rc != 0, except held-back stores, which 2026.10
    reports with rc 0; B8: signals/OOM -> doctor-crashed). final: the pass that should leave nothing
    pending (pass 2 or 3)."""
    norm = normalize_doctor_text(text)
    low = norm.lower()
    complete = "Doctor complete." in norm
    res = {"rc": rc, "complete": complete, "markers": [], "code": None, "cls": None, "message": ""}
    if stopping:
        res.update(code="interrupted", cls="stop", message="stop requested")
        return res
    if timed_out:
        res.update(code="doctor-timeout", cls="hard", message="doctor exceeded its time budget and was stopped")
        return res
    if rc == 0:
        if not complete:
            res.update(code="doctor-incomplete", cls="hard", message="doctor exited 0 without 'Doctor complete.'")
            return res
        sus = [m for m in SUSPICIOUS_MARKERS + (FINAL_PASS_SUSPICIOUS if final else ()) if m.lower() in low]
        warn = None
        if sus:
            idx = low.find(sus[0].lower())
            warn = {"code": "doctor-warnings", "cls": "acceptable", "markers": sus,
                    "message": f"doctor completed with warnings ({', '.join(sus)}): ...{_snippet(norm, idx)}..."}
        held = [(low.find(s.lower()), s) for s in HELD_BACK_MARKERS if s.lower() in low]
        m = _HELD_AGENT_RE.search(norm)
        if m:
            held.append((m.start(), "Held agent"))
        if held:
            idx, s = min(held)
            res.update(code="doctor-held-back", cls="acceptable", markers=[s],
                       message=f"doctor completed but held back agent databases (they stay unmigrated): "
                               f"...{_snippet(norm, idx)}...")
            if warn:  # accepting the held stores must not accept the warnings too
                res["also"] = [warn]
            return res
        if warn:
            res.update(warn)
        return res
    if rc < 0 or rc in (134, 137):
        sig = -rc if rc < 0 else rc - 128
        res.update(code="doctor-crashed", cls="hard",
                   message=f"doctor was killed by signal {sig} (rc {rc}); out of memory? see oc-upgrade log")
        return res
    if rc in (130, 143):
        res.update(code="doctor-interrupted", cls="hard", message=f"doctor was interrupted (rc {rc})")
        return res
    if rc == 2:
        res.update(code="doctor-invocation", cls="hard", message="doctor refused its command line (rc 2)")
        return res
    for code, subs, rx in FATAL_MARKERS:
        for s in subs:
            idx = low.find(s.lower())
            if idx >= 0:
                res.update(code=code, cls="hard", markers=[s],
                           message=f"doctor rc {rc}: ...{_snippet(norm, idx)}...")
                return res
        if rx is not None:
            m = rx.search(norm)
            if m:
                res.update(code=code, cls="hard", markers=[m.group(0)[:60]],
                           message=f"doctor rc {rc}: ...{_snippet(norm, m.start())}...")
                return res
    last = norm[-160:]
    res.update(code="doctor-failed", cls="hard", message=f"doctor rc {rc}: ...{C.redact_text(last)}")
    return res


# Doctor messages about behaviour changes the user should know about (contract addendum 1 item 7).
# Matched on the normalized log (box drawing removed, whitespace collapsed); informational only.
_NOTE_RES = (
    ("info", re.compile(r'(agents\.(?:entries|list)\S*?\.model) is .{1,200}? At runtime this clobbers '
                        r'agents\.defaults\.model\.fallbacks'),
     lambda m: f"{m.group(1)} has no explicit \"fallbacks\" (no fallbacks for that agent; 2026.7.35 behaved the "
               "same, 2026.9+ only reports it)"),
    # "... but no API key was found." or "... but the API key was not found in the CLI environment."
    # (doctor-memory-search-CPASCeub.mjs:370/379; the agent prefix only appears with several agents)
    ("warn", re.compile(r'Agent "([^"]{1,80})": Memory search provider is set to "([^"]{1,40})" but '
                        r'(?:no API key|the API key was not found)'),
     lambda m: f"memory search of agent {m.group(1)} uses provider {m.group(2)} without an API key: semantic "
               "recall does not work until one is configured"),
    ("warn", re.compile(r'Agent "([^"]{1,80})": (\d+) allowed skills? (?:is|are) not usable in this environment'),
     lambda m: f"{m.group(2)} skill(s) of agent {m.group(1)} are not usable in this environment and were disabled "
               "(openclaw skills check)"),
    ("warn", re.compile(r'Create heartbeat monitor for agent "([^"]{1,80})" at (\S{1,20}?)\.(?:\s|$)'),
     lambda m: f"doctor created a heartbeat monitor cron job for agent {m.group(1)} (every {m.group(2)})"),
    ("warn", re.compile(r"Removed untouched (\S{1,200}TOOLS\.md) after archiving it"),
     lambda m: f"doctor archived and removed the untouched {m.group(1)}"),
    ("warn", re.compile(r"Migrated (\S{1,200}HEARTBEAT\.md) into cron scratch"),
     lambda m: f"doctor moved {m.group(1)} into the heartbeat cron job"),
    # retired-model-ref-repair-TouY-fr5.mjs:452/469/514/551: a retired model kept because no successor fits
    ("warn", re.compile(r'Retained (?:model reference )?"?([^"\s]{1,120}?)"? for agent "([^"]{1,80})": (.{1,160}?)\.'),
     lambda m: f"doctor kept the retired model {m.group(1)} for agent {m.group(2)} ({m.group(3)}); choose a current "
               "model for it"),
)


def doctor_notes(text):
    """[[level, message]] for doctor messages worth surfacing after a migration (deduplicated)."""
    norm = normalize_doctor_text(text)
    notes = []
    for level, rx, fmt in _NOTE_RES:
        for m in rx.finditer(norm):
            msg = C.redact_text(fmt(m))
            if [level, msg] not in notes:
                notes.append([level, msg])
    return notes[:40]


# Doctor's retired-model replacements (contract addendum 2 items 7-10), matched on the normalized log.
# Templates verified in the 9.9 dist: retired-model-ref-repair-BeQCC1zw.mjs:612 (Replaced retired /
# Preserved ... as ... after config repair), :676 (Preserved inherited), :694 (Moved retired / Preserved
# ... for other authentication routes and added), :712 (modelPolicy.allow), and
# legacy-config-migrations.runtime.models-j-YXRZQK.mjs:332, :399, :411-412, :552 (Upgraded / Merged);
# unchanged in 10.2: retired-model-ref-repair-TouY-fr5.mjs:637/701/719/737,
# legacy-config-migrations.runtime.models-zfo-BeDg.mjs:225/292/304-305/445.
# Values are JSON.stringify'd (quoted) except in the :676/:694 templates. "Replaced stale ... with default"
# (raw-path damage, exp1raw) deliberately does not match.
_RQ = r'"([^"\s]+)"'
_RETIRED_RES = (
    re.compile(r"Replaced retired \S+ " + _RQ + r" with " + _RQ),
    re.compile(r"Preserved \S+ model " + _RQ + r" as " + _RQ + r" after config repair"),
    re.compile(r"Preserved inherited (\S+) settings in \S+?\.models\.(\S+)"),
    re.compile(r"Moved retired \S+?\.models\.(\S+) to (\S+)"),
    re.compile(r"Preserved \S+?\.models\.(\S+) for other authentication routes and added (\S+)"),
    re.compile(r"Preserved \S+?\.modelPolicy\.allow\.\d+ " + _RQ + r" for other authentication routes and allowed "
               + _RQ),
    re.compile(r"Upgraded \S+ key from " + _RQ + r" to " + _RQ),
    re.compile(r"Merged \S+ key " + _RQ + r" into " + _RQ),
    re.compile(r"Upgraded \S+ from " + _RQ + r" to " + _RQ),
    re.compile(r"Upgraded \S+ provider/model from " + _RQ + r" to " + _RQ),
)
_RETIRED_REMOVED_RE = re.compile(r"Removed retired (\S+) " + _RQ + r" so it inherits")
_LEGACY_PROVIDERS = ("openai-codex", "codex", "codex-cli")


def _clean_ref(s):
    return s.strip().strip("\"'").rstrip(".,;:)")


def acceptable_doctor(ev):
    """The acceptable findings of one evaluated doctor pass: its own code plus any it carries along."""
    out = [ev] if ev.get("code") and ev.get("cls") == "acceptable" else []
    return out + list(ev.get("also") or [])


def doctor_retirements(text):
    """({old base ref: new base ref}, [[path, old ref]]) of doctor's retired-model replacements and
    removals in one doctor log (refs lower-cased without @profile; openai-codex canonicalisations are
    F2's remap, not retirements, and are skipped)."""
    norm = normalize_doctor_text(text)
    pairs, removed = {}, []
    for rx in _RETIRED_RES:
        for m in rx.finditer(norm):
            old, new = mig().ref_base(_clean_ref(m.group(1))), mig().ref_base(_clean_ref(m.group(2)))
            if not old or not new or "/" not in old or "/" not in new or old == new or "*" in old + new:
                continue
            if old.split("/", 1)[0] in _LEGACY_PROVIDERS:
                continue
            pairs[old] = new
    for m in _RETIRED_REMOVED_RE.finditer(norm):
        item = [_clean_ref(m.group(1)), mig().ref_base(_clean_ref(m.group(2)))]
        if item not in removed:
            removed.append(item)
    return pairs, removed[:40]


class LogMirror:
    """Mirror new lines of a growing log to stdout as `[doctor] <line>` (redacted, capped)."""

    def __init__(self, path, offset, cap, emit, label):
        self.path, self.offset, self.cap, self.emit, self.label = Path(path), offset, cap, emit, label
        self.lines, self.partial, self.last, self.capped = 0, b"", "", False

    def pump(self, final=False):
        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                data = f.read()
        except OSError:
            return
        self.offset += len(data)
        data = self.partial + data
        parts = data.split(b"\n")
        self.partial = b"" if final else parts.pop()
        for raw in parts:
            line = ANSI_RE.sub("", raw.decode("utf-8", "replace")).rstrip("\r")
            if not line.strip():
                continue
            self.lines += 1
            self.last = C.redact_text(line.strip())
            if self.lines <= self.cap:
                self.emit(f"[doctor] {C.redact_text(line)}")
            elif not self.capped:
                self.capped = True
                self.emit(f"[gate] (doctor output continues in {self.path})")


# --- archive verification ----------------------------------------------------------------------

class _HashingReader:
    def __init__(self, f, stop):
        self.f, self.h, self.n, self.stop = f, hashlib.sha256(), 0, stop

    def read(self, size=-1):
        if self.stop is not None and self.stop.is_set():
            raise GateStopped()
        b = self.f.read(size)
        self.h.update(b)
        self.n += len(b)
        return b


def verify_archive(path, expected, stop=None):
    """Stream the .tar.gz once: gzip CRC, member count, sha256 of expected members, archive sha256.

    expected: {member_name: sha256}. Returns dict(members, matched, mismatched, missing, sha256, size).
    """
    found, links, members = {}, {}, 0
    with open(path, "rb") as raw:
        hr = _HashingReader(raw, stop)
        gz = gzip.GzipFile(fileobj=hr, mode="rb")
        with tarfile.open(fileobj=gz, mode="r|") as tf:
            for m in tf:
                members += 1
                if stop is not None and stop.is_set():
                    raise GateStopped()
                name = m.name[2:] if m.name.startswith("./") else m.name
                if name in expected:
                    if m.isreg():
                        h = hashlib.sha256()
                        fobj = tf.extractfile(m)
                        while True:
                            if stop is not None and stop.is_set():
                                raise GateStopped()
                            b = fobj.read(C.MIB)
                            if not b:
                                break
                            h.update(b)
                        found[name] = h.hexdigest()
                    elif m.islnk():
                        links[name] = m.linkname[2:] if m.linkname.startswith("./") else m.linkname
        while gz.read(C.MIB):  # rest of the gzip stream: CRC + length check at EOF
            pass
        while hr.read(C.MIB):
            pass
    for name, target in links.items():
        if target in found:
            found[name] = found[target]
    matched = [n for n, h in expected.items() if found.get(n) == h]
    mismatched = [n for n, h in expected.items() if n in found and found[n] != h]
    missing = [n for n in expected if n not in found]
    return {"members": members, "matched": matched, "mismatched": mismatched, "missing": missing,
            "sha256": hr.h.hexdigest(), "size": hr.n}


def compare_members(expected, found, links, members):
    for name, target in links.items():
        if target in found:
            found[name] = found[target]
    return {"members": members, "matched": [n for n, h in expected.items() if found.get(n) == h],
            "mismatched": [n for n, h in expected.items() if n in found and found[n] != h],
            "missing": [n for n in expected if n not in found]}


def age_header(path):
    """Parse an age v1 header (text lines up to '--- <mac>'). Returns {len, stanzas: [type, ...]}."""
    with open(path, "rb") as f:
        head = f.read(4096)
    if not head.startswith(AGE_MAGIC):
        raise ValueError("not an age v1 file")
    pos, stanzas = len(AGE_MAGIC), []
    while True:
        nl = head.find(b"\n", pos)
        if nl < 0:
            raise ValueError("age header truncated")
        line = head[pos:nl]
        pos = nl + 1
        if line.startswith(b"--- "):
            return {"len": pos, "stanzas": stanzas}
        if not line.startswith(b"-> "):
            raise ValueError("unexpected age header line")
        stanzas.append(line[3:].split(b" ", 1)[0].decode("ascii", "replace"))
        while True:  # body: base64 lines of 64 characters, the last one shorter
            nl = head.find(b"\n", pos)
            if nl < 0:
                raise ValueError("age header truncated")
            body, pos = head[pos:nl], nl + 1
            if len(body) < 64:
                break


def age_cipher_size(header_len, plain_size):
    """age STREAM: 16-byte nonce, then 64 KiB chunks with a 16-byte tag each (at least one chunk)."""
    chunks = max(1, -(-plain_size // AGE_CHUNK))
    return header_len + 16 + plain_size + 16 * chunks


class _ArchiveTimeout(Exception):
    pass


class _CountingSink:
    """File-like sink for the gzip stream: hashes and counts the bytes and forwards them to age's stdin."""

    def __init__(self, out):
        self.out, self.h, self.n = out, hashlib.sha256(), 0

    def write(self, b):
        self.out.write(b)
        self.h.update(b)
        self.n += len(b)
        return len(b)

    def flush(self):
        self.out.flush()


class _TeeReader:
    """Reads tar's stdout for tarfile (stream mode) and copies every byte into the gzip writer, so the archive
    is exactly tar's output. Polls STOP, the deadline and the heartbeat while waiting for data."""

    def __init__(self, fd, gz, deadline, stop, on_tick, started):
        self.fd, self.gz, self.deadline, self.stop, self.on_tick, self.started = fd, gz, deadline, stop, on_tick, started

    def read(self, n=-1):
        n = C.MIB if n is None or n < 0 else n
        while True:
            if self.stop.is_set():
                raise GateStopped()
            now = time.monotonic()
            if now > self.deadline:
                raise _ArchiveTimeout()
            if self.on_tick:
                self.on_tick(now - self.started)
            r, _w, _x = select.select([self.fd], [], [], 1.0)
            if r:
                break
        b = os.read(self.fd, n)
        if b:
            self.gz.write(b)
        return b


def stream_encrypted_archive(tar_argv, age_argv, tmp, expected, *, cwd, timeout, tar_log, age_log, on_tick=None,
                             out_fd=None):
    """tar (uncompressed, to a pipe) -> this process (tarfile parse: sha256 of every expected member; gzip -1)
    -> age stdin; age stdout -> a pump thread -> tmp (or out_fd, which this function then owns and closes).
    No plaintext byte is written to disk. A watchdog stops tar and age on STOP or at the deadline, also when
    this thread is blocked writing to a stalled age. Returns a dict with the member comparison, plain/cipher
    sha256 and sizes, the exit codes and the failure kind (if any)."""
    res = {"tar_rc": None, "age_rc": None, "failure": None, "detail": "", "members": 0, "killed": None}
    fd = out_fd if out_fd is not None else \
        os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    cipher = {"h": hashlib.sha256(), "n": 0, "err": None}
    env = dict(os.environ, LC_ALL="C")
    procs = []
    th = None
    done = threading.Event()
    wd = {"why": None}
    for lg in (tar_log, age_log):
        Path(lg).parent.mkdir(parents=True, exist_ok=True)
    tlog = open(tar_log, "ab")
    alog = open(age_log, "ab")
    try:
        agep = subprocess.Popen(age_argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=alog,
                                start_new_session=True, env=env)
        procs.append(agep)
        tarp = subprocess.Popen(tar_argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=tlog, cwd=cwd,
                                start_new_session=True, env=env)
        procs.append(tarp)

        def pump():
            try:
                while True:
                    b = agep.stdout.read(C.MIB)
                    if not b:
                        break
                    cipher["h"].update(b)
                    view = memoryview(b)
                    while view:
                        k = os.write(fd, view)
                        view = view[k:]
                    cipher["n"] += len(b)
            except Exception as exc:  # noqa: BLE001 (OSError on write; ValueError if the pipe was closed)
                cipher["err"] = exc if isinstance(exc, OSError) else OSError(errno.EIO, f"{type(exc).__name__}")
                res["killed"] = "age"
                C._killpg(agep.pid, signal.SIGTERM)

        th = threading.Thread(target=pump, daemon=True)
        th.start()
        sink = _CountingSink(agep.stdin)
        gz = gzip.GzipFile(fileobj=sink, mode="wb", compresslevel=1, mtime=0, filename="")
        started = time.monotonic()

        def watchdog():
            while not done.wait(1.0):
                if STOP.is_set() or time.monotonic() > started + timeout:
                    wd["why"] = "stop" if STOP.is_set() else "timeout"
                    for pr in procs:
                        C._killpg(pr.pid, signal.SIGTERM)
                    if not done.wait(5):
                        for pr in procs:
                            C._killpg(pr.pid, signal.SIGKILL)
                    return

        threading.Thread(target=watchdog, daemon=True).start()
        tee = _TeeReader(tarp.stdout.fileno(), gz, started + timeout, STOP,
                         (lambda el: on_tick(el, sink.n, cipher["n"])) if on_tick else None, started)
        found, links = {}, {}
        try:
            with tarfile.open(fileobj=tee, mode="r|") as tf:
                for m in tf:
                    res["members"] += 1
                    name = m.name[2:] if m.name.startswith("./") else m.name
                    if name in expected:
                        if m.isreg():
                            h = hashlib.sha256()
                            fobj = tf.extractfile(m)
                            while True:
                                b = fobj.read(C.MIB)
                                if not b:
                                    break
                                h.update(b)
                            found[name] = h.hexdigest()
                        elif m.islnk():
                            links[name] = m.linkname[2:] if m.linkname.startswith("./") else m.linkname
            while tee.read(C.MIB):  # tar's trailing blocks: the archive must be all of tar's output
                pass
        except tarfile.TarError as exc:
            res["failure"], res["detail"] = "parse", f"{type(exc).__name__}: {exc}"
            while tee.read(C.MIB):
                pass
        gz.close()
        agep.stdin.close()
        res["tar_rc"] = tarp.wait(60)
        res["age_rc"] = agep.wait(60)
        th.join(60)
        if wd["why"] == "stop":
            raise GateStopped()
        if wd["why"] == "timeout":
            raise _ArchiveTimeout()
        if th.is_alive():
            res["failure"], res["detail"] = "write", "the encrypted output did not finish"
        elif cipher["err"] is not None:
            res["failure"], res["detail"] = "write", os.strerror(cipher["err"].errno or 0) or str(cipher["err"])
        os.fsync(fd)
        try:  # the read-back must come from disk, not from the pages just written
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        except (AttributeError, OSError):
            pass
        res.update(compare_members(expected, found, links, res["members"]))
        res.update({"plain_sha256": sink.h.hexdigest(), "plain_size": sink.n,
                    "cipher_sha256": cipher["h"].hexdigest(), "cipher_size": cipher["n"]})
        return res
    except Exception as exc:  # noqa: BLE001 (every path must reap tar and age)
        if wd["why"] == "stop" and not isinstance(exc, GateStopped):
            exc = GateStopped()
        elif wd["why"] == "timeout":
            exc = _ArchiveTimeout()
        for pr in procs:
            C._killpg(pr.pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        for pr in procs:
            try:
                pr.wait(max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                C._killpg(pr.pid, signal.SIGKILL)
                pr.wait()
        if isinstance(exc, GateStopped):
            raise exc from None
        if not isinstance(exc, (_ArchiveTimeout, OSError, subprocess.TimeoutExpired)):
            raise  # anything unexpected (internal-error HOLD)
        res["tar_rc"] = procs[1].returncode if len(procs) > 1 else None
        res["age_rc"] = procs[0].returncode if procs else None
        if isinstance(exc, _ArchiveTimeout):
            res["failure"] = "timeout"
        elif cipher["err"] is not None:
            res["failure"], res["detail"] = "write", os.strerror(cipher["err"].errno or 0) or str(cipher["err"])
        else:
            res["failure"], res["detail"] = "pipe", f"{type(exc).__name__}: {exc}"
        return res
    finally:
        done.set()
        if th is not None:
            th.join(10)  # age is gone, so its stdout is at EOF: the pump ends before its pipe and fd are closed
        for pr in procs:
            for stream in (pr.stdin, pr.stdout):
                try:
                    if stream:
                        stream.close()
                except (OSError, ValueError):
                    pass
        if th is None or not th.is_alive():
            try:
                os.close(fd)
            except OSError:
                pass
        else:  # never close an fd a live thread may still write to (a reused fd number would get the bytes)
            sys.stderr.write("[gate] WARN: archive writer thread still running; its file descriptor is kept open\n")
        tlog.close()
        alog.close()


# --- the gate run ----------------------------------------------------------------------------------

def _on_signal(signum, _frame):
    if _STOP_SIG[0] is None:
        _STOP_SIG[0] = signum
    STOP.set()


def install_signal_handlers():
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)


def stop_rc():
    return 130 if _STOP_SIG[0] == signal.SIGINT else 143


class Gate:
    def __init__(self, *, dry_run=False, network=False, emit=out):
        self.gp = gpaths()
        self.hooks = load_hooks()
        self.dry_run = dry_run
        self.network = network
        self.emit = emit
        self.j = None
        self.pkg = None
        self.cfg = {}
        self.cfg_raw = None
        self.cls = None
        self.sizes = {}
        self.accepted = set()
        self.phase = "precheck"
        self._tmp = None
        self.facts = {}

    # ----- output / journal -----
    def _event(self, line):
        if self.dry_run or not self.j:
            return
        try:
            d = self.run_dir() if self.j.get("run_id") else self.gp["GATE"]
            d.mkdir(parents=True, exist_ok=True)
            with open(d / "events.log", "a", encoding="utf-8") as f:
                f.write(f"{C.utc_iso()} {line}\n")
        except OSError:
            pass

    def say(self, msg):
        line = f"[gate] {msg}"
        self.emit(line)
        self._event(line)

    def warn(self, msg):
        line = f"WARN [gate] {msg}"
        self.emit(line)
        self._event(line)

    def pn(self, phase=None):
        return f"{PHASE_NO[phase or self.phase]}/9"

    def run_dir(self):
        if self.dry_run or not self.j or not self.j.get("run_id"):
            if self._tmp is None:
                self._tmp = tempfile.mkdtemp(prefix="oc-gate-dry-")
            return Path(self._tmp)
        return self.gp["RUNS"] / self.j["run_id"]

    def save(self):
        if self.dry_run or not self.j:
            return
        ensure_dirs(self.gp)
        C.atomic_write_json(self.gp["JOURNAL"], self.j)

    def history(self, event):
        if not self.j:
            return
        h = self.j.setdefault("history", [])
        h.append({"at": C.utc_iso(), "event": event})
        del h[:-300]

    def check_stop(self):
        if STOP.is_set():
            raise GateStopped()

    def mark_first_write(self):
        if self.j is not None and not self.j.get("first_write_at"):
            self.j["first_write_at"] = C.utc_iso()
            self.history("first write")
            self.save()

    def complete_phase(self, phase):
        if self.j is None:
            return
        done = self.j.setdefault("phases_done", [])
        if phase not in done:
            done.append(phase)
            self.history(f"phase {phase} done")
        self.save()

    def resolve(self, findings, phase, resume_after=False):
        """Log accepted / warn findings; raise HoldError for hard and unaccepted acceptable ones."""
        block = []
        for f in findings:
            f.setdefault("phase", phase)
            if f.get("cls") == "info":
                self.say(f"{self.pn(phase)} info: {f['message']}")
            elif f.get("cls") == "warn":
                self.warn(f"{f['code']}: {f['message']}")
            elif f.get("cls") == "acceptable" and f["code"] in self.accepted:
                self.warn(f"accepted {f['code']}: {f['message']}")
            else:
                if f.get("cls") not in ("hard", "acceptable"):
                    f["cls"] = "hard"
                block.append(f)
        if block:
            block.sort(key=lambda f: 0 if f["cls"] == "hard" else 1)
            raise HoldError(block, phase, resume_after)

    # ----- subprocess helpers -----
    def oc_json(self, args, timeout, tag):
        d = self.run_dir()
        d.mkdir(parents=True, exist_ok=True)
        outp, errp = d / f"{tag}.json", d / f"{tag}.stderr"
        for p in (outp, errp):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        res = C.run_oc(args, timeout=timeout, log_path=errp, stdout_path=outp, stop_event=STOP)
        if res.stopped:
            raise GateStopped()
        try:
            text = outp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        return res, C.parse_json_output(text)

    def config_validate(self, tag):
        res, data = self.oc_json(["config", "validate", "--json"], 180, tag)
        ok = res.rc == 0 and isinstance(data, dict) and data.get("valid") is True
        issues = ""
        if isinstance(data, dict) and isinstance(data.get("issues"), list):
            issues = "; ".join(C.redact_text(str(i.get("message", i) if isinstance(i, dict) else i))[:160]
                               for i in data["issues"][:5])
        return ok, f"rc {res.rc}" + (f": {issues}" if issues else ("" if ok else " (no valid JSON)"))

    # ----- config -----
    def read_config(self):
        self.cfg, self.cfg_raw = C.read_json_strict(self.gp["CONFIG_PATH"], with_text=True)
        return self.cfg

    def write_config(self, cfg):
        C.atomic_write_text(self.gp["CONFIG_PATH"], C.json_dumps(cfg))
        self.cfg = cfg

    def copy_once(self, src, dst):
        """Write-once copy (B2): never overwrite an existing scratch copy of this run."""
        dst = Path(dst)
        if dst.exists():
            return False
        dst.parent.mkdir(parents=True, exist_ok=True)
        C.atomic_write_bytes(dst, Path(src).read_bytes(), 0o600)
        os.chmod(dst, 0o600)
        return True

    def save_copy(self, src, dst):
        dst = Path(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        C.atomic_write_bytes(dst, Path(src).read_bytes(), 0o600)
        os.chmod(dst, 0o600)

    def ledger_add(self, entries, steps):
        """transform-ledger.json: replace this run's entries of `steps`, append the new (redacted) ones."""
        path = self.run_dir() / "transform-ledger.json"
        cur = C.load_json_or_none(path)
        cur = [e for e in (cur if isinstance(cur, list) else []) if e.get("step") not in steps]
        M = mig()
        for e in entries:
            e = dict(e)
            p = str(e.get("path", ""))
            e["before"] = M.redact_value(p, e.get("before"))
            e["after"] = M.redact_value(p, e.get("after"))
            cur.append(e)
        C.atomic_write_json(path, cur)

    # ----- sizes / archive plan -----
    def archive_plan(self):
        p = self.gp
        root, state = p["CONFIG_ROOT"], p["STATE"]
        try:
            srel = state.relative_to(root)
        except ValueError:
            raise HoldError([finding("archive-failed", "hard",
                                     f"state dir {state} is not below {root}; cannot archive it", "archive")],
                            "archive")
        srel = str(srel)
        roots = [srel]
        excludes = [f"{srel}/{d}" for d in STATE_EXCLUDES]
        warns, ws_info = [], []
        included, symlinks = [], []
        for ws in workspaces(self.cfg):
            if not os.path.isdir(ws):
                continue
            real = Path(os.path.realpath(ws))
            try:
                wrel = ws.relative_to(root)
            except ValueError:
                warns.append(f"workspace {ws} is outside {root}: not archived")
                continue
            if str(wrel) in ("", ".") or state == ws or str(state).startswith(str(ws) + "/"):
                warns.append(f"workspace {ws} contains the state directory: archived only through {srel}")
                continue
            # F1: tar would store a symlinked workspace as a bare link (precheck: state-symlink), unless
            # its target is archived anyway (inside the state dir or another workspace root)
            if os.path.islink(ws) and not any(str(real) == str(r) or str(real).startswith(str(r) + "/")
                                              for r in included + [Path(os.path.realpath(state))]):
                symlinks.append(str(ws))
                continue
            if str(ws).startswith(str(state) + "/"):
                continue
            if any(str(real) == str(r) or str(real).startswith(str(r) + "/") for r in included):
                continue
            included.append(real)
            size = 0
            for _p, st in C.walk_lstat(ws, skip_dir=lambda d: d.name == "node_modules", stop_event=STOP):
                if stat.S_ISREG(st.st_mode) and not _is_git_pack_tmp(_p):
                    size += st.st_size
            wrel = str(wrel)
            excludes += [f"{wrel}/node_modules", f"{wrel}/*/node_modules", f"{wrel}/.git/objects/pack/*.tmp",
                         f"{wrel}/*/.git/objects/pack/*.tmp"]
            if size <= WORKSPACE_FULL_LIMIT:
                roots.append(wrel)
                ws_info.append({"path": str(ws), "rel": wrel, "mode": "full", "size": size})
            else:
                sel = []
                try:
                    with os.scandir(ws) as it:
                        for e in it:
                            if e.name.startswith("openclaw-workspace-state.json") or e.name.endswith(".md") \
                                    or (e.name in (".openclaw", "memory", "skills")):
                                sel.append(f"{wrel}/{e.name}")
                except OSError:
                    pass
                roots += sorted(sel)
                warns.append(f"workspace {ws} is {C.human(size)} (> 2 GiB): archiving only state files, *.md, "
                             f"memory/, skills/ and .openclaw/")
                ws_info.append({"path": str(ws), "rel": wrel, "mode": "selective", "size": size, "members": sel})
            for sib in sorted(ws.parent.glob(ws.name + ".attested*")):
                if os.path.lexists(sib):
                    roots.append(str(sib.relative_to(root)))
        return {"roots": roots, "excludes": excludes, "warnings": warns, "workspaces": ws_info, "state_rel": srel,
                "symlinks": symlinks}

    def known_db_members(self, ap):
        """Archive member names of the state DB and of every target agent DB the predicate knows (F1)."""
        if self.cls is None:
            self.cls = classify(self.gp["STATE"], self.cfg, self.pkg["schema_state"], self.pkg["schema_agent"],
                                self.pkg["version"])
        rels = ["state/openclaw.sqlite"] if os.path.lexists(self.gp["STATE"] / "state" / "openclaw.sqlite") else []
        rels += sorted(set((self.cls.get("agent_paths") or {}).values()) - set(rels))
        return [r if os.path.isabs(r) else f"{ap['state_rel']}/{r}" for r in rels]

    def iter_archive_inputs(self, ap):
        """(path, member_name, lstat) of every input (same rules as the tar excludes)."""
        root = self.gp["CONFIG_ROOT"]
        excl_state = {self.gp["STATE"] / d for d in STATE_EXCLUDES}
        for r in ap["roots"]:
            top = root / r
            try:
                st = os.lstat(top)
            except OSError:
                continue
            yield top, r, st
            if not stat.S_ISDIR(st.st_mode):
                continue
            in_state = r == ap["state_rel"]

            def skip(d, in_state=in_state):
                return (in_state and d in excl_state) or (not in_state and d.name == "node_modules")
            for pth, pst in C.walk_lstat(top, skip_dir=skip, stop_event=STOP):
                if not in_state and _is_git_pack_tmp(pth):
                    continue
                yield pth, str(pth.relative_to(root)), pst

    def measure(self, ap):
        state = self.gp["STATE"]
        sqlite_total = transcripts = archive_input = 0
        dbs = {}
        for pth, _name, st in self.iter_archive_inputs(ap):
            if stat.S_ISREG(st.st_mode):
                archive_input += st.st_size
        backups = state / "upgrade-backups"
        for pth, st in C.walk_lstat(state, skip_dir=lambda d: d == backups, stop_event=STOP):
            if not stat.S_ISREG(st.st_mode):
                continue
            n = pth.name
            if n.endswith((".sqlite", ".sqlite-wal", ".sqlite-shm", ".sqlite-journal")):
                sqlite_total += st.st_size
                base = re.sub(r"-(?:wal|shm|journal)$", "", str(pth))
                if n.endswith((".sqlite", ".sqlite-wal")):
                    dbs[base] = dbs.get(base, 0) + st.st_size
        trans_by_dir = {}
        for pat in ("sessions/*.jsonl*", "agents/*/sessions/*.jsonl*"):
            for pth in state.glob(pat):
                try:
                    st = os.lstat(pth)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode):
                    transcripts += st.st_size
                    trans_by_dir[str(pth.parent.parent)] = trans_by_dir.get(str(pth.parent.parent), 0) + st.st_size
        max_db = max(dbs.values()) if dbs else 0
        largest_agent = 0
        for base, size in dbs.items():
            if base.endswith("/agent/openclaw-agent.sqlite"):
                agent_dir = str(Path(base).parent.parent)
                largest_agent = max(largest_agent, size + trans_by_dir.get(agent_dir, 0))
        s_mib = math.ceil((sqlite_total + transcripts) / C.MIB)
        self.sizes = {"sqlite_total": sqlite_total, "transcripts_total": transcripts, "archive_input": archive_input,
                      "max_db": max_db, "largest_agent": largest_agent, "s_mib": s_mib}
        return self.sizes

    def budget(self):
        s_mib = self.sizes.get("s_mib", 0)
        t = min(21600, 3600 + 2 * s_mib)
        if self.hooks.get("doctor_timeout_s"):
            t = int(self.hooks["doctor_timeout_s"])
        return {"s_mib": s_mib, "doctor_pass_seconds": t, "kill_after_seconds": DOCTOR_KILL_AFTER}

    # ----- phase 1: precheck -----
    def precheck_findings(self, mode, generic_only):
        """Run every precheck item (§7.1, B2/B4/B5/B6); return (findings, summary_parts)."""
        F, parts = [], []
        p = self.gp
        try:
            self.pkg = C.runtime_package()
        except C.RuntimePackageError as exc:
            return [finding("runtime-schema-unknown", "hard", str(exc), "precheck")], parts
        rt_env = os.environ.get("OPENCLAW_RUNTIME_VERSION")
        if rt_env and C.version_tuple(rt_env) != C.version_tuple(self.pkg["version"]):
            self.warn(f"OPENCLAW_RUNTIME_VERSION={rt_env} differs from the package version {self.pkg['version']}")
        # 2 node / SQLite capability
        parts.append(self.node_capability(F))
        # 3 other OpenClaw processes
        procs = find_openclaw_processes(self.pkg["entry"])
        if procs:
            msg = "OpenClaw is running: " + "; ".join(f"pid {x['pid']} {x['cmd']}" for x in procs[:3])
            F.append(finding("openclaw-running", "warn" if self.dry_run else "hard", msg, "precheck"))
        # 4 config
        cfg_ok = False
        try:
            self.read_config()
            cfg_ok = True
        except C.ConfigReadError as exc:
            self.cfg, self.cfg_raw = {}, None
            F.append(finding("config-missing" if exc.kind == "missing" else "config-unreadable", "hard", str(exc),
                             "precheck"))
        # B5 legacy state dir
        legacy = p["CONFIG_ROOT"] / ".clawdbot"
        if os.path.lexists(legacy):
            ok = False
            if os.path.islink(legacy):
                ok = os.path.realpath(legacy) == os.path.realpath(p["STATE"])
            elif os.path.isdir(legacy):
                try:
                    with os.scandir(legacy) as it:
                        ok = not any(True for _ in it)
                except OSError:
                    ok = False
            if not ok:
                F.append(finding("legacy-state-dir", "hard",
                                 f"legacy state dir {legacy} exists next to {p['STATE']}; doctor would refuse "
                                 "('State dir migration skipped: target already exists')", "precheck"))
        # 5 predicate
        self.cls = classify(p["STATE"], self.cfg, self.pkg["schema_state"], self.pkg["schema_agent"],
                            self.pkg["version"])
        if self.cls["verdict"] == "newer":
            F.append(finding("newer-state", "hard", "; ".join(self.cls["newer"]), "precheck"))
        if self.cls["orphans"]:
            F.append(finding("orphan-agent-db", "acceptable",
                             "agent databases of unconfigured, unregistered agents are not migrated by doctor and are "
                             "excluded from the checks: " + ", ".join(f"{o['path']} (schema {o['uv']})"
                                                                      for o in self.cls["orphans"]), "precheck"))
        state_db = p["STATE"] / "state" / "openclaw.sqlite"
        checkpoint = startup_checkpoint(state_db)
        if self.j is not None and not self.j.get("first_write_at"):
            self.j["source"] = {"from_checkpoint": checkpoint,
                                "config_last_touched": _cfg_get(self.cfg, "meta", "lastTouchedVersion"),
                                "state_user_version": self.cls.get("state_uv"), "agents": dict(self.cls["agents"])}
            self.j["orphans"] = self.cls["orphans"]
        src = (self.j or {}).get("source") or {"from_checkpoint": checkpoint}
        # 6 from-7x only, and only before the first write (B2)
        if mode == "from-7x" and not generic_only:
            probs = prejournal_problems(state_db)
            if probs:
                F.append(finding("not-pre-journal", "hard", "state DB is not a clean pre-journal 2026.7.x state: "
                                 + "; ".join(probs), "precheck"))
            if checkpoint != CHECKPOINT_735:
                F.append(finding("checkpoint-not-735", "acceptable",
                                 f"startup-migrations checkpoint is {checkpoint or 'missing'}, expected {CHECKPOINT_735} "
                                 "(start 0.5.93-full2 once until the gateway runs cleanly, or accept)", "precheck"))
            M = mig()
            if cfg_ok:
                F += [dict(f) for f in M.config_precheck(self.cfg, self.cfg_raw)]
                F += [dict(f) for f in M.models_preflight(self.cfg)]
            sf = M.classify_state_files(str(p["STATE"]), self.cfg, from_checkpoint=src.get("from_checkpoint"),
                                        accepted=set(self.accepted), mode=mode, query=_mq)
            F += [dict(f) for f in sf.get("findings", [])]
            for i in sf.get("info", []):
                self.say(f"{self.pn('precheck')} info: {i}")
            self.facts["cleanup_plan"] = sf.get("plan", [])
            _stores, sess_f = M.scan_sessions_files(str(p["STATE"]))
            F += [dict(f) for f in sess_f]
        # 6b every gate mode, before the first write: pre-July-2026 formats OpenClaw 2026.10 refuses
        if not (self.j or {}).get("first_write_at"):
            F += self.retired_format_findings(mode, cfg_ok)
        # 7 sizes (and F1: a symlinked state/agent directory or workspace root would be archived as a bare link)
        ap = self.archive_plan()
        links = state_symlinks(p["STATE"], self.cls) + ap["symlinks"]
        if links:
            F.append(finding("state-symlink", "hard", "symlinked director(ies) would be archived as bare links, "
                             "without the data they point to: " + ", ".join(links[:6]), "precheck"))
        sizes = self.measure(ap)
        # 7a archive setting (gate_archive / gate_archive_age_recipient); never a plaintext archive
        opt = C.gate_options()
        need_new_archive = self.archive_setting(F, parts, opt)
        # 8 space
        if self.hooks.get("skip_space_check"):
            parts.append("space check skipped (test hook)")
        else:
            archive_done = bool(self.j and "archive" in self.j.get("phases_done", []) and
                                (self.j.get("archive") or {}).get("verified"))
            no_archive = need_new_archive and opt["archive"]["mode"] == "off"
            need_share = 0 if archive_done or no_archive or not need_new_archive else sizes["archive_input"] + C.GIB
            needs = [("/config", p["CONFIG_ROOT"],
                      2 * sizes["sqlite_total"] + 2 * sizes["transcripts_total"] + 2 * C.GIB, "low-disk-config"),
                     ("/share", p["SHARE"], need_share, "low-disk-share"),
                     ("sqlite-tmp", sqlite_tmpdir(),
                      max(sizes["largest_agent"], sizes["max_db"]) + C.GIB, "low-disk-tmp")]
            sf_, summary = space_check(needs)
            F += sf_
            parts.append(f"space {'ok' if not sf_ else 'LOW'} ({summary})")
        # 9 quick_check
        parts.append(self.quick_checks(F, state_db))
        # 10 network
        if self.hooks.get("skip_network_check") or (self.dry_run and not self.network):
            parts.append("network not checked")
        else:
            parts.append(self.network_check(F))
        # 10b encrypted Home Assistant backup with this add-on (the primary rollback point)
        parts.append(self.ha_backup_check(F, opt))
        # 11 info
        self.info_items(mode, generic_only)
        b = self.budget()
        if self.j is not None:
            self.j["budget"] = b
        parts.append(f"doctor budget {C.fmt_duration(b['doctor_pass_seconds'])}/pass (S={b['s_mib']} MiB)")
        if mode == "from-7x" and not generic_only:
            parts.insert(1, f"checkpoint {checkpoint or 'none'}")
        if NODE_FALLBACKS:
            self.warn(f"node:sqlite fallback used for {len(set(NODE_FALLBACKS))} database(s)")
        return F, parts

    def archive_setting(self, F, parts, opt):
        """Precheck 7a. Records the validated archive option for this run (journal archive_opt, before the first
        write) so phase 2 never re-reads options.json. Returns True when this run still needs a new archive."""
        a_opt = opt["archive"]
        for prob in opt["problems"]:
            self.warn(f"add-on option {prob}")
        first_write = bool((self.j or {}).get("first_write_at"))
        if first_write:
            rec = (self.j.get("archive") or {})
            mode = rec.get("mode") or ("legacy" if rec else "none")
            parts.append(f"archive {mode} (recorded for this run)")
            if a_opt["mode"] and a_opt["mode"] != (rec.get("mode") or "encrypted"):
                self.warn(f"gate_archive is now {a_opt['mode']}, but run {self.j['run_id']} started with {mode}; "
                          "the run keeps its archive setting")
            elif (mode == "encrypted" and a_opt["mode"] == "encrypted" and a_opt["recipient"] and rec.get("recipient")
                  and a_opt["recipient"] != rec["recipient"]):
                self.warn(f"gate_archive_age_recipient is now {C.short_recipient(a_opt['recipient'])}, but run "
                          f"{self.j['run_id']} archived to {C.short_recipient(rec['recipient'])}; the run keeps its "
                          "archive setting: keep the OLD private key until that archive is deleted")
            return False
        snap = {"mode": a_opt["mode"], "recipient": a_opt["recipient"]}
        if a_opt["problem"] == "missing":
            F.append(finding("archive-key-missing", "hard",
                             "gate_archive is 'encrypted' but gate_archive_age_recipient is empty: the gate writes no "
                             "plaintext archive", "precheck"))
        elif a_opt["problem"] == "private-key":
            F.append(finding("archive-key-invalid", "hard",
                             "gate_archive_age_recipient holds an age PRIVATE key (AGE-SECRET-KEY-...): remove it from "
                             "the add-on options now and create a new key pair; only the public key (age1...) belongs "
                             "there", "precheck"))
        elif a_opt["problem"] == "malformed":
            F.append(finding("archive-key-invalid", "hard", "gate_archive_age_recipient is not one age public key "
                             "(age1... with 58 more characters)", "precheck"))
        elif a_opt["problem"] == "invalid-mode":
            F.append(finding("archive-key-invalid", "hard", "gate_archive must be 'encrypted' or 'off'", "precheck"))
        elif a_opt["mode"] == "encrypted":
            age = C.age_bin()
            try:
                v = subprocess.run([age, "--version"], capture_output=True, text=True, timeout=10,
                                   stdin=subprocess.DEVNULL)
                ver = (v.stdout or v.stderr).strip().splitlines()[0] if v.returncode == 0 else None
            except (OSError, subprocess.TimeoutExpired, IndexError):
                ver = None
            if not ver:
                F.append(finding("archive-age-missing", "hard", f"the age tool ({age}) does not run", "precheck"))
            else:
                try:
                    probe = subprocess.run([age, "-r", a_opt["recipient"], "-o", os.devnull],
                                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10)
                    err = "" if probe.returncode == 0 else (probe.stderr.strip().splitlines() or ["age failed"])[0]
                except (OSError, subprocess.TimeoutExpired) as exc:
                    err = type(exc).__name__
                if err:
                    F.append(finding("archive-key-invalid", "hard",
                                     "age rejects gate_archive_age_recipient: " + C.redact_text(err)[:160], "precheck"))
                snap["age_version"] = ver
        if self.j is not None:
            self.j["archive_opt"] = snap
        self.facts["archive_opt"] = snap
        need_new = not self.archive_reusable()
        if a_opt["problem"]:
            parts.append("archive NOT CONFIGURED" if a_opt["problem"] == "missing" else "archive option INVALID")
        elif a_opt["mode"] == "off":
            parts.append("archive off")
            if need_new:
                F.append(finding("archive-off", "warn", "gate_archive is off: no /share archive; rollback only through "
                                 "the encrypted Home Assistant backup", "precheck"))
        else:
            parts.append(f"archive encrypted ({snap.get('age_version') or 'age'}, "
                         f"{C.short_recipient(a_opt['recipient'])})" + ("" if need_new else ", reusing this run's"))
        legacy = sorted(self.gp["ARCHIVES"].glob("*/openclaw-state-*.tar.gz")) if self.gp["ARCHIVES"].is_dir() else []
        if legacy:
            self.warn(f"{len(legacy)} plaintext gate archive(s) from 0.5.94-full1 in {self.gp['ARCHIVES']} hold "
                      "unencrypted secrets; the add-on deletes them gate_cleanup_hours after their run (oc-upgrade "
                      "cleanup lists them)")
        return need_new

    def ha_backup_check(self, F, opt):
        """Precheck 10b (read-only): an encrypted full/partial Home Assistant backup that contains this add-on, is
        at most gate_backup_max_age_hours old and, for from-7x/bump runs, holds the add-on version installed
        before this one (restoring a backup of the new version would not bring the old OpenClaw back)."""
        if self.hooks.get("skip_backup_check"):
            return "HA backup not checked (test hook)"
        if (self.j or {}).get("first_write_at"):
            return "HA backup not re-checked (resume after the first write)"
        mode_off = opt["archive"]["mode"] == "off"
        tail = "; gate_archive is off, so there is no other rollback point" if mode_off else ""
        token = C.supervisor_token(self.hooks.get("supervisor_token_file"))
        if not token:
            F.append(finding("ha-backup-unverified", "acceptable", "no Supervisor token (neither "
                             f"{C.S6_TOKEN_FILE} nor SUPERVISOR_TOKEN is set){tail}", "precheck"))
            return "HA backup UNVERIFIED"
        base = self.hooks.get("supervisor_url")
        try:
            me = C.supervisor_get("/addons/self/info", token, base=base)
            data = C.supervisor_get("/backups/info", token, base=base)
        except C.SupervisorError as exc:
            why = exc.message
            if exc.status in (401, 403):
                why += " (the add-on needs hassio_api with a role that allows /backups/info)"
            F.append(finding("ha-backup-unverified", "acceptable",
                             f"the Supervisor backup list could not be read: {why}{tail}", "precheck"))
            return "HA backup UNVERIFIED"
        slug, version = me.get("slug"), me.get("version")
        hours = opt["backup_max_age_hours"]
        ev = evaluate_ha_backups(data.get("backups"), slug, C.utc_now(), hours * 3600)
        for e in ev["unprotected"][:3]:
            self.warn(f"Home Assistant backup '{e['name']}' ({e['slug']}, {e['date']}) contains this add-on "
                      f"UNENCRYPTED in {e['locations']}: it holds the add-on's secrets in plaintext; delete it and keep "
                      "only encrypted backups")
        need_older = (self.j or {}).get("mode", "from-7x") in ("from-7x", "bump")
        best, same_version, unreadable = None, [], []
        for e in ev["candidates"][:5]:
            bver, why = None, ""
            try:
                bver = backup_addon_version(C.supervisor_get(f"/backups/{e['slug']}/info", token, base=base), slug)
            except C.SupervisorError as exc:
                why = exc.message
            e["addon_version"] = bver
            if need_older:
                # unknown is not "older": a backup taken after the update would not bring the old OpenClaw back
                if not (isinstance(bver, str) and bver and isinstance(version, str) and version):
                    unreadable.append((e, why or ("the running add-on version is unknown" if bver else
                                                  "the backup lists no version for this add-on")))
                    continue
                if bver == version:
                    same_version.append(e)
                    continue
            best = e
            break
        if best:
            if self.j is not None:
                self.j["ha_backup"] = {"checked_at": C.utc_iso(), "slug": best["slug"], "name": best["name"],
                                       "date": best["date"], "type": best["type"], "locations": best["locations"],
                                       "addon_version": best.get("addon_version")}
            age = (C.utc_now() - best["dt"]).total_seconds()
            ver = f", add-on {best['addon_version']}" if best.get("addon_version") else ""
            return f"HA backup ok ('{best['name']}', {C.fmt_duration(age)} old, encrypted{ver})"
        if unreadable:
            e, why = unreadable[0]
            F.append(finding("ha-backup-unverified", "acceptable",
                             f"the add-on version inside backup '{e['name']}' ({e['slug']}) could not be read "
                             f"({C.redact_text(why)[:120]}), so it is not known to hold the version before this "
                             f"update{tail}", "precheck"))
            return "HA backup UNVERIFIED"
        if same_version:
            msg = (f"the encrypted Home Assistant backup(s) of the last {hours} h hold this add-on version ({version}): "
                   "restoring them does not bring back the previous OpenClaw; keep or restore the backup taken before "
                   "the update")
        else:
            nw = ev["newest_with_slug"]
            newest = "none" if not nw else (f"'{nw['name']}' {C.fmt_duration((C.utc_now() - nw['dt']).total_seconds())} "
                                            f"old, {'encrypted' if nw['protected'] else 'NOT encrypted in ' + nw['locations']}")
            msg = (f"no encrypted Home Assistant backup containing this add-on ({slug}) from the last {hours} h "
                   f"({ev['total']} listed, {ev['with_slug']} with this add-on; newest with it: {newest})")
        F.append(finding("ha-backup-missing", "acceptable", msg + tail, "precheck"))
        return "HA backup MISSING"

    def node_capability(self, F):
        node = self.pkg.get("node")
        if not node:
            F.append(finding("node-runtime", "hard", "node is not on PATH", "precheck"))
            return "node missing"
        d = self.run_dir()
        d.mkdir(parents=True, exist_ok=True)
        env = C.openclaw_env()
        env["OCQ_PKG"] = self.pkg["pkg_dir"]
        log, outp = d / "node-check.log", d / "node-check.out"
        for x in (log, outp):
            try:
                x.unlink()
            except FileNotFoundError:
                pass
        res = C.run_process([node, "--input-type=module", "-e", NODE_CAPABILITY_JS], timeout=60, log_path=log,
                            stdout_path=outp, stop_event=STOP, env=env)
        if res.stopped:
            raise GateStopped()
        text = outp.read_text(encoding="utf-8", errors="replace").strip() if outp.exists() else ""
        if res.rc != 0:
            err = log.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-2:] if log.exists() else []
            F.append(finding("node-runtime", "hard", f"Node/SQLite capability check failed (rc {res.rc}): "
                             + C.redact_text(" | ".join(err))[:300], "precheck"))
            return "node check FAILED"
        bits = text.splitlines()[-1].split() if text else []
        return f"node {bits[0] if bits else '?'} sqlite {bits[1] if len(bits) > 1 else '?'} ok"

    def quick_checks(self, F, state_db):
        dbs = []
        if state_db.exists():
            dbs.append(state_db)
        for _aid, relp in sorted((self.cls or {}).get("agent_paths", {}).items()):
            dbs.append(self.gp["STATE"] / relp)
        results, ok, skipped = {}, 0, 0
        for db in dbs:
            r = quick_check(db)
            results[C.rel(db, self.gp["STATE"])] = r
            if r == "ok":
                ok += 1
            elif r == "skipped":
                skipped += 1
                self.warn(f"quick_check of {C.rel(db, self.gp['STATE'])} skipped: WAL without -shm index "
                          "(a private copy would be too large)")
            elif r == "timeout":
                F.append(finding("sqlite-check-timeout", "acceptable",
                                 f"quick_check of {C.rel(db, self.gp['STATE'])} did not finish in time", "precheck"))
            else:
                F.append(finding("sqlite-corrupt", "hard", f"quick_check of {C.rel(db, self.gp['STATE'])}: {r}",
                                 "precheck"))
        self.facts["quick_check"] = results
        verdict = "ok" if ok + skipped == len(dbs) else "FAILED"
        return f"quick_check {verdict} ({ok}/{len(dbs)}" + (f", {skipped} skipped)" if skipped else ")")

    def network_check(self, F):
        npm = shutil.which("npm")
        if not npm:
            F.append(finding("no-network", "acceptable", "npm not found; cannot check the registry", "precheck"))
            return "network unknown"
        d = self.run_dir()
        d.mkdir(parents=True, exist_ok=True)
        log, outp = d / "npm-view.log", d / "npm-view.json"
        for x in (log, outp):
            try:
                x.unlink()
            except FileNotFoundError:
                pass
        res = C.run_process([npm, "view", f"openclaw@{self.pkg['version']}", "version", "--json"], timeout=60,
                            log_path=log, stdout_path=outp, stop_event=STOP, env=C.openclaw_env())
        if res.stopped:
            raise GateStopped()
        data = C.parse_json_output(outp.read_text(encoding="utf-8", errors="replace") if outp.exists() else "")
        if res.rc == 0 and data == self.pkg["version"]:
            return "network ok"
        F.append(finding("no-network", "acceptable",
                         f"npm registry not reachable (rc {res.rc}); doctor installs/updates official plugins", "precheck"))
        return "network FAILED"

    def info_items(self, mode, generic_only):
        state = self.gp["STATE"]
        profiles = read_auth_profiles(state, (self.cls or {}).get("agent_paths", {}))
        if self.j is not None and not self.j.get("first_write_at"):
            self.j["auth_profiles"] = profiles
        now_ms = time.time() * 1000
        for pr in profiles:
            self.say(f"{self.pn('precheck')} auth profile {pr['agent']}/{pr['id']} provider={pr['provider']} "
                     f"type={pr['type']} expires={pr.get('expires_utc') or '-'}")
            exp = pr.get("expires_ms")
            if pr["type"] == "oauth" and pr["provider"] in ("openai", "openai-codex") and exp and exp - now_ms < 86400000:
                self.warn(f"OAuth profile {pr['id']} expires within 24 h; doctor refreshes it, so a rollback may "
                          "need a new login")
        n, cron_ids = codex_cron_ids(state / "state" / "openclaw.sqlite")
        if self.j is not None and not self.j.get("first_write_at"):
            self.j["cron_legacy_ids"] = cron_ids  # F1/PC2: doctor pins these for "migrated cron runtime intent"
            # F15: cron jobs on canonical openai/ models mean Codex was in use (codex_pkg_before)
            self.j["cron_openai_ids"] = codex_cron_ids(state / "state" / "openclaw.sqlite", "openai")[1]
        if n:
            self.warn(f"{n} cron job(s) use openai-codex models: doctor may install the @openclaw/codex plugin "
                      "for them (it stays installed); the fixups revert doctor's codex runtime pins to openclaw")
        # telegram/ingress-spool-*: reported by retired_format_findings (2026.10 doctor imports the spool)
        for ws in workspaces(self.cfg):
            nested = ws / ".openclaw" / "workspace-state.json"
            if os.path.lexists(nested) and not os.path.lexists(ws / "openclaw-workspace-state.json"):
                self.warn(f"{nested} holds the workspace setup state in the pre-July layout, which OpenClaw 2026.10 "
                          "ignores (2026.7.35 copies it to openclaw-workspace-state.json when the workspace is "
                          "used); the agent may offer its first-run setup again")

    def phase_precheck(self):
        mode = self.j["mode"]
        generic = bool(self.j.get("first_write_at")) or mode != "from-7x"
        F, parts = self.precheck_findings(mode, generic)
        self.save()
        self.resolve(F, "precheck")
        jtxt = "journal empty (pre-journal 7.x)" if mode == "from-7x" and not generic else \
            ("resume: generic checks only" if self.j.get("first_write_at") else f"mode {mode}")
        self.say(f"1/9 precheck: {parts[0]}; {jtxt}; " + "; ".join(parts[1:]))

    # ----- phase 2: archive -----
    def archive_reusable(self):
        """Phase 2 may be skipped: before the first write only when the recorded archive matches the validated
        option of this start (a changed option, or a 0.5.94-full1 plaintext archive, makes a new one)."""
        j = self.j or {}
        a = j.get("archive") or {}
        first_write = bool(j.get("first_write_at"))
        want = j.get("archive_opt") or self.facts.get("archive_opt") or {}
        if a.get("mode") == "off":
            return first_write or want.get("mode") == "off"
        if not a.get("verified"):
            return False
        if not first_write and (a.get("mode") != want.get("mode") or a.get("recipient") != want.get("recipient")):
            return False
        f = Path(a.get("dir", "")) / a.get("file", "")
        try:
            return f.is_file() and f.stat().st_size == a.get("size")
        except OSError:
            return False

    def archive_intact(self):
        """Resume after the first write: the archive must still exist with the recorded size and sha256 (for an
        encrypted archive: the ciphertext, plus its age header). Off: there is none, by the owner's choice."""
        a = self.j.get("archive") or {}
        if a.get("mode") == "off":
            self.say("2/9 archive: none for this run (gate_archive was off); rollback only through the encrypted "
                     "Home Assistant backup")
            return True
        if not self.archive_reusable():
            return False
        if not a.get("sha256"):
            return True
        self.say("2/9 archive: re-checking the recorded archive before continuing (sha256)")
        path = Path(a.get("dir", "")) / a.get("file", "")
        if _sha_or_none_stoppable(path) != a.get("sha256"):
            return False
        if a.get("mode") == "encrypted":
            try:
                hdr = age_header(path)
            except (OSError, ValueError):
                return False
            size = path.stat().st_size
            return "X25519" in hdr["stanzas"] and size == age_cipher_size(hdr["len"], a.get("plaintext_size", -1))
        return True

    def phase_archive(self):
        p = self.gp
        want = self.j.get("archive_opt") or {}
        rid = str(self.j["run_id"])
        if not SAFE_ID_RE.fullmatch(rid) or ".." in rid:
            raise HoldError([finding("archive-failed", "hard", "the journal holds an invalid run id", "archive")],
                            "archive")
        adir = p["ARCHIVES"] / rid
        if want.get("mode") == "off":
            self.remove_earlier_archive_dir(rid)  # an earlier attempt of this run, before any write
            self.j["archive"] = {"mode": "off", "verified": False, "created_at": C.utc_iso()}
            self.save()
            self.say("2/9 archive: off (gate_archive: off): no archive written; rollback only through the encrypted "
                     "Home Assistant backup")
            return
        if want.get("mode") != "encrypted" or not want.get("recipient"):
            raise HoldError([finding("archive-key-missing", "hard", "no validated archive setting for this run "
                                     "(gate_archive_age_recipient)", "archive")], "archive")
        rec = want["recipient"]
        ap = self.archive_plan()
        for w in ap["warnings"]:
            self.warn(w)
        old = os.umask(0o077)
        try:
            rfd = open_dir_nofollow(p["SHARE"], p["ARCHIVES"].name, rid, create=True)
            os.fchmod(rfd, 0o700)
        except OSError as exc:
            os.umask(old)
            raise HoldError([finding("archive-failed", "hard", f"{adir} cannot be created as a plain directory "
                                     f"(a symlink?): {exc.strerror or exc}", "archive")], "archive")
        try:
            self._archive_encrypted(p, want, rec, ap, adir, rfd, old)
        finally:
            os.close(rfd)

    def remove_earlier_archive_dir(self, rid):
        """gate_archive off: remove /share/openclaw-upgrade/<run> of an earlier attempt (before any write),
        through a directory fd (a planted symlink is removed as a link, never followed)."""
        try:
            afd = open_dir_nofollow(self.gp["SHARE"], self.gp["ARCHIVES"].name)
        except FileNotFoundError:
            return
        except OSError as exc:
            self.warn(f"{self.gp['ARCHIVES']} is not a plain directory ({exc.strerror or exc}); left alone")
            return
        try:
            try:
                st = os.stat(rid, dir_fd=afd, follow_symlinks=False)
            except FileNotFoundError:
                return
            if stat.S_ISDIR(st.st_mode):
                shutil.rmtree(rid, dir_fd=afd, ignore_errors=True)
                self.say(f"2/9 archive: removed {self.gp['ARCHIVES'] / rid}/ of an earlier attempt "
                         "(gate_archive is now off)")
            else:
                os.unlink(rid, dir_fd=afd)
        finally:
            os.close(afd)

    def _archive_encrypted(self, p, want, rec, ap, adir, rfd, old):
        try:
            rd = fd_path(rfd) if os.path.isdir(fd_path(rfd)) else adir  # path-based reads through the fd
            for n in sorted(os.listdir(rfd)):
                if not (n.endswith(".tmp") or (n.startswith("openclaw-state-") and n.endswith((".tar.gz", ".tar.gz.age")))):
                    continue
                try:
                    os.unlink(n, dir_fd=rfd)  # an earlier attempt of this run (before any write)
                except (FileNotFoundError, IsADirectoryError, PermissionError):
                    continue
                if n.endswith(".tar.gz"):
                    self.say(f"2/9 archive: removed the 0.5.94-full1 plaintext archive {adir / n} of this run")
            name = f"openclaw-state-{C.utc_now().strftime('%Y%m%d-%H%M%S')}-before-{self.pkg['version']}.tar.gz.age"
            final, tmpname = adir / name, name + ".tmp"
            expected, sqlite_meta = {}, []
            for pth, member, st in self.iter_archive_inputs(ap):
                if stat.S_ISREG(st.st_mode) and ".sqlite" in pth.name:
                    try:
                        h = C.sha256_file(pth, STOP)
                    except C.Stopped:
                        raise GateStopped()
                    expected[member] = h
                    entry = {"path": member, "size": st.st_size, "sha256": h}
                    if pth.name.endswith(".sqlite"):
                        entry["user_version"] = C.header_user_version(pth)
                        qc = self.facts.get("quick_check", {}).get(C.rel(pth, p["STATE"]))
                        if qc:
                            entry["quick_check"] = qc
                    sqlite_meta.append(entry)
            # F1 invariant: every database the predicate knows is a hashed archive member
            known = self.known_db_members(ap)
            absent = [m for m in known if m not in expected]
            if absent:
                why = "outside the state directory" if any(os.path.isabs(m) for m in absent) else "symlinked directory?"
                raise HoldError([finding("archive-verify-failed", "hard",
                                         f"database(s) the migration needs would not be in the archive ({why}): "
                                         + ", ".join(absent[:5]), "archive")], "archive")
            tar_argv = ["tar", "--create", "--file=-", f"--directory={p['CONFIG_ROOT']}", "--anchored", "--wildcards"]
            tar_argv += [f"--exclude={e}" for e in ap["excludes"]]
            tar_argv += ["--", *ap["roots"]]
            age_argv = [C.age_bin(), "--encrypt", "-r", rec]
            log, alog = self.run_dir() / "archive-tar.log", self.run_dir() / "archive-age.log"
            off = log.stat().st_size if log.exists() else 0
            aoff = alog.stat().st_size if alog.exists() else 0
            last = [0.0]

            def tick(elapsed, plain, written):
                if elapsed - last[0] >= HEARTBEAT_S:
                    last[0] = elapsed
                    self.say(f"2/9 archive running {C.fmt_duration(elapsed)} ({C.human(plain)} compressed, "
                             f"{C.human(written)} encrypted written)")
            out_fd = os.open(tmpname, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600,
                             dir_fd=rfd)
            try:
                r = stream_encrypted_archive(tar_argv, age_argv, rd / tmpname, expected, cwd=str(p["CONFIG_ROOT"]),
                                             timeout=ARCHIVE_TIMEOUT, tar_log=log, age_log=alog, on_tick=tick,
                                             out_fd=out_fd)
            except GateStopped:
                _unlink_at(rfd, tmpname)
                raise
        finally:
            os.umask(old)

        def fail(code, msg):
            _unlink_at(rfd, tmpname)
            raise HoldError([finding(code, "hard", msg, "archive")], "archive")

        def tail(path, offset):
            if not path.exists():
                return []
            with open(path, "rb") as f:
                f.seek(offset)
                return [x for x in f.read().decode("utf-8", "replace").splitlines() if x.strip()]
        if STOP.is_set():
            _unlink_at(rfd, tmpname)
            raise GateStopped()
        if r["failure"] == "timeout":
            fail("archive-timeout", f"tar/age did not finish within {ARCHIVE_TIMEOUT // 3600} h")
        errlines = tail(log, off)
        sockets = [x for x in errlines if x.rstrip().endswith("socket ignored")]
        # the first cause wins: a failed write or a failed age makes the gate stop tar itself (tar rc -15)
        if r["failure"] == "write":
            fail("archive-failed", f"writing the encrypted archive failed: {r['detail']}")
        tar_failed = r["tar_rc"] not in (0, None) and not (r["tar_rc"] == 1 and errlines and len(sockets) == len(errlines))
        if (r["age_rc"] not in (0, None) and not (tar_failed and r.get("killed") == "age")) or \
                (r["failure"] == "pipe" and not tar_failed):
            age_err = tail(alog, aoff)
            fail("archive-failed", f"age rc {r['age_rc']}: " + C.redact_text(" | ".join(age_err[-2:]) or r["detail"])[:300])
        if tar_failed:
            fail("archive-failed", f"tar rc {r['tar_rc']}: " + C.redact_text(" | ".join(errlines[-3:]))[:400])
        if r["tar_rc"] is None or r["age_rc"] is None:
            fail("archive-failed", "tar or age did not exit")
        if sockets:
            self.say(f"2/9 archive: {len(sockets)} socket(s) skipped (not archivable, recreated at runtime)")
        others = [x for x in errlines if x not in sockets]
        if others:
            self.warn(f"tar printed {len(others)} warning line(s); see {log}")
        if r["failure"] == "parse":
            fail("archive-verify-failed", f"the archive stream could not be parsed: {r['detail']}")
        unmatched = [m for m in known if m not in r["matched"]]
        if r["mismatched"] or r["missing"] or r["members"] == 0 or unmatched:
            bad = list(dict.fromkeys(r["mismatched"] + r["missing"] + unmatched))[:5]
            fail("archive-verify-failed", f"{len(r['matched'])}/{len(expected)} sqlite files match; differing or "
                 "missing: " + ", ".join(bad))
        try:
            hdr = age_header(rd / tmpname)
            size = os.stat(tmpname, dir_fd=rfd, follow_symlinks=False).st_size
        except (OSError, ValueError) as exc:
            fail("archive-verify-failed", f"encrypted archive header unreadable: {exc}")
        if "X25519" not in hdr["stanzas"]:
            fail("archive-verify-failed", "encrypted archive has no X25519 recipient stanza")
        expect = age_cipher_size(hdr["len"], r["plain_size"])
        if size != r["cipher_size"] or size != expect:
            fail("archive-verify-failed", f"encrypted archive is {size} bytes, expected {expect} (truncated?)")
        if _sha_or_none_stoppable(rd / tmpname) != r["cipher_sha256"]:
            fail("archive-verify-failed", "read-back sha256 of the encrypted archive differs from the bytes written")
        os.replace(tmpname, name, src_dir_fd=rfd, dst_dir_fd=rfd)  # created 0600 (O_EXCL) and never chmod'ed by path
        os.fsync(rfd)
        manifest = {"schema": 2, "kind": "openclaw-addon-pre-migration-archive", "format": "tar.gz+age",
                    "run_id": self.j["run_id"], "created_utc": C.utc_iso(), "addon_version": addon_version(),
                    "runtime_from": (self.j.get("source") or {}).get("config_last_touched"),
                    "runtime_to": self.pkg["version"], "mode": self.j["mode"],
                    "archive": {"file": final.name, "size_bytes": size, "sha256": r["cipher_sha256"],
                                "plaintext_sha256": r["plain_sha256"], "plaintext_size": r["plain_size"],
                                "members": r["members"]},
                    "encryption": {"tool": "age", "version": want.get("age_version"), "recipients": [rec],
                                   "stanzas": hdr["stanzas"], "header_len": hdr["len"]},
                    "verification": {"sqlite_in_stream": f"{len(r['matched'])}/{len(expected)}",
                                     "size_formula": True, "readback_equals_stream": True},
                    "roots": ap["roots"], "excludes": ap["excludes"],
                    "workspace_mode": ",".join(sorted({w["mode"] for w in ap["workspaces"]})) or "none",
                    "workspaces": ap["workspaces"], "sqlite": sqlite_meta,
                    "auth_profiles": [{k: x.get(k) for k in ("agent", "provider", "type", "expires_utc")}
                                      for x in self.j.get("auth_profiles") or []],
                    "contains_secrets": True, "encrypted": True}
        _write_new_at(rfd, "manifest.json", C.json_dumps(manifest).encode("utf-8"))
        _write_new_at(rfd, "SHA256SUMS", f"{r['cipher_sha256']}  {final.name}\n".encode("utf-8"))
        os.fsync(rfd)
        self.j["archive"] = {"mode": "encrypted", "format": "tar.gz+age", "dir": str(adir), "file": final.name,
                             "sha256": r["cipher_sha256"], "size": size, "plaintext_sha256": r["plain_sha256"],
                             "plaintext_size": r["plain_size"], "members": r["members"], "recipient": rec,
                             "verified": True, "created_at": C.utc_iso()}
        self.save()
        self.say(f"2/9 archive verified: encrypted (age, {C.short_recipient(rec)}), {r['members']} members, "
                 f"{len(r['matched'])}/{len(expected)} sqlite match, sha256 {r['cipher_sha256'][:12]}… -> {adir}/")

    # ----- phase 3: cleanup -----
    def retired_state(self, mode, cfg=None):
        cfg = self.cfg if cfg is None else cfg
        return mig().classify_retired_state(str(self.gp["STATE"]), cfg, accepted=set(self.accepted), query=_mq,
                                            home=str(self.gp["CONFIG_ROOT"]), mode=mode,
                                            workspaces=[str(w) for w in workspaces(cfg)],
                                            config_root=str(self.gp["CONFIG_ROOT"]))

    def retired_format_findings(self, mode, cfg_ok):
        """Mirror of the 2026.10 refusals (oc_migrate.classify_retired_state / retired_*): HOLD before any write."""
        M = mig()
        F = [dict(f) for f in M.retired_config_findings(self.cfg, mode)] if cfg_ok else []
        rs = self.retired_state("from-7x" if mode == "from-7x" else "bump")
        self.facts["retired_state"] = rs
        F += [dict(f) for f in rs["findings"]]
        for i in rs["info"]:
            self.say(f"{self.pn('precheck')} info: {i}")
        n = sum(1 for e in rs["plan"] if e["action"] == "quarantine")
        if n:
            self.say(f"{self.pn('precheck')} info: {n} retired pre-July-2026 file(s) will be moved to quarantine "
                     "(OpenClaw 2026.10 refuses them; their content is in SQLite or disposable)")
        dbs = [(aid, str(self.gp["STATE"] / rel), (self.cls.get("agents") or {}).get(aid), self.pkg["schema_agent"])
               for aid, rel in sorted((self.cls.get("agent_paths") or {}).items())]
        F += [dict(f) for f in M.retired_db_findings(dbs, str(self.gp["STATE"] / "state" / "openclaw.sqlite"),
                                                     query=_mq)]
        return F

    def phase_cleanup(self):
        M = mig()
        p = self.gp
        if not self.cfg:
            self.read_config()
        cmode = "from-7x" if self.j["mode"] == "from-7x" else "bump"
        src = self.j.get("source") or {}
        sf = M.classify_state_files(str(p["STATE"]), self.cfg, from_checkpoint=src.get("from_checkpoint"),
                                    accepted=set(self.accepted), mode=cmode, query=_mq)
        plan = list(sf.get("plan", [])) + list(self.retired_state(cmode)["plan"])
        skip = set(self.hooks.get("skip_cleanup_kinds") or [])
        qdir = p["QUAR"] / self.j["run_id"]
        mpath = qdir / "MANIFEST.json"
        counts = {}
        for e in plan:
            self.check_stop()
            relp, kind = e.get("rel"), e.get("kind")
            if e.get("action") != "quarantine":
                self.say(f"3/9 leave {kind}: {relp} ({e.get('reason', '')})")
                continue
            if kind in skip:
                self.warn(f"test hook: not quarantining {kind}: {relp}")
                continue
            in_cfg = e.get("root") == "config"
            src_p = (p["CONFIG_ROOT"] if in_cfg else p["STATE"]) / relp
            try:
                st = os.lstat(src_p)
            except FileNotFoundError:
                continue
            self.mark_first_write()
            dst = qdir / ("config-root/" + relp if in_cfg else relp)
            n = 0
            while os.path.lexists(dst):
                n += 1
                dst = qdir / f"{relp}.{n}"
            try:
                d = dst.parent
                d.mkdir(parents=True, exist_ok=True)
                for x in [d, *d.parents]:
                    if x == p["QUAR"] or not str(x).startswith(str(qdir)):
                        break
                    os.chmod(x, 0o700)
                sha = None
                if stat.S_ISREG(st.st_mode) and st.st_size <= 64 * C.MIB:
                    try:
                        sha = C.sha256_file(src_p, STOP)
                    except C.Stopped:
                        raise GateStopped()
                    except OSError:
                        sha = None
                os.rename(src_p, dst)
                man = C.load_json_or_none(mpath)
                man = man if isinstance(man, list) else []
                man.append({"src": relp, "dst": str(dst), "kind": kind, "size": st.st_size, "sha256": sha,
                            "reason": e.get("reason", ""), "at": C.utc_iso(), **({"root": "config"} if in_cfg else {})})
                C.atomic_write_json(mpath, man)
            except OSError as exc:
                raise HoldError([finding("cleanup-failed", "hard", f"cannot quarantine {relp}: {exc}", "cleanup")],
                                "cleanup")
            counts[kind] = counts.get(kind, 0) + 1
            self.say(f"3/9 quarantine {kind}: {relp} ({C.human(st.st_size)})")
        total = sum(counts.values())
        detail = ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "nothing to move"
        self.say(f"3/9 cleanup: quarantined {total} files ({detail}) -> {qdir}/")

    # ----- phase 4: pre-migrate -----
    def phase_premigrate(self):
        if self.j.get("doctor_started"):
            self.say("4/9 pre-migrate: skipped (doctor already started)")
            return
        M = mig()
        p, rd = self.gp, self.run_dir()
        try:
            self.mark_first_write()
            self.copy_once(p["CONFIG_PATH"], rd / "config.pre-gate.json")
            cfg_pre = C.read_json_strict(rd / "config.pre-gate.json")
            removals = self.retired_state("from-7x", cfg_pre)["config_removals"]
            new_cfg, ledger, summary = M.premigrate_config(cfg_pre, removals=removals)
            stores, _f = M.scan_sessions_files(str(p["STATE"]))
            sess_led, pinned, user_explicit, harness = [], [], [], []
            sess_writes = []
            for relp, _store in stores:
                src = p["STATE"] / relp
                if os.path.islink(src):
                    self.warn(f"{relp} is a symlink; session runtime pins skipped for it")
                    continue
                self.copy_once(src, rd / "sessions-pre" / relp)
                store_pre = C.read_json_strict(rd / "sessions-pre" / relp)
                new_store, led, ssum = M.premigrate_sessions(store_pre, relp)
                sess_led += led
                pinned += list(ssum.get("pinned") or [])
                user_explicit += list(ssum.get("user_explicit") or [])
                harness += list(ssum.get("harness") or [])
                if led:
                    sess_writes.append((src, new_store))
            C.atomic_write_json(rd / "config.post-transform.json", new_cfg)
            self.write_config(new_cfg)
            for src, store in sess_writes:
                C.atomic_write_text(src, C.json_dumps(store))
            self.ledger_add(list(ledger) + sess_led, {"R0", "R1", "R2", "R3", "R4", "R5"})
        except (OSError, ValueError, C.ConfigReadError) as exc:  # ValueError: a map that is not an object
            raise HoldError([finding("premigrate-failed", "hard", f"{type(exc).__name__}: {exc}", "premigrate")],
                            "premigrate")
        self.j["transform"] = {"legacy_slots": summary.get("legacy_slots", []), "explicit_ids": summary.get("explicit", []),
                               "scopes": summary.get("scopes", []), "pinned": summary.get("pinned", 0),
                               "model_policy_written": bool(summary.get("model_policy_written")),
                               "sessions_pinned": pinned, "sessions_user_explicit": user_explicit,
                               "sessions_harness": harness}
        self.save()
        scopes = ", ".join(summary.get("scopes") or []) or "none"
        self.say(f"4/9 pre-migrate: openai-codex/* -> {len(summary.get('explicit') or [])} explicit models "
                 f"(scopes: {scopes}); runtime pinned to openclaw on {summary.get('pinned', 0)} entries; "
                 f"{len(pinned)} sessions pinned; modelPolicy {{}} written: "
                 f"{'yes' if summary.get('model_policy_written') else 'no'}")
        r0 = [e["path"] for e in ledger if e.get("step") == "R0"]
        if r0:
            self.say("4/9 pre-migrate: removed retired key(s) OpenClaw 2026.10 refuses: " + ", ".join(r0))

    # ----- doctor -----
    def run_doctor_pass(self, n, phase):
        rd = self.run_dir()
        rd.mkdir(parents=True, exist_ok=True)
        log = rd / f"doctor-pass{n}.log"
        off = log.stat().st_size if log.exists() else 0
        b = self.budget()
        self.j["budget"] = b
        limit = b["doctor_pass_seconds"]
        hook_cmd = self.hooks.get("doctor_cmd")
        if hook_cmd:
            argv = [str(x) for x in hook_cmd]
            self.warn("test hook doctor_cmd in use")
        else:
            argv = [self.pkg.get("node") or "node", self.pkg["entry"], "doctor", "--fix", "--non-interactive"]
        mirror = LogMirror(log, off, DOCTOR_MIRROR_CAP, self.emit, f"pass{n}")
        last_hb = [0.0]
        label = f"{PHASE_NO[phase]}/9 doctor pass {n}"

        def tick(elapsed):
            mirror.pump()
            if elapsed - last_hb[0] >= HEARTBEAT_S:
                last_hb[0] = elapsed
                self.say(f"{label} running {C.fmt_duration(elapsed)} (limit {C.fmt_duration(limit)}; "
                         f"{mirror.lines} log lines; last: \"{mirror.last[:100]}\")")
        started = C.utc_iso()
        sha_before = _sha_or_none(self.gp["CONFIG_PATH"])
        self.say(f"{label} started (limit {C.fmt_duration(limit)}; log {log})")
        res = C.run_process(argv, timeout=limit, log_path=log, stop_event=STOP, kill_grace=DOCTOR_KILL_AFTER,
                            stop_grace=DOCTOR_STOP_GRACE, env=C.openclaw_env(), on_tick=tick)
        mirror.pump(final=True)
        with open(log, "rb") as f:
            f.seek(off)
            text = f.read().decode("utf-8", "replace")
        ev = evaluate_doctor(res.rc, text, timed_out=res.timed_out, stopping=STOP.is_set(), final=n >= 2)
        rec = {"pass": n, "started": started, "ended": C.utc_iso(), "rc": res.rc, "duration_s": round(res.duration),
               "complete": ev["complete"], "markers": ev["markers"], "code": ev["code"],
               "log": str(log.relative_to(self.gp["GATE"])) if str(log).startswith(str(self.gp["GATE"])) else str(log),
               "config_sha256_before": sha_before, "config_sha256_after": _sha_or_none(self.gp["CONFIG_PATH"])}
        self.j.setdefault("doctor", []).append(rec)
        # contract addendum 2 item 7: doctor's retired-model replacements of every pass, in order
        pairs, removed = doctor_retirements(text)
        if pairs:
            rmap = self.j.setdefault("doctor_retired_map", {})
            for old, new in pairs.items():
                rmap.pop(old, None)
                rmap[old] = new
        if removed:
            rem = self.j.setdefault("doctor_retired_removed", [])
            rem += [r for r in removed if r not in rem]
        self.save()
        if ev["code"] == "interrupted":
            self.say(f"{label}: stop requested; doctor was asked to stop (rc {res.rc})")
            raise GateStopped()
        ev["duration"] = res.duration
        ev["text"] = text
        return ev

    def doctor_failure(self, ev, phase, n):
        if ev["code"] and ev["cls"] == "hard":
            raise HoldError([finding(ev["code"], "hard", f"pass {n}: {ev['message']}", phase)], phase)

    def phase_doctor1(self):
        rd, p = self.run_dir(), self.gp
        self.mark_first_write()
        self.j["doctor_started"] = True
        self.save()
        self.copy_once(p["CONFIG_PATH"], rd / "config.pre-pass1.json")
        if self.j.get("plugins_before") is None:
            self.j["plugins_before"] = plugin_snapshot(p["STATE"])
            self.save()
        ev = self.run_doctor_pass(1, "doctor1")
        self.doctor_failure(ev, "doctor1", 1)
        self.j["doctor_notes"] = doctor_notes(ev["text"])
        baks = []
        for b in p["STATE"].rglob("*.pre-startup-migration-*.bak"):
            try:
                baks.append({"path": C.rel(b, p["STATE"]), "size": b.stat().st_size})
            except OSError:
                pass
        self.j["doctor"][-1]["pre_migration_backups"] = baks
        for c in p["STATE"].rglob("*.capturing"):
            self.warn(f"leftover {C.rel(c, p['STATE'])} after doctor pass 1")
        try:
            self.save_copy(p["CONFIG_PATH"], rd / "config.post-pass1.json")
            pre = C.read_json_strict(rd / "config.pre-pass1.json")
            post = C.read_json_strict(rd / "config.post-pass1.json")
            removed = sorted(mig().flatten_paths(pre) - mig().flatten_paths(post))
            if removed:
                self.say(f"5/9 doctor removed {len(removed)} config key(s): " + ", ".join(removed[:40])
                         + (" …" if len(removed) > 40 else ""))
            tuning = mig().retired_tuning_dropped(pre, post)
            if tuning:
                self.warn("doctor removed memory search tuning that OpenClaw 2026.9+ no longer supports (recall now "
                          "uses fixed values: hybrid vector/text 0.7/0.3, MMR 0.7, recency decay with a 365-day half-life in this "
                          "add-on): "
                          + ", ".join(tuning[:8]))
        except C.ConfigReadError as exc:
            self.warn(f"cannot compare config before/after pass 1: {exc}")
        total = sum(x["size"] for x in baks)
        self.say(f"5/9 doctor pass 1 rc={ev['rc']} in {C.fmt_duration(ev['duration'])}: Doctor complete. "
                 f"({len(baks)} pre-migration SQLite backups, {C.human(total)})")
        self.complete_phase("doctor1")
        F = [finding(e["code"], "acceptable", f"pass 1: {e['message']}", "doctor1") for e in acceptable_doctor(ev)]
        if F:  # doctor-warnings, doctor-held-back (2026.10: rc 0)
            self.resolve(F, "doctor1", resume_after=True)

    def codex_pkg_before(self):
        """Codex was in use before doctor pass 1 outside openclaw.json (contract addendum 2 rule 4): a codex
        plugin package existed, or cron jobs used canonical openai/ models (F15; recorded by the precheck)."""
        return any(str(x).startswith("npm/projects/openclaw-codex-") for x in self.j.get("plugins_before") or []) \
            or bool(self.j.get("cron_openai_ids"))

    def phase_fixups(self):
        """F1-F3 (from-7x) or F1b (bump/maintenance), then F4 (contract addendum 2)."""
        M = mig()
        p, rd = self.gp, self.run_dir()
        self.glm_recover()
        cfg_now = self.read_config()
        pre_pass1 = C.read_json_strict(rd / "config.pre-pass1.json")
        if self.j["mode"] == "from-7x":
            pre_gate = C.read_json_strict(rd / "config.pre-gate.json")
            new_cfg, ledger, summary = M.fixups(cfg_now, pre_gate, pre_pass1,
                                                retired_map=self.j.get("doctor_retired_map") or {},
                                                codex_pkg_before=self.codex_pkg_before(),
                                                extra_legacy_ids=self.j.get("cron_legacy_ids") or [])
        else:
            new_cfg, ledger, summary = M.post_doctor_fixups(cfg_now, pre_pass1, codex_pkg_before=self.codex_pkg_before())
        try:
            if ledger:
                self.write_config(new_cfg)
            self.ledger_add(ledger, {"F1", "F1b", "F1c", "F2", "F3"})
            C.atomic_write_json(rd / "config.post-fixups.json", new_cfg)
        except ValueError as exc:
            raise HoldError([finding("fixups-invalid", "hard", f"the fixups could not be written "
                                     f"({type(exc).__name__}: {exc}); openclaw.json unchanged", "fixups")], "fixups")
        ok, detail = self.config_validate("pc-fixups-validate")
        if not ok:
            post1 = rd / "config.post-pass1.json"
            if post1.exists():
                C.atomic_write_bytes(p["CONFIG_PATH"], post1.read_bytes())
            raise HoldError([finding("fixups-invalid", "hard", f"config validate after fixups failed ({detail}); "
                                     "config.post-pass1.json restored", "fixups")], "fixups")
        self.j["fixups"] = {"codex_pins": summary.get("codex_pins", 0), "refs_rewritten": summary.get("refs_rewritten", 0),
                            "compaction_restored": bool(summary.get("compaction_restored")),
                            "codex_plugin_restored": bool(summary.get("codex_plugin_restored")),
                            "codex_needed": bool(summary.get("codex_needed")),
                            "policy_failures": [dict(f) for f in summary.get("policy_failures") or []]}
        self.save()
        plugin = f"codex plugin entry restored: {'yes' if summary.get('codex_plugin_restored') else 'no'}"
        if summary.get("codex_needed"):
            plugin += " (Codex was in use before the migration: doctor's setting kept)"
        if self.j["mode"] == "from-7x":
            self.say(f"6/9 fixups: {summary.get('codex_pins', 0)} codex runtime pins -> openclaw; "
                     f"{summary.get('refs_rewritten', 0)} legacy refs rewritten; compaction restored: "
                     f"{'yes' if summary.get('compaction_restored') else 'no'}; {plugin}")
        else:
            self.say(f"6/9 fixups: {plugin}")
        self.glm_thinking_step()

    def glm_thinking_step(self):
        """G1 (add-on option glm_thinking_levels, every mode): GLM models send the thinking level as
        reasoning_effort. Validated on its own; a failure restores the fixups' config and only warns.
        journal glm_thinking.pending marks a write whose validation has not finished (see glm_recover)."""
        M = mig()
        p, rd = self.gp, self.run_dir()
        try:
            cur = self.read_config()
        except C.ConfigReadError as exc:  # left to pc-config (hard) in the postconditions
            self.warn(f"GLM thinking levels skipped: openclaw.json cannot be read ({exc})")
            return
        on = C.glm_thinking_option()
        scan = M.glm_thinking_scan(cur)
        refs = [f"{pid}/{mid}" for pid, _i, mid in scan["convert"]]
        if on:
            for ref, why in scan["skip"]:
                self.say(f"6/9 info: GLM thinking levels: {ref} left as is ({why})")
        if not refs:
            return
        if not on:
            self.say(f"6/9 info: {', '.join(refs)} only switch thinking on/off (qwen-chat-template); the add-on "
                     "option glm_thinking_levels sends the thinking level instead")
            return
        if not glm_runtime_ok(self.pkg.get("version")):  # 7.35 sends "high" for off and refuses max
            self.say(f"6/9 info: GLM thinking levels need OpenClaw 2026.9+ (runtime {self.pkg.get('version')}); "
                     f"{', '.join(refs)} left as is")
            return
        new_cfg, ledger, refs = M.glm_thinking_levels(cur)
        before = rd / "config.pre-g1.json"
        self.save_copy(p["CONFIG_PATH"], before)
        self.j["glm_thinking"] = {"pending": True, "refs": refs}
        self.save()
        self.ledger_add(ledger, {"G1"})
        try:
            self.write_config(new_cfg)
            ok, detail = self.config_validate("pc-g1-validate")
        except ValueError as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        except BaseException:  # stop request or crash: never leave an unvalidated G1 write behind
            self.glm_undo(refs, "interrupted")
            raise
        if not ok:
            self.glm_undo(refs, detail)
            self.warn(f"GLM thinking levels not applied ({detail}); openclaw.json restored")
            return
        C.atomic_write_json(rd / "config.post-fixups.json", new_cfg)
        self.j["glm_thinking"] = {"applied": True, "refs": refs}
        self.save()
        self.say(f"6/9 GLM thinking levels: {', '.join(refs)} send the level as reasoning_effort "
                 "(off -> none, minimal/low -> low, medium/high -> high, xhigh/max -> max); "
                 f"{len(ledger)} change(s) in {rd / 'transform-ledger.json'}")

    def glm_undo(self, refs, reason):
        """Put back config.pre-g1.json and drop this run's G1 ledger entries."""
        rd = self.run_dir()
        C.atomic_write_bytes(self.gp["CONFIG_PATH"], (rd / "config.pre-g1.json").read_bytes())
        try:
            self.read_config()
        except C.ConfigReadError:
            pass
        self.ledger_add([], {"G1"})
        self.j["glm_thinking"] = {"applied": False, "refs": refs, "reason": reason}
        self.save()

    def glm_recover(self):
        """Start of the fixups phase: a G1 write that was cut off before its validation finished (SIGKILL,
        power loss) is undone first, so the fixups' own validate never judges an unvalidated G1 result
        and G1 runs again with its own validate."""
        g1 = self.j.get("glm_thinking") or {}
        if g1.get("pending") and (self.run_dir() / "config.pre-g1.json").exists():
            self.glm_undo(g1.get("refs") or [], "interrupted")
            self.say("6/9 GLM thinking levels: the step was interrupted before its check finished; "
                     "openclaw.json restored, running it again")

    def post_pass_fixups(self, n):
        """F1b after doctor pass 2/3 (contract addendum 2 rule 4). Returns True when the config changed."""
        M = mig()
        p, rd = self.gp, self.run_dir()
        pre_name = "config.pre-gate.json" if self.j["mode"] == "from-7x" else "config.pre-pass1.json"
        pre = C.read_json_strict(rd / pre_name)
        try:
            cur = self.read_config()
        except C.ConfigReadError as exc:  # left to pc-config (hard) in the postconditions
            self.warn(f"cannot read openclaw.json after doctor pass {n}: {exc}")
            return False
        new_cfg, ledger, summary = M.post_doctor_fixups(cur, pre, codex_pkg_before=self.codex_pkg_before())
        if not ledger:
            return False
        before = rd / f"config.post-pass{n}.raw.json"
        self.save_copy(p["CONFIG_PATH"], before)
        for e in ledger:
            e["step"] = f"{e['step']}@pass{n}"
        try:
            self.write_config(new_cfg)
            self.ledger_add(ledger, {f"F1b@pass{n}"})
        except ValueError as exc:
            C.atomic_write_bytes(p["CONFIG_PATH"], before.read_bytes())
            raise HoldError([finding("fixups-invalid", "hard", f"the pass-{n} fixups could not be written "
                                     f"({type(exc).__name__}: {exc}); doctor's pass-{n} config restored", "doctor2")],
                            "doctor2")
        ok, detail = self.config_validate(f"pc-pass{n}-fixups-validate")
        if not ok:
            C.atomic_write_bytes(p["CONFIG_PATH"], before.read_bytes())
            raise HoldError([finding("fixups-invalid", "hard", f"config validate after the pass-{n} fixups failed "
                                     f"({detail}); doctor's pass-{n} config restored", "doctor2")], "doctor2")
        fx = self.j.setdefault("fixups", {})
        fx.setdefault("policy_failures", [])
        for f in summary.get("policy_failures") or []:
            if f not in fx["policy_failures"]:
                fx["policy_failures"].append(dict(f))
        self.save()
        self.warn(f"doctor pass {n} changed what the fixups set; F1b re-applied: "
                  + ", ".join(sorted({e['path'] for e in ledger})[:10]))
        return True

    def phase_doctor2(self):
        p, rd = self.gp, self.run_dir()
        sha0 = _sha_or_none(p["CONFIG_PATH"])
        ev = self.run_doctor_pass(2, "doctor2")
        self.doctor_failure(ev, "doctor2", 2)
        warnings = acceptable_doctor(ev)
        if "Saved pre-migration SQLite backup" in normalize_doctor_text(ev["text"]):
            self.warn("doctor pass 2 saved another pre-migration SQLite backup")
        sha1 = _sha_or_none(p["CONFIG_PATH"])
        result = "config unchanged"
        hold = None
        if sha1 != sha0:
            self.say("7/9 doctor pass 2 changed openclaw.json: " + ", ".join(self.changed_paths(rd)[:40]))
        # F1b also after pass 2 (contract addendum 2 rule 4: a re-added codex plugin entry is removed again)
        self.post_pass_fixups(2)
        if sha1 != sha0:
            sha1f = _sha_or_none(p["CONFIG_PATH"])
            ev3 = self.run_doctor_pass(3, "doctor2")
            self.doctor_failure(ev3, "doctor2", 3)
            # pass 3 is the last pass now: pass-2 warnings that only rest on a final-pass marker are superseded
            warnings = [w for w in warnings if w["code"] != "doctor-warnings"
                        or set(w.get("markers") or []) - set(FINAL_PASS_SUSPICIOUS)]
            warnings += acceptable_doctor(ev3)
            sha2 = _sha_or_none(p["CONFIG_PATH"])
            self.post_pass_fixups(3)
            result = "config changed in pass 2, unchanged in pass 3" if sha2 == sha1f else "config changed again in pass 3"
            if sha2 != sha1f:
                hold = finding("doctor-not-idempotent", "acceptable",
                               "doctor changed openclaw.json in pass 2 and again in pass 3", "doctor2")
        self.save_copy(p["CONFIG_PATH"], rd / "config.post-pass2.json")
        before = set(self.j.get("plugins_before") or [])
        new = sorted(set(plugin_snapshot(p["STATE"])) - before)
        codex = [x for x in new if x.startswith("npm/projects/openclaw-codex-")]
        if codex and not (self.j.get("fixups") or {}).get("codex_needed"):
            # contract addendum 2 rule 6: only when F1b keeps Codex disabled
            # (`plugins uninstall <ids...>`: v99 docs/cli/plugins.md:45)
            self.warn("doctor installed @openclaw/codex but the add-on keeps it disabled (7.35 behaviour); "
                      "it can be removed with: openclaw plugins uninstall codex")
        elif codex:
            self.say("7/9 info: doctor installed the @openclaw/codex plugin (Codex was in use before the migration)")
        others = [x for x in new if x not in codex]
        if others:
            self.warn("doctor installed new plugin package(s): " + ", ".join(others) + " (left in place)")
        self.say(f"7/9 doctor pass 2 rc={ev['rc']} in {C.fmt_duration(ev['duration'])}: Doctor complete.; {result}")
        self.complete_phase("doctor2")
        F = []
        for w in warnings:  # one finding per code, the first pass that reported it
            if w["code"] not in {f["code"] for f in F}:
                F.append(finding(w["code"], "acceptable", w["message"], "doctor2"))
        if hold:
            F.append(hold)
        if F:
            self.resolve(F, "doctor2", resume_after=True)

    def changed_paths(self, rd):
        try:
            a = _flatten_leaves(C.read_json_strict(rd / "config.post-fixups.json")) if (rd / "config.post-fixups.json").exists() \
                else _flatten_leaves(C.read_json_strict(rd / "config.post-pass1.json"))
            b = _flatten_leaves(self.read_config())
        except C.ConfigReadError:
            return ["(unreadable)"]
        return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))

    # ----- phase 8: postconditions -----
    def phase_postconditions(self):
        M = mig()
        p = self.gp
        mode = self.j["mode"]
        cfg = self.read_config()
        remote = _cfg_get(cfg, "gateway", "mode") == "remote"
        policy, summary = [], []
        o_ids = []

        def pol(code, msg):
            policy.append(finding(code, "acceptable", msg, "postconditions"))

        def hard(code, msg):
            self.resolve([finding(code, "hard", msg, "postconditions")] + policy, "postconditions")

        # 0 auth order (from-7x)
        if mode == "from-7x":
            res, data = self.oc_json(["models", "auth", "list", "--provider", "openai", "--json"], 180, "pc-auth-list")
            profiles = data.get("profiles") if isinstance(data, dict) and isinstance(data.get("profiles"), list) else None
            if profiles is None:
                self.warn(f"models auth list failed (rc {res.rc}); auth order not adjusted")
                profiles = []
            o_ids = [x.get("id") for x in profiles if isinstance(x, dict) and x.get("type") in ("oauth", "token")]
            res2, data2 = self.oc_json(["models", "auth", "order", "get", "--provider", "openai", "--json"], 180,
                                       "pc-auth-order")
            store_order = data2.get("order") if isinstance(data2, dict) else None
            new_cfg, f, led = M.auth_order_adjust(cfg, profiles, store_order)
            if f:
                f = dict(f)
                f.setdefault("cls", "acceptable")
                policy.append(f)
            if new_cfg is not None:
                backup = self.run_dir() / "config.pre-auth-order.json"
                self.save_copy(p["CONFIG_PATH"], backup)
                self.write_config(new_cfg)
                self.ledger_add(led, {"auth-order"})
                ok, detail = self.config_validate("pc-auth-order-validate")
                if not ok:
                    C.atomic_write_bytes(p["CONFIG_PATH"], backup.read_bytes())
                    cfg = self.read_config()
                    pol("pc-auth-order", f"auth.order.openai could not be written (config validate {detail}); restored")
                else:
                    cfg = new_cfg
                    self.say("8/9 auth.order.openai written (subscription first, API key as fallback)")
        # pc-schema (hard)
        cls = classify(p["STATE"], cfg, self.pkg["schema_state"], self.pkg["schema_agent"], self.pkg["version"])
        if cls["schema_verdict"] != "ok":
            hard("pc-schema", "; ".join(cls["gate"] + cls["newer"]) or "schema verdict not ok")
        summary.append(f"schema {self.pkg['schema_state']}/{self.pkg['schema_agent']}")
        # pc-schema-meta
        sm = schema_meta_problems(p["STATE"], cls, self.pkg)
        if sm:
            pol("pc-schema-meta", "; ".join(sm))
        # pc-legacy-files
        if cls["files"]:
            pol("pc-legacy-files", "legacy files remain: " + ", ".join(cls["files"][:5]))
        # pc-config (hard)
        ok, detail = self.config_validate("pc-config")
        if not ok:
            hard("pc-config", f"openclaw config validate failed ({detail})")
        summary.append("config valid")
        # lint (one run)
        lint_t = min(7200, 900 + self.sizes.get("s_mib", self.budget()["s_mib"]))
        res, data = self.oc_json(["doctor", "--lint", "--json", "--all", "--severity-min", "info"], lint_t, "pc-lint")
        if res.rc == 2 or not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            pol("pc-lint-failed", f"doctor --lint did not produce a result (rc {res.rc})")
            summary.append("lint failed")
        else:
            fl = [x for x in data["findings"] if isinstance(x, dict)]
            legacy = [x for x in fl if x.get("checkId") == "core/doctor/legacy-state"]
            errors = [x for x in fl if x.get("severity") == "error" and x.get("checkId") != "core/doctor/legacy-state"]
            if legacy:
                pol("pc-legacy-state", "; ".join(C.redact_text(str(x.get("message", "")))[:200] for x in legacy[:5]))
            if errors:
                pol("pc-lint-errors", "; ".join(f"{x.get('checkId')}: " + C.redact_text(str(x.get('message', '')))[:160]
                                                for x in errors[:5]))
            summary.append(f"lint {len(errors)} errors")
            summary.append("no legacy state" if not legacy else "legacy state reported")
        # PC1-PC3
        probs = M.check_legacy_refs(cfg)
        if probs:
            pol("pc-legacy-refs", "; ".join(probs[:8]))
        else:
            summary.append("no legacy refs")
        # PC2 (contract addendum 2 rule 5): only migrated openai-codex slots; canonical openai/ refs that
        # existed before the gate keep the runtime doctor gives them. pre_cfg is passed in every mode.
        pre_name = "config.pre-gate.json" if mode == "from-7x" else "config.pre-pass1.json"
        pre_cfg = C.load_json_or_none(self.run_dir() / pre_name)
        if not isinstance(pre_cfg, dict):
            self.warn(f"{pre_name} of this run is missing or unreadable; PC2 checks without it")
            pre_cfg = {}
        retired = self.j.get("doctor_retired_map") or {}
        probs = M.check_codex_runtime(cfg, pre_cfg, retired_map=retired, codex_pkg_before=self.codex_pkg_before(),
                                      extra_legacy_ids=self.j.get("cron_legacy_ids") or [])
        if probs:
            pol("pc-codex-runtime", "; ".join(probs[:8]))
        if mode == "from-7x":
            slots = (self.j.get("transform") or {}).get("legacy_slots") or []
            # PC3 accepts doctor's retirement successors (item 9); Codex resolutions are PC2's
            probs = M.check_runtime_pins(cfg, slots, retired, skip_codex=True)
            if probs:
                pol("pc-runtime-pin", "; ".join(probs[:8]))
            else:
                summary.append(f"runtime openclaw ({len(slots)} slots)")
        for f in (self.j.get("fixups") or {}).get("policy_failures") or []:
            f = dict(f)
            f["cls"] = "acceptable"
            f["phase"] = "postconditions"
            policy.append(f)
        # pc-models-status
        if remote:
            summary.append("models/sessions/probe skipped (remote gateway)")
        else:
            res, data = self.oc_json(["models", "status", "--json", "--check"], 300, "pc-models-status")
            codex_ok = bool((self.j.get("fixups") or {}).get("codex_needed"))
            cur_cfg = {}
            try:
                cur_cfg = C.read_json_strict(p["CONFIG_PATH"])
            except Exception:  # noqa: BLE001 - pc-config reports an unreadable config
                cur_cfg = {}
            ms = models_status_problems(res.rc, data, self.j.get("auth_profiles") or [], codex_allowed=codex_ok,
                                        primaries=primary_model_refs(cur_cfg))
            for code, msg in ms:
                if code == "warn":
                    self.warn(msg)
                else:
                    pol(code, msg)
            ms = [m for m in ms if m[0] != "warn"]
            if res.rc == 2:
                self.warn("models status: a credential is expiring")
            if not ms:
                summary.append("models status ok")
            # pc-sessions-runtime
            tr = self.j.get("transform") or {}
            res, data = self.oc_json(["sessions", "--all-agents", "--json", "--limit", "all"], 600, "pc-sessions")
            sp = sessions_problems(res.rc, data, tr.get("sessions_pinned") or [],
                                   set(tr.get("sessions_user_explicit") or []) | set(tr.get("sessions_harness") or []),
                                   codex_allowed=codex_ok)
            if sp:
                pol("pc-sessions-runtime", "; ".join(sp[:6]))
            else:
                summary.append(f"sessions openclaw ({len(tr.get('sessions_pinned') or [])})")
            # pc-probe
            if o_ids:
                res, data = self.oc_json(["models", "status", "--json", "--probe", "--probe-provider", "openai",
                                          "--probe-profile", o_ids[0], "--probe-max-tokens", "8",
                                          "--probe-timeout", "60000"], 300, "pc-probe")
                if not probe_ok(data, o_ids[0]):
                    pol("pc-probe", f"live probe of OpenAI profile {o_ids[0]} did not return ok (rc {res.rc})")
                else:
                    summary.append("probe ok")
        # plugins (WARN only)
        res, data = self.oc_json(["plugins", "list", "--json"], 180, "pc-plugins")
        for w in plugin_version_warnings(data, self.pkg["version"]):
            self.warn(w)
        self.save()
        if policy:
            self.resolve(policy, "postconditions")
        self.say("8/9 postconditions OK: " + ", ".join(summary))

    # ----- phase 9: pins -----
    def phase_pins(self):
        if "pins-invalid" in self.accepted:
            self.warn("accepted pins-invalid: behaviour pins skipped")
            return
        M = mig()
        p, rd = self.gp, self.run_dir()
        led = C.load_json_or_none(p["LEDGER"])
        led = led if isinstance(led, dict) else {"schema": 1, "entries": [], "skipped": []}
        others = [e for e in led.get("entries", []) if e.get("run_id") != self.j["run_id"]]
        if others and self.j["mode"] == "from-7x" and not led.get("reset_for") == self.j["run_id"]:
            # B19: a new from-7x migration (after a rollback) starts a fresh ledger
            old = p["GATE"] / f"pins-ledger.{C.utc_now().strftime('%Y%m%dT%H%M%SZ')}.json"
            C.atomic_write_json(old, led)
            self.say(f"9/9 pins: previous ledger archived as {old.name} (new 2026.7.x migration)")
            led = {"schema": 1, "entries": [], "skipped": [], "reset_for": self.j["run_id"]}
            C.atomic_write_json(p["LEDGER"], led)
        ledgered = {e.get("path") for e in led.get("entries", []) if e.get("run_id") != self.j["run_id"]}
        # a fresh snapshot on every attempt: a retry after pins-invalid applies the pins to the config as
        # the user fixed it (and to what a re-run doctor / fixups / auth order wrote), never to an old copy
        self.save_copy(p["CONFIG_PATH"], rd / "config.pre-pins.json")
        try:
            base = C.read_json_strict(rd / "config.pre-pins.json")
        except C.ConfigReadError as exc:
            raise HoldError([finding("pc-config", "hard", f"openclaw.json cannot be read before the pins: {exc}",
                                     "pins")], "pins")
        new_cfg, written, skipped = M.apply_pins(base, set(ledgered))
        try:
            self.write_config(new_cfg)
        except ValueError as exc:
            C.atomic_write_bytes(p["CONFIG_PATH"], (rd / "config.pre-pins.json").read_bytes())
            raise HoldError([finding("pins-invalid", "acceptable",
                                     f"the behaviour pins could not be written ({type(exc).__name__}: {exc}); "
                                     "restored. Accepting skips the pins.", "pins")], "pins")
        ok, detail = self.config_validate("pc-pins-validate")
        if not ok:
            C.atomic_write_bytes(p["CONFIG_PATH"], (rd / "config.pre-pins.json").read_bytes())
            raise HoldError([finding("pins-invalid", "acceptable",
                                     f"config validate failed after writing the behaviour pins ({detail}); restored. "
                                     "Accepting skips the pins.", "pins")], "pins")
        now = C.utc_iso()
        led["entries"] = [e for e in led.get("entries", []) if e.get("run_id") != self.j["run_id"]] + [
            {"path": w["path"], "value": M.redact_value(w["path"], w.get("value")), "written_at": now,
             "run_id": self.j["run_id"], "runtime": self.pkg["version"]} for w in written]
        led["skipped"] = [s for s in led.get("skipped", []) if s.get("run_id") != self.j["run_id"]] + [
            {"path": s["path"], "reason": s.get("reason", ""), "run_id": self.j["run_id"]} for s in skipped]
        C.atomic_write_json(p["LEDGER"], led)
        C.atomic_write_json(rd / "config.final.json", new_cfg)
        self.j["pins"] = {"written": len(written), "skipped": len(skipped)}
        self.save()
        self.say(f"9/9 pins: wrote {len(written)}, skipped {len(skipped)} (already set / condition); ledger {p['LEDGER']}")

    # ----- finalize -----
    def phase_finalize(self):
        p = self.gp
        cfg = _read_cfg_lenient()
        cls = classify(p["STATE"], cfg, self.pkg["schema_state"], self.pkg["schema_agent"], self.pkg["version"])
        a = self.j.get("archive") or {}
        write_marker(mode=self.j["mode"], run_id=self.j["run_id"], binding=current_binding(p["STATE"], cls),
                     runtime=self.pkg["version"], archive=str(Path(a["dir"]) / a["file"]) if a.get("file") else None,
                     archive_mode=a.get("mode") or ("legacy" if a else None),
                     accepted=sorted(self.accepted), orphans=self.j.get("orphans") or [])
        self.j["status"] = "done"
        self.j["hold"] = None
        self.j["finished_at"] = C.utc_iso()
        self.complete_phase("finalize")
        for f in (p["RETRY"], p["HOLD"]):
            _unlink(f)
        for level, msg in self.j.get("doctor_notes") or []:
            (self.warn if level == "warn" else lambda t: self.say(f"info: {t}"))(f"doctor: {msg}")
        # contract addendum 2 item 10: every retired-model replacement doctor made
        for old, new in (self.j.get("doctor_retired_map") or {}).items():
            self.say(C.redact_text(f"info: doctor replaced retired model {old} with {new}"))
        for path, old in self.j.get("doctor_retired_removed") or []:
            self.say(C.redact_text(f"info: doctor removed retired model {old} from {path} (it inherits the default "
                                   "model)"))
        total = _elapsed_since(self.j.get("started_at"))
        self.say(f"done: MIGRATED {self.pkg['version']} (run {self.j['run_id']}, mode {self.j['mode']}, "
                 f"total {C.fmt_duration(total)})")
        hours = C.gate_options()["cleanup_hours"]
        what = "the archive and the doctor captures" if a.get("file") else "the doctor captures"
        if hours:
            due = C.utc_iso(C.utc_now() + timedelta(hours=hours))
            self.say(f"info: {what} of this run are deleted after {due} (gate_cleanup_hours={hours})")
        else:
            self.say(f"info: {what} of this run are kept (gate_cleanup_hours=0): delete them yourself")

    # ----- holds -----
    def write_hold(self, findings, phase, resume_after=False, post_run=False, sub=None, next_line=None):
        codes = list(dict.fromkeys(f["code"] for f in findings))
        primary = findings[0]
        acceptable = all(f.get("cls") == "acceptable" for f in findings)
        nxt = next_line or advice_for(codes, findings)
        sline = state_line_for(self.j, post_run)
        if self.j is not None:
            self.j["status"] = "hold"
            self.j["phase"] = phase
            self.j["hold"] = {"code": primary["code"], "codes": codes, "phase": phase, "message": primary["message"],
                              "acceptable": acceptable,
                              "retry": "none" if set(codes) & NO_RETRY else ("doctor" if post_run else "continue"),
                              "state_changed": bool(self.j.get("first_write_at")) or post_run,
                              "resume_after": resume_after, "at": C.utc_iso(), "sub": sub,
                              "findings": [{k: f.get(k) for k in ("code", "cls", "message", "phase")} for f in findings],
                              "state_line": sline, "next": nxt}
            self.history(f"HOLD {','.join(codes)} in {phase}")
            try:
                self.save()
            except OSError as exc:
                self.emit(f"WARN [gate] could not save the journal: {exc}")
        runtime = self.pkg["version"] if self.pkg else os.environ.get("OPENCLAW_RUNTIME_VERSION", "unknown")
        text = hold_text(runtime, (self.j or {}).get("run_id"), phase, findings, sline, nxt)
        try:
            self.gp["UPG_DIR"].mkdir(parents=True, exist_ok=True)
            C.atomic_write_text(self.gp["HOLD"], text)
        except OSError as exc:
            self.emit(f"WARN [gate] could not write hold.txt: {exc}")
            sys.stderr.write(text)
        for f in findings:
            self.say(f"reason [{f['code']}] ({f.get('cls')}): {f['message']}")
        self.say(f"HOLD {primary['code']} in {phase}: {primary['message']}")
        self.say(f"next: {nxt}")

    # ----- driver -----
    def start(self, d):
        """Create or resume the journal according to the plan decision `d`."""
        prev = d.get("journal")
        self.pkg = d["pkg"]
        if d["action"] == "run" or prev is None:
            if prev and prev.get("run_id"):
                try:
                    pd = self.gp["RUNS"] / prev["run_id"]
                    pd.mkdir(parents=True, exist_ok=True)
                    C.atomic_write_json(pd / "journal.json", prev)
                except OSError:
                    pass
            run_id = new_run_id()
            self.j = {"schema": 1, "run_id": run_id, "mode": d["mode"], "runtime": self.pkg["version"],
                      "addon_version": addon_version(), "status": "running", "phase": "precheck", "phases_done": [],
                      "first_write_at": None, "doctor_started": False, "auto_resumes": 0, "started_at": C.utc_iso(),
                      "source": {}, "targets": {"state": self.pkg["schema_state"], "agent": self.pkg["schema_agent"]},
                      "archive": None, "budget": {}, "transform": {}, "doctor": [], "accepted": [], "hold": None,
                      "orphans": [], "plugins_before": None, "fixups": {}, "pins": {},
                      "history": list((prev or {}).get("history") or [])[-150:]}
            self.history(f"run {run_id} started (mode {d['mode']}): {d['reason']}")
        else:
            self.j = prev
            if self.j.get("mode") != d.get("mode") and d.get("mode") and not self.j.get("first_write_at"):
                self.j["mode"] = d["mode"]
            self.j["status"] = "running"
            if (d.get("bk") or {}).get("auto_resumes") is not None:
                self.j["auto_resumes"] = d["bk"]["auto_resumes"]
            done = self.j.setdefault("phases_done", [])
            hold = self.j.get("hold") or {}
            newly = set((d.get("bk") or {}).get("accept") or [])
            acc_all = set(self.j.get("accepted") or []) | newly
            if hold.get("resume_after") and hold.get("phase") in done and not set(hold.get("codes") or []) <= acc_all:
                done.remove(hold["phase"])
            if (d.get("bk") or {}).get("redo_doctor"):
                for ph in DOCTOR_PHASES + ("postconditions",):
                    if ph in done:
                        done.remove(ph)
            if self.j.get("hold"):
                self.j.setdefault("previous_holds", []).append(self.j["hold"])
                del self.j["previous_holds"][:-10]
                self.j["hold"] = None
            self.history(f"run resumed: {d['reason']}")
        self.j["accepted"] = sorted(set(self.j.get("accepted") or []) | set((d.get("bk") or {}).get("accept") or []))
        self.accepted = set(self.j["accepted"]) | set(self.hooks.get("accept") or [])
        if self.hooks:
            self.warn(f"test hooks active: {', '.join(sorted(self.hooks))}")
        self.save()
        resume = "" if d["action"] == "run" else f" (resume; done: {','.join(self.j.get('phases_done') or []) or '-'})"
        self.say(f"start: run={self.j['run_id']} mode={self.j['mode']} runtime={self.pkg['version']}{resume}")

    def execute(self):
        for phase in PHASES:
            if self.j["mode"] != "from-7x" and phase in FROM7X_ONLY:
                continue
            done = self.j.get("phases_done") or []
            if phase != "precheck" and phase in done:
                if phase == "archive" and not self.j.get("first_write_at") and not self.archive_reusable():
                    done.remove("archive")
                elif phase == "archive" and not self.j.get("first_write_at") and not self.archive_intact():
                    # nothing written yet: a damaged archive of an earlier attempt is simply written again
                    self.say("2/9 archive: the archive of an earlier attempt failed its re-check; writing a new one")
                    done.remove("archive")
                elif phase == "archive" and not self.archive_intact():
                    # State was already changed: never continue the one-way migration without its rollback copy.
                    a = self.j.get("archive") or {}
                    raise HoldError([finding(
                        "archive-missing", "hard",
                        f"the verified pre-migration archive {a.get('dir')}/{a.get('file')} is missing or changed, "
                        "and the state was already partially migrated", "archive")], "archive")
                else:
                    if phase == "archive":
                        a = self.j.get("archive") or {}
                        if a.get("mode") == "off":
                            self.say("2/9 archive: off for this run")
                        elif a.get("mode") == "encrypted":
                            self.say(f"2/9 archive: reusing verified archive {a.get('dir')}/{a.get('file')} "
                                     f"(encrypted, {C.short_recipient(a.get('recipient'))})")
                        else:
                            self.say(f"2/9 archive: reusing verified archive {a.get('dir')}/{a.get('file')} "
                                     "(PLAINTEXT 0.5.94-full1 archive; deleted by the cleanup after the run)")
                    continue
            self.run_phase(phase)
        return 0

    def run_phase(self, phase):
        self.check_stop()
        self.phase = phase
        self.j["phase"] = phase
        self.j["status"] = "running"
        self.save()
        if self.hooks.get("raise_in_phase") == phase:
            raise RuntimeError(f"test hook raise_in_phase={phase}")
        getattr(self, "phase_" + phase)()
        if phase != "finalize":
            self.complete_phase(phase)
        self.check_stop()

    def cleanup_tmp(self):
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None


# --- helpers used by phases --------------------------------------------------------------------

def _fsync_dir(d):
    try:
        fd = os.open(str(d), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _unlink(p):
    try:
        os.unlink(p)
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        pass


_DIR_NOFOLLOW = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)


def open_dir_nofollow(base, *names, create=False, mode=0o700):
    """fd of base/<names...>. base is resolved once; every named component is opened relative to the previous
    fd with O_NOFOLLOW, so a symlink that another /share writer plants cannot redirect a write or a delete
    (ELOOP/ENOTDIR instead). With create, missing components are made (mode)."""
    fd = os.open(os.path.realpath(str(base)), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for n in names:
            if not n or "/" in n or n in (".", ".."):
                raise OSError(errno.EINVAL, "invalid path component", str(n))
            if create:
                try:
                    os.mkdir(n, mode, dir_fd=fd)
                except FileExistsError:
                    pass
            nfd = os.open(n, _DIR_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def fd_path(fd, name=None):
    """A path that resolves through an open directory fd (/proc/self/fd/N), for path-based reads."""
    base = Path(f"/proc/self/fd/{fd}")
    return base / name if name else base


def _unlink_at(dfd, name):
    try:
        os.unlink(name, dir_fd=dfd)
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        pass


def _write_new_at(dfd, name, data, mode=0o600):
    """Write <dfd>/name via a fresh O_EXCL|O_NOFOLLOW temp file and rename (never through a planted link)."""
    tmp = f".{name}.{uuid.uuid4().hex[:8]}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode, dir_fd=dfd)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        _unlink_at(dfd, tmp)
        raise


def state_symlinks(state_dir, cls):
    """Symlinks on the way to every database the predicate knows (F1): the state dir, state/, agents/
    and each target agent's directories and DB file. tar archives a symlink as a bare link."""
    state_dir = Path(state_dir)
    cands = [state_dir, C.paths()["CONFIG_PATH"], state_dir / "state", state_dir / "state" / "openclaw.sqlite",
             state_dir / "agents"]
    for relp in sorted(set(((cls or {}).get("agent_paths") or {}).values())):
        if os.path.isabs(relp):
            continue  # outside the state dir: the archive invariant reports it
        cur = state_dir
        for part in Path(relp).parts:
            cur = cur / part
            cands.append(cur)
    out = []
    for c in cands:
        if os.path.islink(c) and str(c) not in out:
            out.append(str(c))
    return out


def _is_git_pack_tmp(p):
    s = str(p)
    return s.endswith(".tmp") and "/.git/objects/pack/" in s


def _sha_or_none(p):
    try:
        return C.sha256_file(p)
    except OSError:
        return None


def _sha_or_none_stoppable(p):
    """Like _sha_or_none for multi-GB archives: a stop request interrupts the read (GateStopped)."""
    try:
        return C.sha256_file(p, STOP)
    except C.Stopped:
        raise GateStopped() from None
    except OSError:
        return None


def _elapsed_since(iso):
    try:
        from datetime import datetime
        t = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=C.timezone.utc)
        return (C.utc_now() - t).total_seconds()
    except (TypeError, ValueError):
        return 0


def _flatten_leaves(obj, prefix=""):
    outd = {}
    if isinstance(obj, dict):
        if not obj and prefix:
            outd[prefix] = "{}"
        for k, v in obj.items():
            key = f'{prefix}["{k}"]' if ("." in str(k) or "/" in str(k)) else (f"{prefix}.{k}" if prefix else str(k))
            outd.update(_flatten_leaves(v, key))
    elif isinstance(obj, list):
        outd[prefix] = json.dumps(obj, sort_keys=True)
    else:
        outd[prefix] = json.dumps(obj)
    return outd


def quick_check(path, budget_s=None):
    """'ok' | 'timeout' | <problem text>. Aborts via progress handler on timeout or stop (B17)."""
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    wal, shm = Path(f"{path}-wal"), Path(f"{path}-shm")
    try:
        wal_size = wal.stat().st_size if wal.exists() else 0
    except OSError:
        wal_size = 0
    if wal_size > 0 and not shm.exists() and size + wal_size > QUICK_CHECK_COPY_LIMIT:
        return "skipped"  # would need a private multi-GB copy (WAL without -shm index)
    budget_s = budget_s if budget_s is not None else 300 + math.ceil(1.25 * size / C.MIB)
    deadline = time.monotonic() + budget_s
    why = [None]

    def handler():
        if STOP.is_set():
            why[0] = "stop"
            return 1
        if time.monotonic() > deadline:
            why[0] = "timeout"
            return 1
        return 0
    try:
        rows = C.query_ro(path, "PRAGMA quick_check", progress_handler=handler)
    except sqlite3.OperationalError as exc:
        if why[0] == "stop":
            raise GateStopped()
        if why[0] == "timeout":
            return "timeout"
        rows = _node_quick_check(path, budget_s, exc)
    except sqlite3.DatabaseError as exc:
        rows = _node_quick_check(path, budget_s, exc)
    except OSError as exc:
        return f"unreadable ({exc})"
    if isinstance(rows, str):
        return rows
    vals = [str(r[0]) for r in rows]
    return "ok" if vals == ["ok"] else "; ".join(vals[:5])


def _node_quick_check(path, budget_s, exc):
    try:
        rows = C.node_query(path, "PRAGMA quick_check", timeout=budget_s, stop_event=STOP)
    except C.NodeQueryError as nexc:
        return f"unreadable ({type(exc).__name__}: {exc}; node fallback: {nexc})"
    NODE_FALLBACKS.append(str(path))
    return [tuple(r.values()) for r in rows if isinstance(r, dict)]


def prejournal_problems(state_db):
    """Mirror of 9.9 hasPreJournalStateSchema + retained deletion journal status (§7.1 item 6.1)."""
    if not state_db.exists():
        return ["state/openclaw.sqlite missing"]
    try:
        uv = db_uv(state_db)
        tables = table_names(state_db)
    except (sqlite3.Error, C.SchemaUnknown, C.NodeQueryError) as exc:
        return [f"state DB unreadable ({exc})"]
    try:
        return _prejournal_problems(state_db, uv, tables)
    except (sqlite3.Error, C.SchemaUnknown, C.NodeQueryError) as exc:
        return [f"state DB unreadable ({exc})"]


def _prejournal_problems(state_db, uv, tables):
    probs = []
    if uv != 1:
        probs.append(f"user_version {uv} (expected 1)")
    for t in ("agent_databases", "migration_sources"):
        if t not in tables:
            probs.append(f"table {t} missing")
    for t in ("config_machine_state", "agent_database_leases", "agent_deletion_journal"):
        if t in tables:
            probs.append(f"table {t} present")
    prim = schema_meta_primary(state_db, tables)
    if not prim or prim.get("role") != "global" or prim.get("schema_version") != 1 or prim.get("agent_id") is not None:
        probs.append("schema_meta 'primary' is not role=global/schema_version=1/agent_id=NULL")
    if "migration_sources" in tables:
        if q(state_db, "SELECT 1 FROM migration_sources WHERE target_table='agent_deletion_journal' LIMIT 1"):
            probs.append("migration_sources references agent_deletion_journal")
        n = q(state_db, "SELECT count(*) FROM migration_sources WHERE source_key='agent-deletion-journal-reconstruction'")
        if n and n[0][0]:
            probs.append(f"{n[0][0]} agent-deletion-journal reconstruction receipt(s)")
    return probs


def read_auth_profiles(state_dir, agent_paths):
    """[{agent,id,provider,type,expires_utc,expires_ms}] from 7.x agent auth stores (never tokens)."""
    outl = []
    for aid, relp in sorted(agent_paths.items()):
        db = Path(state_dir) / relp
        try:
            if "auth_profile_store" not in table_names(db):
                continue
            rows = q(db, "SELECT store_json FROM auth_profile_store WHERE store_key='primary'")
        except (sqlite3.Error, C.NodeQueryError, OSError):
            continue
        if not rows:
            continue
        try:
            store = json.loads(rows[0][0])
        except (TypeError, ValueError):
            continue
        profiles = store.get("profiles") if isinstance(store, dict) else None
        for pid, prof in sorted(profiles.items()) if isinstance(profiles, dict) else []:
            if not isinstance(prof, dict):
                continue
            exp = prof.get("expires", prof.get("expiresAt"))
            exp_ms = exp if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None
            exp_utc = None
            if exp_ms:
                try:
                    from datetime import datetime
                    exp_utc = C.utc_iso(datetime.fromtimestamp(exp_ms / 1000, C.timezone.utc))
                except (OverflowError, OSError, ValueError):
                    exp_utc = None
            elif isinstance(exp, str):
                exp_utc = exp[:40]
            outl.append({"agent": aid, "id": str(pid)[:120], "provider": str(prof.get("provider", ""))[:60],
                         "type": str(prof.get("type", ""))[:20], "expires_utc": exp_utc, "expires_ms": exp_ms})
    return outl


def codex_cron_ids(state_db, provider="openai-codex"):
    """(number of cron jobs, sorted model ids) of cron payloads that use <provider>/<id> models
    (openai-codex: 7.x legacy refs; openai: canonical refs, which 7.35 ran on the Codex app-server)."""
    ref_re = re.compile(r"\A\s*" + re.escape(provider) + r"\s*/\s*([^\s@*][^\s@]*)", re.I)
    try:
        if not state_db.exists() or "cron_jobs" not in table_names(state_db):
            return 0, []
        cols = {r[1] for r in q(state_db, "PRAGMA table_info(cron_jobs)")}
        conds, sel = [], []
        if "payload_model" in cols:
            conds.append(f"lower(trim(coalesce(payload_model,''))) LIKE '{provider}/%'")
            sel.append("payload_model")
        else:
            sel.append("NULL")
        if "payload_fallbacks_json" in cols:
            conds.append(f"lower(coalesce(payload_fallbacks_json,'')) LIKE '%{provider}/%'")
            sel.append("payload_fallbacks_json")
        else:
            sel.append("NULL")
        if not conds:
            return 0, []
        rows = q(state_db, f"SELECT {', '.join(sel)} FROM cron_jobs WHERE " + " OR ".join(conds))
    except (sqlite3.Error, C.NodeQueryError, OSError, IndexError, ValueError):
        return 0, []
    ids = set()
    for model, fallbacks in rows:
        refs = [model] if isinstance(model, str) else []
        try:
            fb = json.loads(fallbacks) if isinstance(fallbacks, str) else None
        except ValueError:
            fb = None
        if isinstance(fb, list):
            refs += [x for x in fb if isinstance(x, str)]
        for r in refs:
            m = ref_re.match(r)
            if m:
                ids.add(m.group(1)[:120])
    return len(rows), sorted(ids)[:200]


def plugin_snapshot(state_dir):
    names = set()
    state_dir = Path(state_dir)
    for sub in ("npm/projects", "extensions", "git"):
        d = state_dir / sub
        try:
            with os.scandir(d) as it:
                for e in it:
                    names.add(f"{sub}/" + re.sub(r"__openclaw-generation__g-[0-9a-f]+$", "", e.name))
        except OSError:
            continue
    return sorted(names)


def schema_meta_problems(state_dir, cls, pkg):
    probs = []
    sdb = Path(state_dir) / "state" / "openclaw.sqlite"

    def app_ok(v):
        # Measured on real 2026.9.9 and 2026.10.2 migrations (doctor + gateway): the state DB's primary row keeps
        # app_version NULL while agent DBs get the runtime version. A version written by an earlier 9.x gateway
        # (non-fast path) or kept on an agent DB already at the target schema is not a regression either.
        if v is None or v == pkg["version"]:
            return True
        try:
            return C.version_tuple(str(v)) <= C.version_tuple(pkg["version"])
        except (ValueError, TypeError):
            return False
    try:
        prim = schema_meta_primary(sdb) if sdb.exists() else None
        if not prim or prim.get("role") != "global" or prim.get("schema_version") != pkg["schema_state"] \
                or not app_ok(prim.get("app_version")):
            probs.append(f"state schema_meta primary {prim}")
        for aid, relp in sorted(cls.get("agent_paths", {}).items()):
            ap = schema_meta_primary(Path(state_dir) / relp)
            dirname = Path(relp).parent.parent.name
            if not ap or ap.get("role") != "agent" or ap.get("agent_id") != dirname \
                    or ap.get("schema_version") != pkg["schema_agent"] \
                    or not app_ok(ap.get("app_version")):
                probs.append(f"{relp} schema_meta primary {ap}")
        if sdb.exists() and "agent_databases" in table_names(sdb):
            for aid, sv in q(sdb, "SELECT agent_id, schema_version FROM agent_databases"):
                if sv != pkg["schema_agent"]:
                    probs.append(f"agent_databases[{aid}].schema_version {sv}")
    except (sqlite3.Error, C.NodeQueryError, C.SchemaUnknown, OSError) as exc:
        probs.append(f"schema_meta unreadable ({exc})")
    return probs


def primary_model_refs(cfg):
    """provider/model refs used as a primary model (defaults and per-agent), lower-cased."""
    out = set()

    def add(v):
        if isinstance(v, dict):
            v = v.get("primary")
        if isinstance(v, str) and "/" in v:
            out.add(v.strip().lower())
    agents = cfg.get("agents") if isinstance(cfg, dict) and isinstance(cfg.get("agents"), dict) else {}
    defaults = agents.get("defaults") if isinstance(agents.get("defaults"), dict) else {}
    add(defaults.get("model"))
    entries = agents.get("entries") if isinstance(agents.get("entries"), dict) else {}
    for e in entries.values():
        if isinstance(e, dict):
            add(e.get("model"))
    for e in agents.get("list") or []:
        if isinstance(e, dict):
            add(e.get("model"))
    return out


def models_status_problems(rc, data, auth_profiles, codex_allowed=False, primaries=None):
    """Returns [(code, message)]; code "warn" means log only (never HOLD).

    `models status --check` exits 1 for any route whose auth readiness is merely "indeterminate"
    (v99 docs/cli/models.md:91,108) — normal for Codex native logins and fallback providers, and the
    same on 2026.7. So only real regressions hold: a lost OpenAI/Codex OAuth login, or a non-
    indeterminate issue on a PRIMARY model route. Everything else is a WARN.
    codex_allowed: Codex was in use before the migration (canonical openai/* refs or the codex
    package), so openai routes on the Codex app-server are the 7.35 behaviour (contract addendum 2).
    """
    probs = []
    primaries = {p.lower() for p in (primaries or set())}
    primary_providers = {p.split("/", 1)[0] for p in primaries}
    if not isinstance(data, dict):
        if rc not in (0, 2):
            probs.append(("pc-models-status", f"models status --check rc {rc} without a usable JSON result"))
        else:
            probs.append(("pc-models-status", "models status returned no JSON"))
        return probs
    auth = data.get("auth") if isinstance(data.get("auth"), dict) else {}
    routes = auth.get("runtimeAuthRoutes") if isinstance(auth.get("runtimeAuthRoutes"), list) else []
    codex = [r for r in routes if isinstance(r, dict) and r.get("runtime") == "codex"]
    if codex and not codex_allowed:
        probs.append(("pc-codex-runtime", f"{len(codex)} model route(s) resolve to the codex runtime"))
    issues = auth.get("modelRouteIssues")
    for i in (issues if isinstance(issues, list) else []):
        if not isinstance(i, dict):
            probs.append(("warn", f"models status: route issue {i}"))
            continue
        ref = f"{i.get('provider')}/{i.get('model')}"
        kind = str(i.get("kind") or "")
        text = f"models status: {ref}: {kind}"
        if kind != "indeterminate" and ref.lower() in primaries:
            probs.append(("pc-models-status", f"primary model route {ref}: {kind}"))
        else:
            probs.append(("warn", text))
    missing = auth.get("missingProvidersInUse")
    if isinstance(missing, list) and missing:
        prim_missing = [m for m in missing if str(m).lower() in primary_providers]
        if prim_missing:
            probs.append(("pc-models-status", "primary model provider(s) without credentials: "
                          + ", ".join(map(str, prim_missing[:6]))))
        rest = [m for m in missing if m not in prim_missing]
        if rest:
            probs.append(("warn", "models status: providers in use without credentials: " + ", ".join(map(str, rest[:6]))))
    if rc not in (0, 2) and not any(c != "warn" for c, _ in probs):
        probs.append(("warn", f"models status --check rc {rc} (readiness not confirmed for some routes; not a migration regression)"))
    had_oauth = any(p.get("type") == "oauth" and p.get("provider") in ("openai", "openai-codex") for p in auth_profiles)
    if had_oauth:
        oauth = auth.get("oauth") if isinstance(auth.get("oauth"), dict) else {}
        profs = oauth.get("profiles") if isinstance(oauth.get("profiles"), list) else []
        openai = [x for x in profs if isinstance(x, dict) and x.get("type") == "oauth"
                  and x.get("provider") in ("openai", "openai-codex")]
        # "expired" only means the stored access token ran out (an idle install shows it before the
        # migration too); the gateway refreshes it on first use. Only a lost profile is a regression.
        if not any(x.get("status") in ("ok", "expiring", "expired") for x in openai):
            probs.append(("pc-models-status", "no usable OpenAI OAuth profile after migration (was present before)"))
        elif not any(x.get("status") in ("ok", "expiring") for x in openai):
            probs.append(("warn", "OpenAI OAuth access token is expired; OpenClaw refreshes it on first use - "
                                  "send one test message to an openai/* model after the upgrade"))
    return probs


def sessions_problems(rc, data, pinned, excluded, codex_allowed=False):
    if not isinstance(data, dict) or not isinstance(data.get("sessions"), list):
        return [f"sessions --json returned no usable result (rc {rc})"]
    probs = []
    rows = {}
    for r in data["sessions"]:
        if isinstance(r, dict) and isinstance(r.get("key"), str):
            rows[r["key"]] = r

    def rid(r):
        ar = r.get("agentRuntime")
        return ar.get("id") if isinstance(ar, dict) else None
    for key in pinned:
        r = rows.get(key)
        if r is not None and rid(r) not in ("openclaw", "pi"):
            probs.append(f"session {key}: runtime {rid(r)}")
    for key, r in rows.items():
        if key in excluded:
            continue
        if not codex_allowed and r.get("modelProvider") == "openai" and not r.get("acpRuntime") \
                and rid(r) == "codex":
            probs.append(f"session {key}: openai on codex runtime")
    return probs


def probe_ok(data, profile_id):
    if not isinstance(data, dict):
        return False
    auth = data.get("auth") if isinstance(data.get("auth"), dict) else {}
    probes = auth.get("probes") if isinstance(auth.get("probes"), dict) else {}
    results = probes.get("results") if isinstance(probes.get("results"), list) else []
    return any(isinstance(r, dict) and r.get("profileId") == profile_id and r.get("status") == "ok" for r in results)


def plugin_version_warnings(data, runtime):
    warns = []
    if data is None:
        return ["plugins list --json returned no parseable JSON"]

    def walk(x):
        if isinstance(x, dict):
            if isinstance(x.get("id"), str):
                yield x
            for v in x.values():
                yield from walk(v)
        elif isinstance(x, list):
            for v in x:
                yield from walk(v)
    for p in walk(data):
        spec = str(p.get("packageName") or p.get("package") or p.get("spec") or p.get("source") or "")
        ver = p.get("version")
        if p.get("enabled") is False or "@openclaw/" not in spec or not isinstance(ver, str):
            continue
        if C.version_tuple(ver) and C.version_tuple(ver) != C.version_tuple(runtime):
            warns.append(f"plugin {p['id']} is {ver}, runtime is {runtime}")
    return warns


# --- entry points ----------------------------------------------------------------------------------

def _try_lock(gp):
    import fcntl
    ensure_dirs(gp)
    fd = os.open(str(gp["LOCK"]), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def run_gate():
    """`OC_GATE_FROM_RUNSH=1 oc-upgrade gate`: rc 0 / 20 / 130 / 143 / 1."""
    gp = gpaths()
    _unlink(gp["HOLD"])  # B16: never reuse a stale reason
    STOP.clear()
    _STOP_SIG[0] = None
    old_handlers = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))
    install_signal_handlers()
    g = Gate()
    lock = _try_lock(gp)
    if lock is None:
        g.write_hold([finding("gate-busy", "hard", "another migration gate holds the lock", "precheck")], "precheck")
        return 20
    # run.sh already printed the `gate --plan` output (contract addendum 2 item 11): never print an
    # identical plan/WARN line twice; a decision that changed in between is still printed.
    shown = {x for x in os.environ.get("OC_GATE_PLAN_SHOWN", "").splitlines() if x.strip()}

    def emit_plan(line):
        if line not in shown:
            out(line)

    try:
        d = plan(apply=True, emit=emit_plan)
        if d["rc"] == 0:
            return 0
        if d["rc"] == 1:
            raise RuntimeError(f"planning failed: {d.get('reason')}")
        g.pkg = d.get("pkg")
        if d["rc"] == 3:
            # hold.txt only: a journal HOLD newer-state would outlive a backup restore
            g.write_hold([finding("newer-state", "hard", d["reason"], "precheck")], "precheck",
                         next_line=ADVICE["newer-state"])
            return 20
        if d["rc"] == 11:
            j = d.get("journal")
            if j is not None and (d.get("hold") or {}).get("code") == "interrupted-twice":
                g.j = j
                g.write_hold([finding("interrupted-twice", "hard", d["hold"].get("message", ""), d["hold"]["phase"])],
                             d["hold"]["phase"])
            return 20
        if d["action"] == "housekeeping":
            return 0
        g.start(d)
        return g.execute()
    except HoldError as h:
        g.write_hold(h.findings, h.phase, h.resume_after)
        return 20
    except (GateStopped, C.Stopped):
        sig = "SIGINT" if _STOP_SIG[0] == signal.SIGINT else "SIGTERM"
        if g.j is not None:
            g.j["status"] = "interrupted"
            g.history(f"interrupted by {sig} in {g.phase}")
            try:
                g.save()
            except OSError:
                pass
        g.say(f"interrupted by {sig} in {g.phase}; the next start resumes automatically (once)")
        return stop_rc()
    except BaseException as exc:  # noqa: BLE001 - spec §7: any unexpected error -> HOLD internal-error
        if isinstance(exc, SystemExit):
            raise
        tb = C.redact_text(traceback.format_exc())
        sys.stderr.write(tb)
        g._event(tb)
        try:
            g.write_hold([finding("internal-error", "hard", C.redact_text(f"{type(exc).__name__}: {exc}")[:400],
                                  g.phase)], g.phase)
        except BaseException as exc2:  # noqa: BLE001
            sys.stderr.write(f"[gate] could not write the HOLD: {exc2}\n")
        return 1
    finally:
        g.cleanup_tmp()
        try:
            os.close(lock)
        except OSError:
            pass
        try:
            signal.signal(signal.SIGTERM, old_handlers[0])
            signal.signal(signal.SIGINT, old_handlers[1])
        except (TypeError, ValueError):
            pass


GLM_MIN_RUNTIME = (2026, 9, 0, 0)


def glm_runtime_ok(version):
    """G1 needs the 2026.9+ reasoning_effort mapping (7.35 sends "high" for off and refuses max)."""
    v = C.version_tuple(version)
    return bool(v and v >= GLM_MIN_RUNTIME)


def dry_run(network=False, emit=out):
    """Read-only preview of a gate run: rc 0 would pass, 20 would HOLD, 1 error."""
    if not has_upgrade_sensitive_state():
        emit("[gate] dry-run: fresh install (no OpenClaw state) — nothing to migrate")
        return 0
    g = Gate(dry_run=True, network=network, emit=emit)
    try:
        pkg = C.runtime_package()
        g.pkg = pkg
        cfg = _read_cfg_lenient()
        cls = classify(g.gp["STATE"], cfg, pkg["schema_state"], pkg["schema_agent"], pkg["version"])
        marker = load_marker()
        marker_rt = bool(marker and marker.get("runtime") == pkg["version"])
        gate_needed = cls["schema_verdict"] == "gate" or (cls["files_verdict"] == "gate" and not marker_rt)
        emit(f"[gate] dry-run: {_summary_bits(pkg, cls)}")
        if cls["verdict"] == "newer":
            emit(f"[gate] dry-run: would HOLD newer-state: {'; '.join(cls['newer'])}")
            return 20
        if not gate_needed:
            emit(f"[gate] dry-run: nothing to migrate (marker: {(marker or {}).get('mode') or 'none'})")
            if isinstance(cfg, dict):  # G1 also runs in a maintenance gate (oc-upgrade retry --doctor + restart)
                for ln in mig().glm_thinking_preview(cfg, C.glm_thinking_option()):
                    emit("[gate] dry-run: " + ln)
            return 0
        mode = infer_mode(cls, cfg)
        emit(f"[gate] dry-run: a gate would run in mode {mode}")
        lines, findings = readiness(g, mode)
        for ln in lines:
            emit(ln)
        block = [f for f in findings if f.get("cls") in ("hard", "acceptable")]
        if block:
            emit("[gate] dry-run: would HOLD: " + ", ".join(dict.fromkeys(f["code"] for f in block)))
            return 20
        emit("[gate] dry-run: the precheck would pass")
        return 0
    except Exception as exc:  # noqa: BLE001
        emit(f"[gate] dry-run: error: {type(exc).__name__}: {exc}")
        return 1
    finally:
        g.cleanup_tmp()


def readiness(g, mode):
    """Shared by `gate --dry-run` and `oc-upgrade check` section I. Read-only."""
    lines = []
    F, parts = g.precheck_findings(mode, generic_only=(mode != "from-7x"))
    for f in F:
        lines.append(f"[gate]   {f['cls']:<10} {f['code']}: {f['message']}")
    lines.append("[gate]   precheck: " + "; ".join(parts))
    ao = g.facts.get("archive_opt") or {}
    if ao.get("mode") == "encrypted" and ao.get("recipient"):
        rt = (g.pkg or {}).get("version", "?")
        lines.append(f"[gate]   archive: encrypted to {C.short_recipient(ao['recipient'])} -> {g.gp['ARCHIVES']}/<run>/"
                     f"openclaw-state-<ts>-before-{rt}.tar.gz.age (no plaintext on disk)")
    elif ao.get("mode") == "off":
        lines.append("[gate]   archive: off (rollback only through the encrypted Home Assistant backup)")
    elif ao:
        lines.append("[gate]   archive: NOT CONFIGURED (the gate would HOLD; set gate_archive_age_recipient or "
                     "gate_archive: off)")
    M = mig()
    plan_entries = g.facts.get("cleanup_plan")
    if plan_entries is None:
        sf = M.classify_state_files(str(g.gp["STATE"]), g.cfg, from_checkpoint=startup_checkpoint(
            g.gp["STATE"] / "state" / "openclaw.sqlite"), accepted=set(), mode="from-7x" if mode == "from-7x" else "bump", query=_mq)
        plan_entries = sf.get("plan", [])
    rs = g.facts.get("retired_state") or g.retired_state("from-7x" if mode == "from-7x" else "bump")
    plan_entries = list(plan_entries) + list(rs.get("plan", []))
    counts = {}
    for e in plan_entries:
        if e.get("action") == "quarantine":
            counts[e.get("kind")] = counts.get(e.get("kind"), 0) + 1
    lines.append("[gate]   cleanup plan: " + (", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "nothing to move"))
    if mode == "from-7x" and g.cfg:
        _new, ledger, summary = M.premigrate_config(g.cfg, removals=rs.get("config_removals") or [])
        lines.append(f"[gate]   pre-migrate: explicit ids {', '.join(summary.get('explicit') or []) or 'none'}; "
                     f"{len(ledger)} config change(s); modelPolicy {{}}: "
                     f"{'yes' if summary.get('model_policy_written') else 'no'}")
        for e in ledger[:30]:
            lines.append(f"[gate]     {e.get('step')} {e.get('path')}")
        stores, _f = M.scan_sessions_files(str(g.gp["STATE"]))
        n = 0
        for relp, store in stores:
            _s, led, _sum = M.premigrate_sessions(store, relp)
            n += len(led)
        lines.append(f"[gate]   sessions: {n} runtime pin(s) would be written")
    if g.cfg:
        lines += ["[gate]   " + ln for ln in M.glm_thinking_preview(g.cfg, C.glm_thinking_option())]
    b = g.budget()
    lines.append(f"[gate]   doctor budget {C.fmt_duration(b['doctor_pass_seconds'])}/pass (S={b['s_mib']} MiB)")
    return lines, F


def hold_after_start(code, last_rc=None, emit=out):
    """`gate --hold-exit78` / `gate --hold-crash-loop <rc>`: always rc 0 (spec §10)."""
    gp = gpaths()
    g = Gate(emit=emit)
    try:
        try:
            g.pkg = C.runtime_package()
            cfg = _read_cfg_lenient()
            cls = classify(gp["STATE"], cfg, g.pkg["schema_state"], g.pkg["schema_agent"], g.pkg["version"])
            sub = cls["verdict"]
        except Exception as exc:  # noqa: BLE001
            cls, sub = None, "unknown"
            emit(f"WARN [gate] could not classify the state: {type(exc).__name__}: {exc}")
        what = "OpenClaw exited with code 78" if code == "exit78" else \
            f"OpenClaw kept crashing (crash loop; last exit code {last_rc})"
        if sub == "gate":
            msg = f"{what}; the state still needs migration: " + "; ".join((cls["gate"] + cls["files"])[:4])
            nxt = "oc-upgrade retry runs the gate again (archive per gate_archive, doctor), then restart the add-on"
        elif sub == "newer":
            msg = f"{what}; the state is newer than this runtime: " + "; ".join(cls["newer"][:3])
            nxt = "restore the Home Assistant backup that matches this add-on version"
        else:
            msg = f"{what} after migration (configuration, lock or gateway.mode problem)"
            nxt = ("run `openclaw config validate` (allowed in HOLD), check the gateway log "
                   "/tmp/openclaw/openclaw-<YYYY-MM-DD>.log, fix, then `oc-upgrade retry`; for plugin problems "
                   "`oc-upgrade retry --doctor` (re-runs doctor, updates plugins)")
        try:
            g.j = load_journal()
        except (OSError, ValueError):
            g.j = None
        if g.j is None:
            g.j = {"schema": 1, "run_id": None, "mode": None, "status": "done", "phases_done": [], "history": []}
        g.write_hold([finding(code, "hard", msg, "gateway")], "gateway", post_run=True, sub=sub, next_line=nxt)
        if g.j is not None:
            g.j["hold"]["last_rc"] = last_rc
            try:
                g.save()
            except OSError:
                pass
    except Exception as exc:  # noqa: BLE001 - must never fail; run.sh holds anyway
        emit(f"WARN [gate] could not record the hold: {type(exc).__name__}: {exc}")
        try:
            gp["UPG_DIR"].mkdir(parents=True, exist_ok=True)
            C.atomic_write_text(gp["HOLD"], f"OpenClaw is held — migration gate run n/a, phase gateway\n"
                                            f"Reason [{code}]: gateway exit {last_rc if last_rc is not None else 78}\n"
                                            "Next: oc-upgrade retry\nDetails: oc-upgrade status\n")
        except OSError:
            pass
    return 0


# --- retry / log / status ---------------------------------------------------------------------------

def _hold_codes_from_txt(text):
    return re.findall(r"^Reason \[([A-Za-z0-9_.-]+)\]", text or "", re.M)


def retry_cmd(args, emit=out):
    gp = gpaths()
    doctor = "--doctor" in args
    accept = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--accept" and i + 1 < len(args):
            accept += [c.strip() for c in args[i + 1].split(",") if c.strip()]
            i += 2
            continue
        if a.startswith("--accept="):
            accept += [c.strip() for c in a.split("=", 1)[1].split(",") if c.strip()]
        elif a not in ("--doctor", "--cancel"):
            emit(f"oc-upgrade retry: unknown argument {a}")
            return 2
        i += 1
    if "--cancel" in args:
        if gp["RETRY"].exists():
            _unlink(gp["RETRY"])
            emit("Retry request withdrawn.")
        else:
            emit("No retry request pending.")
        return 0
    try:
        j = load_journal() or {}
    except (OSError, ValueError) as exc:
        emit(f"Cannot read the gate journal ({exc}); nothing to retry.")
        return 1
    hold_txt = gp["HOLD"].read_text(encoding="utf-8", errors="replace") if gp["HOLD"].exists() else ""
    status = j.get("status")
    codes = list((j.get("hold") or {}).get("codes") or ([(j.get("hold") or {}).get("code")] if j.get("hold") else []))
    gate_txt = "migration gate" in hold_txt or "oc-upgrade gate" in hold_txt
    gate_hold = status in ("hold", "running", "interrupted") or gate_txt
    if not codes:
        codes = _hold_codes_from_txt(hold_txt)
    if hold_txt and not gate_txt and status not in ("hold", "running", "interrupted"):
        emit("The current HOLD is not a migration-gate hold (newer state or runtime integrity): restore the matching "
             "backup or reinstall the add-on; oc-upgrade retry cannot clear it.")
        return 1
    if not gate_hold and not (doctor and status == "done"):
        emit("Nothing to retry: the migration gate is not holding." +
             (" (Use `oc-upgrade retry --doctor` for a maintenance doctor run.)" if status == "done" else ""))
        return 1
    bad = sorted(set(codes) & NO_RETRY)
    if bad:
        emit(f"HOLD {', '.join(bad)} cannot be retried: restore the matching backup or reinstall the add-on.")
        return 1
    hold_acc = {f.get("code") for f in (j.get("hold") or {}).get("findings") or [] if f.get("cls") == "acceptable"}
    for c in accept:
        if c not in ACCEPTABLE and c not in hold_acc:
            emit(f"Code {c} cannot be accepted (hard HOLD codes need a fix). Acceptable codes: "
                 + ", ".join(sorted(ACCEPTABLE)))
            return 1
    prev = load_retry() or {}
    req = {"requested_at": C.utc_iso(), "doctor": bool(doctor or prev.get("doctor")),
           "accept": sorted(set(prev.get("accept") or []) | set(accept))}
    ensure_dirs(gp)
    C.atomic_write_json(gp["RETRY"], req)
    what = []
    if req["doctor"]:
        what.append("re-run doctor")
    if req["accept"]:
        what.append("accept " + ",".join(req["accept"]))
    emit(f"Retry requested{(' (' + '; '.join(what) + ')') if what else ''}. Restart the add-on to continue.")
    return 0


def log_cmd(args, emit=out):
    gp = gpaths()
    n_pass, lines = None, 200
    i = 0
    while i < len(args):
        if args[i] == "--pass" and i + 1 < len(args):
            n_pass = args[i + 1]
            i += 2
        elif args[i] == "--lines" and i + 1 < len(args):
            try:
                lines = max(1, int(args[i + 1]))
            except ValueError:
                emit("oc-upgrade log: --lines needs a number")
                return 2
            i += 2
        else:
            emit(f"oc-upgrade log: unknown argument {args[i]}")
            return 2
    try:
        j = load_journal() or {}
    except (OSError, ValueError):
        j = {}
    if not j.get("run_id"):
        emit("No gate run recorded.")
        return 0
    rd = gp["RUNS"] / j["run_id"]
    if n_pass is None:
        logs = sorted(rd.glob("doctor-pass*.log"))
        if not logs:
            emit(f"No doctor log in {rd}.")
            return 0
        path = logs[-1]
    else:
        path = rd / f"doctor-pass{n_pass}.log"
        if not path.exists():
            emit(f"No log {path}.")
            return 0
    data = path.read_bytes().decode("utf-8", "replace").splitlines()
    emit(f"== {path} (last {min(lines, len(data))} of {len(data)} lines, redacted)")
    for ln in data[-lines:]:
        emit(C.redact_text(ANSI_RE.sub("", ln)))
    return 0


# --- automatic deletion of gate archives and doctor captures (gate_cleanup_hours) ----------------

def captures_root(gp):
    """OpenClaw's doctor capture directory: <state dir>.update-captures (update-capture-paths in 2026.10)."""
    return Path(os.path.realpath(str(gp["STATE"])) + ".update-captures")


def rehearsal_root(gp):
    return gp["SHARE"] / "openclaw-rehearsal"


def stage_a_root(gp):
    """Stage A (0.5.93 era) plaintext rollback archives of the 7.x state."""
    return gp["STATE"] / "upgrade-backups"


def _run_journals(gp):
    """Every recorded gate run: runs/<id>/journal.json (copied when a new run starts) plus the current journal.
    A run id that is not one safe path component is ignored (it is joined into paths below)."""
    runs = {}
    for jp in sorted(gp["RUNS"].glob("*/journal.json")):
        j = C.load_json_or_none(jp)
        if isinstance(j, dict) and isinstance(j.get("run_id"), str) and _safe_id(j["run_id"]):
            runs[j["run_id"]] = j
    try:
        cur = load_journal()
    except (OSError, ValueError):
        cur = None
    cur = cur if isinstance(cur, dict) else None
    if cur and isinstance(cur.get("run_id"), str) and _safe_id(cur["run_id"]):
        runs[cur["run_id"]] = cur
    return runs, cur  # cur is returned as is: its status still pauses the cleanup


def _safe_id(s):
    return bool(SAFE_ID_RE.fullmatch(s)) and ".." not in s


def cleanup_blocked(gp, cur):
    """Never delete while a gate run is active, held or about to be retried (its archive is the rollback copy)."""
    if gp["HOLD"].exists():
        return "hold"
    if isinstance(cur, dict) and cur.get("status") in ("running", "interrupted", "hold"):
        return f"gate run {cur.get('run_id')} is {cur.get('status')}"
    if gp["RETRY"].exists():
        return "a retry request is pending"
    fd = _try_lock(gp)
    if fd is None:
        return "the gate is running"
    os.close(fd)
    return None


def run_captures(gp, j):
    """The doctor capture directories a gate run created: parsed from its doctor logs and validated (inside
    <state>.update-captures, OpenClaw's doctor-<uuid> name, a real directory). The owner's rule (no
    plaintext copies of secrets) wins over OpenClaw's own retention, so captures with outcome.json go too."""
    root = captures_root(gp)
    found = set()
    for log in sorted((gp["RUNS"] / str(j.get("run_id"))).glob("doctor-pass*.log")):
        try:
            text = log.read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        for line in text.splitlines():
            m = CAPTURE_RE.search(ANSI_RE.sub("", line))
            if m:
                found.add(m.group(1).rstrip("."))
    keep, refused = [], []
    for c in sorted(found):
        pth = Path(c)
        if os.path.islink(str(root)) or os.path.realpath(str(pth.parent)) != str(root):
            refused.append((c, "not inside " + str(root)))
        elif not CAPTURE_NAME_RE.match(pth.name):
            refused.append((c, "unexpected name"))
        elif os.path.islink(c):
            refused.append((c, "symlink"))
        elif os.path.isdir(c):
            keep.append(root / pth.name)
    return keep, refused


def _dir_bytes(d):
    total = 0
    for _p, st in C.walk_lstat(d):
        if stat.S_ISREG(st.st_mode):
            total += st.st_size
    return total


TOMB_PREFIX = ".oc-addon-deleting-"
REHEARSAL_FILES = ("openclaw-rehearsal.tar.gz", "openclaw-rehearsal.tar.gz.tmp", "openclaw-rehearsal.tar.gz.age",
                   "openclaw-rehearsal.tar.gz.age.tmp", "manifest.txt")
REHEARSAL_DIR_RE = re.compile(r"^\d{8}-\d{6}(?:-[A-Za-z0-9]{6})?$")
STAGE_A_RE = re.compile(r"^openclaw-state-[0-9]{8}-[0-9]{6}-before-[0-9][0-9A-Za-z.+-]*\.tar\.gz(?:\.tmp)?$")


def _open_parent(base):
    """fd of the directory base (not a symlink itself; its own parents are resolved once)."""
    return open_dir_nofollow(os.path.dirname(str(base)), os.path.basename(str(base)))


def _delete_entry(base, name):
    """Delete the directory base/name. Everything goes through a directory fd: the directory is renamed to a
    tombstone first (an interrupted delete never leaves a half archive under its real name) and removed with
    shutil.rmtree(dir_fd=...), so a symlink that another /share writer swaps in is never followed; a symlink
    entry is removed as a link. Raises OSError when something is left (a pass never claims a deletion that did
    not happen)."""
    if not name or "/" in name or name in (".", ".."):
        raise OSError(errno.EINVAL, "invalid name", name)
    bfd = _open_parent(base)
    try:
        st = os.stat(name, dir_fd=bfd, follow_symlinks=False)
        if not stat.S_ISDIR(st.st_mode):
            os.unlink(name, dir_fd=bfd)  # a planted link or file: only the entry itself goes
            return 0
        size = _dir_bytes(Path(base) / name)  # informational only
        tomb = name if name.startswith(TOMB_PREFIX) else TOMB_PREFIX + name
        if tomb != name:
            os.rename(name, tomb, src_dir_fd=bfd, dst_dir_fd=bfd)
        shutil.rmtree(tomb, dir_fd=bfd, ignore_errors=True)
        try:
            os.stat(tomb, dir_fd=bfd, follow_symlinks=False)
        except FileNotFoundError:
            return size
        raise OSError(errno.ENOTEMPTY, "not completely removed", str(Path(base) / tomb))
    finally:
        os.close(bfd)


def _delete_export(base, name):
    """A rehearsal export directory <ts>: unlink only the export's own files (through the directory's fd, never
    following a link), then remove the directory if nothing else is in it."""
    bfd = _open_parent(base)
    try:
        dfd = os.open(name, _DIR_NOFOLLOW, dir_fd=bfd)
        size = 0
        try:
            for f in REHEARSAL_FILES:
                try:
                    st = os.stat(f, dir_fd=dfd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    continue
                os.unlink(f, dir_fd=dfd)
                size += st.st_size if stat.S_ISREG(st.st_mode) else 0
        finally:
            os.close(dfd)
        try:
            os.rmdir(name, dir_fd=bfd)
        except OSError as exc:
            if exc.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                raise
        return size
    finally:
        os.close(bfd)


def _delete_file(base, name):
    """A single regular file base/name (Stage A archive), unlinked through the directory's fd."""
    bfd = _open_parent(base)
    try:
        st = os.stat(name, dir_fd=bfd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            raise OSError(errno.EISDIR, "is a directory", str(Path(base) / name))
        os.unlink(name, dir_fd=bfd)
        return st.st_size if stat.S_ISREG(st.st_mode) else 0
    finally:
        os.close(bfd)


def _safe_delete(gp, p):
    """Dispatch by the cleanup root a target belongs to; anything else is refused."""
    base, name = p.parent, p.name
    if base == rehearsal_root(gp):
        return _delete_export(base, name)
    if base == stage_a_root(gp):
        return _delete_file(base, name)
    if base in (gp["ARCHIVES"], captures_root(gp)):
        return _delete_entry(base, name)
    raise OSError(errno.EPERM, "outside the cleanup roots", str(p))


def _delete_tree(d):
    return _delete_entry(d.parent, d.name)


def _archive_dir_ok(gp, d):
    arch = gp["ARCHIVES"]
    return (not os.path.islink(str(arch)) and d.parent == arch and RUN_ID_RE.match(d.name)
            and d.is_dir() and not os.path.islink(str(d)))


def _mtime_utc(p):
    try:
        return datetime.fromtimestamp(os.lstat(p).st_mtime, timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def run_due_base(j):
    """Retention starts when the run finished, or later when a hold after the run (exit 78, crash loop) was
    cleared: the archive must outlive the last moment the migrated state was shown not to work."""
    base = _parse_backup_date(j.get("finished_at"))
    if base is None:
        return None
    for h in j.get("history") or []:
        if isinstance(h, dict) and str(h.get("event", "")).startswith("journal "):
            at = _parse_backup_date(h.get("at"))
            if at is not None and at > base:
                base = at
    return base


def cleanup_targets(gp, now, hours):
    """[(run_id or None, label, due_utc, [paths], kept)] for every finished run plus orphaned archives,
    leftover tombstones, rehearsal exports (encrypted or plaintext) and, once a 2026.8+ migration is recorded,
    the Stage A plaintext archives of the 7.x state (journal-independent ones by modification time)."""
    runs, cur = _run_journals(gp)
    out_ = []
    referenced = set()
    for rid, j in sorted(runs.items()):
        adir = gp["ARCHIVES"] / rid
        referenced.add(rid)
        fin = run_due_base(j)
        if fin is None:
            continue  # not finished by this gate (held, abandoned): an archive of it is handled as an orphan
        due = fin + timedelta(hours=hours)
        paths, kept = [], []
        if os.path.lexists(str(adir)):
            if _archive_dir_ok(gp, adir):
                paths.append(adir)
            else:
                kept.append((str(adir), "not a plain run directory"))
        caps, refused = run_captures(gp, j)
        paths += caps
        kept += refused
        out_.append((rid, f"run {rid}", due, paths, kept))
    unfinished = {rid for rid, j in runs.items() if not j.get("finished_at")}
    # the current run's archive is its rollback copy while that run can still continue (closed runs: abandoned,
    # or done through bookkeeping without finished_at, are handled like orphans)
    active = (cur.get("run_id") if isinstance(cur, dict) and cur.get("status") not in ("done", "abandoned")
              else None)
    if gp["ARCHIVES"].is_dir() and not os.path.islink(str(gp["ARCHIVES"])):
        for d in sorted(gp["ARCHIVES"].iterdir()):
            if d.name in referenced and d.name not in unfinished:
                continue
            if d.name.startswith(TOMB_PREFIX):
                out_.append((None, f"leftover {d.name}", now, [d], []))
                continue
            if not _archive_dir_ok(gp, d) or d.name == active:
                continue
            mt = _mtime_utc(d)
            if mt is not None:
                out_.append((None, f"orphaned archive {d.name}", mt + timedelta(hours=hours), [d], []))
    caps = captures_root(gp)
    if caps.is_dir() and not os.path.islink(str(caps)):
        for d in sorted(caps.iterdir()):  # a capture delete interrupted after its rename
            if (d.name.startswith(TOMB_PREFIX) and CAPTURE_NAME_RE.match(d.name[len(TOMB_PREFIX):])
                    and not os.path.islink(str(d)) and d.is_dir()):
                out_.append((None, f"leftover {d.name}", now, [d], []))
    reh = rehearsal_root(gp)
    if reh.is_dir() and not os.path.islink(str(reh)):
        for d in sorted(reh.iterdir()):
            if not REHEARSAL_DIR_RE.match(d.name) or os.path.islink(str(d)) or not d.is_dir():
                continue
            files = [d / f for f in REHEARSAL_FILES[:4] if os.path.isfile(d / f) and not os.path.islink(d / f)]
            stamps = [t for t in (_mtime_utc(f) for f in files) if t is not None]
            if stamps:
                kind = "plaintext" if any(f.name.startswith("openclaw-rehearsal.tar.gz") and
                                          not f.name.endswith((".age", ".age.tmp")) for f in files) else "encrypted"
                out_.append((None, f"{kind} rehearsal export {d.name}", max(stamps) + timedelta(hours=hours),
                             [d], []))
    marker = C.load_json_or_none(gp["MARKER"])
    sa = stage_a_root(gp)
    if (isinstance(marker, dict) and (C.version_tuple(str(marker.get("runtime") or "")) or (0,)) >= (2026, 8, 0)
            and sa.is_dir() and not os.path.islink(str(sa))):
        done_at = _parse_backup_date(marker.get("completed_at"))
        for f in sorted(sa.iterdir()):
            if not STAGE_A_RE.match(f.name) or os.path.islink(str(f)) or not f.is_file():
                continue
            mt = _mtime_utc(f)
            if mt is None:
                continue
            base = max(mt, done_at) if done_at else mt
            out_.append((None, f"Stage A plaintext archive {f.name}", base + timedelta(hours=hours), [f], []))
    return out_


def cleanup_pass(now=None, hours=None, emit=out, state=None):
    """One deletion pass: everything whose due time has passed. Logs once per run (announcement, deletion).
    One bad target never stops the pass: it is reported and the next target is handled."""
    gp = gpaths()
    hours = C.gate_options()["cleanup_hours"] if hours is None else hours
    state = state if state is not None else {}
    if not hours:
        return 0
    now = now or C.utc_now()
    import fcntl
    ensure_dirs(gp)
    lk = os.open(str(gp["GATE"] / ".cleanup.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return 0
        _runs, cur = _run_journals(gp)
        why = cleanup_blocked(gp, cur)
        if why:
            if state.get("paused") != why:
                emit(f"[cleanup] paused: {why}")
            state["paused"] = why
            return 0
        state.pop("paused", None)
        deleted = 0
        errors = state.setdefault("errors", set())
        for rid, label, due, paths, kept in cleanup_targets(gp, now, hours):
            if STOP.is_set():
                break
            try:
                deleted += _cleanup_target(gp, now, rid, label, due, paths, kept, emit)
                errors.discard(label)
            except Exception as exc:  # noqa: BLE001 (report, then go on with the next target)
                if label not in errors:
                    emit(f"WARN [cleanup] {label}: {type(exc).__name__}: {C.redact_text(str(exc))[:200]}")
                    errors.add(label)
        return deleted
    finally:
        os.close(lk)


def _cleanup_target(gp, now, rid, label, due, paths, kept, emit):
    rec_path = gp["RUNS"] / rid / "cleanup.json" if rid else None
    rec = C.load_json_or_none(rec_path) if rec_path else None
    rec = rec if isinstance(rec, dict) else {"schema": 1}
    dirty = False
    for path, reason in kept:
        key = f"kept:{path}"
        if not rec.get(key):
            emit(f"WARN [cleanup] {label}: kept {path}: {reason}")
            rec[key] = dirty = True
    live = [p_ for p_ in paths if os.path.lexists(str(p_))]
    if not live:
        if rec.get("deleted_at") is None and rec.get("due_at"):
            rec["deleted_at"] = C.utc_iso(now)
            dirty = True
        if dirty and rec_path and rec_path.parent.is_dir():
            C.atomic_write_json(rec_path, rec)
        return 0
    if now < due:
        if rec_path and not rec.get("announced_at"):
            rec.update({"due_at": C.utc_iso(due), "announced_at": C.utc_iso(now)})
            emit(f"[cleanup] {label}: {len(live)} item(s) (archive / doctor captures) will be deleted at "
                 f"{C.utc_iso(due)}")
            dirty = True
        if dirty and rec_path and rec_path.parent.is_dir():
            C.atomic_write_json(rec_path, rec)
        return 0
    gone = []
    for p_ in live:
        if STOP.is_set():
            break
        try:
            gone.append({"path": str(p_), "bytes": _safe_delete(gp, p_)})
        except OSError as exc:
            emit(f"WARN [cleanup] {label}: could not delete {p_}: {exc.strerror or exc}")
    if gone:
        emit(f"[cleanup] {label}: deleted {len(gone)} item(s), {C.human(sum(g['bytes'] for g in gone))}: "
             + ", ".join(g["path"] for g in gone[:4]) + (" ..." if len(gone) > 4 else ""))
        if rec_path and rec_path.parent.is_dir():
            rec.update({"due_at": rec.get("due_at") or C.utc_iso(due), "deleted_at": C.utc_iso(now)})
            rec.setdefault("deleted", []).extend(gone)
            dirty = True
    if dirty and rec_path and rec_path.parent.is_dir():
        C.atomic_write_json(rec_path, rec)
    return len(gone)


def cleanup_loop(emit=out):
    """Started by run.sh next to the gateway (never during a gate run or HOLD): a pass now, then hourly.
    With gate_cleanup_hours 0 it idles and re-reads the option at every check (it never exits early)."""
    install_signal_handlers()
    STOP.clear()
    hours = C.gate_options()["cleanup_hours"]
    if hours:
        emit(f"[cleanup] gate archives and doctor captures are deleted {hours} h after their gate run (checked hourly)")
    else:
        emit("[cleanup] gate_cleanup_hours=0: automatic deletion is off (oc-upgrade cleanup lists what to delete)")
    state = {}
    while not STOP.is_set():
        hooks = load_hooks()
        now = C.utc_now() + timedelta(seconds=float(hooks.get("cleanup_clock_offset_s") or 0))
        try:
            cleanup_pass(now=now, hours=C.gate_options()["cleanup_hours"], emit=emit, state=state)
        except Exception as exc:  # noqa: BLE001 (the loop must survive one bad pass)
            emit(f"WARN [cleanup] pass failed: {type(exc).__name__}: {C.redact_text(str(exc))[:200]}")
        STOP.wait(float(hooks.get("cleanup_interval_s") or CLEANUP_INTERVAL_S))
    return stop_rc()


def cleanup_cmd(args, emit=out):
    """oc-upgrade cleanup            list what is deleted when (read-only)
       oc-upgrade cleanup --apply    delete everything that is due now
       (run.sh runs `cleanup --loop` next to the gateway)"""
    gp = gpaths()
    if args == ["--loop"]:
        if os.environ.get("OC_GATE_FROM_RUNSH") != "1":
            emit("oc-upgrade cleanup --loop is started by the add-on itself")
            return 2
        return cleanup_loop(emit)
    if args not in ([], ["--apply"]):
        emit("usage: oc-upgrade cleanup [--apply]")
        return 2
    hours = C.gate_options()["cleanup_hours"]
    now = C.utc_now()
    _runs, cur = _run_journals(gp)
    why = cleanup_blocked(gp, cur)
    emit(f"gate_cleanup_hours={hours}" + (" (automatic deletion off)" if not hours else "")
         + (f"; paused: {why}" if why else ""))
    for rid, label, due, paths, kept in cleanup_targets(gp, now, hours or 0):
        live = [p_ for p_ in paths if os.path.lexists(str(p_))]
        if not live:
            verdict = "nothing left"
        elif not hours:
            verdict = "kept (gate_cleanup_hours=0)"
        else:
            verdict = "due now" if now >= due else f"due {C.utc_iso(due)}"
        emit(f"  {label}: {verdict}")
        for p_ in live:
            try:
                size = _dir_bytes(p_) if p_.is_dir() and not p_.is_symlink() else os.lstat(p_).st_size
            except OSError:
                size = None
            emit(f"    {p_} ({C.human(size)})")
        for path, reason in kept:
            emit(f"    kept {path}: {reason}")
    if args == ["--apply"]:
        if not hours:
            emit("gate_cleanup_hours=0: nothing is deleted automatically; delete the listed paths yourself")
            return 0
        if why:
            emit(f"not deleting now: {why}")
            return 1
        n = cleanup_pass(now=now, hours=hours, emit=emit)
        emit(f"deleted {n} item(s)")
    return 0


def status_lines():
    gp = gpaths()
    L = []
    try:
        j = load_journal()
    except (OSError, ValueError) as exc:
        j = None
        L.append(f"Gate journal unreadable: {exc}")
    if j:
        L.append(f"Gate run {j.get('run_id')}: mode {j.get('mode')}, status {j.get('status')}, phase {j.get('phase')}, "
                 f"started {j.get('started_at')}, finished {j.get('finished_at') or '-'}")
        L.append(f"  phases done: {', '.join(j.get('phases_done') or []) or '-'}; first write: "
                 f"{j.get('first_write_at') or 'none'}; auto-resumes {j.get('auto_resumes', 0)}/1")
        for d in j.get("doctor") or []:
            L.append(f"  doctor pass {d.get('pass')}: rc {d.get('rc')} in {C.fmt_duration(d.get('duration_s') or 0)}"
                     f"{' (' + d['code'] + ')' if d.get('code') else ''}")
        h = j.get("hold")
        if h:
            L.append(f"  HOLD {', '.join(h.get('codes') or [h.get('code')])} in {h.get('phase')}: {h.get('message')}")
            L.append(f"  acceptable: {'yes' if h.get('acceptable') else 'no'}; next: {h.get('next') or 'oc-upgrade retry'}")
            acc = [f["code"] for f in h.get("findings") or [] if f.get("cls") == "acceptable"]
            if acc:
                L.append(f"  accept: oc-upgrade retry --accept {','.join(dict.fromkeys(acc))}")
        if j.get("accepted"):
            L.append(f"  accepted codes: {', '.join(j['accepted'])}")
        a = j.get("archive") or {}
        cl = C.load_json_or_none(gp["RUNS"] / str(j.get("run_id")) / "cleanup.json") or {}
        when = f"; deleted {cl['deleted_at']}" if cl.get("deleted_at") else \
            (f"; auto-delete due {cl['due_at']}" if cl.get("due_at") else "")
        if a.get("mode") == "off":
            L.append(f"  archive: off for this run (gate_archive: off){when}")
        elif a.get("mode") == "encrypted":
            L.append(f"  archive: encrypted (age, {C.short_recipient(a.get('recipient'))}) {a.get('dir')}/{a.get('file')} "
                     f"({C.human(a.get('size'))}, sha256 {str(a.get('sha256'))[:12]}…){when}")
        elif a:
            L.append(f"  archive: {a.get('dir')}/{a.get('file')} PLAINTEXT (0.5.94-full1) ({C.human(a.get('size'))}, "
                     f"sha256 {str(a.get('sha256'))[:12]}…){when}")
        hb = j.get("ha_backup")
        if isinstance(hb, dict):
            L.append(f"  HA backup checked: '{hb.get('name')}' ({hb.get('slug')}, {hb.get('date')}, "
                     f"add-on {hb.get('addon_version') or '?'})")
        g1 = j.get("glm_thinking")
        if isinstance(g1, dict):
            refs = ", ".join(g1.get("refs") or []) or "-"
            if g1.get("applied"):
                L.append(f"  GLM thinking levels (G1): applied to {refs} (transform-ledger.json, step G1)")
            elif g1.get("pending"):
                L.append(f"  GLM thinking levels (G1): interrupted for {refs}; undone and repeated on the next run")
            else:
                L.append(f"  GLM thinking levels (G1): not applied to {refs} ({g1.get('reason')})")
    else:
        L.append("Gate: no run recorded.")
    m = load_marker()
    L.append(f"Migrated marker: {m.get('runtime')} ({m.get('mode')}, run {m.get('run_id')}, {m.get('completed_at')})"
             if m else "Migrated marker: none")
    r = load_retry()
    if r:
        L.append(f"Pending retry request: doctor={r.get('doctor')} accept={','.join(r.get('accept') or []) or '-'} "
                 "(runs on the next add-on start)")
    o = C.gate_options()
    ao = o["archive"]
    L.append(f"Gate options: gate_archive {ao['mode'] or '?'}"
             + (f" to {C.short_recipient(ao['recipient'])}" if ao.get("recipient") else "")
             + (f" (problem: {ao['problem']})" if ao.get("problem") else "")
             + f"; delete archives/doctor captures {o['cleanup_hours']} h after a run (0 = never); "
             f"backup max age {o['backup_max_age_hours']} h")
    archives = sorted(gp["ARCHIVES"].glob("*/*.tar.gz")) + sorted(gp["ARCHIVES"].glob("*/*.tar.gz.age"))
    L.append("Gate archives in /share:" if archives else "Gate archives in /share: none")
    for a in archives:
        sums = (a.parent / "SHA256SUMS")
        sha = sums.read_text(encoding="utf-8", errors="replace").split()[0][:12] if sums.exists() else "?"
        try:
            size = a.stat().st_size
        except OSError:
            size = None
        kind = "encrypted" if a.name.endswith(".age") else "PLAINTEXT from 0.5.94-full1: unencrypted secrets"
        L.append(f"  {a} ({C.human(size)}, sha256 {sha}…, {kind})")
    caps = captures_root(gp)
    if caps.is_dir():
        n = sum(1 for x in caps.iterdir() if CAPTURE_NAME_RE.match(x.name.removeprefix(TOMB_PREFIX)))
        L.append(f"Doctor captures: {n} in {caps} (pre-repair database copies; deleted with their gate run)")
    qd = gp["QUAR"]
    if qd.exists():
        n = sum(1 for _p, st in C.walk_lstat(qd) if not stat.S_ISDIR(st.st_mode) and _p.name != "MANIFEST.json")
        L.append(f"Quarantine: {qd} ({n} files)")
    baks = list(gp["STATE"].rglob("*.pre-startup-migration-*.bak")) if gp["STATE"].exists() else []
    if baks:
        total = 0
        for b in baks:
            try:
                total += b.stat().st_size
            except OSError:
                pass
        L.append(f"Doctor pre-migration backups: {len(baks)} ({C.human(total)})")
    led = C.load_json_or_none(gp["LEDGER"])
    if isinstance(led, dict):
        L.append(f"Pins ledger: {len(led.get('entries') or [])} written, {len(led.get('skipped') or [])} skipped")
    return L
