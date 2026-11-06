"""
Migration gate for the bundled OpenClaw runtime (2026.7.x -> 2026.9+/2026.10.x, later bumps).

Phases (spec §7): 1 precheck (incl. the encrypted Home Assistant backup, the rollback point), 2 cleanup/quarantine,
3 pre-migrate (R1-R5, from-7x), 4 doctor pass 1, 5 fixups (F1-F4, from-7x), 6 doctor pass 2 (+3),
7 postconditions, 8 pins (from-7x), finalize (marker). There is no archive of its own (0.5.94-full3).

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
import glob
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import signal
import sqlite3
import stat
import sys
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

PHASES = ("precheck", "cleanup", "premigrate", "doctor1", "fixups", "doctor2",
          "postconditions", "pins", "finalize")
PHASE_NO = {"precheck": 1, "cleanup": 2, "premigrate": 3, "doctor1": 4, "fixups": 5,
            "doctor2": 6, "postconditions": 7, "pins": 8, "finalize": 8}
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
    "data-outside-config",  # acceptable once the encrypted backup also holds that folder (a full backup)
    # full5 prep (OpenClaw 2026.10.5+, runtime_caps): retired runtime files OpenClaw has not imported (accepting
    # moves them to quarantine) and a failed Skill Workshop export before doctor retires the proposals
    "acp-ledger-unimported", "voicewake-unimported", "conversation-bindings-unimported", "plugin-approvals-unimported",
    "restart-sentinel-unimported", "sandbox-registry-unimported",
    "skill-workshop-export-failed",
    # doctor rc 0 that still reports retired pre-July-2026 files it left unchanged (2026.10.5+ only: the
    # doctor:sandbox step only warns; runtime_caps)
    "doctor-retired-warning",
})
NO_RETRY = frozenset({"newer-state", "runtime-integrity"})
# HOLD codes of the gate archive of 0.5.94-full1/full2 (removed in full3): a journal may still hold one
REMOVED_HOLDS = frozenset({"archive-key-missing", "archive-key-invalid", "archive-age-missing", "archive-failed",
                           "archive-verify-failed", "archive-timeout", "archive-missing", "low-disk-share"})
REMOVED_HOLD_ADVICE = ("this check was removed in 0.5.94-full3 (the encrypted Home Assistant backup is the only "
                       "rollback point): oc-upgrade retry, then restart the add-on")
POST_RUN_HOLDS = frozenset({"exit78", "crash-loop"})
HOOK_KEYS = ("raise_in_phase", "doctor_cmd", "skip_network_check", "accept", "skip_cleanup_kinds",
             "doctor_timeout_s", "skip_space_check", "skip_backup_check", "supervisor_url",
             "supervisor_token_file", "cleanup_interval_s", "cleanup_clock_offset_s", "plugin_sync_budget_s",
             "plugin_probe_timeout_s")

DOCTOR_MIRROR_CAP = 3000
HEARTBEAT_S = 60
DOCTOR_KILL_AFTER = 600
DOCTOR_STOP_GRACE = 240
BACKUP_SKEW_S = 600
CLEANUP_INTERVAL_S = 3600
BACKUP_VERSION_LOOKUPS = 50  # recent encrypted backups with this add-on whose add-on version the precheck reads
RUN_ID_RE = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{6}\Z")
SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")  # one path component, never ".."
# OpenClaw 2026.10 doctor: "Pre-repair state retained for manual recovery at <dir>/manifest.json."
CAPTURE_RE = re.compile(r"Pre-repair state retained for manual recovery at (\S+)/manifest\.json")
CAPTURE_NAME_RE = re.compile(r"^doctor-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
# A5/A7: the plaintext files a gate run keeps in runs/<id>/: its copies of openclaw.json (gateway token, literal
# provider and channel keys) and the saved output of `openclaw models status` / `models auth` (OpenClaw's masked key
# fragments, profile ids with e-mail addresses). They go with the doctor captures (owner rule: no plaintext secrets
# outside the encrypted Home Assistant backup); the run's journal, logs, ledger and redacted exports stay.
RUN_PLAINTEXT_RE = re.compile(r"^(?:config\.[A-Za-z0-9_.-]{1,80}|pc-(?:models-status|probe|auth-list|auth-order))"
                              r"\.json\Z")
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

# full5 prep: shared by the *-unimported codes (advice_for appends the accept hint)
RETIRED_RUNTIME_ADVICE = ("OpenClaw 2026.10.4 (0.5.94-full4) imports this file only in a doctor run; if its gate ran "
                          "on this state, that doctor could not import the file either (see its warning in the log of "
                          "that gate run), so going back to 0.5.94-full4 keeps nothing. Accepting keeps the file in "
                          "the gate's quarantine (/config/.openclaw-upgrade/gate/quarantine/<run>/) and it is in the "
                          "encrypted backup. Only if that doctor run failed for a transient reason: restore the "
                          "encrypted backup of 0.5.94-full4, run oc-upgrade retry --doctor there, then update again")

ADVICE = {
    "runtime-schema-unknown": "the add-on image is broken (OpenClaw package lacks schema targets): reinstall or rebuild the add-on",
    "node-runtime": "the bundled Node.js cannot run this OpenClaw: reinstall or rebuild the add-on",
    "openclaw-running": "another OpenClaw process is running: stop it (restart the add-on), then oc-upgrade retry",
    "gate-busy": "another migration gate is running: wait for it, or restart the add-on",
    "config-missing": "restore openclaw.json with oc-config restore (oc-config list shows the snapshots), or restore the "
                      "add-on from the encrypted Home Assistant backup, then oc-upgrade retry",
    "config-unreadable": "fix openclaw.json (strict JSON required; JSON5 comments are unsupported), then oc-upgrade retry",
    "config-includes": "inline the $include files into openclaw.json, then oc-upgrade retry",
    "state-symlink": "replace the symlink by the real directory (or bind-mount it), then oc-upgrade retry",
    "newer-state": "restore the Home Assistant backup that matches this add-on version",
    "not-pre-journal": "restore the 0.5.93 backup (the state is not a clean 2026.7.x state)",
    "ha-backup-missing": "create an encrypted Home Assistant backup that includes this add-on before updating (Settings > "
                         "System > Backups, add-on stopped, stored locally or on a network mount: cloud-only copies are "
                         "not visible to the add-on), then oc-upgrade retry",
    "data-outside-config": "move the agent or workspace below /config, or make sure the encrypted Home Assistant "
                           "backup also holds that folder (a full backup includes /share and /media), then "
                           "oc-upgrade retry --accept data-outside-config",
    "ha-backup-unverified":"the Supervisor backup list could not be read (see the reason): make sure an encrypted backup "
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
    "low-disk-tmp": "free space for SQLite temporary files (/tmp, /var/tmp), then oc-upgrade retry",
    "sqlite-corrupt": "restore the add-on from the encrypted Home Assistant backup (quick_check failed; Settings > "
                      "System > Backups), then oc-upgrade retry",
    "cleanup-failed": "check permissions under /config/.openclaw-upgrade, then oc-upgrade retry",
    "premigrate-failed": "check free space and permissions, then oc-upgrade retry",
    "config-heartbeat-hours": "correct the listed heartbeat.activeHours values in openclaw.json (HH:MM, 24:00 only as "
                              "end) or remove that activeHours, then oc-upgrade retry",
    "config-retired-keys": "change or remove the listed settings in openclaw.json as the reason says (every OpenClaw "
                           "2026.10 refuses them; OpenClaw 2026.7.35 of 0.5.93 does not use them), then oc-upgrade retry",
    "retired-state-outside": "move the listed pre-July-2026 files away by hand (they are in your backup), then oc-upgrade retry",
    "retired-state-uninspectable": "fix or remove the listed paths (they must be directories or absent), then oc-upgrade retry",
    "retired-memory-index": "on 0.5.93 run `openclaw memory index --agent <id>` for each listed agent (2026.7.35 converts "
                            "the index), then oc-upgrade retry",
    "pre-july-schema": "restore a backup taken after a clean 0.5.93 start (pre-July-2026 databases are not migrated by "
                       "OpenClaw 2026.10)",
    "telegram-spool-unsupported": "rename or move the listed telegram/ingress-spool-* entries, then oc-upgrade retry",
    "doctor-retired-format": "doctor refused pre-July-2026 settings or files (see the reason): remove or move them "
                             "(they are in your encrypted Home Assistant backup), "
                             "then oc-upgrade retry; a plain retry repeats the refusal",
    "doctor-held-back": "doctor held back agent databases: re-register the agent (OC_ADDON_UNSAFE=1 openclaw agents add <id> --workspace <ws> --agent-dir <dir> --non-interactive) or restore the backup, then oc-upgrade retry",
    "doctor-migration-refused": "fix the item doctor reported (oc-upgrade log), then oc-upgrade retry",
    "doctor-maintenance-refused": "oc-upgrade retry (doctor resumes from its last committed step); if the reason mentions "
                                  "a different PID namespace, wait 90 s after the previous stop first",
    "doctor-plugin-load": "make sure the network is available, then oc-upgrade retry",
    "no-network": "make the npm registry reachable (network, DNS, proxy), then oc-upgrade retry; accepting it makes "
                  "doctor retry npm for a long time (see the reason)",
    "doctor-config-write": "oc-upgrade retry",
    "doctor-backup-unverifiable": "data at risk: doctor could not verify its own pre-migration SQLite copies "
                                  "(*.pre-startup-migration-*.bak / .scoped.bak beside the databases). Restore the "
                                  "add-on from the encrypted Home Assistant backup (the rollback point; never copy a "
                                  ".bak or .scoped.bak over a database by hand), or oc-upgrade retry to let doctor "
                                  "try again",
    "doctor-incomplete": "oc-upgrade retry (doctor resumes from its last committed step)",
    "doctor-blocked": "fix what doctor's [error] lines name (the reason lists them; oc-upgrade log shows each with its "
                      "fix: hint): edit the openclaw.json values it rejects (openclaw config validate lists them; "
                      "openclaw config set/unset are refused during a HOLD), or remove the blocker of a deferred "
                      "migration, then oc-upgrade retry (doctor resumes from its last committed step)",
    "doctor-failed": "see oc-upgrade log, fix the reported check, then oc-upgrade retry",
    "doctor-timeout": "oc-upgrade retry (doctor resumes; it is not re-run automatically in the same start)",
    "doctor-interrupted": "oc-upgrade retry",
    "doctor-crashed": "doctor was killed (out of memory?): free memory (stop other add-ons), then oc-upgrade retry",
    "doctor-invocation": "the doctor command line was refused (broken image?): reinstall the add-on, then oc-upgrade retry",
    "interrupted-twice": "the gate was interrupted twice: make sure nothing stops the add-on during the migration, then oc-upgrade retry",
    "fixups-invalid": "the post-doctor fixups produced an invalid config (restored): see oc-upgrade status, then oc-upgrade retry",
    "pc-schema": "the databases are not at the target schema: oc-upgrade retry --doctor; if the reason names a store "
                 "doctor held back, first remove that agent from openclaw.json (agents.list) if you no longer use "
                 "it, or restore the encrypted Home Assistant backup of the previous add-on version",
    "orphan-agent-db": "move agent folders you no longer need out of /config/.openclaw/agents (they are in your "
                       "encrypted backup), then oc-upgrade retry",
    "pc-config": "fix the configuration (openclaw config validate), then oc-upgrade retry",
    "internal-error": "see the traceback in the gate events.log (oc-upgrade status), then oc-upgrade retry",
    "bump-repeat": "the gate already ran for this runtime but the state still needs migration: check oc-upgrade check, then oc-upgrade retry",
    "exit78": "see the reason above, fix it, then oc-upgrade retry",
    "crash-loop": "see the gateway log, fix the cause, then oc-upgrade retry",
    # full5 prep (OpenClaw 2026.10.5+; the checks are gated on oc_common.runtime_caps)
    "acp-ledger-unimported": RETIRED_RUNTIME_ADVICE,
    "voicewake-unimported": RETIRED_RUNTIME_ADVICE,
    "conversation-bindings-unimported": RETIRED_RUNTIME_ADVICE,
    "plugin-approvals-unimported": RETIRED_RUNTIME_ADVICE,
    "restart-sentinel-unimported": RETIRED_RUNTIME_ADVICE,
    "sandbox-registry-unimported": RETIRED_RUNTIME_ADVICE,
    "doctor-retired-warning": "move the listed pre-July-2026 files out of /config/.openclaw, or fix the path doctor "
                              "could not inspect (the files are in your encrypted Home Assistant backup; OpenClaw "
                              "2026.10.4 was the last runtime that imported them), then oc-upgrade retry",
    "skill-workshop-export-failed": "free space or fix permissions under /config/.openclaw-upgrade/gate/runs/ (see the "
                                    "reason), then oc-upgrade retry (doctor has not run yet); to migrate without the "
                                    "export: oc-upgrade retry --accept skill-workshop-export-failed (OpenClaw doctor "
                                    "then keeps only the pending and quarantined drafts and drops the other proposals)",
    "sqlite-fk-violation": "restore the listed database from an encrypted Home Assistant backup taken before the "
                           "damage, or move an agent folder you no longer use out of /config/.openclaw/agents (it is "
                           "in your backup); the gate never deletes rows. Then oc-upgrade retry",
    "agent-db-held": "remove the agent from openclaw.json (agents.list) if you no longer use it, then oc-upgrade retry; "
                     "to keep it, restore the encrypted Home Assistant backup of the previous add-on version, run "
                     "openclaw agents add <id> --workspace <ws> --agent-dir <dir> --non-interactive there, then "
                     "update again",
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
DOCTOR_BLOCKED_MARKER = "Doctor blocked; required repairs remain incomplete"
# runFinalConfigValidationHealth findings (renderStructuredHealthFindings): "[error] <checkId>[ <path>] - <message>",
# then "  fix: <hint>" (normalized to one line); checkIds core/doctor/final-config-validation or core/doctor/<step>
_BLOCKED_FINDING_RE = re.compile(r"\[error\] (core/doctor/[A-Za-z0-9._:/-]{1,120})((?: [^ ]{1,300})?) - (.{1,400}?)"
                                 r"(?= fix: | \[(?:error|warning|warn|info)\] |" + re.escape(DOCTOR_BLOCKED_MARKER)
                                 + r"|$)")
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
    # OpenClaw 2026.11.1+ (#187192): --fix exits 1 when the final config is invalid or a required migration step was
    # deferred (doctor-health.ts recordRepairRefusal; not printed by 2026.10.4/2026.10.10). Before the held-back and
    # schema markers: it is the summary of the run, the listed [error] findings are the cause
    ("doctor-blocked", (DOCTOR_BLOCKED_MARKER,), None),
    # after the specific failures: 2026.10 prints held-back warnings on otherwise normal runs
    ("doctor-held-back", HELD_BACK_MARKERS + ("Held agent ", "unverified-agent-databases", "Agent deletion journal"),
     None),
    ("doctor-incomplete", ("schema migration required",), re.compile(r"SQLite .{0,200}?timed out after", re.I)),
    ("doctor-failed", ("Failing check ",), None),
)
SUSPICIOUS_MARKERS = ("Preserved retired", "may contain unmigrated data", "Pre-June OAuth credentials")
# OpenClaw 2026.10.5+: an optional doctor step that refuses retired files (doctor:sandbox for the sandbox registries,
# after the database migration) is only a "Doctor warnings" line with rc 0. Its own code (doctor-retired-warning),
# so accepting it does not accept the other warnings; checked only when runtime_caps says the runtime retires
# these files (evaluate_doctor retired_warning=True), so a 2026.10.4 run is unchanged.
RETIRED_WARNING_MARKERS = ("predates July 1, 2026", "Cannot inspect potentially retired state")
# Only in the last doctor pass: pass 1 reports plugins pinned to the 7.x package as unfinished until doctor
# has updated them (deferred-plugin-migrations-DtqETF3J.mjs:220; gone in pass 2 in every rehearsal).
# The same for auth profile renames: pass 1 always prints "Kept auth profile openai-codex:... unchanged" before
# the alias step renames it (repair-sequencing-DFs-UYNz.mjs:408-413); in the last pass it is a real deferral.
# 2026.10.4 turns a failed dreaming cron inventory into a recoverable warning with rc 0 (memory-core
# doctor-contract-api.js:119); 2026.10.3 refused the step ("Doctor stopped because"), so it must not pass silently.
FINAL_PASS_SUSPICIOUS = ("data/settings upgrade is unfinished", "Deferred auth profile alias",
                         "Deferred stale auth profile alias", "Kept auth profile ",
                         "Dreaming cron inspection remains pending")

# Skill Workshop proposals (full5; runtime_caps retires_skill_proposals, OpenClaw 2026.10.10+): doctor keeps only the
# current drafts of pending/quarantined proposals (as files in the owner agent's workshop-skills/.archive/
# .retired-proposals/) and drops the four tables plus <state>/skill-workshop/proposals and proposals.json
# (doctor-skill-workshop-retire-proposals.ts). The gate exports everything first to runs/<id>/skill-workshop/.
SW_TABLES = ("skill_workshop_proposals", "skill_workshop_proposal_events", "skill_workshop_proposal_rollbacks",
             "skill_workshop_collection_reviews")
SW_STATE_DIR = "skill-workshop"  # <state>/skill-workshop/ (proposals/<id>/..., proposals.json, recovery/)
SW_EXPORT_DIR = "skill-workshop"  # runs/<id>/skill-workshop/ (never deleted by the cleanup)
SW_EXPORT_SCHEMA = "oc-gate/skill-workshop-export/1"
SW_FILE_CAP = 16 * C.MIB  # larger files are listed with size and sha256 only
SW_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{5,120}")  # doctor's PROPOSAL_ID_PATTERN (fullmatch)
SW_DRAFT_RE = re.compile(r"(?:generations/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/)?PROPOSAL\.md")
SW_EXPORTED_STATUSES = ("pending", "quarantined")
SW_STATUSES = ("pending", "quarantined", "applied", "rejected", "stale")
# export redaction per JSON value: a value under one of these keys is hidden whole, whatever its type (the keys the
# log rules of oc_common hide too, *key, api-key and x-api-key included, and every key the "key: value" rule names,
# oc_common.SECRET_NAME_RE: Passwort, Kennwort, pwd, SMTP_PASS, ...; a PIN of 3 to 12 digits under a PIN key too,
# oc_common.PIN_NAME_RE), except the identifiers OpenClaw itself writes under such keys (SW_KEY_KEEP, compared
# lower-cased: origin.sessionKey, origin_session_key, target.skillKey);
# hashes under their keys are kept unless a value beside them was redacted; ids get every log rule except the
# long-token one (a proposal id has up to 121 characters)
SW_SECRET_KEY_RE = re.compile(r"(?i)token|secret|password|passwd|api[_-]?key|private_?key|access_?key|credential|"
                              r"authorization|cookie|key$")
SW_KEY_KEEP = frozenset({"sessionkey", "origin_session_key", "skillkey", "skill_key"})
SW_HASH_KEY_RE = re.compile(r"(?i)(?:hash|sha256|digest)$")
SW_HASH_VALUE_RE = re.compile(r"(?:sha256:)?[0-9a-f]{32,128}")
SW_ID_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,200}")
SW_JSON_COLUMNS = frozenset({"record_json", "actor_json", "payload_json", "support_files_json", "kept_names_json",
                             "written_names_json", "dropped_json"})
# doctor's own SQLite copies beside each database it migrates: <db>.pre-startup-migration-<id>.bak (full) and, from
# OpenClaw 2026.10.10, <db>.pre-startup-migration-<id>.scoped.bak (only the tables of a declared migration)
DOCTOR_COPY_RE = re.compile(r"[^/]{1,240}\.pre-startup-migration-([A-Za-z0-9][A-Za-z0-9-]{0,63})(?:\.scoped)?\.bak")
# "Saved/Reused pre-migration SQLite backup: <db>.pre-startup-migration-<group id>[.scoped].bak" in a doctor log, matched
# with every blank and box character removed (a long path can wrap inside doctor's box): the id names the group
SAVED_COPY_ID_RE = re.compile(r"(?:Saved|Reused)pre-migrationSQLitebackup:\S*?\.pre-startup-migration-"
                              r"([A-Za-z0-9][A-Za-z0-9-]{0,63}?)(?:\.scoped)?\.bak")

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

def default_agent_id(cfg):
    """The default agent (approximation of OpenClaw's resolveDefaultAgentId): the agents.list entry marked
    default, else the only configured agent, else "main"."""
    agents = cfg.get("agents") if isinstance(cfg, dict) else None
    lst = agents.get("list") if isinstance(agents, dict) else None
    ids = []
    for e in lst if isinstance(lst, list) else []:
        if isinstance(e, dict) and isinstance(e.get("id"), str) and e["id"].strip():
            if e.get("default") is True:
                return e["id"].strip()
            ids.append(e["id"].strip())
    ent = agents.get("entries") if isinstance(agents, dict) else None
    for k, e in ent.items() if isinstance(ent, dict) else []:
        if isinstance(k, str) and k.strip():
            if isinstance(e, dict) and e.get("default") is True:
                return k.strip()
            ids.append(k.strip())
    return ids[0] if len(ids) == 1 else "main"


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


_AGENT_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}", re.I | re.A)  # as oc_migrate._AGENT_ID_RE


def norm_agent_id(value):
    """oc_migrate.normalize_agent_id (OpenClaw's normalizeAgentId: "Haus Agent" -> "haus-agent"; listAgentIds and
    resolveDefaultAgentId give configured ids in this form), copied because classify runs at plan time, which must
    not import oc_migrate (mig()); a test keeps both the same."""
    t = value.strip() if isinstance(value, str) else ""
    n = t.lower()
    if _AGENT_ID_RE.fullmatch(t):
        return n
    return re.sub(r"[^a-z0-9_-]+", "-", n).strip("-")[:64] or "main"


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


# --- agent stores OpenClaw holds back (full5) --------------------------------------------------
HELD_RETAINED = "retained-by-deletion"
HELD_PENDING = "deletion pending"


def deletion_journal_held(state_dir, pending=False):
    """{realpath: (agent_id, reason)} of the agent databases OpenClaw's deletion journal holds back. Read-only.

    Mirrors agent-deletion-journal.read.ts (readRetainedAgentDeletionsFromDatabase): retained deletions
    (cleanup_completed=1 AND delete_files=0) on every runtime; pending=True (OpenClaw 2026.10.10+, runtime_caps
    held_store_skip) adds the pending ones (cleanup_completed=0) its maintenance read includes. Each row holds
    <agent_dir>/openclaw-agent.sqlite plus every path of database_paths_json (relative paths resolve against
    the state dir). A missing table or an unreadable DB gives {}, malformed JSON only the agent_dir path; never
    raises (a stop request still does). Reconstruction holds (migration_sources) are only seen in doctor's
    output (held_paths_from_doctor)."""
    state_dir = Path(state_dir)
    sdb = state_dir / "state" / "openclaw.sqlite"
    try:
        if not sdb.exists() or "agent_deletion_journal" not in table_names(sdb):
            return {}
        rows = q(sdb, "SELECT agent_id, agent_dir, database_paths_json, cleanup_completed, delete_files "
                      "FROM agent_deletion_journal")
    except (sqlite3.Error, C.NodeQueryError, C.SchemaUnknown, OSError):
        return {}
    held = {}
    for aid, adir, paths_json, done, delete_files in rows:
        if done == 1 and delete_files == 0:
            reason = HELD_RETAINED
        elif done == 0 and pending:
            reason = HELD_PENDING
        else:
            continue
        if not isinstance(aid, str) or not isinstance(adir, str) or not adir:
            continue
        cands = [Path(adir) / "openclaw-agent.sqlite"]
        try:
            extra = json.loads(paths_json) if isinstance(paths_json, str) else None
        except ValueError:
            extra = None
        if isinstance(extra, list) and all(isinstance(x, str) for x in extra):
            cands += [Path(x) for x in extra if x]
        for c in cands:
            c = c if c.is_absolute() else state_dir / c
            held.setdefault(os.path.realpath(c), (aid, reason))
    return held


def marker_held(state_dir, marker, runtime):
    """{realpath: (agent_id, reason)} of the held stores a migration marker for `runtime` recorded, as long as
    each file is the same one (dev, ino) at the same schema; anything else reads as not held."""
    if not isinstance(marker, dict) or marker.get("runtime") != runtime or not isinstance(marker.get("held"), list):
        return {}
    state_dir = Path(state_dir)
    held = {}
    for h in marker["held"]:
        if not isinstance(h, dict) or not isinstance(h.get("path"), str) or not h["path"]:
            continue
        pth = Path(h["path"])
        pth = pth if pth.is_absolute() else state_dir / pth
        try:
            st = os.stat(pth)
            same = (st.st_dev, st.st_ino) == (h.get("dev"), h.get("ino")) and agent_db_version(pth) == h.get("uv")
        except (OSError, sqlite3.Error, C.SchemaUnknown, C.NodeQueryError):
            same = False
        if same:
            held.setdefault(os.path.realpath(pth), (str(h.get("id")), str(h.get("reason") or "held")))
    return held


def planning_held(state_dir, marker, pkg):
    """Held stores known before doctor runs (plan, dry-run, precheck, oc-upgrade check): the deletion journal
    plus the stores the marker of this runtime recorded as held back by doctor."""
    held = deletion_journal_held(state_dir, pending=C.runtime_caps(pkg)["held_store_skip"])
    for k, v in marker_held(state_dir, marker, (pkg or {}).get("version")).items():
        held.setdefault(k, v)
    return held


def held_marker_entries(state_dir, cls):
    """Marker 'held' entries [{id, path, uv, dev, ino, reason}] for classify()'s res['held']."""
    out_ = []
    for h in cls.get("held") or []:
        try:
            st = os.stat(Path(state_dir) / h["path"])
        except OSError:
            continue
        out_.append({"id": h["id"], "path": h["path"], "uv": h["uv"], "dev": st.st_dev, "ino": st.st_ino,
                     "reason": h["reason"]})
    return out_


def held_reason_text(reason):
    if reason == HELD_RETAINED:
        return "kept from a deleted agent (deletion journal)"
    if reason == HELD_PENDING:
        return "its agent is being deleted (deletion journal: pending)"
    return f"held back by doctor: {reason}"


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


def classify(state_dir, cfg, s_target, a_target, runtime, held=None):
    """Predicate (§6.2). Returns a JSON-able dict; verdict newer|gate|ok.

    held (full5): {realpath: (agent_id, reason)} of agent stores OpenClaw holds back (deletion journal, doctor's
    "Held agent" lines, the marker). Below the target such a store of a configured agent stays in the gate and
    is listed in res['held_configured'] (precheck agent-db-held); one that is only registered leaves the
    predicate into res['held'] when the runtime skips held stores of unconfigured agents (2026.10.10+,
    runtime_caps held_store_skip). A held orphan gets 'held' and 'reason'. held=None is the 0.5.94-full4
    predicate."""
    state_dir = Path(state_dir)
    cfg = cfg if isinstance(cfg, dict) else {}
    held = held or {}
    res = {"verdict": "ok", "schema_verdict": "ok", "files_verdict": "ok", "newer": [], "gate": [], "files": [],
           "state": None, "state_uv": None, "agents": {}, "agent_paths": {}, "agent_ids": {}, "orphans": [],
           "held": [], "held_configured": [], "targets": {"state": s_target, "agent": a_target}}
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
    # ids compared as OpenClaw compares them: the store of "Haus Agent" is registered as haus-agent
    configured = {norm_agent_id(a) for a in configured_agent_ids(cfg)} if held else set()
    skip_held = bool(held) and C.runtime_caps(runtime)["held_store_skip"]
    for aid, pth in targets:
        v = agent_db_version(pth)
        if v is None:
            continue
        h = held.get(os.path.realpath(pth)) if v < a_target else None
        if h is not None:
            entry = {"id": aid, "path": C.rel(pth, state_dir), "uv": v, "reason": h[1]}
            if norm_agent_id(aid) in configured:
                # a pending deletion is not held from doctor: 2026.10.10 prepares (migrates) its store for the
                # deletion recovery (openclaw-agent-db-maintenance.ts preparePendingAgentDeletionDatabases...)
                if h[1] != HELD_PENDING:
                    res["held_configured"].append(entry)
            elif skip_held:
                res["held"].append(entry)
                continue
        key = aid if aid not in res["agents"] else C.rel(pth, state_dir)
        res["agents"][key] = v
        res["agent_paths"][key] = C.rel(pth, state_dir)
        res["agent_ids"][key] = aid
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
        o = {"id": aid, "path": C.rel(pth, state_dir), "uv": v}
        h = held.get(os.path.realpath(pth))
        if h is not None:
            o.update(held=True, reason=h[1])
        res["orphans"].append(o)
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
    if (status == "hold" and not has_retry and removed_hold(j.get("hold")) and j.get("first_write_at") is None
            and j.get("mode") != "maintenance" and gate_needed):
        # nothing was written: the run simply starts again from the precheck (the HA backup check included)
        code = (j.get("hold") or {}).get("code")
        warnings.append(f"previous HOLD {code} no longer applies (0.5.94-full3 writes no gate archive)")
        return R(10, "resume", f"run {run_id}: HOLD {code} no longer applies, re-running from precheck",
                 mode=mode_new, resume_phase="precheck")
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
                return R(10, "run", f"retry after {code}: {m} gate (backup check, doctor)", mode=m, new_run=True)
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
    held = f" held={len(cls['held'])}" if cls.get("held") else ""
    return (f"runtime={pkg['version']} targets={pkg['schema_state']}/{pkg['schema_agent']} "
            f"state={st.get('eff', 'none')} agents={ags}{held} verdict={cls['verdict']}")


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
        # full5: stores OpenClaw holds back (deletion journal, the marker of this runtime) do not ask for a gate
        cls = classify(gp["STATE"], cfg, pkg["schema_state"], pkg["schema_agent"], pkg["version"],
                       held=planning_held(gp["STATE"], marker, pkg))
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
            write_marker(mode="adopted", run_id=None, binding=binding, runtime=pkg["version"],
                         accepted=[], orphans=cls.get("orphans", []), held=held_marker_entries(gp["STATE"], cls))
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
        for line in plan_fixup_lines(d, gp):  # full5: the config fixup before a doctor pass (read-only)
            emit(line)
    else:
        emit(f"[gate] plan: {bits} -> no gate ({d['reason']})")
    if apply:
        apply_bookkeeping(d)
    return d


def plan_fixup_lines(d, gp):
    """`gate --plan` with a gate run ahead (rc 10): the config fixup that run would make before its next doctor pass
    (Gate.cron_config_fixup; runtime_caps cron_refusal), read-only. Nothing when the run has no doctor pass left or on
    any error: planning never depends on it."""
    try:
        pkg, j = d.get("pkg") or {}, d.get("journal") or {}
        caps = C.runtime_caps(pkg)
        if not caps["cron_refusal"]:
            return []
        resume = d.get("action") == "resume"
        if resume and "doctor2" in (j.get("phases_done") or []) and not (d.get("bk") or {}).get("redo_doctor"):
            return []
        done = {a.get("provider") for a in (j.get("cron_autofix") or {}).get("applied") or []
                if isinstance(a, dict)} if resume else set()
        cfg, raw = C.read_json_strict(gp["CONFIG_PATH"], with_text=True)
        plan_ = cron_fixup_plan(gp["STATE"], cfg, raw, pkg["version"], caps["cron_doctor_migration"], done=done)
    except Exception:  # noqa: BLE001 - B11: a preview must not break planning
        return []
    rt = pkg["version"]
    if plan_["include"]:
        return [f"WARN [gate] plan: {cron_fixup_include_text(f, rt, plan_['include'])}" for f in plan_["fix"]]
    when = "the next doctor pass" if resume and j.get("doctor_started") else "doctor pass 1"
    return [f"[gate] plan: config fixup: would set {printable(f['path'])} = \"api-key\" before {when} "
            f"({cron_fixup_why(f['provider'], rt)})" for f in plan_["fix"]]


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


def write_marker(*, mode, run_id, binding, runtime, accepted, orphans, held=None):
    """held (full5): [{id, path, uv, dev, ino, reason}] of stores OpenClaw held back and the gate left out of the
    schema check; written only when there are any (a marker without it reads as none: marker_held)."""
    gp = gpaths()
    ensure_dirs(gp)
    m = {"schema": 1, "runtime": runtime, "mode": mode, "run_id": run_id, "completed_at": C.utc_iso(),
         "binding": binding, "accepted": sorted(set(accepted or [])),
         "orphans": orphans or [], "addon_version": addon_version()}
    if held:
        m["held"] = held
    C.atomic_write_json(gp["MARKER"], m)


# --- hold.txt ---------------------------------------------------------------------------------

def removed_hold(h):
    """True for a HOLD whose every code belongs to the gate archive of 0.5.94-full1/full2 (no such check now)."""
    h = h or {}
    codes = set(h.get("codes") or [h.get("code")]) - {None}
    return bool(codes) and codes <= REMOVED_HOLDS


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
                         REMOVED_HOLD_ADVICE if removed_hold(jh) else
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
    """The text around idx (40 characters before, width from it), redacted before the cut: each side is redacted
    with 400 more characters, so a cut never leaves a secret whose key word it cut off ("...ken: <value>"); the
    joined cut once more (a token on both sides of idx)."""
    pre = C.redact_text(norm[max(0, idx - 440): idx])
    post = C.redact_text(norm[idx: idx + width + 400])
    return C.redact_text(pre[-40:] + post[:width])


def blocked_message(rc, norm, idx):
    """HOLD reason of doctor-blocked: the [error] findings doctor listed before "Doctor blocked" (path and message,
    each redacted on its own, at most 5), else the text around the marker. The path and the message are redacted
    apart: joined, a path that ends in a secret-like key (…apiKey, …botToken) reads as "key: value" and the
    redaction would hide doctor's message (its zod messages do not echo config values)."""
    found = []
    for m in _BLOCKED_FINDING_RE.finditer(norm[:idx]):
        where = m.group(2).strip()
        item = f"{C.redact_text(where or m.group(1))}: {C.redact_text(m.group(3).strip())}"
        if item not in found:
            found.append(item)
    if not found:
        return f"doctor rc {rc}: ...{_snippet(norm, idx)}..."
    shown = "; ".join(f[:200] for f in found[:5])  # redacted before the cut: a cut never exposes more
    more = f" (+{len(found) - 5} more in oc-upgrade log)" if len(found) > 5 else ""
    return f"doctor rc {rc}: doctor blocked, required repairs remain incomplete: {shown}{more}"


def evaluate_doctor(rc, text, *, timed_out=False, stopping=False, final=False, retired_warning=False):
    """Classify one doctor pass (B3: markers only when rc != 0, except held-back stores, which 2026.10
    reports with rc 0; B8: signals/OOM -> doctor-crashed). final: the pass that should leave nothing
    pending (pass 2 or 3). retired_warning: the runtime retires the pre-July runtime files (2026.10.5+), so a
    RETIRED_WARNING_MARKERS hit with rc 0 is doctor-retired-warning."""
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
        retired = [m for m in RETIRED_WARNING_MARKERS if m.lower() in low] if retired_warning else []
        extra = [warn] if warn else []
        if retired:
            idx = low.find(retired[0].lower())
            extra.append({"code": "doctor-retired-warning", "cls": "acceptable", "markers": retired,
                          "message": "doctor completed but reported pre-July-2026 files it left unchanged: "
                                     f"...{_snippet(norm, idx)}..."})
        held = [(low.find(s.lower()), s) for s in HELD_BACK_MARKERS if s.lower() in low]
        m = _HELD_AGENT_RE.search(norm)
        if m:
            held.append((m.start(), "Held agent"))
        if held:
            idx, s = min(held)
            res.update(code="doctor-held-back", cls="acceptable", markers=[s],
                       message=f"doctor completed but held back agent databases (they stay unmigrated): "
                               f"...{_snippet(norm, idx)}...")
            if extra:  # accepting the held stores must not accept the warnings too
                res["also"] = extra
            return res
        if extra:
            res.update(extra[0])
            if extra[1:]:
                res["also"] = extra[1:]
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
                if code == "doctor-blocked":
                    res["message"] = blocked_message(rc, norm, idx)
                return res
        if rx is not None:
            m = rx.search(norm)
            if m:
                res.update(code=code, cls="hard", markers=[m.group(0)[:60]],
                           message=f"doctor rc {rc}: ...{_snippet(norm, m.start())}...")
                return res
    last = C.redact_text(norm[-560:])[-160:]  # redacted before the cut (_snippet)
    res.update(code="doctor-failed", cls="hard", message=f"doctor rc {rc}: ...{last}")
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
     lambda m: f"memory search of agent {m.group(1)} uses provider {m.group(2)} without an API key, so "
               "semantic recall does not work until one is configured"),
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


# OpenClaw 2026.10.10+ doctor retiring the Skill Workshop proposals (doctor-skill-workshop-retire-proposals.ts): only
# counts and proposal ids are captured (a box can wrap a long path). Not doctor warnings for a HOLD: the holdback is
# harmless (the runtime ignores the tables) and the postconditions report it from the real state.
_SW_ID = r"([a-z0-9][a-z0-9-]{5,120})"
_SW_NOTE_RES = (
    ("info", re.compile(r"Exported (\d+) pending Skill Workshop proposal drafts?\b"),
     lambda m: f"doctor archived {m.group(1)} pending/quarantined Skill Workshop draft(s) in the owner agent's "
               "workshop-skills/.archive/.retired-proposals/"),
    ("info", re.compile(r"Retired the Skill Workshop proposal tables"),
     lambda m: "doctor retired the Skill Workshop proposal tables (OpenClaw no longer has the applied, rejected and "
               "stale proposals, their history and undo records)"),
    ("warn", re.compile(r"Restored \S+ from the unfinished apply of Skill Workshop proposal " + _SW_ID),
     lambda m: f"doctor put back the pre-apply skill files of Skill Workshop proposal {m.group(1)} (its apply never "
               "finished)"),
    ("warn", re.compile(r"No configured agent owns Skill Workshop proposal " + _SW_ID),
     lambda m: f"doctor kept Skill Workshop proposal {m.group(1)}: no configured agent owns it (doctor's warning in "
               "oc-upgrade log says what to do)"),
    ("warn", re.compile(r"Skill Workshop proposal " + _SW_ID + r" has no draft left to export"),
     lambda m: f"doctor retired the record of Skill Workshop proposal {m.group(1)}: its draft was already gone"),
    ("warn", re.compile(r"Skill Workshop proposal " + _SW_ID + r" has no (draft|record);"),
     lambda m: f"doctor kept Skill Workshop proposal {m.group(1)}: it has no {m.group(2)} (doctor's warning in "
               "oc-upgrade log says what to do)"),
    ("warn", re.compile(r"Could not (export|read the unfinished apply of|undo the unfinished apply of|read) Skill "
                        r"Workshop proposal " + _SW_ID),
     lambda m: f"doctor could not {m.group(1)} Skill Workshop proposal {m.group(2)}; it kept the proposal storage "
               "(see oc-upgrade log)"),
    ("warn", re.compile(r"Skill Workshop proposals changed during export"),
     lambda m: "doctor did not finish retiring the Skill Workshop proposals (they changed during its export)"),
)


def doctor_notes(text, patterns=None):
    """[[level, message]] for doctor messages worth surfacing after a migration (deduplicated)."""
    norm = normalize_doctor_text(text)
    notes = []
    for level, rx, fmt in _NOTE_RES + _SW_NOTE_RES if patterns is None else patterns:
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


# Doctor's held-store lines (2026.10.4 and 2026.10.10): "Held agent <id> database <path> (<reason>); run openclaw
# doctor --fix to inspect restoration." (state-migrations.media-persistence-targets.ts) and "Held agent <id>
# database <path>; deletion history needs repair." (doctor-agent-deletion-journal.ts). A reworded line matches
# nothing, which keeps the store in the hard schema check (the safe direction).
_HELD_PATH_RE = re.compile(r"Held agent (\S{1,120}) database (/\S{1,512}?)(?: \((retained-by-deletion|deletion "
                           r"journal reconstructed|deletion journal unavailable)\)|; deletion history needs repair)")


def held_paths_from_doctor(text):
    """[[agent_id, abs_path, reason]] of the stores one doctor log holds back (de-duplicated by path, max 200)."""
    found, seen = [], set()
    for m in _HELD_PATH_RE.finditer(normalize_doctor_text(text)):
        path = m.group(2)
        if path in seen:
            continue
        seen.add(path)
        found.append([m.group(1), path, m.group(3) or "deletion history needs repair"])
        if len(found) >= 200:
            break
    return found


class LogMirror:
    """Mirror new lines of a growing log to stdout as `[doctor] <line>` (redacted, capped)."""

    def __init__(self, path, offset, cap, emit, label):
        self.path, self.offset, self.cap, self.emit, self.label = Path(path), offset, cap, emit, label
        self.lines, self.partial, self.last, self.capped = 0, b"", "", False
        self.redactor = C.LineRedactor()  # PEM blocks and values on the next line span lines

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
            shown = self.redactor.line(line)  # every line, also blank ones: they end a value-on-the-next-line
            if not line.strip():
                continue
            self.lines += 1
            self.last = shown.strip()
            if self.lines <= self.cap:
                self.emit(f"[doctor] {shown}")
            elif not self.capped:
                self.capped = True
                self.emit(f"[gate] (doctor output continues in {self.path})")


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
        self._caps = None

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
        return f"{PHASE_NO[phase or self.phase]}/8"

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

    # ----- sizes / symlinked workspaces -----
    def workspace_symlinks(self):
        """F1: symlinked workspace roots below /config whose target is neither inside the state dir nor inside
        another workspace root. A backup (tar) stores such a link without the data it points to."""
        root, state = self.gp["CONFIG_ROOT"], self.gp["STATE"]
        included, symlinks = [], []
        for ws in workspaces(self.cfg):
            if not os.path.isdir(ws):
                continue
            real = Path(os.path.realpath(ws))
            try:
                wrel = ws.relative_to(root)
            except ValueError:
                continue
            if str(wrel) in ("", ".") or state == ws or str(state).startswith(str(ws) + "/"):
                continue
            if os.path.islink(ws) and not any(str(real) == str(r) or str(real).startswith(str(r) + "/")
                                              for r in included + [Path(os.path.realpath(state))]):
                symlinks.append(str(ws))
                continue
            if str(ws).startswith(str(state) + "/"):
                continue
            if any(str(real) == str(r) or str(real).startswith(str(r) + "/") for r in included):
                continue
            included.append(real)
        return symlinks

    def measure(self):
        state = self.gp["STATE"]
        sqlite_total = transcripts = 0
        dbs = {}
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
        self.sizes = {"sqlite_total": sqlite_total, "transcripts_total": transcripts,
                      "max_db": max_db, "largest_agent": largest_agent, "s_mib": s_mib}
        return self.sizes

    def plugin_space_bytes(self):
        """Precheck 8 (A3, runtime_caps doctor_plugin_space, OpenClaw 2026.10.10+): the installed size of the enabled
        official npm plugins. Doctor brings them to its release, a new npm generation beside the old one plus the
        npm cache in /config (counted twice), and copies their files into os.tmpdir() for its recovery set
        (openclaw-plugin-captures-*, counted once there). 0 on earlier runtimes or without such plugins."""
        if not self.caps()["doctor_plugin_space"]:
            return 0
        try:
            installs = official_plugin_installs(self.gp["STATE"], self.cfg if isinstance(self.cfg, dict) else {},
                                                with_path=True)
            return plugin_install_bytes(self.gp["STATE"], [x for x in installs if x["enabled"] is not False])
        except OSError:
            return 0

    def held_map(self, include_doctor):
        """{realpath: (agent_id, reason)} of the agent stores OpenClaw holds back: the deletion journal and the
        marker of this runtime (planning_held), plus with include_doctor the "Held agent" lines of this run's
        doctor passes (journal doctor_held)."""
        held = planning_held(self.gp["STATE"], load_marker(), self.pkg)
        if include_doctor:
            for x in (self.j or {}).get("doctor_held") or []:
                if isinstance(x, list) and len(x) == 3 and isinstance(x[1], str):
                    held.setdefault(os.path.realpath(x[1]), (str(x[0]), str(x[2])))
        return held

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
        # 5 predicate (full5: with the stores OpenClaw holds back; doctor has not run yet)
        self.cls = classify(p["STATE"], self.cfg, self.pkg["schema_state"], self.pkg["schema_agent"],
                            self.pkg["version"], held=self.held_map(False))
        if self.cls["verdict"] == "newer":
            F.append(finding("newer-state", "hard", "; ".join(self.cls["newer"]), "precheck"))
        F += self.agent_store_findings()
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
        # 6c every gate mode (also on a resume): heartbeat windows that OpenClaw 2026.11.1+ doctor keeps invalid and
        # then stops on ("Doctor blocked"); runtime_caps heartbeat_hours_kept, so nothing on 2026.10.4/2026.10.10.
        # Checked after ${VAR} substitution with the environment the gate gives doctor (OpenClaw validates that)
        if cfg_ok:
            try:
                denv = C.openclaw_env()
            except Exception:  # noqa: BLE001 - only the substitution depends on it
                denv = dict(os.environ)
            F += [dict(f) for f in mig().heartbeat_hours_findings(self.cfg, caps=self.caps(),
                                                                  runtime=self.pkg["version"], env=denv)]
        # 7 sizes (and F1: a backup stores a symlinked state/agent directory or workspace root as a bare link)
        links = state_symlinks(p["STATE"], self.cls) + self.workspace_symlinks()
        if links:
            F.append(finding("state-symlink", "hard", "symlinked director(ies) would be backed up as bare links, "
                             "without the data they point to: " + ", ".join(links[:6]), "precheck"))
        root = os.path.realpath(p["CONFIG_ROOT"])
        outside = [a for a in sorted(set((self.cls.get("agent_paths") or {}).values()))
                   if not (os.path.realpath(p["STATE"] / a) + "/").startswith(root + "/")]
        outside += [str(ws) for ws in workspaces(self.cfg)  # doctor writes there too (workspace attestations)
                    if os.path.isdir(ws) and not str(ws).startswith(str(p["CONFIG_ROOT"]) + "/")]
        if outside:
            F.append(finding("data-outside-config", "acceptable",
                             "agent database(s) or workspace(s) outside /config are changed by the migration, but a "
                             "backup of the add-on alone does not contain them: " + ", ".join(outside[:4]), "precheck"))
        sizes = self.measure()
        sw_bytes = self.skill_workshop_precheck()  # 7 (full5): Skill Workshop inventory, export size
        opt = C.gate_options()
        for prob in opt["problems"]:
            self.warn(f"add-on option {prob}")
        plain = C.safe_files_below(p["ARCHIVES"], lambda n: n.endswith(".tar.gz"))
        if plain:
            self.warn(f"{len(plain)} plaintext gate archive(s) of 0.5.94-full1 in {p['ARCHIVES']} hold unencrypted "
                      f"secrets ({leftover_note(opt['cleanup_hours'])})")
        # 8 space
        if self.hooks.get("skip_space_check"):
            parts.append("space check skipped (test hook)")
        else:
            plug = self.plugin_space_bytes()  # A3 (OpenClaw 2026.10.10+): doctor's plugin downloads and tmp copies
            needs = [("/config", p["CONFIG_ROOT"],
                      2 * sizes["sqlite_total"] + 2 * sizes["transcripts_total"] + 2 * C.GIB + sw_bytes + 2 * plug,
                      "low-disk-config"),
                     ("sqlite-tmp", sqlite_tmpdir(),
                      max(sizes["largest_agent"], sizes["max_db"]) + C.GIB, "low-disk-tmp")]
            if plug:
                try:
                    tmp_env = C.openclaw_env()
                except Exception:  # noqa: BLE001 - only the directory depends on it
                    tmp_env = dict(os.environ)
                needs.append(("plugin-tmp", node_tmpdir(tmp_env), plug, "low-disk-tmp"))
            sf_, summary = space_check(needs)
            F += sf_
            parts.append(f"space {'ok' if not sf_ else 'LOW'} ({summary})")
        # 9 quick_check
        parts.append(self.quick_checks(F, state_db))
        # 9b foreign keys (full5)
        fk = self.fk_checks(F, state_db)
        if fk:
            parts.append(fk)
        # 10 network
        if self.hooks.get("skip_network_check") or (self.dry_run and not self.network):
            parts.append("network not checked")
        else:
            parts.append(self.network_check(F))
        # 10b encrypted Home Assistant backup with this add-on (the only rollback point)
        parts.append(self.ha_backup_check(F, opt))
        # 11 info
        self.info_items(mode, generic_only)
        # 11b Skill Workshop, 11c cron inference accounts (full5; information only)
        self.skill_workshop_info(F)
        self.cron_binding_forecast(F, mode)
        # 11d session sizes (full5, openclaw/openclaw#191847; information only)
        self.large_session_info()
        b = self.budget()
        if self.j is not None:
            self.j["budget"] = b
        parts.append(f"doctor budget {C.fmt_duration(b['doctor_pass_seconds'])}/pass (S={b['s_mib']} MiB)")
        if mode == "from-7x" and not generic_only:
            parts.insert(1, f"checkpoint {checkpoint or 'none'}")
        if NODE_FALLBACKS:
            self.warn(f"node:sqlite fallback used for {len(set(NODE_FALLBACKS))} database(s)")
        return F, parts

    def agent_store_findings(self):
        """Precheck 5 (full5): orphan stores doctor would migrate one-way (acceptable orphan-agent-db), stores the
        deletion journal keeps (info), registered stores of agents openclaw.json does not configure (info, D6), and
        configured agents whose store is held back (hard agent-db-held)."""
        F = []
        cls, a_target, ver = self.cls, self.pkg["schema_agent"], self.pkg["version"]
        orphans = [o for o in cls["orphans"] if not o.get("held") and (o.get("uv") is None or o["uv"] < a_target)]
        if orphans:
            owners = {o["path"]: orphan_recorded_owner(self.gp["STATE"], o) for o in orphans}

            def label(o):
                own = f"; records agent {printable(owners[o['path']])} as its owner" if owners[o["path"]] else ""
                return f"{o['path']} (schema {o['uv'] if o.get('uv') is not None else 'unreadable'}{own})"
            F.append(finding("orphan-agent-db", "acceptable",
                             "agent database(s) of agents that are neither configured nor registered: "
                             + ", ".join(label(o) for o in orphans)
                             + f". Doctor of OpenClaw {ver} finds such a store under agents/ and, unless its "
                               f"deletion history holds it back, migrates it one-way to schema {a_target}; a store "
                               "that records another agent as its owner is not migrated: doctor moves it aside as "
                               "<file>.corrupt-<time> only when it and its -wal/-shm files are byte-identical to "
                               "that agent's database (a plaintext copy that is kept), and otherwise refuses it, "
                               "which stops doctor after the other databases are migrated (hard HOLD "
                               "doctor-migration-refused): move such a folder out of agents/ instead of accepting. "
                               "The gateway does not open it. "
                               "The gate checks that it is readable (quick_check, foreign keys) but not its schema "
                               "afterwards; what doctor did is in the gate's final lines and oc-upgrade status",
                             "precheck"))
        for h in [o for o in cls["orphans"] if o.get("held")] + list(cls.get("held") or []):
            if h.get("reason") == HELD_PENDING:
                what = "belongs to an agent OpenClaw is deleting (deletion journal: pending)"
            elif h.get("reason") == HELD_RETAINED:
                what = "is kept from a deleted agent (OpenClaw deletion journal); OpenClaw does not migrate or open it"
            else:
                what = f"was held back by doctor ({h.get('reason')}); OpenClaw does not migrate or open it"
            self.say(f"{self.pn('precheck')} info: {h['path']} (agent {h['id']}, schema {h['uv']}) {what}, and the "
                     "gate leaves it out of the schema checks")
        # D6: a store OpenClaw registered for an agent that openclaw.json no longer configures
        # ids compared as OpenClaw compares them: it registers the store of "Haus Agent" as haus-agent
        configured = {mig().normalize_agent_id(a) for a in configured_agent_ids(self.cfg)}
        held = self.held_map(False)
        for key, relp in sorted((cls.get("agent_paths") or {}).items()):
            aid = (cls.get("agent_ids") or {}).get(key, key)
            if mig().normalize_agent_id(aid) in configured \
                    or os.path.realpath(self.gp["STATE"] / relp) in held:
                continue
            self.say(f"{self.pn('precheck')} info: {relp} (agent {aid}, schema {(cls.get('agents') or {}).get(key)}) "
                     "is registered in OpenClaw's state, but the agent is not configured in openclaw.json: the gate "
                     "checks it with the other agent databases (doctor migrates registered stores too); OpenClaw "
                     "does not run an agent that is not configured, and cancels the runs of its cron jobs ('cron job "
                     "agent is unavailable')")
        for h in cls.get("held_configured") or []:
            why = "from a deletion (deletion journal)" if h.get("reason") == HELD_RETAINED else \
                f"back ({held_reason_text(h.get('reason'))})"
            F.append(finding("agent-db-held", "hard",
                             f"agent {h['id']} is configured, but OpenClaw keeps its database {h['path']} (schema "
                             f"{h['uv']}) {why}: doctor will not migrate it and OpenClaw {ver} refuses the agent "
                             "(the default agent: the gateway does not start or stays not ready)", "precheck"))
        return F

    def ha_backup_check(self, F, opt):
        """Precheck 10b (read-only): an encrypted full/partial Home Assistant backup that contains this add-on, is
        at most gate_backup_max_age_hours old and, for from-7x/bump runs, holds the add-on version installed
        before this one (restoring a backup of the new version would not bring the old OpenClaw back)."""
        if self.hooks.get("skip_backup_check"):
            return "HA backup not checked (test hook)"
        if (self.j or {}).get("first_write_at"):
            return self.recorded_backup_check(F)
        tail = "; the Home Assistant backup is the only rollback point"
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
        if len(ev["unprotected"]) > 3:
            self.warn(f"... and {len(ev['unprotected']) - 3} more Home Assistant backup(s) that contain this add-on "
                      "UNENCRYPTED (Settings > System > Backups)")
        need_older = (self.j or {}).get("mode", "from-7x") in ("from-7x", "bump")
        best, same_version, unreadable = None, [], []
        for e in ev["candidates"][:BACKUP_VERSION_LOOKUPS]:  # newest first, until one holds the previous version
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

    def recorded_backup_check(self, F):
        """Resume after the first write: the backup this run's precheck accepted must still exist and be
        encrypted, because it is the only rollback point for the rest of the one-way migration."""
        hb = (self.j or {}).get("ha_backup") or {}
        if not hb.get("slug"):
            return "HA backup not re-checked (none was recorded for this run)"
        tail = "; the Home Assistant backup is the only rollback point"
        name = f"'{hb.get('name')}' ({hb['slug']})"
        token = C.supervisor_token(self.hooks.get("supervisor_token_file"))
        try:
            if not token:
                raise C.SupervisorError(0, "no Supervisor token")
            info = C.supervisor_get(f"/backups/{hb['slug']}/info", token, base=self.hooks.get("supervisor_url"))
        except C.SupervisorError as exc:
            if exc.status == 404:
                F.append(finding("ha-backup-missing", "acceptable", f"the backup {name} this run relies on no longer "
                                 f"exists, and the state is already partially migrated{tail}", "precheck"))
                return "HA backup MISSING"
            F.append(finding("ha-backup-unverified", "acceptable", f"the backup {name} this run relies on could not "
                             f"be re-checked: {exc.message}{tail}", "precheck"))
            return "HA backup UNVERIFIED"
        if not backup_protected(info):
            F.append(finding("ha-backup-missing", "acceptable", f"the backup {name} this run relies on is no longer "
                             f"encrypted in every location{tail}", "precheck"))
            return "HA backup NOT ENCRYPTED"
        return f"HA backup still there ({name}, encrypted)"

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
        cls = self.cls or {}
        checked = []  # full5: the same databases for the foreign-key check (9b), with their schema position
        if state_db.exists():
            dbs.append(state_db)
            st = cls.get("state") or {}
            checked.append({"path": state_db, "kind": "state", "uv": st.get("eff"),
                            "target": (self.pkg or {}).get("schema_state")})
        a_target = (self.pkg or {}).get("schema_agent")
        for key, relp in sorted(cls.get("agent_paths", {}).items()):
            dbs.append(self.gp["STATE"] / relp)
            checked.append({"path": dbs[-1], "kind": "agent", "uv": (cls.get("agents") or {}).get(key),
                            "target": a_target})
        # full5: doctor also migrates orphan stores below the target one-way (doctor-health.ts), unless held
        for o in cls.get("orphans") or []:
            if not o.get("held") and o.get("uv") is not None and a_target is not None and o["uv"] < a_target:
                dbs.append(self.gp["STATE"] / o["path"])
                checked.append({"path": dbs[-1], "kind": "orphan", "uv": o["uv"], "target": a_target})
        self.facts["checked_dbs"] = checked
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
                         f"npm registry not reachable (rc {res.rc}); doctor installs/updates official plugins from it. "
                         "Accepted, doctor keeps retrying npm for many minutes per plugin (over 10 minutes were seen) "
                         f"and can run into its time budget per pass ({C.fmt_duration(self.budget()['doctor_pass_seconds'])}"
                         "; then the gate holds with doctor-timeout); prefer fixing the network", "precheck"))
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
        # full5: official npm plugins follow the OpenClaw version. doctor --fix updates the enabled official catalog
        # plugins itself (repair-sequencing: version drift, only a warning when a fetch fails); after the gate the
        # add-on brings the enabled ones it left behind (run.sh -> oc-upgrade plugins-sync)
        official = official_plugin_installs(state, self.cfg)
        if official:
            rt = self.pkg["version"]
            text = ", ".join(f"{x['package']} {x['version'] or '?'}"
                             + {True: " (enabled)", False: " (disabled)"}.get(x["enabled"], "") for x in official)
            if any(x["version"] != rt for x in official):
                text += f"; OpenClaw's doctor and then the add-on update the enabled ones to {rt}"
            self.say(f"{self.pn('precheck')} info: official plugins: {text}")
            if self.j is not None and not self.j.get("first_write_at"):
                self.j["plugins_official_before"] = official
        # telegram/ingress-spool-*: reported by retired_format_findings (2026.10 doctor imports the spool)
        for ws in workspaces(self.cfg):
            nested = ws / ".openclaw" / "workspace-state.json"
            if os.path.lexists(nested) and not os.path.lexists(ws / "openclaw-workspace-state.json"):
                self.warn(f"{nested} holds the workspace setup state in the pre-July layout, which OpenClaw 2026.10 "
                          "ignores (2026.7.35 copies it to openclaw-workspace-state.json when the workspace is "
                          "used); the agent may offer its first-run setup again")

    # ----- full5 hooks (OpenClaw 2026.10.5+) -----
    # Call sites in a fixed order (critic, implementation order step 2); each area fills only its own body.
    # precheck: 5 classify -> 6b retired -> 7 sizes + skill_workshop_precheck -> 8 space -> 9 quick_check ->
    # 9b fk_checks -> 10 network -> 10b HA backup -> 11 info_items -> 11b skill_workshop_info ->
    # 11c cron_binding_forecast -> 11d large_session_info. The precheck also runs read-only for `gate --dry-run`
    # and `oc-upgrade check` (self.dry_run, self.j may be None): these hooks never write there. On 2026.10.4
    # (runtime_caps all off) every hook keeps the 0.5.94-full4 output (tests/test_gate_golden_1004.py).
    def caps(self):
        """oc_common.runtime_caps of the bundled runtime (all off while the package is unknown)."""
        ver = (self.pkg or {}).get("version")
        if self._caps is None or self._caps[0] != ver:
            self._caps = (ver, C.runtime_caps(self.pkg))
        return self._caps[1]

    def skill_workshop_precheck(self):
        """Precheck 7 (Skill Workshop): inventory of the proposals; returns the bytes the export adds to the
        /config space need. Only on runtimes whose doctor retires the proposals (runtime_caps
        retires_skill_proposals, 2026.10.10+); read-only, so also in dry-run and oc-upgrade check."""
        self.facts.pop("sw_inventory", None)
        if not self.caps()["retires_skill_proposals"]:
            return 0
        try:
            inv = skill_workshop_inventory(self.gp["STATE"], self.cfg)
        except (sqlite3.Error, C.NodeQueryError, OSError, ValueError) as exc:
            self.warn(f"skill workshop: the proposals could not be counted ({type(exc).__name__}: "
                      f"{C.redact_text(str(exc))[:200]}); the export before doctor pass 1 tries again")
            return 0
        self.facts["sw_inventory"] = inv
        if sw_empty(inv) or self.sw_export_done():
            return 0
        return int(inv["bytes"]) + int(inv["file_bytes"])

    def sw_export_dir(self):
        return self.run_dir() / SW_EXPORT_DIR

    def sw_export_done(self):
        """This run's Skill Workshop export is complete (journal record and MANIFEST.json)."""
        if self.dry_run or not self.j or not self.j.get("run_id"):
            return False
        rec = (self.j.get("skill_workshop") or {}).get("export") or {}
        return bool(rec.get("complete")) and (self.sw_export_dir() / "MANIFEST.json").is_file()

    def fk_checks(self, F, state_db):
        """Precheck 9b (schema): PRAGMA foreign_key_check of the databases quick_check checked; appends findings
        to F and returns a summary part, or None for none.

        Read-only, in every mode (also on resume, dry-run and oc-upgrade check). OpenClaw checks foreign keys at
        the end of every agent schema migration (identity migration) and before it uses the state database
        (assertSqliteIntegrity, 2026.10.4 and 2026.10.10); the gate never deletes rows, so a violation in a
        database below its target is a hard HOLD before the first write. Only the task_delivery_state orphans
        OpenClaw's doctor repairs itself are information; a database already at its target only warns."""
        qc = self.facts.get("quick_check") or {}
        results, n, ok, skipped, repairable, failed = {}, 0, 0, 0, 0, 0
        for db in self.facts.get("checked_dbs") or []:
            rel_ = C.rel(db["path"], self.gp["STATE"])
            if qc.get(rel_) not in ("ok", "skipped"):
                continue  # reported by quick_check
            n += 1
            r = fk_check(db["path"])
            results[rel_] = r
            if r == "ok":
                ok += 1
                continue
            if r == "skipped":
                skipped += 1
                continue
            if r == "timeout":
                failed += 1
                F.append(finding("sqlite-check-timeout", "acceptable",
                                 f"foreign_key_check of {rel_} did not finish in time", "precheck"))
                continue
            if not isinstance(r, dict):
                failed += 1
                self.warn(f"foreign_key_check of {rel_} could not run: {r}")
                continue
            sample = "; ".join(f"{t} row {'?' if rid is None else rid} -> {par}" for t, rid, par, _fk in r["sample"]) \
                + ("; …" if r["count"] > len(r["sample"]) else "")
            if db["kind"] == "state" and r["repairable"]:
                repairable += 1
                self.say(f"{self.pn('precheck')} info: {rel_} has {r['count']} task_delivery_state row(s) whose "
                         "task run is gone; doctor deletes them (OpenClaw's own repair for this case)")
                continue
            failed += 1
            uv, target = db.get("uv"), db.get("target")
            label = "state schema" if db["kind"] == "state" else "agent schema"
            if uv is not None and target is not None and uv < target:
                if db["kind"] == "state":
                    msg = (f"{rel_} ({label} {uv}): {r['count']} foreign-key violation(s): {sample}. OpenClaw checks "
                           "the shared state database's foreign keys before it migrates or opens it and refuses it")
                else:
                    msg = (f"{rel_} ({label} {uv}, OpenClaw {self.pkg['version']} migrates it to {target}): "
                           f"{r['count']} foreign-key violation(s): {sample}. OpenClaw checks foreign keys at the end "
                           "of this one-way migration and stops it ('Agent schema migration failed foreign key "
                           "validation') while other databases are already migrated")
                F.append(finding("sqlite-fk-violation", "hard", msg, "precheck"))
            else:
                self.warn(f"{rel_} (already at {label} {uv}): {r['count']} foreign-key violation(s) ({sample}); "
                          "nothing migrates it now, but the next OpenClaw update will stop on them: restore that "
                          "database from a backup before then")
        self.facts["fk_check"] = {k: v if isinstance(v, str) else {"count": v["count"], "repairable": v["repairable"],
                                                                     "sample": [list(x) for x in v["sample"]]}
                                  for k, v in results.items()}
        if failed:
            return f"foreign keys FAILED ({failed} of {n})"
        extra = [f"{skipped} skipped"] if skipped else []
        extra += [f"{repairable} repaired by doctor"] if repairable else []
        return f"foreign keys ok ({ok}/{n}" + (", " + ", ".join(extra) if extra else "") + ")"

    def skill_workshop_info(self, F):
        """Precheck 11b (Skill Workshop): info and WARN lines about the proposals doctor will retire (never a
        finding: what doctor keeps back is harmless, the postconditions report it from the real state)."""
        inv = self.facts.get("sw_inventory")
        if not self.caps()["retires_skill_proposals"] or sw_empty(inv):
            return None
        bs = inv["by_status"]
        keep = sum(bs.get(s, 0) for s in SW_EXPORTED_STATUSES)
        legacy = f", {inv['legacy_bundles']} pre-SQLite draft folder(s)" if inv.get("legacy_bundles") else ""
        tail = (f"this run's export (secrets redacted): {self.sw_export_dir()}/" if self.sw_export_done() else
                "the gate exports all of them before doctor pass 1 (secrets redacted)")
        self.say(f"{self.pn('precheck')} info: Skill Workshop proposals: {inv['proposals']} ({sw_status_text(bs)}; "
                 f"{inv['events']} events, {inv['rollbacks']} rollback records, {inv['reviews']} collection reviews, "
                 f"{inv['files']} files{legacy}). OpenClaw {self.pkg['version']} doctor keeps only the {keep} "
                 "pending/quarantined drafts (as files in the owner agent's workshop-skills/.archive/"
                 f".retired-proposals/) and drops the rest; {tail}")
        warns = [f"doctor will keep the proposal storage (the migration continues; the gate reports it afterwards): "
                 f"{h}" for h in inv["holdbacks"]] + list(inv["unfinished"])
        for w in warns[:10]:
            self.warn(f"skill workshop: {w}")
        if len(warns) > 10:
            self.warn(f"skill workshop: and {len(warns) - 10} more")
        if self.j is not None and not self.j.get("first_write_at"):
            self.j.setdefault("skill_workshop", {})["inventory"] = sw_counts(inv)
        return None

    def cron_binding_forecast(self, F, mode):
        """Precheck 11c (cron, report only): enabled agentTurn jobs whose models would use a stored auth profile or
        AWS SDK credentials without a recorded inference account (runtime_caps cron_refusal). WARN/info only, never
        a HOLD. The stored logins include the ones doctor creates during this migration from literal provider keys
        (pending_copies; their key fix lines say how to keep the jobs). The providers whose auth "api-key" the gate
        sets itself before doctor pass 1 (cron_config_fixup) get a "config fixup: would set|will set" line, their
        jobs one "kept working by the automatic fix" info line, and the report shows the state after the fixup
        (journal: "autofix"); with $include in openclaw.json the gate writes nothing and WARNs the command instead.

        Before the first write only (a resumed run reports after doctor, cron_binding_postcheck). On a runtime
        whose doctor records the accounts itself (cron_doctor_migration) one info line; the jobs doctor leaves
        are reported after the migration."""
        caps = self.caps()
        if not caps["cron_refusal"] or (self.j or {}).get("first_write_at"):
            return None
        rt, dm, pn = self.pkg["version"], caps["cron_doctor_migration"], self.pn("precheck")
        try:
            rec = cron_account_report(self.gp["STATE"], self.cfg, rt, dm, pending_copies=True)
        except (sqlite3.Error, C.NodeQueryError, OSError, ValueError, TypeError) as exc:
            self.warn(f"could not check the cron jobs for their inference account ({type(exc).__name__}: "
                      f"{C.redact_text(str(exc))[:200]})")
            return None
        # the automatic config fixup before doctor pass 1 (cron_config_fixup): the jobs it keeps working are no
        # refusals, so the report shows the state after it
        plan, after = {"fix": [], "kept": [], "include": []}, None
        try:
            plan = cron_fixup_plan(self.gp["STATE"], self.cfg, self.cfg_raw, rt, dm, rec=rec)
            if plan["fix"] and not plan["include"]:
                after = cron_account_report(self.gp["STATE"], mig().set_provider_auth(self.cfg, plan["fix"])[0], rt,
                                            dm, pending_copies=True)
        except (sqlite3.Error, C.NodeQueryError, OSError, ValueError, TypeError) as exc:
            plan = {"fix": [], "kept": [], "include": []}
            self.warn(f"{pn} config fixup: could not check the auth stores ({type(exc).__name__}: "
                      f"{C.redact_text(str(exc))[:200]}); doctor pass 1 checks again")
        if after is not None:
            behind = []
            kept = cron_fixup_kept_jobs(rec, after, {f["provider"] for f in plan["fix"]}, behind)
            for f in plan["fix"]:
                self.say(f"{pn} config fixup: {'would set' if self.dry_run else 'will set'} {printable(f['path'])} = "
                         f"\"api-key\" before doctor pass 1 ({cron_fixup_why(f['provider'], rt)})")
            if kept:
                self.say(f"{pn} info: {cron_fixup_kept_text(kept, plan['fix'], rt)}")
            if behind:
                self.say(f"{pn} info: {cron_fixup_behind_text(behind)}")

            def on(entries, p_):
                return [str(a.get("id"))[:120] for a, refs in entries if any(r.split("/", 1)[0] == p_ for r in refs)]
            rec = dict(after, autofix=[])
            for f in plan["fix"]:  # jobs: kept working on f's provider; behind: reach it only after a refused ref
                ent = {"provider": f["provider"], "path": f["path"], "jobs": on(kept, f["provider"])}
                late = [x for x in on(behind, f["provider"]) if x not in ent["jobs"]]
                rec["autofix"].append(dict(ent, behind=late) if late else ent)
        elif plan["fix"]:
            for f in plan["fix"]:
                self.warn(f"{pn} {cron_fixup_include_text(f, rt, plan['include'])}")
            rec = dict(rec, autofix_skipped=[{"provider": f["provider"], "path": f["path"], "why": "include"}
                                             for f in plan["fix"]])
        for k in plan["kept"]:
            if k["why"] == "login":
                self.say(f"{pn} info: {cron_fixup_login_text(k)}")
        self.facts["cron_binding_plan"] = rec
        if self.j is not None:
            self.j["cron_binding_forecast"] = rec
        n = len(rec["affected"])
        if n and caps["cron_doctor_migration"]:
            aws = _cron_kinds(rec["affected"])[1]
            self.say(f"{self.pn('precheck')} info: {n} enabled cron job(s) without a recorded inference account use "
                     f"{_cron_on(rec['affected'])}; OpenClaw {self.pkg['version']} doctor records the account"
                     + (" of a stored login, not of AWS SDK credentials" if aws else "")
                     + " (openclaw/openclaw#172792); the gate reports the "
                     "jobs it leaves after the migration")
        elif n:
            for line in cron_job_lines(rec, fixup=bool(rec.get("autofix"))):
                self.warn(line)
        un = cron_unconfigured_line(rec)
        if un:
            self.say(f"{self.pn('precheck')} info: {un}")
        gone = cron_retired_review_line(rec)
        if gone:
            self.say(f"{self.pn('precheck')} info: {gone}")
        inc = cron_include_line(rec)
        if inc:
            self.warn(f"{self.pn('precheck')} {inc}")
        return None

    def cron_config_fixup(self, phase):
        """Before doctor pass 1, and before pass 2 if pass 1 ran without it (a run of an earlier add-on version):
        the automatic config fixup for openclaw/openclaw#192195 (decisions.md addendum 2026-11-05; runtime_caps
        cron_refusal, so nothing on 2026.10.4). For each provider whose literal openclaw.json key doctor copies into
        its auth store and that an enabled cron job uses (cron_fixup_plan), with no auth set and no stored login of
        its own: models.providers.<p>.auth = "api-key" in openclaw.json. OpenClaw then runs <p> on the configured
        key and does not refuse its unbound cron runs on doctor's copy.

        The one write of the cron work: openclaw.json through write_config (atomic replace, mode and owner kept,
        strict JSON as the gate reads it), never with $include (WARN with the command instead), never OpenClaw's
        databases or auth stores, no new copy of openclaw.json (config.pre-pass1.json, taken right after, shows what
        pass 1 starts from). No `config validate` before doctor pass 1: the pre-migration config may hold what only
        doctor converts; the value is in the provider schema of every runtime since 2026.10.4, and pc-config
        validates the result. Journal cron_autofix: "pending" before the write, "applied" after it ({provider, entry,
        path, old None = absent, new, reason, phase, at}; a resume never repeats an applied provider), ledger step C1.
        Never HOLDs: a failure leaves openclaw.json unchanged with a WARN. Returns the config it wrote, else None."""
        caps = self.caps()
        if not caps["cron_refusal"]:
            return None
        rt, pn = self.pkg["version"], self.pn(phase)
        rec = self.j.get("cron_autofix") if isinstance(self.j.get("cron_autofix"), dict) else {}
        applied = [dict(a) for a in rec.get("applied") or [] if isinstance(a, dict) and a.get("provider")]
        pending = [dict(a) for a in rec.get("pending") or [] if isinstance(a, dict) and a.get("provider")]
        try:
            cfg, raw = C.read_json_strict(self.gp["CONFIG_PATH"], with_text=True)
        except C.ConfigReadError as exc:
            self.warn(f"{pn} config fixup skipped: openclaw.json cannot be read ({C.redact_text(str(exc))[:200]})")
            return None
        if pending:  # cut off between the write and its journal record: applied when openclaw.json has it
            provs = _cfg_get(cfg, "models", "providers")
            applied += [a for a in pending if isinstance(provs, dict) and isinstance(provs.get(a.get("entry")), dict)
                        and provs[a["entry"]].get("auth") == mig().CRON_FIXUP_AUTH]
            self.j["cron_autofix"] = {"applied": applied}
            if applied:
                self.cron_fixup_ledger(applied)
            self.save()
        try:
            plan = cron_fixup_plan(self.gp["STATE"], cfg, raw, rt, caps["cron_doctor_migration"],
                                   done={a["provider"] for a in applied})
        except (sqlite3.Error, C.NodeQueryError, OSError, ValueError, TypeError) as exc:
            self.warn(f"{pn} config fixup skipped: could not check the cron jobs ({type(exc).__name__}: "
                      f"{C.redact_text(str(exc))[:200]}); openclaw.json unchanged")
            return None
        if not plan["fix"]:
            return None
        if plan["include"]:
            for f in plan["fix"]:
                self.warn(f"{pn} {cron_fixup_include_text(f, rt, plan['include'])}")
            return None
        new_cfg, _ledger = mig().set_provider_auth(cfg, plan["fix"])
        ents = [{"provider": f["provider"], "entry": f["entry"], "path": f["path"], "old": None,
                 "new": mig().CRON_FIXUP_AUTH, "reason": cron_fixup_why(f["provider"], rt), "phase": phase,
                 "at": C.utc_iso()} for f in plan["fix"]]
        self.j["cron_autofix"] = {"applied": applied, "pending": ents}
        self.save()
        try:
            self.write_config(new_cfg)
        except (OSError, ValueError) as exc:
            self.j["cron_autofix"] = {"applied": applied}
            self.save()
            self.warn(f"{pn} config fixup failed: openclaw.json could not be written ({type(exc).__name__}: "
                      f"{C.redact_text(str(exc))[:200]}); unchanged")
            return None
        self.j["cron_autofix"] = {"applied": applied + ents}
        self.cron_fixup_ledger(applied + ents)
        self.save()
        for a in ents:
            self.say(f"{pn} config fixup: {printable(a['path'])} = \"{a['new']}\" ({a['reason']})")
        return new_cfg

    def cron_fixup_ledger(self, applied):
        """transform-ledger.json step C1: one entry per config fixup of this run (no value but "api-key")."""
        M = mig()
        self.ledger_add([{"step": "C1", "path": M.fmt_path(["models", "providers", a["entry"], "auth"]),
                          "before": None, "after": a.get("new") or M.CRON_FIXUP_AUTH}
                         for a in applied if isinstance(a.get("entry"), str)], {"C1"})

    def skill_workshop_export(self):
        """Doctor pass 1 pre-pass hook (Skill Workshop): export every proposal before doctor retires them; runs
        before mark_first_write. May raise HoldError skill-workshop-export-failed (acceptable).

        Write-once per run (runs/<id>/skill-workshop/, MANIFEST.json last); kept until the user deletes it (the
        cleanup deletes only the run's plaintext config copies, run_plaintext_copies). It does not change the OpenClaw
        state, so it never counts as the first write.
        Also on a resumed run whose doctor already started (a held run after an image update, retry --doctor):
        whatever is still there is exported before the next pass."""
        if not self.caps()["retires_skill_proposals"]:
            return None
        sw = self.j.get("skill_workshop") or {}
        dest = self.sw_export_dir()
        if (dest / "MANIFEST.json").is_file():
            if not (sw.get("export") or {}).get("complete"):  # the journal save after the rename was lost
                rec = sw_export_record(self.gp, self.j["run_id"]) or {}
                self.j.setdefault("skill_workshop", {})["export"] = dict(rec, dir=C.rel(dest, self.gp["GATE"]),
                                                                         complete=True)
                self.save()
            self.say(f"4/8 skill workshop: export of this run already written ({dest}/)")
            return None
        ver = self.pkg["version"]
        try:
            inv = skill_workshop_inventory(self.gp["STATE"], self.cfg)
            if sw_empty(inv):
                if (sw.get("inventory") or {}).get("proposals"):
                    self.warn("skill workshop: the proposal storage the precheck counted is gone before doctor pass 1; "
                              "nothing to export")
                return None
            src = schema_meta_primary(self.gp["STATE"] / "state" / "openclaw.sqlite") or {}
            res = export_skill_workshop(self.gp["STATE"], dest, {"run_id": self.j["run_id"], "openclaw_to": ver,
                                                                 "openclaw_from": src.get("app_version")}, stop=STOP)
        except (GateStopped, C.Stopped):
            raise GateStopped()
        except Exception as exc:  # noqa: BLE001 - any failure: doctor must not run before the user decides
            msg = (f"could not export the Skill Workshop proposals before OpenClaw {ver} doctor drops them: "
                   f"{type(exc).__name__}: {C.redact_text(str(exc))[:240]}")
            if "skill-workshop-export-failed" in self.accepted:
                self.warn(f"accepted skill-workshop-export-failed: {msg}; no export: OpenClaw doctor keeps only the "
                          "pending and quarantined drafts")
                self.j.setdefault("skill_workshop", {})["export"] = {"accepted": True, "error": type(exc).__name__}
                self.save()
                return None
            raise HoldError([finding("skill-workshop-export-failed", "acceptable", msg, "doctor1")], "doctor1")
        self.j.setdefault("skill_workshop", {})["export"] = dict(res, dir=C.rel(dest, self.gp["GATE"]),
                                                                 at=C.utc_iso(), complete=True)
        self.save()
        self.say(f"4/8 skill workshop: exported {res['proposals']} proposals (all states), {res['events']} events, "
                 f"{res['rollbacks']} rollback records, {res['collection_reviews']} collection reviews and "
                 f"{res['files']} files ({res['redactions']} secrets redacted) -> {dest}/")
        for o in (res.get("omitted_paths") or [])[:5]:
            self.warn(f"skill workshop: skill-workshop/{printable(o)} not exported (a link, binary or larger than "
                      f"{C.human(SW_FILE_CAP)}); its size and sha256 are in proposals.json")
        return None

    def cron_binding_postcheck(self, cfg, summary):
        """Postconditions after pc-config (cron, report only): re-read the jobs of the migrated state (doctor may
        have changed them) into journal cron_binding for the finalize and status lines; never writes into
        OpenClaw's databases, never HOLDs."""
        caps = self.caps()
        if not caps["cron_refusal"]:
            return None
        try:
            rec = cron_account_report(self.gp["STATE"], cfg, self.pkg["version"], caps["cron_doctor_migration"])
        except (sqlite3.Error, C.NodeQueryError, OSError, ValueError, TypeError) as exc:
            self.warn(f"7/8 could not check the cron jobs for their inference account ({type(exc).__name__}: "
                      f"{C.redact_text(str(exc))[:200]})")
            return None
        self.j["cron_binding"] = dict(rec, checked_at=C.utc_iso())
        if rec["affected"]:
            summary.append(f"{len(rec['affected'])} cron job(s) without a recorded inference account (report below)")
        return None

    def skill_workshop_postcheck(self, summary):
        """Postconditions before the plugin WARNs (Skill Workshop): WARN when doctor kept the proposal storage
        (decided: WARN, no HOLD; the runtime ignores it and this run's export holds every proposal)."""
        if not self.caps()["retires_skill_proposals"]:
            return None
        sw = self.j.get("skill_workshop") or {}
        exp = sw.get("export") or {}
        where = self.gp["GATE"] / exp["dir"] if exp.get("complete") and exp.get("dir") else None
        try:
            inv = skill_workshop_inventory(self.gp["STATE"], self.cfg)
        except (sqlite3.Error, C.NodeQueryError, OSError, ValueError) as exc:
            self.warn(f"7/8 the Skill Workshop proposal storage could not be checked ({type(exc).__name__}: "
                      f"{C.redact_text(str(exc))[:200]})")
            return None
        if sw_empty(inv):
            if where or (sw.get("inventory") or {}).get("proposals"):
                summary.append("Skill Workshop proposals retired"
                               + (f" (export {C.rel(where, self.gp['GATE'])})" if where else ""))
            return None
        self.j.setdefault("skill_workshop", {})["retained"] = sw_counts(inv)
        self.warn(f"7/8 doctor kept the Skill Workshop proposal storage ({inv['proposals']} proposals, {inv['files']} "
                  f"files): OpenClaw {self.pkg['version']} ignores it; follow doctor's warning (oc-upgrade log), then "
                  "oc-upgrade retry --doctor to retire it."
                  + (f" This run's export holds every proposal: {where}/" if where else ""))
        return None

    def _finalize_skill_lines(self):
        """Finalize, after the doctor notes (Skill Workshop): info line about this run's export."""
        exp = (self.j.get("skill_workshop") or {}).get("export") or {}
        if exp.get("complete") and exp.get("dir"):
            self.say(f"info: Skill Workshop export of this run: {self.gp['GATE'] / exp['dir']}/ ({exp.get('proposals')} "
                     "proposals, secrets redacted); it is kept until you delete it (gate_cleanup_hours does not apply)")
        return None

    def record_doctor_copies(self, n):
        """After doctor pass n: the SQLite copies this pass created (not in the run's baseline taken before its first
        pass, not journaled by an earlier pass of the run), on the pass's journal record. They are deleted with the
        run's doctor captures (run_doctor_copies)."""
        cur = doctor_copies(self.gp["STATE"])
        base = set(self.j.get("doctor_copies_before") or [])
        known = {e.get("path") for d in self.j.get("doctor") or [] if isinstance(d, dict)
                 for e in d.get("pre_migration_backups") or [] if isinstance(e, dict)}
        new = [{"path": r, "size": size, "scope": scope} for r, (size, scope) in sorted(cur.items())
               if r not in base and r not in known]
        rec = self.j["doctor"][-1]
        rec["pre_migration_backups"] = new
        rec["pre_migration_backups_older"] = len(cur) - len(new)
        # beside agent databases outside the state dir: journaled and reported, never deleted by the add-on
        out_base = set(self.j.get("doctor_copies_outside_before") or [])
        out_known = {e.get("path") for d in self.j.get("doctor") or [] if isinstance(d, dict)
                     for e in d.get("pre_migration_backups_outside") or [] if isinstance(e, dict)}
        outside = [{"path": x, "size": size, "scope": scope} for x, (size, scope) in
                   sorted(outside_doctor_copies(outside_agent_dirs(self.gp["STATE"], self.cfg)).items())
                   if x not in out_base and x not in out_known]
        if outside:
            rec["pre_migration_backups_outside"] = outside
        self.save()
        if outside:
            self.warn(f"doctor pass {n}: " + outside_copies_text([e["path"] for e in outside], self.gp["STATE"]))
        return new

    def _finalize_cron_lines(self):
        """Finalize, after the Skill Workshop lines (cron): an info line per config fixup of this run (journal
        cron_autofix), then WARN lines per affected job of the postconditions' report (journal cron_binding).
        openclaw.json is read again: a fixup it no longer holds (removed or changed by hand, e.g. during a HOLD)
        gets the WARN of oc-upgrade status instead of its info line."""
        cfg = _read_cfg_lenient()
        done = cron_fixup_done_lines(self.j, cfg)
        for line in done:
            self.say(f"info: {line}")
        for line in cron_fixup_drift_lines(self.j, cfg, held=self.gp["HOLD"].exists()):
            self.warn(line.removeprefix("WARN: "))
        for line in cron_job_lines(self.j.get("cron_binding"), fixup=bool(done)):
            self.warn(line)
        un = cron_unconfigured_line(self.j.get("cron_binding"))
        if un:
            self.say(f"info: {un}")
        inc = cron_include_line(self.j.get("cron_binding"))
        if inc:
            self.warn(inc)
        return None

    def large_session_info(self):
        """Precheck 11d (openclaw/openclaw#191847, information only): the largest agent database and the event
        count of the biggest session's transcript, so the exposure to the reported out-of-memory of the 512 MB
        SQLite worker on large sessions can be judged. Read-only; runtime_caps large_session_oom_issue."""
        if not self.caps()["large_session_oom_issue"]:
            return None
        try:
            ls = largest_sessions(self.gp["STATE"], self.cfg)
        except (sqlite3.Error, C.NodeQueryError, OSError, ValueError) as exc:
            self.say(f"{self.pn('precheck')} info: session sizes not measured ({type(exc).__name__})")
            return None
        if not ls:
            return None
        self.facts["large_session"] = ls
        db, se = ls["db"], ls["session"]
        text = f"largest agent database {printable(db['path'])} ({C.human(db['bytes'])} with WAL)"
        if se:
            where = ", ".join(printable(x) for x in (se["channel"], se["chat_type"]) if x)
            text += (f"; biggest session: {se['events']} transcript events (agent {printable(se['agent'])}"
                     + (f", {where}" if where else "") + ")")
        self.say(f"{self.pn('precheck')} info: {text}. An open OpenClaw issue reports the 512 MB SQLite worker of "
                 f"OpenClaw {self.pkg['version']} running out of memory on large Telegram direct-chat sessions "
                 "(openclaw/openclaw#191847)")
        return None

    def phase_precheck(self):
        mode = self.j["mode"]
        generic = bool(self.j.get("first_write_at")) or mode != "from-7x"
        F, parts = self.precheck_findings(mode, generic)
        self.save()
        self.resolve(F, "precheck")
        jtxt = "journal empty (pre-journal 7.x)" if mode == "from-7x" and not generic else \
            ("resume: generic checks only" if self.j.get("first_write_at") else f"mode {mode}")
        self.say(f"1/8 precheck: {parts[0]}; {jtxt}; " + "; ".join(parts[1:]))

    # ----- phase 2: cleanup -----
    def retired_state(self, mode, cfg=None):
        cfg = self.cfg if cfg is None else cfg
        # env: what doctor sees (C.openclaw_env sets HOME to the config root; OPENCLAW_HOME/OAUTH_DIR pass through)
        return mig().classify_retired_state(str(self.gp["STATE"]), cfg, accepted=set(self.accepted), query=_mq,
                                            home=str(self.gp["CONFIG_ROOT"]), mode=mode,
                                            workspaces=[str(w) for w in workspaces(cfg)],
                                            config_root=str(self.gp["CONFIG_ROOT"]), caps=self.caps(),
                                            env=dict(os.environ, HOME=str(self.gp["CONFIG_ROOT"])))

    def retired_format_findings(self, mode, cfg_ok):
        """Mirror of the 2026.10 refusals (oc_migrate.classify_retired_state / retired_*): HOLD before any write."""
        M = mig()
        F = [dict(f) for f in M.retired_config_findings(self.cfg, mode, caps=self.caps(),
                                                        runtime=(self.pkg or {}).get("version"))] if cfg_ok else []
        rs = self.retired_state("from-7x" if mode == "from-7x" else "bump")
        self.facts["retired_state"] = rs
        F += [dict(f) for f in rs["findings"]]
        for i in rs["info"]:
            self.say(f"{self.pn('precheck')} info: {i}")
        for e in rs["plan"]:  # OpenClaw 2026.10.5+ runtime files (classify_retired_state caps)
            if e.get("proof") and e["proof"].startswith("nothing to import"):
                self.say(f"{self.pn('precheck')} info: nothing for OpenClaw to import, goes to quarantine: "
                         f"{e['rel']} ({e['proof']})")
            elif e.get("proof"):
                self.say(f"{self.pn('precheck')} info: already imported by OpenClaw, goes to quarantine: "
                         f"{e['rel']} ({e['proof']})")
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
                self.say(f"2/8 leave {kind}: {relp} ({e.get('reason', '')})")
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
                            "reason": e.get("reason", ""), **({"proof": e["proof"]} if e.get("proof") else {}),
                            "at": C.utc_iso(), **({"root": "config"} if in_cfg else {})})
                C.atomic_write_json(mpath, man)
            except OSError as exc:
                raise HoldError([finding("cleanup-failed", "hard", f"cannot quarantine {relp}: {exc}", "cleanup")],
                                "cleanup")
            counts[kind] = counts.get(kind, 0) + 1
            self.say(f"2/8 quarantine {kind}: {relp} ({C.human(st.st_size)}"
                     + (f"; proof: {e['proof']})" if e.get("proof") else ")"))
        total = sum(counts.values())
        detail = ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "nothing to move"
        self.say(f"2/8 cleanup: quarantined {total} files ({detail}) -> {qdir}/")

    # ----- phase 3: pre-migrate -----
    def phase_premigrate(self):
        if self.j.get("doctor_started"):
            self.say("3/8 pre-migrate: skipped (doctor already started)")
            return
        M = mig()
        p, rd = self.gp, self.run_dir()
        try:
            self.mark_first_write()
            self.copy_once(p["CONFIG_PATH"], rd / "config.pre-gate.json")
            cfg_pre = C.read_json_strict(rd / "config.pre-gate.json")
            rs = self.retired_state("from-7x", cfg_pre)
            removals = rs["config_removals"]
            new_cfg, ledger, summary = M.premigrate_config(cfg_pre, removals=removals,
                                                           rewrites=rs.get("config_rewrites") or [])
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
        self.say(f"3/8 pre-migrate: openai-codex/* -> {len(summary.get('explicit') or [])} explicit models "
                 f"(scopes: {scopes}); runtime pinned to openclaw on {summary.get('pinned', 0)} entries; "
                 f"{len(pinned)} sessions pinned; modelPolicy {{}} written: "
                 f"{'yes' if summary.get('model_policy_written') else 'no'}")
        removed_keys = {M.fmt_path(list(parts)) for parts in removals}
        r0 = [e["path"] for e in ledger if e.get("step") == "R0" and e["path"] in removed_keys]
        if r0:
            self.say("3/8 pre-migrate: removed retired key(s) OpenClaw 2026.10 refuses: " + ", ".join(r0))
        rw = [(f'{e["path"]} -> "{e["after"]}"' if e.get("after") is not None else f'removed {e["path"]}')
              for e in ledger if e.get("step") == "R0" and e["path"] not in removed_keys]
        if rw:  # OpenClaw 2026.10.5+ (retired_config_rewrites)
            self.say(f"3/8 pre-migrate: rewrote retired setting(s) OpenClaw {(self.pkg or {}).get('version')} "
                     "refuses: " + "; ".join(rw) + " (what OpenClaw 2026.10.4 doctor did)")

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
        label = f"{PHASE_NO[phase]}/8 doctor pass {n}"

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
        caps = self.caps()
        ev = evaluate_doctor(res.rc, text, timed_out=res.timed_out, stopping=STOP.is_set(), final=n >= 2,
                             retired_warning=caps["runtime_files_retired"] or caps["sandbox_registry_retired"])
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
        held = held_paths_from_doctor(text)  # full5: the stores doctor held back (Gate.held_map)
        if held:
            dh = self.j.setdefault("doctor_held", [])
            known = {x[1] for x in dh if isinstance(x, list) and len(x) == 3}
            dh += [x for x in held if x[1] not in known]
            del dh[200:]
        self.save()
        if ev["code"] == "interrupted":
            self.say(f"{label}: stop requested; " + (  # A2: say when the grace period ended in SIGKILL
                f"doctor did not stop within {C.fmt_duration(DOCTOR_STOP_GRACE)} and was killed (rc {res.rc})"
                if getattr(res, "killed", False) else f"doctor was asked to stop and stopped (rc {res.rc})"))
            raise GateStopped()
        ev["duration"] = res.duration
        ev["text"] = text
        return ev

    def doctor_failure(self, ev, phase, n):
        if ev["code"] and ev["cls"] == "hard":
            raise HoldError([finding(ev["code"], "hard", f"pass {n}: {ev['message']}", phase)], phase)

    def phase_doctor1(self):
        rd, p = self.run_dir(), self.gp
        self.skill_workshop_export()  # full5: before the first write and before doctor_started
        self.mark_first_write()
        self.j["doctor_started"] = True
        if "doctor_copies_before" not in self.j:  # doctor's SQLite copies that existed before this run's doctor
            self.j["doctor_copies_before"] = sorted(doctor_copies(p["STATE"]))[:1000]
            outside = sorted(outside_doctor_copies(outside_agent_dirs(p["STATE"], self.cfg)))
            if outside:  # beside agent databases outside the state dir (only journaled when there are any)
                self.j["doctor_copies_outside_before"] = outside[:1000]
        self.save()
        self.cron_config_fixup("doctor1")  # full5: auth "api-key" for cron jobs on a literal key (2026.10.10+)
        self.copy_once(p["CONFIG_PATH"], rd / "config.pre-pass1.json")
        if self.j.get("plugins_before") is None:
            self.j["plugins_before"] = plugin_snapshot(p["STATE"])
            self.save()
        ev = self.run_doctor_pass(1, "doctor1")
        baks = self.record_doctor_copies(1)  # only the copies of this pass (full .bak / table-scoped .scoped.bak)
        self.doctor_failure(ev, "doctor1", 1)
        self.j["doctor_notes"] = doctor_notes(ev["text"])
        for c in p["STATE"].rglob("*.capturing"):
            self.warn(f"leftover {C.rel(c, p['STATE'])} after doctor pass 1")
        try:
            self.save_copy(p["CONFIG_PATH"], rd / "config.post-pass1.json")
            pre = C.read_json_strict(rd / "config.pre-pass1.json")
            post = C.read_json_strict(rd / "config.post-pass1.json")
            removed = sorted(mig().flatten_paths(pre) - mig().flatten_paths(post))
            if removed:
                self.say(f"4/8 doctor removed {len(removed)} config key(s): " + ", ".join(removed[:40])
                         + (" …" if len(removed) > 40 else ""))
            tuning = mig().retired_tuning_dropped(pre, post)
            if tuning:
                self.warn("doctor removed memory search tuning that OpenClaw 2026.9+ no longer supports (recall now "
                          "uses fixed values: hybrid vector/text 0.7/0.3, MMR 0.7, recency decay with a 365-day half-life in this "
                          "add-on): "
                          + ", ".join(tuning[:8]))
        except C.ConfigReadError as exc:
            self.warn(f"cannot compare config before/after pass 1: {exc}")
        self.say(f"4/8 doctor pass 1 rc={ev['rc']} in {C.fmt_duration(ev['duration'])}: Doctor complete. "
                 f"({copies_text(baks)}{'; not the rollback point' if baks else ''})")
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
            self.say(f"5/8 fixups: {summary.get('codex_pins', 0)} codex runtime pins -> openclaw; "
                     f"{summary.get('refs_rewritten', 0)} legacy refs rewritten; compaction restored: "
                     f"{'yes' if summary.get('compaction_restored') else 'no'}; {plugin}")
        else:
            self.say(f"5/8 fixups: {plugin}")
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
                self.say(f"5/8 info: GLM thinking levels: {ref} left as is ({why})")
        if not refs:
            return
        if not on:
            self.say(f"5/8 info: {', '.join(refs)} only switch thinking on/off (qwen-chat-template); the add-on "
                     "option glm_thinking_levels sends the thinking level instead")
            return
        if not glm_runtime_ok(self.pkg.get("version")):  # 7.35 sends "high" for off and refuses max
            self.say(f"5/8 info: GLM thinking levels need OpenClaw 2026.9+ (runtime {self.pkg.get('version')}); "
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
        self.say(f"5/8 GLM thinking levels: {', '.join(refs)} send the level as reasoning_effort "
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
            self.say("5/8 GLM thinking levels: the step was interrupted before its check finished; "
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
        fixed = self.cron_config_fixup("doctor2")  # full5: only when pass 1 ran without it (earlier add-on version)
        if fixed is not None:  # the baseline of changed_paths: pass 2's diff must not list the gate's own write
            C.atomic_write_json(rd / "config.post-fixups.json", fixed)
        sha0 = _sha_or_none(p["CONFIG_PATH"])
        ev = self.run_doctor_pass(2, "doctor2")
        self.after_later_pass(ev, 2)
        self.doctor_failure(ev, "doctor2", 2)
        warnings = acceptable_doctor(ev)
        sha1 = _sha_or_none(p["CONFIG_PATH"])
        result = "config unchanged"
        hold = None
        if sha1 != sha0:
            self.say("6/8 doctor pass 2 changed openclaw.json: " + ", ".join(self.changed_paths(rd)[:40]))
        # F1b also after pass 2 (contract addendum 2 rule 4: a re-added codex plugin entry is removed again)
        self.post_pass_fixups(2)
        if sha1 != sha0:
            sha1f = _sha_or_none(p["CONFIG_PATH"])
            ev3 = self.run_doctor_pass(3, "doctor2")
            self.after_later_pass(ev3, 3)
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
            self.say("6/8 info: doctor installed the @openclaw/codex plugin (Codex was in use before the migration)")
        others = [x for x in new if x not in codex]
        if others:
            self.warn("doctor installed new plugin package(s): " + ", ".join(others) + " (left in place)")
        leftovers = plugin_install_leftovers(p["STATE"])  # D8: not plugins; whether doctor or an earlier run left them
        if leftovers:
            self.warn("plugin install leftovers: " + install_leftovers_text(leftovers))
        self.say(f"6/8 doctor pass 2 rc={ev['rc']} in {C.fmt_duration(ev['duration'])}: Doctor complete.; {result}")
        self.complete_phase("doctor2")
        F = []
        for w in warnings:  # one finding per code, the first pass that reported it
            if w["code"] not in {f["code"] for f in F}:
                F.append(finding(w["code"], "acceptable", w["message"], "doctor2"))
        if hold:
            F.append(hold)
        if F:
            self.resolve(F, "doctor2", resume_after=True)

    def after_later_pass(self, ev, n):
        """Doctor pass 2/3: its own SQLite copies, and the Skill Workshop notes of a retirement that only finishes in
        a later pass (the other doctor notes come from pass 1 only)."""
        new = self.record_doctor_copies(n)
        if new or "Saved pre-migration SQLite backup" in normalize_doctor_text(ev["text"]):
            self.warn(f"doctor pass {n} saved another pre-migration SQLite copy (doctor's own; not the rollback "
                      "point)")
        notes = self.j.setdefault("doctor_notes", [])
        add = [x for x in doctor_notes(ev["text"], _SW_NOTE_RES) if x not in notes]
        if add:
            notes += add
            self.save()

    def changed_paths(self, rd):
        try:
            a = _flatten_leaves(C.read_json_strict(rd / "config.post-fixups.json")) if (rd / "config.post-fixups.json").exists() \
                else _flatten_leaves(C.read_json_strict(rd / "config.post-pass1.json"))
            b = _flatten_leaves(self.read_config())
        except C.ConfigReadError:
            return ["(unreadable)"]
        return sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))

    # ----- phase 7: postconditions -----
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
                    self.say("7/8 auth.order.openai written (subscription first, API key as fallback)")
        # pc-schema (hard; full5: stores doctor held back of agents that are not configured are listed, not
        # required, on runtimes whose gateway skips them; classify)
        cls = classify(p["STATE"], cfg, self.pkg["schema_state"], self.pkg["schema_agent"], self.pkg["version"],
                       held=self.held_map(True))
        if cls["schema_verdict"] != "ok":
            hard("pc-schema", "; ".join(self.pc_schema_items(cls, cfg) + cls["newer"]) or "schema verdict not ok")
        if cls["held"]:
            self.say("7/8 info: held agent database(s) left at their schema, not checked: "
                     + ", ".join(f"{h['path']} (agent {h['id']}, schema {h['uv']}: {held_reason_text(h['reason'])})"
                                 for h in cls["held"]) + "; the gateway does not open them")
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
        # cron inference accounts (full5, report only)
        self.cron_binding_postcheck(cfg, summary)
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
        # Skill Workshop storage (full5, WARN only)
        self.skill_workshop_postcheck(summary)
        # plugins (WARN only)
        res, data = self.oc_json(["plugins", "list", "--json"], 180, "pc-plugins")
        installs = official_plugin_installs(p["STATE"], cfg)
        for w in plugin_version_warnings(data, self.pkg["version"], installs):
            self.warn(w)
        # D2: the WARN promises plugins-sync after the gate; run.sh skips it while the version's marker exists (a
        # plugin enabled after that step ran), so a stale marker goes
        cohort = plugin_cohort_marker(p["STATE"], self.pkg["version"])
        if plugins_behind(listed_official_plugins(data, installs), self.pkg["version"]) and cohort.exists():
            try:
                cohort.unlink()
            except OSError as exc:
                self.warn(f"could not delete {cohort} ({exc}); delete it so the add-on updates the plugins")
        self.save()
        if policy:
            self.resolve(policy, "postconditions")
        self.say("7/8 postconditions OK: " + ", ".join(summary))

    def pc_schema_items(self, cls, cfg):
        """cls['gate'] for the pc-schema HOLD; on runtimes that refuse agents per agent (2026.10.10+, runtime_caps
        held_store_skip) each configured agent store below the target says what OpenClaw does with it."""
        if not self.caps()["held_store_skip"]:
            return list(cls["gate"])
        configured = {norm_agent_id(a) for a in configured_agent_ids(cfg)}  # as OpenClaw compares them
        default = norm_agent_id(default_agent_id(cfg))
        held_cfg = {h["path"]: h["reason"] for h in cls.get("held_configured") or []}
        notes = {}
        for key, relp in (cls.get("agent_paths") or {}).items():
            uv = (cls.get("agents") or {}).get(key)
            if uv is None or uv >= cls["targets"]["agent"]:
                continue
            aid = norm_agent_id((cls.get("agent_ids") or {}).get(key, key))
            bits = []
            if aid == default:
                bits.append("configured default agent: the gateway refuses to start (exit 78) or stays not ready")
            elif aid in configured:
                bits.append("configured agent: OpenClaw refuses this agent")
            if relp in held_cfg:
                bits.append(f"held back by doctor: {held_cfg[relp]}")
            if bits:
                notes[f"{relp}: agent schema {uv} < {cls['targets']['agent']}"] = "; ".join(bits)
        return [f"{g} ({notes[g]})" if g in notes else g for g in cls["gate"]]

    # ----- phase 8: pins -----
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
            self.say(f"8/8 pins: previous ledger archived as {old.name} (new 2026.7.x migration)")
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
        new_cfg, written, skipped = M.apply_pins(base, set(ledgered),
                                                 retires_skill_proposals=self.caps()["retires_skill_proposals"])
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
        self.say(f"8/8 pins: wrote {len(written)}, skipped {len(skipped)} (already set / condition); ledger {p['LEDGER']}")

    # ----- finalize -----
    def phase_finalize(self):
        p = self.gp
        cfg = _read_cfg_lenient()
        cls = classify(p["STATE"], cfg, self.pkg["schema_state"], self.pkg["schema_agent"], self.pkg["version"],
                       held=self.held_map(True))
        # D11: what doctor did with the orphan stores the precheck recorded (migrated, set aside as .corrupt-<ms>, ...)
        outcomes = orphan_outcomes(p["STATE"], self.j.get("orphans"), self.pkg["schema_agent"],
                                   since=self.j.get("started_at"))
        if outcomes:
            self.j["orphan_outcomes"] = outcomes
        after = {o["path"]: o["outcome"] for o in outcomes}
        orphans = [dict(o, after=after[o["path"]]) if isinstance(o, dict) and o.get("path") in after else o
                   for o in self.j.get("orphans") or []]
        write_marker(mode=self.j["mode"], run_id=self.j["run_id"], binding=current_binding(p["STATE"], cls),
                     runtime=self.pkg["version"], accepted=sorted(self.accepted), orphans=orphans,
                     held=held_marker_entries(p["STATE"], cls))
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
        for o in outcomes:  # D11: a WARN where something is left for the user
            text = orphan_outcome_text(o, self.pkg["schema_agent"])
            if o["outcome"] in ("migrated", "gone") and not o["set_aside"]:
                self.say(f"info: {text}")
            else:
                self.warn(text)
        self._finalize_skill_lines()  # full5: doctor notes -> Skill Workshop -> cron -> done
        self._finalize_cron_lines()
        total = _elapsed_since(self.j.get("started_at"))
        self.say(f"done: MIGRATED {self.pkg['version']} (run {self.j['run_id']}, mode {self.j['mode']}, "
                 f"total {C.fmt_duration(total)})")
        hours = C.gate_options()["cleanup_hours"]
        a = self.j.get("archive") or {}  # a run resumed from 0.5.94-full1/full2 may have one
        what = (f"the doctor captures and the archive {printable(a.get('dir'))}/{printable(a.get('file'))}"
                if a.get("file") else "the doctor captures")
        # A5/A7: and the run's plaintext files (run_plaintext_copies)
        what += (" of this run and the gate's plaintext copies of openclaw.json in its run directory (config.*.json, "
                 "with the saved models status output)")
        if hours:
            due = C.utc_iso(C.utc_now() + timedelta(hours=hours))
            self.say(f"info: {what} are deleted after {due} (gate_cleanup_hours={hours})")
        else:
            self.say(f"info: {what} are kept (gate_cleanup_hours=0): delete them yourself")
        copies = [e for d in self.j.get("doctor") or [] if isinstance(d, dict)
                  for e in d.get("pre_migration_backups") or [] if isinstance(e, dict) and e.get("scope")]
        if copies:  # owner rule: plaintext database copies go like the doctor captures
            self.say(f"info: this run's {copies_text(copies)} (plaintext, beside the databases; not the rollback "
                     "point): " + ("deleted at the same time" if hours else
                                   "kept too (gate_cleanup_hours=0), delete them yourself"))
        outside = run_outside_copies(self.j)
        if outside:
            self.warn(outside_copies_text(outside, self.gp["STATE"]))

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
                    if prev.get("status") == "hold" and (prev.get("hold") or {}).get("code") in POST_RUN_HOLDS:
                        # retry --doctor after an exit-78/crash-loop hold: the earlier run's doctor captures must
                        # outlive this point (their retention restarts here, see run_due_base)
                        prev.setdefault("history", []).append({"at": C.utc_iso(),
                                                               "event": "journal superseded by a new run"})
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
                      "budget": {}, "transform": {}, "doctor": [], "accepted": [], "hold": None,
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


def printable(s):
    """Names from /share or /config listings in a log line: control characters escaped (no forged lines)."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in str(s))


def state_symlinks(state_dir, cls):
    """Symlinks on the way to every database the predicate knows (F1): the state dir, state/, agents/
    and each target agent's directories and DB file. A backup (tar) stores a symlink as a bare link."""
    state_dir = Path(state_dir)
    cands = [state_dir, C.paths()["CONFIG_PATH"], state_dir / "state", state_dir / "state" / "openclaw.sqlite",
             state_dir / "agents"]
    for relp in sorted(set(((cls or {}).get("agent_paths") or {}).values())):
        if os.path.isabs(relp):
            continue  # outside the state dir: not a link below it
        cur = state_dir
        for part in Path(relp).parts:
            cur = cur / part
            cands.append(cur)
    out = []
    for c in cands:
        if os.path.islink(c) and str(c) not in out:
            out.append(str(c))
    return out


def _sha_or_none(p):
    try:
        return C.sha256_file(p)
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


def fk_check(path, budget_s=None):
    """PRAGMA foreign_key_check of one database, read-only (full5, precheck 9b).

    'ok' | 'timeout' | 'skipped' (WAL without -shm index, too large for a private copy) | 'unreadable (...)' |
    {'count': n, 'sample': [(table, rowid, parent, fkid)] (first 5), 'repairable': bool}. repairable: every row is
    the task_delivery_state -> task_runs cascade relation doctor --fix repairs (sqlite-integrity.ts
    runSqliteForeignKeyCheck / readTaskDeliveryCascadeForeignKeyId). Aborts via progress handler on timeout or
    stop (GateStopped) like quick_check; never writes next to the database (query_ro)."""
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
        return "skipped"
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

    def run(sql):
        try:
            return C.query_ro(path, sql, progress_handler=handler)
        except sqlite3.OperationalError as exc:
            if why[0] == "stop":
                raise GateStopped()
            if why[0] == "timeout":
                return "timeout"
            return _node_fk_query(path, sql, budget_s, exc)
        except sqlite3.DatabaseError as exc:
            return _node_fk_query(path, sql, budget_s, exc)
        except OSError as exc:
            return f"unreadable ({exc})"
    if STOP.is_set():
        raise GateStopped()
    if time.monotonic() > deadline:
        return "timeout"
    rows = run("PRAGMA foreign_key_check")
    if isinstance(rows, str):
        return rows
    if not rows:
        return "ok"
    viol = [(str(r[0]), r[1], str(r[2]), r[3]) for r in rows]
    repairable = False
    if all(t == "task_delivery_state" and par == "task_runs" for t, _rid, par, _fk in viol):
        fks = run("PRAGMA foreign_key_list(task_delivery_state)")
        if isinstance(fks, list):
            # columns: id, seq, table, from, to, on_update, on_delete, match
            cand = [r for r in fks if r[2] == "task_runs" and r[3] == "task_id" and r[4] == "task_id"
                    and str(r[6]).upper() == "CASCADE"]
            if cand and sum(1 for r in fks if r[0] == cand[0][0]) == 1:
                repairable = all(fk == cand[0][0] for _t, _rid, _par, fk in viol)
    return {"count": len(viol), "sample": viol[:5], "repairable": repairable}


def _node_fk_query(path, sql, budget_s, exc):
    try:
        rows = C.node_query(path, sql, timeout=budget_s, stop_event=STOP)
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


# --- cron inference accounts (full5, openclaw/openclaw#192195; report only) ----------------------
# Read-only. codex_cron_ids (F15) keeps its own 7.x column reader: a 10.x job on an openai/ model must not
# mark Codex as in use (critic). Nothing here writes into OpenClaw's databases or auth stores. The one write is
# the config fixup of Gate.cron_config_fixup (decisions.md addendum 2026-11-05): models.providers.<p>.auth
# "api-key" in openclaw.json, before doctor pass 1, for a provider whose literal key doctor copies.
CRON_REPORT_MAX = 20
CRON_FIXUP_ISSUE = "openclaw/openclaw#192195"
CRON_MANUAL_EDIT = ("openclaw automations edit <id> --model <provider/model>@<profileId>; it records the account, but "
                    "the job then runs only on that account's provider and its fallbacks to other providers are "
                    "refused (openclaw/openclaw#192463)")
CRON_MANUAL = "Manual alternative after the start: " + CRON_MANUAL_EDIT
# after a key fix line (cron_key_fix_lines): the binding is the last resort, it costs the cross-provider fallbacks
CRON_MANUAL_LAST = "Otherwise (last resort), after the start: " + CRON_MANUAL_EDIT
CRON_ENV_REF = '{"source":"env","provider":"default","id":"<VAR>"}'
# AWS SDK credentials are no stored account: model@profile cannot record them (prepare-auth.ts refuses an aws-sdk
# profile as the job's account), and OpenClaw's own migration (2026.11.5) leaves such a job unbound as well.
CRON_AWS_SDK = ("A model on AWS SDK credentials (models.providers.<provider>.auth \"aws-sdk\") cannot be recorded as "
                "a job's account, also not by OpenClaw's own migration from 2026.11.5: after the start, give the job "
                "a model whose provider runs on a configured key (models.providers.<provider>.apiKey, an environment "
                "variable or a SecretRef) or a local model: openclaw automations edit <id> --model <provider/model> "
                "(for a fallback: --fallbacks <list> without it)")
# a job whose own model needs no stored login and that stops at a fallback on one: no binding (model@profile would
# make that fallback the job's model), and OpenClaw's own migration (2026.11.5) leaves the job unbound
CRON_FALLBACK = ("For a job that only stops at a fallback, after the start: drop that fallback (openclaw automations "
                 "edit <id> --fallbacks <list> without it; the job's own list replaces the agent's and the default "
                 "fallbacks), or run that fallback's provider on a configured key (models.providers.<provider>.apiKey "
                 "as an env SecretRef, or a literal key with models.providers.<provider>.auth \"api-key\"): every run "
                 "of that provider, not only cron, then uses that key instead of its stored login (for a subscription "
                 "login: the metered API key)")


def _cron_kinds(aff):
    """(any affected ref on a stored login, any on AWS SDK credentials) of cron_account_report entries; a record
    without "aws_sdk" (also one of an earlier add-on version) is all stored logins."""
    aws = any(a.get("aws_sdk") for a in aff)
    return any(set(a.get("refs") or []) - set(a.get("aws_sdk") or []) for a in aff) or not aws, aws


def _cron_on(aff):
    """What the affected jobs stop at, for the summary lines."""
    prof, aws = _cron_kinds(aff)
    return " or ".join(x for x, on in (("a stored login", prof), ("AWS SDK credentials", aws)) if on)


def _cron_fallback_only(aff):
    """The affected entries whose own model needs no stored login and that stop at a fallback on a stored login (not
    only on AWS SDK credentials)."""
    return [a for a in aff if not a.get("primary_affected")
            and set(a.get("refs") or []) - set(a.get("aws_sdk") or [])]


def _cron_remedy(aff, key_fix=False):
    """The closing advice: the model@profile binding for a job whose own model is on a stored login (the last resort
    after key fix lines), dropping the fallback or a configured key for a job that only stops at one (no binding: it
    would make that fallback the job's model), a configured-key model for AWS SDK credentials (which no binding can
    record)."""
    aws = _cron_kinds(aff)[1]
    prim = any(a.get("primary_affected") and (a.get("refs") or [""])[0] not in (a.get("aws_sdk") or [])
               for a in aff)
    fb = bool(_cron_fallback_only(aff))
    manual = CRON_MANUAL_LAST if key_fix else CRON_MANUAL
    if prim and fb:  # say which jobs the binding is for
        manual = manual.replace("after the start: ", "after the start, for a job whose own model is refused: ", 1)
    return ". ".join(x for x, on in ((manual, prim), (CRON_FALLBACK, fb), (CRON_AWS_SDK, aws)) if on)


def _cron_key_fix(rec):
    """{provider: key_fix entry} of a cron_account_report record (none in a record of an earlier add-on version)."""
    return {k["provider"]: k for k in (rec or {}).get("key_fix") or []
            if isinstance(k, dict) and isinstance(k.get("provider"), str) and k["provider"]}


def _cron_promise(aff, rec):
    """Whose account OpenClaw's own migration records from 2026.11.5 (#172792), for the closing note: the jobs whose
    own model is on a stored login that is no copy of a provider key. That migration resolves only the job's own model
    (inference-binding-migration.ts resolveCronModelSelection) and skips a job whose model runs on a configured key or
    needs none, so a job that only stops at a fallback stays unbound; it would bind a key-fix provider's jobs to
    doctor's copy; AWS SDK credentials are no stored account. "" when no such job is left."""
    keyed = _cron_key_fix(rec)

    def provider(a):
        r = (a.get("refs") or [""])[0]
        return r.split("/", 1)[0] if "/" in r else None
    prim = [a for a in aff if a.get("primary_affected") and a.get("refs")
            and a["refs"][0] not in (a.get("aws_sdk") or []) and provider(a) not in keyed]
    if not prim:
        return ""
    if len(prim) == len(aff):
        return "such jobs"
    if any(a.get("primary_affected") and provider(a) in keyed for a in aff):
        return "the jobs whose own model is on another stored login"
    return "the jobs whose own model is on a stored login"


def _cron_outlook(aff, rec):
    """What OpenClaw's own migration (2026.11.5, #172792) will do for the affected jobs, as clauses for the closing
    note and `oc-upgrade status`: the account of a job's own model is recorded, but a bound job's fallbacks to other
    providers are refused (cron/run-inference.ts assertCandidate, as with model@profile: #192463); a job whose own
    model needs no account stays unbound, and its fallback on a stored login stays refused (embedded runner
    auth-plan.ts: an unbound cron attempt on a stored profile)."""
    who = _cron_promise(aff, rec)
    out = []
    if who:
        out.append(f"OpenClaw records the inference account of {who} itself from 2026.11.5 (doctor migration, "
                   "openclaw/openclaw#172792), but then refuses their fallbacks to other providers (as with "
                   "openclaw/openclaw#192463)")
    if _cron_fallback_only(aff):
        out.append("OpenClaw's own migration" + ("" if who else " (2026.11.5, openclaw/openclaw#172792)")
                   + " records only the account of a job's own model: a job whose own model needs no account stays "
                   "unbound, and its fallback on a stored login stays refused")
    return out


def cron_key_fix_lines(rec, indent="", held=False):
    """One line per provider of a cron_account_report record's key_fix: OpenClaw's doctor copies (copied) the
    provider's literal key into its auth store, a stored login on which the cron jobs above are refused; the fix
    keeps them and their fallbacks: auth "api-key" (accepted by 2026.10.4 too) or an env SecretRef (the only one
    offered with auth "oauth"/"token"; for a key only in a model catalog: declare it in openclaw.json). Provider ids
    and config paths only, never a key value. held (`oc-upgrade status`): OpenClaw is held (hold.txt), so the wrapper
    refuses `openclaw config set` and `openclaw automations` until the HOLD is cleared; a command not already
    deferred to "after the start" is worded like the drift line (cron_fixup_drift_lines): the hand edit of
    openclaw.json, or the command after the HOLD is cleared."""
    rt = (rec or {}).get("runtime") or "2026.10.10+"
    lines = []
    for p_, k in _cron_key_fix(rec).items():
        p, base = printable(p_), printable(k.get("path") or f"models.providers.{p_}")
        pending = bool(k.get("pending"))
        env_cmd = f"openclaw config set {shlex.quote(base + '.apiKey')} '{CRON_ENV_REF}' --strict-json"
        env_ref = f"a gateway_env_vars entry, then {env_cmd}"
        how = ("To keep them and their fallbacks, " if pending else
               f"To lift the refusal for the cron jobs above that use {p} and keep their fallbacks, ")
        if k.get("where") == "catalog":
            head = (f"provider {p}: an agent's model catalog (models.json) holds a literal API key for {p} "
                    "(placeholders such as EMPTY or NONE count as keys); "
                    + (f"OpenClaw {rt} doctor copies it into OpenClaw's auth store during the migration, and the cron "
                       f"jobs above that use {p} are refused on it from then on" if pending else
                       f"OpenClaw {rt} runs {p} on a stored login (OpenClaw's doctor copies such a key into its auth "
                       "store)"))
            fix = (how + f"declare the key in openclaw.json instead: {base}.apiKey with {base}.auth \"api-key\", or "
                   f"as an env SecretRef (a gateway_env_vars entry and {CRON_ENV_REF} as {base}.apiKey)")
        else:
            own = bool(k.get("own_login"))
            if own:  # the refusal comes from that login, not from doctor's copy
                head = (f"provider {p}: OpenClaw {rt} runs {p} on a stored login of its own (a subscription login, a "
                        f"token or another API key), not on the literal key in {base}.apiKey")
            elif pending:
                head = (f"provider {p}: its key in {base}.apiKey is a literal value (placeholders such as EMPTY or "
                        f"NONE count as keys); OpenClaw {rt} doctor copies it into OpenClaw's auth store during the "
                        f"migration, and the cron jobs above that use {p} are refused on it from then on")
                how += "after the start, "
            else:
                head = (f"provider {p}: OpenClaw {rt} runs {p} on a stored login although {base}.apiKey holds a key (a "
                        "literal value, which OpenClaw's doctor copies into its auth store)")
            # "after the start" (pending, no login of its own) already defers the commands past a HOLD
            by_hand = held and (own or not pending)
            refused = "while OpenClaw is held the wrapper refuses openclaw config set"
            if k.get("auth") in ("oauth", "token"):
                ref = (f"a gateway_env_vars entry and {CRON_ENV_REF} as {base}.apiKey, set in openclaw.json by hand "
                       f"({refused}) or after the HOLD is cleared: {env_cmd}" if by_hand else env_ref)
                fix = how + f"give the key as an env SecretRef: {ref} ({base}.auth \"{k['auth']}\" stays)"
            else:
                fix = (how + (f"set {base}.auth to \"api-key\" in openclaw.json by hand ({refused}), or after the "
                              "HOLD is cleared run: " if by_hand else "run: ")
                       + f"openclaw config set {shlex.quote(base + '.auth')} api-key (OpenClaw then uses the "
                       f"configured key for {p}, not the stored {'copy' if pending else 'login'}; no restart needed"
                       + ("; 2026.10.4 accepts this setting and runs the same" if pending and not own else "")
                       + "), or give the key as an env SecretRef ("
                       + (f"a gateway_env_vars entry and {CRON_ENV_REF} as {base}.apiKey in openclaw.json" if by_hand
                          else env_ref) + ")")
            if own:  # prepare-auth.ts providerBindingSuppressesProfiles: for every run of the provider, not only cron
                prim = any(a.get("primary_affected") and str((a.get("refs") or [""])[0]).split("/", 1)[0] == p_
                           for a in (rec or {}).get("affected") or [] if isinstance(a, dict))
                fix += (f"; this makes every run of {p}, not only cron, use the configured key instead of that login. "
                        "To keep the login" + (", after the HOLD is cleared" if by_hand else "")
                        + f": drop {p} from the job's fallbacks (openclaw automations edit <id> "
                        "--fallbacks <list> without it)"
                        + (f", and for a job whose own model is on {p} the last resort below" if prim else ""))
        lines.append(f"{indent}{head}. {fix}")
    return lines


# cron/system-owned-declaration.ts: jobs with this declaration key are retired from 2026.10.10 (2026.10.4 retired only
# the older skillCollectionReview payload)
RETIRED_REVIEW_PREFIX = "skill-collection-review:"


def cron_jobs_inventory(state_db):
    """Cron jobs of the 2026.10 layout (state DB cron_jobs.job_json) in store order:
    [{store_key, id, name, enabled, runtime_authority, job}], where job keeps only what the forecast reads
    (agentId, sessionKey, sessionTarget, binding fields, payload kind/model/fallbacks; never the prompt) and
    is None when job_json is not a JSON object. [] without the table or for the 7.x wide-row layout
    (payload_model columns; reported after the migration)."""
    state_db = Path(state_db)
    if not state_db.exists():
        return []
    tables = table_names(state_db)
    cols = {r[1] for r in q(state_db, "PRAGMA table_info(cron_jobs)")} if "cron_jobs" in tables else set()
    if "job_json" not in cols or "payload_model" in cols:
        return []
    authority = set()
    if "cron_job_runtime_authorities" in tables:  # a scheduled runtime authority is not refused (auth-plan.ts)
        authority = {(r[0], r[1]) for r in q(state_db, "SELECT store_key, job_id FROM cron_job_runtime_authorities "
                                                      "WHERE recovery_required=0")}
    out = []
    extra = ", ".join(c if c in cols else "NULL" for c in ("declaration_key", "payload_kind"))
    for sk, jid, name, enabled, text, decl, pkind in q(
            state_db, f"SELECT store_key, job_id, name, enabled, job_json, {extra} FROM cron_jobs "
                      "ORDER BY store_key, sort_order, job_id"):
        try:
            raw = json.loads(text) if isinstance(text, str) else None
        except ValueError:
            raw = None
        job = None
        if isinstance(raw, dict):
            pl = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
            job = {k: raw[k] for k in ("agentId", "sessionKey", "sessionTarget", "inferenceBinding",
                                       "authProfileBinding") if k in raw}
            job["payload"] = {k: pl[k] for k in ("kind", "model", "fallbacks") if k in pl}
        # Skill Workshop's retired weekly curator (cron/store/load.kernel.ts isRetiredCollectionReview, 2026.10.10+:
        # deleted when the cron store is loaded for writing, hidden on a read-only load)
        decl = decl if decl is not None else (raw.get("declarationKey") if isinstance(raw, dict) else None)
        retired = (pkind == "skillCollectionReview"
                   or (isinstance(raw, dict) and isinstance(raw.get("payload"), dict)
                       and raw["payload"].get("kind") == "skillCollectionReview")
                   or (isinstance(decl, str) and decl.startswith(RETIRED_REVIEW_PREFIX)))
        out.append({"store_key": sk, "id": str(jid), "name": str(name or ""), "enabled": bool(enabled),
                    "runtime_authority": (sk, jid) in authority, "job": job, "retired_review": retired})
    return out


def _store_profiles(text):
    """[{id, provider}] of an auth profile store JSON (ids and providers only, never credentials)."""
    try:
        store = json.loads(text) if isinstance(text, str) else None
    except ValueError:
        return []
    profiles = store.get("profiles") if isinstance(store, dict) else None
    return [{"id": str(pid), "provider": str(p.get("provider") or "")}
            for pid, p in sorted(profiles.items()) if isinstance(p, dict)] if isinstance(profiles, dict) else []


def auth_profile_index(state_dir, targets, state_db, tables):
    """{"agents": {agent id: [{id, provider}]}, "shared": [...]} of the auth stores: each agent database's
    auth_profile_store, and the shared store every agent inherits (the state DB's config_machine_state
    'authProfiles.store' when 'auth.sharedStore' says state-db, else the main agent's store)."""
    agents = {}
    for aid, pth in targets:
        try:
            if "auth_profile_store" not in table_names(pth):
                continue
            rows = q(pth, "SELECT store_json FROM auth_profile_store WHERE store_key='primary'")
        except (sqlite3.Error, C.NodeQueryError, OSError):
            continue
        if rows:
            agents.setdefault(str(aid).lower(), []).extend(_store_profiles(rows[0][0]))
    shared = agents.get("main", [])
    if "config_machine_state" in tables:
        own = q(state_db, "SELECT value_json FROM config_machine_state WHERE state_key='auth.sharedStore'")
        try:
            loc = json.loads(own[0][0]).get("location") if own else None
        except (ValueError, AttributeError, TypeError):
            loc = None
        if loc == "state-db":
            rows = q(state_db, "SELECT value_json FROM config_machine_state WHERE state_key='authProfiles.store'")
            shared = _store_profiles(rows[0][0]) if rows else []
    return {"agents": agents, "shared": shared}


PLUGIN_CATALOG_SCOPE = "plugin-model-catalog-v1"
PLUGIN_CATALOG_GENERATED_BY = "openclaw-plugin-model-catalog-v1"


def doctor_catalogs(state_dir, targets, orphans):
    """[(agent id, is the main agent dir, {provider key: apiKey value})] of the model catalogs OpenClaw's doctor reads
    for plaintext credentials (doctor-model-catalog-credentials.ts, 2026.10.10 = 2026.11.1): <agentDir>/models.json
    (oc_migrate.parse_model_catalog_json; unreadable or invalid files are skipped, as doctor does) and the agent
    database's generated plugin catalogs (cache_entries, scope plugin-model-catalog-v1, generatedBy
    openclaw-plugin-model-catalog-v1), for agents/main/agent, every agents/*/agent and the directory of each
    configured or registered agent database, minus agents retained after deletion. Read-only; the values stay in
    memory for oc_migrate.doctor_key_copies and are never kept or printed. Not modelled: a configured agentDir
    without an agent database, OPENCLAW_AGENT_DIR."""
    state_dir = Path(state_dir)
    main = state_dir / "agents" / "main" / "agent"
    dirs = {os.path.realpath(main): ("main", main)}
    for aid, pth in list(targets) + list(orphans):
        dirs.setdefault(os.path.realpath(pth.parent), (str(aid).lower(), pth.parent))
    root = state_dir / "agents"
    for d in sorted(root.glob("*/agent")) if root.is_dir() else []:
        if d.is_dir():
            dirs.setdefault(os.path.realpath(d), (d.parent.name.lower(), d))
    retained = {os.path.dirname(p) for p, (_a, why) in deletion_journal_held(state_dir).items() if why == HELD_RETAINED}
    out = []
    for real, (aid, d) in sorted(dirs.items()):
        if real in retained:
            continue
        found = []
        text = mig()._read_regular_text(str(d / "models.json"))
        try:
            root_json = mig().parse_model_catalog_json(text) if text is not None else None
        except (ValueError, RecursionError):
            root_json = None
        if isinstance(root_json, dict) and isinstance(root_json.get("providers"), dict):
            found.append(root_json["providers"])
        db = d / "openclaw-agent.sqlite"
        try:
            rows = q(db, "SELECT value_json FROM cache_entries WHERE scope=? ORDER BY key", (PLUGIN_CATALOG_SCOPE,)) \
                if db.is_file() and "cache_entries" in table_names(db) else []
        except (sqlite3.Error, C.NodeQueryError, OSError):
            rows = []
        for (vj,) in rows:
            try:
                cat = json.loads(vj) if isinstance(vj, str) else None
            except (ValueError, RecursionError):
                continue
            if isinstance(cat, dict) and cat.get("generatedBy") == PLUGIN_CATALOG_GENERATED_BY \
                    and isinstance(cat.get("providers"), dict):
                found.append(cat["providers"])
        for provs in found:
            keys = {k: v.get("apiKey") for k, v in provs.items() if isinstance(k, str) and isinstance(v, dict)}
            if keys:
                out.append((aid, real == os.path.realpath(main), keys))
    return out


def cron_account_report(state_dir, cfg, runtime=None, doctor_migration=False, pending_copies=False):
    """Forecast for openclaw/openclaw#192195 on the current state (read-only): oc_migrate.cron_account_forecast
    with the auth profiles of the stores and of auth.profiles in openclaw.json, and the profiles OpenClaw's doctor
    creates from literal provider keys (oc_migrate.doctor_key_copies over openclaw.json and doctor_catalogs);
    pending_copies (precheck, before doctor ran): those copies are not in the stores yet. Names and ids are cut for
    the journal; no prompt, profile id or credential is kept."""
    state_dir = Path(state_dir)
    cfg = cfg if isinstance(cfg, dict) else {}
    state_db = state_dir / "state" / "openclaw.sqlite"
    rec = {"runtime": runtime, "doctor_migration": bool(doctor_migration), "checked": 0, "bound": 0, "affected": [],
           "key_fix": []}
    jobs = cron_jobs_inventory(state_db)
    if C.runtime_caps(runtime)["retires_skill_proposals"]:  # OpenClaw deletes these jobs (doctor pass 1): no forecast
        gone = [x for x in jobs if x.get("retired_review") and x.get("enabled")]
        jobs = [x for x in jobs if not x.get("retired_review")]
        if gone:
            rec["retired_review"] = [{"id": str(x["id"])[:120], "name": C.redact_text(str(x["name"]))[:120]}
                                     for x in gone[:CRON_REPORT_MAX]]
            rec["retired_review_count"] = len(gone)
    if not jobs:
        return rec
    tables = table_names(state_db)
    targets, orphans = agent_databases(state_dir, cfg, tables)
    index = auth_profile_index(state_dir, targets, state_db, tables)
    cfg_profiles = _cfg_get(cfg, "auth", "profiles")
    declared = [{"id": str(pid), "provider": str(p.get("provider") or "")}
                for pid, p in sorted(cfg_profiles.items()) if isinstance(p, dict)] \
        if isinstance(cfg_profiles, dict) else []

    def profiles_for(aid):
        return index["agents"].get(aid, []) + index["shared"] + declared

    def store_ids(aid):
        return {p["id"] for p in (index["shared"] if aid is None else index["agents"].get(aid, []))}
    copies = mig().doctor_key_copies(cfg, doctor_catalogs(state_dir, targets, orphans), store_ids)

    def copies_for(aid):
        return copies["shared"] + copies["agents"].get(aid, [])
    configured = {mig().normalize_agent_id(a) for a in configured_agent_ids(cfg)}  # as OpenClaw compares them
    fc = mig().cron_account_forecast(jobs, cfg, profiles_for, default_agent_id(cfg), copies_for, pending_copies,
                                     configured=configured)
    # job names are free text (an agent may name a reminder from the conversation): redacted, then cut
    rec.update(checked=fc["checked"], bound=fc["bound"],
               affected=[dict(a, id=str(a["id"])[:120], name=C.redact_text(str(a["name"]))[:120])
                         for a in fc["affected"]],
               key_fix=fc["key_fix"])
    if fc["unconfigured"]:  # D6: only when there are any (a record of an earlier add-on version has none)
        rec["unconfigured"] = [dict(a, id=str(a["id"])[:120], name=C.redact_text(str(a["name"]))[:120])
                               for a in fc["unconfigured"]]
    # a key fix provider with a stored login of its own: auth "api-key" or a SecretRef sets that login aside for every
    # run of it (cron_key_fix_lines says so); only an unreadable store leaves the entries unmarked
    cand = {}
    provs = _cfg_get(cfg, "models", "providers")
    for k in rec["key_fix"]:
        entry = next((v for x, v in provs.items() if isinstance(x, str) and x.strip().lower() == k["provider"]
                      and isinstance(v, dict)), None) if isinstance(provs, dict) and k.get("where") == "config" \
            else None
        if entry is not None and isinstance(entry.get("apiKey"), str):
            cand[k["provider"]] = entry["apiKey"]
    try:
        own = own_provider_logins(state_dir, cfg, cand) if cand else set()
    except (sqlite3.Error, C.NodeQueryError, OSError):
        own = set()
    for k in rec["key_fix"]:
        if k["provider"] in own:
            k["own_login"] = True
    # $include: the report reads only openclaw.json itself (cron_include_line); only when there are jobs to check
    inc = mig().include_paths(cfg)
    if inc and (fc["checked"] or fc["unconfigured"]):
        rec["include"] = [str(x)[:120] for x in inc[:4]]
    return rec


def cron_job_label(a):
    """'<name>' (<id>) of a cron job in a log or status line: the name redacted before the cut (a record of an earlier
    add-on version kept it as stored), control characters escaped."""
    return f"'{C.redact_text(printable(a.get('name')))[:80]}' ({printable(a.get('id'))[:80]})"


def cron_unconfigured_line(rec):
    """D6: the info text for the enabled agentTurn jobs of a cron_account_report record whose agent openclaw.json
    does not configure (OpenClaw cancels their runs), or None. With $include in openclaw.json an included file may
    configure them (not checked)."""
    un = [a for a in (rec or {}).get("unconfigured") or [] if isinstance(a, dict)]
    if not un:
        return None
    agents = ", ".join(dict.fromkeys(printable(a.get("agent")) for a in un))
    jobs = ", ".join(cron_job_label(a) for a in un[:CRON_REPORT_MAX])
    more = f" and {len(un) - CRON_REPORT_MAX} more" if len(un) > CRON_REPORT_MAX else ""
    if rec.get("include"):
        return (f"{len(un)} enabled cron job(s) belong to agent(s) that openclaw.json itself does not configure "
                f"({agents}; its included files are not checked): unless an included file configures them, OpenClaw "
                f"cancels their runs ('cron job agent is unavailable'); the inference-account report leaves them out: "
                f"{jobs}{more}")
    return (f"{len(un)} enabled cron job(s) belong to agent(s) not configured in openclaw.json ({agents}): OpenClaw "
            f"cancels their runs ('cron job agent is unavailable'), so the inference-account report leaves them out: "
            f"{jobs}{more}")


def cron_retired_review_line(rec):
    """The info text for enabled cron jobs of Skill Workshop's retired weekly curator (skill-collection-review-*) in a
    cron_account_report record, which OpenClaw deletes when doctor loads the cron store; None without any."""
    gone = [a for a in (rec or {}).get("retired_review") or [] if isinstance(a, dict)]
    if not gone:
        return None
    n = (rec or {}).get("retired_review_count") or len(gone)
    rt = (rec or {}).get("runtime") or "2026.10.10+"
    more = f" and {n - len(gone)} more" if n > len(gone) else ""
    return (f"{n} enabled cron job(s) of Skill Workshop's retired weekly curator: OpenClaw {rt} doctor deletes them "
            f"during the migration (no replacement), so the inference-account report and the config fixup leave them "
            f"out: {', '.join(cron_job_label(a) for a in gone)}{more}")


def cron_include_line(rec):
    """WARN text for a cron_account_report record of an openclaw.json with $include, or None: the report and the
    config fixup see only openclaw.json itself (the gate never writes such a file, and OpenClaw's doctor also copies
    a literal key of a provider defined in an included file)."""
    inc = [printable(x) for x in (rec or {}).get("include") or [] if isinstance(x, str)]
    if not inc:
        return None
    rt = (rec or {}).get("runtime") or "2026.10.10+"
    return (f"openclaw.json uses $include ({', '.join(inc)}): the cron report reads only openclaw.json itself, so "
            "providers and agents defined in included files are not checked, and the gate makes no automatic config "
            "fixup. For a provider defined there with a literal apiKey that cron jobs use, run after the start: "
            "openclaw config set models.providers.<provider>.auth api-key (doctor stores such a key as a login, and "
            f"OpenClaw {rt} then refuses every unbound cron run on it: {CRON_FIXUP_ISSUE}; for a provider with a "
            "stored login of its own this sets that login aside for every run, not only for cron)")


def cron_job_lines(rec, fixup=False):
    """Per-job WARN texts of a cron_account_report record, the key fix lines, then the closing note (empty when
    none). fixup: the lines above name a config fixup of this run (planned or made), which the closing note
    excepts."""
    aff = (rec or {}).get("affected") or []
    if not aff:
        return []
    rt = rec.get("runtime") or "2026.10.10+"
    keyed = _cron_key_fix(rec)
    lines = []
    for a in aff[:CRON_REPORT_MAX]:
        refs = [printable(r) for r in a.get("refs") or []]
        aws = {printable(r) for r in a.get("aws_sdk") or []}
        copied = {printable(r) for r in a.get("key_copy") or []}
        head = f"cron job {cron_job_label(a)}: "
        more = "".join(f"; also on {on}: {', '.join(x)}" for on, x in (
            ("a stored login", [r for r in refs[1:] if r not in aws]),
            ("AWS SDK credentials", [r for r in refs[1:] if r in aws])) if x)
        if a.get("primary_affected") and refs[0] in aws:
            lines.append(head + f"OpenClaw {rt} refuses every run and tries no fallback: its model {refs[0]} would "
                         f"run on AWS SDK credentials (models.providers.{refs[0].split('/', 1)[0]}.auth "
                         "\"aws-sdk\"), which OpenClaw refuses for a cron job without a recorded inference account "
                         "(openclaw/openclaw#192195)" + more)
        elif a.get("primary_affected") and refs[0] in copied:
            k = keyed.get((a.get("refs") or [""])[0].split("/", 1)[0]) or {}
            p = printable(k.get("path") or f"models.providers.{refs[0].split('/', 1)[0]}")
            where = (f"a literal API key in an agent's model catalog (models.json, provider "
                     f"{printable(k.get('provider'))})" if k.get("where") == "catalog" else
                     f"the API key written as a literal value in {p}.apiKey")
            lines.append(head + f"OpenClaw {rt} refuses every run and tries no fallback: its model {refs[0]} runs on "
                         f"{where}, which OpenClaw {rt} doctor copies into its auth store during this migration (a "
                         "stored login from then on); the job has no recorded inference account "
                         "(openclaw/openclaw#192195)" + more)
        elif a.get("primary_affected"):
            lines.append(head + f"OpenClaw {rt} refuses every run and tries no fallback: its model {refs[0]} would "
                         "use a stored login (auth profile) and the job has no recorded inference account "
                         "(openclaw/openclaw#192195)" + more)
        else:
            primary = f"its model {printable(a['primary'])}" if a.get("primary") else "its primary model"
            on = ("AWS SDK credentials" if refs[0] in aws else
                  "its literal API key becomes a stored login during the migration" if refs[0] in copied else
                  "stored login")
            sep = ";" if refs[0] in copied else ","
            # with $include the report sees only openclaw.json itself (cron_include_line)
            seen = " (as far as openclaw.json itself shows; its included files are not checked)" \
                if rec.get("include") else ""
            lines.append(head + f"{primary} needs no stored login{seen} and keeps working, but when it fails OpenClaw "
                         f"{rt} stops at the fallback {refs[0]} ({on}{sep} no recorded inference account; "
                         "openclaw/openclaw#192195) instead of trying further models" + more)
    if len(aff) > CRON_REPORT_MAX:
        lines.append(f"and {len(aff) - CRON_REPORT_MAX} more cron job(s) (oc-upgrade status)")
    lines += cron_key_fix_lines(rec)
    remedy = _cron_remedy(aff, bool(keyed))
    if rec.get("doctor_migration"):
        lines.append(f"{len(aff)} cron job(s) above still have no recorded inference account after the migration: "
                     f"OpenClaw {rt} doctor left them (its warnings are in oc-upgrade log). {remedy}")
    else:
        lines.append(f"{len(aff)} cron job(s) above: the add-on changes nothing for these jobs"
                     + (" apart from the config fixup above" if fixup else "")
                     + "".join("; " + x for x in _cron_outlook(aff, rec)) + ". " + remedy)
    return lines


def own_provider_logins(state_dir, cfg, candidates, env=None):
    """The providers of `candidates` ({provider (lower case): its literal models.providers.<p>.apiKey}) that have a
    stored login of their own: a profile of that provider that is not an api_key profile holding exactly that key
    (doctor's copy; credentialMatches of doctor-model-catalog-credentials.ts), in an auth store the gateway reads
    (each configured or registered agent database's auth_profile_store, the shared store in the state database), or
    an auth.profiles entry of openclaw.json for it in another mode than api_key. Doctor copies the key as OpenClaw
    reads it, after its ${NAME} / ${NAME:-default} substitution (oc_migrate.env_substituted with `env`, by default
    the environment the gate gives doctor, which holds the gateway_env_vars): a copy of the key as written or as
    substituted is doctor's. auth "api-key" would set any other login aside for every run of the provider (a
    subscription login, a token, another key, or doctor's copy of an earlier value), not only for cron, so the
    config fixup leaves that provider to the report. The values are compared in memory and never kept, printed or
    journaled. Raises sqlite3.Error, C.NodeQueryError or OSError when a store cannot be read."""
    state_dir = Path(state_dir)
    if env is None:
        try:
            env = C.openclaw_env()
        except Exception:  # noqa: BLE001 - only the comparison value depends on it
            env = dict(os.environ)
    copies = {p: {v, mig().env_substituted(v, env)} for p, v in candidates.items()}
    state_db = state_dir / "state" / "openclaw.sqlite"
    tables = table_names(state_db) if state_db.exists() else set()
    targets, _orphans = agent_databases(state_dir, cfg, tables)
    texts = []
    for _aid, pth in targets:
        if "auth_profile_store" in table_names(pth):
            texts += [r[0] for r in q(pth, "SELECT store_json FROM auth_profile_store WHERE store_key='primary'")]
    if "config_machine_state" in tables:  # read also while auth.sharedStore points elsewhere: only ever skips a fixup
        texts += [r[0] for r in q(state_db, "SELECT value_json FROM config_machine_state "
                                            "WHERE state_key='authProfiles.store'")]
    own = set()
    for text in texts:
        try:
            store = json.loads(text) if isinstance(text, str) else None
        except ValueError:
            store = None
        profiles = store.get("profiles") if isinstance(store, dict) else None
        for prof in profiles.values() if isinstance(profiles, dict) else []:
            p = str(prof.get("provider") or "").strip().lower() if isinstance(prof, dict) else ""
            if p in candidates and not (prof.get("type") == "api_key" and isinstance(prof.get("key"), str)
                                        and prof["key"] in copies[p]):
                own.add(p)
    declared = _cfg_get(cfg, "auth", "profiles")
    for prof in declared.values() if isinstance(declared, dict) else []:
        p = str(prof.get("provider") or "").strip().lower() if isinstance(prof, dict) else ""
        if p in candidates and prof.get("mode") != "api_key":
            own.add(p)
    return own


def cron_fixup_plan(state_dir, cfg, raw_text, runtime, doctor_migration=False, done=(), rec=None):
    """The config fixup of Gate.cron_config_fixup on the current state (read-only): {"rec": the cron_account_report
    with doctor's pending copies (`rec` when the caller has it), "fix" / "kept": oc_migrate.cron_key_autofix with
    own_provider_logins, "include": the $include paths of openclaw.json (then the gate writes nothing)}. May raise
    what cron_account_report and own_provider_logins raise."""
    cfg = cfg if isinstance(cfg, dict) else {}
    if rec is None:
        rec = cron_account_report(state_dir, cfg, runtime, doctor_migration, pending_copies=True)
    fix, kept = mig().cron_key_autofix(cfg, rec.get("key_fix"), lambda c: own_provider_logins(state_dir, cfg, c),
                                       set(done))
    return {"rec": rec, "fix": fix, "kept": kept, "include": mig().include_paths(cfg, raw_text)}


def cron_fixup_why(provider, runtime):
    """The reason of a config fixup line (provider id only, never a key)."""
    return (f"doctor stores its literal key as a login; without this OpenClaw {runtime or '2026.10.10+'} refuses every "
            f"unbound cron run on {printable(provider)}: {CRON_FIXUP_ISSUE}")


def cron_fixup_include_text(f, runtime, inc):
    """WARN text for a fixup the gate does not make because openclaw.json uses $include."""
    return (f"config fixup skipped: openclaw.json uses $include ({', '.join(printable(x) for x in inc[:4])}), so the "
            f"gate does not write it; after the start run: openclaw config set {shlex.quote(f['path'])} api-key "
            f"({cron_fixup_why(f['provider'], runtime)})")


def cron_fixup_login_text(k):
    """Info text for a provider the fixup leaves alone because it has a stored login of its own (own_provider_logins;
    that may also be an API key doctor copied from an earlier value of the configured one), with the command."""
    p, path = printable(k["provider"]), printable(k["path"])
    return (f"no automatic config fixup for {p}: it has a stored login of its own: a subscription login, a token, or a "
            "stored API key that differs from the configured one (possibly doctor's copy of an earlier value). "
            f"{path} = \"api-key\" sets that login aside for every run of {p}, not only for cron; to do so after the "
            f"start: openclaw config set {shlex.quote(str(k['path']))} api-key. The provider {p} line gives the other "
            "options")


def cron_fixup_kept_jobs(before, after, providers, behind=None):
    """[(affected entry of `before`, [refs])]: the jobs whose refs on `providers` are refused in `before` (the forecast
    without the fixup) and not in `after` (with it), counting a ref only when no ref that `after` still refuses comes
    before it in the job's chain (the refusal stops the chain there: recordModelFallbackStop). behind: a list that
    gets the (entry, [refs]) of the jobs with such refs that come only after a ref still refused."""
    later = {}
    for a in (after or {}).get("affected") or []:
        later.setdefault(a.get("id"), set()).update(a.get("refs") or [])
    out = []
    for a in (before or {}).get("affected") or []:
        still, kept, late = later.get(a.get("id"), set()), [], []
        blocked = False
        for r in a.get("refs") or []:
            if r in still:
                blocked = True
            elif "/" in r and r.split("/", 1)[0] in providers:
                (late if blocked else kept).append(r)
        if kept:
            out.append((a, kept))
        if late and behind is not None:
            behind.append((a, late))
    return out


def cron_fixup_kept_text(kept, fix, runtime):
    """Info text: the cron jobs the automatic fix keeps working (job id, name and model refs only)."""
    provs = {r.split("/", 1)[0] for _a, refs in kept for r in refs}
    paths = ", ".join(printable(f["path"]) for f in fix if f["provider"] in provs)
    models = ", ".join(dict.fromkeys(printable(r) for _a, refs in kept for r in refs))
    jobs = ", ".join(cron_job_label(a) for a, _r in kept[:CRON_REPORT_MAX])
    more = f" and {len(kept) - CRON_REPORT_MAX} more" if len(kept) > CRON_REPORT_MAX else ""
    return (f"{len(kept)} enabled cron job(s) kept working by the automatic fix ({paths} = \"api-key\" before doctor "
            f"pass 1; otherwise OpenClaw {runtime} refuses {models} on doctor's copy of the literal key): {jobs}{more}")


def cron_fixup_behind_text(behind):
    """Info text: the cron jobs that reach a model the automatic fix covers only after a fallback that stays refused,
    so the fix does not keep them working (job id, name and model refs only)."""
    models = ", ".join(dict.fromkeys(printable(r) for _a, refs in behind for r in refs))
    jobs = ", ".join(cron_job_label(a) for a, _r in behind[:CRON_REPORT_MAX])
    more = f" and {len(behind) - CRON_REPORT_MAX} more" if len(behind) > CRON_REPORT_MAX else ""
    return (f"{len(behind)} enabled cron job(s) reach {models} only after a fallback that stays refused (the WARN "
            f"lines below): the automatic fix covers that model, but the job stops before it: {jobs}{more}")


def _fixup_pass(phase):
    return {"doctor1": 1, "doctor2": 2}.get(phase, 1)


def _cron_fixup_drift(a, cfg):
    """What openclaw.json (`cfg`, read now) shows instead of the applied config fixup `a` (journal cron_autofix
    "applied" entry): "the provider entry is gone", "the setting is removed" or "now <value>"; None while it holds
    models.providers.<entry>.auth = "api-key", and for an entry without its fields or an unreadable `cfg` ({})."""
    if not (isinstance(cfg, dict) and cfg and isinstance(a, dict) and isinstance(a.get("entry"), str)
            and a.get("provider") and a.get("path")):
        return None
    provs = _cfg_get(cfg, "models", "providers")
    ent = provs.get(a["entry"]) if isinstance(provs, dict) else None
    now = ent.get("auth") if isinstance(ent, dict) else None
    if now == mig().CRON_FIXUP_AUTH:
        return None
    return ("the provider entry is gone" if not isinstance(ent, dict) else
            "the setting is removed" if now is None else f"now {printable(json.dumps(now))[:40]}")


def cron_fixup_drift_lines(j, cfg, held=False):
    """A4, `oc-upgrade status` and finalize: a config fixup of gate run `j` that openclaw.json (`cfg`, read now) no
    longer holds: models.providers.<p>.auth is not "api-key" any more (removed or changed by hand), so OpenClaw
    refuses the unbound cron runs on <p> again. One WARN line per provider, with the command; [] when `cfg` is
    unreadable ({}). held: OpenClaw is held (hold.txt), so the wrapper refuses `openclaw config set` until the HOLD
    is cleared; the line says so and names the hand edit of openclaw.json."""
    rec = (j or {}).get("cron_autofix")
    rt = printable((j or {}).get("runtime") or "2026.10.10+")
    out = []
    for a in rec.get("applied") or [] if isinstance(rec, dict) else []:
        state = _cron_fixup_drift(a, cfg)
        if state is None:
            continue
        p, path = printable(a["provider"]), str(a["path"])
        cmd = f"openclaw config set {shlex.quote(path)} api-key"
        how = (f"To restore: set it in openclaw.json by hand (while OpenClaw is held the wrapper refuses openclaw "
               f"config set), or after the HOLD is cleared: {cmd}" if held else f"To restore: {cmd}")
        out.append(f"WARN: openclaw.json no longer holds this run's config fixup {printable(path)} = \"api-key\" "
                   f"({state}): OpenClaw {rt} then runs {p} on the copy of its key that doctor stored and refuses its "
                   f"unbound cron runs again ({CRON_FIXUP_ISSUE}), unless the key now comes from the environment (env "
                   f"SecretRef). {how}")
    return out


def cron_fixup_done_lines(j, cfg=None):
    """The config fixups gate run `j` made (journal cron_autofix "applied"), for finalize and `oc-upgrade status`.
    cfg (finalize: openclaw.json read now): only those it still holds (_cron_fixup_drift; all when it is unreadable),
    the others get cron_fixup_drift_lines instead."""
    rec = (j or {}).get("cron_autofix")
    rt = printable((j or {}).get("runtime") or "2026.10.10+")
    out = []
    for a in rec.get("applied") or [] if isinstance(rec, dict) else []:
        if cfg is not None and _cron_fixup_drift(a, cfg) is not None:
            continue
        if isinstance(a, dict) and a.get("provider") and a.get("path"):
            p = printable(a["provider"])
            out.append(f"config fixup of this run: {printable(a['path'])} = \"{printable(a.get('new') or 'api-key')}\" "
                       f"(before doctor pass {_fixup_pass(a.get('phase'))}): OpenClaw {rt} runs {p} on the configured "
                       f"key, so its unbound cron runs on {p} are not refused on doctor's copy ({CRON_FIXUP_ISSUE}); "
                       "transform-ledger.json step C1")
    return out


def _db_bytes(pth):
    n = 0
    for p_ in (str(pth), f"{pth}-wal"):
        try:
            st = os.lstat(p_)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            n += st.st_size
    return n


def largest_sessions(state_dir, cfg):
    """openclaw/openclaw#191847 exposure (read-only): {"db": {agent, path, bytes}, "session": {agent, events,
    channel, chat_type} or None} for the configured and registered agent databases; None without any."""
    state_dir = Path(state_dir)
    state_db = state_dir / "state" / "openclaw.sqlite"
    tables = table_names(state_db) if state_db.exists() else set()
    targets, _orphans = agent_databases(state_dir, cfg if isinstance(cfg, dict) else {}, tables)
    db = sess = None
    for aid, pth in targets:
        size = _db_bytes(pth)
        if db is None or size > db["bytes"]:
            db = {"agent": aid, "path": C.rel(pth, state_dir), "bytes": size}
        try:
            at = table_names(pth)
            if "transcript_events" not in at:
                continue
            rows = q(pth, "SELECT session_id, count(*) AS n FROM transcript_events GROUP BY session_id "
                          "ORDER BY n DESC LIMIT 1")
            if not rows or (sess is not None and rows[0][1] <= sess["events"]):
                continue
            win = q(pth, "SELECT channel, chat_type FROM session_windows WHERE session_id=?", (rows[0][0],)) \
                if "session_windows" in at else []
        except (sqlite3.Error, C.NodeQueryError, OSError):
            continue
        ch, ct = win[0] if win else (None, None)
        sess = {"agent": aid, "events": int(rows[0][1]), "channel": str(ch)[:40] if ch else None,
                "chat_type": str(ct)[:20] if ct else None}
    return {"db": db, "session": sess} if db else None


# --- Skill Workshop proposals (full5, OpenClaw 2026.10.10+) -------------------------------------

def _sw_quote(name):
    return '"' + str(name).replace('"', '""') + '"'


def _sw_columns(state_db, table):
    return [str(r[1]) for r in q(state_db, f"PRAGMA table_info({_sw_quote(table)})")]


def _sw_json(text):
    try:
        return json.loads(text) if isinstance(text, str) else None
    except ValueError:
        return None


def _sw_owner_from_session(key):
    """The agent id of an "agent:<id>:..." session key (OpenClaw's parseAgentSessionKey), else None."""
    if isinstance(key, str):
        parts = key.strip().split(":")
        if len(parts) >= 3 and parts[0].lower() == "agent" and parts[1].strip():
            return parts[1].strip().lower()
    return None


def skill_workshop_inventory(state_dir, cfg):
    """Read-only count of the Skill Workshop proposal storage OpenClaw 2026.10.10+ doctor retires: the four tables of
    the shared state database and the files below <state>/skill-workshop/. None when there is no such storage (no
    table, no proposals/ directory, no proposals.json). Predicts the cases in which doctor keeps the storage
    (mirrors doctor-skill-workshop-retire-proposals.ts closely, not exactly: an owner found through the target skill
    directory is not resolved here, so those are only warnings). Never writes (query_ro / node fallback)."""
    state_dir = Path(state_dir)
    state_db = state_dir / "state" / "openclaw.sqlite"
    sw_dir = state_dir / SW_STATE_DIR
    rows = {}
    if state_db.is_file():
        names = table_names(state_db)
        rows = {t: int(q(state_db, f"SELECT COUNT(*) FROM {_sw_quote(t)}")[0][0]) for t in SW_TABLES if t in names}
    props_dir = sw_dir / "proposals"
    legacy_manifest = os.path.lexists(sw_dir / "proposals.json")
    if not rows and not os.path.lexists(props_dir) and not legacy_manifest:
        return None
    inv = {"tables": rows, "by_status": {}, "proposals": rows.get("skill_workshop_proposals", 0),
           "events": rows.get("skill_workshop_proposal_events", 0),
           "rollbacks": rows.get("skill_workshop_proposal_rollbacks", 0),
           "reviews": rows.get("skill_workshop_collection_reviews", 0), "bytes": 0, "files": 0, "file_bytes": 0,
           "not_regular": 0, "legacy_bundles": 0, "holdbacks": [], "unfinished": [], "legacy_manifest": legacy_manifest,
           "recovery": os.path.isdir(sw_dir / "recovery")}
    for t in rows:
        cols = _sw_columns(state_db, t)
        if cols:
            expr = "+".join(f"COALESCE(length(CAST({_sw_quote(c)} AS BLOB)),0)" for c in cols)
            inv["bytes"] += int(q(state_db, f"SELECT COALESCE(SUM({expr}),0) FROM {_sw_quote(t)}")[0][0] or 0)
    recorded = set()
    configured = {i.lower() for i in configured_agent_ids(cfg)}
    if "skill_workshop_proposals" in rows:
        cols = set(_sw_columns(state_db, "skill_workshop_proposals"))
        owner = "owner_agent_id" if "owner_agent_id" in cols else "NULL"
        for pid, status, own, rec_text in q(state_db, f"SELECT proposal_id, status, {owner}, record_json FROM "
                                                      "skill_workshop_proposals ORDER BY proposal_id"):
            pid, status = str(pid), str(status)
            recorded.add(pid)
            inv["by_status"][status] = inv["by_status"].get(status, 0) + 1
            if status not in SW_EXPORTED_STATUSES:
                continue
            rec = _sw_json(rec_text)
            if not isinstance(rec, dict):
                inv["holdbacks"].append(f"proposal {pid}: its record cannot be read")
                continue
            draft = rec.get("draftFile", "PROPOSAL.md")
            if not isinstance(draft, str) or not SW_DRAFT_RE.fullmatch(draft):
                inv["holdbacks"].append(f"proposal {pid}: its record has an invalid draft path")
                continue
            if isinstance(own, str) and own.strip():
                if own.strip().lower() not in configured:
                    inv["holdbacks"].append(f"proposal {pid} belongs to agent \"{printable(own.strip())}\", which is "
                                            "not configured")
                    continue
            else:
                origin = rec.get("origin") if isinstance(rec.get("origin"), dict) else {}
                who = origin.get("agentId").strip().lower() if isinstance(origin.get("agentId"), str) and \
                    origin.get("agentId").strip() else _sw_owner_from_session(origin.get("sessionKey"))
                if who and who not in configured:
                    inv["holdbacks"].append(f"proposal {pid} was made by agent \"{printable(who)}\", which is not "
                                            "configured")
                    continue
                if not who and len(configured) > 1:
                    inv["holdbacks"].append(f"proposal {pid}: its owner is unclear (doctor may still find it from the "
                                            "target skill directory)")
                    continue
            bundle = props_dir / pid
            if SW_ID_RE.fullmatch(pid) and os.path.isdir(bundle) and not os.path.lexists(bundle / draft):
                inv["holdbacks"].append(f"proposal {pid} has no draft file {draft}")
    if "skill_workshop_proposal_rollbacks" in rows and "skill_workshop_proposals" in rows:
        for pid, skill_file in q(state_db, "SELECT r.proposal_id, r.target_skill_file FROM "
                                           "skill_workshop_proposal_rollbacks r JOIN skill_workshop_proposals p "
                                           "USING (proposal_id) WHERE p.status != 'applied' ORDER BY r.proposal_id"):
            inv["unfinished"].append(f"proposal {pid} has an unfinished apply; doctor puts back the pre-apply files "
                                     f"in {printable(os.path.dirname(str(skill_file or '')) or '?')}")
    for pth, st in C.walk_lstat(sw_dir) if os.path.isdir(sw_dir) and not os.path.islink(sw_dir) else ():
        if stat.S_ISREG(st.st_mode):
            inv["files"] += 1
            inv["file_bytes"] += st.st_size
        elif not stat.S_ISDIR(st.st_mode):
            inv["not_regular"] += 1
    for d, st in C.safe_children(props_dir):
        if not stat.S_ISDIR(st.st_mode) or not SW_ID_RE.fullmatch(d.name) or d.name in recorded:
            continue
        if os.path.lexists(d / "proposal.json"):
            inv["legacy_bundles"] += 1
        else:
            inv["holdbacks"].append(f"skill-workshop/proposals/{printable(d.name)} has no record")
    return inv


def sw_empty(inv):
    """True when there is nothing to keep: no rows in the proposal tables and no files."""
    return not inv or (not any((inv.get("tables") or {}).values()) and not inv.get("files")
                       and not inv.get("not_regular"))


def sw_counts(inv):
    keys = ("proposals", "events", "rollbacks", "reviews", "files", "legacy_bundles")
    return dict({k: inv.get(k, 0) for k in keys}, by_status=dict(inv.get("by_status") or {}))


def sw_status_text(by_status):
    known = [f"{s} {by_status.get(s, 0)}" for s in SW_STATUSES]
    other = [f"{printable(s)} {n}" for s, n in sorted(by_status.items()) if s not in SW_STATUSES]
    return ", ".join(known + other)


def _sw_write(path, data):
    """A new export file: 0600, never through an existing entry or a link (O_EXCL, O_NOFOLLOW), fsynced."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with open(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _sw_mkdir(path, root=None):
    """path (and every missing directory between root and path) with mode 0700."""
    path = Path(path)
    chain = [path]
    if root is not None:
        cur = path
        while cur != Path(root) and Path(root) in cur.parents:
            cur = cur.parent
            chain.append(cur)
    for d in reversed(chain):
        try:
            os.mkdir(str(d), 0o700)
        except FileExistsError:
            pass
        os.chmod(str(d), 0o700)


def _name_at_end(rx, key):
    """True when rx (oc_common.SECRET_NAME_RE, PIN_NAME_RE) matches the whole key or its end from the start of a word
    ("WLAN Passwort", "SIM PIN", "Mein Kennwort"), as the log rules read "<key>: value" in the JSON text; their
    lookbehinds still see the words before ("first pass" stays no secret name)."""
    return any(rx.fullmatch(key, i) is not None for i in [0] + [m.end() for m in re.finditer(r"\s+", key)])


def _sw_secret_key(key):
    return (bool(key) and (SW_SECRET_KEY_RE.search(key) is not None or _name_at_end(C.SECRET_NAME_RE, key))
            and key.lower() not in SW_KEY_KEEP)


def _sw_pin(key, obj):
    """True for a PIN the log rules hide in the JSON text too: 3 to 12 digits (a number or a string) under a PIN key
    (pin, PIN-Code, simPin, wifi_pin, puk, SIM PIN)."""
    if not key or not _name_at_end(C.PIN_NAME_RE, key) or isinstance(obj, bool):
        return False
    return ((isinstance(obj, int) and obj >= 0 and C.PIN_VALUE_RE.fullmatch(str(obj)) is not None)
            or (isinstance(obj, str) and C.PIN_VALUE_RE.fullmatch(obj) is not None))


def _sw_kept_hash(key, obj):
    """True for a hash the export keeps as it is: a hex digest under a hash key (draftHash, revision_hash, ...)."""
    return (isinstance(obj, str) and bool(key) and SW_HASH_KEY_RE.search(key) is not None
            and not _sw_secret_key(key) and SW_HASH_VALUE_RE.fullmatch(obj) is not None)


def _sw_redact(obj, key, counter, seen=None):
    """One JSON value of the export, redacted with the gate's log rules (oc_common.redact_text_counted): a value under
    a secret-looking key is hidden whole (a string, number, list or object), so is a PIN under a PIN key (_sw_pin);
    every string is redacted, an id under its key without the long-token rule; hashes are kept unless a value beside
    them was redacted (_sw_redact_items).
    It hides at least what the log rules hide in the JSON text of the same value. seen (a set): gets the sha256 of
    every string it redacted (_sw_hide_digests)."""
    if (_sw_secret_key(key) and obj is not None and not isinstance(obj, bool)
            and not (isinstance(obj, (str, bytes, dict, list)) and not obj)) or _sw_pin(key, obj):
        counter[0] += 1
        if seen is not None and isinstance(obj, str):
            seen.add(hashlib.sha256(obj.encode("utf-8")).hexdigest())
        return "***"
    if isinstance(obj, dict):
        return _sw_redact_items(((str(k), v) for k, v in obj.items()), counter, seen)
    if isinstance(obj, list):
        return [_sw_redact(v, key, counter, seen) for v in obj]
    if isinstance(obj, bytes):
        return {"omitted": "binary value", "size": len(obj), "sha256": hashlib.sha256(obj).hexdigest()}
    if not isinstance(obj, str) or not obj or _sw_kept_hash(key, obj):
        return obj
    is_id = bool(key) and (key == "id" or key.endswith(("_id", "Id", "ID"))) and SW_ID_VALUE_RE.fullmatch(obj)
    text, n = C.redact_text_counted(obj, long_tokens=not is_id)
    counter[0] += n
    if n and seen is not None:
        seen.add(hashlib.sha256(obj.encode("utf-8")).hexdigest())
    return text


def _sw_redact_items(items, counter, seen=None):
    """A JSON object or a table row of the export, redacted value by value. When anything in it was redacted, the
    hashes kept beside (previous_content_hash next to previous_content, ...) are hidden too: the sha256 of a
    redacted text confirms a guess of the hidden part offline."""
    before, out, hashes = counter[0], {}, []
    for k, v in items:
        if _sw_kept_hash(k, v):
            hashes.append(k)
            out[k] = v
        else:
            out[k] = _sw_redact(v, k, counter, seen)
    if hashes and counter[0] > before:
        for k in hashes:
            out[k] = "***"
            counter[0] += 1
    return out


def _sw_hide_hashes(obj, counter, key=""):
    """obj (already redacted) with every hash it kept replaced by "***"."""
    if isinstance(obj, dict):
        return {k: _sw_hide_hashes(v, counter, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sw_hide_hashes(v, counter, key) for v in obj]
    if _sw_kept_hash(key, obj):
        counter[0] += 1
        return "***"
    return obj


def _sw_hide_digests(obj, digests, counter):
    """obj (already redacted) with every value that is the sha256 of a redacted text (digests, from _sw_redact and
    the redacted files) replaced by "***", wherever it is: another row can keep the sha256 of the same text (a
    proposal for another skill with the same content, an undo record or event without its proposal)."""
    if isinstance(obj, dict):
        return {k: _sw_hide_digests(v, digests, counter) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sw_hide_digests(v, digests, counter) for v in obj]
    if isinstance(obj, str) and SW_HASH_VALUE_RE.fullmatch(obj) and obj.removeprefix("sha256:") in digests:
        counter[0] += 1
        return "***"
    return obj


def _sw_skill_of(row):
    """The target skill file (else directory) of an exported proposal row, or None."""
    rec = row.get("record_json") if isinstance(row.get("record_json"), dict) else {}
    target = rec.get("target") if isinstance(rec.get("target"), dict) else {}
    skill = target.get("skillFile") or target.get("skillDir")
    return skill if isinstance(skill, str) and skill else None


def _sw_row(cols, values, counter, seen=None):
    def value(c, v):
        parsed = _sw_json(v) if c in SW_JSON_COLUMNS else None
        return parsed if parsed is not None else v
    return _sw_redact_items(((c, value(c, v)) for c, v in zip(cols, values)), counter, seen)


def _sw_name(rec):
    """The skill name of an exported proposal record: name or skillName (as the add-on's tests and later records
    have it), else target.skillName (what OpenClaw 2026.10.4 stores), else the title ("Create wetter-kurz")."""
    rec = rec if isinstance(rec, dict) else {}
    target = rec.get("target") if isinstance(rec.get("target"), dict) else {}
    for v in (rec.get("name"), rec.get("skillName"), target.get("skillName"), rec.get("title")):
        if isinstance(v, str) and v.strip():
            return v
    return None


def _sw_md(text, limit=160):
    s = " ".join(str(text if text is not None else "").split())
    s = s if len(s) <= limit else s[:limit - 1] + "…"
    return s.replace("|", "\\|")


def _sw_proposals_md(doc):
    """PROPOSALS.md: a readable index of the export (the values are already redacted)."""
    L = [f"# Skill Workshop proposals (export of gate run {doc['run_id']})", "",
         f"Exported on {doc['exported_at']} before OpenClaw {doc['openclaw_to']} doctor retired the Skill Workshop "
         "proposals. OpenClaw keeps only the current drafts of pending and quarantined proposals, as files in the owner "
         "agent's `workshop-skills/.archive/.retired-proposals/`; everything else exists only in this export.", "",
         "Secrets are replaced by `***` with the add-on's log redaction rules, and so are the hashes that could "
         "confirm a guess of a redacted value; the exact originals are only in the "
         "encrypted Home Assistant backup taken before the update. All data is in `proposals.json`; the files of "
         "`/config/.openclaw/skill-workshop/` are mirrored under `files/`. To bring a draft back, ask the agent to "
         "save it with `/learn`. This export is kept until you delete it.", "",
         "| id | status | kind | name | target skill | updated | reason |", "|---|---|---|---|---|---|---|"]
    for p in doc["proposals"]:
        rec = p.get("record_json") if isinstance(p.get("record_json"), dict) else {}
        target = rec.get("target") if isinstance(rec.get("target"), dict) else {}
        L.append("| " + " | ".join(_sw_md(x, 80) for x in (
            p.get("proposal_id"), p.get("status"), p.get("kind"), _sw_name(rec),
            target.get("skillDir") or target.get("skillFile"), p.get("updated_at"), p.get("status_reason"))) + " |")
    for p in doc["proposals"]:
        rec = p.get("record_json") if isinstance(p.get("record_json"), dict) else {}
        L += ["", f"## {_sw_md(p.get('proposal_id'))} ({_sw_md(p.get('status'))})", ""]
        if _sw_name(rec):
            L.append(f"- name: {_sw_md(_sw_name(rec), 600)}")
        for k in ("description", "goal", "evidence"):
            if rec.get(k):
                L.append(f"- {k}: {_sw_md(rec.get(k), 600)}")
        L.append(f"- draft: `{p['draft_export']}`" if p.get("draft_export") else "- draft: not in the export")
        L.append(f"- events: {len(p.get('events') or [])}; undo record: {'yes' if p.get('rollback') else 'no'}; "
                 f"files: {len(p.get('files') or [])}")
        L.append(f"- OpenClaw doctor: {p['openclaw_doctor']}")
    if doc.get("bundles_without_record"):
        L += ["", "## Draft folders without a database record", ""]
        L += [f"- {_sw_md(b['proposal_id'])}: {len(b['files'])} file(s)" for b in doc["bundles_without_record"]]
    if doc.get("omitted"):
        L += ["", "## Not exported", ""]
        L += [f"- `{_sw_md(o['path'])}`: {_sw_md(o['omitted'])} ({o.get('size', '?')} bytes)" for o in doc["omitted"]]
    return "\n".join(L) + "\n"


def export_skill_workshop(state_dir, dest, meta, stop=STOP):
    """Export every Skill Workshop proposal (all states, events, undo records, collection reviews) and every file
    below <state>/skill-workshop/ (all draft generations) to dest, redacted with the gate's log rules. Written to
    <dest>.partial and renamed: dest exists only complete, with MANIFEST.json written last. Files are 0600 and
    directories 0700; links are never followed (listed, not copied), and files that are not UTF-8 or larger than
    SW_FILE_CAP are listed with size and sha256 only. Returns the summary. Raises OSError/sqlite3.Error/ValueError
    (the caller HOLDs) or C.Stopped."""
    state_dir, dest = Path(state_dir), Path(dest)
    if (dest / "MANIFEST.json").is_file():  # write-once: a complete export is never replaced
        raise OSError(errno.EEXIST, "a complete export already exists", str(dest))
    part = dest.with_name(dest.name + ".partial")
    if os.path.lexists(part):
        if os.path.isdir(part) and not os.path.islink(part):
            shutil.rmtree(part)
        else:
            os.unlink(part)
    _sw_mkdir(part)
    counter, digests, redacted_undo = [0], set(), set()
    state_db = state_dir / "state" / "openclaw.sqlite"
    tables = {}
    names = table_names(state_db) if state_db.is_file() else set()
    for t in SW_TABLES:
        if t not in names:
            continue
        cols = _sw_columns(state_db, t)
        rows = q(state_db, f"SELECT {', '.join(_sw_quote(c) for c in cols)} FROM {_sw_quote(t)} ORDER BY rowid")
        tables[t] = []
        for r in rows:
            before = counter[0]
            tables[t].append(_sw_row(cols, r, counter, digests))
            if t == "skill_workshop_proposal_rollbacks" and counter[0] > before:
                redacted_undo.add(str(tables[t][-1].get("proposal_id")))
        if stop is not None and stop.is_set():
            raise C.Stopped("stop requested")
    # files: a mirror of <state>/skill-workshop/
    sw_dir = state_dir / SW_STATE_DIR
    files, omitted, written = [], [], []
    entries = sorted(C.walk_lstat(sw_dir, stop_event=stop), key=lambda x: str(x[0])) \
        if os.path.isdir(sw_dir) and not os.path.islink(sw_dir) else []
    for pth, st in entries:
        relp = pth.relative_to(sw_dir).as_posix()
        if stat.S_ISDIR(st.st_mode):
            continue
        if stop is not None and stop.is_set():
            raise C.Stopped("stop requested")
        if not stat.S_ISREG(st.st_mode):
            omitted.append({"path": relp, "type": "symlink" if stat.S_ISLNK(st.st_mode) else "other",
                            "size": st.st_size, "omitted": "not a regular file (not followed)"})
            continue
        fd = os.open(str(pth), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with open(fd, "rb") as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                raise OSError(errno.EINVAL, "not a regular file", str(pth))
            h, data, size = hashlib.sha256(), bytearray(), 0
            for chunk in iter(lambda: f.read(C.MIB), b""):
                h.update(chunk)
                size += len(chunk)
                if size <= SW_FILE_CAP:
                    data += chunk
        if size > SW_FILE_CAP:
            omitted.append({"path": relp, "type": "file", "size": size, "sha256": h.hexdigest(),
                            "omitted": f"larger than {C.human(SW_FILE_CAP)}"})
            continue
        try:
            text = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            omitted.append({"path": relp, "type": "file", "size": size, "sha256": h.hexdigest(),
                            "omitted": "binary (not UTF-8 text)"})
            continue
        before = counter[0]
        parsed = _sw_json(text) if relp.endswith(".json") else None
        if parsed is not None:
            out_text = C.json_dumps(_sw_redact(parsed, "", counter, digests))
        else:
            out_text, n = C.redact_text_counted(text)
            counter[0] += n
        if counter[0] > before:
            digests.add(h.hexdigest())
        target = part / "files" / relp
        _sw_mkdir(target.parent, part)
        blob = out_text.encode("utf-8")
        _sw_write(target, blob)
        written.append({"path": f"files/{relp}", "sha256": hashlib.sha256(blob).hexdigest()})
        fe = {"path": relp, "export": f"files/{relp}", "size": size, "redactions": counter[0] - before}
        if not fe["redactions"]:  # the source hash of a redacted file would confirm a guess of what was hidden
            fe["sha256_source"] = h.hexdigest()
        files.append(fe)
    # proposals.json
    events, rollbacks = {}, {}
    for e in tables.get("skill_workshop_proposal_events", []):
        events.setdefault(str(e.get("proposal_id")), []).append(e)
    for r in tables.get("skill_workshop_proposal_rollbacks", []):
        rollbacks[str(r.get("proposal_id"))] = r
    by_prop, other = {}, []
    for fe in files + omitted:
        parts = fe["path"].split("/")
        if len(parts) >= 3 and parts[0] == "proposals" and SW_ID_RE.fullmatch(parts[1]):
            by_prop.setdefault(parts[1], []).append(fe)
        else:
            other.append(fe)
    # Hashes of a skill's content: a proposal's draft/support file hashes and the revision hashes built on them; its
    # target hashes (target.currentContentHash, supportFiles[].targetContentHash, the evaluation's
    # targetCurrentSha256/targetTreeSha256), which cover the skill as every proposal for it saw it and as an applied
    # one's undo record holds it. Once a draft or an undo record of a skill was redacted, every proposal for that
    # skill keeps none of them.
    prop_rows = tables.get("skill_workshop_proposals", [])
    redacted_skills = {_sw_skill_of(r) for r in prop_rows
                       if str(r.get("proposal_id")) in redacted_undo
                       or any(fe.get("redactions") for fe in by_prop.get(str(r.get("proposal_id")), []))}
    redacted_skills |= {r.get("target_skill_file") for pid, r in rollbacks.items()
                        if pid in redacted_undo and isinstance(r.get("target_skill_file"), str)}
    redacted_skills.discard(None)
    proposals, by_status = [], {}
    for row in prop_rows:
        pid, status = str(row.get("proposal_id")), str(row.get("status"))
        by_status[status] = by_status.get(status, 0) + 1
        rec = row.get("record_json") if isinstance(row.get("record_json"), dict) else {}
        draft = rec.get("draftFile", "PROPOSAL.md")
        draft_rel = f"proposals/{pid}/{draft}" if isinstance(draft, str) and SW_DRAFT_RE.fullmatch(draft) else None
        pfiles = [dict(fe, current_draft=fe["path"] == draft_rel) for fe in by_prop.get(pid, [])]
        exported = any(fe["current_draft"] and fe.get("export") for fe in pfiles)
        evs = events.pop(pid, [])
        if any(fe.get("redactions") for fe in pfiles) or pid in redacted_undo or _sw_skill_of(row) in redacted_skills:
            row, evs = _sw_hide_hashes(row, counter), [_sw_hide_hashes(e, counter) for e in evs]
        proposals.append(dict(row, events=evs, rollback=rollbacks.pop(pid, None), files=pfiles,
                              draft_export=f"files/{draft_rel}" if exported else None,
                              openclaw_doctor=("keeps the current draft in the owner agent's workshop-skills/.archive/"
                                               f".retired-proposals/{pid}/" if status in SW_EXPORTED_STATUSES
                                               else "drops this proposal")))
    recorded = {p["proposal_id"] for p in proposals}
    doc = {"schema": SW_EXPORT_SCHEMA, "run_id": meta.get("run_id"), "exported_at": C.utc_iso(),
           "openclaw_from": meta.get("openclaw_from"), "openclaw_to": meta.get("openclaw_to"),
           "note": "secrets are redacted (***) with the add-on's log redaction rules; the exact originals are only in "
                   "the encrypted Home Assistant backup taken before the update",
           "counts": {"proposals": len(proposals), "by_status": by_status,
                      "events": len(tables.get("skill_workshop_proposal_events", [])),
                      "rollbacks": len(tables.get("skill_workshop_proposal_rollbacks", [])),
                      "collection_reviews": len(tables.get("skill_workshop_collection_reviews", [])),
                      "files": len(files), "omitted": len(omitted)},
           "proposals": proposals,
           "bundles_without_record": [{"proposal_id": k, "files": v} for k, v in sorted(by_prop.items())
                                      if k not in recorded],
           "collection_reviews": tables.get("skill_workshop_collection_reviews", []),
           "events_without_proposal": [e for v in events.values() for e in v],
           "rollbacks_without_proposal": list(rollbacks.values()),
           "other_files": other, "omitted": omitted}
    doc = _sw_hide_digests(doc, digests, counter)
    doc["redactions_total"] = counter[0]
    for name, blob in (("proposals.json", C.json_dumps(doc).encode("utf-8")),
                       ("PROPOSALS.md", _sw_proposals_md(doc).encode("utf-8"))):
        _sw_write(part / name, blob)
        written.append({"path": name, "sha256": hashlib.sha256(blob).hexdigest()})
    summary = dict(doc["counts"], redactions=counter[0], bytes=sum(f["size"] for f in files),
                   omitted_paths=[o["path"] for o in omitted][:50])
    _sw_write(part / "MANIFEST.json", C.json_dumps({"schema": SW_EXPORT_SCHEMA, "complete": True,
                                                     "run_id": meta.get("run_id"), "summary": summary,
                                                     "files": written}).encode("utf-8"))
    for d, _st in [(part, None)] + [(p_, s_) for p_, s_ in C.walk_lstat(part) if stat.S_ISDIR(s_.st_mode)]:
        _fsync_dir(d)
    if os.path.lexists(dest):  # not written by this function (dest only ever exists complete): set aside
        os.rename(dest, dest.with_name(f"{dest.name}.incomplete-{C.utc_now().strftime('%Y%m%dT%H%M%SZ')}"))
    os.rename(part, dest)
    _fsync_dir(dest.parent)
    return summary


def sw_export_record(gp, run_id):
    """The MANIFEST summary of the complete Skill Workshop export of run `run_id`, or None."""
    m = C.load_json_or_none(gp["RUNS"] / str(run_id) / SW_EXPORT_DIR / "MANIFEST.json")
    return m.get("summary") if isinstance(m, dict) and m.get("complete") and isinstance(m.get("summary"), dict) \
        else None


# --- doctor's pre-migration SQLite copies (*.pre-startup-migration-*.bak / .scoped.bak) ---------

def doctor_copies(state_dir):
    """{state-relative path: (size, "full" | "scoped")} of doctor's SQLite copies below the state dir (regular files
    only; links are not followed). The walk runs beside the gateway (cleanup loop): a directory that vanishes or
    cannot be read during it is skipped (os.walk without onerror), never an error that would hold back the rest of
    a run's cleanup (Path.rglob raises FileNotFoundError for it on Python 3.11)."""
    state_dir = Path(state_dir)
    found = {}
    if not state_dir.is_dir():
        return found
    for root, _dirs, files in os.walk(state_dir, followlinks=False):
        for name in files:
            if not DOCTOR_COPY_RE.fullmatch(name):
                continue
            pth = Path(root) / name
            try:
                st = os.lstat(pth)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                found[C.rel(pth, state_dir)] = (st.st_size, "scoped" if name.endswith(".scoped.bak") else "full")
    return found


# D11: OpenClaw sets a SQLite database aside as <file>.corrupt-<Date.now()>[.N] (also its -wal/-shm/-journal), e.g.
# doctor for an agent database that is a byte-identical copy of another agent's ("Preserved the copy at ...",
# state-migrations.agent-owner-recovery.ts / sqlite-recovery-files.ts, 2026.10.4 = 2026.11.1). The file is the
# renamed original, a complete plaintext database; the add-on lists it and never deletes it.
SQLITE_SET_ASIDE_RE = re.compile(r"[^/]{1,200}\.sqlite(?:-wal|-shm|-journal)?\.corrupt-(\d{10,16})(?:\.\d{1,3})?")


def sqlite_set_aside(state_dir, cfg=None):
    """{path (state-relative, absolute outside it): size} of the <db>.corrupt-<ms> files in <state>/state/,
    <state>/agents/*/agent/ and the directories of agent databases outside the state dir. Regular files only, links
    are not followed; read-only."""
    state_dir = Path(state_dir)
    dirs = [state_dir / "state"] + sorted(state_dir.glob("agents/*/agent"))
    dirs += [Path(d) for d in outside_agent_dirs(state_dir, cfg)] if cfg is not None else []
    found = {}
    for d in dirs:
        try:
            with os.scandir(d) as it:
                entries = [(e.name, e.path) for e in it]
        except OSError:
            continue
        for name, path in entries:
            if not SQLITE_SET_ASIDE_RE.fullmatch(name):
                continue
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                found[C.rel(path, state_dir)] = st.st_size
    return found


def orphan_recorded_owner(state_dir, o):
    """The agent an orphan store records as its owner when that is another agent (read-only, schema_meta 'primary'),
    else None. OpenClaw's doctor (state-migrations.agent-owner-recovery.ts, 2026.10.4 to 2026.11.1) does not migrate
    such a store: it sets it aside only as a byte-identical copy of that agent's database (with -wal/-shm and the
    transcript archives) and otherwise refuses it, and the refusal stops doctor (doctor-migration-refused) after the
    other databases are migrated. As there: role 'agent', ids compared normalised (normalize_agent_id; the folder
    name gives the store's own id). An unreadable store gives None (doctor reports it in the normal migration)."""
    if not isinstance(o, dict) or o.get("error") or not isinstance(o.get("path"), str) or not o["path"]:
        return None
    try:
        meta = schema_meta_primary(Path(state_dir) / o["path"])
    except (sqlite3.Error, C.SchemaUnknown, C.NodeQueryError, OSError):
        return None
    owner = (meta or {}).get("agent_id")
    if (meta or {}).get("role") != "agent" or not isinstance(owner, str) or not owner.strip():
        return None
    norm = mig().normalize_agent_id
    return None if norm(owner) == norm(str(o.get("id") or "")) else norm(owner)


def orphan_outcomes(state_dir, orphans, a_target, since=None):
    """D11: what doctor did with each recorded orphan store (not held back): [{"id", "path", "uv", "outcome",
    "uv_after", "set_aside"}], outcome "migrated" (at a_target or above), "not-migrated" (still below), "set-aside"
    (gone, and doctor renamed it to <file>.corrupt-<ms>), "gone" or "unreadable". set_aside: the state-relative
    <file>.corrupt-<ms> names of that store made at or after `since` (ISO time, the gate run's start; all without
    it). Read-only."""
    state_dir = Path(state_dir)
    since_ms = None
    try:
        since_ms = int(datetime.fromisoformat(str(since).replace("Z", "+00:00")).timestamp() * 1000) - 1000 \
            if since else None
    except ValueError:
        since_ms = None
    out = []
    for o in orphans or []:
        if not isinstance(o, dict) or o.get("held") or not isinstance(o.get("path"), str) or not o["path"]:
            continue
        pth = state_dir / o["path"]
        aside = []
        for x in sorted(pth.parent.glob(glob.escape(pth.name) + ".corrupt-*")):  # the database, not its -wal/-shm
            m = SQLITE_SET_ASIDE_RE.fullmatch(x.name)
            if m and (since_ms is None or int(m.group(1)) >= since_ms):
                aside.append(C.rel(x, state_dir))
        rec = {"id": o.get("id"), "path": o["path"], "uv": o.get("uv"), "outcome": None, "uv_after": None,
               "set_aside": aside}
        if os.path.lexists(pth):
            try:
                v = agent_db_version(pth)
            except (sqlite3.Error, C.SchemaUnknown, C.NodeQueryError, OSError) as exc:
                rec.update(outcome="unreadable", error=type(exc).__name__)
            else:
                rec.update(uv_after=v, outcome="migrated" if v is not None and v >= a_target else "not-migrated")
        else:
            rec["outcome"] = "set-aside" if aside else "gone"
        out.append(rec)
    return out


def orphan_outcome_text(o, a_target=None):
    """The finalize/status text of an orphan_outcomes entry."""
    head = f"orphan agent database {printable(o.get('path'))} (agent {printable(o.get('id'))}, schema " \
           f"{o.get('uv') if o.get('uv') is not None else 'unreadable'} before): "
    aside = ", ".join(printable(x) for x in o.get("set_aside") or [])
    kept = (f"set it aside as {aside}: the renamed original, a complete plaintext database that OpenClaw and the "
            "add-on keep; delete it by hand once you are satisfied (oc-upgrade status lists such files)")
    out = o.get("outcome")
    if out == "set-aside":
        return head + "doctor found it to be a byte-identical copy of another agent's database and " + kept
    if out == "migrated":
        text = f"doctor migrated it to schema {o.get('uv_after')}; the gateway does not open it"
    elif out == "not-migrated":
        text = (f"still at schema {o.get('uv_after')}" + (f" (target {a_target})" if a_target else "")
                + ": doctor did not migrate it (refused or held back; oc-upgrade log says why); the gateway does "
                "not open it")
    elif out == "gone":
        text = "gone after doctor"
    else:
        text = f"could not be read after doctor ({printable(o.get('error'))})"
    return head + text + (f"; doctor also {kept}" if aside else "")


def outside_agent_dirs(state_dir, cfg):
    """The real directories of the agent databases (configured or registered) that lie outside the real state dir.
    Doctor saves its SQLite copies beside these databases too, where the add-on does not delete them. Read-only;
    [] when the state database cannot be read."""
    state_dir = Path(state_dir)
    root = os.path.realpath(str(state_dir)).rstrip("/") + "/"
    sdb = state_dir / "state" / "openclaw.sqlite"
    try:
        targets, _orphans = agent_databases(state_dir, cfg if isinstance(cfg, dict) else {},
                                            table_names(sdb) if sdb.exists() else set())
    except (sqlite3.Error, C.NodeQueryError, C.SchemaUnknown, OSError, ValueError):
        return []
    dirs = {os.path.dirname(os.path.realpath(str(pth))) for _aid, pth in targets}
    return sorted(d for d in dirs if not (d + "/").startswith(root))


def outside_doctor_copies(dirs):
    """{absolute path: (size, "full" | "scoped")} of doctor's SQLite copies directly in `dirs` (no recursion; regular
    files only, links are not followed)."""
    found = {}
    for d in dirs:
        try:
            with os.scandir(d) as it:
                entries = [(e.name, e.path) for e in it]
        except OSError:
            continue
        for name, pth in entries:
            if not DOCTOR_COPY_RE.fullmatch(name):
                continue
            try:
                st = os.lstat(pth)
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
                found[pth] = (st.st_size, "scoped" if name.endswith(".scoped.bak") else "full")
    return found


def run_outside_copies(j):
    """The paths of the doctor SQLite copies a gate run journaled beside agent databases outside the state dir that
    still exist (lstat; a link is listed as it is)."""
    out = []
    for d in j.get("doctor") or [] if isinstance(j.get("doctor"), list) else []:
        for e in (d.get("pre_migration_backups_outside") or []) if isinstance(d, dict) else []:
            pth = e.get("path") if isinstance(e, dict) else None
            if isinstance(pth, str) and os.path.isabs(pth) and pth not in out and os.path.lexists(pth):
                out.append(pth)
    return out


def outside_copies_text(paths, state_dir):
    """The WARN text for doctor's SQLite copies beside agent databases outside the state dir: the add-on never
    deletes them (its deletes stay below the state dir)."""
    it = "it" if len(paths) == 1 else "them"
    return (f"{len(paths)} pre-migration SQLite cop{'y' if len(paths) == 1 else 'ies'} by doctor beside agent "
            f"databases outside {state_dir} (plaintext, not the rollback point; the add-on does not delete {it}): "
            f"delete {it} yourself once the update is confirmed: " + ", ".join(printable(x) for x in paths[:4])
            + (" …" if len(paths) > 4 else ""))


def copies_text(entries):
    """'2 full and 1 table-scoped pre-migration SQLite copies by doctor, 1.2 GiB' for journal entries."""
    nf = sum(1 for e in entries if e.get("scope") != "scoped")
    ns = len(entries) - nf
    if not entries:
        return "no new pre-migration SQLite copy by doctor"
    kinds = " and ".join(x for x in (f"{nf} full" if nf else "", f"{ns} table-scoped" if ns else "") if x)
    return (f"{kinds} pre-migration SQLite cop{'y' if len(entries) == 1 else 'ies'} by doctor, "
            f"{C.human(sum(int(e.get('size') or 0) for e in entries))}")


def _doctor_copy_parts(state_real, path):
    """The components of `path` below the (real) state dir when it names one of doctor's SQLite copies, else None."""
    p = os.path.normpath(str(path))
    root = str(state_real).rstrip("/") + "/"
    if not os.path.isabs(p) or not p.startswith(root):
        return None
    parts = p[len(root):].split("/")
    if any(x in ("", ".", "..") for x in parts) or not DOCTOR_COPY_RE.fullmatch(parts[-1]):
        return None
    return parts


def doctor_copy_groups(text):
    """The backup group ids of the copies one doctor log says it saved or reused."""
    flat = re.sub(r"\s+", "", BOX_RE.sub("", ANSI_RE.sub("", text or "")))
    return set(SAVED_COPY_ID_RE.findall(flat))


def run_doctor_copies(gp, j, present=None):
    """Doctor's pre-migration SQLite copies a gate run created: the copies the run journaled per doctor pass (this
    version) and every copy of a backup group its doctor logs say they saved or reused ("Saved pre-migration SQLite
    backup: …", also in the runs of earlier add-on versions). Like the doctor captures they are plaintext copies of the
    databases, so the owner's rule applies: they go gate_cleanup_hours after the run (the encrypted Home Assistant
    backup is the rollback point). Only regular files below the state dir with doctor's name pattern (doctor_copies,
    `present` when the caller listed them already); copies already gone are skipped. Returns (paths, kept): kept
    lists the copies the run journaled beside agent databases outside the state dir, which are reported only."""
    present = doctor_copies(gp["STATE"]) if present is None else present
    want = set()
    for d in j.get("doctor") or [] if isinstance(j.get("doctor"), list) else []:
        for e in (d.get("pre_migration_backups") or []) if isinstance(d, dict) else []:
            if isinstance(e, dict) and e.get("scope") and isinstance(e.get("path"), str):
                want.add(e["path"])
    groups = set()
    for log in sorted((gp["RUNS"] / str(j.get("run_id"))).glob("doctor-pass*.log")):
        try:
            groups |= doctor_copy_groups(log.read_bytes().decode("utf-8", "replace"))
        except OSError:
            continue
    if groups:
        want |= {r for r in present if DOCTOR_COPY_RE.fullmatch(Path(r).name).group(1) in groups}
    state_real = Path(os.path.realpath(str(gp["STATE"])))
    kept = [(x, f"beside an agent database outside {gp['STATE']}: not deleted by the add-on, delete it yourself")
            for x in run_outside_copies(j)]
    return [state_real / r for r in sorted(want) if r in present], kept


PLUGIN_INSTALL_BASES = ("npm/projects", "extensions", "git")
# OpenClaw's own work directories in a plugin install base (install-package-dir.ts, 2026.10.4 = 2026.11.1): mkdtemp
# stage and rollback directories that only an interrupted install leaves behind (OpenClaw never removes them later),
# and the backups of an update that could not be finished ("backup retained at ..."). Never plugins.
PLUGIN_INSTALL_LEFTOVER_RE = re.compile(r"\.openclaw-install-(?:stage|rollback)-[A-Za-z0-9]{6}|\.openclaw-install-backups")


def plugin_snapshot(state_dir):
    """The plugin packages in OpenClaw's install bases (a generation suffix cut off); OpenClaw's dot-named work
    directories (staging, rollback and backup directories, retention markers) are no plugins and left out (D8)."""
    names = set()
    state_dir = Path(state_dir)
    for sub in PLUGIN_INSTALL_BASES:
        d = state_dir / sub
        try:
            with os.scandir(d) as it:
                for e in it:
                    if e.name.startswith("."):
                        continue
                    names.add(f"{sub}/" + re.sub(r"__openclaw-generation__g-[0-9a-f]+$", "", e.name))
        except OSError:
            continue
    return sorted(names)


def plugin_install_leftovers(state_dir):
    """D8: [(relative path, kind)] of OpenClaw's install work directories in the plugin install bases: "stage" or
    "rollback" (left by an interrupted plugin install or update, e.g. a doctor that was stopped), "backups" (a
    non-empty .openclaw-install-backups: the previous version of a plugin whose update could not be finished).
    Read-only; the add-on never deletes them."""
    out = []
    state_dir = Path(state_dir)
    for sub in PLUGIN_INSTALL_BASES:
        try:
            with os.scandir(state_dir / sub) as it:
                entries = sorted((e.name, e.is_dir(follow_symlinks=False)) for e in it)
        except OSError:
            continue
        for name, is_dir in entries:
            if not is_dir or not PLUGIN_INSTALL_LEFTOVER_RE.fullmatch(name):
                continue
            if name == ".openclaw-install-backups":
                try:
                    if not any(os.scandir(state_dir / sub / name)):
                        continue
                except OSError:
                    continue
                out.append((f"{sub}/{name}", "backups"))
            else:
                out.append((f"{sub}/{name}", "stage" if "-stage-" in name else "rollback"))
    return out


def install_leftovers_text(items):
    """The WARN/status text of plugin_install_leftovers items (D8)."""
    work = [p for p, kind in items if kind != "backups"]
    backs = [p for p, kind in items if kind == "backups"]
    parts = []
    if work:
        parts.append(f"{len(work)} staging/rollback director(ies) of an interrupted OpenClaw plugin install or update "
                     f"({', '.join(printable(p) for p in work[:6])}{' …' if len(work) > 6 else ''}): no plugin; "
                     "OpenClaw does not use or remove them, delete them by hand while OpenClaw is not installing "
                     "plugins")
    if backs:
        parts.append(f"OpenClaw kept the previous version of a plugin whose update failed or was interrupted in "
                     f"{', '.join(printable(p) for p in backs)}: delete it by hand once the plugins work (oc-upgrade "
                     "status lists their versions)")
    return "; ".join(parts)


OFFICIAL_PLUGIN_SCOPE = "@openclaw/"
BRAVE_PLUGIN_PACKAGE = "@openclaw/brave-plugin"  # run.sh ensure_brave_plugin owns it


def _npm_name(spec):
    """Package name of an npm spec ('@scope/name@1.2.3', 'npm:@scope/name', 'name@x') or None."""
    if not isinstance(spec, str) or not spec.strip():
        return None
    s = spec.strip()
    if s.startswith("npm:"):
        s = s[4:]
    if s.startswith("@"):
        scope, _, rest = s.partition("/")
        return f"{scope}/{rest.split('@', 1)[0]}" if rest else None
    return s.split("@", 1)[0] or None


def _slot_value(value):
    """OpenClaw's normalizeSlotValue (plugins/slots.ts): a trimmed string, None for "none", "" when unset/blank."""
    t = value.strip() if isinstance(value, str) else ""
    return None if t.lower() == "none" else t


def plugin_config_off(cfg, pid, channel_ids=()):
    """OpenClaw's "disabled" verdict from openclaw.json alone for an installed npm plugin (not bundled, not a
    workspace plugin): resolvePluginActivationStateShared (plugins/config-activation-shared.ts, the same in 2026.10.4
    and 2026.11.1) in its order: plugins.enabled false, plugins.deny, plugins.entries.<id>.enabled false, every
    channel it owns disabled (channels.<channel>.enabled false; channel_ids: its manifest's channels, else its id),
    a non-empty plugins.allow without it (unless it holds the memory or context engine slot). OpenClaw's reason, or
    None (enabled or OpenClaw's default: `openclaw plugins list` and plugins-sync count it). allow/deny compare in
    lower case (normalizePluginPolicyId)."""
    plugins = _cfg_get(cfg if isinstance(cfg, dict) else {}, "plugins")
    plugins = plugins if isinstance(plugins, dict) else {}

    def ids(key):
        v = plugins.get(key)
        return {x.strip().lower() for x in v if isinstance(x, str) and x.strip()} if isinstance(v, list) else set()

    policy = pid.strip().lower()
    if plugins.get("enabled") is False:
        return "plugins disabled"
    if policy in ids("deny"):
        return "blocked by denylist"
    entries = plugins.get("entries") if isinstance(plugins.get("entries"), dict) else {}
    ent = entries.get(pid)
    if isinstance(ent, dict) and ent.get("enabled") is False:
        return "disabled in config"
    channels = _cfg_get(cfg if isinstance(cfg, dict) else {}, "channels")
    if isinstance(channels, dict):
        cands = [c.strip().lower() for c in channel_ids if isinstance(c, str) and c.strip()] or [policy]
        states = [channels[c].get("enabled") if isinstance(channels.get(c), dict) else None for c in cands]
        if all(x is False for x in states):
            return "channel disabled in config"
    slots = plugins.get("slots") if isinstance(plugins.get("slots"), dict) else {}
    memory = _slot_value(slots.get("memory"))
    if pid in ("memory-core" if memory == "" else memory, _slot_value(slots.get("contextEngine"))):
        return None  # a selected slot passes the allowlist (unset memory slot: its default owner memory-core)
    allow = ids("allow")
    if allow and policy not in allow:
        return "not in allowlist"
    return None


def official_plugin_installs(state_dir, cfg, with_path=False):
    """[{id, package, version, enabled}] of the official npm plugins (@openclaw/*) OpenClaw installed, sorted by id;
    with_path: also "install_path" (the recorded installPath as a Path below the state dir, or None).

    Read-only: the install records in config_machine_state 'plugins.installedIndex' (index.installRecords; the
    7.x installed_plugin_index table as a fallback), the version from <installPath>/package.json when readable,
    enabled from openclaw.json plugins.entries.<id>.enabled (None: OpenClaw's default), False also when OpenClaw
    disables it through plugins.enabled, plugins.deny, plugins.allow or its channel (plugin_config_off; channels from
    <installPath>/openclaw.plugin.json): `openclaw plugins list` then lists it as disabled and plugins-sync leaves it
    alone. Never raises."""
    state_dir = Path(state_dir)
    sdb = state_dir / "state" / "openclaw.sqlite"
    records = {}
    try:
        tables = table_names(sdb) if sdb.exists() else set()
        if "config_machine_state" in tables:
            rows = q(sdb, "SELECT value_json FROM config_machine_state WHERE state_key='plugins.installedIndex'")
            val = json.loads(rows[0][0]) if rows and isinstance(rows[0][0], str) else None
            idx = val.get("index") if isinstance(val, dict) else None
            recs = idx.get("installRecords") if isinstance(idx, dict) else None
            if isinstance(recs, dict):
                records = recs
        if not records and "installed_plugin_index" in tables:  # 7.x (oc_migrate._installed_plugin_index_ids)
            rows = q(sdb, "SELECT install_records_json FROM installed_plugin_index "
                          "WHERE index_key='installed-plugin-index'")
            val = json.loads(rows[0][0]) if rows and isinstance(rows[0][0], str) else None
            if isinstance(val, dict):
                records = val
    except (sqlite3.Error, C.NodeQueryError, C.SchemaUnknown, OSError, ValueError, IndexError):
        return []
    entries = _cfg_get(cfg if isinstance(cfg, dict) else {}, "plugins", "entries")
    entries = entries if isinstance(entries, dict) else {}
    out_ = []
    for pid, rec in records.items():
        if not isinstance(pid, str) or not isinstance(rec, dict) or rec.get("source") != "npm":
            continue
        pkg_name = rec.get("resolvedName") if isinstance(rec.get("resolvedName"), str) else None
        pkg_name = pkg_name or _npm_name(rec.get("spec")) or _npm_name(rec.get("resolvedSpec"))
        if not pkg_name or not pkg_name.startswith(OFFICIAL_PLUGIN_SCOPE):
            continue
        version, channel_ids, ipp = None, (), None
        ip = rec.get("installPath")
        if isinstance(ip, str) and ip:
            ipp = Path(ip) if os.path.isabs(ip) else state_dir / ip
            data = C.load_json_or_none(ipp / "package.json")
            if isinstance(data, dict) and isinstance(data.get("version"), str):
                version = data["version"]
            manifest = C.load_json_or_none(ipp / "openclaw.plugin.json")
            if isinstance(manifest, dict) and isinstance(manifest.get("channels"), list):
                channel_ids = tuple(manifest["channels"])
        if version is None:
            for k in ("resolvedVersion", "version"):
                if isinstance(rec.get(k), str) and rec[k]:
                    version = rec[k]
                    break
        ent = entries.get(pid)
        enabled = ent.get("enabled") if isinstance(ent, dict) and isinstance(ent.get("enabled"), bool) else None
        if plugin_config_off(cfg, pid, channel_ids):
            enabled = False
        out_.append({"id": pid, "package": pkg_name, "version": version, "enabled": enabled,
                     **({"install_path": ipp} if with_path else {})})
    return sorted(out_, key=lambda x: x["id"])


def plugin_install_bytes(state_dir, installs):
    """Bytes of the npm projects of `installs` (official_plugin_installs with_path; the enabled ones the caller
    picks): for an installPath <state>/npm/projects/<project>/node_modules/@openclaw/<name> the whole project
    directory (the plugin with its dependencies), else the installPath itself; each directory once, regular files
    only, no link followed. Read-only; 0 for what cannot be read."""
    projects = os.path.realpath(Path(state_dir) / "npm" / "projects")
    dirs = set()
    for x in installs:
        ip = x.get("install_path")
        if not isinstance(ip, Path):
            continue
        real = os.path.realpath(ip)
        if real.startswith(projects + os.sep):
            real = os.path.join(projects, os.path.relpath(real, projects).split(os.sep, 1)[0])
        dirs.add(real)
    total = 0
    for d in sorted(dirs):
        if not os.path.isdir(d) or any(d != o and d.startswith(o + os.sep) for o in dirs):
            continue
        for _pth, st in C.walk_lstat(Path(d), stop_event=STOP):
            if stat.S_ISREG(st.st_mode):
                total += st.st_size
    return total


def node_tmpdir(env=None):
    """The directory Node's os.tmpdir() gives OpenClaw (TMPDIR, TMP, TEMP, else /tmp; trailing "/" dropped)."""
    env = os.environ if env is None else env
    for k in ("TMPDIR", "TMP", "TEMP"):
        v = env.get(k)
        if v:
            return v.rstrip("/") or "/"
    return "/tmp"


_OFFICIAL_PACKAGE_RE = re.compile(r"@openclaw/[a-z0-9][a-z0-9._-]{0,100}")
_OFFICIAL_ROOT_RE = re.compile(r"/node_modules/(@openclaw/[a-z0-9][a-z0-9._-]{0,100})(?:/|$)")


def listed_official_plugins(data, installs=()):
    """[{id, package, version, enabled}] of the official npm plugins (@openclaw/*, Brave included) in the output of
    `openclaw plugins list --json`; None when it has no plugin list.

    The real output (2026.10.4 to 2026.11.1: each entry is OpenClaw's PluginRecord; tests/fixtures/
    plugins-list-2026.10.10.json) has no packageName: an entry counts when it is not bundled, comes from npm
    (OpenClaw's install record of its id in `installs` (official_plugin_installs), trust.installSource 'npm', or
    origin 'global') and its package is known from that install record, trust.installSpec, packageName or its
    rootDir/source path (.../node_modules/@openclaw/<name>/). version: the loaded one (version, else
    packageVersion; None when neither is a CalVer); enabled: OpenClaw's own verdict (True only for enabled true)."""
    plugins = data.get("plugins") if isinstance(data, dict) else None
    if not isinstance(plugins, list):
        return None
    by_id = {x["id"]: x for x in installs or () if isinstance(x, dict) and isinstance(x.get("id"), str)}
    out_ = []
    for x in plugins:
        if not isinstance(x, dict) or not isinstance(x.get("id"), str) or x.get("origin") == "bundled":
            continue
        rec = by_id.get(x["id"])
        trust = x.get("trust") if isinstance(x.get("trust"), dict) else {}
        npm_trust = trust.get("installSource") == "npm"
        if rec is None and not npm_trust and x.get("origin") != "global":
            continue
        names = [rec["package"] if rec else None, _npm_name(trust.get("installSpec")) if npm_trust else None,
                 x.get("packageName")]
        for k in ("rootDir", "source"):
            m = _OFFICIAL_ROOT_RE.search(x[k]) if isinstance(x.get(k), str) else None
            names.append(m.group(1) if m else None)
        pkg = next((n for n in names if isinstance(n, str) and n), None)
        if not pkg or not _OFFICIAL_PACKAGE_RE.fullmatch(pkg):
            continue
        ver = next((v for v in (x.get("version"), x.get("packageVersion"))
                    if isinstance(v, str) and C.version_tuple(v)), None)
        out_.append({"id": x["id"], "package": pkg, "version": ver, "enabled": x.get("enabled") is True})
    return out_


def unlisted_official_installs(data, installs):
    """Official npm install records (installs: official_plugin_installs; not Brave, not disabled in openclaw.json)
    whose plugin id `openclaw plugins list --json` does not show at all (any origin): the list cannot confirm their
    version. All of them when the list shows none of the recorded ids (output OpenClaw did not write as expected).
    [] when the output has no plugin list (the caller reports that)."""
    plugins = data.get("plugins") if isinstance(data, dict) else None
    if not isinstance(plugins, list):
        return []
    ids = {x["id"] for x in plugins if isinstance(x, dict) and isinstance(x.get("id"), str)}
    recs = [x for x in installs or () if isinstance(x, dict) and x.get("id") not in ids]
    if installs and len(recs) == len(installs):
        return recs
    return [x for x in recs if x.get("package") != BRAVE_PLUGIN_PACKAGE and x.get("enabled") is not False]


def schema_meta_problems(state_dir, cls, pkg):
    probs = []
    sdb = Path(state_dir) / "state" / "openclaw.sqlite"
    # full5: registry rows of stores OpenClaw holds back (classify res['held']) are not migrated: not reported
    held = {os.path.realpath(Path(state_dir) / h["path"]) for h in cls.get("held") or []}

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
            for aid, rp, sv in q(sdb, "SELECT agent_id, path, schema_version FROM agent_databases"):
                if held and isinstance(rp, str) and rp and os.path.realpath(
                        rp if os.path.isabs(rp) else Path(state_dir) / rp) in held:
                    continue
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


def plugins_behind(listed, runtime):
    """Enabled official plugins of listed_official_plugins (not Brave, run.sh's own step) older than `runtime`, the
    ones oc-upgrade plugins-sync updates."""
    rt = C.version_tuple(runtime)
    return [x for x in listed or () if x["enabled"] and x["package"] != BRAVE_PLUGIN_PACKAGE and x["version"]
            and rt and C.version_tuple(x["version"]) < rt]


def plugin_version_warnings(data, runtime, installs=()):
    """WARN lines for enabled official plugins whose version differs from the runtime (full5 wording: the add-on
    updates older ones before the gateway starts, oc-upgrade plugins-sync; Brave is run.sh's own step). The same
    plugins as plugins-sync (listed_official_plugins; `installs`: official_plugin_installs)."""
    if data is None:
        return ["plugins list --json returned no parseable JSON"]
    listed = listed_official_plugins(data, installs)
    if listed is None:
        return ["plugins list --json returned no plugin list"]
    warns = []
    rt = C.version_tuple(runtime)
    behind = {x["id"] for x in plugins_behind(listed, runtime)}
    for p in listed:
        if not p["enabled"] or p["package"] == BRAVE_PLUGIN_PACKAGE or not p["version"]:
            continue
        if rt and C.version_tuple(p["version"]) > rt:
            warns.append(f"plugin {p['id']} {p['version']} is newer than OpenClaw {runtime}; left as is")
        elif p["id"] in behind:
            warns.append(f"plugin {p['id']} is {p['version']}, OpenClaw is {runtime}: the add-on updates it before "
                         "the gateway starts (oc-upgrade plugins-sync)")
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
        marker = load_marker()
        cls = classify(g.gp["STATE"], cfg, pkg["schema_state"], pkg["schema_agent"], pkg["version"],
                       held=planning_held(g.gp["STATE"], marker, pkg))
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
    lines.append("[gate]   rollback point: the encrypted Home Assistant backup (no archive of the gate's own)")
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
    lines += _readiness_skills(g)  # full5
    if mode == "from-7x" and g.cfg:
        _new, ledger, summary = M.premigrate_config(g.cfg, removals=rs.get("config_removals") or [],
                                                    rewrites=rs.get("config_rewrites") or [])
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
    lines += _readiness_cron(g)  # full5
    b = g.budget()
    lines.append(f"[gate]   doctor budget {C.fmt_duration(b['doctor_pass_seconds'])}/pass (S={b['s_mib']} MiB)")
    return lines, F


def _readiness_skills(g):
    """Readiness lines after the cleanup plan (Skill Workshop, full5): from g.facts of the precheck."""
    inv = g.facts.get("sw_inventory")
    if not g.caps()["retires_skill_proposals"] or sw_empty(inv):
        return []
    keep = sum(inv["by_status"].get(s, 0) for s in SW_EXPORTED_STATUSES)
    return [f"[gate]   skill workshop: {inv['proposals']} proposals ({sw_status_text(inv['by_status'])}); OpenClaw "
            f"{g.pkg['version']} doctor keeps only the {keep} pending/quarantined drafts: the gate exports all "
            f"{inv['proposals']} first (secrets redacted)"]


def _readiness_cron(g):
    """Readiness lines before the doctor budget (cron, full5): from g.facts of the precheck. The config fixup the
    gate would make before doctor pass 1 (cron_config_fixup), then the report-only line."""
    rec = g.facts.get("cron_binding_plan")
    if not g.caps()["cron_refusal"] or not isinstance(rec, dict):
        return []
    fix = [a for a in rec.get("autofix") or [] if isinstance(a, dict) and a.get("provider")]

    def why(a):
        n, late, p = len(a.get("jobs") or []), len(a.get("behind") or []), printable(a["provider"])
        if not n and late:
            return f"for {late} enabled cron job(s) that reach {p} only after a fallback that stays refused"
        return f"keeps {n} enabled cron job(s) on {p} working"
    lines = [f"[gate]   cron config fixup: would set {printable(a['path'])} = \"api-key\" before doctor pass 1 "
             f"({why(a)}; {CRON_FIXUP_ISSUE})" for a in fix]
    if not rec.get("affected"):
        return lines
    aff = rec["affected"]
    n, rt, on = len(aff), g.pkg["version"], _cron_on(aff)
    if rec.get("doctor_migration"):
        which = " for a stored login, not for AWS SDK credentials" if _cron_kinds(aff)[1] else ""
        return lines + [f"[gate]   cron inference accounts: {n} enabled cron job(s) use {on} without a recorded "
                        f"account; OpenClaw {rt} doctor records it{which} (openclaw/openclaw#172792)"]
    copied = sum(1 for a in aff if a.get("key_copy"))
    return lines + [f"[gate]   cron inference accounts: {n} enabled cron job(s) stop at {on} on OpenClaw {rt} "
                    + (f"({copied} because OpenClaw's doctor copies a literal provider key into its auth store; fix: "
                       "models.providers.<provider>.auth \"api-key\" or an env SecretRef) " if copied else "")
                    + "(the WARN lines above, openclaw/openclaw#192195)"
                    + ("; apart from the config fixup above, the gate changes nothing for cron" if fix else
                       "; report only, the gate changes nothing")]


def hold_after_start(code, last_rc=None, emit=out):
    """`gate --hold-exit78` / `gate --hold-crash-loop <rc>`: always rc 0 (spec §10)."""
    gp = gpaths()
    g = Gate(emit=emit)
    try:
        try:
            g.pkg = C.runtime_package()
            cfg = _read_cfg_lenient()
            cls = classify(gp["STATE"], cfg, g.pkg["schema_state"], g.pkg["schema_agent"], g.pkg["version"],
                           held=planning_held(gp["STATE"], load_marker(), g.pkg))
            sub = cls["verdict"]
        except Exception as exc:  # noqa: BLE001
            cls, sub = None, "unknown"
            emit(f"WARN [gate] could not classify the state: {type(exc).__name__}: {exc}")
        what = "OpenClaw exited with code 78" if code == "exit78" else \
            f"OpenClaw kept crashing (crash loop; last exit code {last_rc})"
        if sub == "gate":
            msg = f"{what}; the state still needs migration: " + "; ".join((cls["gate"] + cls["files"])[:4])
            nxt = "oc-upgrade retry runs the gate again (backup check, doctor), then restart the add-on"
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
    red = C.LineRedactor()  # from the first line: a PEM block or a key above the tail still hides its lines
    shown = [red.line(ANSI_RE.sub("", ln)) for ln in data]
    for ln in shown[-lines:]:
        emit(ln)
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
    """Never delete while a gate run is active, held or about to be retried (its doctor captures may be needed)."""
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
REHEARSAL_DIR_RE = re.compile(r"^\d{8}-\d{6}(?:-[A-Za-z0-9]{6})?\Z")
STAGE_A_RE = re.compile(r"^openclaw-state-[0-9]{8}-[0-9]{6}-before-[0-9][0-9A-Za-z.+-]*\.tar\.gz(?:\.tmp)?\Z")


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


def _delete_run_copy(base, name):
    """One plaintext file of a run directory (RUN_PLAINTEXT_RE), unlinked through the directory's fd (the run
    directory itself must not be a link); only a regular file."""
    bfd = _open_parent(base)
    try:
        st = os.stat(name, dir_fd=bfd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EPERM, "not a regular file", str(Path(base) / name))
        os.unlink(name, dir_fd=bfd)
        return st.st_size
    finally:
        os.close(bfd)


def _delete_doctor_copy(gp, parts):
    """One of doctor's SQLite copies <state>/<parts...>: every directory below the state dir is opened without
    following links, and only a regular file with doctor's name pattern is unlinked."""
    dfd = open_dir_nofollow(gp["STATE"], *parts[:-1])
    try:
        st = os.stat(parts[-1], dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EPERM, "not a regular file", "/".join(parts))
        os.unlink(parts[-1], dir_fd=dfd)
        return st.st_size
    finally:
        os.close(dfd)


def _safe_delete(gp, p):
    """Dispatch by the cleanup root a target belongs to; anything else is refused."""
    base, name = p.parent, p.name
    if base == rehearsal_root(gp):
        return _delete_export(base, name)
    if base.parent == gp["RUNS"] and RUN_ID_RE.match(base.name) and RUN_PLAINTEXT_RE.match(name):
        return _delete_run_copy(base, name)
    if base == stage_a_root(gp):
        return _delete_file(base, name)
    if base in (gp["ARCHIVES"], captures_root(gp)):
        return _delete_entry(base, name)
    parts = _doctor_copy_parts(os.path.realpath(str(gp["STATE"])), str(p))
    if parts is not None:
        return _delete_doctor_copy(gp, parts)
    raise OSError(errno.EPERM, "outside the cleanup roots", str(p))


def _delete_tree(d):
    return _delete_entry(d.parent, d.name)


def _archive_dir_ok(gp, d):
    """A real run directory directly in ARCHIVES (lstat only: a planted link is never followed or stat'ed)."""
    arch = gp["ARCHIVES"]
    try:
        return (d.parent == arch and bool(RUN_ID_RE.match(d.name)) and stat.S_ISDIR(os.lstat(arch).st_mode)
                and stat.S_ISDIR(os.lstat(d).st_mode))
    except OSError:
        return False


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
    hist = j.get("history")
    for h in hist if isinstance(hist, list) else []:
        if isinstance(h, dict) and str(h.get("event", "")).startswith("journal "):  # "journal done/superseded ..."
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
    copies = None  # doctor's SQLite copies below the state dir, listed once for every run
    for rid, j in sorted(runs.items()):
        adir = gp["ARCHIVES"] / rid
        referenced.add(rid)
        try:
            fin = run_due_base(j)
            if fin is None:
                continue  # not finished by this gate (held, abandoned): an archive of it is handled as an orphan
            due = fin + timedelta(hours=hours)
        except (ValueError, TypeError, OverflowError, AttributeError) as exc:
            out_.append((rid, f"run {rid}", now, None, [(str(adir), f"journal unusable: {type(exc).__name__}")]))
            continue
        paths, kept = [], []
        try:
            if os.path.lexists(str(adir)):
                if _archive_dir_ok(gp, adir):
                    paths.append(adir)
                else:
                    kept.append((str(adir), "not a plain run directory"))
        except OSError as exc:
            kept.append((str(adir), f"not checked: {type(exc).__name__}"))
        try:
            caps, refused = run_captures(gp, j)
            paths += caps
            kept += refused
            copies = doctor_copies(gp["STATE"]) if copies is None else copies
            mine, refused = run_doctor_copies(gp, j, copies)  # full5: doctor's *.pre-startup-migration-*.bak
            paths += mine
            kept += refused
            paths += run_plaintext_copies(gp, rid)  # A5/A7: config.*.json, pc-models-status.json, ...
        except OSError as exc:  # like an unusable journal: warn once per loop, record nothing
            out_.append((rid, f"run {rid}", now, None,
                         kept + [(str(captures_root(gp)), f"doctor captures not listed: {type(exc).__name__}")]))
            continue
        out_.append((rid, f"run {rid}", due, paths, kept))
    unfinished = {rid for rid, j in runs.items() if not j.get("finished_at")}
    for what, scan in (("archives", _scan_archives), ("captures", _scan_captures),
                       ("rehearsal", _scan_rehearsal), ("Stage A", _scan_stage_a)):
        try:
            out_ += scan(gp, now, hours, runs, cur, referenced, unfinished)
        except (OSError, ValueError, TypeError, OverflowError) as exc:
            out_.append((None, f"{what} scan", now, [], [("-", f"skipped: {type(exc).__name__}: "
                                                         f"{C.redact_text(str(exc))[:120]}")]))
    return out_


def run_plaintext_copies(gp, rid):
    """The regular files of runs/<rid>/ that RUN_PLAINTEXT_RE names (A5/A7), through a real run directory only (lstat:
    a planted link is never followed)."""
    rd = gp["RUNS"] / str(rid)
    if not RUN_ID_RE.match(str(rid)):
        return []
    return [f for f, st in C.safe_children(rd) if stat.S_ISREG(st.st_mode) and RUN_PLAINTEXT_RE.match(f.name)]


def _scan_archives(gp, now, hours, runs, cur, referenced, unfinished):
    out_ = []
    # the current run's archive is its rollback copy while that run can still continue (closed runs: abandoned,
    # or done through bookkeeping without finished_at, are handled like orphans)
    active = (cur.get("run_id") if isinstance(cur, dict) and cur.get("status") not in ("done", "abandoned")
              else None)
    for d, _st in C.safe_children(gp["ARCHIVES"]):
        if d.name in referenced and d.name not in unfinished:
            continue
        if d.name.startswith(TOMB_PREFIX):
            if RUN_ID_RE.match(d.name[len(TOMB_PREFIX):]):
                out_.append((None, f"leftover {d.name}", now, [d], []))
            continue
        if not _archive_dir_ok(gp, d) or d.name == active:
            continue
        mt = _mtime_utc(d)
        if mt is not None:
            out_.append((None, f"orphaned archive {d.name}", mt + timedelta(hours=hours), [d], []))
    return out_


def _scan_captures(gp, now, hours, runs, cur, referenced, unfinished):
    out_ = []
    for d, st in C.safe_children(captures_root(gp)):  # a capture delete interrupted after its rename
        if (d.name.startswith(TOMB_PREFIX) and CAPTURE_NAME_RE.match(d.name[len(TOMB_PREFIX):])
                and stat.S_ISDIR(st.st_mode)):
            out_.append((None, f"leftover {d.name}", now, [d], []))
    return out_


def _scan_rehearsal(gp, now, hours, runs, cur, referenced, unfinished):
    out_ = []
    for d, st in C.safe_children(rehearsal_root(gp)):
        if not REHEARSAL_DIR_RE.match(d.name) or not stat.S_ISDIR(st.st_mode):
            continue
        files = [f for f, fst in C.safe_children(d) if f.name in REHEARSAL_FILES[:4] and stat.S_ISREG(fst.st_mode)]
        stamps = [t for t in (_mtime_utc(f) for f in files) if t is not None]
        if stamps:
            kind = "plaintext" if any(f.name.startswith("openclaw-rehearsal.tar.gz") and
                                      not f.name.endswith((".age", ".age.tmp")) for f in files) else "encrypted"
            out_.append((None, f"{kind} rehearsal export {d.name}", max(stamps) + timedelta(hours=hours),
                         [d], []))
    return out_


def _scan_stage_a(gp, now, hours, runs, cur, referenced, unfinished):
    out_ = []
    marker = C.load_json_or_none(gp["MARKER"])
    sa = stage_a_root(gp)
    if isinstance(marker, dict) and (C.version_tuple(str(marker.get("runtime") or "")) or (0,)) >= (2026, 8, 0):
        done_at = _parse_backup_date(marker.get("completed_at"))
        mj = runs.get(str(marker.get("run_id")))
        cleared = run_due_base(mj) if mj else None
        if cleared and (done_at is None or cleared > done_at):
            done_at = cleared
        for f, st in C.safe_children(sa):
            if not STAGE_A_RE.match(f.name) or not stat.S_ISREG(st.st_mode):
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
                deleted += _cleanup_target(gp, now, rid, label, due, paths, kept, emit, errors)
                errors.discard(label)
            except Exception as exc:  # noqa: BLE001 (report, then go on with the next target)
                if label not in errors:
                    emit(f"WARN [cleanup] {printable(label)}: {type(exc).__name__}: "
                         f"{printable(C.redact_text(str(exc))[:200])}")
                    errors.add(label)
        return deleted
    finally:
        os.close(lk)


def _cleanup_target(gp, now, rid, label, due, paths, kept, emit, errors=None):
    rec_path = gp["RUNS"] / rid / "cleanup.json" if rid else None
    rec = C.load_json_or_none(rec_path) if rec_path else None
    rec = rec if isinstance(rec, dict) else {"schema": 1}
    errors = errors if errors is not None else set()
    dirty = False
    label = printable(label)
    if paths is None:  # the target could not be built: warn once per loop, never record anything
        for path, reason in kept:
            if f"{label}\0err:{path}" not in errors:
                emit(f"WARN [cleanup] {label}: kept {printable(path)}: {printable(reason)}")
                errors.add(f"{label}\0err:{path}")
        return 0
    for path, reason in kept:
        key = f"kept:{path}"
        if rid is None:  # no record file: once per loop
            if f"{label}\0{key}" not in errors:
                emit(f"WARN [cleanup] {label}: kept {printable(path)}: {printable(reason)}")
                errors.add(f"{label}\0{key}")
        elif not rec.get(key):
            emit(f"WARN [cleanup] {label}: kept {printable(path)}: {printable(reason)}")
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
            emit(f"[cleanup] {label}: {len(live)} item(s) (doctor captures, doctor SQLite copies, plaintext config "
                 f"copies / archive) will be deleted at {C.utc_iso(due)}")
            dirty = True
        elif rec_path and rec.get("due_at") != C.utc_iso(due):
            rec["due_at"] = C.utc_iso(due)  # moved: a hold after the run was cleared later
            emit(f"[cleanup] {label}: deletion moved to {C.utc_iso(due)}")
            dirty = True
        if dirty and rec_path and rec_path.parent.is_dir():
            C.atomic_write_json(rec_path, rec)
        return 0
    gone = []
    for p_ in live:
        if STOP.is_set():
            break
        key = f"{label}\0{p_}"
        try:
            gone.append({"path": str(p_), "bytes": _safe_delete(gp, p_)})
            errors.discard(key)
        except OSError as exc:
            if key not in errors:  # once per path, not at every hourly pass
                emit(f"WARN [cleanup] {label}: could not delete {printable(p_)}: {printable(exc.strerror or exc)}")
                errors.add(key)
    if gone:
        emit(f"[cleanup] {label}: deleted {len(gone)} item(s), {C.human(sum(g['bytes'] for g in gone))}: "
             + ", ".join(printable(g["path"]) for g in gone[:4]) + (" ..." if len(gone) > 4 else ""))
        if rec_path and rec_path.parent.is_dir():
            rec.update({"due_at": C.utc_iso(due), "deleted_at": C.utc_iso(now)})
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
        emit(f"[cleanup] doctor captures, doctor's SQLite copies and the gate's config copies are deleted {hours} h "
             "after their gate run; gate archives and rehearsal exports of earlier add-on versions and the 2026.7 "
             "plaintext archives the same time after their run, export or migration (checked hourly)")
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
        live = [p_ for p_ in paths or [] if os.path.lexists(str(p_))]
        if not live:
            verdict = "nothing left"
        elif not hours:
            verdict = "kept (gate_cleanup_hours=0)"
        else:
            verdict = "due now" if now >= due else f"due {C.utc_iso(due)}"
        emit(f"  {printable(label)}: {verdict}")
        for p_ in live:
            try:
                st = os.lstat(p_)
                size = _dir_bytes(p_) if stat.S_ISDIR(st.st_mode) else st.st_size
            except OSError:
                size = None
            emit(f"    {printable(p_)} ({C.human(size)})")
        for path, reason in kept:
            emit(f"    kept {printable(path)}: {printable(reason)}")
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


def leftover_note(hours):
    """What happens to the copies earlier versions left, for status listings."""
    return ("deleted automatically, see oc-upgrade cleanup" if hours else
            "kept: gate_cleanup_hours=0, delete them yourself")


def _status_cron(j):
    """`oc-upgrade status` lines of the gate run `j` (cron inference accounts, full5, report only): the
    postconditions' report, else the precheck forecast of a run that stopped before."""
    fix = ["  " + x for x in cron_fixup_done_lines(j)]  # the config fixups this run made
    if fix:  # A4: the journal says what the run set; openclaw.json says whether it is still there
        fix += ["  " + x for x in cron_fixup_drift_lines(j, _read_cfg_lenient(), held=gpaths()["HOLD"].exists())]
    rec, when = j.get("cron_binding"), "after the migration"
    if not isinstance(rec, dict):
        rec, when = j.get("cron_binding_forecast"), "precheck forecast"
    if not isinstance(rec, dict):
        return fix
    if not fix and when == "precheck forecast" and not j.get("doctor_started"):  # stopped before doctor pass 1
        rt = rec.get("runtime")
        fix = [f"  config fixup before doctor pass 1: would set {printable(a.get('path'))} = \"api-key\" "
               f"({cron_fixup_why(a.get('provider'), rt)}; precheck forecast)"
               for a in rec.get("autofix") or [] if isinstance(a, dict) and a.get("provider")]
        fix += [f"  config fixup skipped for {printable(a.get('provider'))}: openclaw.json uses $include; after the "
                f"start run: openclaw config set {shlex.quote(str(a.get('path')))} api-key"
                for a in rec.get("autofix_skipped") or [] if isinstance(a, dict) and a.get("provider")]
    aff = [a for a in rec.get("affected") or [] if isinstance(a, dict)]
    head = (f"  cron jobs without a recorded inference account (openclaw/openclaw#192195, OpenClaw "
            f"{printable(rec.get('runtime'))}, {when}): ")
    un = cron_unconfigured_line(rec)  # D6
    inc = cron_include_line(rec)
    gone = cron_retired_review_line(rec)  # a forecast record: the jobs doctor deletes
    if not aff:
        return fix + ([head + f"none affected ({rec['checked']} checked)"] if rec.get("checked") else []) \
            + ([f"  {un}"] if un else []) + ([f"  {gone}"] if gone else []) + ([f"  {inc}"] if inc else [])
    L = fix + [head + f"{len(aff)} affected of {rec.get('checked', 0)} checked"]
    for a in aff[:CRON_REPORT_MAX]:
        refs = [printable(r) for r in a.get("refs") or []]
        aws = {printable(r) for r in a.get("aws_sdk") or []}
        copied = {printable(r) for r in a.get("key_copy") or []}
        what = "every run refused" if a.get("primary_affected") else f"stops at the fallback {refs[0] if refs else '?'}"
        shown = ", ".join(r + (" (AWS SDK credentials)" if r in aws else
                               " (literal key that doctor copies)" if r in copied else "") for r in refs)
        L.append(f"    {cron_job_label(a)}: {what}; {shown}")
    if len(aff) > CRON_REPORT_MAX:
        L.append(f"    and {len(aff) - CRON_REPORT_MAX} more")
    L += cron_key_fix_lines(rec, "    ", held=gpaths()["HOLD"].exists())  # the wrapper refuses config set while held
    L.append("    " + "".join(x + ". " for x in _cron_outlook(aff, rec)) + _cron_remedy(aff, bool(_cron_key_fix(rec))))
    if un:
        L.append(f"  {un}")
    if gone:
        L.append(f"  {gone}")
    if inc:
        L.append(f"  {inc}")
    return L


def _status_skills(gp):
    """`oc-upgrade status` lines after the quarantine (Skill Workshop exports, full5)."""
    found = []
    for m in sorted(gp["RUNS"].glob(f"*/{SW_EXPORT_DIR}/MANIFEST.json")):
        rid = m.parent.parent.name
        if RUN_ID_RE.match(rid) and sw_export_record(gp, rid) is not None:
            found.append((rid, m.parent))
    if not found:
        return []
    rid, d = found[-1]  # run ids sort by their start time
    n = (sw_export_record(gp, rid) or {}).get("proposals")
    return [f"Skill Workshop exports: {len(found)} (newest {d}/, {n} proposals; secrets redacted; kept until you "
            "delete them)"]


PLUGIN_CAPTURES_DIR = ("tmp", "plugin-captures")
PLUGIN_CAPTURES_WALK_MAX = 200_000


def plugin_captures_usage(state_dir):
    """OpenClaw's native plugin captures (<state>/tmp/plugin-captures/<uuid>/, made when a plugin with native files is
    admitted, e.g. by doctor's plugin update; referenced from the installed plugin index and removed by OpenClaw itself
    once nothing refers to them, at gateway start and in doctor --fix): {"path", "captures", "files", "own", "linked",
    "partial"} or None when there is none. own: bytes of the regular files with a single link (data only the capture
    holds); linked: bytes of the files with more links (hard links that share the installed plugin packages' disk
    space; each inode once). Read-only; the walk stops after PLUGIN_CAPTURES_WALK_MAX entries (partial)."""
    root = Path(state_dir).joinpath(*PLUGIN_CAPTURES_DIR)
    try:
        with os.scandir(root) as it:
            caps = sum(1 for e in it if e.is_dir(follow_symlinks=False))
    except OSError:
        return None
    if not caps:
        return None
    res = {"path": str(root), "captures": caps, "files": 0, "own": 0, "linked": 0, "partial": False}
    seen = set()
    for n, (_p, st) in enumerate(C.walk_lstat(root), 1):
        if n > PLUGIN_CAPTURES_WALK_MAX:
            res["partial"] = True
            break
        if not stat.S_ISREG(st.st_mode):
            continue
        res["files"] += 1
        if st.st_nlink <= 1:
            res["own"] += st.st_size
        elif (st.st_dev, st.st_ino) not in seen:
            seen.add((st.st_dev, st.st_ino))
            res["linked"] += st.st_size
    return res


def _status_openclaw_leftovers(gp):
    """`oc-upgrade status` lines (D8, D11, plugin captures): OpenClaw's plugin install leftovers, the databases it set
    aside as <file>.corrupt-<time>, and its native plugin captures. Never deleted by the add-on."""
    L = []
    try:
        cfg = _read_cfg_lenient()
    except Exception:  # noqa: BLE001 - status must never fail on these lines
        cfg = {}
    try:
        left = plugin_install_leftovers(gp["STATE"])
        if left:
            L.append("Plugin install leftovers: " + install_leftovers_text(left))
        aside = sqlite_set_aside(gp["STATE"], cfg)
        if aside:
            names = sorted(aside)
            L.append(f"Databases OpenClaw set aside (<file>.corrupt-<time>): {len(names)} file(s), "
                     f"{C.human(sum(aside.values()))}: " + ", ".join(printable(x) for x in names[:8])
                     + (" …" if len(names) > 8 else "")
                     + " — complete plaintext databases (e.g. doctor's renamed copy of another agent's database); "
                       "OpenClaw and the add-on keep them: delete them by hand once you are satisfied")
        cap = plugin_captures_usage(gp["STATE"])
        if cap:
            L.append(f"OpenClaw plugin captures: {cap['path']} ({cap['captures']} capture(s), {cap['files']} files"
                     + (" or more" if cap["partial"] else "") + f"; {C.human(cap['own'])} of their own, "
                     f"{C.human(cap['linked'])} in hard links that share the installed plugins' disk space): OpenClaw's "
                     "live copy of the native plugin files, removed by OpenClaw once no plugin install refers to it; "
                     "the add-on does not delete it")
    except Exception as exc:  # noqa: BLE001 - status must never fail on these lines
        L.append(f"OpenClaw leftovers not checked ({type(exc).__name__})")
    return L


def plugin_cohort_marker(state_dir, version):
    """run.sh / oc-upgrade plugins-sync: the enabled official plugins were brought to OpenClaw `version`."""
    return Path(state_dir) / f".plugin_cohort_{version}"


def _status_held_and_plugins(gp, marker):
    """Status lines (full5): held stores the marker recorded, and the official plugins against the runtime."""
    L = []
    held = (marker or {}).get("held") if isinstance(marker, dict) else None
    if isinstance(held, list) and held:
        L.append("  held agent databases (not migrated, not opened by the gateway; not checked): "
                 + ", ".join(f"{printable(h.get('path'))} (agent {printable(h.get('id'))}, schema {h.get('uv')}: "
                             f"{held_reason_text(h.get('reason'))})" for h in held if isinstance(h, dict)))
    try:
        official = official_plugin_installs(gp["STATE"], _read_cfg_lenient())
    except Exception:  # noqa: BLE001 - status must never fail on this line
        official = []
    if official:
        try:
            rt = C.runtime_package()["version"]
        except C.RuntimePackageError:
            rt = None
        text = ", ".join(f"{x['package']} {x['version'] or '?'}"
                         + {True: " (enabled)", False: " (disabled)"}.get(x["enabled"], "") for x in official)
        if rt:
            # D2: the versions decide, not the marker (it only says that plugins-sync ran for this version)
            rtv = C.version_tuple(rt)
            mine = [x for x in official if x["enabled"] is not False and x["package"] != BRAVE_PLUGIN_PACKAGE]
            newer = [x for x in mine if rtv and C.version_tuple(x["version"]) and C.version_tuple(x["version"]) > rtv]
            behind = [x["package"] for x in mine if x["version"] != rt and x not in newer]
            cohort = plugin_cohort_marker(gp["STATE"], rt)
            held = gp["HOLD"].exists()  # plugins-sync skips and the wrapper refuses `plugins` while OpenClaw is held
            if behind and cohort.exists():
                how = f"delete {cohort} and restart the add-on, or by hand: openclaw plugins update <package>@{rt}"
                text += (f"; not at OpenClaw {rt}: {', '.join(behind)} (enabled or changed after the add-on's update "
                         f"step for {rt}; " + (f"not while OpenClaw is held: once the HOLD is cleared, {how}" if held
                                               else f"to update: {how}") + ")")
            elif behind and held:
                text += (f"; not yet at OpenClaw {rt}: {', '.join(behind)} (not while OpenClaw is held: the add-on "
                         "updates them at the first start after the HOLD is cleared, after the migration gate, whose "
                         "doctor passes update them too: oc-upgrade plugins-sync)")
            elif behind:
                text += (f"; not yet at OpenClaw {rt}: {', '.join(behind)} (the add-on retries at the next start: "
                         "oc-upgrade plugins-sync)")
            if newer:
                text += f"; newer than OpenClaw {rt}, left as is: {', '.join(x['package'] for x in newer)}"
            if not behind and not newer:
                text += f"; enabled ones {'synced to' if cohort.exists() else 'at'} OpenClaw {rt}"
        L.append(f"Official plugins: {text}")
    return L


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
            nxt = REMOVED_HOLD_ADVICE if removed_hold(h) else h.get("next") or "oc-upgrade retry"
            L.append(f"  acceptable: {'yes' if h.get('acceptable') else 'no'}; next: {nxt}")
            acc = [f["code"] for f in h.get("findings") or [] if f.get("cls") == "acceptable"]
            if acc:
                L.append(f"  accept: oc-upgrade retry --accept {','.join(dict.fromkeys(acc))}")
        if j.get("accepted"):
            L.append(f"  accepted codes: {', '.join(j['accepted'])}")
        a = j.get("archive") or {}
        cl = C.load_json_or_none(gp["RUNS"] / str(j.get("run_id")) / "cleanup.json") or {}
        when = f"; deleted {cl['deleted_at']}" if cl.get("deleted_at") else \
            (f"; auto-delete due {cl['due_at']}" if cl.get("due_at") else "")
        if a.get("file"):  # written by 0.5.94-full1/full2; this version writes none
            L.append(f"  archive (earlier add-on version): {printable(a.get('dir'))}/{printable(a.get('file'))}{when}")
        elif when:
            L.append(f"  doctor captures{when}")
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
        L += _status_cron(j)  # full5
        for o in j.get("orphan_outcomes") or []:  # D11
            if isinstance(o, dict):
                L.append("  " + orphan_outcome_text(o))
    else:
        L.append("Gate: no run recorded.")
    m = load_marker()
    L.append(f"Migrated marker: {m.get('runtime')} ({m.get('mode')}, run {m.get('run_id')}, {m.get('completed_at')})"
             if m else "Migrated marker: none")
    L += _status_held_and_plugins(gp, m)  # full5
    r = load_retry()
    if r:
        L.append(f"Pending retry request: doctor={r.get('doctor')} accept={','.join(r.get('accept') or []) or '-'} "
                 "(runs on the next add-on start)")
    o = C.gate_options()
    L.append("Gate options: delete doctor captures, SQLite copies "
             f"and the gate's config copies {o['cleanup_hours']} h after a run (0 = never); "
             f"backup max age {o['backup_max_age_hours']} h")
    archives = C.safe_files_below(gp["ARCHIVES"], lambda n: n.endswith((".tar.gz", ".tar.gz.age")))
    if archives:
        L.append(f"Gate archives in /share from earlier add-on versions ({leftover_note(o['cleanup_hours'])}):")
    for a, st in archives:
        kind = "encrypted" if a.name.endswith(".age") else "PLAINTEXT: unencrypted secrets"
        L.append(f"  {printable(a)} ({C.human(st.st_size)}, {kind})")
    caps = captures_root(gp)
    if caps.is_dir():
        n = sum(1 for x in caps.iterdir() if CAPTURE_NAME_RE.match(x.name.removeprefix(TOMB_PREFIX)))
        L.append(f"Doctor captures: {n} in {caps} (pre-repair database copies; deleted with their gate run)")
    qd = gp["QUAR"]
    if qd.exists():
        n = sum(1 for _p, st in C.walk_lstat(qd) if not stat.S_ISDIR(st.st_mode) and _p.name != "MANIFEST.json")
        L.append(f"Quarantine: {qd} ({n} files)")
    L += _status_skills(gp)  # full5
    L += _status_openclaw_leftovers(gp)  # D8, D11, plugin captures
    baks = doctor_copies(gp["STATE"])
    if baks:
        ns = sum(1 for _size, scope in baks.values() if scope == "scoped")
        L.append(f"Doctor pre-migration SQLite copies: {len(baks) - ns} full (.bak), {ns} table-scoped (.scoped.bak) "
                 f"({C.human(sum(size for size, _scope in baks.values()))}) beside the databases in {gp['STATE']}: "
                 "plaintext, not the rollback point; those a gate run made: "
                 + leftover_note(o["cleanup_hours"])
                 + ("; restore a .scoped.bak only with openclaw database restore-migration-backup, never by copying"
                    if ns else ""))
    outside = []
    for _rid, rj in sorted(_run_journals(gp)[0].items()):
        outside += [x for x in run_outside_copies(rj) if x not in outside]
    if outside:
        L.append("Doctor pre-migration SQLite copies beside agent databases outside "
                 f"{gp['STATE']}: {len(outside)}, plaintext, not the rollback point; the add-on does not delete them, "
                 "delete them yourself: " + ", ".join(printable(x) for x in outside[:8])
                 + (" …" if len(outside) > 8 else ""))
    led = C.load_json_or_none(gp["LEDGER"])
    if isinstance(led, dict):
        L.append(f"Pins ledger: {len(led.get('entries') or [])} written, {len(led.get('skipped') or [])} skipped")
    return L
