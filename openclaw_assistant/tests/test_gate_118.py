"""The 2026.11.5+ main line as 0.5.94-full7 bundles it: OpenClaw 2026.11.10 (RT models the bundled runtime; schemas
40/42). The file kept its name from 2026.11.8, which full7 targeted first; the 2026.11.10 additions are in
test_gate_1110.

- wizard.lastRunAt: doctor stamps it on every config write; the pass-3 trigger and doctor-not-idempotent ignore it
  (test_gate.GateRunMoreTests).
- Doctor captures: 2026.11.5+ logs a sealed capture only at debug level; the gate records the doctor-<uuid>
  directories that appear during its doctor passes (test_gate_full2_cleanup).
- Default cron partition (state schema 34, runtime_caps cron_partition_binding): the schema migration records
  config_machine_state "cron.defaultStoreKey" only for a provable legacy default or a single partition; otherwise cron
  stays paused. The precheck forecasts it (WARN). OpenClaw 2026.11.8 and 2026.11.10 doctor then stop ("Default cron
  partition selection is unresolved", rehearsal 118 variant P): the hard HOLD doctor-cron-partition says how to select
  the store in a terminal doctor; the postconditions keep pc-cron-partition (acceptable) for a doctor that does not
  stop.
Synthetic fixtures only (10.4-layout state from test_gate, synthetic jobs and store paths).
"""

import json
import os
import sqlite3
import sys
import unittest
import unittest.mock
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
for _p in (str(ADDON), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_common as C  # noqa: E402
import oc_gate as G  # noqa: E402
import test_gate as T  # noqa: E402
import test_gate_cron_binding as CB  # noqa: E402

RT = "2026.11.10"
OTHER = "/srv/synthetic/old-cron/jobs.json"
THIRD = "/srv/synthetic/third/jobs.json"


def state_db(path, tables=("cron_jobs", "config_machine_state")):
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    ddl = {
        "cron_jobs": "CREATE TABLE cron_jobs (store_key TEXT, job_id TEXT)",
        "cron_job_scratch": "CREATE TABLE cron_job_scratch (store_key TEXT, job_id TEXT)",
        "cron_run_receipts": "CREATE TABLE cron_run_receipts (store_key TEXT, run_id TEXT)",
        "cron_run_logs": "CREATE TABLE cron_run_logs (store_key TEXT, id INTEGER)",
        "task_runs": "CREATE TABLE task_runs (runtime TEXT, detail_json TEXT)",
        "diagnostic_events": "CREATE TABLE diagnostic_events (scope TEXT)",
        "config_machine_state": "CREATE TABLE config_machine_state (state_key TEXT PRIMARY KEY, value_json TEXT, "
                                "updated_at_ms INTEGER)",
    }
    for t in tables:
        con.execute(ddl[t])
    con.commit()
    return con


class StateTmp(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.tmp = Path(self._td.name)
        self.state = self.tmp / "state-dir"
        self.env = {"HOME": str(self.tmp / "home"), "OPENCLAW_STATE_DIR": str(self.state),
                    "OPENCLAW_CONFIG_PATH": str(self.state / "openclaw.json")}
        self.legacy = str(self.state / "cron" / "jobs.json")
        self.sdb = self.state / "state" / "openclaw.sqlite"


class CronPartitionStateTests(StateTmp):
    def st(self, cfg=None, migrated=False):
        return G.cron_partition_state(self.sdb, cfg or {}, migrated, env=self.env)

    def test_legacy_key_follows_openclaw_resolve_config_dir(self):
        self.assertEqual(G.cron_legacy_default_key(self.env), self.legacy)
        self.assertEqual(G.cron_legacy_default_key({"HOME": "/h", "OPENCLAW_STATE_DIR": " ~/x/../y "}),
                         "/h/y/cron/jobs.json")
        self.assertEqual(G.cron_legacy_default_key({"HOME": "/h", "OPENCLAW_CONFIG_PATH": "/c/d/openclaw.json"}),
                         "/c/d/cron/jobs.json")
        self.assertEqual(G.cron_legacy_default_key({"HOME": "/h"}), "/h/.openclaw/cron/jobs.json")

    def test_no_state_database_or_empty_inventory_is_the_default(self):
        self.assertEqual(self.st()["status"], "default")
        state_db(self.sdb).close()
        self.assertEqual((self.st()["status"], self.st()["key"]), ("binds", self.legacy))
        self.assertEqual(self.st(migrated=True)["status"], "default")

    def test_jobs_on_the_legacy_default_bind_it(self):
        con = state_db(self.sdb)
        con.executemany("INSERT INTO cron_jobs VALUES (?, ?)", [(self.legacy, "a"), (OTHER, "b")])
        con.commit()
        st = self.st()
        self.assertEqual((st["status"], st["key"]), ("binds", self.legacy))
        self.assertEqual(st["partitions"], {self.legacy: 1, OTHER: 1})
        self.assertEqual(self.st(migrated=True)["status"], "default")

    def test_a_single_other_partition_binds_before_the_migration_only(self):
        con = state_db(self.sdb)
        con.executemany("INSERT INTO cron_jobs VALUES (?, ?)", [(OTHER, "a"), (OTHER, "b")])
        con.commit()
        st = self.st()
        self.assertEqual((st["status"], st["key"], st["partitions"]), ("binds", OTHER, {OTHER: 2}))
        self.assertEqual(self.st(migrated=True)["status"], "unresolved")  # the migration ran and recorded none

    def test_two_other_partitions_stay_unresolved(self):
        con = state_db(self.sdb, ("cron_jobs", "cron_run_logs", "task_runs", "diagnostic_events",
                                  "config_machine_state"))
        con.execute("INSERT INTO cron_jobs VALUES (?, 'a')", (OTHER,))
        con.execute("INSERT INTO cron_run_logs VALUES (?, 1)", (THIRD,))
        con.execute("INSERT INTO task_runs VALUES ('cron', ?)", (json.dumps({"storeKey": THIRD}),))
        con.execute("INSERT INTO task_runs VALUES ('cron', 'not json')")
        con.execute("INSERT INTO task_runs VALUES ('subagent', ?)", (json.dumps({"storeKey": self.legacy}),))
        con.execute("INSERT INTO diagnostic_events VALUES (?)", ("cron.quarantine:" + OTHER,))
        con.execute("INSERT INTO config_machine_state VALUES (?, '{}', 0)", (f"automation-default:{THIRD}:main",))
        con.commit()
        st = self.st()
        self.assertEqual(st["status"], "unresolved")
        self.assertEqual(st["partitions"], {OTHER: 2, THIRD: 3})
        text = G.cron_partition_text(st, True)
        self.assertIn(f"the cron rows belong to 2 store(s) and none is the default {self.legacy} (partitions: "
                      f"{OTHER} (2 row(s)); {THIRD} (3 row(s))): OpenClaw cannot tell which store to run, and its doctor "
                      "stops", text)
        self.assertIn("HOLD doctor-cron-partition", text)
        self.assertIn("OC_ADDON_UNSAFE=1 openclaw doctor --fix", text)
        self.assertNotIn(" `openclaw doctor --fix`", text)
        self.assertIn("cron stays paused", G.cron_partition_text(st, False))
        # a legacy-default row in another source settles it
        con.execute("INSERT INTO cron_run_logs VALUES (?, 2)", (self.legacy,))
        con.commit()
        self.assertEqual(self.st()["status"], "binds")

    def test_recorded_binding_and_explicit_store(self):
        con = state_db(self.sdb)
        con.executemany("INSERT INTO cron_jobs VALUES (?, ?)", [(OTHER, "a"), (THIRD, "b")])
        con.commit()
        self.assertEqual(self.st({"cron": {"store": OTHER}})["status"], "explicit")
        self.assertEqual(self.st({"cron": {"store": self.legacy}}, migrated=True)["status"], "unresolved")
        con.execute("INSERT INTO config_machine_state VALUES ('cron.store', ?, 0)", (json.dumps(THIRD),))
        con.commit()
        st = self.st(migrated=True)
        self.assertEqual((st["status"], st["key"]), ("explicit", THIRD))
        con.execute("DELETE FROM config_machine_state")
        con.execute("INSERT INTO config_machine_state VALUES ('cron.defaultStoreKey', ?, 0)", (json.dumps(OTHER),))
        con.commit()
        st = self.st(migrated=True)
        self.assertEqual((st["status"], st["key"]), ("bound", OTHER))
        con.execute("UPDATE config_machine_state SET value_json='42'")
        con.commit()
        st = self.st(migrated=True)
        self.assertEqual(st["status"], "invalid")
        self.assertIn("record (config_machine_state cron.defaultStoreKey) is unreadable", G.cron_partition_text(st, False))


class CronPartitionGateTests(T.GateEnv):
    """A 2026.10.4-layout state whose cron jobs belong to two non-default stores, migrated by a 2026.11.10 doctor."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, content=True)
        self.sdb = self.state / "state" / "openclaw.sqlite"
        CB.add_jobs(self.state, CB.GLM_JOBS[:2])
        con = sqlite3.connect(str(self.sdb))
        con.execute("UPDATE cron_jobs SET store_key=?", (OTHER,))
        con.execute("UPDATE cron_jobs SET store_key=? WHERE rowid IN (SELECT MIN(rowid) FROM cron_jobs)", (THIRD,))
        con.commit()
        con.close()
        self.write_cfg(CB.CFG_GLM)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime(RT, 40, 42)
        self.hooks()

    def test_precheck_warns_and_a_blocked_doctor_holds_with_its_own_code(self):
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        warn = [x for x in lines if "Default cron partition selection is unresolved" in x]
        self.assertEqual(len(warn), 1, lines)
        self.assertTrue(warn[0].startswith("WARN [gate] 1/8 the cron rows belong to 2 store(s) and none is the "
                                           "default "), warn[0])
        self.assertIn("HOLD doctor-cron-partition", warn[0])
        self.assertIn("Only the jobs of the selected store run afterwards", warn[0])
        self.assertTrue(warn[0].endswith("The migration starts; the gate then holds with doctor-cron-partition (its "
                                         "advice says how to select the store)"), warn[0])
        # what 2026.11.8 doctor printed (rehearsal 118, variant P; the same texts in 2026.11.10)
        self.doctor_script(state_uv=40, agent_uv=42, app_version=RT, rc=1, box=False, print=[
            "Fix now:",
            "- Doctor could not complete State integrity: Default cron partition selection is unresolved; cron is "
            "paused. Run openclaw doctor --fix in an interactive terminal and complete the \"Select the default cron "
            "partition\" selection step. Partition inventory: {\"storeKey\":\"/srv/synthetic/old-cron/jobs.json\"}",
            "  Next step: Resolve the reported inspection failure, then rerun openclaw doctor.",
            "  Docs: https://docs.openclaw.ai/cli/doctor/running#understanding-findings",
            "Doctor blocked; required repairs remain incomplete."])
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["phase"]), ("doctor-cron-partition", "doctor1"))
        adv = G.ADVICE["doctor-cron-partition"]
        self.assertIn("OC_ADDON_UNSAFE=1 openclaw doctor --fix", adv)
        self.assertIn("press the down arrow to the store your jobs run from", adv)
        self.assertIn("Only the jobs of the selected store run afterwards", adv)
        self.assertNotIn("doctor-cron-partition", G.ACCEPTABLE)

    def test_postconditions_hold_when_doctor_leaves_the_partition_unresolved(self):
        self.doctor_script(state_uv=40, agent_uv=42, app_version=RT, drop_tables=["cron_run_logs"],
                           remove=["identity/device.json"])
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["phase"]), ("pc-cron-partition", "postconditions"))
        self.assertIn("cron stays paused", j["hold"]["message"])
        self.assertNotIn("after the migration", j["hold"]["message"])
        self.assertIn("OC_ADDON_UNSAFE=1 openclaw doctor --fix", G.ADVICE["pc-cron-partition"])
        G.retry_cmd(["--accept", "pc-cron-partition"], emit=lambda s: None)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("done: MIGRATED 2026.11.10", self.out)

    def test_doctor_records_a_partition_and_the_gate_does_not_hold(self):
        self.doctor_script(state_uv=40, agent_uv=42, app_version=RT, drop_tables=["cron_run_logs"],
                           remove=["identity/device.json"], sql=[
            "INSERT OR REPLACE INTO config_machine_state VALUES ('cron.defaultStoreKey', '%s', 0)" % json.dumps(OTHER)])
        rc = self.run_gate()
        j = self.journal()
        self.assertNotEqual((j.get("hold") or {}).get("code"), "pc-cron-partition", self.out)
        self.assertEqual(j["cron_partition_forecast"], {"status": "unresolved", "partitions": 2})
        self.assertEqual(rc, 0, self.out)

    def test_heartbeat_retirement_is_announced(self):
        cfg = json.loads(json.dumps(CB.CFG_GLM))
        cfg.setdefault("agents", {}).setdefault("defaults", {})["heartbeat"] = {"every": "30m", "target": "none"}
        self.write_cfg(cfg)
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        info = [x for x in lines if "info: heartbeat (" in x]
        self.assertEqual(info, [f"[gate] 1/8 info: heartbeat (agents.defaults.heartbeat): OpenClaw {RT} retires the "
                                "heartbeat settings; doctor turns them into one ordinary cron job per agent "
                                "(HEARTBEAT.md goes into its cron scratch, a copy under /config/.openclaw/backups/"
                                "heartbeat-migration/). Its model chain is a cron chain from then on: the cron report "
                                "after the migration includes it"], lines)
        self.assertEqual(G.heartbeat_config_paths({"agents": {"list": [{}, {"heartbeat": {}}],
                                                              "entries": {"x": {"heartbeat": {}}}}}),
                         ["agents.list[1].heartbeat", "agents.entries.x.heartbeat"])

    def test_earlier_runtime_checks_nothing(self):
        self.set_runtime("2026.11.4", 22, 27)
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        self.assertFalse([x for x in lines if "cron stays paused" in x or "info: heartbeat (" in x], lines)


class LegacyDeviceIdentityTests(StateTmp):
    def test_device_json_counts_as_migrated_with_the_client_credential_store(self):
        # 2026.11.5+: device_identities lives in <state>/client/credentials.sqlite (state schema 29 cutover)
        (self.state / "identity").mkdir(parents=True)
        (self.state / "identity" / "device.json").write_text("{}")
        state_db(self.sdb).close()
        with unittest.mock.patch.dict(os.environ, {"OPENCLAW_STATE_DIR": str(self.state)}):
            self.assertEqual(G.legacy_files(self.state, {}, set()), [str(self.state / "identity" / "device.json")])
            cdb = self.state / "client" / "credentials.sqlite"
            cdb.parent.mkdir()
            con = sqlite3.connect(str(cdb))
            con.execute("CREATE TABLE device_identities (identity_key TEXT PRIMARY KEY, device_id TEXT)")
            con.commit()
            self.assertEqual(len(G.legacy_files(self.state, {}, set())), 1)  # no row yet
            con.execute("INSERT INTO device_identities VALUES ('primary', 'synthetic-device')")
            con.commit()
            con.close()
            self.assertEqual(G.legacy_files(self.state, {}, set()), [])


SNAP = "agents/main/agent/openclaw-agent.sqlite.auth-profile-migration-0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c.bak"
OLD_SNAP = "state/openclaw.sqlite.pre-exec-approvals-migration-11111111-2222-4333-8444-555555555555.bak"


class DoctorSnapshotTests(T.GateEnv):
    """full7: doctor's verified pre-repair snapshots (auth profile / ACP / exec approvals migrations, gateway token,
    2026.11.4 to 2026.11.10) are plaintext database copies: journaled, reported and deleted with their gate run."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, content=True)
        self.write_cfg(CB.CFG_GLM)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.11.4", 22, 27)
        self.hooks()

    def test_snapshot_of_a_run_is_journaled_and_deleted_an_older_one_is_named_as_kept(self):
        (self.state / OLD_SNAP).write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)  # before the gate: not its own
        self.assertEqual(G.doctor_copy_kind(Path(SNAP).name), "snapshot")
        self.assertIsNone(G.doctor_copy_kind("openclaw.sqlite.auth-profile-migration-x.bak"))
        self.doctor_script(state_uv=22, agent_uv=27, app_version="2026.11.4", drop_tables=["cron_run_logs"],
                           remove=["identity/device.json"], write={SNAP: "SQLite format 3 synthetic"})
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        snaps = [e for d in j["doctor"] for e in d.get("pre_migration_backups") or [] if e["scope"] == "snapshot"]
        self.assertEqual([e["path"] for e in snaps], [SNAP])
        self.assertIn("1 pre-repair SQLite snapshot (auth profile, ACP, exec approvals or gateway token migration) by "
                      "doctor", self.out)
        paths, _kept = G.run_doctor_copies(G.gpaths(), j)
        real = Path(os.path.realpath(str(self.state)))
        self.assertEqual(paths, [real / SNAP])
        st = "\n".join(G.status_lines())
        self.assertIn("Doctor pre-repair SQLite snapshots (*.auth-profile-migration-*.bak, *.pre-acp-*-migration-*.bak, "
                      "*.pre-exec-approvals-migration-*.bak, *.doctor-gateway-token.*.bak): 2 (", st)
        self.assertIn(f"Doctor pre-repair SQLite snapshots no gate run names: 1: {self.state / OLD_SNAP}: kept", st)


class CredentialArchiveTests(StateTmp):
    def test_migrated_credential_files_are_listed(self):
        cred = self.state / "credentials"
        (cred / "auth-profiles").mkdir(parents=True)
        for n in ("oauth.json.migrated", "oauth.json.migrated.2", "telegram-x-allowFrom.json.migrated.ab12.c3",
                  "auth-profiles/" + "0" * 32 + ".json.migrated", "oauth.json", "notes.txt"):
            (cred / n).write_text("synthetic")
        os.symlink("/etc/hostname", cred / "link.json.migrated")
        # the auth migration owner's names (2026.11.8 doctor-auth-migration-receipts.ts) and its prior-import backups
        stamp = "2026-11-25T02-48-33.123Z-0f1e2d3c-4b5a-4968-8776-655443322110"
        for n in (f"oauth.json.migrated-{stamp}", f"auth-profiles/{'0' * 32}.json.migrated-{stamp}",
                  "oauth.json.sqlite-import.1764000000000.bak"):
            (cred / n).write_text("synthetic")
        agent = self.state / "agents" / "main" / "agent"
        agent.mkdir(parents=True)
        for n in (f"auth-profiles.json.migrated-{stamp}", "auth.json.migrated", f"MEMORY.md.migrated-{stamp}"):
            (agent / n).write_text("synthetic")
        got = G.credential_archives(self.state)
        self.assertEqual(sorted(got), sorted(["credentials/" + n for n in (
            "oauth.json.migrated", "oauth.json.migrated.2", "telegram-x-allowFrom.json.migrated.ab12.c3",
            "auth-profiles/" + "0" * 32 + ".json.migrated", f"oauth.json.migrated-{stamp}",
            f"auth-profiles/{'0' * 32}.json.migrated-{stamp}", "oauth.json.sqlite-import.1764000000000.bak")]
            + [f"agents/main/agent/auth-profiles.json.migrated-{stamp}", "agents/main/agent/auth.json.migrated"]))


class SnapshotScopeTests(StateTmp):
    def test_outside_snapshots_are_found_and_cron_backups_are_not(self):
        d = self.tmp / "outside-agent"
        d.mkdir()
        snap = d / "openclaw-agent.sqlite.auth-profile-migration-0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c.bak"
        snap.write_bytes(b"x" * 10)
        (d / "openclaw.sqlite.doctor-cron-1764000000000-0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c.bak").write_bytes(b"y")
        (d / "openclaw-agent.sqlite.pre-startup-migration-abc.bak").write_bytes(b"z" * 3)
        got = G.outside_doctor_copies([d])
        self.assertEqual(got, {str(snap): (10, "snapshot"),
                               str(d / "openclaw-agent.sqlite.pre-startup-migration-abc.bak"): (3, "full")})

    def test_an_older_snapshot_is_not_claimed_by_a_run_whose_baseline_lacks_the_scope(self):
        from types import SimpleNamespace
        from datetime import datetime, timedelta, timezone
        agent = self.state / "agents" / "main" / "agent"
        agent.mkdir(parents=True)
        old = agent / "openclaw-agent.sqlite.auth-profile-migration-11111111-2222-4333-8444-555555555555.bak"
        new = agent / "openclaw-agent.sqlite.pre-acp-key-migration-0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c.bak"
        old.write_bytes(b"old")
        new.write_bytes(b"new")
        t_old = (datetime.now(timezone.utc) - timedelta(days=30)).timestamp()
        os.utime(old, (t_old, t_old))
        start = C.utc_iso(datetime.now(timezone.utc) - timedelta(hours=1))
        j = {"run_id": "20261125T000000Z-abcdef", "started_at": start, "doctor_copies_before": [],
             "doctor": [{"pass": 1}]}
        gp = {"STATE": self.state}
        gate = SimpleNamespace(j=j, gp=gp, cfg={}, save=lambda: None, warn=lambda m: None)
        G.Gate.record_doctor_copies(gate, 1)
        self.assertEqual([e["path"] for e in j["doctor"][0]["pre_migration_backups"]], [C.rel(new, self.state)])


def fix_now_text(*findings, before=()):
    """A 2026.11.8/2026.11.10 doctor run ending in "Doctor blocked" after its "Fix now:" summary
    (doctor-health-contribution.ts)."""
    L = ["┌  OpenClaw doctor", *before, "Fix now:"]
    for msg, path, hint in findings:
        L.append(f"- {msg}")
        if path:
            L.append(f"  Location: {path}")
        if hint:
            L.append(f"  Next step: {hint}")
        L.append("  Docs: https://docs.openclaw.ai/cli/doctor/running#understanding-findings")
    return "\n".join(L + ["└  Doctor blocked; required repairs remain incomplete."]) + "\n"


class DoctorOutput118Tests(unittest.TestCase):
    def test_fix_now_findings_in_the_blocked_reason(self):
        text = fix_now_text(
            ('Kept invalid agents.defaults.heartbeat.activeHours.start: invalid time - use HH:MM. Heartbeat migration '
             'is deferred; fix the value, then rerun', "agents.defaults.heartbeat.activeHours.start",
             "Fix the value, then rerun openclaw doctor --fix."),
            ("Required migration plugin-state-migration was deferred.", None, "Resolve the reported blocker."),
            ("token 123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA is invalid", "channels.telegram.botToken:3", None))
        ev = G.evaluate_doctor(1, text)
        self.assertEqual((ev["code"], ev["cls"]), ("doctor-blocked", "hard"))
        msg = ev["message"]
        self.assertTrue(msg.startswith("doctor rc 1: doctor blocked, required repairs remain incomplete: "
                                       "agents.defaults.heartbeat.activeHours.start: Kept invalid agents.defaults."
                                       "heartbeat.activeHours.start: invalid time - use HH:MM. Heartbeat migration is "
                                       "deferred; fix the value, then rerun; Required migration plugin-state-migration "
                                       "was deferred.; channels.telegram.botToken:"), msg)
        # path and message are redacted apart (a path ending in a key name reads as "key: value" to the redaction)
        self.assertTrue(msg.endswith(": token *** is invalid"), msg)
        self.assertNotIn("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", msg)
        self.assertNotIn("Next step", msg)
        self.assertNotIn("Docs:", msg)
        self.assertIn('"Next step:"', G.ADVICE["doctor-blocked"])

    def test_exit_2_split(self):
        cfg = "◇ unknown: config could not be parsed; fix config (or run `openclaw doctor --fix`), then rerun"
        db = "◇ unknown: database target could not be resolved; fix database settings or credentials, then rerun"
        self.assertEqual(G.evaluate_doctor(2, cfg)["code"], "doctor-config-unparsed")
        self.assertEqual(G.evaluate_doctor(2, db)["code"], "doctor-database-unresolved")
        self.assertEqual(G.evaluate_doctor(2, "error: unknown option '--bogus'")["code"], "doctor-invocation")
        for code in ("doctor-config-unparsed", "doctor-database-unresolved"):
            self.assertIn(code, G.ADVICE)
            self.assertNotIn(code, G.ACCEPTABLE)

    def test_startup_timeout_and_unverifiable_original_copy(self):
        t = ("Error: Doctor startup timed out after 60000ms (state admission). Retry with OPENCLAW_DEBUG=1 openclaw "
             "doctor --lint; if it still stalls, capture a Node diagnostic report before retrying repairs.")
        self.assertEqual(G.evaluate_doctor(1, t)["code"], "doctor-incomplete")
        t = ("Doctor could not verify its admitted original recovery copy: hash mismatch. State repair has not "
             "started.")
        self.assertEqual(G.evaluate_doctor(1, t)["code"], "doctor-backup-unverifiable")

    def test_skill_workshop_drafts_moved_note(self):
        text = ("│  Moved 3 exported Skill Workshop proposal drafts from /x/.archive/.retired-proposals to "
                "/x/.drafts; review them with /learn drafts. │\n└  Doctor complete.\n")
        self.assertIn(["info", "doctor moved 3 earlier exported Skill Workshop draft(s) to the owner agent's "
                               "workshop-skills/.drafts/ (/learn drafts lists them)"], G.doctor_notes(text))

    def test_long_multi_line_fix_now_finding_is_kept(self):
        long = "Required migration heartbeat-retirement was deferred:\n" + "\n".join(
            f"agents.list[{i}].heartbeat: kept /config/.openclaw/agents/a{i}/agent/workspace/HEARTBEAT.md for review"
            for i in range(9))
        self.assertGreater(len(long), 600)
        ev = G.evaluate_doctor(1, fix_now_text((long, None, "Resolve it, then rerun.")))
        self.assertEqual(ev["code"], "doctor-blocked")
        self.assertIn("doctor blocked, required repairs remain incomplete: Required migration heartbeat-retirement",
                      ev["message"])

    def test_reused_capture_line_is_not_claimed(self):
        line = ("Unchanged original recovery copy verified and retained before repair. For manual recovery: "
                "/config/.openclaw.update-captures/doctor-0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c/manifest.json.")
        self.assertIsNone(G.CAPTURE_RE.search(line))
        self.assertIsNotNone(G.CAPTURE_RE.search(line.replace(
            "Unchanged original recovery copy verified and retained before repair.",
            "Recovery copy saved before repair. No action needed.")))

    def test_failing_check_is_named_in_the_reason(self):
        text = ("Failing check plugin-doctor-state (step-refused): Refused plugin migrations that do not match the "
                "immutable action order and authority declared by acpx.\nFailing check sessions "
                "(blocked-by-prior-refusal): Migration step \"sessions\" was not run.\nDoctor stopped because a state "
                "migration refused to continue.\n")
        ev = G.evaluate_doctor(1, text)
        self.assertEqual(ev["code"], "doctor-migration-refused")
        self.assertIn("; failing check plugin-doctor-state (step-refused): Refused plugin migrations that do not "
                      "match the immutable action order and authority declared by acpx.", ev["message"])
        self.assertNotIn("blocked-by-prior-refusal", ev["message"])
        self.assertEqual(G.failing_check_text("nothing here"), "")

    def test_scheduled_run_access_review_and_sender_policy_notes(self):
        text = "\n".join([
            "◇  Cron ────────╮",
            "│  2 tool-bearing cron jobs keep legacy sender-policy resolution because  │",
            "│  an explicit tool cap or provable stored account identity is missing:   │",
            "│  Scheduled-run access review (read-only; nothing was changed).           │",
            "│  2 automations will lose access at the next run:                         │",
            "│  - heartbeat-main (x): sessions_yield (scheduled runs cannot wait)       │",
            "│  1 automation will pause at the next run because the conversation that created it is unavailable: │",
            "│  1 automation runs on a CLI backend, where scheduled runs now get the owner-only tools embedded runs │",
            "│  3 automations are not bound to the conversation that created them:      │",
            "│  1 automation has a creating conversation with no stored chat type, so its runs get no memory: │",
            "│  1 automation could not be evaluated:                                    │",
            "└  Doctor complete."])
        notes = G.doctor_notes(text)
        levels = {m.split(" ", 3)[0] + " " + m.split(" ", 3)[1]: lvl for lvl, m in notes}
        self.assertEqual(len(notes), 7, notes)
        self.assertIn(["warn", "2 automation(s) will lose access at their next run (doctor's \"Scheduled-run access "
                               "review\" in oc-upgrade log names each and what it loses, e.g. owner-only tools or "
                               "sessions_yield)"], notes)
        self.assertTrue(any(lvl == "warn" and m.startswith("1 automation(s) will pause at their next run") for lvl, m in notes))
        self.assertTrue(any(lvl == "info" and m.startswith("2 cron job(s) with tools keep the restrictive legacy sender")
                            for lvl, m in notes))
        self.assertTrue(levels)

    def test_unavailable_recovery_copy_is_a_note_not_a_hold(self):
        text = ("┌  OpenClaw doctor\nFix now:\n- Pre-repair recovery copy was unavailable: ENOSPC: no space left on "
                "device.\n  Docs: https://docs.openclaw.ai/x\n└  Doctor complete.\n")
        ev = G.evaluate_doctor(0, text, final=True)
        self.assertIsNone(ev["code"])
        self.assertIn(["warn", "doctor could not save its pre-repair recovery copy (ENOSPC: no space left on device); "
                               "the encrypted Home Assistant backup stays the rollback point"], G.doctor_notes(text))


if __name__ == "__main__":
    unittest.main()
