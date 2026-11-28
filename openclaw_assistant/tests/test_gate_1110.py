"""OpenClaw 2026.11.10 (its own release line, branched from main on 2026-11-16; 0.5.94-full7 bundles it, schemas 40/42).

- The gateway start upgrades the state by copy and swap (runtime_caps startup_state_upgrade; state-upgrade.ts):
  startup_upgrade_pending mirrors what it would upgrade. The precheck holds on a `.upgrade-*` folder with plan.json
  and deletes one without; the postconditions hold on what is still pending (pc-startup-upgrade); the plan holds
  (startup-upgrade-pending) instead of starting OpenClaw; hold_after_start names it; oc-upgrade status lists the
  leftovers (.upgrade-*, *.pre-<version>, logs/state-upgrade-*.log) and the cleanup deletes them after
  gate_cleanup_hours once the gateway has run on the upgraded state (design decision D2).
- doctor's settled-exit watchdog (runtime_caps doctor_exit_watchdog): rc -15 after a finished pass; the gate reads the
  exit code from doctor's outro (settled_rc).
- The doctor copies 2026.11.10 makes: the cron backup as a .pre-startup-migration copy (SAVED_COPY_ID_RE), the
  cold-navigation recovery directories (cold storage is on by default), the gateway-token snapshot; doctor notes.
- Hygiene: doctor's cron inference-account findings (profile ids) stay out of HOLD reasons.
Synthetic fixtures only (10.4-layout databases from test_gate at the 2026.11.10 schema versions).
"""

import json
import os
import shutil
import sqlite3
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
for _p in (str(ADDON), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_common as C  # noqa: E402
import oc_gate as G  # noqa: E402
import test_gate as T  # noqa: E402

RT = "2026.11.10"
S, A = 40, 42
AGENT = "agents/{}/agent/openclaw-agent.sqlite"
WORK = ".upgrade-2026.11.10-4242-1764000000000"
CFG = {"meta": {"lastTouchedVersion": "2026.11.4"},
       "agents": {"defaults": {"model": {"primary": "vllm/qwen3.5-122b"}}, "list": [{"id": "main", "default": True}]},
       "models": {"providers": {"vllm": {"baseUrl": "http://127.0.0.1:8000/v1", "apiKey": "sk-local-synthetic",
                                         "auth": "api-key", "models": [{"id": "qwen3.5-122b"}]}}},
       "gateway": {"mode": "local", "auth": {"token": "SECRET-GATEWAY-TOKEN"}}}
MARKER = "command settled but the process is still alive after 10000ms; active resources: TCPWrap; terminating"


def sql(db, *statements, params=()):
    con = sqlite3.connect(str(db))
    for st in statements:
        con.execute(st, params)
    con.commit()
    con.close()


def journal_row(state, aid, done, delete_files, agent_dir=None, paths="[]"):
    sql(state / "state" / "openclaw.sqlite",
        "INSERT INTO agent_deletion_journal (agent_id, agent_dir, workspace_dir, sessions_dir, database_paths_json, "
        "created_at, cleanup_completed, delete_files) VALUES (?, ?, '/w', '/s', ?, 0, ?, ?)",
        params=(aid, agent_dir if agent_dir is not None else str(state / "agents" / aid / "agent"), paths, done,
                delete_files))


def recovery_hold(state, aid, rel):
    """doctor's receipt of a reconstructed deletion journal (migration_sources, agent-deletion-journal-recovery)."""
    sql(state / "state" / "openclaw.sqlite",
        "INSERT INTO migration_sources (source_key, migration_kind, source_path, target_table, last_run_id, status, "
        "imported_at, report_json) VALUES ('agent-deletion-journal-reconstruction', 'k', 'p', 't', 'r', 'done', 0, ?)",
        params=(json.dumps({"description": "Reconstructed", "held": [{"agentId": aid, "path": rel}]}),))


def register(state, aid, uv):
    sql(state / "state" / "openclaw.sqlite", "INSERT INTO agent_databases VALUES (?, ?, ?, 0, NULL)",
        params=(aid, AGENT.format(aid), uv))


def to_1104(state):
    """The state as OpenClaw 2026.11.4 left it (schemas 22/27), the source of the bump."""
    sql(state / "state" / "openclaw.sqlite", "PRAGMA user_version=22",
        "UPDATE schema_meta SET schema_version=22, app_version='2026.11.4' WHERE meta_key='primary'")
    sql(state / AGENT.format("main"), "PRAGMA user_version=27",
        "UPDATE schema_meta SET schema_version=27, app_version='2026.11.4' WHERE meta_key='primary'")


class Env1110(T.GateEnv):
    """A 2026.10.4-layout state at the 2026.11.10 schemas (40/42) and a 2026.11.10 runtime package."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, s=S, a=A, app=RT)
        self.write_cfg(dict(CFG, meta={"lastTouchedVersion": RT}))
        self.set_runtime(RT, S, A)
        self.sdb = self.state / "state" / "openclaw.sqlite"

    def pend(self, cfg=None):
        return G.startup_upgrade_pending(self.state, S, A, CFG if cfg is None else cfg)

    def paths_of(self, res):
        return [o["path"] for o in res["outdated"]]


class StartupPendingTests(Env1110):
    def test_a_current_state_has_nothing_pending(self):
        self.assertEqual(self.pend(), {"work_dirs": [], "outdated": []})

    def test_state_database_by_user_version_and_content_version(self):
        sql(self.sdb, "PRAGMA user_version=22")
        self.assertEqual(self.pend()["outdated"], [{"path": "state/openclaw.sqlite", "kind": "state", "id": None,
                                                    "uv": 22, "role": "state"}])
        sql(self.sdb, "INSERT INTO config_machine_state VALUES ('state.schema.contentVersion', '40', 0)")
        self.assertEqual(self.pend()["outdated"], [])  # max(user_version, contentVersion), as state-upgrade.ts

    def test_state_at_version_0_turns_the_upgrade_off_but_a_work_dir_still_counts(self):
        T.make_1004_agent_db(self.state, "old", uv=27)
        sql(self.sdb, "PRAGMA user_version=0")
        self.assertEqual(self.pend(), {"work_dirs": [], "outdated": []})
        (self.state / WORK).mkdir()
        self.assertEqual(self.pend(), {"work_dirs": [{"name": WORK, "plan": False}], "outdated": []})

    def test_orphan_configured_and_registered_stores_below_the_target(self):
        T.make_1004_agent_db(self.state, "old", uv=27)
        T.make_1004_agent_db(self.state, "reg", uv=27)
        register(self.state, "reg", 27)
        sql(self.state / AGENT.format("main"), "PRAGMA user_version=27")
        T.make_1004_agent_db(self.state, "fresh", uv=0)  # version 0 is never upgraded
        got = {o["path"]: (o["role"], o["uv"]) for o in self.pend()["outdated"]}
        self.assertEqual(got, {AGENT.format("main"): ("configured", 27), AGENT.format("old"): ("orphan", 27),
                               AGENT.format("reg"): ("registered", 27)})
        text = G.startup_upgrade_text(self.pend(), RT, S, A)
        self.assertIn(f"{AGENT.format('old')} (agent old, neither configured nor registered; schema 27 < 42)", text)
        self.assertIn(f"{AGENT.format('main')} (agent main, configured; schema 27 < 42)", text)
        self.assertIn("would upgrade the state by copy and swap (a full plaintext copy in .upgrade-*, then the replaced "
                      "files kept as *.pre-2026.11.10)", text)

    def test_what_the_deletion_journal_or_its_reconstruction_holds_is_left_alone(self):
        for aid in ("gone", "going", "moved", "held1", "tomb"):
            T.make_1004_agent_db(self.state, aid, uv=27)
        journal_row(self.state, "gone", 1, 0)  # retained
        journal_row(self.state, "going", 0, 1)  # pending
        # named by its database paths only (the agent dir was elsewhere)
        journal_row(self.state, "x", 1, 0, agent_dir="/srv/synthetic/elsewhere",
                    paths=json.dumps([AGENT.format("moved")]))
        recovery_hold(self.state, "held1", AGENT.format("held1"))  # "deletion journal reconstructed"
        journal_row(self.state, "tomb", 1, 1)  # a status-only tombstone holds nothing
        self.assertEqual(self.paths_of(self.pend()), [AGENT.format("tomb")])

    def test_an_agent_id_alone_does_not_hold_a_store(self):
        # startup asks the deletion classifier with the path only (state-upgrade.ts discoverDatabases)
        T.make_1004_agent_db(self.state, "old", uv=27)
        journal_row(self.state, "old", 1, 0, agent_dir="/srv/synthetic/elsewhere/old/agent")
        self.assertEqual(self.paths_of(self.pend()), [AGENT.format("old")])

    def test_a_surviving_owner_of_another_agent_keeps_a_journal_named_store_a_target(self):
        sql(self.state / AGENT.format("main"), "PRAGMA user_version=27")
        journal_row(self.state, "gone", 1, 0, agent_dir="/srv/synthetic/gone",
                    paths=json.dumps([AGENT.format("main")]))
        self.assertEqual(self.paths_of(self.pend()), [AGENT.format("main")])

    def test_without_a_readable_shared_history_every_store_counts(self):
        T.make_1004_agent_db(self.state, "gone", uv=27)
        journal_row(self.state, "gone", 1, 0)
        self.assertEqual(self.paths_of(self.pend()), [])
        self.sdb.unlink()  # no shared database: the deletion history is unavailable
        self.assertEqual(self.paths_of(self.pend()), [AGENT.format("gone")])

    def test_databases_below_a_symlinked_directory_are_no_targets(self):
        real = self.tmp / "elsewhere"
        T.make_1004_agent_db(real, "linked", uv=27)
        os.symlink(real / "agents" / "linked", self.state / "agents" / "linked")
        self.assertEqual(self.paths_of(self.pend()), [])
        # a symlinked state/ is no target either, but its history still classifies the agent stores
        sql(self.sdb, "PRAGMA user_version=22")
        (self.state / "state").rename(self.tmp / "state-real")
        os.symlink(self.tmp / "state-real", self.state / "state")
        T.make_1004_agent_db(self.state, "gone", uv=27)
        journal_row(self.state, "gone", 1, 0)
        self.assertEqual(self.pend(), {"work_dirs": [], "outdated": []})

    def test_work_dirs_with_and_without_a_swap_plan(self):
        (self.state / WORK).mkdir()
        planned = self.state / ".upgrade-2026.11.10-77-1764000000001"
        planned.mkdir()
        (planned / "plan.json").write_text('{"appVersion": "2026.11.10", "ops": []}')
        self.assertEqual(self.pend()["work_dirs"], [{"name": WORK, "plan": False},
                                                    {"name": planned.name, "plan": True}])

    def test_recovery_holds_and_a_broken_receipt(self):
        self.assertEqual(G.deletion_recovery_holds(self.state), {})
        recovery_hold(self.state, "held1", AGENT.format("held1"))
        self.assertEqual(G.deletion_recovery_holds(self.state),
                         {os.path.realpath(self.state / AGENT.format("held1")): "held1"})
        sql(self.sdb, "UPDATE migration_sources SET report_json='not json'")
        self.assertEqual(G.deletion_recovery_holds(self.state), {})


class StartupGateRunTests(Env1110):
    """A bump from a 2026.11.4 state (22/27) by the 2026.11.10 gate."""

    def setUp(self):
        super().setUp()
        to_1104(self.state)
        self.write_cfg(CFG)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.11.4", "mode": "bump"}))
        self.hooks()

    def test_a_work_dir_with_a_swap_plan_holds_before_doctor(self):
        planned = self.state / WORK
        planned.mkdir()
        (planned / "plan.json").write_text("{}")
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["hold"]["phase"], j["hold"]["acceptable"]),
                         ("startup-upgrade-unfinished", "precheck", False))
        self.assertFalse(j.get("doctor_started"))
        self.assertTrue((planned / "plan.json").exists())
        hold = (self.upg / "hold.txt").read_text()
        self.assertIn("Do not delete it", hold)
        self.assertIn("OC_ADDON_UNSAFE=1 openclaw gateway run", hold)

    def test_a_work_dir_without_a_plan_is_deleted_and_recorded(self):
        (self.state / WORK / "state").mkdir(parents=True)
        (self.state / WORK / "state" / "openclaw.sqlite").write_bytes(b"SQLite format 3\x00" + b"\x00" * 200)
        staged = ".openclaw.json" + WORK  # what the same attempt staged beside the live config before its plan
        (self.state / staged).write_text("synthetic staged config copy")
        other = ".openclaw.json.upgrade-2026.11.10-3999999-1764000000009"  # another attempt's: left to the cleanup
        (self.state / other).write_text("synthetic")
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        self.assertTrue((self.state / WORK).exists())  # the preview never deletes
        self.assertTrue(any("without a swap plan" in x and "a gate run deletes it" in x for x in lines), lines)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertFalse(os.path.lexists(self.state / WORK))
        self.assertFalse([n for n in os.listdir(self.state) if n.startswith(G.TOMB_PREFIX)])
        self.assertEqual([r["name"] for r in self.journal()["startup_upgrade_removed"]], [WORK, staged])
        self.assertFalse(os.path.lexists(self.state / staged))
        self.assertTrue((self.state / other).exists())
        self.assertIn(f"1/8 deleted {WORK} in {self.state}: an unfinished state-upgrade copy", self.out)
        self.assertIn(f"1/8 deleted {staged} in {self.state}: the staged copy of the same attempt", self.out)
        self.assertIn("no gateway-start upgrade pending", self.out)

    def test_an_orphan_doctor_leaves_below_the_target_holds_in_the_postconditions(self):
        T.make_1004_agent_db(self.state, "old", uv=27)
        self.hooks(accept=["orphan-agent-db"])
        self.doctor_script(state_uv=S, agent_uv=A, app_version=RT, drop_tables=["cron_run_logs"],
                           remove=["identity/device.json"], skip_agents=["old"])
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertIn("The gateway opens it read-only at each start; if it is still below the target, every start "
                      "copies the state to upgrade it", self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["hold"]["phase"], j["hold"]["acceptable"]),
                         ("pc-startup-upgrade", "postconditions", False))
        self.assertIn(f"{AGENT.format('old')} (agent old, neither configured nor registered; schema 27 < 42)",
                      j["hold"]["message"])
        self.assertNotIn("pc-startup-upgrade", G.ACCEPTABLE)

    def test_a_store_the_deletion_journal_keeps_is_information_only(self):
        T.make_1004_agent_db(self.state, "gone", uv=27)
        register(self.state, "gone", 27)
        journal_row(self.state, "gone", 1, 0)
        self.doctor_script(state_uv=S, agent_uv=A, app_version=RT, drop_tables=["cron_run_logs"],
                           remove=["identity/device.json"], skip_agents=["gone"])
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn(f"7/8 info: held agent database(s) left at their schema, not checked: {AGENT.format('gone')} "
                      "(agent gone, schema 27: kept from a deleted agent (deletion journal)); the gateway does not "
                      "open them, and its start does not upgrade them", self.out)

    def test_a_store_doctor_holds_for_unavailable_history_holds(self):
        # doctor holds a store whose deletion history it cannot verify, but the gateway start upgrades it
        T.make_1004_agent_db(self.state, "lost", uv=27)
        register(self.state, "lost", 27)
        self.doctor_script(state_uv=S, agent_uv=A, app_version=RT, drop_tables=["cron_run_logs"],
                           remove=["identity/device.json"], skip_agents=["lost"], print=[
                               f"Held agent lost database {self.state / AGENT.format('lost')}; deletion history "
                               "needs repair."])
        self.hooks(accept=["doctor-held-back"])
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual(j["hold"]["code"], "pc-startup-upgrade")
        self.assertIn(f"{AGENT.format('lost')} (agent lost, registered, not configured; schema 27 < 42; held back by "
                      "doctor: deletion history needs repair)", j["hold"]["message"])

    def test_an_earlier_runtime_has_none_of_it(self):
        self.set_runtime("2026.11.8", 36, 38)
        (self.state / WORK).mkdir()
        (self.state / WORK / "plan.json").write_text("{}")
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertTrue((self.state / WORK / "plan.json").exists())
        self.assertNotIn("startup", json.dumps(self.journal().get("hold") or {}))


class StartupPlanTests(Env1110):
    def mark(self, runtime=RT):
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": runtime, "mode": "bump",
                                                                     "run_id": "r1"}))

    def test_migrated_state_with_an_outdated_orphan_holds_instead_of_starting(self):
        self.mark()
        self.assertEqual(self.plan()["rc"], 0, self.out)
        T.make_1004_agent_db(self.state, "old", uv=27)  # e.g. a folder restored from an older backup
        d = self.plan()
        self.assertEqual((d["rc"], d["hold"]["code"]), (11, "startup-upgrade-pending"), self.out)
        self.assertIn("-> HOLD startup-upgrade-pending", self.out)
        hold = (self.upg / "hold.txt").read_text()
        self.assertIn(f"{AGENT.format('old')} (agent old, neither configured nor registered; schema 27 < 42)", hold)
        self.assertIn("move it out of /config/.openclaw/agents", hold)
        self.assertIn("oc-upgrade retry --doctor", hold)
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 20)
        self.assertTrue(any("would HOLD startup-upgrade-pending" in x for x in lines), lines)
        # a plain retry changes nothing; retry --doctor runs a maintenance gate (its doctor migrates in place)
        self.assertEqual(G.retry_cmd([], emit=lambda s: None), 0)
        self.assertEqual(self.plan()["rc"], 11)
        self.assertEqual(G.retry_cmd(["--doctor"], emit=lambda s: None), 0)
        d = self.plan()
        self.assertEqual((d["rc"], d["action"], d["mode"]), (10, "run", "maintenance"), self.out)
        (self.upg / "gate" / "retry-request.json").unlink()
        sql(self.state / AGENT.format("old"), "PRAGMA user_version=42")
        self.assertEqual(self.plan()["rc"], 0, self.out)

    def test_a_work_dir_without_a_plan_alone_does_not_hold(self):
        # the gateway start only removes it (state-upgrade.ts) and copies nothing
        self.mark()
        (self.state / WORK).mkdir()
        self.assertEqual(self.plan()["rc"], 0, self.out)

    def test_no_adoption_while_a_swap_plan_waits(self):
        planned = self.state / WORK
        planned.mkdir()
        (planned / "plan.json").write_text("{}")
        d = self.plan(apply=True)
        self.assertEqual((d["rc"], d["hold"]["code"]), (11, "startup-upgrade-unfinished"), self.out)
        self.assertFalse((self.upg / "gate" / "migrated.json").exists())  # not adopted
        planned.joinpath("plan.json").unlink()
        planned.rmdir()
        self.assertEqual(self.plan(apply=True)["marker"], "adopt")

    def test_a_gate_run_ahead_is_not_held_and_earlier_runtimes_never_hold(self):
        T.make_1004_agent_db(self.state, "old", uv=27)
        self.mark("2026.11.4")
        self.assertEqual(self.plan()["rc"], 10, self.out)  # the gate's doctor migrates first
        self.set_runtime("2026.11.8", S, A)
        self.mark("2026.11.8")
        self.write_cfg(dict(CFG, meta={"lastTouchedVersion": "2026.11.8"}))
        self.assertEqual(self.plan()["rc"], 0, self.out)

    def test_a_failing_check_holds(self):
        self.mark()
        with mock.patch.object(G, "startup_upgrade_pending", side_effect=RuntimeError("synthetic")):
            d = self.plan()
        self.assertEqual((d["rc"], d["hold"]["code"]), (11, "startup-upgrade-pending"))
        self.assertIn("could not check what the gateway start of OpenClaw 2026.11.10 would upgrade (RuntimeError: "
                      "synthetic)", d["hold"]["message"])


class HoldAfterStartTests(Env1110):
    def test_exit78_names_the_work_dir_and_the_gateway_lines(self):
        (self.state / WORK).mkdir()
        self.assertEqual(self.quiet(G.hold_after_start, "exit78", 78), 0)
        hold = (self.upg / "hold.txt").read_text()
        self.assertIn(f"{WORK} (an unfinished copy of the state without a swap plan)", hold)
        self.assertIn('"State upgrade to <version> stopped: ..."', hold)
        self.assertIn('"State upgrade to <version> not applied: ..."', hold)
        self.assertIn("oc-upgrade retry --doctor", hold)
        (self.state / WORK / "plan.json").write_text("{}")
        self.quiet(G.hold_after_start, "crash-loop", 1)
        self.assertIn("OC_ADDON_UNSAFE=1 openclaw gateway run", (self.upg / "hold.txt").read_text())

    def test_nothing_pending_keeps_the_old_text(self):
        self.quiet(G.hold_after_start, "exit78", 78)
        self.assertNotIn("copy and swap", (self.upg / "hold.txt").read_text())


class SettledExitTests(unittest.TestCase):
    def ev(self, rc, text, on=True):
        return G.evaluate_doctor(rc, text, settled_exit=on)

    def test_the_outro_gives_the_exit_code(self):
        ok = f"│  {MARKER} │\n└  Doctor complete.\n"
        ev = self.ev(-15, ok)
        self.assertEqual((ev["code"], ev["rc"], ev["settled_from"]), (None, 0, -15))
        ev = self.ev(-15, f"{MARKER}\n└  Doctor blocked; required repairs remain incomplete.\n")
        self.assertEqual((ev["code"], ev["rc"]), ("doctor-blocked", 1))
        ev = self.ev(-15, f"{MARKER}\n└  Doctor finished with plugin load errors.\n")
        self.assertEqual(ev["code"], "doctor-plugin-load")
        ev = self.ev(-15, f"{MARKER}\n└  Doctor finished, but config fixes were not applied.\n")
        self.assertEqual(ev["code"], "doctor-config-write")
        ev = self.ev(-15, "◇ unknown: config could not be parsed; fix config (or run `openclaw doctor --fix`), then "
                          f"rerun\n{MARKER}\n└  Doctor blocked. Database checks remain unknown; no state migrations "
                          "were performed.\n")
        self.assertEqual((ev["code"], ev["rc"]), ("doctor-config-unparsed", 2))
        ev = self.ev(143, "◇ unknown: database target could not be resolved; fix database settings\n"
                          f"{MARKER}\n└  Doctor finished, but some config fixes were not applied.\n")
        self.assertEqual((ev["code"], ev["rc"]), ("doctor-database-unresolved", 2))

    def test_without_the_outro_or_the_marker_it_stays_a_crash(self):
        ev = self.ev(-15, f"{MARKER}\n")
        self.assertEqual((ev["code"], ev["rc"]), ("doctor-crashed", -15))
        self.assertIn("settled-exit watchdog", ev["message"])
        ev = self.ev(-15, "└  Doctor complete.\n")
        self.assertEqual(ev["code"], "doctor-crashed")
        self.assertIn("killed by signal 15", ev["message"])
        self.assertEqual(self.ev(-15, f"{MARKER}\n└  Doctor complete.\n", on=False)["code"], "doctor-crashed")
        self.assertEqual(G.settled_rc(-9, f"{MARKER} Doctor complete."), -9)
        self.assertEqual(G.settled_rc(0, f"{MARKER} Doctor complete."), 0)



class PluginSourceUnpreparedTests(unittest.TestCase):
    """2026.11.10 doctor: the config repair after the plugin refresh loads the refreshed codex configRepair contract
    outside the plan's deferral scope and throws (openclaw/openclaw#205695; rehearsal 1110 gate 1). The add-on's dist
    patch doctor-restore-env-refs-deferral fixes it; should it still happen, the hold has its own code and advice."""

    # the closing lines of the rehearsal's pass 1 (synthetic, the ids and times are not the rehearsal's)
    TAIL = ("[state-migrations] Plugin \"codex\" data/settings upgrade is unfinished: The configured plugin package is "
            "missing or has not converged. Your existing data and settings have been kept. Run \"openclaw update "
            "repair\", then \"openclaw doctor --fix\" to retry the upgrade.\n"
            "Doctor: maintenance finish\n"
            "Doctor could not complete maintenance. Check the reported service state and resolve the failure.\n"
            "Doctor: maintenance release\n"
            "Plugin codex Doctor source must be prepared before loading\n")

    def test_its_own_hard_code_before_the_maintenance_refusal(self):
        ev = G.evaluate_doctor(1, self.TAIL)
        self.assertEqual((ev["code"], ev["cls"]), ("doctor-plugin-source-unprepared", "hard"))
        self.assertIn("Plugin codex Doctor source must be prepared before loading", ev["message"])
        self.assertEqual(G.evaluate_doctor(1, self.TAIL.rsplit("Plugin codex", 1)[0])["code"],
                         "doctor-maintenance-refused")
        # the final pass too (the "unfinished" line is suspicious there, the throw decides)
        self.assertEqual(G.evaluate_doctor(1, self.TAIL, final=True)["code"], "doctor-plugin-source-unprepared")

    def test_advice_is_the_retry_and_never_the_update_bypass(self):
        self.assertNotIn("doctor-plugin-source-unprepared", G.ACCEPTABLE)
        adv = G.ADVICE["doctor-plugin-source-unprepared"]
        self.assertTrue(adv.startswith("oc-upgrade retry"))
        self.assertIn("doctor-restore-env-refs-deferral", adv)
        self.assertIn("restore the encrypted Home Assistant backup", adv)
        self.assertNotIn("OC_ADDON_UNSAFE", adv)
        self.assertNotIn("--accept", adv)
        self.assertIn("Not openclaw update repair", adv)


class DistPatchShippedTests(unittest.TestCase):
    def test_the_image_patch_set_carries_the_doctor_fix(self):
        image = "2026.11.11"  # the bundled version (Dockerfile ARG OPENCLAW_VERSION), of the 2026.11.10 line
        self.assertIn(f"\nARG OPENCLAW_VERSION={image}\n", (ADDON / "Dockerfile").read_text())
        man = json.loads((ADDON / "oc-patches" / image / "manifest.json").read_text())
        names = {e["name"]: e for e in man["patches"]}
        e = names["doctor-restore-env-refs-deferral"]
        self.assertEqual(e["file"], "dist/automatic-config-repair-DirHmWYF.mjs")
        self.assertEqual(e["region"], "//!src/commands/doctor/shared/automatic-config-repair.ts")
        diff = (ADDON / "oc-patches" / image / e["diff"]).read_text()
        self.assertIn("+function canPlanAutomaticConfigRepair(", diff)
        self.assertEqual(diff.count("withPluginContracts(()=>restoreDoctorConfigEnvRefs(u,"
                                    "prepareDoctorConfigReferenceSource(e)))"), 1)


class SettledExitGateTests(Env1110):
    def setUp(self):
        super().setUp()
        to_1104(self.state)
        self.write_cfg(CFG)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.11.4", "mode": "bump"}))
        self.hooks()

    def step(self, **kw):
        base = dict(state_uv=S, agent_uv=A, app_version=RT, drop_tables=["cron_run_logs"],
                    remove=["identity/device.json"], signal=15, print=[MARKER])
        base.update(kw)
        self.doctor_script(**base)

    def test_no_flag_or_variable_turns_the_watchdog_off(self):
        # the gate's doctor command line and environment stay as they were; settled_rc is the only handling
        self.hooks(doctor_cmd=None)  # no doctor_cmd: the real command line
        g = G.Gate(emit=lambda s: None)
        g.pkg = dict(C.runtime_package(), node="node", entry="/x/openclaw.mjs")
        g.j = {"run_id": "r-argv", "mode": "bump", "doctor": [], "history": []}
        g.sizes = {"s_mib": 1}
        seen = {}

        def fake(argv, **kw):
            seen.update(argv=list(argv), env=kw.get("env"))
            Path(kw["log_path"]).write_text(f"{MARKER}\n└  Doctor complete.\n")
            return mock.Mock(rc=-15, timed_out=False, duration=1.0)
        with mock.patch.object(C, "run_process", side_effect=fake):
            ev = g.run_doctor_pass(1, "doctor1")
        self.assertEqual(seen["argv"], ["node", "/x/openclaw.mjs", "doctor", "--fix", "--non-interactive"])
        self.assertEqual(seen["env"], C.openclaw_env())
        self.assertEqual((ev["code"], ev["rc"]), (None, 0))

    def test_a_finished_pass_stopped_by_the_watchdog_passes(self):
        self.step()
        self.assertEqual(self.run_gate(), 0, self.out)
        d = self.journal()["doctor"][0]
        self.assertEqual((d["rc"], d["settled_rc"], d["code"]), (-15, 0, None))
        self.assertIn("stopped itself with SIGTERM 10 s later (rc -15, OpenClaw's settled-exit watchdog); its outro "
                      "says exit 0", self.out)
        self.assertIn("doctor pass 1: rc -15 (stopped by its settled-exit watchdog; outro: exit 0)",
                      "\n".join(G.status_lines()))

    def test_without_an_outro_it_holds_as_a_crash(self):
        self.step(box=False)
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertEqual(self.journal()["hold"]["code"], "doctor-crashed")

    def test_an_earlier_runtime_keeps_the_crash(self):
        self.set_runtime("2026.11.8", 36, 38)
        self.step(state_uv=36, agent_uv=38, app_version="2026.11.8")
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertIn("killed by signal 15", self.journal()["hold"]["message"])


class DoctorCopies1110Tests(unittest.TestCase):
    def test_cron_backup_as_a_pre_migration_copy(self):
        uid = "0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c"
        db = "/config/.openclaw/state/openclaw.sqlite"
        log = (f"│  Saved pre-repair cron backup: {db}.pre-startup-migration-{uid}.bak │\n"
               f"Cron Doctor repair failed; verified backup retained at {db}.pre-startup-migration-"
               "restart-recovery-11111111-2222-4333-8444-555555555555.bak: Error: synthetic\n")
        self.assertEqual(G.doctor_copy_groups(log),
                         {uid, "restart-recovery-11111111-2222-4333-8444-555555555555"})
        # a long path wrapped inside doctor's box still matches
        self.assertEqual(G.doctor_copy_groups(f"│  Saved pre-repair cron backup: {db}.pre-startup-migra │\n"
                                              f"│  tion-{uid}.bak │\n"), {uid})
        # a PostgreSQL / earlier cron backup is the R5 name; the scan never runs into a later line
        later = (f"Saved pre-repair cron backup: {db}.doctor-cron-1764000000000-{uid}.bak\n"
                 f"Doctor said: {db}.pre-startup-migration-22222222-2222-4333-8444-555555555555.bak\n")
        self.assertEqual(G.doctor_copy_groups(later), set())
        self.assertEqual(G.doctor_cron_copy_ids(later), {f"1764000000000-{uid}"})

    def test_dreaming_cron_repair_backup_lines(self):
        # memory-core doctor-dreaming-cron.ts:195-196 takes the cron store's pre-repair backup, a pre-migration copy
        # on 2026.11.10 SQLite, and names it as "... SQLite backup: <path>."
        uid = "0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c"
        db = "/config/.openclaw/state/openclaw.sqlite"
        for line in (f"Repaired 2 historical dreaming cron row(s); the active job is preserved. SQLite backup: "
                     f"{db}.pre-startup-migration-{uid}.bak.",
                     f"Retired 1 managed dreaming cron row(s) because dreaming is disabled. SQLite backup: "
                     f"{db}.pre-startup-migration-{uid}.bak."):
            with self.subTest(line=line[:20]):
                self.assertEqual(G.doctor_copy_groups(f"│  {line} │\n"), {uid})
        wrapped = (f"│  Retired 1 managed dreaming cron row(s) because dreaming is disabled. SQLite backup: {db}.pr │\n"
                   f"│  e-startup-migration-{uid}.bak. │\n")
        self.assertEqual(G.doctor_copy_groups(wrapped), {uid})
        # other lines that end in "SQLite backup:" name no copy of this run
        for line in (f"Discarded incomplete pre-migration SQLite backup: {db}.pre-startup-migration-{uid}.bak",
                     f"Cannot verify pre-migration SQLite backup: {db}.pre-startup-migration-{uid}.bak"):
            self.assertEqual(G.doctor_copy_groups(line), set(), line)

    def test_models_json_copy(self):
        # 2026.11.10 doctor-plugin-model-catalog.ts removeRootProviderCopies: models.json.bak-<Date.now()>
        self.assertEqual(G.doctor_copy_kind("models.json.bak-1764140000000"), "catalog")
        for name in ("models.json.bak", "models.json.bak-12", "x-models.json.bak-1764140000000", "models.json"):
            self.assertIsNone(G.doctor_copy_kind(name), name)
        self.assertEqual(G.doctor_cron_copy_ms("models.json.bak-1764140000000"), 1764140000000)
        line = ('Removed provider "azure-openai" (a copy of plugin openai\'s generated catalog) from '
                "~/.openclaw/agents/main/agent/models.json; backup: ~/.openclaw/agents/main/agent/models.json.bak-"
                "1764140000000.")
        self.assertEqual(G.doctor_catalog_copy_ids(f"│  {line} │\n"), {"1764140000000"})
        self.assertEqual(G.doctor_catalog_copy_ids(f"│  {line[:150]} │\n│  {line[150:]} │\n"), {"1764140000000"})
        self.assertEqual(G.doctor_catalog_copy_ids("backup: ~/.openclaw/agents/main/agent/models.json.bak-"
                                                   "1764140000000."), set())  # only doctor's removal line
        self.assertEqual(G.copies_text([{"scope": "catalog", "size": 2048}]),
                         "1 copy of an agent's models.json (models.json.bak-*, with its literal provider keys) by "
                         "doctor, 2.0 KiB")

    def test_cold_navigation_recovery_dirs(self):
        name = "openclaw-cold-navigation-recovery-AbC123"
        self.assertTrue(G.DOCTOR_RECOVERY_DIR_RE.fullmatch(name))
        log = f"│  Saved pre-repair SQLite backup: /config/.openclaw/agents/main/agent/{name}/database.sqlite │\n"
        self.assertEqual(G.doctor_recovery_dirs(log), {name})

    def test_gateway_token_snapshot_and_failed_capture_line(self):
        self.assertEqual(G.doctor_copy_kind("openclaw.sqlite.doctor-gateway-token."
                                            "0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c.bak"), "snapshot")
        self.assertIsNone(G.doctor_copy_kind("openclaw.sqlite.doctor-gateway-token.x.bak"))
        m = G.CAPTURE_RE.search("Original update capture failed; incomplete copy cleanup failed; evidence retained at "
                                "/config/.openclaw.update-captures/doctor-0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c")
        self.assertEqual(next(g for g in m.groups() if g),
                         "/config/.openclaw.update-captures/doctor-0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c")
        self.assertIsNone(G.CAPTURE_RE.search("Original update capture failed; incomplete copy removed from /x"))

    def test_cold_navigation_note(self):
        text = ("│  Cold transcript navigation in /config/.openclaw/agents/main/agent/openclaw-agent.sqlite: migrated 12, "
                "pending 3; resumes on the next doctor run (openclaw doctor --fix). Pending archives keep the existing "
                "cold-restore path. │\n└  Doctor complete.\n")
        self.assertEqual(G.doctor_notes(text), [["info", "doctor added the navigation of 12 cold-archived chat(s) in "
                                                         "/config/.openclaw/agents/main/agent/openclaw-agent.sqlite; 3 "
                                                         "more follow at its next run (oc-upgrade retry --doctor); until "
                                                         "then they open through the cold restore as before"]])
        self.assertIsNone(G.evaluate_doctor(0, text, final=True)["code"])


class DoctorCopiesOnDiskTests(T.GateEnv):
    def test_cold_navigation_dir_is_a_doctor_copy_and_work_dirs_are_never_walked(self):
        T.make_1004_state(self.state, s=S, a=A, app=RT)
        rec = self.state / "agents" / "main" / "agent" / "openclaw-cold-navigation-recovery-AbC123"
        rec.mkdir()
        (rec / "database.sqlite").write_bytes(b"x" * 10)
        shadow = self.state / WORK / "state" / "state"
        shadow.mkdir(parents=True)
        (shadow / "openclaw.sqlite.pre-startup-migration-0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c.bak").write_bytes(b"y")
        self.assertEqual(G.doctor_copies(self.state), {C.rel(rec, self.state): (10, "recovery")})


class NoNetworkCodexFloorTests(Env1110):
    """Offline on the update from 2026.11.4: doctor cannot update the enabled Codex plugin of 2026.11.4, which
    2026.11.10 does not load, so the no-network reason says that accepting it still ends in a hold."""

    def setUp(self):
        super().setUp()
        to_1104(self.state)
        self.write_cfg(dict(CFG, plugins={"entries": {"codex": {"enabled": True}, "acpx": {"enabled": True}}}))
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.11.4", "mode": "bump"}))
        npm = self.bin / "npm"
        npm.write_text("#!/bin/sh\necho 'npm error code ENOTFOUND' >&2\nexit 1\n")
        npm.chmod(0o755)
        self.hooks(skip_network_check=False)

    def test_the_reason_names_the_plugin_below_the_floor(self):
        T.write_install_records(self.state, {"codex": ("@openclaw/codex", "2026.11.4", None),
                                             "acpx": ("@openclaw/acpx", "2026.11.4", None)})
        self.assertEqual(self.run_gate(), 20, self.out)
        hold = (self.upg / "hold.txt").read_text()
        self.assertIn("then the gate holds with doctor-timeout); @openclaw/codex 2026.11.4 is enabled and below the "
                      "minimum OpenClaw 2026.11.10 loads: without npm doctor cannot update it, so the gate then holds "
                      "(doctor-plugin-load, or doctor-warnings at the last pass); prefer fixing the network", hold)
        self.assertNotIn("@openclaw/acpx 2026.11.4 is enabled", hold)

    def test_nothing_extra_at_the_floor_or_when_disabled(self):
        T.write_install_records(self.state, {"codex": ("@openclaw/codex", "2026.11.5-beta.1", None)})
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertIn("doctor-timeout); prefer fixing the network", (self.upg / "hold.txt").read_text())


class CliErrorEnvelopeTests(unittest.TestCase):
    """A failed --json command of OpenClaw 2026.11.x writes {ok: false, error: {type: "cli_error", message}} to
    stdout (failure-output.ts): models status must not read it as a status without routes or logins."""

    ENV = {"ok": False, "error": {"type": "cli_error", "message": "Config secret ${MISSING} could not be resolved"}}

    def test_models_status_failure_is_reported_as_such(self):
        oauth = [{"provider": "openai", "type": "oauth", "agent": "main"}]
        for profiles in ([], oauth):
            probs = G.models_status_problems(1, self.ENV, profiles, primaries={"openai/gpt-x"})
            self.assertEqual(probs, [("pc-models-status", "models status --check failed (rc 1): Config secret "
                                                          "${MISSING} could not be resolved")])
        self.assertEqual(G.models_status_problems(0, {"models": []}, oauth),
                         [("pc-models-status", "models status --check failed (rc 0): no auth status in its JSON")])
        ok = {"auth": {"oauth": {"profiles": [{"provider": "openai", "type": "oauth", "status": "ok"}]}}}
        self.assertEqual(G.models_status_problems(0, ok, oauth), [])

    def test_envelope_helpers(self):
        self.assertTrue(G.is_cli_error(self.ENV))
        self.assertTrue(G.is_cli_error({"error": {"message": "x"}}))
        self.assertFalse(G.is_cli_error({"ok": True, "profiles": []}))
        self.assertFalse(G.is_cli_error(None))
        self.assertEqual(G.cli_error_text({"ok": False}), "")
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwx", G.cli_error_text(
            {"ok": False, "error": {"message": "bad key sk-abcdefghijklmnopqrstuvwx"}}))


class ModelsJsonCopyGateTests(Env1110):
    """2026.11.10 doctor's models.json.bak-<ms> (plaintext, literal provider keys): journaled by the pass that made it,
    deleted with the run's doctor copies; an older one is listed and kept."""

    def setUp(self):
        super().setUp()
        to_1104(self.state)
        self.write_cfg(CFG)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.11.4", "mode": "bump"}))
        self.hooks()

    def test_journaled_counted_and_deleted_with_the_run(self):
        ms = int((C.utc_now() + timedelta(minutes=1)).timestamp() * 1000)
        new = f"agents/main/agent/models.json.bak-{ms}"
        old = self.state / "agents" / "main" / "agent" / "models.json.bak-1764000000000"
        old.parent.mkdir(parents=True, exist_ok=True)
        old.write_text('{"providers": {"x": {"apiKey": "SYNTHETIC-OLD"}}}')
        self.doctor_script(passes=[
            dict(state_uv=S, agent_uv=A, app_version=RT, drop_tables=["cron_run_logs"], remove=["identity/device.json"],
                 write={new: '{"providers": {"x": {"apiKey": "SYNTHETIC-KEY"}}}'},
                 print=['Removed provider "azure-openai" (a copy of plugin openai\'s generated catalog) from '
                        f"~/.openclaw/agents/main/agent/models.json; backup: ~/.openclaw/{new}."]),
            dict(state_uv=S, agent_uv=A, app_version=RT)])
        self.assertEqual(self.run_gate(), 0, self.out)
        d = self.journal()["doctor"][0]
        self.assertEqual([(e["path"], e["scope"]) for e in d["pre_migration_backups"]], [(new, "catalog")])
        self.assertIn("1 copy of an agent's models.json (models.json.bak-*, with its literal provider keys) by doctor",
                      self.out)
        self.assertNotIn("SYNTHETIC-KEY", self.out)
        st = "\n".join(G.status_lines())
        self.assertIn("Doctor copies of an agent's models.json (models.json.bak-*): 2 ", st)
        later = C.utc_now() + timedelta(hours=49)
        with mock.patch.object(G, "gateway_started_at", return_value=later - timedelta(hours=2)):
            G.cleanup_pass(now=later, hours=48, emit=lambda s: None)
        self.assertFalse((self.state / new).exists())
        self.assertTrue(old.exists())  # no gate run made it: kept


class Hygiene1110Tests(unittest.TestCase):
    def test_cron_account_findings_stay_out_of_the_hold_reason(self):
        text = "\n".join([
            "Fix now:",
            "- Automation nightly (abc): retain openai:someone@example.com for openai/gpt-6.1-sol; model/default/"
            "fallback selections stay unchanged. Its runs are refused until it records this account.",
            "  Location: /config/.openclaw/state/openclaw.sqlite",
            "  Next step: Run openclaw doctor --fix to record the planned eligible account; otherwise follow the "
            "account selection command in the finding.",
            "  Docs: https://docs.openclaw.ai/cli/doctor/running#understanding-findings",
            "- Required migration plugin-state-migration was deferred.",
            "  Docs: https://docs.openclaw.ai/cli/doctor/running#understanding-findings",
            "└  Doctor blocked; required repairs remain incomplete."])
        msg = G.evaluate_doctor(1, text)["message"]
        self.assertNotIn("example.com", msg)
        self.assertNotIn("someone", msg)
        self.assertIn("Required migration plugin-state-migration was deferred.", msg)
        self.assertIn("1 cron inference-account finding(s), only in oc-upgrade log", msg)
        only = text.replace("- Required migration plugin-state-migration was deferred.\n"
                            "  Docs: https://docs.openclaw.ai/cli/doctor/running#understanding-findings\n", "")
        msg = G.evaluate_doctor(1, only)["message"]
        self.assertTrue(msg.endswith("doctor blocked, required repairs remain incomplete: 1 cron inference-account "
                                     "finding(s), only in oc-upgrade log (they name auth profile ids)"), msg)
        self.assertNotIn("example.com", G.failing_check_text(
            "Failing check legacy-cron (step-refused): Automation x: retain openai:someone@example.com for y"))


class LeftoverTests(Env1110):
    """D2: what a gateway start's copy-and-swap upgrade left: listed by oc-upgrade status, deleted by the cleanup
    gate_cleanup_hours after the newest of it, only once the gateway has run on the upgraded state. Without a swap
    plan unless a test adds one (add_plan): a waiting plan alone keeps everything, so it would hide the other rules.
    os.utime cannot set ctime, which _leftover_stamp also reads, so the deleting passes run at a `now` 49 h ahead."""

    GEN = ("state/openclaw.sqlite.pre-2026.11.10", "openclaw.json.pre-2026.11.10",
           "agents/main/agent/openclaw-agent.sqlite.pre-2026.11.10", "credentials/oauth.json.pre-2026.11.10-beta.1")
    PLANNED = ".upgrade-2026.11.10-77-1764000000001"
    STAGED = ".openclaw.json" + WORK  # the staged copy of WORK's attempt
    ORPHAN = ".openclaw.json.upgrade-2026.11.10-3999999-1764000000002"  # its work dir is gone (removed by a start)

    def setUp(self):
        super().setUp()
        for rel in self.GEN + (self.STAGED, self.ORPHAN):
            p = self.state / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("synthetic plaintext copy")
        (self.state / "logs").mkdir()
        (self.state / "logs" / "state-upgrade-2026.11.10.log").write_text("synthetic chain log")
        (self.state / WORK / "state").mkdir(parents=True)
        (self.state / WORK / "state" / "openclaw.json").write_text("{}")
        self.planned = self.state / self.PLANNED
        # never leftovers: doctor's copies, other runtimes' snapshots, node_modules, uncopied dirs, links, other logs,
        # a staged name below the state dir's top level
        for rel in ("state/openclaw.sqlite.pre-startup-migration-0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c.bak",
                    "state/openclaw.sqlite.pre-acp-key-migration-0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c.bak",
                    "npm/node_modules/x/index.js.pre-2026.11.10", "tmp/y.pre-2026.11.10", "logs/gateway.log",
                    "agents/main/agent/state-upgrade-2026.11.10.log",
                    "agents/main/.x.json.upgrade-2026.11.10-3999999-1764000000003"):
            p = self.state / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("keep")
        os.symlink("/etc/hostname", self.state / "link.pre-2026.11.10")
        os.symlink("/etc/hostname", self.state / ".openclaw.json.upgrade-2026.11.10-3999999-1764000000004")
        self.age_all(days=3)
        self.later = C.utc_now() + timedelta(hours=49)

    def age_all(self, days):
        old = (C.utc_now() - timedelta(days=days)).timestamp()
        for p in self.state.rglob("*"):
            os.utime(p, (old, old), follow_symlinks=False)

    def add_plan(self):
        """A swap plan waiting for the next start, with the staged copy its plan names."""
        self.planned.mkdir()
        (self.planned / "plan.json").write_text("{}")
        (self.state / (".openclaw.json" + self.PLANNED)).write_text("synthetic staged copy of a swap plan")

    def up(self, ago, now=None):
        return mock.patch.object(G, "gateway_started_at", return_value=(now or C.utc_now()) - ago)

    def removed(self):
        return [r for r in self.GEN + ("logs/state-upgrade-2026.11.10.log", WORK, self.STAGED, self.ORPHAN)
                if not os.path.lexists(self.state / r)]

    def test_listing(self):
        self.add_plan()
        left = G.startup_upgrade_leftovers(self.state, CFG)
        self.assertEqual(sorted(left["generations"]), sorted(self.GEN))
        self.assertEqual(list(left["logs"]), ["logs/state-upgrade-2026.11.10.log"])
        self.assertEqual([(w["path"], w["plan"]) for w in left["work_dirs"]],
                         [(WORK, False), (self.planned.name, True)])
        self.assertEqual(sorted(left["staged"]), sorted([self.STAGED, self.ORPHAN, ".openclaw.json" + self.PLANNED]))
        self.assertEqual(left["staged_held"], [".openclaw.json" + self.PLANNED])
        self.assertEqual(G.leftover_paths(left)[-2:], sorted([self.STAGED, self.ORPHAN]))
        st = "\n".join(G.status_lines())
        self.assertIn(f"WARN: unfinished OpenClaw state upgrade {self.planned} with its swap plan (plan.json): never "
                      "deleted by the add-on; an interrupted OpenClaw state upgrade", st)
        self.assertIn("OpenClaw state-upgrade leftovers (a gateway start upgraded the state by copy and swap): 8 "
                      "item(s)", st)
        self.assertIn(".<file>.upgrade-* a staged copy of that file", st)
        self.assertIn("deleted 48 h after the newest of them, once the gateway has run on the upgraded state", st)
        self.assertNotIn(self.planned.name + ",", st)
        self.assertNotIn(".openclaw.json" + self.PLANNED, st)

    def test_kept_until_a_healthy_gateway_start(self):
        lines = []
        with mock.patch.object(G, "gateway_started_at", return_value=None):
            self.assertEqual(G.cleanup_cmd([], emit=lines.append), 0)
            self.assertIn("  OpenClaw state-upgrade leftovers: kept until the gateway has run 2 min on the upgraded "
                          "state, then due 48 h after the newest of them", lines)
            self.assertEqual(G.cleanup_pass(now=self.later, hours=48, emit=lines.append), 0)  # no gateway runs
        self.assertEqual(self.removed(), [])
        # a gateway that started a minute ago is not yet proven
        with self.up(timedelta(seconds=60), self.later):
            self.assertEqual(G.cleanup_pass(now=self.later, hours=48, emit=lines.append), 0)
        # nor one whose start would still upgrade something
        sql(self.state / AGENT.format("main"), "PRAGMA user_version=27")
        with self.up(timedelta(hours=2), self.later):
            self.assertEqual(G.cleanup_pass(now=self.later, hours=48, emit=lines.append), 0)
        self.assertEqual(self.removed(), [])
        # all conditions hold: everything goes, nothing else
        sql(self.state / AGENT.format("main"), f"PRAGMA user_version={A}")
        with self.up(timedelta(hours=2), self.later):
            self.assertEqual(G.cleanup_pass(now=self.later, hours=48, emit=lines.append), 8, lines)
        self.assertEqual(len(self.removed()), 8)
        for rel in ("state/openclaw.sqlite.pre-startup-migration-0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c.bak",
                    "npm/node_modules/x/index.js.pre-2026.11.10", "tmp/y.pre-2026.11.10", "logs/gateway.log",
                    "agents/main/.x.json.upgrade-2026.11.10-3999999-1764000000003"):
            self.assertTrue((self.state / rel).exists(), rel)
        self.assertTrue(os.path.islink(self.state / "link.pre-2026.11.10"))
        self.assertTrue(os.path.islink(self.state / ".openclaw.json.upgrade-2026.11.10-3999999-1764000000004"))

    def test_a_swap_plan_keeps_everything_and_its_staged_copy_stays_after_it(self):
        self.add_plan()
        lines = []
        with self.up(timedelta(hours=2), self.later):
            self.assertEqual(G.cleanup_pass(now=self.later, hours=48, emit=lines.append), 0)  # a swap plan waits
        self.assertTrue(any("kept" in x and self.planned.name in x and "never deleted" in x for x in lines), lines)
        self.assertEqual(self.removed(), [])
        with self.assertRaises(OSError):
            G._safe_delete(G.gpaths(), Path(os.path.realpath(self.state)) / self.planned.name)
        # once the plan is gone, a staged copy left beside it is an orphan like the others
        os.unlink(self.planned / "plan.json")
        self.planned.rmdir()
        with self.up(timedelta(hours=2), self.later):
            self.assertEqual(G.cleanup_pass(now=self.later, hours=48, emit=lines.append), 9, lines)
        self.assertFalse(os.path.lexists(self.state / (".openclaw.json" + self.PLANNED)))

    def test_gate_cleanup_hours_counts_from_the_newest_leftover(self):
        with self.up(timedelta(hours=2)):  # ctime of every leftover is now: nothing is 48 h old
            self.assertEqual(G.cleanup_pass(hours=48, emit=lambda s: None), 0)
        self.assertEqual(self.removed(), [])
        new = (self.later - timedelta(hours=10)).timestamp()  # one leftover written 10 h before `later`
        os.utime(self.state / self.GEN[0], (new, new))
        with self.up(timedelta(hours=2), self.later):
            self.assertEqual(G.cleanup_pass(now=self.later, hours=48, emit=lambda s: None), 0)
        with self.up(timedelta(hours=2), self.later + timedelta(hours=39)):
            self.assertEqual(G.cleanup_pass(now=self.later + timedelta(hours=39), hours=48, emit=lambda s: None), 8)

    def test_a_hard_linked_generation_counts_from_the_swap_not_from_its_old_content(self):
        # state-upgrade-tree.ts preserve(): <file>.pre-<version> is a hard link of the replaced live file, so its
        # mtime is the old content's; link() sets the inode's ctime to the swap
        for rel in self.GEN + (self.STAGED, self.ORPHAN, "logs/state-upgrade-2026.11.10.log"):
            os.unlink(self.state / rel)
        shutil.rmtree(self.state / WORK)
        live = self.state / "state" / "openclaw.sqlite.old-live"
        live.write_text("content written 5 days ago")
        old = (C.utc_now() - timedelta(days=5)).timestamp()
        os.utime(live, (old, old))
        os.link(live, self.state / self.GEN[0])
        self.assertEqual(os.lstat(self.state / self.GEN[0]).st_mtime, old)
        with self.up(timedelta(minutes=3)):
            self.assertEqual(G.cleanup_pass(hours=48, emit=lambda s: None), 0)
        self.assertTrue((self.state / self.GEN[0]).exists())
        with self.up(timedelta(hours=2), self.later):
            self.assertEqual(G.cleanup_pass(now=self.later, hours=48, emit=lambda s: None), 1)
        self.assertFalse((self.state / self.GEN[0]).exists())

    def test_only_listed_names_are_deleted(self):
        real = Path(os.path.realpath(self.state))
        for bad in (real / "logs" / "gateway.log", real / "agents/main/.x.json.upgrade-2026.11.10-3999999-1764000000003",
                    real / ".openclaw.json.upgrade-2026.11.10-3999999-1764000000004"):
            with self.assertRaises(OSError):
                G._safe_delete(G.gpaths(), bad)
        self.assertGreater(G._safe_delete(G.gpaths(), real / self.ORPHAN), 0)

    def test_earlier_runtimes_only_list_them(self):
        self.set_runtime("2026.11.8", 36, 38)
        with self.up(timedelta(hours=2), self.later):
            self.assertEqual(G.cleanup_pass(now=self.later, hours=48, emit=lambda s: None), 0)
        self.assertTrue((self.state / self.GEN[0]).exists())
        self.assertIn("the add-on deletes them only with OpenClaw 2026.11.10 or later: delete them yourself",
                      "\n".join(G.status_lines()))


class GatewayStartTests(unittest.TestCase):
    def test_gateway_start_time_from_proc(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            proc = Path(td)
            (proc / "stat").write_text("cpu 1 2 3\nbtime 1764000000\n")
            tick = os.sysconf("SC_CLK_TCK")

            def add(pid, argv, start_ticks):
                d = proc / str(pid)
                d.mkdir()
                (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
                rest = ["S", "1"] + ["0"] * 17 + [str(start_ticks)] + ["0"] * 20
                (d / "stat").write_text(f"{pid} (node) " + " ".join(rest))
            add(10, ["node", "/usr/lib/node_modules/openclaw/openclaw.mjs", "doctor", "--fix"], 5 * tick)
            add(11, ["openclaw-gateway"], 100 * tick)
            add(12, ["node", "/usr/lib/node_modules/openclaw/openclaw.mjs", "gateway", "run"], 50 * tick)
            got = G.gateway_started_at(str(proc))
            self.assertEqual(got.timestamp(), 1764000050)
            self.assertIsNone(G.gateway_started_at(str(proc / "missing")))


if __name__ == "__main__":
    unittest.main()
