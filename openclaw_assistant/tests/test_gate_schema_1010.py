"""Schema crossing to OpenClaw 2026.10.10 / 2026.11.1 (state 20 -> 22, agent 24 -> 27) and the official plugins
(full5 prep).

- Agent stores OpenClaw holds back: the deletion journal (retained deletions; pending ones from 2026.10.10), doctor's
  "Held agent ... database ..." lines and the migration marker. A held store of an agent that is only registered
  leaves the schema check on 2026.10.10+ (the gateway skips it); a configured agent whose store is held is the hard
  precheck code agent-db-held (its advice never asks to bypass the wrapper's HOLD).
- Orphan stores (neither configured nor registered): doctor migrates them one-way; orphan-agent-db stays acceptable.
- A read-only PRAGMA foreign_key_check in the precheck (9b): a violation in a database below its target is the hard
  code sqlite-fk-violation before the first write (the gate never deletes rows); the task_delivery_state orphans
  doctor repairs are information; a database at its target only warns.
- pc-schema names what OpenClaw does with a configured store below the target; schema_meta skips held stores.
- The official npm plugins: an info line in the precheck, the drift WARN wording, a status line.
"""

import json
import os
import shutil
import sqlite3
import sys
import unittest
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

AGENT = "agents/{}/agent/openclaw-agent.sqlite"
CFG_1004 = {"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local"},
            "agents": {"list": [{"id": "main", "default": True}]}}


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


def register(state, aid, uv):
    sql(state / "state" / "openclaw.sqlite", "INSERT INTO agent_databases VALUES (?, ?, ?, 0, NULL)",
        params=(aid, AGENT.format(aid), uv))


def board_violation(db):
    """An agent DB row that breaks a foreign key (board_tabs -> session_nodes), written with foreign keys off."""
    sql(db, "INSERT INTO board_tabs (session_key, tab_id, title, position, created_by, revision) "
            "VALUES ('agent:main:gone', 't1', 'Tab', 0, 'user', 0)")


def state_fk(state, repairable=True):
    db = state / "state" / "openclaw.sqlite"
    if repairable:
        sql(db, "INSERT INTO task_delivery_state (task_id) VALUES ('task-gone')")
    else:
        sql(db, "INSERT INTO workspace_generated_bootstrap_hashes VALUES ('ws-gone', 'AGENTS.md', 'sha')")


class HeldClassifyTests(T.GateEnv):
    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state)

    def test_targets_22_27_from_1004_state(self):
        c = G.classify(self.state, CFG_1004, 22, 27, "2026.10.10")
        self.assertEqual((c["verdict"], c["newer"]), ("gate", []))
        self.assertEqual(c["gate"], ["state schema 20 < 22", f"{AGENT.format('main')}: agent schema 24 < 27"])
        self.assertEqual(G.infer_mode(c, CFG_1004), "bump")
        self.assertEqual((c["held"], c["held_configured"]), ([], []))

    def test_orphan_at_24_listed_under_27_but_not_under_24(self):
        T.make_1004_agent_db(self.state, "ghost")
        c = G.classify(self.state, CFG_1004, 22, 27, "2026.10.10")
        self.assertEqual([(o["id"], o["uv"]) for o in c["orphans"]], [("ghost", 24)])
        self.assertNotIn("ghost", " ".join(c["gate"]))
        self.assertEqual(G.classify(self.state, CFG_1004, 20, 24, "2026.10.4")["orphans"], [])

    def test_deletion_journal_held(self):
        st = self.state
        self.assertEqual(G.deletion_journal_held(st), {})
        journal_row(st, "kept", 1, 0, paths=json.dumps([str(st / "extra" / "kept.sqlite"), "rel/kept2.sqlite"]))
        journal_row(st, "pending", 0, 1)
        journal_row(st, "gone", 1, 1)
        journal_row(st, "badjson", 1, 0, paths="{not json")
        journal_row(st, "relative", 1, 0, agent_dir="agents/relative/agent")
        held = G.deletion_journal_held(st)
        self.assertEqual(held, {
            os.path.realpath(st / AGENT.format("kept")): ("kept", G.HELD_RETAINED),
            os.path.realpath(st / "extra" / "kept.sqlite"): ("kept", G.HELD_RETAINED),
            os.path.realpath(st / "rel" / "kept2.sqlite"): ("kept", G.HELD_RETAINED),
            os.path.realpath(st / AGENT.format("badjson")): ("badjson", G.HELD_RETAINED),
            os.path.realpath(st / AGENT.format("relative")): ("relative", G.HELD_RETAINED)})
        # 2026.10.10's maintenance read also holds the pending deletions (critic correction)
        pend = G.deletion_journal_held(st, pending=True)
        self.assertEqual(pend[os.path.realpath(st / AGENT.format("pending"))], ("pending", G.HELD_PENDING))
        self.assertNotIn(os.path.realpath(st / AGENT.format("gone")), pend)
        # missing table / unreadable DB: nothing held, no exception
        sql(st / "state" / "openclaw.sqlite", "DROP TABLE agent_deletion_journal")
        self.assertEqual(G.deletion_journal_held(st, pending=True), {})
        shutil.rmtree(st / "state")
        self.assertEqual(G.deletion_journal_held(st), {})

    def test_held_registered_store_excluded_only_from_1010(self):
        T.make_1004_agent_db(self.state, "old")
        register(self.state, "old", 24)
        journal_row(self.state, "old", 1, 0)
        held = G.deletion_journal_held(self.state)
        c = G.classify(self.state, CFG_1004, 22, 27, "2026.10.10", held=held)
        self.assertEqual(c["held"], [{"id": "old", "path": AGENT.format("old"), "uv": 24, "reason": G.HELD_RETAINED}])
        self.assertNotIn("old", c["agents"])
        self.assertNotIn(AGENT.format("old"), " ".join(c["gate"]) + " ".join(c["agent_paths"].values()))
        self.assertEqual(c["held_configured"], [])
        self.assertIn(" held=1 ", G._summary_bits({"version": "2026.10.10", "schema_state": 22, "schema_agent": 27},
                                                  c))
        self.assertEqual(c["verdict"], "gate")  # the state DB and main are still below 22/27
        # 2026.10.4 with a forced target 27: the 10.4 gateway does not skip it, so it stays in the check
        c4 = G.classify(self.state, CFG_1004, 22, 27, "2026.10.4", held=held)
        self.assertEqual(c4["held"], [])
        self.assertIn(f"{AGENT.format('old')}: agent schema 24 < 27", c4["gate"])
        # newer than the target: still newer
        sql(self.state / AGENT.format("old"), "PRAGMA user_version=28")
        c = G.classify(self.state, CFG_1004, 22, 27, "2026.10.10", held=held)
        self.assertIn(f"{AGENT.format('old')}: agent schema 28 > 27", c["newer"])
        # without held: the 0.5.94-full4 predicate
        sql(self.state / AGENT.format("old"), "PRAGMA user_version=24")
        c = G.classify(self.state, CFG_1004, 22, 27, "2026.10.10")
        self.assertIn(f"{AGENT.format('old')}: agent schema 24 < 27", c["gate"])

    def test_held_configured_store_stays_in_gate(self):
        T.make_1004_agent_db(self.state, "old")
        register(self.state, "old", 24)
        journal_row(self.state, "old", 1, 0)
        cfg = dict(CFG_1004, agents={"list": [{"id": "main", "default": True}, {"id": "old"}]})
        c = G.classify(self.state, cfg, 22, 27, "2026.10.10", held=G.deletion_journal_held(self.state))
        self.assertIn(f"{AGENT.format('old')}: agent schema 24 < 27", c["gate"])
        self.assertEqual(c["held_configured"], [{"id": "old", "path": AGENT.format("old"), "uv": 24,
                                                 "reason": G.HELD_RETAINED}])
        # a pending deletion is prepared (migrated) by 2026.10.10's doctor: no agent-db-held
        sql(self.state / "state" / "openclaw.sqlite", "UPDATE agent_deletion_journal SET cleanup_completed=0")
        c = G.classify(self.state, cfg, 22, 27, "2026.10.10", held=G.deletion_journal_held(self.state, pending=True))
        self.assertEqual(c["held_configured"], [])
        self.assertIn(f"{AGENT.format('old')}: agent schema 24 < 27", c["gate"])

    def test_held_orphan_is_flagged(self):
        T.make_1004_agent_db(self.state, "ghost")
        journal_row(self.state, "ghost", 1, 0)
        c = G.classify(self.state, CFG_1004, 22, 27, "2026.10.10", held=G.deletion_journal_held(self.state))
        self.assertEqual(c["orphans"], [{"id": "ghost", "path": AGENT.format("ghost"), "uv": 24, "held": True,
                                         "reason": G.HELD_RETAINED}])

    def test_marker_held_needs_the_same_file_and_schema(self):
        T.make_1004_agent_db(self.state, "old")
        st = os.stat(self.state / AGENT.format("old"))
        marker = {"runtime": "2026.10.10", "held": [{"id": "old", "path": AGENT.format("old"), "uv": 24,
                                                     "dev": st.st_dev, "ino": st.st_ino, "reason": "x"}]}
        rp = os.path.realpath(self.state / AGENT.format("old"))
        self.assertEqual(G.marker_held(self.state, marker, "2026.10.10"), {rp: ("old", "x")})
        self.assertEqual(G.marker_held(self.state, marker, "2026.11.1"), {})  # another runtime
        sql(self.state / AGENT.format("old"), "PRAGMA user_version=27")  # doctor migrated it after all
        self.assertEqual(G.marker_held(self.state, marker, "2026.10.10"), {})
        self.assertEqual(G.marker_held(self.state, {"runtime": "2026.10.10"}, "2026.10.10"), {})  # older marker

    def test_schema_meta_problems_skips_held_registry_rows(self):
        for aid in ("old", "other"):
            T.make_1004_agent_db(self.state, aid)
            register(self.state, aid, 24)
        pkg = {"version": "2026.10.10", "schema_state": 20, "schema_agent": 27}
        cls = {"agent_paths": {}, "held": [{"id": "old", "path": AGENT.format("old"), "uv": 24, "reason": "x"}]}
        probs = G.schema_meta_problems(self.state, cls, pkg)
        self.assertIn("agent_databases[other].schema_version 24", probs)
        self.assertNotIn("agent_databases[old].schema_version 24", probs)


class DoctorHeldTests(unittest.TestCase):
    def test_held_paths_from_doctor_text(self):
        text = ("\x1b[33m│  Held agent old database /c/.openclaw/agents/old/agent/openclaw-agent.sqlite (deletion journal "
                "reconstructed); run openclaw doctor --fix to inspect restoration. │\x1b[0m\n"
                "◇  Held agent kept database /c/.openclaw/agents/kept/agent/openclaw-agent.sqlite (retained-by-deletion); "
                "run openclaw doctor --fix to inspect restoration.\n"
                "Held agent x database /p/x.sqlite; deletion history needs repair.\n"
                "Held agent old database /c/.openclaw/agents/old/agent/openclaw-agent.sqlite (deletion journal "
                "reconstructed); again\n")
        self.assertEqual(G.held_paths_from_doctor(text), [
            ["old", "/c/.openclaw/agents/old/agent/openclaw-agent.sqlite", "deletion journal reconstructed"],
            ["kept", "/c/.openclaw/agents/kept/agent/openclaw-agent.sqlite", "retained-by-deletion"],
            ["x", "/p/x.sqlite", "deletion history needs repair"]])
        self.assertEqual(G.held_paths_from_doctor("Doctor complete. Agent old is fine. Held agents: none"), [])
        self.assertEqual(G.held_paths_from_doctor(""), [])

    def test_evaluate_doctor_1010_texts(self):
        ev = G.evaluate_doctor(1, "Doctor finished with plugin load errors.")
        self.assertEqual(ev["code"], "doctor-plugin-load")
        ev = G.evaluate_doctor(1, "Doctor stopped because a state migration refused to continue: Agent schema "
                                  "migration failed foreign key validation for /x")
        self.assertEqual(ev["code"], "doctor-migration-refused")
        ev = G.evaluate_doctor(0, "Held agent kept database /c/a.sqlite (retained-by-deletion); run openclaw doctor "
                                  "--fix to inspect restoration.\nDoctor complete.")
        self.assertIsNone(ev["code"])


class FkCheckTests(T.GateEnv):
    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state)
        self.adb = self.state / AGENT.format("main")
        self.sdb = self.state / "state" / "openclaw.sqlite"

    def test_fk_check_ok_violation_skipped(self):
        self.assertEqual(G.fk_check(self.adb), "ok")
        board_violation(self.adb)
        r = G.fk_check(self.adb)
        self.assertEqual((r["count"], r["repairable"]), (1, False))
        self.assertEqual([x[0] for x in r["sample"]], ["board_tabs"])
        self.assertEqual((r["sample"][0][2], r["sample"][0][3]), ("session_nodes", 0))
        self.assertFalse(Path(f"{self.adb}-wal").exists() or Path(f"{self.adb}-shm").exists())
        # WAL content without -shm index, too large for a private copy
        Path(f"{self.adb}-wal").write_bytes(b"x" * 64)
        with mock.patch.object(G, "QUICK_CHECK_COPY_LIMIT", 10):
            self.assertEqual(G.fk_check(self.adb), "skipped")

    def test_fk_check_timeout_and_stop(self):
        board_violation(self.adb)
        self.assertEqual(G.fk_check(self.adb, budget_s=0), "timeout")
        G.STOP.set()
        try:
            with self.assertRaises(G.GateStopped):
                G.fk_check(self.adb)
        finally:
            G.STOP.clear()

    def test_state_task_delivery_orphans_repairable(self):
        state_fk(self.state)
        r = G.fk_check(self.sdb)
        self.assertEqual((r["count"], r["repairable"]), (1, True))
        state_fk(self.state, repairable=False)
        r = G.fk_check(self.sdb)
        self.assertEqual((r["count"], r["repairable"]), (2, False))


class SchemaGate1010Tests(T.GateEnv):
    """A 2026.10.4 state (20/24) under the 2026.10.10 runtime (22/27): a bump run."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state)
        self.cfg = json.loads(json.dumps(CFG_1004))
        self.write_cfg(self.cfg)
        (self.upg / "gate").mkdir(parents=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.10.10", 22, 27)
        self.hooks()

    def hold_txt(self):
        return (self.upg / "hold.txt").read_text()

    def test_precheck_fk_violation_below_target_holds_before_first_write(self):
        board_violation(self.state / AGENT.format("main"))
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["codes"], j["phase"]), (["sqlite-fk-violation"], "precheck"))
        self.assertIsNone(j.get("first_write_at"))
        self.assertFalse((self.upg / "gate" / "runs" / j["run_id"] / "doctor-pass1.log").exists())
        hold = self.hold_txt()
        self.assertIn(f"{AGENT.format('main')} (agent schema 24, OpenClaw 2026.10.10 migrates it to 27): 1 foreign-key "
                      "violation(s): board_tabs row 1 -> session_nodes", hold)
        self.assertIn("foreign key validation", hold)
        self.assertIn("the gate never deletes rows", hold)
        self.assertNotIn("--accept", hold)
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 20)
        self.assertIn("quick_check ok (2/2); foreign keys FAILED (1 of 2)", "\n".join(lines))

    def test_precheck_fk_violation_at_target_only_warns(self):
        # a 2026.9.9 state (19/24) under 2026.10.4 (20/24): the agent DB is already at its target
        shutil.rmtree(self.state / "state")
        shutil.rmtree(self.state / "agents")
        T.make_1004_state(self.state, s=19, a=24, app="2026.9.9")
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.9", "mode": "from-7x"}))
        self.set_runtime("2026.10.4", 20, 24)
        board_violation(self.state / AGENT.format("main"))
        warn = (f"WARN [gate] {AGENT.format('main')} (already at agent schema 24): 1 foreign-key violation(s) "
                "(board_tabs row 1 -> session_nodes); nothing migrates it now, but the next OpenClaw update will stop "
                "on them: restore that database from a backup before then")
        for mode in ("bump", "maintenance"):
            if mode == "maintenance":
                self.assertEqual(G.retry_cmd(["--doctor"], emit=lambda s: None), 0)
            self.assertEqual(self.run_gate(), 0, self.out)
            self.assertEqual(self.journal()["mode"], mode)
            self.assertIn(warn, self.out)
            self.assertIn("quick_check ok (2/2); foreign keys FAILED (1 of 2)", self.out)
            self.assertNotIn("sqlite-fk-violation", self.out)

    def test_precheck_state_fk_repairable_is_info(self):
        state_fk(self.state)
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        text = "\n".join(lines)
        self.assertIn("[gate] 1/8 info: state/openclaw.sqlite has 1 task_delivery_state row(s) whose task run "
                      "is gone; doctor deletes them (OpenClaw's own repair for this case)", text)
        self.assertIn("foreign keys ok (1/2, 1 repaired by doctor)", text)
        state_fk(self.state, repairable=False)
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 20)
        text = "\n".join(lines)
        self.assertIn("hard       sqlite-fk-violation: state/openclaw.sqlite (state schema 20): 2 foreign-key "
                      "violation(s)", text)
        self.assertIn("refuses it", text)

    def test_orphan_wording_and_held_orphan_info(self):
        T.make_1004_agent_db(self.state, "ghost")
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 20)
        self.assertIn("quick_check ok (3/3); foreign keys ok (3/3)", "\n".join(lines))  # the orphan is checked too
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["codes"], j["hold"]["acceptable"]), (["orphan-agent-db"], True))
        hold = self.hold_txt()
        self.assertIn("agent database(s) of agents that are neither configured nor registered: "
                      f"{AGENT.format('ghost')} (schema 24)", hold)
        self.assertIn("migrates it one-way to schema 27", hold)
        self.assertIn("Next: move agent folders you no longer need out of /config/.openclaw/agents (they are in your "
                      "encrypted backup), then oc-upgrade retry, or accept: oc-upgrade retry --accept orphan-agent-db "
                      "(then restart the add-on)", hold)
        # a journal-held orphan: information only
        journal_row(self.state, "ghost", 1, 0)
        self.assertEqual(G.retry_cmd([], emit=lambda s: None), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn(f"[gate] 1/8 info: {AGENT.format('ghost')} (agent ghost, schema 24) is kept from a "
                      "deleted agent (OpenClaw deletion journal); OpenClaw does not migrate or open it, and the gate "
                      "leaves it out of the schema checks", self.out)
        self.assertIn("quick_check ok (2/2); foreign keys ok (2/2)", self.out)

    def test_precheck_agent_db_held_configured_is_hard(self):
        T.make_1004_agent_db(self.state, "old")
        register(self.state, "old", 24)
        journal_row(self.state, "old", 1, 0)
        self.cfg["agents"]["list"].append({"id": "old"})
        self.write_cfg(self.cfg)
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["codes"], j["hold"]["acceptable"]), (["agent-db-held"], False))
        self.assertIsNone(j.get("first_write_at"))
        hold = self.hold_txt()
        self.assertIn(f"agent old is configured, but OpenClaw keeps its database {AGENT.format('old')} (schema 24) "
                      "from a deletion (deletion journal): doctor will not migrate it and OpenClaw 2026.10.10 refuses "
                      "the agent", hold)
        self.assertNotIn("OC_ADDON_UNSAFE", hold)
        # under 2026.10.4 (target 24) the store is not below the target: nothing to report
        G.retry_cmd(["--cancel"], emit=lambda s: None)
        self.set_runtime("2026.10.4", 20, 24)
        lines = []
        self.quiet(G.dry_run, emit=lines.append)
        self.assertNotIn("agent-db-held", "\n".join(lines))

    def test_1010_bump_with_doctor_held_registered_store_completes(self):
        T.make_1004_agent_db(self.state, "old")
        register(self.state, "old", 24)
        old_abs = self.state / AGENT.format("old")
        self.doctor_script(state_uv=22, agent_uv=27, app_version="2026.10.10", skip_agents=["old"],
                           print=[f"Held agent old database {old_abs} (deletion journal reconstructed); run openclaw "
                                  "doctor --fix to inspect restoration.", "1 store held back. Updates can continue; "
                                  "held stores remain untouched."])
        self.hooks(accept=["doctor-held-back"])
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("pc-schema", self.out)
        self.assertIn(f"[gate] 7/8 info: held agent database(s) left at their schema, not checked: {AGENT.format('old')} "
                      "(agent old, schema 24: held back by doctor: deletion journal reconstructed); the gateway does "
                      "not open them", self.out)
        self.assertIn("[gate] done: MIGRATED 2026.10.10", self.out)
        self.assertEqual(self.journal()["doctor_held"], [["old", str(old_abs), "deletion journal reconstructed"]])
        m = json.loads((self.upg / "gate" / "migrated.json").read_text())
        self.assertEqual([(h["id"], h["path"], h["uv"]) for h in m["held"]], [("old", AGENT.format("old"), 24)])
        self.assertNotIn(AGENT.format("old"), [a["path"] for a in m["binding"]["agents"]])
        st = G.status_lines()
        self.assertIn(f"  held agent databases (not migrated, not opened by the gateway; not checked): "
                      f"{AGENT.format('old')} (agent old, schema 24: held back by doctor: deletion journal "
                      "reconstructed)", st)
        # the next start: no bump-repeat
        d = self.plan()
        self.assertEqual((d["rc"], d["action"]), (0, "none"), self.out)
        self.assertIn("held=1", self.out)
        # the user configures the agent again: its store is in the check again (a new run, as the agents changed),
        # and the store doctor holds back is the hard agent-db-held before anything is written
        self.cfg["agents"]["list"].append({"id": "old"})
        self.write_cfg(self.cfg)
        d = self.plan()
        self.assertEqual((d["rc"], d["action"]), (10, "run"), self.out)
        self.assertIn(f"{AGENT.format('old')}: agent schema 24 < 27", self.out)
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["codes"], j["phase"], j.get("first_write_at")), (["agent-db-held"], "precheck", None))
        self.assertIn("(held back by doctor: deletion journal reconstructed)", (self.upg / "hold.txt").read_text())

    def test_pc_schema_message_names_default_agent_consequence(self):
        self.doctor_script(state_uv=22, agent_uv=24, app_version="2026.10.10")
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["phase"]), ("pc-schema", "postconditions"))
        hold = self.hold_txt()
        self.assertIn(f"{AGENT.format('main')}: agent schema 24 < 27 (configured default agent: the gateway refuses to "
                      "start (exit 78) or stays not ready)", hold)
        self.assertNotIn("OC_ADDON_UNSAFE", hold)
        self.assertIn("oc-upgrade retry --doctor", hold)

    def test_official_plugins_info_line_and_status(self):
        codex = self.state / "npm" / "projects" / "openclaw-codex" / "node_modules" / "@openclaw" / "codex"
        codex.mkdir(parents=True)
        (codex / "package.json").write_text(json.dumps({"name": "@openclaw/codex", "version": "2026.10.4"}))
        idx = {"index": {"installRecords": {
            "codex": {"source": "npm", "spec": "@openclaw/codex@2026.10.4", "resolvedName": "@openclaw/codex",
                      "resolvedVersion": "2026.10.3", "installPath": str(codex)},
            "acpx": {"source": "npm", "spec": "@openclaw/acpx@2026.10.4", "resolvedVersion": "2026.10.4"},
            "brave": {"source": "npm", "spec": "npm:@openclaw/brave-plugin@2026.10.4", "version": "2026.10.4"},
            "thirdparty": {"source": "npm", "spec": "openclaw-plugin-x@1.0.0", "version": "1.0.0"},
            "local": {"source": "path", "spec": "@openclaw/local", "version": "2026.10.4"}}}}
        sql(self.state / "state" / "openclaw.sqlite", "INSERT INTO config_machine_state VALUES "
            "('plugins.installedIndex', ?, 0)", params=(json.dumps(idx),))
        self.cfg["plugins"] = {"entries": {"codex": {"enabled": True}, "acpx": {"enabled": False}}}
        self.write_cfg(self.cfg)
        got = G.official_plugin_installs(self.state, self.cfg)
        self.assertEqual(got, [
            {"id": "acpx", "package": "@openclaw/acpx", "version": "2026.10.4", "enabled": False},
            {"id": "brave", "package": "@openclaw/brave-plugin", "version": "2026.10.4", "enabled": None},
            {"id": "codex", "package": "@openclaw/codex", "version": "2026.10.4", "enabled": True}])  # on-disk version
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("[gate] 1/8 info: official plugins: @openclaw/acpx 2026.10.4 (disabled), "
                      "@openclaw/brave-plugin 2026.10.4, @openclaw/codex 2026.10.4 (enabled); OpenClaw's doctor and "
                      "then the add-on update the enabled ones to 2026.10.10", self.out)
        self.assertNotIn("doctor does not", self.out)  # doctor --fix updates enabled official plugins itself
        self.assertEqual([x["id"] for x in self.journal()["plugins_official_before"]], ["acpx", "brave", "codex"])
        st = G.status_lines()
        line = next(x for x in st if x.startswith("Official plugins:"))
        self.assertIn("; not yet at OpenClaw 2026.10.10: @openclaw/codex (the add-on retries at the next start", line)
        G.plugin_cohort_marker(self.state, "2026.10.10").write_text("2026.10.10\n")
        line = next(x for x in G.status_lines() if x.startswith("Official plugins:"))
        self.assertTrue(line.endswith("; enabled ones synced to OpenClaw 2026.10.10"), line)
        sql(self.state / "state" / "openclaw.sqlite", "DELETE FROM config_machine_state")
        self.assertEqual(G.official_plugin_installs(self.state, self.cfg), [])

    def test_plugin_version_warnings_1010(self):
        data = {"plugins": [
            {"id": "codex", "packageName": "@openclaw/codex", "version": "2026.10.4", "enabled": True},
            {"id": "brave", "packageName": "@openclaw/brave-plugin", "version": "2026.10.4", "enabled": True},
            {"id": "acpx", "packageName": "@openclaw/acpx", "version": "2026.10.4", "enabled": False},
            {"id": "beta", "packageName": "@openclaw/beta", "version": "2026.11.5-beta.1", "enabled": True},
            {"id": "same", "packageName": "@openclaw/same", "version": "2026.10.10", "enabled": True}]}
        self.assertEqual(G.plugin_version_warnings(data, "2026.10.10"), [
            "plugin codex is 2026.10.4, OpenClaw is 2026.10.10: the add-on updates it before the gateway starts "
            "(oc-upgrade plugins-sync)",
            "plugin beta 2026.11.5-beta.1 is newer than OpenClaw 2026.10.10; left as is"])


class CodesTests(unittest.TestCase):
    def test_reworded_advice_never_bypasses_the_hold(self):
        for code in ("pc-schema", "orphan-agent-db", "agent-db-held", "sqlite-fk-violation"):
            self.assertNotIn("OC_ADDON_UNSAFE", G.ADVICE[code])
        self.assertIn("orphan-agent-db", G.ACCEPTABLE)
        self.assertNotIn("agent-db-held", G.ACCEPTABLE)
        self.assertNotIn("sqlite-fk-violation", G.ACCEPTABLE)
        self.assertEqual(G.advice_for(["orphan-agent-db"]),
                         G.ADVICE["orphan-agent-db"] + ", or accept: oc-upgrade retry --accept orphan-agent-db "
                                                       "(then restart the add-on)")
        self.assertEqual(G.default_agent_id({"agents": {"list": [{"id": "a"}, {"id": "b", "default": True}]}}), "b")
        self.assertEqual(G.default_agent_id({"agents": {"list": [{"id": "solo"}]}}), "solo")
        self.assertEqual(G.default_agent_id({"agents": {"list": [{"id": "a"}, {"id": "b"}]}}), "main")
        self.assertEqual(C.runtime_caps("2026.10.10")["held_store_skip"], True)


class DocsWordingTests(unittest.TestCase):
    """User-facing claims that the review checked against the OpenClaw sources (2026.10.4 / 2026.10.10)."""

    REPO = ADDON.parent

    def text(self, rel):
        return (self.REPO / rel).read_text(encoding="utf-8")

    def test_doctor_updates_enabled_official_plugins(self):
        # repair-sequencing.ts: doctor --fix runs repairMissingConfiguredPluginInstalls with repairVersionDrift, so
        # it updates enabled official catalog plugins itself; the add-on only catches what it left behind
        wrong = ("doctor never updates", "doctor does not update", "OpenClaw's doctor never",
                 "OpenClaw's doctor does not", "doctor never does this", "doctor never brings",
                 "doctor does not update them")
        for rel in ("DOCS.md", "SECURITY.md", "openclaw_assistant/CHANGELOG.md", "openclaw_assistant/run.sh",
                    "openclaw_assistant/oc_upgrade.py", "openclaw_assistant/oc_gate.py"):
            body = self.text(rel)
            for phrase in wrong:
                with self.subTest(file=rel, phrase=phrase):
                    self.assertNotIn(phrase, body)
        sec = self.text("SECURITY.md")
        self.assertIn("OpenClaw's own doctor, in the migration gate's doctor passes", sec)
        self.assertIn("then neither doctor nor the add-on updates them", sec)

    def test_hold_codes_version_scope(self):
        docs = self.text("DOCS.md")
        self.assertIn("`sqlite-fk-violation`, `orphan-agent-db` and `agent-db-held` apply with every OpenClaw\n"
                      "version", docs)
        nxt = docs.split("**OpenClaw 2026.11.1 (this add-on version).**", 1)[1].split("With OpenClaw 2026.10.4", 1)[0]
        self.assertNotIn("agent databases outside the configured agents", nxt)

    def test_memory_half_life_still_selects_the_returned_results(self):
        # 2026.10.10 manager-search-orchestration.ts: minScore filter, decay, sort, slice(0, maxResults)
        docs = self.text("DOCS.md")
        section = docs.split("#### Memory search recency", 1)[1].split("\n#### ", 1)[0]
        self.assertNotIn("only sets the order", section)
        self.assertIn("`maxResults` (default 6)", section)
        note = json.loads(self.text("openclaw_assistant/oc-patches/2026.10.10/manifest.json"))
        half = next(e for e in note["patches"] if e["name"] == "memory-search-half-life")
        self.assertIn("maxResults", half["note"])


if __name__ == "__main__":
    unittest.main()
