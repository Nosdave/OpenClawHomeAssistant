"""Golden regression test: the gate output on the 2026.10.4 target (full5 prep).

The full5 work adds checks for OpenClaw 2026.10.5+ (retired files, Skill Workshop, held agent stores, cron
accounts) behind oc_common.runtime_caps. On the 2026.10.4 target the gate must keep printing and journaling
exactly what 0.5.94-full4 printed. This test runs a read-only preview (`gate --dry-run`, `oc-upgrade check`), a
bump run (state of 2026.9.9 -> runtime 2026.10.4), `oc-upgrade status`, then a maintenance run
(`oc-upgrade retry --doctor`), and compares every output with tests/fixtures/golden/gate-2026.10.4.txt.
Run ids, timestamps, durations, sizes and the temporary root are replaced by placeholders.

The golden file was captured from the gate code before the full5 hooks existed. A change to it must be a
deliberate, decided 10.4-visible change (named in the CHANGELOG), made in the same commit as the code:
    OC_GATE_GOLDEN_UPDATE=1 python3 -m pytest -q tests/test_gate_golden_1004.py
Deliberate changes so far: the precheck line's "foreign keys ok (2/2)" part (read-only foreign-key check, which
OpenClaw 2026.10.4 enforces too; CHANGELOG "Migration gate, foreign keys"); doctor's SQLite copies (CHANGELOG
"doctor's pre-migration SQLite copies"): the doctor pass 1 line counts only the copies of that pass ("1 full
pre-migration SQLite copy by doctor ...; not the rollback point", none in the maintenance run), the journal records
them per pass (scope, pre_migration_backups_older, doctor_copies_before), finalize says they are deleted with the
doctor captures, and the status lines name them ("Doctor pre-migration SQLite copies", "Gate options: delete doctor
captures and SQLite copies"); the official plugins (CHANGELOG "Official plugins follow the OpenClaw version"; the
fixture has Brave and an enabled codex in OpenClaw's install index): the precheck's "info: official plugins: ..."
line, the journal's plugins_official_before and the status line "Official plugins: ..."; a store of an unconfigured
agent that a retained deletion keeps (CHANGELOG "agent databases outside the configured agents"; OpenClaw 2026.10.4
reads retained deletions too): an "info: ... is kept from a deleted agent" line instead of the acceptable HOLD
orphan-agent-db, `oc-upgrade check` lists it under "held agent databases", the journal's orphans entry has
held/reason.
Not in the fixture because each one is a HOLD (DOCS "Upgrading to OpenClaw 2026.10"); Holds1004Tests pins them
instead: the reworded orphan-agent-db text (reworded again after the host rehearsal, D11: doctor sets a copy of
another agent's database aside instead of migrating it; CHANGELOG "orphan agent databases"), quick_check and the foreign-key check on such a store below the target
(its counts, and a hard sqlite-fk-violation for a damaged one), and the hard code agent-db-held for a configured
agent whose store a retained deletion keeps.
"""

import json
import os
import re
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
for _p in (str(ADDON), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_gate as G  # noqa: E402
import test_gate as T  # noqa: E402

GOLDEN = TESTS / "fixtures" / "golden" / "gate-2026.10.4.txt"
SCRIPT = ADDON / "oc_upgrade.py"
SECTION_RE = re.compile(r"^### (.+)$", re.M)

CFG = {
    "meta": {"lastTouchedVersion": "2026.9.9"},
    "agents": {"defaults": {"model": {"primary": "vllm/qwen3.5-122b",
                                      "fallbacks": ["openai/gpt-5.5", "anthropic/claude-sonnet-4-6"]},
                            "models": {"vllm/qwen3.5-122b": {}, "openai/gpt-5.5": {"alias": "gpt"},
                                       "anthropic/claude-sonnet-4-6": {}}},
               "list": [{"id": "main", "default": True}]},
    "models": {"providers": {"vllm": {"baseUrl": "http://127.0.0.1:8000/v1", "models": [{"id": "qwen3.5-122b"}]}}},
    "gateway": {"mode": "local", "auth": {"token": "SECRET-GATEWAY-TOKEN"}},
    "channels": {"telegram": {"enabled": True, "botToken": "123456:SECRET-BOT-TOKEN"}},
    "plugins": {"entries": {"codex": {"enabled": True}}},
}

# durations of C.fmt_duration ("0s", "1m05s", "1h00m"), sizes of C.human, ISO times, run ids
_DUR_RE = re.compile(r"\b\d+(?:h\d{2}m|m\d{2}s|s)\b")
_SIZE_RE = re.compile(r"\b\d+(?:\.\d+)? (?:B|KiB|MiB|GiB|TiB)\b")
_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b")
_CHECK_TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\b")
_RUN_RE = re.compile(r"\b\d{8}T\d{6}Z-[0-9a-f]{6}\b")
_S_MIB_RE = re.compile(r"\bS=\d+ MiB\b")
# journal/marker values that depend on the SQLite page layout, the clock or the file system
_JOURNAL_NUMBERS = {"size", "s_mib", "doctor_pass_seconds", "duration_s", "dev", "ino"}


def parse_golden(text):
    names = SECTION_RE.findall(text)
    bodies = SECTION_RE.split(text)[2::2]
    return dict(zip(names, (b.strip("\n") for b in bodies)))


class Golden1004Tests(T.GateEnv):
    maxDiff = None

    def setUp(self):
        super().setUp()
        self.set_runtime("2026.10.4", 20, 24)
        # the image's build-time record as a 2026.10.4 image writes it (no 2026.10.10 capabilities)
        self.features(cron_refusal=False, cron_doctor_migration=False, retires_skill_proposals=False)
        T.make_1004_state(self.state, s=19, a=24, app="2026.9.9", content=True)
        self.write_cfg(CFG)
        (self.ws / "AGENTS.md").write_text("# agents\n")
        sess = self.state / "agents" / "main" / "sessions"
        sess.mkdir(parents=True)
        (sess / "sessions.json").write_text(json.dumps({
            "agent:main:main": {"sessionId": "s1", "updatedAt": 1, "model": "vllm/qwen3.5-122b"}}))
        self.add_plugins_and_retained_store()
        (self.upg / "gate").mkdir(parents=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.9", "mode": "from-7x"}))
        self.hooks()
        # pass 1 of the bump makes doctor's full pre-migration copy of the state DB; later passes make none.
        # Doctor leaves the store a retained deletion keeps alone (agent-deletion-journal.read.ts, also in 10.4).
        step = {"state_uv": 20, "agent_uv": 24, "app_version": "2026.10.4", "drop_tables": ["cron_run_logs"],
                "remove": ["identity/device.json"], "skip_agents": ["retired"]}
        self.doctor_script(passes=[dict(step, baks=["state/openclaw.sqlite"]), step])
        self.pylib = self.tmp / "pylib"
        self.pylib.mkdir()

    def add_plugins_and_retained_store(self):
        """Two official npm plugins in OpenClaw's install index (Brave, codex enabled, both behind 2026.10.4) and the
        store of an unconfigured agent that a retained deletion keeps (schema 20, below the target): synthetic."""
        codex = self.state / "npm" / "projects" / "openclaw-codex" / "node_modules" / "@openclaw" / "codex"
        codex.mkdir(parents=True)
        (codex / "package.json").write_text(json.dumps({"name": "@openclaw/codex", "version": "2026.10.2"}))
        idx = {"index": {"installRecords": {
            "brave": {"source": "npm", "spec": "npm:@openclaw/brave-plugin@2026.10.2", "version": "2026.10.2"},
            "codex": {"source": "npm", "spec": "@openclaw/codex@2026.10.2", "resolvedName": "@openclaw/codex",
                      "resolvedVersion": "2026.10.2", "installPath": str(codex)}}}}
        T.make_1004_agent_db(self.state, "retired", uv=20, app="2026.9.9")
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute("INSERT INTO config_machine_state VALUES ('plugins.installedIndex', ?, 0)", (json.dumps(idx),))
        con.execute("INSERT INTO agent_deletion_journal (agent_id, agent_dir, workspace_dir, sessions_dir, created_at, "
                    "cleanup_completed, delete_files) VALUES ('retired', ?, '/w', '/s', 0, 1, 0)",
                    (str(self.state / "agents" / "retired" / "agent"),))
        con.commit()
        con.close()

    # ----- normalization -----
    def norm(self, text):
        text = text.replace(str(self.tmp), "<TMP>")
        for rx, sub in ((_RUN_RE, "<RUN>"), (_TS_RE, "<TS>"), (_CHECK_TIME_RE, "<TIME>"), (_S_MIB_RE, "S=<N> MiB"),
                        (_SIZE_RE, "<SIZE>"), (_DUR_RE, "<DUR>")):
            text = rx.sub(sub, text)
        return "\n".join(ln.rstrip() for ln in text.strip("\n").splitlines())

    def norm_json(self, obj):
        def walk(x):
            if isinstance(x, dict):
                return {k: ("<N>" if k in _JOURNAL_NUMBERS and isinstance(v, (int, float)) else walk(v))
                        for k, v in x.items()}
            if isinstance(x, list):
                return [walk(v) for v in x]
            return x
        return self.norm(json.dumps(walk(obj), indent=1, ensure_ascii=False))

    # ----- capture -----
    def check_output(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", OC_ADDON_PYLIB=str(self.pylib),
                   OPENCLAW_RUNTIME_VERSION=self.runtime)
        p = subprocess.run([sys.executable, "-B", str(SCRIPT), "check"], capture_output=True, text=True, env=env,
                           timeout=300)
        return f"rc={p.returncode}\n{p.stdout}" + (f"\nstderr:\n{p.stderr}" if p.stderr else "")

    def run_section(self, label, sections):
        rc = self.run_gate()
        self.assertEqual(rc, 0, self.out + self.err)
        j = self.journal()
        sections[f"{label}: gate output"] = self.norm(self.out + (f"\nstderr:\n{self.err}" if self.err else ""))
        sections[f"{label}: events.log"] = self.norm(
            (self.upg / "gate" / "runs" / j["run_id"] / "events.log").read_text(encoding="utf-8"))
        sections[f"{label}: journal"] = self.norm_json(j)
        sections[f"{label}: marker"] = self.norm_json(json.loads((self.upg / "gate" / "migrated.json").read_text()))
        sections[f"{label}: status"] = self.norm("\n".join(G.status_lines()))
        self.assertNotIn("SECRET", self.out)
        return j

    def capture(self):
        sections = {}
        lines = []
        rc = self.quiet(G.dry_run, emit=lines.append)
        sections["dry-run"] = self.norm(f"rc={rc}\n" + "\n".join(lines) + self.out)
        sections["check before the bump"] = self.norm(self.check_output())
        j1 = self.run_section("bump", sections)
        self.assertEqual(j1["mode"], "bump")
        sections["check after the bump"] = self.norm(self.check_output())
        self.assertEqual(G.retry_cmd(["--doctor"], emit=lambda s: None), 0)
        j2 = self.run_section("maintenance", sections)
        self.assertEqual(j2["mode"], "maintenance")
        return sections

    def test_gate_output_on_the_2026_10_4_target_is_unchanged(self):
        got = self.capture()
        if os.environ.get("OC_GATE_GOLDEN_UPDATE") == "1":
            GOLDEN.parent.mkdir(parents=True, exist_ok=True)
            GOLDEN.write_text("\n".join(f"### {k}\n{v}\n" for k, v in got.items()), encoding="utf-8")
        want = parse_golden(GOLDEN.read_text(encoding="utf-8"))
        self.assertEqual(list(got), list(want), "sections of the golden file")
        for name, text in got.items():
            with self.subTest(section=name):
                self.assertEqual(text, want[name])


class Holds1004Tests(T.GateEnv):
    """The 10.4-visible HOLDs of the full5 agent store handling (review gate1010), pinned word for word: a 2026.9.9
    state (19/24) under the 2026.10.4 runtime (20/24) with a store below the target that is neither configured nor
    registered, or a configured agent whose store a retained deletion keeps."""
    maxDiff = None
    CFG = {"meta": {"lastTouchedVersion": "2026.9.9"}, "gateway": {"mode": "local"},
           "agents": {"list": [{"id": "main", "default": True}]}}
    GHOST = "agents/ghost/agent/openclaw-agent.sqlite"
    # rehearsal D11: 2026.10.4 doctor (like 2026.10.10 and 2026.11.1, state-migrations.agent-owner-recovery.ts) does
    # not migrate a store that records another agent as its owner; it sets a byte-identical copy aside as
    # <file>.corrupt-<time> and refuses any other, so the text no longer promises the one-way migration for every store.
    # Review 11.1 (regress-docs): the refusal stops doctor after the other databases are migrated
    # (DoctorStateMigrationRefusalError -> the hard doctor-migration-refused), so the text says so and advises moving
    # such a folder away instead of accepting; a store that records another agent is named with that owner.
    ORPHAN_TAIL = ("Doctor of OpenClaw 2026.10.4 finds such a store under agents/ and, unless its deletion history holds "
                   "it back, migrates it one-way to schema 24; a store that records another agent as its owner is not "
                   "migrated: doctor moves it aside as <file>.corrupt-<time> only when it and its -wal/-shm files are "
                   "byte-identical to that agent's database (a plaintext copy that is kept), and otherwise refuses "
                   "it, which stops doctor after the other databases are migrated (hard HOLD "
                   "doctor-migration-refused): move such a folder out of agents/ instead of accepting. The gateway "
                   "does not open it. The gate checks that it is readable (quick_check, foreign keys) but not its "
                   "schema afterwards; what doctor did is in the gate's final lines and oc-upgrade status")
    ORPHAN = ("agent database(s) of agents that are neither configured nor registered: " + GHOST + " (schema 20). "
              + ORPHAN_TAIL)

    def setUp(self):
        super().setUp()
        self.set_runtime("2026.10.4", 20, 24)
        self.features(cron_refusal=False, cron_doctor_migration=False, retires_skill_proposals=False)
        T.make_1004_state(self.state, s=19, a=24, app="2026.9.9")
        self.write_cfg(self.CFG)
        (self.upg / "gate").mkdir(parents=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.9", "mode": "from-7x"}))
        self.hooks()

    def hold(self):
        """(codes, acceptable, reason/next lines of hold.txt) of a precheck HOLD before the first write."""
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["phase"], j.get("first_write_at")), ("precheck", None))
        text = (self.upg / "hold.txt").read_text(encoding="utf-8")
        return (j["hold"]["codes"], j["hold"]["acceptable"],
                [ln for ln in text.splitlines() if ln.startswith(("Reason ", "Next: ", "Accept "))])

    def test_orphan_store_below_the_target(self):
        T.make_1004_agent_db(self.state, "ghost", uv=20, app="2026.9.9")
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 20)
        self.assertIn("quick_check ok (3/3); foreign keys ok (3/3)", "\n".join(lines))  # the orphan is checked too
        self.assertEqual(self.hold(), (["orphan-agent-db"], True, [
            "Reason [orphan-agent-db]: " + self.ORPHAN,
            "Next: move agent folders you no longer need out of /config/.openclaw/agents (they are in your encrypted "
            "backup), then oc-upgrade retry, or accept: oc-upgrade retry --accept orphan-agent-db (then restart the "
            "add-on)",
            "Accept (only if you understand the consequence): oc-upgrade retry --accept orphan-agent-db"]))

    def test_orphan_store_that_records_another_agent_names_that_owner(self):
        """A copied agent folder: agents/copy holds a store whose schema_meta names agent main. Doctor sets it aside only
        as a byte-identical copy of main's database and otherwise refuses it, which stops doctor after the other
        databases are migrated: the reason names the recorded owner (read-only) so the owner moves the folder away. A
        store that records its own id (also in another letter case, as OpenClaw normalises ids) is not flagged."""
        T.make_1004_agent_db(self.state, "ghost", uv=20, app="2026.9.9")
        T.make_1004_agent_db(self.state, "copy", uv=20, app="2026.9.9")
        T.make_1004_agent_db(self.state, "Upper", uv=20, app="2026.9.9")
        for aid, owner in (("copy", "main"), ("Upper", "upper")):
            con = sqlite3.connect(str(self.state / f"agents/{aid}/agent/openclaw-agent.sqlite"))
            con.execute("UPDATE schema_meta SET agent_id=? WHERE meta_key='primary'", (owner,))
            con.commit()
            con.close()
        before = {p.name: p.read_bytes() for p in (self.state / "agents" / "copy" / "agent").iterdir()}
        codes, acceptable, lines = self.hold()
        self.assertEqual((codes, acceptable), (["orphan-agent-db"], True))
        self.assertEqual(lines[0], "Reason [orphan-agent-db]: agent database(s) of agents that are neither configured "
                         "nor registered: agents/Upper/agent/openclaw-agent.sqlite (schema 20), "
                         "agents/copy/agent/openclaw-agent.sqlite (schema 20; records agent main as its owner), "
                         + self.GHOST + " (schema 20). " + self.ORPHAN_TAIL)
        self.assertEqual({p.name: p.read_bytes() for p in (self.state / "agents" / "copy" / "agent").iterdir()},
                         before)  # read-only: no -wal/-shm left behind, nothing changed

    def test_damaged_orphan_store_is_hard(self):
        T.make_1004_agent_db(self.state, "ghost", uv=20, app="2026.9.9")
        con = sqlite3.connect(str(self.state / self.GHOST))  # a row that breaks a foreign key (foreign keys off)
        con.execute("INSERT INTO board_tabs (session_key, tab_id, title, position, created_by, revision) "
                    "VALUES ('agent:main:gone', 't1', 'Tab', 0, 'user', 0)")
        con.commit()
        con.close()
        codes, acceptable, lines = self.hold()
        self.assertEqual((codes, acceptable), (["sqlite-fk-violation", "orphan-agent-db"], False))
        self.assertEqual(lines[:2], [
            "Reason [sqlite-fk-violation]: " + self.GHOST + " (agent schema 20, OpenClaw 2026.10.4 migrates it to "
            "24): 1 foreign-key violation(s): board_tabs row 1 -> session_nodes. OpenClaw checks foreign keys at the "
            "end of this one-way migration and stops it ('Agent schema migration failed foreign key validation') "
            "while other databases are already migrated",
            "Reason [orphan-agent-db]: " + self.ORPHAN])

    def test_configured_agent_whose_store_a_retained_deletion_keeps(self):
        T.make_1004_agent_db(self.state, "old", uv=20, app="2026.9.9")
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute("INSERT INTO agent_databases VALUES ('old', 'agents/old/agent/openclaw-agent.sqlite', 20, 0, NULL)")
        con.execute("INSERT INTO agent_deletion_journal (agent_id, agent_dir, workspace_dir, sessions_dir, created_at, "
                    "cleanup_completed, delete_files) VALUES ('old', ?, '/w', '/s', 0, 1, 0)",
                    (str(self.state / "agents" / "old" / "agent"),))
        con.commit()
        con.close()
        self.write_cfg(dict(self.CFG, agents={"list": [{"id": "main", "default": True}, {"id": "old"}]}))
        self.assertEqual(self.hold(), (["agent-db-held"], False, [
            "Reason [agent-db-held]: agent old is configured, but OpenClaw keeps its database "
            "agents/old/agent/openclaw-agent.sqlite (schema 20) from a deletion (deletion journal): doctor will not "
            "migrate it and OpenClaw 2026.10.4 refuses the agent (the default agent: the gateway does not start or "
            "stays not ready)",
            "Next: remove the agent from openclaw.json (agents.list) if you no longer use it, then oc-upgrade retry; "
            "to keep it, restore the encrypted Home Assistant backup of the previous add-on version, run openclaw "
            "agents add <id> --workspace <ws> --agent-dir <dir> --non-interactive there, then update again (then "
            "restart the add-on)"]))


if __name__ == "__main__":
    unittest.main()
