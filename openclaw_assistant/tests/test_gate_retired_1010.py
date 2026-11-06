"""Gate-level tests: retired runtime files and retired config keys on the OpenClaw 2026.10.10 line (full5 prep).

OpenClaw 2026.10.5+ refuses pre-July-2026 runtime files 2026.10.4 still imported (ACP replay ledger, Voice Wake
settings, conversation bindings, plugin-binding approvals, restart sentinel, sandbox registries) and the
"openai-codex-responses" API id / extension cdpUrl settings; 2026.10.6+ tolerates an empty plugins.installs.
The gate quarantines a file only with proof that OpenClaw imported it (or when 2026.10.4 would import nothing),
holds otherwise, and leaves everything as before on the 2026.10.4 target (oc_common.runtime_caps).
"""

import hashlib
import json
import shutil
import sqlite3
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

LEDGER = {"version": 1, "sessions": {"s1": {
    "sessionId": "s1", "sessionKey": "agent:main:acp", "cwd": "/config/clawd", "complete": True, "createdAt": 1000,
    "updatedAt": 2000, "nextSeq": 2, "events": [{"seq": 1, "at": 1100, "sessionId": "s1", "sessionKey": "agent:main:acp",
                                                 "update": {"sessionUpdate": "agent_message_chunk"}}]}}}
SENTINEL = '{"version":1,"payload":{"kind":"restart","ts":1}}'
SANDBOX_WARNING = ("doctor:sandbox run failed: Sandbox registries: retired files whose last writer predates July 1, "
                   "2026: /config/.openclaw/sandbox/containers.json. The files were left unchanged.")


class RetiredGate1010Tests(T.GateEnv):
    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state)
        self.cfg = {"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local"},
                    "agents": {"list": [{"id": "main", "default": True}]}}
        self.write_cfg(self.cfg)
        (self.upg / "gate").mkdir(parents=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.10.10", 22, 27)
        self.hooks()

    def sql(self, statement, params=()):
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute(statement, params)
        con.commit()
        con.close()

    def write(self, rel, text):
        p = self.state / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        return p

    def imported_ledger(self):
        self.sql("INSERT INTO acp_replay_sessions (session_id, session_key, cwd, complete, created_at, updated_at, "
                 "next_seq) VALUES ('s1', 'agent:main:acp', '/config/clawd', 1, 1000, 2000, 2)")
        self.sql("INSERT INTO acp_replay_events (session_id, seq, at, session_key, run_id, update_json) VALUES "
                 "('s1', 1, 1100, 'agent:main:acp', NULL, ?)", (json.dumps({"sessionUpdate": "agent_message_chunk"}),))
        return self.write("acp/event-ledger.json", json.dumps(LEDGER))

    def state_for_104(self):
        """A state 2026.10.4 still has to migrate (2026.9.9 -> runtime 2026.10.4)."""
        shutil.rmtree(self.state / "state")
        shutil.rmtree(self.state / "agents")
        T.make_1004_state(self.state, s=19, a=24, app="2026.9.9")
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.9", "mode": "from-7x"}))
        self.set_runtime("2026.10.4", 20, 24)

    def manifest(self):
        return json.loads(next((self.upg / "gate" / "quarantine").glob("*/MANIFEST.json")).read_text())

    def test_bump_1010_retired_runtime_files_hold_then_accept(self):
        ledger = self.imported_ledger()
        sentinel = self.write("restart-sentinel.json", SENTINEL)  # no migration receipt for these bytes
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["codes"], j["phase"]), (["restart-sentinel-unimported"], "precheck"))
        self.assertIsNone(j.get("first_write_at"))
        self.assertTrue(ledger.exists() and sentinel.exists(), "nothing moved before the HOLD")
        self.assertIn("1/8 info: already imported by OpenClaw, goes to quarantine: acp/event-ledger.json "
                      "(1 session(s), 1 event(s) in acp_replay_*)", self.out)
        hold = (self.upg / "hold.txt").read_text()
        self.assertIn("restart-sentinel.json (no receipt for sha256 %s...)"
                      % hashlib.sha256(SENTINEL.encode()).hexdigest()[:12], hold)
        self.assertIn("--accept restart-sentinel-unimported", hold)
        G.retry_cmd(["--accept", "restart-sentinel-unimported"], emit=lambda s: None)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertFalse(ledger.exists() or sentinel.exists())
        man = {e["kind"]: e for e in self.manifest()}
        self.assertEqual(set(man), {"restart-sentinel-json", "acp-replay-ledger"})
        self.assertEqual(man["acp-replay-ledger"]["proof"], "1 session(s), 1 event(s) in acp_replay_*")
        self.assertNotIn("proof", man["restart-sentinel-json"])
        self.assertEqual(man["restart-sentinel-json"]["reason"], "accepted: restart-sentinel-unimported")
        self.assertIn("2/8 quarantine acp-replay-ledger: acp/event-ledger.json (", self.out)
        self.assertIn("; proof: 1 session(s), 1 event(s) in acp_replay_*)", self.out)

    def test_bump_1010_receipt_and_empty_registry_need_no_accept(self):
        sha = hashlib.sha256(SENTINEL.encode()).hexdigest()
        report = json.dumps({"source": "legacy-restart-sentinel-json", "target": "gateway_restart_sentinel",
                             "decision": "legacy-imported", "sourceSha256": sha, "sourceValid": True,
                             "importedRecordCount": 1, "preservedSqliteRecordCount": 0})
        self.sql("INSERT INTO migration_runs VALUES (?, 1, 1, 'completed', ?)",
                 ("restart-sentinel-json:%s:%s" % ("0" * 64, sha[:16]), report))
        self.write("restart-sentinel.json", SENTINEL)
        (self.state / "sandbox" / "containers").mkdir(parents=True)
        (self.state / "sandbox" / "skills-workspaces").mkdir()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("goes to quarantine: restart-sentinel.json (receipt legacy-imported)", self.out)
        self.assertIn("nothing for OpenClaw to import, goes to quarantine: sandbox/containers (nothing to import)",
                      self.out)
        man = {e["src"]: e for e in self.manifest()}
        self.assertEqual(set(man), {"restart-sentinel.json", "sandbox/containers"})
        self.assertTrue(Path(man["sandbox/containers"]["dst"]).is_dir())
        self.assertTrue((self.state / "sandbox" / "skills-workspaces").is_dir(), "live runtime path untouched")

    def test_bump_104_target_leaves_runtime_files_to_doctor(self):
        """2026.10.4 imports these files itself: no check, no move, no new line (as in 0.5.94-full4)."""
        self.state_for_104()
        self.write_cfg(dict(self.cfg, meta={"lastTouchedVersion": "2026.9.9"}))
        files = [self.write("acp/event-ledger.json", json.dumps(LEDGER)), self.write("restart-sentinel.json", SENTINEL),
                 self.write("sandbox/containers.json", "{}"), self.write("settings/voicewake.json", "{}")]
        self.doctor_script(state_uv=20, agent_uv=24, app_version="2026.10.4", print=[SANDBOX_WARNING])
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("done: MIGRATED 2026.10.4", self.out)
        self.assertTrue(all(f.exists() for f in files))
        self.assertNotIn("goes to quarantine", self.out)
        self.assertNotIn("unimported", self.out)
        self.assertNotIn("doctor-retired-warning", self.out)

    def test_doctor_sandbox_warning_holds_on_1010(self):
        """The doctor:sandbox refusal is a rc-0 warning after the migration: its own acceptable HOLD."""
        self.doctor_script(state_uv=22, agent_uv=27, app_version="2026.10.10", drop_tables=["cron_run_logs"],
                           print=[SANDBOX_WARNING])
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["codes"], j["phase"]), (["doctor-retired-warning"], "doctor1"))
        self.assertIn("doctor completed but reported pre-July-2026 files it left unchanged", self.out)
        G.retry_cmd(["--accept", "doctor-retired-warning"], emit=lambda s: None)
        self.assertEqual(self.run_gate(), 0, self.out)

    def test_bump_empty_plugins_installs_by_target(self):
        self.write_cfg(dict(self.cfg, plugins={"installs": {}}))
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("1/8 info: openclaw.json plugins.installs is an empty object; OpenClaw doctor removes it "
                      "(install records stay in SQLite)", self.out)
        # 2026.10.4 refuses any plugins.installs (a hard HOLD, as before)
        self.state_for_104()
        self.write_cfg(dict(self.cfg, meta={"lastTouchedVersion": "2026.9.9"}, plugins={"installs": {}}))
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["codes"], j["phase"]), (["config-retired-keys"], "precheck"))
        self.assertNotIn("empty object", self.out)

    def test_bump_1010_codex_responses_is_hard_hold(self):
        cfg = dict(self.cfg, models={"providers": {"openai": {"api": "openai-codex-responses", "models": []}}},
                   browser={"profiles": {"chrome": {"driver": "extension", "cdpUrl": "http://127.0.0.1:18792"}}})
        self.write_cfg(cfg)
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["codes"], j["phase"]), (["config-retired-keys"], "precheck"))
        hold = (self.upg / "hold.txt").read_text()
        self.assertIn("OpenClaw 2026.10.10 refuses", hold)
        self.assertIn('set models.providers.openai.api to "openai-chatgpt-responses"', hold)
        self.assertIn("delete browser.profiles.chrome.cdpUrl", hold)
        self.assertNotIn("--accept config-retired-keys", hold)
        self.assertEqual(json.loads((self.state / "openclaw.json").read_text()), cfg, "the gate never fixes it here")


class RetiredFrom7x1010Tests(T.GateEnv):
    def test_from7x_1010_rewrites_codex_responses_and_cdpurl(self):
        self.build_735()
        cfg = json.loads((self.state / "openclaw.json").read_text())
        cfg["models"]["providers"]["custom"] = {"baseUrl": "https://example.invalid/v1", "api": "openai-codex-responses",
                                                "models": [{"id": "m", "api": "openai-codex-responses"}]}
        cfg["browser"] = {"profiles": {"chrome": {"driver": "extension", "cdpUrl": "ws://u:pw@127.0.0.1:18792/x"}}}
        self.write_cfg(cfg)
        self.set_runtime("2026.10.10", 22, 27)
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn('3/8 pre-migrate: rewrote retired setting(s) OpenClaw 2026.10.10 refuses: '
                      'models.providers.custom.api -> "openai-chatgpt-responses"; '
                      'models.providers.custom.models[0].api -> "openai-chatgpt-responses"; '
                      'removed browser.profiles.chrome.cdpUrl (what OpenClaw 2026.10.4 doctor did)', self.out)
        self.assertNotIn("removed retired key(s)", self.out)
        final = json.loads((self.state / "openclaw.json").read_text())
        self.assertEqual(final["models"]["providers"]["custom"]["api"], "openai-chatgpt-responses")
        self.assertEqual(final["models"]["providers"]["custom"]["models"][0]["api"], "openai-chatgpt-responses")
        self.assertNotIn("cdpUrl", final["browser"]["profiles"]["chrome"])
        rd = next((self.upg / "gate" / "runs").glob("*/transform-ledger.json")).parent
        led = {e["path"]: e for e in json.loads((rd / "transform-ledger.json").read_text()) if e["step"] == "R0"}
        self.assertEqual(set(led), {"models.providers.custom.api", "models.providers.custom.models[0].api",
                                    "browser.profiles.chrome.cdpUrl"})
        self.assertEqual(led["browser.profiles.chrome.cdpUrl"]["before"], "ws://127.0.0.1:18792")
        pre = json.loads((rd / "config.pre-gate.json").read_text())
        self.assertEqual(pre["models"]["providers"]["custom"]["api"], "openai-codex-responses")
        self.assertEqual(pre["browser"]["profiles"]["chrome"]["cdpUrl"], "ws://u:pw@127.0.0.1:18792/x")
        self.assertNotIn("u:pw@", self.out)


if __name__ == "__main__":
    unittest.main()
