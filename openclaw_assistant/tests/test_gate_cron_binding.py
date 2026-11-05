"""Cron inference accounts on OpenClaw 2026.10.10 / 2026.11.1 (full5 prep; openclaw/openclaw#192195; REPORT ONLY).

These runtimes refuse a cron agent turn that has no recorded inference account as soon as a candidate model would run
on a stored auth profile, and the refusal stops the fallback chain. OpenClaw's own doctor migration (#172792) comes
with 2026.11.5. The gate only reports (precheck 11c WARN lines, a postconditions summary bit, finalize WARN lines,
`oc-upgrade status`, the dry-run/`oc-upgrade check` readiness line); it never holds and never writes into OpenClaw's
databases or auth stores. codex_cron_ids/F15 keep reading only the 7.x columns.

Also the read-only precheck info 11d for openclaw/openclaw#191847 (largest agent database, biggest session).
Synthetic 10.4-shaped fixtures only (tests/fixtures/openclaw-*-schema-2026.10.4.sql).
"""

import hashlib
import json
import os
import sqlite3
import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
for _p in (str(ADDON), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_common as C  # noqa: E402
import oc_gate as G  # noqa: E402
import test_gate as T  # noqa: E402

PROMPT = "SYNTHETIC-PROMPT-TEXT"
CFG = {"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local"},
       "agents": {"defaults": {"model": {"primary": "vllm/qwen3.5-122b",
                                         "fallbacks": ["openai/gpt-5.5", "google/gemini-3-pro"]}},
                  "list": [{"id": "main", "default": True}]},
       "models": {"providers": {"vllm": {"baseUrl": "http://127.0.0.1:8000/v1"}}}}
# job-morning (openai/gpt-5.5 primary, anthropic fallback) and job-local (default chain) come from T.CRON_1004_JOBS
EXTRA_JOBS = [
    ("job-bound", {"agentId": "main", "sessionTarget": "isolated",
                   "inferenceBinding": {"version": 1, "provider": "openai", "profileId": "openai:default",
                                        "authorizationId": "a" * 64, "authRequirement": "subscription",
                                        "source": "user"},
                   "payload": {"kind": "agentTurn", "message": PROMPT, "model": "openai/gpt-5.5"}}),
    ("job-keyed", {"agentId": "main", "sessionTarget": "isolated",
                   "payload": {"kind": "agentTurn", "message": PROMPT, "model": "vllm/qwen3.5-122b", "fallbacks": []}}),
    ("job-paused", {"agentId": "main", "sessionTarget": "isolated", "enabled": False,
                    "payload": {"kind": "agentTurn", "message": PROMPT, "model": "openai/gpt-5.5"}}),
]


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest() if Path(p).exists() else None


def add_jobs(state, jobs, start=10):
    con = sqlite3.connect(str(state / "state" / "openclaw.sqlite"))
    for i, (jid, job) in enumerate(jobs):
        job = dict({"id": jid, "name": jid.replace("-", " ").title(), "enabled": True,
                    "schedule": {"kind": "cron", "expr": "0 6 * * *"}}, **job)
        con.execute("INSERT INTO cron_jobs (store_key, job_id, name, enabled, agent_id, payload_kind, job_json, "
                    "sort_order, updated_at) VALUES ('default', ?, ?, ?, ?, ?, ?, ?, 0)",
                    (jid, job["name"], int(job["enabled"]), job.get("agentId"), job["payload"]["kind"],
                     json.dumps(job), start + i))
    con.commit()
    con.close()


class CronForecastGateTests(T.GateEnv):
    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, content=True)
        add_jobs(self.state, EXTRA_JOBS)
        self.write_cfg(CFG)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.10.10", 22, 27)
        self.hooks()
        self.sdb = self.state / "state" / "openclaw.sqlite"
        self.adb = self.state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"

    def cron_lines(self, text):
        return [ln for ln in text.splitlines() if "cron job" in ln or "cron inference" in ln]

    def test_dry_run_forecast_is_read_only(self):
        before = {p: sha(p) for p in (self.sdb, self.adb)}
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        text = "\n".join(lines)
        self.assertEqual({p: sha(p) for p in (self.sdb, self.adb)}, before)
        for p in (self.sdb, self.adb):
            self.assertFalse(os.path.exists(f"{p}-wal"))
        cl = self.cron_lines(text)
        self.assertEqual(cl, [
            "WARN [gate] cron job 'Morning summary' (job-morning): OpenClaw 2026.10.10 refuses every run and tries "
            "no fallback: its model openai/gpt-5.5 would use a stored login (auth profile) and the job has no recorded "
            "inference account (openclaw/openclaw#192195); also on a stored login: anthropic/claude-sonnet-4-6",
            "WARN [gate] cron job 'Local digest' (job-local): its model vllm/qwen3.5-122b needs no stored login and "
            "keeps working, but when it fails OpenClaw 2026.10.10 stops at the fallback openai/gpt-5.5 (stored login, "
            "no recorded inference account; openclaw/openclaw#192195) instead of trying further models",
            "WARN [gate] 2 cron job(s) above: the add-on changes nothing; OpenClaw records the inference account of "
            "such jobs itself from 2026.11.5 (doctor migration, openclaw/openclaw#172792). " + G.CRON_MANUAL,
            "[gate]   cron inference accounts: 2 enabled cron job(s) stop at a stored login on OpenClaw 2026.10.10 "
            "(the WARN lines above, openclaw/openclaw#192195); report only, the gate changes nothing"])
        self.assertIn("openclaw automations edit <id> --model <provider/model>@<profileId>", G.CRON_MANUAL)
        self.assertIn("openclaw/openclaw#192463", G.CRON_MANUAL)
        # report only: never a HOLD code
        self.assertIn("[gate] dry-run: the precheck would pass", text)
        # id + name + model refs only: no prompt, no profile id, no credential
        for bad in (PROMPT, "SECRET", "openai:default", "anthropic:default"):
            self.assertFalse([ln for ln in cl if bad in ln], bad)

    def test_aws_sdk_jobs_name_their_credentials_and_a_remedy_that_applies(self):
        """Recheck: a model on AWS SDK credentials (auth "aws-sdk") is refused too, but it is no stored login and
        model@<profileId> cannot record it (nor can OpenClaw's own migration): the lines say AWS SDK credentials and
        give the configured-key model as the way out; the @<profileId> alternative only where a stored login is."""
        cfg = json.loads(json.dumps(CFG))
        cfg["models"]["providers"]["amazon-bedrock"] = {"auth": "aws-sdk"}
        self.write_cfg(cfg)
        add_jobs(self.state, [
            ("job-bedrock", {"agentId": "main", "sessionTarget": "isolated",
                             "payload": {"kind": "agentTurn", "message": PROMPT, "model": "amazon-bedrock/claude-x",
                                         "fallbacks": []}}),
            ("job-bedrock-fb", {"agentId": "main", "sessionTarget": "isolated",
                                "payload": {"kind": "agentTurn", "message": PROMPT,
                                            "fallbacks": ["amazon-bedrock/claude-x", "openai/gpt-5.5"]}})], start=50)
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        cl = self.cron_lines("\n".join(lines))
        self.assertEqual(cl[2:], [
            "WARN [gate] cron job 'Job Bedrock' (job-bedrock): OpenClaw 2026.10.10 refuses every run and tries no "
            "fallback: its model amazon-bedrock/claude-x would run on AWS SDK credentials "
            "(models.providers.amazon-bedrock.auth \"aws-sdk\"), which OpenClaw refuses for a cron job without a "
            "recorded inference account (openclaw/openclaw#192195)",
            "WARN [gate] cron job 'Job Bedrock Fb' (job-bedrock-fb): its model vllm/qwen3.5-122b needs no stored login "
            "and keeps working, but when it fails OpenClaw 2026.10.10 stops at the fallback amazon-bedrock/claude-x "
            "(AWS SDK credentials, no recorded inference account; openclaw/openclaw#192195) instead of trying further "
            "models; also on a stored login: openai/gpt-5.5",
            "WARN [gate] 4 cron job(s) above: the add-on changes nothing; OpenClaw records the inference account of a "
            "stored login itself from 2026.11.5 (doctor migration, openclaw/openclaw#172792). " + G.CRON_MANUAL + ". "
            + G.CRON_AWS_SDK,
            "[gate]   cron inference accounts: 4 enabled cron job(s) stop at a stored login or AWS SDK credentials on "
            "OpenClaw 2026.10.10 (the WARN lines above, openclaw/openclaw#192195); report only, the gate changes "
            "nothing"])
        self.assertIn("openclaw automations edit <id> --model <provider/model> (for a fallback: --fallbacks <list> "
                      "without it)", G.CRON_AWS_SDK)
        self.assertNotIn("@<profileId>", G.CRON_AWS_SDK)
        # the recheck's setup: no auth profile at all, so only the AWS SDK jobs are affected; no @<profileId> remedy
        con = sqlite3.connect(str(self.adb))
        con.execute("DELETE FROM auth_profile_store")
        con.commit()
        con.close()
        rec = G.cron_account_report(self.state, cfg, "2026.10.10")
        self.assertEqual([(a["id"], a["refs"], a["aws_sdk"]) for a in rec["affected"]],
                         [("job-bedrock", ["amazon-bedrock/claude-x"], ["amazon-bedrock/claude-x"]),
                          ("job-bedrock-fb", ["amazon-bedrock/claude-x"], ["amazon-bedrock/claude-x"])])
        lines = G.cron_job_lines(rec)
        self.assertEqual(lines[-1], "2 cron job(s) above: the add-on changes nothing. " + G.CRON_AWS_SDK)
        self.assertEqual(G.cron_job_lines(dict(rec, doctor_migration=True))[-1],
                         "2 cron job(s) above still have no recorded inference account after the migration: OpenClaw "
                         "2026.10.10 doctor left them (its warnings are in oc-upgrade log). " + G.CRON_AWS_SDK)
        st = G._status_cron({"cron_binding": rec})
        self.assertEqual(st[1:], [
            "    'Job Bedrock' (job-bedrock): every run refused; amazon-bedrock/claude-x (AWS SDK credentials)",
            "    'Job Bedrock Fb' (job-bedrock-fb): stops at the fallback amazon-bedrock/claude-x; "
            "amazon-bedrock/claude-x (AWS SDK credentials)",
            "    " + G.CRON_AWS_SDK])
        for ln in lines + st:
            self.assertNotIn("stored login (auth profile)", ln)
            self.assertNotIn("@<profileId>", ln)
        # a runtime whose doctor records the accounts does so only for a stored login
        self.set_runtime("2026.11.5-beta.1", 22, 27)
        text = self.quiet_dry()
        self.assertIn("[gate] 1/8 info: 2 enabled cron job(s) without a recorded inference account use AWS SDK "
                      "credentials; OpenClaw 2026.11.5-beta.1 doctor records the account of a stored login, not of "
                      "AWS SDK credentials (openclaw/openclaw#172792); the gate reports the jobs it leaves after the "
                      "migration", text)
        self.assertIn("[gate]   cron inference accounts: 2 enabled cron job(s) use AWS SDK credentials without a "
                      "recorded account; OpenClaw 2026.11.5-beta.1 doctor records it for a stored login, not for AWS "
                      "SDK credentials (openclaw/openclaw#172792)", text)

    def test_bump_reports_in_precheck_finalize_and_status(self):
        before = {p: sha(p) for p in (self.sdb, self.adb)}
        self.assertEqual(self.run_gate(), 0, self.out)
        out = self.out.splitlines()
        warns = [i for i, ln in enumerate(out) if ln.startswith("WARN [gate] cron job 'Morning summary'")]
        self.assertEqual(len(warns), 2, self.out)  # precheck and finalize
        pre = next(i for i, ln in enumerate(out) if ln.startswith("[gate] 1/8 precheck:"))
        done = next(i for i, ln in enumerate(out) if ln.startswith("[gate] done: MIGRATED"))
        sw = next(i for i, ln in enumerate(out) if ln.startswith("[gate] info: Skill Workshop export"))
        self.assertLess(warns[0], pre)
        self.assertLess(sw, warns[1])
        self.assertLess(warns[1], done)
        pc = next(ln for ln in out if ln.startswith("[gate] 7/8 postconditions OK:"))
        self.assertIn("config valid, 2 cron job(s) without a recorded inference account (report below), lint", pc)
        j = self.journal()
        self.assertEqual(j["status"], "done")
        fc, rec = j["cron_binding_forecast"], j["cron_binding"]
        self.assertEqual((fc["runtime"], fc["checked"], fc["bound"], fc["doctor_migration"]),
                         ("2026.10.10", 3, 1, False))
        self.assertEqual([a["id"] for a in rec["affected"]], ["job-morning", "job-local"])
        self.assertEqual(rec["affected"][1], {"id": "job-local", "name": "Local digest", "agent": "main",
                                              "primary": "vllm/qwen3.5-122b", "primary_affected": False,
                                              "refs": ["openai/gpt-5.5"]})
        self.assertNotIn(PROMPT, json.dumps(j))
        # F15 stays 7.x-only (critic): 10.x job_json on openai/ does not mark Codex as in use
        self.assertEqual((j["cron_legacy_ids"], j["cron_openai_ids"]), ([], []))
        # the gate wrote nothing into the cron jobs (doctor's scripted migration only bumps schema versions)
        rows = C.query_ro(self.sdb, "SELECT job_id, job_json FROM cron_jobs ORDER BY job_id")
        self.assertTrue(all("inferenceBinding" not in r[1] for r in rows if r[0] != "job-bound"))
        self.assertNotEqual(sha(self.sdb), before[self.sdb])  # the fake doctor migrated it
        st = G.status_lines()
        i = next(i for i, x in enumerate(st) if x.startswith("  cron jobs without a recorded inference account"))
        self.assertEqual(st[i:i + 4], [
            "  cron jobs without a recorded inference account (openclaw/openclaw#192195, OpenClaw 2026.10.10, after "
            "the migration): 2 affected of 3 checked",
            "    'Morning summary' (job-morning): every run refused; openai/gpt-5.5, anthropic/claude-sonnet-4-6",
            "    'Local digest' (job-local): stops at the fallback openai/gpt-5.5; openai/gpt-5.5",
            "    OpenClaw records the account itself from 2026.11.5 (openclaw/openclaw#172792). " + G.CRON_MANUAL])
        self.assertLess(i, next(k for k, x in enumerate(st) if x.startswith("Migrated marker")))
        # a later maintenance run reports again from the migrated state
        G.retry_cmd(["--doctor"], emit=lambda s: None)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual(len([ln for ln in self.out.splitlines()
                              if ln.startswith("WARN [gate] cron job 'Local digest'")]), 2, self.out)

    def test_postconditions_read_the_migrated_jobs(self):
        # doctor binds one job and moves the other to a local model: only what is left is reported afterwards
        bound = {"version": 1, "provider": "openai", "profileId": "openai:default", "authorizationId": "b" * 64,
                 "authRequirement": "subscription", "source": "auto"}
        self.doctor_script(state_uv=22, agent_uv=27, app_version="2026.10.10", sql=[
            "UPDATE cron_jobs SET job_json=json_set(job_json, '$.inferenceBinding', json('%s')) "
            "WHERE job_id='job-morning'" % json.dumps(bound)])
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertEqual([a["id"] for a in j["cron_binding_forecast"]["affected"]], ["job-morning", "job-local"])
        self.assertEqual([a["id"] for a in j["cron_binding"]["affected"]], ["job-local"])
        self.assertEqual(j["cron_binding"]["bound"], 2)
        fin = self.out[self.out.index("[gate] 7/8 postconditions OK"):]
        self.assertNotIn("'Morning summary'", fin)
        self.assertIn("WARN [gate] 1 cron job(s) above:", fin)

    def test_status_lines_without_affected_jobs(self):
        rec = {"runtime": "2026.10.10", "checked": 3, "bound": 1, "affected": []}
        self.assertEqual(G._status_cron({"cron_binding": rec}), [
            "  cron jobs without a recorded inference account (openclaw/openclaw#192195, OpenClaw 2026.10.10, after "
            "the migration): none affected (3 checked)"])
        self.assertEqual(G._status_cron({"cron_binding_forecast": dict(rec, checked=0)}), [])  # no cron jobs at all
        self.assertEqual(G._status_cron({}), [])
        self.assertEqual(G.cron_job_lines(rec), [])

    def test_shared_state_db_store_and_declared_profiles(self):
        # the main agent's store is empty; the accounts live in the state DB's shared store (auth.sharedStore)
        con = sqlite3.connect(str(self.adb))
        con.execute("DELETE FROM auth_profile_store")
        con.commit()
        con.close()
        rec = G.cron_account_report(self.state, CFG, "2026.10.10")
        self.assertEqual(rec["affected"], [])
        con = sqlite3.connect(str(self.sdb))
        con.execute("INSERT INTO config_machine_state VALUES ('auth.sharedStore', ?, 0)",
                    (json.dumps({"location": "state-db"}),))
        con.execute("INSERT INTO config_machine_state VALUES ('authProfiles.store', ?, 0)",
                    (json.dumps(T.AUTH_1004_STORE),))
        con.commit()
        con.close()
        rec = G.cron_account_report(self.state, CFG, "2026.10.10")
        self.assertEqual([a["id"] for a in rec["affected"]], ["job-morning", "job-local"])
        # a profile declared in auth.profiles of openclaw.json counts too (google here)
        con = sqlite3.connect(str(self.sdb))
        con.execute("DELETE FROM config_machine_state WHERE state_key LIKE 'auth%'")
        con.commit()
        con.close()
        cfg = json.loads(json.dumps(CFG))
        cfg["auth"] = {"profiles": {"google:work": {"provider": "google", "mode": "api_key"}}}
        rec = G.cron_account_report(self.state, cfg, "2026.10.10")
        self.assertEqual([(a["id"], a["refs"]) for a in rec["affected"]], [("job-local", ["google/gemini-3-pro"])])
        # a non-main agent inherits the shared store (legacy-main: the main agent's database)
        add_jobs(self.state, [("job-mail", {"agentId": "mail", "sessionTarget": "isolated",
                                            "payload": {"kind": "agentTurn", "message": PROMPT,
                                                        "model": "anthropic/claude-sonnet-4-6"}})], start=50)
        con = sqlite3.connect(str(self.adb))
        con.execute("INSERT INTO auth_profile_store VALUES ('primary', ?, 0)", (json.dumps(T.AUTH_1004_STORE),))
        con.commit()
        con.close()
        rec = G.cron_account_report(self.state, CFG, "2026.10.10")
        self.assertIn(("job-mail", "mail", True), [(a["id"], a["agent"], a["primary_affected"])
                                                   for a in rec["affected"]])

    def test_runtime_authority_and_7x_layout_are_skipped(self):
        con = sqlite3.connect(str(self.sdb))
        con.execute("INSERT INTO cron_job_runtime_authorities VALUES ('default', 'job-morning', '{}', 'fp', 0)")
        con.commit()
        con.close()
        rec = G.cron_account_report(self.state, CFG, "2026.10.10")
        self.assertEqual([a["id"] for a in rec["affected"]], ["job-local"])
        inv = G.cron_jobs_inventory(self.sdb)
        self.assertEqual(len(inv), len(T.CRON_1004_JOBS) + len(EXTRA_JOBS))
        self.assertNotIn(PROMPT, json.dumps(inv))
        self.assertNotIn("synthetic prompt", json.dumps(inv))
        # the 7.x wide-row layout (payload_model columns) is reported only after the migration
        db = self.tmp / "s7.sqlite"
        con = sqlite3.connect(str(db))
        con.execute("CREATE TABLE cron_jobs (store_key TEXT, job_id TEXT, name TEXT, enabled INTEGER, "
                    "payload_model TEXT, job_json TEXT)")
        con.execute("INSERT INTO cron_jobs VALUES ('default', 'j', 'J', 1, 'openai/gpt-5.5', '{}')")
        con.commit()
        con.close()
        self.assertEqual(G.cron_jobs_inventory(db), [])
        self.assertEqual(G.cron_jobs_inventory(self.tmp / "missing.sqlite"), [])

    def test_doctor_migration_runtime_reports_only_what_doctor_leaves(self):
        self.set_runtime("2026.11.5-beta.1", 22, 27)
        self.assertEqual(self.run_gate(), 0, self.out)
        out = self.out
        pre = out[:out.index("[gate] 1/8 precheck:")]
        self.assertIn("[gate] 1/8 info: 2 enabled cron job(s) without a recorded inference account use a stored "
                      "login; OpenClaw 2026.11.5-beta.1 doctor records the account (openclaw/openclaw#172792)", pre)
        self.assertNotIn("WARN [gate] cron job", pre)
        fin = out[out.index("[gate] 7/8 postconditions OK"):]
        self.assertIn("WARN [gate] cron job 'Morning summary' (job-morning)", fin)  # the fake doctor binds nothing
        self.assertIn("WARN [gate] 2 cron job(s) above still have no recorded inference account after the migration: "
                      "OpenClaw 2026.11.5-beta.1 doctor left them", fin)
        self.assertTrue(self.journal()["cron_binding"]["doctor_migration"])

    def test_features_record_switches_the_report_on(self):
        # an image whose dist grep found the refusal (e.g. a backport) reports on that version too
        self.set_runtime("2026.10.9", 22, 27)
        self.assertFalse(self.cron_lines(self.quiet_dry()))
        self.features(cron_refusal=True)
        self.assertTrue([ln for ln in self.cron_lines(self.quiet_dry()) if ln.startswith("WARN [gate] cron job")])

    def quiet_dry(self):
        lines = []
        self.quiet(G.dry_run, emit=lines.append)
        return "\n".join(lines)

    def test_no_report_and_no_journal_keys_on_1004(self):
        self.set_runtime("2026.10.4", 20, 24)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.9", "mode": "bump"}))
        con = sqlite3.connect(str(self.sdb))
        con.execute("PRAGMA user_version=19")
        con.execute("UPDATE schema_meta SET schema_version=19, app_version='2026.9.9' WHERE meta_key='primary'")
        con.commit()
        con.close()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertFalse(self.cron_lines(self.out), self.out)
        self.assertNotIn("openclaw/openclaw#191847", self.out)
        j = self.journal()
        self.assertNotIn("cron_binding", j)
        self.assertNotIn("cron_binding_forecast", j)
        self.assertEqual(G._status_cron(j), [])

    def test_never_holds_when_the_check_fails(self):
        con = sqlite3.connect(str(self.sdb))
        con.execute("UPDATE cron_jobs SET job_json='not json' WHERE job_id='job-local'")
        con.commit()
        con.close()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual([a["id"] for a in self.journal()["cron_binding"]["affected"]], ["job-morning"])
        orig = G.cron_account_report

        def broken(*a, **kw):
            raise sqlite3.DatabaseError("synthetic read failure")
        G.cron_account_report = broken
        try:
            G.retry_cmd(["--doctor"], emit=lambda s: None)
            self.assertEqual(self.run_gate(), 0, self.out)
        finally:
            G.cron_account_report = orig
        self.assertIn("WARN [gate] 7/8 could not check the cron jobs for their inference account (DatabaseError: "
                      "synthetic read failure)", self.out)


class LargeSessionInfoTests(T.GateEnv):
    """openclaw/openclaw#191847 (open issue): the precheck states the largest agent database and the biggest
    session's transcript event count, read-only, from 2026.10.10 on."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, agents=("main", "ops"))
        self.write_cfg({"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local"},
                        "agents": {"list": [{"id": "main", "default": True}, {"id": "ops"}]}})
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.sessions("ops", [("s-small", 3, "telegram", "group")])
        self.sessions("main", [("s-big", 7, "telegram", "direct"), ("s-mid", 5, None, None)])
        self.hooks()

    def sessions(self, aid, spec):
        con = sqlite3.connect(str(self.state / "agents" / aid / "agent" / "openclaw-agent.sqlite"))
        for sid, n, channel, chat in spec:
            key = f"agent:{aid}:{sid}"
            con.execute("INSERT INTO session_nodes (session_key, current_session_id, entry_json, updated_at) "
                        "VALUES (?, ?, '{}', 0)", (key, sid))
            con.execute("INSERT INTO session_windows (session_id, session_key, created_at, updated_at, channel, "
                        "chat_type) VALUES (?, ?, 0, 0, ?, ?)", (sid, key, channel, chat))
            for seq in range(n):
                con.execute("INSERT INTO transcript_events (session_id, seq, event_json, created_at) "
                            "VALUES (?, ?, ?, 0)", (sid, seq, json.dumps({"text": PROMPT})))
        con.commit()
        con.close()

    def test_info_line_on_1010_only(self):
        adb = self.state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"
        (Path(f"{adb}-wal")).write_bytes(b"\0" * 4096 * 64)  # counted with the database
        ls = G.largest_sessions(self.state, {"agents": {"list": [{"id": "main"}, {"id": "ops"}]}})
        self.assertEqual(ls["session"], {"agent": "main", "events": 7, "channel": "telegram", "chat_type": "direct"})
        self.assertEqual(ls["db"]["path"], "agents/main/agent/openclaw-agent.sqlite")
        self.assertEqual(ls["db"]["bytes"], adb.stat().st_size + 4096 * 64)
        os.unlink(f"{adb}-wal")
        before = sha(adb)
        self.set_runtime("2026.10.10", 22, 27)
        lines = []
        self.quiet(G.dry_run, emit=lines.append)
        info = [ln for ln in lines if "openclaw/openclaw#191847" in ln]
        self.assertEqual(len(info), 1, "\n".join(lines))
        self.assertRegex(info[0], r"^\[gate\] 1/8 info: largest agent database agents/(main|ops)/agent/"
                                  r"openclaw-agent\.sqlite \([0-9.]+ KiB with WAL\); biggest session: 7 "
                                  r"transcript events \(agent main, telegram, direct\)\. An open OpenClaw issue "
                                  r"reports the 512 MB SQLite worker of OpenClaw 2026\.10\.10 running out of memory "
                                  r"on large Telegram direct-chat sessions \(openclaw/openclaw#191847\)$")
        self.assertNotIn(PROMPT, "\n".join(lines))
        self.assertNotIn("s-big", info[0])  # no session ids or keys
        self.assertEqual(sha(adb), before)
        # the 2026.10.4 target prints nothing new
        self.set_runtime("2026.10.4", 20, 24)
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute("PRAGMA user_version=19")
        con.commit()
        con.close()
        lines = []
        self.quiet(G.dry_run, emit=lines.append)
        self.assertFalse([ln for ln in lines if "191847" in ln], "\n".join(lines))

    def test_gate_run_passes_and_records_nothing_new(self):
        self.set_runtime("2026.10.10", 22, 27)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual(len([ln for ln in self.out.splitlines() if "openclaw/openclaw#191847" in ln]), 1, self.out)
        self.assertNotIn("large_session", json.dumps(self.journal()))
        # no agent database: no line
        self.assertIsNone(G.largest_sessions(self.tmp / "nothing", {}))


if __name__ == "__main__":
    unittest.main()
