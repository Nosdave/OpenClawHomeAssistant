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
        cfg = json.loads(json.dumps(CFG))
        cfg["agents"]["list"].append({"id": "mail"})
        rec = G.cron_account_report(self.state, cfg, "2026.10.10")
        self.assertIn(("job-mail", "mail", True), [(a["id"], a["agent"], a["primary_affected"])
                                                   for a in rec["affected"]])
        # D6: with the agent not configured, OpenClaw cancels its runs ("cron job agent is unavailable"): left out
        rec = G.cron_account_report(self.state, CFG, "2026.10.10")
        self.assertNotIn("job-mail", [a["id"] for a in rec["affected"]])
        self.assertEqual(rec["unconfigured"], [{"id": "job-mail", "name": "Job Mail", "agent": "mail"}])

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


GLM_KEY = "sk-synthetic-glm-literal-0000"
CFG_GLM = {"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local"},
           "agents": {"defaults": {"model": {"primary": "glm/glm-5", "fallbacks": ["openai/gpt-5.5"]}},
                      "list": [{"id": "main", "default": True}, {"id": "haus"}]},
           "models": {"providers": {
               "glm": {"baseUrl": "http://127.0.0.1:8000/v1", "api": "openai-completions", "apiKey": GLM_KEY,
                       "models": [{"id": "glm-5"}]},
               "lan": {"baseUrl": "http://127.0.0.1:8001/v1", "api": "openai-completions", "models": [{"id": "q"}]}}}}
GLM_JOBS = [
    ("job-glm-haus", {"agentId": "haus", "sessionTarget": "isolated",
                      "payload": {"kind": "agentTurn", "message": PROMPT, "model": "glm/glm-5", "fallbacks": []}}),
    ("job-lan-fb", {"agentId": "main", "sessionTarget": "isolated",
                    "payload": {"kind": "agentTurn", "message": PROMPT, "model": "lan/q",
                                "fallbacks": ["glm/glm-5", "openai/gpt-5.5"]}}),
]
D1_HAUS = ("cron job 'Job Glm Haus' (job-glm-haus): OpenClaw {rt} refuses every run and tries no fallback: its model "
           "glm/glm-5 runs on the API key written as a literal value in models.providers.glm.apiKey, which OpenClaw "
           "{rt} doctor copies into its auth store during this migration (a stored login from then on); the job has "
           "no recorded inference account (openclaw/openclaw#192195)")
D1_FIX = ("provider glm: its key in models.providers.glm.apiKey is a literal value (placeholders such as EMPTY or NONE "
          "count as keys); OpenClaw {rt} doctor copies it into OpenClaw's auth store during the migration, and the "
          "cron jobs above that use glm are refused on it from then on. To keep them and their fallbacks, after the "
          "start, run: openclaw config set models.providers.glm.auth api-key (OpenClaw then uses the configured key "
          "for glm, not the stored copy; no restart needed; 2026.10.4 accepts this setting and runs the same), or "
          "give the key as an env SecretRef (a gateway_env_vars entry, then openclaw config set "
          "models.providers.glm.apiKey '{{\"source\":\"env\",\"provider\":\"default\",\"id\":\"<VAR>\"}}' "
          "--strict-json)")


class CronKeyCopyGateTests(T.GateEnv):
    """Rehearsal D1: OpenClaw's doctor (also 2026.10.10 and 2026.11.1, in the gate's doctor --fix passes) copies a
    literal models.providers.<p>.apiKey (also EMPTY or NONE), or a literal key in an agent's model catalog, into its
    auth store; from then on these runtimes refuse every cron run on that provider without a recorded inference
    account. The precheck forecast counts that copy and names the fix (auth "api-key" or an env SecretRef) before
    the binding; the postconditions, finalize and status give it too. Report only; synthetic key and jobs."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, agents=("main", "haus"), content=True)
        add_jobs(self.state, GLM_JOBS)
        self.write_cfg(CFG_GLM)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.10.10", 22, 27)
        self.hooks()
        self.sdb = self.state / "state" / "openclaw.sqlite"

    def dry(self):
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        return lines

    def report(self, cfg, pending=True):
        return G.cron_account_report(self.state, cfg, "2026.11.1", pending_copies=pending)

    def glm(self, **pcfg):
        cfg = json.loads(json.dumps(CFG_GLM))
        cfg["models"]["providers"]["glm"] = dict({k: v for k, v in cfg["models"]["providers"]["glm"].items()
                                                  if k != "apiKey"}, **pcfg)
        return cfg

    def test_precheck_counts_doctors_copy_of_a_literal_key(self):
        """The D1 regression: the glm-only job of agent haus was reported as working; 2026.10.10 refused every run."""
        for rt in ("2026.10.10", "2026.11.1"):
            with self.subTest(runtime=rt):
                self.set_runtime(rt, 22, 27)
                lines = self.dry()
                text = "\n".join(lines)
                self.assertIn("WARN [gate] " + D1_HAUS.format(rt=rt), lines)
                self.assertIn("WARN [gate] cron job 'Job Lan Fb' (job-lan-fb): its model lan/q needs no stored login "
                              f"and keeps working, but when it fails OpenClaw {rt} stops at the fallback glm/glm-5 "
                              "(its literal API key becomes a stored login during the migration; no recorded inference "
                              "account; openclaw/openclaw#192195) instead of trying further models; also on a stored "
                              "login: openai/gpt-5.5", lines)
                fix = lines.index("WARN [gate] " + D1_FIX.format(rt=rt))
                close = next(i for i, ln in enumerate(lines) if ln.startswith("WARN [gate] 4 cron job(s) above:"))
                self.assertEqual(fix + 1, close)
                self.assertEqual(lines[close], "WARN [gate] 4 cron job(s) above: the add-on changes nothing; OpenClaw "
                                 "records the inference account of the jobs on other stored logins itself from "
                                 "2026.11.5 (doctor migration, openclaw/openclaw#172792). " + G.CRON_MANUAL_LAST)
                self.assertTrue(G.CRON_MANUAL_LAST.startswith("Otherwise (last resort), after the start: openclaw "
                                                              "automations edit <id> --model"))
                self.assertIn(f"[gate]   cron inference accounts: 4 enabled cron job(s) stop at a stored login on "
                              f"OpenClaw {rt} (3 because OpenClaw's doctor copies a literal provider key into its "
                              "auth store; fix: models.providers.<provider>.auth \"api-key\" or an env SecretRef) "
                              "(the WARN lines above, openclaw/openclaw#192195); report only, the gate changes "
                              "nothing", lines)
                self.assertIn("[gate] dry-run: the precheck would pass", text)  # WARN only, never a HOLD
                self.assertNotIn(GLM_KEY, text)

    def test_what_the_doctor_copy_depends_on(self):
        def affected(cfg):
            rec = self.report(cfg)
            return {a["id"]: (a["primary_affected"], a.get("key_copy"), a.get("aws_sdk"))
                    for a in rec["affected"] if a["id"] == "job-glm-haus"}, rec["key_fix"]
        copied = {"job-glm-haus": (True, ["glm/glm-5"], None)}
        for pcfg in ({"apiKey": GLM_KEY, "auth": "api-key"},
                     {"apiKey": {"source": "env", "provider": "default", "id": "GLM_API_KEY"}},
                     {"apiKey": "${GLM_API_KEY}"}, {"apiKey": "VLLM_API_KEY"}, {"apiKey": "custom-local"}, {}):
            with self.subTest(kept=pcfg):
                self.assertEqual(affected(self.glm(**pcfg)), ({}, []))
        for literal in ("EMPTY", "NONE", " EMPTY ", "${glm_key}"):
            with self.subTest(copied=literal):
                self.assertEqual(affected(self.glm(apiKey=literal))[0], copied)
        aff, fix = affected(self.glm(apiKey=GLM_KEY, auth="oauth"))
        self.assertEqual((aff, [(k["provider"], k["auth"]) for k in fix]), (copied, [("glm", "oauth")]))
        lines = G.cron_job_lines(self.report(self.glm(apiKey=GLM_KEY, auth="oauth")))
        oauth = next(ln for ln in lines if ln.startswith("provider glm:"))
        self.assertTrue(oauth.endswith("To keep them and their fallbacks, after the start, give the key as an env "
                                       "SecretRef: a gateway_env_vars entry, then openclaw config set "
                                       "models.providers.glm.apiKey '{\"source\":\"env\",\"provider\":\"default\","
                                       "\"id\":\"<VAR>\"}' --strict-json (models.providers.glm.auth \"oauth\" stays)"),
                        oauth)
        self.assertNotIn("auth api-key", oauth)
        self.assertEqual(affected(self.glm(apiKey=GLM_KEY, auth="aws-sdk")),
                         ({"job-glm-haus": (True, None, ["glm/glm-5"])}, []))

    def test_catalog_keys_follow_their_agent(self):
        """A literal key only in an agent's models.json (comments and trailing commas allowed) or generated plugin
        catalog is copied too: into that agent's store, or for agents/main/agent into the shared store."""
        add_jobs(self.state, [
            ("job-cat-haus", {"agentId": "haus", "sessionTarget": "isolated",
                              "payload": {"kind": "agentTurn", "message": PROMPT, "model": "cat/m", "fallbacks": []}}),
            ("job-cat-main", {"agentId": "main", "sessionTarget": "isolated",
                              "payload": {"kind": "agentTurn", "message": PROMPT, "model": "cat/m",
                                          "fallbacks": []}})], start=50)
        cfg = self.glm(apiKey=GLM_KEY, auth="api-key")
        models = '{\n  // generated, then edited\n  "providers": {"cat": {"apiKey": "sk-synthetic-cat", },},\n}\n'
        haus = self.state / "agents" / "haus" / "agent"
        main = self.state / "agents" / "main" / "agent"
        ids = lambda rec: [a["id"] for a in rec["affected"] if a["id"].startswith("job-cat")]  # noqa: E731
        self.assertEqual(ids(self.report(cfg)), [])
        (haus / "models.json").write_text(models)
        rec = self.report(cfg)
        self.assertEqual(ids(rec), ["job-cat-haus"])
        self.assertEqual(rec["key_fix"], [{"provider": "cat", "path": "models.providers.cat", "auth": None,
                                           "where": "catalog", "pending": True}])
        lines = G.cron_job_lines(rec)
        self.assertIn("cron job 'Job Cat Haus' (job-cat-haus): OpenClaw 2026.11.1 refuses every run and tries no "
                      "fallback: its model cat/m runs on a literal API key in an agent's model catalog (models.json, "
                      "provider cat), which OpenClaw 2026.11.1 doctor copies into its auth store during this migration "
                      "(a stored login from then on); the job has no recorded inference account "
                      "(openclaw/openclaw#192195)", lines)
        self.assertIn("provider cat: an agent's model catalog (models.json) holds a literal API key for cat "
                      "(placeholders such as EMPTY or NONE count as keys); OpenClaw 2026.11.1 doctor copies it into "
                      "OpenClaw's auth store during the migration, and the cron jobs above that use cat are refused on "
                      "it from then on. To keep them and their fallbacks, declare the key in openclaw.json instead: "
                      "models.providers.cat.apiKey with models.providers.cat.auth \"api-key\", or as an env SecretRef "
                      "(a gateway_env_vars entry and {\"source\":\"env\",\"provider\":\"default\",\"id\":\"<VAR>\"} as "
                      "models.providers.cat.apiKey)", lines)
        (haus / "models.json").unlink()
        (main / "models.json").write_text(models)
        self.assertEqual(ids(self.report(cfg)), ["job-cat-haus", "job-cat-main"])
        (main / "models.json").write_text("{ not json")  # skipped, as doctor does
        self.assertEqual(ids(self.report(cfg)), [])
        # an env SecretRef in openclaw.json stops the catalog copy of that provider
        (main / "models.json").write_text(models)
        cfg["models"]["providers"]["cat"] = {"apiKey": {"source": "env", "provider": "default", "id": "CAT_KEY"}}
        self.assertEqual(ids(self.report(cfg)), [])
        del cfg["models"]["providers"]["cat"]
        (main / "models.json").unlink()
        # generated plugin catalogs in the agent database count; other cache entries do not
        con = sqlite3.connect(str(haus / "openclaw-agent.sqlite"))
        for key, gen in (("plugin-a", "openclaw-plugin-model-catalog-v1"), ("plugin-b", "someone-else")):
            con.execute("INSERT INTO cache_entries (scope, key, value_json, updated_at) VALUES (?, ?, ?, 0)",
                        ("plugin-model-catalog-v1", key, json.dumps(
                            {"generatedBy": gen, "providers": {"cat" if gen != "someone-else" else "other":
                                                               {"apiKey": "sk-synthetic-cat"}}})))
        con.commit()
        con.close()
        self.assertEqual(ids(self.report(cfg)), ["job-cat-haus"])
        self.assertNotIn("sk-synthetic-cat", json.dumps(self.report(cfg)) + "\n".join(G.cron_job_lines(rec)))

    def test_postconditions_finalize_and_status_after_doctors_copy(self):
        """After the migration doctor's copy glm:default is in the shared store (state DB); the literal key still
        names the fix, before the binding as the last resort."""
        store = json.loads(json.dumps(T.AUTH_1004_STORE))
        store["profiles"]["glm:default"] = {"type": "api_key", "provider": "glm", "key": GLM_KEY}
        self.doctor_script(state_uv=22, agent_uv=27, app_version="2026.10.10", sql=[
            "INSERT OR REPLACE INTO config_machine_state VALUES ('auth.sharedStore', "
            "'{\"location\": \"state-db\"}', 0)",
            "INSERT OR REPLACE INTO config_machine_state VALUES ('authProfiles.store', '%s', 0)" % json.dumps(store)])
        self.assertEqual(self.run_gate(), 0, self.out)
        out = self.out.splitlines()
        j = self.journal()
        self.assertEqual(j["cron_binding_forecast"]["key_fix"], [{"provider": "glm", "path": "models.providers.glm",
                                                                  "auth": None, "where": "config", "pending": True}])
        self.assertEqual(j["cron_binding"]["key_fix"], [{"provider": "glm", "path": "models.providers.glm",
                                                         "auth": None, "where": "config", "pending": False}])
        self.assertEqual([(a["id"], a["primary_affected"], a.get("key_copy")) for a in j["cron_binding"]["affected"]],
                         [("job-morning", True, None), ("job-local", True, None), ("job-glm-haus", True, None),
                          ("job-lan-fb", False, None)])
        fin = out[next(i for i, ln in enumerate(out) if ln.startswith("[gate] 7/8 postconditions OK")):]
        fix = next(i for i, ln in enumerate(fin) if ln.startswith("WARN [gate] provider glm:"))
        self.assertEqual(fin[fix], "WARN [gate] provider glm: OpenClaw 2026.10.10 runs glm on a stored login although "
                         "models.providers.glm.apiKey holds a key (a literal value, which OpenClaw's doctor copies "
                         "into its auth store). To lift the refusal for the cron jobs above that use glm and keep "
                         "their fallbacks, run: openclaw config set models.providers.glm.auth api-key (OpenClaw then "
                         "uses the configured key for glm, not the stored login; no restart needed), or give the key "
                         "as an env SecretRef (a gateway_env_vars entry, then openclaw config set "
                         "models.providers.glm.apiKey '{\"source\":\"env\",\"provider\":\"default\",\"id\":\"<VAR>\"}' "
                         "--strict-json)")
        last = next(i for i, ln in enumerate(fin) if "Otherwise (last resort)" in ln)
        self.assertLess(fix, last)
        st = G.status_lines()
        i = next(i for i, x in enumerate(st) if x.startswith("    provider glm:"))
        self.assertIn("openclaw config set models.providers.glm.auth api-key", st[i])
        self.assertEqual(st[i + 1], "    OpenClaw records the account of the jobs on other stored logins itself from "
                         "2026.11.5 (openclaw/openclaw#172792). " + G.CRON_MANUAL_LAST)
        for blob in (self.out, json.dumps(j), "\n".join(st)):
            self.assertNotIn(GLM_KEY, blob)
            self.assertNotIn(PROMPT, blob)

    def test_status_from_the_precheck_forecast(self):
        rec = self.report(CFG_GLM)
        st = G._status_cron({"cron_binding_forecast": rec})
        self.assertIn("    'Job Glm Haus' (job-glm-haus): every run refused; glm/glm-5 (literal key that doctor "
                      "copies)", st)
        self.assertIn("    " + D1_FIX.format(rt="2026.11.1"), st)
        self.assertTrue(st[-1].endswith(G.CRON_MANUAL_LAST), st[-1])
        # only provider keys and paths: the jobs of a provider with a key fix get no 2026.11.5 promise
        only = dict(rec, affected=[a for a in rec["affected"] if a["id"] == "job-glm-haus"])
        self.assertEqual(G._status_cron({"cron_binding_forecast": only})[-1], "    " + G.CRON_MANUAL_LAST)
        self.assertEqual(G.cron_job_lines(only)[-1], "1 cron job(s) above: the add-on changes nothing. "
                         + G.CRON_MANUAL_LAST)
        self.assertNotIn(GLM_KEY, json.dumps(rec) + "\n".join(st))

    def test_key_fix_line_variants(self):
        rec = {"runtime": "2026.11.1", "key_fix": [
            {"provider": "cat", "path": "models.providers.cat", "auth": None, "where": "catalog", "pending": False},
            {"provider": "tok", "path": "models.providers.tok", "auth": "token", "where": "config", "pending": False},
            {"provider": "x\nWARN", "path": "models.providers[\"x\\nWARN\"]", "auth": None, "where": "config",
             "pending": True}]}
        lines = G.cron_key_fix_lines(rec)
        self.assertEqual(lines[0], "provider cat: an agent's model catalog (models.json) holds a literal API key for "
                         "cat (placeholders such as EMPTY or NONE count as keys); OpenClaw 2026.11.1 runs cat on a "
                         "stored login (OpenClaw's doctor copies such a key into its auth store). To lift the refusal "
                         "for the cron jobs above that use cat and keep their fallbacks, declare the key in "
                         "openclaw.json instead: models.providers.cat.apiKey with models.providers.cat.auth "
                         "\"api-key\", or as an env SecretRef (a gateway_env_vars entry and {\"source\":\"env\","
                         "\"provider\":\"default\",\"id\":\"<VAR>\"} as models.providers.cat.apiKey)")
        self.assertEqual(lines[1], "provider tok: OpenClaw 2026.11.1 runs tok on a stored login although "
                         "models.providers.tok.apiKey holds a key (a literal value, which OpenClaw's doctor copies "
                         "into its auth store). To lift the refusal for the cron jobs above that use tok and keep "
                         "their fallbacks, give the key as an env SecretRef: a gateway_env_vars entry, then openclaw "
                         "config set models.providers.tok.apiKey '{\"source\":\"env\",\"provider\":\"default\","
                         "\"id\":\"<VAR>\"}' --strict-json (models.providers.tok.auth \"token\" stays)")
        self.assertEqual(len(lines), 3)
        self.assertNotIn("\n", "".join(lines))  # a provider key cannot add a log line
        self.assertEqual(G.cron_key_fix_lines({"key_fix": [{"provider": ""}, "x", None]}), [])

    def test_bracket_path_for_a_provider_key_that_is_no_identifier(self):
        cfg = json.loads(json.dumps(CFG_GLM))
        cfg["models"]["providers"]["my.glm"] = cfg["models"]["providers"].pop("glm")
        cfg["agents"]["defaults"]["model"] = {"primary": "lan/q", "fallbacks": []}
        rec = self.report(cfg)
        self.assertEqual(rec["key_fix"], [])  # nothing runs on my.glm yet
        add_jobs(self.state, [("job-dot", {"agentId": "main", "sessionTarget": "isolated",
                                           "payload": {"kind": "agentTurn", "message": PROMPT,
                                                       "model": "my.glm/glm-5", "fallbacks": []}})], start=50)
        lines = G.cron_job_lines(self.report(cfg))
        fix = next(ln for ln in lines if ln.startswith("provider my.glm:"))
        self.assertIn("its key in models.providers[\"my.glm\"].apiKey is a literal value", fix)
        self.assertIn("run: openclaw config set 'models.providers[\"my.glm\"].auth' api-key (", fix)
        self.assertIn("openclaw config set 'models.providers[\"my.glm\"].apiKey' '{", fix)

    def test_no_report_on_1004(self):
        """The 2026.10.4 target: no cron report, no key fix, nothing new in the journal (doctor 2026.10.4 copies the
        key as well, but 2026.10.4 has no cron refusal)."""
        self.set_runtime("2026.10.4", 20, 24)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.9", "mode": "bump"}))
        con = sqlite3.connect(str(self.sdb))
        con.execute("PRAGMA user_version=19")
        con.execute("UPDATE schema_meta SET schema_version=19, app_version='2026.9.9' WHERE meta_key='primary'")
        con.commit()
        con.close()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("cron job", self.out)
        self.assertNotIn("provider glm", self.out)
        self.assertNotIn(GLM_KEY, self.out)
        j = self.journal()
        self.assertNotIn("cron_binding", j)
        self.assertNotIn("cron_binding_forecast", j)


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
