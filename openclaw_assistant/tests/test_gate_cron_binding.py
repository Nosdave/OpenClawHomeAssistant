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
import unittest.mock
from datetime import timedelta
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


# what OpenClaw's own migration (2026.11.5, openclaw/openclaw#172792) does for the jobs: it records the account of a
# job's own model only (inference-binding-migration.ts), and a bound job's fallbacks to other providers are refused
OUTLOOK_PRIM = ("OpenClaw records the inference account of {who} itself from 2026.11.5 (doctor migration, "
                "openclaw/openclaw#172792), but then refuses their fallbacks to other providers (as with "
                "openclaw/openclaw#192463)")
OUTLOOK_FB = ("OpenClaw's own migration{v} records only the account of a job's own model: a job whose own model needs "
              "no account stays unbound, and its fallback on a stored login stays refused")
OUTLOOK_FB_ALONE = OUTLOOK_FB.format(v=" (2026.11.5, openclaw/openclaw#172792)")
MANUAL_SCOPED = G.CRON_MANUAL.replace("after the start: ", "after the start, for a job whose own model is refused: ")
MANUAL_LAST_SCOPED = G.CRON_MANUAL_LAST.replace("after the start: ",
                                                "after the start, for a job whose own model is refused: ")


def outlook(who):
    """The closing note's 2026.11.5 clauses for jobs on a stored login (who) and jobs that only stop at a fallback."""
    return OUTLOOK_PRIM.format(who=who) + "; " + OUTLOOK_FB.format(v="")


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
            "WARN [gate] 2 cron job(s) above: the add-on changes nothing for these jobs; "
            + outlook("the jobs whose own model is on a stored login") + ". " + MANUAL_SCOPED + ". " + G.CRON_FALLBACK,
            "[gate]   cron inference accounts: 2 enabled cron job(s) stop at a stored login on OpenClaw 2026.10.10 "
            "(the WARN lines above, openclaw/openclaw#192195); report only, the gate changes nothing"])
        self.assertIn("openclaw automations edit <id> --model <provider/model>@<profileId>", G.CRON_MANUAL)
        self.assertIn("openclaw/openclaw#192463", G.CRON_MANUAL)
        # a job that only stops at a fallback: no binding (it would make that fallback the job's model)
        self.assertIn("openclaw automations edit <id> --fallbacks <list> without it", G.CRON_FALLBACK)
        self.assertNotIn("@<profileId>", G.CRON_FALLBACK)
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
            "WARN [gate] 4 cron job(s) above: the add-on changes nothing for these jobs; "
            + outlook("the jobs whose own model is on a stored login") + ". " + MANUAL_SCOPED + ". " + G.CRON_FALLBACK
            + ". " + G.CRON_AWS_SDK,
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
        self.assertEqual(lines[-1], "2 cron job(s) above: the add-on changes nothing for these jobs. " + G.CRON_AWS_SDK)
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
            "    " + OUTLOOK_PRIM.format(who="the jobs whose own model is on a stored login") + ". "
            + OUTLOOK_FB.format(v="") + ". " + MANUAL_SCOPED + ". " + G.CRON_FALLBACK])
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


def included(cfg):
    """openclaw.json with $include: the gate writes nothing to it (no automatic config fixup)."""
    return dict(json.loads(json.dumps(cfg)), **{"$include": "./extra.json5"})


class CronKeyCopyGateTests(T.GateEnv):
    """Rehearsal D1: OpenClaw's doctor (also 2026.10.10 and 2026.11.1, in the gate's doctor --fix passes) copies a
    literal models.providers.<p>.apiKey (also EMPTY or NONE), or a literal key in an agent's model catalog, into its
    auth store; from then on these runtimes refuse every cron run on that provider without a recorded inference
    account. The precheck forecast counts that copy and names the fix (auth "api-key" or an env SecretRef) before
    the binding; the postconditions, finalize and status give it too. Where the gate can, it sets auth "api-key"
    itself before doctor pass 1 (CronConfigFixupTests); the gate runs here use openclaw.json with $include, where it
    cannot. Synthetic key and jobs."""

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
        """The D1 regression: the glm-only job of agent haus was reported as working; 2026.10.10 refused every run.
        Here openclaw.json uses $include, so the gate cannot set auth "api-key" itself (CronConfigFixupTests)."""
        self.write_cfg(included(CFG_GLM))
        for rt in ("2026.10.10", "2026.11.1"):
            with self.subTest(runtime=rt):
                self.set_runtime(rt, 22, 27)
                lines = self.dry()
                text = "\n".join(lines)
                self.assertIn("WARN [gate] " + D1_HAUS.format(rt=rt), lines)
                # openclaw.json uses $include: "keeps working" only as far as openclaw.json itself shows
                self.assertIn("WARN [gate] cron job 'Job Lan Fb' (job-lan-fb): its model lan/q needs no stored login "
                              "(as far as openclaw.json itself shows; its included files are not checked) and keeps "
                              f"working, but when it fails OpenClaw {rt} stops at the fallback glm/glm-5 "
                              "(its literal API key becomes a stored login during the migration; no recorded inference "
                              "account; openclaw/openclaw#192195) instead of trying further models; also on a stored "
                              "login: openai/gpt-5.5", lines)
                fix = lines.index("WARN [gate] " + D1_FIX.format(rt=rt))
                close = next(i for i, ln in enumerate(lines) if ln.startswith("WARN [gate] 4 cron job(s) above:"))
                self.assertEqual(fix + 1, close)
                self.assertEqual(lines[close], "WARN [gate] 4 cron job(s) above: the add-on changes nothing for these "
                                 "jobs; " + outlook("the jobs whose own model is on another stored login") + ". "
                                 + MANUAL_LAST_SCOPED + ". " + G.CRON_FALLBACK)
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
        names the fix, before the binding as the last resort (openclaw.json with $include: no automatic fixup)."""
        self.write_cfg(included(CFG_GLM))
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
        self.assertEqual(st[i + 1], "    " + OUTLOOK_PRIM.format(who="the jobs whose own model is on another stored "
                                                                "login") + ". " + OUTLOOK_FB.format(v="") + ". "
                         + MANUAL_LAST_SCOPED + ". " + G.CRON_FALLBACK)
        for blob in (self.out, json.dumps(j), "\n".join(st)):
            self.assertNotIn(GLM_KEY, blob)
            self.assertNotIn(PROMPT, blob)

    def test_status_from_the_precheck_forecast(self):
        rec = self.report(CFG_GLM)
        st = G._status_cron({"cron_binding_forecast": rec})
        self.assertIn("    'Job Glm Haus' (job-glm-haus): every run refused; glm/glm-5 (literal key that doctor "
                      "copies)", st)
        self.assertIn("    " + D1_FIX.format(rt="2026.11.1"), st)
        self.assertTrue(st[-1].endswith(MANUAL_LAST_SCOPED + ". " + G.CRON_FALLBACK), st[-1])
        # only provider keys and paths: the jobs of a provider with a key fix get no 2026.11.5 promise
        only = dict(rec, affected=[a for a in rec["affected"] if a["id"] == "job-glm-haus"])
        self.assertEqual(G._status_cron({"cron_binding_forecast": only})[-1], "    " + G.CRON_MANUAL_LAST)
        self.assertEqual(G.cron_job_lines(only)[-1], "1 cron job(s) above: the add-on changes nothing for these "
                         "jobs. " + G.CRON_MANUAL_LAST)
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

    def test_key_fix_line_variants_while_held(self):
        """held (oc-upgrade status during a HOLD): no bare command the wrapper refuses (config set, automations);
        a catalog key (a hand edit) and a forecast's "after the start" stay as they are."""
        ref = G.CRON_ENV_REF
        rec = {"runtime": "2026.11.1", "affected": [{"primary_affected": True, "refs": ["own/m"]}], "key_fix": [
            {"provider": "cat", "path": "models.providers.cat", "auth": None, "where": "catalog", "pending": False},
            {"provider": "tok", "path": "models.providers.tok", "auth": "token", "where": "config", "pending": False},
            {"provider": "fc", "path": "models.providers.fc", "auth": None, "where": "config", "pending": True},
            {"provider": "own", "path": "models.providers.own", "auth": None, "where": "config", "pending": True,
             "own_login": True}]}
        plain, held = G.cron_key_fix_lines(rec), G.cron_key_fix_lines(rec, held=True)
        self.assertEqual((held[0], held[2]), (plain[0], plain[2]))
        self.assertIn("after the start, run: openclaw config set models.providers.fc.auth api-key", held[2])
        self.assertTrue(held[1].endswith(
            "give the key as an env SecretRef: a gateway_env_vars entry and " + ref + " as models.providers.tok.apiKey"
            ", set in openclaw.json by hand (while OpenClaw is held the wrapper refuses openclaw config set) or after "
            "the HOLD is cleared: openclaw config set models.providers.tok.apiKey '" + ref + "' --strict-json "
            "(models.providers.tok.auth \"token\" stays)"), held[1])
        self.assertEqual(held[3], "provider own: OpenClaw 2026.11.1 runs own on a stored login of its own (a "
                         "subscription login, a token or another API key), not on the literal key in "
                         "models.providers.own.apiKey. To keep them and their fallbacks, set models.providers.own.auth "
                         "to \"api-key\" in openclaw.json by hand (while OpenClaw is held the wrapper refuses openclaw "
                         "config set), or after the HOLD is cleared run: openclaw config set models.providers.own.auth "
                         "api-key (OpenClaw then uses the configured key for own, not the stored copy; no restart "
                         "needed), or give the key as an env SecretRef (a gateway_env_vars entry and " + ref + " as "
                         "models.providers.own.apiKey in openclaw.json); this makes every run of own, not only cron, "
                         "use the configured key instead of that login. To keep the login, after the HOLD is cleared: "
                         "drop own from the job's fallbacks (openclaw automations edit <id> --fallbacks <list> without "
                         "it), and for a job whose own model is on own the last resort below")
        self.assertEqual(held[3].replace(
            "set models.providers.own.auth to \"api-key\" in openclaw.json by hand (while OpenClaw is held the wrapper "
            "refuses openclaw config set), or after the HOLD is cleared run: ", "run: ").replace(
            "a gateway_env_vars entry and " + ref + " as models.providers.own.apiKey in openclaw.json",
            "a gateway_env_vars entry, then openclaw config set models.providers.own.apiKey '" + ref + "' "
            "--strict-json").replace("To keep the login, after the HOLD is cleared:", "To keep the login:"), plain[3])

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


FIXUP_WHY = ("doctor stores its literal key as a login; without this OpenClaw {rt} refuses every unbound cron run on "
             "glm: openclaw/openclaw#192195")
FIXUP = 'config fixup: models.providers.glm.auth = "api-key" (' + FIXUP_WHY + ")"
FIXUP_PRE = ('config fixup: {verb} models.providers.glm.auth = "api-key" before doctor pass 1 (' + FIXUP_WHY + ")")
FIXUP_KEPT = ("info: 3 enabled cron job(s) kept working by the automatic fix (models.providers.glm.auth = \"api-key\" "
              "before doctor pass 1; otherwise OpenClaw {rt} refuses glm/glm-5 on doctor's copy of the literal key): "
              "'Local digest' (job-local), 'Job Glm Haus' (job-glm-haus), 'Job Lan Fb' (job-lan-fb)")
FIXUP_ENTRY = {"provider": "glm", "entry": "glm", "path": "models.providers.glm.auth", "old": None, "new": "api-key"}


class CronConfigFixupTests(T.GateEnv):
    """decisions.md addendum 2026-11-05 (rehearsal D1): glm is the owner's local model, its apiKey only a non-blank
    placeholder, and its cron jobs must keep running on 2026.11.1 without the owner's help. On runtimes with the cron
    refusal (2026.10.10+) the gate sets models.providers.<p>.auth "api-key" in openclaw.json before doctor pass 1 for
    each provider whose literal openclaw.json key doctor copies and that an enabled cron job uses (auth unset, no
    stored login of its own): one config fixup line per provider, journal cron_autofix, ledger step C1. Nothing in
    OpenClaw's databases or auth stores, nothing on 2026.10.4. Synthetic key and jobs (10.4-layout state)."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, agents=("main", "haus"), content=True)
        add_jobs(self.state, GLM_JOBS)
        self.write_cfg(CFG_GLM)
        self.cfgp = self.state / "openclaw.json"
        os.chmod(self.cfgp, 0o640)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.11.1", 22, 27)
        self.hooks()
        self.sdb = self.state / "state" / "openclaw.sqlite"

    def doctor_copies_key(self, rt, **step):
        """The fake doctor migrates and, like OpenClaw's, stores the literal glm key as glm:default (shared store)."""
        store = json.loads(json.dumps(T.AUTH_1004_STORE))
        store["profiles"]["glm:default"] = {"type": "api_key", "provider": "glm", "key": GLM_KEY}
        self.doctor_script(state_uv=22, agent_uv=27, app_version=rt, sql=[
            "INSERT OR REPLACE INTO config_machine_state VALUES ('auth.sharedStore', '{\"location\": \"state-db\"}', 0)",
            "INSERT OR REPLACE INTO config_machine_state VALUES ('authProfiles.store', '%s', 0)" % json.dumps(store)],
            **step)

    def dry(self):
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        return lines

    def cfg_now(self):
        return json.loads(self.cfgp.read_text())

    def run_dir(self):
        return self.upg / "gate" / "runs" / self.journal()["run_id"]

    def gate_obj(self, journal=None):
        """A Gate for a direct call of cron_config_fixup (a resumed run's state)."""
        g = G.Gate(emit=lambda s: None)
        g.pkg = C.runtime_package()
        lines = []
        g.emit = lines.append
        g.j = dict({"run_id": "20261105T120000Z-abc123", "runtime": g.pkg["version"], "mode": "bump"}, **(journal or {}))
        return g, lines

    def key_holders(self):
        """Files below /config that hold the synthetic key, relative to the config root."""
        key = GLM_KEY.encode()
        return sorted(str(x.relative_to(self.root)) for x in self.root.rglob("*")
                      if x.is_file() and not x.is_symlink() and key in x.read_bytes())

    def test_precheck_presents_the_jobs_as_kept_working(self):
        """dry-run (also `oc-upgrade check`) and --plan say "would set" and write nothing; the jobs on glm are kept
        working, not refused; what stays is the report of the stored-login fallbacks."""
        for rt in ("2026.10.10", "2026.11.1"):
            with self.subTest(runtime=rt):
                self.set_runtime(rt, 22, 27)
                before = (self.cfgp.read_bytes(), os.stat(self.cfgp).st_mode, sha(self.sdb))
                lines = self.dry()
                self.assertIn("[gate] 1/8 " + FIXUP_PRE.format(verb="would set", rt=rt), lines)
                self.assertIn("[gate] 1/8 " + FIXUP_KEPT.format(rt=rt), lines)
                self.assertNotIn("WARN [gate] " + D1_HAUS.format(rt=rt), lines)
                self.assertFalse([ln for ln in lines if ln.startswith(("WARN [gate] provider glm:",
                                                                       "WARN [gate] cron job 'Job Glm Haus'"))], lines)
                self.assertIn("WARN [gate] cron job 'Job Lan Fb' (job-lan-fb): its model lan/q needs no stored login "
                              f"and keeps working, but when it fails OpenClaw {rt} stops at the fallback openai/gpt-5.5 "
                              "(stored login, no recorded inference account; openclaw/openclaw#192195) instead of "
                              "trying further models", lines)
                self.assertIn("WARN [gate] cron job 'Local digest' (job-local): its model glm/glm-5 needs no stored "
                              f"login and keeps working, but when it fails OpenClaw {rt} stops at the fallback "
                              "openai/gpt-5.5 (stored login, no recorded inference account; openclaw/openclaw#192195) "
                              "instead of trying further models", lines)
                self.assertIn("[gate]   cron config fixup: would set models.providers.glm.auth = \"api-key\" before "
                              "doctor pass 1 (keeps 3 enabled cron job(s) on glm working; openclaw/openclaw#192195)",
                              lines)
                self.assertIn(f"[gate]   cron inference accounts: 3 enabled cron job(s) stop at a stored login on "
                              f"OpenClaw {rt} (the WARN lines above, openclaw/openclaw#192195); apart from the config "
                              "fixup above, the gate changes nothing for cron", lines)
                self.assertFalse([x for x in lines if "cron inference accounts" in x and "report only" in x])
                self.assertIn("[gate] dry-run: the precheck would pass", lines)
                d = self.plan()
                self.assertEqual(d["rc"], 10)
                self.assertIn("[gate] plan: " + FIXUP_PRE.format(verb="would set", rt=rt), self.out.splitlines())
                # read-only: openclaw.json (bytes and mode), the databases, no journal or ledger
                self.assertEqual((self.cfgp.read_bytes(), os.stat(self.cfgp).st_mode, sha(self.sdb)), before)
                self.assertFalse((self.upg / "gate" / "journal.json").exists())
                self.assertFalse(list((self.upg / "gate").rglob("transform-ledger.json")))
                self.assertNotIn(GLM_KEY, "\n".join(lines) + self.out)

    def test_retired_skill_collection_review_jobs_are_left_out(self):
        """Rehearsal finding: OpenClaw 2026.10.10+ deletes Skill Workshop's retired weekly curator jobs when doctor
        loads the cron store (cron/store/load.kernel.ts isRetiredCollectionReview: payload kind
        skillCollectionReview, or a declaration key skill-collection-review:*), so the forecast named jobs that no
        longer exist after the gate as "kept working" and WARNed about them. They get one info line instead; the fix
        and its count stay those of the other jobs. On 2026.10.4 nothing changes."""
        add_jobs(self.state, [
            ("skill-collection-review-main", {"agentId": "main", "sessionTarget": "isolated",
                                              "declarationKey": "skill-collection-review:main",
                                              "payload": {"kind": "agentTurn", "message": PROMPT,
                                                          "model": "glm/glm-5", "fallbacks": ["openai/gpt-5.5"]}}),
            ("old-review", {"agentId": "main", "sessionTarget": "isolated",
                            "payload": {"kind": "skillCollectionReview", "model": "openai/gpt-5.5"}})], start=40)
        lines = self.dry()
        self.assertIn("[gate] 1/8 " + FIXUP_KEPT.format(rt="2026.11.1"), lines)
        self.assertIn("[gate] 1/8 info: 2 enabled cron job(s) of Skill Workshop's retired weekly curator: OpenClaw "
                      "2026.11.1 doctor deletes them during the migration (no replacement), so the inference-account "
                      "report and the config fixup leave them out: 'Skill Collection Review Main' "
                      "(skill-collection-review-main), 'Old Review' (old-review)", lines)
        self.assertFalse([x for x in lines if x.startswith("WARN") and "review" in x.lower()], lines)
        self.assertIn("[gate]   cron inference accounts: 3 enabled cron job(s) stop at a stored login on OpenClaw "
                      "2026.11.1 (the WARN lines above, openclaw/openclaw#192195); apart from the config fixup above, "
                      "the gate changes nothing for cron", lines)
        # the inventory marks them as OpenClaw does; the report keeps them out of checked/affected
        inv = {x["id"]: x["retired_review"] for x in G.cron_jobs_inventory(self.sdb)}
        self.assertEqual((inv["skill-collection-review-main"], inv["old-review"], inv["job-lan-fb"]),
                         (True, True, False))
        rec = G.cron_account_report(self.state, self.cfg_now(), "2026.11.1", pending_copies=True)
        self.assertEqual(rec["retired_review_count"], 2)
        self.assertFalse([a for a in rec["affected"] if "review" in a["id"]])
        # 2026.10.4 (no Skill Workshop retirement, no cron refusal): no line
        self.set_runtime("2026.10.4", 20, 24)
        self.assertFalse([x for x in self.dry() if "retired weekly curator" in x])
        self.assertNotIn("retired_review", G.cron_account_report(self.state, self.cfg_now(), "2026.10.4"))

    def check_gate_run(self, rt):
        self.set_runtime(rt, 22, 27)
        self.doctor_copies_key(rt)
        cfg0 = self.cfg_now()
        self.assertEqual(self.run_gate(), 0, self.out)
        out = self.out.splitlines()
        pre = out.index("[gate] 1/8 " + FIXUP_PRE.format(verb="will set", rt=rt))
        self.assertIn("[gate] 1/8 " + FIXUP_KEPT.format(rt=rt), out)
        fix = out.index("[gate] 4/8 " + FIXUP.format(rt=rt))
        pass1 = next(i for i, ln in enumerate(out) if ln.startswith("[gate] 4/8 doctor pass 1 started"))
        self.assertLess(pre, fix)
        self.assertLess(fix, pass1)
        self.assertEqual(sum(1 for ln in out if "config fixup: models.providers" in ln), 1)  # pass 2: nothing again
        # openclaw.json: only auth added (doctor sets meta.lastTouchedVersion); mode kept; pass 1 started with it
        cfg1 = self.cfg_now()
        self.assertEqual(cfg1["models"]["providers"]["glm"]["auth"], "api-key")
        expect = json.loads(json.dumps(cfg0))
        expect["models"]["providers"]["glm"]["auth"] = "api-key"
        expect["meta"] = cfg1["meta"]
        self.assertEqual(cfg1, expect)
        self.assertEqual(stat_mode(self.cfgp), 0o640)
        rd = self.run_dir()
        self.assertEqual(json.loads((rd / "config.pre-pass1.json").read_text())["models"]["providers"]["glm"]["auth"],
                         "api-key")
        j = self.journal()
        applied = j["cron_autofix"]["applied"]
        self.assertEqual([{k: a[k] for k in FIXUP_ENTRY} for a in applied], [FIXUP_ENTRY])
        self.assertEqual((applied[0]["reason"], applied[0]["phase"]), (FIXUP_WHY.format(rt=rt), "doctor1"))
        self.assertNotIn("pending", j["cron_autofix"])
        led = json.loads((rd / "transform-ledger.json").read_text())
        self.assertIn({"step": "C1", "path": "models.providers.glm.auth", "before": None, "after": "api-key"}, led)
        # the precheck forecast shows the state after the fixup; the jobs it keeps are listed with it
        fc = j["cron_binding_forecast"]
        self.assertEqual(fc["autofix"], [{"provider": "glm", "path": "models.providers.glm.auth",
                                          "jobs": ["job-local", "job-glm-haus", "job-lan-fb"]}])
        self.assertEqual(fc["key_fix"], [])
        # the postcheck reads doctor's real copy (glm:default in the shared store): no glm job is refused
        self.assertIn("glm:default", self.sdb.read_bytes().decode("utf-8", "replace"))
        rec = j["cron_binding"]
        self.assertEqual(rec["key_fix"], [])
        self.assertEqual([(a["id"], a["refs"]) for a in rec["affected"]],
                         [("job-morning", ["openai/gpt-5.5", "anthropic/claude-sonnet-4-6"]),
                          ("job-local", ["openai/gpt-5.5"]), ("job-lan-fb", ["openai/gpt-5.5"])])
        self.assertFalse([ln for ln in out if "provider glm:" in ln])
        done = ("info: config fixup of this run: models.providers.glm.auth = \"api-key\" (before doctor pass 1): "
                f"OpenClaw {rt} runs glm on the configured key, so its unbound cron runs on glm are not refused on "
                "doctor's copy (openclaw/openclaw#192195); transform-ledger.json step C1")
        fin = out.index("[gate] " + done)
        self.assertLess(fin, next(i for i, ln in enumerate(out) if ln.startswith("[gate] done: MIGRATED")))
        st = G.status_lines()
        self.assertIn("  " + done.removeprefix("info: "), st)
        # no key value in any output, journal, ledger or event log; no new plaintext copy of openclaw.json: the key
        # is only in openclaw.json, doctor's copy (state DB) and the run's documented config copies
        events = (rd / "events.log").read_text()
        for blob in (self.out, json.dumps(j), json.dumps(led), "\n".join(st), events):
            self.assertNotIn(GLM_KEY, blob)
        rid = j["run_id"]
        allowed = {".openclaw/openclaw.json", ".openclaw/state/openclaw.sqlite"}
        holders = [h for h in self.key_holders() if h not in allowed]
        self.assertTrue(holders)
        for h in holders:
            self.assertRegex(h, rf"\A\.openclaw-upgrade/gate/runs/{rid}/config\.[a-z0-9-]+\.json\Z")
        self.assertFalse(list(self.state.glob(".openclaw.json.*")))  # no temp file left behind

    def test_gate_run_sets_auth_before_doctor_pass_1_on_1111(self):
        self.check_gate_run("2026.11.1")

    def test_gate_run_sets_auth_before_doctor_pass_1_on_1010(self):
        self.check_gate_run("2026.10.10")

    def test_status_warns_when_the_fixup_is_gone_and_cleanup_removes_the_config_copies(self):
        """Rehearsal A4: `oc-upgrade status` re-reads openclaw.json for each config fixup of the run and WARNs, with
        the command, when models.providers.<p>.auth is no longer "api-key". A5: gate_cleanup_hours after the run the
        cleanup deletes the run's plaintext config copies; the key is then only in openclaw.json and doctor's copy."""
        self.doctor_copies_key("2026.11.1")
        self.assertEqual(self.run_gate(), 0, self.out)
        warn = ("  WARN: openclaw.json no longer holds this run's config fixup models.providers.glm.auth = \"api-key\" "
                "({}): OpenClaw 2026.11.1 then runs glm on the copy of its key that doctor stored and refuses its "
                "unbound cron runs again (openclaw/openclaw#192195), unless the key now comes from the environment (env "
                "SecretRef). To restore: openclaw config set models.providers.glm.auth api-key")
        self.assertFalse([x for x in G.status_lines() if "no longer holds" in x])
        cfg = self.cfg_now()
        cfg["models"]["providers"]["glm"]["auth"] = "token"
        self.write_cfg(cfg)
        st = G.status_lines()
        self.assertIn(warn.format('now "token"'), st)
        del cfg["models"]["providers"]["glm"]["auth"]
        self.write_cfg(cfg)
        st = G.status_lines()
        i = st.index(warn.format("the setting is removed"))
        self.assertTrue(st[i - 1].startswith("  config fixup of this run: models.providers.glm.auth"), st[i - 1])
        self.assertNotIn(GLM_KEY, "\n".join(st))
        del cfg["models"]["providers"]["glm"]
        self.write_cfg(cfg)
        self.assertIn(warn.format("the provider entry is gone"), G.status_lines())
        (self.state / "openclaw.json").write_text("{not json")  # unreadable: no guess
        self.assertFalse([x for x in G.status_lines() if "no longer holds" in x])
        # A5: the plaintext copies go with the doctor captures
        j = self.journal()
        rid = j["run_id"]
        self.assertTrue([h for h in self.key_holders() if h.startswith(f".openclaw-upgrade/gate/runs/{rid}/")])
        G.cleanup_pass(now=G.run_due_base(j) + timedelta(hours=48), hours=48, emit=lambda _s: None)
        self.assertEqual([h for h in self.key_holders() if h.startswith(".openclaw-upgrade/")], [])
        self.assertTrue((self.upg / "gate" / "runs" / rid / "transform-ledger.json").exists())

    def test_resume_does_not_repeat_it(self):
        """Doctor pass 1 fails after the fixup (HOLD); the user even removes the setting by hand; `oc-upgrade retry`
        resumes before pass 1 and leaves it to the report: one journal entry, one config fixup line in all. Status
        during the HOLD and the end of the resumed run read openclaw.json again: the drift WARN instead of the
        fixup's info line (during the HOLD without a command the wrapper refuses), no closing note excepting it."""
        self.doctor_copies_key("2026.11.1", rc=1)
        self.assertEqual(self.run_gate(), 20, self.out)
        first = self.out
        self.assertIn("[gate] 4/8 " + FIXUP.format(rt="2026.11.1"), first.splitlines())
        self.assertEqual(self.journal()["status"], "hold")
        cfg = self.cfg_now()
        self.assertEqual(cfg["models"]["providers"]["glm"]["auth"], "api-key")
        del cfg["models"]["providers"]["glm"]["auth"]
        self.write_cfg(cfg)
        drift = ("openclaw.json no longer holds this run's config fixup models.providers.glm.auth = \"api-key\" (the "
                 "setting is removed): OpenClaw 2026.11.1 then runs glm on the copy of its key that doctor stored and "
                 "refuses its unbound cron runs again (openclaw/openclaw#192195), unless the key now comes from the "
                 "environment (env SecretRef). To restore: ")
        cmd = "openclaw config set models.providers.glm.auth api-key"
        self.assertTrue((self.upg / "hold.txt").exists())
        self.assertIn(f"  WARN: {drift}set it in openclaw.json by hand (while OpenClaw is held the wrapper refuses "
                      f"openclaw config set), or after the HOLD is cleared: {cmd}", G.status_lines())
        self.doctor_copies_key("2026.11.1")
        self.assertEqual(self.quiet(G.retry_cmd, []), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        warn = f"WARN [gate] {drift}{cmd}"
        out = self.out.splitlines()
        self.assertIn(warn, out)
        self.assertLess(out.index(warn), next(i for i, ln in enumerate(out) if ln.startswith("[gate] done: MIGRATED")))
        self.assertNotIn("config fixup", self.out.replace(warn, ""))  # no info line, no "apart from the config fixup"
        self.assertIn(f"  WARN: {drift}{cmd}", G.status_lines())  # the HOLD is cleared: the plain command
        self.assertNotIn("auth", self.cfg_now()["models"]["providers"]["glm"])
        j = self.journal()
        self.assertEqual([a["provider"] for a in j["cron_autofix"]["applied"]], ["glm"])
        # the setting is gone, so the postconditions report the refusal with the fix (report only)
        self.assertIn("job-glm-haus", [a["id"] for a in j["cron_binding"]["affected"]])
        self.assertTrue([ln for ln in self.out.splitlines() if ln.startswith("WARN [gate] provider glm:")
                         and "openclaw config set models.providers.glm.auth api-key" in ln])

    def test_status_key_fix_line_during_a_postconditions_hold(self):
        """As test_resume_does_not_repeat_it, but the resumed run HOLDs in postconditions after the cron report
        (pc-legacy-state). Status during that HOLD words the key fix line like the drift WARN above it (the wrapper
        refuses openclaw config set while OpenClaw is held); once the HOLD is cleared, the plain command again."""
        self.doctor_copies_key("2026.11.1", rc=1)
        self.assertEqual(self.run_gate(), 20, self.out)
        cfg = self.cfg_now()
        del cfg["models"]["providers"]["glm"]["auth"]
        self.write_cfg(cfg)
        self.doctor_copies_key("2026.11.1")
        self.assertEqual(self.quiet(G.retry_cmd, []), 0)
        os.environ["FAKE_OC_MODE"] = "lint-legacy"
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["hold"]["phase"]), ("pc-legacy-state", "postconditions"))
        self.assertIn("job-glm-haus", [a["id"] for a in j["cron_binding"]["affected"]])
        self.assertTrue((self.upg / "hold.txt").exists())
        head = ("    provider glm: OpenClaw 2026.11.1 runs glm on a stored login although models.providers.glm.apiKey "
                "holds a key (a literal value, which OpenClaw's doctor copies into its auth store). To lift the "
                "refusal for the cron jobs above that use glm and keep their fallbacks, ")
        cmd = ("openclaw config set models.providers.glm.auth api-key (OpenClaw then uses the configured key for glm, "
               "not the stored login; no restart needed), or give the key as an env SecretRef (")
        st = G.status_lines()
        self.assertTrue([x for x in st if x.startswith("  WARN: openclaw.json no longer holds this run's config "
                                                       "fixup") and "after the HOLD is cleared" in x], st)
        self.assertIn(head + "set models.providers.glm.auth to \"api-key\" in openclaw.json by hand (while OpenClaw is "
                      "held the wrapper refuses openclaw config set), or after the HOLD is cleared run: " + cmd
                      + f"a gateway_env_vars entry and {G.CRON_ENV_REF} as models.providers.glm.apiKey in "
                      "openclaw.json)", st)
        self.assertFalse([x for x in st if x.startswith("    provider glm:") and "run: openclaw config set" in x
                          and "after the HOLD is cleared" not in x], st)
        # accepted: finalize (hold.txt removed) and status give the plain command
        self.assertEqual(self.quiet(G.retry_cmd, ["--accept", "pc-legacy-state"]), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertFalse((self.upg / "hold.txt").exists())
        plain = (head + "run: " + cmd + "a gateway_env_vars entry, then openclaw config set "
                 f"models.providers.glm.apiKey '{G.CRON_ENV_REF}' --strict-json)")
        self.assertIn("WARN [gate] " + plain.strip(), self.out.splitlines())
        self.assertIn(plain, G.status_lines())

    def test_interrupted_write_and_idempotence(self):
        """A write cut off before its journal record ("pending") counts as applied when openclaw.json has it; one
        that never reached the file is planned again; a second call changes nothing."""
        entry = dict(FIXUP_ENTRY, reason=FIXUP_WHY.format(rt="2026.11.1"), phase="doctor1", at="2026-11-05T12:00:00Z")
        cfg = self.cfg_now()
        cfg["models"]["providers"]["glm"]["auth"] = "api-key"
        self.write_cfg(cfg)
        g, lines = self.gate_obj({"cron_autofix": {"pending": [entry]}})
        g.cron_config_fixup("doctor1")
        self.assertEqual(g.j["cron_autofix"], {"applied": [entry]})
        self.assertEqual(lines, [])
        led = json.loads((self.upg / "gate" / "runs" / g.j["run_id"] / "transform-ledger.json").read_text())
        self.assertEqual(led, [{"step": "C1", "path": "models.providers.glm.auth", "before": None, "after": "api-key"}])
        # the write never happened: planned again, written once
        self.write_cfg(CFG_GLM)
        g, lines = self.gate_obj({"cron_autofix": {"pending": [entry]}})
        g.cron_config_fixup("doctor1")
        self.assertEqual(lines, ["[gate] 4/8 " + FIXUP.format(rt="2026.11.1")])
        self.assertEqual([{k: a[k] for k in FIXUP_ENTRY} for a in g.j["cron_autofix"]["applied"]], [FIXUP_ENTRY])
        after = self.cfgp.read_bytes()
        g.cron_config_fixup("doctor1")
        g.cron_config_fixup("doctor2")
        self.assertEqual((len(lines), self.cfgp.read_bytes(), len(g.j["cron_autofix"]["applied"])), (1, after, 1))

    def test_before_pass_2_when_pass_1_ran_without_it(self):
        """A run of an earlier add-on version whose pass 1 ran without the fixup: it comes before pass 2."""
        g, lines = self.gate_obj({"phases_done": ["precheck", "cleanup", "doctor1", "fixups"]})
        g.cron_config_fixup("doctor2")
        self.assertEqual(lines, ["[gate] 6/8 " + FIXUP.format(rt="2026.11.1")])
        self.assertEqual(g.j["cron_autofix"]["applied"][0]["phase"], "doctor2")
        self.assertIn("(before doctor pass 2)", G.cron_fixup_done_lines(g.j)[0])

    def test_write_failure_warns_and_never_holds(self):
        """A failed write or an openclaw.json the gate cannot parse: openclaw.json unchanged, a WARN, no HOLD."""
        g, lines = self.gate_obj()
        before = self.cfgp.read_bytes()

        def broken(_cfg):
            raise OSError(28, "No space left on device")
        g.write_config = broken
        self.assertIsNone(g.cron_config_fixup("doctor1"))
        self.assertEqual(lines, ["WARN [gate] 4/8 config fixup failed: openclaw.json could not be written (OSError: "
                                 "[Errno 28] No space left on device); unchanged"])
        self.assertEqual((g.j["cron_autofix"], self.cfgp.read_bytes()), ({"applied": []}, before))
        # openclaw.json that is no strict JSON (JSON5 comment): nothing written, a WARN
        text = self.cfgp.read_text().replace("{", "{\n  // edited by hand", 1)
        self.cfgp.write_text(text)
        g, lines = self.gate_obj()
        g.cron_config_fixup("doctor1")
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("WARN [gate] 4/8 config fixup skipped: openclaw.json cannot be read ("),
                        lines)
        self.assertEqual((self.cfgp.read_text(), "cron_autofix" in g.j), (text, False))

    def test_auth_already_set_is_left_alone(self):
        """auth "oauth"/"token": no write; the precheck keeps the WARN with the SecretRef advice."""
        for auth in ("oauth", "token"):
            with self.subTest(auth=auth):
                cfg = json.loads(json.dumps(CFG_GLM))
                cfg["models"]["providers"]["glm"]["auth"] = auth
                self.write_cfg(cfg)
                lines = self.dry()
                self.assertFalse([ln for ln in lines if "config fixup" in ln], lines)
                fix = next(ln for ln in lines if ln.startswith("WARN [gate] provider glm:"))
                self.assertIn(f"give the key as an env SecretRef: a gateway_env_vars entry, then openclaw config set "
                              f"models.providers.glm.apiKey '{G.CRON_ENV_REF}' --strict-json (models.providers.glm.auth "
                              f"\"{auth}\" stays)", fix)
        before = self.cfgp.read_bytes()
        self.doctor_copies_key("2026.11.1")
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("config fixup", self.out)
        self.assertEqual(self.cfg_now()["models"]["providers"]["glm"]["auth"], "token")
        self.assertEqual(json.loads((self.run_dir() / "config.pre-pass1.json").read_bytes()), json.loads(before))
        self.assertNotIn("cron_autofix", self.journal())

    def test_catalog_only_key_is_left_alone(self):
        """A key only in an agent's models.json: no provider entry is created; the WARN says to declare it."""
        cfg = json.loads(json.dumps(CFG_GLM))
        cfg["models"]["providers"]["glm"]["auth"] = "api-key"
        self.write_cfg(cfg)
        add_jobs(self.state, [("job-cat", {"agentId": "haus", "sessionTarget": "isolated",
                                           "payload": {"kind": "agentTurn", "message": PROMPT, "model": "cat/m",
                                                       "fallbacks": []}})], start=50)
        (self.state / "agents" / "haus" / "agent" / "models.json").write_text(
            '{"providers": {"cat": {"apiKey": "sk-synthetic-cat-0000"}}}')
        lines = self.dry()
        self.assertFalse([ln for ln in lines if "config fixup" in ln], lines)
        self.assertTrue([ln for ln in lines if ln.startswith("WARN [gate] provider cat: an agent's model catalog")])
        before = self.cfgp.read_bytes()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("config fixup", self.out)
        self.assertNotIn("cat", self.cfg_now()["models"]["providers"])
        self.assertEqual(json.loads((self.run_dir() / "config.pre-pass1.json").read_bytes()), json.loads(before))
        self.assertNotIn("cron_autofix", self.journal())
        self.assertNotIn("sk-synthetic-cat-0000", self.out + json.dumps(self.journal()))

    def test_key_also_in_main_catalog_and_a_keyed_fallback_provider(self):
        """The layout of the owner's install (2026-11-07, structure only, synthetic values): the same literal
        placeholder for glm in openclaw.json and in agents/main/agent/models.json, a second local provider with the
        same placeholder that no cron job uses, a catalog-only provider no job uses, and a cloud provider with a real
        literal key as the last default fallback. Doctor copies the duplicate only once; current config owns the
        provider's auth, so the openclaw.json fixup covers glm and no catalog WARN appears for it. The fallback
        provider gets its own fixup; the unused providers are left alone; no key value is printed."""
        cloud_key = "AIzaSy-synthetic-cloud-key-0000000000000000"
        cfg = json.loads(json.dumps(CFG_GLM))
        prov = cfg["models"]["providers"]
        prov["glm-alt"] = dict(prov["glm"], models=[{"id": "glm-5-alt"}])
        prov["cloud"] = {"baseUrl": "https://cloud.invalid/v1", "api": "openai-completions", "apiKey": cloud_key,
                         "models": [{"id": "c1"}]}
        cfg["agents"]["defaults"]["model"]["fallbacks"] = ["openai/gpt-5.5", "cloud/c1"]
        self.write_cfg(cfg)
        add_jobs(self.state, [("job-default", {"agentId": "main", "sessionTarget": "isolated",
                                               "payload": {"kind": "agentTurn", "message": PROMPT}})], start=50)
        (self.state / "agents" / "main" / "agent" / "models.json").write_text(json.dumps({"providers": {
            "glm": {"baseUrl": prov["glm"]["baseUrl"], "apiKey": GLM_KEY, "models": [{"id": "glm-5"}]},
            "glm-alt": {"baseUrl": prov["glm"]["baseUrl"], "apiKey": GLM_KEY, "models": [{"id": "glm-5-alt"}]},
            "spare": {"baseUrl": "http://127.0.0.1:8009/v1", "apiKey": "spare1", "models": [{"id": "s"}]}}}))
        lines = self.dry()
        fixups = [ln for ln in lines if "config fixup: would set" in ln and ln.startswith("[gate] 1/8 ")]
        self.assertEqual(sorted(ln.split("models.providers.")[1].split(".auth")[0] for ln in fixups),
                         ["cloud", "glm"], lines)
        self.assertFalse([ln for ln in lines if "model catalog" in ln or "glm-alt" in ln or "spare" in ln], lines)
        out = "\n".join(lines)
        for secret in (GLM_KEY, cloud_key, "spare1"):
            self.assertNotIn(secret, out)
        self.doctor_copies_key("2026.11.1")
        self.assertEqual(self.run_gate(), 0, self.out)
        now = self.cfg_now()["models"]["providers"]
        self.assertEqual((now["glm"].get("auth"), now["cloud"].get("auth")), ("api-key", "api-key"))
        self.assertNotIn("auth", now["glm-alt"])
        for secret in (GLM_KEY, cloud_key, "spare1"):
            self.assertNotIn(secret, self.out + json.dumps(self.journal()))

    def test_no_enabled_cron_job_uses_the_provider(self):
        cfg = json.loads(json.dumps(CFG_GLM))
        cfg["agents"]["defaults"]["model"] = {"primary": "lan/q", "fallbacks": ["openai/gpt-5.5"]}
        self.write_cfg(cfg)
        con = sqlite3.connect(str(self.sdb))
        con.execute("UPDATE cron_jobs SET enabled=0 WHERE job_id IN ('job-glm-haus', 'job-lan-fb')")
        con.commit()
        con.close()
        lines = self.dry()
        self.assertFalse([ln for ln in lines if "config fixup" in ln or "provider glm" in ln], lines)
        before = self.cfgp.read_bytes()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("config fixup", self.out)
        self.assertNotIn("auth", self.cfg_now()["models"]["providers"]["glm"])
        self.assertEqual(json.loads((self.run_dir() / "config.pre-pass1.json").read_bytes()), json.loads(before))
        self.assertNotIn("cron_autofix", self.journal())

    def test_own_stored_login_is_left_alone(self):
        """auth "api-key" would set a provider's own login aside for every run (here an OAuth login next to a literal
        openai key): no fixup, an info line; doctor's copy of the same key (an earlier doctor run) is no own login."""
        cfg = json.loads(json.dumps(CFG_GLM))
        cfg["models"]["providers"]["openai"] = {"apiKey": "sk-synthetic-openai-0000"}
        self.write_cfg(cfg)
        adb = self.state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"
        store = json.loads(json.dumps(T.AUTH_1004_STORE))
        store["profiles"]["glm:default"] = {"type": "api_key", "provider": "glm", "key": GLM_KEY}  # earlier copy
        con = sqlite3.connect(str(adb))
        con.execute("UPDATE auth_profile_store SET store_json=? WHERE store_key='primary'", (json.dumps(store),))
        con.commit()
        con.close()
        lines = self.dry()
        self.assertIn("[gate] 1/8 " + FIXUP_PRE.format(verb="would set", rt="2026.11.1"), lines)
        self.assertIn("[gate] 1/8 info: no automatic config fixup for openai: it has a stored login of its own: a "
                      "subscription login, a token, or a stored API key that differs from the configured one "
                      "(possibly doctor's copy of an earlier value). models.providers.openai.auth = \"api-key\" sets "
                      "that login aside for every run of openai, not only for cron; to do so after the start: "
                      "openclaw config set models.providers.openai.auth api-key. The provider openai line gives the "
                      "other options", lines)
        # the provider line: the refusal comes from openai's own login, and both remedies cost it for every run
        own = ("provider openai: OpenClaw 2026.11.1 runs openai on a stored login of its own (a subscription login, a "
               "token or another API key), not on the literal key in models.providers.openai.apiKey. To lift the "
               "refusal for the cron jobs above that use openai and keep their fallbacks, run: openclaw config set "
               "models.providers.openai.auth api-key (OpenClaw then uses the configured key for openai, not the "
               "stored login; no restart needed), or give the key as an env SecretRef (a gateway_env_vars entry, then "
               "openclaw config set models.providers.openai.apiKey '" + G.CRON_ENV_REF + "' --strict-json); this "
               "makes every run of openai, not only cron, use the configured key instead of that login. To keep the "
               "login: drop openai from the job's fallbacks (openclaw automations edit <id> --fallbacks <list> "
               "without it), and for a job whose own model is on openai the last resort below")
        self.assertIn("WARN [gate] " + own, lines)
        rec = G.cron_account_report(self.state, cfg, "2026.11.1", pending_copies=True)
        self.assertEqual([(k["provider"], k.get("own_login")) for k in rec["key_fix"]],
                         [("glm", None), ("openai", True)])  # glm: doctor's earlier copy of the same key
        self.assertFalse([ln for ln in lines if "would set models.providers.openai" in ln])
        self.assertEqual(G.own_provider_logins(self.state, cfg, {"glm": GLM_KEY, "openai": "x"}), {"openai"})
        # another key for glm, a declared non-api_key profile: an own login too
        self.assertEqual(G.own_provider_logins(self.state, cfg, {"glm": "sk-synthetic-other"}), {"glm"})
        decl = dict(cfg, auth={"profiles": {"glm:sub": {"provider": "glm", "mode": "oauth"}}})
        self.assertEqual(G.own_provider_logins(self.state, decl, {"glm": GLM_KEY}), {"glm"})
        self.assertEqual(G.own_provider_logins(self.state, cfg, {}), set())
        self.assertEqual(self.run_gate(), 0, self.out)
        provs = self.cfg_now()["models"]["providers"]
        self.assertEqual((provs["glm"].get("auth"), provs["openai"].get("auth")), ("api-key", None))
        # finalize and status give the same provider line (the postconditions' report marks the own login too)
        fin = self.out[self.out.index("[gate] 7/8 postconditions OK"):].splitlines()
        self.assertIn("WARN [gate] " + own, fin)
        self.assertIn("    " + own, G.status_lines())
        self.assertNotIn("sk-synthetic-openai-0000", self.out + json.dumps(self.journal()))

    def test_include_config_writes_nothing_and_warns(self):
        """openclaw.json with $include: the gate cannot write it safely; a WARN gives the command, the D1 report
        stays (the jobs on glm are refused once doctor copied the key)."""
        self.write_cfg(included(CFG_GLM))
        warn = ("config fixup skipped: openclaw.json uses $include ($include), so the gate does not write it; after "
                "the start run: openclaw config set models.providers.glm.auth api-key (" + FIXUP_WHY + ")")
        lines = self.dry()
        self.assertIn("WARN [gate] 1/8 " + warn.format(rt="2026.11.1"), lines)
        self.assertIn("WARN [gate] " + D1_HAUS.format(rt="2026.11.1"), lines)
        self.assertIn("WARN [gate] " + D1_FIX.format(rt="2026.11.1"), lines)
        self.assertFalse([ln for ln in lines if "would set" in ln], lines)
        self.plan()
        self.assertIn("WARN [gate] plan: " + warn.format(rt="2026.11.1"), self.out.splitlines())
        before = self.cfgp.read_bytes()
        self.doctor_copies_key("2026.11.1")
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("WARN [gate] 4/8 " + warn.format(rt="2026.11.1"), self.out.splitlines())
        self.assertEqual((self.run_dir() / "config.pre-pass1.json").read_bytes(), before)
        self.assertNotIn("auth", self.cfg_now()["models"]["providers"]["glm"])
        j = self.journal()
        self.assertNotIn("cron_autofix", j)
        self.assertEqual(j["cron_binding_forecast"]["autofix_skipped"],
                         [{"provider": "glm", "path": "models.providers.glm.auth", "why": "include"}])
        self.assertIn("job-glm-haus", [a["id"] for a in j["cron_binding"]["affected"]])
        self.assertNotIn(GLM_KEY, self.out + json.dumps(j))

    def test_status_of_a_run_that_stopped_before_doctor(self):
        rec = {"runtime": "2026.11.1", "checked": 4, "affected": [],
               "autofix": [{"provider": "glm", "path": "models.providers.glm.auth", "jobs": ["job-glm-haus"]}]}
        st = G._status_cron({"cron_binding_forecast": rec})
        self.assertEqual(st[0], "  config fixup before doctor pass 1: would set models.providers.glm.auth = "
                         "\"api-key\" (" + FIXUP_WHY.format(rt="2026.11.1") + "; precheck forecast)")
        self.assertEqual(G._status_cron({"cron_binding_forecast": rec, "doctor_started": True})[:1],
                         ["  cron jobs without a recorded inference account (openclaw/openclaw#192195, OpenClaw "
                          "2026.11.1, precheck forecast): none affected (4 checked)"])

    def test_fallback_only_jobs_get_no_2026_11_5_promise(self):
        """The owner's layout after the fix: every job runs its own model on glm (the configured key) or on a local model
        and stops only at a stored-login fallback. OpenClaw's own migration (2026.11.5) resolves only the job's own
        model and skips a job whose model runs on a configured key or needs none (inference-binding-migration.ts), and
        2026.11.5 still refuses an unbound cron attempt on a stored login: no line promises that 2026.11.5 records these
        jobs, and none offers the binding (it would make the fallback the job's model)."""
        con = sqlite3.connect(str(self.sdb))
        con.execute("UPDATE cron_jobs SET enabled=0 WHERE job_id='job-morning'")
        con.commit()
        con.close()
        # review 11.1 (regress-docs): the closing note excepts the config fixup named above it
        close = ("2 cron job(s) above: the add-on changes nothing for these jobs apart from the config fixup above; "
                 + OUTLOOK_FB_ALONE + ". " + G.CRON_FALLBACK)
        lines = self.dry()
        self.assertIn("WARN [gate] " + close, lines)
        self.doctor_copies_key("2026.11.1")
        self.assertEqual(self.run_gate(), 0, self.out)
        fin = self.out[self.out.index("[gate] 7/8 postconditions OK"):].splitlines()
        self.assertIn("WARN [gate] " + close, fin)
        st = G.status_lines()
        self.assertIn("    " + OUTLOOK_FB_ALONE + ". " + G.CRON_FALLBACK, st)
        text = "\n".join(lines + fin + st)
        self.assertNotIn("records the inference account", text)
        self.assertNotIn("@<profileId>", text)
        # whose account 2026.11.5 records: the jobs whose own model is on a stored login (no AWS SDK, no key fix)
        prim = {"id": "p", "primary_affected": True, "refs": ["openai/gpt-5.5"]}
        fb = {"id": "f", "primary_affected": False, "refs": ["openai/gpt-5.5"]}
        aws = {"id": "a", "primary_affected": True, "refs": ["bedrock/x"], "aws_sdk": ["bedrock/x"]}
        keyed = {"id": "k", "primary_affected": True, "refs": ["glm/glm-5"]}
        kf = {"key_fix": [{"provider": "glm"}]}
        self.assertEqual(G._cron_promise([fb], {}), "")
        self.assertEqual(G._cron_promise([aws, fb], {}), "")
        self.assertEqual(G._cron_promise([keyed, fb], kf), "")
        self.assertEqual(G._cron_promise([prim], {}), "such jobs")
        self.assertEqual(G._cron_promise([prim, fb], {}), "the jobs whose own model is on a stored login")
        self.assertEqual(G._cron_promise([prim, keyed], kf), "the jobs whose own model is on another stored login")
        self.assertEqual(G._cron_outlook([prim], {}), [OUTLOOK_PRIM.format(who="such jobs")])
        self.assertEqual(G._cron_remedy([prim]), G.CRON_MANUAL)
        self.assertEqual(G._cron_remedy([fb]), G.CRON_FALLBACK)

    def test_providers_in_an_included_file(self):
        """$include with the providers in the included file: the report reads only openclaw.json itself, so it says
        so in the precheck, the finalize and `oc-upgrade status` (with the command), says "keeps working" only as far
        as openclaw.json shows, and qualifies the line about unconfigured agents; the gate writes nothing."""
        cfg = json.loads(json.dumps(CFG_GLM))
        moved = {"models": cfg.pop("models")}
        cfg["$include"] = "./models.json5"
        self.write_cfg(cfg)
        (self.state / "models.json5").write_text(json.dumps(moved))
        add_jobs(self.state, [("job-mail", {"agentId": "mail", "sessionTarget": "isolated",
                                            "payload": {"kind": "agentTurn", "message": PROMPT,
                                                        "model": "lan/q"}})], start=50)
        inc = ("openclaw.json uses $include ($include): the cron report reads only openclaw.json itself, so providers "
               "and agents defined in included files are not checked, and the gate makes no automatic config fixup. "
               "For a provider defined there with a literal apiKey that cron jobs use, run after the start: openclaw "
               "config set models.providers.<provider>.auth api-key (doctor stores such a key as a login, and "
               "OpenClaw 2026.11.1 then refuses every unbound cron run on it: openclaw/openclaw#192195; for a "
               "provider with a stored login of its own this sets that login aside for every run, not only for cron)")
        lines = self.dry()
        self.assertIn("WARN [gate] 1/8 " + inc, lines)
        self.assertIn("WARN [gate] cron job 'Local digest' (job-local): its model glm/glm-5 needs no stored login (as "
                      "far as openclaw.json itself shows; its included files are not checked) and keeps working, but "
                      "when it fails OpenClaw 2026.11.1 stops at the fallback openai/gpt-5.5 (stored login, no "
                      "recorded inference account; openclaw/openclaw#192195) instead of trying further models", lines)
        self.assertIn("[gate] 1/8 info: 1 enabled cron job(s) belong to agent(s) that openclaw.json itself does not "
                      "configure (mail; its included files are not checked): unless an included file configures them, "
                      "OpenClaw cancels their runs ('cron job agent is unavailable'); the inference-account report "
                      "leaves them out: 'Job Mail' (job-mail)", lines)
        self.assertFalse([ln for ln in lines if "config fixup:" in ln], lines)
        raw = self.cfgp.read_text()
        plan = G.cron_fixup_plan(self.state, cfg, raw, "2026.11.1")
        self.assertEqual((plan["fix"], plan["include"]), ([], ["$include"]))
        before = self.cfgp.read_bytes()
        self.doctor_copies_key("2026.11.1")
        self.assertEqual(self.run_gate(), 0, self.out)
        fin = self.out[self.out.index("[gate] 7/8 postconditions OK"):].splitlines()
        self.assertIn("WARN [gate] " + inc, fin)
        self.assertIn("  " + inc, G.status_lines())
        self.assertNotIn("models", self.cfg_now())  # nothing written into openclaw.json (no provider entry)
        self.assertEqual(json.loads((self.run_dir() / "config.pre-pass1.json").read_bytes()), json.loads(before))
        j = self.journal()
        self.assertNotIn("cron_autofix", j)
        self.assertEqual(j["cron_binding"]["include"], ["$include"])
        self.assertNotIn(GLM_KEY, self.out + json.dumps(j))
        # without $include no such line and no key
        self.assertNotIn("include", G.cron_account_report(self.state, CFG_GLM, "2026.11.1"))
        self.assertIsNone(G.cron_include_line({"affected": []}))

    def test_env_template_key_and_doctors_earlier_copy(self):
        """OpenClaw substitutes "${NAME}" / "${NAME:-default}" (NAME also lower-case-free with "_") before doctor copies
        the key, but treats only "${UPPER}"/"$UPPER" as a SecretRef: a stored api_key profile with the substituted value
        is doctor's earlier copy, no login of its own, so the gate still sets auth "api-key"."""
        cfg = json.loads(json.dumps(CFG_GLM))
        cfg["models"]["providers"]["glm"]["apiKey"] = "${GLM_KEY:-sk-synthetic-local}"
        self.write_cfg(cfg)
        adb = self.state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"
        store = json.loads(json.dumps(T.AUTH_1004_STORE))
        store["profiles"]["glm:default"] = {"type": "api_key", "provider": "glm", "key": "sk-synthetic-local"}
        con = sqlite3.connect(str(adb))
        con.execute("UPDATE auth_profile_store SET store_json=? WHERE store_key='primary'", (json.dumps(store),))
        con.commit()
        con.close()
        lines = self.dry()
        self.assertIn("[gate] 1/8 " + FIXUP_PRE.format(verb="would set", rt="2026.11.1"), lines)
        self.assertFalse([ln for ln in lines if "no automatic config fixup for glm" in ln], lines)
        tmpl = {"glm": "${GLM_KEY:-sk-synthetic-local}"}
        self.assertEqual(G.own_provider_logins(self.state, cfg, tmpl, env={}), set())
        # the variable set (gateway_env_vars): doctor copied its value; the default is then no copy of it
        self.assertEqual(G.own_provider_logins(self.state, cfg, tmpl, env={"GLM_KEY": "sk-synthetic-local"}), set())
        self.assertEqual(G.own_provider_logins(self.state, cfg, tmpl, env={"GLM_KEY": "sk-synthetic-env"}), {"glm"})
        self.assertEqual(G.own_provider_logins(self.state, cfg, {"glm": "${_GLM}"}, env={"_GLM": "sk-synthetic-local"}),
                         set())
        self.assertEqual(G.own_provider_logins(self.state, cfg, {"glm": "$${_GLM}"}, env={"_GLM": "sk-synthetic-local"}),
                         {"glm"})
        self.assertNotIn("sk-synthetic-local", "\n".join(lines))

    def test_a_fixed_model_behind_a_refused_fallback_is_not_kept_working(self):
        """A job reaches the fixed provider only after a fallback that stays refused (the refusal stops the chain): the
        fix is still written, but the job is not counted as kept working; the readiness line says why it is set."""
        cfg = json.loads(json.dumps(CFG_GLM))
        cfg["models"]["providers"]["google"] = {"apiKey": "sk-synthetic-google-0000"}
        self.write_cfg(cfg)
        add_jobs(self.state, [("job-lan-g", {"agentId": "main", "sessionTarget": "isolated",
                                             "payload": {"kind": "agentTurn", "message": PROMPT, "model": "lan/q",
                                                         "fallbacks": ["openai/gpt-5.5", "google/gemini-3-pro"]}})],
                 start=50)
        lines = self.dry()
        self.assertIn("[gate] 1/8 config fixup: would set models.providers.google.auth = \"api-key\" before doctor "
                      "pass 1 (doctor stores its literal key as a login; without this OpenClaw 2026.11.1 refuses every "
                      "unbound cron run on google: openclaw/openclaw#192195)", lines)
        self.assertIn("[gate] 1/8 " + FIXUP_KEPT.format(rt="2026.11.1"), lines)
        self.assertIn("[gate] 1/8 info: 1 enabled cron job(s) reach google/gemini-3-pro only after a fallback that "
                      "stays refused (the WARN lines below): the automatic fix covers that model, but the job stops "
                      "before it: 'Job Lan G' (job-lan-g)", lines)
        self.assertIn("[gate]   cron config fixup: would set models.providers.google.auth = \"api-key\" before doctor "
                      "pass 1 (for 1 enabled cron job(s) that reach google only after a fallback that stays refused; "
                      "openclaw/openclaw#192195)", lines)
        self.assertFalse([ln for ln in lines if "on google working" in ln], lines)
        before = {"affected": [{"id": "j", "refs": ["glm/glm-5", "openai/gpt-5.5", "google/g"]}]}
        after = {"affected": [{"id": "j", "refs": ["openai/gpt-5.5"]}]}
        behind = []
        self.assertEqual(G.cron_fixup_kept_jobs(before, after, {"glm", "google"}, behind),
                         [(before["affected"][0], ["glm/glm-5"])])
        self.assertEqual(behind, [(before["affected"][0], ["google/g"])])
        self.assertNotIn("sk-synthetic-google-0000", "\n".join(lines))

    def test_pass_2_diff_leaves_out_the_fixup_before_pass_2(self):
        """A run whose pass 1 ran without the fixup (an earlier add-on version) gets it before pass 2; when pass 2
        then changes openclaw.json, its diff lists only doctor's change, not the gate's own auth."""
        orig = G.Gate.cron_config_fixup

        def earlier_version(gate, phase):
            return None if phase == "doctor1" else orig(gate, phase)
        p2 = {"state_uv": 22, "agent_uv": 27, "app_version": "2026.11.1"}
        p1 = dict(p2, app_version="2026.10.10")  # pass 2 then changes meta.lastTouchedVersion
        self.doctor_script(passes=[p1, p2, p2])
        with unittest.mock.patch.object(G.Gate, "cron_config_fixup", earlier_version):
            self.assertEqual(self.run_gate(), 0, self.out)
        out = self.out.splitlines()
        self.assertIn("[gate] 6/8 " + FIXUP.format(rt="2026.11.1"), out)
        self.assertIn("[gate] 6/8 doctor pass 2 changed openclaw.json: meta.lastTouchedVersion", out)
        self.assertEqual(self.cfg_now()["models"]["providers"]["glm"]["auth"], "api-key")


    def test_nothing_on_1004(self):
        """2026.10.4 (no cron refusal): no line, no write, no journal key, no ledger step."""
        self.set_runtime("2026.10.4", 20, 24)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.9", "mode": "bump"}))
        con = sqlite3.connect(str(self.sdb))
        con.execute("PRAGMA user_version=19")
        con.execute("UPDATE schema_meta SET schema_version=19, app_version='2026.9.9' WHERE meta_key='primary'")
        con.commit()
        con.close()
        lines = self.dry()
        self.assertFalse([ln for ln in lines if "config fixup" in ln], lines)
        self.plan()
        self.assertNotIn("config fixup", self.out)
        before = self.cfgp.read_bytes()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("config fixup", self.out)
        self.assertEqual((self.run_dir() / "config.pre-pass1.json").read_bytes(), before)
        self.assertNotIn("auth", self.cfg_now()["models"]["providers"]["glm"])
        self.assertNotIn("cron_autofix", self.journal())
        led = C.load_json_or_none(self.run_dir() / "transform-ledger.json") or []
        self.assertFalse([e for e in led if e.get("step") == "C1"])
        self.assertFalse([ln for ln in G.status_lines() if "config fixup" in ln])


def stat_mode(p):
    return os.stat(p).st_mode & 0o777


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
