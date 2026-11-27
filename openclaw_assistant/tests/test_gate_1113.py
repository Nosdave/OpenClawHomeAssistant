"""OpenClaw 2026.11.2 / 2026.11.3 / 2026.11.4 (maintenance releases on the 2026.11.1 line; PR #7 retargeted to
2026.11.3, 0.5.94-full6 bundles 2026.11.4, which keeps every behaviour below: RT models the bundled runtime).

- R3/R4: OpenClaw's doctor migration of cron inference accounts (#172792) was backported to 2026.11.2
  (runtime_caps cron_doctor_migration from 2026.11.2). It records only the account of a job's own model on a stored
  login: the precheck says so for those jobs only (info line), keeps the WARN lines of the jobs that only stop at a
  fallback on a stored login, and says that a bound job's fallbacks to other providers are refused.
- R5: whenever doctor commits a cron repair (also that migration) it writes a full plaintext copy of the state database
  <state>/state/openclaw.sqlite.doctor-cron-<ms>-<uuid>.bak and logs "Saved pre-repair cron backup: <path>". The gate
  journals, reports and deletes the ones a gate run made like doctor's pre-migration copies (gate_cleanup_hours),
  also after an interrupted and resumed pass and for runs of earlier add-on versions (their doctor logs).
- Doctor's pre-repair recovery directories (<db dir>/openclaw-<repair>-recovery-XXXXXX/database.sqlite, full plaintext
  copies before a media-persistence, transcript, session-window, index or orphan task delivery repair): journaled,
  reported and deleted like the cron backups.
- R6: from 2026.11.2 the gateway warns at every start for each unbound agentTurn job whose own model runs on a
  configured key (doctor leaves those unbound on purpose): an info line in the finalize and `oc-upgrade status`.
- R7: from 2026.11.3 an agent whose memory search provider differs from the shared one no longer inherits the shared
  remote apiKey/headers (#184966): a precheck WARN with agent ids and field names only.
- R8: from 2026.11.3 a model row without maxTokens gets an output cap sized from its context window (#193899): a
  precheck info line with provider/model ids and numbers only.
Synthetic fixtures only (10.4-layout state from test_gate, synthetic keys and jobs).
"""

import json
import os
import shutil
import sqlite3
import sys
import threading
import time
import unittest
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
import test_gate_cron_binding as CB  # noqa: E402
import test_gate_skill_workshop as SW  # noqa: E402

RT = "2026.11.4"
UUID_NEW = "0b4e9f2c-1d2e-4f3a-9b8c-7d6e5f4a3b2c"
UUID_OLD = "11111111-2222-4333-8444-555555555555"
OLD_MS = 1700000000000  # 2023: a copy OpenClaw made long before any gate run
SECRET = "SYNTHETIC-SECRET-VALUE-0000"
BINDING = {"version": 1, "provider": "openai", "profileId": "openai:default", "authorizationId": "a" * 64,
           "authRequirement": "subscription", "source": "doctor"}
FB_ONLY = ("records only the account of a job's own model: a job whose own model needs no account stays unbound, and "
           "its fallback on a stored login stays refused")


def cron_bak(ms, uid=UUID_NEW):
    return f"state/openclaw.sqlite.doctor-cron-{ms}-{uid}.bak"


def future_ms():
    """A creation time after the run's start (the run starts after the test set it up)."""
    return int(time.time() * 1000) + 60_000


class CapabilityTests(unittest.TestCase):
    def test_floors(self):
        for v, dm, mem in (("2026.11.1", False, False), ("2026.11.2", True, False), ("2026.11.3", True, True),
                           ("2026.11.4", True, True),
                           ("2026.11.5-beta.2", True, True)):
            caps = C.runtime_caps(v)
            self.assertEqual((caps["cron_doctor_migration"], caps["memory_remote_scoped"],
                              caps["output_cap_raised"]), (dm, mem, mem), v)
        # the version table says 2026.11.2 now; no text names 2026.11.5 as the first release with the migration
        for text in (G.CRON_AWS_SDK,
                     "; ".join(G._cron_outlook([{"id": "p", "primary_affected": True, "refs": ["openai/x"]},
                                                {"id": "f", "refs": ["openai/x"]}], {})),
                     "; ".join(G._cron_outlook([{"id": "f", "refs": ["openai/x"]}], {}))):
            self.assertNotIn("2026.11.5", text)
            self.assertIn("2026.11.2", text)


# --- R3/R4/R6: cron on 2026.11.4 ------------------------------------------------------------------------------

GLM_OFF = [("job-glm-off", {"agentId": "main", "sessionTarget": "isolated", "enabled": False,
                            "payload": {"kind": "agentTurn", "message": CB.PROMPT, "model": "glm/glm-5"}})]
# N2: a job on the openai login with the fixed glm as fallback (the rehearsal's 'Codex-Bericht'), and a disabled one on
# the anthropic login (doctor binds it too: 'Claude-Notiz')
CODEX_JOBS = [("job-codex", {"agentId": "main", "sessionTarget": "isolated", "payload": {
                  "kind": "agentTurn", "message": CB.PROMPT, "model": "openai/gpt-5.5", "fallbacks": ["glm/glm-5"]}}),
              ("job-claude-off", {"agentId": "main", "sessionTarget": "isolated", "enabled": False, "payload": {
                  "kind": "agentTurn", "message": CB.PROMPT, "model": "anthropic/claude-sonnet-4-6",
                  "fallbacks": ["glm/glm-5", "openai/gpt-5.5"]}})]


class CronOn1113Tests(T.GateEnv):
    """A layout from a real install on 2026.11.4: glm (literal placeholder key) as primary, kept on its configured key by the
    gate's auth "api-key" fixup; openai/anthropic stored logins as fallbacks; one job (job-morning) on openai."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, agents=("main", "haus"), content=True)
        CB.add_jobs(self.state, CB.GLM_JOBS)
        CB.add_jobs(self.state, GLM_OFF, start=20)
        self.write_cfg(CB.CFG_GLM)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime(RT, 22, 27)
        self.hooks()
        self.sdb = self.state / "state" / "openclaw.sqlite"

    def dry(self):
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        return lines

    def doctor_binds_morning(self, extra_sql=(), **extra):
        """Like OpenClaw 2026.11.4 doctor: stores the literal glm key as glm:default, records job-morning's account
        (its own model is on the openai login) after a pre-repair copy of the state database."""
        store = json.loads(json.dumps(T.AUTH_1004_STORE))
        store["profiles"]["glm:default"] = {"type": "api_key", "provider": "glm", "key": CB.GLM_KEY}
        bak = cron_bak(future_ms())
        self.doctor_script(state_uv=22, agent_uv=27, app_version=RT, drop_tables=["cron_run_logs"],
                           remove=["identity/device.json"], sql=[
            "INSERT OR REPLACE INTO config_machine_state VALUES ('auth.sharedStore', '{\"location\": \"state-db\"}', 0)",
            "INSERT OR REPLACE INTO config_machine_state VALUES ('authProfiles.store', '%s', 0)" % json.dumps(store),
            "UPDATE cron_jobs SET job_json = json_set(job_json, '$.inferenceBinding', json('%s')) "
            "WHERE job_id = 'job-morning'" % json.dumps(BINDING)] + list(extra_sql), **extra)
        return bak

    def test_precheck_promises_doctor_only_for_a_job_on_its_own_stored_login(self):
        lines = self.dry()
        text = "\n".join(lines)
        self.assertIn("[gate] 1/8 info: 1 enabled cron job(s) without a recorded inference account run their own model "
                      "on a stored login: 'Morning summary' (job-morning); OpenClaw 2026.11.4 doctor records that "
                      "account during the migration when exactly one fits (openclaw/openclaw#172792), but then refuses "
                      "their fallbacks to other providers (as with openclaw/openclaw#192463); the gate reports the jobs "
                      "doctor leaves after the migration", lines)
        # the jobs that only stop at a fallback keep their WARN lines (doctor records nothing for them)
        self.assertNotIn("WARN [gate] cron job 'Morning summary'", text)
        for jid in ("'Local digest' (job-local)", "'Job Lan Fb' (job-lan-fb)"):
            self.assertIn(f"WARN [gate] cron job {jid}: its model ", text)
        self.assertIn("WARN [gate] 2 cron job(s) above: the add-on changes nothing for these jobs apart from the config "
                      f"fixup above; OpenClaw 2026.11.4 doctor {FB_ONLY}. " + G.CRON_FALLBACK, lines)
        self.assertIn("[gate]   cron inference accounts: 1 enabled cron job(s) run their own model on a stored login "
                      "without a recorded account; OpenClaw 2026.11.4 doctor records it when exactly one account fits "
                      "(openclaw/openclaw#172792), then refuses their fallbacks to other providers", lines)
        self.assertIn("[gate]   cron inference accounts: 2 enabled cron job(s) stop at a stored login on OpenClaw "
                      "2026.11.4 and doctor records no account for them (the WARN lines above, "
                      "openclaw/openclaw#192195); apart from the config fixup above, the gate changes nothing for cron",
                      lines)
        # the earlier single line that promised doctor's account for every affected job is gone
        self.assertNotIn("doctor records the account (openclaw/openclaw#172792)", text)
        self.assertNotIn("2026.11.5", text)
        self.assertNotIn(CB.GLM_KEY, text)

    def test_owner_layout_only_fallbacks_no_promise(self):
        """All enabled jobs on glm or a local model: doctor binds none of them, so no line promises it does."""
        con = sqlite3.connect(str(self.sdb))
        con.execute("UPDATE cron_jobs SET enabled=0 WHERE job_id='job-morning'")
        con.commit()
        con.close()
        lines = self.dry()
        text = "\n".join(lines)
        self.assertNotIn("records that account", text)
        self.assertNotIn("records it when", text)
        self.assertIn("WARN [gate] 2 cron job(s) above: the add-on changes nothing for these jobs apart from the config "
                      f"fixup above; OpenClaw 2026.11.4 doctor {FB_ONLY}. " + G.CRON_FALLBACK, lines)
        self.assertEqual([ln for ln in lines if ln.startswith("[gate]   cron inference accounts:")], [
            "[gate]   cron inference accounts: 2 enabled cron job(s) stop at a stored login on OpenClaw 2026.11.4 and "
            "doctor records no account for them (the WARN lines above, openclaw/openclaw#192195); apart from the "
            "config fixup above, the gate changes nothing for cron"])

    def test_jobs_doctor_binds_to_its_key_copy_get_the_provider_line(self):
        """openclaw.json with $include (no automatic fix): doctor would record its copy of glm's literal key as the
        account of the glm jobs; the info line says so and the provider line it points at is printed."""
        self.write_cfg(CB.included(CB.CFG_GLM))
        con = sqlite3.connect(str(self.sdb))
        con.execute("UPDATE cron_jobs SET enabled=0 WHERE job_id IN ('job-morning', 'job-lan-fb')")
        con.commit()
        con.close()
        lines = self.dry()
        info = [ln for ln in lines if "records that account" in ln]
        self.assertEqual(len(info), 1, lines)
        self.assertIn("2 enabled cron job(s) without a recorded inference account run their own model on a stored "
                      "login", info[0])
        self.assertIn("; for glm that account would be doctor's copy of the literal key (the provider line below says "
                      "how to keep that key configured instead); ", info[0])
        self.assertIn("WARN [gate] " + CB.D1_FIX.format(rt=RT), lines)
        self.assertLess(lines.index(info[0]), lines.index("WARN [gate] " + CB.D1_FIX.format(rt=RT)))
        self.assertFalse([ln for ln in lines if ln.startswith("WARN [gate] cron job ")])
        self.assertNotIn(CB.GLM_KEY, "\n".join(lines))

    def test_behind_text_points_at_the_warn_lines(self):
        self.assertIn("(the WARN lines below)", G.cron_fixup_behind_text([({"id": "a", "name": "A"}, ["glm/x"])]))

    def test_a_job_doctor_binds_is_not_behind_a_refused_fallback(self):
        """N2 (11.3 rehearsal, 'Codex-Bericht'): a job whose own model is on the openai login and whose fallback is on
        the fixed glm. Doctor binds its own model (it runs), and its glm fallback is refused from then on: the
        precheck no longer says it reaches glm "only after a fallback that stays refused"; the info line on the jobs
        doctor binds names it."""
        CB.add_jobs(self.state, CODEX_JOBS, start=30)
        lines = self.dry()
        text = "\n".join(lines)
        self.assertNotIn("only after a fallback that stays refused", text)
        info = [ln for ln in lines if "records that account" in ln]
        self.assertEqual(len(info), 1, lines)
        self.assertIn("2 enabled cron job(s) without a recorded inference account run their own model on a stored "
                      "login: 'Morning summary' (job-morning), 'Job Codex' (job-codex); ", info[0])
        self.assertNotIn("WARN [gate] cron job 'Job Codex'", text)
        # a job that is not bound and reaches glm only after a refused fallback keeps the behind line
        CB.add_jobs(self.state, [("job-lan-oa", {"agentId": "main", "sessionTarget": "isolated", "payload": {
            "kind": "agentTurn", "message": CB.PROMPT, "model": "lan/q", "fallbacks": ["openai/gpt-5.5",
                                                                                   "glm/glm-5"]}})], start=40)
        lines = self.dry()
        behind = [ln for ln in lines if "only after a fallback that stays refused" in ln]
        self.assertEqual(behind, ["[gate] 1/8 info: 1 enabled cron job(s) reach glm/glm-5 only after a fallback that "
                                  "stays refused (the WARN lines below): the automatic fix covers that model, but the "
                                  "job stops before it: 'Job Lan Oa' (job-lan-oa)"])

    def test_fixup_that_keeps_no_job_says_why(self):
        """wf4 N2-R2: the only enabled job that reaches the key-fixed glm is a job doctor binds to its own openai login
        (glm only as its fallback, refused either way). The precheck and the readiness line no longer say 'keeps 0
        enabled cron job(s) on glm working'; they say why the fixup keeps none."""
        con = sqlite3.connect(str(self.sdb))
        con.execute("DELETE FROM cron_jobs")
        con.commit()
        con.close()
        CB.add_jobs(self.state, CODEX_JOBS[:1], start=30)
        lines = self.dry()
        text = "\n".join(lines)
        self.assertNotIn("keeps 0 enabled cron job(s)", text)
        none = ("for no enabled cron job: the 1 enabled cron job(s) that reach glm only as a fallback run their own "
                "model on another provider's stored login, so OpenClaw 2026.11.4 refuses glm for them either way (with "
                "the account doctor records for them, or without it)")
        self.assertIn("[gate] 1/8 config fixup: would set models.providers.glm.auth = \"api-key\" before doctor pass 1 "
                      f"({G.cron_fixup_why('glm', RT)}); {none}", lines)
        self.assertIn("[gate]   cron config fixup: would set models.providers.glm.auth = \"api-key\" before doctor "
                      f"pass 1 ({none}; {G.CRON_FIXUP_ISSUE})", lines)
        self.assertNotIn("only after a fallback that stays refused", text)

    def test_jobs_doctor_bound_are_listed_after_the_migration_with_their_refused_fallbacks(self):
        """N2: after the migration the end of the run and oc-upgrade status name the jobs with a recorded account,
        disabled ones too, and the fallbacks OpenClaw now refuses for them (other providers than the account's);
        never the recorded profile id."""
        CB.add_jobs(self.state, CODEX_JOBS, start=30)
        anth = dict(BINDING, provider="anthropic", profileId="anthropic:manual")
        self.doctor_binds_morning(extra_sql=[
            "UPDATE cron_jobs SET job_json = json_set(job_json, '$.inferenceBinding', json('%s')) "
            "WHERE job_id = 'job-codex'" % json.dumps(BINDING),
            "UPDATE cron_jobs SET job_json = json_set(job_json, '$.inferenceBinding', json('%s')) "
            "WHERE job_id = 'job-claude-off'" % json.dumps(anth)])
        self.assertEqual(self.run_gate(), 0, self.out)
        fin = self.out[self.out.index("[gate] 7/8 postconditions OK"):]
        rec = self.journal()["cron_binding"]
        self.assertEqual(rec["bound"], 2)  # enabled ones only (the forecast's count)
        self.assertEqual([(a["id"], a["enabled"], a["provider"], a["refused"]) for a in rec["bound_jobs"]], [
            ("job-morning", True, "openai", ["anthropic/claude-sonnet-4-6"]),
            ("job-codex", True, "openai", ["glm/glm-5"]),
            ("job-claude-off", False, "anthropic", ["glm/glm-5", "openai/gpt-5.5"])])
        bl = ("3 cron job(s) (1 of them disabled) have a recorded inference account (OpenClaw 2026.11.2+ doctor "
              "records one for a job whose own model is on a stored login, openclaw/openclaw#172792): "
              "their own model runs on that account, and OpenClaw refuses their fallbacks to other providers (as "
              "with openclaw/openclaw#192463): 'Morning summary' (job-morning) on openai, refused: "
              "anthropic/claude-sonnet-4-6; 'Job Codex' (job-codex) on openai, refused: glm/glm-5; 'Job Claude Off' "
              "(job-claude-off, disabled) on anthropic, refused: glm/glm-5, openai/gpt-5.5. To keep such a fallback "
              "from being tried, drop it (openclaw automations edit <id> --fallbacks <list> without it; the job's own "
              "list replaces the agent's and the default fallbacks)")
        self.assertIn(f"[gate] info: {bl}", fin)
        st = G.status_lines()
        self.assertIn(f"  {bl}", st)
        for ln in [fin] + st:
            self.assertNotIn("anthropic:manual", ln)
            self.assertNotIn("openai:default", ln)
            self.assertNotIn(CB.GLM_KEY, ln)

    def test_bound_jobs_rules(self):
        cfg = json.loads(json.dumps(CB.CFG_GLM))

        def job(jid, **kw):
            j = {"agentId": "main", "sessionTarget": "isolated",
                 "payload": dict({"kind": "agentTurn", "model": "openai/gpt-5.5"}, **kw.pop("payload", {}))}
            j.update(kw)
            return {"id": jid, "name": jid, "enabled": kw.pop("enabled", True), "runtime_authority": False, "job": j}
        jobs = [job("plain"), job("bound", inferenceBinding={"provider": "OpenAI", "profileId": "openai:x"}),
                job("pinned", inferenceBinding={"provider": "openai"},
                    payload={"fallbacks": ["openai/gpt-5.5-mini@openai:y", "glm/glm-5@glm:z", "nope"]}),
                job("noprov", inferenceBinding={"profileId": "x"}),
                job("event", inferenceBinding={"provider": "openai"}, payload={"kind": "systemEvent"}),
                job("ghost", agentId="ghost", inferenceBinding={"provider": "openai"}),
                dict(job("gone", inferenceBinding={"provider": "openai"}), retired_review=True)]
        got = G.cron_bound_jobs(jobs, cfg, "main", {"main"})
        # the agent's default fallbacks (openai/gpt-5.5 from agents.defaults) apply when the job lists none
        self.assertEqual([(a["id"], a["provider"], a["refused"]) for a in got], [
            ("bound", "openai", []), ("pinned", "openai", ["glm/glm-5"]), ("noprov", None, [])])
        self.assertIsNone(G.cron_bound_line({"bound_jobs": []}))
        rec = {"runtime": RT, "bound_jobs": got, "bound_jobs_count": 5}
        line = G.cron_bound_line(rec)
        # wf4 N2-R1: a record without a provider is no "no fallback on another provider" case: OpenClaw rejects it
        self.assertNotIn("noprov", line)
        self.assertTrue(line.startswith("4 cron job(s) have a recorded inference account (OpenClaw 2026.11.2+ doctor "
                                        "records one for a job whose own model is on a stored login, "
                                        "openclaw/openclaw#172792): "), line)
        self.assertIn("'bound' (bound) on openai, no fallback on another provider; ", line)
        self.assertIn(" and 2 more. To keep", line)
        self.assertNotIn("openai:x", line)
        self.assertEqual(G.cron_bound_warn_lines(rec), [
            "cron job 'noprov' (noprov): its recorded inference account names no provider: OpenClaw 2026.11.4 treats "
            "such a record as invalid ('Invalid automation inference binding; explicitly select an account again.'); "
            "to fix: openclaw automations edit <id> --model <provider/model>@<profileId>"])

    def test_bound_job_whose_own_model_is_on_another_provider(self):
        """wf4 N2-R1: doctor bound a job to openai while its own model was openai; later its model (here the default
        model it inherits) moved to anthropic. OpenClaw keeps the record, refuses the job's own model (another provider
        than the record's) and goes on only to fallbacks on openai: no "their own model runs on that account", and the
        remedy is --model …@<profileId>, not --fallbacks."""
        cfg = json.loads(json.dumps(CB.CFG_GLM))
        cfg["agents"]["defaults"]["model"] = {"primary": "anthropic/claude-x", "fallbacks": ["glm/glm-5"]}

        def job(jid, **payload):
            return {"id": jid, "name": jid, "enabled": True, "runtime_authority": False, "job": {
                "agentId": "main", "sessionTarget": "isolated", "inferenceBinding": dict(BINDING),
                "payload": dict({"kind": "agentTurn"}, **payload)}}
        jobs = [job("inh"), job("edited", model="anthropic/claude-sonnet-4-6", fallbacks=["openai/gpt-5.5-mini",
                                                                                         "anthropic/claude-x"]),
                job("fine", model="openai/gpt-5.5", fallbacks=["anthropic/claude-x"])]
        got = G.cron_bound_jobs(jobs, cfg, "main", {"main"})
        self.assertEqual(got, [
            {"id": "inh", "name": "inh", "enabled": True, "provider": "openai", "refused": ["glm/glm-5"],
             "own_refused": "anthropic/claude-x", "on_account": []},
            {"id": "edited", "name": "edited", "enabled": True, "provider": "openai", "refused": ["anthropic/claude-x"],
             "own_refused": "anthropic/claude-sonnet-4-6", "on_account": ["openai/gpt-5.5-mini"]},
            {"id": "fine", "name": "fine", "enabled": True, "provider": "openai", "refused": ["anthropic/claude-x"]}])
        rec = {"runtime": RT, "bound_jobs": got, "bound_jobs_count": 3}
        line = G.cron_bound_line(rec)
        self.assertTrue(line.startswith("1 cron job(s) have a recorded inference account"), line)
        self.assertIn(": 'fine' (fine) on openai, refused: anthropic/claude-x. To keep", line)
        self.assertNotIn("'inh'", line)
        self.assertNotIn("'edited'", line)
        fix = "; to fix: openclaw automations edit <id> --model <provider/model>@<profileId>"
        self.assertEqual(G.cron_bound_warn_lines(rec), [
            "cron job 'inh' (inh): its own model anthropic/claude-x is on anthropic, not on its recorded inference "
            "account's provider openai: OpenClaw 2026.11.4 refuses it ('The selected model uses a different provider "
            "from this job's stored account') and tries only fallbacks on openai; the job has none, so every run "
            "fails" + fix,
            "cron job 'edited' (edited): its own model anthropic/claude-sonnet-4-6 is on anthropic, not on its "
            "recorded inference account's provider openai: OpenClaw 2026.11.4 refuses it ('The selected model uses a "
            "different provider from this job's stored account') and tries only fallbacks on openai "
            "(openai/gpt-5.5-mini)" + fix])
        # only odd jobs: no info line, only the WARN lines
        odd = {"runtime": RT, "bound_jobs": got[:2], "bound_jobs_count": 2}
        self.assertIsNone(G.cron_bound_line(odd))
        self.assertEqual(len(G.cron_bound_warn_lines(odd)), 2)

    def test_bound_job_on_another_provider_warned_at_the_end_and_in_status(self):
        """wf4 N2-R1 end to end: after the migration the default model is anthropic; job-local (inherits it) has an
        openai record (doctor bound it while the default was openai). The end of the run and oc-upgrade status warn."""
        self.doctor_binds_morning(extra_sql=[
            "UPDATE cron_jobs SET job_json = json_set(job_json, '$.inferenceBinding', json('%s')) "
            "WHERE job_id = 'job-local'" % json.dumps(BINDING)])
        cfg = json.loads(json.dumps(CB.CFG_GLM))
        cfg["agents"]["defaults"]["model"] = {"primary": "anthropic/claude-x", "fallbacks": ["openai/gpt-5.5"]}
        self.write_cfg(cfg)
        self.assertEqual(self.run_gate(), 0, self.out)
        fin = self.out[self.out.index("[gate] 7/8 postconditions OK"):]
        warn = ("cron job 'Local digest' (job-local): its own model anthropic/claude-x is on anthropic, not on its "
                "recorded inference account's provider openai: OpenClaw 2026.11.4 refuses it ('The selected model uses "
                "a different provider from this job's stored account') and tries only fallbacks on openai "
                "(openai/gpt-5.5); to fix: openclaw automations edit <id> --model <provider/model>@<profileId>")
        self.assertIn(f"WARN [gate] {warn}", fin)
        self.assertIn(f"  WARN: {warn}", G.status_lines())
        bl = [ln for ln in fin.splitlines() if "have a recorded inference account" in ln]
        self.assertEqual(len(bl), 1, fin)
        self.assertNotIn("'Local digest'", bl[0])
        self.assertNotIn("openai:default", fin + "\n".join(G.status_lines()))

    def test_run_reports_what_doctor_left_and_the_gateway_warning(self):
        self.doctor_binds_morning()
        self.assertEqual(self.run_gate(), 0, self.out)
        fin = self.out[self.out.index("[gate] 7/8 postconditions OK"):]
        j = self.journal()
        rec = j["cron_binding"]
        self.assertTrue(rec["doctor_migration"])
        self.assertEqual([a["id"] for a in rec["affected"]], ["job-local", "job-lan-fb"])
        self.assertEqual(rec["bound"], 1)
        self.assertNotIn("WARN [gate] cron job 'Morning summary'", fin)
        self.assertIn("WARN [gate] 2 cron job(s) above still have no recorded inference account after the migration: "
                      f"OpenClaw 2026.11.4 doctor {FB_ONLY}. " + G.CRON_FALLBACK, fin)
        # R6: the jobs on glm's configured key (also the disabled one), not the keyless local lan job
        self.assertEqual([(a["id"], a["enabled"], a["provider"]) for a in rec["load_warn"]],
                         [("job-local", True, "glm"), ("job-glm-haus", True, "glm"), ("job-glm-off", False, "glm")])
        lw = ("3 cron job(s) (1 of them disabled) run their own model on a configured key (glm: "
              "models.providers.<provider>.apiKey) and have no recorded inference account: OpenClaw 2026.11.4 doctor "
              "leaves such jobs unbound on purpose, but its gateway writes 'cron: automation has no recorded inference "
              "account; run openclaw doctor --fix before its next scheduled run ...' for each of them to OpenClaw's own "
              "log (openclaw logs, the Control UI's Logs page; not the add-on log) at every start and cron reload. "
              "Expected and harmless for their own model, which runs on that key; nothing to do (a "
              "fallback on a stored login that stays refused is reported separately). The add-on refuses openclaw "
              "doctor --fix, and its equivalent oc-upgrade retry --doctor would not record an account for these jobs "
              "either: 'Local digest' (job-local), 'Job Glm Haus' (job-glm-haus), 'Job Glm Off' (job-glm-off)")
        self.assertIn(f"[gate] info: {lw}", fin)
        st = G.status_lines()
        self.assertIn(f"  {lw}", st)
        i = next(i for i, x in enumerate(st) if x.startswith("  cron jobs without a recorded inference account"))
        self.assertIn("after the migration): 2 affected of 3 checked", st[i])
        self.assertIn(f"    OpenClaw 2026.11.4 doctor {FB_ONLY}. " + G.CRON_FALLBACK, st)
        for ln in [fin] + st:
            self.assertNotIn(CB.GLM_KEY, ln)
            self.assertNotIn("SECRET", ln)
            self.assertNotIn("2026.11.5", ln)

    def test_no_gateway_warning_line_before_2026_11_2(self):
        self.set_runtime("2026.11.1", 22, 27)
        self.doctor_script(state_uv=22, agent_uv=27, app_version="2026.11.1", drop_tables=["cron_run_logs"],
                           remove=["identity/device.json"])
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("load_warn", self.journal()["cron_binding"])
        self.assertNotIn("automation has no recorded inference account; run", self.out)

    def test_load_warn_rules(self):
        cfg = json.loads(json.dumps(CB.CFG_GLM))
        cfg["models"]["providers"]["glm"]["auth"] = "api-key"
        cfg["models"]["providers"]["envkey"] = {"apiKey": {"source": "env", "provider": "default", "id": "X"},
                                                "models": [{"id": "m"}]}
        cfg["models"]["providers"]["blank"] = {"apiKey": "  ", "models": [{"id": "m"}]}

        def job(jid, **kw):
            j = {"agentId": "main", "sessionTarget": "isolated",
                 "payload": dict({"kind": "agentTurn", "model": "glm/glm-5"}, **kw.pop("payload", {}))}
            j.update(kw)
            return {"id": jid, "name": jid, "enabled": True, "runtime_authority": False, "job": j}
        jobs = [job("glm"), job("env", payload={"model": "envkey/m"}), job("blank", payload={"model": "blank/m"}),
                job("main", sessionTarget="main"), job("bound", inferenceBinding={"provider": "glm"}),
                job("event", payload={"kind": "systemEvent"}), job("pinned", payload={"model": "glm/glm-5@glm:x"}),
                job("openai", payload={"model": "openai/x"}), job("ghost", agentId="ghost"),
                dict(job("auth"), runtime_authority=True)]
        prof = [{"id": "openai:default", "provider": "openai"}]
        got = G.cron_load_warn_jobs(jobs, cfg, lambda _a: prof, "main", {"main"})
        # a blank apiKey is no configured key (hasExplicitProviderApiKeyConfig): only the environment can give one
        self.assertEqual([(a["id"], a["key"]) for a in got], [("glm", "config"), ("env", "config"), ("blank", "env")])
        # without auth "api-key" doctor's copy of the literal key comes first: doctor binds the job, no warning
        cfg["models"]["providers"]["glm"].pop("auth")
        got = G.cron_load_warn_jobs(jobs, cfg, lambda _a: prof + [{"id": "glm:default", "provider": "glm"}], "main",
                                    {"main"})
        self.assertEqual([a["id"] for a in got], ["env", "blank"])
        self.assertIsNone(G.cron_load_warn_line({"load_warn": []}))

    def test_load_warn_key_from_the_environment(self):
        """GC2: a job whose provider has no models.providers entry (its key only in the environment, e.g.
        GEMINI_API_KEY in gateway_env_vars) stays unbound after doctor and is warned about by the gateway: reported
        with key "env"; keyless local providers and CLI runtime providers are not (the warning skips them), nor a job
        whose provider has a stored login (doctor records it)."""
        cfg = json.loads(json.dumps(CB.CFG_GLM))
        cfg["models"]["providers"]["glm"]["auth"] = "api-key"
        cfg["models"]["providers"]["tok"] = {"baseUrl": "http://127.0.0.1:8002/v1", "api": "openai-completions",
                                             "auth": "token", "models": [{"id": "m"}]}

        def job(jid, model):
            return {"id": jid, "name": f"Job {jid}", "enabled": True, "runtime_authority": False,
                    "job": {"agentId": "main", "sessionTarget": "isolated",
                            "payload": {"kind": "agentTurn", "model": model}}}
        jobs = [job("gem", "google/gemini-x"), job("lan", "lan/q"), job("cli", "claude-cli/default"),
                job("glm", "glm/glm-5"), job("tok", "tok/m")]
        got = G.cron_load_warn_jobs(jobs, cfg, lambda _a: [], "main", {"main"})
        self.assertEqual([(a["id"], a["provider"], a["key"]) for a in got],
                         [("gem", "google", "env"), ("glm", "glm", "config"), ("tok", "tok", "env")])
        got = G.cron_load_warn_jobs(jobs, cfg, lambda _a: [{"id": "google:default", "provider": "google"}], "main",
                                    {"main"})
        self.assertEqual([a["id"] for a in got], ["glm", "tok"])
        # the info line names both groups and says the environment group depends on the variable being set
        rec = {"runtime": RT, "load_warn": [dict(a, name=f"Job {a['id']}") for a in
                                            G.cron_load_warn_jobs(jobs[:1], cfg, lambda _a: [], "main", {"main"})]
               + [{"id": "glm", "name": "Job glm", "enabled": False, "provider": "glm", "key": "config"}]}
        line = G.cron_load_warn_line(rec)
        self.assertTrue(line.startswith(
            "2 cron job(s) (1 of them disabled) run their own model on a configured key (glm: "
            "models.providers.<provider>.apiKey) or on a key from the environment (google: a gateway_env_vars entry "
            "such as OPENAI_API_KEY or GEMINI_API_KEY) and have no recorded inference account: OpenClaw 2026.11.4 "
            "doctor leaves such jobs unbound on purpose"), line)
        self.assertIn("(a fallback on a stored login that stays refused is reported separately). For the jobs on a key "
                      "from the environment this holds only while that variable is set for the gateway (a gate run "
                      "cannot check it): without it they have no credential and fail when they run. The add-on "
                      "refuses openclaw doctor --fix", line)
        self.assertTrue(line.endswith("either: 'Job gem' (gem), 'Job glm' (glm)"), line)
        # only the environment group: no configured-key clause; an older record without "key" counts as configured
        only_env = G.cron_load_warn_line({"runtime": RT, "load_warn": rec["load_warn"][:1]})
        self.assertIn("run their own model on a key from the environment (google: ", only_env)
        self.assertNotIn("configured key", only_env)
        old = G.cron_load_warn_line({"runtime": RT, "load_warn": [{"id": "x", "name": "X", "enabled": True,
                                                                   "provider": "glm"}]})
        self.assertIn("run their own model on a configured key (glm: models.providers.<provider>.apiKey) and have",
                      old)
        self.assertNotIn("environment", old)


# --- R5: doctor's pre-repair cron backups ----------------------------------------------------------------------

# wf4: the 11.3 rehearsal's layout (synthetic): a keyless local primary, then an openai login (Codex runtime when the
# Codex plugin is active) and an anthropic token as the default fallbacks
CFG_CODEX = {"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local"},
             "agents": {"defaults": {"model": {"primary": "lan/q",
                                               "fallbacks": ["openai/gpt-5.5", "anthropic/claude-sonnet-4-6"]}},
                        "list": [{"id": "main", "default": True}]},
             "models": {"providers": {"lan": {"baseUrl": "http://127.0.0.1:8001/v1", "api": "openai-completions",
                                              "models": [{"id": "q"}]}}},
             "plugins": {"entries": {"codex": {"enabled": True}}}}
CODEX_CLAUSE = ("; openai/gpt-5.5 runs on the Codex runtime, so before that refusal Codex signs in with the stored "
                "login and looks up the account and its models unless it has them already (for a ChatGPT login at "
                "chatgpt.com), and if that "
                "lookup fails OpenClaw counts the fallback as failed and tries the next one (without network the run "
                "can first wait on it for many minutes)")
LOCAL_EMBEDDED = ("WARN [gate] cron job 'Local digest' (job-local): its model lan/q needs no stored login and keeps "
                  "working, but when it fails OpenClaw 2026.11.4 stops at the fallback openai/gpt-5.5 (stored login, "
                  "no recorded inference account; openclaw/openclaw#192195) instead of trying further models")
ALSO_ANTH = "; also on a stored login: anthropic/claude-sonnet-4-6"


class CronCodexRuntimeTests(T.GateEnv):
    """wf4 (11.3 rehearsal): openai/gpt-5.5 as a cron fallback ran on the Codex app-server runtime,
    which loads its model catalog with the stored openai login before OpenClaw refuses the candidate; offline that
    lookup failed, which is no chain stop, so the chain went on to anthropic. With the Codex plugin installed and
    enabled the WARN lines and oc-upgrade status say so; without it (or disabled) the text stays as it was."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, content=True)
        CB.add_jobs(self.state, [("job-anth-first", {"agentId": "main", "sessionTarget": "isolated", "payload": {
            "kind": "agentTurn", "message": CB.PROMPT, "model": "lan/q",
            "fallbacks": ["anthropic/claude-sonnet-4-6", "openai/gpt-5.5"]}})], start=30)
        T.write_install_records(self.state, {"codex": ("@openclaw/codex", "2026.10.4", None)})
        os.makedirs(T.plugin_project_dir(self.state, "@openclaw/codex", "2026.10.4"), exist_ok=True)
        self.write_cfg(CFG_CODEX)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime(RT, 22, 27)
        self.hooks()

    def dry(self):
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        return lines

    def test_fallback_on_the_codex_runtime(self):
        lines = self.dry()
        self.assertIn(LOCAL_EMBEDDED + CODEX_CLAUSE + ALSO_ANTH, lines)
        self.assertIn("WARN [gate] cron job 'Job Anth First' (job-anth-first): its model lan/q needs no stored login "
                      "and keeps working, but when it fails OpenClaw 2026.11.4 stops at the fallback "
                      "anthropic/claude-sonnet-4-6 (stored login, no recorded inference account; "
                      "openclaw/openclaw#192195) instead of trying further models; also on a stored login: "
                      "openai/gpt-5.5 (Codex runtime)", lines)
        # the job whose own model is the openai login: doctor binds it (no WARN), as without Codex
        self.assertFalse([ln for ln in lines if ln.startswith("WARN [gate] cron job 'Morning summary'")])
        self.assertIn("'Morning summary' (job-morning)", "\n".join(ln for ln in lines if "records that account" in ln))
        self.assertNotIn("SECRET", "\n".join(lines))

    def test_status_after_the_migration(self):
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn(LOCAL_EMBEDDED + CODEX_CLAUSE + ALSO_ANTH, self.out.splitlines())
        rec = self.journal()["cron_binding"]
        self.assertTrue(rec["codex_active"])
        local = next(a for a in rec["affected"] if a["id"] == "job-local")
        self.assertEqual(local["codex"], ["openai/gpt-5.5"])
        st = G.status_lines()
        self.assertIn("    'Local digest' (job-local): stops at the fallback openai/gpt-5.5 (Codex runtime: it signs "
                      "in with the stored login and looks up the models first unless it has them); openai/gpt-5.5, "
                      "anthropic/claude-sonnet-4-6", st)
        self.assertIn("    'Job Anth First' (job-anth-first): stops at the fallback anthropic/claude-sonnet-4-6; "
                      "anthropic/claude-sonnet-4-6, openai/gpt-5.5 (Codex runtime)", st)

    def test_codex_home_scope_user(self):
        cfg = json.loads(json.dumps(CFG_CODEX))
        cfg["plugins"]["entries"]["codex"]["config"] = {"appServer": {"homeScope": "user"}}
        self.write_cfg(cfg)
        lines = self.dry()
        self.assertIn(LOCAL_EMBEDDED + CODEX_CLAUSE.replace(
            "signs in with the stored login", "uses the login of its own Codex home (appServer.homeScope \"user\")")
            + ALSO_ANTH, lines)

    def test_disabled_or_missing_codex_keeps_the_embedded_text(self):
        for name, plugins in (("entry disabled", {"entries": {"codex": {"enabled": False}}}),
                              ("denied", {"deny": ["codex"]}),
                              ("allowlist without it", {"allow": ["brave"]}),
                              ("plugins off", {"enabled": False}),
                              ("discovery off", {"entries": {"codex": {"config": {"discovery": {"enabled": False}}}}})):
            with self.subTest(name):
                self.write_cfg(dict(CFG_CODEX, plugins=plugins))
                lines = self.dry()
                self.assertIn(LOCAL_EMBEDDED + ALSO_ANTH, lines)
                self.assertNotIn("Codex runtime", "\n".join(lines))
        # not installed: no install record and no npm project
        self.write_cfg(CFG_CODEX)
        T.write_install_records(self.state, {})
        for d in (self.state / "npm" / "projects").iterdir():
            os.rmdir(d)
        lines = self.dry()
        self.assertIn(LOCAL_EMBEDDED + ALSO_ANTH, lines)
        self.assertNotIn("Codex runtime", "\n".join(lines))

    def test_own_model_pinned_to_codex_is_left_unbound_by_doctor(self):
        cfg = json.loads(json.dumps(CFG_CODEX))
        cfg["agents"]["defaults"]["models"] = {"openai/gpt-5.5": {"agentRuntime": {"id": "codex"}}}
        self.write_cfg(cfg)
        lines = self.dry()
        text = "\n".join(lines)
        self.assertNotIn("records that account", text)  # doctor binds no job: no info line promises it
        self.assertIn("WARN [gate] cron job 'Morning summary' (job-morning): OpenClaw 2026.11.4 refuses every run and "
                      "tries no fallback: its model openai/gpt-5.5 would use a stored login (auth profile) and the job "
                      "has no recorded inference account (openclaw/openclaw#192195); openai/gpt-5.5 runs on the Codex "
                      "runtime, so before that refusal Codex signs in with the stored login and looks up the account "
                      "and its models unless it has them already (for a ChatGPT login at chatgpt.com); if that lookup "
                      "fails, OpenClaw may try the fallbacks instead (without network the run can first wait on it for "
                      "many minutes); its model is set to the codex runtime "
                      "(agents.defaults.models[\"openai/gpt-5.5\"].agentRuntime), so OpenClaw 2026.11.4 doctor records "
                      "no inference account for it (doctor: 'runtime codex inference ownership was left unchanged') "
                      "and every run stays refused" + ALSO_ANTH, lines)
        self.assertEqual(G._cron_doctor_binds([{"primary_affected": True, "refs": ["openai/gpt-5.5"],
                                                "own_runtime": "codex"},
                                               {"primary_affected": True, "refs": ["claude-cli/default"]},
                                               {"primary_affected": True, "refs": ["openai/gpt-5.5"]}]),
                         [{"primary_affected": True, "refs": ["openai/gpt-5.5"]}])


class DoctorCronBackupTests(SW.Base):
    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state)
        self.write_cfg(self.cfg)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime(RT, 22, 27)
        self.old = self.state / cron_bak(OLD_MS, UUID_OLD)  # OpenClaw's own, before any gate run
        self.old.write_bytes(b"older cron backup")
        self.new = cron_bak(future_ms())
        self.hooks()

    def step(self, **kw):
        return self.step_1010(retire=False, app_version=RT, **kw)

    def made(self):
        return {"write": {self.new: "cron backup"}, "print": [f"Saved pre-repair cron backup: {self.state / self.new}"]}

    def test_run_journals_reports_and_deletes_its_cron_backup(self):
        self.doctor_script(passes=[self.step(**self.made()), self.step()])
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertIn("Doctor complete. (1 pre-repair cron backup of the state database by doctor, 11 B; not the "
                      "rollback point)", self.out)
        p1, p2 = j["doctor"][:2]
        self.assertEqual(p1["pre_migration_backups"], [{"path": self.new, "size": 11, "scope": "cron"}])
        self.assertEqual((p1["pre_migration_backups_older"], p2["pre_migration_backups"]), (1, []))
        self.assertEqual(j["doctor_copies_before"], [C.rel(self.old, self.state)])
        self.assertIn("[gate] info: this run's 1 pre-repair cron backup of the state database by doctor, 11 B "
                      "(plaintext, beside the databases; not the rollback point): deleted at the same time", self.out)
        st = G.status_lines()
        line = next(x for x in st if x.startswith("Doctor pre-repair cron backups"))
        self.assertEqual(line, "Doctor pre-repair cron backups of the state database (openclaw.sqlite.doctor-cron-*.bak): "
                               f"2 (28 B) in {self.state / 'state'}: plaintext copies (device keys and tokens), not the "
                               "rollback point; OpenClaw never deletes them; those a gate run made: deleted "
                               "automatically, see oc-upgrade cleanup")
        self.assertFalse([x for x in st if x.startswith("Doctor pre-migration SQLite copies")])
        finished = G._parse_backup_date(j["finished_at"])
        lines = []
        self.assertEqual(G.cleanup_pass(now=finished + timedelta(hours=47), hours=48, emit=lines.append), 0)
        self.assertTrue((self.state / self.new).exists())
        plain = G.run_plaintext_copies(G.gpaths(), j["run_id"])
        self.assertEqual(G.cleanup_pass(now=finished + timedelta(hours=48), hours=48, emit=lines.append),
                         1 + len(plain))
        self.assertFalse((self.state / self.new).exists())
        self.assertTrue(self.old.exists())  # not this run's
        self.assertTrue(self.sdb.exists())

    def test_later_pass_cron_backup_is_reported_not_warned(self):
        self.doctor_script(passes=[self.step(), self.step(**self.made())])
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("[gate] 6/8 doctor pass 2: 1 pre-repair cron backup of the state database by doctor, 11 B "
                      "(plaintext, not the rollback point)", self.out)
        self.assertNotIn("saved another pre-migration SQLite copy", self.out)
        self.assertEqual(self.journal()["doctor"][1]["pre_migration_backups"],
                         [{"path": self.new, "size": 11, "scope": "cron"}])

    def test_interrupted_pass_resumed_keeps_the_backup_on_the_run(self):
        """The gate is stopped while doctor pass 1 runs, after doctor saved its cron backup (no journal record of
        that pass): the resumed pass 1 journals it (not in the baseline, made after the run started), the finalize
        names it and the cleanup deletes it with the run."""
        slow = self.bin / "cron-bak-then-sleep"
        slow.write_text("#!/usr/bin/env python3\nimport os, sys, time\n"
                        "p = os.path.join(os.environ['OPENCLAW_STATE_DIR'], sys.argv[1])\n"
                        "open(p, 'w').write('cron backup')\n"
                        "print('│  Saved pre-repair cron backup: ' + p + ' │', flush=True)\n"
                        "time.sleep(30)\n")
        slow.chmod(0o755)
        self.hooks(doctor_cmd=[str(slow), self.new])
        threading.Timer(3.0, lambda: os.kill(os.getpid(), 15)).start()
        self.assertEqual(self.run_gate(), 143, self.out)
        j = self.journal()
        self.assertEqual((j["status"], j["phase"]), ("interrupted", "doctor1"))
        self.assertTrue((self.state / self.new).exists())
        self.assertNotIn("pre_migration_backups", j["doctor"][0])
        # a cleanup before the run finished deletes nothing (the run is not finished)
        G.STOP.clear()
        self.assertEqual(G.cleanup_pass(now=C.utc_now() + timedelta(days=30), hours=48, emit=lambda s: None), 0)
        self.assertTrue((self.state / self.new).exists())
        self.doctor_script(passes=[self.step(), self.step()])
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertEqual([d["pass"] for d in j["doctor"]], [1, 1, 2])
        self.assertEqual(j["doctor"][1]["pre_migration_backups"], [{"path": self.new, "size": 11, "scope": "cron"}])
        self.assertIn("[gate] info: this run's 1 pre-repair cron backup of the state database by doctor", self.out)
        finished = G._parse_backup_date(j["finished_at"])
        G.cleanup_pass(now=finished + timedelta(hours=48), hours=48, emit=lambda s: None)
        self.assertFalse((self.state / self.new).exists())
        self.assertTrue(self.old.exists())

    def test_earlier_version_run_from_its_log(self):
        """A run of an earlier add-on version journaled no cron backup: the backups its doctor logs name ("Saved
        pre-repair cron backup", the dreaming repair's "SQLite backup:", a failed repair's "verified backup retained
        at", also wrapped in doctor's box) are deleted with it; others, links and the database are not."""
        gp = G.gpaths()
        rid = "20261101T120000Z-abcdef"
        rd = gp["RUNS"] / rid
        rd.mkdir(parents=True)
        ids = [f"{OLD_MS + i}-{UUID_NEW[:-1]}{i}" for i in range(3)]
        made = [self.state / f"state/openclaw.sqlite.doctor-cron-{x}.bak" for x in ids]
        for m in made:
            m.write_bytes(b"run backup")
        other = self.state / cron_bak(OLD_MS + 9, UUID_NEW)
        other.write_bytes(b"not named in the log")
        link = self.state / f"state/x.sqlite.doctor-cron-{OLD_MS + 5}-{UUID_NEW}.bak"
        os.symlink(self.sdb, link)
        w = str(made[0])
        (rd / "doctor-pass1.log").write_text("\n".join([
            "┌  OpenClaw doctor", "◇  Doctor changes ──────╮",
            f"\x1b[90m│\x1b[39m  Saved pre-repair cron backup: {w[:40]}  │", f"│  {w[40:85]}   │", f"│  {w[85:]} │",
            f"│  Repaired 1 historical dreaming cron row(s); survivor IDs, order, and runtime state preserved. SQLite "
            f"backup: {made[1]}. │",
            f"Cron inference account migration was not committed: Cron Doctor repair failed; verified backup retained "
            f"at {made[2]}: Error: synthetic",
            f"│  Saved pre-repair cron backup: {link} │",
            "└  Doctor complete."]) + "\n")
        (rd / "journal.json").write_text(json.dumps({
            "run_id": rid, "status": "done", "finished_at": "2026-11-01T12:00:00Z", "started_at": "2026-11-01T11:00:00Z",
            "doctor": [{"pass": 1, "pre_migration_backups": []}]}))
        self.assertEqual(G.doctor_cron_copy_ids((rd / "doctor-pass1.log").read_text()),
                         set(ids) | {f"{OLD_MS + 5}-{UUID_NEW}"})
        now = G._parse_backup_date("2026-11-10T00:00:00Z")
        targets = {t[0]: t for t in G.cleanup_targets(gp, now, 48)}
        real = Path(os.path.realpath(self.state))
        self.assertEqual(sorted(targets[rid][3]), sorted(real / C.rel(m, self.state) for m in made))
        lines = []
        self.assertEqual(G.cleanup_pass(now=now, hours=48, emit=lines.append), 3, lines)
        self.assertFalse([m for m in made if m.exists()])
        for p in (other, self.old, self.sdb):
            self.assertTrue(p.exists(), p)
        self.assertTrue(os.path.islink(link))

    def test_baseline_of_an_earlier_version_never_claims_an_older_backup(self):
        """A run whose baseline an earlier add-on version took (it did not list cron backups) and that this version
        resumes: a backup made before the run started is not this run's."""
        (self.state / self.new).write_bytes(b"made by this run")
        g = G.Gate(emit=lambda s: None)
        g.pkg = C.runtime_package()
        g.cfg = self.cfg
        g.j = {"run_id": "20261112T120000Z-abc123", "started_at": C.utc_iso(), "doctor_copies_before": [],
               "doctor": [{"pass": 1}]}
        new = g.record_doctor_copies(1)
        self.assertEqual(new, [{"path": self.new, "size": 16, "scope": "cron"}])
        g.j["started_at"] = None  # unknown start: no cron backup is claimed
        g.j["doctor"].append({"pass": 2})
        (self.state / self.new).unlink()
        newer = cron_bak(future_ms(), UUID_OLD)
        (self.state / newer).write_bytes(b"x")
        self.assertEqual(g.record_doctor_copies(2), [])

    def test_names_and_parts(self):
        n = f"openclaw.sqlite.doctor-cron-{OLD_MS}-{UUID_NEW}.bak"
        self.assertEqual((G.doctor_copy_kind(n), G.doctor_cron_copy_ms(n)), ("cron", OLD_MS))
        for bad in (f"openclaw.sqlite.doctor-cron-{OLD_MS}-{UUID_NEW}.bak.tmp", f"openclaw.sqlite.doctor-cron-x-{UUID_NEW}.bak",
                    f"openclaw.sqlite.doctor-cron-{OLD_MS}-{UUID_NEW.upper()}.bak", "openclaw.sqlite"):
            self.assertIsNone(G.doctor_copy_kind(bad), bad)
        real = os.path.realpath(self.state)
        self.assertEqual(G._doctor_copy_parts(real, f"{real}/state/{n}"), ["state", n])
        self.assertIsNone(G._doctor_copy_parts(real, f"{real}/../{n}"))
        self.assertEqual(G.copies_text([{"scope": "full", "size": 1024}, {"scope": "cron", "size": 1024},
                                        {"scope": "cron", "size": 1024}]),
                         "1 full pre-migration SQLite copy and 2 pre-repair cron backups of the state database by "
                         "doctor, 3.0 KiB")
        # without a cron backup the text is the one of earlier versions
        self.assertEqual(G.copies_text([{"scope": "full", "size": 1024}]),
                         "1 full pre-migration SQLite copy by doctor, 1.0 KiB")


# --- doctor's pre-repair recovery directories (openclaw-<repair>-recovery-XXXXXX/database.sqlite) ----------------

MEDIA_DIR = "agents/main/agent/openclaw-media-persistence-recovery-AbC123"
TASK_DIR = "state/openclaw-task-delivery-recovery-Xy12Z9"
OLD_DIR = "state/openclaw-index-recovery-Old123"  # OpenClaw's own, long before any gate run


class DoctorRecoveryDirTests(SW.Base):
    """Doctor's other plaintext copies: before a media-persistence, transcript, session-window or index repair (and
    the orphan task delivery repair the precheck lets it make) it saves a full copy of the database in a private
    directory beside it and never deletes it. The gate journals, reports and deletes the ones a run made like its
    pre-repair cron backups. Synthetic files only."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state)
        self.write_cfg(self.cfg)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime(RT, 22, 27)
        old = self.state / OLD_DIR
        old.mkdir()
        (old / "database.sqlite").write_bytes(b"older copy")
        os.utime(old, (OLD_MS / 1000, OLD_MS / 1000))
        self.hooks()

    def step(self, **kw):
        return self.step_1010(retire=False, app_version=RT, **kw)

    def test_run_journals_reports_and_deletes_its_recovery_dirs(self):
        media = {"write": {f"{MEDIA_DIR}/database.sqlite": "media copy"},
                 "print": [f"Saved pre-repair SQLite backup: {self.state / MEDIA_DIR}/database.sqlite"]}
        task = {"write": {f"{TASK_DIR}/database.sqlite": "state copy", f"{TASK_DIR}/orphan-rows.jsonl": "{}\n",
                          f"{TASK_DIR}/manifest.json": "{}"},
                "print": ["Preserved and recovered 1 orphan task delivery rows; backup and row export: "
                          f"{self.state / TASK_DIR}"]}
        self.doctor_script(passes=[self.step(**media), self.step(**task)])
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertIn("Doctor complete. (1 pre-repair recovery directory with a full database copy by doctor, 10 B; "
                      "not the rollback point)", self.out)
        self.assertIn("[gate] 6/8 doctor pass 2: 1 pre-repair recovery directory with a full database copy by doctor, "
                      "15 B (plaintext, not the rollback point)", self.out)
        self.assertNotIn("saved another pre-migration SQLite copy", self.out)
        p1, p2 = j["doctor"][:2]
        self.assertEqual(p1["pre_migration_backups"], [{"path": MEDIA_DIR, "size": 10, "scope": "recovery"}])
        self.assertEqual(p2["pre_migration_backups"], [{"path": TASK_DIR, "size": 15, "scope": "recovery"}])
        self.assertEqual(j["doctor_copies_before"], [OLD_DIR])
        self.assertIn("[gate] info: this run's 2 pre-repair recovery directories with full database copies by doctor, "
                      "25 B (plaintext, beside the databases; not the rollback point): deleted at the same time",
                      self.out)
        st = G.status_lines()
        line = next(x for x in st if x.startswith("Doctor pre-repair recovery directories"))
        self.assertEqual(line, "Doctor pre-repair recovery directories (openclaw-*-recovery-*/database.sqlite): 3 (35 B): "
                               + ", ".join(str(self.state / d) for d in sorted((MEDIA_DIR, TASK_DIR, OLD_DIR)))
                               + ": full plaintext copies of the databases (transcripts, device keys and tokens), not "
                               "the rollback point; OpenClaw never deletes them; those a gate run made: deleted "
                               "automatically, see oc-upgrade cleanup")
        self.assertFalse([x for x in st if x.startswith("Doctor pre-migration SQLite copies")])
        finished = G._parse_backup_date(j["finished_at"])
        lines = []
        self.assertEqual(G.cleanup_pass(now=finished + timedelta(hours=47), hours=48, emit=lines.append), 0)
        self.assertTrue((self.state / MEDIA_DIR).is_dir())
        plain = G.run_plaintext_copies(G.gpaths(), j["run_id"])
        self.assertEqual(G.cleanup_pass(now=finished + timedelta(hours=48), hours=48, emit=lines.append),
                         2 + len(plain), lines)
        for d in (MEDIA_DIR, TASK_DIR):
            self.assertFalse(os.path.lexists(self.state / d), d)
        self.assertTrue((self.state / OLD_DIR / "database.sqlite").exists())  # not this run's
        self.assertTrue((self.state / "agents/main/agent/openclaw-agent.sqlite").exists())
        self.assertTrue((self.state / "state/openclaw.sqlite").exists())

    def test_earlier_version_run_from_its_log(self):
        """A run that journaled no recovery directory: the ones its doctor logs name (also wrapped in doctor's box,
        a failed index repair's "Preserved pre-repair database", a failed task delivery repair's "retained
        artifacts") are deleted with it; a directory with an entry doctor does not write is refused and reported,
        and lookalikes (a link, a regular file) and directories no log names are left alone."""
        gp = G.gpaths()
        rid = "20261101T120000Z-abcdef"
        rd = gp["RUNS"] / rid
        rd.mkdir(parents=True)
        made = [self.state / "agents/main/agent/openclaw-transcript-headers-recovery-Hd0001",
                self.state / "state/openclaw-index-recovery-Ix0002",
                self.state / "state/openclaw-task-delivery-recovery-Td0003"]
        for m in made:
            m.mkdir()
            (m / "database.sqlite").write_bytes(b"run copy")
        (made[2] / "orphan-rows.jsonl").write_bytes(b"{}")
        odd = self.state / "state/openclaw-session-window-recovery-Sw0004"
        odd.mkdir()
        (odd / "database.sqlite").write_bytes(b"run copy")
        (odd / "notes.txt").write_bytes(b"not doctor's")
        other = self.state / "state/openclaw-transcript-labels-recovery-Lb0005"
        other.mkdir()
        (other / "database.sqlite").write_bytes(b"not named in the log")
        target = self.tmp / "elsewhere"
        target.mkdir()
        (target / "database.sqlite").write_bytes(b"outside")
        link = self.state / "state/openclaw-index-recovery-Lk0006"
        os.symlink(target, link)
        flat = self.state / "state/openclaw-index-recovery-Fl0007"
        flat.write_bytes(b"a file")
        w = f"{made[0]}/database.sqlite"
        (rd / "doctor-pass1.log").write_text("\n".join([
            "┌  OpenClaw doctor", "◇  Doctor changes ──────╮",
            f"\x1b[90m│\x1b[39m  - Saved pre-repair SQLite backup: {w[:40]}  │", f"│  {w[40:85]}   │",
            f"│  {w[85:]} │",
            f"SQLite index repair refused for {self.state}/state/openclaw.sqlite. Preserved pre-repair database: "
            f"{made[1]}/database.sqlite. Preserve the database and its WAL",
            f"Task delivery recovery failed without committing row removal; retained artifacts: {made[2]}: Error: x",
            f"Saved pre-repair SQLite backup: {odd}/database.sqlite",
            f"Saved pre-repair SQLite backup: {link}/database.sqlite",
            f"Saved pre-repair SQLite backup: {flat}/database.sqlite",
            "└  Doctor complete."]) + "\n")
        (rd / "journal.json").write_text(json.dumps({
            "run_id": rid, "status": "done", "finished_at": "2026-11-01T12:00:00Z", "started_at": "2026-11-01T11:00:00Z",
            "doctor": [{"pass": 1, "pre_migration_backups": []}]}))
        self.assertEqual(G.doctor_recovery_dirs((rd / "doctor-pass1.log").read_text()),
                         {m.name for m in made} | {odd.name, link.name, flat.name})
        now = G._parse_backup_date("2026-11-10T00:00:00Z")
        targets = {t[0]: t for t in G.cleanup_targets(gp, now, 48)}
        real = Path(os.path.realpath(self.state))
        self.assertEqual(sorted(targets[rid][3]), sorted(real / C.rel(m, self.state) for m in made + [odd]))
        lines = []
        self.assertEqual(G.cleanup_pass(now=now, hours=48, emit=lines.append), 3, lines)
        self.assertFalse([m for m in made if os.path.lexists(m)])
        self.assertTrue([x for x in lines if x.startswith(f"WARN [cleanup] run {rid}: could not delete ")
                         and "unexpected entry notes.txt in doctor's recovery directory" in x], lines)
        self.assertEqual(sorted(os.listdir(odd)), ["database.sqlite", "notes.txt"])  # nothing removed
        for p in (other / "database.sqlite", target / "database.sqlite", flat, self.state / OLD_DIR / "database.sqlite"):
            self.assertTrue(p.exists(), p)
        self.assertTrue(os.path.islink(link))

    def test_older_directory_is_not_claimed_and_names(self):
        """A resumed run whose baseline an earlier add-on version took (no recovery directories in it): a directory
        last changed before the run started is not this run's. Names, parts and the inventory's rules."""
        g = G.Gate(emit=lambda s: None)
        g.pkg = C.runtime_package()
        g.cfg = self.cfg
        g.j = {"run_id": "20261112T120000Z-abc123", "started_at": C.utc_iso(), "doctor_copies_before": [],
               "doctor": [{"pass": 1}]}
        new = self.state / MEDIA_DIR
        new.mkdir()
        (new / "database.sqlite").write_bytes(b"made by this run")
        self.assertEqual(g.record_doctor_copies(1), [{"path": MEDIA_DIR, "size": 16, "scope": "recovery"}])
        self.assertEqual(g.j["doctor"][0]["pre_migration_backups_older"], 1)  # OLD_DIR
        # a recovery-named directory that is not beside a database, or not of a known repair, is not doctor's
        (self.state / "state/sub/openclaw-index-recovery-Nd0001").mkdir(parents=True)
        (self.state / "state/openclaw-other-recovery-Ab0001").mkdir()
        self.assertEqual(sorted(r for r, v in G.doctor_copies(self.state).items() if v[1] == "recovery"),
                         sorted([MEDIA_DIR, OLD_DIR]))
        real = os.path.realpath(self.state)
        self.assertEqual(G._doctor_copy_parts(real, f"{real}/{TASK_DIR}"), TASK_DIR.split("/"))
        for bad in ("state/openclaw-index-recovery-Ab12", "state/openclaw-index-recovery-Ab1234/database.sqlite",
                    "state/openclaw-other-recovery-Ab1234"):
            self.assertIsNone(G._doctor_copy_parts(real, f"{real}/{bad}"), bad)
        self.assertEqual(G.copies_text([{"scope": "full", "size": 1024}, {"scope": "cron", "size": 1024},
                                        {"scope": "recovery", "size": 1024}]),
                         "1 full pre-migration SQLite copy, 1 pre-repair cron backup of the state database and 1 "
                         "pre-repair recovery directory with a full database copy by doctor, 3.0 KiB")
        # beside an agent database outside the state dir: reported, never deleted by the add-on
        outside = self.tmp / "outside-agent"
        (outside / "openclaw-transcript-labels-recovery-Ou0001").mkdir(parents=True)
        (outside / "openclaw-transcript-labels-recovery-Ou0001" / "database.sqlite").write_bytes(b"x")
        found = G.outside_doctor_copies([str(outside)])
        self.assertEqual(list(found.values()), [(1, "recovery")])
        self.assertTrue(G.outside_copies_text(list(found), self.state).startswith(
            f"1 SQLite copy by doctor beside agent databases outside {self.state} (plaintext"))


# --- R7 memory search remote, R8 output caps -------------------------------------------------------------------

MS_104 = {"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local"},
          "agents": {"defaults": {"memorySearch": {"provider": "gemini",
                                                   "remote": {"apiKey": SECRET, "headers": {"X-Title": SECRET}}}},
                     "list": [{"id": "main", "default": True},
                              {"id": "lan", "memorySearch": {"provider": "openai",
                                                             "remote": {"baseUrl": "http://192.168.1.5:9000/v1"}}},
                              {"id": "same", "memorySearch": {"provider": " Google ",
                                                              "remote": {"baseUrl": "http://192.168.1.6/v1"}}},
                              {"id": "own", "memorySearch": {"provider": "mistral",
                                                             "remote": {"baseUrl": "", "apiKey": SECRET}}},
                              {"id": "off", "memorySearch": {"provider": "openai", "enabled": False,
                                                             "remote": {"baseUrl": "http://x/v1"}}},
                              {"id": "fts", "memorySearch": {"provider": "None", "remote": {"baseUrl": "http://x"}}},
                              {"id": "inherit", "memorySearch": {"provider": "openai"}}]}}


class MemoryRemoteTests(T.GateEnv):
    def test_rule(self):
        # the shared remote has no baseUrl: also the agent without a remote of its own loses the shared fields
        self.assertEqual(G.memory_remote_losses(MS_104), [("lan", ["remote.apiKey", "remote.headers"]),
                                                          ("own", ["remote.headers"]),
                                                          ("inherit", ["remote.apiKey", "remote.headers"])])
        # a different provider without its own baseUrl inherits the whole remote while the shared baseUrl is set
        cfg = json.loads(json.dumps(MS_104))
        cfg["agents"]["defaults"]["memorySearch"]["remote"]["baseUrl"] = "https://example.invalid/v1"
        self.assertEqual(G.memory_remote_losses(cfg), [("lan", ["remote.apiKey", "remote.headers"]),
                                                       ("own", ["remote.headers"])])
        cfg["agents"]["defaults"]["memorySearch"]["remote"]["baseUrl"] = "  "  # blank: no longer inherited
        self.assertEqual([a for a, _f in G.memory_remote_losses(cfg)], ["lan", "own", "inherit"])
        # canonical ids: unset/auto = openai, google = gemini, none in any case
        for shared, agent, lost in ((None, "OpenAI", False), ("auto", "openai", False), ("gemini", "google", False),
                                    ("openai", "gemini", True), ("NONE", "none", False), ("local", "Local ", False)):
            c = {"memory": {"search": {"provider": shared, "remote": {"apiKey": SECRET}}},
                 "agents": {"entries": {"a": {"memory": {"search": {"provider": agent,
                                                                    "remote": {"baseUrl": "http://x"}}}}}}}
            self.assertEqual(bool(G.memory_remote_losses(c)), lost, (shared, agent))

    def test_both_config_shapes_give_the_same_result(self):
        """2026.10.4 (agents.defaults.memorySearch, agents.list[].memorySearch) and after doctor's move (memory.search,
        agents.entries.<id>.memory.search), with explicit memory.search values winning over the legacy ones."""
        migrated = {"memory": {"search": MS_104["agents"]["defaults"]["memorySearch"]},
                    "agents": {"entries": {a["id"]: ({"memory": {"search": a["memorySearch"]}} if "memorySearch" in a
                                                     else {}) for a in MS_104["agents"]["list"]}}}
        self.assertEqual(G.memory_remote_losses(migrated), G.memory_remote_losses(MS_104))
        mixed = json.loads(json.dumps(MS_104))
        mixed["memory"] = {"search": {"provider": "openai"}}  # explicit: wins over the legacy provider gemini
        self.assertEqual(G.memory_remote_losses(mixed), [("same", ["remote.apiKey", "remote.headers"]),
                                                         ("own", ["remote.headers"])])
        self.assertEqual(G.memory_remote_losses({}), [])
        self.assertEqual(G.memory_remote_losses({"agents": {"list": "x"}, "memory": []}), [])

    def precheck(self, cfg, rt):
        T.make_1004_state(self.state, content=True)
        self.write_cfg(cfg)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime(rt, 22, 27)
        self.hooks()
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        return lines

    def test_precheck_warn_names_agents_and_fields_only(self):
        lines = self.precheck(MS_104, RT)
        warn = [ln for ln in lines if "memory search:" in ln]
        self.assertEqual(warn, [
            "WARN [gate] 1/8 memory search: OpenClaw 2026.11.4 no longer gives an agent whose memory search provider "
            "differs from the shared one (memory.search.provider) the shared memory.search.remote apiKey/headers when "
            "the agent sets its own remote.baseUrl or the shared remote.baseUrl is empty (openclaw/openclaw#184966). "
            "3 agent(s) lose shared fields: agent lan: remote.apiKey, remote.headers; agent own: remote.headers; "
            "agent inherit: remote.apiKey, remote.headers. "
            "If its provider needs a credential, without its own such an agent's memory embeddings fail: give it its own memory search remote "
            "apiKey/headers (in its agent entry in openclaw.json) or a key for its provider in "
            "models.providers.<provider>; if it relied on shared headers that are no credential, rebuild its memory "
            "index afterwards (openclaw memory index --force). The migration continues"])
        text = "\n".join(lines)
        for bad in (SECRET, "192.168.1.5", "gemini", "mistral"):
            self.assertNotIn(bad, warn[0])
        self.assertNotIn(SECRET, text)
        self.assertIn("[gate] dry-run: the precheck would pass", text)  # a WARN, never a HOLD

    def test_no_warn_before_2026_11_3(self):
        lines = self.precheck(MS_104, "2026.11.2")
        self.assertFalse([ln for ln in lines if "memory search:" in ln])


class OutputCapTests(T.GateEnv):
    CFG = {"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local"},
           "agents": {"list": [{"id": "main", "default": True}]},
           "models": {"providers": {
               "glm": {"baseUrl": "http://127.0.0.1:8000/v1", "api": "openai-completions", "apiKey": SECRET,
                       "models": [{"id": "glm-a"}, {"id": "glm-b", "contextWindow": 32768},
                                  {"id": "glm-c", "contextWindow": 131072, "maxTokens": 8192},
                                  {"id": "glm-d", "contextWindow": 131072, "contextTokens": 40000},
                                  {"id": "glm-e", "contextWindow": 4096}]},
               "capped": {"maxTokens": 4096, "models": [{"id": "x"}]},
               "bad": {"models": "x"}}}}

    def test_rows(self):
        rows = G.output_cap_rows(self.CFG)
        self.assertEqual([(r["ref"], r["old"], r["new"]) for r in rows],
                         [("glm/glm-a", 8192, 32768), ("glm/glm-b", 8192, 16384), ("glm/glm-d", 8192, 20000),
                          ("glm/glm-e", 4096, 4096)])
        self.assertEqual(G.output_cap_rows({}), [])

    def test_precheck_info_on_2026_11_3_only(self):
        T.make_1004_state(self.state, content=True)
        self.write_cfg(self.CFG)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        for rt, want in (("2026.11.2", False), (RT, True)):
            self.set_runtime(rt, 22, 27)
            self.hooks()
            lines = []
            self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
            info = [ln for ln in lines if "model output caps:" in ln]
            self.assertEqual(bool(info), want, rt)
            self.assertFalse([ln for ln in lines if SECRET in ln])
        self.assertEqual(info, [
            "[gate] 1/8 info: model output caps: OpenClaw 2026.11.4 gives a model row without maxTokens (row or "
            "provider level) an output cap of min(32768, max(8192, window/2)) instead of 8192 "
            "(openclaw/openclaw#193899; a window under 8192 stays the cap): glm/glm-a (no contextWindow, so 200000 "
            "is assumed; output cap 8192 -> 32768), glm/glm-b (contextWindow 32768; output cap 8192 -> 16384), "
            "glm/glm-d (contextWindow 131072, contextTokens 40000; output cap 8192 -> 20000), glm/glm-e "
            "(contextWindow 4096; output cap 4096, unchanged). A model OpenClaw's own catalog knows keeps the "
            "catalog's limit. For a local server, set contextWindow (and maxTokens, if it limits the output) to its "
            "real limits"])



# --- GHSA-pw3x-g8v8-fvj2 (OpenClaw 2026.11.4, runtime_caps delegated_change_approval) ---------------------------------

DEL_BASE = {"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local", "auth": {"token": SECRET}},
            "agents": {"entries": {"main": {"default": True}, "haus": {}}}}


def del_cfg(tools=None, agents=None):
    cfg = json.loads(json.dumps(DEL_BASE))
    if tools is not None:
        cfg["tools"] = tools
    for aid, t in (agents or {}).items():
        cfg["agents"]["entries"].setdefault(aid, {})["tools"] = t
    return cfg


GRANT_CFG = del_cfg(tools={"openclaw": {"autoApproveChanges": True}, "deny": ["exec", "OpenClaw"]},
                    agents={"haus": {"openclaw": {"autoApproveChanges": True}, "deny": ["openclaw"]},
                            "main": {"openclaw": {"autoApproveChanges": False}}})
# both grants take effect: the openclaw tool is not denied anywhere
ACTIVE_CFG = del_cfg(tools={"openclaw": {"autoApproveChanges": True}, "deny": ["exec"]},
                     agents={"haus": {"openclaw": {"autoApproveChanges": True}},
                             "main": {"openclaw": {"autoApproveChanges": False}}})
# the global grant takes effect, haus's own grant not (haus denies the tool)
MIXED_CFG = del_cfg(tools={"openclaw": {"autoApproveChanges": True}},
                    agents={"haus": {"openclaw": {"autoApproveChanges": True}, "deny": ["openclaw"]}})


class DelegationTests(T.GateEnv):
    """GHSA-pw3x-g8v8-fvj2 is fixed in the bundled 2026.11.4: a WARN only when tools.openclaw.autoApproveChanges is true
    (global or an agent's override: it re-enables automatic delegated changes) in a scope that does not deny the
    openclaw tool, an info line for a grant such a deny keeps without effect, an info line in the finalize when tools.deny
    still blocks the openclaw tool (the interim measure); nothing on a default config or before 2026.11.4."""

    def test_cap_floor(self):
        for v, want in (("2026.10.4", False), ("2026.11.3", False), ("2026.11.3-2", False), (RT, True),
                        ("2026.11.6", True)):
            self.assertEqual(C.runtime_caps(v)["delegated_change_approval"], want, v)

    def test_paths(self):
        self.assertEqual(G.delegation_grants(GRANT_CFG), ["tools.openclaw.autoApproveChanges",
                                                          "agents.entries.haus.tools.openclaw.autoApproveChanges"])
        self.assertEqual(G.openclaw_tool_denies(GRANT_CFG), ["tools.deny", "agents.entries.haus.tools.deny"])
        # a deny of the openclaw tool keeps the grants of its scope without effect (tools.deny: every grant)
        both = ["tools.openclaw.autoApproveChanges", "agents.entries.haus.tools.openclaw.autoApproveChanges"]
        self.assertEqual(G.delegation_grant_split(GRANT_CFG), ([], both))
        self.assertEqual(G.delegation_grant_split(ACTIVE_CFG), (both, []))
        self.assertEqual(G.delegation_grant_split(MIXED_CFG), (both[:1], both[1:]))
        odd_id = del_cfg(agents={"1x": {"openclaw": {"autoApproveChanges": True}, "deny": ["openclaw"]}})
        self.assertEqual(G.delegation_grant_split(odd_id), ([], ['agents.entries["1x"].tools.openclaw.autoApproveChanges']))
        # only the boolean true counts; groups are a choice of their own; odd ids are bracketed; bad shapes are ignored
        odd = del_cfg(tools={"openclaw": {"autoApproveChanges": "true"}, "deny": ["group:openclaw", "group:automation"]},
                      agents={"1x": {"openclaw": {"autoApproveChanges": True}, "deny": [" openclaw "]}})
        self.assertEqual(G.delegation_grants(odd), ['agents.entries["1x"].tools.openclaw.autoApproveChanges'])
        self.assertEqual(G.openclaw_tool_denies(odd), ['agents.entries["1x"].tools.deny'])
        for bad in ({}, None, [], {"tools": "x", "agents": {"entries": []}},
                    {"tools": {"openclaw": True, "deny": "openclaw"}},
                    {"agents": {"entries": {"__proto__": {"tools": {"openclaw": {"autoApproveChanges": True}}}}}}):
            self.assertEqual((G.delegation_grants(bad), G.openclaw_tool_denies(bad)), ([], []), bad)
        self.assertEqual((G.delegation_grants(DEL_BASE), G.openclaw_tool_denies(DEL_BASE)), ([], []))

    def precheck(self, cfg, rt=RT):
        T.make_1004_state(self.state, content=True)
        self.write_cfg(cfg)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime(rt, 22, 27)
        self.hooks()
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        return lines

    def test_precheck_warns_on_a_grant_only(self):
        lines = self.precheck(ACTIVE_CFG)
        warn = [ln for ln in lines if "delegated changes:" in ln]
        self.assertEqual(warn, [
            "WARN [gate] 1/8 delegated changes: tools.openclaw.autoApproveChanges, "
            "agents.entries.haus.tools.openclaw.autoApproveChanges is true, so OpenClaw 2026.11.4 applies every "
            "permitted change an agent asks the openclaw tool for (configuration, plugins, gateway restarts) without "
            "asking anyone, also for an agent whose exec tools are denied: the path GHSA-pw3x-g8v8-fvj2 closed (an "
            "agent's own setting takes precedence over the global one). Only containment still stops it: a session "
            "permission mode other than Full Access or a workspace-only file policy (tools.fs.workspaceOnly). Unless "
            "you want that, set it to false (then every such change waits for a human approval, also in Full Access) "
            "or remove it (openclaw config unset <path>; then such changes are automatic only in Full Access sessions "
            "and for agents that may run exec on the gateway host unrestricted). The migration continues"])
        text = "\n".join(lines)
        self.assertIn("[gate] dry-run: the precheck would pass", text)  # a WARN, never a HOLD
        self.assertNotIn(SECRET, text)
        # grants the deny entries keep without effect: an info line, no WARN
        fresh_state(self)
        lines = [ln for ln in self.precheck(GRANT_CFG) if "delegated changes" in ln]
        self.assertEqual(lines, [
            "[gate] 1/8 info: delegated changes: tools.openclaw.autoApproveChanges, "
            "agents.entries.haus.tools.openclaw.autoApproveChanges is true, but has no effect while tools.deny, "
            "agents.entries.haus.tools.deny denies the openclaw tool. Without that deny entry OpenClaw 2026.11.4 would "
            "apply every permitted change an agent asks the openclaw tool for without asking anyone, also for an agent "
            "whose exec tools are denied (the path GHSA-pw3x-g8v8-fvj2 closed): set it to false or remove it before "
            "you remove the deny entry"])
        # the deny entries alone, a default config, and every runtime before the fix: no line
        for cfg, rt in ((del_cfg(tools={"deny": ["openclaw"]}), RT), (DEL_BASE, RT), (ACTIVE_CFG, "2026.11.3"),
                        (GRANT_CFG, "2026.11.3")):
            with self.subTest(rt=rt, cfg=cfg.get("tools")):
                fresh_state(self)
                self.assertFalse([ln for ln in self.precheck(cfg, rt) if "delegated changes" in ln])

    def run_migration(self, cfg):
        T.make_1004_state(self.state, content=True)
        self.write_cfg(cfg)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime(RT, 22, 27)
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        return self.out[self.out.index("[gate] 7/8 postconditions OK"):], G.status_lines()

    def test_finalize_and_status(self):
        fin, st = self.run_migration(MIXED_CFG)
        grant = G.delegation_grant_text(["tools.openclaw.autoApproveChanges"], RT)
        dormant = G.delegation_dormant_text(["agents.entries.haus.tools.openclaw.autoApproveChanges"],
                                            ["agents.entries.haus.tools.deny"], RT)
        lines = fin.splitlines()
        self.assertIn(f"WARN [gate] {grant}", lines)
        self.assertIn(f"[gate] info: {dormant}", lines)
        info = ("[gate] info: delegated changes: OpenClaw 2026.11.4 contains the fix for GHSA-pw3x-g8v8-fvj2: for an "
                "agent whose exec tool is denied or restricted, a change it asks the openclaw tool for (configuration, "
                "plugins, gateway restarts) now waits for a human approval. Without approval OpenClaw still applies "
                "such changes in a Full Access session, for an agent that may run exec on the gateway host "
                "unrestricted (security full, ask off, no sandbox: OpenClaw's default) and when "
                "tools.openclaw.autoApproveChanges is true. The \"openclaw\" entry in agents.entries.haus.tools.deny "
                "still blocks that tool completely (the interim measure). It can stay; if you remove it, set "
                "tools.openclaw.autoApproveChanges to false (global or the agent's own) where every such change should "
                "wait for a human approval")
        self.assertIn(info, lines)
        done = next(i for i, ln in enumerate(lines) if ln.startswith("[gate] done: MIGRATED"))
        self.assertLess(lines.index(info), done)
        self.assertIn(f"WARN: {grant}", st)
        self.assertIn(f"info: {dormant}", st)
        for ln in [fin] + st:
            self.assertNotIn(SECRET, ln)

    def test_default_config_says_nothing(self):
        fin, st = self.run_migration(DEL_BASE)
        self.assertNotIn("delegated changes", fin + "\n".join(st))
        self.assertNotIn("GHSA", fin + "\n".join(st))


def fresh_state(tc):
    """An empty state directory for the next precheck of the same test (make_1004_state builds it again)."""
    shutil.rmtree(tc.state, ignore_errors=True)
    tc.state.mkdir(parents=True)


if __name__ == "__main__":
    unittest.main()
