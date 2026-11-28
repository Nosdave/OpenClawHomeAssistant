"""Cron inference accounts on OpenClaw 2026.11.10 (0.5.94-full7 bundles it; schemas 40/42; REPORT ONLY).

Three changes against 2026.11.4 and 2026.11.8, each behind a runtime_caps floor of 2026.11.10 (the betas count,
2026.11.9 does not):
- cron_bound_live_fallbacks (e8ff306f741, openclaw/openclaw#196539): a job with a recorded inference account runs
  only its candidates on the recorded provider on that account. Every candidate on another provider, its fallbacks
  there and an own model on another provider, runs on live credentials, as in an interactive run. There is no account
  per fallback. Unbound jobs are refused at a stored login as before (#192195), and that stops the chain.
- cron_load_warn_stored_only (b9d66a0da1b, #195905): the gateway's start warning "automation has no recorded
  inference account" skips a first credential that is a configured key. Of the jobs the gate listed (R6), only the
  ones on a key from the environment are left, and only while that variable is missing. The check has a 5 s budget.
- cron_doctor_binds_codex (74d1342d3ac, #189979): doctor also binds a job whose own model runs on the Codex runtime,
  when that model's first credential is a stored profile.
The 2026.11.4 texts stay as they were (tests/test_gate_1113.py, tests/test_gate_cron_binding.py).
Synthetic fixtures only (10.4-layout state from test_gate, synthetic keys, logins and jobs).
"""

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
import test_gate_1113 as R  # noqa: E402
import test_gate_cron_binding as CB  # noqa: E402

RT = "2026.11.10"
OLD = "2026.11.4"
S, A = 40, 42
LIVE = "openclaw/openclaw#196539"
# 2026.11.10 schema 34 records the default cron partition; the fake doctor does what OpenClaw's does for one store
PARTITION = "INSERT OR REPLACE INTO config_machine_state VALUES ('cron.defaultStoreKey', '\"default\"', 0)"
FB_ONLY = R.FB_ONLY
BOUND_HEAD = ("have a recorded inference account (OpenClaw 2026.11.2+ doctor records one for a job whose own model is "
              "on a stored login, openclaw/openclaw#172792): OpenClaw 2026.11.10 uses that one account only for their "
              "candidates on its provider; their fallbacks on other providers run on live credentials, as in an "
              f"interactive run ({LIVE}; there is no account per fallback): ")
BINDS_LIVE = ("(openclaw/openclaw#172792) when an eligible account fits (with several, the one a run would take now), "
              "and their fallbacks on other providers then run on live credentials, as in an interactive run "
              f"({LIVE})")


def rec(**kw):
    return dict({"runtime": RT, "doctor_migration": True}, **kw)


class CapabilityTests(unittest.TestCase):
    CAPS = ("cron_bound_live_fallbacks", "cron_load_warn_stored_only", "cron_doctor_binds_codex")

    def test_floors(self):
        for v, on in (("2026.11.4", False), ("2026.11.8", False), ("2026.11.9", False),
                      ("2026.11.10-beta.1", True), ("2026.11.10", True), ("2026.12.1", True)):
            caps = C.runtime_caps(v)
            self.assertEqual([caps[c] for c in self.CAPS], [on] * 3, v)
            self.assertTrue(caps["cron_refusal"] and caps["cron_doctor_migration"], v)  # unbound jobs: as before

    def test_manual_binding_texts(self):
        # the 2026.11.4 texts are unchanged
        self.assertIn("openclaw/openclaw#192463", G.CRON_MANUAL)
        self.assertTrue(G.CRON_MANUAL_LAST.startswith("Otherwise (last resort), after the start: "))
        for t in (G.CRON_MANUAL_LIVE, G.CRON_MANUAL_LAST_LIVE):
            self.assertIn("openclaw automations edit <id> --model <provider/model>@<profileId>", t)
            self.assertIn("its fallbacks on other providers then run on live credentials", t)
            self.assertIn(LIVE, t)
            self.assertIn("after the start: ", t)  # _cron_remedy scopes it to the jobs whose own model is refused
            for bad in ("refused", "192463", "last resort"):
                self.assertNotIn(bad, t)
        prim = {"id": "p", "primary_affected": True, "refs": ["openai/gpt-5.5"]}
        fb = {"id": "f", "primary_affected": False, "refs": ["openai/gpt-5.5"]}
        self.assertEqual(G._cron_remedy([prim], rec=rec()), G.CRON_MANUAL_LIVE)
        self.assertEqual(G._cron_remedy([prim], True, rec()), G.CRON_MANUAL_LAST_LIVE)
        self.assertEqual(G._cron_remedy([prim], rec=rec(runtime=OLD)), G.CRON_MANUAL)
        self.assertEqual(G._cron_remedy([prim]), G.CRON_MANUAL)
        self.assertEqual(G._cron_remedy([prim, fb], rec=rec()),
                         G.CRON_MANUAL_LIVE.replace("after the start: ", "after the start, for a job whose own model "
                                                    "is refused: ") + ". " + G.CRON_FALLBACK)
        self.assertEqual(G._cron_remedy([fb], rec=rec()), G.CRON_FALLBACK)  # unbound jobs: unchanged

    def test_outlook_before_the_migration(self):
        prim = {"id": "p", "primary_affected": True, "refs": ["openai/gpt-5.5"]}
        fb = {"id": "f", "primary_affected": False, "refs": ["openai/gpt-5.5"]}
        self.assertEqual(G._cron_outlook([prim, fb], rec()), [
            "OpenClaw 2026.11.10 doctor records the inference account of the jobs whose own model is on a stored login "
            "during the migration " + BINDS_LIVE, f"OpenClaw 2026.11.10 doctor {FB_ONLY}"])
        old = G._cron_outlook([prim], rec(runtime=OLD))
        self.assertEqual(old, ["OpenClaw 2026.11.4 doctor records the inference account of such jobs during the "
                               "migration (openclaw/openclaw#172792) when an eligible account fits (with several, the one "
                               "a run would take now), but then refuses their fallbacks to other providers (as with "
                               "openclaw/openclaw#192463)"])
        # after the migration: what doctor left, as before
        self.assertEqual(G._cron_outlook([prim, fb], rec(), after=True), [
            "OpenClaw 2026.11.10 doctor left the jobs whose own model is refused (its warnings are in oc-upgrade log)",
            f"OpenClaw 2026.11.10 doctor {FB_ONLY}"])

    def test_doctor_binds_text(self):
        binds = [{"id": "j", "name": "J", "primary_affected": True, "refs": ["openai/gpt-5.5"]}]
        line = G.cron_doctor_binds_text(binds, rec(), RT)
        self.assertEqual(line, "1 enabled cron job(s) without a recorded inference account run their own model on a "
                               "stored login: 'J' (j); OpenClaw 2026.11.10 doctor records that account during the "
                               f"migration {BINDS_LIVE}; the gate reports the jobs doctor leaves after the migration")
        self.assertIn("(openclaw/openclaw#172792) when an eligible account fits (with several, the one a run would "
                      "take now), but then refuses their fallbacks to other providers (as with "
                      "openclaw/openclaw#192463)", G.cron_doctor_binds_text(binds, rec(), OLD))


class BoundJobTests(unittest.TestCase):
    """N2 on 2026.11.10: bound jobs keep their fallbacks on other providers, on live credentials."""

    def jobs(self):
        def job(jid, binding, enabled=True, **payload):
            return {"id": jid, "name": jid, "enabled": enabled, "runtime_authority": False, "job": {
                "agentId": "main", "sessionTarget": "isolated", "inferenceBinding": binding,
                "payload": dict({"kind": "agentTurn"}, **payload)}}
        return [job("fine", dict(R.BINDING), model="openai/gpt-5.5", fallbacks=["anthropic/claude-x", "glm/glm-5"]),
                job("alone", dict(R.BINDING), model="openai/gpt-5.5", fallbacks=["openai/gpt-5.5-mini"]),
                job("inh", dict(R.BINDING)),  # its default model moved to anthropic
                job("off", dict(R.BINDING, provider="anthropic"), enabled=False, model="anthropic/claude-x",
                    fallbacks=["openai/gpt-5.5"]),
                job("noprov", {"profileId": "x"}, model="openai/gpt-5.5")]

    def cfg(self):
        cfg = json.loads(json.dumps(CB.CFG_GLM))
        cfg["agents"]["defaults"]["model"] = {"primary": "anthropic/claude-x", "fallbacks": ["glm/glm-5"]}
        return cfg

    def test_entries_name_the_live_candidates(self):
        got = G.cron_bound_jobs(self.jobs(), self.cfg(), "main", {"main"}, live=True)
        self.assertEqual(got, [
            {"id": "fine", "name": "fine", "enabled": True, "provider": "openai",
             "live": ["anthropic/claude-x", "glm/glm-5"]},
            {"id": "alone", "name": "alone", "enabled": True, "provider": "openai", "live": []},
            {"id": "inh", "name": "inh", "enabled": True, "provider": "openai", "live": ["glm/glm-5"],
             "own_live": "anthropic/claude-x"},
            {"id": "off", "name": "off", "enabled": False, "provider": "anthropic", "live": ["openai/gpt-5.5"]},
            {"id": "noprov", "name": "noprov", "enabled": True, "provider": None, "live": []}])
        # 2026.11.4: the same jobs with their refused refs (unchanged)
        old = G.cron_bound_jobs(self.jobs(), self.cfg(), "main", {"main"})
        self.assertEqual([(a["id"], a.get("refused"), a.get("own_refused")) for a in old], [
            ("fine", ["anthropic/claude-x", "glm/glm-5"], None), ("alone", [], None),
            ("inh", ["glm/glm-5"], "anthropic/claude-x"), ("off", ["openai/gpt-5.5"], None), ("noprov", [], None)])

    def test_bound_line_has_no_refusal_and_names_an_own_model_on_another_provider(self):
        got = G.cron_bound_jobs(self.jobs(), self.cfg(), "main", {"main"}, live=True)
        r = rec(bound_jobs=got, bound_jobs_count=len(got))
        line = G.cron_bound_line(r)
        self.assertEqual(line, "4 cron job(s) (1 of them disabled) " + BOUND_HEAD
                         + "'fine' (fine) on openai; 'alone' (alone) on openai; 'inh' (inh) on openai (its own model "
                           "anthropic/claude-x is on another provider, so it runs on live credentials too); 'off' (off, "
                           "disabled) on anthropic")
        for bad in ("refused", "192463", "drop it", "openai:default"):
            self.assertNotIn(bad, line)
        # the own model on another provider is an info now; only the record without a provider is a WARN
        self.assertEqual(G.cron_bound_warn_lines(r), [
            "cron job 'noprov' (noprov): its recorded inference account names no provider: OpenClaw 2026.11.10 "
            "treats such a record as invalid ('Invalid automation inference binding; explicitly select an account "
            "again.'); to fix: openclaw automations edit <id> --model <provider/model>@<profileId>"])
        self.assertNotIn("different provider", "\n".join(G.cron_bound_warn_lines(r)))
        # more jobs than listed
        self.assertIn("'off' (off, disabled) on anthropic and 3 more", G.cron_bound_line(dict(r, bound_jobs_count=8)))

    def test_old_runtime_keeps_its_texts(self):
        old = G.cron_bound_jobs(self.jobs(), self.cfg(), "main", {"main"})
        r = {"runtime": OLD, "bound_jobs": old, "bound_jobs_count": len(old)}
        self.assertIn("OpenClaw refuses their fallbacks to other providers (as with openclaw/openclaw#192463)",
                      G.cron_bound_line(r))
        warn = G.cron_bound_warn_lines(r)
        self.assertEqual(len(warn), 2)
        self.assertIn("refuses it ('The selected model uses a different provider from this job's stored account')",
                      warn[0])

    def test_record_of_a_live_runtime_with_old_field_names(self):
        """A 2026.11.10 record written with the 2026.11.4 field names still reads (own_refused as the own model)."""
        r = rec(bound_jobs=[{"id": "x", "name": "X", "enabled": True, "provider": "openai", "refused": ["glm/glm-5"],
                             "own_refused": "anthropic/claude-x", "on_account": []}])
        self.assertIn("'X' (x) on openai (its own model anthropic/claude-x is on another provider",
                      G.cron_bound_line(r))
        self.assertEqual(G.cron_bound_warn_lines(r), [])


class LoadWarnTests(unittest.TestCase):
    """R6 on 2026.11.10: the start warning skips a configured key."""

    def setUp(self):
        cfg = json.loads(json.dumps(CB.CFG_GLM))
        cfg["models"]["providers"]["glm"]["auth"] = "api-key"
        cfg["models"]["providers"]["envkey"] = {"apiKey": {"source": "env", "provider": "default", "id": "X"},
                                                "models": [{"id": "m"}]}
        cfg["models"]["providers"]["blank"] = {"apiKey": "  ", "models": [{"id": "m"}]}
        self.cfg = cfg

        def job(jid, model):
            return {"id": jid, "name": f"Job {jid}", "enabled": True, "runtime_authority": False,
                    "job": {"agentId": "main", "sessionTarget": "isolated",
                            "payload": {"kind": "agentTurn", "model": model}}}
        self.jobs = [job("glm", "glm/glm-5"), job("env", "envkey/m"), job("blank", "blank/m"),
                     job("gem", "google/gemini-x"), job("lan", "lan/q"), job("cli", "claude-cli/default")]

    def test_only_the_environment_jobs_are_left(self):
        prof = [{"id": "openai:default", "provider": "openai"}]
        old = G.cron_load_warn_jobs(self.jobs, self.cfg, lambda _a: prof, "main", {"main"})
        self.assertEqual([(a["id"], a["key"]) for a in old],
                         [("glm", "config"), ("env", "config"), ("blank", "env"), ("gem", "env")])
        got = G.cron_load_warn_jobs(self.jobs, self.cfg, lambda _a: prof, "main", {"main"}, stored_only=True)
        self.assertEqual([(a["id"], a["provider"], a["key"]) for a in got],
                         [("blank", "blank", "env"), ("gem", "google", "env")])

    def test_line_says_when_the_gateway_warns(self):
        got = G.cron_load_warn_jobs(self.jobs, self.cfg, lambda _a: [], "main", {"main"}, stored_only=True)
        got[0]["enabled"] = False
        line = G.cron_load_warn_line(rec(load_warn=got))
        self.assertEqual(line, (
            "2 cron job(s) (1 of them disabled) run their own model on a key from the environment (blank, google: a "
            "gateway_env_vars entry such as OPENAI_API_KEY or GEMINI_API_KEY) and have no recorded inference account: "
            "OpenClaw 2026.11.10 doctor leaves such jobs unbound on purpose, and they run on that key while the "
            "variable is set for the gateway (a gate run cannot check it). While it is missing they have no credential "
            "and fail when they run, and the gateway writes 'cron: automation has no recorded inference account; run "
            "openclaw doctor --fix before its next scheduled run ...' (or 'cron: legacy inference account readiness "
            "could not be determined; inspect it with openclaw doctor --lint ...') for each of them to OpenClaw's own "
            "log (openclaw logs, the Control UI's Logs page; not the add-on log), at every start and after each "
            "cron.* config change; with the variable set it writes nothing for them. That check stops after 5 s in "
            "all ('cron: startup inference diagnostics reached their time budget; N jobs were not checked. Run "
            "openclaw doctor --lint for a complete check.'); openclaw doctor --lint is allowed in the add-on and "
            "checks every job. The add-on refuses openclaw doctor --fix, and its equivalent oc-upgrade retry --doctor "
            "would not record an account for these jobs either: 'Job blank' (blank), 'Job gem' (gem)"))
        self.assertNotIn("configured key", line)
        self.assertNotIn("Expected and harmless", line)
        self.assertIn("'Job gem' (gem) and 3 more", G.cron_load_warn_line(rec(load_warn=got, load_warn_count=5)))
        # configured-key entries (a record of an earlier add-on version, or one without "key") give no line
        self.assertIsNone(G.cron_load_warn_line(rec(load_warn=[{"id": "x", "name": "X", "enabled": True,
                                                                "provider": "glm", "key": "config"},
                                                               {"id": "y", "name": "Y", "provider": "glm"}])))
        # 2026.11.4 keeps its line for both groups
        old = G.cron_load_warn_line({"runtime": OLD, "load_warn": [{"id": "x", "name": "X", "enabled": True,
                                                                    "provider": "glm", "key": "config"}]})
        self.assertIn("run their own model on a configured key (glm: models.providers.<provider>.apiKey)", old)
        self.assertIn("at every start and cron reload", old)


class CodexBindTests(unittest.TestCase):
    def test_doctor_binds_a_job_on_the_codex_runtime(self):
        cdx = {"primary_affected": True, "refs": ["openai/gpt-5.5"], "own_runtime": "codex"}
        other = {"primary_affected": True, "refs": ["openai/gpt-5.5"], "own_runtime": "pi"}
        cli = {"primary_affected": True, "refs": ["claude-cli/default"]}
        plain = {"primary_affected": True, "refs": ["openai/gpt-5.5"]}
        self.assertEqual(G._cron_doctor_binds([cdx, other, cli, plain], rec()), [cdx, plain])
        self.assertEqual(G._cron_doctor_binds([cdx, other, cli, plain], rec(runtime=OLD)), [plain])
        self.assertEqual(G._cron_doctor_binds([cdx, plain]), [plain])  # no record: the 2026.11.2 rule

    def test_own_runtime_clause(self):
        a = {"own_runtime": "codex", "own_runtime_at": "agents.defaults.models[\"openai/gpt-5.5\"].agentRuntime"}
        self.assertEqual(G.cron_own_runtime_clause(a, rec()), (
            "; its model is set to the codex runtime (agents.defaults.models[\"openai/gpt-5.5\"].agentRuntime): "
            "OpenClaw 2026.11.10 doctor records the account of such a job for the Codex runtime when that model's "
            "first credential is a stored login (openclaw/openclaw#189979), but it left this job unbound (doctor's "
            "warnings are in oc-upgrade log)"))
        self.assertIn("so OpenClaw 2026.11.4 doctor records no inference account for it (doctor: 'runtime codex "
                      "inference ownership was left unchanged')", G.cron_own_runtime_clause(a, rec(runtime=OLD)))
        pi = dict(a, own_runtime="pi")
        self.assertIn("so OpenClaw 2026.11.10 doctor records no inference account for it (doctor: 'runtime pi "
                      "inference ownership was left unchanged')", G.cron_own_runtime_clause(pi, rec()))


class FixupTextTests(unittest.TestCase):
    def test_none_text(self):
        a = {"provider": "glm", "path": "models.providers.glm.auth", "jobs": [], "bound": ["job-codex"]}
        self.assertEqual(G.cron_fixup_none_text(a, RT), (
            "for no enabled cron job: the 1 enabled cron job(s) that reach glm only as a fallback run their own model "
            "on another provider's stored login; once OpenClaw 2026.11.10 doctor records that account for them, their "
            f"fallbacks on other providers run on live credentials ({LIVE}), glm on the configured key with this fixup "
            "and on doctor's copy of the key without it; without that account their own model is refused and the "
            "chain stops before glm"))
        self.assertIn("refuses glm for them either way", G.cron_fixup_none_text(a, OLD))
        self.assertEqual(G.cron_fixup_none_text(dict(a, bound=[]), RT), "for no enabled cron job")

    def test_kept_text_tells_own_model_jobs_from_fallback_jobs(self):
        own = {"id": "own", "name": "Own", "primary_affected": True, "refs": ["glm/glm-5", "openai/gpt-5.5"]}
        alone = {"id": "alone", "name": "Alone", "primary_affected": True, "refs": ["glm/glm-5"]}
        fb = {"id": "fb", "name": "Fb", "primary_affected": False, "refs": ["glm/glm-5"]}
        kept = [(own, ["glm/glm-5"]), (alone, ["glm/glm-5"]), (fb, ["glm/glm-5"])]
        fix = [{"provider": "glm", "path": "models.providers.glm.auth"}]
        line = G.cron_fixup_kept_text(kept, fix, RT, {"own"})
        self.assertEqual(line, (
            "1 enabled cron job(s) kept working by the automatic fix (models.providers.glm.auth = \"api-key\" before "
            "doctor pass 1; otherwise OpenClaw 2026.11.10 refuses glm/glm-5 on doctor's copy of the literal key, and "
            "that stops the chain): 'Fb' (fb). 2 enabled cron job(s) whose own model the automatic fix keeps on the "
            "configured key (models.providers.glm.auth = \"api-key\" before doctor pass 1): 'Own' (own), 'Alone' "
            "(alone). Without the fix OpenClaw 2026.11.10 doctor would record its copy of the literal key as their "
            "account: their own model would run on that copy, and their fallbacks on other providers on live "
            f"credentials ({LIVE}). With the fix they stay unbound, so a fallback that needs a recorded account stays "
            "refused (openclaw/openclaw#192195) for 'Own' (own) (the WARN lines below)"))
        self.assertTrue(G.cron_fixup_kept_text(kept[1:2], fix, RT).endswith("With the fix they stay unbound"))
        self.assertEqual(G.cron_fixup_kept_text(kept, fix, OLD), (
            "3 enabled cron job(s) kept working by the automatic fix (models.providers.glm.auth = \"api-key\" before "
            "doctor pass 1; otherwise OpenClaw 2026.11.4 refuses glm/glm-5 on doctor's copy of the literal key): 'Own' "
            "(own), 'Alone' (alone), 'Fb' (fb)"))


# --- gate runs on 2026.11.10 ----------------------------------------------------------------------------------

class Cron1110GateTests(T.GateEnv):
    """CB.CFG_GLM (glm on a literal key, kept on it by the gate's auth "api-key" fixup; openai/anthropic stored
    logins) with the 2026.11.4 rehearsal jobs, migrated by a 2026.11.10 doctor."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, agents=("main", "haus"), content=True)
        CB.add_jobs(self.state, CB.GLM_JOBS)
        CB.add_jobs(self.state, R.GLM_OFF, start=20)
        self.write_cfg(CB.CFG_GLM)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime(RT, S, A)
        self.hooks()
        self.sdb = self.state / "state" / "openclaw.sqlite"

    def dry(self):
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        return lines

    def doctor(self, bind=("job-morning",), extra_sql=()):
        """Like OpenClaw 2026.11.10 doctor: stores glm's literal key as glm:default, records the openai account of
        the `bind` jobs and the default cron partition."""
        store = json.loads(json.dumps(T.AUTH_1004_STORE))
        store["profiles"]["glm:default"] = {"type": "api_key", "provider": "glm", "key": CB.GLM_KEY}
        ids = ", ".join(f"'{x}'" for x in bind)
        self.doctor_script(state_uv=S, agent_uv=A, app_version=RT, drop_tables=["cron_run_logs"],
                           remove=["identity/device.json"], sql=[
            PARTITION,
            "INSERT OR REPLACE INTO config_machine_state VALUES ('auth.sharedStore', '{\"location\": \"state-db\"}', 0)",
            "INSERT OR REPLACE INTO config_machine_state VALUES ('authProfiles.store', '%s', 0)" % json.dumps(store),
            "UPDATE cron_jobs SET job_json = json_set(job_json, '$.inferenceBinding', json('%s')) "
            "WHERE job_id IN (%s)" % (json.dumps(R.BINDING), ids)] + list(extra_sql))

    def test_precheck_says_bound_jobs_keep_their_fallbacks(self):
        CB.add_jobs(self.state, R.CODEX_JOBS, start=30)
        lines = self.dry()
        text = "\n".join(lines)
        info = [ln for ln in lines if "records that account" in ln]
        self.assertEqual(info, ["[gate] 1/8 info: 2 enabled cron job(s) without a recorded inference account run "
                                "their own model on a stored login: 'Morning summary' (job-morning), 'Job Codex' "
                                "(job-codex); OpenClaw 2026.11.10 doctor records that account during the migration "
                                f"{BINDS_LIVE}; the gate reports the jobs doctor leaves after the migration"])
        self.assertIn("[gate]   cron inference accounts: 2 enabled cron job(s) run their own model on a stored login "
                      "without a recorded account; OpenClaw 2026.11.10 doctor records it (openclaw/openclaw#172792) "
                      "when an eligible account fits (with several, the one a run would take now), and their fallbacks "
                      f"on other providers then run on live credentials ({LIVE})", lines)
        # the fixup: job-lan-fb reaches glm as a fallback (kept working); job-local and job-glm-haus run their own
        # model on glm, which doctor would otherwise bind to its copy of the key
        kept = [ln for ln in lines if "kept working by the automatic fix" in ln]
        self.assertEqual(len(kept), 1, lines)
        self.assertTrue(kept[0].startswith(
            "[gate] 1/8 info: 1 enabled cron job(s) kept working by the automatic fix (models.providers.glm.auth = "
            "\"api-key\" before doctor pass 1; otherwise OpenClaw 2026.11.10 refuses glm/glm-5 on doctor's copy of "
            "the literal key, and that stops the chain): 'Job Lan Fb' (job-lan-fb). 2 enabled cron job(s) whose own "
            "model the automatic fix keeps on the configured key"), kept[0])
        self.assertTrue(kept[0].endswith("for 'Local digest' (job-local) (the WARN lines below)"), kept[0])
        self.assertIn("[gate]   cron config fixup: would set models.providers.glm.auth = \"api-key\" before doctor "
                      "pass 1 (keeps 1 enabled cron job(s) that reach glm as a fallback working, and makes 2 enabled "
                      "cron job(s) whose own model is on glm use its configured key, not doctor's copy; "
                      "openclaw/openclaw#192195)", lines)
        self.assertLess(lines.index(kept[0]), next(i for i, ln in enumerate(lines)
                                                   if ln.startswith("WARN [gate] cron job 'Local digest'")))
        self.assertEqual(json.loads(json.dumps(self.journal_forecast()))["autofix"], [
            {"provider": "glm", "path": "models.providers.glm.auth",
             "jobs": ["job-local", "job-glm-haus", "job-lan-fb"], "bound": ["job-codex"],
             "own": ["job-local", "job-glm-haus"]}])
        for bad in ("192463", "then refuses their fallbacks", "exactly one", CB.GLM_KEY, "SECRET"):
            self.assertNotIn(bad, text)

    def journal_forecast(self):
        g = G.Gate(emit=lambda s: None)
        g.pkg = C.runtime_package()
        g.cfg = json.loads((self.state / "openclaw.json").read_text())
        g.cfg_raw = (self.state / "openclaw.json").read_text()
        g.j = None
        g.dry_run = True
        g.cron_binding_forecast({}, "bump")
        return g.facts["cron_binding_plan"]

    def test_fixup_that_keeps_no_job_says_the_bound_job_runs_glm_live(self):
        con = sqlite3.connect(str(self.sdb))
        con.execute("DELETE FROM cron_jobs")
        con.commit()
        con.close()
        CB.add_jobs(self.state, R.CODEX_JOBS[:1], start=30)
        lines = self.dry()
        none = G.cron_fixup_none_text({"provider": "glm", "bound": ["job-codex"]}, RT)
        self.assertIn("[gate] 1/8 config fixup: would set models.providers.glm.auth = \"api-key\" before doctor pass 1 "
                      f"({G.cron_fixup_why('glm', RT)}); {none}", lines)
        self.assertIn("[gate]   cron config fixup: would set models.providers.glm.auth = \"api-key\" before doctor "
                      f"pass 1 ({none}; {G.CRON_FIXUP_ISSUE})", lines)
        self.assertIn("their fallbacks on other providers run on live credentials", none)

    def test_bound_jobs_after_the_migration(self):
        """N2 end to end: the end of the run and oc-upgrade status name the bound jobs, disabled ones too, without a
        'refused:' list; a bound job whose default model moved to another provider is an info, not a WARN."""
        CB.add_jobs(self.state, R.CODEX_JOBS, start=30)
        anth = dict(R.BINDING, provider="anthropic", profileId="anthropic:manual")
        self.doctor(bind=("job-morning", "job-codex", "job-local"), extra_sql=[
            "UPDATE cron_jobs SET job_json = json_set(job_json, '$.inferenceBinding', json('%s')) "
            "WHERE job_id = 'job-claude-off'" % json.dumps(anth)])
        cfg = json.loads(json.dumps(CB.CFG_GLM))
        cfg["agents"]["defaults"]["model"] = {"primary": "anthropic/claude-x", "fallbacks": ["openai/gpt-5.5"]}
        self.write_cfg(cfg)
        self.assertEqual(self.run_gate(), 0, self.out)
        fin = self.out[self.out.index("[gate] 7/8 postconditions OK"):]
        rec_ = self.journal()["cron_binding"]
        self.assertEqual([(a["id"], a["enabled"], a["provider"], a["live"], a.get("own_live"))
                          for a in rec_["bound_jobs"]], [
            ("job-morning", True, "openai", ["anthropic/claude-sonnet-4-6"], None),
            ("job-local", True, "openai", [], "anthropic/claude-x"),
            ("job-codex", True, "openai", ["glm/glm-5"], None),
            ("job-claude-off", False, "anthropic", ["glm/glm-5", "openai/gpt-5.5"], None)])
        self.assertFalse([a for a in rec_["bound_jobs"] if "refused" in a or "own_refused" in a])
        bl = ("4 cron job(s) (1 of them disabled) " + BOUND_HEAD + "'Morning summary' (job-morning) on openai; "
              "'Local digest' (job-local) on openai (its own model anthropic/claude-x is on another provider, so it "
              "runs on live credentials too); 'Job Codex' (job-codex) on openai; 'Job Claude Off' (job-claude-off, "
              "disabled) on anthropic")
        self.assertIn(f"[gate] info: {bl}", fin)
        st = G.status_lines()
        self.assertIn(f"  {bl}", st)
        for ln in [fin] + st:
            for bad in ("different provider", "refused: ", "192463", "anthropic:manual", "openai:default",
                        CB.GLM_KEY):
                self.assertNotIn(bad, ln)

    def test_no_gateway_warning_line_for_configured_keys(self):
        """R6: the glm jobs run on glm's configured key; 2026.11.10's gateway writes nothing for them."""
        self.doctor()
        self.assertEqual(self.run_gate(), 0, self.out)
        rec_ = self.journal()["cron_binding"]
        self.assertNotIn("load_warn", rec_)
        self.assertNotIn("automation has no recorded inference account", self.out)
        self.assertNotIn("automation has no recorded inference account", "\n".join(G.status_lines()))
        self.assertIn("WARN [gate] 2 cron job(s) above still have no recorded inference account after the migration: "
                      f"OpenClaw 2026.11.10 doctor {FB_ONLY}. " + G.CRON_FALLBACK, self.out)

    def test_gateway_warning_line_for_a_key_from_the_environment(self):
        CB.add_jobs(self.state, [("job-gem", {"agentId": "main", "sessionTarget": "isolated", "payload": {
            "kind": "agentTurn", "message": CB.PROMPT, "model": "google/gemini-x", "fallbacks": []}})], start=40)
        self.doctor()
        self.assertEqual(self.run_gate(), 0, self.out)
        rec_ = self.journal()["cron_binding"]
        self.assertEqual([(a["id"], a["provider"], a["key"]) for a in rec_["load_warn"]],
                         [("job-gem", "google", "env")])
        line = G.cron_load_warn_line(rec_)
        self.assertTrue(line.startswith("1 cron job(s) run their own model on a key from the environment (google: "),
                        line)
        self.assertIn(f"[gate] info: {line}", self.out)
        self.assertIn(f"  {line}", G.status_lines())


class CronCodex1110Tests(T.GateEnv):
    """A job whose own model openai/gpt-5.5 is set to the codex runtime: 2026.11.10 doctor binds it (it is in the
    precheck's info line, not a WARN); a job doctor left gets the 2026.11.10 clause."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, content=True)
        T.write_install_records(self.state, {"codex": ("@openclaw/codex", "2026.11.10", None)})
        os.makedirs(T.plugin_project_dir(self.state, "@openclaw/codex", "2026.11.10"), exist_ok=True)
        cfg = json.loads(json.dumps(R.CFG_CODEX))
        cfg["agents"]["defaults"]["models"] = {"openai/gpt-5.5": {"agentRuntime": {"id": "codex"}}}
        self.write_cfg(cfg)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime(RT, S, A)
        self.hooks()

    def test_precheck_counts_the_codex_job_among_the_ones_doctor_binds(self):
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        info = [ln for ln in lines if "records that account" in ln]
        self.assertEqual(len(info), 1, lines)
        self.assertIn("run their own model on a stored login: 'Morning summary' (job-morning); ", info[0])
        self.assertFalse([ln for ln in lines if ln.startswith("WARN [gate] cron job 'Morning summary'")])
        self.assertNotIn("inference ownership was left unchanged", "\n".join(lines))

    def test_a_codex_job_doctor_left(self):
        self.doctor_script(state_uv=S, agent_uv=A, app_version=RT, drop_tables=["cron_run_logs"],
                           remove=["identity/device.json"], sql=[PARTITION])
        self.assertEqual(self.run_gate(), 0, self.out)
        warn = [ln for ln in self.out.splitlines() if ln.startswith("WARN [gate] cron job 'Morning summary'")]
        self.assertEqual(len(warn), 1, self.out)
        self.assertIn("; its model is set to the codex runtime (agents.defaults.models[\"openai/gpt-5.5\"]"
                      ".agentRuntime): OpenClaw 2026.11.10 doctor records the account of such a job for the Codex "
                      "runtime when that model's first credential is a stored login (openclaw/openclaw#189979), but "
                      "it left this job unbound (doctor's warnings are in oc-upgrade log)", warn[0])
        self.assertNotIn("left unchanged", warn[0])


# --- a realistic layout (synthetic) ----------------------------------------------------------------------------

GEMINI_REF = {"source": "env", "provider": "default", "id": "GEMINI_API_KEY"}
CFG_OWNER = {"meta": {"lastTouchedVersion": "2026.11.4"}, "gateway": {"mode": "local"},
             "agents": {"defaults": {"model": {"primary": "glm/glm-5",
                                               "fallbacks": ["openai/gpt-5.5", "xai/grok-x", "anthropic/claude-x",
                                                             "google/gemini-x"]},
                                     "heartbeat": {"every": "30m"}},
                        "list": [{"id": "main", "default": True}, {"id": "other_agent"}]},
             "models": {"providers": {
                 "glm": {"baseUrl": "http://127.0.0.1:8000/v1", "api": "openai-completions", "apiKey": CB.GLM_KEY,
                         "auth": "api-key", "models": [{"id": "glm-5"}]},
                 "google": {"apiKey": GEMINI_REF}}},
             "auth": {"profiles": {"xai:oauth": {"provider": "xai", "mode": "oauth"}}},
             "plugins": {"entries": {"codex": {"enabled": True}}}}
OWNER_JOBS = ([(f"job-{i}", {"agentId": "main", "sessionTarget": "isolated", "payload": {
                  "kind": "agentTurn", "message": CB.PROMPT, "model": "glm/glm-5", "fallbacks": ["google/gemini-x"]}})
               for i in range(8)]
              + [(f"job-mail-{i}", {"agentId": "other_agent", "sessionTarget": "isolated", "payload": {
                  "kind": "agentTurn", "message": CB.PROMPT, "model": "glm/glm-5", "fallbacks": []}})
                 for i in range(2)])


def heartbeat_job_sql(agent, order):
    """The cron job 2026.11.10 doctor makes from agents.defaults.heartbeat for `agent` (no model, no fallbacks)."""
    job = {"id": f"hb-{agent}", "name": f"Heartbeat {agent}", "enabled": True, "agentId": agent,
           "sessionTarget": f"session:agent:{agent}:main", "schedule": {"kind": "every", "everyMs": 1800000},
           "payload": {"kind": "agentTurn", "message": "synthetic heartbeat"}}
    return ("INSERT OR IGNORE INTO cron_jobs (store_key, job_id, name, enabled, agent_id, payload_kind, job_json, "
            "sort_order, updated_at) VALUES ('default', '%s', '%s', 1, '%s', 'agentTurn', '%s', %d, 0)"
            % (job["id"], job["name"], agent, json.dumps(job), order))


class OwnerLayout1110Tests(T.GateEnv):
    """8 jobs glm -> google/gemini-x (google's key as an env SecretRef in models.providers), 2 other_agent jobs on glm
    only, glm on a literal key with auth "api-key", openai and xai on OAuth logins, the Codex plugin active, and a
    heartbeat that doctor turns into one cron job per agent. Every cron line must hold on 2026.11.10."""

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, agents=("main", "other_agent"), content=True)
        self.sdb = self.state / "state" / "openclaw.sqlite"
        con = sqlite3.connect(str(self.sdb))
        con.execute("DELETE FROM cron_jobs")
        con.commit()
        con.close()
        CB.add_jobs(self.state, OWNER_JOBS)
        T.write_install_records(self.state, {"codex": ("@openclaw/codex", "2026.11.10", None)})
        os.makedirs(T.plugin_project_dir(self.state, "@openclaw/codex", "2026.11.10"), exist_ok=True)
        self.write_cfg(CFG_OWNER)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.11.4", "mode": "bump"}))
        self.set_runtime(RT, S, A)
        self.doctor_script(state_uv=S, agent_uv=A, app_version=RT, drop_tables=["cron_run_logs"],
                           remove=["identity/device.json"],
                           sql=[PARTITION, heartbeat_job_sql("main", 50), heartbeat_job_sql("other_agent", 51)])
        self.hooks()

    def test_precheck_has_no_cron_finding(self):
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        self.assertFalse([ln for ln in lines if "cron job " in ln.replace("cron job per agent", "")
                          or "cron inference" in ln or "config fixup" in ln], lines)

    def test_after_the_migration_only_the_heartbeat_jobs_stop_at_a_login(self):
        self.assertEqual(self.run_gate(), 0, self.out)
        fin = self.out[self.out.index("[gate] 7/8 postconditions OK"):]
        rec_ = self.journal()["cron_binding"]
        self.assertEqual(rec_["checked"], 12)
        self.assertEqual([(a["id"], a["refs"], a.get("codex")) for a in rec_["affected"]], [
            (f"hb-{x}", ["openai/gpt-5.5", "xai/grok-x", "anthropic/claude-x"], ["openai/gpt-5.5"])
            for x in ("main", "other_agent")])
        for k in ("load_warn", "bound_jobs", "autofix", "key_fix"):
            self.assertFalse(rec_.get(k), k)
        warn = [ln for ln in fin.splitlines() if ln.startswith("WARN [gate] cron job ")]
        self.assertEqual(warn, [
            f"WARN [gate] cron job 'Heartbeat {x}' (hb-{x}): its model glm/glm-5 needs no stored login and keeps "
            "working, but when it fails OpenClaw 2026.11.10 stops at the fallback openai/gpt-5.5 (stored login, no "
            "recorded inference account; openclaw/openclaw#192195) instead of trying further models"
            + R.CODEX_CLAUSE + "; also on a stored login: xai/grok-x, anthropic/claude-x"
            for x in ("main", "other_agent")])
        self.assertIn("WARN [gate] 2 cron job(s) above still have no recorded inference account after the migration: "
                      f"OpenClaw 2026.11.10 doctor {FB_ONLY}. " + G.CRON_FALLBACK, fin)
        st = "\n".join(G.status_lines())
        for text in (fin, st):
            for bad in ("automation has no recorded inference account", "have a recorded inference account",
                        "job-0", "job-mail-0", "google/gemini-x", "glm:default", CB.GLM_KEY, "SECRET"):
                self.assertNotIn(bad, text)


if __name__ == "__main__":
    unittest.main()
