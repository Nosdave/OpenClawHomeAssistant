"""OpenClaw 2026.11.1 (the image default since the full5 prep): what changed in the gate against 2026.10.10.

- openclaw/openclaw#186305: doctor keeps an invalid heartbeat.activeHours window instead of removing it, and with
  #187192 `doctor --fix` then exits 1 ("Doctor blocked; required repairs remain incomplete.") after the migration has
  started. The precheck holds first with the hard code config-heartbeat-hours (oc_common.runtime_caps
  heartbeat_hours_kept); nothing changes for 2026.10.4 or 2026.10.10, whose doctor removes the window.
- #187192: a blocked doctor is its own hard code doctor-blocked whose reason lists doctor's [error] findings, instead of
  the generic doctor-failed (or doctor-held-back when a held-store warning came first).
Doctor texts are the 2026.11.1 ones (doctor-health.ts, doctor-config-validation-findings.ts,
doctor-health-contribution.ts renderStructuredHealthFindings, legacy-config-core-migrate.ts).
"""

import json
import shutil
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
import oc_migrate as M  # noqa: E402
import test_gate as T  # noqa: E402

CAPS_1111 = C.runtime_caps("2026.11.1")
BLOCKED_OUTRO = "└  Doctor blocked; required repairs remain incomplete."
FIX_CONFIG = ("  fix: Run `openclaw doctor --fix` to migrate or remove retired keys. If no migration applies, correct the "
              "value or use `openclaw config unset <key>` with the rejected key path, then rerun Doctor.")
KEPT_WARNING = ('│  - Kept invalid agents.defaults.heartbeat.activeHours.start="25:00": invalid time (use "HH:MM" 24h '
                'format). Heartbeat config remains invalid; fix the value, then rerun "openclaw doctor --fix".')


def blocked_text(*findings, before=()):
    lines = list(before)
    for check, path, message, fix in findings:
        lines.append(f"[error] {check}{' ' + path if path else ''} - {message}")
        lines.append(fix)
    lines.append(BLOCKED_OUTRO)
    return "\n".join(lines) + "\n"


class HeartbeatHoursFindingTests(unittest.TestCase):
    def codes(self, cfg, caps=CAPS_1111):
        return M.heartbeat_hours_findings(cfg, caps=caps, runtime="2026.11.1")

    def hb(self, **active):
        return {"agents": {"defaults": {"heartbeat": {"every": "30m", "activeHours": active}}}}

    def test_capability_by_version(self):
        self.assertTrue(CAPS_1111["heartbeat_hours_kept"])
        for v in ("2026.10.4", "2026.10.10", "2026.11.0"):
            self.assertFalse(C.runtime_caps(v)["heartbeat_hours_kept"], v)
        self.assertTrue(C.runtime_caps("2026.11.5-beta.1")["heartbeat_hours_kept"])

    def test_off_before_2026_11_1(self):
        bad = self.hb(start="25:00", end="08:00")
        self.assertEqual(self.codes(bad, caps=None), [])
        self.assertEqual(self.codes(bad, caps=C.runtime_caps("2026.10.10")), [])
        self.assertEqual(self.codes(bad, caps=C.runtime_caps("2026.10.4")), [])

    def test_valid_windows_pass(self):
        for active in ({"start": "08:00", "end": "22:30"}, {"start": "00:00", "end": "24:00", "timezone": "UTC"},
                       {"start": "", "end": ""}, {}, {"timezone": "Europe/Berlin"}, {"start": "23:59"}):
            with self.subTest(active=active):
                self.assertEqual(self.codes(self.hb(**active)), [])
        self.assertEqual(self.codes({"agents": {"defaults": {"heartbeat": {"every": "1h"}}}}), [])
        self.assertEqual(self.codes({}), [])
        self.assertEqual(self.codes({"agents": "x"}), [])

    def test_doctor_rules_with_exact_field_and_value(self):
        cases = [
            ({"start": "25:00"}, 'agents.defaults.heartbeat.activeHours.start="25:00" '
                                 '(invalid time (use "HH:MM" 24h format))'),
            ({"start": "8:00"}, 'activeHours.start="8:00" (invalid time (use "HH:MM" 24h format))'),
            ({"end": "24:30"}, 'activeHours.end="24:30" (invalid time (24:00 is the only allowed 24:xx value))'),
            ({"start": "24:00"}, 'activeHours.start="24:00" (invalid time (start cannot be 24:00))'),
            ({"start": "08:00\n"}, 'activeHours.start="08:00\\n"'),  # JS $ without the m flag: end of string only
            ({"start": "０８:00"}, 'activeHours.start="０８:00"'),  # JS \d is ASCII only
            ({"start": 800}, "activeHours.start=800 (expected a string)"),
            ({"from": "08:00"}, 'activeHours.from="08:00" (unknown key)'),
        ]
        for active, want in cases:
            with self.subTest(active=active):
                f = self.codes(self.hb(**active))
                self.assertEqual([(x["code"], x["cls"], x["phase"]) for x in f],
                                 [("config-heartbeat-hours", "hard", "precheck")])
                self.assertIn(want, f[0]["message"])
                self.assertIn("OpenClaw 2026.11.1 refuses", f[0]["message"])
                self.assertIn("openclaw/openclaw#186305", f[0]["message"])
                self.assertIn("then oc-upgrade retry", f[0]["message"])
        f = self.codes({"agents": {"defaults": {"heartbeat": {"activeHours": None}}}})
        self.assertIn("agents.defaults.heartbeat.activeHours=null (expected an object", f[0]["message"])
        f = self.codes({"agents": {"defaults": {"heartbeat": {"activeHours": "08:00-22:00"}}}})
        self.assertIn('agents.defaults.heartbeat.activeHours="08:00-22:00"', f[0]["message"])

    def test_agent_roster_like_read_agent_roster_property(self):
        bad = {"heartbeat": {"activeHours": {"start": "7:30", "end": "22:00"}}}
        f = self.codes({"agents": {"list": [{"id": "main"}, dict(bad, id="ops")]}})
        self.assertIn('agents.list[1].heartbeat.activeHours.start="7:30"', f[0]["message"])
        f = self.codes({"agents": {"entries": {"ops": bad}}})
        self.assertIn('agents.entries.ops.heartbeat.activeHours.start="7:30"', f[0]["message"])
        # agents.entries, when present, is the roster: agents.list is not read (readAgentRosterProperty)
        self.assertEqual(self.codes({"agents": {"entries": {"ops": {"id": "ops"}}, "list": [bad]}}), [])
        self.assertEqual(self.codes({"agents": {"entries": [bad]}}), [])  # entries must be an object
        self.assertEqual(self.codes({"agents": {"list": {"ops": bad}}}), [])  # list must be an array
        # defaults and every agent in one finding
        f = self.codes({"agents": {"defaults": {"heartbeat": {"activeHours": {"end": "25:00"}}},
                                   "list": [dict(bad, id="a"), dict(bad, id="b")]}})
        self.assertEqual(len(f), 1)
        for path in ("agents.defaults.heartbeat.activeHours.end", "agents.list[0].heartbeat.activeHours.start",
                     "agents.list[1].heartbeat.activeHours.start"):
            self.assertIn(path, f[0]["message"])

    def test_advice(self):
        self.assertIn("config-heartbeat-hours", G.ADVICE)
        self.assertNotIn("config-heartbeat-hours", G.ACCEPTABLE)
        self.assertNotIn("--accept", G.advice_for(["config-heartbeat-hours"]))


class DoctorBlockedTests(unittest.TestCase):
    def test_blocked_is_its_own_code_with_the_findings(self):
        text = blocked_text(
            ("core/doctor/final-config-validation", "agents.defaults.heartbeat.activeHours.start",
             'invalid time (use "HH:MM" 24h format)', FIX_CONFIG),
            ("core/doctor/plugin-state-migration", "", "Required migration plugin-state-migration was deferred.",
             "  fix: Resolve the reported blocker, then rerun `openclaw doctor --fix` before restarting the Gateway."),
            before=["◇  Doctor warnings ──────╮", KEPT_WARNING, "├──────╯"])
        ev = G.evaluate_doctor(1, text)
        self.assertEqual((ev["code"], ev["cls"]), ("doctor-blocked", "hard"))
        self.assertEqual(ev["message"],
                         'doctor rc 1: doctor blocked, required repairs remain incomplete: '
                         'agents.defaults.heartbeat.activeHours.start: invalid time (use "HH:MM" 24h format); '
                         'core/doctor/plugin-state-migration: Required migration plugin-state-migration was deferred.')
        self.assertNotIn("fix:", ev["message"])
        self.assertIn("doctor-blocked", G.ADVICE)
        self.assertNotIn("doctor-blocked", G.ACCEPTABLE)
        self.assertIn("oc-upgrade retry", G.advice_for(["doctor-blocked"]))

    def test_blocked_wins_over_held_back_and_schema_markers(self):
        # before: a held-store warning or a "schema migration required" finding decided the code
        for line in ("Warning: Agent deletion journal reconstructed; 1 store held back.",
                     "[error] core/doctor/agent-database-migration - agent schema migration required for ops."):
            text = blocked_text(before=[line])
            self.assertEqual(G.evaluate_doctor(1, text)["code"], "doctor-blocked", line)
        # the specific refusals keep their codes (their own advice)
        text = blocked_text(("core/doctor/final-config-validation", "plugins.installs",
                             "Config contains retired pre-July-2026 settings: plugins.installs.", FIX_CONFIG))
        self.assertEqual(G.evaluate_doctor(1, text)["code"], "doctor-retired-format")

    def test_many_findings_are_capped_and_redacted(self):
        findings = [("core/doctor/final-config-validation", f"channels.x{i}.botToken",
                     "token 123456789:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA is invalid", FIX_CONFIG) for i in range(7)]
        ev = G.evaluate_doctor(1, blocked_text(*findings))
        self.assertEqual(ev["code"], "doctor-blocked")
        self.assertIn("(+2 more in oc-upgrade log)", ev["message"])
        self.assertNotIn("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ev["message"])
        # no parseable finding: the text around the marker
        ev = G.evaluate_doctor(1, BLOCKED_OUTRO + "\n")
        self.assertEqual(ev["code"], "doctor-blocked")
        self.assertIn("Doctor blocked; required repairs remain incomplete", ev["message"])

    def test_rc0_and_older_doctor_texts_unchanged(self):
        # only a failing doctor is classified by markers (2026.11.1 exits 1 when blocked)
        self.assertIsNone(G.evaluate_doctor(0, "Doctor complete.\n")["code"])
        # 2026.10.4/2026.10.10 print no "Doctor blocked": their texts keep their codes
        self.assertEqual(G.evaluate_doctor(1, "Invalid config:\n- agents.defaults.x: bad")["code"], "doctor-failed")
        self.assertEqual(G.evaluate_doctor(1, "2 agent database(s) held back")["code"], "doctor-held-back")


class Gate1111Tests(T.GateEnv):
    BAD = {"heartbeat": {"every": "30m", "activeHours": {"start": "25:00", "end": "08:00"}}}

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state)
        self.cfg = {"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local"},
                    "agents": {"defaults": self.BAD, "list": [{"id": "main", "default": True}]}}
        self.write_cfg(self.cfg)
        (self.upg / "gate").mkdir(parents=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.11.1", 22, 27)
        self.hooks()

    def state_uv(self):
        return C.user_version(self.state / "state" / "openclaw.sqlite")

    def test_invalid_heartbeat_window_holds_in_precheck_on_1111(self):
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["codes"], j["phase"]), (["config-heartbeat-hours"], "precheck"))
        self.assertFalse(j.get("first_write_at"))
        self.assertEqual(self.state_uv(), 20, "nothing migrated")
        hold = (self.upg / "hold.txt").read_text()
        self.assertIn('agents.defaults.heartbeat.activeHours.start="25:00" (invalid time (use "HH:MM" 24h format))',
                      hold)
        self.assertIn("OpenClaw 2026.11.1 refuses", hold)
        self.assertNotIn("--accept config-heartbeat-hours", hold)
        self.assertEqual(json.loads((self.state / "openclaw.json").read_text()), self.cfg, "the gate never fixes it")
        # the dry run and oc-upgrade check name it too
        lines = []
        self.assertEqual(G.dry_run(emit=lines.append), 20)
        self.assertIn("config-heartbeat-hours", "\n".join(lines))
        # fixed by hand: the next run passes
        cfg = json.loads(json.dumps(self.cfg))
        cfg["agents"]["defaults"]["heartbeat"]["activeHours"]["start"] = "07:00"
        self.write_cfg(cfg)
        self.assertEqual(G.retry_cmd([], emit=lambda s: None), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual(self.state_uv(), 22)

    def test_no_hold_before_2026_11_1(self):
        # 2026.10.10 doctor removes the invalid window itself (unrestricted hours afterwards)
        self.set_runtime("2026.10.10", 22, 27)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("config-heartbeat-hours", self.out)

    def test_no_hold_on_the_1004_target(self):
        shutil.rmtree(self.state / "state")
        shutil.rmtree(self.state / "agents")
        T.make_1004_state(self.state, s=19, a=24, app="2026.9.9")
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.9", "mode": "from-7x"}))
        self.set_runtime("2026.10.4", 20, 24)
        self.write_cfg(dict(self.cfg, meta={"lastTouchedVersion": "2026.9.9"}))
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("config-heartbeat-hours", self.out)

    def test_blocked_doctor_holds_with_its_findings(self):
        self.write_cfg(dict(self.cfg, agents={"list": [{"id": "main", "default": True}]}))
        blocked = blocked_text(("core/doctor/final-config-validation", "channels.telegram.streaming",
                                "Invalid option: expected one of off|partial|block", FIX_CONFIG),
                               before=["Warning: 1 store held back."]).splitlines()
        self.doctor_script(box=False, rc=1, state_uv=22, agent_uv=27, app_version="2026.11.1", print=blocked)
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["phase"]), ("doctor-blocked", "doctor1"))
        hold = (self.upg / "hold.txt").read_text()
        self.assertIn("doctor blocked, required repairs remain incomplete: channels.telegram.streaming: Invalid "
                      "option: expected one of off|partial|block", hold)
        self.assertIn(G.ADVICE["doctor-blocked"], hold)


class Docs1111Tests(unittest.TestCase):
    """The texts say what the image bundles (Dockerfile ARG OPENCLAW_VERSION), not the 2026.10.10 stand-in."""

    REPO = ADDON.parent

    def dockerfile_arg(self, name):
        for line in (ADDON / "Dockerfile").read_text().splitlines():
            if line.startswith(f"ARG {name}="):
                return line.split("=", 1)[1]
        self.fail(f"Dockerfile has no ARG {name}")

    def test_pins_and_texts_name_the_bundled_version(self):
        version = self.dockerfile_arg("OPENCLAW_VERSION")
        self.assertEqual(version, "2026.11.1")
        # after openclaw@2026.11.1 (npm, 2026-11-05T09:41:26Z), the last package the image resolves with this cutoff
        self.assertGreater(self.dockerfile_arg("NPM_BEFORE"), "2026-11-05T09:41:26Z")
        self.assertLess(self.dockerfile_arg("NPM_BEFORE"), "2026-11-05T10:00:00Z")
        docs = (self.REPO / "DOCS.md").read_text(encoding="utf-8")
        self.assertIn(f"This fork now ships **OpenClaw `{version}`**", docs)
        log = (ADDON / "CHANGELOG.md").read_text(encoding="utf-8")
        unreleased = log.split("## [Unreleased]", 1)[1].split("\n## [", 1)[0]
        self.assertIn(f"**The image now bundles OpenClaw `{version}`**", unreleased)
        for rel, body in (("DOCS.md", docs), ("CHANGELOG.md [Unreleased]", unreleased),
                          ("SECURITY.md", (self.REPO / "SECURITY.md").read_text(encoding="utf-8")),
                          ("Dockerfile", (ADDON / "Dockerfile").read_text())):
            for stale in ("still ships OpenClaw", "2026.11.1 candidate", "not on npm yet", "preparation for OpenClaw",
                          "Next OpenClaw line (in preparation)"):
                with self.subTest(file=rel, phrase=stale):
                    self.assertNotIn(stale, body)


if __name__ == "__main__":
    unittest.main()
