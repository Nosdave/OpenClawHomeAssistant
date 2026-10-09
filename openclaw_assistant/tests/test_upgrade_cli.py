"""CLI tests for oc_upgrade.py (subprocess; the shell <-> Python contract §6)."""

import json
import os
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

import test_gate as T  # noqa: E402  (shared fixture builders: fake node, fake doctor, synthetic states)

SCRIPT = ADDON / "oc_upgrade.py"


class CliEnv(T.GateEnv):
    def setUp(self):
        super().setUp()
        self.pylib = self.tmp / "pylib"
        self.pylib.mkdir()
        os.environ["OC_ADDON_PYLIB"] = str(self.pylib)

    def cli(self, *args, env=None):
        e = dict(os.environ)
        e["PYTHONDONTWRITEBYTECODE"] = "1"
        e.update(env or {})
        p = subprocess.run([sys.executable, "-B", str(SCRIPT), *args], capture_output=True, text=True, env=e,
                           timeout=300)
        self.stdout, self.stderr = p.stdout, p.stderr
        return p.returncode


class GateCliTests(CliEnv):
    def test_help_and_unknown(self):
        self.assertEqual(self.cli("--help"), 0)
        self.assertIn("retry [--doctor]", self.stdout)
        self.assertEqual(self.cli("bogus"), 1)
        self.assertEqual(self.cli("gate", "--bogus"), 2)

    def test_gate_refuses_without_runsh(self):
        self.assertEqual(self.cli("gate"), 2)
        self.assertIn("oc-upgrade retry", self.stdout)

    def test_plan_fresh_and_735(self):
        self.assertEqual(self.cli("gate", "--plan"), 0)
        self.assertTrue(self.stdout.startswith("[gate] plan: fresh install"))
        self.build_735()
        self.assertEqual(self.cli("gate", "--plan"), 10, self.stdout + self.stderr)
        plan_lines = [x for x in self.stdout.splitlines() if x.startswith("[gate] plan:")]
        self.assertEqual(len(plan_lines), 1)
        self.assertIn("mode=from-7x", plan_lines[0])
        others = [x for x in self.stdout.splitlines() if not x.startswith("[gate] plan:")]
        self.assertTrue(all(x.startswith("WARN [gate] ") for x in others), others)

    def test_plan_newer_is_3(self):
        T.make_99_state(self.state, s=25)
        self.write_cfg({})
        self.assertEqual(self.cli("gate", "--plan"), 3)

    def test_full_gate_via_cli_then_plan_0(self):
        self.build_735()
        self.hooks()
        rc = self.cli("gate", env={"OC_GATE_FROM_RUNSH": "1"})
        self.assertEqual(rc, 0, self.stdout[-3000:] + self.stderr[-2000:])
        self.assertIn("[gate] done: MIGRATED 2026.9.9", self.stdout)
        bad = [x for x in self.stdout.splitlines()
               if not (x.startswith("[gate] ") or x.startswith("WARN [gate] ") or x.startswith("[doctor] "))]
        self.assertEqual(bad, [])
        self.assertNotIn("SECRET", self.stdout + self.stderr)
        self.assertEqual(self.cli("gate", "--plan"), 0)
        self.assertEqual(self.cli("status"), 0)
        self.assertIn("Migrated marker: 2026.9.9 (from-7x", self.stdout)
        self.assertEqual(self.cli("log", "--pass", "1", "--lines", "5"), 0)
        self.assertIn("Doctor complete.", self.stdout)
        self.assertEqual(self.cli("retry"), 1)  # nothing to retry
        self.assertEqual(self.cli("retry", "--doctor"), 0)  # maintenance request
        self.assertEqual(self.cli("gate", "--plan"), 10)
        self.assertIn("mode=maintenance", self.stdout)
        self.assertEqual(self.cli("retry", "--cancel"), 0)

    def test_hold_exit78_and_crash_loop_always_0(self):
        T.make_99_state(self.state)
        self.write_cfg({"meta": {"lastTouchedVersion": T.RUNTIME}})
        self.assertEqual(self.cli("gate", "--hold-exit78"), 0, self.stderr)
        self.assertIn("[gate] HOLD exit78 in gateway:", self.stdout)
        self.assertTrue((self.upg / "hold.txt").exists())
        self.assertEqual(self.cli("gate", "--plan"), 11)
        self.assertEqual(self.cli("retry"), 0)
        self.assertEqual(self.cli("gate", "--plan"), 10)  # bookkeeping: the gate clears the hold
        self.assertIn("housekeeping", self.stdout)
        self.assertEqual(self.cli("gate", env={"OC_GATE_FROM_RUNSH": "1"}), 0, self.stdout)
        self.assertEqual(self.cli("gate", "--plan"), 0)
        self.assertEqual(self.cli("gate", "--hold-crash-loop", "7"), 0)
        self.assertEqual(json.loads((self.upg / "gate" / "journal.json").read_text())["hold"]["last_rc"], 7)
        # even a broken environment never makes the hold helpers fail
        self.assertEqual(self.cli("gate", "--hold-exit78", env={"OC_ADDON_ENTRY_FILE": "/nonexistent"}), 0)

    def test_dry_run(self):
        self.build_735()
        self.hooks()
        rc = self.cli("gate", "--dry-run")
        self.assertIn(rc, (0, 20), self.stdout + self.stderr)
        self.assertIn("a gate would run in mode from-7x", self.stdout)
        self.assertFalse((self.upg / "gate" / "journal.json").exists())

    def test_B11_broken_gate_module(self):
        (self.pylib / "oc_gate.py").write_text("raise ImportError('broken image')\n")
        T.make_99_state(self.state)
        self.write_cfg({})
        self.assertEqual(self.cli("gate", "--plan"), 1)
        self.assertIn("[gate] plan: error", self.stdout)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": T.RUNTIME, "mode": "from-7x"}))
        self.assertEqual(self.cli("gate", "--plan"), 0)
        self.assertIn("WARN [gate] migration gate unavailable", self.stdout)
        self.assertEqual(self.cli("gate", env={"OC_GATE_FROM_RUNSH": "1"}), 1)
        self.assertTrue((self.upg / "hold.txt").exists())


class StateGuardCheckTests(CliEnv):
    def test_state_guard_9x(self):
        T.make_735_state(self.state)
        self.write_cfg(T.CFG_735)
        env = {"OPENCLAW_RUNTIME_VERSION": T.RUNTIME}
        self.assertEqual(self.cli("state-guard", env=env), 0, self.stdout)
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute("PRAGMA user_version=25")
        con.commit()
        con.close()
        self.assertEqual(self.cli("state-guard", env=env), 3)
        self.assertIn("state schema 25 > 19", self.stdout)

    def test_state_guard_9x_fails_closed_without_targets(self):
        T.make_99_state(self.state)
        self.write_cfg({})
        pkg = Path((self.tmp / "entry").read_text().strip()).parent / "package.json"
        pkg.write_text(json.dumps({"version": T.RUNTIME}))
        self.assertEqual(self.cli("state-guard", env={"OPENCLAW_RUNTIME_VERSION": T.RUNTIME}), 3)

    def test_state_guard_7x_unchanged(self):
        T.make_99_state(self.state)
        self.write_cfg({"meta": {"lastTouchedVersion": T.RUNTIME}})
        self.assertEqual(self.cli("state-guard", env={"OPENCLAW_RUNTIME_VERSION": "2026.7.35"}), 3)
        self.assertIn("only understands 1", self.stdout)

    def test_check_sections(self):
        self.build_735()
        (self.state / "telegram").mkdir()
        (self.state / "telegram" / "sticker-cache.json").write_text("{}")
        rc = self.cli("check", env={"OPENCLAW_RUNTIME_VERSION": T.RUNTIME})
        self.assertIn(rc, (0, 4), self.stdout + self.stderr)
        for s in ("== A Versions", "bundled OpenClaw schema targets: state 19, agent 24", "predicate: gate",
                  "== C Legacy Telegram", "telegram/sticker-cache.json", "== F Model wildcards",
                  "== I Migration gate readiness", "== Result"):
            self.assertIn(s, self.stdout)
        self.assertNotIn("SECRET", self.stdout)


if __name__ == "__main__":
    unittest.main()
