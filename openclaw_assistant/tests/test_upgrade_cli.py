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

    def test_check_c2_lists_retired_runtime_files_for_1010(self):
        """full5: C2 shows the 2026.10.5+ retired runtime files (with the proof) only for such a runtime."""
        T.make_1004_state(self.state)
        self.write_cfg({"meta": {"lastTouchedVersion": "2026.10.4"},
                        "models": {"providers": {"p": {"api": "openai-codex-responses"}}}})
        (self.state / "acp").mkdir()
        (self.state / "acp" / "event-ledger.json").write_text('{"version": 1, "sessions": {"s": {}}}')
        (self.state / "sandbox" / "browsers").mkdir(parents=True)
        self.set_runtime("2026.10.10", 22, 27)
        rc = self.cli("check", env={"OPENCLAW_RUNTIME_VERSION": "2026.10.10"})
        self.assertIn(rc, (0, 4), self.stdout + self.stderr)
        c2 = self.stdout.split("== C2 ", 1)[1].split("\n== ", 1)[0]
        self.assertIn("acp/event-ledger.json (", c2)
        self.assertIn("acp-replay-ledger: leave", c2)
        self.assertIn("ACCEPTABLE acp-ledger-unimported", c2)
        self.assertIn("sandbox/browsers (", c2)
        self.assertIn("sandbox-registry: quarantine", c2)
        self.assertIn("(proof: nothing to import)", c2)
        self.assertIn("openclaw.json models.providers.p.api: retired setting", c2)
        self.set_runtime("2026.10.4", 20, 24)
        self.cli("check", env={"OPENCLAW_RUNTIME_VERSION": "2026.10.4"})
        c2 = self.stdout.split("== C2 ", 1)[1].split("\n== ", 1)[0]
        for s in ("acp/event-ledger.json", "sandbox/browsers", "models.providers.p.api"):
            self.assertNotIn(s, c2)

    def test_check_wildcard_note_only_for_legacy_codex_wildcards(self):
        # live box: canonical wildcards only -> no "expanded" note (they stay as they are)
        self.build_735()
        cfg = json.loads((self.state / "openclaw.json").read_text())
        models = cfg["agents"]["defaults"]["models"]
        models.pop("openai-codex/*")
        models.update({"ollama/*": {}, "anthropic/*": {}, "openai/*": {}})
        self.write_cfg(cfg)
        self.cli("check", env={"OPENCLAW_RUNTIME_VERSION": T.RUNTIME})
        self.assertIn("openai/*", self.stdout)
        self.assertNotIn("wildcards are expanded", self.stdout)
        cfg["agents"]["defaults"]["models"]["openai-codex/*"] = {}
        self.write_cfg(cfg)
        self.cli("check", env={"OPENCLAW_RUNTIME_VERSION": T.RUNTIME})
        self.assertIn("openai-codex/* wildcards are expanded", self.stdout)


    def test_check_glm_preview(self):
        self.build_735()
        cfg = json.loads((self.state / "openclaw.json").read_text())
        cfg["models"]["providers"]["glm"] = {"api": "openai-completions", "baseUrl": "http://192.0.2.10:8888/v1",
                                             "models": [{"id": "GLM-5.3-Flash-EXL3", "reasoning": True,
                                                         "compat": {"thinkingFormat": "qwen-chat-template"}}]}
        self.write_cfg(cfg)
        opts = self.tmp / "options.json"
        opts.write_text(json.dumps({"glm_thinking_levels": True}))
        env = {"OPENCLAW_RUNTIME_VERSION": T.RUNTIME, "OC_ADDON_OPTIONS_FILE": str(opts)}
        self.cli("check", env=env)
        self.assertIn("GLM thinking levels (option glm_thinking_levels on): glm/GLM-5.3-Flash-EXL3 would send "
                      "the level as reasoning_effort", self.stdout)
        opts.write_text(json.dumps({"glm_thinking_levels": False}))
        self.cli("check", env=env)
        self.assertIn("(option glm_thinking_levels off): glm/GLM-5.3-Flash-EXL3 only switch thinking on/off",
                      self.stdout)


# --- 0.5.94-full2/full3: cleanup / status (the rehearsal export is gone since full3) ------------------

import fcntl  # noqa: E402
import signal  # noqa: E402
import time  # noqa: E402
import uuid  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

RC_ERROR = 1  # oc_upgrade.RC_ERROR (oc_upgrade is not imported here: its import rewrites sys.path)
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# Values the removed archive options of an earlier add-on version can leave in options.json (fakes, no real key)
FAKE_RECIPIENT = "age1" + (BECH32 * 2)[:58]
FAKE_SECRET_KEY = "AGE-SECRET-KEY-1" + (BECH32.upper() * 2)[:58]
FAKE_SECRET_BODY = FAKE_SECRET_KEY[len("AGE-SECRET-KEY-1"):]


class Full2CliTests(CliEnv):
    def setUp(self):
        super().setUp()
        self.archives = self.share / "openclaw-upgrade"
        # OpenClaw's doctor capture root, next to the state dir (inside self.tmp, removed by GateEnv.tearDown)
        self.caproot = Path(os.path.realpath(str(self.state)) + ".update-captures")

    # helpers
    def set_options(self, opts):
        (self.tmp / "options.json").write_text(json.dumps(opts))

    def share_files(self):
        return sorted(str(p.relative_to(self.share)) for p in self.share.rglob("*"))

    def files_containing(self, needle, skip=()):
        hits = []
        for p in self.tmp.rglob("*"):
            if p.is_file() and not p.is_symlink() and p not in skip:
                try:
                    if needle.encode() in p.read_bytes():
                        hits.append(str(p))
                except OSError:
                    pass
        return hits

    def tree(self, *roots):
        """{path: (mode, bytes or link target)} below roots, by lstat: what a command must not touch."""
        snap = {}
        for root in roots:
            for p in [root, *root.rglob("*")]:
                st = os.lstat(p)
                data = os.readlink(p) if p.is_symlink() else (p.read_bytes() if p.is_file() else None)
                snap[str(p)] = (st.st_mode, data)
        return snap

    def finished_run(self, hours_ago, captures=1):
        """A gate run that finished `hours_ago` hours ago, with the (encrypted-looking) archive dir an earlier
        add-on version wrote to /share and `captures` doctor capture dirs named in its doctor log."""
        fin = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        rid = fin.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6]
        rdir = self.upg / "gate" / "runs" / rid
        rdir.mkdir(parents=True)
        (rdir / "journal.json").write_text(json.dumps({"run_id": rid, "mode": "from-7x", "status": "done",
                                                       "finished_at": fin.isoformat()}))
        adir = self.archives / rid
        adir.mkdir(parents=True)
        (adir / f"openclaw-state-{rid[:15]}-before-{T.RUNTIME}.tar.gz.age").write_bytes(
            b"age-encryption.org/v1\n" + os.urandom(2048))
        (adir / "SHA256SUMS").write_text("0" * 64 + "  archive\n")
        caps, lines = [], []
        for _ in range(captures):
            c = self.caproot / f"doctor-{uuid.uuid4()}"
            c.mkdir(parents=True)
            (c / "manifest.json").write_text("{}")
            (c / "openclaw.sqlite").write_bytes(b"\0" * 4096)
            caps.append(c)
            lines.append(f"\x1b[2m│\x1b[0m  Pre-repair state retained for manual recovery at {c}/manifest.json.")
        (rdir / "doctor-pass1.log").write_text("┌  OpenClaw doctor\n" + "\n".join(lines) + "\nDoctor complete.\n")
        return rid, adir, caps

    @staticmethod
    def age_back(path, hours):
        t = time.time() - hours * 3600
        os.utime(path, (t, t))

    # help
    def test_help_lists_cleanup(self):
        for arg in ("help", "--help", "-h"):
            with self.subTest(arg=arg):
                self.assertEqual(self.cli(arg), 0)
                self.assertIn("cleanup [--apply]", self.stdout)
                self.assertIn("gate_cleanup_hours", self.stdout)
                self.assertIn("checked Home Assistant backup", self.stdout)
                self.assertNotRegex(self.stdout, r"(?m)^  export")  # no export command since 0.5.94-full3
                self.assertNotRegex(self.stdout, r"(?i)\bage\b")  # nothing is age-encrypted any more
        self.assertEqual(self.cli(), 1)
        self.assertIn("cleanup [--apply]", self.stdout)

    # 0.5.94-full3: the rehearsal export is gone. `export` (incl. --cancel) and run.sh's former internal
    # `export-write` are unknown commands like any other: help text, the same rc, nothing written or removed.
    def test_export_commands_are_unknown_now(self):
        self.set_options({"gate_cleanup_hours": 48})
        req = self.upg / "export-request"  # a request of an earlier add-on version (run.sh removes it)
        req.write_text("2026-10-18T12:00:00+00:00\n")
        leftover = self.share / "openclaw-rehearsal" / "20261018-120000-AbC123" / "openclaw-rehearsal.tar.gz.age.tmp"
        leftover.parent.mkdir(parents=True)
        leftover.write_bytes(b"age-encryption.org/v1\n")
        self.assertEqual(self.cli("bogus"), RC_ERROR)
        unknown_out, unknown_err = self.stdout, self.stderr
        self.assertIn("cleanup [--apply]", unknown_out)
        before = self.tree(self.upg, self.share)
        for args in (("export",), ("export", "--cancel"), ("export-write", "--sweep"),
                     ("export-write", "--begin", "20261019-120000"), ("export-write", "--abort", "x")):
            for env in (None, {"OC_GATE_FROM_RUNSH": "1"}):
                with self.subTest(args=args, env=env):
                    self.assertEqual(self.cli(*args, env=env), RC_ERROR, self.stdout + self.stderr)
                    self.assertEqual((self.stdout, self.stderr), (unknown_out, unknown_err))
                    self.assertEqual(self.tree(self.upg, self.share), before)
        self.assertTrue(req.exists() and leftover.exists())  # untouched: run.sh / cleanup remove them
        self.assertFalse((self.share / "openclaw-upgrade").exists())
        self.assertEqual(self.cli("status"), 0, self.stderr)
        self.assertNotIn("Export requested", self.stdout)
        self.assertNotIn("oc-upgrade export", self.stdout)

    # cleanup
    def test_cleanup_dry_run_on_an_empty_tree(self):
        self.assertEqual(self.cli("cleanup"), 0, self.stdout + self.stderr)
        self.assertEqual(self.stdout.splitlines(), ["gate_cleanup_hours=48"])
        self.assertEqual(self.stderr, "")
        self.assertEqual(self.share_files(), [])
        self.assertFalse((self.upg / "hold.txt").exists())
        self.assertEqual(self.cli("cleanup", "--apply"), 0, self.stdout + self.stderr)
        self.assertIn("deleted 0 item(s)", self.stdout)
        self.assertEqual(self.share_files(), [])
        self.options(gate_cleanup_hours=0)
        self.assertEqual(self.cli("cleanup"), 0)
        self.assertEqual(self.stdout.splitlines()[0], "gate_cleanup_hours=0 (automatic deletion off)")
        self.assertEqual(self.cli("cleanup", "--apply"), 0)
        self.assertIn("nothing is deleted automatically", self.stdout)

    def test_cleanup_usage_errors(self):
        for args in (("cleanup", "--bogus"), ("cleanup", "--apply", "--loop"), ("cleanup", "--now"),
                     ("cleanup", "apply")):
            with self.subTest(args=args):
                self.assertEqual(self.cli(*args), 2)
                self.assertIn("usage: oc-upgrade cleanup [--apply]", self.stdout)

    def test_cleanup_loop_is_refused_without_runsh(self):
        rid, adir, caps = self.finished_run(72)
        for env in (None, {"OC_GATE_FROM_RUNSH": "0"}, {"OC_GATE_FROM_RUNSH": "yes"}):
            with self.subTest(env=env):
                t0 = time.monotonic()
                self.assertEqual(self.cli("cleanup", "--loop", env=env), 2)
                self.assertLess(time.monotonic() - t0, 60)
                self.assertIn("oc-upgrade cleanup --loop is started by the add-on itself", self.stdout)
        self.assertTrue(adir.exists())
        self.assertTrue(caps[0].exists())

    def test_cleanup_loop_with_cleanup_off_idles_until_sigterm(self):
        rid, adir, caps = self.finished_run(72)
        self.options(gate_cleanup_hours=0)
        self.hooks(cleanup_interval_s=0.2)
        e = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", OC_GATE_FROM_RUNSH="1")
        p = subprocess.Popen([sys.executable, "-B", str(SCRIPT), "cleanup", "--loop"], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, env=e)
        try:
            time.sleep(1.5)
            self.assertIsNone(p.poll(), "the cleanup loop exited although run.sh tracks it until shutdown")
            p.send_signal(signal.SIGTERM)
            out, _ = p.communicate(timeout=60)
        finally:
            if p.poll() is None:
                p.kill()
                p.communicate()
        self.assertEqual(p.returncode, 143, out)
        self.assertIn("gate_cleanup_hours=0: automatic deletion is off", out)
        self.assertTrue(adir.exists())
        self.assertTrue(caps[0].exists())

    def test_cleanup_lists_then_apply_deletes_only_what_is_due(self):
        old_rid, old_adir, old_caps = self.finished_run(72, captures=2)
        new_rid, new_adir, new_caps = self.finished_run(1)
        unrelated = self.caproot / f"doctor-{uuid.uuid4()}"  # not named in any gate run's doctor log
        unrelated.mkdir()
        self.assertEqual(self.cli("cleanup"), 0, self.stdout + self.stderr)
        self.assertIn(f"  run {old_rid}: due now", self.stdout)
        for p in [old_adir, *old_caps, new_adir, *new_caps]:
            self.assertIn(f"    {p} (", self.stdout)
        self.assertRegex(self.stdout, rf"  run {new_rid}: due \d{{4}}-\d\d-\d\dT")
        self.assertNotIn(str(unrelated), self.stdout)
        for p in [old_adir, *old_caps, new_adir, *new_caps, unrelated]:
            self.assertTrue(p.exists(), f"dry run deleted {p}")
        self.assertFalse((self.upg / "gate" / "runs" / old_rid / "cleanup.json").exists())

        self.assertEqual(self.cli("cleanup", "--apply"), 0, self.stdout + self.stderr)
        self.assertIn(f"[cleanup] run {old_rid}: deleted 3 item(s)", self.stdout)
        self.assertIn("deleted 3 item(s)", self.stdout.splitlines()[-1])
        for p in [old_adir, *old_caps]:
            self.assertFalse(os.path.lexists(p), f"{p} survived --apply")
        for p in [new_adir, *new_caps, unrelated, self.caproot, self.archives]:
            self.assertTrue(p.exists(), f"{p} was deleted although not due / not a target")
        leftovers = [str(p) for p in list(self.share.rglob("*")) + list(self.caproot.iterdir())
                     if ".oc-addon-deleting-" in p.name]
        self.assertEqual(leftovers, [])
        rec = json.loads((self.upg / "gate" / "runs" / old_rid / "cleanup.json").read_text())
        self.assertTrue(rec.get("deleted_at"))
        self.assertEqual(sorted(d["path"] for d in rec["deleted"]), sorted(str(p) for p in [old_adir, *old_caps]))
        new_rec = json.loads((self.upg / "gate" / "runs" / new_rid / "cleanup.json").read_text())
        self.assertTrue(new_rec.get("due_at"))
        self.assertIsNone(new_rec.get("deleted_at"))

        self.assertEqual(self.cli("cleanup", "--apply"), 0)
        self.assertIn("deleted 0 item(s)", self.stdout)
        self.assertEqual(self.cli("cleanup"), 0)
        self.assertIn(f"  run {old_rid}: nothing left", self.stdout)

    def test_cleanup_waits_during_hold_retry_held_run_and_gate_lock(self):
        rid, adir, caps = self.finished_run(72)
        gate = self.upg / "gate"

        def assert_refused(why):
            self.assertEqual(self.cli("cleanup"), 0)
            self.assertIn(f"; paused: {why}", self.stdout.splitlines()[0])
            self.assertEqual(self.cli("cleanup", "--apply"), 1, self.stdout)
            self.assertIn(f"not deleting now: {why}", self.stdout)
            self.assertTrue(adir.exists())
            self.assertTrue(caps[0].exists())

        hold = self.upg / "hold.txt"
        hold.write_text("OpenClaw is held\n")
        assert_refused("hold")
        hold.unlink()
        (gate / "retry-request.json").write_text(json.dumps({"doctor": False}))
        assert_refused("a retry request is pending")
        (gate / "retry-request.json").unlink()
        (gate / "journal.json").write_text(json.dumps({"run_id": "20261018T000000Z-aaaaaa", "status": "hold"}))
        assert_refused("gate run 20261018T000000Z-aaaaaa is hold")
        (gate / "journal.json").unlink()
        fd = os.open(str(gate / ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            assert_refused("the gate is running")
        finally:
            os.close(fd)
        self.assertEqual(self.cli("cleanup", "--apply"), 0, self.stdout)
        self.assertFalse(adir.exists())
        self.assertFalse(caps[0].exists())

    def test_cleanup_orphans_tombstones_and_rehearsal_exports(self):
        orphan = self.archives / "20261001T120000Z-abcdef"
        fresh = self.archives / "20261018T120000Z-123456"
        other = self.archives / "not-a-run-dir"
        tomb = self.archives / ".oc-addon-deleting-20261001T000000Z-000000"
        for d in (orphan, fresh, other, tomb):
            d.mkdir(parents=True)
            (d / "openclaw-state-x.tar.gz.age").write_bytes(b"age-encryption.org/v1\n")
        for d in (orphan, other, tomb):
            self.age_back(d, 72)
        reh = self.share / "openclaw-rehearsal"
        plain = reh / "20261001-120000" / "openclaw-rehearsal.tar.gz"
        enc = reh / "20261002-120000" / "openclaw-rehearsal.tar.gz.age"
        for f in (plain, enc):
            f.parent.mkdir(parents=True)
            f.write_bytes(b"\x1f\x8b" + b"\0" * 64 if f is plain else b"age-encryption.org/v1\n")
            (f.parent / "manifest.txt").write_text("rehearsal\n")
            self.age_back(f, 72)

        self.assertEqual(self.cli("status"), 0)
        self.assertIn(f"  {plain} (66 B, PLAINTEXT; deleted automatically, see oc-upgrade cleanup)\n", self.stdout)
        self.assertIn(f"  {enc} (22 B, encrypted; deleted automatically, see oc-upgrade cleanup)\n", self.stdout)

        self.assertEqual(self.cli("cleanup"), 0, self.stdout + self.stderr)
        self.assertIn(f"  orphaned archive {orphan.name}: due now", self.stdout)
        self.assertIn(f"  leftover {tomb.name}: due now", self.stdout)
        self.assertIn("  plaintext rehearsal export 20261001-120000: due now", self.stdout)
        self.assertRegex(self.stdout, rf"  orphaned archive {fresh.name}: due \d{{4}}-")
        self.assertNotIn("not-a-run-dir", self.stdout)
        self.assertIn("  encrypted rehearsal export 20261002-120000: due now", self.stdout)  # deleted as well
        self.assertTrue(orphan.exists() and plain.exists() and tomb.exists() and enc.exists())

        self.assertEqual(self.cli("cleanup", "--apply"), 0, self.stdout + self.stderr)
        self.assertFalse(orphan.exists())
        self.assertFalse(tomb.exists())
        self.assertFalse(plain.parent.exists())
        self.assertFalse(enc.parent.exists())
        for p in (fresh, other):
            self.assertTrue(p.exists(), f"{p} was deleted")
        self.assertEqual([p.name for p in self.archives.iterdir() if p.name.startswith(".oc-addon-deleting-")], [])
        self.assertEqual(self.cli("status"), 0)
        self.assertIn("Rehearsal exports (earlier add-on versions):\n  none\n", self.stdout)
        self.assertNotIn(str(plain), self.stdout)
        self.assertNotIn(str(enc), self.stdout)

    # Regression: listings use lstat only. A link another add-on planted in /share whose target cannot even be
    # resolved (stat: ENAMETOOLONG) neither breaks `oc-upgrade status` / `cleanup` nor hides the real entries.
    def test_status_and_cleanup_survive_links_with_over_long_targets(self):
        long_target = "x" * 300
        rid, adir, caps = self.finished_run(1)
        reh = self.share / "openclaw-rehearsal"
        exp = reh / "20261001-120000-AbC123" / "openclaw-rehearsal.tar.gz.age"
        exp.parent.mkdir(parents=True)
        exp.write_bytes(b"age-encryption.org/v1\n")
        stage_a = self.state / "upgrade-backups"
        stage_a.mkdir()
        links = [self.archives / "20260901T000000Z-0bad0f", self.archives / "long-link",
                 adir / "openclaw-state-20260901-000000-before-2026.9.9.tar.gz",
                 reh / "20260901-000000-LnkLnk", reh / "long-link", exp.parent / "openclaw-rehearsal.tar.gz.age.tmp",
                 stage_a / "openclaw-state-20260101-120000-before-2026.7.35.tar.gz"]
        for link in links:
            os.symlink(long_target, link)
        self.assertEqual(self.cli("status"), 0, self.stdout + self.stderr)
        self.assertEqual(self.stderr, "")
        self.assertNotIn("n/a (", self.stdout)  # the gate section (status_lines) did not fail either
        self.assertIn("Pre-upgrade archives (local, Stage A, 7.x only):\n  none\n", self.stdout)
        self.assertIn(f"Rehearsal exports (earlier add-on versions):\n  {exp} (22 B, encrypted; deleted "
                      "automatically, see oc-upgrade cleanup)\nMigration gate:", self.stdout)
        # the archive an earlier add-on version wrote: listed by lstat, no checksum (SHA256SUMS is not read)
        self.assertRegex(self.stdout, rf"\n  Gate archives in /share from earlier add-on versions \(deleted "
                                      rf"automatically, see oc-upgrade cleanup\):\n    {adir}/openclaw-state-[^ ]+"
                                      r"\.tar\.gz\.age \(2\.\d KiB, encrypted\)\n")
        self.assertNotIn("sha256", self.stdout)
        for name in ("0bad0f", "long-link", "LnkLnk", ".age.tmp", "2026.7.35", "20260901-000000-before"):
            self.assertNotIn(name, self.stdout)
        self.assertEqual(self.cli("cleanup"), 0, self.stdout + self.stderr)
        self.assertIn(f"  run {rid}: due ", self.stdout)
        self.assertIn("  encrypted rehearsal export 20261001-120000-AbC123: ", self.stdout)
        self.assertNotIn("scan", self.stdout)
        for link in links:
            self.assertTrue(os.path.islink(link), link)

    def test_cleanup_loop_deletes_what_is_due_and_stops_on_sigterm(self):
        rid, adir, caps = self.finished_run(1)  # due in 47 h; the clock offset hook makes it due now
        self.hooks(cleanup_interval_s=0.3, cleanup_clock_offset_s=48 * 3600)
        e = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", OC_GATE_FROM_RUNSH="1")
        p = subprocess.Popen([sys.executable, "-B", str(SCRIPT), "cleanup", "--loop"], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, text=True, env=e)
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and (adir.exists() or caps[0].exists()):
                if p.poll() is not None:
                    break
                time.sleep(0.2)
            self.assertIsNone(p.poll(), "the cleanup loop exited on its own")
            p.send_signal(signal.SIGTERM)
            out, _ = p.communicate(timeout=60)
        finally:
            if p.poll() is None:
                p.kill()
                p.communicate()
        self.assertEqual(p.returncode, 143, out)
        self.assertIn("[cleanup] doctor captures and doctor's SQLite copies are deleted 48 h after their gate run; "
                      "gate archives and rehearsal exports of earlier add-on versions and the 2026.7 plaintext "
                      "archives the same time after their run, export or migration (checked hourly)\n", out)
        self.assertIn(f"[cleanup] run {rid}: deleted 2 item(s)", out)
        self.assertFalse(adir.exists())
        self.assertFalse(caps[0].exists())

    def test_status_labels_stage_a_archives_as_deleted_after_the_migration(self):
        stage_a = self.state / "upgrade-backups"
        stage_a.mkdir()
        f = stage_a / "openclaw-state-20260101-120000-before-2026.7.35.tar.gz"
        f.write_bytes(b"\x1f\x8b" + b"\0" * 30)
        self.assertEqual(self.cli("status"), 0, self.stderr)
        self.assertIn(f"Pre-upgrade archives (local, Stage A, 7.x only):\n  {f} (32 B, PLAINTEXT; deleted "
                      "automatically after the 2026.8+ migration, see oc-upgrade cleanup)\n", self.stdout)

    # status
    def gate_options_line(self):
        lines = [x.strip() for x in self.stdout.splitlines() if x.strip().startswith("Gate options:")]
        self.assertEqual(len(lines), 1, self.stdout)
        return lines[0]

    def test_status_shows_the_gate_options_line(self):
        self.set_options({"gate_cleanup_hours": 12, "gate_backup_max_age_hours": 72})
        self.assertEqual(self.cli("status"), 0, self.stderr)
        self.assertEqual(self.gate_options_line(),
                         "Gate options: delete doctor captures and SQLite copies 12 h after a run "
                         "(0 = never); backup max age 72 h")

        self.set_options({"gate_cleanup_hours": 0})
        self.assertEqual(self.cli("status"), 0)
        self.assertEqual(self.gate_options_line(),
                         "Gate options: delete doctor captures and SQLite copies 0 h after a run "
                         "(0 = never); backup max age 24 h")

        (self.tmp / "options.json").unlink()
        self.assertEqual(self.cli("status"), 0)
        self.assertEqual(self.gate_options_line(),
                         "Gate options: delete doctor captures and SQLite copies 48 h after a run "
                         "(0 = never); backup max age 24 h")

        self.set_options({"gate_cleanup_hours": "secret-ish-48", "gate_backup_max_age_hours": 9999})
        self.assertEqual(self.cli("status"), 0)
        self.assertEqual(self.gate_options_line(),
                         "Gate options: delete doctor captures and SQLite copies 48 h after a run "
                         "(0 = never); backup max age 24 h")
        self.assertNotIn("secret-ish", self.stdout + self.stderr)
        self.assertNotIn("9999", self.stdout + self.stderr)

        # the archive options of an earlier add-on version are not shown (they are gone)
        self.set_options({"gate_archive": "encrypted", "gate_archive_age_recipient": FAKE_RECIPIENT,
                          "gate_cleanup_hours": 12})
        self.assertEqual(self.cli("status"), 0)
        self.assertEqual(self.gate_options_line(),
                         "Gate options: delete doctor captures and SQLite copies 12 h after a run "
                         "(0 = never); backup max age 24 h")
        self.assertNotIn("gate_archive", self.stdout)
        self.assertNotIn(FAKE_RECIPIENT[:9], self.stdout)
        self.assertNotIn("Export requested", self.stdout)

    # options.json written by an earlier add-on version can still hold a private key pasted into the removed
    # gate_archive_age_recipient option: no command prints it or copies it anywhere.
    def test_a_private_key_left_in_the_options_is_never_printed(self):
        keyfile = f"# created: 2026-10-18T12:00:00Z\n# public key: {FAKE_RECIPIENT}\n{FAKE_SECRET_KEY}\n"
        opts_file = self.tmp / "options.json"
        for key in (FAKE_SECRET_KEY, f"  {FAKE_SECRET_KEY.lower()}\n", keyfile):
            with self.subTest(key=key.strip()[:18]):
                self.set_options({"gate_archive": "encrypted", "gate_archive_age_recipient": key})
                self.assertEqual(self.cli("status"), 0, self.stderr)
                self.assertEqual(self.gate_options_line(), "Gate options: delete doctor captures and SQLite copies "
                                                           "48 h after a run (0 = never); backup max age 24 h")
                out = self.stdout + self.stderr
                for args in (("cleanup",), ("cleanup", "--apply"), ("export",), ("help",)):
                    self.cli(*args)
                    out += self.stdout + self.stderr
                self.assertNotIn(FAKE_SECRET_BODY.lower(), out.lower())
                self.assertNotIn("AGE-SECRET-KEY", out.upper())  # not even redacted: nothing reads the value
                self.assertEqual(self.files_containing(FAKE_SECRET_BODY, skip=(opts_file,)), [])
                self.assertEqual(self.files_containing(FAKE_SECRET_BODY.lower(), skip=(opts_file,)), [])
                self.assertEqual(self.share_files(), [])

    def test_check_and_dry_run_name_the_backup_as_the_rollback_point(self):
        """No archive step and no archive-key HOLD any more, even with a private key left in the options of an
        earlier add-on version; the readiness names the HA backup as the only rollback point."""
        self.build_735()
        self.hooks()
        self.set_options({"gate_archive": "encrypted", "gate_archive_age_recipient": FAKE_SECRET_KEY})
        env = {"OPENCLAW_RUNTIME_VERSION": T.RUNTIME}
        rollback = "rollback point: the encrypted Home Assistant backup (no archive of the gate's own)\n"
        self.assertIn(self.cli("check", env=env), (0, 4), self.stdout + self.stderr)
        self.assertIn("\n  " + rollback, self.stdout)  # section I prints the readiness without the [gate] prefix
        out = self.stdout + self.stderr
        self.assertIn(self.cli("gate", "--dry-run", env=env), (0, 20), self.stdout + self.stderr)
        self.assertIn("a gate would run in mode from-7x", self.stdout)
        self.assertIn("\n[gate]   " + rollback, self.stdout)
        out += self.stdout + self.stderr
        for gone in ("archive-key", "archive-age", "archive-off", "gate_archive", "low-disk-share", "PRIVATE key"):
            self.assertNotIn(gone, out)
        self.assertNotIn("archive:", out)
        self.assertNotIn(FAKE_SECRET_BODY, out)
        self.assertEqual(self.files_containing(FAKE_SECRET_BODY, skip=(self.tmp / "options.json",)), [])
        self.assertEqual(self.share_files(), [])
        self.assertFalse((self.upg / "gate" / "journal.json").exists())


# --- full5: official plugins follow the OpenClaw version (oc-upgrade plugins-sync) ----------------------------------

# Fake node for `plugins list --json` / `plugins update <spec>`: the plugin entries (real shape, T.listed_plugin) live
# in $FAKE_PLUGINS and are printed inside the fixture's top level (T.plugins_list_output); every call is logged to
# $FAKE_ARGV_LOG; FAKE_UPDATE_RC / FAKE_LIST_RC make the update / the list fail; an update writes its PID to
# $FAKE_UPDATE_PIDFILE and takes $FAKE_UPDATE_SLEEP seconds. Like OpenClaw (plugins-update-selection.ts), an update
# `<package>@<version>` changes the npm install of that package (here: the entry whose rootDir is
# .../node_modules/<package>; a new generation project) and fails with rc 1 when there is none.
PLUGINS_NODE = r'''#!/usr/bin/env python3
import hashlib, json, os, re, sys, time
args = sys.argv[2:]
with open(os.environ["FAKE_ARGV_LOG"], "a") as f:
    f.write(json.dumps(args) + "\n")
with open(os.environ["FAKE_PLUGINS"]) as f:
    plugins = json.load(f)
if args[:2] == ["plugins", "list"]:
    if os.environ.get("FAKE_LIST_RC"):
        sys.stderr.write("plugin registry unreadable\n")
        sys.exit(int(os.environ["FAKE_LIST_RC"]))
    with open(os.environ["FAKE_PLUGINS_TOP"]) as f:
        top = json.load(f)
    top["plugins"] = plugins
    print(json.dumps(top, indent=2))
    sys.exit(0)
if args[:2] == ["plugins", "update"]:
    if os.environ.get("FAKE_UPDATE_PIDFILE"):
        with open(os.environ["FAKE_UPDATE_PIDFILE"], "a") as f:
            f.write(f"{os.getpid()}\n")
    time.sleep(float(os.environ.get("FAKE_UPDATE_SLEEP") or 0))
    if os.environ.get("FAKE_UPDATE_RC"):
        sys.stderr.write("npm error 404 Not Found; npm_config_token=SECRET-NPM-TOKEN\n")
        sys.exit(int(os.environ["FAKE_UPDATE_RC"]))
    pkg, ver = args[2].rsplit("@", 1)
    hit = [p for p in plugins if p.get("origin") != "bundled" and p.get("rootDir", "").endswith("/node_modules/" + pkg)]
    if not hit:
        sys.stderr.write(f"No tracked plugin or hook pack found for {args[2]}\n")
        sys.exit(1)
    for p in hit:
        old = p["rootDir"]
        gen = hashlib.sha256(args[2].encode()).hexdigest()[:16]
        new = re.sub(r"__openclaw-generation__g-[0-9a-f]{16}/", f"__openclaw-generation__g-{gen}/", old)
        p.update(json.loads(json.dumps(p).replace(old, new)))
        p["version"] = ver
    with open(os.environ["FAKE_PLUGINS"], "w") as f:
        json.dump(plugins, f)
    print("Updated " + pkg)
    sys.exit(0)
sys.exit(3)
'''


def plugin(pid, pkg, ver, enabled=True, origin="global", spec=None):
    """A `plugins list --json` entry in the real shape (tests/fixtures/plugins-list-2026.10.10.json)."""
    return T.listed_plugin(pid, pkg, ver, enabled=enabled, origin=origin, spec=spec)


class PluginsSyncTests(CliEnv):
    def setUp(self):
        super().setUp()
        (self.bin / "node").write_text(PLUGINS_NODE)
        self.plugins = self.tmp / "plugins.json"
        self.top = self.tmp / "plugins-top.json"  # the output around the entries (workspaceDir, registry, ...)
        self.top.write_text(json.dumps(T.plugins_list_output([])))
        self.argv_log = self.tmp / "argv.log"
        self.set_runtime("2026.10.10", 22, 27, doctor=False)
        self.write_plugins([
            plugin("codex", "@openclaw/codex", "2026.10.4"),
            plugin("acpx", "@openclaw/acpx", "2026.10.4", enabled=False),
            plugin("brave", "@openclaw/brave-plugin", "2026.10.4"),
            plugin("thirdparty", "openclaw-plugin-x", "1.0.0"),
            plugin("memory-core", "@openclaw/memory-core", "2026.10.10", origin="bundled")])

    def write_plugins(self, plugins):
        self.plugins.write_text(json.dumps(plugins))

    def sync(self, **env):
        if self.argv_log.exists():
            self.argv_log.unlink()
        rc = self.cli("plugins-sync", env={"FAKE_PLUGINS": str(self.plugins), "FAKE_ARGV_LOG": str(self.argv_log),
                                           "FAKE_PLUGINS_TOP": str(self.top), **env})
        self.assertEqual(rc, 0, self.stdout + self.stderr)
        return [json.loads(x) for x in self.argv_log.read_text().splitlines()] if self.argv_log.exists() else []

    def marker(self, ver="2026.10.10"):
        return self.state / f".plugin_cohort_{ver}"

    def test_plugins_sync_updates_enabled_official_only(self):
        calls = self.sync()
        self.assertEqual([c for c in calls if c[:2] == ["plugins", "update"]],
                         [["plugins", "update", "@openclaw/codex@2026.10.10"]])
        self.assertEqual(calls[0], ["plugins", "list", "--json"])
        self.assertEqual(calls[-1], ["plugins", "list", "--json"])  # checked after the update
        self.assertEqual(self.stdout.splitlines(), [
            "INFO: Official plugins: updating @openclaw/codex 2026.10.4 -> 2026.10.10 (OpenClaw 2026.10.10)...",
            "INFO: Official plugins match OpenClaw 2026.10.10."])
        self.assertTrue(self.marker().is_file())
        self.assertEqual(self.sync(), [])  # once per OpenClaw version
        self.assertEqual(self.stdout, "")

    def test_plugins_sync_failure_keeps_no_marker(self):
        calls = self.sync(FAKE_UPDATE_RC="1")
        self.assertIn(["plugins", "update", "@openclaw/codex@2026.10.10"], calls)
        self.assertIn("WARN: @openclaw/codex stays at 2026.10.4 (openclaw plugins update failed, rc 1: ", self.stdout)
        self.assertIn("OpenClaw 2026.10.10 still loads it (minimum 2026.9.7). The add-on tries again at the next start; "
                      "by hand: openclaw plugins update @openclaw/codex@2026.10.10", self.stdout)
        self.assertNotIn("SECRET", self.stdout + self.stderr)
        self.assertFalse(self.marker().exists())
        self.assertIn(["plugins", "update", "@openclaw/codex@2026.10.10"], self.sync())  # retried at the next start
        self.assertTrue(self.marker().is_file())
        # the list itself fails: WARN, nothing updated, no marker
        self.marker().unlink()
        self.assertEqual(self.sync(FAKE_LIST_RC="1"), [["plugins", "list", "--json"]])
        self.assertIn("WARN: Official plugins not updated: openclaw plugins list failed (rc 1", self.stdout)
        self.assertFalse(self.marker().exists())

    def test_plugins_sync_no_downgrade_and_noop_on_1004(self):
        self.write_plugins([plugin("codex", "@openclaw/codex", "2026.10.4"),
                            plugin("next", "@openclaw/next", "2026.11.5-beta.1")])
        calls = self.sync()
        self.assertEqual([c[2] for c in calls if c[:2] == ["plugins", "update"]], ["@openclaw/codex@2026.10.10"])
        self.assertIn("WARN: @openclaw/next 2026.11.5-beta.1 is newer than OpenClaw 2026.10.10; left as is "
                      "(no downgrade)", self.stdout)
        # D2: no marker while an enabled official plugin is not at the OpenClaw version, a newer one included: the
        # next start reads the list again (no update) and repeats the WARN
        self.assertFalse(self.marker().exists())
        self.assertEqual(self.sync(), [["plugins", "list", "--json"]])
        self.assertIn("WARN: @openclaw/next 2026.11.5-beta.1 is newer than OpenClaw 2026.10.10", self.stdout)
        self.assertFalse(self.marker().exists())
        # runtime 2026.10.4 with every plugin at 2026.10.4: nothing to update, the marker is written
        self.set_runtime("2026.10.4", 20, 24, doctor=False)
        self.write_plugins([plugin("codex", "@openclaw/codex", "2026.10.4"),
                            plugin("acpx", "@openclaw/acpx", "2026.10.4")])
        self.assertEqual(self.sync(), [["plugins", "list", "--json"]])
        self.assertEqual(self.stdout.strip(), "INFO: Official plugins match OpenClaw 2026.10.4.")
        self.assertTrue(self.marker("2026.10.4").is_file())
        # run.sh's validated OPENCLAW_RUNTIME_VERSION names the version (and the marker)
        self.assertEqual(self.sync(OPENCLAW_RUNTIME_VERSION="2026.10.4"), [])
        self.sync(OPENCLAW_RUNTIME_VERSION="2026.10.10")  # the package still says 2026.10.4
        self.assertIn("updating @openclaw/codex 2026.10.4 -> 2026.10.10", self.stdout)
        # a HOLD: never touch the plugins
        self.marker().unlink()
        (self.upg / "hold.txt").write_text("OpenClaw is held\n")
        self.assertEqual(self.sync(), [])
        self.assertIn("OpenClaw is held", self.stdout)
        self.assertFalse(self.marker().exists())

    def test_plugins_sync_on_the_real_list_output(self):
        """Rehearsal D2: OpenClaw's real output has no packageName (tests/fixtures/plugins-list-2026.10.10.json). The
        official npm plugins are found by trust.installSpec / rootDir, the enabled older ones updated, and the marker
        is written only after the list confirms them at the OpenClaw version."""
        data = T.plugins_list_output()
        self.assertFalse(any("packageName" in x or "packageVersion" in x for x in data["plugins"]))
        self.write_plugins(data["plugins"])  # codex, acpx and Brave at 2026.10.10, three bundled ones
        self.assertEqual(self.sync(), [["plugins", "list", "--json"]])
        self.assertEqual(self.stdout.strip(), "INFO: Official plugins match OpenClaw 2026.10.10.")
        self.assertTrue(self.marker().is_file())
        # the rehearsal's check: codex and acpx (and Brave) left at 2026.10.4
        self.marker().unlink()
        for x in data["plugins"]:
            if x["origin"] == "global":
                x["version"] = "2026.10.4"
        self.write_plugins(data["plugins"])
        calls = self.sync()
        self.assertEqual([c[2] for c in calls if c[:2] == ["plugins", "update"]],
                         ["@openclaw/acpx@2026.10.10", "@openclaw/codex@2026.10.10"])  # never Brave (run.sh's step)
        self.assertEqual(calls[-1], ["plugins", "list", "--json"])
        self.assertIn("INFO: Official plugins match OpenClaw 2026.10.10.", self.stdout)
        self.assertNotIn("none enabled besides Brave", self.stdout)
        self.assertTrue(self.marker().is_file())
        listed = {x["id"]: x["version"] for x in json.loads(self.plugins.read_text())}
        self.assertEqual((listed["codex"], listed["acpx"], listed["brave"]), ("2026.10.10", "2026.10.10", "2026.10.4"))
        # a disabled one stays as it is, and so does the marker logic: only enabled ones count
        self.marker().unlink()
        for x in data["plugins"]:
            if x["id"] == "acpx":
                x.update(enabled=False, status="disabled")
        self.write_plugins(data["plugins"])
        self.assertEqual([c[2] for c in self.sync() if c[:2] == ["plugins", "update"]], ["@openclaw/codex@2026.10.10"])
        self.assertTrue(self.marker().is_file())
        self.assertEqual({x["id"]: x["version"] for x in json.loads(self.plugins.read_text())}["acpx"], "2026.10.4")

    def test_plugins_sync_identifies_plugins_like_the_gate(self):
        """Package from OpenClaw's install record of the id, else trust.installSpec (npm), else the rootDir/source
        path; an @openclaw/ checkout on a load path (no install record, not from npm) and third-party packages are
        never updated."""
        T.make_1004_state(self.state)
        self.write_cfg({"plugins": {"entries": {"codex": {"enabled": True}}}})
        T.write_install_records(self.state, {"codex": ("@openclaw/codex", "2026.10.4", "@openclaw/codex@2026.10.4")})
        codex = plugin("codex", "@openclaw/codex", "2026.10.4")
        codex["trust"] = {"reason": "record-missing", "registryPath": codex["trust"]["registryPath"],
                          "origin": "global"}
        acpx = plugin("acpx", "@openclaw/acpx", "2026.10.4")  # no install record: trust.installSpec names it
        acpx["trust"]["installSpec"] = "npm:@openclaw/acpx@2026.10.4"
        voice = plugin("voice", "@openclaw/voice-call", "2026.10.4")  # only its path names it
        voice["trust"] = {"reason": "record-missing", "registryPath": voice["trust"]["registryPath"],
                          "origin": "global"}
        voice.pop("trustedOfficialInstall")
        self.write_plugins([codex, acpx, voice, plugin("dev", "@openclaw/dev-tools", "2026.10.4", origin="config"),
                            plugin("thirdparty", "openclaw-plugin-x", "1.0.0"),
                            plugin("alibaba", "@openclaw/alibaba-provider", "2026.10.4", origin="bundled")])
        calls = self.sync()
        self.assertEqual(sorted(c[2] for c in calls if c[:2] == ["plugins", "update"]),
                         ["@openclaw/acpx@2026.10.10", "@openclaw/codex@2026.10.10", "@openclaw/voice-call@2026.10.10"])
        self.assertTrue(self.marker().is_file())

    def test_plugins_sync_install_records_the_list_does_not_show_keep_no_marker(self):
        """Rehearsal D2: a list that shows none of OpenClaw's recorded npm installs (or not an enabled one) cannot
        confirm their version: a WARN per record, no marker, the next start looks again."""
        T.make_1004_state(self.state)
        self.write_cfg({"plugins": {"entries": {"codex": {"enabled": True}, "acpx": {"enabled": False}}}})
        T.write_install_records(self.state, {
            "codex": ("@openclaw/codex", "2026.10.4", "@openclaw/codex@2026.10.4"),
            "acpx": ("@openclaw/acpx", "2026.10.4", None),
            "brave": ("@openclaw/brave-plugin", "2026.10.4", "@openclaw/brave-plugin@2026.10.4")})
        self.write_plugins([plugin("memory-core", "@openclaw/memory-core", "2026.10.10", origin="bundled")])
        self.assertEqual(self.sync(), [["plugins", "list", "--json"]])
        for pkg, pid in (("@openclaw/acpx", "acpx"), ("@openclaw/brave-plugin", "brave"), ("@openclaw/codex", "codex")):
            self.assertIn(f"WARN: OpenClaw recorded the npm install of {pkg} 2026.10.4 (plugin {pid}), but openclaw "
                          "plugins list does not show it, so its version is not confirmed (check: openclaw plugins "
                          "doctor). The add-on looks again at the next start.", self.stdout)
        self.assertNotIn("match OpenClaw", self.stdout)
        self.assertNotIn("none enabled besides Brave", self.stdout)
        self.assertFalse(self.marker().exists())
        # the list shows Brave but not the enabled codex: still no marker (the disabled acpx does not count)
        self.write_plugins([plugin("brave", "@openclaw/brave-plugin", "2026.10.4")])
        self.sync()
        self.assertIn("(plugin codex), but openclaw plugins list does not show it", self.stdout)
        self.assertNotIn("(plugin acpx)", self.stdout)
        self.assertFalse(self.marker().exists())
        # once the list shows codex (updated here), the marker follows
        self.write_plugins([plugin("brave", "@openclaw/brave-plugin", "2026.10.4"),
                            plugin("codex", "@openclaw/codex", "2026.10.4", spec="@openclaw/codex@2026.10.4")])
        self.assertIn(["plugins", "update", "@openclaw/codex@2026.10.10"], self.sync())
        self.assertIn("INFO: Official plugins match OpenClaw 2026.10.10.", self.stdout)
        self.assertTrue(self.marker().is_file())

    def test_plugins_sync_time_budget_leaves_the_rest_for_the_next_start(self):
        """No update starts after the step's time budget (PLUGIN_SYNC_BUDGET; here 2 s through the test hook), so the
        last update and the relist end before run.sh's outer `timeout 1200`; the skipped ones keep the marker away."""
        self.write_plugins([plugin("acpx", "@openclaw/acpx", "2026.10.4"),
                            plugin("codex", "@openclaw/codex", "2026.10.4")])
        self.hooks(plugin_sync_budget_s=2)
        calls = self.sync(FAKE_UPDATE_SLEEP="3")
        self.assertEqual([c for c in calls if c[:2] == ["plugins", "update"]],
                         [["plugins", "update", "@openclaw/acpx@2026.10.10"]])
        self.assertEqual(calls[-1], ["plugins", "list", "--json"])
        self.assertIn("WARN: @openclaw/codex stays at 2026.10.4 (not started: the update step's time budget (2 s) ran "
                      "out); OpenClaw 2026.10.10 still loads it (minimum 2026.9.7). The add-on tries again at the next "
                      "start", self.stdout)
        self.assertNotIn("acpx stays", self.stdout)
        self.assertFalse(self.marker().exists())
        self.assertEqual([c for c in self.sync() if c[:2] == ["plugins", "update"]],
                         [["plugins", "update", "@openclaw/codex@2026.10.10"]])  # the next start
        self.assertTrue(self.marker().is_file())

    def test_plugins_sync_sigterm_stops_the_update_and_its_process_group(self):
        """run.sh's shutdown trap (or its outer `timeout`) sends SIGTERM: the running `openclaw plugins update` runs
        in its own session, so it is stopped with its process group (it must not keep installing while the add-on
        stops or the gateway starts); no marker, rc 0."""
        pidfile = self.tmp / "update.pid"
        e = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", FAKE_PLUGINS=str(self.plugins),
                 FAKE_PLUGINS_TOP=str(self.top), FAKE_ARGV_LOG=str(self.argv_log), FAKE_UPDATE_PIDFILE=str(pidfile),
                 FAKE_UPDATE_SLEEP="120")
        proc = subprocess.Popen([sys.executable, "-B", str(SCRIPT), "plugins-sync"], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=e)
        child = None
        try:
            for _ in range(200):
                if pidfile.exists() and pidfile.read_text().strip():
                    break
                time.sleep(0.05)
            child = int(pidfile.read_text().split()[0])
            start = time.monotonic()
            proc.send_signal(signal.SIGTERM)
            out, err = proc.communicate(timeout=60)
            self.assertLess(time.monotonic() - start, 20)
            self.assertEqual(proc.returncode, 0, out + err)
            self.assertIn("INFO: Official plugins: update step stopped (add-on stop or time limit); the add-on tries "
                          "again at the next start.", out)
            with self.assertRaises(ProcessLookupError):
                os.kill(child, 0)
            self.assertFalse(self.marker().exists())
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
            if child is not None:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass


class HeldStoreCheckTests(CliEnv):
    def test_check_prints_new_orphan_and_held_lines(self):
        self.set_runtime("2026.10.10", 22, 27, doctor=False)
        T.make_1004_state(self.state)
        self.write_cfg({"meta": {"lastTouchedVersion": "2026.10.4"}, "agents": {"list": [{"id": "main"}]}})
        T.make_1004_agent_db(self.state, "ghost")
        T.make_1004_agent_db(self.state, "old")
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute("INSERT INTO agent_databases VALUES ('old', 'agents/old/agent/openclaw-agent.sqlite', 24, 0, NULL)")
        con.execute("INSERT INTO agent_deletion_journal (agent_id, agent_dir, workspace_dir, sessions_dir, created_at, "
                    "cleanup_completed, delete_files) VALUES ('old', ?, '/w', '/s', 0, 1, 0)",
                    (str(self.state / "agents" / "old" / "agent"),))
        con.commit()
        con.close()
        self.cli("check", env={"OPENCLAW_RUNTIME_VERSION": "2026.10.10"})
        self.assertIn("  agent databases of no configured or registered agent (doctor may migrate them one-way; the "
                      "gateway does not open them): agents/ghost/agent/openclaw-agent.sqlite (schema 24)", self.stdout)
        self.assertIn("  held agent databases (kept from deleted agents; not migrated, not opened): "
                      "agents/old/agent/openclaw-agent.sqlite (agent old, schema 24: kept from a deleted agent "
                      "(deletion journal))", self.stdout)
        # readiness (section I) uses the same held stores
        self.assertIn("[gate] 1/8 info: agents/old/agent/openclaw-agent.sqlite (agent old, schema 24) is kept from a "
                      "deleted agent", self.stdout)
        # state, main and the orphan doctor would migrate; not the held store
        self.assertIn("quick_check ok (3/3); foreign keys ok (3/3)", self.stdout)


if __name__ == "__main__":
    unittest.main()
