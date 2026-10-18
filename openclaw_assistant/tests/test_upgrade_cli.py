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


# --- 0.5.94-full2: cleanup / export / status ---------------------------------------------------------

import fcntl  # noqa: E402
import signal  # noqa: E402
import time  # noqa: E402
import uuid  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

import oc_common as C  # noqa: E402

RC_ERROR = 1  # oc_upgrade.RC_ERROR (oc_upgrade is not imported here: its import rewrites sys.path)
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
FAKE_RECIPIENT = "age1" + (BECH32 * 2)[:58]  # shape-valid (regex), no real key behind it
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

    def finished_run(self, hours_ago, captures=1):
        """A gate run that finished `hours_ago` hours ago, with an (encrypted-looking) archive dir in /share and
        `captures` doctor capture dirs named in its doctor log."""
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
                self.assertIn("no plaintext copies", self.stdout)
        self.assertEqual(self.cli(), 1)
        self.assertIn("cleanup [--apply]", self.stdout)

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
        self.assertIn(f"  {plain} (", self.stdout)
        self.assertIn("PLAINTEXT: delete it", self.stdout)
        self.assertIn(f"  {enc} (", self.stdout)

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
        self.assertNotIn("PLAINTEXT: delete it", self.stdout)
        self.assertNotIn(str(enc), self.stdout)

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
        self.assertIn("[cleanup] gate archives and doctor captures are deleted 48 h after their gate run", out)
        self.assertIn(f"[cleanup] run {rid}: deleted 2 item(s)", out)
        self.assertFalse(adir.exists())
        self.assertFalse(caps[0].exists())

    # export
    def test_export_is_refused_without_encryption_and_writes_nothing(self):
        cases = [
            {"gate_archive": "off"},
            {"gate_archive": "off", "gate_archive_age_recipient": FAKE_RECIPIENT},
            {"gate_archive": "encrypted", "gate_archive_age_recipient": ""},
            {"gate_archive": "encrypted"},
            {"gate_archive": "encrypted", "gate_archive_age_recipient": "age1notakey"},
            {"gate_archive": "plaintext", "gate_archive_age_recipient": FAKE_RECIPIENT},
            {},
            None,  # no options file at all
        ]
        for opts in cases:
            with self.subTest(opts=opts):
                if opts is None:
                    (self.tmp / "options.json").unlink()
                else:
                    self.set_options(opts)
                self.assertEqual(self.cli("export"), RC_ERROR, self.stdout + self.stderr)
                self.assertIn("Export refused", self.stderr)
                self.assertNotIn("Export requested", self.stdout)
                self.assertFalse((self.upg / "export-request").exists())
                self.assertEqual(self.share_files(), [])
        self.assertEqual(self.cli("status"), 0)
        self.assertIn("Export requested: no", self.stdout)

    def test_export_refused_for_a_private_key_never_echoes_it(self):
        keys = [FAKE_SECRET_KEY] + ([T.AGE_IDENTITY] if T.HAVE_AGE else [])
        for key in keys:
            with self.subTest(real=key != FAKE_SECRET_KEY):
                self.set_options({"gate_archive": "encrypted", "gate_archive_age_recipient": key})
                self.assertEqual(self.cli("export"), RC_ERROR)
                self.assertIn("Export refused", self.stderr)
                self.assertNotIn(key[16:], self.stdout + self.stderr)
                self.assertFalse((self.upg / "export-request").exists())
                self.assertEqual(self.share_files(), [])

    def test_export_with_a_valid_recipient_only_records_a_request(self):
        self.set_options({"gate_archive": "encrypted", "gate_archive_age_recipient": FAKE_RECIPIENT})
        self.assertEqual(self.cli("export"), 0, self.stdout + self.stderr)
        self.assertIn("Export requested.", self.stdout)
        self.assertIn(f"encrypted with age to {C.short_recipient(FAKE_RECIPIENT)}", self.stdout)
        self.assertTrue((self.upg / "export-request").exists())
        self.assertEqual(self.share_files(), [])  # the copy is made by run.sh on the next start
        self.assertEqual(self.cli("status"), 0)
        self.assertIn("Export requested: yes", self.stdout)
        # a later switch to off: the pending request can still be withdrawn
        self.set_options({"gate_archive": "off"})
        self.assertEqual(self.cli("export", "--cancel"), 0)
        self.assertIn("Export request withdrawn.", self.stdout)
        self.assertFalse((self.upg / "export-request").exists())
        self.assertEqual(self.cli("export", "--cancel"), 0)
        self.assertIn("No export request pending.", self.stdout)

    # status
    def gate_options_line(self):
        lines = [x.strip() for x in self.stdout.splitlines() if x.strip().startswith("Gate options:")]
        self.assertEqual(len(lines), 1, self.stdout)
        return lines[0]

    def test_status_shows_the_gate_options_line(self):
        self.set_options({"gate_archive": "encrypted", "gate_archive_age_recipient": FAKE_RECIPIENT,
                          "gate_cleanup_hours": 12, "gate_backup_max_age_hours": 72})
        self.assertEqual(self.cli("status"), 0, self.stderr)
        line = self.gate_options_line()
        self.assertTrue(line.startswith(f"Gate options: gate_archive encrypted to {C.short_recipient(FAKE_RECIPIENT)};"),
                        line)
        self.assertIn("12 h after a run (0 = never)", line)
        self.assertIn("backup max age 72 h", line)
        self.assertNotIn("problem", line)

        self.set_options({"gate_archive": "off", "gate_archive_age_recipient": FAKE_RECIPIENT,
                          "gate_cleanup_hours": 0})
        self.assertEqual(self.cli("status"), 0)
        line = self.gate_options_line()
        self.assertTrue(line.startswith("Gate options: gate_archive off;"), line)
        self.assertIn(" 0 h after a run (0 = never)", line)
        self.assertIn("backup max age 24 h", line)

        (self.tmp / "options.json").unlink()
        self.assertEqual(self.cli("status"), 0)
        self.assertTrue(self.gate_options_line().startswith("Gate options: gate_archive encrypted (problem: missing);"))

        self.set_options({"gate_archive": "plaintext", "gate_cleanup_hours": "secret-ish-48",
                          "gate_backup_max_age_hours": 9999})
        self.assertEqual(self.cli("status"), 0)
        line = self.gate_options_line()
        self.assertIn("gate_archive ? (problem: invalid-mode)", line)
        self.assertIn(" 48 h after a run", line)
        self.assertIn("backup max age 24 h", line)
        self.assertNotIn("secret-ish", self.stdout + self.stderr)
        self.assertNotIn("9999", self.stdout + self.stderr)

    def test_status_never_prints_a_pasted_private_key(self):
        keys = [FAKE_SECRET_KEY, f"  {FAKE_SECRET_KEY.lower()}\n"] + ([T.AGE_IDENTITY] if T.HAVE_AGE else [])
        opts_file = self.tmp / "options.json"
        for key in keys:
            with self.subTest(key=key.strip()[:18]):
                self.set_options({"gate_archive": "encrypted", "gate_archive_age_recipient": key})
                body = key.strip()[16:]
                self.assertEqual(self.cli("status"), 0, self.stderr)
                self.assertIn("Gate options: gate_archive encrypted (problem: private-key);", self.gate_options_line())
                out = self.stdout + self.stderr
                for args in (("cleanup",), ("cleanup", "--apply"), ("export",), ("help",)):
                    self.cli(*args)
                    out += self.stdout + self.stderr
                self.assertNotIn(body, out)
                self.assertNotIn(body.lower(), out.lower())
                self.assertEqual(self.files_containing(body, skip=(opts_file,)), [])
                self.assertEqual(self.share_files(), [])

    def test_check_and_dry_run_name_the_private_key_problem_without_echoing_it(self):
        self.build_735()
        self.hooks()
        self.set_options({"gate_archive": "encrypted", "gate_archive_age_recipient": FAKE_SECRET_KEY})
        env = {"OPENCLAW_RUNTIME_VERSION": T.RUNTIME}
        self.assertEqual(self.cli("check", env=env), 4, self.stdout + self.stderr)
        self.assertIn("a gate would HOLD with: archive-key-invalid", self.stdout)
        out = self.stdout + self.stderr
        self.assertEqual(self.cli("gate", "--dry-run", env=env), 20, self.stdout + self.stderr)
        self.assertIn("[gate] dry-run: would HOLD: archive-key-invalid", self.stdout)
        out += self.stdout + self.stderr
        self.assertIn("PRIVATE key", out)
        self.assertNotIn(FAKE_SECRET_BODY, out)
        self.assertEqual(self.files_containing(FAKE_SECRET_BODY, skip=(self.tmp / "options.json",)), [])
        self.assertEqual(self.share_files(), [])
        self.assertFalse((self.upg / "gate" / "journal.json").exists())


if __name__ == "__main__":
    unittest.main()
