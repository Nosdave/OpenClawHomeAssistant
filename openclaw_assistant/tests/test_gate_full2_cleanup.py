"""Tests of the 0.5.94-full2 automatic deletion of gate archives and doctor captures (gate_cleanup_hours) and of
the archive / backup / cleanup lines of `oc-upgrade status` (status_lines) and the readiness preview.

Covers oc_gate.captures_root, _run_journals, cleanup_blocked, run_captures, _delete_tree, _archive_dir_ok,
cleanup_targets, cleanup_pass, cleanup_loop and cleanup_cmd in the temporary tree of test_gate.GateEnv, partly
on the state a real gate run leaves (fake node, a fake doctor that writes OpenClaw-style doctor captures) and
partly on journals written directly. The safety rules under test: nothing is deleted before finished_at +
gate_cleanup_hours, never during a HOLD / running gate / pending retry / held gate lock, never outside
<state>.update-captures and /share/openclaw-upgrade, never through a symlink; and no status line prints the
full age recipient, a token or a secret.
"""

import fcntl
import json
import os
import signal
import sys
import threading
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
for _p in (str(ADDON), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import test_gate as T  # noqa: E402  (GateEnv, fake node/doctor, synthetic 7.35 state, throwaway age keys)

C, G = T.C, T.G

NEEDS_AGE = unittest.skipUnless(T.HAVE_AGE, "age / age-keygen not installed")
# A syntactically valid recipient for the journal-only tests (age itself never runs with it).
FAKE_PUB = "age1" + "q" * 58
T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
H48 = timedelta(hours=48)
SEC = timedelta(seconds=1)

# Wraps the fake doctor of test_gate: like OpenClaw 2026.10 it first copies the pre-repair state into
# <realpath(state)>.update-captures/doctor-<uuid4>/ and logs the clack-box line naming its manifest.
CAPTURE_DOCTOR = r'''#!/usr/bin/env python3
import os, sys, uuid
state = os.path.realpath(os.environ["OPENCLAW_STATE_DIR"])
d = os.path.join(state + ".update-captures", "doctor-" + str(uuid.uuid4()))
os.makedirs(d)
with open(os.path.join(d, "manifest.json"), "w") as f:
    f.write('{"schemaVersion": 2, "generation": {"kind": "baseline"}}\n')
with open(os.path.join(d, "openclaw.sqlite"), "wb") as f:
    f.write(b"SQLite format 3\x00" + b"\x00" * 8192)
print("\x1b[90m│\x1b[39m  Pre-repair state retained for manual recovery at " + d + "/manifest.json.", flush=True)
os.execv(sys.argv[1], sys.argv[1:])
'''


def iso(dt):
    return C.utc_iso(dt)


class CleanupEnv(T.GateEnv):
    def setUp(self):
        super().setUp()
        # The openclaw-running precheck matches any */openclaw.mjs process on the machine, which includes the fake
        # node of test suites running in parallel; only processes of this test's own tree count here.
        real_find = G.find_openclaw_processes
        mine = str(self.tmp)
        patcher = mock.patch.object(G, "find_openclaw_processes",
                                    lambda *a, **kw: [p for p in real_find(*a, **kw) if mine in p["cmd"]])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.gp = G.gpaths()
        G.ensure_dirs(self.gp)
        self.arch = self.share / "openclaw-upgrade"
        self.caps = G.captures_root(self.gp)
        self.n = 0

    # ----- builders -----
    def new_rid(self):
        self.n += 1
        return f"20261001T1200{self.n:02d}Z-{self.n:06x}"

    def capture(self, root=None, name=None):
        d = (root or self.caps) / (name or f"doctor-{uuid.uuid4()}")
        d.mkdir(parents=True)
        (d / "manifest.json").write_text(json.dumps({"schemaVersion": 2, "runId": d.name}))
        (d / "openclaw.sqlite").write_bytes(b"SQLite format 3\x00" + b"\x00" * 4000)
        return d

    @staticmethod
    def capture_line(path, ansi=True):
        line = f"Pre-repair state retained for manual recovery at {path}/manifest.json."
        return f"\x1b[90m│\x1b[39m  \x1b[2m{line}\x1b[22m" if ansi else line

    def make_archive(self, rid, kind="age", root=None):
        adir = (root or self.arch) / rid
        adir.mkdir(parents=True)
        name = f"openclaw-state-20261001-120000-before-{T.RUNTIME}.tar.gz" + (".age" if kind == "age" else "")
        f = adir / name
        body = (G.AGE_MAGIC + b"-> X25519 stanza\n") if kind == "age" else b"\x1f\x8b\x08\x00"
        f.write_bytes(body + os.urandom(3000))
        sha = C.sha256_file(f)
        (adir / "SHA256SUMS").write_text(f"{sha}  {name}\n")
        (adir / "manifest.json").write_text("{}\n")
        rec = {"dir": str(adir), "file": name, "sha256": sha, "size": f.stat().st_size, "members": 3,
               "verified": True}
        if kind == "age":
            rec.update({"mode": "encrypted", "format": "tar.gz+age", "recipient": FAKE_PUB})
        return adir, f, rec

    def make_run(self, finished=T0, status="done", archive="age", captures=1, current=False, extra_lines=(),
                 rid=None, **extra):
        """A gate run as the gate leaves it: journal (current or runs/<id>/journal.json), its archive dir under
        /share/openclaw-upgrade and its doctor captures, named in runs/<id>/doctor-pass1.log / -pass2.log."""
        rid = rid or self.new_rid()
        rd = self.gp["RUNS"] / rid
        rd.mkdir(parents=True, exist_ok=True)
        start = (finished or T0) - timedelta(minutes=5)
        j = {"run_id": rid, "mode": "from-7x", "status": status, "phase": "finalize" if finished else "doctor1",
             "started_at": iso(start), "finished_at": iso(finished) if finished else None,
             "phases_done": [], "doctor": [], "first_write_at": iso(start)}
        adir = self.arch / rid
        afile = None
        if archive == "off":
            j["archive"] = {"mode": "off"}
        elif archive:
            adir, afile, j["archive"] = self.make_archive(rid, archive)
        caps = [self.capture() for _ in range(captures)]
        pass1 = ["┌  OpenClaw doctor"] + [self.capture_line(c) for c in caps[:1]] + list(extra_lines)
        (rd / "doctor-pass1.log").write_text("\n".join(pass1 + ["└  Doctor complete."]) + "\n")
        if caps[1:]:
            (rd / "doctor-pass2.log").write_text("\n".join(self.capture_line(c, ansi=False) for c in caps[1:])
                                                + "\n")
        j.update(extra)
        (self.gp["JOURNAL"] if current else rd / "journal.json").write_text(json.dumps(j))
        return SimpleNamespace(rid=rid, rd=rd, adir=adir, afile=afile, caps=caps, j=j)

    def write_current(self, j):
        self.gp["JOURNAL"].write_text(json.dumps(j))

    def age_old(self, path, when):
        ts = when.timestamp()
        os.utime(path, (ts, ts), follow_symlinks=False)

    # ----- runners -----
    def cleanup(self, now, hours=48, state=None):
        lines = []
        n = G.cleanup_pass(now=now, hours=hours, emit=lines.append, state=state)
        self.lines = lines
        self.text = "\n".join(lines)
        return n

    def cmd(self, *args):
        lines = []
        rc = G.cleanup_cmd(list(args), emit=lines.append)
        self.lines = lines
        self.text = "\n".join(lines)
        return rc

    def record(self, rid):
        p = self.gp["RUNS"] / rid / "cleanup.json"
        return json.loads(p.read_text()) if p.exists() else None

    def protect_signals(self):
        """cleanup_loop installs the gate's SIGTERM/SIGINT handlers and never restores them."""
        old = (signal.getsignal(signal.SIGTERM), signal.getsignal(signal.SIGINT))

        def restore():
            signal.signal(signal.SIGTERM, old[0])
            signal.signal(signal.SIGINT, old[1])
            G._STOP_SIG[0] = None
            G.STOP.clear()
        self.addCleanup(restore)

    def real_gate_with_captures(self):
        """A real from-7x gate run whose doctor passes each leave one capture; returns (journal, captures)."""
        self.build_735()
        doc = self.bin / "capture-doctor"
        doc.write_text(CAPTURE_DOCTOR)
        doc.chmod(0o755)
        self.hooks(doctor_cmd=[str(doc), str(self.bin / "fake-doctor")])
        rc = self.run_gate()
        self.assertEqual(rc, 0, self.out + self.err)
        caps = sorted(p for p in self.caps.iterdir() if G.CAPTURE_NAME_RE.match(p.name))
        self.assertEqual(len(caps), 2, caps)  # one per doctor pass
        return self.journal(), caps


class CleanupTests(CleanupEnv):
    # ----- a real gate run ------------------------------------------------------------------------
    @NEEDS_AGE
    def test_real_gate_run_archive_and_captures_kept_until_due_then_deleted_once(self):
        j, caps = self.real_gate_with_captures()
        rid = j["run_id"]
        adir = Path(j["archive"]["dir"])
        self.assertEqual(adir, self.arch / rid)
        self.assertTrue(list(adir.glob("*.tar.gz.age")))
        self.assertIn("info: the archive and the doctor captures of this run are deleted after", self.out)
        self.assertIn("(gate_cleanup_hours=48)", self.out)
        stray = self.capture()  # a capture no run log names (doctor run by hand): never touched
        fin = datetime.strptime(j["finished_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        due = fin + H48

        keep, refused = G.run_captures(self.gp, j)
        self.assertEqual((sorted(keep), refused), (caps, []))

        # one second before: nothing deleted, announced once
        self.assertEqual(self.cleanup(due - SEC), 0)
        self.assertEqual(self.lines, [f"[cleanup] run {rid}: 3 item(s) (archive / doctor captures) will be deleted "
                                      f"at {iso(due)}"])
        rec = self.record(rid)
        self.assertEqual((rec["due_at"], rec["announced_at"]), (iso(due), iso(due - SEC)))
        self.assertTrue(adir.is_dir() and all(c.is_dir() for c in caps))
        self.assertEqual(self.cleanup(due - SEC), 0)
        self.assertEqual(self.lines, [])  # repeated passes are silent

        # at the due time: archive dir and both captures go, nothing else
        self.assertEqual(self.cleanup(due), 3)
        self.assertEqual(len(self.lines), 1, self.text)
        self.assertTrue(self.lines[0].startswith(f"[cleanup] run {rid}: deleted 3 item(s), "), self.text)
        self.assertFalse(os.path.lexists(adir))
        for c in caps:
            self.assertFalse(os.path.lexists(c), c)
        self.assertTrue(stray.is_dir())
        self.assertTrue(self.caps.is_dir())
        self.assertEqual(sorted(p.name for p in self.arch.iterdir()), [])  # no tombstone left behind
        self.assertEqual([p.name for p in self.caps.iterdir()], [stray.name])
        rec = self.record(rid)
        self.assertEqual(rec["deleted_at"], iso(due))
        self.assertEqual(sorted(d["path"] for d in rec["deleted"]), sorted([str(adir)] + [str(c) for c in caps]))
        self.assertTrue(all(d["bytes"] > 0 for d in rec["deleted"]), rec)
        # the gate's own records survive (only /share and the captures are deleted)
        self.assertTrue((self.gp["RUNS"] / rid / "doctor-pass1.log").exists())
        self.assertTrue((self.upg / "gate" / "migrated.json").exists())

        # idempotent: a later pass is a silent no-op and leaves the record alone
        self.assertEqual(self.cleanup(due + timedelta(days=30)), 0)
        self.assertEqual(self.lines, [])
        self.assertEqual(self.record(rid), rec)
        self.assertNotIn("SECRET", self.out)

    def test_real_gate_run_with_archive_off_deletes_only_the_captures(self):
        self.base_options = {"gate_archive": "off"}
        self.options()
        j, caps = self.real_gate_with_captures()
        self.assertIn("info: the doctor captures of this run are deleted after", self.out)
        self.assertFalse(self.arch.exists() and any(self.arch.iterdir()))
        fin = datetime.strptime(j["finished_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        self.assertEqual(self.cleanup(fin + H48 - SEC), 0)
        self.assertIn("2 item(s)", self.text)
        self.assertEqual(self.cleanup(fin + H48), 2)
        for c in caps:
            self.assertFalse(os.path.lexists(c))

    # ----- capture parsing and path validation ---------------------------------------------------------
    def test_captures_root_is_next_to_the_resolved_state_dir(self):
        self.assertEqual(self.caps, Path(os.path.realpath(self.state) + ".update-captures"))
        real = self.tmp / "data" / "oc-state"
        real.mkdir(parents=True)
        link = self.tmp / "linked-state"
        os.symlink(real, link)
        with mock.patch.dict(os.environ, {"OPENCLAW_STATE_DIR": str(link)}):
            self.assertEqual(G.captures_root(G.gpaths()), Path(str(real) + ".update-captures"))

    def test_capture_lines_parsed_with_ansi_and_box_drawing(self):
        r = self.make_run(captures=0)
        good = [self.capture() for _ in range(3)]
        (r.rd / "doctor-pass1.log").write_text(
            "┌  OpenClaw doctor\n"
            f"{self.capture_line(good[0])}\n"
            f"│  {self.capture_line(good[1], ansi=False)}  │\n"
            "└  Doctor complete.\n")
        (r.rd / "doctor-pass2.log").write_text(self.capture_line(good[2], ansi=False).rstrip(".") + "\n"
                                               + self.capture_line(good[0]) + "\n")  # duplicate: once
        noise = self.capture()
        (r.rd / "events.log").write_text(self.capture_line(noise) + "\n")  # not a doctor log: ignored
        (r.rd / "doctor-notes.txt").write_text(self.capture_line(noise) + "\n")
        keep, refused = G.run_captures(self.gp, r.j)
        self.assertEqual(sorted(keep), sorted(good))
        self.assertEqual(refused, [])

    def test_capture_paths_outside_the_root_symlinks_and_odd_names_are_never_deleted(self):
        victim = self.tmp / "victim"
        victim.mkdir()
        (victim / "precious.txt").write_text("keep me")
        outside_ws = self.capture(root=self.ws)  # doctor-<uuid> inside the workspace
        outside_cfg = self.capture(root=self.root)  # next to the captures root, reached through ".."
        dotdot = self.caps / ".." / outside_cfg.name
        etc = Path("/etc") / f"doctor-{uuid.uuid4()}"
        link = self.caps / f"doctor-{uuid.uuid4()}"
        self.caps.mkdir(parents=True, exist_ok=True)
        os.symlink(victim, link)
        badname = self.capture(name="doctor-not-a-uuid")
        upper = self.capture(name=f"doctor-{str(uuid.uuid4()).upper()}")
        nested = self.capture(root=self.caps / f"doctor-{uuid.uuid4()}")  # a doctor-<uuid> one level deeper
        missing = self.caps / f"doctor-{uuid.uuid4()}"  # named, never created
        afile = self.caps / f"doctor-{uuid.uuid4()}"
        afile.write_text("not a directory")
        good = self.capture()
        lines = [self.capture_line(p) for p in (outside_ws, dotdot, etc, link, badname, upper, nested, missing,
                                                afile, good)]
        r = self.make_run(captures=0, extra_lines=lines)

        keep, refused = G.run_captures(self.gp, r.j)
        self.assertEqual(keep, [good])
        reasons = dict(refused)
        root = str(self.caps)
        self.assertEqual(reasons[str(outside_ws)], "not inside " + root)
        self.assertEqual(reasons[str(dotdot)], "not inside " + root)
        self.assertEqual(reasons[str(etc)], "not inside " + root)
        self.assertEqual(reasons[str(nested)], "not inside " + root)
        self.assertEqual(reasons[str(link)], "symlink")
        self.assertEqual(reasons[str(badname)], "unexpected name")
        self.assertEqual(reasons[str(upper)], "unexpected name")
        self.assertNotIn(str(missing), reasons)
        self.assertNotIn(str(afile), reasons)

        self.assertEqual(self.cleanup(T0 + H48), 2)  # the archive dir and the one valid capture
        self.assertFalse(os.path.lexists(good))
        self.assertFalse(os.path.lexists(r.adir))
        for p in (outside_ws, outside_cfg, badname, upper, nested, afile):
            self.assertTrue(os.path.lexists(p), p)
        self.assertTrue(os.path.islink(link))
        self.assertEqual((victim / "precious.txt").read_text(), "keep me")
        for p in (outside_ws, link, badname, etc):
            self.assertIn(f"WARN [cleanup] run {r.rid}: kept {p}: ", self.text)
        # each refusal is logged once
        self.assertEqual(self.cleanup(T0 + H48 + SEC), 0)
        self.assertEqual(self.lines, [])

    def test_symlinked_captures_root_refuses_every_capture(self):
        elsewhere = self.tmp / "elsewhere"
        elsewhere.mkdir()
        os.symlink(elsewhere, self.caps)
        cap = self.capture(root=elsewhere)
        r = self.make_run(captures=0, extra_lines=[self.capture_line(self.caps / cap.name)])
        keep, refused = G.run_captures(self.gp, r.j)
        self.assertEqual(keep, [])
        self.assertEqual(refused, [(str(self.caps / cap.name), "not inside " + str(self.caps))])
        self.assertEqual(self.cleanup(T0 + H48), 1)  # only the archive
        self.assertTrue(cap.is_dir())
        self.assertTrue(os.path.islink(self.caps))

    def test_symlinks_inside_a_deleted_tree_are_not_followed(self):
        victim = self.tmp / "victim"
        (victim / "sub").mkdir(parents=True)
        (victim / "precious.txt").write_text("keep me")
        (victim / "sub" / "x").write_text("x")
        r = self.make_run(captures=1)
        os.symlink(victim / "precious.txt", r.adir / "link-to-file")
        os.symlink(victim, r.adir / "link-to-dir")
        os.symlink(victim, r.caps[0] / "link-to-dir")
        self.assertEqual(self.cleanup(T0 + H48), 2)
        self.assertFalse(os.path.lexists(r.adir))
        self.assertFalse(os.path.lexists(r.caps[0]))
        self.assertEqual((victim / "precious.txt").read_text(), "keep me")
        self.assertTrue((victim / "sub" / "x").exists())

    # ----- due logic --------------------------------------------------------------------------------
    def test_due_boundary_record_and_second_pass_noop(self):
        r = self.make_run(captures=2)
        self.assertEqual(self.cleanup(T0), 0)
        self.assertEqual(self.cleanup(T0 + H48 - SEC), 0)
        self.assertTrue(r.adir.is_dir() and all(c.is_dir() for c in r.caps))
        rec = self.record(r.rid)
        self.assertEqual((rec["due_at"], rec["announced_at"]), (iso(T0 + H48), iso(T0)))  # announced once, first
        self.assertEqual(self.cleanup(T0 + H48), 3)
        self.assertFalse(os.path.lexists(r.adir))
        rec = self.record(r.rid)
        self.assertEqual(rec["schema"], 1)
        self.assertEqual(rec["deleted_at"], iso(T0 + H48))
        self.assertEqual(len(rec["deleted"]), 3)
        self.assertEqual(self.cleanup(T0 + H48 * 10), 0)
        self.assertEqual(self.lines, [])
        self.assertEqual(self.record(r.rid), rec)

    def test_finished_at_in_the_future_keeps(self):
        r = self.make_run(finished=T0 + timedelta(days=3))
        self.assertEqual(self.cleanup(T0 + H48), 0)
        self.assertTrue(r.adir.is_dir() and r.caps[0].is_dir())

    def test_hours_option_is_read_when_not_given(self):
        self.options(gate_cleanup_hours=2)
        r = self.make_run()
        lines = []
        self.assertEqual(G.cleanup_pass(now=T0 + timedelta(hours=2) - SEC, emit=lines.append), 0)
        self.assertEqual(G.cleanup_pass(now=T0 + timedelta(hours=2), emit=lines.append), 2)
        self.assertFalse(os.path.lexists(r.adir))

    def test_hours_zero_keeps_everything(self):
        r = self.make_run(captures=1)
        orphan_dir, _f, _rec = self.make_archive(self.new_rid())
        self.age_old(orphan_dir, T0 - timedelta(days=400))
        self.assertEqual(self.cleanup(T0 + timedelta(days=365), hours=0), 0)
        self.assertEqual(self.lines, [])
        self.options(gate_cleanup_hours=0)
        self.assertEqual(G.cleanup_pass(now=T0 + timedelta(days=365), emit=lambda s: None), 0)
        self.assertEqual(self.cmd("--apply"), 0)
        self.assertIn("gate_cleanup_hours=0 (automatic deletion off)", self.text)
        self.assertIn("gate_cleanup_hours=0: nothing is deleted automatically", self.text)
        self.assertTrue(r.adir.is_dir() and r.caps[0].is_dir() and orphan_dir.is_dir())
        self.assertIsNone(self.record(r.rid))

    def test_unfinished_run_is_no_run_target_and_its_captures_stay(self):
        r = self.make_run(finished=None, status="done")  # closed through bookkeeping: no finished_at
        self.assertEqual([t for t in G.cleanup_targets(self.gp, T0, 48) if t[0] == r.rid], [])
        self.age_old(r.adir, T0)
        self.assertEqual(self.cleanup(T0 + H48 - SEC), 0)
        self.assertTrue(r.adir.is_dir())
        self.assertEqual(self.cleanup(T0 + H48), 1)  # its archive as an orphan, by modification time
        self.assertIn(f"[cleanup] orphaned archive {r.rid}: deleted 1 item(s)", self.text)
        self.assertFalse(os.path.lexists(r.adir))
        self.assertTrue(r.caps[0].is_dir())

    def test_previous_and_current_runs_each_processed_once_current_wins(self):
        a = self.make_run(finished=T0, captures=1)
        b = self.make_run(finished=T0 + timedelta(hours=1), captures=2, current=True)
        # a stale copy of the current run in runs/ (unfinished): the current journal wins
        (b.rd / "journal.json").write_text(json.dumps({**b.j, "status": "hold", "finished_at": None}))
        runs, cur = G._run_journals(self.gp)
        self.assertEqual(sorted(runs), sorted([a.rid, b.rid]))
        self.assertEqual(cur["run_id"], b.rid)
        self.assertEqual(runs[b.rid]["status"], "done")
        targets = G.cleanup_targets(self.gp, T0, 48)
        self.assertEqual([t[1] for t in targets], [f"run {a.rid}", f"run {b.rid}"])
        self.assertEqual(self.cleanup(T0 + H48), 2)  # only a is due
        self.assertTrue(b.adir.is_dir())
        self.assertEqual(self.cleanup(T0 + H48 + timedelta(hours=1)), 3)
        self.assertEqual(sum(1 for x in self.lines if f"run {b.rid}: deleted" in x), 1, self.text)
        self.assertNotIn("orphaned", self.text)
        self.assertFalse(os.path.lexists(b.adir))
        self.assertEqual(self.record(b.rid)["deleted_at"], iso(T0 + H48 + timedelta(hours=1)))

    def test_corrupt_journals_are_ignored(self):
        a = self.make_run()
        (self.gp["RUNS"] / "junk").mkdir()
        (self.gp["RUNS"] / "junk" / "journal.json").write_text("[1, 2]")
        (self.gp["RUNS"] / "broken").mkdir()
        (self.gp["RUNS"] / "broken" / "journal.json").write_text("{not json")
        self.gp["JOURNAL"].write_text("{not json")
        runs, cur = G._run_journals(self.gp)
        self.assertEqual((list(runs), cur), ([a.rid], None))

    # ----- oc-upgrade cleanup -----------------------------------------------------------------------
    def test_dry_run_lists_and_deletes_nothing_then_apply_deletes_what_is_due(self):
        now = C.utc_now()
        old = self.make_run(finished=now - timedelta(hours=72), captures=1)
        link = self.caps / f"doctor-{uuid.uuid4()}"
        os.symlink(self.tmp, link)
        (old.rd / "doctor-pass2.log").write_text(self.capture_line(link) + "\n")
        fresh = self.make_run(finished=now - timedelta(hours=1), captures=1)
        orphan, _f, _r = self.make_archive(self.new_rid())
        self.age_old(orphan, now - timedelta(days=5))
        before = sorted(str(p) for p in self.tmp.rglob("*"))

        self.assertEqual(self.cmd(), 0)
        self.assertEqual(self.lines[0], "gate_cleanup_hours=48")
        self.assertIn(f"  run {old.rid}: due now", self.lines)
        self.assertIn(f"    {old.adir} (", self.text)
        self.assertIn(f"    {old.caps[0]} (", self.text)
        self.assertIn(f"    kept {link}: symlink", self.lines)
        due_fresh = C.utc_iso(datetime.strptime(fresh.j["finished_at"], "%Y-%m-%dT%H:%M:%SZ")
                              .replace(tzinfo=timezone.utc) + H48)
        self.assertIn(f"  run {fresh.rid}: due {due_fresh}", self.lines)
        self.assertIn(f"  orphaned archive {orphan.name}: due now", self.lines)
        self.assertEqual(sorted(str(p) for p in self.tmp.rglob("*")
                                if p.name not in (".lock",)), [p for p in before if not p.endswith("/.lock")])
        self.assertIsNone(self.record(old.rid))  # a dry run writes no cleanup record either

        self.assertEqual(self.cmd("--apply"), 0)
        self.assertIn("deleted 3 item(s)", self.lines[-1])
        self.assertFalse(os.path.lexists(old.adir) or os.path.lexists(old.caps[0]) or os.path.lexists(orphan))
        self.assertTrue(fresh.adir.is_dir() and fresh.caps[0].is_dir())
        self.assertTrue(os.path.islink(link))
        self.assertEqual(self.cmd(), 0)
        self.assertIn(f"  run {old.rid}: nothing left", self.lines)
        self.assertNotIn(f"orphaned archive {orphan.name}", self.text)

    def test_loop_refused_outside_runsh_and_usage_errors(self):
        self.assertNotIn("OC_GATE_FROM_RUNSH", os.environ)
        r = self.make_run(finished=C.utc_now() - timedelta(days=5))
        self.assertEqual(self.cmd("--loop"), 2)
        self.assertEqual(self.lines, ["oc-upgrade cleanup --loop is started by the add-on itself"])
        with mock.patch.dict(os.environ, {"OC_GATE_FROM_RUNSH": "0"}):
            self.assertEqual(self.cmd("--loop"), 2)
        for bad in (["--bogus"], ["--apply", "--loop"], ["--apply", "--apply"], ["--now"]):
            self.assertEqual(self.cmd(*bad), 2, bad)
            self.assertEqual(self.lines, ["usage: oc-upgrade cleanup [--apply]"])
        self.assertTrue(r.adir.is_dir() and r.caps[0].is_dir())

    # ----- blocked ------------------------------------------------------------------------------------
    def blocked_case(self, why_part, setup, teardown=None):
        prev = self.make_run(finished=T0, captures=1)
        setup()
        try:
            self.assertIn(why_part, G.cleanup_blocked(self.gp, G._run_journals(self.gp)[1]) or "")
            state = {}
            self.assertEqual(self.cleanup(T0 + H48 * 3, state=state), 0)
            self.assertEqual(len(self.lines), 1, self.text)
            self.assertTrue(self.lines[0].startswith("[cleanup] paused: ") and why_part in self.lines[0],
                            self.text)
            self.assertEqual(self.cleanup(T0 + H48 * 3, state=state), 0)
            self.assertEqual(self.lines, [])  # once per change of state
            self.assertTrue(prev.adir.is_dir() and prev.caps[0].is_dir())
            self.assertIsNone(self.record(prev.rid))
            self.assertEqual(self.cmd(), 0)
            self.assertIn("; paused: ", self.lines[0])
            self.assertIn(why_part, self.lines[0])
            self.assertEqual(self.cmd("--apply"), 1)
            self.assertIn("not deleting now: ", self.lines[-1])
            self.assertTrue(prev.adir.is_dir() and prev.caps[0].is_dir())
        finally:
            if teardown:
                teardown()
        return prev, state

    def test_blocked_by_hold_txt(self):
        self.make_run(finished=T0, current=True, captures=0)
        prev, state = self.blocked_case("hold", lambda: (self.upg / "hold.txt").write_text("HOLD x\n"))
        (self.upg / "hold.txt").unlink()
        self.assertEqual(self.cleanup(T0 + H48 * 3, state=state), 3)
        self.assertNotIn("paused", self.text)
        self.assertFalse(os.path.lexists(prev.adir))

    def test_blocked_by_journal_status(self):
        for status in ("running", "interrupted", "hold"):
            with self.subTest(status):
                cur = self.make_run(finished=None, status=status, current=True, captures=1)
                self.age_old(cur.adir, T0 - timedelta(days=30))  # an old archive of the active run: never
                prev, _state = self.blocked_case(f"gate run {cur.rid} is {status}", lambda: None)
                self.assertTrue(cur.adir.is_dir() and cur.caps[0].is_dir())

    def test_blocked_by_post_run_hold_of_a_finished_run(self):
        cur = self.make_run(finished=T0, status="hold", current=True, captures=1,
                            hold={"code": "crash-loop", "phase": "post-run", "acceptable": False})
        self.blocked_case(f"gate run {cur.rid} is hold", lambda: None)
        self.assertTrue(cur.adir.is_dir() and cur.caps[0].is_dir())

    def test_blocked_by_pending_retry(self):
        self.make_run(finished=T0, current=True, captures=0)
        self.blocked_case("a retry request is pending",
                          lambda: self.gp["RETRY"].write_text(json.dumps({"doctor": False, "accept": []})))

    def test_blocked_by_held_gate_lock_and_lock_free_afterwards(self):
        self.make_run(finished=T0, current=True, captures=0)
        fds = []

        def take():
            fd = os.open(str(self.gp["LOCK"]), os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fds.append(fd)

        prev, state = self.blocked_case("the gate is running", take, lambda: [os.close(f) for f in fds])
        fd = G._try_lock(self.gp)  # the cleanup's probe never keeps the gate lock
        self.assertIsNotNone(fd)
        os.close(fd)
        self.assertEqual(self.cleanup(T0 + H48 * 3, state=state), 3)  # previous run (2) + current archive
        self.assertFalse(os.path.lexists(prev.adir))
        fd = G._try_lock(self.gp)
        self.assertIsNotNone(fd)
        os.close(fd)

    def test_busy_cleanup_lock_skips_quietly(self):
        r = self.make_run()
        fd = os.open(str(self.gp["GATE"] / ".cleanup.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.cleanup(T0 + H48), 0)
            self.assertEqual(self.lines, [])
            self.assertTrue(r.adir.is_dir())
        finally:
            os.close(fd)
        self.assertEqual(self.cleanup(T0 + H48), 2)

    # ----- orphans, rehearsal exports ---------------------------------------------------------------
    def test_orphan_archive_dirs(self):
        old = T0 - timedelta(days=10)
        orphan, _f, _r = self.make_archive(self.new_rid())
        self.age_old(orphan, old)
        young, _f, _r = self.make_archive(self.new_rid())
        self.age_old(young, T0 + H48 + timedelta(hours=1))
        unfinished = self.make_run(finished=None, status="abandoned", captures=1)
        self.age_old(unfinished.adir, old)
        notrun = self.arch / "not-a-run"
        notrun.mkdir()
        (notrun / "x.tar.gz").write_bytes(b"\x1f\x8b")
        upper = self.arch / "20261001T120000Z-ABCDEF"
        upper.mkdir()
        nested = self.arch / "sub" / self.new_rid()
        nested.mkdir(parents=True)
        victim = self.tmp / "victim"
        victim.mkdir()
        (victim / "precious.txt").write_text("keep me")
        linked = self.arch / self.new_rid()
        os.symlink(victim, linked)
        filename = self.arch / self.new_rid()
        filename.write_text("a file with a run-id name")
        (self.arch / "notes.txt").write_text("user notes")
        elsewhere = self.share / "other" / self.new_rid()
        elsewhere.mkdir(parents=True)
        for p in (notrun, upper, nested, nested.parent, linked, filename, self.arch / "notes.txt", elsewhere):
            self.age_old(p, old)
        current = self.make_run(finished=T0, current=True, captures=0)  # its archive is not due yet
        self.age_old(current.adir, old)

        labels = [t[1] for t in G.cleanup_targets(self.gp, T0, 48)]
        self.assertIn(f"orphaned archive {orphan.name}", labels)
        self.assertIn(f"orphaned archive {unfinished.rid}", labels)
        self.assertNotIn(f"orphaned archive {current.rid}", labels)
        self.assertEqual(self.cleanup(T0 + timedelta(hours=1)), 2)
        self.assertFalse(os.path.lexists(orphan))
        self.assertFalse(os.path.lexists(unfinished.adir))
        self.assertTrue(unfinished.caps[0].is_dir())  # captures of an unfinished run are never guessed at
        for p in (young, notrun, upper, nested, filename, self.arch / "notes.txt", elsewhere, current.adir):
            self.assertTrue(os.path.lexists(p), p)
        self.assertTrue(os.path.islink(linked))
        self.assertEqual((victim / "precious.txt").read_text(), "keep me")
        self.assertEqual(self.cleanup(T0 + timedelta(hours=1)), 0)
        self.assertEqual(self.cleanup(T0 + H48), 1)  # the current run's archive (finished T0) is due now
        self.assertFalse(os.path.lexists(current.adir))
        self.assertTrue(young.is_dir())  # an orphan is due by its own mtime (T0 + 49 h + 48 h)

    def test_symlinked_archives_root_is_never_walked(self):
        real = self.tmp / "real-archives"
        real.mkdir()
        self.share.mkdir(exist_ok=True)
        os.symlink(real, self.arch)
        orphan, _f, _r = self.make_archive(self.new_rid(), root=real)
        self.age_old(orphan, T0 - timedelta(days=10))
        r = self.make_run(archive=None, captures=0)
        (real / r.rid).mkdir()
        self.assertFalse(G._archive_dir_ok(self.gp, self.arch / r.rid))
        self.assertEqual(self.cleanup(T0 + H48), 0)
        self.assertTrue(orphan.is_dir() and (real / r.rid).is_dir())
        self.assertIn(f"WARN [cleanup] run {r.rid}: kept {self.arch / r.rid}: not a plain run directory", self.text)

    def test_journal_run_id_that_is_no_run_id_never_reaches_outside(self):
        victim = self.share / "victim"
        victim.mkdir()
        (victim / "precious.txt").write_text("keep me")
        self.arch.mkdir(parents=True)
        for bad in ("bad-id", "../victim"):
            with self.subTest(bad):
                r = self.make_run(rid=self.new_rid(), archive=None, captures=1)
                j = dict(r.j, run_id=bad)
                (r.rd / "journal.json").write_text(json.dumps(j))
                if bad == "bad-id":
                    (self.arch / bad).mkdir(parents=True)
                kept = [t[4] for t in G.cleanup_targets(self.gp, T0 + H48, 48) if t[0] == bad]
                if bad == "bad-id":
                    self.assertEqual(kept, [[(str(self.arch / bad), "not a plain run directory")]])
                else:  # not one safe path component: the journal is ignored altogether
                    self.assertEqual(kept, [])
                self.cleanup(T0 + H48)
                self.assertTrue(os.path.lexists(self.arch / bad))
        self.assertEqual((victim / "precious.txt").read_text(), "keep me")

    def test_journal_archive_dir_outside_the_archives_root_is_never_deleted(self):
        r = self.make_run(captures=0)
        elsewhere = self.root / "not-an-archive" / r.rid
        elsewhere.mkdir(parents=True)
        (elsewhere / "precious.txt").write_text("keep me")
        (r.rd / "journal.json").write_text(json.dumps({**r.j, "archive": {**r.j["archive"], "dir": str(elsewhere)}}))
        self.assertEqual(self.cleanup(T0 + H48), 1)  # only /share/openclaw-upgrade/<run>
        self.assertFalse(os.path.lexists(r.adir))
        self.assertEqual((elsewhere / "precious.txt").read_text(), "keep me")

    def test_delete_tree_returns_the_size_and_leaves_no_tombstone(self):
        d = self.arch / self.new_rid()
        (d / "sub").mkdir(parents=True)
        (d / "a").write_bytes(b"x" * 1000)
        (d / "sub" / "b").write_bytes(b"y" * 24)
        victim = self.tmp / "victim.txt"
        victim.write_text("keep me")
        os.symlink(victim, d / "link")
        self.assertEqual(G._delete_tree(d), 1024)  # regular files only; the link is not followed
        self.assertEqual(list(self.arch.iterdir()), [])
        self.assertEqual(victim.read_text(), "keep me")

    def test_archive_dir_ok(self):
        rid = self.new_rid()
        good, _f, _r = self.make_archive(rid)
        self.assertTrue(G._archive_dir_ok(self.gp, good))
        victim = self.tmp / "victim"
        victim.mkdir()
        link = self.arch / self.new_rid()
        os.symlink(victim, link)
        self.assertFalse(G._archive_dir_ok(self.gp, link))
        bad = self.arch / "20261001-120000-abc"
        bad.mkdir()
        self.assertFalse(G._archive_dir_ok(self.gp, bad))
        nested = self.arch / rid / self.new_rid()
        nested.mkdir()
        self.assertFalse(G._archive_dir_ok(self.gp, nested))
        self.assertFalse(G._archive_dir_ok(self.gp, self.arch / self.new_rid()))  # missing
        f = self.arch / self.new_rid()
        f.write_text("x")
        self.assertFalse(G._archive_dir_ok(self.gp, f))

    def test_finished_run_whose_archive_path_is_a_symlink_is_kept(self):
        victim = self.tmp / "victim"
        victim.mkdir()
        (victim / "precious.txt").write_text("keep me")
        r = self.make_run(archive=None, captures=1)
        self.arch.mkdir(parents=True, exist_ok=True)
        os.symlink(victim, self.arch / r.rid)
        self.assertEqual(self.cleanup(T0 + H48), 1)  # the capture only
        self.assertIn(f"WARN [cleanup] run {r.rid}: kept {self.arch / r.rid}: not a plain run directory",
                      self.text)
        self.assertTrue(os.path.islink(self.arch / r.rid))
        self.assertEqual((victim / "precious.txt").read_text(), "keep me")

    def test_rehearsal_exports_deleted_young_ones_and_links_kept(self):
        reh = self.share / "openclaw-rehearsal"
        old = T0 - timedelta(days=3)

        def export(ts, name, when):
            d = reh / ts
            d.mkdir(parents=True, exist_ok=True)
            f = d / name
            f.write_bytes(b"\x1f\x8b" + b"x" * 100)
            (d / "manifest.txt").write_text("contains_secrets=yes\n")
            self.age_old(f, when)
            return d

        plain = export("20260901-000000", "openclaw-rehearsal.tar.gz", old)
        tmp = export("20260902-000000", "openclaw-rehearsal.tar.gz.tmp", old)
        enc = export("20260903-000000", "openclaw-rehearsal.tar.gz.age", old)
        enc_tmp = export("20260904-000000", "openclaw-rehearsal.tar.gz.age.tmp", old)
        young = export("20260905-000000", "openclaw-rehearsal.tar.gz", T0)
        victim = self.tmp / "victim"
        victim.mkdir()
        (victim / "openclaw-rehearsal.tar.gz").write_bytes(b"\x1f\x8b precious")
        self.age_old(victim / "openclaw-rehearsal.tar.gz", old)
        linkfile = reh / "20260907-000000"
        linkfile.mkdir()
        os.symlink(victim / "openclaw-rehearsal.tar.gz", linkfile / "openclaw-rehearsal.tar.gz")
        # an encrypted gate archive of a run that is not due yet stays as well
        r = self.make_run(finished=T0, captures=0)

        self.assertEqual(self.cleanup(T0 + timedelta(hours=1)), 4)  # encrypted exports go as well
        self.assertIn("[cleanup] plaintext rehearsal export 20260901-000000: deleted 1 item(s)", self.text)
        self.assertIn("[cleanup] plaintext rehearsal export 20260902-000000: deleted 1 item(s)", self.text)
        self.assertIn("[cleanup] encrypted rehearsal export 20260903-000000: deleted 1 item(s)", self.text)
        self.assertIn("[cleanup] encrypted rehearsal export 20260904-000000: deleted 1 item(s)", self.text)
        for d in (plain, tmp, enc, enc_tmp):
            self.assertFalse(os.path.lexists(d), d)
        for d in (young, linkfile, r.adir):
            self.assertTrue(d.is_dir(), d)
        self.assertEqual((victim / "openclaw-rehearsal.tar.gz").read_bytes(), b"\x1f\x8b precious")
        self.assertTrue((linkfile / "openclaw-rehearsal.tar.gz").is_symlink())
        self.assertEqual(self.cleanup(T0 + H48), 2)  # the young export and the run's archive are due now
        self.assertFalse(os.path.lexists(young) or os.path.lexists(r.adir))
        self.assertEqual((victim / "openclaw-rehearsal.tar.gz").read_bytes(), b"\x1f\x8b precious")

    # ----- tombstones -------------------------------------------------------------------------------
    def test_interrupted_archive_delete_is_finished_on_the_next_pass(self):
        r = self.make_run(captures=0)
        with mock.patch.object(G.shutil, "rmtree", lambda *a, **kw: None):  # nothing removed after the rename
            self.assertEqual(self.cleanup(T0 + H48), 0)  # never claimed as deleted
        tomb = self.arch / f".oc-addon-deleting-{r.rid}"
        self.assertTrue(any("could not delete" in x and "not completely removed" in x for x in self.lines), self.lines)
        self.assertTrue(tomb.is_dir())
        self.assertFalse(os.path.lexists(r.adir))  # never a half archive under its real name
        self.assertEqual([t[1] for t in G.cleanup_targets(self.gp, T0, 48) if t[0] is None],
                         [f"leftover {tomb.name}"])
        self.assertEqual(self.cmd(), 0)
        self.assertIn(f"  leftover {tomb.name}: due now", self.lines)
        self.assertEqual(self.cleanup(T0 + H48 + SEC), 1)
        self.assertIn(f"[cleanup] leftover {tomb.name}: deleted 1 item(s)", self.text)
        self.assertEqual(list(self.arch.iterdir()), [])
        self.assertEqual(self.cleanup(T0 + H48 + SEC), 0)
        self.assertEqual(self.lines, [])

    def test_leftover_tombstone_is_removed_even_before_any_run_is_due(self):
        tomb = self.arch / ".oc-addon-deleting-20260101T000000Z-abcdef"
        (tomb / "deep").mkdir(parents=True)
        (tomb / "deep" / "x.tar.gz.age").write_bytes(G.AGE_MAGIC)
        r = self.make_run(finished=T0)
        self.assertEqual(self.cleanup(T0), 1)
        self.assertFalse(os.path.lexists(tomb))
        self.assertTrue(r.adir.is_dir())

    def test_symlinked_tombstone_never_deletes_its_target(self):
        victim = self.tmp / "victim"
        victim.mkdir()
        (victim / "precious.txt").write_text("keep me")
        self.arch.mkdir(parents=True)
        os.symlink(victim, self.arch / ".oc-addon-deleting-x")
        for i in range(2):
            self.cleanup(T0 + timedelta(hours=i))
        self.assertEqual((victim / "precious.txt").read_text(), "keep me")

    def test_symlinked_rehearsal_dir_never_deletes_its_target(self):
        reh = self.share / "openclaw-rehearsal"
        reh.mkdir(parents=True)
        victim = self.tmp / "victim"
        victim.mkdir()
        (victim / "openclaw-rehearsal.tar.gz").write_bytes(b"\x1f\x8b precious")
        (victim / "other.txt").write_text("keep me")
        self.age_old(victim / "openclaw-rehearsal.tar.gz", T0 - timedelta(days=3))
        os.symlink(victim, reh / "20260906-000000")
        for i in range(3):
            self.cleanup(T0 + timedelta(hours=1 + i))
        self.assertEqual((victim / "openclaw-rehearsal.tar.gz").read_bytes(), b"\x1f\x8b precious")
        self.assertEqual((victim / "other.txt").read_text(), "keep me")

    # Regression: a symlink among the cleanup targets is never renamed again and again (the link itself is
    # removed or left alone, the target is never touched) and a pass never claims a deletion it did not do.
    def test_symlink_targets_are_not_renamed_again_and_again(self):
        reh = self.share / "openclaw-rehearsal"
        reh.mkdir(parents=True)
        victim = self.tmp / "victim"
        victim.mkdir()
        (victim / "openclaw-rehearsal.tar.gz").write_bytes(b"\x1f\x8b precious")
        self.age_old(victim / "openclaw-rehearsal.tar.gz", T0 - timedelta(days=3))
        os.symlink(victim, reh / "20260906-000000")
        self.arch.mkdir(parents=True)
        os.symlink(victim, self.arch / ".oc-addon-deleting-x")
        claims = 0
        for i in range(3):
            self.cleanup(T0 + timedelta(hours=1 + i))
            claims += sum(1 for x in self.lines if ": deleted " in x)
        names = sorted(os.listdir(reh)) + sorted(os.listdir(self.arch))
        self.assertFalse([n for n in names if n.startswith(".oc-addon-deleting-.oc-addon-deleting-")], names)
        self.assertLessEqual(claims, 2)

    # Regression: a doctor-capture delete interrupted after the rename (a .oc-addon-deleting-doctor-<uuid>
    # tombstone holding a pre-repair database copy) is finished on the next pass.
    def test_interrupted_capture_delete_is_finished_on_the_next_pass(self):
        r = self.make_run(archive=None, captures=1)
        cap = r.caps[0]
        with mock.patch.object(G.shutil, "rmtree", lambda *a, **kw: None):
            self.assertEqual(self.cleanup(T0 + H48), 0)
        tomb = self.caps / f".oc-addon-deleting-{cap.name}"
        self.assertTrue(tomb.is_dir())
        self.cleanup(T0 + H48 + SEC)
        self.assertFalse(os.path.lexists(tomb), "leftover capture tombstone was not removed")

    # ----- WARN once --------------------------------------------------------------------------------
    # Regression: a "kept" WARN is recorded in runs/<run>/cleanup.json and printed once, also for a run with
    # nothing else left to delete.
    def test_kept_warning_is_logged_once_for_a_run_with_nothing_else_to_delete(self):
        victim = self.tmp / "victim"
        victim.mkdir()
        link = self.caps / f"doctor-{uuid.uuid4()}"
        self.caps.mkdir(parents=True, exist_ok=True)
        os.symlink(victim, link)
        r = self.make_run(archive="off", captures=0, extra_lines=[self.capture_line(link)])
        self.cleanup(T0 + H48)
        self.assertEqual(self.lines, [f"WARN [cleanup] run {r.rid}: kept {link}: symlink"])
        self.cleanup(T0 + H48 + timedelta(hours=1))
        self.assertEqual(self.lines, [])

    # ----- closed current run ----------------------------------------------------------------------
    # Regression: the archive of a closed current run (abandoned, or done without finished_at) is deleted like
    # an orphan; only a run that can still continue keeps its archive.
    def test_archive_of_a_closed_current_run_is_deleted_like_an_orphan(self):
        r = self.make_run(finished=None, status="abandoned", archive="plain", captures=0, current=True)
        self.age_old(r.adir, T0)
        self.assertIsNone(G.cleanup_blocked(self.gp, G._run_journals(self.gp)[1]))
        self.assertEqual(self.cleanup(T0 + H48), 1)
        self.assertFalse(os.path.lexists(r.adir), "plaintext archive of the abandoned current run kept")

    def test_archive_of_an_active_current_run_is_never_an_orphan(self):
        for status in ("running", "interrupted", "hold"):
            with self.subTest(status):
                cur = {"run_id": self.new_rid(), "status": status, "finished_at": None}
                self.write_current(cur)
                adir, _f, _r = self.make_archive(cur["run_id"])
                self.age_old(adir, T0 - timedelta(days=30))
                self.assertNotIn(f"orphaned archive {cur['run_id']}",
                                 [t[1] for t in G.cleanup_targets(self.gp, T0 + H48, 48)])
                self.assertEqual(self.cleanup(T0 + H48), 0)
                self.assertTrue(adir.is_dir())

    # ----- cleanup_loop -----------------------------------------------------------------------------
    def test_loop_stops_promptly_when_stop_is_set(self):
        self.protect_signals()
        self.hooks(cleanup_interval_s=60)
        r = self.make_run(finished=C.utc_now() - timedelta(days=5))
        lines = []
        timer = threading.Timer(0.3, G.STOP.set)
        timer.start()
        t = time.monotonic()
        try:
            rc = G.cleanup_loop(emit=lines.append)
        finally:
            timer.join()
        self.assertLess(time.monotonic() - t, 10)
        self.assertEqual(rc, 143)
        self.assertEqual(lines[0], "[cleanup] gate archives and doctor captures are deleted 48 h after their gate "
                                   "run (checked hourly)")
        self.assertFalse(os.path.lexists(r.adir))  # the first pass runs at once

    def test_loop_exits_143_on_sigterm(self):
        self.protect_signals()
        self.hooks(cleanup_interval_s=60)
        lines = []
        timer = threading.Timer(0.3, os.kill, (os.getpid(), signal.SIGTERM))
        timer.start()
        t = time.monotonic()
        try:
            rc = G.cleanup_loop(emit=lines.append)
        finally:
            timer.join()
        self.assertEqual(rc, 143)
        self.assertLess(time.monotonic() - t, 10)
        self.assertTrue(G.STOP.is_set())

    def test_loop_repeats_passes_and_survives_a_failing_one(self):
        self.protect_signals()
        self.hooks(cleanup_interval_s=0.01)
        calls = []
        token = "tok" + "A1b2C3d4" * 6  # a 51-character token-like string in the exception text

        def fake_pass(now=None, hours=None, emit=None, state=None):
            calls.append((now, hours, state))
            if len(calls) == 1:
                raise RuntimeError(f"boom {token}")
            if len(calls) >= 3:
                G.STOP.set()
            return 0

        lines = []
        with mock.patch.object(G, "cleanup_pass", side_effect=fake_pass):
            rc = G.cleanup_loop(emit=lines.append)
        self.assertEqual(rc, 143)
        self.assertEqual(len(calls), 3)
        self.assertIs(calls[1][2], calls[2][2])  # one state dict across passes (pause logged once)
        self.assertEqual(calls[0][1], 48)
        warn = [x for x in lines if x.startswith("WARN [cleanup] pass failed: RuntimeError: boom")]
        self.assertEqual(len(warn), 1, lines)
        self.assertNotIn(token, "\n".join(lines))

    def test_loop_clock_offset_hook_makes_items_due(self):
        self.protect_signals()
        self.hooks(cleanup_interval_s=0.01, cleanup_clock_offset_s=48 * 3600)
        r = self.make_run(finished=C.utc_now() - timedelta(minutes=5), captures=1)
        real_pass = G.cleanup_pass
        nows = []

        def one_pass(**kw):
            nows.append(kw["now"])
            try:
                return real_pass(**kw)
            finally:
                G.STOP.set()

        lines = []
        with mock.patch.object(G, "cleanup_pass", side_effect=one_pass):
            G.cleanup_loop(emit=lines.append)
        self.assertGreater(nows[0] - C.utc_now(), timedelta(hours=47))
        self.assertFalse(os.path.lexists(r.adir) or os.path.lexists(r.caps[0]), "\n".join(lines))

    def test_loop_hooks_ignored_without_test_hooks_env(self):
        self.protect_signals()
        self.hooks(cleanup_interval_s=0.01, cleanup_clock_offset_s=48 * 3600)
        os.environ["OC_GATE_TEST_HOOKS"] = "0"
        r = self.make_run(finished=C.utc_now() - timedelta(minutes=5), captures=1)
        real_pass = G.cleanup_pass
        nows = []

        def one_pass(**kw):
            nows.append(kw["now"])
            try:
                return real_pass(**kw)
            finally:
                G.STOP.set()

        with mock.patch.object(G, "cleanup_pass", side_effect=one_pass), \
                mock.patch.object(G.STOP, "wait", wraps=G.STOP.wait) as waited:
            G.cleanup_loop(emit=lambda s: None)
        self.assertLess(abs(nows[0] - C.utc_now()), timedelta(minutes=5))
        self.assertEqual(waited.call_args[0][0], float(G.CLEANUP_INTERVAL_S))
        self.assertTrue(r.adir.is_dir() and r.caps[0].is_dir())

    def test_loop_with_hours_zero_idles_and_deletes_nothing(self):
        # it never exits early (run.sh keeps one known child) and re-reads the option at every check
        self.protect_signals()
        self.hooks(cleanup_interval_s=0.01)
        self.options(gate_cleanup_hours=0)
        r = self.make_run(finished=C.utc_now() - timedelta(days=30))
        lines = []
        timer = threading.Timer(0.3, G.STOP.set)
        timer.start()
        try:
            self.assertEqual(G.cleanup_loop(emit=lines.append), 143)
        finally:
            timer.cancel()
        self.assertEqual(lines, ["[cleanup] gate_cleanup_hours=0: automatic deletion is off (oc-upgrade cleanup "
                                 "lists what to delete)"])
        self.assertTrue(r.adir.is_dir())

    def test_loop_picks_up_a_changed_cleanup_option(self):
        self.protect_signals()
        self.hooks(cleanup_interval_s=0.01)
        self.options(gate_cleanup_hours=0)
        r = self.make_run(finished=C.utc_now() - timedelta(days=30))
        real_pass, n = G.cleanup_pass, [0]

        def counting_pass(**kw):
            n[0] += 1
            if n[0] == 3:
                self.options(gate_cleanup_hours=48)  # the owner changes the option while the loop runs
            try:
                return real_pass(**kw)
            finally:
                if not os.path.lexists(r.adir):
                    G.STOP.set()
                elif n[0] > 200:
                    G.STOP.set()

        lines = []
        with mock.patch.object(G, "cleanup_pass", side_effect=counting_pass):
            G.cleanup_loop(emit=lines.append)
        self.assertFalse(os.path.lexists(r.adir), "\n".join(lines))

    def test_loop_pauses_during_a_hold_and_resumes_after_it(self):
        self.protect_signals()
        self.hooks(cleanup_interval_s=0.01)
        r = self.make_run(finished=C.utc_now() - timedelta(days=5))
        (self.upg / "hold.txt").write_text("HOLD crash-loop\n")
        real_pass = G.cleanup_pass
        n = [0]

        def counted(**kw):
            n[0] += 1
            if n[0] == 3:
                (self.upg / "hold.txt").unlink()
            rv = real_pass(**kw)
            if n[0] >= 4:
                G.STOP.set()
            return rv

        lines = []
        with mock.patch.object(G, "cleanup_pass", side_effect=counted):
            G.cleanup_loop(emit=lines.append)
        self.assertEqual(lines.count("[cleanup] paused: hold"), 1, lines)
        self.assertFalse(os.path.lexists(r.adir))


class StatusTests(CleanupEnv):
    def status(self):
        self.st = "\n".join(G.status_lines())
        return self.st

    def line(self, prefix):
        hits = [x for x in self.st.splitlines() if x.lstrip().startswith(prefix)]
        self.assertEqual(len(hits), 1, f"{prefix!r} in:\n{self.st}")
        return hits[0]

    @NEEDS_AGE
    def test_encrypted_run_short_recipient_cleanup_progress_and_captures(self):
        j, caps = self.real_gate_with_captures()
        short = C.short_recipient(T.AGE_PUB)
        self.status()
        a = self.line("archive: ")
        want = f"  archive: encrypted (age, {short}) {j['archive']['dir']}/{j['archive']['file']}"
        self.assertTrue(a.startswith(want), a)
        self.assertIn(f"sha256 {j['archive']['sha256'][:12]}…", a)
        self.assertNotIn("auto-delete", a)
        self.assertEqual(self.line("Gate options: "),
                         f"Gate options: gate_archive encrypted to {short}; delete archives/doctor captures 48 h after "
                         "a run (0 = never); backup max age 24 h")
        self.assertEqual(self.line("Gate archives in /share"), "Gate archives in /share:")
        f = Path(j["archive"]["dir"]) / j["archive"]["file"]
        self.assertIn(f"  {f} (", self.st)
        self.assertTrue(self.line(str(f)).endswith(", encrypted)"))
        self.assertEqual(self.line("Doctor captures: "),
                         f"Doctor captures: 2 in {self.caps} (pre-repair database copies; deleted with their gate run)")
        self.assertNotIn(T.AGE_PUB, self.st)
        self.assertNotIn("SECRET", self.st)
        self.assertNotIn("HA backup checked", self.st)  # skip_backup_check hook: nothing recorded

        fin = datetime.strptime(j["finished_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        self.cleanup(fin)
        self.status()
        self.assertTrue(self.line("archive: ").endswith(f"; auto-delete due {iso(fin + H48)}"), self.st)
        self.cleanup(fin + H48)
        self.status()
        self.assertTrue(self.line("archive: ").endswith(f"; deleted {iso(fin + H48)}"), self.st)
        self.assertEqual(self.line("Gate archives in /share"), "Gate archives in /share: none")
        self.assertEqual(self.line("Doctor captures: ").split(" (")[0], f"Doctor captures: 0 in {self.caps}")
        self.assertNotIn(T.AGE_PUB, self.st)

    def test_off_run_lines(self):
        self.base_options = {"gate_archive": "off"}
        self.options()
        self.build_735()
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertEqual(j["archive"]["mode"], "off")
        self.status()
        self.assertEqual(self.line("archive: "), "  archive: off for this run (gate_archive: off)")
        self.assertEqual(self.line("Gate options: "),
                         "Gate options: gate_archive off; delete archives/doctor captures 48 h after a run "
                         "(0 = never); backup max age 24 h")
        self.assertEqual(self.line("Gate archives in /share"), "Gate archives in /share: none")
        self.assertNotIn("Doctor captures:", self.st)  # no capture root yet
        self.assertNotIn("SECRET", self.st)

    def test_legacy_plaintext_run_and_archive_kinds(self):
        r = self.make_run(archive="plain", captures=0, current=True)
        enc_dir, enc_file, _rec = self.make_archive(self.new_rid())
        (self.gp["RUNS"] / r.rid / "cleanup.json").write_text(json.dumps({"schema": 1, "due_at": iso(T0 + H48)}))
        self.status()
        a = self.line("archive: ")
        self.assertTrue(a.startswith(f"  archive: {r.adir}/{r.afile.name} PLAINTEXT (0.5.94-full1) ("), a)
        self.assertTrue(a.endswith(f"; auto-delete due {iso(T0 + H48)}"), a)
        self.assertIn(f"sha256 {r.j['archive']['sha256'][:12]}…", a)
        self.assertTrue(self.line(str(r.afile)).endswith(", PLAINTEXT from 0.5.94-full1: unencrypted secrets)"))
        self.assertTrue(self.line(str(enc_file)).endswith(", encrypted)"))
        sha = (r.adir / "SHA256SUMS").read_text().split()[0][:12]
        self.assertIn(f"sha256 {sha}…", self.line(str(r.afile)))

    def test_encrypted_journal_record_uses_the_short_recipient(self):
        r = self.make_run(archive="age", captures=0, current=True)
        self.status()
        a = self.line("archive: ")
        self.assertIn(f"encrypted (age, {C.short_recipient(FAKE_PUB)})", a)
        self.assertNotIn(FAKE_PUB, self.st)
        self.assertEqual(C.short_recipient(FAKE_PUB), FAKE_PUB[:9] + "…" + FAKE_PUB[-6:])
        self.assertIn(str(r.afile), self.st)

    def test_ha_backup_line_and_tokens_never_printed(self):
        sv_token = "svtok-" + "Zx9" * 15
        token_file = self.tmp / "supervisor-token"
        token_file.write_text(sv_token + "\n")
        self.hooks(supervisor_token_file=str(token_file))
        os.environ["SUPERVISOR_TOKEN"] = sv_token
        os.environ["HASSIO_TOKEN"] = sv_token
        self.make_run(captures=0, current=True, ha_backup={
            "name": "Full backup 2026-10-01", "slug": "a1b2c3d4", "date": "2026-10-01T10:00:00Z",
            "addon_version": "0.5.93", "protected": True})
        self.status()
        self.assertEqual(self.line("HA backup checked: "),
                         "  HA backup checked: 'Full backup 2026-10-01' (a1b2c3d4, 2026-10-01T10:00:00Z, "
                         "add-on 0.5.93)")
        self.assertNotIn(sv_token, self.st)
        self.assertNotIn("svtok", self.st)
        # an older record without the add-on version
        self.make_run(captures=0, current=True, ha_backup={"name": "b", "slug": "s", "date": "d"})
        self.status()
        self.assertEqual(self.line("HA backup checked: "), "  HA backup checked: 'b' (s, d, add-on ?)")

    def test_gate_options_line_problem_codes_never_values(self):
        priv = (T.AGE_IDENTITY or "AGE-SECRET-KEY-1" + "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L" * 2)[:74]
        cases = [
            ({"gate_archive": "encrypted", "gate_archive_age_recipient": ""},
             "Gate options: gate_archive encrypted (problem: missing); "),
            ({"gate_archive": "encrypted", "gate_archive_age_recipient": priv},
             "Gate options: gate_archive encrypted (problem: private-key); "),
            ({"gate_archive": "encrypted", "gate_archive_age_recipient": "age1-not-a-key-but-long-enough-to-show"},
             "Gate options: gate_archive encrypted (problem: malformed); "),
            ({"gate_archive": "plaintext"}, "Gate options: gate_archive ? (problem: invalid-mode); "),
            ({"gate_archive": "encrypted", "gate_archive_age_recipient": f"  {FAKE_PUB}\n"},
             f"Gate options: gate_archive encrypted to {C.short_recipient(FAKE_PUB)}; "),
        ]
        for opts, want in cases:
            with self.subTest(want):
                self.base_options = opts
                self.options()
                self.status()
                self.assertTrue(self.line("Gate options: ").startswith(want), self.st)
                rec = opts.get("gate_archive_age_recipient", "").strip()
                if rec and rec != FAKE_PUB:
                    self.assertNotIn(rec, self.st)
                    self.assertNotIn(rec[16:40], self.st)
                self.assertNotIn(FAKE_PUB, self.st)
        self.base_options = {"gate_archive": "off"}
        self.options(gate_cleanup_hours=0, gate_backup_max_age_hours=72)
        self.status()
        self.assertEqual(self.line("Gate options: "),
                         "Gate options: gate_archive off; delete archives/doctor captures 0 h after a run (0 = never); "
                         "backup max age 72 h")

    def test_doctor_captures_count_only_doctor_uuid_dirs(self):
        for _ in range(3):
            self.capture()
        self.capture(name="doctor-not-a-uuid")
        (self.caps / "README").write_text("x")
        (self.caps / f".oc-addon-deleting-doctor-{uuid.uuid4()}").mkdir()  # still a copy on disk until deleted
        self.status()
        self.assertTrue(self.line("Doctor captures: ").startswith(f"Doctor captures: 4 in {self.caps} "), self.st)

    def test_no_run_recorded(self):
        self.status()
        self.assertIn("Gate: no run recorded.", self.st)
        self.assertTrue(self.line("Gate options: ").startswith("Gate options: gate_archive "))
        self.assertEqual(self.line("Gate archives in /share"), "Gate archives in /share: none")

    def test_readiness_archive_preview_agrees_with_status_options(self):
        self.build_735()
        self.hooks()
        cases = [({"gate_archive": "off"}, "[gate]   archive: off (rollback only through the encrypted Home "
                                           "Assistant backup)", "gate_archive off;"),
                 ({"gate_archive": "encrypted", "gate_archive_age_recipient": ""}, "[gate]   archive: NOT CONFIGURED",
                  "gate_archive encrypted (problem: missing)")]
        if T.HAVE_AGE:
            short = C.short_recipient(T.AGE_PUB)
            cases.append(({"gate_archive": "encrypted", "gate_archive_age_recipient": T.AGE_PUB},
                          f"[gate]   archive: encrypted to {short} -> ", f"gate_archive encrypted to {short};"))
        for opts, ready, opt_line in cases:
            with self.subTest(ready):
                self.base_options = opts
                self.options()
                lines = []
                G.dry_run(emit=lines.append)
                text = "\n".join(lines)
                self.assertTrue(any(x.startswith(ready) for x in lines), text)
                self.status()
                self.assertIn(opt_line, self.line("Gate options: "))
                if T.HAVE_AGE:
                    self.assertNotIn(T.AGE_PUB, text + self.st)
                self.assertNotIn("SECRET", text + self.st)


if __name__ == "__main__":
    unittest.main()
