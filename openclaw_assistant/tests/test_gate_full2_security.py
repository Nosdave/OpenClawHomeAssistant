"""Regression tests for the security and correctness review fixes of add-on 0.5.94-full2 (commit 7d1b347), as far
as they still apply since 0.5.94-full3: the gate writes no archive and no rehearsal export any more, and the
automatic cleanup deletes what earlier add-on versions left in /share and /config.

Every race is simulated deterministically: a swap happens between oc_gate.cleanup_targets() and the deletes of
cleanup_pass() (by wrapping cleanup_targets), or inside a function the code calls between its check and its use
(_dir_bytes in _delete_entry), never by a concurrent attacker thread. A call that must not block (a FIFO in /share)
runs under a timer that unblocks it and fails the test, so a regression never hangs the suite.

Covers:
- /share symlink attacks on the delete side, for leftovers of earlier add-on versions: /share/openclaw-upgrade,
  /share/openclaw-rehearsal, a rehearsal <ts> directory, a run's archive directory and tombstones turned into
  symlinks to a victim directory under the config root after the cleanup listed its targets, or planted before it:
  nothing in the victim is deleted.
- cleanup robustness, Stage A plaintext archives, retention after a cleared post-run hold.
- Supervisor client hardening: token validation, deep JSON, content.addons type, overall deadline, redacted
  internal-error HOLDs.
- lstat-only listings: links with unresolvable (over-long) targets in /share; `oc-upgrade status` lists leftover
  gate archives without opening anything below /share/openclaw-upgrade (a FIFO, a link, a 1 TiB sparse file);
  names from /share listings never reach a log line raw, and only directories named like the add-on's are
  cleaned up.

Python tests must run inside `unshare --pid --fork --mount-proc` on hosts with rehearsal containers (their
OpenClaw processes would make the openclaw-running precheck HOLD); find_openclaw_processes is additionally
filtered to this test's own temporary tree.
"""

import errno
import io
import json
import os
import re
import shutil
import socket
import stat
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

import test_gate as T  # noqa: E402  (GateEnv, fake node/doctor, synthetic 7.35 state)

C, G = T.C, T.G

# What 0.5.94-full2 left behind (it is only ever deleted or listed now): the recipient its journal recorded
# (syntactically valid, never used), the first line of its age-encrypted gate archives, and the names of its
# rehearsal export (G.REHEARSAL_FILES lists them for the cleanup).
FAKE_PUB = "age1" + "q" * 58
AGE_MAGIC = b"age-encryption.org/v1\n"
EXPORT_FILE = "openclaw-rehearsal.tar.gz.age"
EXPORT_TMP = "openclaw-rehearsal.tar.gz.age.tmp"
T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
H48 = timedelta(hours=48)
SEC = timedelta(seconds=1)
SLUG = "a0d7b954_openclaw_assistant"
TIB = 2 ** 40  # a sparse file this size is created at once; reading it to its end would take many minutes
# One 300-character path component as a symlink target: lstat works, stat (any follow) fails with ENAMETOOLONG.
LONG_TARGET = "x" * 300

# Like OpenClaw 2026.10's doctor: copies the pre-repair state into <realpath(state)>.update-captures/doctor-<uuid>/
# and logs the line naming its manifest, then runs the fake doctor of test_gate.
CAPTURE_DOCTOR = r'''#!/usr/bin/env python3
import os, sys, uuid
state = os.path.realpath(os.environ["OPENCLAW_STATE_DIR"])
d = os.path.join(state + ".update-captures", "doctor-" + str(uuid.uuid4()))
os.makedirs(d)
with open(os.path.join(d, "manifest.json"), "w") as f:
    f.write('{"schemaVersion": 2}\n')
print("Pre-repair state retained for manual recovery at " + d + "/manifest.json.", flush=True)
os.execv(sys.argv[1], sys.argv[1:])
'''


def iso(dt):
    return C.utc_iso(dt)


def tree(root):
    """{relative path: ("d",) | ("l", target) | ("f", bytes)} of everything below root; never follows a link."""
    out = {}
    root = Path(root)
    if not os.path.lexists(root):
        return None
    for dirpath, dirs, files in os.walk(root):
        for n in dirs + files:
            q = Path(dirpath) / n
            st = os.lstat(q)
            rel = str(q.relative_to(root))
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("l", os.readlink(q))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("d",)
            else:
                out[rel] = ("f", q.read_bytes())
    return out


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class SecEnv(T.GateEnv):
    def setUp(self):
        super().setUp()
        real_find = G.find_openclaw_processes
        mine = str(self.tmp)
        patcher = mock.patch.object(G, "find_openclaw_processes",
                                    lambda *a, **kw: [p for p in real_find(*a, **kw) if mine in p["cmd"]])
        patcher.start()
        self.addCleanup(patcher.stop)
        self.gp = G.gpaths()
        G.ensure_dirs(self.gp)
        self.arch = self.share / "openclaw-upgrade"
        self.reh = self.share / "openclaw-rehearsal"
        self.caps = G.captures_root(self.gp)
        self.n = 0

    # ----- builders -----
    def new_rid(self):
        self.n += 1
        return f"20261001T1200{self.n:02d}Z-{self.n:06x}"

    def victim(self, name, entries):
        """A directory under the config root (where a redirected delete or write would do damage)."""
        v = self.root / name
        v.mkdir(parents=True, exist_ok=True)
        for rel, data in entries.items():
            f = v / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(data)
        return v

    def capture(self, root=None):
        d = (root or self.caps) / f"doctor-{uuid.uuid4()}"
        d.mkdir(parents=True)
        (d / "manifest.json").write_text("{}\n")
        return d

    def age_old(self, path, when):
        ts = when.timestamp()
        os.utime(path, (ts, ts), follow_symlinks=False)

    def make_run(self, finished=T0, captures=0, history=None, rid=None, archive=True):
        """A finished gate run: runs/<id>/journal.json and its doctor captures named in runs/<id>/doctor-pass1.log.
        With archive, a run of 0.5.94-full2: also the encrypted archive directory it left under
        /share/openclaw-upgrade (archive, SHA256SUMS, manifest.json) and the journal's archive record; without, a
        run of this version (no archive)."""
        rid = rid or self.new_rid()
        rd = self.gp["RUNS"] / rid
        rd.mkdir(parents=True, exist_ok=True)
        adir = self.arch / rid
        name = f"openclaw-state-20261001-120000-before-{T.RUNTIME}.tar.gz.age"
        if archive:
            adir.mkdir(parents=True)
            (adir / name).write_bytes(AGE_MAGIC + os.urandom(2000))
            (adir / "SHA256SUMS").write_text(f"{C.sha256_file(adir / name)}  {name}\n")
            (adir / "manifest.json").write_text("{}\n")
        caps = [self.capture() for _ in range(captures)]
        lines = [f"Pre-repair state retained for manual recovery at {c}/manifest.json." for c in caps]
        (rd / "doctor-pass1.log").write_text("\n".join(["┌  OpenClaw doctor"] + lines + ["└  Doctor complete."]) + "\n")
        j = {"run_id": rid, "mode": "from-7x", "status": "done", "phase": "finalize",
             "started_at": iso(finished - timedelta(minutes=5)), "finished_at": iso(finished),
             "first_write_at": iso(finished - timedelta(minutes=4)), "phases_done": [], "doctor": [],
             "history": history or []}
        if archive:
            j["archive"] = {"mode": "encrypted", "format": "tar.gz+age", "dir": str(adir), "file": name,
                            "recipient": FAKE_PUB, "verified": True}
        (rd / "journal.json").write_text(json.dumps(j))
        return SimpleNamespace(rid=rid, rd=rd, adir=adir, caps=caps, j=j, file=adir / name)

    def make_export(self, ts, files=("openclaw-rehearsal.tar.gz", "manifest.txt"), when=None):
        d = self.reh / ts
        d.mkdir(parents=True, exist_ok=True)
        for f in files:
            (d / f).write_bytes(b"\x1f\x8b plaintext export" if f.endswith(".tar.gz") else b"export file")
            self.age_old(d / f, when or (T0 - timedelta(days=3)))
        return d

    # ----- runners -----
    def cleanup(self, now, hours=48, state=None):
        lines = []
        n = G.cleanup_pass(now=now, hours=hours, emit=lines.append, state=state)
        self.lines = lines
        self.text = "\n".join(lines)
        return n

    def swap_after_listing(self, *swaps):
        """Patch cleanup_targets so that every swap() runs after the real listing and before the first delete."""
        real = G.cleanup_targets

        def racing(*a, **kw):
            targets = real(*a, **kw)
            for s in swaps:
                s()
            return targets
        return mock.patch.object(G, "cleanup_targets", side_effect=racing)

    def replace_with_link(self, path, target, keep_as=None):
        """What a /share writer does: move the real directory away (or delete it) and plant a symlink."""
        if keep_as is not None:
            os.rename(path, keep_as)
        os.symlink(str(target), str(path))

    def long_link(self, path):
        """A symlink another /share writer plants whose target cannot be resolved (ENAMETOOLONG on any stat that
        follows it): only lstat-based listings survive it."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        os.symlink(LONG_TARGET, str(path))
        with self.assertRaises(OSError) as cm:
            os.stat(path)
        self.assertEqual(cm.exception.errno, errno.ENAMETOOLONG)
        return Path(path)

    def watchdog(self, *fifos, after=10.0):
        """Started before a call that must return at once. If it is still running after `after` s, STOP is set (loops
        that check it end) and, until done() is called, a writer opens every one of `fifos` every 0.2 s (a reader
        blocked opening one returns): a regression fails instead of hanging the suite. Returns done(), which gives
        (elapsed s, whether the watchdog had to act)."""
        fired = []
        finished = threading.Event()

        def fire():
            if finished.wait(after):
                return
            fired.append(1)
            G.STOP.set()
            while not finished.is_set():
                for f in fifos:
                    try:
                        os.close(os.open(str(f), os.O_WRONLY | os.O_NONBLOCK))
                    except OSError:
                        pass
                finished.wait(0.2)
        t = threading.Thread(target=fire, daemon=True)
        t0 = time.monotonic()
        t.start()
        self.addCleanup(finished.set)

        def done():
            finished.set()
            elapsed = time.monotonic() - t0
            t.join(5)
            G.STOP.clear()
            return elapsed, bool(fired)
        return done


# --- /share symlink swaps during the cleanup (leftovers of earlier add-on versions) -------------------------

class ShareSwapTests(SecEnv):
    def assert_not_deleted(self, label):
        self.assertNotRegex(self.text, rf"\[cleanup\] {re.escape(label)}: deleted", self.text)
        self.assertRegex(self.text, rf"WARN \[cleanup\] {re.escape(label)}: could not delete", self.text)

    def test_archives_root_swapped_to_a_symlink_after_listing_deletes_nothing_in_the_victim(self):
        r = self.make_run(finished=T0)
        victim = self.victim("victim-arch", {f"{r.rid}/precious.txt": b"keep me",
                                             f"{r.rid}/{r.file.name}": b"victim's own file"})
        before = tree(victim)
        listed = [t[1] for t in G.cleanup_targets(self.gp, T0 + H48, 48)]
        self.assertIn(f"run {r.rid}", listed)
        with self.swap_after_listing(lambda: self.replace_with_link(self.arch, victim, self.share / "arch-real")):
            self.assertEqual(self.cleanup(T0 + H48), 0)
        self.assertEqual(tree(victim), before)
        self.assert_not_deleted(f"run {r.rid}")
        self.assertTrue((self.share / "arch-real" / r.rid / r.file.name).is_file())  # nothing was deleted at all
        self.assertTrue(os.path.islink(self.arch))

    def test_rehearsal_root_swapped_to_a_symlink_after_listing_deletes_nothing_in_the_victim(self):
        ts = "20260901-000000"
        self.make_export(ts)
        victim = self.victim("victim-reh", {f"{ts}/openclaw-rehearsal.tar.gz": b"victim's archive",
                                            f"{ts}/manifest.txt": b"victim's manifest",
                                            f"{ts}/precious.txt": b"keep me"})
        before = tree(victim)
        label = f"plaintext rehearsal export {ts}"
        self.assertIn(label, [t[1] for t in G.cleanup_targets(self.gp, T0, 48)])
        with self.swap_after_listing(lambda: self.replace_with_link(self.reh, victim, self.share / "reh-real")):
            self.assertEqual(self.cleanup(T0 + H48), 0)
        self.assertEqual(tree(victim), before)
        self.assert_not_deleted(label)
        self.assertTrue((self.share / "reh-real" / ts / "openclaw-rehearsal.tar.gz").is_file())

    def test_both_share_roots_swapped_in_one_pass(self):
        ts = "20260901-000000"
        r = self.make_run(finished=T0)
        self.make_export(ts)
        v_arch = self.victim("victim-a", {f"{r.rid}/precious.txt": b"keep a"})
        v_reh = self.victim("victim-r", {f"{ts}/openclaw-rehearsal.tar.gz": b"keep r", f"{ts}/manifest.txt": b"m"})
        before = (tree(v_arch), tree(v_reh))
        with self.swap_after_listing(lambda: self.replace_with_link(self.arch, v_arch, self.share / "a-real"),
                                     lambda: self.replace_with_link(self.reh, v_reh, self.share / "r-real")):
            self.assertEqual(self.cleanup(T0 + H48), 0)
        self.assertEqual((tree(v_arch), tree(v_reh)), before)
        self.assert_not_deleted(f"run {r.rid}")
        self.assert_not_deleted(f"plaintext rehearsal export {ts}")

    def test_export_dir_swapped_to_a_symlink_after_listing_deletes_nothing_in_the_victim(self):
        ts = "20260902-000000-AbC123"  # the <ts>-XXXXXX form of the 0.5.94-full2 exports
        self.make_export(ts, files=("openclaw-rehearsal.tar.gz.age", "manifest.txt"))
        victim = self.victim("victim-ts", {"openclaw-rehearsal.tar.gz.age": b"victim's archive",
                                           "openclaw-rehearsal.tar.gz": b"victim's plaintext",
                                           "manifest.txt": b"victim's manifest"})
        before = tree(victim)
        label = f"encrypted rehearsal export {ts}"
        self.assertIn(label, [t[1] for t in G.cleanup_targets(self.gp, T0, 48)])
        with self.swap_after_listing(lambda: self.replace_with_link(self.reh / ts, victim, self.share / "ts-real")):
            self.assertEqual(self.cleanup(T0 + H48), 0)
        self.assertEqual(tree(victim), before)
        self.assert_not_deleted(label)
        self.assertTrue(os.path.islink(self.reh / ts))

    def test_run_dir_swapped_to_a_symlink_after_listing_only_the_link_goes(self):
        r = self.make_run(finished=T0)
        victim = self.victim("victim-run", {"precious.txt": b"keep me", r.file.name: b"victim's file"})
        before = tree(victim)
        with self.swap_after_listing(lambda: self.replace_with_link(r.adir, victim, self.share / "moved-run")):
            self.cleanup(T0 + H48)
        self.assertEqual(tree(victim), before)
        self.assertFalse(os.path.lexists(r.adir))  # the planted link itself is removed, never followed

    def test_run_dir_swapped_between_the_check_and_the_rename_deletes_nothing_in_the_victim(self):
        """_delete_entry stats the run directory, then (via _dir_bytes) renames it to a tombstone: a symlink planted
        in between is renamed, and rmtree(dir_fd=...) refuses to follow it."""
        r = self.make_run(finished=T0)
        victim = self.victim("victim-race", {"precious.txt": b"keep me", "sub/x.db": b"db"})
        before = tree(victim)
        real_dir_bytes = G._dir_bytes
        swapped = []

        def racing_dir_bytes(d):
            if Path(d) == r.adir and not swapped:
                swapped.append(1)
                self.replace_with_link(r.adir, victim, self.share / "moved-run")
                return 0
            return real_dir_bytes(d)
        with mock.patch.object(G, "_dir_bytes", side_effect=racing_dir_bytes):
            self.assertEqual(self.cleanup(T0 + H48), 0)
        self.assertEqual(swapped, [1])
        self.assertEqual(tree(victim), before)
        self.assert_not_deleted(f"run {r.rid}")
        tomb = self.arch / (G.TOMB_PREFIX + r.rid)
        self.assertTrue(os.path.islink(tomb), sorted(os.listdir(self.arch)))
        # the next pass removes the leftover tombstone as a link, still without following it
        self.cleanup(T0 + H48 + SEC)
        self.assertFalse(os.path.lexists(tomb))
        self.assertEqual(tree(victim), before)

    def test_tombstone_symlinks_are_unlinked_never_followed(self):
        victim = self.victim("victim-tomb", {"precious.txt": b"keep me", "deep/x.tar.gz.age": AGE_MAGIC})
        before = tree(victim)
        self.arch.mkdir(parents=True)
        planted = self.arch / (G.TOMB_PREFIX + "20261001T000000Z-aaaaaa")
        os.symlink(str(victim), planted)
        # a capture tombstone that is a real directory when listed and a symlink when deleted
        self.caps.mkdir(parents=True, exist_ok=True)
        ctomb = self.caps / f"{G.TOMB_PREFIX}doctor-{uuid.uuid4()}"
        ctomb.mkdir()
        (ctomb / "manifest.json").write_text("{}")
        labels = [t[1] for t in G.cleanup_targets(self.gp, T0, 48)]
        self.assertIn(f"leftover {planted.name}", labels)
        self.assertIn(f"leftover {ctomb.name}", labels)

        def swap_capture_tomb():
            os.rename(ctomb, self.tmp / "ctomb-real")
            os.symlink(str(victim), ctomb)
        with self.swap_after_listing(swap_capture_tomb):
            self.cleanup(T0)
        self.assertEqual(tree(victim), before)
        self.assertFalse(os.path.lexists(planted))
        self.assertFalse(os.path.lexists(ctomb))

    def test_stage_a_root_swapped_to_a_symlink_after_listing_deletes_nothing_in_the_victim(self):
        name = "openclaw-state-20260101-120000-before-2026.7.35.tar.gz"
        sa = self.state / "upgrade-backups"
        sa.mkdir()
        (sa / name).write_bytes(b"\x1f\x8b stage A")
        self.age_old(sa / name, T0 - timedelta(days=30))
        self.gp["MARKER"].write_text(json.dumps({"runtime": T.RUNTIME, "completed_at": iso(T0 - timedelta(days=30))}))
        victim = self.victim("victim-sa", {name: b"victim's file"})
        before = tree(victim)
        with self.swap_after_listing(lambda: self.replace_with_link(sa, victim, self.state / "sa-real")):
            self.assertEqual(self.cleanup(T0), 0)
        self.assertEqual(tree(victim), before)
        self.assert_not_deleted(f"Stage A plaintext archive {name}")

    def test_export_keeps_user_files_and_never_removes_a_non_empty_directory(self):
        ts = "20260901-000000"
        d = self.make_export(ts, files=("openclaw-rehearsal.tar.gz", "openclaw-rehearsal.tar.gz.age", "manifest.txt"))
        (d / "notes.txt").write_text("the user's own notes")
        (d / "openclaw-rehearsal.tar.gz.tmp").mkdir()  # a directory with an export name is not an export file
        self.assertEqual(self.cleanup(T0 + H48), 1)
        self.assertEqual(sorted(os.listdir(d)), ["notes.txt", "openclaw-rehearsal.tar.gz.tmp"])
        # a fully owned export directory goes completely
        d2 = self.make_export("20260901-000001", files=("openclaw-rehearsal.tar.gz.age", "manifest.txt"))
        self.assertEqual(self.cleanup(T0 + H48), 1)
        self.assertFalse(os.path.lexists(d2))

    def test_crafted_run_ids_in_journals_are_ignored(self):
        outside = self.victim("outside", {"precious.txt": b"keep me"})
        before = tree(outside)
        for i, rid in enumerate((str(outside), "../../outside", "..", "a/b")):
            rd = self.gp["RUNS"] / f"x{i}"
            rd.mkdir(parents=True)
            (rd / "journal.json").write_text(json.dumps({"run_id": rid, "status": "done", "finished_at": iso(T0)}))
            (rd / "doctor-pass1.log").write_text("")
        self.assertEqual([t for t in G.cleanup_targets(self.gp, T0 + H48, 48) if t[0] is not None], [])
        self.cleanup(T0 + H48)
        self.assertEqual(tree(outside), before)
        self.assertFalse((self.upg / "outside").exists())


# --- symlinks planted before the cleanup lists its targets -------------------------------------------------

class PlantedLinkTests(SecEnv):
    """Another /share writer plants symlinks to victim directories under the config root where the cleanup looks
    for the leftovers of earlier add-on versions, before it lists its targets. The listing is lstat-only: a linked
    directory is never listed or entered, a planted tombstone or export file goes as a link, nothing in a victim."""

    def assert_only_kept_warning(self, r):
        self.assertEqual([x for x in self.lines if x.startswith("WARN")],
                         [f"WARN [cleanup] run {r.rid}: kept {r.adir}: not a plain run directory"])

    def test_links_planted_for_a_run_an_orphan_a_tombstone_and_an_export_are_never_followed(self):
        old = T0 - timedelta(days=30)
        r = self.make_run(finished=T0, captures=1)
        v_run = self.victim("victim-run", {r.file.name: b"victim's archive", "SHA256SUMS": b"victim's sums",
                                           "precious.txt": b"keep me"})
        v_orphan = self.victim("victim-orphan", {"openclaw-state-x.tar.gz.age": AGE_MAGIC, "precious.txt": b"keep"})
        v_tomb = self.victim("victim-tomb", {"precious.txt": b"keep me", "deep/x.db": b"db"})
        v_exp = self.victim("victim-exp", {EXPORT_FILE: b"victim's archive", "manifest.txt": b"victim's manifest"})
        v_file = self.victim("victim-file", {"precious.txt": b"keep me"})
        victims = (v_run, v_orphan, v_tomb, v_exp, v_file)
        before = [tree(v) for v in victims]
        shutil.rmtree(r.adir)
        orphan = self.arch / "20260902T000000Z-0abcde"
        tomb = self.arch / (G.TOMB_PREFIX + "20260903T000000Z-0abcde")
        exp_link = self.reh / "20260904-000000-AbC123"
        self.reh.mkdir()
        for link, target in ((r.adir, v_run), (orphan, v_orphan), (tomb, v_tomb), (exp_link, v_exp)):
            os.symlink(str(target), link)
            self.age_old(link, old)
        for f in v_exp.iterdir():
            self.age_old(f, old)  # due, if the link were followed
        # a real 0.5.94-full2 export whose manifest another writer replaced by a link to a victim's file
        exp = self.make_export("20260905-000000-DeF456", files=(EXPORT_FILE,), when=old)
        os.symlink(str(v_file / "precious.txt"), exp / "manifest.txt")
        labels = [t[1] for t in G.cleanup_targets(self.gp, T0 + H48, 48)]
        self.assertEqual(sorted(labels), sorted([f"run {r.rid}", f"leftover {tomb.name}",
                                                 f"encrypted rehearsal export {exp.name}"]))
        self.assertEqual(self.cleanup(T0 + H48), 3, self.text)  # the run's doctor capture, the tombstone, the export
        self.assertEqual([tree(v) for v in victims], before)
        for gone in (r.caps[0], tomb, exp):
            self.assertFalse(os.path.lexists(gone), gone)
        for link in (r.adir, orphan, exp_link):
            self.assertTrue(os.path.islink(link), link)
        self.assert_only_kept_warning(r)
        self.assertEqual(self.cleanup(T0 + H48 + SEC), 0)
        self.assertEqual([tree(v) for v in victims], before)

    def test_share_roots_planted_as_links_are_never_followed(self):
        old = T0 - timedelta(days=30)
        r = self.make_run(finished=T0, captures=1)
        ts = "20260901-000000-AbC123"
        self.make_export(ts, files=(EXPORT_FILE, "manifest.txt"), when=old)
        orphan, tomb = "20260902T000000Z-0abcde", G.TOMB_PREFIX + "20260903T000000Z-0abcde"
        v_arch = self.victim("victim-arch", {f"{r.rid}/{r.file.name}": b"victim's archive",
                                             f"{orphan}/openclaw-state-x.tar.gz.age": AGE_MAGIC,
                                             f"{tomb}/precious.txt": b"keep me"})
        v_reh = self.victim("victim-reh", {f"{ts}/{EXPORT_FILE}": b"victim's export", f"{ts}/manifest.txt": b"m"})
        for q in (v_arch / orphan, v_reh / ts / EXPORT_FILE, v_reh / ts / "manifest.txt"):
            self.age_old(q, old)
        before = (tree(v_arch), tree(v_reh))
        self.replace_with_link(self.arch, v_arch, self.share / "arch-real")
        self.replace_with_link(self.reh, v_reh, self.share / "reh-real")
        self.assertEqual([t[1] for t in G.cleanup_targets(self.gp, T0 + H48, 48)], [f"run {r.rid}"])
        self.assertEqual(self.cleanup(T0 + H48), 1, self.text)  # only the run's doctor capture
        self.assertEqual((tree(v_arch), tree(v_reh)), before)
        self.assertFalse(os.path.lexists(r.caps[0]))
        self.assertTrue(os.path.islink(self.arch) and os.path.islink(self.reh))
        self.assert_only_kept_warning(r)
        # the real directories that were moved away are not the cleanup's any more: untouched
        self.assertTrue((self.share / "arch-real" / r.rid / r.file.name).is_file())
        self.assertTrue((self.share / "reh-real" / ts / EXPORT_FILE).is_file())


# --- cleanup robustness ----------------------------------------------------------------------------------

class CleanupRobustnessTests(SecEnv):
    def test_a_cleanup_record_that_is_not_an_object_does_not_stop_the_next_run(self):
        for bad in ("[1]", "null", '"text"', "7", "{broken"):
            with self.subTest(bad=bad):
                a = self.make_run(finished=T0)
                b = self.make_run(finished=T0 + SEC)
                (a.rd / "cleanup.json").write_text(bad)
                self.assertEqual(self.cleanup(T0 + H48 + SEC), 2, self.text)
                self.assertFalse(os.path.lexists(a.adir))
                self.assertFalse(os.path.lexists(b.adir))
                self.assertNotIn("WARN", self.text)
                rec = json.loads((a.rd / "cleanup.json").read_text())
                self.assertIsInstance(rec, dict)
                self.assertEqual(rec["deleted_at"], iso(T0 + H48 + SEC))

    def test_an_unexpected_error_in_one_target_is_reported_once_and_the_next_target_is_handled(self):
        a = self.make_run(finished=T0)
        b = self.make_run(finished=T0 + SEC)
        real = G._safe_delete

        def failing(gp, p):
            if p == a.adir:
                raise RuntimeError("simulated bug")
            return real(gp, p)
        state = {}
        with mock.patch.object(G, "_safe_delete", side_effect=failing):
            self.assertEqual(self.cleanup(T0 + H48 + SEC, state=state), 1)
            self.assertEqual(self.lines.count(f"WARN [cleanup] run {a.rid}: RuntimeError: simulated bug"), 1, self.text)
            self.assertFalse(os.path.lexists(b.adir))
            self.assertTrue(a.adir.is_dir())
            self.assertEqual(self.cleanup(T0 + H48 + 2 * SEC, state=state), 0)
            self.assertEqual(self.lines, [])  # not again at every pass
        self.assertEqual(self.cleanup(T0 + H48 + 3 * SEC, state=state), 1)  # fixed: deleted at the next pass
        self.assertFalse(os.path.lexists(a.adir))

    def test_an_os_error_in_one_target_is_reported_once_and_the_next_target_is_handled(self):
        a = self.make_run(finished=T0)
        b = self.make_run(finished=T0 + SEC)
        real = G._safe_delete

        def failing(gp, p):
            if p == a.adir:
                raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(p))
            return real(gp, p)
        state = {}
        with mock.patch.object(G, "_safe_delete", side_effect=failing):
            self.assertEqual(self.cleanup(T0 + H48 + SEC, state=state), 1)
            warns = [x for x in self.lines if x.startswith(f"WARN [cleanup] run {a.rid}:")]
            self.assertEqual(len(warns), 1, self.text)
            self.assertFalse(os.path.lexists(b.adir))
            for k in range(2, 5):
                self.cleanup(T0 + H48 + k * SEC, state=state)
                self.assertEqual(self.lines, [], f"pass {k}: {self.text}")


# --- links with over-long targets and failing listings in /share -------------------------------------------

class UnresolvableLinkTests(SecEnv):
    """Other add-ons can write /share: a link there whose target cannot even be resolved (ENAMETOOLONG on every
    stat that follows it) must not stop the cleanup, a gate run or the status. Listings use lstat only."""

    def plant(self):
        return [self.long_link(self.arch / "20260901T000000Z-0bad0f"),  # named like a run directory
                self.long_link(self.arch / "long-link"),
                self.long_link(self.reh / "20260901-000000-LnkLnk"),  # named like an export directory
                self.long_link(self.reh / "long-link")]

    def assert_links_left(self, links):
        for link in links:
            self.assertTrue(os.path.islink(link), link)
            self.assertEqual(os.readlink(link), LONG_TARGET)

    def test_cleanup_still_deletes_due_runs_orphans_exports_and_captures(self):
        links = self.plant()
        tomb = self.long_link(self.arch / (G.TOMB_PREFIX + "20260901T000000Z-0bad0f"))  # a leftover: unlinked
        r = self.make_run(finished=T0, captures=2)
        self.long_link(r.adir / "SHA256SUMS.link")  # inside a run directory: removed with it
        orphan = self.arch / "20260902T000000Z-0abcde"
        orphan.mkdir()
        (orphan / "openclaw-state-x.tar.gz.age").write_bytes(AGE_MAGIC)
        self.age_old(orphan, T0)
        exp = self.make_export("20260903-000000-AbC123", files=(EXPORT_FILE, "manifest.txt"), when=T0)
        self.long_link(exp / EXPORT_TMP)  # an export file name: unlinked as a link
        listing = []
        self.assertEqual(G.cleanup_cmd([], emit=listing.append), 0)
        self.assertTrue(any(x.startswith(f"  run {r.rid}: due") for x in listing), listing)
        self.assertNotIn("scan", "\n".join(listing))
        state = {}
        self.assertEqual(self.cleanup(T0 + H48, state=state), 6, self.text)  # run 3, orphan, export, tombstone
        self.assertNotIn("WARN", self.text)
        for gone in (r.adir, *r.caps, orphan, exp, tomb):
            self.assertFalse(os.path.lexists(gone), gone)
        self.assert_links_left(links)
        rec = json.loads((r.rd / "cleanup.json").read_text())
        self.assertEqual(sorted(x["path"] for x in rec["deleted"]), sorted(str(x) for x in (r.adir, *r.caps)))
        self.assertEqual(self.cleanup(T0 + H48 + SEC, state=state), 0)
        self.assertEqual(self.lines, [])

    def test_a_run_directory_replaced_by_such_a_link_still_loses_its_doctor_captures(self):
        r = self.make_run(finished=T0, captures=2)
        shutil.rmtree(r.adir)
        self.long_link(r.adir)
        state = {}
        self.assertEqual(self.cleanup(T0 + H48, state=state), 2, self.text)
        for c in r.caps:
            self.assertFalse(os.path.lexists(c), c)
        self.assertTrue(os.path.islink(r.adir))  # not a plain run directory: kept, never followed
        warns = [x for x in self.lines if x.startswith("WARN ")]
        self.assertEqual(warns, [f"WARN [cleanup] run {r.rid}: kept {r.adir}: not a plain run directory"])
        rec = json.loads((r.rd / "cleanup.json").read_text())
        self.assertEqual(sorted(x["path"] for x in rec["deleted"]), sorted(str(c) for c in r.caps))
        self.assertEqual(self.cleanup(T0 + H48 + SEC, state=state), 0)
        self.assertEqual(self.lines, [])

    def test_a_gate_run_leaves_share_alone_and_status_lines_survive_such_links(self):
        self.build_735()
        self.hooks()
        links = self.plant()
        legacy = self.arch / "20260901T000000Z-abcdef" / f"openclaw-state-20260901-000000-before-{T.RUNTIME}.tar.gz"
        legacy.parent.mkdir(parents=True)
        legacy.write_bytes(b"\x1f\x8b legacy plaintext")
        self.long_link(legacy.parent / "openclaw-state-20260901-000001-before-2026.9.9.tar.gz")  # not listed
        before = tree(self.share)
        rc = self.run_gate()
        self.assertNotIn("internal-error", self.out + self.err)
        self.assertNotIn("Traceback", self.err)
        self.assertEqual(rc, 0, self.out + self.err)
        self.assertEqual(self.journal()["status"], "done")
        self.assertEqual(tree(self.share), before)  # no archive of its own: nothing created, changed or removed
        self.assert_links_left(links)
        st = G.status_lines()
        self.assertIn(f"  {legacy} (", "\n".join(st))
        self.assertNotIn("long-link", "\n".join(st))
        self.assertNotIn("openclaw-state-20260901-000001-", "\n".join(st))

    # Regression: a run whose doctor captures cannot be listed is an error target: warned once per loop,
    # nothing recorded in cleanup.json (no deleted_at), deleted on a later pass.
    def test_a_failing_capture_listing_records_no_deletion_and_warns_once_per_loop(self):
        for with_archive in (False, True):  # a run of this version, and one of 0.5.94-full2 with its archive
            with self.subTest(with_archive=with_archive):
                r = self.make_run(finished=T0, captures=1, archive=with_archive)
                self.assertEqual(self.cleanup(T0 + timedelta(hours=1)), 0)  # announced: due_at recorded
                rec_path = r.rd / "cleanup.json"
                self.assertEqual(json.loads(rec_path.read_text())["due_at"], iso(T0 + H48))
                real = G.run_captures

                def failing(gp, j, rid=r.rid):  # this run's doctor-log listing fails (EIO), the others' do not
                    if j.get("run_id") == rid:
                        raise OSError(errno.EIO, "Input/output error")
                    return real(gp, j)
                warn = (f"WARN [cleanup] run {r.rid}: kept {self.caps}: doctor captures not listed: OSError")
                loop1, loop2 = {}, {}
                with mock.patch.object(G, "run_captures", side_effect=failing):
                    self.cleanup(T0 + H48, state=loop1)
                    self.assertEqual([x for x in self.lines if x.startswith("WARN")], [warn])
                    rec = json.loads(rec_path.read_text())
                    self.assertNotIn("deleted_at", rec)
                    self.assertEqual([k for k in rec if k.startswith("kept:")], [])
                    self.cleanup(T0 + H48 + SEC, state=loop1)
                    self.assertEqual([x for x in self.lines if x.startswith("WARN")], [])  # same loop: once
                    self.cleanup(T0 + H48 + 2 * SEC, state=loop2)  # a new loop (add-on restart): again
                    self.assertEqual([x for x in self.lines if x.startswith("WARN")], [warn])
                    self.assertNotIn("deleted_at", json.loads(rec_path.read_text()))
                self.assertTrue(os.path.isdir(r.caps[0]))
                self.cleanup(T0 + H48 + 3 * SEC, state=loop2)  # listed again: everything goes, now recorded
                self.assertFalse(os.path.lexists(r.caps[0]))
                self.assertFalse(os.path.lexists(r.adir))
                rec = json.loads(rec_path.read_text())
                self.assertTrue(rec.get("deleted_at"), rec)
                self.assertIn(str(r.caps[0]), [x["path"] for x in rec["deleted"]])

    def test_an_unusable_journal_warns_once_per_loop_and_records_nothing(self):
        r = self.make_run(finished=T0)
        (r.rd / "journal.json").write_text(json.dumps(dict(r.j, finished_at="9999-12-31T23:00:00Z")))
        loop1, loop2 = {}, {}
        self.assertEqual(self.cleanup(T0 + H48, state=loop1), 0)
        warns = [x for x in self.lines if x.startswith("WARN")]
        self.assertEqual(len(warns), 1, self.lines)
        self.assertIn(f"run {r.rid}: kept {r.adir}: journal unusable: OverflowError", warns[0])
        self.assertFalse((r.rd / "cleanup.json").exists())
        self.assertEqual(self.cleanup(T0 + H48 + SEC, state=loop1), 0)
        self.assertEqual(self.lines, [])
        self.assertEqual(self.cleanup(T0 + H48 + SEC, state=loop2), 0)
        self.assertEqual(len([x for x in self.lines if x.startswith("WARN")]), 1, self.lines)
        self.assertFalse((r.rd / "cleanup.json").exists())
        self.assertTrue(r.adir.is_dir())

# --- oc-upgrade status: leftover gate archives in /share are listed by lstat only ---------------------------

class StatusListingTests(SecEnv):
    """status_lines() lists the gate archives earlier add-on versions left in /share/openclaw-upgrade. 0.5.94-full2
    also opened each directory's SHA256SUMS there; now nothing below that root is opened or stat'ed through a link,
    so a FIFO, an unresolvable link or a 1 TiB sparse file another /share writer planted neither blocks nor slows the
    status, and a forged name never makes a second line."""

    HEADER = "Gate archives in /share from earlier add-on versions (deleted automatically, see oc-upgrade cleanup):"

    def status(self):
        """status_lines() while every open and every link-following stat of a path below /share/openclaw-upgrade is
        recorded; returns (lines, [(kind, path), ...])."""
        below = str(self.arch)
        touched = []
        real_open, real_os_open, real_stat = io.open, os.open, os.stat

        def rec(kind, path):
            if isinstance(path, (str, bytes, os.PathLike)):
                q = os.fsdecode(path)
                if q == below or q.startswith(below + "/"):
                    touched.append((kind, q))

        def opener(file, *a, **kw):
            rec("open", file)
            return real_open(file, *a, **kw)

        def os_opener(path, *a, **kw):
            rec("os.open", path)
            return real_os_open(path, *a, **kw)

        def stater(path, *a, follow_symlinks=True, **kw):
            if follow_symlinks:
                rec("stat", path)
            return real_stat(path, *a, follow_symlinks=follow_symlinks, **kw)
        with mock.patch("builtins.open", opener), mock.patch.object(io, "open", opener), \
                mock.patch.object(os, "open", os_opener), mock.patch.object(os, "stat", stater):
            lines = G.status_lines()
        return lines, touched

    def listed(self, lines):
        """The archive lines under HEADER."""
        i = lines.index(self.HEADER)
        out = []
        for x in lines[i + 1:]:
            if not x.startswith("  "):
                break
            out.append(x)
        return out

    def test_no_leftover_archives_no_section(self):
        self.arch.mkdir()
        (self.arch / "20260901T000000Z-abcdef").mkdir()  # an empty run directory of an earlier version
        for setup in (lambda: None, lambda: shutil.rmtree(self.arch)):
            setup()
            lines, touched = self.status()
            self.assertFalse([x for x in lines if "Gate archives" in x], lines)
            self.assertEqual(touched, [])

    def test_leftover_archives_are_listed_by_lstat_only_and_never_opened(self):
        r = self.make_run(finished=T0)  # 0.5.94-full2: <run>/<archive>.tar.gz.age, SHA256SUMS, manifest.json
        os.unlink(r.adir / "SHA256SUMS")
        os.mkfifo(r.adir / "SHA256SUMS", 0o600)  # what 0.5.94-full2's status opened: a blocking open hangs
        self.gp["JOURNAL"].write_text(json.dumps(r.j))
        (r.rd / "cleanup.json").write_text(json.dumps({"schema": 1, "due_at": iso(T0 + H48)}))
        plain = self.arch / "20260901T000000Z-abcdef" / f"openclaw-state-20260901-000000-before-{T.RUNTIME}.tar.gz"
        plain.parent.mkdir()
        plain.write_bytes(b"\x1f\x8b plaintext 0.5.94-full1 archive")
        huge = self.arch / "20260902T000000Z-abcdef" / "openclaw-state-20260902-000000-before-2026.9.9.tar.gz.age"
        huge.parent.mkdir()
        with open(huge, "wb") as f:
            f.truncate(TIB)  # sparse: its size comes from lstat at once, its bytes are never read
        forged = self.arch / "20260903T000000Z-abcdef\nINFO: forged line" / "openclaw-state-x.tar.gz.age"
        forged.parent.mkdir()
        forged.write_bytes(AGE_MAGIC)
        odd = self.arch / "20260904T000000Z-abcdef"
        odd.mkdir()
        fifo = odd / "openclaw-state-fifo.tar.gz.age"
        os.mkfifo(fifo, 0o600)
        self.long_link(odd / "openclaw-state-long.tar.gz.age")
        victim = self.victim("victim", {"openclaw-state-v.tar.gz": b"victim's file",
                                        "run/openclaw-state-w.tar.gz.age": b"victim's archive"})
        os.symlink(str(victim / "openclaw-state-v.tar.gz"), odd / "openclaw-state-v.tar.gz")
        os.symlink(str(victim / "run"), self.arch / "20260905T000000Z-abcdef")  # a linked run directory
        self.long_link(self.arch / "20260906T000000Z-abcdef")
        size = {q: os.lstat(q).st_size for q in (r.file, plain, forged)}
        done = self.watchdog(fifo, r.adir / "SHA256SUMS", after=3)
        try:
            lines, touched = self.status()
        finally:
            elapsed, fired = done()
        self.assertFalse(fired, "status_lines blocked on a FIFO in /share")
        self.assertLess(elapsed, 2.0)
        self.assertEqual(touched, [])
        self.assertEqual(sorted(self.listed(lines)), sorted([
            f"  {r.file} ({C.human(size[r.file])}, encrypted)",
            f"  {plain} ({C.human(size[plain])}, PLAINTEXT: unencrypted secrets)",
            f"  {huge} (1.0 TiB, encrypted)",
            f"  {self.arch}/20260903T000000Z-abcdef\\x0aINFO: forged line/{forged.name} ({C.human(size[forged])}, "
            "encrypted)"]))
        self.assertNotIn("sha256", "\n".join(lines))
        self.assertTrue(all(x.isprintable() for x in lines), lines)
        # the journal's record of the run's archive is shown as recorded, never checked against /share
        self.assertIn(f"  archive (earlier add-on version): {r.adir}/{r.file.name}; auto-delete due {iso(T0 + H48)}",
                      lines)


# --- Stage A plaintext archives (/config/.openclaw/upgrade-backups) -----------------------------------------

class StageATests(SecEnv):
    NAME = "openclaw-state-20260101-120000-before-2026.7.35.tar.gz"

    def setUp(self):
        super().setUp()
        self.sa = self.state / "upgrade-backups"
        self.sa.mkdir()

    def marker(self, runtime, completed_at=T0):
        m = {"schema": 1, "runtime": runtime, "mode": "from-7x", "run_id": "r"}
        if completed_at is not None:
            m["completed_at"] = iso(completed_at)
        self.gp["MARKER"].write_text(json.dumps(m))

    def archive(self, name, mtime):
        f = self.sa / name
        f.write_bytes(b"\x1f\x8b plaintext stage A archive")
        self.age_old(f, mtime)
        return f

    def test_deleted_hours_after_the_later_of_mtime_and_marker_completion(self):
        self.marker(T.RUNTIME, completed_at=T0)
        old = self.archive(self.NAME, T0 - timedelta(days=10))
        tmp = self.archive("openclaw-state-20260102-120000-before-2026.7.35.tar.gz.tmp", T0 - timedelta(days=9))
        new = self.archive("openclaw-state-20261001-170000-before-2026.7.35.tar.gz", T0 + timedelta(hours=5))
        other = self.sa / "README.txt"
        other.write_text("not an archive")
        self.assertEqual(self.cleanup(T0 + H48 - SEC), 0)
        self.assertTrue(old.exists() and tmp.exists() and new.exists())
        self.assertEqual(self.cleanup(T0 + H48), 2)
        self.assertIn(f"[cleanup] Stage A plaintext archive {old.name}: deleted 1 item(s)", self.text)
        self.assertIn(f"[cleanup] Stage A plaintext archive {tmp.name}: deleted 1 item(s)", self.text)
        self.assertFalse(old.exists() or tmp.exists())
        self.assertTrue(new.exists())
        self.assertEqual(self.cleanup(T0 + timedelta(hours=5) + H48 - SEC), 0)
        self.assertTrue(new.exists())
        self.assertEqual(self.cleanup(T0 + timedelta(hours=5) + H48), 1)
        self.assertFalse(new.exists())
        self.assertTrue(other.exists() and self.sa.is_dir())

    def test_marker_without_completion_time_uses_the_mtime_and_any_2026_8_plus_runtime_counts(self):
        for runtime in ("2026.8.0", "2026.10.4", T.RUNTIME):
            with self.subTest(runtime=runtime):
                self.marker(runtime, completed_at=None)
                f = self.archive(self.NAME, T0)
                self.assertEqual(self.cleanup(T0 + H48 - SEC), 0)
                self.assertEqual(self.cleanup(T0 + H48), 1)
                self.assertFalse(f.exists())

    def test_kept_without_a_marker_or_with_a_7x_marker(self):
        f = self.archive(self.NAME, T0 - timedelta(days=100))
        late = T0 + timedelta(days=365)
        self.assertEqual(self.cleanup(late), 0)
        for m in ({"runtime": "2026.7.35", "completed_at": iso(T0)}, {"runtime": "2026.7.99"}, {"completed_at": iso(T0)},
                  {"runtime": "garbage"}, {"runtime": None}, [1], "x"):
            with self.subTest(marker=m):
                self.gp["MARKER"].write_text(json.dumps(m))
                self.assertEqual(self.cleanup(late), 0)
                self.assertTrue(f.exists())
        self.assertNotIn("Stage A", " ".join(t[1] for t in G.cleanup_targets(self.gp, late, 48)))

    def test_other_names_directories_and_symlinks_are_never_deleted(self):
        self.marker(T.RUNTIME, completed_at=T0 - timedelta(days=30))
        old = T0 - timedelta(days=30)
        victim = self.victim("victim-sa", {self.NAME: b"victim", "file.bin": b"victim file"})
        before = tree(victim)
        odd = ["openclaw-state-latest.tar.gz", self.NAME + ".age", self.NAME + ".bak", "x" + self.NAME,
               "openclaw-state-2026010-120000-before-2026.7.35.tar.gz", "notes.txt",
               "openclaw-state-20260101-120000-before-.tar.gz"]
        for n in odd:
            self.archive(n, old)
        d = self.sa / "openclaw-state-20260101-130000-before-2026.7.35.tar.gz"
        d.mkdir()
        self.age_old(d, old)
        link = self.sa / "openclaw-state-20260101-140000-before-2026.7.35.tar.gz"
        os.symlink(str(victim / "file.bin"), link)
        self.age_old(link, old)
        self.assertEqual(self.cleanup(T0 + H48), 0, self.text)
        for n in odd:
            self.assertTrue((self.sa / n).is_file(), n)
        self.assertTrue(d.is_dir() and os.path.islink(link))
        self.assertEqual(tree(victim), before)
        # a symlinked upgrade-backups directory is never listed
        os.rename(self.sa, self.state / "sa-real")
        os.symlink(str(victim), self.sa)
        self.assertEqual(self.cleanup(T0 + H48), 0)
        self.assertEqual(tree(victim), before)


# --- retention after a post-run hold -----------------------------------------------------------------------

class RetentionBaseTests(SecEnv):
    def test_a_later_journal_event_moves_the_due_time(self):
        cleared = T0 + timedelta(hours=72)
        r = self.make_run(finished=T0, history=[
            {"at": iso(T0 - timedelta(hours=1)), "event": "journal hold: earlier"},  # before the finish: ignored
            {"at": iso(cleared), "event": "journal done: retry after exit78: hold cleared"},
            {"at": iso(T0 + timedelta(hours=200)), "event": "first write"},  # not a journal event: ignored
            {"at": "not a date", "event": "journal done: garbage"}, "junk"])
        self.assertEqual(G.run_due_base(r.j), cleared)
        due = cleared + H48
        self.assertEqual(self.cleanup(T0 + H48), 0)  # finished_at + 48 h is not enough any more
        self.assertEqual(self.lines, [f"[cleanup] run {r.rid}: 1 item(s) (doctor captures / archive) will be deleted "
                                      f"at {iso(due)}"])
        self.assertEqual(self.cleanup(due - SEC), 0)
        self.assertTrue(r.adir.is_dir())
        self.assertEqual(self.cleanup(due), 1)
        self.assertFalse(os.path.lexists(r.adir))

    def test_exit78_hold_cleared_by_retry_restarts_the_retention(self):
        """The real sequence: gate run done -> exit 78 HOLD -> oc-upgrade retry -> next start closes the hold."""
        self.build_735()
        doc = self.bin / "capture-doctor"
        doc.write_text(CAPTURE_DOCTOR)
        doc.chmod(0o755)
        self.hooks(doctor_cmd=[str(doc), str(self.bin / "fake-doctor")])
        self.assertEqual(self.run_gate(), 0, self.out + self.err)
        j = self.journal()
        fin = G._parse_backup_date(j["finished_at"])
        items = G.cleanup_targets(self.gp, fin, 48)
        paths = [p for t in items if t[0] == j["run_id"] for p in t[3]]
        self.assertGreaterEqual(len(paths), 2, items)  # the doctor captures of both passes (no archive any more)
        self.assertFalse(any(Path(p).is_relative_to(self.share) for p in paths), paths)

        self.assertEqual(self.quiet(G.hold_after_start, "exit78", None, emit=print), 0)
        self.assertEqual(self.journal()["status"], "hold")
        self.assertEqual(self.cleanup(fin + timedelta(hours=72)), 0)
        self.assertEqual(self.lines, ["[cleanup] paused: hold"])

        self.assertEqual(G.retry_cmd([], emit=lambda s: None), 0)
        shift = timedelta(hours=72)
        real_now = C.utc_now
        with mock.patch.object(C, "utc_now", side_effect=lambda: real_now() + shift):
            self.assertEqual(self.run_gate(), 0, self.out + self.err)  # the next start: hold closed, no gate
        j = self.journal()
        self.assertEqual(j["status"], "done")
        cleared = G._parse_backup_date(j["history"][-1]["at"])
        self.assertTrue(j["history"][-1]["event"].startswith("journal done: "), j["history"][-1])
        self.assertGreaterEqual(cleared - fin, shift - timedelta(minutes=5))
        due = cleared + H48
        self.assertEqual(self.cleanup(fin + H48 + timedelta(minutes=1)), 0)
        self.assertIn(f"will be deleted at {iso(due)}", self.text)
        self.assertEqual(self.cleanup(due - SEC), 0)
        self.assertTrue(all(os.path.lexists(p) for p in paths))
        self.assertEqual(self.cleanup(due), len(paths), self.text)
        self.assertFalse(any(os.path.lexists(p) for p in paths))


    def test_a_post_run_hold_superseded_by_a_new_run_restarts_the_retention(self):
        """retry --doctor after an exit-78 hold starts a new run: the old run's journal gets a 'journal superseded'
        event when it is copied, so its doctor captures (and the archive of a 0.5.94-full2 run) outlive the new run
        by gate_cleanup_hours."""
        r = self.make_run(finished=T0)
        prev = dict(r.j, status="hold", hold={"code": "exit78", "codes": ["exit78"], "phase": "gateway"})
        g = G.Gate()
        g.j = None
        superseded = T0 + timedelta(hours=100)
        real_iso, sup_iso = C.utc_iso, iso(superseded)
        with mock.patch.object(C, "utc_iso", side_effect=lambda dt=None: sup_iso if dt is None else real_iso(dt)), \
                mock.patch.object(G, "new_run_id", return_value=self.new_rid()):
            try:
                g.start({"action": "run", "journal": prev, "mode": "maintenance",
                         "pkg": {"version": T.RUNTIME, "schema_state": 19, "schema_agent": 24}})
            except Exception as exc:  # noqa: BLE001 (only the copy of the previous journal matters here)
                self.start_error = exc
        copied = json.loads((self.gp["RUNS"] / r.rid / "journal.json").read_text())
        self.assertEqual(copied["history"][-1]["event"], "journal superseded by a new run")
        self.assertEqual(G.run_due_base(copied), superseded)
        self.assertEqual(self.cleanup(T0 + timedelta(hours=101)), 0)
        self.assertTrue(r.adir.is_dir())
        self.assertEqual(self.cleanup(superseded + H48), 1)

    def test_a_moved_due_time_is_recorded_and_logged_once(self):
        r = self.make_run(finished=T0)
        self.assertEqual(self.cleanup(T0 + timedelta(hours=1)), 0)  # announced for T0 + 48 h
        rec = r.rd / "cleanup.json"
        self.assertEqual(json.loads(rec.read_text())["due_at"], iso(T0 + H48))
        cleared = T0 + timedelta(hours=60)
        j = dict(r.j, history=[{"at": iso(cleared), "event": "journal done: retry after exit78"}])
        (r.rd / "journal.json").write_text(json.dumps(j))
        state = {}
        self.assertEqual(self.cleanup(T0 + timedelta(hours=61), state=state), 0)
        self.assertEqual(self.lines, [f"[cleanup] run {r.rid}: deletion moved to {iso(cleared + H48)}"])
        self.assertEqual(json.loads(rec.read_text())["due_at"], iso(cleared + H48))
        self.assertEqual(self.cleanup(T0 + timedelta(hours=62), state=state), 0)
        self.assertEqual(self.lines, [])
        self.assertEqual(self.cleanup(cleared + H48, state=state), 1)
        self.assertEqual(json.loads(rec.read_text())["due_at"], iso(cleared + H48))


class TargetEnumerationTests(SecEnv):
    def test_an_unusable_journal_never_stops_the_other_runs(self):
        a = self.make_run(finished=T0)
        b = self.make_run(finished=T0)
        (a.rd / "journal.json").write_text(json.dumps(dict(a.j, history=1)))  # not a list
        self.assertEqual(self.cleanup(T0 + H48), 2)
        self.assertFalse(os.path.lexists(a.adir) or os.path.lexists(b.adir))
        c = self.make_run(finished=T0)
        d = self.make_run(finished=T0)
        (c.rd / "journal.json").write_text(json.dumps(dict(c.j, finished_at="9999-12-31T23:00:00Z")))
        self.assertEqual(self.cleanup(T0 + H48), 1)  # c: date overflow, reported; d: deleted
        self.assertTrue(c.adir.is_dir())
        self.assertFalse(os.path.lexists(d.adir))
        self.assertTrue(any(f"run {c.rid}: kept" in x and "journal unusable" in x for x in self.lines), self.lines)

    def test_a_failing_root_scan_is_reported_once_and_the_runs_are_still_handled(self):
        r = self.make_run(finished=T0)
        real = G._scan_rehearsal

        def boom(*a, **kw):
            raise OSError(5, "Input/output error")
        state = {}
        with mock.patch.object(G, "_scan_rehearsal", side_effect=boom):
            self.assertEqual(self.cleanup(T0 + H48, state=state), 1)
            self.assertFalse(os.path.lexists(r.adir))
            self.assertTrue(any("rehearsal scan" in x and "Input/output error" in x for x in self.lines), self.lines)
            self.cleanup(T0 + H48 + SEC, state=state)
            self.assertEqual([x for x in self.lines if "rehearsal scan" in x], [])  # once per loop
        self.assertIs(G._scan_rehearsal, real)

# --- Supervisor client hardening ----------------------------------------------------------------------------

class RawServer:
    """127.0.0.1 listener that reads one request head per connection and lets handler(conn, stop) answer."""

    def __init__(self, handler):
        self.handler = handler
        self.stop = threading.Event()
        self.requests = []
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.srv.settimeout(0.1)
        self.url = f"http://127.0.0.1:{self.srv.getsockname()[1]}"
        self.th = threading.Thread(target=self._run, daemon=True)
        self.th.start()

    def _run(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(5)
                buf = b""
                try:
                    while b"\r\n\r\n" not in buf:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        buf += chunk
                    self.requests.append(buf)
                    self.handler(conn, self.stop)
                except OSError:
                    pass

    def close(self):
        self.stop.set()
        self.th.join(10)
        self.srv.close()


def http_head(length, status="200 OK"):
    return (f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {length}\r\n"
            "Connection: close\r\n\r\n").encode()


class SupervisorHardeningTests(SecEnv):
    def setUp(self):
        super().setUp()
        os.environ.pop("SUPERVISOR_TOKEN", None)
        os.environ.pop("HASSIO_TOKEN", None)
        self.missing = str(self.tmp / "no-such-token-file")

    def server(self, handler):
        s = RawServer(handler)
        self.addCleanup(s.close)
        return s

    def assert_absent(self, secret, *texts):
        """secret appears in no text and no file of the temporary tree; a failure names the place, never the value
        (the values are synthetic, but a regression must not turn the test log into a leak either)."""
        for i, t in enumerate(texts):
            self.assertTrue(secret not in t, f"secret found in text #{i}")
        for q in self.tmp.rglob("*"):
            if q.is_file() and not q.is_symlink():
                self.assertTrue(secret.encode() not in q.read_bytes(), f"secret found in {q.relative_to(self.tmp)}")

    @staticmethod
    def masked(text, *secrets):
        for x in secrets:
            text = text.replace(x, "<secret>")
        return text

    def test_env_and_file_tokens_with_whitespace_or_control_characters_are_rejected(self):
        secret = f"SEKRET-{uuid.uuid4().hex[:12]}"
        # (a NUL byte cannot be in the environment at all)
        for i, bad in enumerate((f"{secret}\nx", f"{secret}\rx", f"{secret} x", f"{secret}\tx", f"{secret}\x7f",
                                 f"\x1b{secret}", f"tök-{secret}", "x" * 1025)):
            with self.subTest(case=i):  # the label never shows the value
                os.environ["SUPERVISOR_TOKEN"] = bad
                self.assertTrue(C.supervisor_token(self.missing) is None, "an unusable token was accepted")
        os.environ["SUPERVISOR_TOKEN"] = f"  {secret}  \n"
        self.assertTrue(C.supervisor_token(self.missing) == secret, "surrounding whitespace is not stripped")
        f = self.tmp / "tok"
        f.write_text(f"abc\ndef-{secret}\n")
        self.assertTrue(C.supervisor_token(str(f)) == secret, "a file token with an inner newline was used")
        f.write_bytes(b"\xff\xfe-not-utf8")
        self.assertTrue(C.supervisor_token(str(f)) == secret, "an undecodable token file was used")

    def test_supervisor_get_refuses_an_invalid_token_without_connecting_or_echoing_it(self):
        secret = f"SEKRET-{uuid.uuid4().hex[:12]}"
        with mock.patch("http.client.HTTPConnection", side_effect=AssertionError("no connection expected")):
            for i, bad in enumerate((f"{secret}\nx", f"{secret} x", "", None)):
                with self.subTest(case=i):
                    with self.assertRaises(C.SupervisorError) as cm:
                        C.supervisor_get("/backups/info", bad, base=f"http://127.0.0.1:{free_port()}", timeout=1)
                    self.assertEqual((cm.exception.status, cm.exception.message), (0, "invalid Supervisor token"))
                    self.assertTrue(secret not in str(cm.exception), "the token is in the error")

    def test_value_errors_from_http_client_never_carry_the_token(self):
        secret = f"SEKRET-{uuid.uuid4().hex[:12]}"

        class Conn:
            def __init__(self, *a, **kw):
                pass

            def request(self, method, path, headers=None):
                raise ValueError(f"Invalid header value b'{headers['Authorization']}'")

            def close(self):
                pass
        caught, escaped = None, None
        with mock.patch("http.client.HTTPConnection", Conn):
            try:
                C.supervisor_get("/backups/info", secret, base="http://127.0.0.1:9", timeout=1)
            except C.SupervisorError as exc:
                caught = exc
            except Exception as exc:  # noqa: BLE001 (its text carries the token: report the type only)
                escaped = type(exc).__name__
        self.assertIsNone(escaped, "the exception escaped supervisor_get unmapped")
        self.assertIsNotNone(caught)
        self.assertEqual((caught.status, caught.message), (0, "invalid request"))
        self.assertTrue(secret not in str(caught), "the token is in the error")
        self.assertIsNone(caught.__cause__)
        self.assertTrue(caught.__suppress_context__)

    def test_gate_holds_unverified_for_an_env_token_with_a_newline_and_never_records_it(self):
        secret = f"SEKRET-{uuid.uuid4().hex[:12]}"
        self.build_735()
        os.environ["SUPERVISOR_TOKEN"] = f"{secret}\nx"
        srv = self.server(lambda conn, stop: conn.sendall(http_head(2) + b"{}"))
        self.hooks(skip_backup_check=False, supervisor_url=srv.url, supervisor_token_file=self.missing)
        rc = self.run_gate()
        self.assertEqual(rc, 20, self.masked(self.out + self.err, secret))
        j = self.journal()
        self.assertEqual((j["status"], j["hold"]["code"], j["phase"]), ("hold", "ha-backup-unverified", "precheck"))
        self.assertIn("no Supervisor token", self.masked(j["hold"]["message"], secret))
        # without an archive of the gate's own, the hold says what is at stake
        self.assertTrue(j["hold"]["message"].endswith("; the Home Assistant backup is the only rollback point"),
                        self.masked(j["hold"]["message"], secret))
        self.assertEqual(len(srv.requests), 0)  # the token never left the process
        self.assert_absent(secret, self.out, self.err)

    def test_deeply_nested_json_is_a_supervisor_error(self):
        depth = 200_000
        body = b'{"result": "ok", "data": {"backups": ' + b"[" * depth + b"]" * depth + b"}}"
        srv = self.server(lambda conn, stop: conn.sendall(http_head(len(body)) + body))
        with self.assertRaises(C.SupervisorError) as cm:
            C.supervisor_get("/backups/info", "tok-123", base=srv.url, timeout=5)
        self.assertEqual((cm.exception.status, cm.exception.message), (0, "invalid JSON response"))

    def test_content_addons_must_be_a_list_of_slugs(self):
        now = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)

        def entry(value, key="addons"):
            return {"slug": "b1", "name": "n", "date": (now - timedelta(hours=1)).isoformat(), "type": "full",
                    "protected": True, "location_attributes": {".local": {"protected": True}},
                    "content": {"homeassistant": True, key: value}}
        ok = G.evaluate_ha_backups([entry([SLUG])], SLUG, now, 24 * 3600)
        self.assertEqual((ok["with_slug"], len(ok["candidates"])), (1, 1))
        self.assertEqual(G.evaluate_ha_backups([entry([7, None, SLUG])], SLUG, now, 24 * 3600)["with_slug"], 1)
        for value, key in ((SLUG, "addons"), (f"core_mosquitto,{SLUG}", "addons"), (SLUG, "apps"),
                           ({SLUG: True}, "addons"), ([{"slug": SLUG}], "addons"), ([[SLUG]], "addons"),
                           ([f"{SLUG}_old", f"x{SLUG}"], "addons"), ((SLUG,), "addons")):
            with self.subTest(value=value, key=key):
                b = entry(value, key)
                if isinstance(value, tuple):
                    b = json.loads(json.dumps(b))  # a tuple arrives as a list over JSON: only the str check applies
                    self.assertEqual(G.evaluate_ha_backups([b], SLUG, now, 24 * 3600)["with_slug"], 1)
                    continue
                r = G.evaluate_ha_backups([b], SLUG, now, 24 * 3600)
                self.assertEqual((r["with_slug"], r["candidates"], r["newest_with_slug"]), (0, [], None), r)

    def test_a_slow_drip_body_is_cut_off_by_the_overall_deadline(self):
        def drip(conn, stop):
            conn.sendall(http_head(4096))
            end = time.monotonic() + 5
            while time.monotonic() < end and not stop.is_set():
                conn.sendall(b" ")
                time.sleep(0.05)
        srv = self.server(drip)
        t0 = time.monotonic()
        with self.assertRaises(C.SupervisorError) as cm:
            C.supervisor_get("/backups/info", "tok-123", base=srv.url, timeout=0.3)  # overall limit 0.9 s
        elapsed = time.monotonic() - t0
        self.assertEqual(cm.exception.status, 0)
        self.assertLess(elapsed, 2.5, f"slow drip kept the request open for {elapsed:.1f} s")

    def test_internal_error_hold_text_and_traceback_are_redacted(self):
        pw = f"pw-{uuid.uuid4().hex[:12]}"
        bearer = f"bt-{uuid.uuid4().hex[:12]}"
        msg = f"boom password={pw} Authorization: Bearer {bearer}"

        def phase_cleanup(_self):
            raise RuntimeError(msg)
        self.build_735()
        self.hooks()
        with mock.patch.object(G.Gate, "phase_cleanup", phase_cleanup):
            rc = self.run_gate()
        self.assertEqual(rc, 1, self.masked(self.out + self.err, pw, bearer))
        j = self.journal()
        self.assertEqual((j["status"], j["hold"]["code"]), ("hold", "internal-error"))
        hold_msg = self.masked(j["hold"]["message"], pw, bearer)
        self.assertIn("password=***", hold_msg)
        self.assertIn("Bearer ***", hold_msg)
        self.assertIn("Traceback", self.err)  # the traceback is still written, redacted
        self.assertIn("RuntimeError: boom password=***", self.err)
        for x in (pw, bearer):
            self.assert_absent(x, self.out, self.err)
        events = (self.gp["RUNS"] / j["run_id"] / "events.log").read_text()
        self.assertIn("RuntimeError: boom password=***", self.masked(events, pw, bearer))


# --- names from /share listings ---------------------------------------------------------------------------

class ShareNameTests(SecEnv):
    # Regression: names from a /share listing never reach a log line raw, and the cleanup only touches directories
    # named like earlier add-on versions created them (run ids and their tombstones, exports <ts> or <ts>-XXXXXX):
    # a renamed or foreign directory is left alone, its export files included (they are not the add-on's any
    # more), and an empty directory of its owner survives.
    def test_foreign_names_in_share_are_never_handled_or_logged(self):
        fake = "[gate] info: archive sha256 " + "f" * 64 + "…"
        self.arch.mkdir(parents=True)
        odd_arch = [G.TOMB_PREFIX + "x\n" + fake,  # a tombstone name whose suffix is no run id
                    G.TOMB_PREFIX + "20260901T000000Z-abcdef\n",  # `$` accepted the trailing newline
                    "20260901T000000Z-abcdef\n" + fake, "20260901T000000Z-abcdef\n", "20260901T000000Z-ABCDEF"]
        for n in odd_arch:
            (self.arch / n).mkdir()
            (self.arch / n / "openclaw-state-x.tar.gz.age").write_bytes(AGE_MAGIC)
            self.age_old(self.arch / n, T0 - timedelta(days=30))
        odd_reh = ["evil\nINFO: fake", "20260901-000000\nINFO: fake", "20260901-000000\n",
                   "20260901-000000-AbC123.moved", "20260901-000000-AbC12", "x20260901-000000"]
        for n in odd_reh:
            d = self.reh / n
            d.mkdir(parents=True)
            for f in (EXPORT_TMP, "openclaw-rehearsal.tar.gz.tmp", EXPORT_FILE):
                (d / f).write_bytes(b"ENCRYPTED")
                self.age_old(d / f, T0 - timedelta(days=30))
        (self.reh / "owner-dir").mkdir()  # empty: a cleanup that removes every empty directory would take it
        (self.reh / "20260901-000001-Empty1.moved").mkdir()
        before = tree(self.share)

        lines = []
        self.assertEqual(G.cleanup_pass(now=T0 + timedelta(days=365), hours=48, emit=lines.append), 0)
        self.assertEqual(G.cleanup_cmd([], emit=lines.append), 0)
        self.assertEqual(tree(self.share), before)  # nothing touched, moved or removed
        text = "\n".join(lines)
        for line in text.splitlines():
            self.assertFalse(line.startswith(("[gate]", "INFO:")), line)
        for needle in ("evil", "fake", "abcdef", "ABCDEF", "moved", "owner-dir", "AbC12", "x20260901"):
            self.assertNotIn(needle, text)

    def test_names_that_are_logged_have_control_characters_escaped(self):
        self.assertEqual(G.printable("a\nb\rc\x1b[31md\x7f\u2028e…/x y"),
                         "a\\x0ab\\x0dc\\x1b[31md\\x7f\\x2028e…/x y")
        # a run whose doctor log names a capture outside the capture root with a control character in its path:
        # the "kept" WARN shows it escaped, on one line
        r = SimpleNamespace(rid="20261001T120000Z-0000ff")
        rd = self.gp["RUNS"] / r.rid
        rd.mkdir(parents=True)
        (rd / "journal.json").write_text(json.dumps({"run_id": r.rid, "status": "done", "finished_at": iso(T0)}))
        bad = f"/tmp/\x08\x08\x08\x1b]0;x\x07doctor-{uuid.uuid4()}"  # backspaces, an OSC title sequence
        (rd / "doctor-pass1.log").write_text(f"Pre-repair state retained for manual recovery at {bad}/manifest.json.\n")
        lines = []
        G.cleanup_pass(now=T0 + H48, hours=48, emit=lines.append)
        kept = [x for x in lines if "kept" in x]
        self.assertEqual(len(kept), 1, lines)
        self.assertIn("/tmp/\\x08\\x08\\x08\\x1b]0;x\\x07doctor-", kept[0])
        self.assertTrue(all(c.isprintable() for c in kept[0]), kept[0])


if __name__ == "__main__":
    unittest.main()
