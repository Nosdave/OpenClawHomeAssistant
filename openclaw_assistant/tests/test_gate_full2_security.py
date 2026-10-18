"""Regression tests for the security and correctness review fixes of add-on 0.5.94-full2 (commit 7d1b347).

Every race is simulated deterministically: a swap happens between oc_gate.cleanup_targets() and the deletes of
cleanup_pass() (by wrapping cleanup_targets), or inside a function the code calls between its check and its use
(_dir_bytes in _delete_entry), never by a concurrent attacker thread. Stalls are detected by looking at the worker
thread's Python stack, not by sleeping.

Covers:
- /share symlink swaps: /share/openclaw-upgrade, /share/openclaw-rehearsal, a rehearsal <ts> directory, a run
  directory and tombstones turned into symlinks to a victim directory under the config root after the cleanup
  listed its targets: nothing in the victim is deleted.
- phase_archive: symlinked /share/openclaw-upgrade or <run> (encrypted and off), invalid run ids, file modes of
  the tmp / manifest / SHA256SUMS created through the run directory's fd.
- stream_encrypted_archive: a stalled age is stopped by STOP and by the deadline (watchdog), a failing output fd
  is reported as a write failure (ENOSPC / EPIPE) and wins over the tar rc -15 the gate caused itself, no thread
  traceback after a STOP.
- cleanup robustness, Stage A plaintext archives, retention after a cleared post-run hold.
- Supervisor client hardening: token validation, deep JSON, content.addons type, overall deadline, redacted
  internal-error HOLDs.

Python tests must run inside `unshare --pid --fork --mount-proc` on hosts with rehearsal containers (their
OpenClaw processes would make the openclaw-running precheck HOLD); find_openclaw_processes is additionally
filtered to this test's own temporary tree.
"""

import errno
import hashlib
import io
import json
import os
import re
import socket
import stat
import subprocess
import sys
import threading
import time
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
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
FAKE_PUB = "age1" + "q" * 58  # syntactically valid; age never runs with it
PUB = T.AGE_PUB or FAKE_PUB
T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
H48 = timedelta(hours=48)
SEC = timedelta(seconds=1)
MIB = 1024 * 1024
SLUG = "a0d7b954_openclaw_assistant"

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

    def make_run(self, finished=T0, captures=0, history=None, rid=None):
        """A finished gate run as the gate leaves it: runs/<id>/journal.json, its encrypted archive directory under
        /share/openclaw-upgrade and its doctor captures named in runs/<id>/doctor-pass1.log."""
        rid = rid or self.new_rid()
        rd = self.gp["RUNS"] / rid
        rd.mkdir(parents=True, exist_ok=True)
        adir = self.arch / rid
        adir.mkdir(parents=True)
        name = f"openclaw-state-20261001-120000-before-{T.RUNTIME}.tar.gz.age"
        (adir / name).write_bytes(G.AGE_MAGIC + os.urandom(2000))
        (adir / "SHA256SUMS").write_text(f"{C.sha256_file(adir / name)}  {name}\n")
        (adir / "manifest.json").write_text("{}\n")
        caps = [self.capture() for _ in range(captures)]
        lines = [f"Pre-repair state retained for manual recovery at {c}/manifest.json." for c in caps]
        (rd / "doctor-pass1.log").write_text("\n".join(["┌  OpenClaw doctor"] + lines + ["└  Doctor complete."]) + "\n")
        j = {"run_id": rid, "mode": "from-7x", "status": "done", "phase": "finalize",
             "started_at": iso(finished - timedelta(minutes=5)), "finished_at": iso(finished),
             "first_write_at": iso(finished - timedelta(minutes=4)), "phases_done": [], "doctor": [],
             "history": history or [],
             "archive": {"mode": "encrypted", "format": "tar.gz+age", "dir": str(adir), "file": name,
                         "recipient": FAKE_PUB, "verified": True}}
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


# --- /share symlink swaps during the cleanup ---------------------------------------------------------------

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
        ts = "20260902-000000-AbC123"  # the mktemp -d form run.sh creates now
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
        victim = self.victim("victim-tomb", {"precious.txt": b"keep me", "deep/x.tar.gz.age": G.AGE_MAGIC})
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


# --- phase_archive: the run directory is reached through dir fds -------------------------------------------

class ArchiveEnv(SecEnv):
    RID = "20261018T000000Z-abcdef"

    def setUp(self):
        super().setUp()
        T.make_735_state(self.state)
        self.write_cfg(T.CFG_735)
        (self.ws / "AGENTS.md").write_text("# a\n")
        Path(f"{self.ws}.attested").write_bytes(G.ATTESTATION_HEADER)
        self.lines = []

    def gate(self, rid=None, mode="encrypted"):
        g = G.Gate(emit=self.lines.append)
        g.pkg = C.runtime_package()
        g.cfg = dict(T.CFG_735)
        opt = {"mode": "off", "recipient": None} if mode == "off" else \
            {"mode": "encrypted", "recipient": PUB, "age_version": "test"}
        g.j = {"run_id": self.RID if rid is None else rid, "mode": "from-7x", "history": [],
               "source": {"config_last_touched": "2026.7.35"}, "auth_profiles": [], "archive_opt": opt}
        return g

    def fake_bin(self, name, body):
        f = self.bin / name
        f.write_text("#!/bin/sh\n" + body)
        f.chmod(0o755)
        return str(f)

    def stale_victim(self, name, sub=""):
        p = f"{sub}/" if sub else ""
        return self.victim(name, {f"{p}openclaw-state-20260101-000000-before-2026.7.35.tar.gz": b"stage A rollback",
                                  f"{p}openclaw-state-20260101-000000-before-2026.9.9.tar.gz.age": b"other archive",
                                  f"{p}partial.tmp": b"user tmp", f"{p}manifest.json": b"victim manifest",
                                  f"{p}keep.txt": b"keep me"})

    def assert_hold(self, fn, code, needle):
        with self.assertRaises(G.HoldError) as cm:
            fn()
        f = cm.exception.findings[0]
        self.assertEqual(f["code"], code, f)
        self.assertIn(needle, f["message"])
        return f["message"]


class ArchiveDirTests(ArchiveEnv):
    def test_symlinked_archives_root_holds_and_touches_nothing(self):
        victim = self.stale_victim("victim-root", sub=self.RID)
        os.symlink(str(victim), self.arch)
        before = tree(victim)
        with mock.patch.object(G, "stream_encrypted_archive", side_effect=AssertionError("must not run")):
            self.assert_hold(self.gate().phase_archive, "archive-failed", "cannot be created as a plain directory")
        self.assertEqual(tree(victim), before)
        self.assertTrue(os.path.islink(self.arch))

    def test_planted_run_dir_symlink_holds_and_touches_nothing(self):
        victim = self.stale_victim("victim-run")
        self.arch.mkdir()
        os.symlink(str(victim), self.arch / self.RID)
        before = tree(victim)
        with mock.patch.object(G, "stream_encrypted_archive", side_effect=AssertionError("must not run")):
            self.assert_hold(self.gate().phase_archive, "archive-failed", "cannot be created as a plain directory")
        self.assertEqual(tree(victim), before)
        self.assertTrue(os.path.islink(self.arch / self.RID))

    def test_off_mode_with_a_symlinked_archives_root_warns_and_leaves_the_target(self):
        victim = self.stale_victim("victim-off", sub=self.RID)
        os.symlink(str(victim), self.arch)
        before = tree(victim)
        g = self.gate(mode="off")
        g.phase_archive()
        self.assertEqual(g.j["archive"]["mode"], "off")
        self.assertEqual(tree(victim), before)
        warns = [x for x in self.lines if x.startswith("WARN [gate] ")]
        self.assertEqual(len(warns), 1, self.lines)
        self.assertIn("is not a plain directory", warns[0])
        self.assertIn("left alone", warns[0])

    def test_off_mode_removes_a_planted_run_link_without_following_it(self):
        victim = self.stale_victim("victim-off-run")
        self.arch.mkdir()
        os.symlink(str(victim), self.arch / self.RID)
        before = tree(victim)
        self.gate(mode="off").phase_archive()
        self.assertEqual(tree(victim), before)
        self.assertFalse(os.path.lexists(self.arch / self.RID))
        # an earlier attempt's real directory is still removed
        (self.arch / self.RID).mkdir()
        (self.arch / self.RID / "x.tar.gz.age.tmp").write_bytes(b"x")
        self.gate(mode="off").phase_archive()
        self.assertFalse(os.path.lexists(self.arch / self.RID))
        self.assertTrue(self.arch.is_dir())

    def test_invalid_run_ids_hold_before_any_path_is_used(self):
        outside = self.victim("outside", {"precious.txt": b"keep me", "x/precious.txt": b"keep me too"})
        for rid in ("../../x", "..", "a/../b", "a/b", str(outside), str(outside / "x"), ".hidden", "", "a" * 81):
            for mode in ("off", "encrypted"):
                with self.subTest(rid=rid, mode=mode):
                    before = tree(self.tmp)
                    self.lines = []
                    with mock.patch.object(G, "stream_encrypted_archive", side_effect=AssertionError("must not run")):
                        self.assert_hold(self.gate(rid=rid, mode=mode).phase_archive, "archive-failed",
                                         "invalid run id")
                    self.assertEqual(tree(self.tmp), before)  # nothing created, written or removed anywhere
                    self.assertEqual(self.lines, [])

    @NEEDS_AGE
    def test_tmp_manifest_and_sums_are_created_in_the_real_run_dir_0600_and_dir_0700(self):
        rdir = self.arch / self.RID
        rdir.mkdir(parents=True)
        os.chmod(rdir, 0o755)
        v_manifest = self.victim("victim-files", {"manifest.json": b"victim manifest", "sums": b"victim sums"})
        os.symlink(str(v_manifest / "manifest.json"), rdir / "manifest.json")  # planted links are replaced as links
        os.symlink(str(v_manifest / "sums"), rdir / "SHA256SUMS")
        before = tree(v_manifest)
        real = G.stream_encrypted_archive
        seen = {}

        def spy(tar_argv, age_argv, tmp, expected, **kw):
            fd = kw["out_fd"]
            st = os.fstat(fd)
            seen["fd_mode"] = stat.S_IMODE(st.st_mode)
            seen["fd_reg"] = stat.S_ISREG(st.st_mode)
            seen["dir_mode"] = stat.S_IMODE(os.lstat(rdir).st_mode)
            seen["dir_is_dir"] = stat.S_ISDIR(os.lstat(rdir).st_mode)
            tmps = [n for n in os.listdir(rdir) if n.endswith(".tmp")]
            seen["tmps"] = tmps
            seen["same_inode"] = [os.lstat(rdir / n).st_ino for n in tmps] == [st.st_ino]
            seen["tmp_real"] = os.path.realpath(str(tmp))
            old = os.umask(0o077)
            os.umask(old)
            seen["umask"] = old
            return real(tar_argv, age_argv, tmp, expected, **kw)
        g = self.gate()
        with mock.patch.object(G, "stream_encrypted_archive", side_effect=spy):
            g.phase_archive()
        self.assertEqual((seen["fd_mode"], seen["fd_reg"]), (0o600, True))
        self.assertEqual((seen["dir_mode"], seen["dir_is_dir"]), (0o700, True))
        self.assertEqual(len(seen["tmps"]), 1, seen)
        self.assertTrue(seen["same_inode"])
        self.assertEqual(seen["tmp_real"], str(rdir / seen["tmps"][0]))
        self.assertEqual(seen["umask"], 0o077)
        a = g.j["archive"]
        self.assertEqual(Path(a["dir"]), rdir)
        self.assertEqual(sorted(os.listdir(rdir)), sorted([a["file"], "manifest.json", "SHA256SUMS"]))
        self.assertEqual(stat.S_IMODE(os.lstat(rdir).st_mode), 0o700)
        for n in os.listdir(rdir):
            st = os.lstat(rdir / n)
            self.assertTrue(stat.S_ISREG(st.st_mode), n)
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o600, n)
        self.assertEqual(tree(v_manifest), before)
        self.assertEqual(json.loads((rdir / "manifest.json").read_text())["run_id"], self.RID)
        self.assertEqual((rdir / "SHA256SUMS").read_text().split(), [a["sha256"], a["file"]])


# --- stream_encrypted_archive: watchdog, write failures, clean shutdown ------------------------------------

class StreamEnv(ArchiveEnv):
    def setUp(self):
        super().setUp()
        self.procs = []
        real_popen = subprocess.Popen
        procs = self.procs

        def recording_popen(*a, **kw):
            p = real_popen(*a, **kw)
            procs.append(p)
            return p
        patcher = mock.patch.object(G.subprocess, "Popen", side_effect=recording_popen)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.kill_leftovers)
        self.src = self.tmp / "src"
        self.src.mkdir()
        (self.src / "random.bin").write_bytes(os.urandom(16 * MIB))  # incompressible: never fits in the pipes
        self.stalled_age = self.fake_bin("stalled-age", "head -c 1000 >/dev/null\nexec sleep 3600\n")

    def kill_leftovers(self):
        for p in self.procs:
            if p.poll() is None:
                C._killpg(p.pid, 9)
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    pass

    def tar_argv(self):
        return ["tar", "--create", "--file=-", f"--directory={self.src}", "--", "."]

    def stream(self, age_argv, out_fd=None, timeout=600):
        if out_fd is None:
            out_fd = os.open(str(self.tmp / "out.age"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        return G.stream_encrypted_archive(self.tar_argv(), age_argv, self.tmp / "out.age", {}, cwd=str(self.src),
                                          timeout=timeout, tar_log=self.tmp / "logs" / "tar.log",
                                          age_log=self.tmp / "logs" / "age.log", out_fd=out_fd)

    def run_in_worker(self, fn, stop_when_blocked=False, limit=30):
        """Run fn in a worker thread with stderr and threading.excepthook captured. With stop_when_blocked, STOP is
        set once the worker is seen blocked writing into age's stdin (_CountingSink.write) for 0.25 s."""
        res = {}
        hooked = []
        before = set(threading.enumerate())

        def target():
            t0 = time.monotonic()
            try:
                res["value"] = fn()
            except BaseException as exc:  # noqa: BLE001
                res["exc"] = exc
            res["elapsed"] = time.monotonic() - t0
        err = io.StringIO()
        with redirect_stderr(err), mock.patch.object(threading, "excepthook", side_effect=hooked.append):
            th = threading.Thread(target=target, daemon=True)
            th.start()
            if stop_when_blocked:
                self.wait_blocked_in_age_write(th)
                res["stop_at"] = time.monotonic()
                G.STOP.set()
            th.join(limit)
            if th.is_alive():
                self.kill_leftovers()
                th.join(30)
                self.fail(f"the archive stream did not end within {limit} s (STOP / deadline ignored)")
            for t in set(threading.enumerate()) - before:  # the pump and the watchdog end as well
                t.join(10)
                self.assertFalse(t.is_alive(), f"thread {t.name} still running")
        res["stderr"] = err.getvalue()
        res["excepthook"] = hooked
        return res

    def wait_blocked_in_age_write(self, th, limit=20):
        sink_code = (G._CountingSink.write.__code__, G._CountingSink.flush.__code__)
        hits, end = 0, time.monotonic() + limit
        while time.monotonic() < end and th.is_alive():
            f = sys._current_frames().get(th.ident)
            if f is not None and f.f_code in sink_code:  # top frame: inside the blocking write to age's stdin
                hits += 1
                if hits >= 5:
                    return
            else:
                hits = 0
            time.sleep(0.05)
        self.fail("the worker never blocked writing into the stalled age")

    def assert_reaped(self):
        self.assertGreaterEqual(len(self.procs), 2)
        for p in self.procs:
            self.assertIsNotNone(p.returncode, p.args)
            with self.assertRaises(ChildProcessError):
                os.waitpid(p.pid, os.WNOHANG)

    def assert_clean_shutdown(self, res):
        self.assertEqual(res["excepthook"], [])
        self.assertNotIn("Exception in thread", res["stderr"])
        self.assertNotIn("Traceback", res["stderr"])
        self.assertNotIn("still running", res["stderr"])


class StreamWatchdogTests(StreamEnv):
    def test_stop_while_blocked_writing_to_a_stalled_age_raises_gate_stopped(self):
        res = self.run_in_worker(lambda: self.stream([self.stalled_age]), stop_when_blocked=True)
        self.assertIsInstance(res.get("exc"), G.GateStopped, res)
        self.assertLess(time.monotonic() - res["stop_at"], 15)
        self.assert_reaped()
        self.assert_clean_shutdown(res)

    def test_deadline_while_blocked_writing_to_a_stalled_age_is_a_timeout(self):
        res = self.run_in_worker(lambda: self.stream([self.stalled_age], timeout=2))
        self.assertNotIn("exc", res, res)
        r = res["value"]
        self.assertEqual(r["failure"], "timeout", r)
        self.assertLess(res["elapsed"], 20)
        self.assert_reaped()
        self.assert_clean_shutdown(res)

    def test_failing_output_fd_is_a_write_failure_with_the_errno_text(self):
        cat_age = self.fake_bin("cat-age", "exec cat\n")
        r_end, w_end = os.pipe()
        os.close(r_end)
        cases = [("ENOSPC", lambda: os.open("/dev/full", os.O_WRONLY), os.strerror(errno.ENOSPC)),
                 ("EPIPE", lambda: w_end, os.strerror(errno.EPIPE))]
        for label, make_fd, text in cases:
            with self.subTest(label):
                del self.procs[:]
                fd = make_fd()
                res = self.run_in_worker(lambda: self.stream([cat_age], out_fd=fd))
                self.assertNotIn("exc", res, res)
                r = res["value"]
                self.assertEqual((r["failure"], r["detail"]), ("write", text), r)
                self.assert_reaped()
                self.assert_clean_shutdown(res)

    def test_phase_archive_stop_while_age_stalls_is_gate_stopped_and_leaves_no_tmp(self):
        (self.ws / "big.bin").write_bytes(os.urandom(8 * MIB))
        g = self.gate()
        with mock.patch.dict(os.environ, {"OC_ADDON_AGE": self.stalled_age}):
            res = self.run_in_worker(g.phase_archive, stop_when_blocked=True)
        self.assertIsInstance(res.get("exc"), G.GateStopped, res)
        self.assertEqual([n for n in os.listdir(self.arch / self.RID) if n.endswith(".tmp")], [])
        self.assert_reaped()
        self.assert_clean_shutdown(res)

    def test_phase_archive_reports_the_write_error_not_tar_rc(self):
        """The pump fails (ENOSPC), stops age, the gate then stops tar itself (rc -15): the write error wins."""
        (self.ws / "big.bin").write_bytes(os.urandom(8 * MIB))
        cat_age = self.fake_bin("cat-age", "exec cat\n")
        real = G.stream_encrypted_archive

        def full_disk(*a, **kw):
            os.close(kw["out_fd"])
            kw["out_fd"] = os.open("/dev/full", os.O_WRONLY)
            return real(*a, **kw)
        g = self.gate()
        with mock.patch.dict(os.environ, {"OC_ADDON_AGE": cat_age}), \
                mock.patch.object(G, "stream_encrypted_archive", side_effect=full_disk):
            res = self.run_in_worker(g.phase_archive)
        exc = res.get("exc")
        self.assertIsInstance(exc, G.HoldError, res)
        msg = exc.findings[0]["message"]
        self.assertEqual(exc.findings[0]["code"], "archive-failed")
        self.assertEqual(msg, f"writing the encrypted archive failed: {os.strerror(errno.ENOSPC)}")
        self.assertNotIn("tar rc", msg)
        self.assertEqual([n for n in os.listdir(self.arch / self.RID) if n.endswith(".tmp")], [])
        self.assert_reaped()
        self.assert_clean_shutdown(res)

    def test_phase_archive_reports_age_failure_not_tar_rc(self):
        (self.ws / "big.bin").write_bytes(os.urandom(8 * MIB))
        bad_age = self.fake_bin("crash-age", "head -c 100 >/dev/null\necho 'age: error: simulated crash' >&2\nexit 1\n")
        g = self.gate()
        with mock.patch.dict(os.environ, {"OC_ADDON_AGE": bad_age}):
            res = self.run_in_worker(g.phase_archive)
        exc = res.get("exc")
        self.assertIsInstance(exc, G.HoldError, res)
        msg = exc.findings[0]["message"]
        self.assertEqual(exc.findings[0]["code"], "archive-failed")
        self.assertTrue(msg.startswith("age rc 1: "), msg)
        self.assertIn("simulated crash", msg)
        self.assertNotIn("tar rc", msg)
        self.assert_reaped()


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
        self.assertEqual(self.lines, [f"[cleanup] run {r.rid}: 1 item(s) (archive / doctor captures) will be deleted "
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
        self.assertGreaterEqual(len(paths), 2, items)  # the doctor captures (and the archive with age)

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
        event when it is copied, so its archive outlives the new run by gate_cleanup_hours."""
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
        self.assertEqual(self.lines, [f"[cleanup] run {r.rid}: deletion moved to {iso(cleared + H48)} "
                                      "(a hold after the run was cleared)"])
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


class FsyncErrorTests(StreamEnv):
    def test_a_write_error_reported_only_by_fsync_is_a_write_failure(self):
        real = os.fsync
        hit = []

        def fsync(fd):
            if not hit and stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_size > 0:
                hit.append(fd)
                raise OSError(28, "No space left on device")
            return real(fd)
        with mock.patch.object(G.os, "fsync", side_effect=fsync):
            res = self.stream([T._REAL_WHICH("age") or "age", "-r", T.AGE_PUB or "age1x"], timeout=60) \
                if T.HAVE_AGE else None
        if res is None:
            self.skipTest("age not installed")
        self.assertEqual(res["failure"], "write", res)
        self.assertIn("No space left on device", res["detail"])
        self.assertTrue(hit)


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


# --- the rehearsal export's /share side: oc-upgrade export-write (run.sh process_export_request) -------------

class ExportWriteTests(SecEnv):
    """oc_gate.export_write: every file operation of run.sh's rehearsal export on /share runs through directory fds,
    so another /share writer can neither redirect the export nor make it delete or write anything else. Swaps are
    made between the calls (as between run.sh's --begin and --finish) or from inside the stdin --begin streams."""

    TS = "20261018-120000"
    FIELDS = (TS, "0.5.94-test", "2026.10.4", "age1qpzry...a7lqpz")  # <created> <addon> <runtime> <recipient>
    NAME_RE = r"^20261018-120000-[A-Za-z0-9]{6}$"

    def setUp(self):
        super().setUp()
        old = os.umask(0)  # the modes must not depend on the caller's umask
        self.addCleanup(os.umask, old)

    def ew(self, *args, data=b"", runsh=True, stdin=None):
        """export_write as run.sh calls it (stdin: data); sets self.out / self.err and returns the exit status."""
        stdin = stdin or io.BytesIO(data)
        buf, err = io.StringIO(), io.StringIO()
        env = {"OC_GATE_FROM_RUNSH": "1"} if runsh else {}
        with mock.patch.dict(os.environ, env), mock.patch.object(sys, "stdin", SimpleNamespace(buffer=stdin)), \
                redirect_stdout(buf), redirect_stderr(err):
            rc = G.export_write(list(args))
        self.out, self.err = buf.getvalue(), err.getvalue()
        return rc

    def begin(self, data=b"ciphertext"):
        self.assertEqual(self.ew("--begin", self.TS, data=data), 0, self.out + self.err)
        self.assertRegex(self.out, self.NAME_RE)
        return self.out.strip()

    @staticmethod
    def mode(p):
        return stat.S_IMODE(os.lstat(p).st_mode)

    def assert_plain_file(self, p, mode=0o600):
        st = os.lstat(p)
        self.assertTrue(stat.S_ISREG(st.st_mode), p)
        self.assertEqual(stat.S_IMODE(st.st_mode), mode, p)

    def test_refused_without_oc_gate_from_runsh(self):
        for args in (["--sweep"], ["--begin", self.TS]):
            self.assertEqual(self.ew(*args, data=b"ciphertext", runsh=False), 2, args)
            self.assertIn("used by the add-on itself", self.out)
        self.assertEqual(os.listdir(self.share), [])
        name = self.begin()
        before = tree(self.share)
        for args in (["--finish", name, *self.FIELDS], ["--abort", name], ["--sweep"]):
            self.assertEqual(self.ew(*args, runsh=False), 2, args)
            self.assertIn("used by the add-on itself", self.out)
        self.assertEqual(tree(self.share), before)

    def test_begin_streams_stdin_into_a_fresh_0700_directory_as_a_0600_tmp_and_prints_its_name(self):
        data = os.urandom(3 * MIB) + b"\0tail\n"  # several 1 MiB chunks
        name = self.begin(data)
        self.assertEqual(self.out, name + "\n")
        d = self.reh / name
        self.assertEqual(self.mode(self.reh), 0o700)  # the root, created by --begin
        self.assertTrue(stat.S_ISDIR(os.lstat(d).st_mode))
        self.assertEqual(self.mode(d), 0o700)
        self.assertEqual(os.listdir(d), [G.EXPORT_TMP])
        self.assert_plain_file(d / G.EXPORT_TMP)
        self.assertEqual((d / G.EXPORT_TMP).read_bytes(), data)
        # the same second again: another fresh directory, the first one untouched; empty stdin: an empty .tmp
        name2 = self.begin(b"")
        self.assertNotEqual(name2, name)
        self.assertEqual((self.reh / name2 / G.EXPORT_TMP).read_bytes(), b"")
        self.assertEqual((d / G.EXPORT_TMP).read_bytes(), data)
        self.assertEqual(sorted(os.listdir(self.reh)), sorted([name, name2]))

    def test_begin_failing_while_streaming_leaves_no_tmp_and_no_directory(self):
        class FailingStdin:
            calls = 0

            def read(self, n=-1):
                self.calls += 1
                if self.calls > 1:
                    raise OSError(errno.EIO, "Input/output error")
                return b"partial"
        self.assertEqual(self.ew("--begin", self.TS, stdin=FailingStdin()), 1)
        self.assertEqual(self.out, "")  # no directory name for run.sh
        self.assertIn("Input/output error", self.err)
        self.assertEqual(os.listdir(self.reh), [])

    def test_finish_renames_the_tmp_and_writes_the_manifest(self):
        data = os.urandom(MIB + 123)
        name = self.begin(data)
        d = self.reh / name
        self.assertEqual(self.ew("--finish", name, *self.FIELDS), 0, self.out + self.err)
        self.assertEqual(self.out, f"{d / G.EXPORT_FILE}\n")
        self.assertEqual(sorted(os.listdir(d)), ["manifest.txt", G.EXPORT_FILE])
        self.assert_plain_file(d / G.EXPORT_FILE)
        self.assert_plain_file(d / "manifest.txt")
        self.assertEqual((d / G.EXPORT_FILE).read_bytes(), data)
        self.assertEqual((d / "manifest.txt").read_text().splitlines(), [
            f"created_utc={self.TS}", "addon_version=0.5.94-test", "openclaw_runtime=2026.10.4",
            f"sha256={hashlib.sha256(data).hexdigest()}", f"size_bytes={len(data)}", "encrypted=age",
            "recipient=age1qpzry...a7lqpz", "contains_secrets=yes"])
        before = tree(self.reh)
        # finished: a second --finish has no .tmp and changes nothing
        self.assertEqual(self.ew("--finish", name, *self.FIELDS), 1)
        self.assertEqual(self.out, "")
        self.assertEqual(tree(self.reh), before)
        # run.sh passes an empty runtime when openclaw_runtime_version fails: still the six-argument shape
        name2 = self.begin(b"x")
        self.assertEqual(self.ew("--finish", name2, self.TS, "0.5.94-test", "", "r"), 0, self.err)
        self.assertIn("openclaw_runtime=\n", (self.reh / name2 / "manifest.txt").read_text())

    def test_abort_removes_the_tmp_and_the_directory(self):
        name = self.begin(b"partial")
        keep = self.begin(b"other export")
        self.assertEqual(self.ew("--abort", name), 0, self.err)
        self.assertFalse(os.path.lexists(self.reh / name))
        self.assertEqual(os.listdir(self.reh), [keep])  # only the named export
        self.assertEqual((self.reh / keep / G.EXPORT_TMP).read_bytes(), b"other export")
        self.assertEqual(self.ew("--abort", name), 0)  # nothing (left) to abort
        # only the export's own .tmp goes: a directory with anything else in it is kept
        (self.reh / keep / "notes.txt").write_text("user file")
        self.assertEqual(self.ew("--abort", keep), 0)
        self.assertEqual(os.listdir(self.reh / keep), ["notes.txt"])
        # no rehearsal root: nothing to do, nothing created
        os.rename(self.reh, self.share / "elsewhere")
        self.assertEqual(self.ew("--abort", keep), 0)
        self.assertFalse(os.path.lexists(self.reh))

    def test_sweep_removes_incomplete_exports_and_never_follows_a_link(self):
        r = self.reh
        outside = self.victim("outside", {G.EXPORT_TMP: b"OUTSIDE", "openclaw-rehearsal.tar.gz.tmp": b"OUTSIDE"})
        victim = self.root / "victim.txt"
        victim.write_bytes(b"VICTIM")
        for d in ("20260101-000000-AAAAAA", "20260101-000001", "20260101-000002-BBBBBB", "20260101-000003-CCCCCC",
                  "20260101-000007-GGGGGG"):
            (r / d).mkdir(parents=True)
        (r / "20260101-000000-AAAAAA" / G.EXPORT_TMP).write_bytes(b"PARTIAL")  # plain: removed with its dir
        (r / "20260101-000001" / "openclaw-rehearsal.tar.gz.tmp").write_bytes(b"PARTIAL")  # older plaintext name
        (r / "20260101-000001" / "notes.txt").write_bytes(b"KEEP")  # keeps its directory
        os.symlink(victim, r / "20260101-000002-BBBBBB" / G.EXPORT_TMP)  # the link goes, never its target
        os.symlink(self.root / "nowhere", r / "20260101-000003-CCCCCC" / "openclaw-rehearsal.tar.gz.tmp")
        os.symlink(outside, r / "20260101-000004-DDDDDD")  # a linked <ts> directory: never entered
        done = self.make_export("20260101-000005-EEEEEE", files=(G.EXPORT_FILE, "manifest.txt"))
        (r / "20260101-000006-FFFFFF" / G.EXPORT_TMP).mkdir(parents=True)  # a directory under the .tmp name
        os.symlink(victim, r / "20260101-000008-HHHHHH")  # a link to a file
        (r / "README").write_bytes(b"a file in the root")
        before_outside, before_done = tree(outside), tree(done)
        self.assertEqual(self.ew("--sweep"), 0, self.err)
        self.assertEqual(sorted(os.listdir(r)), ["20260101-000001", "20260101-000004-DDDDDD", "20260101-000005-EEEEEE",
                                                 "20260101-000006-FFFFFF", "20260101-000008-HHHHHH", "README"])
        self.assertEqual(os.listdir(r / "20260101-000001"), ["notes.txt"])
        self.assertEqual(victim.read_bytes(), b"VICTIM")
        self.assertFalse(os.path.lexists(self.root / "nowhere"))
        self.assertEqual(tree(outside), before_outside)
        self.assertEqual(os.readlink(r / "20260101-000004-DDDDDD"), str(outside))
        self.assertEqual(os.readlink(r / "20260101-000008-HHHHHH"), str(victim))
        self.assertEqual(tree(done), before_done)
        self.assertTrue(stat.S_ISDIR(os.lstat(r / "20260101-000006-FFFFFF" / G.EXPORT_TMP).st_mode))
        removed = [x for x in self.out.splitlines() if x.startswith("WARN: Removed incomplete rehearsal export ")]
        self.assertEqual(len(removed), 4, self.out)
        self.assertNotIn("20260101-000004-DDDDDD", self.out)
        self.assertEqual(self.ew("--sweep"), 0)  # nothing left to remove
        self.assertEqual(self.out, "")

    def test_sweep_without_a_rehearsal_root_creates_nothing(self):
        self.assertEqual(self.ew("--sweep"), 0, self.err)
        self.assertEqual(os.listdir(self.share), [])

    def test_sweep_never_enters_a_symlinked_rehearsal_root(self):
        v = self.victim("victim", {f"20260101-000000-AAAAAA/{G.EXPORT_TMP}": b"PARTIAL",
                                   "20260101-000001-BBBBBB/openclaw-rehearsal.tar.gz.tmp": b"PARTIAL"})
        (v / "20260101-000002-CCCCCC").mkdir()  # empty: a followed sweep would remove it
        os.symlink(v, self.reh)
        before = tree(v)
        self.assertEqual(self.ew("--sweep"), 1)
        self.assertIn("WARN: rehearsal export:", self.err)
        self.assertEqual(tree(v), before)
        self.assertEqual(os.readlink(self.reh), str(v))

    def test_symlinked_rehearsal_root_makes_begin_fail_and_writes_nothing_at_the_target(self):
        v = self.victim("victim", {"openclaw.json": b"{}"})
        before = tree(v)
        os.symlink(v, self.reh)
        self.assertEqual(self.ew("--begin", self.TS, data=b"ciphertext"), 1)
        self.assertEqual(self.out, "")
        self.assertIn("WARN: rehearsal export:", self.err)
        self.assertEqual(tree(v), before)
        self.assertEqual(os.readlink(self.reh), str(v))
        # dangling: the target is not created
        os.unlink(self.reh)
        os.symlink(self.root / "nowhere", self.reh)
        self.assertEqual(self.ew("--begin", self.TS, data=b"ciphertext"), 1)
        self.assertFalse(os.path.lexists(self.root / "nowhere"))
        # a regular file: left as it is
        os.unlink(self.reh)
        self.reh.write_bytes(b"NOT A DIR")
        self.assertEqual(self.ew("--begin", self.TS, data=b"ciphertext"), 1)
        self.assertEqual(self.reh.read_bytes(), b"NOT A DIR")
        self.assertEqual(os.listdir(self.share), ["openclaw-rehearsal"])

    def test_swaps_while_begin_streams_never_redirect_the_tmp_or_its_cleanup(self):
        """--begin holds fds of the root and the fresh directory: a swap while it streams changes nothing for it,
        and its cleanup after a failing read goes through the same fds."""
        test = self

        class SwappingStdin:
            def __init__(self, swap, fail):
                self.swap, self.fail, self.calls = swap, fail, 0

            def read(self, n=-1):
                self.calls += 1
                if self.calls == 1:
                    self.swap()
                    return b"cipher"
                if self.fail:
                    raise OSError(errno.EIO, "Input/output error")
                return b"text" if self.calls == 2 else b""

        for what in ("root", "dir"):
            for fail in (False, True):
                with self.subTest(swap=what, fail=fail):
                    v = self.victim(f"victim-{what}-{fail}", {G.EXPORT_TMP: b"DECOY", "openclaw.json": b"{}"})
                    before = tree(v)
                    moved = self.share / f"moved-{what}-{fail}"
                    if os.path.lexists(self.reh):
                        os.rename(self.reh, self.share / f"old-{what}-{fail}")

                    def swap():
                        if what == "root":
                            test.replace_with_link(test.reh, v, keep_as=moved)
                        else:
                            (d,) = os.listdir(test.reh)
                            test.replace_with_link(test.reh / d, v, keep_as=moved)
                    rc = self.ew("--begin", self.TS, stdin=SwappingStdin(swap, fail))
                    self.assertEqual(tree(v), before)
                    real = moved / self.out.strip() if what == "root" else moved
                    if fail:
                        self.assertEqual((rc, self.out), (1, ""))
                        # the cleanup removed the real .tmp (and, through the root's fd, the real directory)
                        self.assertEqual(tree(moved), {})
                    else:
                        self.assertEqual(rc, 0, self.err)
                        self.assertRegex(self.out, self.NAME_RE)
                        self.assertEqual((real / G.EXPORT_TMP).read_bytes(), b"ciphertext")

    def test_finish_and_abort_with_a_directory_swapped_to_a_symlink_touch_nothing_outside(self):
        name = self.begin(b"ciphertext")
        d = self.reh / name
        v = self.victim("victim", {G.EXPORT_TMP: b"DECOY", "openclaw.json": b"{}"})
        before = tree(v)
        self.replace_with_link(d, v, keep_as=self.reh / f"{name}.moved")
        self.assertEqual(self.ew("--finish", name, *self.FIELDS), 1)
        self.assertEqual(self.out, "")
        self.assertIn("WARN: rehearsal export:", self.err)
        self.assertEqual(tree(v), before)
        self.assertEqual(self.ew("--abort", name), 0)  # run.sh's next step: the link is not followed either
        self.assertEqual(tree(v), before)
        self.assertEqual(os.readlink(d), str(v))
        self.assertEqual(os.listdir(self.reh / f"{name}.moved"), [G.EXPORT_TMP])

    def test_finish_and_abort_with_the_rehearsal_root_swapped_to_a_symlink_touch_nothing_outside(self):
        name = self.begin(b"ciphertext")
        v = self.victim("victim", {f"{name}/{G.EXPORT_TMP}": b"DECOY", "openclaw.json": b"{}"})
        before = tree(v)
        self.replace_with_link(self.reh, v, keep_as=self.share / "moved")
        self.assertEqual(self.ew("--finish", name, *self.FIELDS), 1)
        self.assertEqual(self.out, "")
        self.assertEqual(tree(v), before)
        self.assertIn(self.ew("--abort", name), (0, 1))  # run.sh ignores its status
        self.assertEqual(tree(v), before)
        self.assertEqual(os.listdir(self.share / "moved" / name), [G.EXPORT_TMP])

    def test_links_planted_in_the_fresh_directory_before_finish_are_never_followed(self):
        victim = self.root / "victim.txt"
        victim.write_bytes(b"VICTIM")
        vdir = self.victim("victim-dir", {})
        name = self.begin(b"ciphertext")
        d = self.reh / name
        os.symlink(vdir, d / G.EXPORT_FILE)  # the final name: replaced, never moved into
        os.symlink(victim, d / "manifest.txt")  # replaced, never written through
        self.assertEqual(self.ew("--finish", name, *self.FIELDS), 0, self.err)
        self.assert_plain_file(d / G.EXPORT_FILE)
        self.assert_plain_file(d / "manifest.txt")
        self.assertEqual((d / G.EXPORT_FILE).read_bytes(), b"ciphertext")
        self.assertIn(f"sha256={hashlib.sha256(b'ciphertext').hexdigest()}\n", (d / "manifest.txt").read_text())
        self.assertEqual(sorted(os.listdir(d)), ["manifest.txt", G.EXPORT_FILE])
        self.assertEqual(victim.read_bytes(), b"VICTIM")
        self.assertEqual(os.listdir(vdir), [])
        # the .tmp replaced with a link: refused; --abort removes the link only, then the empty directory
        name = self.begin(b"ciphertext")
        d = self.reh / name
        os.unlink(d / G.EXPORT_TMP)
        os.symlink(victim, d / G.EXPORT_TMP)
        self.assertEqual(self.ew("--finish", name, *self.FIELDS), 1)
        self.assertEqual(os.listdir(d), [G.EXPORT_TMP])
        self.assertEqual(self.ew("--abort", name), 0)
        self.assertFalse(os.path.lexists(d))
        self.assertEqual(victim.read_bytes(), b"VICTIM")

    def test_bad_argument_shapes_are_rc_2_and_create_nothing(self):
        n = "20261018-120000-abcdef"
        for args in ([], ["--bogus"], ["--sweep", "extra"], ["--begin"], ["--begin", "2026-10-18"],
                     ["--begin", "../20261018-120000"], ["--begin", n], ["--begin", self.TS, "extra"],
                     ["--finish", n], ["--finish", n, "a", "b", "c"], ["--finish", n, *self.FIELDS, "extra"],
                     ["--finish", "../../config", *self.FIELDS], ["--finish", f"{n}/..", *self.FIELDS],
                     ["--abort"], ["--abort", "../share"], ["--abort", "."], ["--abort", ""], ["--abort", n, "x"]):
            with self.subTest(args=args):
                self.assertEqual(self.ew(*args, data=b"ciphertext"), 2)
                self.assertIn("usage: oc-upgrade export-write", self.out)
        self.assertEqual(os.listdir(self.share), [])

    # Regression: a --finish that fails after the rename (e.g. ENOSPC on manifest.txt) leaves nothing after --abort.
    def test_finish_failing_after_the_rename_leaves_nothing_behind_after_abort(self):
        name = self.begin(b"ciphertext")
        with mock.patch.object(G, "_write_new_at", side_effect=OSError(errno.ENOSPC, "No space left on device")):
            self.assertEqual(self.ew("--finish", name, *self.FIELDS), 1)
        self.assertIn("No space left on device", self.err)
        self.assertEqual(self.ew("--abort", name), 0)
        self.assertFalse(os.path.lexists(self.reh / name), tree(self.reh))



if __name__ == "__main__":
    unittest.main()
