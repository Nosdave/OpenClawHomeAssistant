"""Gate-level tests of the 0.5.94-full2 archive options (gate_archive / gate_archive_age_recipient).

Covers oc_gate.Gate.archive_setting (precheck 7a), archive_reusable, archive_intact, phase_archive and the
readiness / status previews, driven through full gate runs (fake node, fake doctor, real oc_migrate) in the
temporary tree of test_gate.GateEnv. Owner rule: no plaintext secrets in archives or backups, so every test
that writes under /share checks that nothing there is plaintext, and a pasted private key is never echoed.
"""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import unittest
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
for _p in (str(ADDON), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import test_gate as T  # noqa: E402  (GateEnv, fake node/doctor, synthetic 7.35 state, throwaway age keys)

C, G = T.C, T.G

# A syntactically valid recipient for hosts without age (age itself never runs with it in those tests).
FAKE_PUB = "age1" + "q" * 58
# A private key for the "pasted the wrong key" tests: the real throwaway identity when age exists, else a
# synthetic one with the same shape (the gate must refuse it without ever calling age).
_BECH32 = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
IDENT = T.AGE_IDENTITY or ("AGE-SECRET-KEY-1" + (_BECH32 * 2)[:58])
IDENT_BODY = IDENT[len("AGE-SECRET-KEY-1"):]
PUB = T.AGE_PUB or FAKE_PUB
NEEDS_AGE = unittest.skipUnless(T.HAVE_AGE, "age / age-keygen not installed")


def new_keypair():
    ident = subprocess.run(["age-keygen"], capture_output=True, text=True, check=True).stdout
    ident = next(x for x in ident.splitlines() if x.startswith("AGE-SECRET-KEY-"))
    pub = subprocess.run(["age-keygen", "-y"], input=ident + "\n", capture_output=True, text=True,
                         check=True).stdout.strip()
    return ident, pub


def decrypt_with(ident, path):
    return subprocess.run(["age", "-d", "-i", "-", str(path)], input=(ident + "\n").encode(),
                          capture_output=True, check=True).stdout


class ArchiveModeTests(T.GateEnv):
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

    # ----- helpers -----
    def retry(self, *args):
        lines = []
        rc = G.retry_cmd(list(args), emit=lines.append)
        self.retry_out = "\n".join(lines)
        return rc

    def marker(self):
        return json.loads((self.upg / "gate" / "migrated.json").read_text())

    def hold_txt(self):
        return (self.upg / "hold.txt").read_text()

    def write_journal(self, j):
        (self.upg / "gate" / "journal.json").write_text(json.dumps(j))

    def share_files(self):
        return sorted(p for p in self.share.rglob("*") if not p.is_dir())

    def age_files(self):
        return sorted(self.share.glob("openclaw-upgrade/*/*.tar.gz.age"))

    def archive_path(self, j=None):
        a = (j or self.journal())["archive"]
        return Path(a["dir"]) / a["file"]

    def assert_no_plaintext_under_share(self):
        for f in self.share_files():
            data = f.read_bytes()
            self.assertFalse(data.startswith(b"\x1f\x8b"), f"plaintext gzip under /share: {f}")
            self.assertNotIn(b"SECRET", data, f"plaintext secret under /share: {f}")

    def assert_key_nowhere(self, extra_text=()):
        """The private key (or its bech32 body) appears in no output and no file of the tree except the add-on
        options file the user put it in. Failure messages name the place, never the key."""
        needles = [IDENT_BODY, IDENT_BODY.lower()]
        for label, text in [("stdout", getattr(self, "out", "")), ("stderr", getattr(self, "err", ""))] + \
                list(extra_text):
            for n in needles:
                self.assertNotIn(n, text, f"private key echoed in {label}")
        opts = self.tmp / "options.json"
        for p in self.tmp.rglob("*"):
            if p == opts or p.is_symlink() or not p.is_file():
                continue
            data = p.read_bytes()
            for n in needles:
                self.assertNotIn(n.encode(), data, f"private key found in {p.relative_to(self.tmp)}")

    def hold(self):
        return self.journal()["hold"]

    def run_until_cleanup(self):
        """A run that stops (internal-error HOLD) right before phase 3: archive written, nothing else changed."""
        self.hooks(raise_in_phase="cleanup")
        self.assertEqual(self.run_gate(), 1, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["phase"], j["first_write_at"]), ("internal-error", "cleanup", None))
        self.assertIn("archive", j["phases_done"])
        return j

    def run_until_fixups(self):
        """A run that stops (internal-error HOLD) after doctor pass 1: the state is partially migrated."""
        self.hooks(raise_in_phase="fixups")
        self.assertEqual(self.run_gate(), 1, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["phase"]), ("internal-error", "fixups"))
        self.assertTrue(j["first_write_at"])
        return j

    def resume(self):
        self.hooks()
        self.assertEqual(self.retry(), 0, self.retry_out)
        return self.run_gate()

    def make_plaintext_archive(self, adir, stamp="20260901-000000"):
        """A 0.5.94-full1 style archive: plaintext tar.gz (with the config's secrets) plus SHA256SUMS."""
        adir.mkdir(parents=True, exist_ok=True)
        f = adir / f"openclaw-state-{stamp}-before-{T.RUNTIME}.tar.gz"
        with tarfile.open(f, "w:gz") as tf:
            tf.add(self.state / "openclaw.json", arcname=".openclaw/openclaw.json")
        sha = C.sha256_file(f)
        (adir / "SHA256SUMS").write_text(f"{sha}  {f.name}\n")
        rec = {"dir": str(adir), "file": f.name, "sha256": sha, "size": f.stat().st_size, "members": 1,
               "verified": True}
        return f, rec

    def to_full1_journal(self, j):
        """Rewrite the journal as 0.5.94-full1 left it: a plaintext archive record without mode/recipient and
        no archive_opt snapshot; the encrypted archive of this run is replaced by the plaintext one."""
        adir = self.share / "openclaw-upgrade" / j["run_id"]
        for f in adir.glob("*"):
            f.unlink()
        f, rec = self.make_plaintext_archive(adir)
        j["archive"] = rec
        j.pop("archive_opt", None)
        self.write_journal(j)
        return f, rec

    def path_without_age(self):
        """PATH = fake bin + a shim directory linking every tool of the current PATH except age*."""
        shim = self.tmp / "shim"
        shim.mkdir()
        for d in os.environ.get("PATH", "").split(os.pathsep):
            if not d or Path(d) == self.bin or not os.path.isdir(d):
                continue
            for n in os.listdir(d):
                src, dst = os.path.join(d, n), shim / n
                if n.startswith("age") or os.path.lexists(dst):
                    continue
                if os.path.isfile(src) and os.access(src, os.X_OK):
                    os.symlink(src, dst)
        return f"{self.bin}{os.pathsep}{shim}"

    def unit_gate(self, j):
        lines = []
        g = G.Gate(emit=lines.append)
        g.j = j
        g.save = lambda: None
        g.lines = lines
        return g

    # ----- gate_archive: off ---------------------------------------------------------------------
    def test_off_full_run_writes_nothing_to_share(self):
        self.build_735()
        self.hooks()
        self.options(gate_archive="off")
        rc = self.run_gate()
        self.assertEqual(rc, 0, self.out)
        self.assertIn("[gate] done: MIGRATED 2026.9.9", self.out)
        self.assertEqual(list(self.share.rglob("*")), [])  # not even /share/openclaw-upgrade
        j = self.journal()
        self.assertEqual(j["status"], "done")
        self.assertEqual((j["archive"]["mode"], j["archive"]["verified"]), ("off", False))
        self.assertNotIn("file", j["archive"])
        self.assertIn("archive", j["phases_done"])
        self.assertEqual(j["archive_opt"], {"mode": "off", "recipient": None})
        self.assertIn("WARN [gate] archive-off: gate_archive is off: no /share archive; rollback only through the "
                      "encrypted Home Assistant backup", self.out)
        self.assertRegex(self.out, r"\[gate\] 1/9 precheck: [^\n]*; archive off;")
        self.assertIn("[gate] 2/9 archive: off (gate_archive: off): no archive written", self.out)
        self.assertNotIn("2/9 archive verified", self.out)
        self.assertIn("info: the doctor captures of this run are deleted after", self.out)
        self.assertNotIn("the archive and the doctor captures", self.out)
        m = self.marker()
        self.assertEqual((m["archive"], m["archive_mode"]), (None, "off"))
        st = "\n".join(G.status_lines())
        self.assertIn("  archive: off for this run (gate_archive: off)", st)
        self.assertIn("Gate options: gate_archive off;", st)
        self.assertIn("Gate archives in /share: none", st)
        ev = (self.upg / "gate" / "runs" / j["run_id"] / "events.log").read_text()
        self.assertIn("archive-off", ev)

    def test_off_needs_no_age_and_ignores_the_recipient_field(self):
        """Off never calls age, and a private key left in the (unused) recipient field is never echoed."""
        self.build_735()
        self.hooks()
        self.options(gate_archive="off", gate_archive_age_recipient=IDENT)
        with mock.patch.dict(os.environ, {"OC_ADDON_AGE": str(self.tmp / "no-such-age")}):
            rc = self.run_gate()
        self.assertEqual(rc, 0, self.out)
        self.assertEqual(self.journal()["archive"]["mode"], "off")
        self.assertEqual(list(self.share.rglob("*")), [])
        self.assertNotIn("archive-age-missing", self.out)
        st = "\n".join(G.status_lines())
        self.assertIn("Gate options: gate_archive off;", st)
        self.assert_key_nowhere([("status", st)])

    # ----- encrypted without a usable recipient --------------------------------------------------
    def test_encrypted_without_recipient_is_a_hard_hold_then_recovers(self):
        self.build_735()
        self.hooks()
        self.options(gate_archive="encrypted", gate_archive_age_recipient="")
        cfg_before = (self.state / "openclaw.json").read_bytes()
        db_before = (self.state / "state" / "openclaw.sqlite").read_bytes()
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertIn("[gate] HOLD archive-key-missing in precheck: gate_archive is 'encrypted' but "
                      "gate_archive_age_recipient is empty: the gate writes no plaintext archive", self.out)
        h = self.hold()
        self.assertEqual((h["code"], h["phase"], h["acceptable"], h["state_changed"]),
                         ("archive-key-missing", "precheck", False, False))
        self.assertEqual([f["cls"] for f in h["findings"]], ["hard"])
        self.assertNotIn("archive-key-missing", G.ACCEPTABLE)
        txt = self.hold_txt()
        self.assertIn("Reason [archive-key-missing]:", txt)
        self.assertIn("State: unchanged (nothing written yet)", txt)
        self.assertNotIn("Accept", txt)
        nxt = next(x for x in txt.splitlines() if x.startswith("Next: "))
        self.assertIn("gate_archive_age_recipient", nxt)
        self.assertIn("gate_archive: off", nxt)
        self.assertTrue(G.ADVICE["archive-key-missing"].endswith("oc-upgrade retry"))
        self.assertIn(G.ADVICE["archive-key-missing"], nxt)
        self.assertEqual(list(self.share.rglob("*")), [])
        self.assertEqual((self.state / "openclaw.json").read_bytes(), cfg_before)
        self.assertEqual((self.state / "state" / "openclaw.sqlite").read_bytes(), db_before)
        self.assertIsNone(self.journal()["archive"])
        # sticky, and not acceptable
        self.assertEqual(self.plan()["rc"], 11)
        self.assertEqual(self.retry("--accept", "archive-key-missing"), 1)
        # the owner's way out: configure a key (or off), then oc-upgrade retry
        if T.HAVE_AGE:
            self.options(gate_archive="encrypted", gate_archive_age_recipient=T.AGE_PUB)
        else:
            self.options(gate_archive="off")
        self.assertEqual(self.retry(), 0, self.retry_out)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("[gate] done: MIGRATED", self.out)
        self.assert_no_plaintext_under_share()
        self.assertEqual(len(self.age_files()), 1 if T.HAVE_AGE else 0)

    def test_missing_or_unreadable_options_file_holds_fail_closed(self):
        self.build_735()
        self.hooks()
        opts = self.tmp / "options.json"
        variants = [("missing", None), ("not json", "{gate_archive: off"), ("json list", '["off"]'),
                    ("empty object", "{}")]
        for i, (label, content) in enumerate(variants):
            with self.subTest(label):
                if content is None:
                    opts.unlink(missing_ok=True)
                else:
                    opts.write_text(content)
                if i:
                    self.assertEqual(self.retry(), 0, self.retry_out)
                rc = self.run_gate()
                self.assertEqual(rc, 20, self.out)
                self.assertNotIn("Traceback", self.out + self.err)
                h = self.hold()
                self.assertEqual((h["code"], h["phase"], h["acceptable"]), ("archive-key-missing", "precheck", False))
                self.assertEqual(list(self.share.rglob("*")), [])
                self.assertIsNone(self.journal()["archive"])

    def test_private_key_as_recipient_is_refused_and_never_echoed(self):
        self.build_735()
        self.hooks()
        calls = []
        real_popen = subprocess.Popen

        class SpyPopen(real_popen):
            def __init__(self, args, *a, **kw):
                calls.append((list(map(str, args)) if not isinstance(args, (str, bytes)) else [str(args)],
                              dict(kw.get("env") or {})))
                super().__init__(args, *a, **kw)
        outputs = []
        variants = [("as pasted", IDENT), ("with whitespace", f"  {IDENT}\n"), ("lower case", IDENT.lower()),
                    ("whole key file", f"# created: 2026-10-18T00:00:00Z\n# public key: {PUB}\n{IDENT}\n")]
        with mock.patch.object(subprocess, "Popen", SpyPopen):
            for i, (label, value) in enumerate(variants):
                with self.subTest(label):
                    self.options(gate_archive="encrypted", gate_archive_age_recipient=value)
                    if i:
                        self.assertEqual(self.retry(), 0, self.retry_out)
                    self.assertEqual(self.run_gate(), 20, self.out)
                    outputs += [(f"stdout {label}", self.out), (f"stderr {label}", self.err)]
                    h = self.hold()
                    self.assertEqual((h["code"], h["phase"], h["acceptable"]), ("archive-key-invalid", "precheck", False))
                    self.assertEqual(self.journal()["archive_opt"]["recipient"], None)
                    self.assertEqual(list(self.share.rglob("*")), [])
                    self.assertEqual(self.retry("--accept", "archive-key-invalid"), 1)
                    self.assertIn("create a new key pair", self.hold_txt())  # the advice says: rotate it
                    if label != "whole key file":
                        self.assertIn("holds an age PRIVATE key", h["message"])
                        st = "\n".join(G.status_lines())
                        self.assertIn("(problem: private-key)", st)
                        outputs.append((f"status {label}", st))
        for argv, env in calls:
            joined = "\0".join(argv + list(env.values()))
            self.assertNotIn(IDENT_BODY, joined.upper(), "the private key reached a subprocess")
        self.assertFalse(any(os.path.basename(a[0]) == "age" for a, _e in calls), "age ran with a private key option")
        lines = []
        self.assertEqual(G.dry_run(emit=lines.append), 20)
        self.assert_key_nowhere(outputs + [("status", "\n".join(G.status_lines())), ("dry-run", "\n".join(lines)),
                                           ("hold.txt", self.hold_txt())])

    def test_malformed_recipient_is_refused(self):
        self.build_735()
        self.hooks()
        variants = [("short", "age1notakey"), ("too long", PUB + "q"), ("two recipients", f"{PUB} {PUB}"),
                    ("upper case", PUB.upper()), ("ssh key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0 user@host"),
                    ("not a string", ["age1" + "q" * 58])]
        for i, (label, value) in enumerate(variants):
            with self.subTest(label):
                self.options(gate_archive="encrypted", gate_archive_age_recipient=value)
                if i:
                    self.assertEqual(self.retry(), 0, self.retry_out)
                self.assertEqual(self.run_gate(), 20, self.out)
                h = self.hold()
                self.assertEqual((h["code"], h["acceptable"]), ("archive-key-missing" if label == "not a string"
                                                                else "archive-key-invalid", False))
                if label != "not a string":
                    self.assertIn("is not one age public key", h["message"])
                    self.assertEqual(C.gate_options()["archive"]["problem"], "malformed")
                self.assertEqual(list(self.share.rglob("*")), [])

    @NEEDS_AGE
    def test_recipient_that_age_rejects_is_refused(self):
        """Regex-valid but a broken bech32 checksum: only age can tell; precheck probes it before any write."""
        self.build_735()
        self.hooks()
        last = T.AGE_PUB[-1]
        bad = T.AGE_PUB[:-1] + ("p" if last == "q" else "q")
        self.assertTrue(C.AGE_RECIPIENT_RE.fullmatch(bad))
        self.options(gate_archive="encrypted", gate_archive_age_recipient=bad)
        self.assertEqual(self.run_gate(), 20, self.out)
        h = self.hold()
        self.assertEqual((h["code"], h["phase"], h["acceptable"]), ("archive-key-invalid", "precheck", False))
        self.assertIn("age rejects gate_archive_age_recipient", h["message"])
        self.assertEqual(list(self.share.rglob("*")), [])

    def test_invalid_gate_archive_value(self):
        self.build_735()
        self.hooks()
        self.options(gate_archive="plain", gate_archive_age_recipient=PUB)
        self.assertEqual(C.gate_options()["archive"]["problem"], "invalid-mode")
        self.assertEqual(self.run_gate(), 20, self.out)
        h = self.hold()
        self.assertEqual((h["code"], h["phase"], h["acceptable"]), ("archive-key-invalid", "precheck", False))
        self.assertEqual(h["message"], "gate_archive must be 'encrypted' or 'off'")
        self.assertEqual(list(self.share.rglob("*")), [])
        self.assertIn("(problem: invalid-mode)", "\n".join(G.status_lines()))
        for value in ("ENCRYPTED", "Off", "", "plaintext", True, 1, ["off"], {"mode": "off"}):
            with self.subTest(value=value):
                self.options(gate_archive=value, gate_archive_age_recipient=PUB)
                self.assertEqual(C.gate_options()["archive"]["problem"], "invalid-mode")
                lines = []
                self.assertEqual(G.dry_run(emit=lines.append), 20, "\n".join(lines))
                self.assertIn("[gate] dry-run: would HOLD: archive-key-invalid", lines)
                self.assertIn("archive option INVALID", "\n".join(lines))

    def test_invalid_integer_options_warn_without_echoing_the_value(self):
        self.build_735()
        self.hooks()
        self.options(gate_archive="off", gate_cleanup_hours="SECRET-VALUE-1", gate_backup_max_age_hours=True)
        lines = []
        self.assertEqual(G.dry_run(emit=lines.append), 0, "\n".join(lines))
        text = "\n".join(lines)
        self.assertIn("WARN [gate] add-on option gate_cleanup_hours is not an integer in 0..720; using 48", text)
        self.assertIn("WARN [gate] add-on option gate_backup_max_age_hours is not an integer in 1..168; using 24", text)
        self.assertNotIn("SECRET-VALUE", text)

    # ----- the age tool --------------------------------------------------------------------------
    def test_age_missing_via_env_override(self):
        self.build_735()
        self.hooks()
        self.options(gate_archive="encrypted", gate_archive_age_recipient=PUB)
        missing = str(self.tmp / "no-such-age")
        with mock.patch.dict(os.environ, {"OC_ADDON_AGE": missing}):
            self.assertEqual(C.age_bin(), missing)
            self.assertEqual(self.run_gate(), 20, self.out)
        h = self.hold()
        self.assertEqual((h["code"], h["phase"], h["acceptable"]), ("archive-age-missing", "precheck", False))
        self.assertIn(missing, h["message"])
        self.assertIn("reinstall or rebuild the add-on", self.hold_txt())
        self.assertEqual(list(self.share.rglob("*")), [])
        self.assertEqual(self.retry("--accept", "archive-age-missing"), 1)

    def test_age_bin_resolution_order_and_broken_recorded_age(self):
        fake = self.tmp / "recorded-age"
        fake.write_text("#!/bin/sh\necho 'age: broken' >&2\nexit 1\n")
        fake.chmod(0o755)
        record = self.tmp / "age-bin"
        record.write_text(f"{fake}\n")
        os.environ.pop("OC_ADDON_AGE", None)
        with mock.patch.object(C, "AGE_BIN_RECORD", str(record)):
            self.assertEqual(C.age_bin(), str(fake))  # the record beats PATH (a brew age must never win)
            with mock.patch.dict(os.environ, {"OC_ADDON_AGE": "/env/age"}):
                self.assertEqual(C.age_bin(), "/env/age")  # the test override beats the record
            fake.chmod(0o644)
            self.assertEqual(C.age_bin(), shutil.which("age") or "age")  # not executable: PATH
            fake.chmod(0o755)
            self.build_735()
            self.hooks()
            self.options(gate_archive="encrypted", gate_archive_age_recipient=PUB)
            self.assertEqual(self.run_gate(), 20, self.out)
        h = self.hold()
        self.assertEqual(h["code"], "archive-age-missing")
        self.assertIn(str(fake), h["message"])
        self.assertEqual(list(self.share.rglob("*")), [])
        with mock.patch.object(C, "AGE_BIN_RECORD", str(self.tmp / "no-record")):
            self.assertEqual(C.age_bin(), shutil.which("age") or "age")

    def test_age_missing_from_path(self):
        self.build_735()
        self.hooks()
        self.options(gate_archive="encrypted", gate_archive_age_recipient=PUB)
        path = self.path_without_age()
        os.environ.pop("OC_ADDON_AGE", None)
        with mock.patch.dict(os.environ, {"PATH": path}), \
                mock.patch.object(C, "AGE_BIN_RECORD", str(self.tmp / "no-record")):
            self.assertIsNone(shutil.which("age"))
            self.assertEqual(C.age_bin(), "age")
            self.assertEqual(self.run_gate(), 20, self.out)
        h = self.hold()
        self.assertEqual((h["code"], h["phase"]), ("archive-age-missing", "precheck"))
        self.assertEqual(list(self.share.rglob("*")), [])

    # ----- the option changes during a run ---------------------------------------------------------
    def _change_options_after_precheck(self, **opts):
        real = G.Gate.phase_precheck
        test = self

        def precheck_then_edit(gate):
            real(gate)
            test.options(**opts)  # the owner saves the Configuration while the gate runs
        return mock.patch.object(G.Gate, "phase_precheck", precheck_then_edit)

    @NEEDS_AGE
    def test_option_changed_to_off_after_precheck_uses_the_validated_snapshot(self):
        self.build_735()
        self.hooks()
        with self._change_options_after_precheck(gate_archive="off"):
            self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertEqual((j["archive"]["mode"], j["archive"]["recipient"]), ("encrypted", T.AGE_PUB))
        self.assertEqual(j["archive_opt"]["mode"], "encrypted")
        self.assertEqual(len(self.age_files()), 1)
        self.assertEqual(self.marker()["archive_mode"], "encrypted")
        self.assert_no_plaintext_under_share()

    @NEEDS_AGE
    def test_option_changed_to_a_private_key_after_precheck_never_reaches_age(self):
        self.build_735()
        self.hooks()
        with self._change_options_after_precheck(gate_archive="encrypted", gate_archive_age_recipient=IDENT):
            self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertEqual(j["archive"]["recipient"], T.AGE_PUB)
        self.assertTrue(T.age_decrypt(self.archive_path(j)))
        self.assert_key_nowhere()

    @NEEDS_AGE
    def test_option_change_before_first_write_encrypted_to_off_removes_the_archive(self):
        self.build_735()
        j = self.run_until_cleanup()
        self.assertEqual(len(self.age_files()), 1)
        self.options(gate_archive="off")
        self.assertEqual(self.resume(), 0, self.out)
        self.assertIn(f"2/9 archive: removed {self.share / 'openclaw-upgrade' / j['run_id']}/ of an earlier attempt "
                      "(gate_archive is now off)", self.out)
        self.assertIn("WARN [gate] archive-off:", self.out)
        self.assertEqual(self.share_files(), [])
        self.assertFalse((self.share / "openclaw-upgrade" / j["run_id"]).exists())
        j = self.journal()
        self.assertEqual((j["archive"]["mode"], j["archive"]["verified"]), ("off", False))
        m = self.marker()
        self.assertEqual((m["archive"], m["archive_mode"]), (None, "off"))

    @NEEDS_AGE
    def test_option_change_before_first_write_off_to_encrypted_writes_an_archive(self):
        self.build_735()
        self.options(gate_archive="off")
        self.run_until_cleanup()
        self.assertEqual(self.share_files(), [])
        self.options(gate_archive="encrypted", gate_archive_age_recipient=T.AGE_PUB)
        self.assertEqual(self.resume(), 0, self.out)
        self.assertIn("2/9 archive verified: encrypted (age, ", self.out)
        j = self.journal()
        self.assertEqual((j["archive"]["mode"], j["archive"]["recipient"]), ("encrypted", T.AGE_PUB))
        self.assertEqual(self.age_files(), [self.archive_path(j)])
        self.assertTrue(T.age_decrypt(self.archive_path(j)))
        m = self.marker()
        self.assertEqual((m["archive"], m["archive_mode"]), (str(self.archive_path(j)), "encrypted"))
        self.assert_no_plaintext_under_share()

    @NEEDS_AGE
    def test_option_change_before_first_write_new_recipient_re_encrypts(self):
        self.build_735()
        self.run_until_cleanup()
        ident2, pub2 = new_keypair()
        self.options(gate_archive="encrypted", gate_archive_age_recipient=pub2)
        self.assertEqual(self.resume(), 0, self.out)
        self.assertNotIn("reusing verified archive", self.out)
        j = self.journal()
        self.assertEqual(j["archive"]["recipient"], pub2)
        arch = self.archive_path(j)
        self.assertEqual(self.age_files(), [arch])
        plain = decrypt_with(ident2, arch)
        self.assertEqual(hashlib.sha256(plain).hexdigest(), j["archive"]["plaintext_sha256"])
        with self.assertRaises(subprocess.CalledProcessError):
            T.age_decrypt(arch)  # the old key no longer opens the rollback copy
        man = json.loads((arch.parent / "manifest.json").read_text())
        self.assertEqual(man["encryption"]["recipients"], [C.short_recipient(pub2)])

    @NEEDS_AGE
    def test_option_change_after_first_write_keeps_the_recorded_archive(self):
        self.build_735()
        j0 = self.run_until_fixups()
        arch = self.archive_path(j0)
        st0 = arch.stat()
        self.options(gate_archive="off")
        self.assertEqual(self.resume(), 0, self.out)
        self.assertIn(f"WARN [gate] gate_archive is now off, but run {j0['run_id']} started with encrypted; the run "
                      "keeps its archive setting", self.out)
        self.assertRegex(self.out, r"1/9 precheck: [^\n]*archive encrypted \(recorded for this run\)")
        self.assertIn("2/9 archive: re-checking the recorded archive before continuing (sha256)", self.out)
        self.assertIn(f"2/9 archive: reusing verified archive {arch.parent}/{arch.name} (encrypted, "
                      f"{C.short_recipient(T.AGE_PUB)})", self.out)
        self.assertNotIn("2/9 archive: off", self.out)
        self.assertNotIn("WARN [gate] archive-off", self.out)
        j = self.journal()
        self.assertEqual(j["archive"], j0["archive"])
        self.assertEqual(self.age_files(), [arch])
        self.assertEqual((arch.stat().st_ino, arch.stat().st_mtime_ns), (st0.st_ino, st0.st_mtime_ns))
        m = self.marker()
        self.assertEqual((m["archive"], m["archive_mode"]), (str(arch), "encrypted"))

    def test_option_change_after_first_write_off_run_stays_off(self):
        self.build_735()
        self.options(gate_archive="off")
        j0 = self.run_until_fixups()
        self.options(gate_archive="encrypted", gate_archive_age_recipient=PUB)
        self.assertEqual(self.resume(), 0, self.out)
        self.assertIn(f"WARN [gate] gate_archive is now encrypted, but run {j0['run_id']} started with off; the run "
                      "keeps its archive setting", self.out)
        self.assertIn("2/9 archive: none for this run (gate_archive was off); rollback only through the encrypted "
                      "Home Assistant backup", self.out)
        self.assertIn("2/9 archive: off for this run", self.out)
        self.assertNotIn("archive-missing", self.out)
        self.assertEqual(list(self.share.rglob("*")), [])
        self.assertEqual(self.journal()["archive"]["mode"], "off")
        self.assertEqual(self.marker()["archive_mode"], "off")

    @NEEDS_AGE
    def test_option_problems_after_first_write_never_block_forward_recovery(self):
        """After the first write the run keeps its recorded archive: a broken option (here a pasted private key)
        or a missing age tool must not stop the one-way migration from finishing."""
        self.build_735()
        j0 = self.run_until_fixups()
        self.options(gate_archive="encrypted", gate_archive_age_recipient=IDENT)
        with mock.patch.dict(os.environ, {"OC_ADDON_AGE": str(self.tmp / "no-such-age")}):
            self.assertEqual(self.resume(), 0, self.out)
        self.assertNotIn("archive-key-invalid", self.out)
        self.assertNotIn("archive-age-missing", self.out)
        self.assertEqual(self.journal()["archive"], j0["archive"])
        self.assert_key_nowhere()

    # Regression: after the first write a changed recipient (not only a changed mode) must WARN that the run
    # keeps its archive (encrypted to the old key), so the owner keeps the old private key.
    @NEEDS_AGE
    def test_recipient_change_after_first_write_warns(self):
        self.build_735()
        j0 = self.run_until_fixups()
        _ident2, pub2 = new_keypair()
        self.options(gate_archive="encrypted", gate_archive_age_recipient=pub2)
        self.assertEqual(self.resume(), 0, self.out)
        self.assertEqual(self.journal()["archive"]["recipient"], T.AGE_PUB)  # kept, as it must be
        self.assertEqual(self.journal()["archive"]["sha256"], j0["archive"]["sha256"])
        self.assertIn("the run keeps its archive setting", self.out)

    # ----- resume / reuse ------------------------------------------------------------------------
    @NEEDS_AGE
    def test_interrupted_before_first_write_reuses_the_verified_archive(self):
        self.build_735()
        self.hooks()
        with mock.patch.object(G.Gate, "phase_cleanup", side_effect=G.GateStopped()):
            self.assertEqual(self.run_gate(), 143, self.out)
        j0 = self.journal()
        self.assertEqual((j0["status"], j0["phase"], j0["first_write_at"]), ("interrupted", "cleanup", None))
        arch = self.archive_path(j0)
        st0 = arch.stat()
        self.assertEqual(self.run_gate(), 0, self.out)  # automatic resume (1/1), no retry needed
        self.assertRegex(self.out, r"1/9 precheck: [^\n]*archive encrypted \([^)]*\), reusing this run's")
        self.assertIn(f"2/9 archive: reusing verified archive {arch.parent}/{arch.name} (encrypted, "
                      f"{C.short_recipient(T.AGE_PUB)})", self.out)
        self.assertNotIn("2/9 archive verified", self.out)
        j = self.journal()
        self.assertEqual(j["archive"], j0["archive"])
        self.assertEqual(self.age_files(), [arch])
        self.assertEqual((arch.stat().st_ino, arch.stat().st_mtime_ns), (st0.st_ino, st0.st_mtime_ns))
        self.assertEqual(C.sha256_file(arch), j["archive"]["sha256"])

    @NEEDS_AGE
    def test_interrupted_after_first_write_rechecks_and_reuses_the_archive(self):
        self.build_735()
        self.hooks()
        with mock.patch.object(G.Gate, "phase_fixups", side_effect=G.GateStopped()):
            self.assertEqual(self.run_gate(), 143, self.out)
        j0 = self.journal()
        self.assertEqual((j0["status"], j0["phase"]), ("interrupted", "fixups"))
        self.assertTrue(j0["first_write_at"])
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("2/9 archive: re-checking the recorded archive before continuing (sha256)", self.out)
        self.assertIn("2/9 archive: reusing verified archive", self.out)
        self.assertEqual(self.journal()["archive"], j0["archive"])
        self.assertEqual(len(self.age_files()), 1)

    @NEEDS_AGE
    def test_archive_deleted_before_first_write_is_written_again(self):
        self.build_735()
        j0 = self.run_until_cleanup()
        self.archive_path(j0).unlink()
        self.assertEqual(self.resume(), 0, self.out)
        self.assertNotIn("archive-missing", self.out)
        self.assertIn("2/9 archive verified: encrypted (age, ", self.out)
        j = self.journal()
        self.assertEqual(self.age_files(), [self.archive_path(j)])
        self.assertEqual(C.sha256_file(self.archive_path(j)), j["archive"]["sha256"])

    # Regression: before the first write an archive that fails its re-check (changed, same size) is written
    # again instead of HOLDing archive-missing "already partially migrated" (nothing was written yet).
    @NEEDS_AGE
    def test_archive_changed_before_first_write_is_written_again(self):
        self.build_735()
        j0 = self.run_until_cleanup()
        arch = self.archive_path(j0)
        raw = bytearray(arch.read_bytes())
        raw[-5] ^= 0xFF  # same size: archive_reusable() still says yes
        arch.write_bytes(bytes(raw))
        rc = self.resume()
        self.assertNotIn("partially migrated", self.out)
        self.assertEqual(rc, 0, self.out)
        j = self.journal()
        self.assertEqual(C.sha256_file(self.archive_path(j)), j["archive"]["sha256"])
        self.assertTrue(T.age_decrypt(self.archive_path(j)))

    @NEEDS_AGE
    def test_legacy_plaintext_archive_of_another_run_warns_and_is_not_reused(self):
        self.build_735()
        self.hooks()
        legacy, rec = self.make_plaintext_archive(self.share / "openclaw-upgrade" / "20260901T000000Z-abcdef")
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn(f"WARN [gate] 1 plaintext gate archive(s) from 0.5.94-full1 in {self.share / 'openclaw-upgrade'} "
                      "hold unencrypted secrets", self.out)
        j = self.journal()
        arch = self.archive_path(j)
        self.assertTrue(arch.name.endswith(".tar.gz.age"))
        self.assertEqual(arch.parent, self.share / "openclaw-upgrade" / j["run_id"])
        self.assertEqual(j["archive"]["mode"], "encrypted")
        self.assertNotEqual(j["archive"]["sha256"], rec["sha256"])
        self.assertEqual(self.marker()["archive"], str(arch))
        self.assertEqual(C.sha256_file(legacy), rec["sha256"])  # the gate leaves it to the cleanup
        st = "\n".join(G.status_lines())
        self.assertIn(f"  {legacy} (", st)
        self.assertIn("PLAINTEXT from 0.5.94-full1: unencrypted secrets", st)
        self.assertRegex(st, rf"  {arch} \([^)]*, encrypted\)")
        for f in self.share_files():
            if f != legacy:
                self.assertFalse(f.read_bytes().startswith(b"\x1f\x8b"), f)

    @NEEDS_AGE
    def test_full1_run_resumed_before_first_write_is_re_archived_encrypted(self):
        self.build_735()
        j = self.run_until_cleanup()
        legacy, _rec = self.to_full1_journal(j)
        self.assertEqual(self.resume(), 0, self.out)
        self.assertIn("WARN [gate] 1 plaintext gate archive(s) from 0.5.94-full1", self.out)
        self.assertNotIn("reusing verified archive", self.out)
        self.assertIn("2/9 archive verified: encrypted (age, ", self.out)
        self.assertFalse(legacy.exists())
        j = self.journal()
        self.assertEqual(j["archive"]["mode"], "encrypted")
        self.assertEqual(self.age_files(), [self.archive_path(j)])
        self.assertEqual(sorted(self.share.glob("openclaw-upgrade/*/*.tar.gz")), [])
        sums = (legacy.parent / "SHA256SUMS").read_text()
        self.assertNotIn(legacy.name, sums)
        self.assertEqual(self.marker()["archive_mode"], "encrypted")
        self.assert_no_plaintext_under_share()

    def test_full1_run_resumed_before_first_write_with_off_removes_the_plaintext(self):
        self.build_735()
        j = self.run_until_cleanup()
        adir = self.share / "openclaw-upgrade" / j["run_id"]
        if not T.HAVE_AGE:  # base options are off there: give the run a full1 archive dir by hand
            adir.mkdir(parents=True)
        legacy, _rec = self.to_full1_journal(j)
        self.options(gate_archive="off")
        self.assertEqual(self.resume(), 0, self.out)
        self.assertFalse(legacy.exists())
        self.assertFalse(adir.exists())
        self.assertEqual(self.share_files(), [])
        self.assertEqual(self.journal()["archive"]["mode"], "off")
        self.assertEqual(self.marker()["archive_mode"], "off")

    def test_full1_run_resumed_after_first_write_keeps_its_plaintext_rollback_copy(self):
        self.build_735()
        j = self.run_until_fixups()
        if not T.HAVE_AGE:
            (self.share / "openclaw-upgrade" / j["run_id"]).mkdir(parents=True)
        legacy, rec = self.to_full1_journal(j)
        self.assertEqual(self.resume(), 0, self.out)
        self.assertIn("2/9 archive: re-checking the recorded archive before continuing (sha256)", self.out)
        self.assertIn(f"2/9 archive: reusing verified archive {legacy.parent}/{legacy.name} (PLAINTEXT 0.5.94-full1 "
                      "archive; deleted by the cleanup after the run)", self.out)
        self.assertNotIn("archive-missing", self.out)
        self.assertTrue(legacy.exists())  # the only rollback copy of this run: kept until the cleanup
        self.assertEqual(self.journal()["archive"], rec)
        self.assertEqual(self.age_files(), [])  # no second archive after the first write
        m = self.marker()
        self.assertEqual((m["archive"], m["archive_mode"]), (str(legacy), "legacy"))

    # ----- archive content ---------------------------------------------------------------------
    @NEEDS_AGE
    def test_encrypted_archive_content_journal_and_manifest(self):
        self.build_735()
        self.hooks()
        db_before = (self.state / "state" / "openclaw.sqlite").read_bytes()
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        a = j["archive"]
        arch = self.archive_path(j)
        self.assertEqual((a["mode"], a["format"], a["recipient"], a["verified"]),
                         ("encrypted", "tar.gz+age", T.AGE_PUB, True))
        self.assertRegex(arch.name, r"^openclaw-state-\d{8}-\d{6}-before-2026\.9\.9\.tar\.gz\.age$")
        self.assertIn(f"2/9 archive verified: encrypted (age, {C.short_recipient(T.AGE_PUB)}), {a['members']} members",
                      self.out)
        raw = arch.read_bytes()
        self.assertTrue(raw.startswith(G.AGE_MAGIC))
        self.assertNotIn(b"SECRET", raw)
        self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (a["size"], a["sha256"]))
        plain = T.age_decrypt(arch)
        self.assertTrue(plain.startswith(b"\x1f\x8b"))
        self.assertEqual((len(plain), hashlib.sha256(plain).hexdigest()), (a["plaintext_size"], a["plaintext_sha256"]))
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tf:
            names = tf.getnames()
            self.assertEqual(len(names), a["members"])
            db = tf.extractfile(".openclaw/state/openclaw.sqlite").read()
            cfg = tf.extractfile(".openclaw/openclaw.json").read()
        self.assertEqual(db, db_before)  # the pre-migration state, taken before doctor
        self.assertEqual(int.from_bytes(db[60:64], "big"), 1)
        self.assertIn(b"SECRET-GATEWAY-TOKEN", cfg)  # secrets are inside: that is why it is encrypted
        self.assertIn(b"openai-codex/", cfg)
        man_text = (arch.parent / "manifest.json").read_text()
        man = json.loads(man_text)
        self.assertEqual((man["schema"], man["format"], man["encrypted"], man["contains_secrets"]),
                         (2, "tar.gz+age", True, True))
        self.assertEqual(man["archive"]["file"], arch.name)
        self.assertEqual((man["archive"]["sha256"], man["archive"]["plaintext_sha256"]),
                         (a["sha256"], a["plaintext_sha256"]))
        self.assertEqual(man["encryption"]["recipients"], [C.short_recipient(T.AGE_PUB)])
        self.assertNotIn(T.AGE_PUB, man_text)  # the full recipient is in the journal only
        self.assertEqual(j["archive"]["recipient"], T.AGE_PUB)
        self.assertIn("X25519", man["encryption"]["stanzas"])
        sq = {s["path"]: s for s in man["sqlite"]}
        self.assertEqual(sq[".openclaw/state/openclaw.sqlite"]["sha256"], hashlib.sha256(db).hexdigest())
        self.assertEqual(sq[".openclaw/state/openclaw.sqlite"]["user_version"], 1)
        self.assertNotIn("SECRET", man_text)
        self.assertNotIn("AGE-SECRET-KEY", man_text)
        self.assertNotIn("openai-codex:default", man_text)  # auth profile ids are not in the manifest
        self.assertTrue(man["auth_profiles"])
        self.assertTrue(all(set(p) <= {"agent", "provider", "type", "expires_utc"} for p in man["auth_profiles"]))
        self.assertEqual((arch.parent / "SHA256SUMS").read_text(), f"{a['sha256']}  {arch.name}\n")
        self.assertEqual(sorted(p.name for p in arch.parent.iterdir()), sorted([arch.name, "manifest.json",
                                                                                 "SHA256SUMS"]))
        for p in arch.parent.iterdir():
            self.assertEqual(p.stat().st_mode & 0o077, 0, p)
        self.assert_no_plaintext_under_share()
        m = self.marker()
        self.assertEqual((m["archive"], m["archive_mode"]), (str(arch), "encrypted"))
        self.assertIn("info: the archive and the doctor captures of this run are deleted after", self.out)
        st = "\n".join(G.status_lines())
        self.assertIn(f"  archive: encrypted (age, {C.short_recipient(T.AGE_PUB)}) {arch.parent}/{arch.name}", st)
        self.assertIn(f"Gate options: gate_archive encrypted to {C.short_recipient(T.AGE_PUB)};", st)

    # ----- previews --------------------------------------------------------------------------------
    def test_dry_run_preview_for_each_setting_writes_nothing(self):
        self.build_735()
        self.hooks()
        cases = [("off", {"gate_archive": "off"}, 0,
                  "[gate]   archive: off (rollback only through the encrypted Home Assistant backup)"),
                 ("missing", {"gate_archive": "encrypted", "gate_archive_age_recipient": ""}, 20,
                  "[gate]   archive: NOT CONFIGURED (the gate would HOLD; set gate_archive_age_recipient or "
                  "gate_archive: off)"),
                 ("private key", {"gate_archive": "encrypted", "gate_archive_age_recipient": IDENT}, 20,
                  "[gate]   archive: NOT CONFIGURED")]
        if T.HAVE_AGE:
            cases.append(("encrypted", {"gate_archive": "encrypted", "gate_archive_age_recipient": T.AGE_PUB}, 0,
                          f"[gate]   archive: encrypted to {C.short_recipient(T.AGE_PUB)} -> "
                          f"{self.share / 'openclaw-upgrade'}/<run>/openclaw-state-<ts>-before-2026.9.9.tar.gz.age"))
        texts = []
        for label, opts, want_rc, want_line in cases:
            with self.subTest(label):
                self.options(**opts)
                lines = []
                self.assertEqual(G.dry_run(emit=lines.append), want_rc, "\n".join(lines))
                text = "\n".join(lines)
                texts.append((f"dry-run {label}", text))
                self.assertTrue(any(x.startswith(want_line) for x in lines), text)
                if label == "off":
                    self.assertIn("[gate]   warn       archive-off:", text)
                    self.assertIn("[gate] dry-run: the precheck would pass", text)
                elif label == "missing":
                    self.assertIn("[gate] dry-run: would HOLD: archive-key-missing", lines)
                elif label == "private key":
                    self.assertIn("[gate] dry-run: would HOLD: archive-key-invalid", lines)
                else:
                    self.assertNotIn(T.AGE_PUB, text)  # logged short (a 62-char token would be redacted)
                    self.assertIn("[gate] dry-run: the precheck would pass", text)
                self.assertEqual(list(self.share.rglob("*")), [])
                self.assertFalse((self.upg / "gate" / "journal.json").exists())
                self.assertFalse((self.upg / "hold.txt").exists())
        self.assert_key_nowhere(texts)

    # ----- archive_reusable / archive_intact (unit) ------------------------------------------------
    def test_reuse_rules_for_off_and_legacy_records(self):
        adir = self.share / "openclaw-upgrade" / "r-unit"
        self.write_cfg(T.CFG_735)
        legacy, rec = self.make_plaintext_archive(adir)
        enc = {"mode": "encrypted", "recipient": PUB}
        off = {"mode": "off", "recipient": None}
        cases = [  # (archive record, archive_opt of this start, first write?, reusable?)
            ({"mode": "off", "verified": False}, off, False, True),
            ({"mode": "off", "verified": False}, enc, False, False),  # off -> encrypted: archive now
            ({"mode": "off", "verified": False}, enc, True, True),  # after the first write: the run keeps off
            (rec, enc, False, False),  # full1 plaintext before the first write: re-archive encrypted
            (rec, off, False, False),
            (rec, enc, True, True),  # after the first write: the rollback copy of this run
            (dict(rec, size=rec["size"] + 1), enc, True, False),
            (dict(rec, verified=False), enc, True, False),
            (dict(rec, file="gone.tar.gz"), enc, True, False),
            (None, enc, False, False),
        ]
        for i, (a, want, fw, expect) in enumerate(cases):
            with self.subTest(i=i):
                g = self.unit_gate({"run_id": "r-unit", "archive": a, "archive_opt": want,
                                    "first_write_at": "2026-10-18T00:00:00Z" if fw else None})
                self.assertIs(g.archive_reusable(), expect)
        g = self.unit_gate({"run_id": "r-unit", "archive": {"mode": "off", "verified": False}, "archive_opt": enc,
                            "first_write_at": "t"})
        self.assertTrue(g.archive_intact())
        self.assertIn("2/9 archive: none for this run (gate_archive was off); rollback only through the encrypted "
                      "Home Assistant backup", "\n".join(g.lines))
        g = self.unit_gate({"run_id": "r-unit", "archive": rec, "archive_opt": enc, "first_write_at": "t"})
        self.assertTrue(g.archive_intact())
        data = bytearray(legacy.read_bytes())
        data[-9] ^= 0x01  # same size, different bytes
        legacy.write_bytes(bytes(data))
        self.assertFalse(g.archive_intact())

    @NEEDS_AGE
    def test_reuse_rules_for_encrypted_records(self):
        T.make_735_state(self.state)
        self.write_cfg(T.CFG_735)
        g = G.Gate(emit=lambda s: None)
        g.pkg = C.runtime_package()
        g.cfg = dict(T.CFG_735)
        g.save = lambda: None
        g.j = {"run_id": "r-unit", "mode": "from-7x", "history": [], "source": {}, "auth_profiles": [],
               "archive_opt": {"mode": "encrypted", "recipient": T.AGE_PUB, "age_version": "test"},
               "first_write_at": None}
        g.phase_archive()
        a = dict(g.j["archive"])
        arch = Path(a["dir"]) / a["file"]
        self.assertTrue(g.archive_reusable())
        _ident2, pub2 = new_keypair()
        g.j["archive_opt"] = {"mode": "encrypted", "recipient": pub2}
        self.assertFalse(g.archive_reusable())  # another key before the first write: new archive
        g.j["archive_opt"] = {"mode": "off", "recipient": None}
        self.assertFalse(g.archive_reusable())
        g.j["first_write_at"] = "2026-10-18T00:00:00Z"
        self.assertTrue(g.archive_reusable())  # after the first write the recorded archive is the one
        self.assertTrue(g.archive_intact())
        g.j["archive"] = dict(a, plaintext_size=a["plaintext_size"] + 1)
        self.assertFalse(g.archive_intact())  # the ciphertext size must match the age size formula
        g.j["archive"] = dict(a, verified=False)
        self.assertFalse(g.archive_reusable())
        g.j["archive"] = a
        raw = bytearray(arch.read_bytes())
        raw[30] ^= 0x01  # inside the age header: same size, sha differs
        arch.write_bytes(bytes(raw))
        self.assertTrue(g.archive_reusable())  # size only
        self.assertFalse(g.archive_intact())  # sha re-check catches it


if __name__ == "__main__":
    unittest.main()
