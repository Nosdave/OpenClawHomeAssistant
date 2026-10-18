"""Unit tests for oc_common (stdlib unittest, Python 3.11)."""

import json
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ADDON = Path(__file__).resolve().parent.parent
if str(ADDON) not in sys.path:
    sys.path.insert(0, str(ADDON))

import oc_common as C  # noqa: E402


def make_db(path, uv=1, tables=("t",), wal=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
    for t in tables:
        con.execute(f'CREATE TABLE "{t}" (a)')
        con.execute(f'INSERT INTO "{t}" VALUES (1)')
    con.execute(f"PRAGMA user_version={uv}")
    con.commit()
    return con


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="oc-common-test-"))
        self.env = mock.patch.dict(os.environ, {
            "OPENCLAW_STATE_DIR": str(self.tmp / "config" / ".openclaw"),
            "OC_UPGRADE_DIR": str(self.tmp / "config" / ".openclaw-upgrade"),
            "OC_UPGRADE_SHARE_DIR": str(self.tmp / "share"),
            "OC_CONFIG_ROOT": str(self.tmp / "config"),
        })
        self.env.start()
        for k in ("OPENCLAW_CONFIG_PATH", "OPENCLAW_WORKSPACE_DIR"):
            os.environ.pop(k, None)
        (self.tmp / "config" / ".openclaw").mkdir(parents=True)

    def tearDown(self):
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)


class VersionTests(unittest.TestCase):
    def test_version_tuple(self):
        self.assertEqual(C.version_tuple("2026.7.35"), (2026, 7, 35, 0))
        self.assertEqual(C.version_tuple("2026.7.1-2"), (2026, 7, 1, 2))
        self.assertEqual(C.version_tuple("OpenClaw 2026.9.9 (abc123)"), (2026, 9, 9, 0))
        self.assertIsNone(C.version_tuple("nope"))
        self.assertIsNone(C.version_tuple(None))
        self.assertLess(C.version_tuple("2026.7.35"), C.version_tuple("2026.9.9"))
        self.assertEqual(C.fmt_version((2026, 7, 1, 2)), "2026.7.1-2")
        self.assertEqual(C.fmt_version(None), "unknown")


class PathsTests(TmpCase):
    def test_paths_defaults_and_overrides(self):
        p = C.paths()
        self.assertEqual(p["STATE"], self.tmp / "config" / ".openclaw")
        self.assertEqual(p["CONFIG_PATH"], self.tmp / "config" / ".openclaw" / "openclaw.json")
        self.assertEqual(p["WORKSPACE"], self.tmp / "config" / "clawd")
        self.assertEqual(p["SHARE"], self.tmp / "share")
        with mock.patch.dict(os.environ, {"OPENCLAW_CONFIG_PATH": "/x/y.json"}):
            self.assertEqual(C.paths()["CONFIG_PATH"], Path("/x/y.json"))


class SqliteTests(TmpCase):
    def test_header_and_user_version_without_wal(self):
        db = self.tmp / "a.sqlite"
        make_db(db, uv=7).close()
        self.assertEqual(C.header_user_version(db), 7)
        self.assertEqual(C.user_version(db), 7)
        self.assertIsNone(C.header_user_version(self.tmp / "missing.sqlite"))

    def test_query_ro_creates_no_companion_files(self):
        db = self.tmp / "b.sqlite"
        make_db(db, uv=1).close()
        before = sorted(os.listdir(self.tmp))
        rows = C.query_ro(db, "SELECT a FROM t WHERE a=?", (1,))
        self.assertEqual(rows, [(1,)])
        self.assertEqual(sorted(os.listdir(self.tmp)), before)

    def test_user_version_reads_wal(self):
        db = self.tmp / "w.sqlite"
        con = make_db(db, uv=1, wal=True)
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.execute("PRAGMA user_version=19")
        con.commit()
        # header may still say 1 while the WAL carries 19
        self.assertEqual(C.user_version(db), 19)
        con.close()

    def test_progress_handler_aborts(self):
        db = self.tmp / "p.sqlite"
        make_db(db).close()
        with self.assertRaises(sqlite3.OperationalError):
            C.query_ro(db, "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) SELECT count(*) FROM c",
                       progress_handler=lambda: 1, progress_n=100)

    @unittest.skipUnless(shutil.which("node"), "node not available")
    def test_node_query_fallback_reader(self):
        db = self.tmp / "n.sqlite"
        make_db(db).close()
        try:
            rows = C.node_query(db, "SELECT a FROM t WHERE a=?", params=(1,))
        except C.NodeQueryError as exc:  # node without node:sqlite
            self.skipTest(str(exc))
        self.assertEqual(rows, [{"a": 1}])

    def test_node_query_missing_node(self):
        with mock.patch.object(C, "image_node", return_value=None):
            with self.assertRaises(C.NodeQueryError):
                C.node_query(self.tmp / "x.sqlite", "SELECT 1")

    @unittest.skipUnless(shutil.which("node"), "node not available")
    def test_node_query_creates_no_companion_files(self):
        """F11: like query_ro, a DB without WAL content is opened immutable (node used to create -wal/-shm)."""
        d = self.tmp / "dir with space?#%"
        d.mkdir()
        db = d / "nq.sqlite"
        make_db(db, wal=True).close()
        self.assertEqual(sorted(os.listdir(d)), ["nq.sqlite"])
        with mock.patch.object(C, "image_node", return_value=shutil.which("node")):
            try:
                rows = C.node_query(db, "SELECT a FROM t WHERE a=?", params=(1,))
            except C.NodeQueryError as exc:  # node without node:sqlite
                self.skipTest(str(exc))
        self.assertEqual(rows, [{"a": 1}])
        self.assertEqual(sorted(os.listdir(d)), ["nq.sqlite"])

    def test_node_query_honours_the_stop_event(self):
        slow = self.tmp / "slow-node"
        slow.write_text("#!/bin/sh\nsleep 30\n")
        slow.chmod(0o755)
        ev = threading.Event()
        threading.Timer(0.3, ev.set).start()
        t0 = time.monotonic()
        with mock.patch.object(C, "image_node", return_value=str(slow)):
            with self.assertRaises(C.Stopped):
                C.node_query(self.tmp / "x.sqlite", "SELECT 1", stop_event=ev)
        self.assertLess(time.monotonic() - t0, 15)
        with mock.patch.object(C, "image_node", return_value=str(slow)):
            with self.assertRaises(C.NodeQueryError) as cm:
                C.node_query(self.tmp / "x.sqlite", "SELECT 1", timeout=1)
        self.assertIn("timed out", str(cm.exception))


class FileTests(TmpCase):
    def test_atomic_write_keeps_mode_and_defaults_0600(self):
        f = self.tmp / "new.json"
        C.atomic_write_json(f, {"a": 1})
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600)
        self.assertEqual(json.loads(f.read_text()), {"a": 1})
        g = self.tmp / "existing.txt"
        g.write_text("old")
        os.chmod(g, 0o644)
        C.atomic_write_text(g, "new")
        self.assertEqual(g.read_text(), "new")
        self.assertEqual(stat.S_IMODE(os.stat(g).st_mode), 0o644)
        self.assertEqual([x for x in os.listdir(self.tmp) if x.endswith(".tmp")], [])

    def test_json_dumps_lone_surrogates(self):
        """F5: a lone UTF-16 surrogate (truncated emoji) must not make a config/session rewrite crash."""
        self.assertEqual(C.json_dumps({"a": "Grüße"}), '{\n  "a": "Grüße"\n}\n')
        text = C.json_dumps({"a": "Hallo \ud83d", "b": "Grüße"})
        text.encode("utf-8")
        self.assertEqual(json.loads(text), {"a": "Hallo \ud83d", "b": "Grüße"})
        f = self.tmp / "s.json"
        C.atomic_write_json(f, {"label": "x \udc00"})
        self.assertEqual(json.loads(f.read_bytes().decode("utf-8")), {"label": "x \udc00"})

    def test_read_json_strict(self):
        f = self.tmp / "c.json"
        with self.assertRaises(C.ConfigReadError) as cm:
            C.read_json_strict(f)
        self.assertEqual(cm.exception.kind, "missing")
        f.write_text('{ // comment\n "a": 1 }')
        with self.assertRaises(C.ConfigReadError) as cm:
            C.read_json_strict(f)
        self.assertEqual(cm.exception.kind, "unreadable")
        self.assertIn("JSON5", str(cm.exception))
        f.write_text('{"a": NaN}')
        with self.assertRaises(C.ConfigReadError):
            C.read_json_strict(f)
        f.write_text("[1]")
        with self.assertRaises(C.ConfigReadError) as cm:
            C.read_json_strict(f)
        self.assertEqual(cm.exception.kind, "not-object")
        f.write_text('{"a": 1}')
        obj, text = C.read_json_strict(f, with_text=True)
        self.assertEqual(obj, {"a": 1})
        self.assertEqual(text, '{"a": 1}')

    def test_sha256_and_walk_never_follow_symlinks(self):
        d = self.tmp / "tree"
        (d / "sub").mkdir(parents=True)
        (d / "f").write_text("x")
        os.symlink("/etc", d / "link")
        names = sorted(str(p.relative_to(d)) for p, _st in C.walk_lstat(d))
        self.assertEqual(names, ["f", "link", "sub"])
        with self.assertRaises(OSError):
            C.sha256_file(d / "link")
        ev = threading.Event()
        ev.set()
        with self.assertRaises(C.Stopped):
            C.sha256_file(d / "f", stop_event=ev)


class RuntimePackageTests(TmpCase):
    def _pkg(self, data):
        pkg = self.tmp / "pkg" / "openclaw"
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "openclaw.mjs").write_text("")
        (pkg / "package.json").write_text(json.dumps(data))
        entry = self.tmp / "entry"
        entry.write_text(str(pkg / "openclaw.mjs") + "\n")
        return entry

    def test_runtime_package(self):
        entry = self._pkg({"version": "2026.9.9", "openclaw": {"schemaVersions": {"state": 19, "agent": 24}}})
        with mock.patch.dict(os.environ, {"OC_ADDON_ENTRY_FILE": str(entry)}):
            p = C.runtime_package()
        self.assertEqual((p["version"], p["schema_state"], p["schema_agent"]), ("2026.9.9", 19, 24))
        self.assertTrue(p["entry"].endswith("openclaw.mjs"))

    def test_runtime_package_uses_the_recorded_image_node(self):
        """F8: a Homebrew node earlier on PATH must not run OpenClaw."""
        entry = self._pkg({"version": "2026.9.9", "openclaw": {"schemaVersions": {"state": 19, "agent": 24}}})
        image, brew = self.tmp / "usr-bin" / "node", self.tmp / "linuxbrew" / "node"
        for n in (image, brew):
            n.parent.mkdir(parents=True)
            n.write_text("#!/bin/sh\n")
            n.chmod(0o755)
        record = entry.parent / "openclaw-node"
        record.write_text(f"{image}\n")
        with mock.patch.dict(os.environ, {"OC_ADDON_ENTRY_FILE": str(entry),
                                          "PATH": f"{brew.parent}:{os.environ.get('PATH', '')}"}):
            self.assertEqual(C.runtime_package()["node"], str(image))
            self.assertEqual(C.image_node(), str(image))
            record.write_text(f"{self.tmp / 'gone'}\n")  # stale record: PATH fallback
            self.assertEqual(C.image_node(), str(brew))
            record.unlink()
            self.assertEqual(C.runtime_package()["node"], str(brew))

    def test_runtime_package_without_schema_targets(self):
        entry = self._pkg({"version": "2026.9.9"})
        with mock.patch.dict(os.environ, {"OC_ADDON_ENTRY_FILE": str(entry)}):
            with self.assertRaises(C.RuntimePackageError):
                C.runtime_package()
        with mock.patch.dict(os.environ, {"OC_ADDON_ENTRY_FILE": str(self.tmp / "nope")}):
            with self.assertRaises(C.RuntimePackageError):
                C.runtime_package()


class EnvTests(TmpCase):
    def test_openclaw_env(self):
        with mock.patch.dict(os.environ, {
            "NODE_OPTIONS": "--require /x/shim.cjs --max-old-space-size=2048 --dns-result-order=ipv4first",
            "OPENCLAW_UPDATE_IN_PROGRESS": "1", "OPENCLAW_SKIP_CHANNELS": "1", "OPENCLAW_CONTAINER": "x",
            "INVOCATION_ID": "y", "NODE_COMPILE_CACHE": "/tmp/c", "KEEP_ME": "1"}):
            env = C.openclaw_env()
        self.assertEqual(env["NODE_OPTIONS"], "--require /x/shim.cjs --dns-result-order=ipv4first")
        for k in ("OPENCLAW_UPDATE_IN_PROGRESS", "OPENCLAW_SKIP_CHANNELS", "OPENCLAW_CONTAINER", "INVOCATION_ID",
                  "NODE_COMPILE_CACHE"):
            self.assertNotIn(k, env)
        self.assertEqual(env["KEEP_ME"], "1")
        self.assertEqual(env["HOME"], str(self.tmp / "config"))
        self.assertEqual(env["OPENCLAW_CONFIG_PATH"], str(self.tmp / "config" / ".openclaw" / "openclaw.json"))
        self.assertEqual(env["OPENCLAW_WORKSPACE_DIR"], str(self.tmp / "config" / "clawd"))
        for k, v in (("OPENCLAW_NO_RESPAWN", "1"), ("OPENCLAW_NO_AUTO_UPDATE", "1"),
                     ("OPENCLAW_SUPERVISOR_MODE", "external"), ("OPENCLAW_SERVICE_REPAIR_POLICY", "external"),
                     ("NO_COLOR", "1"), ("FORCE_COLOR", "0")):
            self.assertEqual(env[k], v)

    def test_heap_cap_only_option(self):
        with mock.patch.dict(os.environ, {"NODE_OPTIONS": "--max-old-space-size=768"}):
            self.assertNotIn("NODE_OPTIONS", C.openclaw_env())
        self.assertEqual(C.strip_heap_cap("--a --max_old_space_size=5 --b"), "--a --b")


class RedactTests(unittest.TestCase):
    def test_review_patterns(self):
        """F12: secrets in key: value, CLI flag, URL userinfo and Telegram Bot API forms."""
        tok = "fakeGatewayTokenForUnitTests0000"  # 32 chars, like a gateway token
        for raw, want in (
                ("{ mode: 'token', token: '%s' }" % tok, "{ mode: 'token', token: '***' }"),
                ("token: %s" % tok, "token: ***"),
                ("gateway.auth.token = %s" % tok, "gateway.auth.token = ***"),
                ("openclaw gateway call health --token %s" % tok, "openclaw gateway call health --token ***"),
                ("--password hunter2 --json", "--password *** --json"),
                ("--api-key abc123", "--api-key ***"),
                ("baseUrl http://admin:S3cretPass@192.168.1.5:8000/v1 down", "baseUrl http://***@192.168.1.5:8000/v1 down"),
                ("apiKey: 'FAKE-TU-VLLM-KEY-91d0e2'", "apiKey: '***'"),
                ("x-api-key: abcdef0123456789abcdef", "x-api-key: ***"),
                ("GET /bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/getMe failed", "GET /bot***/getMe failed"),
                ("access eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl", "access ***"),
                ("gateway token " + "9f86d081" * 8 + ".", "gateway token ***."),
                ("http://127.0.0.1:18789/?token=%s&lang=de" % tok, "http://127.0.0.1:18789/?token=***&lang=de")):
            with self.subTest(raw=raw):
                self.assertEqual(C.redact_text(raw), want)

    def test_paths_and_file_names_are_not_tokens(self):
        """F12: the 40+ character rule leaves path segments and file names alone."""
        for line in (
                "Saved pre-migration SQLite backup: /config/.openclaw/state/openclaw.sqlite.pre-startup-migration-"
                "2026-10-09T12-00-00-000Z-3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b.bak",
                "npm/projects/openclaw-codex-" + "0123456789abcdef" * 3 + "/node_modules/@openclaw/codex",
                "/share/openclaw-upgrade/r-full/openclaw-state-20261009-120000-before-2026.9.9.tar.gz.tmp: Wrote only 4096",
                "https://github.com/openclaw/openclaw/commit/" + "0123456789abcdef" * 2 + "01234567",
                "Paths: gateway.auth.token, channels.telegram.botToken",
                '"maxTokens": 8, maxTokens: 8, sessionKey: agent:main:main',
                "Replaced retired openai/gpt-5.4-mini with openai/gpt-5.6-luna."):
            with self.subTest(line=line[:40]):
                self.assertEqual(C.redact_text(line), line)

    def test_redact_text(self):
        s = ('key sk-abcdefghijklmnop "apiKey": "abc123" token=deadbeef '
             '123456789:AAHbcdefghijklmnopqrstuvwxyz0123456 ' + "A" * 45 + ' Bearer abcdefghijkl')
        r = C.redact_text(s)
        for secret in ("sk-abcdefghijklmnop", "abc123", "deadbeef", "AAHbcdefghij", "A" * 45, "abcdefghijkl"):
            self.assertNotIn(secret, r)
        self.assertIn('"apiKey": "***"', r)
        self.assertEqual(C.redact_text("Doctor complete."), "Doctor complete.")


class RunProcessTests(TmpCase):
    def test_success_appends_to_log_never_pipe(self):
        log = self.tmp / "log.txt"
        log.write_text("previous\n")
        res = C.run_process(["sh", "-c", "echo out; echo err >&2; readlink /proc/self/fd/1; exit 3"],
                            timeout=30, log_path=log)
        self.assertEqual(res.rc, 3)
        rc, dur = res  # tuple unpacking (contract signature)
        self.assertEqual(rc, 3)
        self.assertFalse(res.timed_out)
        text = log.read_text()
        self.assertTrue(text.startswith("previous\n"))
        self.assertIn("out\n", text)
        self.assertIn("err\n", text)
        self.assertIn(str(log), text)  # stdout is the log file, not a pipe

    def test_separate_stdout(self):
        log, outp = self.tmp / "e.log", self.tmp / "o.json"
        res = C.run_process(["sh", "-c", 'echo \'{"a":1}\'; echo warn >&2'], timeout=30, log_path=log,
                            stdout_path=outp)
        self.assertEqual(res.rc, 0)
        self.assertEqual(json.loads(outp.read_text()), {"a": 1})
        self.assertEqual(log.read_text().strip(), "warn")

    def test_timeout_kills_process_group(self):
        log = self.tmp / "t.log"
        marker = self.tmp / "child-alive"
        t0 = time.monotonic()
        res = C.run_process(["sh", "-c", f"(sleep 5; touch {marker}) & sleep 30"], timeout=1, log_path=log,
                            kill_grace=2)
        self.assertTrue(res.timed_out)
        self.assertLess(res.rc, 0)
        self.assertLess(time.monotonic() - t0, 10)
        time.sleep(5.5)
        self.assertFalse(marker.exists(), "grandchild survived the process-group kill")

    def test_stop_event(self):
        ev = threading.Event()
        threading.Timer(0.5, ev.set).start()
        res = C.run_process(["sleep", "30"], timeout=60, log_path=self.tmp / "s.log", stop_event=ev, stop_grace=5)
        self.assertTrue(res.stopped)
        self.assertLess(res.duration, 10)

    def test_kill_after_grace_when_term_ignored(self):
        res = C.run_process(["sh", "-c", "trap '' TERM; sleep 30"], timeout=0.5, log_path=self.tmp / "k.log",
                            kill_grace=1)
        self.assertTrue(res.timed_out)
        self.assertEqual(res.rc, -9)

    def test_on_tick_and_missing_binary(self):
        ticks = []
        C.run_process(["sleep", "1.5"], timeout=10, log_path=self.tmp / "x.log", on_tick=ticks.append, tick=0.2)
        self.assertTrue(ticks)
        res = C.run_process([str(self.tmp / "nope")], timeout=10, log_path=self.tmp / "y.log")
        self.assertEqual(res.rc, 127)

    def test_run_oc_uses_node_and_entry(self):
        bindir = self.tmp / "bin"
        bindir.mkdir()
        node = bindir / "node"
        node.write_text("#!/bin/sh\necho \"argv: $*\"\necho \"home=$HOME respawn=$OPENCLAW_NO_RESPAWN\"\n")
        node.chmod(0o755)
        pkg = self.tmp / "pkg"
        pkg.mkdir()
        (pkg / "openclaw.mjs").write_text("")
        (pkg / "package.json").write_text(json.dumps({"version": "2026.9.9",
                                                      "openclaw": {"schemaVersions": {"state": 19, "agent": 24}}}))
        (self.tmp / "entry").write_text(str(pkg / "openclaw.mjs"))
        with mock.patch.dict(os.environ, {"PATH": f"{bindir}:{os.environ['PATH']}",
                                          "OC_ADDON_ENTRY_FILE": str(self.tmp / "entry")}):
            res = C.run_oc(["config", "validate", "--json"], timeout=10, log_path=self.tmp / "oc.log")
        self.assertEqual(res.rc, 0)
        text = (self.tmp / "oc.log").read_text()
        self.assertIn(f"argv: {pkg / 'openclaw.mjs'} config validate --json", text)
        self.assertIn(f"home={self.tmp / 'config'} respawn=1", text)


class ParseJsonTests(unittest.TestCase):
    def test_parse_json_output(self):
        self.assertEqual(C.parse_json_output('{"a":1}'), {"a": 1})
        self.assertEqual(C.parse_json_output('noise\n{"a":2}\n'), {"a": 2})
        self.assertIsNone(C.parse_json_output("nothing"))
        self.assertIsNone(C.parse_json_output(None))


# --- 0.5.94-full2: gate archive / backup / cleanup options, age, Supervisor token -----------------

_TESTS = Path(__file__).resolve().parent
if str(_TESTS) not in sys.path:
    sys.path.insert(0, str(_TESTS))
import re  # noqa: E402
import test_gate as T  # noqa: E402  (AGE_IDENTITY / AGE_PUB / HAVE_AGE: a throwaway age key pair)

BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"  # the bech32 data charset (no 1, b, i, o)
# Shape-valid fakes (the recipient regex checks the charset and length, not the bech32 checksum).
FAKE_RECIPIENT = "age1" + (BECH32 * 2)[:58]
FAKE_SECRET_KEY = "AGE-SECRET-KEY-1" + (BECH32.upper() * 2)[:58]
FAKE_SECRET_BODY = FAKE_SECRET_KEY[len("AGE-SECRET-KEY-1"):]


class OptionsCase(TmpCase):
    """TmpCase with its own add-on options file (OC_ADDON_OPTIONS_FILE). TmpCase's patch.dict restores the
    whole environment in tearDown, so every variable set or removed here is undone."""

    def setUp(self):
        super().setUp()
        self.opts = self.tmp / "options.json"
        os.environ["OC_ADDON_OPTIONS_FILE"] = str(self.opts)
        for k in ("OC_ADDON_AGE", "SUPERVISOR_TOKEN", "HASSIO_TOKEN"):
            os.environ.pop(k, None)

    def write(self, obj=None, raw=None):
        self.opts.write_text(raw if raw is not None else json.dumps(obj), encoding="utf-8")


class GateOptionsTests(OptionsCase):
    DEFAULT_ARCHIVE = {"mode": "encrypted", "recipient": None, "problem": "missing"}

    def assert_fail_closed_defaults(self, o):
        self.assertEqual(o["archive"], self.DEFAULT_ARCHIVE)
        self.assertEqual((o["cleanup_hours"], o["backup_max_age_hours"]), (48, 24))
        self.assertEqual(o["problems"], [])

    def test_result_shape_and_defaults_constant(self):
        self.write({})
        o = C.gate_options()
        self.assertEqual(set(o), {"archive", "cleanup_hours", "backup_max_age_hours", "problems"})
        self.assertEqual(set(o["archive"]), {"mode", "recipient", "problem"})
        self.assertEqual(C.GATE_OPTION_DEFAULTS, {"gate_archive": "encrypted", "gate_archive_age_recipient": "",
                                                  "gate_cleanup_hours": 48, "gate_backup_max_age_hours": 24})
        self.assertEqual(C._GATE_INT_RANGES, {"gate_cleanup_hours": (0, 720), "gate_backup_max_age_hours": (1, 168)})

    def test_defaults_match_config_yaml(self):
        """The fail-closed defaults and ranges in oc_common are the ones config.yaml declares."""
        text = (ADDON / "config.yaml").read_text(encoding="utf-8")
        opts_block = text.split("\noptions:", 1)[1].split("\nschema:", 1)[0]
        schema_block = text.split("\nschema:", 1)[1]
        for key, want in C.GATE_OPTION_DEFAULTS.items():
            m = re.search(rf"^  {key}: (.*)$", opts_block, re.M)
            self.assertIsNotNone(m, key)
            self.assertEqual(m.group(1).strip(), '""' if want == "" else str(want), key)
        for key, (lo, hi) in C._GATE_INT_RANGES.items():
            self.assertRegex(schema_block, rf"(?m)^  {key}: int\({lo},{hi}\)\?$")
        self.assertRegex(schema_block, r"(?m)^  gate_archive: list\(encrypted\|off\)\?$")
        m = re.search(r'(?m)^  gate_archive_age_recipient: "match\(\^\((.*)\)\?\$\)\?"$', schema_block)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), C.AGE_RECIPIENT_RE.pattern)

    def test_missing_empty_or_broken_options_file_is_encrypted_without_recipient(self):
        """No options means the config.yaml defaults: encrypted, no recipient -> problem 'missing' (never plaintext)."""
        self.assertFalse(self.opts.exists())
        self.assert_fail_closed_defaults(C.gate_options())
        for raw in ("", "   \n", "{not json", '{"gate_archive": "off"', "[1, 2]", "null", '"off"', "42"):
            with self.subTest(raw=raw):
                self.write(raw=raw)
                self.assert_fail_closed_defaults(C.gate_options())
        self.opts.write_bytes(b"\xff\xfe{\x00")  # not UTF-8
        self.assert_fail_closed_defaults(C.gate_options())
        self.opts.unlink()
        self.opts.mkdir()  # unreadable as a file
        self.assert_fail_closed_defaults(C.gate_options())

    def test_options_file_is_read_at_call_time(self):
        self.write({"gate_archive": "off"})
        self.assertEqual(C.gate_options()["archive"]["mode"], "off")
        self.write({"gate_archive": "encrypted", "gate_archive_age_recipient": FAKE_RECIPIENT})
        self.assertEqual(C.gate_options()["archive"]["recipient"], FAKE_RECIPIENT)

    def test_encrypted_with_valid_recipient(self):
        self.write({"gate_archive": "encrypted", "gate_archive_age_recipient": FAKE_RECIPIENT,
                    "gate_cleanup_hours": 12, "gate_backup_max_age_hours": 72})
        o = C.gate_options()
        self.assertEqual(o["archive"], {"mode": "encrypted", "recipient": FAKE_RECIPIENT, "problem": None})
        self.assertEqual((o["cleanup_hours"], o["backup_max_age_hours"], o["problems"]), (12, 72, []))
        # gate_archive left out: the default (encrypted) applies to the recipient
        self.write({"gate_archive_age_recipient": FAKE_RECIPIENT})
        self.assertEqual(C.gate_options()["archive"], {"mode": "encrypted", "recipient": FAKE_RECIPIENT,
                                                       "problem": None})

    @unittest.skipUnless(T.HAVE_AGE, "age not installed")
    def test_real_age_public_key_is_valid(self):
        self.write({"gate_archive": "encrypted", "gate_archive_age_recipient": T.AGE_PUB})
        self.assertEqual(C.gate_options()["archive"], {"mode": "encrypted", "recipient": T.AGE_PUB, "problem": None})

    def test_recipient_whitespace_is_stripped(self):
        for raw in (f"  {FAKE_RECIPIENT}  ", f"{FAKE_RECIPIENT}\n", f"\t{FAKE_RECIPIENT}\r\n"):
            with self.subTest(raw=repr(raw)):
                self.write({"gate_archive": "encrypted", "gate_archive_age_recipient": raw})
                a = C.gate_options()["archive"]
                self.assertEqual((a["recipient"], a["problem"]), (FAKE_RECIPIENT, None))

    def test_empty_or_non_string_recipient_is_missing(self):
        for rec in ("", "   ", None, 123, ["age1x"], {"k": FAKE_RECIPIENT}, True):
            with self.subTest(rec=rec):
                self.write({"gate_archive": "encrypted", "gate_archive_age_recipient": rec})
                self.assertEqual(C.gate_options()["archive"], self.DEFAULT_ARCHIVE)

    def test_private_key_is_refused_and_never_returned(self):
        for raw in (FAKE_SECRET_KEY, f"  {FAKE_SECRET_KEY}\n", FAKE_SECRET_KEY.lower(),
                    "AGE-SECRET-KEY-1", f"Age-Secret-Key-1{FAKE_SECRET_BODY}"):
            with self.subTest(raw=raw[:20]):
                self.write({"gate_archive": "encrypted", "gate_archive_age_recipient": raw,
                            "gate_cleanup_hours": 48})
                o = C.gate_options()
                self.assertEqual(o["archive"], {"mode": "encrypted", "recipient": None, "problem": "private-key"})
                dumped = json.dumps(o, ensure_ascii=False)
                self.assertNotIn(raw.strip(), dumped)
                self.assertNotIn(FAKE_SECRET_BODY.lower(), dumped.lower())
                self.assertNotIn("SECRET", dumped.upper())

    @unittest.skipUnless(T.HAVE_AGE, "age not installed")
    def test_real_age_identity_is_refused_and_never_returned(self):
        self.write({"gate_archive": "encrypted", "gate_archive_age_recipient": T.AGE_IDENTITY})
        o = C.gate_options()
        self.assertEqual(o["archive"]["problem"], "private-key")
        self.assertIsNone(o["archive"]["recipient"])
        self.assertNotIn(T.AGE_IDENTITY[16:], json.dumps(o))

    def test_whole_key_file_pasted_is_refused_and_never_returned(self):
        """age-keygen's key file (comments, public key, private key) pasted as a whole: refused, not echoed."""
        keyfile = (f"# created: 2026-10-18T12:00:00Z\n# public key: {FAKE_RECIPIENT}\n{FAKE_SECRET_KEY}\n")
        self.write({"gate_archive": "encrypted", "gate_archive_age_recipient": keyfile})
        o = C.gate_options()
        self.assertIn(o["archive"]["problem"], ("private-key", "malformed"))
        self.assertIsNone(o["archive"]["recipient"])
        self.assertNotIn(FAKE_SECRET_BODY, json.dumps(o))

    def test_malformed_recipient_is_refused_and_never_returned(self):
        for raw in ("age1", "age1tooshort", FAKE_RECIPIENT[:-1], FAKE_RECIPIENT + "q", FAKE_RECIPIENT.upper(),
                    "AGE1" + FAKE_RECIPIENT[4:], FAKE_RECIPIENT[:10] + "b" + FAKE_RECIPIENT[11:],
                    f"{FAKE_RECIPIENT} {FAKE_RECIPIENT}", f"{FAKE_RECIPIENT},{FAKE_RECIPIENT}",
                    f"-r {FAKE_RECIPIENT}", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvbmcta2V5LW5vdC1yZWFs x@y",
                    "age2" + FAKE_RECIPIENT[4:], f"{FAKE_RECIPIENT[:30]} {FAKE_RECIPIENT[30:]}"):
            with self.subTest(raw=raw[:24]):
                self.write({"gate_archive": "encrypted", "gate_archive_age_recipient": raw})
                o = C.gate_options()
                self.assertEqual(o["archive"], {"mode": "encrypted", "recipient": None, "problem": "malformed"})
                self.assertNotIn(raw, json.dumps(o))

    def test_mode_off_never_returns_a_recipient(self):
        for rec in ("", FAKE_RECIPIENT, FAKE_SECRET_KEY, "garbage"):
            with self.subTest(rec=rec[:12]):
                self.write({"gate_archive": "off", "gate_archive_age_recipient": rec})
                o = C.gate_options()
                self.assertEqual(o["archive"], {"mode": "off", "recipient": None, "problem": None})
                self.assertNotIn(FAKE_SECRET_BODY, json.dumps(o))

    def test_invalid_mode(self):
        for mode in ("plaintext", "Encrypted", "OFF", "", "none", None, True, False, 1, ["encrypted"]):
            with self.subTest(mode=mode):
                self.write({"gate_archive": mode, "gate_archive_age_recipient": FAKE_RECIPIENT})
                o = C.gate_options()
                self.assertEqual(o["archive"], {"mode": None, "recipient": None, "problem": "invalid-mode"})

    def test_integer_ranges(self):
        ok = {"gate_cleanup_hours": (0, 1, 48, 719, 720), "gate_backup_max_age_hours": (1, 24, 167, 168)}
        out_key = {"gate_cleanup_hours": "cleanup_hours", "gate_backup_max_age_hours": "backup_max_age_hours"}
        for key, values in ok.items():
            for v in values:
                with self.subTest(key=key, v=v):
                    self.write({**self.base(), key: v})
                    o = C.gate_options()
                    self.assertEqual(o[out_key[key]], v)
                    self.assertEqual(o["problems"], [])

    def test_out_of_range_or_wrong_type_uses_the_default_with_a_problem(self):
        bad = {"gate_cleanup_hours": (-1, 721, 10 ** 9, "48", "", 12.0, 0.5, True, False, None, [48], {"h": 1}),
               "gate_backup_max_age_hours": (0, -5, 169, "24", 24.0, True, False, None)}
        default = {"gate_cleanup_hours": ("cleanup_hours", 48, "0..720"),
                   "gate_backup_max_age_hours": ("backup_max_age_hours", 24, "1..168")}
        for key, values in bad.items():
            out_key, dflt, rng = default[key]
            for v in values:
                with self.subTest(key=key, v=v):
                    self.write({**self.base(), key: v})
                    o = C.gate_options()
                    self.assertEqual(o[out_key], dflt)
                    self.assertEqual(len(o["problems"]), 1, o["problems"])
                    self.assertIn(key, o["problems"][0])
                    self.assertIn(rng, o["problems"][0])
                    self.assertIn(f"using {dflt}", o["problems"][0])
                    # the archive part is unaffected by a bad integer
                    self.assertEqual(o["archive"]["problem"], None)

    def test_bool_is_not_an_integer_even_inside_the_range(self):
        """False == 0 and True == 1 in Python, both inside the ranges: still rejected (a YAML/JSON bool)."""
        self.write({**self.base(), "gate_cleanup_hours": False, "gate_backup_max_age_hours": True})
        o = C.gate_options()
        self.assertEqual((o["cleanup_hours"], o["backup_max_age_hours"]), (48, 24))
        self.assertEqual(len(o["problems"]), 2)

    def test_problems_never_echo_values(self):
        self.write({"gate_archive": "encrypted", "gate_archive_age_recipient": FAKE_SECRET_KEY,
                    "gate_cleanup_hours": FAKE_SECRET_KEY, "gate_backup_max_age_hours": "hunter2-" + FAKE_SECRET_BODY})
        o = C.gate_options()
        self.assertEqual(len(o["problems"]), 2)
        dumped = json.dumps(o)
        self.assertNotIn(FAKE_SECRET_BODY, dumped)
        self.assertNotIn("hunter2", dumped)

    def base(self):
        return {"gate_archive": "encrypted", "gate_archive_age_recipient": FAKE_RECIPIENT}


class AgeRecipientTests(unittest.TestCase):
    def test_fake_recipient_is_shape_valid(self):
        self.assertEqual(len(FAKE_RECIPIENT), 62)
        self.assertTrue(C.AGE_RECIPIENT_RE.fullmatch(FAKE_RECIPIENT))

    @unittest.skipUnless(T.HAVE_AGE, "age not installed")
    def test_real_public_key_matches(self):
        self.assertTrue(C.AGE_RECIPIENT_RE.fullmatch(T.AGE_PUB))
        self.assertFalse(C.AGE_RECIPIENT_RE.fullmatch(T.AGE_IDENTITY))

    def test_every_bech32_character_is_accepted(self):
        for ch in BECH32:
            with self.subTest(ch=ch):
                self.assertTrue(C.AGE_RECIPIENT_RE.fullmatch("age1" + ch * 58))

    def test_non_bech32_characters_after_the_prefix_are_rejected(self):
        for ch in "bio1BIOQ-_.+/= \t\nä":
            for pos in (4, 30, 61):
                with self.subTest(ch=ch, pos=pos):
                    bad = FAKE_RECIPIENT[:pos] + ch + FAKE_RECIPIENT[pos + 1:]
                    self.assertEqual(len(bad), 62)
                    self.assertIsNone(C.AGE_RECIPIENT_RE.fullmatch(bad))

    def test_wrong_length_prefix_or_case(self):
        for bad in ("", "age1", FAKE_RECIPIENT[:-1], FAKE_RECIPIENT + "q", FAKE_RECIPIENT + FAKE_RECIPIENT[4:],
                    "age" + FAKE_RECIPIENT[4:] + "q", "age0" + FAKE_RECIPIENT[4:], "AGE1" + FAKE_RECIPIENT[4:],
                    FAKE_RECIPIENT.upper(), " " + FAKE_RECIPIENT, FAKE_RECIPIENT + "\n"):
            with self.subTest(bad=bad[:16]):
                self.assertIsNone(C.AGE_RECIPIENT_RE.fullmatch(bad))


class ShortRecipientTests(unittest.TestCase):
    def test_long_recipient_is_shortened(self):
        s = C.short_recipient(FAKE_RECIPIENT)
        head, sep, tail = s.partition("…")
        self.assertEqual(sep, "…")
        self.assertTrue(head.startswith("age1") and FAKE_RECIPIENT.startswith(head), s)
        self.assertIn(len(head), (8, 9))  # spec: 8 characters; the implementation keeps 9
        self.assertEqual(tail, FAKE_RECIPIENT[-6:])
        self.assertLess(len(s), 20)
        self.assertNotEqual(s, FAKE_RECIPIENT)

    def test_short_form_survives_redaction_where_the_full_key_would_not(self):
        """The reason for the short form: the 40-character token rule would turn the full key into ***."""
        s = C.short_recipient(FAKE_RECIPIENT)
        self.assertEqual(C.redact_text(f"encrypted to {s}"), f"encrypted to {s}")
        self.assertNotIn(FAKE_RECIPIENT, C.redact_text(f"encrypted to {FAKE_RECIPIENT}"))

    @unittest.skipUnless(T.HAVE_AGE, "age not installed")
    def test_real_key(self):
        s = C.short_recipient(T.AGE_PUB)
        self.assertTrue(s.endswith(T.AGE_PUB[-6:]))
        self.assertTrue(T.AGE_PUB.startswith(s.split("…")[0]))

    def test_empty_and_short_values(self):
        self.assertEqual(C.short_recipient(""), "")
        self.assertEqual(C.short_recipient(None), "")
        self.assertEqual(C.short_recipient("age1short"), "age1short")
        self.assertEqual(C.short_recipient("x" * 16), "x" * 16)
        s = C.short_recipient("abcdefghijklmnopq")  # 17 characters: shortened
        self.assertIn("…", s)
        self.assertTrue(s.endswith("lmnopq"))
        self.assertTrue("abcdefghijklmnopq".startswith(s.split("…")[0]))


class AgeBinTests(OptionsCase):
    def setUp(self):
        super().setUp()
        self.pathbin = self.tmp / "pathbin"
        self.imgbin = self.tmp / "img"
        self.empty = self.tmp / "emptybin"
        for d in (self.pathbin, self.imgbin, self.empty):
            d.mkdir()
        self.path_age = self.exe(self.pathbin / "age")
        self.img_age = self.exe(self.imgbin / "age")
        self.record = self.tmp / "libexec" / "age-bin"
        self.record.parent.mkdir()
        os.environ["PATH"] = str(self.pathbin)
        self.rec_patch = mock.patch.object(C, "AGE_BIN_RECORD", str(self.record))
        self.rec_patch.start()
        self.addCleanup(self.rec_patch.stop)

    @staticmethod
    def exe(p, mode=0o755):
        p.write_text("#!/bin/sh\necho age-fake\n")
        p.chmod(mode)
        return p

    def test_record_constant_is_the_one_the_dockerfile_writes(self):
        self.rec_patch.stop()
        try:
            self.assertEqual(C.AGE_BIN_RECORD, "/usr/local/libexec/oc-addon/age-bin")
            self.assertIn(f"> {C.AGE_BIN_RECORD}", (ADDON / "Dockerfile").read_text(encoding="utf-8"))
        finally:
            self.rec_patch.start()

    def test_env_override_wins(self):
        self.record.write_text(f"{self.img_age}\n")
        with mock.patch.dict(os.environ, {"OC_ADDON_AGE": "/nonexistent/test-age"}):
            self.assertEqual(C.age_bin(), "/nonexistent/test-age")  # a test hook: taken as given
        with mock.patch.dict(os.environ, {"OC_ADDON_AGE": ""}):
            self.assertEqual(C.age_bin(), str(self.img_age))  # empty means unset

    def test_build_time_record_wins_over_path(self):
        """A Homebrew age earlier on PATH must never win over the image's recorded age."""
        self.record.write_text(f"{self.img_age}\n")
        self.assertEqual(C.age_bin(), str(self.img_age))
        self.record.write_text(f"  {self.img_age}  \n/some/other/age\n")  # first line, stripped
        self.assertEqual(C.age_bin(), str(self.img_age))

    def test_stale_or_broken_record_falls_back_to_path(self):
        noexec = self.imgbin / "age-noexec"
        self.exe(noexec, 0o644)
        for content in (f"{self.tmp / 'gone' / 'age'}\n", f"{noexec}\n", "", "\n", f"\n{self.img_age}\n"):
            with self.subTest(content=content.strip()[-20:]):
                self.record.write_text(content)
                self.assertEqual(C.age_bin(), str(self.path_age))
        self.record.unlink()
        self.assertEqual(C.age_bin(), str(self.path_age))
        self.record.mkdir()  # unreadable record
        self.assertEqual(C.age_bin(), str(self.path_age))

    def test_nothing_found_returns_bare_age(self):
        os.environ["PATH"] = str(self.empty)
        self.assertEqual(C.age_bin(), "age")


class SupervisorTokenTests(OptionsCase):
    def setUp(self):
        super().setUp()
        self.f = self.tmp / "s6" / "SUPERVISOR_TOKEN"
        self.f.parent.mkdir()
        # never read a real /run/s6 file from a test
        self.s6_patch = mock.patch.object(C, "S6_TOKEN_FILE", str(self.tmp / "s6" / "default-SUPERVISOR_TOKEN"))
        self.s6_patch.start()
        self.addCleanup(self.s6_patch.stop)

    def test_default_path_is_the_s6_container_environment(self):
        self.s6_patch.stop()
        try:
            self.assertEqual(C.S6_TOKEN_FILE, "/run/s6/container_environment/SUPERVISOR_TOKEN")
        finally:
            self.s6_patch.start()
        Path(C.S6_TOKEN_FILE).write_text("s6tok\n")
        os.environ["SUPERVISOR_TOKEN"] = "envtok"
        self.assertEqual(C.supervisor_token(), "s6tok")

    def test_file_first_trailing_newline_stripped(self):
        self.f.write_text("filetok123\n")
        os.environ["SUPERVISOR_TOKEN"] = "envtok"
        self.assertEqual(C.supervisor_token(str(self.f)), "filetok123")
        self.f.write_text("  \tfiletok123 \r\n")
        self.assertEqual(C.supervisor_token(str(self.f)), "filetok123")

    def test_empty_whitespace_or_invalid_file_falls_back_to_env(self):
        os.environ["SUPERVISOR_TOKEN"] = "envtok"
        for content in ("", "\n", "   \n\t", "two words", "line1\nline2"):
            with self.subTest(content=repr(content)):
                self.f.write_text(content)
                self.assertEqual(C.supervisor_token(str(self.f)), "envtok")

    def test_missing_or_unreadable_file_falls_back_to_env(self):
        os.environ["SUPERVISOR_TOKEN"] = "  envtok \n"
        self.assertEqual(C.supervisor_token(str(self.tmp / "nope")), "envtok")
        self.assertEqual(C.supervisor_token(), "envtok")  # default (patched) s6 path is missing too
        self.assertEqual(C.supervisor_token(str(self.f.parent)), "envtok")  # a directory

    def test_neither_gives_none(self):
        self.assertIsNone(C.supervisor_token(str(self.tmp / "nope")))
        self.assertIsNone(C.supervisor_token())
        for v in ("", "   ", "\n"):
            with self.subTest(env=repr(v)):
                os.environ["SUPERVISOR_TOKEN"] = v
                self.f.write_text("")
                self.assertIsNone(C.supervisor_token(str(self.f)))

    def test_hassio_token_is_not_a_fallback(self):
        os.environ["HASSIO_TOKEN"] = "legacy"
        self.assertIsNone(C.supervisor_token(str(self.tmp / "nope")))

    # Regression: an undecodable token file falls back to SUPERVISOR_TOKEN (never an internal-error HOLD).
    def test_undecodable_file_falls_back_to_env(self):
        self.f.write_bytes(b"\xff\xfe\x00tok")
        os.environ["SUPERVISOR_TOKEN"] = "envtok"
        self.assertEqual(C.supervisor_token(str(self.f)), "envtok")
        del os.environ["SUPERVISOR_TOKEN"]
        self.assertIsNone(C.supervisor_token(str(self.f)))


class Full2RedactTests(unittest.TestCase):
    def test_age_secret_key_is_masked(self):
        for raw, want in (
                (FAKE_SECRET_KEY, "AGE-SECRET-KEY-***"),
                (f"recipient: {FAKE_SECRET_KEY}", "recipient: AGE-SECRET-KEY-***"),
                (f'age: error: malformed recipient "{FAKE_SECRET_KEY}": invalid type',
                 'age: error: malformed recipient "AGE-SECRET-KEY-***": invalid type'),
                (f"x={FAKE_SECRET_KEY}.", "x=AGE-SECRET-KEY-***."),
                (f"/share/{FAKE_SECRET_KEY}/x", "/share/AGE-SECRET-KEY-***/x"),
                (f"[{FAKE_SECRET_KEY}]", "[AGE-SECRET-KEY-***]")):
            with self.subTest(raw=raw[:30]):
                self.assertEqual(C.redact_text(raw), want)

    def test_lowercase_or_mixed_case_key_body_never_survives(self):
        for raw in (FAKE_SECRET_KEY.lower(), f"recipient={FAKE_SECRET_KEY.lower()}",
                    f"gate_archive_age_recipient: {FAKE_SECRET_KEY.lower()}",
                    f"Age-Secret-Key-1{FAKE_SECRET_BODY}"):
            with self.subTest(raw=raw[:30]):
                self.assertNotIn(FAKE_SECRET_BODY.lower(), C.redact_text(raw).lower())

    @unittest.skipUnless(T.HAVE_AGE, "age not installed")
    def test_real_identity(self):
        r = C.redact_text(f"pasted {T.AGE_IDENTITY} by mistake")
        self.assertEqual(r, "pasted AGE-SECRET-KEY-*** by mistake")
        self.assertNotIn(T.AGE_IDENTITY[16:], r)

    def test_age_secret_key_rule_is_first(self):
        rx, rep = C._REDACT_RES[0]
        self.assertEqual(rep, "AGE-SECRET-KEY-***")
        self.assertTrue(rx.search(FAKE_SECRET_KEY))

    def test_plain_words_untouched(self):
        for line in ("gate_archive_age_recipient holds an age PRIVATE key (AGE-SECRET-KEY-…): remove it",
                     "never the AGE-SECRET-KEY private key", "Gate options: gate_archive encrypted (problem: private-key)"):
            with self.subTest(line=line[:30]):
                self.assertEqual(C.redact_text(line), line)


class SupervisorCredentialEnvTests(OptionsCase):
    def test_env_remove_lists_the_supervisor_credentials(self):
        self.assertIn("SUPERVISOR_TOKEN", C.ENV_REMOVE)
        self.assertIn("HASSIO_TOKEN", C.ENV_REMOVE)

    def test_openclaw_env_drops_them(self):
        with mock.patch.dict(os.environ, {"SUPERVISOR_TOKEN": "sup-secret-0123", "HASSIO_TOKEN": "hassio-secret-0123",
                                          "KEEP_ME": "1"}):
            env = C.openclaw_env()
            self.assertEqual(os.environ["SUPERVISOR_TOKEN"], "sup-secret-0123")  # the caller's env is untouched
        self.assertNotIn("SUPERVISOR_TOKEN", env)
        self.assertNotIn("HASSIO_TOKEN", env)
        self.assertEqual(env["KEEP_ME"], "1")
        self.assertNotIn("sup-secret-0123", json.dumps(env))
        self.assertNotIn("hassio-secret-0123", json.dumps(env))

    def test_openclaw_child_never_sees_them(self):
        """run_oc (OpenClaw CLI and doctor) runs with openclaw_env(): the child process has no Supervisor token."""
        bindir = self.tmp / "bin"
        bindir.mkdir()
        node = bindir / "node"
        node.write_text('#!/bin/sh\necho "sup=[${SUPERVISOR_TOKEN:-}] hassio=[${HASSIO_TOKEN:-}] keep=[${KEEP_ME:-}]"\n'
                        "env | grep -c -e '^SUPERVISOR_TOKEN=' -e '^HASSIO_TOKEN=' || true\n")
        node.chmod(0o755)
        pkg = self.tmp / "pkg"
        pkg.mkdir()
        (pkg / "openclaw.mjs").write_text("")
        (pkg / "package.json").write_text(json.dumps({"version": "2026.10.4",
                                                      "openclaw": {"schemaVersions": {"state": 19, "agent": 24}}}))
        (self.tmp / "entry").write_text(str(pkg / "openclaw.mjs"))
        log = self.tmp / "oc.log"
        with mock.patch.dict(os.environ, {"PATH": f"{bindir}:{os.environ['PATH']}",
                                          "OC_ADDON_ENTRY_FILE": str(self.tmp / "entry"),
                                          "SUPERVISOR_TOKEN": "sup-secret-0123", "HASSIO_TOKEN": "hassio-secret-0123",
                                          "KEEP_ME": "kept"}):
            res = C.run_oc(["--version"], timeout=30, log_path=log)
        self.assertEqual(res.rc, 0)
        text = log.read_text()
        self.assertIn("sup=[] hassio=[] keep=[kept]", text)
        self.assertEqual(text.strip().splitlines()[-1], "0")
        self.assertNotIn("secret-0123", text)


if __name__ == "__main__":
    unittest.main()
