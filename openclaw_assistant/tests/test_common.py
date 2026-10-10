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
        tok = "98CQRdpOS9aIqH9zUd6Q0jBQEYcz5bTw"
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


if __name__ == "__main__":
    unittest.main()
