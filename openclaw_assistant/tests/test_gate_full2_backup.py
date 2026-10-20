"""0.5.94-full2: the migration gate's Home Assistant backup check (precheck 10b) and its Supervisor client.
Since 0.5.94-full3 the gate writes no archive of its own: that backup is the only rollback point, and every
ha-backup-missing / ha-backup-unverified message says so (ROLLBACK_TAIL), whatever an earlier version's
gate_archive options left in options.json.

BackupEvalTests: pure tests of oc_gate.evaluate_ha_backups / backup_protected / backup_locations /
_parse_backup_date / backup_addon_version.
SupervisorClientTests: oc_common.supervisor_get / supervisor_token against a fake Supervisor on 127.0.0.1.
BackupCheckGateTests: full gate runs (test_gate.GateEnv) pointed at the fake Supervisor through the test hooks
supervisor_url / supervisor_token_file.

Owner rule: no plaintext secrets in archives or backups; HA backups only inside the HA backup system and
encrypted. The Supervisor token and the add-on options returned by /addons/self/info must never reach a log,
hold.txt, the journal or any file under the upgrade directory.
"""

import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
for _p in (str(ADDON), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_common as C  # noqa: E402
import oc_gate as G  # noqa: E402
import test_gate as T  # noqa: E402  (GateEnv: temp tree, fake node, fake doctor)

SLUG = "a0d7b954_openclaw_assistant"
RUNNING_VER = "0.5.94-full3"
PREV_VER = "0.5.93"
NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)
H = 3600
ROLLBACK_TAIL = "; the Home Assistant backup is the only rollback point"


def _short_secret(prefix):
    # Shorter than the 40-character redaction rule, so a leak would show up verbatim instead of as ***.
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def ok(data):
    return {"result": "ok", "data": data}


# --- fake Supervisor ------------------------------------------------------------------------------

class FakeSupervisor:
    """Minimal Supervisor API on 127.0.0.1 (ThreadingHTTPServer). Every request is recorded; it answers 400
    without `Host: supervisor`, 401 without `Authorization: Bearer <token>`, otherwise from `routes`
    {path: (status, body: dict | bytes, extra_headers)} and 404 for unknown paths."""

    def __init__(self, token):
        self.token = token
        self.routes = {}
        self.requests = []
        self._lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # keep the test output clean
                pass

            def _record(self, method):
                with fake._lock:
                    fake.requests.append({"method": method, "path": self.path, "host": self.headers.get("Host"),
                                          "auth": self.headers.get("Authorization")})

            def _send(self, status, body, headers=None):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._record("GET")
                if self.headers.get("Host") != "supervisor":
                    return self._send(400, {"result": "error", "message": "bad Host header"})
                if self.headers.get("Authorization") != f"Bearer {fake.token}":
                    return self._send(401, {"result": "error", "message": "Invalid token"})
                route = fake.routes.get(self.path)
                if route is None:
                    return self._send(404, {"result": "error", "message": "not found"})
                status, body, headers = route
                return self._send(status, body, headers)

            def do_POST(self):
                self._record("POST")
                return self._send(405, {"result": "error", "message": "read-only fake"})

            do_PUT = do_DELETE = do_POST

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def route(self, path, body, status=200, headers=None):
        self.routes[path] = (status, body, headers or {})

    def paths(self):
        with self._lock:
            return [r["path"] for r in self.requests]

    def clear(self):
        with self._lock:
            del self.requests[:]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(5)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- (a) pure evaluation ----------------------------------------------------------------------------

def bk(slug="b1", *, age_s=1 * H, now=NOW, date=None, btype="full", protected=True, addons=(SLUG,),
       key="addons", la="match", name=None):
    """A /backups/info entry. la: "match" -> {".local": {protected}}, None -> key absent, else used as given."""
    b = {"slug": slug, "name": name if name is not None else f"backup {slug}",
         "date": date if date is not None else (now - timedelta(seconds=age_s)).isoformat(),
         "type": btype, "protected": protected, "location": None, "locations": [None],
         "content": {"homeassistant": True, key: list(addons), "folders": []}}
    if la == "match":
        b["location_attributes"] = {".local": {"protected": protected, "size_bytes": 1000}}
    elif la is not None:
        b["location_attributes"] = la
    return b


def ev(backups, now=NOW, max_age_s=24 * H, **kw):
    return G.evaluate_ha_backups(backups, SLUG, now, max_age_s, **kw)


class BackupEvalTests(unittest.TestCase):
    # _parse_backup_date
    def test_parse_backup_date(self):
        p = G._parse_backup_date
        self.assertEqual(p("2026-10-18T10:00:00.123456+00:00"),
                         datetime(2026, 10, 18, 10, 0, 0, 123456, tzinfo=timezone.utc))
        self.assertEqual(p("2026-10-18T10:00:00Z"), datetime(2026, 10, 18, 10, tzinfo=timezone.utc))
        self.assertEqual(p(" 2026-10-18T10:00:00Z "), datetime(2026, 10, 18, 10, tzinfo=timezone.utc))
        naive = p("2026-10-18T10:00:00")
        self.assertEqual(naive, datetime(2026, 10, 18, 10, tzinfo=timezone.utc))  # naive = UTC
        self.assertIsNotNone(naive.tzinfo)
        off = p("2026-10-18T12:00:00+02:00")
        self.assertEqual(off, datetime(2026, 10, 18, 10, tzinfo=timezone.utc))  # same instant
        for bad in (None, "", "yesterday", "2026-13-01T00:00:00Z", 1760000000, ["2026-10-18"], {"d": 1}):
            self.assertIsNone(p(bad), bad)

    # backup_protected
    def test_protected_location_attributes_all_must_be_protected(self):
        self.assertTrue(G.backup_protected(bk(la={".local": {"protected": True}, "nas": {"protected": True}})))
        self.assertFalse(G.backup_protected(bk(la={".local": {"protected": True}, "nas": {"protected": False}})))
        # location_attributes wins over the top-level flag (which covers only the first location)
        self.assertFalse(G.backup_protected(bk(protected=True, la={".local": {"protected": False}})))
        self.assertTrue(G.backup_protected(bk(protected=False, la={".local": {"protected": True}})))

    def test_protected_empty_or_malformed_location_attributes_do_not_count(self):
        for la in ({}, [], [{"protected": True}], "protected", 1, {".local": True}, {".local": None},
                   {".local": {"protected": "true"}}, {".local": {"protected": 1}}, {".local": {}},
                   {".local": {"protected": True}, "nas": "yes"}):
            self.assertFalse(G.backup_protected(bk(protected=True, la=la)), la)

    def test_protected_without_location_attributes_uses_top_level_flag(self):
        self.assertTrue(G.backup_protected(bk(protected=True, la=None)))
        self.assertFalse(G.backup_protected(bk(protected=False, la=None)))
        self.assertFalse(G.backup_protected({"protected": "true"}))
        self.assertFalse(G.backup_protected({}))
        # an explicit JSON null counts as absent
        self.assertTrue(G.backup_protected({"protected": True, "location_attributes": None}))

    # backup_locations
    def test_backup_locations(self):
        self.assertEqual(G.backup_locations(bk(la={".local": {"protected": True}, "nas": {"protected": True}})),
                         ".local,nas")
        self.assertEqual(G.backup_locations({"location_attributes": {"": {}}}), ".local")
        self.assertEqual(G.backup_locations({"location": None}), ".local")
        self.assertEqual(G.backup_locations({"location": "nas"}), "nas")
        self.assertEqual(G.backup_locations({"locations": ["nas"]}), "nas")
        self.assertEqual(G.backup_locations({}), ".local")
        self.assertEqual(G.backup_locations({"location_attributes": {}, "location": "nas"}), "nas")

    # backup_addon_version
    def test_backup_addon_version(self):
        self.assertEqual(G.backup_addon_version({"addons": [{"slug": "core_x", "version": "1"},
                                                             {"slug": SLUG, "version": PREV_VER}]}, SLUG), PREV_VER)
        self.assertEqual(G.backup_addon_version({"apps": [{"slug": SLUG, "version": "0.5.92"}]}, SLUG), "0.5.92")
        self.assertIsNone(G.backup_addon_version({"addons": [{"slug": "other", "version": "1"}]}, SLUG))
        self.assertIsNone(G.backup_addon_version({}, SLUG))
        self.assertIsNone(G.backup_addon_version({"addons": None, "apps": None}, SLUG))
        self.assertIsNone(G.backup_addon_version({"addons": ["a0d7b954_openclaw_assistant", 3, None]}, SLUG))
        self.assertIsNone(G.backup_addon_version({"addons": [{"slug": SLUG}]}, SLUG))

    # evaluate_ha_backups
    def test_own_slug_present_or_absent(self):
        r = ev([bk("b1"), bk("b2", addons=("core_mosquitto",)), bk("b3", addons=())])
        self.assertEqual((r["total"], r["with_slug"]), (3, 1))
        self.assertEqual([e["slug"] for e in r["candidates"]], ["b1"])
        # exact match only: a slug from another repository prefix does not count
        r = ev([bk("b1", addons=("local_openclaw_assistant", "openclaw_assistant", SLUG + "_dev"))])
        self.assertEqual((r["with_slug"], r["candidates"]), (0, []))
        self.assertIsNone(r["newest_with_slug"])

    def test_content_apps_key(self):
        r = ev([bk("b1", key="apps")])
        self.assertEqual([e["slug"] for e in r["candidates"]], ["b1"])
        # an empty addons list falls back to apps
        b = bk("b2", key="apps")
        b["content"]["addons"] = []
        self.assertEqual([e["slug"] for e in ev([b])["candidates"]], ["b2"])
        # no content / malformed content
        for content in (None, [], "x", {}):
            b = bk("b3")
            b["content"] = content
            self.assertEqual(ev([b])["with_slug"], 0, content)

    def test_type_full_partial_other(self):
        r = ev([bk("f", btype="full", age_s=1 * H), bk("p", btype="partial", age_s=2 * H),
                bk("o", btype="other", age_s=0.5 * H), bk("n", btype=None, age_s=0.2 * H)])
        self.assertEqual([e["slug"] for e in r["candidates"]], ["f", "p"])
        self.assertEqual(r["with_slug"], 4)
        self.assertEqual(r["candidates"][1]["type"], "partial")

    def test_age_limit_and_future_skew(self):
        r = ev([bk("exact", age_s=24 * H), bk("over", age_s=24 * H + 1)])
        self.assertEqual([e["slug"] for e in r["candidates"]], ["exact"])
        r = ev([bk("skew-ok", age_s=-599), bk("skew-edge", age_s=-600), bk("future", age_s=-601),
                bk("far-future", age_s=-48 * H)])
        self.assertEqual(sorted(e["slug"] for e in r["candidates"]), ["skew-edge", "skew-ok"])
        self.assertEqual(r["with_slug"], 4)
        self.assertEqual(G.BACKUP_SKEW_S, 600)
        # an explicit skew
        r = ev([bk("future", age_s=-601)], skew_s=3600)
        self.assertEqual([e["slug"] for e in r["candidates"]], ["future"])
        r = ev([bk("s", age_s=-1)], skew_s=0)
        self.assertEqual(r["candidates"], [])

    def test_bad_dates_counted_and_skipped(self):
        r = ev([bk("good"), bk("bad1", date="not a date"), bk("bad2", date=""), bk("bad3", date="2026-02-30T00:00Z"),
                bk("bad4", date="garbage", protected=False), bk("other", date="garbage", addons=("x",))])
        self.assertEqual(r["bad_dates"], 4)
        self.assertEqual((r["total"], r["with_slug"]), (6, 5))
        self.assertEqual([e["slug"] for e in r["candidates"]], ["good"])
        self.assertEqual(r["unprotected"], [])  # a bad date is skipped before the protection check
        b = bk("nodate")
        del b["date"]
        self.assertEqual(ev([b])["bad_dates"], 1)

    def test_newest_first_ordering(self):
        r = ev([bk("mid", age_s=5 * H), bk("new", age_s=1 * H), bk("old", age_s=20 * H),
                bk("newest", age_s=60)])
        self.assertEqual([e["slug"] for e in r["candidates"]], ["newest", "new", "mid", "old"])
        self.assertTrue(all(isinstance(e["dt"], datetime) for e in r["candidates"]))

    def test_newest_with_slug(self):
        # the newest backup with this add-on, whatever its protection, type or age
        r = ev([bk("enc-old", age_s=30 * H), bk("plain-new", age_s=2 * H, protected=False),
                bk("foreign-newest", age_s=60, addons=("x",)), bk("bad", date="x")])
        self.assertEqual(r["newest_with_slug"]["slug"], "plain-new")
        self.assertFalse(r["newest_with_slug"]["protected"])
        self.assertEqual(r["candidates"], [])
        r = ev([bk("too-old", age_s=50 * H)])
        self.assertEqual(r["newest_with_slug"]["slug"], "too-old")
        self.assertTrue(r["newest_with_slug"]["protected"])
        r = ev([bk("o", btype="other", age_s=60), bk("f", age_s=2 * H)])
        self.assertEqual(r["newest_with_slug"]["slug"], "o")
        self.assertEqual([e["slug"] for e in r["candidates"]], ["f"])
        self.assertIsNone(ev([])["newest_with_slug"])

    def test_unprotected_counting(self):
        r = ev([bk("plain1", protected=False, age_s=1 * H),
                bk("plain-old", protected=False, age_s=100 * H),  # all ages
                bk("plain-other", protected=False, btype="other"),  # any type
                bk("mixed", la={".local": {"protected": True}, "nas": {"protected": False}}),
                bk("empty-la", la={}),
                bk("enc"),
                bk("plain-foreign", protected=False, addons=("x",))])
        self.assertEqual(sorted(e["slug"] for e in r["unprotected"]),
                         ["empty-la", "mixed", "plain-old", "plain-other", "plain1"])
        self.assertEqual([e["slug"] for e in r["candidates"]], ["enc"])
        self.assertTrue(all(e["protected"] is False for e in r["unprotected"]))
        mixed = next(e for e in r["unprotected"] if e["slug"] == "mixed")
        self.assertEqual(mixed["locations"], ".local,nas")

    def test_only_unprotected_has_no_candidates(self):
        r = ev([bk("p1", protected=False), bk("p2", protected=False, la=None)])
        self.assertEqual(r["candidates"], [])
        self.assertEqual(len(r["unprotected"]), 2)
        self.assertEqual(r["with_slug"], 2)

    def test_malformed_input(self):
        for backups in (None, {}, "x", 3, {"backups": []}):
            r = ev(backups)
            self.assertEqual((r["total"], r["with_slug"], r["candidates"]), (0, 0, []), backups)
        r = ev([None, "x", 3, [], bk("ok")])
        self.assertEqual((r["total"], r["with_slug"]), (1, 1))
        self.assertEqual([e["slug"] for e in r["candidates"]], ["ok"])

    def test_entry_fields_and_name_redaction(self):
        long_name = "N" * 30 + " " + "x" * 100
        r = ev([bk("b1", name=long_name, btype="partial", la={".local": {"protected": True},
                                                               "nas": {"protected": True}})])
        e = r["candidates"][0]
        self.assertEqual((e["slug"], e["type"], e["protected"], e["locations"]), ("b1", "partial", True, ".local,nas"))
        self.assertLessEqual(len(e["name"]), 80)
        self.assertEqual(e["date"], C.utc_iso(NOW - timedelta(hours=1)))
        r = ev([bk("b2", name=None)])
        self.assertEqual(r["candidates"][0]["name"], "backup b2")
        b = bk("b3")
        b["name"] = None
        self.assertEqual(ev([b])["candidates"][0]["name"], "")

    # Regression: an offset backup date is converted to UTC before it is reported (12:00+02:00 -> 10:00Z).
    def test_entry_date_is_utc_for_offset_dates(self):
        r = ev([bk("b1", date="2026-10-18T12:00:00+02:00")])
        self.assertEqual(r["candidates"][0]["date"], "2026-10-18T10:00:00Z")


# --- oc_common Supervisor client ------------------------------------------------------------------

class SupervisorClientTests(unittest.TestCase):
    def setUp(self):
        self.token = _short_secret("svtok")
        self.fake = FakeSupervisor(self.token)
        self.addCleanup(self.fake.close)
        self.tmp = Path(tempfile.mkdtemp(prefix="oc-sup-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.env = mock.patch.dict(os.environ, {})
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop("SUPERVISOR_TOKEN", None)

    def get(self, path, **kw):
        return C.supervisor_get(path, kw.pop("token", self.token), base=kw.pop("base", self.fake.url), **kw)

    def test_sends_host_supervisor_and_bearer_token(self):
        self.fake.route("/addons/self/info", ok({"slug": SLUG, "version": RUNNING_VER}))
        self.assertEqual(self.get("/addons/self/info"), {"slug": SLUG, "version": RUNNING_VER})
        self.assertEqual(len(self.fake.requests), 1)
        r = self.fake.requests[0]
        self.assertEqual((r["method"], r["path"], r["host"], r["auth"]),
                         ("GET", "/addons/self/info", "supervisor", f"Bearer {self.token}"))

    def test_base_url_forms(self):
        self.fake.route("/backups/info", ok({"backups": []}))
        self.assertEqual(C.supervisor_get("/backups/info", self.token, base=self.fake.url + "/"), {"backups": []})
        for bad in ("https://127.0.0.1:1", "http://127.0.0.1:1/api", "ftp://x", "127.0.0.1:1", "http://",
                    "http://[::1]:1", "http://127.0.0.1:port"):
            with self.assertRaises(C.SupervisorError, msg=bad) as cm:
                C.supervisor_get("/backups/info", self.token, base=bad)
            self.assertEqual(cm.exception.status, 0)
            self.assertIn("invalid Supervisor base URL", cm.exception.message)

    def test_default_address_is_the_fixed_supervisor_ip(self):
        """No name resolution of 'supervisor' (a host_network resolver could answer it): 172.30.32.2:80."""
        seen = []

        class Conn:
            def __init__(self, host, port=None, timeout=None):
                seen.append((host, port, timeout))

            def request(self, *a, **kw):
                raise ConnectionRefusedError("refused")

            def close(self):
                pass

        with mock.patch("http.client.HTTPConnection", Conn), \
                mock.patch("socket.getaddrinfo", side_effect=AssertionError("no DNS lookup expected")):
            with self.assertRaises(C.SupervisorError) as cm:
                C.supervisor_get("/backups/info", self.token, timeout=3)
        self.assertEqual(seen, [("172.30.32.2", 80, 3)])
        self.assertEqual(C.SUPERVISOR_ADDR, ("172.30.32.2", 80))
        self.assertEqual(cm.exception.status, 0)
        self.assertNotIn(self.token, str(cm.exception))

    def test_does_not_follow_redirects(self):
        self.fake.route("/backups/info", {}, status=302, headers={"Location": f"{self.fake.url}/elsewhere"})
        self.fake.route("/elsewhere", ok({"backups": []}))
        with self.assertRaises(C.SupervisorError) as cm:
            self.get("/backups/info")
        self.assertEqual(cm.exception.status, 302)
        self.assertEqual(self.fake.paths(), ["/backups/info"])

    def test_ignores_proxy_environment(self):
        self.fake.route("/backups/info", ok({"backups": [1]}))
        dead = f"http://127.0.0.1:{free_port()}"
        with mock.patch.dict(os.environ, {"HTTP_PROXY": dead, "http_proxy": dead, "HTTPS_PROXY": dead,
                                          "https_proxy": dead, "ALL_PROXY": dead, "all_proxy": dead,
                                          "NO_PROXY": "", "no_proxy": ""}):
            self.assertEqual(self.get("/backups/info"), {"backups": [1]})
        self.assertEqual(self.fake.paths(), ["/backups/info"])

    def test_non_2xx_raises_with_status_and_no_body(self):
        for status in (401, 403, 404, 500, 502):
            self.fake.route("/backups/info", {"result": "error", "message": "BODY-MARKER " + self.token},
                            status=status)
            with self.assertRaises(C.SupervisorError) as cm:
                self.get("/backups/info")
            self.assertEqual(cm.exception.status, status)
            self.assertEqual(cm.exception.message, f"HTTP {status}")
            self.assertNotIn("BODY-MARKER", str(cm.exception))
            self.assertNotIn(self.token, str(cm.exception))
        self.fake.route("/backups/info", ok({}), status=201)
        with self.assertRaises(C.SupervisorError) as cm:
            self.get("/backups/info")
        self.assertEqual(cm.exception.status, 201)

    def test_wrong_token_is_401(self):
        self.fake.route("/backups/info", ok({"backups": []}))
        with self.assertRaises(C.SupervisorError) as cm:
            self.get("/backups/info", token="not-the-token")
        self.assertEqual(cm.exception.status, 401)

    def test_max_bytes(self):
        def body_of(n):
            base = json.dumps(ok({"pad": ""})).encode()
            return json.dumps(ok({"pad": "x" * (n - len(base))})).encode()
        exact = body_of(1000)
        self.assertEqual(len(exact), 1000)
        self.fake.route("/exact", exact)
        self.assertEqual(len(self.get("/exact", max_bytes=1000)["pad"]), 1000 - len(json.dumps(ok({"pad": ""}))))
        self.fake.route("/big", body_of(1001))
        with self.assertRaises(C.SupervisorError) as cm:
            self.get("/big", max_bytes=1000)
        self.assertEqual((cm.exception.status, cm.exception.message), (0, "response too large"))
        self.fake.route("/huge", body_of(200_000))
        with self.assertRaises(C.SupervisorError) as cm:
            self.get("/huge", max_bytes=1000)
        self.assertEqual(cm.exception.message, "response too large")

    def test_invalid_and_unexpected_responses(self):
        cases = {"/trunc": (b'{"result": "ok", "data": {"backups": [', "invalid JSON response"),
                 "/html": (b"<html>hi</html>", "invalid JSON response"),
                 "/nan": (b'{"result": "ok", "data": {"x": NaN', "invalid JSON response"),
                 "/error": ({"result": "error", "message": "nope"}, "unexpected response"),
                 "/nodata": ({"result": "ok"}, "unexpected response"),
                 "/listdata": ({"result": "ok", "data": []}, "unexpected response"),
                 "/list": (b"[1, 2]", "unexpected response")}
        for path, (body, msg) in cases.items():
            self.fake.route(path, body)
            with self.assertRaises(C.SupervisorError, msg=path) as cm:
                self.get(path)
            self.assertEqual((cm.exception.status, cm.exception.message), (0, msg), path)

    def test_connection_refused_and_timeout(self):
        with self.assertRaises(C.SupervisorError) as cm:
            C.supervisor_get("/backups/info", self.token, base=f"http://127.0.0.1:{free_port()}", timeout=2)
        self.assertEqual(cm.exception.status, 0)
        self.assertIn("ConnectionRefusedError", cm.exception.message)
        # a listener that never answers
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)
        with self.assertRaises(C.SupervisorError) as cm:
            C.supervisor_get("/backups/info", self.token, base=f"http://127.0.0.1:{srv.getsockname()[1]}",
                             timeout=0.5)
        self.assertEqual(cm.exception.status, 0)
        self.assertNotIn(self.token, cm.exception.message)

    # supervisor_token
    def test_token_from_file_first(self):
        f = self.tmp / "SUPERVISOR_TOKEN"
        f.write_text(self.token + "\n")
        os.environ["SUPERVISOR_TOKEN"] = "env-token"
        self.assertEqual(C.supervisor_token(str(f)), self.token)
        with mock.patch.object(C, "S6_TOKEN_FILE", str(f)):
            self.assertEqual(C.supervisor_token(), self.token)  # the s6 container environment by default

    def test_token_env_fallback(self):
        missing = str(self.tmp / "missing")
        self.assertIsNone(C.supervisor_token(missing))
        os.environ["SUPERVISOR_TOKEN"] = "  env-token \n"
        self.assertEqual(C.supervisor_token(missing), "env-token")
        empty = self.tmp / "empty"
        empty.write_text("\n")
        self.assertEqual(C.supervisor_token(str(empty)), "env-token")
        spaced = self.tmp / "spaced"
        spaced.write_text("two words\n")
        self.assertEqual(C.supervisor_token(str(spaced)), "env-token")  # a value with whitespace is rejected
        os.environ["SUPERVISOR_TOKEN"] = "   "
        self.assertIsNone(C.supervisor_token(str(spaced)))
        self.assertIsNone(C.supervisor_token(str(self.tmp)))  # a directory is not a token file
        with mock.patch.object(C, "S6_TOKEN_FILE", missing):
            os.environ.pop("SUPERVISOR_TOKEN")
            self.assertIsNone(C.supervisor_token())


# --- (b) gate runs against the fake Supervisor -----------------------------------------------------

class BackupCheckGateTests(T.GateEnv):
    def setUp(self):
        super().setUp()
        self.token = _short_secret("svtok")
        self.opt_secret = _short_secret("optsecret")
        self.fake = FakeSupervisor(self.token)
        self.addCleanup(self.fake.close)
        (self.tmp / "s6").mkdir()
        self.token_file = self.tmp / "s6" / "SUPERVISOR_TOKEN"
        self.token_file.write_text(self.token + "\n")
        os.environ.pop("SUPERVISOR_TOKEN", None)
        os.environ.pop("HASSIO_TOKEN", None)
        self.transcript = []
        # The openclaw-running precheck matches any */openclaw.mjs process on the machine, which includes the fake
        # node of test suites running in parallel; only processes of this test's own tree count here.
        real_find = G.find_openclaw_processes
        mine = str(self.tmp)
        patcher = mock.patch.object(G, "find_openclaw_processes",
                                    lambda *a, **kw: [p for p in real_find(*a, **kw) if mine in p["cmd"]])
        patcher.start()
        self.addCleanup(patcher.stop)
        # /addons/self/info carries the add-on's options in clear: never logged or persisted
        self.fake.route("/addons/self/info", ok({"slug": SLUG, "version": RUNNING_VER, "hassio_api": True,
                                                 "hassio_role": "default",
                                                 "options": {"homeassistant_token": self.opt_secret}}))
        self.set_backups([])
        self.sup_hooks()

    # helpers
    def sup_hooks(self, **kw):
        base = {"skip_backup_check": False, "supervisor_url": self.fake.url,
                "supervisor_token_file": str(self.token_file)}
        base.update(kw)
        self.hooks(**base)

    def backup(self, bslug, name, hours_ago, *, protected=True, btype="full", addons=(SLUG,), locations=None):
        dt = C.utc_now() - timedelta(hours=hours_ago)
        locs = locations or [".local"]
        return {"slug": bslug, "name": name, "date": dt.isoformat(), "type": btype, "size": 1.0,
                "location": None, "locations": [None if x == ".local" else x for x in locs], "protected": protected,
                "compressed": True,
                "location_attributes": {x: {"protected": protected, "size_bytes": 1234} for x in locs},
                "content": {"homeassistant": True, "addons": list(addons), "folders": ["share"]}}

    def set_backups(self, backups, versions=None):
        self.fake.route("/backups/info", ok({"backups": backups, "days_until_stale": 30}))
        for b in backups:
            ver = (versions or {}).get(b["slug"], PREV_VER)
            self.fake.route(f"/backups/{b['slug']}/info", ok({
                "slug": b["slug"], "type": b["type"], "name": b["name"], "date": b["date"], "protected": b["protected"],
                "addons": [{"slug": a, "name": a, "version": ver if a == SLUG else "1.0", "size": 1.0}
                           for a in b["content"]["addons"]], "repositories": [], "folders": ["share"]}))

    def run_gate(self):
        rc = super().run_gate()
        self.transcript.append(self.out + self.err)
        return rc

    def retry(self, *args):
        lines = []
        rc = G.retry_cmd(list(args), emit=lines.append)
        self.transcript.append("\n".join(lines))
        return rc

    def hold(self):
        return self.journal()["hold"]

    def assert_hold(self, code):
        j = self.journal()
        self.assertEqual((j["status"], j["hold"]["code"], j["phase"]), ("hold", code, "precheck"), self.out)
        self.assertTrue(j["hold"]["acceptable"])
        self.assertIsNone(j.get("first_write_at"))
        self.assertNotIn("ha_backup", j)
        msg = j["hold"]["message"]
        self.assertTrue(msg.endswith(ROLLBACK_TAIL), msg)
        self.assertEqual(msg.count(ROLLBACK_TAIL), 1, msg)
        self.assertNotIn("gate_archive", msg)
        txt = (self.upg / "hold.txt").read_text()
        self.assertIn(f"Reason [{code}]:", txt)
        self.assertIn(f"{ROLLBACK_TAIL}\n", txt)
        self.assertIn(f"oc-upgrade retry --accept {code}", txt)
        self.assertIn("State: unchanged (nothing written yet)", txt)
        self.assertIn(f"[gate] HOLD {code} in precheck:", self.out)
        return j["hold"]["message"]

    def assert_no_secrets(self):
        secrets = (self.token, self.opt_secret)
        for text in self.transcript:
            for s in secrets:
                self.assertNotIn(s, text)
        n = 0
        for root in (self.root, self.share):
            for dirpath, _dirs, files in os.walk(root):
                for fn in files:
                    p = Path(dirpath) / fn
                    if p.is_symlink() or not p.is_file():
                        continue
                    data = p.read_bytes()
                    n += 1
                    for s in secrets:
                        self.assertNotIn(s.encode(), data, str(p))
        self.assertGreater(n, 0)

    def assert_requests_authenticated(self):
        self.assertTrue(self.fake.requests)
        for r in self.fake.requests:
            self.assertEqual((r["method"], r["host"], r["auth"]), ("GET", "supervisor", f"Bearer {self.token}"), r)

    # tests
    def test_recent_encrypted_backup_passes_and_is_journaled(self):
        self.build_735()
        self.set_backups([self.backup("old1", "Nightly", 10), self.backup("pre1", "Before update", 1),
                          self.backup("foreign", "Other", 0.5, addons=("core_mosquitto",))])
        rc = self.run_gate()
        self.assertEqual(rc, 0, self.out)
        self.assertIn("HA backup ok ('Before update', ", self.out)
        self.assertIn(f"encrypted, add-on {PREV_VER})", self.out)
        self.assertIn("[gate] done: MIGRATED", self.out)
        j = self.journal()
        self.assertEqual(j["status"], "done")
        hb = j["ha_backup"]
        self.assertEqual((hb["slug"], hb["name"], hb["type"], hb["locations"], hb["addon_version"]),
                         ("pre1", "Before update", "full", ".local", PREV_VER))
        self.assertRegex(hb["date"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertRegex(hb["checked_at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(self.fake.paths(), ["/addons/self/info", "/backups/info", "/backups/pre1/info"])
        self.assert_requests_authenticated()
        self.assert_no_secrets()

    def test_partial_backup_on_two_encrypted_locations_counts(self):
        self.build_735()
        self.set_backups([self.backup("part", "Partial", 2, btype="partial", locations=[".local", "nas"])])
        self.assertEqual(self.run_gate(), 0, self.out)
        hb = self.journal()["ha_backup"]
        self.assertEqual((hb["type"], hb["locations"]), ("partial", ".local,nas"))

    def test_no_backups_holds_missing(self):
        self.build_735()
        before = (self.state / "openclaw.json").read_bytes()
        self.assertEqual(self.run_gate(), 20, self.out)
        msg = self.assert_hold("ha-backup-missing")
        self.assertIn(f"no encrypted Home Assistant backup containing this add-on ({SLUG}) from the last 24 h", msg)
        self.assertIn("0 listed, 0 with this add-on; newest with it: none", msg)
        self.assertEqual((self.state / "openclaw.json").read_bytes(), before)
        self.assertFalse((self.share / "openclaw-upgrade").exists())
        self.assertEqual(self.fake.paths(), ["/addons/self/info", "/backups/info"])
        self.assert_requests_authenticated()
        self.assert_no_secrets()

    def test_backups_without_this_addon_hold_missing(self):
        self.build_735()
        self.set_backups([self.backup("f1", "HA only", 1, addons=("core_mosquitto",)),
                          self.backup("f2", "HA only 2", 2, addons=())])
        self.assertEqual(self.run_gate(), 20, self.out)
        msg = self.assert_hold("ha-backup-missing")
        self.assertIn("2 listed, 0 with this add-on; newest with it: none", msg)

    def test_only_unprotected_backups_hold_missing_and_warn(self):
        self.build_735()
        self.set_backups([self.backup("plain1", "Daily plain", 1, protected=False),
                          self.backup("plain2", "Weekly plain", 30, protected=False, locations=[".local", "nas"])])
        self.assertEqual(self.run_gate(), 20, self.out)
        msg = self.assert_hold("ha-backup-missing")
        self.assertIn("2 listed, 2 with this add-on", msg)
        self.assertIn("'Daily plain'", msg)
        self.assertIn("NOT encrypted in .local", msg)
        warns = [ln for ln in self.out.splitlines() if ln.startswith("WARN [gate] Home Assistant backup ")]
        self.assertEqual(len(warns), 2, self.out)
        self.assertIn("'Daily plain' (plain1, ", warns[0] + warns[1])
        self.assertTrue(all("UNENCRYPTED in" in w and "plaintext" in w for w in warns), warns)
        self.assertIn("UNENCRYPTED in .local,nas", self.out)
        # the WARNs also reach the run's events.log
        rd = self.upg / "gate" / "runs" / self.journal()["run_id"]
        self.assertIn("UNENCRYPTED in", (rd / "events.log").read_text())
        # never asks for the version of an unencrypted backup
        self.assertEqual(self.fake.paths(), ["/addons/self/info", "/backups/info"])
        self.assert_no_secrets()

    def test_backup_with_one_unprotected_location_does_not_count(self):
        self.build_735()
        b = self.backup("mixed", "Mixed", 1, locations=[".local", "nas"])
        b["location_attributes"]["nas"]["protected"] = False  # top-level protected stays True
        self.set_backups([b])
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assert_hold("ha-backup-missing")
        self.assertIn("'Mixed' (mixed, ", self.out)
        self.assertIn("UNENCRYPTED in .local,nas", self.out)

    def test_too_old_backup_holds_then_a_larger_max_age_passes(self):
        self.build_735()
        self.set_backups([self.backup("old", "Last week", 30)])
        self.assertEqual(self.run_gate(), 20, self.out)
        msg = self.assert_hold("ha-backup-missing")
        self.assertIn("from the last 24 h", msg)
        self.assertIn("1 listed, 1 with this add-on; newest with it: 'Last week' 30h", msg)
        self.assertIn("old, encrypted)", msg)
        self.options(gate_backup_max_age_hours=48)
        self.assertEqual(self.retry(), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("HA backup ok ('Last week', 30h", self.out)
        self.assertEqual(self.journal()["ha_backup"]["slug"], "old")
        self.assert_no_secrets()

    def test_same_version_backup_holds_for_from7x(self):
        """A backup taken after the update holds the new add-on: restoring it does not bring the old OpenClaw."""
        self.build_735()
        self.set_backups([self.backup("same", "After update", 1)], versions={"same": RUNNING_VER})
        self.assertEqual(self.run_gate(), 20, self.out)
        msg = self.assert_hold("ha-backup-missing")
        self.assertIn(f"hold this add-on version ({RUNNING_VER})", msg)
        self.assertIn("/backups/same/info", self.fake.paths())
        self.assertEqual(self.journal()["mode"], "from-7x")
        self.assert_requests_authenticated()

    def test_older_backup_with_previous_version_wins_over_newer_same_version(self):
        self.build_735()
        self.set_backups([self.backup("same", "After update", 1), self.backup("prev", "Before update", 5)],
                         versions={"same": RUNNING_VER, "prev": PREV_VER})
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("HA backup ok ('Before update', ", self.out)
        hb = self.journal()["ha_backup"]
        self.assertEqual((hb["slug"], hb["addon_version"]), ("prev", PREV_VER))
        self.assertEqual(self.fake.paths(), ["/addons/self/info", "/backups/info", "/backups/same/info",
                                             "/backups/prev/info"])

    def test_previous_version_backup_behind_many_newer_same_version_backups_is_found(self):
        """Scheduled backups taken while the gate holds (new add-on version) must not hide the pre-update backup."""
        self.build_735()
        newer = [self.backup(f"same{i}", f"Auto {i}", 0.5 + i * 0.25) for i in range(6)]
        self.set_backups(newer + [self.backup("prev", "Before update", 5)],
                         versions={**{f"same{i}": RUNNING_VER for i in range(6)}, "prev": PREV_VER})
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("HA backup ok ('Before update', ", self.out)
        self.assertEqual(self.journal()["ha_backup"]["slug"], "prev")
        self.assertEqual([p for p in self.fake.paths() if p.endswith("/info") and p.startswith("/backups/")
                          and p != "/backups/info"], [f"/backups/same{i}/info" for i in range(6)] + ["/backups/prev/info"])

    def test_backup_info_with_apps_key_is_read(self):
        self.build_735()
        b = self.backup("v2", "V2 names", 1)
        b["content"] = {"homeassistant": True, "apps": [SLUG], "folders": []}
        self.fake.route("/backups/info", ok({"backups": [b]}))
        self.fake.route("/backups/v2/info", ok({"slug": "v2", "apps": [{"slug": SLUG, "version": RUNNING_VER}]}))
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertIn(f"hold this add-on version ({RUNNING_VER})", self.assert_hold("ha-backup-missing"))

    def test_bump_run_needs_a_different_version_too(self):
        T.make_99_state(self.state)
        self.write_cfg({"meta": {"lastTouchedVersion": T.RUNTIME}, "gateway": {"mode": "local"}})
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.5", "mode": "from-7x"}))
        self.set_backups([self.backup("same", "After update", 1)], versions={"same": RUNNING_VER})
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertEqual(self.journal()["mode"], "bump")
        self.assert_hold("ha-backup-missing")
        self.set_backups([self.backup("prev", "Before update", 2)])
        self.assertEqual(self.retry(), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual(self.journal()["ha_backup"]["slug"], "prev")

    def test_maintenance_run_accepts_a_same_version_backup(self):
        self.build_735()
        self.set_backups([self.backup("prev", "Before update", 2)])
        self.assertEqual(self.run_gate(), 0, self.out)
        self.set_backups([self.backup("same", "After update", 0.5)], versions={"same": RUNNING_VER})
        self.assertEqual(self.retry("--doctor"), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertEqual(j["mode"], "maintenance")
        self.assertEqual(j["ha_backup"]["slug"], "same")
        self.assertIn(f"add-on {RUNNING_VER})", self.out)

    def test_forbidden_is_unverified(self):
        self.build_735()
        self.fake.route("/backups/info", {"result": "error", "message": "Forbidden"}, status=403)
        self.assertEqual(self.run_gate(), 20, self.out)
        msg = self.assert_hold("ha-backup-unverified")
        self.assertIn("the Supervisor backup list could not be read: HTTP 403", msg)
        self.assertIn("hassio_api", msg)
        self.assert_no_secrets()

    def test_wrong_token_is_unverified(self):
        self.build_735()
        self.token_file.write_text("some-other-token\n")
        self.assertEqual(self.run_gate(), 20, self.out)
        msg = self.assert_hold("ha-backup-unverified")
        self.assertIn("HTTP 401", msg)
        self.assertEqual(self.fake.paths(), ["/addons/self/info"])

    def test_no_token_is_unverified(self):
        self.build_735()
        self.sup_hooks(supervisor_token_file=str(self.tmp / "s6" / "missing"))
        self.assertNotIn("SUPERVISOR_TOKEN", os.environ)
        self.assertEqual(self.run_gate(), 20, self.out)
        msg = self.assert_hold("ha-backup-unverified")
        self.assertIn("no Supervisor token", msg)
        self.assertEqual(self.fake.requests, [])

    def test_env_token_is_the_fallback(self):
        self.build_735()
        self.sup_hooks(supervisor_token_file=str(self.tmp / "s6" / "missing"))
        os.environ["SUPERVISOR_TOKEN"] = self.token
        self.set_backups([self.backup("pre1", "Before update", 1)])
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual(self.journal()["ha_backup"]["slug"], "pre1")
        self.assert_requests_authenticated()
        self.assert_no_secrets()

    def test_unreachable_supervisor_is_unverified(self):
        self.build_735()
        self.sup_hooks(supervisor_url=f"http://127.0.0.1:{free_port()}")
        self.assertEqual(self.run_gate(), 20, self.out)
        msg = self.assert_hold("ha-backup-unverified")
        self.assertIn("ConnectionRefusedError", msg)

    def test_malformed_json_and_unexpected_response_are_unverified(self):
        self.build_735()
        self.fake.route("/backups/info", b'{"result": "ok", "data": {"backups": [')
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertIn("invalid JSON response", self.assert_hold("ha-backup-unverified"))
        self.fake.route("/backups/info", {"result": "error", "message": "x"})
        self.assertEqual(self.retry(), 0)
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertIn("unexpected response", self.assert_hold("ha-backup-unverified"))
        self.fake.route("/addons/self/info", b"\x00\xff not json")
        self.assertEqual(self.retry(), 0)
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertIn("invalid JSON response", self.assert_hold("ha-backup-unverified"))
        self.assert_no_secrets()

    def test_accept_missing_lets_the_gate_continue(self):
        self.build_735()
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assert_hold("ha-backup-missing")
        self.assertEqual(self.retry("--accept", "ha-backup-missing"), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("WARN [gate] accepted ha-backup-missing:", self.out)
        accepted = [x for x in self.out.splitlines() if x.startswith("WARN [gate] accepted ha-backup-missing:")]
        self.assertTrue(accepted and all(x.endswith(ROLLBACK_TAIL) for x in accepted), self.out)
        self.assertIn("HA backup MISSING", self.out)
        j = self.journal()
        self.assertEqual(j["status"], "done")
        self.assertNotIn("ha_backup", j)
        self.assertFalse((self.upg / "hold.txt").exists())
        self.assert_no_secrets()

    def test_accept_unverified_lets_the_gate_continue(self):
        self.build_735()
        self.fake.route("/backups/info", {"result": "error"}, status=403)
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertEqual(self.retry("--accept", "ha-backup-unverified"), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("WARN [gate] accepted ha-backup-unverified:", self.out)
        accepted = [x for x in self.out.splitlines() if x.startswith("WARN [gate] accepted ha-backup-unverified:")]
        self.assertTrue(accepted and all(x.endswith(ROLLBACK_TAIL) for x in accepted), self.out)
        self.assertIn("HA backup UNVERIFIED", self.out)

    def test_hold_clears_after_a_backup_is_made_and_retried(self):
        self.build_735()
        self.assertEqual(self.run_gate(), 20, self.out)
        self.set_backups([self.backup("pre1", "Made during the HOLD", 0.1)])
        self.assertEqual(self.retry(), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual(self.journal()["ha_backup"]["slug"], "pre1")

    def interrupted_after_the_first_write(self):
        self.build_735()
        self.set_backups([self.backup("pre1", "Before update", 1)])
        self.sup_hooks(raise_in_phase="fixups")
        self.assertEqual(self.run_gate(), 1, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["phase"]), ("internal-error", "fixups"))
        self.assertTrue(j.get("first_write_at"))
        self.assertEqual(j["ha_backup"]["slug"], "pre1")

    def test_resume_after_the_first_write_rechecks_only_the_recorded_backup(self):
        self.interrupted_after_the_first_write()
        # the backup list is refused and the backup is older than gate_backup_max_age_hours by now: the resume
        # asks only for the recorded backup
        self.fake.clear()
        self.set_backups([self.backup("pre1", "Before update", 30)])
        self.fake.route("/backups/info", {"result": "error"}, status=500)
        self.sup_hooks()
        self.assertEqual(self.retry(), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("HA backup still there ('Before update' (pre1), encrypted)", self.out)
        self.assertEqual([r["path"] for r in self.fake.requests], ["/backups/pre1/info"])
        self.assertEqual(self.journal()["ha_backup"]["slug"], "pre1")  # the record of the first attempt stays
        self.assert_no_secrets()

    def test_resume_holds_when_the_recorded_backup_is_gone(self):
        self.interrupted_after_the_first_write()
        self.set_backups([])  # deleted between the interruption and the retry
        self.fake.routes.pop("/backups/pre1/info")
        self.sup_hooks()
        self.assertEqual(self.retry(), 0)
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["hold"]["phase"], j["hold"]["acceptable"]),
                         ("ha-backup-missing", "precheck", True))
        self.assertIn("'Before update' (pre1) this run relies on no longer exists", j["hold"]["message"])
        self.assertTrue(j["hold"]["message"].endswith(ROLLBACK_TAIL))
        self.assertIn("partially migrated", (self.upg / "hold.txt").read_text())
        self.assertEqual(j["phases_done"].count("doctor1"), 1)  # nothing re-ran before the HOLD
        # accepting it continues the migration
        self.assertEqual(self.retry("--accept", "ha-backup-missing"), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual(self.journal()["status"], "done")
        self.assert_no_secrets()

    def test_resume_holds_when_the_recorded_backup_cannot_be_rechecked(self):
        self.interrupted_after_the_first_write()
        self.fake.route("/backups/pre1/info", {"result": "error"}, status=500)
        self.sup_hooks()
        self.assertEqual(self.retry(), 0)
        self.assertEqual(self.run_gate(), 20, self.out)
        h = self.journal()["hold"]
        self.assertEqual((h["code"], h["acceptable"]), ("ha-backup-unverified", True))
        self.assertIn("could not be re-checked: HTTP 500", h["message"])

    def test_dry_run_previews_the_check(self):
        self.build_735()
        lines = []
        self.assertEqual(G.dry_run(emit=lines.append), 20)
        out = "\n".join(lines)
        self.assertIn("ha-backup-missing", out)
        self.assertIn("would HOLD", out)
        preview = [x for x in lines if "ha-backup-missing: " in x]
        self.assertTrue(preview and all(x.endswith(ROLLBACK_TAIL) for x in preview), out)
        self.assertIn("[gate]   rollback point: the encrypted Home Assistant backup (no archive of the gate's own)",
                      lines)
        self.assertFalse((self.upg / "gate" / "journal.json").exists())
        self.set_backups([self.backup("pre1", "Before update", 1)])
        lines = []
        self.assertEqual(G.dry_run(emit=lines.append), 0, "\n".join(lines))
        self.assertIn("HA backup ok ('Before update'", "\n".join(lines))
        self.transcript.append("\n".join(lines))
        self.assertFalse((self.upg / "gate" / "journal.json").exists())
        self.assert_no_secrets()

    def test_secrets_from_supervisor_never_persisted(self):
        """The token and the /addons/self/info options appear nowhere: stdout, stderr, hold.txt, journal, runs/."""
        self.build_735()
        self.set_backups([self.backup("plain", "Daily plain", 1, protected=False)])
        self.assertEqual(self.run_gate(), 20, self.out)
        self.fake.route("/backups/info", {"result": "error", "message": self.token}, status=500)
        self.assertEqual(self.retry(), 0)
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertIn("HTTP 500", self.assert_hold("ha-backup-unverified"))
        self.set_backups([self.backup("pre1", "Before update", 1)])
        self.assertEqual(self.retry(), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        for name in ("journal.json", "migrated.json"):
            self.assertNotIn(self.token, (self.upg / "gate" / name).read_text())
        self.assert_no_secrets()

    # Regression (0.5.94-full3): the gate's own archive is gone, so a missing or unverified backup is always
    # reported as the only rollback point, also when options.json still holds an earlier version's gate_archive
    # options (gate_archive: off used to add its own tail; a missing recipient used to HOLD archive-key-missing).
    def test_backup_holds_name_the_only_rollback_point_whatever_stale_archive_options_say(self):
        self.build_735()
        stale = [{"gate_archive": "off"}, {"gate_archive": "encrypted", "gate_archive_age_recipient": ""},
                 {"gate_archive": "encrypted", "gate_archive_age_recipient": "age1" + "q" * 58}]
        for i, opts in enumerate(stale):
            with self.subTest(sorted(opts)):
                self.base_options = opts
                self.options()
                if i:
                    self.assertEqual(self.retry(), 0)
                self.assertEqual(self.run_gate(), 20, self.out)
                msg = self.assert_hold("ha-backup-missing")
                self.assertTrue(msg.startswith("no encrypted Home Assistant backup containing this add-on"), msg)
                self.assertEqual(self.hold()["codes"], ["ha-backup-missing"])
                self.assertNotIn("archive-key", self.out)
                self.assertNotIn("archive-off", self.out)
                self.assertNotIn("no other rollback point", self.out)
                self.assertNotIn("gate_archive", self.out + (self.upg / "hold.txt").read_text())
        # the unverified messages carry the same tail
        self.fake.route("/backups/info", {"result": "error", "message": "Forbidden"}, status=403)
        self.assertEqual(self.retry(), 0)
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertIn("HTTP 403", self.assert_hold("ha-backup-unverified"))
        self.assertTrue(self.hold()["message"].endswith(" /backups/info)" + ROLLBACK_TAIL), self.hold()["message"])
        self.assert_no_secrets()

    # Regression: for from-7x/bump runs an unreadable add-on version in the backup is not "older": the check
    # HOLDs ha-backup-unverified instead of reporting "HA backup ok" (fail-closed).
    def test_version_lookup_error_is_not_ok(self):
        self.build_735()
        self.set_backups([self.backup("pre1", "Maybe after update", 1)])
        self.fake.route("/backups/pre1/info", {"result": "error"}, status=500)
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assert_hold("ha-backup-unverified")


if __name__ == "__main__":
    unittest.main()
