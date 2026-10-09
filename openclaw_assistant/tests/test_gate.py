"""Unit and integration tests for oc_gate (stdlib unittest, Python 3.11).

Everything runs in a temporary tree (OPENCLAW_STATE_DIR, OC_UPGRADE_DIR, OC_UPGRADE_SHARE_DIR,
OC_CONFIG_ROOT, OC_ADDON_ENTRY_FILE) with a fake `node` (fake OpenClaw CLI) and a fake doctor
passed through the OC_GATE_TEST_HOOKS doctor_cmd hook. The real oc_migrate is used.
"""

import io
import json
import os
import shutil
import socket
import sqlite3
import stat
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ADDON = Path(__file__).resolve().parent.parent
if str(ADDON) not in sys.path:
    sys.path.insert(0, str(ADDON))

import oc_common as C  # noqa: E402
import oc_gate as G  # noqa: E402

_REAL_WHICH = shutil.which


def which_without_npm(name, *a, **kw):
    return None if name == "npm" else _REAL_WHICH(name, *a, **kw)

RUNTIME = "2026.9.9"

FAKE_NODE = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
if args[:1] == ["--input-type=module"]:
    if os.environ.get("OCQ_SQL"):
        sys.stderr.write("fake node: no node:sqlite\n")
        sys.exit(1)
    print("24.16.0 3.50.4")
    sys.exit(0)
cmd = args[1:]
mode = os.environ.get("FAKE_OC_MODE", "")
def out(o, rc=0):
    sys.stdout.write(json.dumps(o) + "\n")
    sys.exit(rc)
if cmd[:2] == ["config", "validate"]:
    if "invalid-config" in mode:
        out({"valid": False, "issues": [{"message": "bogus key"}]}, 1)
    out({"valid": True, "path": "x", "warnings": []})
if cmd[:1] == ["doctor"] and "--lint" in cmd:
    f = []
    if "lint-legacy" in mode:
        f.append({"checkId": "core/doctor/legacy-state", "severity": "warning", "message": "legacy sidecar"})
    out({"schemaVersion": 1, "ok": not f, "checksRun": 10, "checksSkipped": 0, "findings": f}, 1 if f else 0)
if cmd[:3] == ["models", "auth", "list"]:
    out({"profiles": []})
if cmd[:3] == ["models", "auth", "order"]:
    out({"order": None})
if cmd[:2] == ["models", "status"]:
    out({"auth": {"runtimeAuthRoutes": [], "modelRouteIssues": [], "missingProvidersInUse": [],
                  "oauth": {"profiles": [{"profileId": "openai:default", "provider": "openai", "type": "oauth",
                                          "status": "ok"}]}}})
if cmd[:1] == ["sessions"]:
    out({"sessions": []})
if cmd[:2] == ["plugins", "list"]:
    out({"plugins": []})
sys.stderr.write("fake node: unhandled %r\n" % (cmd,))
sys.exit(3)
'''

# Fake doctor: "migrates" the synthetic DBs to 19/24, canonicalizes openai-codex refs, prints a clack box.
FAKE_DOCTOR = r'''#!/usr/bin/env python3
import glob, json, os, sqlite3, sys
state = os.environ["OPENCLAW_STATE_DIR"]
cfgp = os.environ["OPENCLAW_CONFIG_PATH"]
sdb = os.path.join(state, "state", "openclaw.sqlite")
if os.path.exists(sdb):
    c = sqlite3.connect(sdb)
    c.execute("PRAGMA user_version=19")
    c.execute("UPDATE schema_meta SET schema_version=19, app_version='2026.9.9' WHERE meta_key='primary'")
    c.execute("DROP TABLE IF EXISTS cron_run_logs")
    c.execute("UPDATE agent_databases SET schema_version=24")
    c.commit()
    c.close()
for a in glob.glob(os.path.join(state, "agents/*/agent/openclaw-agent.sqlite")):
    c = sqlite3.connect(a)
    c.execute("PRAGMA user_version=24")
    c.execute("UPDATE schema_meta SET schema_version=24 WHERE meta_key='primary'")
    c.commit()
    c.close()
dev = os.path.join(state, "identity", "device.json")
if os.path.exists(dev):
    os.remove(dev)
text = open(cfgp, encoding="utf-8").read()
cfg = json.loads(text.replace("openai-codex/", "openai/"))
meta = cfg.setdefault("meta", {})
meta["lastTouchedVersion"] = "2026.9.9"
meta.setdefault("migrations", {})["modelPolicyAllowlist"] = True
new = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
if new != text:
    with open(cfgp, "w", encoding="utf-8") as f:
        f.write(new)
print("┌  OpenClaw doctor")
print("│")
print("◇  Doctor changes ───╮")
print("│  - Migrated shared state tables │")
print("└  Doctor complete.")
'''


def make_735_state(state, with_cron_codex=False):
    """Minimal clean pre-journal 7.35 state DB + main agent DB (schemas from the 7.35 DDL)."""
    (state / "state").mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(state / "state" / "openclaw.sqlite"))
    c.executescript("""
        CREATE TABLE schema_meta (meta_key TEXT NOT NULL PRIMARY KEY, role TEXT NOT NULL,
            schema_version INTEGER NOT NULL, agent_id TEXT, app_version TEXT, created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL);
        INSERT INTO schema_meta VALUES ('primary','global',1,NULL,NULL,0,0);
        INSERT INTO schema_meta VALUES ('startup-migrations','global',1,NULL,'2026.7.35',0,0);
        CREATE TABLE agent_databases (agent_id TEXT NOT NULL, path TEXT NOT NULL, schema_version INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL, size_bytes INTEGER, PRIMARY KEY (agent_id, path));
        INSERT INTO agent_databases VALUES ('main','agents/main/agent/openclaw-agent.sqlite',1,0,NULL);
        CREATE TABLE migration_sources (source_key TEXT, target_table TEXT);
        CREATE TABLE cron_run_logs (id INTEGER);
        CREATE TABLE device_identities (identity_key TEXT);
        CREATE TABLE cron_jobs (job_id TEXT, payload_model TEXT, payload_fallbacks_json TEXT);
        PRAGMA user_version=1;
    """)
    if with_cron_codex:
        c.execute("INSERT INTO cron_jobs VALUES ('j1','openai-codex/gpt-5.4-mini',NULL)")
    c.commit()
    c.close()
    make_agent_db(state, "main", 1)


def make_agent_db(state, aid, uv, auth=True):
    d = state / "agents" / aid / "agent"
    d.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(d / "openclaw-agent.sqlite"))
    c.executescript(f"""
        CREATE TABLE schema_meta (meta_key TEXT NOT NULL PRIMARY KEY, role TEXT NOT NULL,
            schema_version INTEGER NOT NULL, agent_id TEXT, app_version TEXT, created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL);
        INSERT INTO schema_meta VALUES ('primary','agent',{uv},'{aid}',NULL,0,0);
        PRAGMA user_version={uv};
    """)
    if auth:
        c.execute("CREATE TABLE auth_profile_store (store_key TEXT PRIMARY KEY, store_json TEXT, updated_at INTEGER)")
        c.execute("INSERT INTO auth_profile_store VALUES ('primary', ?, 0)", (json.dumps({"profiles": {
            "openai-codex:default": {"type": "oauth", "provider": "openai-codex", "access": "SECRET-ACCESS",
                                     "refresh": "SECRET-REFRESH", "expires": 4102444800000}}}),))
    c.commit()
    c.close()


def make_99_state(state, s=19, a=24, app=RUNTIME):
    (state / "state").mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(state / "state" / "openclaw.sqlite"))
    c.executescript(f"""
        CREATE TABLE schema_meta (meta_key TEXT NOT NULL PRIMARY KEY, role TEXT NOT NULL,
            schema_version INTEGER NOT NULL, agent_id TEXT, app_version TEXT, created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL);
        INSERT INTO schema_meta VALUES ('primary','global',{s},NULL,'{app}',0,0);
        CREATE TABLE agent_databases (agent_id TEXT NOT NULL, path TEXT NOT NULL, schema_version INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL, size_bytes INTEGER, PRIMARY KEY (agent_id, path));
        INSERT INTO agent_databases VALUES ('main','agents/main/agent/openclaw-agent.sqlite',{a},0,NULL);
        CREATE TABLE config_machine_state (state_key TEXT PRIMARY KEY, value_json TEXT);
        CREATE TABLE device_identities (identity_key TEXT);
        INSERT INTO device_identities VALUES ('primary');
        PRAGMA user_version={s};
    """)
    c.commit()
    c.close()
    make_agent_db(state, "main", a, auth=False)


CFG_735 = {
    "meta": {"lastTouchedVersion": "2026.7.35"},
    "agents": {"defaults": {"model": {"primary": "openai-codex/gpt-5.5", "fallbacks": ["vllm/qwen3.5-122b"]},
                            "models": {"openai-codex/*": {}, "openai-codex/gpt-5.5": {"alias": "gpt"},
                                       "vllm/qwen3.5-122b": {}}},
               "list": [{"id": "main", "default": True}]},
    "models": {"providers": {"vllm": {"baseUrl": "http://127.0.0.1:8000/v1", "models": [{"id": "qwen3.5-122b"}]}}},
    "gateway": {"mode": "local", "auth": {"token": "SECRET-GATEWAY-TOKEN"}},
    "channels": {"telegram": {"enabled": True, "botToken": "123456:SECRET-BOT-TOKEN"}},
}


class GateEnv(unittest.TestCase):
    """Temporary add-on tree with fake runtime package, fake node and fake doctor."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="oc-gate-test-"))
        self.root = self.tmp / "config"
        self.state = self.root / ".openclaw"
        self.upg = self.root / ".openclaw-upgrade"
        self.share = self.tmp / "share"
        self.ws = self.root / "clawd"
        for d in (self.state, self.upg, self.share, self.ws):
            d.mkdir(parents=True)
        pkg = self.tmp / "pkg" / "openclaw"
        pkg.mkdir(parents=True)
        (pkg / "openclaw.mjs").write_text("")
        (pkg / "package.json").write_text(json.dumps({"version": RUNTIME,
                                                      "openclaw": {"schemaVersions": {"state": 19, "agent": 24}}}))
        (self.tmp / "entry").write_text(str(pkg / "openclaw.mjs") + "\n")
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        for name, body in (("node", FAKE_NODE), ("fake-doctor", FAKE_DOCTOR)):
            (self.bin / name).write_text(body)
            (self.bin / name).chmod(0o755)
        self.env = mock.patch.dict(os.environ, {
            "OPENCLAW_STATE_DIR": str(self.state), "OC_UPGRADE_DIR": str(self.upg),
            "OC_UPGRADE_SHARE_DIR": str(self.share), "OC_CONFIG_ROOT": str(self.root),
            "OC_ADDON_ENTRY_FILE": str(self.tmp / "entry"), "PATH": f"{self.bin}:{os.environ.get('PATH', '')}",
            "OC_GATE_TEST_HOOKS": "1", "TMPDIR": str(self.tmp), "ADDON_VERSION": "0.5.94-test"})
        self.env.start()
        for k in ("OPENCLAW_CONFIG_PATH", "OPENCLAW_WORKSPACE_DIR", "OPENCLAW_RUNTIME_VERSION", "FAKE_OC_MODE",
                  "SQLITE_TMPDIR", "OC_GATE_FROM_RUNSH"):
            os.environ.pop(k, None)
        os.environ["OPENCLAW_CONFIG_PATH"] = str(self.state / "openclaw.json")
        G.STOP.clear()
        G._STOP_SIG[0] = None
        del G.NODE_FALLBACKS[:]

    def tearDown(self):
        self.env.stop()
        G.STOP.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers
    def write_cfg(self, cfg):
        (self.state / "openclaw.json").write_text(json.dumps(cfg, indent=2) + "\n")

    def hooks(self, **kw):
        base = {"skip_network_check": True, "skip_space_check": True,
                "doctor_cmd": [str(self.bin / "fake-doctor")]}
        base.update(kw)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "test-hooks.json").write_text(json.dumps(base))

    def journal(self):
        return json.loads((self.upg / "gate" / "journal.json").read_text())

    def quiet(self, fn, *a, **kw):
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rv = fn(*a, **kw)
        self.out = buf.getvalue()
        self.err = err.getvalue()
        return rv

    def run_gate(self):
        return self.quiet(G.run_gate)

    def plan(self, apply=False):
        lines = []
        d = G.plan(apply=apply, emit=lines.append)
        self.out = "\n".join(lines)
        return d

    def build_735(self, **kw):
        make_735_state(self.state, **kw)
        self.write_cfg(CFG_735)
        (self.state / "agents" / "main" / "sessions").mkdir(parents=True)
        (self.state / "agents" / "main" / "sessions" / "sessions.json").write_text(json.dumps({
            "agent:main:main": {"sessionId": "s1", "updatedAt": 1, "modelProvider": "openai-codex", "model": "gpt-5.5"},
            "agent:main:x": {"sessionId": "s2", "updatedAt": 1, "model": "vllm/qwen3.5-122b"}}))
        (self.ws / "AGENTS.md").write_text("# agents\n")
        (self.ws / "node_modules" / "big").mkdir(parents=True, exist_ok=True)
        (self.ws / "node_modules" / "big" / "x.js").write_text("x" * 1000)


# --- decision table ---------------------------------------------------------------------------

def cls_of(verdict="ok", schema=None, files=False, state_uv=19, agents=None):
    schema = schema or ("ok" if verdict in ("ok",) else verdict)
    return {"verdict": verdict, "schema_verdict": schema, "files_verdict": "gate" if files else "ok",
            "newer": ["state schema 20 > 19"] if verdict == "newer" else [],
            "gate": ["state schema 1 < 19"] if schema == "gate" else [], "files": ["x/device.json"] if files else [],
            "state": {"uv": state_uv, "eff": state_uv}, "state_uv": state_uv,
            "agents": agents if agents is not None else {"main": 24 if state_uv != 1 else 1},
            "agent_paths": {"main": "agents/main/agent/openclaw-agent.sqlite"}, "orphans": []}


BIND = {"state_db": {"dev": 1, "ino": 2}, "agents": [{"path": "agents/main/agent/openclaw-agent.sqlite", "dev": 1,
                                                       "ino": 3}]}


def ctx(**kw):
    c = {"fresh": False, "runtime": RUNTIME, "cls": cls_of(), "journal": None, "marker": None, "retry": None,
         "cfg": {"meta": {"lastTouchedVersion": RUNTIME}}, "binding": BIND}
    c.update(kw)
    return c


class DecideTests(unittest.TestCase):
    def test_fresh(self):
        d = G.decide(ctx(fresh=True))
        self.assertEqual((d["rc"], d["action"]), (0, "none"))
        self.assertFalse(d["bk"]["consume_retry"])

    def test_fresh_with_stale_hold_journal_needs_housekeeping(self):
        d = G.decide(ctx(fresh=True, journal={"status": "hold", "hold": {"code": "doctor-failed"}}))
        self.assertEqual(d["rc"], 0)
        self.assertEqual(d["bk"]["journal_status"], "abandoned")

    def test_newer(self):
        self.assertEqual(G.decide(ctx(cls=cls_of("newer")))["rc"], 3)

    def test_from_7x_gate(self):
        d = G.decide(ctx(cls=cls_of("gate", state_uv=1), cfg={"meta": {"lastTouchedVersion": "2026.7.35"}}))
        self.assertEqual((d["rc"], d["action"], d["mode"]), (10, "run", "from-7x"))

    def test_hold_without_retry_is_sticky(self):
        j = {"status": "hold", "run_id": "r1", "phase": "postconditions", "first_write_at": "t",
             "hold": {"code": "pc-legacy-refs", "phase": "postconditions"}}
        d = G.decide(ctx(journal=j))
        self.assertEqual((d["rc"], d["hold"]["code"]), (11, "pc-legacy-refs"))

    def test_B1_retry_after_successful_doctor_resumes_not_adopts(self):
        # verdict ok (doctor done), no marker, lastTouched == runtime: must resume, never adopt
        j = {"status": "hold", "run_id": "r1", "mode": "from-7x", "phase": "postconditions", "first_write_at": "t",
             "doctor_started": True, "hold": {"code": "pc-legacy-refs", "phase": "postconditions"}}
        d = G.decide(ctx(journal=j, retry={"accept": ["pc-legacy-refs"], "doctor": False}))
        self.assertEqual((d["rc"], d["action"], d["mode"], d["resume_phase"]),
                         (10, "resume", "from-7x", "postconditions"))
        self.assertIsNone(d["marker"])
        self.assertTrue(d["bk"]["consume_retry"])
        self.assertEqual(d["bk"]["accept"], ["pc-legacy-refs"])
        self.assertEqual(d["bk"]["auto_resumes"], 0)

    def test_B1_retry_doctor_redo(self):
        j = {"status": "hold", "run_id": "r1", "mode": "from-7x", "phase": "postconditions", "first_write_at": "t",
             "doctor_started": True, "hold": {"code": "pc-schema", "phase": "postconditions"}}
        d = G.decide(ctx(journal=j, retry={"doctor": True}))
        self.assertTrue(d["bk"]["redo_doctor"])

    def test_retry_before_first_write_reruns_precheck(self):
        j = {"status": "hold", "run_id": "r1", "mode": "from-7x", "phase": "precheck", "first_write_at": None,
             "hold": {"code": "no-network", "phase": "precheck"}}
        d = G.decide(ctx(journal=j, retry={"accept": ["no-network"]},
                         cls=cls_of("gate", state_uv=1), cfg={"meta": {"lastTouchedVersion": "2026.7.35"}}))
        self.assertEqual((d["rc"], d["action"], d["resume_phase"]), (10, "resume", "precheck"))

    def test_retry_before_first_write_when_nothing_left_closes_run(self):
        j = {"status": "hold", "run_id": "r1", "mode": "bump", "phase": "precheck", "first_write_at": None,
             "hold": {"code": "low-disk-share", "phase": "precheck"}}
        d = G.decide(ctx(journal=j, retry={}))
        self.assertEqual(d["rc"], 0)
        self.assertEqual(d["bk"]["journal_status"], "done")
        self.assertEqual(d["marker"], "adopt")

    def test_exit78_retry_ok_and_gate(self):
        j = {"status": "hold", "run_id": "r1", "mode": "from-7x", "first_write_at": "t",
             "hold": {"code": "exit78", "phase": "gateway"}}
        marker = {"runtime": RUNTIME, "mode": "from-7x", "binding": BIND}
        d = G.decide(ctx(journal=j, retry={}, marker=marker))
        self.assertEqual(d["rc"], 0)
        self.assertEqual(d["bk"]["journal_status"], "done")
        d = G.decide(ctx(journal=j, retry={}, marker=marker, cls=cls_of("gate", state_uv=19)))
        self.assertEqual((d["rc"], d["mode"], d["new_run"]), (10, "maintenance", True))
        d = G.decide(ctx(journal=j, retry={"doctor": True}, marker=marker))
        self.assertEqual((d["rc"], d["mode"]), (10, "maintenance"))

    def test_interrupt_counting(self):
        j = {"status": "interrupted", "run_id": "r1", "mode": "from-7x", "phase": "doctor1", "auto_resumes": 0}
        d = G.decide(ctx(journal=j))
        self.assertEqual((d["rc"], d["action"], d["resume_phase"], d["bk"]["auto_resumes"]),
                         (10, "resume", "doctor1", 1))
        j["auto_resumes"] = 1
        d = G.decide(ctx(journal=j))
        self.assertEqual((d["rc"], d["hold"]["code"]), (11, "interrupted-twice"))
        d = G.decide(ctx(journal=j, retry={}))
        self.assertEqual((d["rc"], d["action"], d["bk"]["auto_resumes"]), (10, "resume", 0))
        j2 = dict(j, status="running", auto_resumes=0)
        self.assertEqual(G.decide(ctx(journal=j2))["rc"], 10)

    def test_B4_bump_repeat_guard(self):
        marker = {"runtime": RUNTIME, "mode": "bump", "binding": BIND}
        done = {"status": "done", "run_id": "r1"}
        d = G.decide(ctx(journal=done, marker=marker, cls=cls_of("gate", state_uv=19)))
        self.assertEqual((d["rc"], d["hold"]["code"]), (11, "bump-repeat"))
        d = G.decide(ctx(journal=done, marker=marker, cls=cls_of("gate", state_uv=19), retry={}))
        self.assertEqual((d["rc"], d["mode"]), (10, "bump"))
        other = {"state_db": {"dev": 1, "ino": 99}, "agents": BIND["agents"]}
        d = G.decide(ctx(journal=done, marker=marker, cls=cls_of("gate", state_uv=19), binding=other))
        self.assertEqual((d["rc"], d["mode"]), (10, "bump"))

    def test_maintenance_request(self):
        marker = {"runtime": RUNTIME, "mode": "from-7x", "binding": BIND}
        d = G.decide(ctx(journal={"status": "done"}, marker=marker, retry={"doctor": True}))
        self.assertEqual((d["rc"], d["mode"]), (10, "maintenance"))

    def test_ok_paths(self):
        marker = {"runtime": RUNTIME, "mode": "from-7x", "binding": BIND}
        d = G.decide(ctx(marker=marker))
        self.assertEqual((d["rc"], d["marker"]), (0, None))
        d = G.decide(ctx(marker=marker, binding={"state_db": {"dev": 9, "ino": 9}, "agents": []}))
        self.assertEqual((d["rc"], d["marker"]), (0, "rebind"))
        self.assertTrue(any("marker rebound" in w for w in d["warnings"]))
        d = G.decide(ctx(marker=dict(marker, runtime="2026.9.5")))
        self.assertEqual((d["rc"], d["mode"]), (10, "bump"))
        d = G.decide(ctx(cfg={}))
        self.assertEqual((d["rc"], d["marker"]), (0, "adopt"))
        d = G.decide(ctx(cfg={"meta": {"lastTouchedVersion": "2026.9.5"}}))
        self.assertEqual((d["rc"], d["mode"]), (10, "bump"))

    def test_files_only_gate_with_marker_is_logged_only(self):
        marker = {"runtime": RUNTIME, "mode": "from-7x", "binding": BIND}
        d = G.decide(ctx(marker=marker, cls=cls_of("gate", schema="ok", files=True)))
        self.assertEqual(d["rc"], 0)
        self.assertTrue(any("legacy files" in w for w in d["warnings"]))
        d = G.decide(ctx(cls=cls_of("gate", schema="ok", files=True)))
        self.assertEqual((d["rc"], d["mode"]), (10, "bump"))

    def test_newer_state_hold_closes_after_restore(self):
        j = {"status": "hold", "run_id": "r1", "hold": {"code": "newer-state", "phase": "precheck"}}
        d = G.decide(ctx(journal=j))
        self.assertEqual(d["rc"], 0)
        self.assertEqual(d["bk"]["journal_status"], "done")

    def test_stale_retry_is_discarded(self):
        marker = {"runtime": RUNTIME, "mode": "from-7x", "binding": BIND}
        d = G.decide(ctx(marker=marker, journal={"status": "done"}, retry={"accept": ["x"]}))
        self.assertEqual(d["rc"], 0)
        self.assertTrue(d["bk"]["consume_retry"])

    def test_infer_mode(self):
        self.assertEqual(G.infer_mode(cls_of("gate", state_uv=1), {}), "from-7x")
        self.assertEqual(G.infer_mode(cls_of("gate", state_uv=19), {}), "bump")
        c = cls_of("gate", state_uv=None, agents={"main": 1})
        self.assertEqual(G.infer_mode(c, {}), "from-7x")
        c = cls_of("gate", state_uv=None, agents={})
        self.assertEqual(G.infer_mode(c, {"meta": {"lastTouchedVersion": "2026.7.35"}}), "from-7x")
        # F6: a v1 agent DB or a 7.x config means from-7x whatever the state DB says
        for uv in (0, 19):
            self.assertEqual(G.infer_mode(cls_of("gate", state_uv=uv, agents={"main": 24, "work": 1}), {}), "from-7x")
            self.assertEqual(G.infer_mode(cls_of("gate", state_uv=uv),
                                          {"meta": {"lastTouchedVersion": "2026.7.35"}}), "from-7x")
        self.assertEqual(G.infer_mode(cls_of("gate", state_uv=19), {"meta": {"lastTouchedVersion": "2026.9.5"}}), "bump")

    def test_F6_from7x_wins_for_post_run_retries_and_bumps(self):
        """Reviewer repro decide_test.py: a rolled-back 2026.7.x state never gets a maintenance or bump run."""
        cls735 = cls_of("gate", state_uv=1)
        cfg7 = {"meta": {"lastTouchedVersion": "2026.7.35"}}
        marker = {"runtime": RUNTIME, "mode": "from-7x", "run_id": "old", "binding": {}}
        for code in ("exit78", "crash-loop"):
            j = {"status": "hold", "run_id": "old", "mode": "from-7x", "first_write_at": None,
                 "hold": {"code": code, "phase": "gateway"}}
            for retry in ({"doctor": False, "accept": []}, {"doctor": True}):
                d = G.decide(ctx(cls=cls735, journal=j, marker=marker, retry=retry, cfg=cfg7, binding={}))
                self.assertEqual((d["rc"], d["action"], d["mode"], d["new_run"]), (10, "run", "from-7x", True))
        # version bumps (marker for another runtime / config written by another version)
        d = G.decide(ctx(marker=dict(marker, runtime="2026.9.5"), cfg=cfg7))
        self.assertEqual((d["rc"], d["mode"]), (10, "from-7x"))
        d = G.decide(ctx(cfg=cfg7))
        self.assertEqual((d["rc"], d["mode"]), (10, "from-7x"))
        d = G.decide(ctx(cls=cls_of("gate", state_uv=19, agents={"main": 1}), marker=dict(marker, runtime="2026.9.5")))
        self.assertEqual((d["rc"], d["mode"]), (10, "from-7x"))


# --- classification ---------------------------------------------------------------------------

class ClassifyTests(GateEnv):
    def test_735_state_needs_gate(self):
        make_735_state(self.state)
        c = G.classify(self.state, {}, 19, 24, RUNTIME)
        self.assertEqual((c["verdict"], c["schema_verdict"], c["state_uv"]), ("gate", "gate", 1))
        self.assertEqual(c["agents"], {"main": 1})

    def test_99_state_ok_and_newer(self):
        make_99_state(self.state)
        c = G.classify(self.state, {}, 19, 24, RUNTIME)
        self.assertEqual(c["verdict"], "ok", c)
        c = G.classify(self.state, {}, 18, 24, "2026.9.5")
        self.assertEqual(c["verdict"], "newer")
        c = G.classify(self.state, {"meta": {"lastTouchedVersion": "2026.10.1"}}, 19, 24, RUNTIME)
        self.assertEqual(c["verdict"], "newer")

    def test_content_version_and_cron_run_logs(self):
        make_99_state(self.state, s=18)
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute("INSERT INTO config_machine_state VALUES ('state.schema.contentVersion', '19')")
        con.commit()
        c = G.classify(self.state, {}, 19, 24, RUNTIME)
        self.assertEqual((c["state"]["eff"], c["verdict"]), (19, "ok"))
        con.execute("CREATE TABLE cron_run_logs (id INTEGER)")
        con.commit()
        con.close()
        c = G.classify(self.state, {}, 19, 24, RUNTIME)
        self.assertEqual(c["verdict"], "gate")
        self.assertIn("legacy cron_run_logs table present", c["gate"])

    def test_B4_orphan_agent_db_excluded(self):
        make_99_state(self.state)
        make_agent_db(self.state, "ghost", 1, auth=False)
        c = G.classify(self.state, {}, 19, 24, RUNTIME)
        self.assertEqual(c["verdict"], "ok")
        self.assertEqual([o["id"] for o in c["orphans"]], ["ghost"])
        cfg = {"agents": {"list": [{"id": "main"}, {"id": "ghost"}]}}
        c = G.classify(self.state, cfg, 19, 24, RUNTIME)
        self.assertEqual(c["verdict"], "gate")
        self.assertEqual(c["orphans"], [])

    def test_fresh_agent_db_ignored(self):
        make_99_state(self.state)
        d = self.state / "agents" / "main" / "agent"
        os.remove(d / "openclaw-agent.sqlite")
        sqlite3.connect(str(d / "openclaw-agent.sqlite")).close()
        c = G.classify(self.state, {}, 19, 24, RUNTIME)
        self.assertEqual(c["verdict"], "ok")
        self.assertEqual(c["agents"], {})

    def test_files_verdict(self):
        make_99_state(self.state)
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute("DELETE FROM device_identities")
        con.commit()
        con.close()
        (self.state / "identity").mkdir()
        (self.state / "identity" / "device.json").write_text("{}")
        c = G.classify(self.state, {}, 19, 24, RUNTIME)
        self.assertEqual((c["schema_verdict"], c["files_verdict"], c["verdict"]), ("ok", "gate", "gate"))
        os.remove(self.state / "identity" / "device.json")
        (self.ws / "openclaw-workspace-state.json").write_text("{}")
        self.assertEqual(G.classify(self.state, {}, 19, 24, RUNTIME)["files_verdict"], "gate")
        os.remove(self.ws / "openclaw-workspace-state.json")
        Path(f"{self.ws}.attested").write_bytes(b"not an attestation")
        self.assertEqual(G.classify(self.state, {}, 19, 24, RUNTIME)["files_verdict"], "ok")
        Path(f"{self.ws}.attested").write_bytes(G.ATTESTATION_HEADER + b"x")
        self.assertEqual(G.classify(self.state, {}, 19, 24, RUNTIME)["files_verdict"], "gate")

    def test_B5_legacy_dir_attestation(self):
        import hashlib
        make_99_state(self.state)
        key = hashlib.sha256(str(self.ws).encode()).hexdigest()
        d = self.root / ".clawdbot" / "workspace-attestations"
        d.mkdir(parents=True)
        (d / f"{key}.attested").write_text("x")
        self.assertEqual(G.classify(self.state, {}, 19, 24, RUNTIME)["files_verdict"], "gate")

    def test_prejournal_check(self):
        make_735_state(self.state)
        sdb = self.state / "state" / "openclaw.sqlite"
        self.assertEqual(G.prejournal_problems(sdb), [])
        con = sqlite3.connect(str(sdb))
        con.execute("CREATE TABLE config_machine_state (state_key TEXT)")
        con.execute("INSERT INTO migration_sources VALUES ('agent-deletion-journal-reconstruction', 'x')")
        con.commit()
        con.close()
        probs = G.prejournal_problems(sdb)
        self.assertIn("table config_machine_state present", probs)
        self.assertTrue(any("reconstruction receipt" in p for p in probs))
        self.assertEqual(G.prejournal_problems(self.state / "nope.sqlite"), ["state/openclaw.sqlite missing"])

    def test_schema_meta_check_accepts_real_99_shape(self):
        # real 2026.9.9 result: state primary app_version NULL, agent primary app_version = runtime
        make_99_state(self.state, app=None)
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute("UPDATE schema_meta SET app_version=NULL WHERE meta_key='primary'")
        con.commit()
        con.close()
        con = sqlite3.connect(str(self.state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"))
        con.execute("UPDATE schema_meta SET app_version=? WHERE meta_key='primary'", (RUNTIME,))
        con.commit()
        con.close()
        pkg = {"version": RUNTIME, "schema_state": 19, "schema_agent": 24}
        c = G.classify(self.state, {}, 19, 24, RUNTIME)
        self.assertEqual(G.schema_meta_problems(self.state, c, pkg), [])
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute("UPDATE schema_meta SET app_version='2026.9.5' WHERE meta_key='primary'")
        con.commit()
        con.close()
        self.assertEqual(len(G.schema_meta_problems(self.state, c, pkg)), 1)

    def test_workspaces_from_config(self):
        cfg = {"agents": {"defaults": {"workspace": "~/clawd"}, "list": [{"id": "a", "workspace": "~/ws-a"}],
                          "entries": {"b": {"workspace": str(self.root / "ws-b")}}}}
        self.assertEqual(G.workspaces(cfg), [self.ws, self.root / "ws-a", self.root / "ws-b"])


# --- plan (integration, read-only) -----------------------------------------------------------------

class PlanTests(GateEnv):
    def test_fresh_install(self):
        self.assertEqual(self.plan()["rc"], 0)
        self.assertIn("[gate] plan: fresh install", self.out)

    def test_735_plan_is_read_only(self):
        make_735_state(self.state)
        self.write_cfg(CFG_735)
        (self.upg / "gate").mkdir(parents=True)
        (self.upg / "gate" / "retry-request.json").write_text("{}")
        before = {p: p.stat().st_mtime_ns for p in self.tmp.rglob("*") if p.is_file()}
        d = self.plan()
        self.assertEqual((d["rc"], d["mode"]), (10, "from-7x"))
        self.assertEqual(sum(1 for x in self.out.splitlines() if x.startswith("[gate] plan:")), 1)
        after = {p: p.stat().st_mtime_ns for p in self.tmp.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertTrue((self.upg / "gate" / "retry-request.json").exists())

    def test_adopt_writes_marker(self):
        make_99_state(self.state)
        self.write_cfg({"meta": {"lastTouchedVersion": RUNTIME}})
        self.assertEqual(self.plan()["rc"], 0)
        m = json.loads((self.upg / "gate" / "migrated.json").read_text())
        self.assertEqual((m["runtime"], m["mode"]), (RUNTIME, "adopted"))

    def test_B11_plan_error_with_marker_starts(self):
        make_99_state(self.state)
        self.write_cfg({})
        (self.upg / "gate").mkdir(parents=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": RUNTIME, "mode": "from-7x"}))
        with mock.patch.object(G, "classify", side_effect=RuntimeError("boom")):
            d = self.plan()
        self.assertEqual(d["rc"], 0)
        self.assertIn("WARN [gate] planning failed", self.out)
        os.remove(self.upg / "gate" / "migrated.json")
        with mock.patch.object(G, "classify", side_effect=RuntimeError("boom")):
            self.assertEqual(self.plan()["rc"], 1)

    def test_B11_shortcut_only_without_an_open_gate_run(self):
        """Reviewer repro b11.py: a planning error must not bypass a held maintenance run."""
        make_99_state(self.state)
        self.write_cfg({})
        (self.upg / "gate").mkdir(parents=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": RUNTIME, "mode": "from-7x"}))
        jpath = self.upg / "gate" / "journal.json"
        for status, rc in (("hold", 1), ("running", 1), ("interrupted", 1), ("done", 0), ("abandoned", 0)):
            jpath.write_text(json.dumps({"status": status, "run_id": "m1", "mode": "maintenance",
                                         "first_write_at": "t", "hold": {"code": "doctor-failed", "phase": "doctor2"}}))
            with self.subTest(status=status), mock.patch.object(G, "classify", side_effect=ValueError("boom")):
                d = self.plan()
                self.assertEqual(d["rc"], rc, self.out)
                self.assertEqual("planning error ignored" in self.out, rc == 0)
        jpath.write_text("{not json")
        with mock.patch.object(G, "classify", side_effect=ValueError("boom")):
            self.assertEqual(self.plan()["rc"], 1)

    def test_plan_reraises_a_stop(self):
        make_99_state(self.state)
        self.write_cfg({})
        (self.upg / "gate").mkdir(parents=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": RUNTIME, "mode": "from-7x"}))
        with mock.patch.object(G, "classify", side_effect=C.Stopped("stop requested")):
            with self.assertRaises(C.Stopped):
                self.plan()

    def test_sticky_hold_writes_hold_txt(self):
        make_735_state(self.state)
        self.write_cfg(CFG_735)
        (self.upg / "gate").mkdir(parents=True)
        j = {"schema": 1, "run_id": "r1", "mode": "from-7x", "status": "hold", "phase": "precheck",
             "first_write_at": None, "hold": {"code": "no-network", "codes": ["no-network"], "phase": "precheck",
                                              "message": "npm unreachable", "acceptable": True,
                                              "findings": [{"code": "no-network", "cls": "acceptable",
                                                            "message": "npm unreachable"}]}}
        (self.upg / "gate" / "journal.json").write_text(json.dumps(j))
        d = self.plan()
        self.assertEqual(d["rc"], 11)
        txt = (self.upg / "hold.txt").read_text()
        self.assertIn("migration gate run r1, phase precheck", txt)
        self.assertIn("Reason [no-network]: npm unreachable", txt)
        self.assertIn("oc-upgrade retry --accept no-network", txt)
        self.assertEqual(self.journal()["status"], "hold")

    def test_newer_rc3(self):
        make_99_state(self.state, s=25)
        self.write_cfg({})
        self.assertEqual(self.plan()["rc"], 3)


# --- doctor output ---------------------------------------------------------------------------------

BOX_OK = ("┌  OpenClaw doctor\n│\n◇  Doctor warnings ──╮\n"
          "│  - Model metadata looked corrupt but Doctor could  │\n"
          "│    not prove the responsible config write. It was left unchanged. │\n"
          "│  - provider catalog timed out after 5000ms │\n└  Doctor complete.\n")


class DoctorNotesTests(unittest.TestCase):
    """Contract addendum 1 item 7: behaviour-change notes parsed from the normalized doctor log."""

    LOG = "\n".join([
        "\u25c7  Doctor warnings \u2500\u2500\u2500\u256e",
        "\u2502  - agents.entries.mail_reader.model is \"vllm/qwen3.5-122b\", a bare      \u2502",
        "\u2502    string with no fallbacks. At runtime this clobbers                   \u2502",
        "\u2502    agents.defaults.model.fallbacks (openai/gpt-5.5), leaving   \u2502",
        "\u2502  Agent \"main\":                                                           \u2502",
        "\u2502  31 allowed skills are not usable in this environment (missing           \u2502",
        "\u2502  Create heartbeat monitor for agent \"main\" at 1h.         \u2502",
        "\u2502  Create heartbeat monitor for agent \"main\" at 1h.         \u2502",
        "\u2502  Removed untouched ~/clawd/TOOLS.md after archiving it.  \u2502",
        "\u2502  Migrated ~/clawd/HEARTBEAT.md into cron scratch for Heartbeat (main).  \u2502",
        "\u2502  Agent \"main\": Memory search provider is set to \"openai\" but no API key  \u2502",
        "\u2502  was found. sk-abcdefghijklmnopqrstuvwxyz \u2502",
    ])

    def test_notes(self):
        notes = G.doctor_notes(self.LOG)
        levels = [n[0] for n in notes]
        text = "\n".join(n[1] for n in notes)
        self.assertEqual(levels, ["info", "warn", "warn", "warn", "warn", "warn"])
        self.assertIn("agents.entries.mail_reader.model has no explicit \"fallbacks\"", text)
        self.assertIn("memory search of agent main uses provider openai without an API key", text)
        self.assertIn("31 skill(s) of agent main", text)
        self.assertEqual(text.count("heartbeat monitor"), 1, "deduplicated")
        self.assertIn("~/clawd/TOOLS.md", text)
        self.assertIn("~/clawd/HEARTBEAT.md", text)
        self.assertNotIn("sk-abc", text)
        self.assertEqual(G.doctor_notes("Doctor complete."), [])

    def test_info_findings_never_hold(self):
        g = G.Gate(dry_run=True, emit=lambda _l: None)
        lines = []
        g.emit = lines.append
        g.resolve([G.finding("canonical-openai-refs", "info", "3 canonical openai/* refs/keys will be pinned"),
                   G.finding("x", "warn", "w")], "precheck")
        self.assertEqual(lines, ["[gate] 1/9 info: 3 canonical openai/* refs/keys will be pinned", "WARN [gate] x: w"])
        g.cleanup_tmp()


class DoctorRetirementTests(unittest.TestCase):
    """Contract addendum 2 item 7: retired-model replacements parsed from the normalized doctor log.
    The lines are copied from real 9.9 doctor logs (harness T1 pass 1, exp5 pass 1, exp1raw) or built
    from the dist templates (retired-model-ref-repair-BeQCC1zw.mjs, legacy-config-migrations.runtime.models)."""

    T1_PASS1 = "\n".join([
        "◇  Doctor changes ───╮",
        "│  Replaced retired agents.defaults.model.fallbacks.0                      │",
        "│  \"openai/gpt-5.4-mini\" with \"openai/gpt-5.6-luna\".                       │",
        "│  Replaced retired agents.defaults.heartbeat.model \"openai/gpt-5.4-mini\"  │",
        "│  with \"openai/gpt-5.6-luna\".                                             │",
        "│  Preserved inherited openai/gpt-5.4 settings in                          │",
        "│  agents.entries.main.models.openai/gpt-5.6-terra.                        │",
        "│  Replaced retired hooks.mappings.0.model \"openai/gpt-5.4-mini\" with      │",
        "│  \"openai/gpt-5.6-luna\".                                                  │",
        "│  Repaired Codex model routes:- agents.defaults.model.primary:          │",
        "│  openai-codex/gpt-5.5 -> openai/gpt-5.5.-                              │",
        "│  - Discarded retired shared-state commitments rows, table, and indexes  │",
    ])
    EXP5_PASS1 = "\n".join([
        "│  - Upgraded config.agents.defaults.models key from                       │",
        "│    \"anthropic/claude-opus-4-5\" to \"anthropic/claude-opus-4-7\".           │",
        "│  - Merged config.agents.defaults.models key \"anthropic/claude-opus-4-5\"  │",
        "│    into \"anthropic/claude-opus-4-7\".                                     │",
        "│  - Merged config.agents.defaults.models key                              │",
        "│    \"anthropic/claude-sonnet-4-5\" into \"anthropic/claude-sonnet-4-6\".     │",
        "│  - Upgraded config.agents.defaults.models key from                       │",
        "│    \"openai/gpt-5.1-codex\" to \"openai/gpt-5.3-codex\".                     │",
    ])
    RAW = "\n".join([
        "│  Replaced stale agents.defaults.model primary \"openai-codex/gpt-5.5\"    │",
        "│  with default \"openai/gpt-6-astra\" (provider \"openai-codex\" is          │",
        "│  unavailable).                                                          │",
        "│  Added agents.defaults.models entry \"openai/gpt-6-astra\" to keep the    │",
    ])

    def test_real_t1_log(self):
        pairs, removed = G.doctor_retirements(self.T1_PASS1)
        self.assertEqual(pairs, {"openai/gpt-5.4-mini": "openai/gpt-5.6-luna", "openai/gpt-5.4": "openai/gpt-5.6-terra"})
        self.assertEqual(removed, [])

    def test_real_exp5_log(self):
        pairs, _r = G.doctor_retirements(self.EXP5_PASS1)
        self.assertEqual(pairs, {"anthropic/claude-opus-4-5": "anthropic/claude-opus-4-7",
                                 "anthropic/claude-sonnet-4-5": "anthropic/claude-sonnet-4-6",
                                 "openai/gpt-5.1-codex": "openai/gpt-5.3-codex"})

    def test_raw_path_damage_is_no_retirement(self):
        self.assertEqual(G.doctor_retirements(self.RAW), ({}, []))

    def test_other_dist_templates(self):
        text = "\n".join([
            'Moved retired agents.entries.ops.models.openai/gpt-5.2-pro to openai/gpt-5.5-pro.',
            'Preserved agents.defaults.models.openai/gpt-5.4-nano for other authentication routes and added '
            'openai/gpt-5.6-luna.',
            'Preserved agents.defaults.modelPolicy.allow.3 "openai/o3" for other authentication routes and allowed '
            '"openai/gpt-5.5".',
            'Replaced retired agents.defaults.modelPolicy.allow.0 "xai/grok-4.3" with "xai/grok-4.7".',
            'Preserved agents.defaults.imageModel model "openai/gpt-image-1@openai:old" as '
            '"openai/gpt-image-2@openai:default" after config repair.',
            'Upgraded config.agents.defaults.model.primary from "google/gemini-3-pro" to "google/gemini-3.1-pro".',
            'Upgraded config.x provider/model from "a/b" to "a/c".',
            'Upgraded config.models.providers.vllm.models.0.id from "qwen" to "qwen3".',
            'Upgraded config.x key from "openai-codex/gpt-5.2" to "openai/gpt-5.5".',
            'Removed retired agents.defaults.heartbeat.model "openai/gpt-4o" so it inherits the configured '
            'default model.',
        ])
        pairs, removed = G.doctor_retirements(text)
        self.assertEqual(pairs, {"openai/gpt-5.2-pro": "openai/gpt-5.5-pro",
                                 "openai/gpt-5.4-nano": "openai/gpt-5.6-luna", "openai/o3": "openai/gpt-5.5",
                                 "xai/grok-4.3": "xai/grok-4.7", "openai/gpt-image-1": "openai/gpt-image-2",
                                 "google/gemini-3-pro": "google/gemini-3.1-pro", "a/b": "a/c"})
        self.assertEqual(removed, [["agents.defaults.heartbeat.model", "openai/gpt-4o"]])


class DoctorEvalTests(unittest.TestCase):
    def test_success(self):
        ev = G.evaluate_doctor(0, "\x1b[32m└  Doctor complete.\x1b[0m\n")
        self.assertIsNone(ev["code"])
        self.assertTrue(ev["complete"])

    def test_B3_benign_marker_text_with_rc0_passes(self):
        ev = G.evaluate_doctor(0, BOX_OK)
        self.assertIsNone(ev["code"], ev)

    def test_rc0_without_complete(self):
        self.assertEqual(G.evaluate_doctor(0, "Doctor maintenance deferred")["code"], "doctor-incomplete")

    def test_rc0_suspicious(self):
        ev = G.evaluate_doctor(0, "Preserved retired table x\nDoctor complete.\n")
        self.assertEqual((ev["code"], ev["cls"]), ("doctor-warnings", "acceptable"))

    def test_markers_with_rc1(self):
        cases = {
            "Held agent databases: main": "doctor-held-back",
            "2 agent database(s) held back": "doctor-held-back",
            "Doctor stopped because a state migration refused to continue.": "doctor-migration-refused",
            "Doctor could not enter maintenance mode": "doctor-maintenance-refused",
            "Doctor found plugin load errors": "doctor-plugin-load",
            "config fixes were not applied": "doctor-config-write",
            "Cannot verify pre-migration SQLite backup": "doctor-backup-unverifiable",
            "state database schema migration required": "doctor-incomplete",
            "SQLite integrity check of x timed out after 300s": "doctor-incomplete",
            "Failing check plugin-doctor-state (step-refused)": "doctor-failed",
            "something else entirely": "doctor-failed",
            "provider catalog timed out after 5000ms": "doctor-failed",
        }
        for text, code in cases.items():
            self.assertEqual(G.evaluate_doctor(1, text)["code"], code, text)

    def test_wrapped_clack_box(self):
        text = "│  Doctor stopped     │\n│  because the step refused │\n"
        self.assertEqual(G.evaluate_doctor(1, text)["code"], "doctor-migration-refused")

    def test_exit_codes(self):
        self.assertEqual(G.evaluate_doctor(-9, "")["code"], "doctor-crashed")
        self.assertEqual(G.evaluate_doctor(137, "")["code"], "doctor-crashed")
        self.assertEqual(G.evaluate_doctor(134, "")["code"], "doctor-crashed")
        self.assertEqual(G.evaluate_doctor(143, "")["code"], "doctor-interrupted")
        self.assertEqual(G.evaluate_doctor(2, "Doctor stopped because")["code"], "doctor-invocation")
        self.assertEqual(G.evaluate_doctor(-15, "", timed_out=True)["code"], "doctor-timeout")
        self.assertEqual(G.evaluate_doctor(-15, "", stopping=True)["code"], "interrupted")


class DoctorRunnerTests(GateEnv):
    def gate_for_doctor(self, script, **hooks):
        f = self.bin / "doc.sh"
        f.write_text("#!/bin/sh\n" + script)
        f.chmod(0o755)
        self.hooks(doctor_cmd=[str(f)], **hooks)
        g = G.Gate(emit=lambda s: None)
        g.pkg = C.runtime_package()
        g.j = {"run_id": "r-doc", "mode": "bump", "doctor": [], "history": []}
        g.sizes = {"s_mib": 1}
        return g

    def test_success_and_mirror(self):
        lines = []
        g = self.gate_for_doctor("echo 'token sk-abcdefghijklmnopqrst'; echo 'Doctor complete.'; exit 0")
        g.emit = lines.append
        ev = g.run_doctor_pass(1, "doctor1")
        self.assertIsNone(ev["code"])
        self.assertTrue(any(x.startswith("[doctor] ") for x in lines))
        self.assertFalse(any("sk-abcdefghijklmnopqrst" in x for x in lines))
        self.assertEqual(g.j["doctor"][0]["rc"], 0)
        self.assertTrue((self.upg / "gate" / "runs" / "r-doc" / "doctor-pass1.log").exists())

    def test_each_marker_class_rc1(self):
        for text, code in (("Doctor stopped because x", "doctor-migration-refused"),
                           ("Held agent main", "doctor-held-back"), ("plugin load errors", "doctor-plugin-load"),
                           ("Doctor could not enter maintenance", "doctor-maintenance-refused"),
                           ("config fixes were not applied", "doctor-config-write"),
                           ("backup group is missing", "doctor-backup-unverifiable"),
                           ("schema migration required (audit-events-v2)", "doctor-incomplete"),
                           ("Failing check foo", "doctor-failed")):
            g = self.gate_for_doctor(f"echo '{text}'; exit 1")
            self.assertEqual(g.run_doctor_pass(1, "doctor1")["code"], code)

    def test_rc0_benign_marker_text_passes(self):
        g = self.gate_for_doctor("echo 'Doctor could not prove the responsible config write'; "
                                 "echo 'catalog timed out after 5000ms'; echo 'Doctor complete.'")
        self.assertIsNone(g.run_doctor_pass(1, "doctor1")["code"])

    def test_only_this_attempts_output_is_evaluated(self):
        g = self.gate_for_doctor("echo 'Doctor complete.'")
        log = self.upg / "gate" / "runs" / "r-doc" / "doctor-pass1.log"
        log.parent.mkdir(parents=True)
        log.write_text("Doctor stopped because earlier attempt\n")
        self.assertIsNone(g.run_doctor_pass(1, "doctor1")["code"])

    def test_timeout(self):
        g = self.gate_for_doctor("sleep 30", doctor_timeout_s=1)
        t0 = time.monotonic()
        ev = g.run_doctor_pass(1, "doctor1")
        self.assertEqual(ev["code"], "doctor-timeout")
        self.assertLess(time.monotonic() - t0, 15)

    def test_stop_signal(self):
        g = self.gate_for_doctor("sleep 30")
        threading.Timer(0.5, G.STOP.set).start()
        with self.assertRaises(G.GateStopped):
            g.run_doctor_pass(1, "doctor1")
        self.assertEqual(len(g.j["doctor"]), 1)


# --- space ---------------------------------------------------------------------------------------

class SpaceTests(unittest.TestCase):
    @staticmethod
    def du(free):
        return lambda p: mock.Mock(free=free[p])

    def needs(self):
        return [("/config", "/c", 6 * C.GIB, "low-disk-config"), ("/share", "/s", 3 * C.GIB, "low-disk-share"),
                ("sqlite-tmp", "/t", 2 * C.GIB, "low-disk-tmp")]

    def test_shared_disk_sum(self):
        fs = {"/c": {"dev": 1, "mm": "8:1", "fstype": "ext4"}, "/s": {"dev": 1, "mm": "8:1", "fstype": "ext4"},
              "/t": {"dev": 5, "mm": "0:50", "fstype": "overlay"}}
        free = {"/c": 10 * C.GIB, "/s": 10 * C.GIB, "/t": 40 * C.GIB}
        with mock.patch.object(G, "existing_parent", side_effect=lambda p: p):
            F, summary = G.space_check(self.needs(), disk_usage=self.du(free), fsinfo=lambda p: fs[p])
        self.assertEqual([f["code"] for f in F], ["low-disk-config"])  # 11 GiB > 10 GiB (overlay not distinct)
        self.assertIn("/config+/share+sqlite-tmp need 11.0 GiB have 10.0 GiB", summary)

    def test_distinct_filesystems(self):
        fs = {"/c": {"dev": 1, "mm": "8:1", "fstype": "ext4"}, "/s": {"dev": 2, "mm": "8:2", "fstype": "ext4"},
              "/t": {"dev": 3, "mm": "0:60", "fstype": "tmpfs"}}
        free = {"/c": 7 * C.GIB, "/s": 4 * C.GIB, "/t": 1 * C.GIB}
        with mock.patch.object(G, "existing_parent", side_effect=lambda p: p):
            F, _s = G.space_check(self.needs(), disk_usage=self.du(free), fsinfo=lambda p: fs[p])
        self.assertEqual([f["code"] for f in F], ["low-disk-tmp"])

    def test_proven_distinct(self):
        a = {"dev": 1, "mm": "8:1", "fstype": "ext4"}
        self.assertFalse(G.proven_distinct(a, dict(a)))
        self.assertTrue(G.proven_distinct(a, {"dev": 2, "mm": "8:2", "fstype": "ext4"}))
        self.assertFalse(G.proven_distinct(a, {"dev": 2, "mm": "0:40", "fstype": "overlay"}))
        self.assertFalse(G.proven_distinct(a, {"dev": 2, "mm": "0:41", "fstype": "btrfs"}))
        self.assertTrue(G.proven_distinct(a, {"dev": 2, "mm": "0:42", "fstype": "tmpfs"}))
        self.assertFalse(G.proven_distinct(a, None))

    def test_mountinfo_parse(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write("22 1 8:1 / / rw - ext4 /dev/sda1 rw\n"
                    "30 22 0:50 / /tmp rw - tmpfs tmpfs rw\n")
        try:
            m = G.read_mountinfo(f.name)
            self.assertEqual(m[1], {"mm": "0:50", "mountpoint": "/tmp", "fstype": "tmpfs"})
            ident = G.fs_identity("/tmp", mounts=m)
            self.assertEqual(ident["mm"], "0:50")
        finally:
            os.unlink(f.name)


# --- archive -------------------------------------------------------------------------------------

class ArchiveTests(GateEnv):
    def setUp(self):
        super().setUp()
        make_735_state(self.state)
        self.write_cfg(CFG_735)
        (self.state / "logs").mkdir()
        (self.state / "logs" / "big.log").write_text("x" * 5000)
        (self.state / "tailscale").mkdir()
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(self.state / "tailscale" / "tailscaled.sock"))
        os.symlink("../openclaw.json", self.state / "tailscale" / "link-to-config")
        (self.state / "memory.sqlite-wal").write_bytes(b"wal-bytes")
        (self.ws / "AGENTS.md").write_text("# a\n")
        (self.ws / "node_modules").mkdir()
        (self.ws / "node_modules" / "x.js").write_text("x")
        Path(f"{self.ws}.attested").write_bytes(G.ATTESTATION_HEADER)

    def tearDown(self):
        self.sock.close()
        super().tearDown()

    def gate(self):
        g = G.Gate(emit=lambda s: None)
        g.pkg = C.runtime_package()
        g.cfg = dict(CFG_735)
        g.j = {"run_id": "r-arch", "mode": "from-7x", "history": [], "source": {"config_last_touched": "2026.7.35"},
               "auth_profiles": [{"agent": "main", "id": "openai-codex:default", "provider": "openai-codex",
                                  "type": "oauth", "expires_utc": "2100-01-01T00:00:00Z", "expires_ms": 1}]}
        return g

    def test_archive_create_and_verify(self):
        g = self.gate()
        g.phase_archive()
        a = g.j["archive"]
        adir = Path(a["dir"])
        self.assertEqual(adir, self.share / "openclaw-upgrade" / "r-arch")
        self.assertEqual(stat.S_IMODE(adir.stat().st_mode), 0o700)
        arch = adir / a["file"]
        self.assertRegex(a["file"], r"^openclaw-state-\d{8}-\d{6}-before-2026\.9\.9\.tar\.gz$")
        self.assertEqual(stat.S_IMODE(arch.stat().st_mode), 0o600)
        self.assertEqual(list(adir.glob("*.tmp")), [])
        with tarfile.open(arch) as tf:
            names = set(tf.getnames())
        self.assertIn(".openclaw/state/openclaw.sqlite", names)
        self.assertIn(".openclaw/agents/main/agent/openclaw-agent.sqlite", names)
        self.assertIn(".openclaw/tailscale/link-to-config", names)
        self.assertNotIn(".openclaw/tailscale/tailscaled.sock", names)
        self.assertNotIn(".openclaw/logs/big.log", names)
        self.assertIn("clawd/AGENTS.md", names)
        self.assertNotIn("clawd/node_modules/x.js", names)
        self.assertIn("clawd.attested", names)
        sums = (adir / "SHA256SUMS").read_text().split()
        self.assertEqual(sums, [a["sha256"], a["file"]])
        man = json.loads((adir / "manifest.json").read_text())
        self.assertEqual(man["kind"], "openclaw-addon-pre-migration-archive")
        self.assertEqual(man["archive"]["sha256"], a["sha256"])
        self.assertTrue(man["contains_secrets"])
        self.assertIn(".openclaw/state/openclaw.sqlite", [s["path"] for s in man["sqlite"]])
        self.assertNotIn("SECRET", json.dumps(man))
        self.assertTrue(a["verified"])

    def test_verify_detects_corruption(self):
        g = self.gate()
        g.phase_archive()
        a = g.j["archive"]
        arch = Path(a["dir"]) / a["file"]
        v = G.verify_archive(arch, {".openclaw/state/openclaw.sqlite": "0" * 64})
        self.assertEqual(v["mismatched"], [".openclaw/state/openclaw.sqlite"])
        data = bytearray(arch.read_bytes())
        data[len(data) // 2] ^= 0xFF
        arch.write_bytes(bytes(data))
        with self.assertRaises((OSError, EOFError, tarfile.TarError, ValueError)):
            G.verify_archive(arch, {})

    def test_archive_failure_is_hold(self):
        g = self.gate()
        with mock.patch.object(C, "run_process", return_value=C.RunResult(2, 0.1)):
            with self.assertRaises(G.HoldError) as cm:
                g.phase_archive()
        self.assertEqual(cm.exception.findings[0]["code"], "archive-failed")

    def test_selective_workspace_over_limit(self):
        g = self.gate()
        with mock.patch.object(G, "WORKSPACE_FULL_LIMIT", 10):
            (self.ws / "memory").mkdir()
            (self.ws / "memory" / "m.md").write_text("m")
            (self.ws / "big.bin").write_text("x" * 100)
            ap = g.archive_plan()
        self.assertEqual(ap["workspaces"][0]["mode"], "selective")
        self.assertIn("clawd/AGENTS.md", ap["roots"])
        self.assertIn("clawd/memory", ap["roots"])
        self.assertNotIn("clawd/big.bin", ap["roots"])
        self.assertTrue(any("2 GiB" in w for w in ap["warnings"]))


# --- quarantine ----------------------------------------------------------------------------------

class QuarantineTests(GateEnv):
    def test_moves_and_manifest(self):
        make_735_state(self.state)
        self.write_cfg(CFG_735)
        tg = self.state / "telegram"
        tg.mkdir()
        (tg / "sticker-cache.json").write_text('{"a":1}')
        os.symlink("/etc/hostname", tg / "bot-info-default.json")
        sp = tg / "ingress-spool-default"
        sp.mkdir()
        (sp / "1.json").write_text("{}")
        adir = self.state / "agents" / "main" / "agent"
        (adir / "openclaw-agent.sqlite.memory-reindex-0123abcd-0123-4123-8123-0123456789ab").write_text("x")
        qdir = self.upg / "gate" / "quarantine" / "r-q"
        (qdir / "telegram").mkdir(parents=True)
        (qdir / "telegram" / "sticker-cache.json").write_text("older")
        g = G.Gate(emit=lambda s: None)
        g.pkg = C.runtime_package()
        g.read_config()
        g.j = {"run_id": "r-q", "mode": "from-7x", "history": [], "source": {"from_checkpoint": "2026.7.35"},
               "first_write_at": None}
        g.phase_cleanup()
        self.assertTrue(g.j["first_write_at"])
        man = json.loads((qdir / "MANIFEST.json").read_text())
        kinds = {m["src"]: m["kind"] for m in man}
        self.assertEqual(kinds.get("telegram/sticker-cache.json"), "telegram-cache")
        self.assertEqual(kinds.get("telegram/bot-info-default.json"), "telegram-cache")
        self.assertIn("sqlite-transient", kinds.values())
        self.assertTrue((qdir / "telegram" / "sticker-cache.json.1").exists())  # collision suffix
        self.assertTrue(os.path.islink(qdir / "telegram" / "bot-info-default.json"))  # moved, not followed
        self.assertFalse(os.path.lexists(tg / "bot-info-default.json"))
        self.assertTrue((sp / "1.json").exists())  # ingress spool is left in place
        self.assertEqual(stat.S_IMODE(qdir.stat().st_mode), 0o700)
        sticker = [m for m in man if m["src"] == "telegram/sticker-cache.json"][0]
        self.assertEqual(len(sticker["sha256"]), 64)
        # idempotent re-run: nothing left to move
        g.phase_cleanup()
        self.assertEqual(len(json.loads((qdir / "MANIFEST.json").read_text())), len(man))

    def test_skip_cleanup_kinds_hook(self):
        make_735_state(self.state)
        self.write_cfg(CFG_735)
        (self.state / "telegram").mkdir()
        (self.state / "telegram" / "sticker-cache.json").write_text("{}")
        self.hooks(skip_cleanup_kinds=["telegram-cache"])
        g = G.Gate(emit=lambda s: None)
        g.read_config()
        g.j = {"run_id": "r-q2", "mode": "from-7x", "history": [], "source": {"from_checkpoint": "2026.7.35"}}
        g.phase_cleanup()
        self.assertTrue((self.state / "telegram" / "sticker-cache.json").exists())


# --- hold.txt / retry / processes ------------------------------------------------------------------

class HoldRetryTests(GateEnv):
    def test_hold_text_format(self):
        txt = G.hold_text(RUNTIME, "r1", "precheck",
                          [{"code": "no-network", "cls": "acceptable", "message": "npm unreachable"},
                           {"code": "sqlite-corrupt", "cls": "hard", "message": "bad page"}],
                          "unchanged (nothing written yet)", "fix it")
        lines = txt.splitlines()
        self.assertEqual(lines[0], "OpenClaw is held (bundled runtime 2026.9.9) — migration gate run r1, phase precheck")
        self.assertEqual(lines[1], "Reason [no-network]: npm unreachable")
        self.assertEqual(lines[2], "Reason [sqlite-corrupt]: bad page")
        self.assertEqual(lines[3], "State: unchanged (nothing written yet)")
        self.assertEqual(lines[4], "Next: fix it")
        self.assertEqual(lines[5], "Accept (only if you understand the consequence): oc-upgrade retry --accept no-network")
        self.assertEqual(lines[6], "Details: oc-upgrade status | oc-upgrade log")

    def write_journal(self, j):
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "journal.json").write_text(json.dumps(j))

    def retry(self, *args):
        lines = []
        rc = G.retry_cmd(list(args), emit=lines.append)
        self.out = "\n".join(lines)
        return rc

    def test_retry_rules(self):
        self.assertEqual(self.retry(), 1)  # nothing to retry
        self.write_journal({"run_id": "r1", "status": "hold", "hold": {
            "code": "no-network", "codes": ["no-network", "sqlite-corrupt"],
            "findings": [{"code": "no-network", "cls": "acceptable"}, {"code": "sqlite-corrupt", "cls": "hard"}]}})
        self.assertEqual(self.retry("--accept", "sqlite-corrupt"), 1)
        self.assertEqual(self.retry("--accept", "bogus"), 1)
        self.assertEqual(self.retry("--accept", "no-network"), 0)
        req = json.loads((self.upg / "gate" / "retry-request.json").read_text())
        self.assertEqual((req["doctor"], req["accept"]), (False, ["no-network"]))
        self.assertEqual(self.retry("--doctor", "--accept=pc-probe"), 0)
        req = json.loads((self.upg / "gate" / "retry-request.json").read_text())
        self.assertEqual((req["doctor"], req["accept"]), (True, ["no-network", "pc-probe"]))
        self.assertEqual(self.retry("--cancel"), 0)
        self.assertFalse((self.upg / "gate" / "retry-request.json").exists())

    def test_retry_refuses_newer_and_foreign_holds(self):
        self.write_journal({"run_id": "r1", "status": "hold", "hold": {"code": "newer-state", "codes": ["newer-state"]}})
        self.assertEqual(self.retry(), 1)
        self.write_journal({"run_id": "r1", "status": "done"})
        (self.upg / "hold.txt").write_text("OpenClaw is held (bundled runtime 2026.9.9):\nstate is newer\n")
        self.assertEqual(self.retry(), 1)
        self.assertIn("not a migration-gate hold", self.out)
        os.remove(self.upg / "hold.txt")
        self.assertEqual(self.retry(), 1)
        self.assertEqual(self.retry("--doctor"), 0)  # maintenance request after done

    def test_retry_for_plan_sticky_hold(self):
        self.write_journal({"run_id": "r1", "status": "interrupted", "auto_resumes": 1})
        self.assertEqual(self.retry(), 0)

    def test_hold_after_start(self):
        make_99_state(self.state)
        self.write_cfg({"meta": {"lastTouchedVersion": RUNTIME}})
        self.write_journal({"schema": 1, "run_id": "r1", "mode": "from-7x", "status": "done", "phases_done": [],
                            "history": []})
        rc = self.quiet(G.hold_after_start, "exit78", None, emit=print)
        self.assertEqual(rc, 0)
        j = self.journal()
        self.assertEqual((j["status"], j["hold"]["code"], j["hold"]["sub"]), ("hold", "exit78", "ok"))
        txt = (self.upg / "hold.txt").read_text()
        self.assertIn("migrated (gateway refused to start)", txt)
        self.assertIn("oc-upgrade retry --doctor", txt)  # B15
        self.assertIn("[gate] HOLD exit78 in gateway:", self.out)
        self.assertEqual(self.quiet(G.hold_after_start, "crash-loop", 1, emit=print), 0)
        self.assertEqual(self.journal()["hold"]["code"], "crash-loop")

    def test_find_openclaw_processes(self):
        proc = self.tmp / "proc"

        def add(pid, argv, ppid=1):
            d = proc / str(pid)
            d.mkdir(parents=True)
            (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
            (d / "stat").write_text(f"{pid} (x y) S {ppid} 0 0")
        add(10, ["node", "/usr/local/lib/node_modules/openclaw/openclaw.mjs", "gateway", "run"])
        add(11, ["openclaw-gateway"])
        add(12, ["/bin/bash", "/run.sh"])
        add(13, ["python3", "/usr/local/bin/oc-upgrade", "gate"])
        add(14, ["node", "/usr/local/lib/node_modules/openclaw/openclaw.mjs", "doctor"], ppid=13)
        add(15, ["node", "/usr/local/lib/node_modules/openclaw/openclaw.mjs", "gateway", "call", "health",
                 "--token", "SECRET-TOKEN-VALUE"])
        add(16, ["openclaw", "--token=SECRET-TOKEN-VALUE", "status"])
        found = G.find_openclaw_processes("/usr/local/lib/node_modules/openclaw/openclaw.mjs", proc_dir=str(proc),
                                          self_pid=13)
        self.assertEqual([f["pid"] for f in found], [10, 11, 15, 16])
        # F13: argv[0..2] only, redacted
        cmds = {f["pid"]: f["cmd"] for f in found}
        self.assertEqual(cmds[15], "node /usr/local/lib/node_modules/openclaw/openclaw.mjs gateway")
        self.assertEqual(cmds[16], "openclaw --token=*** status")
        self.assertNotIn("SECRET", json.dumps(found))


# --- full gate runs (fake node + fake doctor + real oc_migrate) -------------------------------------

class GateRunTests(GateEnv):
    def test_from_7x_happy_path_then_second_boot(self):
        self.build_735()
        self.hooks()
        rc = self.run_gate()
        self.assertEqual(rc, 0, self.out)
        self.assertIn("[gate] done: MIGRATED 2026.9.9", self.out)
        for n in range(1, 10):
            self.assertIn(f"[gate] {n}/9 ", self.out)
        self.assertNotIn("SECRET", self.out)
        j = self.journal()
        self.assertEqual((j["status"], j["mode"]), ("done", "from-7x"))
        self.assertEqual(j["phases_done"], list(G.PHASES))
        m = json.loads((self.upg / "gate" / "migrated.json").read_text())
        self.assertEqual((m["runtime"], m["mode"]), (RUNTIME, "from-7x"))
        cfg = json.loads((self.state / "openclaw.json").read_text())
        self.assertNotIn("openai-codex/", json.dumps(cfg))
        self.assertEqual(cfg["agents"]["defaults"]["models"]["openai/gpt-5.5"]["agentRuntime"]["id"], "openclaw")
        self.assertIn("vllm/qwen3.5-122b", cfg["agents"]["defaults"]["models"])  # untouched
        sess = json.loads((self.state / "agents/main/sessions/sessions.json").read_text())
        self.assertEqual(sess["agent:main:main"]["agentRuntimeOverride"], "openclaw")
        self.assertNotIn("agentRuntimeOverride", sess["agent:main:x"])
        rd = self.upg / "gate" / "runs" / j["run_id"]
        for f in ("config.pre-gate.json", "config.pre-pass1.json", "config.post-pass1.json", "transform-ledger.json",
                  "doctor-pass1.log", "doctor-pass2.log", "events.log"):
            self.assertTrue((rd / f).exists(), f)
        self.assertEqual(stat.S_IMODE((rd / "config.pre-gate.json").stat().st_mode), 0o600)
        self.assertNotIn("SECRET", (rd / "transform-ledger.json").read_text())
        led = json.loads((self.upg / "gate" / "pins-ledger.json").read_text())
        self.assertGreater(len(led["entries"]), 10)
        self.assertFalse((self.upg / "hold.txt").exists())
        # second boot: nothing to do
        d = self.plan()
        self.assertEqual(d["rc"], 0, self.out)
        self.assertIn("migrated (from-7x", self.out)

    def test_precheck_hold_leaves_state_unchanged_then_accept(self):
        self.build_735()
        self.hooks(skip_network_check=False)
        with mock.patch.object(G.shutil, "which", side_effect=which_without_npm):
            before = (self.state / "openclaw.json").read_bytes()
            self.assertEqual(self.run_gate(), 20, self.out)
        self.assertIn("[gate] HOLD no-network in precheck:", self.out)
        self.assertIn("[gate] next:", self.out)
        self.assertEqual((self.state / "openclaw.json").read_bytes(), before)
        self.assertFalse((self.share / "openclaw-upgrade").exists())
        txt = (self.upg / "hold.txt").read_text()
        self.assertIn("State: unchanged (nothing written yet)", txt)
        self.assertEqual(self.plan()["rc"], 11)
        self.assertEqual(G.retry_cmd(["--accept", "no-network"], emit=lambda s: None), 0)
        self.assertEqual(self.plan()["rc"], 10)
        with mock.patch.object(G.shutil, "which", side_effect=which_without_npm):
            rc = self.run_gate()
        self.assertEqual(rc, 0, self.out)
        self.assertIn("WARN [gate] accepted no-network", self.out)

    def test_doctor_failure_hold_and_retry_resumes_doctor(self):
        self.build_735()
        bad = self.bin / "bad-doctor"
        bad.write_text("#!/bin/sh\necho 'Doctor stopped because a state migration refused to continue.'\nexit 1\n")
        bad.chmod(0o755)
        self.hooks(doctor_cmd=[str(bad)])
        self.assertEqual(self.run_gate(), 20)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["phase"]), ("doctor-migration-refused", "doctor1"))
        self.assertIn("partially migrated (doctor started)", (self.upg / "hold.txt").read_text())
        archive_file = j["archive"]["file"]
        self.hooks()
        G.retry_cmd([], emit=lambda s: None)
        rc = self.run_gate()
        self.assertEqual(rc, 0, self.out)
        j = self.journal()
        self.assertEqual(j["archive"]["file"], archive_file)  # never retaken after the first write
        self.assertEqual(len(list((self.share / "openclaw-upgrade").glob("*/*.tar.gz"))), 1)

    def test_interrupt_resume_once_then_interrupted_twice(self):
        self.build_735()
        slow = self.bin / "slow-doctor"
        slow.write_text("#!/bin/sh\nsleep 30\n")
        slow.chmod(0o755)
        self.hooks(doctor_cmd=[str(slow)])
        threading.Timer(3.0, lambda: os.kill(os.getpid(), 15)).start()
        rc = self.run_gate()
        self.assertEqual(rc, 143, self.out)
        j = self.journal()
        self.assertEqual((j["status"], j["phase"]), ("interrupted", "doctor1"))
        d = self.plan()
        self.assertEqual((d["rc"], d["action"]), (10, "resume"))
        G.STOP.clear()
        threading.Timer(3.0, lambda: os.kill(os.getpid(), 15)).start()
        self.assertEqual(self.run_gate(), 143)
        self.assertEqual(self.journal()["auto_resumes"], 1)
        d = self.plan()
        self.assertEqual((d["rc"], d["hold"]["code"]), (11, "interrupted-twice"))
        self.assertIn("interrupted-twice", (self.upg / "hold.txt").read_text())
        G.STOP.clear()
        self.hooks()
        self.assertEqual(G.retry_cmd([], emit=lambda s: None), 0)
        self.assertEqual(self.run_gate(), 0, self.out)

    def test_internal_error_hold_and_resume_at_phase(self):
        self.build_735()
        self.hooks(raise_in_phase="fixups")
        self.assertEqual(self.run_gate(), 1)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["phase"]), ("internal-error", "fixups"))
        rd = self.upg / "gate" / "runs" / j["run_id"]
        self.assertIn("Traceback", (rd / "events.log").read_text())
        self.hooks()
        G.retry_cmd([], emit=lambda s: None)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("resume: generic checks only", self.out)  # B2: no from-7x prechecks after the first write
        self.assertIn("openai-codex/*", (rd / "config.pre-gate.json").read_text())  # B2: write-once
        self.assertEqual(self.journal()["doctor"][-1]["pass"], 2)  # pass 1 not repeated
        self.assertEqual(sum(1 for d in self.journal()["doctor"] if d["pass"] == 1), 1)

    def test_postcondition_policy_hold_and_accept(self):
        self.build_735()
        self.hooks()
        os.environ["FAKE_OC_MODE"] = "lint-legacy"
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["hold"]["acceptable"]), ("pc-legacy-state", True))  # B4a: policy
        G.retry_cmd(["--accept", "pc-legacy-state"], emit=lambda s: None)
        self.assertEqual(self.run_gate(), 0, self.out)

    def test_bump_mode_skips_from7x_phases(self):
        make_99_state(self.state)
        self.write_cfg({"meta": {"lastTouchedVersion": RUNTIME}, "gateway": {"mode": "local"}})
        (self.upg / "gate").mkdir(parents=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.5", "mode": "from-7x"}))
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertEqual(j["mode"], "bump")
        self.assertNotIn("premigrate", j["phases_done"])
        self.assertNotIn("pins", j["phases_done"])
        self.assertFalse((self.upg / "gate" / "pins-ledger.json").exists())
        # B4 guard: the same runtime on the same state never bumps twice
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute("CREATE TABLE cron_run_logs (id INTEGER)")
        con.commit()
        con.close()
        d = self.plan()
        self.assertEqual((d["rc"], d["hold"]["code"]), (11, "bump-repeat"))

    def test_gate_refuses_without_runsh_and_deletes_stale_hold(self):
        make_99_state(self.state)
        self.write_cfg({"meta": {"lastTouchedVersion": RUNTIME}})
        (self.upg / "hold.txt").write_text("stale")
        self.assertEqual(self.run_gate(), 0)
        self.assertFalse((self.upg / "hold.txt").exists())  # B16


class GateRunMoreTests(GateEnv):
    def test_fixups_invalid_restores_post_pass1(self):
        self.build_735()
        self.hooks()
        os.environ["FAKE_OC_MODE"] = "invalid-config"
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["phase"]), ("fixups-invalid", "fixups"))
        rd = self.upg / "gate" / "runs" / j["run_id"]
        self.assertEqual((self.state / "openclaw.json").read_bytes(), (rd / "config.post-pass1.json").read_bytes())

    def test_not_idempotent_runs_pass3_then_accept(self):
        self.build_735()
        flappy = self.bin / "flappy-doctor"
        flappy.write_text(FAKE_DOCTOR + "\nimport time\ncfg = json.load(open(cfgp))\ncfg['x'] = time.time_ns()\n"
                          "open(cfgp, 'w').write(json.dumps(cfg))\n")
        flappy.chmod(0o755)
        self.hooks(doctor_cmd=[str(flappy)])
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual(j["hold"]["code"], "doctor-not-idempotent")
        self.assertEqual([d["pass"] for d in j["doctor"]], [1, 2, 3])
        self.assertIn("doctor2", j["phases_done"])
        G.retry_cmd(["--accept", "doctor-not-idempotent"], emit=lambda s: None)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual([d["pass"] for d in self.journal()["doctor"]], [1, 2, 3])  # not re-run

    def test_maintenance_run_after_migration(self):
        self.build_735()
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        first = self.journal()["run_id"]
        self.assertEqual(G.retry_cmd(["--doctor"], emit=lambda s: None), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertNotEqual(j["run_id"], first)
        self.assertEqual(j["mode"], "maintenance")
        self.assertNotIn("pins", j["phases_done"])
        self.assertTrue((self.upg / "gate" / "runs" / first / "journal.json").exists())
        self.assertEqual(len(list((self.share / "openclaw-upgrade").glob("*/*.tar.gz"))), 2)

    def test_B19_new_from7x_run_resets_pins_ledger(self):
        self.build_735()
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        n1 = len(json.loads((self.upg / "gate" / "pins-ledger.json").read_text())["entries"])
        # rollback: restore a 7.35 state and config
        shutil.rmtree(self.state)
        self.state.mkdir()
        self.build_735()
        self.assertEqual(self.run_gate(), 0, self.out)
        led = json.loads((self.upg / "gate" / "pins-ledger.json").read_text())
        self.assertEqual(len(led["entries"]), n1)
        self.assertEqual(len(list((self.upg / "gate").glob("pins-ledger.*.json"))), 1)

    def test_openclaw_running_is_hard_hold(self):
        self.build_735()
        self.hooks()
        with mock.patch.object(G, "find_openclaw_processes", return_value=[{"pid": 42, "cmd": "openclaw-gateway"}]):
            self.assertEqual(self.run_gate(), 20)
        self.assertEqual(self.journal()["hold"]["code"], "openclaw-running")

    def test_not_pre_journal_is_hard_hold(self):
        self.build_735()
        self.hooks()
        con = sqlite3.connect(str(self.state / "state" / "openclaw.sqlite"))
        con.execute("CREATE TABLE agent_deletion_journal (x)")
        con.commit()
        con.close()
        self.assertEqual(self.run_gate(), 20)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["hold"]["acceptable"]), ("not-pre-journal", False))
        self.assertIsNone(j["first_write_at"])
        self.assertEqual(G.retry_cmd(["--accept", "not-pre-journal"], emit=lambda s: None), 1)

    def test_legacy_state_dir_hold(self):
        self.build_735()
        self.hooks()
        (self.root / ".clawdbot").mkdir()
        (self.root / ".clawdbot" / "x").write_text("1")
        self.assertEqual(self.run_gate(), 20)
        self.assertIn("legacy-state-dir", self.journal()["hold"]["codes"])


class GateAddendum2Tests(GateEnv):
    """Contract addendum 2: retired-model replacements, codex plugin rule 4/6, plan lines not repeated."""

    RETIRING = FAKE_DOCTOR + r"""
# doctor 9.9 online: retired openai/gpt-5.4-mini -> openai/gpt-5.6-luna in every value slot; with legacy
# refs in the config (pass 1) the Codex route repair also deletes compaction.model
cfg = json.load(open(cfgp, encoding="utf-8"))
lines = []
if "openai-codex/" in text:
    comp = cfg.get("agents", {}).get("defaults", {}).get("compaction")
    if isinstance(comp, dict) and comp.pop("model", None) is not None:
        lines.append("Removed agents.defaults.compaction.model; Codex runtime uses native server-side compaction.")
def walk(node, path):
    if isinstance(node, dict):
        for k in list(node):
            if isinstance(node[k], str) and node[k] == "openai/gpt-5.4-mini" and "modelPolicy" not in path:
                node[k] = "openai/gpt-5.6-luna"
                lines.append('Replaced retired %s "openai/gpt-5.4-mini" with "openai/gpt-5.6-luna".' % ".".join(path + [k]))
            else:
                walk(node[k], path + [k])
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if v == "openai/gpt-5.4-mini" and "modelPolicy" not in path:
                node[i] = "openai/gpt-5.6-luna"
                lines.append('Replaced retired %s "openai/gpt-5.4-mini" with "openai/gpt-5.6-luna".' % ".".join(path + [str(i)]))
            else:
                walk(v, path + [str(i)])
walk(cfg, [])
if lines:
    open(cfgp, "w", encoding="utf-8").write(json.dumps(cfg, indent=2) + "\n")
    print("◇  Doctor changes ───╮")
    for l in lines:
        # clack wraps long lines inside the box at a word boundary
        cut = l.rfind(" ", 0, 60) if len(l) > 60 else len(l)
        print("│  " + l[:cut] + "  │")
        if l[cut:].strip():
            print("│  " + l[cut:].strip() + "  │")
if os.environ.get("FAKE_CODEX_PKG") == "1":
    os.makedirs(os.path.join(state, "npm", "projects", "openclaw-codex-0123abcd"), exist_ok=True)
print("Doctor complete.")
"""

    def build_retiring(self):
        make_735_state(self.state)
        cfg = json.loads(json.dumps(CFG_735))
        d = cfg["agents"]["defaults"]
        d["model"]["fallbacks"] = ["openai-codex/gpt-5.4-mini", "vllm/qwen3.5-122b"]
        d["heartbeat"] = {"model": "openai-codex/gpt-5.4-mini"}
        d["compaction"] = {"model": "openai-codex/gpt-5.4-mini"}
        self.write_cfg(cfg)
        (self.ws / "AGENTS.md").write_text("# agents\n")
        doc = self.bin / "retiring-doctor"
        doc.write_text(self.RETIRING)
        doc.chmod(0o755)
        self.hooks(doctor_cmd=[str(doc)])

    def test_retired_models_followed_no_hold_no_pass3(self):
        """Harness T1/T3: PC3 accepts doctor's successor, F3 restores compaction.model as the successor,
        so pass 2 leaves openclaw.json unchanged (no pass 3)."""
        self.build_retiring()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("[gate] done: MIGRATED", self.out)
        self.assertIn("config unchanged", self.out)
        self.assertNotIn("doctor pass 3", self.out)
        j = self.journal()
        self.assertEqual([x["pass"] for x in j["doctor"]], [1, 2])
        self.assertEqual(j["doctor_retired_map"], {"openai/gpt-5.4-mini": "openai/gpt-5.6-luna"})
        cfg = json.loads((self.state / "openclaw.json").read_text())
        d = cfg["agents"]["defaults"]
        self.assertEqual(d["compaction"]["model"], "openai/gpt-5.6-luna")
        self.assertEqual(d["heartbeat"]["model"], "openai/gpt-5.6-luna")
        self.assertEqual(d["model"]["fallbacks"], ["openai/gpt-5.6-luna", "vllm/qwen3.5-122b"])
        self.assertEqual(d["models"]["openai/gpt-5.6-luna"]["agentRuntime"]["id"], "openclaw")
        self.assertIn("[gate] info: doctor replaced retired model openai/gpt-5.4-mini with openai/gpt-5.6-luna",
                      self.out)
        ledger = json.loads((self.upg / "gate" / "runs" / j["run_id"] / "transform-ledger.json").read_text())
        f3 = [e for e in ledger if e["step"] == "F3"]
        self.assertEqual([(e["path"], e["after"]) for e in f3],
                         [("agents.defaults.compaction.model", "openai/gpt-5.6-luna")])

    def test_codex_package_warning_only_when_kept_disabled(self):
        self.build_retiring()
        os.environ["FAKE_CODEX_PKG"] = "1"
        try:
            self.assertEqual(self.run_gate(), 0, self.out)
        finally:
            os.environ.pop("FAKE_CODEX_PKG", None)
        self.assertIn("WARN [gate] doctor installed @openclaw/codex but the add-on keeps it disabled", self.out)
        self.assertFalse(self.journal()["fixups"]["codex_needed"])

    def test_codex_package_before_keeps_doctor_setting(self):
        self.build_retiring()
        (self.state / "npm" / "projects" / "openclaw-codex-old").mkdir(parents=True)
        os.environ["FAKE_CODEX_PKG"] = "1"
        try:
            self.assertEqual(self.run_gate(), 0, self.out)
        finally:
            os.environ.pop("FAKE_CODEX_PKG", None)
        self.assertNotIn("keeps it disabled", self.out)
        self.assertIn("[gate] 7/9 info: doctor installed the @openclaw/codex plugin", self.out)
        self.assertIn("codex plugin entry restored: no (Codex was in use before the migration", self.out)
        self.assertTrue(self.journal()["fixups"]["codex_needed"])

    def test_codex_cron_ids(self):
        """F1/PC2 input: openai-codex ids used by 7.x cron jobs (doctor pins them for cron intent)."""
        make_735_state(self.state, with_cron_codex=True)
        db = self.state / "state" / "openclaw.sqlite"
        c = sqlite3.connect(str(db))
        c.execute("INSERT INTO cron_jobs VALUES ('j2','vllm/qwen3.5-122b',?)",
                  (json.dumps(["openai-codex/gpt-5.5", "openai-codex/*", "vllm/x"]),))
        c.execute("INSERT INTO cron_jobs VALUES ('j3','anthropic/claude-sonnet-4-6',NULL)")
        c.commit()
        c.close()
        self.assertEqual(G.codex_cron_ids(db), (2, ["gpt-5.4-mini", "gpt-5.5"]))
        self.assertEqual(G.codex_cron_ids(self.state / "missing.sqlite"), (0, []))
        self.write_cfg(CFG_735)
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual(self.journal()["cron_legacy_ids"], ["gpt-5.4-mini", "gpt-5.5"])
        self.assertIn("2 cron job(s) use openai-codex models", self.out)

    def test_spool_info_printed_once(self):
        """Harness finding 4: the Telegram ingress spool line appeared twice in from-7x runs."""
        self.build_735()
        self.hooks()
        sp = self.state / "telegram" / "ingress-spool-default"
        sp.mkdir(parents=True)
        (sp / "1.json").write_text("{}")
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual(sum(1 for x in self.out.splitlines() if "undelivered legacy Telegram update" in x), 1,
                         self.out)

    def test_gate_run_does_not_repeat_plan_lines(self):
        """Addendum 2 item 11: run.sh prints `gate --plan`; the gate run must not print it again."""
        self.build_735()
        self.hooks()
        d = self.plan()
        self.assertEqual(d["rc"], 10)
        plan_lines = self.out
        self.assertIn("[gate] plan:", plan_lines)
        os.environ["OC_GATE_PLAN_SHOWN"] = plan_lines
        try:
            self.assertEqual(self.run_gate(), 0, self.out)
        finally:
            os.environ.pop("OC_GATE_PLAN_SHOWN", None)
        self.assertNotIn("[gate] plan:", self.out)
        self.assertIn("[gate] done: MIGRATED", self.out)

    def test_gate_run_prints_a_changed_plan(self):
        self.build_735()
        self.hooks()
        os.environ["OC_GATE_PLAN_SHOWN"] = "[gate] plan: something else -> gate run"
        try:
            self.assertEqual(self.run_gate(), 0, self.out)
        finally:
            os.environ.pop("OC_GATE_PLAN_SHOWN", None)
        self.assertEqual(sum(1 for x in self.out.splitlines() if x.startswith("[gate] plan:")), 1, self.out)


class ReviewFixTests(GateEnv):
    """Stage B review fixes: F1 symlinked archive roots, F4 pins retry, F5 lone surrogates, F15 cron."""

    @staticmethod
    def move_aside(path, dest):
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.rename(path, dest)
        os.symlink(dest, path)

    def test_F1_state_symlinks_at_every_level(self):
        make_735_state(self.state)
        cls = G.classify(self.state, {}, 19, 24, RUNTIME)
        self.assertEqual(G.state_symlinks(self.state, cls), [])
        for rel in ("state", "state/openclaw.sqlite", "agents", "agents/main", "agents/main/agent",
                    "agents/main/agent/openclaw-agent.sqlite"):
            src, dst = self.state / rel, self.tmp / "moved" / rel.replace("/", "_")
            self.move_aside(src, dst)
            try:
                with self.subTest(rel=rel):
                    self.assertEqual(G.state_symlinks(self.state, cls), [str(src)])
            finally:
                os.unlink(src)
                os.rename(dst, src)
        self.move_aside(self.state, self.tmp / "big-disk" / ".openclaw")
        self.assertEqual(G.state_symlinks(self.state, cls), [str(self.state)])

    def test_F1_symlinked_agent_dir_holds_before_anything_is_written(self):
        """Reviewer repro symstate.py: a symlinked directory gave a 'verified' archive without the DBs."""
        self.build_735()
        self.hooks()
        adir = self.state / "agents" / "main" / "agent"
        self.move_aside(adir, self.tmp / "media" / "agent")
        self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertEqual((j["hold"]["code"], j["hold"]["acceptable"], j["first_write_at"]),
                         ("state-symlink", False, None))
        self.assertIn(str(adir), j["hold"]["message"])
        self.assertIn("replace the symlink by the real directory", (self.upg / "hold.txt").read_text())
        self.assertFalse((self.share / "openclaw-upgrade").exists())
        self.assertEqual(G.retry_cmd(["--accept", "state-symlink"], emit=lambda s: None), 1)

    def test_F1_symlinked_workspace_holds(self):
        """Reviewer repro archive_test.py: only the link of a symlinked workspace was archived."""
        self.build_735()
        self.hooks()
        ext = self.tmp / "elsewhere" / "ws2"
        (ext / "memory").mkdir(parents=True)
        (ext / "memory" / "notes.md").write_text("important")
        os.symlink(ext, self.root / "clawd-helper")
        cfg = json.loads(json.dumps(CFG_735))
        cfg["agents"]["list"].append({"id": "helper", "workspace": str(self.root / "clawd-helper")})
        self.write_cfg(cfg)
        self.assertEqual(self.run_gate(), 20, self.out)
        h = self.journal()["hold"]
        self.assertEqual(h["code"], "state-symlink")
        self.assertIn("clawd-helper", h["message"])
        # a link whose target is archived anyway (another workspace root, the state dir) is fine
        os.unlink(self.root / "clawd-helper")
        os.symlink(self.ws, self.root / "clawd-helper")
        (self.state / "workspace-ops").mkdir()
        os.symlink(self.state / "workspace-ops", self.root / "ws-ops")
        cfg["agents"]["list"].append({"id": "ops", "workspace": str(self.root / "ws-ops")})
        g = G.Gate(emit=lambda s: None)
        g.cfg = cfg
        ap = g.archive_plan()
        self.assertEqual(ap["symlinks"], [])
        self.assertEqual(ap["roots"][:2], [".openclaw", "clawd"])

    def gate_for_archive(self, run_id):
        g = G.Gate(emit=lambda s: None)
        g.pkg = C.runtime_package()
        g.cfg = json.loads(json.dumps(CFG_735))
        g.j = {"run_id": run_id, "mode": "from-7x", "history": [], "source": {}, "auth_profiles": []}
        return g

    def test_F1_archive_invariant_every_known_db_is_archived(self):
        make_735_state(self.state)
        self.write_cfg(CFG_735)
        self.move_aside(self.state / "agents" / "main" / "agent", self.tmp / "media" / "agent")
        g = self.gate_for_archive("r-inv")  # the precheck is bypassed: the archive phase refuses by itself
        with self.assertRaises(G.HoldError) as cm:
            g.phase_archive()
        f = cm.exception.findings[0]
        self.assertEqual(f["code"], "archive-verify-failed")
        self.assertIn(".openclaw/agents/main/agent/openclaw-agent.sqlite", f["message"])
        self.assertIsNone(g.j.get("archive"))
        self.assertEqual(list((self.share / "openclaw-upgrade" / "r-inv").glob("*.tar.gz*")), [])

    def test_F1_archive_invariant_after_verification(self):
        make_735_state(self.state)
        self.write_cfg(CFG_735)
        g = self.gate_for_archive("r-inv2")
        real_verify = G.verify_archive

        def drop_agent_db(path, expected, stop=None):
            v = real_verify(path, expected, stop)
            v["matched"] = [m for m in v["matched"] if "/agents/" not in m]
            return v
        with mock.patch.object(G, "verify_archive", side_effect=drop_agent_db):
            with self.assertRaises(G.HoldError) as cm:
                g.phase_archive()
        self.assertEqual(cm.exception.findings[0]["code"], "archive-verify-failed")
        self.assertIn("agents/main/agent/openclaw-agent.sqlite", cm.exception.findings[0]["message"])
        self.assertEqual(list((self.share / "openclaw-upgrade" / "r-inv2").glob("*.tar.gz*")), [])

    def test_F4_pins_retry_applies_pins_to_the_current_config(self):
        """Reviewer repro pins_stale.py: the retry used the first attempt's snapshot."""
        cfgp = self.state / "openclaw.json"
        self.write_cfg({"channels": {"telegram": {"streaming": "on"}}, "gateway": {"mode": "local"}})
        g = G.Gate(emit=lambda s: None)
        g.pkg = C.runtime_package()
        g.j = {"run_id": "r-pins", "mode": "from-7x", "history": []}
        G.ensure_dirs()
        answers = iter([(False, "rc 1: channels.telegram.streaming invalid"), (True, "rc 0")])
        with mock.patch.object(g, "config_validate", side_effect=lambda tag: next(answers)):
            with self.assertRaises(G.HoldError) as cm:
                g.phase_pins()
            self.assertEqual(cm.exception.findings[0]["code"], "pins-invalid")
            self.assertEqual(json.loads(cfgp.read_text())["channels"]["telegram"]["streaming"], "on")  # restored
            cur = json.loads(cfgp.read_text())
            cur["channels"]["telegram"]["streaming"] = {"mode": "partial"}
            cur["userFix"] = True
            cfgp.write_text(json.dumps(cur))
            g.phase_pins()
        final = json.loads(cfgp.read_text())
        self.assertTrue(final["userFix"])
        self.assertEqual(final["channels"]["telegram"]["streaming"]["mode"], "partial")
        self.assertEqual(final["agents"]["defaults"]["maxConcurrent"], 4)
        pre = json.loads((self.upg / "gate" / "runs" / "r-pins" / "config.pre-pins.json").read_text())
        self.assertTrue(pre["userFix"])

    def test_F5_lone_surrogates_in_config_and_sessions(self):
        """Reviewer repro surrogate.py: Node writes "\\ud83d" for a label cut mid-emoji."""
        self.build_735()
        cfg = json.loads(json.dumps(CFG_735))
        cfg["ui"] = {"assistant": {"name": "Volt \ud83d"}}
        self.write_cfg(cfg)
        sp = self.state / "agents" / "main" / "sessions" / "sessions.json"
        store = json.loads(sp.read_text())
        store["agent:main:main"]["label"] = "Hallo \ud83d"
        sp.write_text(json.dumps(store))
        # 9.9 (Node's JSON.stringify) writes lone surrogates as \\u escapes too
        doc = self.bin / "ascii-doctor"
        doc.write_text(FAKE_DOCTOR.replace("ensure_ascii=False", "ensure_ascii=True"))
        doc.chmod(0o755)
        self.hooks(doctor_cmd=[str(doc)])
        self.assertEqual(self.run_gate(), 0, self.out)
        new = json.loads((self.state / "openclaw.json").read_bytes().decode("utf-8"))
        self.assertEqual(new["ui"]["assistant"]["name"], "Volt \ud83d")
        sess = json.loads(sp.read_bytes().decode("utf-8"))
        self.assertEqual((sess["agent:main:main"]["agentRuntimeOverride"], sess["agent:main:main"]["label"]),
                         ("openclaw", "Hallo \ud83d"))

    def test_F5_premigrate_value_error_is_premigrate_failed(self):
        self.build_735()
        cfg = json.loads(json.dumps(CFG_735))
        cfg["agents"]["defaults"]["models"] = ["openai-codex/gpt-5.5"]  # not an object: R2 cannot pin
        self.write_cfg(cfg)
        self.hooks()
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertEqual(self.journal()["hold"]["code"], "premigrate-failed")

    def test_F15_cron_jobs_on_openai_models_mean_codex_in_use(self):
        make_735_state(self.state)
        db = self.state / "state" / "openclaw.sqlite"
        c = sqlite3.connect(str(db))
        c.execute("INSERT INTO cron_jobs VALUES ('j1','openai/gpt-5.5',NULL)")
        c.execute("INSERT INTO cron_jobs VALUES ('j2','vllm/q',?)", (json.dumps(["OpenAI/gpt-5.4-mini"]),))
        c.execute("INSERT INTO cron_jobs VALUES ('j3','openai-codex/gpt-5.4',NULL)")
        c.commit()
        c.close()
        self.assertEqual(G.codex_cron_ids(db, "openai")[1], ["gpt-5.4-mini", "gpt-5.5"])
        self.assertEqual(G.codex_cron_ids(db)[1], ["gpt-5.4"])
        g = G.Gate(emit=lambda s: None)
        g.j = {"plugins_before": [], "cron_openai_ids": []}
        self.assertFalse(g.codex_pkg_before())
        g.j["cron_openai_ids"] = ["gpt-5.5"]
        self.assertTrue(g.codex_pkg_before())
        self.write_cfg(CFG_735)
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertEqual(j["cron_openai_ids"], ["gpt-5.4-mini", "gpt-5.5"])
        self.assertTrue(j["fixups"]["codex_needed"])


class DryRunTests(GateEnv):
    def test_dry_run_is_read_only(self):
        self.build_735()
        self.hooks()
        before = {str(p): p.stat().st_mtime_ns for p in self.root.rglob("*") if p.is_file()}
        lines = []
        rc = G.dry_run(network=False, emit=lines.append)
        out = "\n".join(lines)
        self.assertIn(rc, (0, 20), out)
        self.assertIn("a gate would run in mode from-7x", out)
        self.assertIn("pre-migrate:", out)
        after = {str(p): p.stat().st_mtime_ns for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertFalse((self.upg / "gate" / "journal.json").exists())


class CodexAllowedPostconditionTests(unittest.TestCase):
    """Harness TU: on the live-like install Codex runs canonical openai/* routes already on 7.35."""

    ROUTES = {"auth": {"runtimeAuthRoutes": [{"provider": "openai", "runtime": "codex",
                                                 "authProvider": "openai", "status": "indeterminate"}],
                       "modelRouteIssues": [], "missingProvidersInUse": []}}

    def test_models_status_codex_route_fails_when_codex_was_not_in_use(self):
        probs = G.models_status_problems(0, self.ROUTES, [])
        self.assertIn("pc-codex-runtime", [c for c, _ in probs])

    def test_models_status_codex_route_ok_when_codex_was_in_use(self):
        self.assertEqual(G.models_status_problems(0, self.ROUTES, [], codex_allowed=True), [])

    def test_sessions_codex_rows(self):
        data = {"sessions": [
            {"key": "agent:main:main", "modelProvider": "openai", "agentRuntime": {"id": "codex"}},
            {"key": "agent:main:legacy", "modelProvider": "openai", "agentRuntime": {"id": "codex"}},
        ]}
        self.assertEqual(len(G.sessions_problems(0, data, [], set())), 2)
        # canonical sessions may stay on Codex, but sessions R5 pinned to openclaw must not
        probs = G.sessions_problems(0, data, ["agent:main:legacy"], set(), codex_allowed=True)
        self.assertEqual(probs, ["session agent:main:legacy: runtime codex"])


class ModelsStatusRegressionOnlyTests(unittest.TestCase):
    """`models status --check` exits 1 for merely indeterminate readiness (v99 docs/cli/models.md:91)."""

    def issues(self, *items):
        return {"auth": {"runtimeAuthRoutes": [], "missingProvidersInUse": [],
                         "modelRouteIssues": [{"kind": k, "provider": pr, "model": m} for k, pr, m in items]}}

    def test_indeterminate_and_fallback_issues_only_warn(self):
        data = self.issues(("indeterminate", "openai", "gpt-5.5"), ("missing", "anthropic", "claude-opus-4-8"))
        probs = G.models_status_problems(1, data, [], primaries={"vllm/qwen3.5-122b"})
        self.assertTrue(probs)
        self.assertEqual({c for c, _ in probs}, {"warn"})

    def test_primary_route_issue_holds(self):
        data = self.issues(("missing", "openai", "gpt-5.5"))
        probs = G.models_status_problems(1, data, [], primaries={"openai/gpt-5.5"})
        self.assertIn("pc-models-status", [c for c, _ in probs])

    def test_indeterminate_primary_only_warns(self):
        data = self.issues(("indeterminate", "openai", "gpt-5.5"))
        probs = G.models_status_problems(1, data, [], primaries={"openai/gpt-5.5"})
        self.assertEqual({c for c, _ in probs}, {"warn"})

    def test_lost_oauth_login_holds(self):
        data = {"auth": {"oauth": {"profiles": []}, "modelRouteIssues": []}}
        probs = G.models_status_problems(0, data, [{"type": "oauth", "provider": "openai-codex"}])
        self.assertIn("pc-models-status", [c for c, _ in probs])

    def test_primary_model_refs(self):
        cfg = {"agents": {"defaults": {"model": {"primary": "vllm/Qwen3.5-122b"}},
                          "entries": {"mail_reader": {"model": "vllm/qwen3.5-122b"},
                                      "x": {"model": {"primary": "openai/gpt-5.5"}}}}}
        self.assertEqual(G.primary_model_refs(cfg), {"vllm/qwen3.5-122b", "openai/gpt-5.5"})


if __name__ == "__main__":
    unittest.main()
