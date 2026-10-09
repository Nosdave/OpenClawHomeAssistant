"""End-to-end smoke test of the migration gate WITHOUT docker (stdlib unittest, Python 3.11).

The real `oc-upgrade` CLI (oc_upgrade.py -> oc_gate / oc_migrate / oc_common) runs as a subprocess,
exactly as run.sh calls it, against a temporary tree:

- a synthetic 2026.7.35-like state: state/openclaw.sqlite (user_version 1, clean pre-journal tables,
  startup-migrations checkpoint 2026.7.35), agents/main/agent/openclaw-agent.sqlite (user_version 1),
  openclaw.json, a sessions.json and a workspace;
- a FAKE runtime package: package.json (2026.9.9, schemaVersions state 19 / agent 24), node-sqlite.mjs
  (capability probe) and openclaw.mjs, a node script emulating the CLI calls the gate makes. Its
  `doctor --fix --non-interactive` bumps the databases to 19/24 with node:sqlite, canonicalizes
  openai-codex/ refs, copies the models map into modelPolicy.allow and (like 9.9, E9) enables the codex
  plugin when an openai/ models-map key has no runtime pin. It prints "Doctor complete.".

The real `node` binary on PATH runs the fake entry (no doctor_cmd hook). Test hooks only skip the
network and free-space checks. Skipped when node (with node:sqlite) is not available.

Cases: openai-codex wildcard (plan 10 -> gate 0 + migrated.json -> plan 0), a second gate run is a no-op,
a live-user-shaped config with canonical openai/* refs (contract addendum 2: no HOLD, they keep their
runtime and doctor's codex plugin setting stays), a doctor that re-enables the codex plugin in every pass
on a legacy-only config (F1b after each pass, pass 3, doctor-not-idempotent, retry --accept), and a
9.x -> 9.y bump (no pre-migrate or pins; canonical refs and the user's codex pin untouched).
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
SCRIPT = ADDON / "oc_upgrade.py"
RUNTIME = "2026.9.9"

NODE = shutil.which("node")


def _node_has_sqlite():
    if not NODE:
        return False
    try:
        p = subprocess.run([NODE, "-e", "require('node:sqlite')"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 0


HAVE_NODE = _node_has_sqlite()

FAKE_NODE_SQLITE = r"""
export async function detectCurrentSqliteCapabilities() { return { version: "3.50.4" }; }
export function nodeRuntimeFailure(_nodeVersion, _caps) { return null; }
"""

FAKE_OPENCLAW = r"""
// Fake OpenClaw 2026.9.9 CLI for the migration-gate e2e smoke test (never a real migration).
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const args = process.argv.slice(2);
const has = (a) => args.includes(a);
const stateDir = process.env.OPENCLAW_STATE_DIR || path.join(process.env.HOME || "/config", ".openclaw");
const cfgPath = process.env.OPENCLAW_CONFIG_PATH || path.join(stateDir, "openclaw.json");
const out = (o, rc = 0) => { process.stdout.write(JSON.stringify(o) + "\n"); process.exit(rc); };
const log = (s) => fs.appendFileSync(path.join(stateDir, "fake-openclaw-calls.log"), s + "\n");
log(args.join(" "));

function exec(file, sql) {
  const db = new DatabaseSync(file);
  try { db.exec(sql); } finally { db.close(); }
}

function userVersion(file) {
  const db = new DatabaseSync(file);
  try { return db.prepare("PRAGMA user_version").get().user_version; } finally { db.close(); }
}

function sessionStores() {
  const stores = [];
  const agents = path.join(stateDir, "agents");
  if (fs.existsSync(agents)) {
    for (const a of fs.readdirSync(agents)) {
      const f = path.join(agents, a, "sessions", "sessions.json");
      if (fs.existsSync(f)) stores.push(f);
    }
  }
  return stores;
}

function unpinnedOpenAiKeys(cfg) {
  const maps = [];
  const ag = cfg.agents || {};
  if (ag.defaults && ag.defaults.models) maps.push(ag.defaults.models);
  for (const e of Object.values(ag.entries || {})) if (e && e.models) maps.push(e.models);
  for (const e of ag.list || []) if (e && e.models) maps.push(e.models);
  let n = 0;
  for (const m of maps) {
    for (const [k, v] of Object.entries(m)) {
      if (!/^\s*openai\s*\//i.test(k)) continue;
      const id = v && v.agentRuntime && typeof v.agentRuntime.id === "string" ? v.agentRuntime.id.trim() : "";
      if (!id || id === "auto" || id === "default") n++;
    }
  }
  return n;
}

function doctorFix() {
  const sdb = path.join(stateDir, "state", "openclaw.sqlite");
  if (fs.existsSync(sdb) && userVersion(sdb) < 19) {
    exec(sdb, "PRAGMA user_version=19; UPDATE schema_meta SET schema_version=19 WHERE meta_key='primary';" +
              "DROP TABLE IF EXISTS cron_run_logs; UPDATE agent_databases SET schema_version=24;");
    console.log("Saved pre-migration SQLite backup: (fake)");
  }
  const agents = path.join(stateDir, "agents");
  for (const a of fs.existsSync(agents) ? fs.readdirSync(agents) : []) {
    const f = path.join(agents, a, "agent", "openclaw-agent.sqlite");
    if (fs.existsSync(f)) {
      exec(f, "PRAGMA user_version=24; UPDATE schema_meta SET schema_version=24, app_version='2026.9.9' " +
              "WHERE meta_key='primary';");
    }
  }
  const text = fs.readFileSync(cfgPath, "utf8");
  const cfg = JSON.parse(text.replace(/openai-codex\//g, "openai/"));
  cfg.meta = cfg.meta || {};
  cfg.meta.lastTouchedVersion = "2026.9.9";
  cfg.meta.migrations = Object.assign({}, cfg.meta.migrations, { modelPolicyAllowlist: true });
  const d = (cfg.agents = cfg.agents || {}).defaults = (cfg.agents.defaults || {});
  if (d.models && Object.keys(d.models).length && !d.modelPolicy) d.modelPolicy = { allow: Object.keys(d.models) };
  if (unpinnedOpenAiKeys(cfg) > 0 || process.env.FAKE_DOCTOR_READD_CODEX === "1") {
    // 9.9: unpinned openai/* routes may select the native Codex harness implicitly (E9).
    cfg.plugins = cfg.plugins || {};
    cfg.plugins.entries = cfg.plugins.entries || {};
    if (!cfg.plugins.entries.codex || cfg.plugins.entries.codex.enabled !== true) {
      cfg.plugins.entries.codex = Object.assign({}, cfg.plugins.entries.codex, { enabled: true });
      console.log("codex agent runtime configured, enabled automatically");
    }
  }
  const next = JSON.stringify(cfg, null, 2) + "\n";
  if (next !== text) fs.writeFileSync(cfgPath, next);
  for (const f of sessionStores()) {
    const t = fs.readFileSync(f, "utf8");
    const n = t.replace(/openai-codex\//g, "openai/").replace(/"openai-codex"/g, "\"openai\"");
    if (n !== t) fs.writeFileSync(f, n);
  }
  console.log("┌  OpenClaw doctor\n│\n◇  Doctor changes ───╮\n└  Doctor complete.");
  process.exit(0);
}

const cmd = args.filter((a) => !a.startsWith("-"));
if (has("--version")) { console.log("OpenClaw 2026.9.9 (fake)"); process.exit(0); }
if (cmd[0] === "doctor" && has("--lint")) {
  out({ schemaVersion: 1, ok: true, checksRun: 1, checksSkipped: 0, findings: [] });
}
if (cmd[0] === "doctor" && has("--fix") && has("--non-interactive")) doctorFix();
if (cmd[0] === "config" && cmd[1] === "validate") out({ valid: true, path: cfgPath, warnings: [] });
if (cmd[0] === "models" && cmd[1] === "auth" && cmd[2] === "list") out({ profiles: [] });
if (cmd[0] === "models" && cmd[1] === "auth" && cmd[2] === "order") out({ order: null });
if (cmd[0] === "models" && cmd[1] === "status") {
  out({ auth: { runtimeAuthRoutes: [], modelRouteIssues: [], missingProvidersInUse: [], oauth: { profiles: [] } } });
}
if (cmd[0] === "sessions") {
  const rows = [];
  for (const f of sessionStores()) {
    for (const [key, e] of Object.entries(JSON.parse(fs.readFileSync(f, "utf8")))) {
      const prov = String(e.modelProvider || "").replace("openai-codex", "openai");
      const rt = e.agentRuntimeOverride && e.agentRuntimeOverride !== "auto" ? e.agentRuntimeOverride
        : (prov === "openai" ? "codex" : "openclaw");
      rows.push({ key, modelProvider: prov, acpRuntime: false, agentRuntime: { id: rt, source: "fake" } });
    }
  }
  out({ sessions: rows });
}
if (cmd[0] === "plugins" && cmd[1] === "list") out({ plugins: [] });
process.stderr.write("fake openclaw: unhandled " + JSON.stringify(args) + "\n");
process.exit(3);
"""

CFG_CODEX_WILDCARD = {
    "meta": {"lastTouchedVersion": "2026.7.35"},
    "agents": {
        "defaults": {
            "model": {"primary": "openai-codex/gpt-5.5", "fallbacks": ["vllm/qwen3.5-122b"]},
            "models": {"openai-codex/*": {}, "openai-codex/gpt-5.5": {"alias": "gpt"}, "vllm/qwen3.5-122b": {}},
        },
        "list": [{"id": "main", "default": True}],
    },
    "models": {"providers": {"vllm": {"baseUrl": "http://127.0.0.1:8000/v1", "api": "openai-completions",
                                      "models": [{"id": "qwen3.5-122b", "name": "Qwen"}]}}},
    "gateway": {"mode": "local", "auth": {"token": "SECRET-GATEWAY-TOKEN-0123456789"}},
    "channels": {"telegram": {"enabled": True, "botToken": "123456:SECRET-BOT-TOKEN"}},
}

# Shaped like the live user's config (contract addendum 1b): no openai-codex refs at all, canonical
# openai/* wildcard plus explicit openai/ keys, vLLM primary.
CFG_LIVE_LIKE = {
    "meta": {"lastTouchedVersion": "2026.7.35"},
    "agents": {
        "defaults": {
            "model": {"primary": "vllm/qwen3.5-122b", "fallbacks": ["openai/gpt-5.5"]},
            "models": {"vllm/qwen3.5-122b": {"alias": "qwen"}, "openai/*": {}, "anthropic/*": {},
                       "openai/gpt-5.5": {"alias": "gpt"}},
            "heartbeat": {"every": "1h"},
        },
        "list": [{"id": "main", "default": True}, {"id": "mail_reader", "model": "vllm/qwen3.5-122b"}],
    },
    "models": {"providers": {"vllm": {"baseUrl": "http://127.0.0.1:8000/v1", "api": "openai-completions",
                                      "models": [{"id": "qwen3.5-122b", "name": "Qwen"}]}}},
    "gateway": {"mode": "local", "auth": {"token": "SECRET-GATEWAY-TOKEN-0123456789"}},
}

SECRETS = ("SECRET-GATEWAY-TOKEN-0123456789", "SECRET-BOT-TOKEN", "SECRET-ACCESS-TOKEN")


def make_state_db(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(path))
    c.executescript("""
        CREATE TABLE schema_meta (meta_key TEXT NOT NULL PRIMARY KEY, role TEXT NOT NULL,
            schema_version INTEGER NOT NULL, agent_id TEXT, app_version TEXT, created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL);
        INSERT INTO schema_meta VALUES ('primary','global',1,NULL,NULL,0,0);
        INSERT INTO schema_meta VALUES ('startup-migrations','global',1,NULL,'2026.7.35',0,0);
        CREATE TABLE agent_databases (agent_id TEXT NOT NULL, path TEXT NOT NULL, schema_version INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL, size_bytes INTEGER, PRIMARY KEY (agent_id, path));
        INSERT INTO agent_databases VALUES ('main','agents/main/agent/openclaw-agent.sqlite',1,0,NULL);
        CREATE TABLE migration_sources (source_key TEXT NOT NULL PRIMARY KEY, target_table TEXT);
        CREATE TABLE cron_run_logs (id INTEGER PRIMARY KEY);
        CREATE TABLE device_identities (identity_key TEXT PRIMARY KEY);
        PRAGMA user_version=1;
    """)
    c.commit()
    c.close()


def make_agent_db(path, aid):
    path.parent.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(str(path))
    c.executescript(f"""
        CREATE TABLE schema_meta (meta_key TEXT NOT NULL PRIMARY KEY, role TEXT NOT NULL,
            schema_version INTEGER NOT NULL, agent_id TEXT, app_version TEXT, created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL);
        INSERT INTO schema_meta VALUES ('primary','agent',1,'{aid}',NULL,0,0);
        CREATE TABLE auth_profile_store (store_key TEXT PRIMARY KEY, store_json TEXT, updated_at INTEGER);
        PRAGMA user_version=1;
    """)
    c.execute("INSERT INTO auth_profile_store VALUES ('primary', ?, 0)", (json.dumps({"profiles": {
        "anthropic:default": {"type": "api_key", "provider": "anthropic", "key": "SECRET-ACCESS-TOKEN"}}}),))
    c.commit()
    c.close()


def uv(path):
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return c.execute("PRAGMA user_version").fetchone()[0]
    finally:
        c.close()


@unittest.skipUnless(HAVE_NODE, "node with node:sqlite is required for the fake OpenClaw entry")
class FakeRuntimeE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="oc-gate-e2e-"))
        self.root = self.tmp / "config"
        self.state = self.root / ".openclaw"
        self.upg = self.root / ".openclaw-upgrade"
        self.share = self.tmp / "share"
        self.ws = self.root / "clawd"
        for d in (self.state, self.upg, self.share, self.ws):
            d.mkdir(parents=True)
        pkg = self.tmp / "pkg" / "openclaw"
        pkg.mkdir(parents=True)
        (pkg / "openclaw.mjs").write_text(FAKE_OPENCLAW)
        (pkg / "node-sqlite.mjs").write_text(FAKE_NODE_SQLITE)
        (pkg / "package.json").write_text(json.dumps(
            {"name": "openclaw", "version": RUNTIME, "type": "module",
             "openclaw": {"schemaVersions": {"state": 19, "agent": 24}}}))
        self.entry_file = self.tmp / "openclaw-entry"
        self.entry_file.write_text(str(pkg / "openclaw.mjs") + "\n")
        self.pylib = self.tmp / "pylib"  # empty: oc-upgrade must fall back to its own directory
        self.pylib.mkdir()
        (self.upg / "gate").mkdir()
        (self.upg / "gate" / "test-hooks.json").write_text(json.dumps(
            {"skip_network_check": True, "skip_space_check": True}))
        drop = ("OPENCLAW_", "OC_GATE_", "OC_UPGRADE_", "OC_ADDON_", "OC_CONFIG_ROOT", "SQLITE_TMPDIR")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(drop)}
        self.env.update({
            "OPENCLAW_STATE_DIR": str(self.state), "OPENCLAW_CONFIG_PATH": str(self.state / "openclaw.json"),
            "OC_UPGRADE_DIR": str(self.upg), "OC_UPGRADE_SHARE_DIR": str(self.share),
            "OC_CONFIG_ROOT": str(self.root), "OC_ADDON_ENTRY_FILE": str(self.entry_file),
            "OC_ADDON_PYLIB": str(self.pylib), "OC_GATE_TEST_HOOKS": "1", "TMPDIR": str(self.tmp),
            "ADDON_VERSION": "0.5.94-e2e", "PYTHONDONTWRITEBYTECODE": "1", "NODE_NO_WARNINGS": "1",
            "OPENCLAW_RUNTIME_VERSION": RUNTIME,
        })

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers ---
    def build_735(self, cfg):
        make_state_db(self.state / "state" / "openclaw.sqlite")
        make_agent_db(self.state / "agents" / "main" / "agent" / "openclaw-agent.sqlite", "main")
        (self.state / "openclaw.json").write_text(json.dumps(cfg, indent=2) + "\n")
        sess = self.state / "agents" / "main" / "sessions"
        sess.mkdir(parents=True)
        (sess / "sessions.json").write_text(json.dumps({
            "agent:main:main": {"sessionId": "s1", "updatedAt": 1, "modelProvider": "openai-codex", "model": "gpt-5.5"},
            "agent:main:local": {"sessionId": "s2", "updatedAt": 1, "model": "vllm/qwen3.5-122b"}}, indent=2))
        # a 9.9 transient sidecar (quarantined) and a 0-byte broken-empty leftover (left in place)
        (self.state / "agents" / "main" / "agent" / "openclaw-agent.sqlite.reindex-lock.sqlite").write_bytes(b"")
        (self.state / "agents" / "main" / "agent" / "openclaw-agent.sqlite.broken-empty-20260617-095841") \
            .write_bytes(b"")
        (self.ws / "AGENTS.md").write_text("# agents\n")

    def cli(self, *args, runsh=False):
        env = dict(self.env)
        if runsh:
            env["OC_GATE_FROM_RUNSH"] = "1"
        p = subprocess.run([sys.executable, "-B", str(SCRIPT), *args], capture_output=True, text=True, env=env,
                           cwd=str(self.tmp), timeout=600)
        self.stdout, self.stderr = p.stdout, p.stderr
        return p.returncode

    def config(self):
        return json.loads((self.state / "openclaw.json").read_text())

    def assert_no_secrets(self):
        texts = [self.stdout, self.stderr]
        for p in list(self.upg.rglob("*")) + list(self.share.rglob("*.json")):
            if p.is_file() and p.suffix in (".json", ".txt", ".log") and "config." not in p.name \
                    and "sessions-pre" not in str(p):
                texts.append(p.read_text(errors="replace"))
        for t in texts:
            for s in SECRETS:
                self.assertNotIn(s, t)

    def run_full_gate(self):
        rc = self.cli("gate", "--plan")
        self.assertEqual(rc, 10, self.stdout + self.stderr)
        plan_lines = [x for x in self.stdout.splitlines() if x.startswith("[gate] plan:")]
        self.assertEqual(len(plan_lines), 1, self.stdout)
        self.assertIn("mode=from-7x", plan_lines[0])
        self.assertFalse((self.upg / "gate" / "journal.json").exists(), "--plan must not write the journal")
        rc = self.cli("gate", runsh=True)
        self.assertEqual(rc, 0, self.stdout + self.stderr)
        marker = json.loads((self.upg / "gate" / "migrated.json").read_text())
        self.assertEqual(marker["runtime"], RUNTIME)
        self.assertEqual(marker["mode"], "from-7x")
        self.assertIn(f"[gate] done: MIGRATED {RUNTIME}", self.stdout)
        self.assertFalse((self.upg / "hold.txt").exists())
        gate_out = self.stdout
        rc = self.cli("gate", "--plan")
        self.assertEqual(rc, 0, self.stdout + self.stderr)
        self.assertIn("-> no gate (migrated (from-7x", self.stdout)
        return gate_out

    def common_asserts(self, out):
        self.assertEqual(uv(self.state / "state" / "openclaw.sqlite"), 19)
        self.assertEqual(uv(self.state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"), 24)
        for n in range(1, 10):
            self.assertIn(f"[gate] {n}/9 ", out)
        self.assertIn("7/9 doctor pass 2 rc=0", out)
        self.assertIn("config unchanged", out)
        self.assertIn("8/9 postconditions OK", out)
        j = json.loads((self.upg / "gate" / "journal.json").read_text())
        self.assertEqual(j["status"], "done")
        self.assertEqual([d["pass"] for d in j["doctor"]], [1, 2])
        # archive in /share, verified, with manifest and checksums
        adir = Path(j["archive"]["dir"])
        self.assertTrue(str(adir).startswith(str(self.share / "openclaw-upgrade")))
        self.assertTrue((adir / j["archive"]["file"]).is_file())
        self.assertTrue((adir / "manifest.json").is_file() and (adir / "SHA256SUMS").is_file())
        # quarantine: the transient sidecar moved, the broken-empty leftover stays
        agent_dir = self.state / "agents" / "main" / "agent"
        self.assertFalse((agent_dir / "openclaw-agent.sqlite.reindex-lock.sqlite").exists())
        self.assertTrue((agent_dir / "openclaw-agent.sqlite.broken-empty-20260617-095841").exists())
        qman = json.loads((self.upg / "gate" / "quarantine" / j["run_id"] / "MANIFEST.json").read_text())
        self.assertEqual([m["kind"] for m in qman], ["sqlite-transient"])
        # vLLM provider block and refs untouched
        cfg = self.config()
        self.assertEqual(cfg["models"]["providers"]["vllm"],
                         CFG_CODEX_WILDCARD["models"]["providers"]["vllm"])
        # behaviour pins written once, ledgered
        led = json.loads((self.upg / "gate" / "pins-ledger.json").read_text())
        self.assertGreaterEqual(len(led["entries"]), 20)
        self.assertEqual(cfg["agents"]["defaults"]["maxConcurrent"], 4)
        # the gate never ran a writing OpenClaw command other than the two doctor passes
        calls = (self.state / "fake-openclaw-calls.log").read_text().splitlines()
        self.assertEqual(sum(1 for c in calls if c.startswith("doctor --fix")), 2, calls)
        self.assert_no_secrets()
        return cfg, j

    def build_99(self, cfg, marker_runtime="2026.9.8"):
        """A state already migrated by an earlier 9.x runtime (marker for marker_runtime)."""
        sdb = self.state / "state" / "openclaw.sqlite"
        make_state_db(sdb)
        c = sqlite3.connect(str(sdb))
        c.executescript("PRAGMA user_version=19; UPDATE schema_meta SET schema_version=19 WHERE meta_key='primary';"
                        "DROP TABLE cron_run_logs; UPDATE agent_databases SET schema_version=24;")
        c.commit()
        c.close()
        adb = self.state / "agents" / "main" / "agent" / "openclaw-agent.sqlite"
        make_agent_db(adb, "main")
        c = sqlite3.connect(str(adb))
        c.executescript("PRAGMA user_version=24; UPDATE schema_meta SET schema_version=24, app_version='2026.9.8' "
                        "WHERE meta_key='primary';")
        c.commit()
        c.close()
        (self.state / "openclaw.json").write_text(json.dumps(cfg, indent=2) + "\n")
        (self.upg / "gate" / "migrated.json").write_text(json.dumps(
            {"schema": 1, "runtime": marker_runtime, "mode": "from-7x", "run_id": "old", "binding": {}}))

    # --- tests ---
    def test_codex_wildcard_state_migrates_end_to_end(self):
        self.build_735(CFG_CODEX_WILDCARD)
        out = self.run_full_gate()
        cfg, j = self.common_asserts(out)
        d = cfg["agents"]["defaults"]
        self.assertEqual(d["model"]["primary"], "openai/gpt-5.5")
        self.assertEqual(d["model"]["fallbacks"], ["vllm/qwen3.5-122b"])
        self.assertEqual(d["models"]["openai/gpt-5.5"], {"alias": "gpt", "agentRuntime": {"id": "openclaw"}})
        self.assertNotIn("openai/*", d["models"])
        self.assertNotIn("openai-codex/*", d["models"])
        self.assertNotIn("codex", (cfg.get("plugins") or {}).get("entries") or {})
        self.assertIn("agent:main:main", j["transform"]["sessions_pinned"])
        sessions = json.loads((self.state / "agents/main/sessions/sessions.json").read_text())
        self.assertEqual(sessions["agent:main:main"]["agentRuntimeOverride"], "openclaw")
        self.assertNotIn("agentRuntimeOverride", sessions["agent:main:local"])

    def test_second_gate_run_is_a_noop(self):
        self.build_735(CFG_CODEX_WILDCARD)
        self.run_full_gate()
        before = (self.state / "openclaw.json").read_bytes()
        self.assertEqual(self.cli("gate", runsh=True), 0, self.stdout + self.stderr)
        self.assertEqual((self.state / "openclaw.json").read_bytes(), before)
        self.assertEqual(self.cli("state-guard"), 0, self.stdout + self.stderr)


    def test_live_like_canonical_openai_refs_keep_their_runtime(self):
        """Contract addendum 2: canonical openai/* refs are no HOLD and are never pinned by the gate; doctor
        enables the codex plugin for them (E9, as 7.35 did implicitly) and that setting stays (rule 4)."""
        self.build_735(CFG_LIVE_LIKE)
        out = self.run_full_gate()
        self.assertIn("[gate] 1/9 info: 3 canonical openai/* refs keep their runtime (Codex app-server by default, "
                      "as on 7.35)", out)
        self.assertNotIn("HOLD", out)
        cfg, j = self.common_asserts(out)
        d = cfg["agents"]["defaults"]
        self.assertEqual(d["model"], CFG_LIVE_LIKE["agents"]["defaults"]["model"])
        self.assertEqual(d["models"]["openai/*"], {})
        self.assertEqual(d["models"]["openai/gpt-5.5"], {"alias": "gpt"})
        self.assertEqual(d["models"]["anthropic/*"], {})
        self.assertEqual(d["models"]["vllm/qwen3.5-122b"], {"alias": "qwen"})
        self.assertEqual(cfg["plugins"]["entries"]["codex"], {"enabled": True})
        self.assertEqual((j["fixups"]["codex_needed"], j["fixups"]["codex_plugin_restored"]), (True, False))
        self.assertIn("6/9 fixups: 0 codex runtime pins -> openclaw; 0 legacy refs rewritten; compaction restored: "
                      "no; codex plugin entry restored: no (Codex was in use before the migration", out)
        self.assertNotIn("keeps it disabled", out)
        ledger = json.loads((self.upg / "gate" / "runs" / j["run_id"] / "transform-ledger.json").read_text())
        self.assertEqual(sorted({e["step"] for e in ledger}), ["R5"])

    def test_doctor_readding_codex_is_not_idempotent_hold(self):
        """F1b also after pass 2 (Codex not in use before: legacy refs only): a doctor that re-enables the
        codex plugin in every pass forces pass 3, then HOLD."""
        self.build_735(CFG_CODEX_WILDCARD)
        self.env["FAKE_DOCTOR_READD_CODEX"] = "1"
        self.assertEqual(self.cli("gate", "--plan"), 10, self.stdout + self.stderr)
        self.assertEqual(self.cli("gate", runsh=True), 20, self.stdout + self.stderr)
        self.assertIn("[gate] HOLD doctor-not-idempotent in doctor2", self.stdout)
        self.assertIn("WARN [gate] doctor pass 2 changed what the fixups set; F1b re-applied: "
                      "plugins.entries.codex", self.stdout)
        self.assertIn("doctor pass 3", self.stdout)
        self.assertNotIn("codex", (self.config().get("plugins") or {}).get("entries") or {})
        hold = (self.upg / "hold.txt").read_text()
        self.assertIn("oc-upgrade retry --accept doctor-not-idempotent", hold)
        self.assertEqual(self.cli("gate", "--plan"), 11, self.stdout + self.stderr)
        # accepting continues with the postconditions on the next start
        self.env.pop("FAKE_DOCTOR_READD_CODEX")
        self.assertEqual(self.cli("retry", "--accept", "doctor-not-idempotent"), 0, self.stdout + self.stderr)
        self.assertEqual(self.cli("gate", "--plan"), 10, self.stdout + self.stderr)
        self.assertEqual(self.cli("gate", runsh=True), 0, self.stdout + self.stderr)
        self.assertIn("8/9 postconditions OK", self.stdout)
        marker = json.loads((self.upg / "gate" / "migrated.json").read_text())
        self.assertEqual(marker["accepted"], ["doctor-not-idempotent"])
        self.assert_no_secrets()

    def test_bump_mode_leaves_canonical_refs(self):
        """A 9.x -> 9.y bump: no pre-migrate and no pins; canonical refs, the user's codex pin and doctor's
        codex plugin setting stay (contract addendum 2 rules 2 and 4)."""
        cfg = json.loads(json.dumps(CFG_LIVE_LIKE))
        cfg["meta"]["lastTouchedVersion"] = "2026.9.8"
        cfg["agents"]["defaults"]["models"]["openai/gpt-5.4"] = {"agentRuntime": {"id": "codex"}}  # user's choice
        cfg["agents"]["defaults"]["modelPolicy"] = {}
        self.build_99(cfg)
        self.assertEqual(self.cli("gate", "--plan"), 10, self.stdout + self.stderr)
        self.assertIn("mode=bump", self.stdout)
        self.assertEqual(self.cli("gate", runsh=True), 0, self.stdout + self.stderr)
        out = self.stdout
        self.assertNotIn("4/9", out)
        self.assertNotIn("9/9 pins", out)
        self.assertIn("6/9 fixups: codex plugin entry restored: no (Codex was in use before the migration", out)
        new = self.config()
        dm = new["agents"]["defaults"]["models"]
        self.assertEqual(dm["openai/*"], {})
        self.assertEqual(dm["openai/gpt-5.4"], {"agentRuntime": {"id": "codex"}})
        self.assertEqual(new["plugins"]["entries"]["codex"], {"enabled": True})
        self.assertNotIn("maxConcurrent", new["agents"]["defaults"])
        marker = json.loads((self.upg / "gate" / "migrated.json").read_text())
        self.assertEqual((marker["runtime"], marker["mode"]), (RUNTIME, "bump"))
        self.assertEqual(self.cli("gate", "--plan"), 0, self.stdout + self.stderr)


if __name__ == "__main__":
    unittest.main()
