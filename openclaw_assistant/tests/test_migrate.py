"""Unit tests for oc_migrate (Stage B migration gate: pure transforms and checks).

Run: cd openclaw_assistant && PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v

Golden fixtures (tests/fixtures/, tokens replaced by fake values) come from the experiments with a real
OpenClaw 2026.9.9 doctor on a real 7.35 state (contract E3/E4):
  e4_before.json          7.35 config before the gate (exp1 .openclaw/openclaw.json)
  e4_pretransform.json    the R1+R2 config doctor accepted (exp2 openclaw.json.bak.2)
  e4_after_pass2.json     config after doctor pass 2 with the pre-transform (exp2/out/after2.json)
  e3_raw_after_pass2.json config after doctor without the pre-transform (exp1raw .openclaw/openclaw.json)
  pins_final_99.json      pins validated against the 9.9 schema (specwf/config-keys/pins_final.json)
The scratchpad originals are compared too when they still exist (skipped otherwise).
"""

import copy
import json
import os
import socket
import sqlite3
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import oc_migrate as m  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
SCRATCH = "/tmp/claude-0/-home-user-OpenClawHomeAssistant/6503d59a-0f4b-5f0f-b521-f4389a32b335/scratchpad"
SCRATCH_GOLDEN = {
    "e4_before.json": SCRATCH + "/exp1/config/.openclaw/openclaw.json",
    "e4_pretransform.json": SCRATCH + "/exp2/config/.openclaw/openclaw.json.bak.2",
    "e4_after_pass2.json": SCRATCH + "/exp2/out/after2.json",
    "e3_raw_after_pass2.json": SCRATCH + "/exp1raw/config/.openclaw/openclaw.json",
    "pins_final_99.json": SCRATCH + "/specwf/config-keys/pins_final.json",
    # contract addendum 1b: live-user-shaped config through real 9.9 doctor (pass 1; after2 is the
    # superseded addendum-1 F1c result, kept as a "canonical keys were pinned" counter-example)
    "exp5_pre_gate.json": SCRATCH + "/exp5/out/pre-gate.json",
    "exp5_after_pass1.json": SCRATCH + "/exp5/out/after1.json",
    "exp5_after_pass2.json": SCRATCH + "/exp5/out/after2.json",
}
UUID = "3f2b8c1e-9a4d-4e6f-8b7a-1c2d3e4f5a6b"


def fix(name):
    path = os.path.join(FIX, name)
    if not os.path.exists(path):
        raise unittest.SkipTest("golden fixture missing: %s" % path)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def sanitize(cfg):
    cfg = copy.deepcopy(cfg)
    a = cfg.get("gateway", {}).get("auth")
    if isinstance(a, dict) and "token" in a:
        a["token"] = "fake-gateway-token-for-unit-tests"
    t = cfg.get("channels", {}).get("telegram")
    if isinstance(t, dict) and "botToken" in t:
        t["botToken"] = "123456:FAKE-TOKEN-FOR-UNIT-TESTS"
    return cfg


def spec_example():
    """§7.4.2 'before' example plus the F-735 builder additions (§15.2) and a vLLM provider."""
    return {
        "meta": {"lastTouchedVersion": "2026.7.35"},
        "agents": {
            "defaults": {
                "model": {"primary": "openai-codex/gpt-5.5", "fallbacks": ["openai-codex/gpt-5.4-mini"]},
                "heartbeat": {"model": "openai-codex/gpt-5.4-mini"},
                "compaction": {"model": "openai-codex/gpt-5.4-mini"},
                "models": {"openai-codex/*": {}, "openai-codex/gpt-5.5": {"alias": "main"},
                           "anthropic/claude-sonnet-4-6": {"alias": "sonnet"}},
            },
            "list": [{"id": "main", "default": True},
                     {"id": "helper", "models": {"openai-codex/*": {"alias": "x", "params": {"temperature": 0.2},
                                                                    "agentRuntime": {"id": "auto"}}}}],
        },
        "hooks": {"mappings": [{"model": "openai-codex/gpt-5.4-mini"}]},
        "channels": {"telegram": {"enabled": True, "botToken": "123456:FAKE"}},
        "auth": {"order": {"openai-codex": ["openai-codex:default"]}},
    }


def vllm_block():
    return {"baseUrl": "http://192.168.1.20:8000/v1", "api": "openai-completions", "apiKey": "sk-local-fake",
            "models": [{"id": "qwen3.5-122b", "name": "Qwen 3.5 122B", "contextWindow": 131072}]}


def live_like():
    """Shape of the live user: vLLM primary, Codex only as fallback / in the models map."""
    return {
        "meta": {"lastTouchedVersion": "2026.7.35"},
        "models": {"providers": {"vllm": vllm_block()}},
        "agents": {"defaults": {
            "model": {"primary": "vllm/qwen3.5-122b", "fallbacks": ["openai-codex/gpt-5.5", "vllm/qwen3.5-122b"]},
            "models": {"vllm/qwen3.5-122b": {"alias": "qwen"}, "vllm/*": {}, "openai-codex/gpt-5.5": {}},
            "workspace": "/config/clawd"}},
        "channels": {"telegram": {"enabled": True, "botToken": "123456:FAKE", "dmPolicy": "pairing"}},
        "gateway": {"controlUi": {"allowInsecureAuth": True, "dangerouslyDisableDeviceAuth": True}},
        "hooks": {"allowRequestSessionKey": True},
    }


# --- regexes ----------------------------------------------------------------------------------


class TestRegexes(unittest.TestCase):
    def test_transient_sqlite_positive(self):
        names = [
            "openclaw-agent.sqlite.reindex-lock.sqlite",
            "openclaw-agent.sqlite.reindex-lock.sqlite-journal",
            "openclaw-agent.sqlite.generation-lock.sqlite",
            "openclaw-agent.sqlite.generation-writer.sqlite",
            "openclaw-agent.sqlite.generation-writer.sqlite-wal",
            "openclaw-agent.sqlite.memory-reindex-" + UUID,
            "openclaw-agent.sqlite.memory-reindex-" + UUID + "-wal",
            "openclaw-agent.sqlite.memory-reindex-" + UUID + "-shm",
            "openclaw-agent.sqlite.memory-reindex-" + UUID + "-journal",
            "openclaw-agent.sqlite.backup-" + UUID,
            "openclaw-agent.sqlite.tmp-" + UUID.upper(),     # flag i (JS /iu)
            "OPENCLAW-AGENT.SQLITE.REINDEX-LOCK.SQLITE",
            "x.sqlite.tmp-" + UUID + "-shm",
        ]
        for n in names:
            with self.subTest(n=n):
                self.assertTrue(m.TRANSIENT_SQLITE_RE.match(n))
                self.assertTrue(m.TRANSIENT_SQLITE_RE.fullmatch(n))

    def test_transient_sqlite_negative(self):
        names = [
            "openclaw-agent.sqlite", "openclaw-agent.sqlite-wal", "openclaw-agent.sqlite-shm",
            "openclaw-agent.sqlite.migrated",
            "openclaw-agent.sqlite.memory-reindex-1234",                       # not a uuid
            "openclaw-agent.sqlite.memory-reindex-" + UUID + ".bak",
            "openclaw-agent.sqlite.memory-reindex-" + UUID[:-1],
            "openclaw-agent.sqlite.reindex-lock.sqlite-wal\n",                # Python '$' trap
            "openclaw-agent.sqlite.reindex-lock.sqlite.bak",
            "a/b.sqlite.reindex-lock.sqlite",                                 # basename only
            ".sqlite.reindex-lock.sqlite",                                    # [^/]+ needs a stem
            "openclaw-agent.sqlite.generation-1.sqlite",
        ]
        for n in names:
            with self.subTest(n=n):
                self.assertIsNone(m.TRANSIENT_SQLITE_RE.match(n))
                self.assertIsNone(m.TRANSIENT_SQLITE_RE.search(n))

    def test_telegram_cache_names(self):
        pos = ["bot-info-default.json", "sticker-cache.json", "thread-bindings-default.json",
               "thread-bindings-acc2.json", "update-offset-default.json", "update-offset-123456789.json",
               "bot-info-a.b.json"]
        neg = ["bot-info-.json", "sticker-cache.json.migrated", "thread-bindings-default.json.migrated",
               "thread-bindings-default.json.migrated.2", "sessions.json.telegram-messages.json",
               "ingress-spool-default", "sticker-cache-2.json", "Sticker-cache.json", "update-offset-default.json\n",
               "update-offset-x\n.json", "thread-bindings.json", "bot-info-default.JSON"]
        for n in pos:
            with self.subTest(pos=n):
                self.assertTrue(m.TELEGRAM_CACHE_RE.match(n))
        for n in neg:
            with self.subTest(neg=n):
                self.assertIsNone(m.TELEGRAM_CACHE_RE.match(n))

    def test_empty_bindings_variants(self):
        pos = ['{"version":1,"bindings":[]}', '{"bindings":[],"version":1}',
               '  {\n  "version" : 1 ,\n  "bindings" : [ ]\n}\n', '{\t"bindings":[\n],"version":1}\r\n']
        neg = ['{"version":2,"bindings":[]}', '{"version":1,"bindings":[{}]}', '{"bindings":[]}',
               '{"version":1,"bindings":[],"x":1}', '{"version":"1","bindings":[]}', '{"version":1.0,"bindings":[]}',
               '{"version":1,"bindings":[]}x', '[]', '']
        for raw in pos:
            with self.subTest(pos=raw):
                self.assertTrue(any(rx.match(raw) for rx in m.EMPTY_BINDINGS_RES))
                json.loads(raw)
        for raw in neg:
            with self.subTest(neg=raw):
                self.assertFalse(any(rx.match(raw) for rx in m.EMPTY_BINDINGS_RES))

    def test_legacy_ref_regex(self):
        cases = {"openai-codex/gpt-5.5": ("gpt-5.5", None), " OpenAI-Codex / gpt-5.4-mini ": ("gpt-5.4-mini", None),
                 "openai-codex/*": ("*", None), "openai-codex/gpt-5.5@openai-codex:default": ("gpt-5.5", "openai-codex:default")}
        for s, (x, prof) in cases.items():
            mm = m.LEGACY_REF_RE.match(s)
            self.assertTrue(mm, s)
            self.assertEqual((mm.group(1), mm.group(2)), (x, prof))
        for s in ("openai/gpt-5.5", "vllm/qwen3.5-122b", "codex/gpt-5", "openai-codex", "openai-codex/gpt 5.5",
                  "xopenai-codex/gpt-5.5", "openai-codex/gpt-5.5\nfoo"):
            self.assertIsNone(m.LEGACY_REF_RE.match(s), s)


class TestPathsAndRedaction(unittest.TestCase):
    def test_fmt_parse_roundtrip(self):
        for parts in (["agents", "defaults", "models", "openai-codex/gpt-5.5", "agentRuntime"],
                      ["agents", "list", 1, "models", "openai-codex/*"],
                      ["plugins", "entries", "memory-core", "config"],
                      ["agent:main:telegram:group:-100.5", "agentRuntimeOverride"],
                      ["a", "", 'we"ird', "x y", 0]):
            self.assertEqual(m.parse_path(m.fmt_path(parts)), parts)
        self.assertEqual(m.fmt_path(["agents", "defaults", "models", "openai-codex/gpt-5.5"]),
                         'agents.defaults.models["openai-codex/gpt-5.5"]')
        self.assertEqual(m.fmt_path(["plugins", "entries", "memory-core", "config", "dreaming", "enabled"]),
                         "plugins.entries.memory-core.config.dreaming.enabled")

    def test_redact_value(self):
        self.assertEqual(m.redact_value("gateway.auth.token", "abc"), "***")
        self.assertEqual(m.redact_value("channels.telegram.botToken", "1:x"), "***")
        self.assertEqual(m.redact_value("models.providers.vllm.apiKey", "sk"), "***")
        self.assertEqual(m.redact_value("auth.profiles", {"openai:default": {"type": "oauth"}}), "***")
        self.assertEqual(m.redact_value('auth.profiles["openai:default"].email', "a@b"), "***")
        self.assertEqual(m.redact_value("x.client_secret", "s"), "***")
        self.assertEqual(m.redact_value("x.password", "s"), "***")
        self.assertEqual(m.redact_value("agents.defaults.model.primary", "openai/gpt-5.5"), "openai/gpt-5.5")
        self.assertIsNone(m.redact_value("gateway.auth.token", None))
        nested = m.redact_value("channels.telegram", {"enabled": True, "botToken": "1:x", "accounts": {"a": {"botToken": "2"}}})
        self.assertEqual(nested, {"enabled": True, "botToken": "***", "accounts": {"a": {"botToken": "***"}}})
        whole = m.redact_value("", {"auth": {"profiles": {"p": {"access": "t"}}, "order": {"openai": ["p"]}}})
        self.assertEqual(whole, {"auth": {"profiles": "***", "order": {"openai": ["p"]}}})
        self.assertEqual(m.redact_value(["gateway", "auth", "token"], "abc"), "***")

    def test_flatten_paths(self):
        cfg = {"a": {"b": 1, "c": {}}, "l": [{"x": 1}, 2], "e": []}
        self.assertEqual(m.flatten_paths(cfg), {"a.b", "a.c", "l[0].x", "l[1]", "e"})
        before = fix("e4_before.json")
        after = fix("e4_after_pass2.json")
        removed = m.flatten_paths(before) - m.flatten_paths(after)
        self.assertIn("meta.lastTouchedAt", removed)
        self.assertIn("gateway.controlUi.dangerouslyDisableDeviceAuth", removed)


# --- refs scan, preflight, EXPLICIT ------------------------------------------------------------------


class TestScanAndPreflight(unittest.TestCase):
    def test_scan_domains(self):
        cfg = spec_example()
        cfg["agents"]["entries"] = {"ops": {"models": {"openai-codex/gpt-5.4@openai-codex:work": {}},
                                            "heartbeat": {"model": "openai-codex/gpt-5.4-pro@openai-codex:work"}}}
        cfg["models"] = {"providers": {"openai-codex": {"models": [{"id": "openai-codex/gpt-5.5"}]},
                                       "vllm": vllm_block()}}
        cfg["auth"]["profiles"] = {"openai-codex:default": {"provider": "openai-codex", "note": "openai-codex/gpt-5.5"}}
        cfg["misc"] = {"openai-codex/gpt-5.5": "not-a-models-map"}
        refs = {(r["path"], r["where"]) for r in m.scan_legacy_refs(cfg)}
        self.assertIn(("agents.defaults.model.primary", "value"), refs)
        self.assertIn(("agents.defaults.model.fallbacks[0]", "value"), refs)
        self.assertIn(("agents.defaults.heartbeat.model", "value"), refs)
        self.assertIn(("hooks.mappings[0].model", "value"), refs)
        self.assertIn(('agents.defaults.models["openai-codex/*"]', "key"), refs)
        self.assertIn(('agents.list[1].models["openai-codex/*"]', "key"), refs)
        self.assertIn(('agents.entries.ops.models["openai-codex/gpt-5.4@openai-codex:work"]', "key"), refs)
        self.assertIn(("agents.entries.ops.heartbeat.model", "value"), refs)
        self.assertFalse(any(p.startswith("auth") for p, _ in refs), "auth must not be scanned")
        self.assertFalse(any(p.startswith("models.providers") for p, _ in refs), "provider model ids excluded")
        self.assertFalse(any(p.startswith("misc") for p, _ in refs), "keys only inside models maps")
        prof = [r for r in m.scan_legacy_refs(cfg) if r["path"] == "agents.entries.ops.heartbeat.model"][0]
        self.assertEqual((prof["id"], prof["profile"], prof["agent_id"]), ("gpt-5.4-pro", "openai-codex:work", "ops"))
        helper = [r for r in m.scan_legacy_refs(cfg) if r["path"].startswith("agents.list[1]")][0]
        self.assertEqual(helper["agent_id"], "helper")

    def test_vllm_refs_not_legacy(self):
        self.assertEqual(m.scan_legacy_refs({"agents": {"defaults": {"model": "vllm/qwen3.5-122b",
                                                                     "models": {"vllm/*": {}}}}}), [])
        self.assertEqual(m.models_preflight(live_like()), [])

    def codes(self, cfg):
        return {f["code"]: f["cls"] for f in m.models_preflight(cfg)}

    def test_preflight_clean_examples(self):
        self.assertEqual(self.codes(spec_example()), {})
        self.assertEqual(self.codes(fix("e4_before.json")), {})

    def test_preflight_codex_provider(self):
        cfg = spec_example()
        cfg["agents"]["defaults"]["imageModel"] = "codex/gpt-5"
        self.assertEqual(self.codes(cfg)["models-codex-provider"], "hard")
        cfg = spec_example()
        cfg["agents"]["defaults"]["models"]["Codex-CLI / gpt-5"] = {}
        self.assertIn("models-codex-provider", self.codes(cfg))
        cfg = spec_example()
        cfg["models"] = {"providers": {"Codex": {"models": []}}}
        self.assertIn("models-codex-provider", self.codes(cfg))

    def test_preflight_codex_runtime_legacy_entries_only(self):
        """F3: a Codex pin on a legacy openai-codex/codex entry is hard; on a canonical openai/ entry,
        models.providers.openai or any other holder it is the documented 7.35 choice: kept (info)."""
        def pinned(where, rid):
            cfg = spec_example()
            cfg["agents"]["defaults"]["models"]["openai/o3"] = {}
            cfg["agents"]["list"][0]["models"] = {"openai-codex/gpt-5.4": {}}
            cfg["models"] = {"providers": {"openai": {"models": [{"id": "o3"}]},
                                           "openai-codex": {"models": [{"id": "gpt-5.5"}]}}}
            node = cfg
            for p in where:
                node = node[p]
            node["agentRuntime"] = {"id": rid}
            return self.codes(cfg)
        for rid in ("codex", " Codex-App-Server ", "codex-cli"):
            for where in (["agents", "defaults", "models", "openai-codex/gpt-5.5"],
                          ["agents", "defaults", "models", "openai-codex/*"],
                          ["agents", "list", 0, "models", "openai-codex/gpt-5.4"],
                          ["models", "providers", "openai-codex"], ["models", "providers", "openai-codex", "models", 0]):
                with self.subTest(where=where, rid=rid):
                    self.assertEqual(pinned(where, rid).get("models-codex-runtime"), "hard")
            for where in (["agents", "defaults", "models", "openai/o3"],
                          ["agents", "defaults", "models", "anthropic/claude-sonnet-4-6"], ["agents", "defaults"],
                          ["agents", "list", 0], ["models", "providers", "openai"],
                          ["models", "providers", "openai", "models", 0]):
                with self.subTest(where=where, rid=rid):
                    codes = pinned(where, rid)
                    self.assertNotIn("models-codex-runtime", codes)
                    self.assertEqual(codes.get("codex-runtime-kept"), "info")
        cfg = spec_example()
        cfg["agents"]["defaults"]["models"]["Codex/gpt-5"] = {"agentRuntime": {"id": "codex"}}
        self.assertEqual(self.codes(cfg).get("models-codex-runtime"), "hard")

    def test_preflight_documented_735_codex_pins_are_kept(self):
        """Reviewer repro userpin.py: v735 docs/providers/openai.md forces the Codex app-server this way."""
        for cfg in ({"agents": {"defaults": {"model": {"primary": "vllm/q", "fallbacks": ["openai/gpt-5.5"]},
                                             "models": {"openai/gpt-5.5": {"agentRuntime": {"id": "codex"}}}}}},
                    {"models": {"providers": {"openai": {"agentRuntime": {"id": "codex"}, "models": []}}},
                     "agents": {"defaults": {"model": {"primary": "openai/gpt-5.6-sol"}}}}):
            codes = self.codes(cfg)
            self.assertEqual(codes, {"codex-runtime-kept": "info", "canonical-openai-refs": "info"})
            msg = [f["message"] for f in m.models_preflight(cfg) if f["code"] == "codex-runtime-kept"][0]
            self.assertIn("agentRuntime.id=codex", msg)

    def test_preflight_provider_merge(self):
        cfg = spec_example()
        cfg["models"] = {"providers": {"openai-codex": {"models": [{"id": "gpt-5.5"}, {"id": "gpt-5.4-mini"}]},
                                       "openai": {"apiKey": "sk-x", "models": [{"id": "gpt-5.5"}]}}}
        self.assertEqual(self.codes(cfg).get("models-provider-merge"), "hard")
        cfg["models"]["providers"]["openai"]["models"].append({"id": "gpt-5.4-mini"})
        self.assertNotIn("models-provider-merge", self.codes(cfg))
        del cfg["models"]["providers"]["openai"]
        self.assertNotIn("models-provider-merge", self.codes(cfg))

    def test_preflight_wildcard_pinned(self):
        for rid, held in (("", False), ("auto", False), ("default", False), ("openclaw", False), ("pi", False),
                          ("claude-cli", True), ("codex", True)):
            cfg = spec_example()
            cfg["agents"]["defaults"]["models"]["openai-codex/*"] = {"agentRuntime": {"id": rid}}
            with self.subTest(rid=rid):
                self.assertEqual("models-wildcard-pinned" in self.codes(cfg), held)

    def test_preflight_platform_only_and_canonical(self):
        cfg = spec_example()
        cfg["agents"]["defaults"]["model"]["fallbacks"].append("openai-codex/GPT-5.6")
        cfg["agents"]["defaults"]["imageModel"] = "openai-codex/chat-latest"
        self.assertEqual(self.codes(cfg).get("models-platform-only"), "acceptable")
        cfg = spec_example()
        cfg["tools"] = {"media": {"model": "openai/whisper-1"}}
        # contract addendum 2 (D12 replaced): logged only, never a HOLD, never re-pinned
        self.assertEqual(self.codes(cfg).get("canonical-openai-refs"), "info")
        msg = [f["message"] for f in m.models_preflight(cfg) if f["code"] == "canonical-openai-refs"][0]
        self.assertTrue(msg.startswith("1 canonical openai/* refs keep their runtime (Codex app-server by default, "
                                       "as on 7.35)"), msg)
        cfg = spec_example()
        cfg["agents"]["defaults"]["models"]["OpenAI/o3"] = {}
        self.assertIn("canonical-openai-refs", self.codes(cfg))
        # F2: an id that is also a legacy ref is a route collision, not "keeps its runtime"
        cfg["agents"]["defaults"]["models"]["OpenAI/gpt-5.5"] = {}
        self.assertEqual(self.codes(cfg).get("models-route-collision"), "acceptable")
        msg = [f["message"] for f in m.models_preflight(cfg) if f["code"] == "canonical-openai-refs"][0]
        self.assertIn("OpenAI/o3", msg)
        self.assertNotIn("gpt-5.5", msg)
        cfg = spec_example()
        cfg["models"] = {"providers": {"openai": {"models": [{"id": "openai/gpt-5.5"}]}}}
        self.assertNotIn("canonical-openai-refs", self.codes(cfg), "provider model ids are not scanned")

    def test_findings_shape(self):
        cfg = spec_example()
        cfg["agents"]["defaults"]["imageModel"] = "codex/gpt-5"
        for f in m.models_preflight(cfg):
            self.assertEqual(set(f), {"code", "cls", "message", "phase"})
            self.assertEqual(f["phase"], "precheck")

    def test_explicit_ids(self):
        cfg = spec_example()
        cfg["models"] = {"providers": {"openai-codex": {"models": [{"id": "gpt-5.2"}, {"id": "bad id"}]}}}
        cfg["agents"]["defaults"]["imageModel"] = "openai-codex/gpt-5.4-nano@openai-codex:x"
        ids = m.explicit_ids(cfg)
        self.assertEqual(ids, sorted(set(ids)))
        for x in m.EXPLICIT_DEFAULT_IDS + ["gpt-5.2", "gpt-5.4-nano"]:
            self.assertIn(x, ids)
        self.assertNotIn("*", ids)
        self.assertNotIn("bad id", ids)
        self.assertEqual(m.explicit_ids({}), sorted(m.EXPLICIT_DEFAULT_IDS))

    def test_remap(self):
        self.assertEqual(m.remap_model_id("gpt-5.2-codex"), "gpt-5.5")
        self.assertEqual(m.remap_model_id("GPT-5.2"), "gpt-5.5")
        self.assertEqual(m.remap_model_id("gpt-5.1-codex"), "gpt-5.5")
        self.assertEqual(m.remap_model_id("gpt-5-codex"), "gpt-5.5")
        self.assertEqual(m.remap_model_id("gpt-4.1-nano"), "gpt-5.4-mini")
        self.assertEqual(m.remap_model_id("gpt-5-nano"), "gpt-5.4-mini")
        self.assertEqual(m.remap_model_id("gpt-5-mini"), "gpt-5.4-mini")      # generic retired-OpenAI table
        self.assertEqual(m.remap_model_id("gpt-5-pro"), "gpt-5.5-pro")
        self.assertEqual(m.remap_model_id("gpt-5.5"), "gpt-5.5")
        self.assertEqual(m.remap_model_id("My-Model"), "My-Model")


# --- R1-R3 ------------------------------------------------------------------------------------------


class TestPremigrateConfig(unittest.TestCase):
    def test_golden_e4(self):
        before = fix("e4_before.json")
        expected = fix("e4_pretransform.json")
        snapshot = copy.deepcopy(before)
        new, ledger, summary = m.premigrate_config(before)
        self.assertEqual(before, snapshot, "input mutated")
        self.assertEqual(new["agents"]["defaults"]["models"], expected["agents"]["defaults"]["models"])
        self.assertEqual(new, expected, "only agents.defaults.models may change")
        self.assertNotIn("modelPolicy", new["agents"]["defaults"])
        self.assertFalse(summary["model_policy_written"])
        self.assertEqual(summary["scopes"], ["defaults"])
        self.assertEqual(summary["pinned"], 10)
        self.assertEqual(set(summary["explicit"]), set(m.EXPLICIT_DEFAULT_IDS))
        self.assertEqual({s["path"] for s in summary["legacy_slots"]},
                         {"agents.defaults.model.primary", 'agents.defaults.models["openai-codex/gpt-5.5"]'})
        self.assertEqual(new["meta"], before["meta"])
        steps = [e["step"] for e in ledger]
        self.assertEqual(steps.count("R1"), 1 + 9)   # wildcard removed + 9 new keys
        for e in ledger:
            self.assertEqual(set(e) - {"note"}, {"step", "file", "path", "before", "after"})
        json.dumps(ledger)
        json.dumps(summary)

    def test_golden_scratch_originals(self):
        for name, path in SCRATCH_GOLDEN.items():
            if not os.path.exists(path):
                self.skipTest("scratchpad golden missing: %s" % path)
            with open(path, encoding="utf-8") as f:
                original = json.load(f)
            if name != "pins_final_99.json":
                original = sanitize(original)
            self.assertEqual(original, fix(name), name)

    def test_spec_example(self):
        cfg = spec_example()
        new, ledger, summary = m.premigrate_config(cfg)
        dm = new["agents"]["defaults"]["models"]
        self.assertNotIn("openai-codex/*", dm)
        self.assertEqual(dm["openai-codex/gpt-5.5"], {"alias": "main", "agentRuntime": {"id": "openclaw"}})
        self.assertEqual(dm["openai-codex/gpt-5.4-mini"], {"agentRuntime": {"id": "openclaw"}})
        for x in m.EXPLICIT_DEFAULT_IDS:
            self.assertEqual(dm["openai-codex/" + x]["agentRuntime"], {"id": "openclaw"})
        self.assertEqual(dm["anthropic/claude-sonnet-4-6"], {"alias": "sonnet"}, "non-legacy entries untouched")
        # refs stay legacy (R4)
        self.assertEqual(new["agents"]["defaults"]["model"]["primary"], "openai-codex/gpt-5.5")
        self.assertEqual(new["hooks"], cfg["hooks"])
        self.assertEqual(new["auth"], cfg["auth"])
        # per-agent wildcard (agents.list[1]): expanded with params, without alias/agentRuntime, then pinned
        hm = new["agents"]["list"][1]["models"]
        self.assertNotIn("openai-codex/*", hm)
        for x in m.EXPLICIT_DEFAULT_IDS:
            self.assertEqual(hm["openai-codex/" + x], {"params": {"temperature": 0.2}, "agentRuntime": {"id": "openclaw"}})
        self.assertEqual(sorted(summary["scopes"]), sorted(["defaults", "agents.list[1]"]))
        # never: canonical keys, provider runtime, agent-level runtime
        self.assertFalse(any(k.startswith("openai/") for k in dm))
        self.assertNotIn("agentRuntime", new["agents"]["defaults"])
        self.assertNotIn("agentRuntime", new["agents"]["list"][1])
        self.assertNotIn("models", new)
        self.assertFalse(summary["model_policy_written"])

    def test_per_agent_entries_wildcard(self):
        cfg = {"agents": {"defaults": {"model": "vllm/qwen3.5-122b"},
                          "entries": {"ops": {"models": {"OpenAI-Codex / * ": {"streaming": True},
                                                         "openai-codex/gpt-5.5": {"alias": "g"}}}}}}
        new, ledger, summary = m.premigrate_config(cfg)
        om = new["agents"]["entries"]["ops"]["models"]
        self.assertNotIn("OpenAI-Codex / * ", om)
        self.assertEqual(om["openai-codex/gpt-5.5"], {"alias": "g", "agentRuntime": {"id": "openclaw"}})
        self.assertEqual(om["openai-codex/gpt-6-astra"], {"streaming": True, "agentRuntime": {"id": "openclaw"}})
        self.assertEqual(summary["scopes"], ["agents.entries.ops"])
        # defaults map created for the explicit ref (i) -> R3 writes modelPolicy {}
        self.assertEqual(new["agents"]["defaults"]["models"], {"openai-codex/gpt-5.5": {"agentRuntime": {"id": "openclaw"}}})
        self.assertEqual(new["agents"]["defaults"]["modelPolicy"], {})
        self.assertTrue(summary["model_policy_written"])

    def test_r1_existing_key_variants_not_duplicated(self):
        cfg = {"agents": {"defaults": {"models": {"openai-codex/*": {}, "OPENAI-CODEX / gpt-5.4": {"alias": "four"}}}}}
        new, _ledger, _summary = m.premigrate_config(cfg)
        dm = new["agents"]["defaults"]["models"]
        self.assertNotIn("openai-codex/gpt-5.4", dm)
        self.assertEqual(dm["OPENAI-CODEX / gpt-5.4"], {"alias": "four", "agentRuntime": {"id": "openclaw"}})

    def test_r2_runtime_values(self):
        cases = {None: {"id": "openclaw"}, "": {"id": "openclaw", "x": 1}, "auto": {"id": "openclaw", "x": 1},
                 "default": {"id": "openclaw", "x": 1}, "openclaw": {"id": "openclaw", "x": 1}, "pi": {"id": "pi", "x": 1}}
        for prior, want in cases.items():
            entry = {} if prior is None else {"agentRuntime": {"id": prior, "x": 1}}
            cfg = {"agents": {"defaults": {"model": "openai-codex/gpt-5.5", "models": {"openai-codex/gpt-5.5": entry}}}}
            new, _l, _s = m.premigrate_config(cfg)
            with self.subTest(prior=prior):
                self.assertEqual(new["agents"]["defaults"]["models"]["openai-codex/gpt-5.5"]["agentRuntime"], want)

    def test_r2_profile_refs_pin_bare_key(self):
        cfg = {"agents": {"defaults": {"model": {"primary": "openai-codex/gpt-5.5@openai-codex:work"},
                                       "models": {"vllm/qwen": {}}}}}
        new, _l, summary = m.premigrate_config(cfg)
        self.assertEqual(new["agents"]["defaults"]["models"]["openai-codex/gpt-5.5"], {"agentRuntime": {"id": "openclaw"}})
        self.assertEqual(new["agents"]["defaults"]["model"]["primary"], "openai-codex/gpt-5.5@openai-codex:work")
        self.assertNotIn("modelPolicy", new["agents"]["defaults"])
        self.assertEqual(summary["legacy_slots"][0]["profile"], "openai-codex:work")

    def test_r3_variants(self):
        for models, written in ((None, True), ({}, True), ({"anthropic/x": {}}, False)):
            d = {"model": {"primary": "openai-codex/gpt-5.5"}}
            if models is not None:
                d["models"] = models
            new, ledger, summary = m.premigrate_config({"agents": {"defaults": d}})
            with self.subTest(models=models):
                self.assertEqual(summary["model_policy_written"], written)
                self.assertEqual("modelPolicy" in new["agents"]["defaults"], written)
                self.assertEqual(any(e["step"] == "R3" for e in ledger), written)
        new, _l, summary = m.premigrate_config({"agents": {"defaults": {"model": "openai-codex/gpt-5.5",
                                                                         "modelPolicy": {"allow": ["x"]}}}})
        self.assertEqual(new["agents"]["defaults"]["modelPolicy"], {"allow": ["x"]})
        self.assertFalse(summary["model_policy_written"])

    def test_no_legacy_refs_is_noop(self):
        for cfg in (live_like_without_codex(), {"agents": {"defaults": {}}}, {}):
            new, ledger, summary = m.premigrate_config(cfg)
            self.assertEqual(new, cfg)
            self.assertEqual(ledger, [])
            self.assertEqual(summary, {"explicit": [], "pinned": 0, "scopes": [], "model_policy_written": False,
                                       "legacy_slots": []})

    def test_live_like_vllm_untouched(self):
        cfg = live_like()
        new, ledger, summary = m.premigrate_config(cfg)
        self.assertEqual(new["models"], cfg["models"])
        self.assertEqual(new["agents"]["defaults"]["model"], cfg["agents"]["defaults"]["model"])
        dm = new["agents"]["defaults"]["models"]
        self.assertEqual(dm["vllm/qwen3.5-122b"], {"alias": "qwen"})
        self.assertEqual(dm["vllm/*"], {})
        self.assertEqual(dm["openai-codex/gpt-5.5"], {"agentRuntime": {"id": "openclaw"}})
        self.assertEqual(summary["pinned"], 1)
        self.assertEqual(summary["scopes"], [])
        self.assertFalse(summary["model_policy_written"])
        self.assertFalse(any("vllm" in e["path"] for e in ledger))

    def test_non_object_models_map_raises(self):
        with self.assertRaises(ValueError):
            m.premigrate_config({"agents": {"defaults": {"model": "openai-codex/gpt-5.5", "models": []}}})
        with self.assertRaises(ValueError):
            m.premigrate_config([])

    def test_deterministic_rerun(self):
        cfg = spec_example()
        a = m.premigrate_config(cfg)
        b = m.premigrate_config(cfg)
        self.assertEqual(a, b)


def live_like_without_codex():
    cfg = live_like()
    cfg["agents"]["defaults"]["model"]["fallbacks"] = ["vllm/qwen3.5-122b"]
    del cfg["agents"]["defaults"]["models"]["openai-codex/gpt-5.5"]
    return cfg


# --- R5 sessions -----------------------------------------------------------------------------------


class TestSessions(unittest.TestCase):
    def store(self):
        return {
            "agent:main:main": {"sessionId": "a", "updatedAt": 1, "modelProvider": "openai-codex", "model": "gpt-5.5"},
            "agent:main:telegram:direct:1": {"sessionId": "b", "providerOverride": "openai-codex",
                                             "modelOverride": "gpt-5.4-mini"},
            "agent:main:x": {"sessionId": "c", "agentRuntimeOverride": "openclaw"},
            "agent:main:auto": {"modelProvider": " OpenAI-Codex ", "agentRuntimeOverride": "auto"},
            "agent:main:empty": {"model": "openai-codex/gpt-5.5", "agentRuntimeOverride": ""},
            "agent:main:none": {"modelOverride": "codex/gpt-5", "agentRuntimeOverride": None},
            "agent:main:pi": {"modelProvider": "codex", "agentRuntimeOverride": "pi"},
            "agent:main:user": {"modelProvider": "openai-codex", "agentRuntimeOverride": "codex"},
            "agent:main:harness": {"modelProvider": "openai-codex", "agentHarnessId": "codex-supervisor"},
            "agent:main:vllm": {"modelProvider": "vllm", "model": "qwen3.5-122b"},
            "agent:main:noneprov": {"modelProvider": None, "model": None},
            "weird": "not-a-dict",
        }

    def test_r5(self):
        store = self.store()
        snap = copy.deepcopy(store)
        new, ledger, summary = m.premigrate_sessions(store, "agents/main/sessions/sessions.json")
        self.assertEqual(store, snap)
        for k in ("agent:main:main", "agent:main:telegram:direct:1", "agent:main:auto", "agent:main:empty",
                  "agent:main:none"):
            self.assertEqual(new[k]["agentRuntimeOverride"], "openclaw", k)
            self.assertIn(k, summary["pinned"])
        self.assertIn("agent:main:pi", summary["pinned"])
        self.assertEqual(new["agent:main:pi"]["agentRuntimeOverride"], "pi")
        self.assertEqual(summary["user_explicit"], ["agent:main:user"])
        self.assertEqual(new["agent:main:user"]["agentRuntimeOverride"], "codex")
        self.assertEqual(summary["harness"], ["agent:main:harness"])
        self.assertNotIn("agentRuntimeOverride", new["agent:main:harness"])
        for k in ("agent:main:x", "agent:main:vllm", "agent:main:noneprov", "weird"):
            self.assertEqual(new[k], snap[k])
        notes = {e["path"]: e.get("note") for e in ledger}
        self.assertEqual(notes["agent:main:user.agentRuntimeOverride"], "user-explicit")
        self.assertEqual(notes["agent:main:harness.agentRuntimeOverride"], "harness")
        changed = [e for e in ledger if "note" not in e]
        self.assertEqual(len(changed), 5)
        for e in ledger:
            self.assertEqual(e["step"], "R5")
            self.assertEqual(e["file"], "agents/main/sessions/sessions.json")
        with self.assertRaises(ValueError):
            m.premigrate_sessions([], "x")

    def test_scan_sessions_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "agents", "main", "sessions"))
            os.makedirs(os.path.join(tmp, "agents", "bad", "sessions"))
            os.makedirs(os.path.join(tmp, "agents", "list", "sessions"))
            os.makedirs(os.path.join(tmp, "agents", "link", "sessions"))
            os.makedirs(os.path.join(tmp, "agents", "nosess"))
            os.makedirs(os.path.join(tmp, "sessions"))
            with open(os.path.join(tmp, "agents/main/sessions/sessions.json"), "w") as f:
                json.dump(self.store(), f)
            with open(os.path.join(tmp, "sessions/sessions.json"), "w") as f:
                f.write("{}")
            with open(os.path.join(tmp, "agents/bad/sessions/sessions.json"), "w") as f:
                f.write("{not json")
            with open(os.path.join(tmp, "agents/list/sessions/sessions.json"), "w") as f:
                f.write("[]")
            os.symlink(os.path.join(tmp, "sessions/sessions.json"), os.path.join(tmp, "agents/link/sessions/sessions.json"))
            stores, findings = m.scan_sessions_files(tmp)
            self.assertEqual([r for r, _ in stores], ["sessions/sessions.json", "agents/main/sessions/sessions.json"])
            self.assertEqual(stores[1][1]["agent:main:main"]["model"], "gpt-5.5")
            self.assertEqual(len(findings), 1)
            self.assertEqual((findings[0]["code"], findings[0]["cls"]), ("sessions-unreadable", "hard"))
            for bad in ("agents/bad", "agents/list", "agents/link"):
                self.assertIn(bad, findings[0]["message"])
            stores, findings = m.scan_sessions_files(os.path.join(tmp, "missing"))
            self.assertEqual((stores, findings), ([], []))


# --- F1-F3 -------------------------------------------------------------------------------------------


def doctor_pass1_like():
    """What doctor pass 1 writes on spec_example() after R1/R2 (refs canonical, list -> entries, plus the
    doctor-side effects F1-F3 must repair)."""
    return {
        "meta": {"lastTouchedVersion": "2026.9.9", "migrations": {"modelPolicyAllowlist": True}},
        "agents": {
            "defaults": {
                "model": {"primary": "openai/gpt-5.5", "fallbacks": ["openai/gpt-5.4-mini"]},
                "heartbeat": {"model": "openai/gpt-5.4-mini"},
                "models": {"openai/gpt-5.5": {"alias": "main", "agentRuntime": {"id": "openclaw"}},
                           "openai/gpt-5.4-mini": {"agentRuntime": {"id": "codex", "authProfileId": "openai:default"}},
                           "openai/gpt-6-astra": {"agentRuntime": {"id": "openclaw"}},
                           "anthropic/claude-sonnet-4-6": {"alias": "sonnet"}},
                "modelPolicy": {"allow": ["openai/gpt-5.5", "openai/gpt-5.4-mini", "anthropic/claude-sonnet-4-6"]},
            },
            "entries": {"main": {"default": True},
                        "helper": {"models": {"openai/gpt-5.5": {"agentRuntime": {"id": "codex-app-server"}},
                                              "openai-codex/gpt-5.2-codex": {"params": {"t": 1}}},
                                   "heartbeat": {"model": "openai-codex/gpt-5.4-mini"}}},
        },
        "hooks": {"mappings": [{"model": "openai-codex/gpt-5.4-mini"}]},
        "channels": {"telegram": {"enabled": True}, "modelByChannel": {"telegram": {"default": "openai-codex/gpt-5-nano"}}},
        "models": {"providers": {"openai": {"agentRuntime": {"id": "codex"},
                                            "models": [{"id": "gpt-5.5", "agentRuntime": {"id": "codex"}}]},
                                 "vllm": vllm_block()}},
        "plugins": {"entries": {"codex": {"enabled": True}, "openai": {"enabled": True}}},
    }


class TestFixups(unittest.TestCase):
    def setUp(self):
        self.pre_gate = spec_example()
        self.pre_pass1, _l, _s = m.premigrate_config(self.pre_gate)
        self.now = doctor_pass1_like()

    def run_fixups(self):
        snap = (copy.deepcopy(self.now), copy.deepcopy(self.pre_gate), copy.deepcopy(self.pre_pass1))
        out = m.fixups(self.now, self.pre_gate, self.pre_pass1)
        self.assertEqual((self.now, self.pre_gate, self.pre_pass1), snap, "inputs mutated")
        return out

    def test_f1_codex_pins_to_openclaw(self):
        new, ledger, s = self.run_fixups()
        d = new["agents"]["defaults"]["models"]
        self.assertEqual(d["openai/gpt-5.4-mini"]["agentRuntime"], {"id": "openclaw", "authProfileId": "openai:default"})
        self.assertEqual(new["agents"]["entries"]["helper"]["models"]["openai/gpt-5.5"]["agentRuntime"], {"id": "openclaw"})
        # contract addendum 2 rule 3: only models-map keys of migrated slots; provider blocks never
        self.assertEqual(new["models"]["providers"]["openai"], self.now["models"]["providers"]["openai"])
        self.assertEqual(s["codex_pins"], 2)
        self.assertEqual(new["models"]["providers"]["vllm"], vllm_block())
        self.assertEqual(m.check_codex_runtime(new, pre_cfg=self.pre_gate), [])

    def test_f1_list_scope(self):
        now = {"agents": {"list": [{"id": "a", "models": {"openai/x": {"agentRuntime": {"id": "CODEX"}}}}]}}
        new, _l, s = m.fixups(now, {}, {})
        self.assertEqual(new, now, "no legacy slot before the gate: nothing to flip")
        pre = {"agents": {"list": [{"id": "A", "model": "openai-codex/x"}]}}
        new, _l, s = m.fixups(now, pre, pre)
        self.assertEqual(new["agents"]["list"][0]["models"]["openai/x"]["agentRuntime"]["id"], "openclaw")
        self.assertEqual(s["codex_pins"], 1)

    def test_f1_never_touches_canonical_keys_or_refs(self):
        """Addendum 2 rules 2/3: keys that existed canonically, an agent's own canonical refs (doctor's
        shield) and the openai/* wildcard keep doctor's runtime; legacy-derived keys are flipped."""
        pre = {"agents": {"defaults": {"model": {"primary": "openai-codex/gpt-5.5",
                                                 "fallbacks": ["openai-codex/gpt-5.4-mini"]},
                                       "models": {"openai/gpt-5.4-mini": {"alias": "mini"}, "openai/*": {}}},
                          "list": [{"id": "main"}, {"id": "ops", "model": "openai/gpt-5.5"}]},
               "hooks": {"mappings": [{"model": "openai-codex/gpt-5.6-sol"}]}}
        codex = {"agentRuntime": {"id": "codex"}}
        now = {"agents": {"defaults": {"model": {"primary": "openai/gpt-5.5", "fallbacks": ["openai/gpt-5.4-mini"]},
                                       "models": {"openai/gpt-5.5": dict(codex), "openai/gpt-5.4-mini": dict(codex),
                                                  "openai/*": dict(codex),
                                                  "openai/gpt-5.6-sol": {"agentRuntime": {"id": "openclaw"}}}},
                          "entries": {"main": {"models": {"openai/gpt-5.5": dict(codex),
                                                          "openai/gpt-5.6-sol": dict(codex),
                                                          "openai/gpt-5.4": dict(codex)}},
                                      "ops": {"model": "openai/gpt-5.5",
                                              "models": {"openai/gpt-5.5": dict(codex)}}}},
               "hooks": {"mappings": [{"model": "openai/gpt-5.6-sol"}]}}
        new, ledger, s = m.fixups(now, pre, pre)
        rt = lambda *p: m._get(new, list(p) + ["agentRuntime", "id"])  # noqa: E731
        self.assertEqual(rt("agents", "defaults", "models", "openai/gpt-5.5"), "openclaw")          # legacy
        self.assertEqual(rt("agents", "defaults", "models", "openai/gpt-5.4-mini"), "codex")        # canonical key
        self.assertEqual(rt("agents", "defaults", "models", "openai/*"), "codex")                   # wildcard
        self.assertEqual(rt("agents", "entries", "main", "models", "openai/gpt-5.5"), "openclaw")   # inherited legacy
        self.assertEqual(rt("agents", "entries", "main", "models", "openai/gpt-5.6-sol"), "openclaw")  # hooks slot
        self.assertEqual(rt("agents", "entries", "main", "models", "openai/gpt-5.4"), "codex")      # never legacy
        self.assertEqual(rt("agents", "entries", "ops", "models", "openai/gpt-5.5"), "codex")       # ops' own canonical
        self.assertEqual(s["codex_pins"], 3)
        # PC2 then reports only the deliberate conflicts: the legacy fallback lands on the canonical
        # gpt-5.4-mini key, and agent ops' own canonical gpt-5.5 key (shield) for the inherited primary
        probs = m.check_codex_runtime(new, pre)
        self.assertTrue(probs and all("gpt-5.4-mini" in p or "agent ops" in p for p in probs), probs)
        self.assertFalse(any(p.startswith("Codex runtime pin on migrated") for p in probs), probs)
        before = m.check_codex_runtime(now, pre)
        self.assertEqual(sum(1 for p in before if p.startswith("Codex runtime pin on migrated")), 3, before)
        # cron-only legacy ids (doctor: "migrated cron runtime intent")
        new2, _l, s2 = m.fixups(now, pre, pre, extra_legacy_ids=["gpt-5.4"])
        self.assertEqual(m._get(new2, ["agents", "entries", "main", "models", "openai/gpt-5.4", "agentRuntime", "id"]),
                         "openclaw")
        self.assertEqual(s2["codex_pins"], 4)

    def test_legacy_key_context(self):
        pre = spec_example()
        pre["agents"]["list"][0]["model"] = {"primary": "openai/gpt-5.4-pro"}
        ctx = m.legacy_key_context(pre, {"openai/gpt-5.4-mini": "openai/gpt-5.6-luna"})
        self.assertTrue(m.is_migrated_legacy_key(ctx, None, "gpt-5.6-luna"), "retirement successor of a legacy id")
        self.assertTrue(m.is_migrated_legacy_key(ctx, "helper", "gpt-6-astra"), "R1 expansion (EXPLICIT)")
        self.assertTrue(m.is_migrated_legacy_key(ctx, "main", "gpt-5.5"))
        self.assertFalse(m.is_migrated_legacy_key(ctx, "main", "gpt-5.4-pro"), "main's own canonical ref")
        self.assertTrue(m.is_migrated_legacy_key(ctx, "helper", "gpt-5.4-pro"))
        self.assertFalse(m.is_migrated_legacy_key(ctx, None, "*"))
        self.assertFalse(m.is_migrated_legacy_key(ctx, None, "gpt-9-unknown"))
        self.assertFalse(m.is_migrated_legacy_key(m.legacy_key_context({}), None, "gpt-5.5"))

    def test_f1b_codex_plugin(self):
        new, ledger, s = self.run_fixups()
        self.assertNotIn("codex", new["plugins"]["entries"])
        self.assertTrue(s["codex_plugin_restored"])
        self.assertFalse(s["codex_needed"])
        self.assertEqual([e for e in ledger if e["step"] == "F1b"][0]["after"], None)
        # pre value restored exactly
        self.pre_pass1["plugins"] = {"entries": {"codex": {"enabled": False, "config": {"a": 1}}}}
        new, _l, s = self.run_fixups()
        self.assertEqual(new["plugins"]["entries"]["codex"], {"enabled": False, "config": {"a": 1}})
        # unchanged -> nothing
        self.now["plugins"]["entries"]["codex"] = {"enabled": False, "config": {"a": 1}}
        new, ledger, s = self.run_fixups()
        self.assertFalse(s["codex_plugin_restored"])
        self.assertFalse(any(e["step"] == "F1b" for e in ledger))
        # deleted by doctor -> restored
        del self.now["plugins"]["entries"]["codex"]
        new, _l, s = self.run_fixups()
        self.assertEqual(new["plugins"]["entries"]["codex"], {"enabled": False, "config": {"a": 1}})

    def test_f1b_rule4_codex_in_use_before(self):
        """Addendum 2 rule 4: doctor's codex plugin value stays when Codex was in use before the gate
        (canonical openai/ refs or keys, or an installed codex plugin package)."""
        new, ledger, s = m.fixups(self.now, self.pre_gate, self.pre_pass1, codex_pkg_before=True)
        self.assertEqual(new["plugins"]["entries"]["codex"], {"enabled": True})
        self.assertEqual((s["codex_plugin_restored"], s["codex_needed"]), (False, True))
        self.assertFalse(any(e["step"] == "F1b" for e in ledger))
        # F15: only text-model uses count; image/TTS/PDF/media/memory-search models never ran on Codex
        not_text = ({"agents": {"defaults": {"imageModel": "openai/gpt-image-1"}}},
                    {"agents": {"defaults": {"imageGenerationModel": {"primary": "openai/gpt-image-1"}}}},
                    {"agents": {"defaults": {"pdfModel": "openai/gpt-5.5"}}},
                    {"agents": {"defaults": {"memorySearch": {"model": "openai/text-embedding-3-small"}}}},
                    {"messages": {"tts": {"openai": {"model": "openai/gpt-4o-mini-tts"}}}},
                    {"tools": {"media": {"audio": {"models": [{"model": "openai/whisper-1"}]}}}})
        text = ({"agents": {"defaults": {"model": {"primary": "vllm/q", "fallbacks": ["openai/gpt-5.5"]}}}},
                {"agents": {"defaults": {"heartbeat": {"model": "openai/o3"}}}},
                {"agents": {"defaults": {"subagents": {"model": {"primary": "openai/o3"}}}}},
                {"agents": {"defaults": {"compaction": {"model": "openai/o3"}}}},
                {"agents": {"defaults": {"utilityModel": "openai/o3"}}},
                {"agents": {"list": [{"id": "a", "model": "openai/o3"}]}},
                {"agents": {"entries": {"a": {"heartbeat": {"model": "openai/o3"}}}}},
                {"agents": {"defaults": {"models": {"openai/o3": {}}}}},
                {"hooks": {"mappings": [{"model": "openai/o3"}]}})
        for extra, needed in [(x, False) for x in not_text] + [(x, True) for x in text]:
            with self.subTest(extra=extra):
                self.assertEqual(bool(m.canonical_text_model_refs(extra)), needed)
                pre = copy.deepcopy(self.pre_gate)
                for k, v in copy.deepcopy(extra).items():
                    if k != "agents":
                        pre[k] = v
                        continue
                    for ak, av in v.items():
                        if ak == "defaults":
                            pre["agents"]["defaults"].update(av)
                        else:
                            pre["agents"][ak] = av
                new, _l, s = m.fixups(self.now, pre, self.pre_pass1)
                self.assertEqual(s["codex_needed"], needed)
                self.assertEqual("codex" in new["plugins"]["entries"], needed)
        # the same rule after pass 2/3 and in bump/maintenance mode
        now = {"plugins": {"entries": {"codex": {"enabled": True}}}}
        self.assertEqual(m.post_doctor_fixups(now, {})[2]["codex_plugin_restored"], True)
        self.assertEqual(m.post_doctor_fixups(now, {}, codex_pkg_before=True)[1], [])
        self.assertEqual(m.post_doctor_fixups(now, {"agents": {"defaults": {"models": {"openai/*": {}}}}})[1], [])

    def test_f2_rewrites_and_pins(self):
        new, ledger, s = self.run_fixups()
        self.assertEqual(new["agents"]["entries"]["helper"]["heartbeat"]["model"], "openai/gpt-5.4-mini")
        self.assertEqual(new["hooks"]["mappings"][0]["model"], "openai/gpt-5.4-mini")
        self.assertEqual(new["channels"]["modelByChannel"]["telegram"]["default"], "openai/gpt-5.4-mini")  # gpt-5-nano
        hm = new["agents"]["entries"]["helper"]["models"]
        self.assertNotIn("openai-codex/gpt-5.2-codex", hm)
        # renamed key merged into the existing canonical entry without overwriting its fields
        self.assertEqual(hm["openai/gpt-5.5"], {"agentRuntime": {"id": "openclaw"}, "params": {"t": 1}})
        self.assertEqual(s["refs_rewritten"], 4)
        d = new["agents"]["defaults"]["models"]
        self.assertEqual(d["openai/gpt-5.5"]["agentRuntime"]["id"], "openclaw")
        self.assertEqual(d["openai/gpt-5.4-mini"]["agentRuntime"]["id"], "openclaw")
        self.assertEqual(s["policy_failures"], [])
        self.assertEqual(m.check_legacy_refs(new), [])

    def test_f2_profile_and_wildcard_left(self):
        self.now["agents"]["defaults"]["imageModel"] = "openai-codex/gpt-5.4@openai-codex:work"
        self.now["agents"]["defaults"]["modelPolicy"]["allow"].append("openai-codex/*")
        new, _l, _s = self.run_fixups()
        self.assertEqual(new["agents"]["defaults"]["imageModel"], "openai-codex/gpt-5.4@openai-codex:work")
        self.assertIn("openai-codex/*", new["agents"]["defaults"]["modelPolicy"]["allow"])
        problems = m.check_legacy_refs(new)
        self.assertTrue(any("imageModel" in p for p in problems))
        self.assertTrue(any("modelPolicy.allow" in p for p in problems))

    def test_f2_key_rename_without_canonical(self):
        now = {"meta": {"migrations": {"modelPolicyAllowlist": True}},
               "agents": {"defaults": {"models": {"a/b": {}, "openai-codex/gpt-5.4": {"alias": "four"}, "z/z": {}}}}}
        new, ledger, s = m.fixups(now, {}, {})
        self.assertEqual(list(new["agents"]["defaults"]["models"]), ["a/b", "openai/gpt-5.4", "z/z"])
        self.assertEqual(new["agents"]["defaults"]["models"]["openai/gpt-5.4"],
                         {"alias": "four", "agentRuntime": {"id": "openclaw"}})

    def test_f2_merge_canonical_later_in_map(self):
        now = {"meta": {"migrations": {"modelPolicyAllowlist": True}},
               "agents": {"defaults": {"models": {"openai-codex/gpt-5.5": {"alias": "old", "params": {"p": 1}},
                                                  "openai/gpt-5.5": {"alias": "new"}}}}}
        new, _l, _s = m.fixups(now, {}, {})
        self.assertEqual(new["agents"]["defaults"]["models"],
                         {"openai/gpt-5.5": {"alias": "new", "params": {"p": 1}, "agentRuntime": {"id": "openclaw"}}})

    def test_f2_pin_policy_failure(self):
        now = {"agents": {"defaults": {"heartbeat": {"model": "openai-codex/gpt-5.4-mini"}}}}
        new, _l, s = m.fixups(now, {}, {})
        self.assertEqual(new["agents"]["defaults"]["heartbeat"]["model"], "openai/gpt-5.4-mini")
        self.assertNotIn("models", new["agents"]["defaults"])
        self.assertEqual([(f["code"], f["cls"]) for f in s["policy_failures"]], [("pc-runtime-pin", "acceptable")])
        now["agents"]["defaults"]["modelPolicy"] = {}
        new, _l, s = m.fixups(now, {}, {})
        self.assertEqual(new["agents"]["defaults"]["models"], {"openai/gpt-5.4-mini": {"agentRuntime": {"id": "openclaw"}}})
        self.assertEqual(s["policy_failures"], [])

    def test_f3_compaction_restore(self):
        self.pre_gate["agents"]["defaults"]["compaction"]["provider"] = "safeguard"
        self.pre_gate["agents"]["list"][1]["compaction"] = {"model": "openai-codex/gpt-5.2", "provider": "lossless-claw"}
        self.pre_pass1, _l, _s = m.premigrate_config(self.pre_gate)
        self.now["agents"]["entries"]["helper"]["compaction"] = {"reserveTokens": 100}
        new, ledger, s = self.run_fixups()
        self.assertTrue(s["compaction_restored"])
        self.assertEqual(new["agents"]["defaults"]["compaction"], {"model": "openai/gpt-5.4-mini", "provider": "safeguard"})
        # agents.list[1] (pre) -> agents.entries.helper (now); lossless-claw provider is not restored
        self.assertEqual(new["agents"]["entries"]["helper"]["compaction"],
                         {"reserveTokens": 100, "model": "openai/gpt-5.5"})
        self.assertEqual(new["agents"]["defaults"]["models"]["openai/gpt-5.5"]["agentRuntime"]["id"], "openclaw")

    def test_f3_provider_not_restored_when_context_engine_changed(self):
        self.pre_gate["agents"]["defaults"]["compaction"]["provider"] = "LOSSLESS-CLAW"
        new, _l, _s = self.run_fixups()
        self.assertEqual(new["agents"]["defaults"]["compaction"], {"model": "openai/gpt-5.4-mini"})
        self.pre_gate["agents"]["defaults"]["compaction"]["provider"] = "custom-engine"
        self.now["plugins"]["slots"] = {"contextEngine": "custom-engine"}
        new, _l, _s = self.run_fixups()
        self.assertEqual(new["agents"]["defaults"]["compaction"], {"model": "openai/gpt-5.4-mini"})

    def test_f2_f3_follow_doctor_retirements(self):
        """Addendum 2 item 8: remap o retired_map, so doctor pass 2 does not replace the value again."""
        retired = {"openai/gpt-5.4-mini": "openai/gpt-5.6-luna"}
        new, ledger, s = m.fixups(self.now, self.pre_gate, self.pre_pass1, retired_map=retired)
        self.assertEqual(new["agents"]["defaults"]["compaction"], {"model": "openai/gpt-5.6-luna"})
        self.assertEqual(new["hooks"]["mappings"][0]["model"], "openai/gpt-5.6-luna")
        self.assertEqual(new["channels"]["modelByChannel"]["telegram"]["default"], "openai/gpt-5.6-luna")  # gpt-5-nano
        self.assertEqual(new["agents"]["defaults"]["models"]["openai/gpt-5.6-luna"], {"agentRuntime": {"id": "openclaw"}})
        # a canonical pre value doctor retired elsewhere follows doctor's choice too (no F2 pin for it)
        self.pre_gate["agents"]["defaults"]["compaction"]["model"] = "anthropic/claude-sonnet-4-5"
        new, _l, _s = m.fixups(self.now, self.pre_gate, self.pre_pass1,
                               retired_map={"anthropic/claude-sonnet-4-5": "anthropic/claude-sonnet-4-6"})
        self.assertEqual(new["agents"]["defaults"]["compaction"], {"model": "anthropic/claude-sonnet-4-6"})

    def test_retired_chain_helpers(self):
        rmap = {"openai/gpt-5.4-mini": "openai/gpt-5.6-luna", "OpenAI/GPT-5.6-luna": "openai/gpt-5.7-luna",
                "a/x": "a/y", "a/y": "a/x"}
        self.assertEqual(m.retired_chain("openai/gpt-5.4-mini", rmap), ["openai/gpt-5.6-luna", "openai/gpt-5.7-luna"])
        self.assertEqual(m.apply_retired("openai/gpt-5.4-mini@openai:work", rmap), "openai/gpt-5.7-luna@openai:work")
        self.assertEqual(m.apply_retired("vllm/qwen3.5-122b", rmap), "vllm/qwen3.5-122b")
        self.assertEqual(m.retired_chain("a/x", rmap), ["a/y"], "cycles end")
        self.assertEqual(m.apply_retired("openai/gpt-5.5", None), "openai/gpt-5.5")

    def test_f3_present_value_kept(self):
        self.now["agents"]["defaults"]["compaction"] = {"model": "anthropic/claude-sonnet-4-6"}
        new, ledger, s = self.run_fixups()
        self.assertEqual(new["agents"]["defaults"]["compaction"], {"model": "anthropic/claude-sonnet-4-6"})
        self.assertFalse(s["compaction_restored"])

    def test_golden_e4_noop(self):
        after = fix("e4_after_pass2.json")
        new, ledger, s = m.fixups(after, fix("e4_before.json"), fix("e4_pretransform.json"))
        self.assertEqual(new, after)
        self.assertEqual(ledger, [])
        self.assertEqual(s, {"codex_pins": 0, "refs_rewritten": 0, "compaction_restored": False,
                             "codex_plugin_restored": False, "codex_needed": False, "policy_failures": []})

    def test_vllm_untouched_by_fixups(self):
        before = live_like()
        pre_pass1, _l, _s = m.premigrate_config(before)
        now = copy.deepcopy(pre_pass1)
        now["meta"] = {"lastTouchedVersion": "2026.9.9", "migrations": {"modelPolicyAllowlist": True}}
        dm = now["agents"]["defaults"]["models"]
        dm["openai/gpt-5.5"] = dm.pop("openai-codex/gpt-5.5")
        now["agents"]["defaults"]["model"]["fallbacks"][0] = "openai/gpt-5.5"
        new, ledger, s = m.fixups(now, before, pre_pass1)
        self.assertEqual(new, now)
        self.assertEqual(ledger, [])
        self.assertEqual(new["models"]["providers"]["vllm"], vllm_block())


# --- PC1-PC3 ---------------------------------------------------------------------------------------


class TestPostconditions(unittest.TestCase):
    def test_golden_after2_passes(self):
        before = fix("e4_before.json")
        _new, _l, summary = m.premigrate_config(before)
        after = fix("e4_after_pass2.json")
        self.assertEqual(m.check_legacy_refs(after), [])
        self.assertEqual(m.check_codex_runtime(after), [])
        self.assertEqual(m.check_codex_runtime(after, pre_cfg=before), [])
        self.assertEqual(m.check_runtime_pins(after, summary["legacy_slots"]), [])
        # slots survive a JSON round trip (journal) and the bare {path, value} form
        slots = json.loads(json.dumps(summary["legacy_slots"]))
        self.assertEqual(m.check_runtime_pins(after, slots), [])
        self.assertEqual(m.check_runtime_pins(after, [{"path": s["path"], "value": s["value"]} for s in slots]), [])

    def test_golden_raw_fails(self):
        before = fix("e4_before.json")
        _new, _l, summary = m.premigrate_config(before)
        raw = fix("e3_raw_after_pass2.json")
        pc3 = m.check_runtime_pins(raw, summary["legacy_slots"])
        self.assertTrue(any("model.primary" in p and "gpt-6-astra" in p for p in pc3), pc3)
        self.assertTrue(any("no openai/gpt-5.5 entry" in p for p in pc3), pc3)
        pc2 = m.check_codex_runtime(raw, pre_cfg=before)
        self.assertTrue(any("plugins.entries.codex" in p for p in pc2), pc2)
        self.assertTrue(m.check_codex_runtime(raw))
        self.assertTrue(any("modelPolicy.allow" in p for p in m.check_legacy_refs(raw)))

    def test_pc1_auth_and_providers(self):
        cfg = {"auth": {"order": {"openai-codex": ["x"], "openai": ["openai:default", "OpenAI-Codex:old"]},
                        "profiles": {"openai-codex:default": {"access": "secret-token-value"}}},
               "models": {"providers": {"openai-codex": {}, "Codex": {}, "vllm": vllm_block()}},
               "agents": {"defaults": {"models": {"codex-cli/gpt-5": {}}}},
               "x": {"y": " codex / gpt"}}
        problems = m.check_legacy_refs(cfg)
        text = "\n".join(problems)
        for needle in ("auth.order.openai-codex", "OpenAI-Codex:old", "auth.profiles", "models.providers.openai-codex",
                       "models.providers.Codex", "codex-cli/gpt-5", "x.y"):
            self.assertIn(needle, text)
        self.assertNotIn("secret-token-value", text)
        self.assertNotIn("vllm", text)
        self.assertEqual(m.check_legacy_refs({"agents": {"defaults": {"model": "vllm/qwen3.5-122b"}},
                                              "models": {"providers": {"vllm": vllm_block()}}}), [])

    def test_pc1_redacts_secret_paths(self):
        problems = m.check_legacy_refs({"x": {"apiKey": "openai-codex/should-not-print"}})
        self.assertEqual(len(problems), 1)
        self.assertNotIn("should-not-print", problems[0])

    def test_pc2(self):
        """Addendum 2 rule 5: only migrated openai-codex slots count; canonical refs keep their runtime."""
        cfg = {"a": [{"b": {"agentRuntime": {"id": "Codex-CLI"}}}], "agents": {"defaults": {"agentRuntime": "codex"}}}
        self.assertEqual(m.check_codex_runtime(cfg), [], "pins outside migrated legacy keys are not PC2's")
        enabled = {"plugins": {"entries": {"codex": {"enabled": True}}}}
        self.assertEqual(len(m.check_codex_runtime(enabled)), 1)
        self.assertEqual(m.check_codex_runtime(enabled, pre_cfg=enabled), [], "enabled before the migration")
        self.assertEqual(m.check_codex_runtime({"plugins": {"entries": {"codex": {"enabled": False}}}}), [])
        self.assertEqual(m.check_codex_runtime(enabled, codex_pkg_before=True), [], "codex package installed before")
        # canonical openai/ refs before the gate: Codex was in use, doctor's plugin setting and pins are fine
        pre_canonical = {"agents": {"defaults": {"model": {"primary": "vllm/qwen3.5-122b",
                                                           "fallbacks": ["openai/gpt-5.6-sol"]}}}}
        self.assertEqual(m.check_codex_runtime(enabled, pre_cfg=pre_canonical), [])
        self.assertEqual(len(m.check_codex_runtime(enabled, pre_cfg=live_like())), 1, "legacy refs only: not in use")
        pinned = {"plugins": {"entries": {"codex": {"enabled": True}}},
                  "agents": {"defaults": {"models": {"openai/gpt-5.6-sol": {"agentRuntime": {"id": "codex"}}}}}}
        self.assertEqual(m.check_codex_runtime(pinned, pre_cfg=pre_canonical), [])
        # the same key from a legacy openai-codex ref (live_like: openai-codex/gpt-5.5) must not be Codex
        legacy = {"agents": {"defaults": {"model": {"fallbacks": ["openai/gpt-5.5"]},
                                          "models": {"openai/gpt-5.5": {"agentRuntime": {"id": "codex-app-server"}}}}}}
        probs = m.check_codex_runtime(legacy, pre_cfg=live_like())
        self.assertEqual(len(probs), 3, probs)  # the key, and the fallback and map-key slots resolving to it
        self.assertIn('agents.defaults.models["openai/gpt-5.5"].agentRuntime.id', probs[0])
        self.assertIn("resolves to the Codex runtime", probs[1])
        legacy["agents"]["defaults"]["models"]["openai/gpt-5.5"]["agentRuntime"]["id"] = "openclaw"
        self.assertEqual(m.check_codex_runtime(legacy, pre_cfg=live_like()), [])

    def test_pc3_accepts_doctor_retirements_only(self):
        """Addendum 2 item 9: doctor's retirement successor counts as kept; any other value still fails."""
        pre = {"agents": {"defaults": {"model": {"primary": "openai-codex/gpt-5.5",
                                                 "fallbacks": ["openai-codex/gpt-5.4-mini"]},
                                       "heartbeat": {"model": "openai-codex/gpt-5.4-mini"},
                                       "models": {"openai-codex/gpt-5.4-mini": {}}}}}
        slots = self.slots(pre)
        cfg = {"agents": {"defaults": {"model": {"primary": "openai/gpt-5.5", "fallbacks": ["openai/gpt-5.6-luna"]},
                                       "heartbeat": {"model": "openai/gpt-5.6-luna"},
                                       "models": {"openai/gpt-5.5": {"agentRuntime": {"id": "openclaw"}},
                                                  "openai/gpt-5.6-luna": {"agentRuntime": {"id": "openclaw"}}}}}}
        self.assertEqual(len(m.check_runtime_pins(cfg, slots)), 3, "without the doctor log map")
        retired = {"openai/gpt-5.4-mini": "openai/gpt-5.6-luna"}
        self.assertEqual(m.check_runtime_pins(cfg, slots, retired), [])
        # the successor must still resolve to openclaw
        cfg["agents"]["defaults"]["models"]["openai/gpt-5.6-luna"]["agentRuntime"]["id"] = "codex"
        probs = m.check_runtime_pins(cfg, slots, retired)
        self.assertTrue(probs and all("gpt-5.6-luna" in p for p in probs), probs)
        self.assertEqual(m.check_runtime_pins(cfg, slots, retired, skip_codex=True), [], "left to PC2")
        self.assertTrue(m.check_codex_runtime(cfg, pre, retired_map=retired))
        # raw-path damage: the primary replaced by a default that is no retirement successor
        cfg["agents"]["defaults"]["models"]["openai/gpt-5.6-luna"]["agentRuntime"]["id"] = "openclaw"
        cfg["agents"]["defaults"]["model"]["primary"] = "openai/gpt-6-astra"
        probs = m.check_runtime_pins(cfg, slots, retired)
        self.assertEqual(len(probs), 1, probs)
        self.assertIn("now openai/gpt-6-astra, expected openai/gpt-5.5", probs[0])
        # retired to another provider: kept, no OpenAI runtime to resolve
        cfg["agents"]["defaults"]["model"]["primary"] = "anthropic/claude-x"
        self.assertEqual(m.check_runtime_pins(cfg, slots, dict(retired, **{"openai/gpt-5.5": "anthropic/claude-x"})),
                         [])

    def slot_cfg(self):
        return {"agents": {"defaults": {"model": {"primary": "openai/gpt-5.5"},
                                        "models": {"openai/gpt-5.5": {"agentRuntime": {"id": "openclaw"}}}},
                           "entries": {"main": {}, "helper": {}}}}

    def slots(self, cfg):
        return [s for s in m.premigrate_config(cfg)[2]["legacy_slots"]]

    def test_pc3_precedence(self):
        pre = {"agents": {"defaults": {"model": {"primary": "openai-codex/gpt-5.5"}}}}
        slots = self.slots(pre)
        cfg = self.slot_cfg()
        self.assertEqual(m.check_runtime_pins(cfg, slots), [])
        # an agent's own exact entry beats the defaults
        cfg["agents"]["entries"]["helper"]["models"] = {"openai/gpt-5.5": {"agentRuntime": {"id": "codex"}}}
        problems = m.check_runtime_pins(cfg, slots)
        self.assertEqual(len(problems), 1)
        self.assertIn("agent helper", problems[0])
        # pi counts as openclaw
        cfg["agents"]["entries"]["helper"]["models"]["openai/gpt-5.5"]["agentRuntime"]["id"] = "pi"
        self.assertEqual(m.check_runtime_pins(cfg, slots), [])
        # auto / default fail; empty id does not count as a policy
        for rid in ("auto", "default"):
            cfg = self.slot_cfg()
            cfg["agents"]["defaults"]["models"]["openai/gpt-5.5"]["agentRuntime"]["id"] = rid
            self.assertTrue(m.check_runtime_pins(cfg, slots), rid)
        cfg = self.slot_cfg()
        cfg["agents"]["defaults"]["models"]["openai/gpt-5.5"]["agentRuntime"]["id"] = ""
        self.assertTrue(any("none (implicit choice)" in p for p in m.check_runtime_pins(cfg, slots)))
        # provider models[] beats wildcards; wildcard beats provider-level
        cfg = self.slot_cfg()
        del cfg["agents"]["defaults"]["models"]["openai/gpt-5.5"]
        cfg["agents"]["defaults"]["models"]["openai/*"] = {"agentRuntime": {"id": "codex"}}
        cfg["models"] = {"providers": {"openai": {"agentRuntime": {"id": "codex"},
                                                  "models": [{"id": "gpt-5.5", "agentRuntime": {"id": "openclaw"}}]}}}
        self.assertEqual(m.check_runtime_pins(cfg, slots), [])
        cfg["models"]["providers"]["openai"]["models"][0].pop("agentRuntime")
        self.assertTrue(m.check_runtime_pins(cfg, slots))
        cfg["agents"]["defaults"]["models"]["openai/*"]["agentRuntime"]["id"] = "openclaw"
        self.assertEqual(m.check_runtime_pins(cfg, slots), [])
        del cfg["agents"]["defaults"]["models"]["openai/*"]
        self.assertTrue(m.check_runtime_pins(cfg, slots))
        cfg["models"]["providers"]["openai"]["agentRuntime"]["id"] = "openclaw"
        self.assertEqual(m.check_runtime_pins(cfg, slots), [])

    def test_pc3_list_slot_maps_to_entries(self):
        pre = {"agents": {"list": [{"id": "main"}, {"id": "helper", "heartbeat": {"model": "openai-codex/gpt-5.4-mini"},
                                                     "models": {"openai-codex/gpt-5.4-mini": {}}}]}}
        slots = self.slots(pre)
        self.assertEqual({s["agent_id"] for s in slots}, {"helper"})
        cfg = {"agents": {"entries": {"main": {}, "helper": {
            "heartbeat": {"model": "openai/gpt-5.4-mini"},
            "models": {"openai/gpt-5.4-mini": {"agentRuntime": {"id": "openclaw"}}}}}}}
        self.assertEqual(m.check_runtime_pins(cfg, slots), [])
        cfg["agents"]["entries"]["helper"]["heartbeat"]["model"] = "openai-codex/gpt-5.4-mini"
        self.assertTrue(any("still a legacy ref" in p for p in m.check_runtime_pins(cfg, slots)))
        del cfg["agents"]["entries"]["helper"]["heartbeat"]
        self.assertTrue(any("value missing" in p for p in m.check_runtime_pins(cfg, slots)))

    def test_pc3_remap_and_fallback_membership(self):
        pre = {"agents": {"defaults": {"model": {"primary": "openai-codex/gpt-5.5",
                                                 "fallbacks": ["openai-codex/gpt-5.5", "openai-codex/gpt-5.2-codex"]},
                                       "imageModel": "openai-codex/gpt-5.6"}}}
        slots = self.slots(pre)
        cfg = {"agents": {"defaults": {"model": {"primary": "openai/gpt-5.5", "fallbacks": ["openai/gpt-5.5"]},
                                       "imageModel": "openai/gpt-5.6-sol",
                                       "models": {"openai/gpt-5.5": {"agentRuntime": {"id": "openclaw"}},
                                                  "openai/gpt-5.6-sol": {"agentRuntime": {"id": "openclaw"}}}}}}
        self.assertEqual(m.check_runtime_pins(cfg, slots), [])
        cfg["agents"]["defaults"]["model"]["fallbacks"] = ["openai/gpt-5.4"]
        self.assertTrue(any("missing from agents.defaults.model.fallbacks" in p for p in m.check_runtime_pins(cfg, slots)))

    def test_pc3_string_model_became_object(self):
        pre = {"agents": {"defaults": {"model": "openai-codex/gpt-5.5"}}}
        slots = self.slots(pre)
        self.assertEqual(m.check_runtime_pins(self.slot_cfg(), slots), [])

    def test_pc3_non_agent_slot_checked_for_every_agent(self):
        pre = {"hooks": {"mappings": [{"model": "openai-codex/gpt-5.5"}]}}
        slots = self.slots(pre)
        cfg = self.slot_cfg()
        cfg["hooks"] = {"mappings": [{"model": "openai/gpt-5.5"}]}
        self.assertEqual(m.check_runtime_pins(cfg, slots), [])
        cfg["agents"]["entries"]["helper"]["models"] = {"openai/*": {"agentRuntime": {"id": "codex"}},
                                                        "openai/gpt-5.5": {"agentRuntime": {"id": "codex"}}}
        self.assertTrue(m.check_runtime_pins(cfg, slots))


# --- canonical refs keep their runtime (contract addendum 2) ------------------------------------------


class TestCanonicalRefs(unittest.TestCase):
    def test_golden_exp5_left_as_doctor_leaves_it(self):
        """Live-user-shaped config through real 9.9 doctor pass 1: canonical openai/ refs only, doctor
        enabled the codex plugin. Nothing is pinned or restored and PC2 passes (rules 2, 4, 5)."""
        pre, a1 = fix("exp5_pre_gate.json"), fix("exp5_after_pass1.json")
        self.assertEqual(m.check_codex_runtime(a1, pre_cfg=pre), [])
        self.assertEqual(m.check_codex_runtime(a1, pre_cfg={}),
                         ["plugins.entries.codex.enabled is true (Codex agent runtime enabled by the migration)"])
        new, ledger, s = m.fixups(a1, pre, pre)
        self.assertEqual((new, ledger), (a1, []))
        self.assertEqual((s["codex_pins"], s["codex_plugin_restored"], s["codex_needed"]), (0, False, True))
        self.assertEqual(m.post_doctor_fixups(a1, pre)[1], [])
        self.assertEqual(m.check_legacy_refs(a1), [])
        for prov in ("vllm", "vllm-nothink", "vllm-fast"):
            self.assertEqual(a1["models"]["providers"][prov], pre["models"]["providers"][prov])
        self.assertTrue(m.canonical_openai_refs(pre))
        # the superseded addendum-1 result (canonical keys pinned to openclaw) is never produced
        a2 = fix("exp5_after_pass2.json")
        self.assertNotEqual(new, a2)

    def test_canonical_codex_pins_left_alone(self):
        pre = {"agents": {"defaults": {"model": {"primary": "openai/gpt-5.5"},
                                       "models": {"openai/gpt-5.5": {"alias": "g"}, "openai/*": {}}}}}
        now = {"agents": {"defaults": {"model": {"primary": "openai/gpt-5.5"},
                                       "models": {"openai/gpt-5.5": {"alias": "g", "agentRuntime": {"id": "codex"}},
                                                  "openai/*": {"agentRuntime": {"id": "codex"}}}}},
               "plugins": {"entries": {"codex": {"enabled": True}}}}
        new, ledger, s = m.fixups(now, pre, pre)
        self.assertEqual((new, ledger), (now, []))
        self.assertEqual(m.check_codex_runtime(now, pre), [])
        self.assertEqual(m.post_doctor_fixups(now, pre)[1], [])

    def test_canonical_openai_refs(self):
        cfg = {"agents": {"defaults": {"model": {"fallbacks": [" OpenAI/gpt-5.5"]}, "models": {"openai/*": {}}}},
               "auth": {"order": {"openai": ["openai/not-a-ref"]}},
               "models": {"providers": {"openai": {"models": [{"id": "openai/gpt-5.5"}]}}}}
        self.assertEqual(m.canonical_openai_refs(cfg), ['agents.defaults.model.fallbacks[0]=OpenAI/gpt-5.5',
                                                        'agents.defaults.models["openai/*"]=openai/*'])
        self.assertEqual(m.canonical_openai_refs(live_like()), [])


class TestRouteCollision(unittest.TestCase):
    """F2: a model used both as openai-codex/<id> and as openai/<id> ends up on one openai/<id> route."""

    def codes(self, cfg):
        return {f["code"]: f["cls"] for f in m.models_preflight(cfg)}

    @staticmethod
    def mixed():
        """Reviewer repro collision.py: E3-shaped wildcard plus a live-user-style canonical fallback."""
        return {"agents": {"defaults": {
            "model": {"primary": "vllm/qwen3.5-122b", "fallbacks": ["openai/gpt-5.5", "openai-codex/gpt-5.4-mini"]},
            "models": {"openai-codex/*": {}, "vllm/qwen3.5-122b": {}, "openai/gpt-5.5": {"alias": "gpt"}}}}}

    def test_r1_skips_expansions_with_an_existing_canonical_key(self):
        cfg = self.mixed()
        self.assertEqual(m.route_collisions(cfg), {})
        self.assertNotIn("models-route-collision", self.codes(cfg))
        new, ledger, summary = m.premigrate_config(cfg)
        dm = new["agents"]["defaults"]["models"]
        self.assertNotIn("openai-codex/gpt-5.5", dm)
        self.assertEqual(dm["openai/gpt-5.5"], {"alias": "gpt"}, "the canonical entry keeps its runtime")
        self.assertEqual(dm["openai-codex/gpt-5.4-mini"], {"agentRuntime": {"id": "openclaw"}})
        for x in set(m.EXPLICIT_DEFAULT_IDS) - {"gpt-5.5"}:
            self.assertIn("openai-codex/" + x, dm)
        self.assertFalse(any(e["path"].endswith('"openai-codex/gpt-5.5"]') for e in ledger))
        # the info line still claims "keep their runtime" for the canonical refs, and it is true now
        msg = [f["message"] for f in m.models_preflight(cfg) if f["code"] == "canonical-openai-refs"][0]
        self.assertIn("openai/gpt-5.5", msg)
        # F1/PC2 never treat the skipped id as a migrated slot (defaults or any agent)
        ctx = m.legacy_key_context(cfg)
        self.assertFalse(m.is_migrated_legacy_key(ctx, None, "gpt-5.5"))
        self.assertFalse(m.is_migrated_legacy_key(ctx, "main", "gpt-5.5"))
        self.assertTrue(m.is_migrated_legacy_key(ctx, None, "gpt-5.4"))
        # doctor merges nothing into openai/gpt-5.5, so the canonical fallback keeps the implicit choice
        post = copy.deepcopy(new)
        post["agents"]["defaults"]["models"] = {
            ("openai/" + m.remap_model_id(k.split("/", 1)[1]) if k.startswith("openai-codex/") else k): v
            for k, v in dm.items()}
        self.assertEqual(m._resolve_openai_runtime(post, "gpt-5.5", None), (None, "none"))

    def test_real_legacy_ref_plus_canonical_use_is_acceptable_hold(self):
        cfg = self.mixed()
        cfg["agents"]["defaults"]["model"]["primary"] = "openai-codex/gpt-5.5"
        col = m.route_collisions(cfg)
        self.assertEqual(sorted(col), ["gpt-5.5"])
        self.assertEqual(col["gpt-5.5"], ["agents.defaults.model.fallbacks[0]", 'agents.defaults.models["openai/gpt-5.5"]'])
        codes = self.codes(cfg)
        self.assertEqual(codes["models-route-collision"], "acceptable")
        self.assertNotIn("canonical-openai-refs", codes, "no 'keep their runtime' claim for a collided id")
        msg = [f["message"] for f in m.models_preflight(cfg) if f["code"] == "models-route-collision"][0]
        self.assertIn("gpt-5.5 (agents.defaults.model.fallbacks[0]", msg)
        # a real legacy ref is still expanded and pinned (it is reported, not silently dropped)
        self.assertIn("openai-codex/gpt-5.5", m.premigrate_config(cfg)[0]["agents"]["defaults"]["models"])

    def test_remapped_legacy_id_and_agent_scopes(self):
        # openai-codex/gpt-5.2 becomes openai/gpt-5.5; R2 pins it in agents.defaults.models (every scope)
        cfg = {"agents": {"list": [{"id": "work", "model": "openai-codex/gpt-5.2"},
                                   {"id": "home", "model": {"fallbacks": ["openai/gpt-5.5"]}}]}}
        self.assertEqual(m.route_collisions(cfg), {"gpt-5.5": ["agents.list[1].model.fallbacks[0]"]})
        # an agent-scope wildcard expands only into that agent's map
        cfg = {"agents": {"defaults": {"model": "openai/gpt-5.4"},
                          "list": [{"id": "work", "models": {"openai-codex/*": {}}},
                                   {"id": "home", "model": "openai/gpt-5.4-mini"}]}}
        self.assertEqual(sorted(m.route_collisions(cfg)), ["gpt-5.4"], "defaults overlaps every agent")
        cfg["agents"]["defaults"]["model"] = "vllm/q"
        self.assertEqual(m.route_collisions(cfg), {}, "another agent's scope does not overlap")
        cfg["agents"]["list"][0]["model"] = "openai/gpt-5.4-mini"
        self.assertEqual(m.route_collisions(cfg), {"gpt-5.4-mini": ["agents.list[0].model"]})
        self.assertEqual(m.route_collisions(live_like()), {})
        self.assertEqual(m.route_collisions(spec_example()), {})


# --- pins --------------------------------------------------------------------------------------------


class TestPins(unittest.TestCase):
    def test_table_matches_validated_pins(self):
        ref = fix("pins_final_99.json")
        self.assertEqual([(p["path"], p["value"]) for p in m.PINS], [(p["path"], p["value"]) for p in ref])
        self.assertEqual(len(m.PINS), 30)
        paths = {m.fmt_path(p["path"]) for p in m.PINS}
        for dropped in ("dreaming.enabled", "heartbeat.target", "cyberFailover.mode", "utilityModel", "agentRuntime.id",
                        "agents.defaults.agentRuntime.id", "skills.workshop.autonomous.enabled"):
            self.assertNotIn(dropped, paths)

    def test_table_matches_spec_99_conditions(self):
        path = SCRATCH + "/specwf/config-keys/pins_spec_99.json"
        if not os.path.exists(path):
            self.skipTest("scratchpad pins_spec_99.json missing: %s" % path)
        with open(path, encoding="utf-8") as f:
            spec = json.load(f)
        self.assertEqual([(m.fmt_path(p["path"]), p["value"]) for p in m.PINS],
                         [(p["path"], p["value"]) for p in spec["pins"]])
        conditional = {p["path"] for p in spec["pins"] if "only" in p.get("condition", "")}
        ours = {m.fmt_path(p["path"]) for p in m.PINS if p["cond"]}
        self.assertTrue(conditional <= ours, conditional - ours)

    def apply(self, cfg, ledgered=()):
        snap = copy.deepcopy(cfg)
        out = m.apply_pins(cfg, set(ledgered))
        self.assertEqual(cfg, snap, "input mutated")
        return out

    def skipped(self, skipped):
        return {s["path"]: s["reason"] for s in skipped}

    def test_empty_config(self):
        new, written, skipped = self.apply({})
        sk = self.skipped(skipped)
        self.assertEqual(len(written) + len(skipped), 30)
        self.assertEqual(new["agents"]["defaults"]["maxConcurrent"], 4)
        self.assertEqual(new["session"]["reset"], {"mode": "daily", "atHour": 4})
        self.assertFalse(new["plugins"]["entries"]["memory-core"]["config"]["dreaming"]["enabled"])
        self.assertNotIn("channels", new)
        self.assertNotIn("heartbeat", new["agents"]["defaults"])
        self.assertTrue(sk["agents.defaults.heartbeat.target"].startswith("condition:"))
        for p in ("channels.telegram.streaming.mode", "channels.telegram.streaming.preview.commandText",
                  "channels.telegram.joinIntro"):
            self.assertEqual(sk[p], "condition:channels.telegram not configured")
        self.assertNotIn("enabled", new["skills"]["workshop"]["autonomous"])

    def test_golden_after2(self):
        after = fix("e4_after_pass2.json")
        new, written, skipped = self.apply(after)
        self.assertEqual(new["agents"]["defaults"]["heartbeat"], {"target": "none"}, "roster has exactly 1 agent")
        self.assertEqual(new["channels"]["telegram"]["streaming"], {"mode": "partial", "preview": {"commandText": "raw"}})
        self.assertFalse(new["channels"]["telegram"]["joinIntro"])
        self.assertEqual(len(written), 30)
        self.assertEqual(skipped, [])
        self.assertEqual(new["channels"]["telegram"]["botToken"], after["channels"]["telegram"]["botToken"])

    def test_union_keys_any_value_counts(self):
        for v in ({"enabled": True}, "auto", True, None, {}):
            new, written, skipped = self.apply({"tools": {"codeMode": v, "toolSearch": v, "swarm": v}})
            sk = self.skipped(skipped)
            with self.subTest(v=v):
                for k in ("tools.codeMode", "tools.toolSearch", "tools.swarm"):
                    self.assertEqual(sk[k], "already-set")
                    self.assertEqual(new["tools"][k.split(".")[1]], v)

    def test_telegram_rules(self):
        new, _w, skipped = self.apply({"channels": {"telegram": {"streaming": "partial", "accounts": {"a": {}}}}})
        sk = self.skipped(skipped)
        self.assertEqual(new["channels"]["telegram"]["streaming"], "partial")
        self.assertEqual(sk["channels.telegram.streaming.mode"], "condition:channels.telegram.streaming is a scalar")
        self.assertTrue(sk["channels.telegram.streaming.preview.commandText"].startswith("condition:"))
        self.assertFalse(new["channels"]["telegram"]["joinIntro"])
        self.assertEqual(new["channels"]["telegram"]["accounts"], {"a": {}}, "accounts never touched")
        new, _w, skipped = self.apply({"channels": {"telegram": {"streaming": {"progress": {"commandText": "status"}}}}})
        sk = self.skipped(skipped)
        self.assertEqual(new["channels"]["telegram"]["streaming"]["mode"], "partial")
        self.assertNotIn("preview", new["channels"]["telegram"]["streaming"])
        self.assertIn("progress.commandText", sk["channels.telegram.streaming.preview.commandText"])
        new, _w, skipped = self.apply({"channels": {"telegram": {"streaming": {"mode": "off", "preview": "x"},
                                                                 "joinIntro": True}}})
        sk = self.skipped(skipped)
        self.assertEqual(sk["channels.telegram.streaming.mode"], "already-set")
        self.assertEqual(sk["channels.telegram.streaming.preview.commandText"], "parent-not-dict")
        self.assertEqual(sk["channels.telegram.joinIntro"], "already-set")
        new, _w, skipped = self.apply({"channels": {"telegram": True}})
        self.assertEqual(new["channels"]["telegram"], True)

    def test_heartbeat_roster(self):
        cases = [({"agents": {"defaults": {"heartbeat": {"every": "30m"}}, "entries": {"a": {}, "b": {}}}}, True),
                 ({"agents": {"entries": {"main": {}}}}, True),
                 ({"agents": {"list": [{"id": "main"}]}}, True),
                 ({"agents": {"entries": {"a": {}, "b": {}}}}, False),
                 ({"agents": {"entries": {}}}, False),
                 ({"agents": {"defaults": {"heartbeat": {"target": "owner"}}}}, False)]
        for cfg, written in cases:
            new, w, skipped = self.apply(cfg)
            with self.subTest(cfg=cfg):
                self.assertEqual("agents.defaults.heartbeat.target" in {x["path"] for x in w}, written)
        new, _w, _s = self.apply({"agents": {"defaults": {"heartbeat": {"target": "owner"}}, "entries": {"main": {}}}})
        self.assertEqual(new["agents"]["defaults"]["heartbeat"]["target"], "owner")

    def test_dreaming_slot_rule(self):
        for slot, written in ((None, True), ("memory-core", True), ("memory-lancedb", False), ("", True)):
            cfg = {} if slot is None else {"plugins": {"slots": {"memory": slot}}}
            new, w, skipped = self.apply(cfg)
            with self.subTest(slot=slot):
                self.assertEqual("plugins.entries.memory-core.config.dreaming.enabled" in {x["path"] for x in w}, written)
        new, w, skipped = self.apply({"plugins": {"entries": {"memory-core": {"config": {"dreaming": {"enabled": True}}}}}})
        self.assertTrue(new["plugins"]["entries"]["memory-core"]["config"]["dreaming"]["enabled"])

    def test_session_reset_whole_object(self):
        new, _w, skipped = self.apply({"session": {"reset": {"mode": "idle"}}})
        self.assertEqual(new["session"]["reset"], {"mode": "idle"})
        self.assertEqual(self.skipped(skipped)["session.reset"], "already-set")
        new, _w, _s = self.apply({"session": {"dmScope": "main"}})
        self.assertEqual(new["session"]["reset"], {"mode": "daily", "atHour": 4})
        self.assertEqual(new["session"]["dmScope"], "main")
        # written value is a copy, not the PINS object
        new["session"]["reset"]["mode"] = "changed"
        self.assertEqual([p for p in m.PINS if p["path"] == ["session", "reset"]][0]["value"]["mode"], "daily")

    def test_parent_not_dict_and_ledgered(self):
        new, w, skipped = self.apply({"gateway": {"terminal": True, "controlUi": []}},
                                     ledgered={"tools.codeMode", "agents.defaults.maxConcurrent"})
        sk = self.skipped(skipped)
        self.assertEqual(sk["gateway.terminal.enabled"], "parent-not-dict")
        self.assertEqual(sk["gateway.controlUi.sessionObserver"], "parent-not-dict")
        self.assertEqual(sk["tools.codeMode"], "ledgered")
        self.assertEqual(sk["agents.defaults.maxConcurrent"], "ledgered")
        self.assertNotIn("codeMode", new["tools"])
        self.assertEqual(new["gateway"]["terminal"], True)

    def test_false_and_zero_values_count_as_set(self):
        new, _w, skipped = self.apply({"agents": {"defaults": {"maxConcurrent": 0, "utilityModel": None}}})
        sk = self.skipped(skipped)
        self.assertEqual(sk["agents.defaults.maxConcurrent"], "already-set")
        self.assertEqual(sk["agents.defaults.utilityModel"], "already-set")
        self.assertEqual(new["agents"]["defaults"]["maxConcurrent"], 0)

    def test_vllm_untouched_by_pins(self):
        cfg = live_like()
        new, _w, _s = self.apply(cfg)
        self.assertEqual(new["models"], cfg["models"])
        self.assertEqual(new["agents"]["defaults"]["model"], cfg["agents"]["defaults"]["model"])
        self.assertEqual(new["agents"]["defaults"]["models"], cfg["agents"]["defaults"]["models"])


# --- auth order -----------------------------------------------------------------------------------


class TestAuthOrder(unittest.TestCase):
    PROFILES = [{"id": "openai:default", "type": "oauth"}, {"id": "openai:key", "type": "api_key"},
                {"id": "openai:tok", "type": "token"}]

    def test_no_api_key_noop(self):
        self.assertEqual(m.auth_order_adjust({}, [{"id": "openai:default", "type": "oauth"}], None), (None, None, []))

    def test_write_oauth_first(self):
        cfg = {"auth": {"profiles": {"openai:default": {"x": 1}}}}
        new, finding, ledger = m.auth_order_adjust(cfg, self.PROFILES, None)
        self.assertIsNone(finding)
        self.assertEqual(new["auth"]["order"]["openai"], ["openai:default", "openai:tok", "openai:key"])
        self.assertEqual(ledger, [{"step": "auth-order", "file": "openclaw.json", "path": "auth.order.openai",
                                   "before": None, "after": ["openai:default", "openai:tok", "openai:key"]}])
        self.assertNotIn("order", cfg["auth"])
        new, finding, ledger = m.auth_order_adjust({}, self.PROFILES, [])
        self.assertEqual(new["auth"]["order"]["openai"][0], "openai:default")

    def test_store_order_api_key_first_is_policy(self):
        new, finding, ledger = m.auth_order_adjust({}, self.PROFILES, ["openai:key", "openai:default"])
        self.assertIsNone(new)
        self.assertEqual((finding["code"], finding["cls"], finding["phase"]), ("pc-auth-order", "acceptable", "postconditions"))
        self.assertEqual(ledger, [])

    def test_store_order_oauth_first_and_config_present(self):
        self.assertEqual(m.auth_order_adjust({}, self.PROFILES, ["openai:default"]), (None, None, []))
        cfg = {"auth": {"order": {"openai": ["openai:key"]}}}
        self.assertEqual(m.auth_order_adjust(cfg, self.PROFILES, None), (None, None, []))

    def test_api_key_only_not_written(self):
        self.assertEqual(m.auth_order_adjust({}, [{"id": "openai:key", "type": "api_key"}], None), (None, None, []))

    def test_auth_not_object(self):
        new, finding, ledger = m.auth_order_adjust({"auth": []}, self.PROFILES, None)
        self.assertIsNone(new)
        self.assertEqual(finding["code"], "pc-auth-order")


# --- config precheck ----------------------------------------------------------------------------------


class TestConfigPrecheck(unittest.TestCase):
    def codes(self, cfg, raw=""):
        return {f["code"]: f["cls"] for f in m.config_precheck(cfg, raw)}

    def test_includes(self):
        self.assertEqual(self.codes({"agents": {"$include": "./agents.json5"}}), {"config-includes": "hard"})
        self.assertEqual(self.codes({"a": [{"b": {"$include": ["x"]}}]}), {"config-includes": "hard"})
        self.assertEqual(self.codes({"$include": "x"}), {"config-includes": "hard"})
        self.assertEqual(self.codes({}, '{"$include": "x", "$include": "y"}'), {"config-includes": "hard"})
        self.assertEqual(self.codes({"a": "text mentioning $include"}, '{"a": "text mentioning $include"}'), {})

    def test_session_store(self):
        self.assertEqual(self.codes({"session": {"store": "/data/{agentId}.json"}}), {"custom-session-store": "hard"})
        self.assertEqual(self.codes({"session": {"store": "  "}}), {})
        self.assertEqual(self.codes({"session": {"store": None}}), {})

    def test_not_object(self):
        self.assertEqual(self.codes([]), {"config-unreadable": "hard"})
        self.assertEqual(self.codes(fix("e4_before.json")), {})


# --- state-file classification ------------------------------------------------------------------------


def _write(root, rel, text=""):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def _sqlite(path, statements):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path)
    try:
        for s in statements:
            con.execute(s)
        con.commit()
    finally:
        con.close()


def _agent_db(root, profiles):
    store = json.dumps({"version": 1, "profiles": profiles})
    _sqlite(os.path.join(root, "agents/main/agent/openclaw-agent.sqlite"), [
        "PRAGMA user_version=1",
        "CREATE TABLE auth_profile_store (store_key TEXT NOT NULL PRIMARY KEY, store_json TEXT NOT NULL, updated_at INTEGER NOT NULL)",
        "INSERT INTO auth_profile_store VALUES ('primary', '%s', 0)" % store.replace("'", "''"),
    ])


def _snapshot(root):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for n in dirnames + filenames:
            p = os.path.join(dirpath, n)
            st = os.lstat(p)
            out[os.path.relpath(p, root)] = (st.st_mode, st.st_size, st.st_mtime_ns)
    return out


class TestClassify(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = r = self.tmp.name
        self.cfg = {"channels": {"telegram": {"enabled": True}}}
        _agent_db(r, {"openai-codex:default": {"type": "oauth", "provider": "openai-codex"}})
        _write(r, "agents/main/agent/openclaw-agent.sqlite-wal")                       # empty WAL: family, ignored
        _sqlite(os.path.join(r, "agents/main/agent/openclaw-agent.sqlite.reindex-lock.sqlite"), ["CREATE TABLE t(x)"])
        _write(r, "agents/main/agent/openclaw-agent.sqlite.memory-reindex-" + UUID, "x")
        _write(r, "agents/main/agent/openclaw-agent.sqlite.memory-reindex-" + UUID + "-wal", "x")
        _write(r, "agents/main/agent/other.sqlite", "x")
        _write(r, "agents/main/agent/openclaw-agent.sqlite.migrated", "x")
        _write(r, "telegram/bot-info-default.json", "{}")
        _write(r, "telegram/sticker-cache.json", '{"a":1}')
        _write(r, "telegram/update-offset-default.json", "{}")
        _write(r, "telegram/thread-bindings-default.json", '{"version":1,"bindings":[]}')
        _write(r, "telegram/thread-bindings-acc2.json", '{"version":1,"bindings":[{"k":1}]}')
        _write(r, "telegram/sticker-cache.json.migrated", "{}")
        _write(r, "telegram/notes.txt", "x")
        os.symlink("/nonexistent/target", os.path.join(r, "telegram/update-offset-link.json"))
        _write(r, "telegram/ingress-spool-default/1.json", "{}")
        _write(r, "telegram/ingress-spool-default/2.json.tmp", "{}")
        _write(r, "telegram/ingress-spool-default/lock", "")
        for suf in m.TELEGRAM_SESSION_SUFFIXES:
            _write(r, "agents/main/sessions/sessions.json.%s.json" % suf, "{}")
        _write(r, "agents/main/sessions/sessions.json", "{}")
        _write(r, "agents/main/sessions/sessions.json.telegram-message-dispatch-default.json", "{}")
        _write(r, "sessions/sessions.json.telegram-messages.json", "{}")
        _write(r, "plugins/active-memory/session-toggles.json", '{"sessions":{}}')
        _write(r, "credentials/oauth.json", '{"openai-codex":{"type":"oauth"}}')
        _sqlite(os.path.join(r, "tasks/runs.sqlite"), ["CREATE TABLE runs(id)", "INSERT INTO runs VALUES (1)"])
        _sqlite(os.path.join(r, "flows/registry.sqlite"), ["CREATE TABLE flows(id)"])
        _write(r, "flows/registry.sqlite.migrated", "x")
        _write(r, "plugin-state/state.sqlite", "this is not a database")
        _write(r, "memory/main.sqlite", "x")

    def tearDown(self):
        self.tmp.cleanup()

    def classify(self, **kw):
        args = {"from_checkpoint": "2026.7.35", "accepted": set(), "mode": "from-7x"}
        args.update(kw)
        before = _snapshot(self.root)
        out = m.classify_state_files(self.root, self.cfg, **args)
        self.assertEqual(_snapshot(self.root), before, "classification must not touch the state dir")
        json.dumps(out)
        return out

    def plan(self, out):
        return {p["rel"]: (p["kind"], p["action"]) for p in out["plan"]}

    def codes(self, out):
        return {f["code"]: f["cls"] for f in out["findings"]}

    def test_from_7x_plan(self):
        out = self.classify()
        plan = self.plan(out)
        q = lambda kind: ("%s" % kind, "quarantine")  # noqa: E731
        self.assertEqual(plan["agents/main/agent/openclaw-agent.sqlite.reindex-lock.sqlite"], q("sqlite-transient"))
        self.assertEqual(plan["agents/main/agent/openclaw-agent.sqlite.memory-reindex-" + UUID], q("sqlite-transient"))
        self.assertEqual(plan["agents/main/agent/openclaw-agent.sqlite.memory-reindex-" + UUID + "-wal"], q("sqlite-transient"))
        self.assertEqual(plan["agents/main/agent/other.sqlite"], ("sqlite-other", "leave"))
        self.assertEqual(plan["agents/main/agent/openclaw-agent.sqlite.migrated"], ("migrated-archive", "leave"))
        self.assertNotIn("agents/main/agent/openclaw-agent.sqlite", plan)
        self.assertNotIn("agents/main/agent/openclaw-agent.sqlite-wal", plan)
        for n in ("bot-info-default.json", "sticker-cache.json", "update-offset-default.json", "update-offset-link.json",
                  "thread-bindings-acc2.json"):
            self.assertEqual(plan["telegram/" + n], q("telegram-cache"), n)
        self.assertEqual(plan["telegram/thread-bindings-default.json"], ("telegram-cache", "leave"))
        self.assertEqual(plan["telegram/sticker-cache.json.migrated"], ("migrated-archive", "leave"))
        self.assertNotIn("telegram/notes.txt", plan)
        for suf in m.TELEGRAM_SESSION_SUFFIXES:
            self.assertEqual(plan["agents/main/sessions/sessions.json.%s.json" % suf], q("telegram-session-cache"))
        self.assertEqual(plan["sessions/sessions.json.telegram-messages.json"], q("telegram-session-cache"))
        self.assertEqual(plan["agents/main/sessions/sessions.json.telegram-message-dispatch-default.json"],
                         ("telegram-dispatch", "leave"))
        self.assertEqual(plan["plugins/active-memory/session-toggles.json"], q("active-memory-toggles"))
        self.assertEqual(plan["credentials/oauth.json"], q("oauth-json"))
        self.assertEqual(plan["tasks/runs.sqlite"], ("legacy-db", "leave"))
        self.assertEqual(plan["flows/registry.sqlite"], ("legacy-db", "leave"))
        self.assertEqual(plan["flows/registry.sqlite.migrated"], ("migrated-archive", "leave"))
        self.assertEqual(plan["memory/main.sqlite"], ("legacy-memory-sidecar", "leave"))
        codes = self.codes(out)
        self.assertEqual(codes, {"legacy-db-unimported": "acceptable", "legacy-memory-sidecar": "acceptable"})
        msg = [f["message"] for f in out["findings"] if f["code"] == "legacy-db-unimported"][0]
        self.assertIn("tasks/runs.sqlite (1 rows)", msg)
        self.assertIn("plugin-state/state.sqlite (unreadable)", msg)
        self.assertNotIn("flows/registry.sqlite", msg)
        self.assertTrue(any("2 undelivered legacy Telegram update" in i for i in out["info"]), out["info"])
        for p in out["plan"]:
            self.assertEqual(set(p), {"rel", "kind", "action", "reason", "size"})
            self.assertIn(p["action"], ("quarantine", "leave"))
            if p["action"] == "quarantine":
                self.assertIn(p["kind"], m.QUARANTINE_KINDS)
        sizes = {p["rel"]: p["size"] for p in out["plan"]}
        self.assertEqual(sizes["telegram/sticker-cache.json"], 7)

    def test_bump_mode_transient_only(self):
        out = self.classify(mode="bump")
        kinds = {p["kind"] for p in out["plan"] if p["action"] == "quarantine"}
        self.assertEqual(kinds, {"sqlite-transient"})
        self.assertEqual(out["findings"], [])
        self.assertFalse(any(p["rel"].startswith("telegram/") for p in out["plan"]))

    def test_bindings_rules(self):
        out = self.classify(from_checkpoint="2026.7.34")
        self.assertEqual(self.plan(out)["telegram/thread-bindings-acc2.json"], ("telegram-cache", "leave"))
        self.assertEqual(self.codes(out)["telegram-bindings-nonempty"], "acceptable")
        out = self.classify(from_checkpoint=None, accepted={"telegram-bindings-nonempty"})
        self.assertEqual(self.plan(out)["telegram/thread-bindings-acc2.json"], ("telegram-cache", "quarantine"))
        self.assertIn("telegram-bindings-nonempty", self.codes(out))
        self.cfg = {"channels": {"telegram": True}}
        out = self.classify()
        self.assertIn("telegram-bindings-nonempty", self.codes(out))
        # symlinked "empty" bindings are not verified-empty
        os.remove(os.path.join(self.root, "telegram/thread-bindings-default.json"))
        _write(self.root, "elsewhere/b.json", '{"version":1,"bindings":[]}')
        os.symlink(os.path.join(self.root, "elsewhere/b.json"), os.path.join(self.root, "telegram/thread-bindings-default.json"))
        self.cfg = {"channels": {"telegram": {}}}
        out = self.classify()
        self.assertEqual(self.plan(out)["telegram/thread-bindings-default.json"], ("telegram-cache", "quarantine"))

    def test_active_memory_optouts(self):
        _write(self.root, "plugins/active-memory/session-toggles.json",
               '{"sessions":{"agent:main:main":{"disabled":true},"x":{"disabled":false}," ":{"disabled":true}}}')
        out = self.classify()
        self.assertEqual(self.plan(out)["plugins/active-memory/session-toggles.json"], ("active-memory-toggles", "leave"))
        self.assertIn("(1 disabled session(s))", [f for f in out["findings"] if f["code"] == "active-memory-optouts"][0]["message"])
        out = self.classify(accepted={"active-memory-optouts"})
        self.assertEqual(self.plan(out)["plugins/active-memory/session-toggles.json"],
                         ("active-memory-toggles", "quarantine"))
        _write(self.root, "plugins/active-memory/session-toggles.json", "{broken")
        out = self.classify()
        self.assertEqual(self.plan(out)["plugins/active-memory/session-toggles.json"],
                         ("active-memory-toggles", "quarantine"))
        self.assertNotIn("active-memory-optouts", self.codes(out))

    def test_oauth_json_only(self):
        os.remove(os.path.join(self.root, "agents/main/agent/openclaw-agent.sqlite"))
        out = self.classify()
        self.assertEqual(self.plan(out)["credentials/oauth.json"], ("oauth-json", "leave"))
        self.assertEqual(self.codes(out)["oauth-json-only"], "acceptable")
        out = self.classify(accepted={"oauth-json-only"})
        self.assertEqual(self.plan(out)["credentials/oauth.json"], ("oauth-json", "quarantine"))
        _agent_db(self.root, {})
        out = self.classify()
        self.assertIn("has no profiles", [f for f in out["findings"] if f["code"] == "oauth-json-only"][0]["message"])

    def test_injected_query(self):
        calls = []

        def query(path, sql):
            calls.append(os.path.basename(path))
            raise sqlite3.DatabaseError("boom")

        out = m.classify_state_files(self.root, self.cfg, from_checkpoint="2026.7.35", accepted=set(),
                                     mode="from-7x", query=query)
        self.assertIn("openclaw-agent.sqlite", calls)
        self.assertIn("oauth-json-only", self.codes(out))
        msg = [f["message"] for f in out["findings"] if f["code"] == "legacy-db-unimported"][0]
        self.assertIn("flows/registry.sqlite (unreadable)", msg)

    def test_sockets_never_opened(self):
        path = os.path.join(self.root, "telegram", "bot-info-sock.json")
        if len(path.encode()) > 100:
            self.skipTest("temp path too long for AF_UNIX")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.bind(path)
            tog = os.path.join(self.root, "plugins/active-memory/session-toggles.json")
            os.remove(tog)
            os.mkfifo(tog)
            out = self.classify()
            plan = self.plan(out)
            self.assertNotIn("telegram/bot-info-sock.json", plan, "9.9 only matches files and symlinks")
            self.assertEqual(plan["plugins/active-memory/session-toggles.json"], ("active-memory-toggles", "quarantine"))
        finally:
            s.close()

    def test_wal_mode_legacy_db(self):
        path = os.path.join(self.root, "tasks/runs.sqlite")
        os.remove(path)
        con = sqlite3.connect(path)
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA wal_autocheckpoint=0")
            con.execute("CREATE TABLE runs(id)")
            con.execute("INSERT INTO runs VALUES (1)")
            con.execute("INSERT INTO runs VALUES (2)")
            con.commit()
            self.assertGreater(os.path.getsize(path + "-wal"), 0)
            out = self.classify()
            msg = [f["message"] for f in out["findings"] if f["code"] == "legacy-db-unimported"][0]
            self.assertIn("tasks/runs.sqlite (2 rows)", msg)  # read through the WAL index (readonly_shm)
        finally:
            con.close()

    def test_missing_state_dir(self):
        out = m.classify_state_files(os.path.join(self.root, "nope"), {}, from_checkpoint=None, accepted=None,
                                     mode="from-7x")
        self.assertEqual(out, {"plan": [], "findings": [], "info": []})


class TestVllmUntouched(unittest.TestCase):
    """The live user's primary is vllm/qwen3.5-122b: no transform may touch vllm refs or the provider block."""

    def vllm_view(self, cfg):
        refs = sorted((m.fmt_path(p), s) for p, s, _w in m._iter_scanned(cfg, keys_everywhere=True)
                      if s.strip().lower().startswith("vllm/"))
        return refs, m._get(cfg, ["models", "providers", "vllm"], None)

    def test_every_transform(self):
        before = live_like()
        want = self.vllm_view(before)
        self.assertEqual(m.models_preflight(before), [])
        self.assertEqual(m.config_precheck(before, json.dumps(before)), [])
        pre, _l, summary = m.premigrate_config(before)
        self.assertEqual(self.vllm_view(pre), want)
        # simulated doctor pass 1: legacy refs canonicalised, codex pin written, codex plugin enabled
        now = copy.deepcopy(pre)
        now["meta"] = {"lastTouchedVersion": "2026.9.9", "migrations": {"modelPolicyAllowlist": True}}
        dm = now["agents"]["defaults"]["models"]
        dm["openai/gpt-5.5"] = {"agentRuntime": {"id": "codex"}}
        del dm["openai-codex/gpt-5.5"]
        now["agents"]["defaults"]["model"]["fallbacks"][0] = "openai/gpt-5.5"
        now["agents"]["defaults"]["modelPolicy"] = {"allow": list(dm)}
        now["plugins"] = {"entries": {"codex": {"enabled": True}}}
        want = self.vllm_view(now)  # doctor copied the vllm keys into modelPolicy.allow
        self.assertIn(("agents.defaults.modelPolicy.allow[1]", "vllm/*"), want[0])
        fixed, _l, s = m.fixups(now, before, pre)
        self.assertEqual(self.vllm_view(fixed), want)
        self.assertEqual(s["codex_pins"], 1)
        self.assertTrue(s["codex_plugin_restored"])
        self.assertEqual(m.check_legacy_refs(fixed), [])
        self.assertEqual(m.check_codex_runtime(fixed, pre_cfg=before), [])
        self.assertEqual(m.check_runtime_pins(fixed, summary["legacy_slots"]), [])
        new, _f, _ledger = m.auth_order_adjust(fixed, TestAuthOrder.PROFILES, None)
        self.assertEqual(self.vllm_view(new), want)
        pinned, _w, _s = m.apply_pins(new, set())
        self.assertEqual(self.vllm_view(pinned), want)
        self.assertEqual(pinned["models"]["providers"]["vllm"], vllm_block())

    def test_sessions(self):
        store = {"agent:main:main": {"modelProvider": "vllm", "model": "qwen3.5-122b"},
                 "agent:main:telegram:direct:1": {"modelOverride": "vllm/qwen3.5-122b"}}
        new, ledger, summary = m.premigrate_sessions(store, "agents/main/sessions/sessions.json")
        self.assertEqual(new, store)
        self.assertEqual(ledger, [])
        self.assertEqual(summary, {"pinned": [], "user_explicit": [], "harness": []})


class TestPurity(unittest.TestCase):
    def test_all_transforms_leave_inputs_alone(self):
        before = spec_example()
        snap = copy.deepcopy(before)
        m.scan_legacy_refs(before)
        m.models_preflight(before)
        m.explicit_ids(before)
        pre, _l, summary = m.premigrate_config(before)
        snap_pre = copy.deepcopy(pre)
        now = doctor_pass1_like()
        snap_now = copy.deepcopy(now)
        fixed, _l, _s = m.fixups(now, before, pre)
        m.check_legacy_refs(fixed)
        m.check_codex_runtime(fixed, pre_cfg=before)
        m.check_runtime_pins(fixed, summary["legacy_slots"])
        m.apply_pins(fixed, set())
        m.auth_order_adjust(fixed, TestAuthOrder.PROFILES, None)
        m.config_precheck(before, json.dumps(before))
        m.flatten_paths(before)
        self.assertEqual(before, snap)
        self.assertEqual(pre, snap_pre)
        self.assertEqual(now, snap_now)

    def test_end_to_end_spec_example(self):
        """premigrate -> simulated doctor -> fixups -> PC1/PC2/PC3 -> pins on the §7.4.2 example."""
        before = spec_example()
        pre, _l, summary = m.premigrate_config(before)
        fixed, _l, s = m.fixups(doctor_pass1_like(), before, pre)
        self.assertEqual(s["policy_failures"], [])
        fixed.setdefault("auth", {})["order"] = {"openai": ["openai:default"]}
        self.assertEqual(m.check_legacy_refs(fixed), [])
        self.assertEqual(m.check_codex_runtime(fixed, pre_cfg=before), [])
        self.assertEqual(m.check_runtime_pins(fixed, summary["legacy_slots"]), [])
        pinned, written, skipped = m.apply_pins(fixed, set())
        self.assertEqual(m.check_runtime_pins(pinned, summary["legacy_slots"]), [])
        self.assertTrue(written)


if __name__ == "__main__":
    unittest.main()
