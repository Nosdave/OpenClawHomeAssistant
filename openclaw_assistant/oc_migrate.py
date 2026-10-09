#!/usr/bin/env python3
"""oc_migrate -- transforms and checks for the OpenClaw 2026.7.x -> 2026.9.x migration gate.

Every function in this module is pure with respect to its arguments: inputs are
deep-copied and never mutated, nothing runs a subprocess and nothing writes a file.
Read-only filesystem access happens only in classify_state_files() and
scan_sessions_files() (lstat-based; symlinks are never followed into files and
sockets/FIFOs are never opened).

Stage B spec references: §7.3 (cleanup table), §7.4 (models preflight, R1-R5),
§7.6 (fixups F1-F3; F4 validation is a subprocess owned by oc_gate), §7.8
(PC1-PC3, auth-order adjustment), §7.9 (pins), critique B2/B13/B14/B19.
Contract addendum 2: canonical openai/ refs keep their runtime (no F1c); F1 and PC2 only cover
migrated openai-codex slots; F1b only when Codex was not in use before; F2/F3/PC3 follow doctor's
retired-model replacements (retired_map, parsed from the doctor log by oc_gate).

Finding    = {"code", "cls": "hard"|"acceptable"|"warn"|"info", "message", "phase"}
             ("info" is logged only: canonical-openai-refs)
LedgerEntry = {"step", "file", "path", "before", "after"[, "note"]}  (raw values;
              the caller redacts them with redact_value() before persisting)
"""

from __future__ import annotations

import copy
import json
import os
import re
import sqlite3
import stat
from urllib.parse import quote as _urlquote

__all__ = [
    "EXPLICIT_DEFAULT_IDS", "PINS", "TRANSIENT_SQLITE_RE", "TELEGRAM_CACHE_RE", "EMPTY_BINDINGS_RES",
    "LEGACY_REF_RE", "redact_value", "fmt_path", "parse_path", "remap_model_id", "scan_legacy_refs",
    "models_preflight", "explicit_ids", "premigrate_config", "premigrate_sessions", "fixups",
    "post_doctor_fixups", "canonical_openai_refs", "canonical_text_model_refs", "route_collisions", "ref_base",
    "retired_chain", "apply_retired",
    "legacy_key_context", "is_migrated_legacy_key",
    "check_legacy_refs", "check_codex_runtime", "check_runtime_pins", "apply_pins", "auth_order_adjust",
    "classify_state_files", "scan_sessions_files", "config_precheck", "flatten_paths",
]

CONFIG_FILE = "openclaw.json"
_MISSING = object()

# --- constants -------------------------------------------------------------------

# §7.4.2 (iii): OpenAI subscription model ids known to both 2026.7.35 and 2026.9.9
# (v735 openai-chatgpt-provider-BwYoRWrr.js:27-44; v99 model-route-contract-DJO9mHH6.mjs:1-61).
EXPLICIT_DEFAULT_IDS = [
    "gpt-6-astra", "gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5", "gpt-5.5-pro",
    "gpt-5.4", "gpt-5.4-pro", "gpt-5.4-mini", "gpt-5.3-codex-spark",
]

# 9.9 platform-only (API key) ids: a legacy subscription ref to one of them changes billing (§7.4.1).
PLATFORM_ONLY_IDS = frozenset({"gpt-5.6", "chat-latest"})

# Runtime ids that mean "Codex harness" (v99 agent-runtime-id-D1H9nIYN.mjs:6-13).
CODEX_RUNTIME_IDS = frozenset({"codex", "codex-app-server", "codex-cli"})
DOCTOR_CODEX_PIN_IDS = frozenset({"codex", "codex-app-server"})       # what F1 reverts
DEFAULT_RUNTIME_IDS = frozenset({"", "auto", "default"})              # "no explicit runtime"
OPENCLAW_RUNTIME_IDS = frozenset({"openclaw", "pi"})                  # "pi" is an alias of openclaw

# Retired-model remap that 9.9 applies to openai-codex refs while canonicalising them
# (v99 legacy-config-migrations.runtime.models-j-YXRZQK.mjs:149-162,225-235): the codex
# overrides win, then the generic retired-OpenAI table applies. Keys are lower-case.
def _model_table(groups):
    return {old: new for new, olds in groups.items() for old in olds.split()}


_RETIRED_OPENAI_MODELS = _model_table({
    "gpt-5.3-codex": "gpt-5.2-codex gpt-5.1-codex gpt-5-codex",
    "gpt-5.5-pro": "gpt-5-pro gpt-5.2-pro",
    "gpt-5.4-nano": "gpt-4.1-nano gpt-5-nano",
    "gpt-5.4-mini": "gpt-4.1-mini gpt-4o-mini gpt-5.1-codex-mini gpt-5-mini",
    "gpt-5.5": "gpt-4 gpt-4-turbo gpt-4.1 gpt-4o gpt-4o-2024-05-13 gpt-4o-2024-08-06 gpt-4o-2024-11-20 "
               "gpt-5 gpt-5-chat-latest gpt-5.1 gpt-5.1-chat-latest gpt-5.1-codex-max gpt-5.2 gpt-5.2-chat-latest",
})
_RETIRED_CODEX_OVERRIDES = _model_table({
    "gpt-5.5": "gpt-5.2 gpt-5.2-codex gpt-5.1-codex gpt-5-codex",
    "gpt-5.4-mini": "gpt-4.1-nano gpt-5-nano",
})
# Later 9.9 canonicalisation of an already-canonical id (openai/gpt-5.6 -> openai/gpt-5.6-sol);
# PC3 accepts either value for such a slot.
_CANONICAL_FOLLOWUPS = {"gpt-5.6": "gpt-5.6-sol"}

# --- regexes ---------------------------------------------------------------------
# All self-anchored with \A...\Z so match(), search() and fullmatch() behave the same
# (Python's "$" would also match before a trailing newline).

# §7.4: legacy ref; group(1) = model id X ("*" = wildcard), group(2) = @profile.
LEGACY_REF_RE = re.compile(r"\A\s*openai-codex\s*/\s*([^\s@][^\s@]*)(?:@(\S+))?\s*\Z", re.I)
_LEGACY_WILDCARD_KEY_RE = re.compile(r"\A\s*openai-codex\s*/\s*\*\s*\Z", re.I)
_CODEX_PROVIDER_REF_RE = re.compile(r"\A\s*(?:codex|codex-cli)\s*/", re.I)
_CANONICAL_OPENAI_PREFIX_RE = re.compile(r"\A\s*openai\s*/", re.I)
_CANONICAL_OPENAI_REF_RE = re.compile(r"\A\s*openai\s*/\s*([^\s@][^\s@]*)(?:@(\S+))?\s*\Z", re.I)
_PC1_LEGACY_RE = re.compile(r"\A\s*(?:openai-codex|codex|codex-cli)\s*/", re.I)
_SESSION_CODEX_MODEL_RE = re.compile(r"\A\s*(?:openai-codex|codex)\s*/", re.I)

# §7.3 sqlite-transient: v99 backup-shared-C70-jGjT.mjs:147 (flags iu), applied to a basename.
TRANSIENT_SQLITE_RE = re.compile(
    r"\A(?:[^/]+\.sqlite\.(?:generation-(?:lock|writer)|reindex-lock)\.sqlite"
    r"|[^/]+\.sqlite\.(?:backup|memory-reindex|tmp)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    r"(?:-wal|-shm|-journal)?\Z",
    re.I,
)
# §7.3 telegram-cache: v99 state-migrations-Dw3bDJEV.mjs:31 (case-sensitive; JS "." excludes
# line terminators, mirrored by the explicit class).
_JS_DOT = r"[^\n\r  ]"
TELEGRAM_CACHE_RE = re.compile(
    r"\A(?:bot-info-" + _JS_DOT + r"+|sticker-cache|thread-bindings-" + _JS_DOT + r"+|update-offset-"
    + _JS_DOT + r"+)\.json\Z"
)
# Verified-empty thread bindings: v99 state-migrations-Dw3bDJEV.mjs:13 (plus JSON.parse success).
EMPTY_BINDINGS_RES = [
    re.compile(r'\A\s*\{\s*"version"\s*:\s*1\s*,\s*"bindings"\s*:\s*\[\s*\]\s*\}\s*\Z'),
    re.compile(r'\A\s*\{\s*"bindings"\s*:\s*\[\s*\]\s*,\s*"version"\s*:\s*1\s*\}\s*\Z'),
]
TELEGRAM_SESSION_SUFFIXES = ("telegram-messages", "telegram-sent-messages", "telegram-topic-names")
LEGACY_DATABASES = ("tasks/runs.sqlite", "flows/registry.sqlite", "plugin-state/state.sqlite")
_AGENT_DB_FAMILY = frozenset({"openclaw-agent.sqlite", "openclaw-agent.sqlite-wal",
                              "openclaw-agent.sqlite-shm", "openclaw-agent.sqlite-journal"})

# Quarantine kinds (§7.3) -- exactly these produce action "quarantine".
QUARANTINE_KINDS = ("telegram-cache", "telegram-session-cache", "sqlite-transient",
                    "active-memory-toggles", "oauth-json")

# §7.9 pins (validated against the 9.9 schema: specwf/config-keys/pins_final.json).
# The leaf is written only if absent from its parent dict; "cond" names an extra condition.
PINS = [
    {"path": ["agents", "defaults", "maxConcurrent"], "value": 4, "cond": None},
    {"path": ["agents", "defaults", "subagents", "maxSpawnDepth"], "value": 1, "cond": None},
    {"path": ["agents", "defaults", "subagents", "delegationMode"], "value": "suggest", "cond": None},
    {"path": ["gateway", "terminal", "enabled"], "value": False, "cond": None},
    {"path": ["tools", "sessions", "visibility"], "value": "tree", "cond": None},
    {"path": ["tools", "agentToAgent", "enabled"], "value": False, "cond": None},
    {"path": ["tools", "message", "crossContext", "allowAcrossProviders"], "value": False, "cond": None},
    # union keys (boolean | "auto" | object): any existing value counts as set (leaf-absent rule)
    {"path": ["tools", "codeMode"], "value": False, "cond": None},
    {"path": ["tools", "toolSearch"], "value": False, "cond": None},
    {"path": ["tools", "swarm"], "value": False, "cond": None},
    {"path": ["gateway", "cliAgents", "enabled"], "value": False, "cond": None},
    {"path": ["skills", "workshop", "approvalPolicy"], "value": "pending", "cond": None},
    {"path": ["skills", "workshop", "autonomous", "mode"], "value": "off", "cond": None},  # never .enabled
    {"path": ["plugins", "entries", "memory-core", "config", "dreaming", "enabled"], "value": False,
     "cond": "memory-slot"},
    {"path": ["transcripts", "enabled"], "value": False, "cond": None},
    {"path": ["agents", "defaults", "utilityModel"], "value": "", "cond": None},
    {"path": ["memory", "search", "rememberAcrossConversations"], "value": False, "cond": None},
    {"path": ["channels", "telegram", "streaming", "mode"], "value": "partial", "cond": "telegram-streaming"},
    {"path": ["channels", "telegram", "streaming", "preview", "commandText"], "value": "raw",
     "cond": "telegram-preview"},
    {"path": ["channels", "telegram", "joinIntro"], "value": False, "cond": "telegram-dict"},
    {"path": ["agents", "defaults", "silentReply", "group"], "value": "allow", "cond": None},
    # whole-object rule: written only if session.reset is absent (leaf-absent rule on "reset")
    {"path": ["session", "reset"], "value": {"mode": "daily", "atHour": 4}, "cond": None},
    {"path": ["agents", "defaults", "heartbeat", "target"], "value": "none", "cond": "heartbeat-roster"},
    {"path": ["session", "maintenance", "maxEntries"], "value": 500, "cond": None},
    {"path": ["session", "notifyOnCreate"], "value": False, "cond": None},
    {"path": ["gateway", "controlUi", "sessionObserver"], "value": False, "cond": None},
    {"path": ["gateway", "controlUi", "automaticallyFetchFavicons"], "value": False, "cond": None},
    {"path": ["plugins", "entries", "geolocation", "enabled"], "value": False, "cond": None},
    {"path": ["plugins", "entries", "github", "enabled"], "value": False, "cond": None},
    {"path": ["agents", "defaults", "embeddedAgent", "cyberFailover", "mode"], "value": "off", "cond": None},
]

_SECRET_KEY_RE = re.compile(r"(?i)token|secret|password|apikey|api_key|botToken|key$")

# --- small helpers ----------------------------------------------------------------


def _finding(code, cls, message, phase):
    return {"code": code, "cls": cls, "message": message, "phase": phase}


def _is_index(p):
    return isinstance(p, int) and not isinstance(p, bool)


_BRACKET_NEEDED_RE = re.compile(r'[/.\[\]"\\\s]')


def fmt_path(parts):
    """Dotted path; ["..."] for keys containing / . [ ] quote, backslash or whitespace; [i] for indices."""
    out = ""
    for p in parts:
        if _is_index(p):
            out += "[%d]" % p
            continue
        s = str(p)
        if s == "" or _BRACKET_NEEDED_RE.search(s):
            out += "[" + json.dumps(s, ensure_ascii=False) + "]"
        else:
            out += ("." if out else "") + s
    return out


def parse_path(path):
    """Inverse of fmt_path(). Raises ValueError on malformed input."""
    parts, i, n = [], 0, len(path)
    decoder = json.JSONDecoder()
    while i < n:
        c = path[i]
        if c == ".":
            i += 1
            continue
        if c == "[":
            if i + 1 < n and path[i + 1] == '"':
                val, end = decoder.raw_decode(path, i + 1)
                if end >= n or path[end] != "]":
                    raise ValueError("malformed path: %r" % path)
                parts.append(val)
                i = end + 1
            else:
                j = path.find("]", i)
                if j < 0:
                    raise ValueError("malformed path: %r" % path)
                parts.append(int(path[i + 1:j]))
                i = j + 1
            continue
        j = i
        while j < n and path[j] not in ".[":
            j += 1
        parts.append(path[i:j])
        i = j
    return parts


def _get(obj, parts, default=_MISSING):
    cur = obj
    for p in parts:
        if _is_index(p):
            if isinstance(cur, list) and 0 <= p < len(cur):
                cur = cur[p]
            else:
                return default
        elif isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


def _ensure_dict_path(root, parts):
    """Walk/create dicts along parts; returns the dict or None if a non-dict is in the way."""
    cur = root
    for p in parts:
        if not isinstance(cur, dict):
            return None
        if p not in cur:
            cur[p] = {}
        cur = cur[p]
    return cur if isinstance(cur, dict) else None


def _split_ref(s):
    """'prov/model' -> (provider lower-cased+trimmed, model trimmed); bare id -> (None, id)."""
    s = s.strip()
    i = s.find("/")
    if i <= 0:
        return None, s
    return s[:i].strip().lower(), s[i + 1:].strip()


def _runtime_id_raw(ar):
    """The id of an agentRuntime value (object with id, or legacy plain string)."""
    if isinstance(ar, dict):
        v = ar.get("id")
        return v if isinstance(v, str) else None
    if isinstance(ar, str):
        return ar
    return None


def _norm_runtime(raw):
    """9.9 normalizeOptionalAgentRuntimeId: None when empty; pi->openclaw; codex-app-server->codex."""
    if not isinstance(raw, str):
        return None
    v = raw.strip().lower()
    if not v:
        return None
    if v in OPENCLAW_RUNTIME_IDS:
        return "openclaw"
    if v == "codex-app-server":
        return "codex"
    return v


def _is_models_map_path(parts):
    if len(parts) == 3 and parts[0] == "agents" and parts[1] == "defaults" and parts[2] == "models":
        return True
    if len(parts) == 4 and parts[0] == "agents" and parts[3] == "models":
        return (parts[1] == "list" and _is_index(parts[2])) or (parts[1] == "entries" and isinstance(parts[2], str))
    return False


def _is_provider_model_id(parts):
    return (len(parts) == 6 and parts[0] == "models" and parts[1] == "providers" and parts[3] == "models"
            and _is_index(parts[4]) and parts[5] == "id")


def _iter_scanned(cfg, *, keys_everywhere=False):
    """(parts, string, "value"|"key") for every scanned string (§7.4 ref scan).

    Values: everywhere except under the root key "auth" and models.providers.*.models[].id.
    Keys: only inside agents.defaults.models / agents.list[i].models / agents.entries.<id>.models,
    or every dict key (outside "auth") when keys_everywhere is set (PC1).
    """
    out = []

    def visit(node, parts):
        if isinstance(node, dict):
            scan_keys = keys_everywhere or _is_models_map_path(parts)
            for k, v in node.items():
                if not parts and k == "auth":
                    continue
                if scan_keys and isinstance(k, str):
                    out.append((parts + [k], k, "key"))
                visit(v, parts + [k])
        elif isinstance(node, list):
            for i, v in enumerate(node):
                visit(v, parts + [i])
        elif isinstance(node, str):
            if not _is_provider_model_id(parts):
                out.append((parts, node, "value"))

    visit(cfg, [])
    return out


def _iter_runtime_holders(cfg):
    """(parts_of_holder, holder_dict) for every dict that has an "agentRuntime" key (any depth)."""
    out = []

    def visit(node, parts):
        if isinstance(node, dict):
            if "agentRuntime" in node:
                out.append((parts, node))
            for k, v in node.items():
                visit(v, parts + [k])
        elif isinstance(node, list):
            for i, v in enumerate(node):
                visit(v, parts + [i])

    visit(cfg, [])
    return out


def _models_map_scopes(cfg):
    """[(label, parts, agent_id, map)] for every models map that is a dict."""
    out = []
    agents = cfg.get("agents") if isinstance(cfg, dict) else None
    if not isinstance(agents, dict):
        return out
    defaults = agents.get("defaults")
    if isinstance(defaults, dict) and isinstance(defaults.get("models"), dict):
        out.append(("defaults", ["agents", "defaults", "models"], None, defaults["models"]))
    lst = agents.get("list")
    if isinstance(lst, list):
        for i, a in enumerate(lst):
            if isinstance(a, dict) and isinstance(a.get("models"), dict):
                aid = a.get("id") if isinstance(a.get("id"), str) else None
                out.append((fmt_path(["agents", "list", i]), ["agents", "list", i, "models"], aid, a["models"]))
    entries = agents.get("entries")
    if isinstance(entries, dict):
        for aid, a in entries.items():
            if isinstance(a, dict) and isinstance(a.get("models"), dict):
                out.append((fmt_path(["agents", "entries", aid]), ["agents", "entries", aid, "models"], aid,
                            a["models"]))
    return out


def _agent_id_for_parts(cfg, parts):
    if len(parts) >= 3 and parts[0] == "agents":
        if parts[1] == "list" and _is_index(parts[2]):
            a = _get(cfg, ["agents", "list", parts[2]], None)
            v = a.get("id") if isinstance(a, dict) else None
            return v if isinstance(v, str) else None
        if parts[1] == "entries" and isinstance(parts[2], str):
            return parts[2]
    return None


def _brief(items, limit=6):
    items = list(items)
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + " (+%d more)" % (len(items) - limit)


def remap_model_id(model_id):
    """Retired-id remap 9.9 applies when canonicalising an openai-codex ref (case-insensitive)."""
    k = model_id.strip().lower()
    if k in _RETIRED_CODEX_OVERRIDES:
        return _RETIRED_CODEX_OVERRIDES[k]
    if k in _RETIRED_OPENAI_MODELS:
        return _RETIRED_OPENAI_MODELS[k]
    return model_id.strip()


# --- redaction ---------------------------------------------------------------------


def redact_value(path, value):
    """Return value, or "***" when it may hold a secret (auth.profiles, *token*, *secret*, *key ...).

    `path` is a fmt_path() string or a list of parts. Dicts/lists are redacted recursively.
    None stays None (absent is not a secret).
    """
    if value is None:
        return None
    if isinstance(path, (list, tuple)):
        parts = list(path)
    else:
        try:
            parts = parse_path(str(path))
        except (ValueError, json.JSONDecodeError):
            parts = [str(path)]
    if len(parts) >= 2 and parts[0] == "auth" and parts[1] == "profiles":
        return "***"
    for p in parts:
        if isinstance(p, str) and _SECRET_KEY_RE.search(p):
            return "***"
    if isinstance(value, dict):
        return {k: redact_value(parts + [k], v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(parts + [i], v) for i, v in enumerate(value)]
    return value


# --- refs, preflight, EXPLICIT --------------------------------------------------------


def scan_legacy_refs(cfg):
    """Every legacy openai-codex ref (§7.4): [{path, value, where, id, profile, parts, agent_id}]."""
    out = []
    if not isinstance(cfg, dict):
        return out
    for parts, s, where in _iter_scanned(cfg):
        m = LEGACY_REF_RE.match(s)
        if not m:
            continue
        out.append({"path": fmt_path(parts), "value": s, "where": where, "id": m.group(1),
                    "profile": m.group(2), "parts": list(parts), "agent_id": _agent_id_for_parts(cfg, parts)})
    return out


def _provider_blocks(cfg, name):
    provs = _get(cfg, ["models", "providers"], None)
    if not isinstance(provs, dict):
        return []
    return [(k, v) for k, v in provs.items() if isinstance(k, str) and k.strip().lower() == name]


def _provider_model_ids(block):
    ids = []
    models = block.get("models") if isinstance(block, dict) else None
    if isinstance(models, list):
        for m in models:
            if isinstance(m, dict) and isinstance(m.get("id"), str) and m["id"].strip():
                ids.append(m["id"].strip())
    return ids


_LEGACY_PROVIDER_IDS = ("openai-codex", "codex", "codex-cli")


def _is_legacy_runtime_holder(parts):
    """True for an agentRuntime holder the migration rewrites: a models-map entry keyed
    openai-codex/... or codex/... (wildcards included), or a legacy provider block / its models."""
    if parts and isinstance(parts[-1], str) and _is_models_map_path(parts[:-1]):
        return _split_ref(parts[-1])[0] in _LEGACY_PROVIDER_IDS
    if len(parts) >= 3 and parts[0] == "models" and parts[1] == "providers" and isinstance(parts[2], str):
        return parts[2].strip().lower() in _LEGACY_PROVIDER_IDS
    return False


def models_preflight(cfg):
    """§7.4.1 codes for the pre-migration config (run only in from-7x precheck)."""
    phase = "precheck"
    findings = []
    if not isinstance(cfg, dict):
        return findings
    codex_refs, platform, canonical = [], [], []
    for parts, s, _where in _iter_scanned(cfg):
        if _CANONICAL_OPENAI_PREFIX_RE.match(s):
            cm = _CANONICAL_OPENAI_REF_RE.match(s)
            canonical.append(("%s=%s" % (fmt_path(parts), redact_value(parts, s.strip())),
                              cm.group(1).lower() if cm else None))
        if _CODEX_PROVIDER_REF_RE.match(s):
            codex_refs.append(fmt_path(parts))
        m = LEGACY_REF_RE.match(s)
        if m and m.group(1).lower() in PLATFORM_ONLY_IDS:
            platform.append("%s=%s" % (fmt_path(parts), redact_value(parts, s.strip())))
    codex_prov = [fmt_path(["models", "providers", k]) for k, _v in _provider_blocks(cfg, "codex")]
    if codex_refs or codex_prov:
        findings.append(_finding(
            "models-codex-provider", "hard",
            "config uses the retired 'codex'/'codex-cli' provider (%s); 9.9 cannot migrate it automatically. "
            "Switch these to openai-codex/<model> (or remove them) on 0.5.93 first."
            % _brief(codex_refs + codex_prov), phase))
    runtime_hits, runtime_kept = [], []
    for parts, holder in _iter_runtime_holders(cfg):
        if parts and parts[0] == "auth":
            continue
        rid = _runtime_id_raw(holder.get("agentRuntime"))
        if isinstance(rid, str) and rid.strip().lower() in CODEX_RUNTIME_IDS:
            hit = "%s=%s" % (fmt_path(parts + ["agentRuntime", "id"]), rid.strip())
            (runtime_hits if _is_legacy_runtime_holder(parts) else runtime_kept).append(hit)
    if runtime_hits:
        findings.append(_finding(
            "models-codex-runtime", "hard",
            "config pins the Codex runtime on legacy openai-codex/codex entries (%s); the migration turns them into "
            "openai/ entries that the gate keeps on the OpenClaw runtime, so these pins cannot be kept. Remove them "
            "(or use openai/<model> entries for Codex) on 0.5.93 first." % _brief(runtime_hits), phase))
    if runtime_kept:
        # the documented 7.35 way to force the Codex app-server; the gate and doctor leave these alone
        findings.append(_finding(
            "codex-runtime-kept", "info",
            "Codex runtime pins kept as configured: %s" % _brief(runtime_kept), phase))
    legacy_blocks = _provider_blocks(cfg, "openai-codex")
    canonical_blocks = _provider_blocks(cfg, "openai")
    if legacy_blocks and canonical_blocks:
        canon_ids = set()
        for _k, b in canonical_blocks:
            canon_ids.update(_provider_model_ids(b))
        missing = []
        for _k, b in legacy_blocks:
            missing.extend(i for i in _provider_model_ids(b) if i not in canon_ids)
        if missing:
            findings.append(_finding(
                "models-provider-merge", "hard",
                "models.providers has both an 'openai-codex' and an 'openai' block and the legacy block defines "
                "models the canonical one lacks (%s); 9.9 refuses to merge them and would strand every "
                "openai-codex ref. Merge the blocks by hand on 0.5.93 first." % _brief(sorted(set(missing))), phase))
    wild_pinned = []
    for _label, parts, _aid, mmap in _models_map_scopes(cfg):
        for k, entry in mmap.items():
            if isinstance(k, str) and _LEGACY_WILDCARD_KEY_RE.match(k) and isinstance(entry, dict) \
                    and "agentRuntime" in entry:
                rid = _runtime_id_raw(entry.get("agentRuntime"))
                norm = rid.strip().lower() if isinstance(rid, str) else None
                if norm not in DEFAULT_RUNTIME_IDS | OPENCLAW_RUNTIME_IDS:
                    wild_pinned.append("%s=%s" % (fmt_path(parts + [k, "agentRuntime", "id"]), rid))
    if wild_pinned:
        findings.append(_finding(
            "models-wildcard-pinned", "hard",
            "an openai-codex/* wildcard carries a runtime pin the gate cannot expand safely (%s)."
            % _brief(wild_pinned), phase))
    if platform:
        findings.append(_finding(
            "models-platform-only", "acceptable",
            "legacy refs name models that 9.9 serves only with an OpenAI API key (metered), not with the "
            "ChatGPT subscription: %s" % _brief(platform), phase))
    collisions = route_collisions(cfg)
    if collisions:
        findings.append(_finding(
            "models-route-collision", "acceptable",
            "openai-codex model(s) also used as canonical openai/ refs: %s. 9.9 has one openai/<model> route per "
            "model, so after the migration these openai/ refs run on the OpenClaw runtime like the migrated "
            "openai-codex refs (on 7.35 they used the Codex app-server)"
            % _brief("%s (%s)" % (mid, _brief(paths, 3)) for mid, paths in sorted(collisions.items())), phase))
    canonical = [c for c, mid in canonical if mid not in collisions]
    if canonical:
        # Contract addendum 2 (replaces addendum 1 items 1-4): not a HOLD and never re-pinned. 7.35 ran
        # unpinned openai/* turns on the bundled Codex app-server, and 9.9 does the same.
        findings.append(_finding(
            "canonical-openai-refs", "info",
            "%d canonical openai/* refs keep their runtime (Codex app-server by default, as on 7.35): %s"
            % (len(canonical), _brief(canonical)), phase))
    return findings


def explicit_ids(cfg):
    """§7.4.2 EXPLICIT: sorted unique union of legacy ref ids, openai-codex provider models, defaults."""
    ids = set(EXPLICIT_DEFAULT_IDS)
    if isinstance(cfg, dict):
        for r in scan_legacy_refs(cfg):
            if r["id"] != "*":
                ids.add(r["id"])
        for _k, block in _provider_blocks(cfg, "openai-codex"):
            for mid in _provider_model_ids(block):
                if not re.search(r"[\s@*]", mid):
                    ids.add(mid)
    return sorted(ids)


def _r1_expansion(mmap, explicit, ref_ids):
    """Ids R1 adds as openai-codex/<x> keys for a map's openai-codex/* wildcard: the EXPLICIT ids the
    map lacks, except expansions whose canonical openai/<remap x> key the map already has (F2: that
    key keeps its runtime; a real legacy ref id is still expanded and reported as a collision)."""
    existing = {_split_ref(k) for k in mmap if isinstance(k, str)}
    canonical = {m.lower() for p, m in existing if p == "openai" and m and m != "*"}
    real = {i.lower() for i in ref_ids}
    out = []
    for x in explicit:
        if ("openai-codex", x) in existing:
            continue
        if x.lower() not in real and remap_model_id(x).lower() in canonical:
            continue
        out.append(x)
        existing.add(("openai-codex", x))
    return out


def _ref_scope(cfg, parts):
    """None for a defaults/global ref, else its agent (lower-cased id, or the agents.list[i] label)."""
    if len(parts) >= 3 and parts[0] == "agents" and parts[1] in ("list", "entries"):
        aid = _agent_id_for_parts(cfg, parts)
        return aid.strip().lower() if isinstance(aid, str) else fmt_path(parts[:3])
    return None


def route_collisions(cfg):
    """F2: {openai model id: [paths]} of canonical openai/<id> refs and keys whose id an openai-codex
    ref (after the retired-id remap) or an R1 wildcard expansion also uses in an overlapping scope.

    9.9 keeps one openai/<id> route per scope: the migrated openai-codex slot and the canonical use end
    up on the same entry, pinned to the OpenClaw runtime (R2), while 7.35 ran the canonical use on the
    Codex app-server. R2 pins every legacy ref id in agents.defaults.models, so a real legacy ref
    overlaps every scope; an R1 expansion only its own map's scope (defaults = every scope).
    """
    if not isinstance(cfg, dict):
        return {}
    refs = scan_legacy_refs(cfg)
    legacy = {}
    for r in refs:
        if r["id"] != "*":
            legacy.setdefault(remap_model_id(r["id"]).lower(), set()).add(None)
    if refs:
        explicit = explicit_ids(cfg)
        ref_ids = {r["id"] for r in refs if r["id"] != "*"}
        for label, parts, aid, mmap in _models_map_scopes(cfg):
            if any(isinstance(k, str) and _LEGACY_WILDCARD_KEY_RE.match(k) for k in mmap):
                for x in _r1_expansion(mmap, explicit, ref_ids):
                    legacy.setdefault(remap_model_id(x).lower(), set()).add(_scope_id(parts, aid, label))
    out = {}
    for parts, s, _where in _iter_scanned(cfg):
        m = _CANONICAL_OPENAI_REF_RE.match(s)
        mid = m.group(1).lower() if m else None
        if mid is None or mid not in legacy:
            continue
        scope = _ref_scope(cfg, parts)
        if None in legacy[mid] or scope is None or scope in legacy[mid]:
            path = fmt_path(parts)
            if path not in out.setdefault(mid, []):
                out[mid].append(path)
    return out


# --- R1-R3: pre-migrate config ---------------------------------------------------------


def _legacy_key_id(k):
    """Model id of a legacy openai-codex map key (None if the key is not legacy)."""
    if not isinstance(k, str):
        return None
    prov, model = _split_ref(k)
    if prov != "openai-codex" or not model:
        return None
    return model


def _pin_entry(mmap, key, parts, ledger, step):
    """R2 pin on mmap[key]: agentRuntime.id -> openclaw unless already openclaw/pi or explicit other."""
    entry = mmap.get(key)
    if not isinstance(entry, dict):
        entry = {}
    ar = entry.get("agentRuntime")
    rid = _runtime_id_raw(ar)
    norm = rid.strip().lower() if isinstance(rid, str) else None
    if norm in OPENCLAW_RUNTIME_IDS:
        return False
    if ar is not None and norm not in DEFAULT_RUNTIME_IDS and not (isinstance(ar, dict) and rid is None):
        return False  # explicit other runtime: precheck decides (models-codex-runtime / wildcard-pinned)
    new_ar = dict(ar) if isinstance(ar, dict) else {}
    new_ar["id"] = "openclaw"
    new_entry = dict(entry)
    new_entry["agentRuntime"] = new_ar
    ledger.append({"step": step, "file": CONFIG_FILE, "path": fmt_path(parts + [key, "agentRuntime"]),
                   "before": copy.deepcopy(ar), "after": copy.deepcopy(new_ar)})
    mmap[key] = new_entry
    return True


def premigrate_config(cfg):
    """R1 (wildcards), R2 (openclaw runtime pins), R3 (modelPolicy {}) -- §7.4.2. R4: nothing.

    Pass the run's write-once config.pre-gate.json (critique B2): R3 and EXPLICIT are evaluated on the
    input, so the result is the same on every re-run. `meta` is never touched.
    Returns (new_cfg, ledger, summary) with summary keys explicit, pinned, scopes,
    model_policy_written, legacy_slots (the pre-transform legacy refs without wildcards; PC3 input).
    Raises ValueError when a models map that must be edited is not an object.
    """
    if not isinstance(cfg, dict):
        raise ValueError("openclaw.json top-level value is not an object")
    new = copy.deepcopy(cfg)
    ledger = []
    refs = scan_legacy_refs(cfg)
    legacy_slots = [{k: copy.deepcopy(r[k]) for k in ("path", "value", "where", "id", "profile", "parts", "agent_id")}
                    for r in refs if r["id"] != "*"]
    ref_ids = {r["id"] for r in refs if r["id"] != "*"}
    explicit = explicit_ids(cfg) if refs else []
    before_defaults_models = _get(cfg, ["agents", "defaults", "models"])
    map_absent_or_empty = before_defaults_models is _MISSING or before_defaults_models == {}

    # R1: expand legacy wildcards in every scope.
    scopes = []
    for label, parts, _aid, mmap in _models_map_scopes(new):
        wild = [k for k in mmap if isinstance(k, str) and _LEGACY_WILDCARD_KEY_RE.match(k)]
        if not wild:
            continue
        template = mmap[wild[0]]
        template = copy.deepcopy(template) if isinstance(template, dict) else {}
        template.pop("alias", None)
        template.pop("agentRuntime", None)
        for k in wild:
            ledger.append({"step": "R1", "file": CONFIG_FILE, "path": fmt_path(parts + [k]),
                           "before": copy.deepcopy(mmap[k]), "after": None})
            del mmap[k]
        for x in _r1_expansion(mmap, explicit, ref_ids):
            key = "openai-codex/" + x
            mmap[key] = copy.deepcopy(template)
            ledger.append({"step": "R1", "file": CONFIG_FILE, "path": fmt_path(parts + [key]),
                           "before": None, "after": copy.deepcopy(template)})
        scopes.append(label)

    # R2: defaults map gets a pinned entry for every legacy id; existing per-agent legacy keys are pinned.
    pinned = 0
    dm = _get(new, ["agents", "defaults", "models"])
    ids2 = set(ref_ids)
    if isinstance(dm, dict):
        ids2.update(i for i in (_legacy_key_id(k) for k in dm) if i and i != "*")
    if ids2:
        if dm is _MISSING:
            agents = new.get("agents", _MISSING)
            if agents is _MISSING:
                new["agents"] = agents = {}
            if not isinstance(agents, dict):
                raise ValueError("agents is not an object")
            defaults = agents.get("defaults", _MISSING)
            if defaults is _MISSING:
                agents["defaults"] = defaults = {}
            if not isinstance(defaults, dict):
                raise ValueError("agents.defaults is not an object")
            defaults["models"] = dm = {}
        elif not isinstance(dm, dict):
            raise ValueError("agents.defaults.models is not an object")
        dparts = ["agents", "defaults", "models"]
        for x in sorted(ids2):
            key = next((k for k in dm if isinstance(k, str) and _split_ref(k) == ("openai-codex", x)), None)
            if key is None:
                key = "openai-codex/" + x
                dm[key] = {"agentRuntime": {"id": "openclaw"}}
                ledger.append({"step": "R2", "file": CONFIG_FILE, "path": fmt_path(dparts + [key]),
                               "before": None, "after": copy.deepcopy(dm[key])})
                pinned += 1
            elif _pin_entry(dm, key, dparts, ledger, "R2"):
                pinned += 1
    for _label, parts, _aid, mmap in _models_map_scopes(new):
        if parts == ["agents", "defaults", "models"]:
            continue
        for k in list(mmap):
            x = _legacy_key_id(k)
            if x and x != "*" and _pin_entry(mmap, k, parts, ledger, "R2"):
                pinned += 1

    # R3: a defaults map that did not exist (or was empty) must not become an allowlist in 9.9.
    model_policy_written = False
    defaults = _get(new, ["agents", "defaults"])
    if (map_absent_or_empty and isinstance(defaults, dict) and isinstance(defaults.get("models"), dict)
            and defaults["models"] and "modelPolicy" not in defaults):
        defaults["modelPolicy"] = {}
        model_policy_written = True
        ledger.append({"step": "R3", "file": CONFIG_FILE, "path": "agents.defaults.modelPolicy",
                       "before": None, "after": {}})

    summary = {"explicit": explicit, "pinned": pinned, "scopes": scopes,
               "model_policy_written": model_policy_written, "legacy_slots": legacy_slots}
    return new, ledger, summary


# --- R5: sessions ------------------------------------------------------------------------


def _session_uses_codex(e):
    for f in ("modelProvider", "providerOverride"):
        if str(e.get(f, "")).strip().lower() in ("openai-codex", "codex"):
            return True
    for f in ("model", "modelOverride"):
        v = e.get(f)
        if isinstance(v, str) and _SESSION_CODEX_MODEL_RE.match(v):
            return True
    return False


def premigrate_sessions(store, rel):
    """R5 (§7.4.2 + critique B13) on one 7.35 sessions.json dict.

    Returns (new_store, ledger, {"pinned": [...], "user_explicit": [...], "harness": [...]}).
    "pinned" lists entries pinned now plus entries already on openclaw/pi (pc-sessions-runtime checks
    all of them); "user_explicit" and "harness" are ledgered with a note and excluded from that check.
    """
    if not isinstance(store, dict):
        raise ValueError("%s: top-level value is not an object" % rel)
    new = copy.deepcopy(store)
    ledger, pinned, user_explicit, harness = [], [], [], []
    for key, e in new.items():
        if not isinstance(e, dict) or not _session_uses_codex(e):
            continue
        path = fmt_path([key, "agentRuntimeOverride"])
        ov = e.get("agentRuntimeOverride", _MISSING)
        cur = None if ov is _MISSING else copy.deepcopy(ov)
        if e.get("agentHarnessId"):
            harness.append(key)
            ledger.append({"step": "R5", "file": rel, "path": path, "before": cur, "after": cur, "note": "harness"})
            continue
        norm = ov.strip().lower() if isinstance(ov, str) else None
        if ov is _MISSING or ov is None or norm in DEFAULT_RUNTIME_IDS:
            e["agentRuntimeOverride"] = "openclaw"
            ledger.append({"step": "R5", "file": rel, "path": path, "before": cur, "after": "openclaw"})
            pinned.append(key)
        elif norm in OPENCLAW_RUNTIME_IDS:
            pinned.append(key)
        else:
            user_explicit.append(key)
            ledger.append({"step": "R5", "file": rel, "path": path, "before": cur, "after": cur,
                           "note": "user-explicit"})
    return new, ledger, {"pinned": pinned, "user_explicit": user_explicit, "harness": harness}


# --- canonical refs, retired-model map, migrated legacy keys (contract addendum 2) ----------------


def canonical_openai_refs(cfg):
    """["path=value"] of canonical openai/ refs: string values outside "auth" and models-map keys.

    Contract addendum 2: they keep their runtime (Codex app-server by default, as on 7.35), and their
    presence before the gate means Codex was in use (F1b rule 4).
    """
    out = []
    if not isinstance(cfg, dict):
        return out
    for parts, s, _where in _iter_scanned(cfg):
        if _CANONICAL_OPENAI_PREFIX_RE.match(s):
            out.append("%s=%s" % (fmt_path(parts), redact_value(parts, s.strip())))
    return out


def ref_base(ref):
    """'Provider / Model@profile' -> 'provider/model' (lower-cased, no @profile); None for a non-string."""
    if not isinstance(ref, str):
        return None
    s = ref.strip()
    at = s.find("@")
    if at > 0:
        s = s[:at]
    prov, model = _split_ref(s)
    return (prov + "/" + model.lower()) if prov else s.lower()


def _retired_view(retired_map):
    """{base ref: successor base ref} with normalised keys (the journal map may come from JSON)."""
    view = {}
    if isinstance(retired_map, dict):
        for k, v in retired_map.items():
            kb, vb = ref_base(k), ref_base(v)
            if kb and vb and kb != vb:
                view[kb] = vb
    return view


def retired_chain(ref, retired_map):
    """Successors doctor gave `ref` (journal doctor_retired_map, all passes), in order; [] if none."""
    view = _retired_view(retired_map)
    cur = ref_base(ref)
    seen, out = {cur}, []
    while cur in view and view[cur] not in seen:
        cur = view[cur]
        seen.add(cur)
        out.append(cur)
    return out


def apply_retired(ref, retired_map):
    """remap o retired_map for F2/F3: doctor's final successor of `ref` (its @profile kept), else `ref`."""
    chain = retired_chain(ref, retired_map)
    if not chain:
        return ref
    s = ref.strip()
    at = s.find("@")
    return chain[-1] + (s[at:] if at > 0 else "")


def _derived_ids(model_id, retired_map):
    """Lower-case openai/ ids a legacy openai-codex/<model_id> can end up as after doctor: the id, its
    retired-id remap, the 9.9 follow-up canonicalisation and doctor's retirement successors."""
    ids = set()
    for y in (model_id.strip().lower(), remap_model_id(model_id).lower()):
        ids.add(y)
        if y in _CANONICAL_FOLLOWUPS:
            ids.add(_CANONICAL_FOLLOWUPS[y])
    for y in list(ids):
        for r in retired_chain("openai/" + y, retired_map):
            prov, mid = _split_ref(r)
            if prov == "openai" and mid:
                ids.add(mid.lower())
    return ids


def _scope_id(parts, aid, label):
    """None for agents.defaults.models, else the lower-cased agent id (label when the agent has no id)."""
    if list(parts[:3]) == ["agents", "defaults", "models"]:
        return None
    return aid.strip().lower() if isinstance(aid, str) else label


def legacy_key_context(pre_gate, retired_map=None, extra_ids=()):
    """Contract addendum 2 rule 3: which openai/<id> models-map keys are migrated legacy slots.

    pre_gate: config.pre-gate.json (the 7.35 original); extra_ids: openai-codex model ids used only by
    cron jobs (doctor pins them for "migrated cron runtime intent"). Returns
    {"defaults": ids, "global": ids, "agents": {aid: ids}, "pre_keys": {scope: ids}, "pre_refs": {aid: ids}}:
    legacy ids of the defaults map (every legacy ref: R2 pins them all there), legacy ids every agent
    inherits (defaults/global refs), each agent's own legacy ids, and the canonical openai/ ids that already
    existed per scope (keys; for agents also the agent's own canonical refs, which doctor's "shield" pins).
    """
    ctx = {"defaults": set(), "global": set(), "agents": {}, "pre_keys": {}, "pre_refs": {}}
    if not isinstance(pre_gate, dict):
        return ctx
    refs = scan_legacy_refs(pre_gate)
    explicit = explicit_ids(pre_gate) if refs else []
    ref_ids = {r["id"] for r in refs if r["id"] != "*"}
    wild = {}  # scope -> derived ids of the keys R1 adds there (F2: not the skipped canonical ones)
    for label, parts, aid, mmap in _models_map_scopes(pre_gate):
        scope = _scope_id(parts, aid, label)
        keys = ctx["pre_keys"].setdefault(scope, set())
        for k in mmap:
            if not isinstance(k, str):
                continue
            if _LEGACY_WILDCARD_KEY_RE.match(k):
                ids = wild.setdefault(scope, set())
                for x in _r1_expansion(mmap, explicit, ref_ids):
                    ids |= _derived_ids(x, retired_map)
            prov, mid = _split_ref(k)
            if prov == "openai" and mid and mid != "*":
                keys.add(mid.lower())
    for r in refs:
        if r["id"] == "*":
            continue
        ids = _derived_ids(r["id"], retired_map)
        ctx["defaults"] |= ids
        aid = r.get("agent_id")
        if isinstance(aid, str) and aid.strip():
            ctx["agents"].setdefault(aid.strip().lower(), set()).update(ids)
        else:
            ctx["global"] |= ids
    for x in extra_ids or ():
        if isinstance(x, str) and x.strip() and x.strip() != "*":
            ids = _derived_ids(x, retired_map)
            ctx["defaults"] |= ids
            ctx["global"] |= ids
    if None in wild:
        ctx["defaults"] |= wild[None]
        ctx["global"] |= wild[None]
    for scope, ids in wild.items():
        if scope is not None:
            ctx["agents"].setdefault(scope, set()).update(ids)
    for parts, s, where in _iter_scanned(pre_gate):
        if where != "value" or len(parts) < 3 or parts[0] != "agents" or parts[1] not in ("list", "entries"):
            continue
        aid = _agent_id_for_parts(pre_gate, parts)
        m = _CANONICAL_OPENAI_REF_RE.match(s)
        if not m or m.group(1) == "*" or not isinstance(aid, str):
            continue
        a = aid.strip().lower()
        mid = m.group(1).lower()
        if mid not in ctx["agents"].get(a, ()):
            ctx["pre_refs"].setdefault(a, set()).add(mid)
    return ctx


def is_migrated_legacy_key(ctx, scope, model_id):
    """True when models-map key openai/<model_id> in `scope` (None = defaults, else lower-cased agent id)
    holds a migrated openai-codex slot (F1 flips doctor's Codex pins there; PC2 checks it)."""
    if not isinstance(model_id, str):
        return False
    mid = model_id.strip().lower()
    if not mid or mid == "*" or mid in ctx["pre_keys"].get(scope, ()):
        return False
    if scope is None:
        return mid in ctx["defaults"]
    if mid in ctx["pre_refs"].get(scope, ()):
        return False
    return mid in ctx["global"] or mid in ctx["agents"].get(scope, ())


_TEXT_MODEL_HOLDERS = ("heartbeat", "subagents", "compaction")


def _is_text_model_slot(parts):
    """A config path that selects a text (chat) model: agents.defaults / agents.list[i] /
    agents.entries.<id> .model (primary/fallbacks), .utilityModel and .heartbeat/.subagents/.compaction
    .model, and any *.model / *.utilityModel under hooks (mappings) or cron. Image, media, TTS, PDF and
    memory-search models never run on an agent runtime and do not count."""
    p = [x for x in parts if not _is_index(x)]
    if len(p) >= 2 and p[-2] in ("model", "utilityModel") and p[-1] in ("primary", "fallbacks"):
        p = p[:-1]
    if not p or p[-1] not in ("model", "utilityModel"):
        return False
    if p[0] in ("hooks", "cron"):
        return True
    if len(p) < 3 or p[0] != "agents":
        return False
    if p[1] in ("defaults", "list"):
        rest = p[2:]
    elif p[1] == "entries" and len(p) >= 4:
        rest = p[3:]
    else:
        return False
    return len(rest) == 1 or (len(rest) == 2 and rest[0] in _TEXT_MODEL_HOLDERS)


def canonical_text_model_refs(cfg):
    """["path=value"] of canonical openai/ refs that select a text model: models-map keys of the defaults
    and agents, and the slots of _is_text_model_slot (F15: what "Codex was in use" means)."""
    out = []
    if not isinstance(cfg, dict):
        return out
    for parts, s, where in _iter_scanned(cfg):
        if _CANONICAL_OPENAI_PREFIX_RE.match(s) and (where == "key" or _is_text_model_slot(parts)):
            out.append("%s=%s" % (fmt_path(parts), redact_value(parts, s.strip())))
    return out


def _codex_needed(rule_cfg, codex_pkg_before):
    """F1b rule 4: Codex was in use before the gate (canonical openai/ text-model refs, or other evidence
    the gate passes as codex_pkg_before: an installed codex plugin, cron jobs on openai/ models)."""
    return bool(codex_pkg_before) or bool(canonical_text_model_refs(rule_cfg))


def _f1b(new, pre_value_cfg, rule_cfg, codex_pkg_before, ledger, policy_failures, phase="fixups"):
    """F1b (contract addendum 2 rule 4): plugins.entries.codex back to its pre value (absent -> delete),
    but only when Codex was not in use before the gate. Returns (restored, codex_needed)."""
    needed = _codex_needed(rule_cfg, codex_pkg_before)
    pre_codex = _get(pre_value_cfg, ["plugins", "entries", "codex"])
    now_codex = _get(new, ["plugins", "entries", "codex"])
    if needed or pre_codex == now_codex:
        return False, needed
    before = None if now_codex is _MISSING else copy.deepcopy(now_codex)
    after = None if pre_codex is _MISSING else copy.deepcopy(pre_codex)
    if pre_codex is _MISSING:
        del new["plugins"]["entries"]["codex"]
    else:
        entries = _ensure_dict_path(new, ["plugins", "entries"])
        if entries is None:
            policy_failures.append(_finding(
                "pc-codex-runtime", "acceptable",
                "could not restore plugins.entries.codex: plugins.entries is not an object", phase))
            return False, needed
        entries["codex"] = copy.deepcopy(pre_codex)
    ledger.append({"step": "F1b", "file": CONFIG_FILE, "path": "plugins.entries.codex",
                   "before": before, "after": after})
    return True, needed


# --- F1-F3: fixups between doctor pass 1 and pass 2 ---------------------------------------------


def _canonicalize_ref(s):
    """openai-codex/<X> (no @profile, not a wildcard) -> (openai/<remap X>, remapped id); else (None, None)."""
    m = LEGACY_REF_RE.match(s) if isinstance(s, str) else None
    if not m or m.group(2) or m.group(1) == "*":
        return None, None
    y = remap_model_id(m.group(1))
    return "openai/" + y, y


def _canonicalize_retired(s, retired_map):
    """F2/F3 rewrite: openai-codex/<X> -> remap o retired_map; (new ref, openai id or None) or (None, None)."""
    canon, y = _canonicalize_ref(s)
    if canon is None:
        return None, None
    final = apply_retired(canon, retired_map)
    prov, mid = _split_ref(final)
    return final, (mid if prov == "openai" else None)


def _set_at(root, parts, value):
    parent = _get(root, parts[:-1], None)
    if isinstance(parent, (dict, list)):
        parent[parts[-1]] = value


def fixups(cfg_now, cfg_pre_gate, cfg_pre_pass1, *, retired_map=None, codex_pkg_before=False,
           extra_legacy_ids=()):
    """F1, F1b, F2, F3 (§7.6 with contract addendum 2) on the config written by doctor pass 1.

    cfg_pre_gate: config.pre-gate.json (7.35 original); cfg_pre_pass1: config.pre-pass1.json.
    retired_map: doctor's retired-model replacements so far (journal doctor_retired_map); F2/F3 map
    their values through it so pass 2 does not undo them. codex_pkg_before: Codex was in use outside
    openclaw.json (a codex plugin package npm/projects/openclaw-codex-* existed before pass 1, or cron jobs
    used openai/ models). extra_legacy_ids: openai-codex ids used by cron jobs only.
    Returns (new_cfg, ledger, summary{codex_pins, refs_rewritten, compaction_restored,
    codex_plugin_restored, codex_needed, policy_failures}). F4 (config validate) is run by the caller.
    """
    if not isinstance(cfg_now, dict):
        raise ValueError("openclaw.json top-level value is not an object")
    pre_gate = cfg_pre_gate if isinstance(cfg_pre_gate, dict) else {}
    pre_pass1 = cfg_pre_pass1 if isinstance(cfg_pre_pass1, dict) else {}
    new = copy.deepcopy(cfg_now)
    ledger, policy_failures = [], []
    ctx = legacy_key_context(pre_gate, retired_map, extra_legacy_ids)

    # F1: doctor-written Codex pins on migrated legacy keys -> openclaw (addendum 2 rule 3). Keys that
    # existed canonically before the gate, the openai/* wildcard and provider blocks are never touched.
    codex_pins = 0
    for label, parts, aid, mmap in _models_map_scopes(new):
        scope = _scope_id(parts, aid, label)
        for k, entry in mmap.items():
            if not isinstance(k, str) or not isinstance(entry, dict) or "agentRuntime" not in entry:
                continue
            prov, mid = _split_ref(k)
            if prov != "openai" or not is_migrated_legacy_key(ctx, scope, mid):
                continue
            ar = entry["agentRuntime"]
            rid = _runtime_id_raw(ar)
            if not (isinstance(rid, str) and rid.strip().lower() in DOCTOR_CODEX_PIN_IDS):
                continue
            new_ar = dict(ar) if isinstance(ar, dict) else {}
            new_ar["id"] = "openclaw"
            ledger.append({"step": "F1", "file": CONFIG_FILE, "path": fmt_path(parts + [k, "agentRuntime"]),
                           "before": copy.deepcopy(ar), "after": copy.deepcopy(new_ar)})
            entry["agentRuntime"] = new_ar
            codex_pins += 1

    # F1b: plugins.entries.codex back to its pre-pass1 value, only if Codex was not in use before.
    codex_plugin_restored, codex_needed = _f1b(new, pre_pass1, pre_gate, codex_pkg_before, ledger,
                                               policy_failures)

    # F2: leftover legacy refs (values) -> remap o retired_map; legacy map keys renamed/merged.
    refs_rewritten = 0
    rewritten_ids = set()
    for parts, s, where in _iter_scanned(new):
        if where != "value":
            continue
        canon, y = _canonicalize_retired(s, retired_map)
        if canon is None:
            continue
        _set_at(new, parts, canon)
        ledger.append({"step": "F2", "file": CONFIG_FILE, "path": fmt_path(parts), "before": s, "after": canon})
        refs_rewritten += 1
        if y:
            rewritten_ids.add(y)
    for _label, parts, _aid, mmap in _models_map_scopes(new):
        legacy_keys = [k for k in mmap if _canonicalize_ref(k)[0] is not None]
        if not legacy_keys:
            continue
        legacy_set = set(legacy_keys)
        rebuilt = {}
        for k, v in mmap.items():
            if k not in legacy_set:
                rebuilt.setdefault(k, v)  # may already hold a merged canonical entry
                continue
            canon, y = _canonicalize_retired(k, retired_map)
            target_base = ref_base(canon)
            candidates = list(rebuilt) + [ek for ek in mmap if ek not in legacy_set and ek not in rebuilt]
            target_key = next((ek for ek in candidates if isinstance(ek, str) and ref_base(ek) == target_base),
                              None)
            if target_key is not None:
                # merge into the canonical entry without overwriting its fields; a canonical key that
                # comes later in the map is claimed here (setdefault above then keeps the merge)
                target = rebuilt[target_key] if target_key in rebuilt else mmap[target_key]
                merged = copy.deepcopy(target) if isinstance(target, dict) else {}
                if isinstance(v, dict):
                    for fk, fv in v.items():
                        if fk not in merged:
                            merged[fk] = copy.deepcopy(fv)
                rebuilt[target_key] = merged
                ledger.append({"step": "F2", "file": CONFIG_FILE, "path": fmt_path(parts + [k]),
                               "before": copy.deepcopy(v), "after": None})
                ledger.append({"step": "F2", "file": CONFIG_FILE, "path": fmt_path(parts + [target_key]),
                               "before": copy.deepcopy(target), "after": copy.deepcopy(merged)})
            else:
                rebuilt[canon] = v
                ledger.append({"step": "F2", "file": CONFIG_FILE, "path": fmt_path(parts + [k]),
                               "before": copy.deepcopy(v), "after": None})
                ledger.append({"step": "F2", "file": CONFIG_FILE, "path": fmt_path(parts + [canon]),
                               "before": None, "after": copy.deepcopy(v)})
            refs_rewritten += 1
            if y:
                rewritten_ids.add(y)
        mmap.clear()
        mmap.update(rebuilt)

    # F3: restore compaction.model / compaction.provider that doctor deleted.
    compaction_restored = False
    pre_holders = {None: _get(pre_gate, ["agents", "defaults"], None)}
    pre_entries = _get(pre_gate, ["agents", "entries"], None)
    if isinstance(pre_entries, dict):
        for aid, a in pre_entries.items():
            pre_holders.setdefault(aid, a)
    pre_list = _get(pre_gate, ["agents", "list"], None)
    if isinstance(pre_list, list):
        for a in pre_list:
            if isinstance(a, dict) and isinstance(a.get("id"), str):
                pre_holders.setdefault(a["id"], a)
    now_holders = []
    d = _get(new, ["agents", "defaults"], None)
    if isinstance(d, dict):
        now_holders.append((None, ["agents", "defaults"], d))
    ents = _get(new, ["agents", "entries"], None)
    if isinstance(ents, dict):
        for aid, a in ents.items():
            if isinstance(a, dict):
                now_holders.append((aid, ["agents", "entries", aid], a))
    lst = _get(new, ["agents", "list"], None)
    if isinstance(lst, list):
        for i, a in enumerate(lst):
            if isinstance(a, dict) and isinstance(a.get("id"), str):
                now_holders.append((a["id"], ["agents", "list", i], a))
    ctx_engine_same = _get(new, ["plugins", "slots", "contextEngine"]) == _get(pre_pass1, ["plugins", "slots", "contextEngine"])
    for aid, hparts, holder in now_holders:
        pre_holder = pre_holders.get(aid)
        pre_comp = pre_holder.get("compaction") if isinstance(pre_holder, dict) else None
        if not isinstance(pre_comp, dict):
            continue
        now_comp = holder.get("compaction", _MISSING)
        if now_comp is not _MISSING and not isinstance(now_comp, dict):
            continue
        for field in ("model", "provider"):
            if field not in pre_comp:
                continue
            if isinstance(now_comp, dict) and field in now_comp:
                continue
            val = copy.deepcopy(pre_comp[field])
            if field == "provider":
                if isinstance(val, str) and val.strip().lower() == "lossless-claw":
                    continue
                if not ctx_engine_same:
                    continue
            else:
                canon, y = _canonicalize_retired(val, retired_map)
                if canon is not None:
                    val = canon
                    if y:
                        rewritten_ids.add(y)
                elif isinstance(val, str):
                    val = apply_retired(val, retired_map)  # doctor retired it elsewhere: keep its choice
            if now_comp is _MISSING:
                holder["compaction"] = now_comp = {}
            now_comp[field] = val
            ledger.append({"step": "F3", "file": CONFIG_FILE, "path": fmt_path(hparts + ["compaction", field]),
                           "before": None, "after": copy.deepcopy(val)})
            compaction_restored = True

    # F2 (cont.): every rewritten id must resolve to openclaw via agents.defaults.models["openai/<Y>"]
    # (never through a key that existed canonically before the gate: addendum 2 rule 3).
    for y in sorted(rewritten_ids):
        if y.strip().lower() in ctx["pre_keys"].get(None, ()):
            continue
        dm = _get(new, ["agents", "defaults", "models"])
        key = None
        if isinstance(dm, dict):
            key = next((k for k in dm if isinstance(k, str) and _split_ref(k) == ("openai", y)), None)
        dparts = ["agents", "defaults", "models"]
        if key is not None:
            _pin_entry(dm, key, dparts, ledger, "F2")
            continue
        allow_create = (_get(new, ["meta", "migrations", "modelPolicyAllowlist"], None) is True
                        or isinstance(_get(new, ["agents", "defaults", "modelPolicy"], None), dict))
        target = _ensure_dict_path(new, dparts) if allow_create else None
        if target is None:
            policy_failures.append(_finding(
                "pc-runtime-pin", "acceptable",
                "openai/%s cannot be pinned to the OpenClaw runtime: adding agents.defaults.models[\"openai/%s\"] "
                "would %s" % (y, y, "restrict model choice (no modelPolicy and no allowlist marker)"
                                     if not allow_create else "require replacing a non-object value"), "fixups"))
            continue
        key = "openai/" + y
        target[key] = {"agentRuntime": {"id": "openclaw"}}
        ledger.append({"step": "F2", "file": CONFIG_FILE, "path": fmt_path(dparts + [key]),
                       "before": None, "after": copy.deepcopy(target[key])})

    summary = {"codex_pins": codex_pins, "refs_rewritten": refs_rewritten,
               "compaction_restored": compaction_restored, "codex_plugin_restored": codex_plugin_restored,
               "codex_needed": codex_needed, "policy_failures": policy_failures}
    return new, ledger, summary


def post_doctor_fixups(cfg_now, cfg_pre, *, codex_pkg_before=False):
    """F1b for bump/maintenance runs (after pass 1) and for every mode after pass 2/3 (addendum 2 rule 4).

    cfg_pre: config.pre-gate.json (from-7x) or config.pre-pass1.json (bump/maintenance).
    Returns (new_cfg, ledger, summary{codex_plugin_restored, codex_needed, policy_failures}).
    """
    if not isinstance(cfg_now, dict):
        raise ValueError("openclaw.json top-level value is not an object")
    pre = cfg_pre if isinstance(cfg_pre, dict) else {}
    new = copy.deepcopy(cfg_now)
    ledger, policy_failures = [], []
    restored, needed = _f1b(new, pre, pre, codex_pkg_before, ledger, policy_failures)
    return new, ledger, {"codex_plugin_restored": restored, "codex_needed": needed,
                         "policy_failures": policy_failures}


# --- PC1-PC3 ------------------------------------------------------------------------------


def check_legacy_refs(cfg):
    """PC1 (pc-legacy-refs): list of problems, empty = pass."""
    problems = []
    if not isinstance(cfg, dict):
        return ["openclaw.json top-level value is not an object"]
    for parts, s, where in _iter_scanned(cfg, keys_everywhere=True):
        if _PC1_LEGACY_RE.match(s):
            if where == "key":
                problems.append("legacy model ref as key at %s" % fmt_path(parts))
            else:
                problems.append("legacy model ref at %s: %s" % (fmt_path(parts), redact_value(parts, s)))
    auth = cfg.get("auth")
    if isinstance(auth, dict):
        order = auth.get("order")
        if isinstance(order, dict):
            for k, v in order.items():
                if isinstance(k, str) and k.strip().lower() in ("openai-codex", "codex"):
                    problems.append("legacy auth.order key %s" % fmt_path(["auth", "order", k]))
                if isinstance(v, list):
                    for i, e in enumerate(v):
                        if isinstance(e, str) and e.strip().lower().startswith("openai-codex:"):
                            problems.append("legacy profile id in %s: %s" % (fmt_path(["auth", "order", k, i]), e))
        profiles = auth.get("profiles")
        if isinstance(profiles, dict):
            for k in profiles:
                if isinstance(k, str) and k.strip().lower().startswith("openai-codex:"):
                    problems.append("legacy auth profile id %s" % fmt_path(["auth", "profiles", k]))
    for k, _v in _provider_blocks(cfg, "openai-codex") + _provider_blocks(cfg, "codex"):
        problems.append("legacy provider block %s" % fmt_path(["models", "providers", k]))
    return problems


def check_codex_runtime(cfg, pre_cfg=None, *, retired_map=None, codex_pkg_before=False, extra_legacy_ids=()):
    """PC2 (pc-codex-runtime), contract addendum 2 rule 5: only migrated legacy slots count.

    Fails when (a) a migrated legacy models-map key (keys created by R1/R2 and canonicalised by doctor,
    or doctor's pins on such ids for agents; see is_migrated_legacy_key) carries a Codex runtime id,
    (b) a legacy slot of pre_cfg resolves to the Codex runtime, or (c) plugins.entries.codex.enabled is
    true although it was not enabled before and Codex was not in use before (rule 4).
    pre_cfg: config.pre-gate.json (from-7x) or config.pre-pass1.json (bump/maintenance); canonical openai/
    refs and keys that existed there keep whatever runtime doctor gives them (rule 2).
    """
    problems = []
    if not isinstance(cfg, dict):
        return ["openclaw.json top-level value is not an object"]
    pre = pre_cfg if isinstance(pre_cfg, dict) else {}
    ctx = legacy_key_context(pre, retired_map, extra_legacy_ids)
    for label, parts, aid, mmap in _models_map_scopes(cfg):
        scope = _scope_id(parts, aid, label)
        for k, entry in mmap.items():
            if not isinstance(k, str) or not isinstance(entry, dict):
                continue
            prov, mid = _split_ref(k)
            if prov != "openai" or not is_migrated_legacy_key(ctx, scope, mid):
                continue
            rid = _runtime_id_raw(entry.get("agentRuntime"))
            if isinstance(rid, str) and rid.strip().lower() in CODEX_RUNTIME_IDS:
                problems.append("Codex runtime pin on migrated openai-codex model at %s: %s"
                                % (fmt_path(parts + [k, "agentRuntime", "id"]), rid.strip()))
    if pre:
        try:
            slots = premigrate_config(pre)[2]["legacy_slots"] if scan_legacy_refs(pre) else []
        except ValueError:  # a models map that is not an object: PC3 / pc-config report the config
            slots = []
        for item in _pc3_eval(cfg, slots, retired_map):
            if item[0] != "found" or item[2] is None:
                continue
            _kind, label, found_id, scope = item
            for a in scope:
                rid, src = _resolve_openai_runtime(cfg, found_id, a)
                if rid == "codex":
                    problems.append("slot %s: openai/%s for %s resolves to the Codex runtime (%s)"
                                    % (label, found_id, "agent " + a if a else "defaults", src))
    entry = _get(cfg, ["plugins", "entries", "codex"], None)
    if isinstance(entry, dict) and entry.get("enabled") is True:
        pre_entry = _get(pre, ["plugins", "entries", "codex"], None)
        expected = (isinstance(pre_entry, dict) and pre_entry.get("enabled") is True) \
            or _codex_needed(pre, codex_pkg_before)
        if not expected:
            problems.append("plugins.entries.codex.enabled is true (Codex agent runtime enabled by the migration)")
    return problems


def _agent_entry(cfg, agent_id):
    ents = _get(cfg, ["agents", "entries"], None)
    if isinstance(ents, dict):
        if isinstance(ents.get(agent_id), dict):
            return ents[agent_id]
        for k, v in ents.items():
            if isinstance(k, str) and k.strip().lower() == agent_id.strip().lower() and isinstance(v, dict):
                return v
    lst = _get(cfg, ["agents", "list"], None)
    if isinstance(lst, list):
        for a in lst:
            if isinstance(a, dict) and isinstance(a.get("id"), str) \
                    and a["id"].strip().lower() == agent_id.strip().lower():
                return a
    return None


def _agent_ids(cfg):
    ids = []
    ents = _get(cfg, ["agents", "entries"], None)
    if isinstance(ents, dict):
        ids.extend(k for k in ents if isinstance(k, str))
    lst = _get(cfg, ["agents", "list"], None)
    if isinstance(lst, list):
        ids.extend(a["id"] for a in lst if isinstance(a, dict) and isinstance(a.get("id"), str))
    return sorted(set(ids))


def _map_runtime_key(models, model_id, kind):
    """9.9 resolveAgentModelEntryRuntimePolicy for one models map and provider openai: (rid, key)."""
    if not isinstance(models, dict):
        return None, None
    provider_matches, bare_matches = [], []
    for k, entry in models.items():
        if not isinstance(k, str) or not isinstance(entry, dict):
            continue
        rid = _runtime_id_raw(entry.get("agentRuntime"))
        if not (isinstance(rid, str) and rid.strip()):
            continue
        if kind == "exact" and k.strip() == model_id:
            bare_matches.append((rid, k))
            continue
        prov, model = _split_ref(k)
        if prov != "openai":
            continue
        if (kind == "exact" and model == model_id) or (kind == "wildcard" and model == "*"):
            provider_matches.append((rid, k))
    found = provider_matches or bare_matches
    return found[0] if found else (None, None)


def _map_runtime(models, model_id, kind):
    return _map_runtime_key(models, model_id, kind)[0]


def _agent_entry_parts(cfg, agent_id):
    """Path parts of the agent's entry (agents.entries.<id> or agents.list[i]), or None."""
    ents = _get(cfg, ["agents", "entries"], None)
    if isinstance(ents, dict):
        if isinstance(ents.get(agent_id), dict):
            return ["agents", "entries", agent_id]
        for k, v in ents.items():
            if isinstance(k, str) and k.strip().lower() == agent_id.strip().lower() and isinstance(v, dict):
                return ["agents", "entries", k]
    lst = _get(cfg, ["agents", "list"], None)
    if isinstance(lst, list):
        for i, a in enumerate(lst):
            if isinstance(a, dict) and isinstance(a.get("id"), str) \
                    and a["id"].strip().lower() == agent_id.strip().lower():
                return ["agents", "list", i]
    return None


def _resolve_openai_runtime_at(cfg, model_id, agent_id):
    """(normalised runtime id or None, source, parts of the deciding holder or None) for openai/<model_id>
    in the scope of agent_id, with the 9.9 precedence (model-runtime-policy-Cdswy_mh.mjs:84-152)."""
    aparts = _agent_entry_parts(cfg, agent_id) if agent_id else None
    agent = _get(cfg, aparts, None) if aparts else None
    agent_models = agent.get("models") if isinstance(agent, dict) else None
    defaults_models = _get(cfg, ["agents", "defaults", "models"], None)
    dparts = ["agents", "defaults", "models"]
    rid, key = _map_runtime_key(agent_models, model_id, "exact")
    if rid is not None:
        return _norm_runtime(rid), "agent model entry", aparts + ["models", key]
    rid, key = _map_runtime_key(defaults_models, model_id, "exact")
    if rid is not None:
        return _norm_runtime(rid), "defaults model entry", dparts + [key]
    blocks = _provider_blocks(cfg, "openai")
    for pk, block in blocks:
        models = block.get("models") if isinstance(block, dict) else None
        if isinstance(models, list):
            for i, m in enumerate(models):
                if not isinstance(m, dict) or not isinstance(m.get("id"), str):
                    continue
                mid = m["id"].strip()
                prov, model = _split_ref(mid)
                if mid == model_id or (prov == "openai" and model == model_id):
                    r = _runtime_id_raw(m.get("agentRuntime"))
                    if isinstance(r, str) and r.strip():
                        return _norm_runtime(r), "provider model", ["models", "providers", pk, "models", i]
    rid, key = _map_runtime_key(agent_models, model_id, "wildcard")
    if rid is not None:
        return _norm_runtime(rid), "agent openai/* entry", aparts + ["models", key]
    rid, key = _map_runtime_key(defaults_models, model_id, "wildcard")
    if rid is not None:
        return _norm_runtime(rid), "defaults openai/* entry", dparts + [key]
    for pk, block in blocks:
        r = _runtime_id_raw(block.get("agentRuntime")) if isinstance(block, dict) else None
        if isinstance(r, str) and r.strip():
            return _norm_runtime(r), "provider", ["models", "providers", pk]
    return None, "none", None


def _resolve_openai_runtime(cfg, model_id, agent_id):
    """(normalised runtime id or None, source) for openai/<model_id> in the scope of agent_id."""
    rid, src, _parts = _resolve_openai_runtime_at(cfg, model_id, agent_id)
    return rid, src


def _expected_ids(legacy_id, retired_map=None):
    """(lower-case openai ids, other lower-case base refs) a legacy slot may hold after the migration:
    remap(X), its 9.9 follow-up, and doctor's retirement successors (contract addendum 2 item 9)."""
    y = remap_model_id(legacy_id).lower()
    ids = {y}
    if y in _CANONICAL_FOLLOWUPS:
        ids.add(_CANONICAL_FOLLOWUPS[y])
    others = set()
    for e in list(ids):
        for r in retired_chain("openai/" + e, retired_map):
            prov, mid = _split_ref(r)
            if prov == "openai" and mid:
                ids.add(mid.lower())
            else:
                others.add(r)
    return ids, others


def _post_parts(slot_parts, agent_id):
    """agents.list[i] -> agents.entries[<id>] (9.9 renames the list)."""
    if len(slot_parts) >= 3 and slot_parts[0] == "agents" and slot_parts[1] == "list" and _is_index(slot_parts[2]):
        if agent_id:
            return ["agents", "entries", agent_id] + list(slot_parts[3:])
        return None
    return list(slot_parts)


def _pc3_eval(cfg, legacy_slots, retired_map=None):
    """Per legacy slot: ("problem", text) or ("found", label, openai model id or None, agent scope list).

    The id is None when doctor retired the model to a non-OpenAI successor (nothing to resolve).
    """
    all_agents = _agent_ids(cfg)
    out = []
    for slot in legacy_slots or []:
        value = slot.get("value")
        parts = slot.get("parts")
        if not isinstance(parts, list):
            try:
                parts = parse_path(slot.get("path", ""))
            except (ValueError, json.JSONDecodeError):
                out.append(("problem", "slot %s: unparseable path" % slot.get("path")))
                continue
        m = LEGACY_REF_RE.match(value) if isinstance(value, str) else None
        legacy_id = slot.get("id") or (m.group(1) if m else None)
        if not legacy_id or legacy_id == "*":
            continue
        where = slot.get("where") or ("key" if parts and parts[-1] == value else "value")
        agent_id = slot.get("agent_id")
        if agent_id is None and len(parts) >= 3 and parts[0] == "agents" and parts[1] == "entries":
            agent_id = parts[2]
        label = "%s (%s)" % (slot.get("path") or fmt_path(parts), value)
        post = _post_parts(parts, agent_id)
        if post is None:
            out.append(("problem", "slot %s: agent list entry without id cannot be mapped to agents.entries" % label))
            continue
        expected, others = _expected_ids(legacy_id, retired_map)
        want = "openai/" + remap_model_id(legacy_id)
        successors = retired_chain(want, retired_map)
        if successors:
            want += " (or doctor's successor %s)" % successors[-1]
        found_id = None
        found_other = False

        def match(ref, expected=expected, others=others):
            cm = _CANONICAL_OPENAI_REF_RE.match(ref) if isinstance(ref, str) else None
            if cm and cm.group(1).lower() in expected:
                return cm.group(1)
            if isinstance(ref, str) and ref_base(ref) in others:
                return ""
            return None

        if where == "key":
            parent = _get(cfg, post[:-1], None)
            if not isinstance(parent, dict) and post != parts:
                parent = _get(cfg, parts[:-1], None)
            if isinstance(parent, dict):
                for k in parent:
                    hit = match(k)
                    if hit is not None:
                        found_id, found_other = hit or None, hit == ""
                        break
            if found_id is None and not found_other:
                out.append(("problem", "slot %s: no %s entry after the migration" % (label, want)))
                continue
        else:
            candidates = []
            in_list = bool(post) and _is_index(post[-1])
            if in_list:
                # list element (e.g. fallbacks[1]): doctor may dedupe/reorder, so check membership
                parent = _get(cfg, post[:-1], None)
                if not isinstance(parent, list) and post != parts:
                    parent = _get(cfg, parts[:-1], None)
                if isinstance(parent, list):
                    candidates = [v for v in parent if isinstance(v, str)]
            else:
                v = _get(cfg, post)
                if v is _MISSING and post != parts:
                    v = _get(cfg, parts)
                if isinstance(v, dict) and isinstance(v.get("primary"), str):
                    v = v["primary"]
                if v is not _MISSING:
                    candidates = [v]
            if not candidates:
                out.append(("problem", "slot %s: value missing after the migration (expected %s)" % (label, want)))
                continue
            current = None
            for c in candidates:
                hit = match(c)
                if hit is not None:
                    found_id, found_other = hit or None, hit == ""
                    break
                current = c
            if found_id is None and not found_other:
                legacy_left = [c for c in candidates if isinstance(c, str) and _PC1_LEGACY_RE.match(c)]
                if legacy_left:
                    out.append(("problem", "slot %s: still a legacy ref (%s)" % (label, legacy_left[0])))
                elif in_list:
                    out.append(("problem", "slot %s: %s missing from %s" % (label, want, fmt_path(post[:-1]))))
                else:
                    out.append(("problem", "slot %s: now %s, expected %s"
                                % (label, redact_value(post, current), want)))
                continue
        out.append(("found", label, found_id, [agent_id] if agent_id else [None] + all_agents))
    return out


def check_runtime_pins(cfg, legacy_slots, retired_map=None, *, skip_codex=False):
    """PC3 (pc-runtime-pin): every pre-transform legacy slot now holds openai/<remap X> -- or doctor's
    retirement successor of it (retired_map, contract addendum 2 item 9) -- and resolves to the OpenClaw
    runtime with the 9.9 precedence. Defaults-scope (and non-agent) slots are resolved for the defaults
    and for every agent. Use the summary["legacy_slots"] of premigrate_config(). skip_codex: leave
    resolutions to the Codex runtime to PC2 (check_codex_runtime reports them).
    """
    problems = []
    if not isinstance(cfg, dict):
        return ["openclaw.json top-level value is not an object"]
    seen = set()

    def add(msg):
        if msg not in seen:
            seen.add(msg)
            problems.append(msg)

    for item in _pc3_eval(cfg, legacy_slots, retired_map):
        if item[0] == "problem":
            add(item[1])
            continue
        _kind, label, found_id, scope = item
        if found_id is None:
            continue  # retired to a non-OpenAI model: no OpenAI runtime involved
        for a in scope:
            rid, src = _resolve_openai_runtime(cfg, found_id, a)
            if rid != "openclaw" and not (skip_codex and rid == "codex"):
                add("slot %s: openai/%s for %s resolves to runtime %s (%s)"
                    % (label, found_id, "agent " + a if a else "defaults", rid or "none (implicit choice)", src))
    return problems


# --- pins ---------------------------------------------------------------------------------


def _pin_condition(cfg, cond):
    """None if the condition holds, else a short reason text."""
    if cond is None:
        return None
    if cond == "memory-slot":
        slot = _get(cfg, ["plugins", "slots", "memory"], None)
        if slot is None or (isinstance(slot, str) and slot.strip() in ("", "memory-core")):
            return None
        return "plugins.slots.memory is not memory-core"
    tg = _get(cfg, ["channels", "telegram"], None)
    if cond in ("telegram-dict", "telegram-streaming", "telegram-preview"):
        if not isinstance(tg, dict):
            return "channels.telegram not configured"
        if cond == "telegram-dict":
            return None
        streaming = tg.get("streaming", _MISSING)
        if streaming is not _MISSING and not isinstance(streaming, dict):
            return "channels.telegram.streaming is a scalar"
        if cond == "telegram-preview" and isinstance(streaming, dict):
            progress = streaming.get("progress")
            if isinstance(progress, dict) and "commandText" in progress:
                return "channels.telegram.streaming.progress.commandText is set"
        return None
    if cond == "heartbeat-roster":
        if isinstance(_get(cfg, ["agents", "defaults", "heartbeat"], None), dict):
            return None
        ents = _get(cfg, ["agents", "entries"], None)
        lst = _get(cfg, ["agents", "list"], None)
        n = len(ents) if isinstance(ents, dict) else (len(lst) if isinstance(lst, list) else 0)
        if n == 1:
            return None
        return "agents.defaults.heartbeat absent and roster has %d agents" % n
    raise ValueError("unknown pin condition %r" % cond)


def apply_pins(cfg, ledgered_paths):
    """§7.9: write each pin only where its leaf key is absent; never re-apply a ledgered path.

    Returns (new_cfg, written[{path, value}], skipped[{path, reason}]) with reasons
    "ledgered", "already-set", "parent-not-dict" or "condition:<text>".
    """
    if not isinstance(cfg, dict):
        raise ValueError("openclaw.json top-level value is not an object")
    new = copy.deepcopy(cfg)
    ledgered = set(ledgered_paths or ())
    written, skipped = [], []
    for pin in PINS:
        parts = pin["path"]
        path = fmt_path(parts)
        if path in ledgered:
            skipped.append({"path": path, "reason": "ledgered"})
            continue
        why = _pin_condition(new, pin["cond"])
        if why is not None:
            skipped.append({"path": path, "reason": "condition:" + why})
            continue
        cur, blocked = new, False
        for p in parts[:-1]:
            nxt = cur.get(p, _MISSING)
            if nxt is _MISSING:
                break
            if not isinstance(nxt, dict):
                blocked = True
                break
            cur = nxt
        if blocked:
            skipped.append({"path": path, "reason": "parent-not-dict"})
            continue
        parent = _get(new, parts[:-1], None)
        if isinstance(parent, dict) and parts[-1] in parent:
            skipped.append({"path": path, "reason": "already-set"})
            continue
        parent = _ensure_dict_path(new, parts[:-1])
        parent[parts[-1]] = copy.deepcopy(pin["value"])
        written.append({"path": path, "value": copy.deepcopy(pin["value"])})
    return new, written, skipped


# --- auth order (§7.8 step 0) ---------------------------------------------------------------


def auth_order_adjust(cfg, profiles, store_order):
    """Keep the ChatGPT subscription ahead of an OpenAI API key after the openclaw pin (D13).

    profiles: `models auth list --provider openai --json` .profiles (listed order);
    store_order: `models auth order get --provider openai --json` .order (None = no store order).
    Returns (new_cfg or None if unchanged, policy Finding or None, ledger).
    Deviations: nothing is written when there is no OAuth/token profile (an API-key-only order
    would exclude a later OAuth login) or when a non-empty store order exists (it beats config).
    """
    oauth = [p["id"] for p in profiles or [] if isinstance(p, dict) and isinstance(p.get("id"), str)
             and p.get("type") in ("oauth", "token")]
    keys = [p["id"] for p in profiles or [] if isinstance(p, dict) and isinstance(p.get("id"), str)
            and p.get("type") == "api_key"]
    if not keys:
        return None, None, []
    if isinstance(store_order, list) and store_order:
        if store_order[0] in keys:
            return None, _finding(
                "pc-auth-order", "acceptable",
                "the auth store order for openai starts with API-key profile %s, so turns are billed to the API "
                "key instead of the ChatGPT subscription; change it with 'openclaw models auth order set "
                "--provider openai ...' or accept" % store_order[0], "postconditions"), []
        return None, None, []
    if not oauth or not isinstance(cfg, dict):
        return None, None, []
    if _get(cfg, ["auth", "order", "openai"]) is not _MISSING:
        return None, None, []
    new = copy.deepcopy(cfg)
    order = _ensure_dict_path(new, ["auth", "order"])
    if order is None:
        return None, _finding("pc-auth-order", "acceptable",
                              "cannot write auth.order.openai: auth or auth.order is not an object",
                              "postconditions"), []
    value = oauth + [k for k in keys if k not in oauth]
    order["openai"] = list(value)
    ledger = [{"step": "auth-order", "file": CONFIG_FILE, "path": "auth.order.openai", "before": None,
               "after": list(value)}]
    return new, None, ledger


# --- state files (§7.1 item 6.3, §7.3) --------------------------------------------------------


def _lstat(path):
    try:
        return os.lstat(path)
    except OSError:
        return None


def _read_regular_text(path, limit=64 * 1024 * 1024):
    """Text of a regular file (never follows a symlink, never opens a socket/FIFO); None otherwise."""
    st = _lstat(path)
    if st is None or not stat.S_ISREG(st.st_mode) or st.st_size > limit:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as f:
            data = f.read()
    except OSError:
        return None
    if len(data) > limit:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _query_ro_local(path, sql):
    """Read-only query that creates no file: immutable when the WAL is empty, readonly_shm otherwise."""
    wal_st = _lstat(path + "-wal")
    wal_data = wal_st is not None and wal_st.st_size > 0
    if not wal_data:
        uri = "file:%s?mode=ro&immutable=1" % _urlquote(path)
    elif _lstat(path + "-shm") is not None:
        uri = "file:%s?mode=ro&readonly_shm=1" % _urlquote(path)
    else:
        raise sqlite3.OperationalError("WAL without -shm index; a private copy would be needed")
    con = sqlite3.connect(uri, uri=True, timeout=2)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def _cell(row, idx=0):
    if isinstance(row, dict):
        vals = list(row.values())
        return vals[idx] if len(vals) > idx else None
    return row[idx]


def _verified_empty_bindings(path):
    raw = _read_regular_text(path)
    if raw is None:
        return False
    try:
        json.loads(raw)
    except ValueError:
        return False
    return any(rx.match(raw) for rx in EMPTY_BINDINGS_RES)


def _toggles_disabled_count(path):
    """(disabled entry count, parsed ok) with the 7.35 importer rule."""
    raw = _read_regular_text(path)
    if raw is None:
        return 0, False
    try:
        data = json.loads(raw)
    except ValueError:
        return 0, False
    sessions = data.get("sessions") if isinstance(data, dict) else None
    if not isinstance(sessions, dict):
        return 0, True
    n = sum(1 for k, v in sessions.items() if str(k).strip() and isinstance(v, dict) and v.get("disabled") is True)
    return n, True


def _legacy_db_rows(path, query):
    st = _lstat(path)
    if st is None or not stat.S_ISREG(st.st_mode):
        return None
    try:
        tables = [_cell(r) for r in query(path, "SELECT name FROM sqlite_master WHERE type='table' "
                                                "AND name NOT LIKE 'sqlite_%'")]
        total = 0
        for t in tables:
            ident = '"' + str(t).replace('"', '""') + '"'
            total += int(_cell(query(path, "SELECT COUNT(*) FROM " + ident)[0]))
        return total
    except Exception:  # unreadable for any reason: the caller holds (acceptable code)
        return None


def _main_auth_profile_count(state_dir, query):
    db = os.path.join(state_dir, "agents", "main", "agent", "openclaw-agent.sqlite")
    st = _lstat(db)
    if st is None or not stat.S_ISREG(st.st_mode):
        return None
    try:
        rows = query(db, "SELECT store_json FROM auth_profile_store WHERE store_key='primary'")
        if not rows:
            return 0
        data = json.loads(_cell(rows[0]))
    except Exception:
        return None
    profiles = data.get("profiles") if isinstance(data, dict) else None
    return len(profiles) if isinstance(profiles, (dict, list)) else 0


def _scandir_sorted(path):
    try:
        with os.scandir(path) as it:
            return sorted(it, key=lambda e: e.name)
    except OSError:
        return []


def classify_state_files(state_dir, cfg, *, from_checkpoint, accepted, mode, query=None):
    """Cleanup plan (§7.3) plus the from-7x state-file HOLD codes (§7.1 item 6.3).

    mode "from-7x": every kind; other modes: sqlite-transient only and no findings.
    accepted: accepted codes that switch a "leave" into "quarantine" (telegram-bindings-nonempty,
    active-memory-optouts, oauth-json-only). Findings are reported whether accepted or not.
    query(path, sql) -> rows: read-only SQLite reader (default: an immutable/readonly_shm reader that
    never creates files; oc_gate may pass oc_common.query_ro).
    custom-session-store is reported by config_precheck(), not here.
    Returns {"plan": [{rel, kind, action, reason, size}], "findings": [...], "info": [...]}.
    """
    q = query or _query_ro_local
    accepted = set(accepted or ())
    from7 = mode == "from-7x"
    cfg = cfg if isinstance(cfg, dict) else {}
    plan, info = [], []
    by_code = {}

    def add(rel, kind, action, reason):
        st = _lstat(os.path.join(state_dir, rel))
        plan.append({"rel": rel, "kind": kind, "action": action, "reason": reason,
                     "size": st.st_size if st is not None else 0})

    def flag(code, item):
        by_code.setdefault(code, []).append(item)

    agents_dir = os.path.join(state_dir, "agents")
    agent_names = [e.name for e in _scandir_sorted(agents_dir) if e.is_dir()]

    # sqlite-transient (all modes) and other SQLite files next to agent DBs (log only).
    for name in agent_names:
        adir_rel = "agents/%s/agent" % name
        for e in _scandir_sorted(os.path.join(state_dir, adir_rel)):
            rel = adir_rel + "/" + e.name
            st = _lstat(os.path.join(state_dir, rel))
            if st is None:
                continue
            if TRANSIENT_SQLITE_RE.match(e.name):
                if stat.S_ISREG(st.st_mode):
                    add(rel, "sqlite-transient", "quarantine", "transient SQLite file (9.9 backup rules)")
                else:
                    add(rel, "sqlite-other", "leave", "transient name but not a regular file")
            elif e.name in _AGENT_DB_FAMILY:
                continue
            elif ".migrated" in e.name:
                add(rel, "migrated-archive", "leave", "archive of an imported file; 9.9 ignores it")
            elif ".sqlite" in e.name.lower():
                add(rel, "sqlite-other", "leave", "other SQLite file next to the agent DB")
    if not from7:
        return {"plan": plan, "findings": [], "info": info}

    tg_dict = isinstance(cfg.get("channels"), dict) and isinstance(cfg["channels"].get("telegram"), dict)
    bindings_ok = from_checkpoint == "2026.7.35" and tg_dict

    # Telegram retired JSON state.
    spool = 0
    for e in _scandir_sorted(os.path.join(state_dir, "telegram")):
        rel = "telegram/" + e.name
        st = _lstat(os.path.join(state_dir, rel))
        if st is None:
            continue
        regular_or_link = stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)
        if TELEGRAM_CACHE_RE.match(e.name) and regular_or_link:
            if e.name.startswith("thread-bindings-"):
                if _verified_empty_bindings(os.path.join(state_dir, rel)):
                    add(rel, "telegram-cache", "leave", "verified-empty thread bindings; 9.9 archives it itself")
                elif bindings_ok or "telegram-bindings-nonempty" in accepted:
                    if not bindings_ok:
                        flag("telegram-bindings-nonempty", rel)
                    add(rel, "telegram-cache", "quarantine",
                        "thread bindings (7.35 checkpoint proved nothing importable)" if bindings_ok
                        else "thread bindings (accepted: telegram-bindings-nonempty)")
                else:
                    flag("telegram-bindings-nonempty", rel)
                    add(rel, "telegram-cache", "leave", "non-empty thread bindings without a clean 7.35 checkpoint")
            else:
                add(rel, "telegram-cache", "quarantine", "retired Telegram cache; 9.9 doctor refuses while it exists")
        elif ".migrated" in e.name:
            add(rel, "migrated-archive", "leave", "archive of an imported file; 9.9 ignores it")
        elif e.name.startswith("ingress-spool-") and stat.S_ISDIR(st.st_mode):
            for f in _scandir_sorted(os.path.join(state_dir, rel)):
                if ".json" in f.name and f.is_file(follow_symlinks=False):
                    spool += 1
    if spool:
        info.append("telegram ingress spool: %d undelivered legacy Telegram update file(s) will not be "
                    "processed by 9.9 (left in place)" % spool)

    # Telegram session caches next to every session store.
    store_dirs = ["sessions"] + ["agents/%s/sessions" % n for n in agent_names]
    for sdir in store_dirs:
        for suf in TELEGRAM_SESSION_SUFFIXES:
            rel = "%s/sessions.json.%s.json" % (sdir, suf)
            st = _lstat(os.path.join(state_dir, rel))
            if st is not None and (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                add(rel, "telegram-session-cache", "quarantine",
                    "retired Telegram session cache; 9.9 doctor refuses while it exists")
        for e in _scandir_sorted(os.path.join(state_dir, sdir)):
            if e.name.startswith("sessions.json.telegram-message-dispatch-") and e.name.endswith(".json"):
                add(sdir + "/" + e.name, "telegram-dispatch", "leave", "dispatch file; 9.9 ignores it")
            elif e.name.startswith("sessions.json.telegram-") and ".migrated" in e.name:
                add(sdir + "/" + e.name, "migrated-archive", "leave", "archive of an imported file; 9.9 ignores it")

    # Active Memory per-session toggles.
    rel = "plugins/active-memory/session-toggles.json"
    if _lstat(os.path.join(state_dir, rel)) is not None:
        n, ok = _toggles_disabled_count(os.path.join(state_dir, rel))
        if n > 0:
            flag("active-memory-optouts", "%s (%d disabled session(s))" % (rel, n))
            if "active-memory-optouts" in accepted:
                add(rel, "active-memory-toggles", "quarantine", "accepted: active-memory-optouts")
            else:
                add(rel, "active-memory-toggles", "leave", "%d per-session opt-out(s) would be lost" % n)
        else:
            add(rel, "active-memory-toggles", "quarantine",
                "no disabled entries; 9.9 doctor refuses while it exists" if ok
                else "unreadable or invalid JSON; 9.9 doctor refuses while it exists")

    # credentials/oauth.json (9.9 never reads it; startup may fence on it).
    rel = "credentials/oauth.json"
    if _lstat(os.path.join(state_dir, rel)) is not None:
        count = _main_auth_profile_count(state_dir, q)
        if count:
            add(rel, "oauth-json", "quarantine", "main agent auth store holds %d profile(s)" % count)
        else:
            flag("oauth-json-only", rel + (" (main agent auth store unreadable or missing)" if count is None
                                           else " (main agent auth store has no profiles)"))
            if "oauth-json-only" in accepted:
                add(rel, "oauth-json", "quarantine", "accepted: oauth-json-only")
            else:
                add(rel, "oauth-json", "leave", "credentials may exist only in oauth.json")

    # Pre-June legacy databases 9.9 never imports.
    for dbrel in LEGACY_DATABASES:
        path = os.path.join(state_dir, dbrel)
        if _lstat(path) is not None:
            rows = _legacy_db_rows(path, q)
            if rows is None or rows > 0:
                flag("legacy-db-unimported", "%s (%s)" % (dbrel, "unreadable" if rows is None else "%d rows" % rows))
                add(dbrel, "legacy-db", "leave", "not imported; 9.9 ignores it")
            else:
                add(dbrel, "legacy-db", "leave", "empty")
        ddir = os.path.dirname(dbrel)
        base = os.path.basename(dbrel)
        for e in _scandir_sorted(os.path.join(state_dir, ddir)):
            if e.name.startswith(base) and ".migrated" in e.name:
                add(ddir + "/" + e.name, "migrated-archive", "leave", "archive of an imported file; 9.9 ignores it")

    # Legacy memory sidecars (memory/<agentId>.sqlite).
    for e in _scandir_sorted(os.path.join(state_dir, "memory")):
        if e.name.endswith(".sqlite"):
            flag("legacy-memory-sidecar", "memory/" + e.name)
            add("memory/" + e.name, "legacy-memory-sidecar", "leave", "legacy memory sidecar")

    messages = {
        "telegram-bindings-nonempty": ("non-empty Telegram thread-bindings file(s) without a clean 2026.7.35 "
                                       "checkpoint and a configured channels.telegram: %s; accepting moves them "
                                       "to quarantine (bindings are not imported)"),
        "active-memory-optouts": ("Active Memory per-session opt-outs would be lost (9.9 cannot import them): %s; "
                                  "accepting re-enables recall for those sessions"),
        "oauth-json-only": ("credentials/oauth.json exists but the main agent auth store has no profiles: %s; "
                            "the credentials may exist only there and 9.9 never reads it"),
        "legacy-db-unimported": ("pre-June database(s) with data 9.9 never imports: %s; upgrade through 2026.9.5 "
                                 "first or accept losing these records"),
        "legacy-memory-sidecar": ("legacy memory sidecar database(s) %s; 9.9 may leave them unimported"),
    }
    findings = [_finding(code, "acceptable", messages[code] % _brief(items), "precheck")
                for code, items in by_code.items()]
    return {"plan": plan, "findings": findings, "info": info}


def scan_sessions_files(state_dir):
    """Parse sessions/sessions.json and agents/*/sessions/sessions.json (§7.1 item 6.5).

    Returns ([(rel, store_dict)], findings) -- a hard sessions-unreadable finding for any file that is
    not a regular file, not UTF-8 JSON or not a JSON object.
    """
    out, bad = [], []
    cands = ["sessions/sessions.json"]
    cands += ["agents/%s/sessions/sessions.json" % e.name
              for e in _scandir_sorted(os.path.join(state_dir, "agents")) if e.is_dir()]
    for rel in cands:
        path = os.path.join(state_dir, rel)
        st = _lstat(path)
        if st is None:
            continue
        if not stat.S_ISREG(st.st_mode):
            bad.append("%s: not a regular file" % rel)
            continue
        raw = _read_regular_text(path, limit=1 << 40)
        if raw is None:
            bad.append("%s: unreadable or not UTF-8" % rel)
            continue
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            bad.append("%s: invalid JSON (%s at line %d column %d)" % (rel, exc.msg, exc.lineno, exc.colno))
            continue
        except ValueError:
            bad.append("%s: invalid JSON" % rel)
            continue
        if not isinstance(data, dict):
            bad.append("%s: top-level value is not an object" % rel)
            continue
        out.append((rel, data))
    findings = []
    if bad:
        findings.append(_finding("sessions-unreadable", "hard",
                                 "session store(s) cannot be read safely: %s" % _brief(bad), "precheck"))
    return out, findings


def _find_key_paths(node, key, parts=None):
    parts = parts or []
    out = []
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                out.append(parts + [k])
            out.extend(_find_key_paths(v, key, parts + [k]))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out.extend(_find_key_paths(v, key, parts + [i]))
    return out


def config_precheck(cfg, raw_text):
    """Hard config findings: config-unreadable (not an object), config-includes ($include, B14),
    custom-session-store (non-empty session.store)."""
    phase = "precheck"
    if not isinstance(cfg, dict):
        return [_finding("config-unreadable", "hard",
                         "openclaw.json must be a strict JSON object (JSON5 comments are unsupported)", phase)]
    findings = []
    inc = [fmt_path(p) for p in _find_key_paths(cfg, "$include")]
    if not inc and isinstance(raw_text, str) and re.search(r'"\$include"\s*:', raw_text):
        inc = ["(raw text)"]
    if inc:
        findings.append(_finding(
            "config-includes", "hard",
            "openclaw.json uses $include (%s); the gate can only transform a single file. Inline the included "
            "files into openclaw.json on 0.5.93, then oc-upgrade retry" % _brief(inc), phase))
    store = _get(cfg, ["session", "store"], None)
    if isinstance(store, str) and store.strip():
        findings.append(_finding(
            "custom-session-store", "hard",
            "session.store points to a custom session store (%s); the gate only handles the default "
            "agents/<id>/sessions/sessions.json stores" % store.strip(), phase))
    return findings


def flatten_paths(cfg):
    """Set of leaf paths (fmt_path) -- empty dicts/lists count as leaves. Values are not returned."""
    out = set()

    def visit(node, parts):
        if isinstance(node, dict) and node:
            for k, v in node.items():
                visit(v, parts + [k])
        elif isinstance(node, list) and node:
            for i, v in enumerate(node):
                visit(v, parts + [i])
        elif parts:
            out.add(fmt_path(parts))

    visit(cfg, [])
    return out
