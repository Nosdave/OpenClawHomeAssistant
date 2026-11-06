#!/usr/bin/env python3
"""oc_migrate -- transforms and checks for the OpenClaw 2026.7.x -> 2026.9+/2026.10 migration gate.

Every function in this module is pure with respect to its arguments: inputs are
deep-copied and never mutated, nothing runs a subprocess and nothing writes a file.
Read-only filesystem access happens only in classify_state_files(),
classify_retired_state(), retired_db_findings() and scan_sessions_files() (lstat-based; symlinks
are never followed into files and sockets/FIFOs are never opened).

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
import ipaddress
import json
import os
import re
import sqlite3
import stat
from urllib.parse import quote as _urlquote, urlsplit as _urlsplit

__all__ = [
    "EXPLICIT_DEFAULT_IDS", "PINS", "TRANSIENT_SQLITE_RE", "TELEGRAM_CACHE_RE", "EMPTY_BINDINGS_RES",
    "LEGACY_REF_RE", "redact_value", "fmt_path", "parse_path", "remap_model_id", "scan_legacy_refs",
    "models_preflight", "explicit_ids", "premigrate_config", "premigrate_sessions", "fixups",
    "post_doctor_fixups", "canonical_openai_refs", "canonical_text_model_refs", "route_collisions", "ref_base",
    "retired_chain", "apply_retired",
    "legacy_key_context", "is_migrated_legacy_key",
    "check_legacy_refs", "check_codex_runtime", "check_runtime_pins", "apply_pins", "auth_order_adjust",
    "split_trailing_auth_profile", "normalize_agent_id", "cron_job_agent", "cron_model_chain", "cron_model_ref",
    "cron_ref_refusal", "cron_ref_uses_stored_profile", "cron_account_forecast", "is_secret_ref", "is_key_marker",
    "doctor_copies", "doctor_key_copies", "config_path", "parse_model_catalog_json",
    "classify_state_files", "scan_sessions_files", "config_precheck", "flatten_paths",
    "retired_config_keys", "retired_config_rewrites", "retired_config_findings", "classify_retired_state",
    "retired_db_findings", "heartbeat_hours_findings",
    "retired_tuning_dropped", "RETIRED_QUARANTINE_KINDS",
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
                    "active-memory-toggles", "oauth-json", "legacy-memory-sidecar")

# §7.9 pins (validated against the 9.9 schema: specwf/config-keys/pins_final.json; types, values and
# defaults unchanged in 10.2, and `config validate` runs after the pins on every gate run).
# The leaf is written only if absent from its parent dict; "cond" names an extra condition.
SYSTEM_AGENT = "@agents.defaults.systemAgent.agentId"  # pin value resolved at apply time

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
    # gone with the Skill Workshop proposals in OpenClaw 2026.10.10 (strict skills.workshop schema; doctor removes it)
    {"path": ["skills", "workshop", "approvalPolicy"], "value": "pending", "cond": "workshop-proposals"},
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
    # multi-agent roster without a heartbeat block: 9.9 runs the heartbeat for the system agent only,
    # but creating agents.defaults.heartbeat without agentId would enroll every agent
    # (heartbeat-config-CEn374Nf.mjs:62-69; v102 heartbeat-config--CDRLwW6.mjs:57-65), so name the system agent first
    {"path": ["agents", "defaults", "heartbeat", "agentId"], "value": SYSTEM_AGENT, "cond": "heartbeat-system-agent"},
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


def _url_origin(v):
    """scheme://host[:port] of a URL for the transform ledger (user info, path and query may carry a token)."""
    try:
        u = _urlsplit(v) if isinstance(v, str) else None
        port = u.port if u is not None else None
    except ValueError:
        return "***"
    if u is None or not u.scheme or not u.hostname:
        return "***"
    host = "[%s]" % u.hostname if ":" in u.hostname else u.hostname
    return "%s://%s%s" % (u.scheme, host, ":%d" % port if port else "")


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
            "config uses the retired 'codex'/'codex-cli' provider (%s); OpenClaw 2026.9+ cannot migrate it automatically. "
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
                "models the canonical one lacks (%s); OpenClaw 2026.9+ refuses to merge them and would strand every "
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
            "legacy refs name models that OpenClaw 2026.9+ serves only with an OpenAI API key (metered), not with the "
            "ChatGPT subscription: %s" % _brief(platform), phase))
    collisions = route_collisions(cfg)
    if collisions:
        findings.append(_finding(
            "models-route-collision", "acceptable",
            "openai-codex model(s) also used as canonical openai/ refs: %s. OpenClaw 2026.9+ has one openai/<model> route per "
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


def premigrate_config(cfg, removals=(), rewrites=()):
    """R0 (retired keys from classify_retired_state), R1 (wildcards), R2 (openclaw runtime pins),
    R3 (modelPolicy {}) -- §7.4.2. R4: nothing.

    rewrites: retired_config_rewrites() (OpenClaw 2026.10.5+ targets): R0 also sets each API id that still holds
    the retired value and deletes each listed extension-profile cdpUrl; a value changed by hand is left alone.

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
    # R0: retired keys 2026.10 refuses whose content 7.x keeps elsewhere (plugins.installs: SQLite index).
    for parts in removals:
        parent = _get(new, list(parts[:-1]))
        if isinstance(parent, dict) and parts[-1] in parent:
            ledger.append({"step": "R0", "file": CONFIG_FILE, "path": fmt_path(list(parts)),
                           "before": copy.deepcopy(parent[parts[-1]]), "after": None})
            del parent[parts[-1]]
    # R0 rewrites: what 2026.10.4 doctor did for settings 2026.10.5+ refuses (API id rename, extension cdpUrl)
    for e in rewrites:
        parts = list(e["parts"])
        parent = _get(new, parts[:-1], None)
        if not isinstance(parent, dict) or parts[-1] not in parent:
            continue
        old = parent[parts[-1]]
        if e.get("op") == "set" and old == e.get("from"):
            parent[parts[-1]] = e["value"]
            ledger.append({"step": "R0", "file": CONFIG_FILE, "path": fmt_path(parts), "before": old,
                           "after": e["value"]})
        elif e.get("op") == "delete":
            del parent[parts[-1]]
            ledger.append({"step": "R0", "file": CONFIG_FILE, "path": fmt_path(parts),
                           "before": _url_origin(old), "after": None})
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


def _pin_condition(cfg, cond, retires_skill_proposals=False):
    """None if the condition holds, else a short reason text."""
    if cond is None:
        return None
    if cond == "workshop-proposals":
        return "Skill Workshop proposals were removed in this OpenClaw version" if retires_skill_proposals else None
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
    if cond in ("heartbeat-roster", "heartbeat-system-agent"):
        has_defaults = isinstance(_get(cfg, ["agents", "defaults", "heartbeat"], None), dict)
        ents = _get(cfg, ["agents", "entries"], None)
        lst = _get(cfg, ["agents", "list"], None)
        roster = list(ents.values()) if isinstance(ents, dict) else (lst if isinstance(lst, list) else [])
        n = len(roster)
        # agents with their own heartbeat block are the only ones enrolled; defaults only fill them in
        explicit = any(isinstance(e, dict) and e.get("heartbeat") not in (None, False, 0, "") for e in roster)
        if cond == "heartbeat-roster":
            if has_defaults or n == 1 or explicit:
                return None
            return "agents.defaults.heartbeat absent and roster has %d agents" % n
        if has_defaults or n <= 1 or explicit:
            return "not needed"
        if not _system_agent_id(cfg):
            return "agents.defaults.systemAgent.agentId not set"
        return None
    raise ValueError("unknown pin condition %r" % cond)


def _system_agent_id(cfg):
    v = _get(cfg, ["agents", "defaults", "systemAgent", "agentId"], None)
    return v.strip() if isinstance(v, str) and v.strip() else None


def apply_pins(cfg, ledgered_paths, retires_skill_proposals=False):
    """§7.9: write each pin only where its leaf key is absent; never re-apply a ledgered path.

    retires_skill_proposals: the bundled OpenClaw has no Skill Workshop proposals any more (runtime_caps, 2026.10.10+),
    so skills.workshop.approvalPolicy is not written (its strict schema refuses the key).
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
        why = _pin_condition(new, pin["cond"], retires_skill_proposals)
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
        value = _system_agent_id(new) if pin["value"] == SYSTEM_AGENT else pin["value"]
        parent = _ensure_dict_path(new, parts[:-1])
        parent[parts[-1]] = copy.deepcopy(value)
        written.append({"path": path, "value": copy.deepcopy(value)})
    return new, written, skipped


# --- G1 GLM thinking levels (add-on option glm_thinking_levels, opt-in) ----------------------------
#
# With compat.thinkingFormat "qwen-chat-template" a custom provider id only ever sends
# chat_template_kwargs.enable_thinking, never a level (measured on 7.35, 9.9, 10.2 and 10.5-beta.2;
# the level variant of that format is wired to the bundled `vllm` provider id only, 10.5
# extensions/vllm/stream.ts, so `vllm` is left alone). Without thinkingFormat and with
# supportsReasoningEffort, 9.9+ sends the level as the root reasoning_effort, limited to
# supportedReasoningEfforts and remapped by reasoningEffortMap (packages/ai openai-completions-policy,
# openai-reasoning-compat; "off" becomes "none" only when "none" is in the list, so a model that already
# has its own list or map is not converted). 7.35 maps "off" to "high": the gate only runs on 2026.9+.
GLM_REASONING_EFFORTS = ["none", "low", "high", "max"]
GLM_REASONING_EFFORT_MAP = {"minimal": "low", "medium": "high", "xhigh": "max"}
# "glm" at the start of the id or after a separator: GLM-5.3-Flash, zai-org/glm-4.6 (not chatglm3)
_GLM_ID_RE = re.compile(r"(?i)(?<![a-z0-9])glm")


def glm_thinking_scan(cfg):
    """GLM models (id matches _GLM_ID_RE, reasoning true, compat.thinkingFormat "qwen-chat-template", api
    openai-completions or unset) -> {"convert": [(provider_id, model_index, model_id)],
    "skip": [(ref, reason)]}. Skipped: the bundled vllm provider id, a supportsReasoningEffort false,
    and models that already have their own supportedReasoningEfforts or reasoningEffortMap."""
    out = {"convert": [], "skip": []}
    provs = _get(cfg, ["models", "providers"], None) if isinstance(cfg, dict) else None
    if not isinstance(provs, dict):
        return out
    for pid, prov in provs.items():
        if not isinstance(prov, dict) or not isinstance(prov.get("models"), list):
            continue
        for i, m in enumerate(prov["models"]):
            if not isinstance(m, dict):
                continue
            mid, compat = m.get("id"), m.get("compat")
            # compat.thinkingFormat is an openai-completions setting, and OpenClaw runs a custom provider
            # without an api as openai-completions
            if not (isinstance(mid, str) and _GLM_ID_RE.search(mid)
                    and (m.get("api") or prov.get("api") or "openai-completions") == "openai-completions"
                    and m.get("reasoning") is True and isinstance(compat, dict)
                    and compat.get("thinkingFormat") == "qwen-chat-template"):
                continue
            ref = "%s/%s" % (pid, mid)
            if str(pid).strip().lower() == "vllm":
                out["skip"].append((ref, "provider id vllm: OpenClaw 2026.10.5+ sends its levels itself"))
            elif compat.get("supportsReasoningEffort") is False:
                out["skip"].append((ref, "compat.supportsReasoningEffort is false"))
            elif "supportedReasoningEfforts" in compat or "reasoningEffortMap" in compat:
                out["skip"].append((ref, "has its own supportedReasoningEfforts / reasoningEffortMap"))
            else:
                out["convert"].append((pid, i, mid))
    return out


def glm_thinking_levels(cfg):
    """G1: move the models glm_thinking_scan converts to the root reasoning_effort contract: remove
    compat.thinkingFormat, set supportsReasoningEffort, add GLM_REASONING_EFFORTS and
    GLM_REASONING_EFFORT_MAP, drop a static model-level params.reasoning_effort.
    Returns (new_cfg, ledger[{step, file, path, before, after}], refs)."""
    if not isinstance(cfg, dict):
        raise ValueError("openclaw.json top-level value is not an object")
    new = copy.deepcopy(cfg)
    ledger, refs = [], []
    for pid, i, mid in glm_thinking_scan(new)["convert"]:
        base = ["models", "providers", pid, "models", i, "compat"]
        compat = _get(new, base)
        changes = [("thinkingFormat", compat.pop("thinkingFormat"), None)]
        for key, value in (("supportsReasoningEffort", True), ("supportedReasoningEfforts", GLM_REASONING_EFFORTS),
                           ("reasoningEffortMap", GLM_REASONING_EFFORT_MAP)):
            if compat.get(key) != value:
                changes.append((key, compat.get(key), value))
                compat[key] = copy.deepcopy(value)
        ledger += [{"step": "G1", "file": CONFIG_FILE, "path": fmt_path(base + [k]),
                    "before": copy.deepcopy(b), "after": copy.deepcopy(a)} for k, b, a in changes]
        # a static model-level params.reasoning_effort is not sent by 7.35-10.5 (measured), but it contradicts
        # the levels and a later release could start sending it: drop it
        model = _get(new, ["models", "providers", pid, "models", i])
        params = model.get("params")
        if isinstance(params, dict):
            for key in ("reasoning_effort", "reasoningEffort"):
                if key in params:
                    ledger.append({"step": "G1", "file": CONFIG_FILE,
                                   "path": fmt_path(["models", "providers", pid, "models", i, "params", key]),
                                   "before": copy.deepcopy(params.pop(key)), "after": None})
            if not params:
                del model["params"]
        refs.append("%s/%s" % (pid, mid))
    return new, ledger, refs


def glm_thinking_preview(cfg, option_on):
    """Read-only lines for `gate --dry-run` / `oc-upgrade check`: what G1 would do (or why not)."""
    scan = glm_thinking_scan(cfg)
    lines = []
    if scan["convert"]:
        refs = ", ".join("%s/%s" % (pid, mid) for pid, _i, mid in scan["convert"])
        lines.append("GLM thinking levels (option glm_thinking_levels %s): %s %s" % (
            "on" if option_on else "off", refs,
            "would send the level as reasoning_effort at the next gate run (G1)" if option_on
            else "only switch thinking on/off"))
    lines += ["GLM thinking levels: %s left as is (%s)" % (ref, why) for ref, why in scan["skip"]]
    return lines


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


# --- cron inference accounts (openclaw/openclaw#192195; report only) ---------------------------------
# OpenClaw 2026.10.10 and 2026.11.1 (the cron/auth sources are unchanged between them) refuse a cron agent turn
# that has no recorded inference account (job_json inferenceBinding, #172590) as soon as a prepared candidate
# would run on a stored auth profile or a direct credential that is not a configured key
# (embedded-agent-runner/run/auth-plan.ts), and
# the refusal stops the fallback chain (recordModelFallbackStop). OpenClaw's own doctor migration (#172792)
# ships with 2026.11.5; it records only the account of a job's own model (inference-binding-migration.ts), so a job
# that only stops at a fallback stays refused there. The gate only forecasts which jobs are affected; it writes
# nothing. The stored logins include
# the ones OpenClaw's doctor creates during the migration from literal provider keys (doctor_key_copies; found in the
# add-on's 10.10 rehearsal): a job on such a provider is refused unless the key is a SecretRef or has auth "api-key".

_PROFILE_SUFFIX_NOT_PROFILE = (re.compile(r"[0-9]{8}(?:@|\Z)", re.A),
                               re.compile(r"(?:i?q[0-9]+(?:_[a-z0-9]+)*|[0-9]+bit)(?:@|\Z)", re.A | re.I))
# models.providers.<p>.apiKey values OpenClaw 2026.10.10 and 2026.11.1 do not take as a literal key (unchanged
# between them):
# - a SecretRef (config/types.secrets.ts parseSecretRef): an object of exactly source/provider/id, or an env template
#   "${VAR}" or "$VAR" (VAR upper case, at most 128 characters; the value trimmed). "${lower}", "${_X}",
#   "${X:-default}" or "prefix${X}" are no reference and count as a literal key;
# - a non-secret marker (agents/model-auth-markers.ts isNonSecretApiKeyMarker; trimmed, case-sensitive): "oauth:..."
#   and "secretref-env:..." prefixes, the core markers, the nonSecretAuthMarkers of the bundled plugins (equal in the
#   2026.10.10 and 2026.11.1 npm packages), the AWS SDK names, and the env-var names OpenClaw knows (its core and
#   legacy names and those of the bundled provider manifests). Any other value (also "EMPTY", "NONE",
#   "MY_LOCAL_KEY", "openai_api_key") is a literal key. A marker of a plugin that is not bundled counts as a literal
#   key here, so the forecast can only over-report it.
_ENV_REF_RE = re.compile(r"\A(?:\$\{[A-Z][A-Z0-9_]{0,127}\}|\$[A-Z][A-Z0-9_]{0,127})\Z")
_SECRET_REF_SOURCES = ("env", "file", "exec", "store")
_KNOWN_ENV_KEY_MARKERS = frozenset((
    "ANTHROPIC_ADMIN_API_KEY", "ANTHROPIC_ADMIN_KEY", "ANTHROPIC_API_KEY", "ANTHROPIC_OAUTH_TOKEN", "AZURE_API_KEY",
    "AZURE_OPENAI_API_KEY", "AZURE_SPEECH_API_KEY", "AZURE_SPEECH_KEY", "AZURE_SPEECH_REGION", "CEREBRAS_API_KEY",
    "CLAWROUTER_API_KEY", "CODEX_API_KEY", "COPILOT_GITHUB_TOKEN", "DASHSCOPE_API_KEY", "DEEPGRAM_API_KEY",
    "DEEPSEEK_API_KEY", "ELEVENLABS_API_KEY", "FAL_API_KEY", "FAL_KEY", "FIREWORKS_API_KEY", "GEMINI_API_KEY",
    "GOOGLE_API_KEY", "GOOGLE_CLOUD_API_KEY", "HF_TOKEN", "HUGGINGFACE_HUB_TOKEN", "KIE_API_KEY", "LITELLM_API_KEY",
    "LM_API_TOKEN", "MINIMAX_API_KEY", "MINIMAX_CODE_PLAN_KEY", "MINIMAX_CODING_API_KEY", "MINIMAX_OAUTH_TOKEN",
    "MODELSTUDIO_API_KEY", "NOVITA_API_KEY", "NVIDIA_API_KEY", "OLLAMA_API_KEY", "OPENAI_ADMIN_KEY", "OPENAI_API_KEY",
    "OPENCODE_API_KEY", "OPENCODE_ZEN_API_KEY", "OPENROUTER_API_KEY", "PERPLEXITY_API_KEY", "QWEN_API_KEY",
    "RUNWAYML_API_SECRET", "RUNWAY_API_KEY", "SENSEAUDIO_API_KEY", "SGLANG_API_KEY", "SPEECH_KEY", "SPEECH_REGION",
    "TOGETHER_API_KEY", "VLLM_API_KEY", "VOYAGE_API_KEY", "XAI_API_KEY", "XI_API_KEY"))
# AWS SDK markers are markers, but never a usable key: the stored profiles still come first
_AWS_SDK_KEY_MARKERS = frozenset(("AWS_BEARER_TOKEN_BEDROCK", "AWS_ACCESS_KEY_ID", "AWS_PROFILE"))
_CORE_KEY_MARKERS = frozenset(("custom-local", "codex-app-server", "gcp-vertex-credentials", "ollama-local",
                               "secretref-managed"))
_BUNDLED_KEY_MARKERS = frozenset(("openclaw:claude-cli-native-auth", "apple-fm-local", "lmstudio-local",
                                  "minimax-oauth", "ollama-local"))
_KEY_MARKERS = _KNOWN_ENV_KEY_MARKERS | _AWS_SDK_KEY_MARKERS | _CORE_KEY_MARKERS | _BUNDLED_KEY_MARKERS
# model-auth-provider-config.ts MODEL_AUTH_LOCAL_HOST_ALIASES (with model-provider-local.ts isLocalProviderBaseUrl)
_LOCAL_HOST_ALIASES = frozenset(("localhost", "0.0.0.0", "docker.orb.internal", "host.docker.internal",
                                 "host.orb.internal"))
_RFC1918 = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def is_secret_ref(value):
    """OpenClaw's parseSecretRef on an authored config value: an object of exactly source (env/file/exec/store),
    provider and id (both non-blank strings), or an env template "${VAR}" / "$VAR" (VAR upper case)."""
    if isinstance(value, dict):
        return (len(value) == 3 and value.get("source") in _SECRET_REF_SOURCES
                and isinstance(value.get("provider"), str) and bool(value["provider"].strip())
                and isinstance(value.get("id"), str) and bool(value["id"].strip()))
    return isinstance(value, str) and bool(_ENV_REF_RE.match(value.strip()))


def is_key_marker(value):
    """OpenClaw's isNonSecretApiKeyMarker (agents/model-auth-markers.ts): a placeholder, not a key."""
    t = value.strip() if isinstance(value, str) else ""
    return bool(t) and (t.startswith("oauth:") or t.startswith("secretref-env:") or t in _KEY_MARKERS)


def _local_base_url(url):
    """model-provider-local.ts isLocalProviderBaseUrl with the model-auth host aliases: localhost, 0.0.0.0, *.local,
    the Docker/OrbStack host names, a loopback or an RFC 1918 IPv4 address."""
    try:
        host = (_urlsplit(url.strip()).hostname or "") if isinstance(url, str) else ""
    except ValueError:
        return False
    if not host:
        return False
    if host in _LOCAL_HOST_ALIASES or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return ip.is_loopback or (ip.version == 4 and any(ip in n for n in _RFC1918))


_ENV_TEMPLATE_NAME_RE = re.compile(r"\A[A-Z_][A-Z0-9_]*\Z")  # env-substitution.ts ENV_VAR_NAME_PATTERN


def env_substituted(value, env):
    """OpenClaw's substituteString (config/env-substitution.ts, 2026.11.1) on one config string with the onMissing
    behaviour of a snapshot read (pure): "${NAME}" and "${NAME:-default}" (NAME upper case or "_", the default without
    "$" or "{") take the variable's value from `env`, an unset or empty one the default, without one the placeholder
    stays; "$${NAME}" is the escaped placeholder "${NAME}". Anything else stays as written. The config OpenClaw's
    doctor reads (sourceConfig) is substituted so, so its copy of a literal key holds this value."""
    if not isinstance(value, str) or "$" not in value:
        return value
    out, end, i = [], 0, value.find("$")
    while i != -1:
        escaped = value[i + 1:i + 3] == "${"
        if escaped or value[i + 1:i + 2] == "{":
            start = i + (3 if escaped else 2)
            close = value.find("}", start)
            if close != -1:
                body = value[start:close]
                name, sep, default = body.partition(":-")
                if _ENV_TEMPLATE_NAME_RE.match(name) and not (sep and ("$" in default or "{" in default)):
                    out.append(value[end:i])
                    end = close + 1
                    token = "${" + body + "}"
                    if escaped:
                        out.append(token)
                    elif (env or {}).get(name):
                        out.append(env[name])
                    else:
                        out.append(default if sep else token)
                    i = value.find("$", close + 1)
                    continue
        i = value.find("$", i + 1)
    out.append(value[end:])
    return "".join(out)


def doctor_copies(value, cfg_entry=None, store_ids=()):
    """True when OpenClaw's doctor copies this provider apiKey value into an auth store as an api_key profile (its
    plaintext model-credential step since 2026.8.1, unchanged in 2026.10.10 and 2026.11.1 and run by
    `doctor --fix` without a prompt: doctor-model-catalog-credentials.ts collectCredentials).

    value: the apiKey of a models.providers entry in openclaw.json or of an agent's model catalog; cfg_entry: the
    openclaw.json entry of the same provider (None without one); store_ids: ids of the profiles of the store the copy
    would go to. Not copied: no string or a blank one, any value when the openclaw.json entry holds a SecretRef (also
    a "${VAR}"/"$VAR" template there), a non-secret marker, a value that is the id of a stored profile. Not modelled:
    a profile of that provider that already holds the same key (the gate never reads key values); that provider has
    a stored login anyway. models.providers.<p>.auth plays no part ("api-key" does not stop the copy)."""
    if not isinstance(value, str) or not value.strip():
        return False
    if isinstance(cfg_entry, dict) and is_secret_ref(cfg_entry.get("apiKey")):
        return False
    return not is_key_marker(value) and value not in store_ids


_CATALOG_COMMENT_RE = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*')
_CATALOG_TRAILING_COMMA_RE = re.compile(r'"(?:\\.|[^"\\])*"|,(\s*[}\]])')


def parse_model_catalog_json(text):
    """OpenClaw's parseModelCatalogJson (agents/model-catalog-json.ts) for an agent's models.json: // comments
    outside strings and trailing commas are dropped, then strict JSON. Raises ValueError like JSON.parse."""
    text = _CATALOG_COMMENT_RE.sub(lambda m: m.group(0) if m.group(0)[0] == '"' else "", text)
    text = _CATALOG_TRAILING_COMMA_RE.sub(lambda m: m.group(1) if m.group(1) is not None else m.group(0), text)
    return json.loads(text, parse_constant=_reject_json_constant)


def _reject_json_constant(name):
    raise ValueError(f"not JSON: {name}")


def config_path(provider_key):
    """models.providers.<key> as OpenClaw prints and parses it (shared/dot-path.ts appendConfigPathSegment): a key
    that is no identifier in brackets, JSON-quoted."""
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$:-]*", provider_key):
        return f"models.providers.{provider_key}"
    return f"models.providers[{json.dumps(provider_key, ensure_ascii=False)}]"


def doctor_key_copies(cfg, catalogs=(), store_ids_for=None):
    """The auth profiles OpenClaw's doctor creates from plaintext provider keys (pure; port of
    maybeMigrateModelCatalogCredentials, 2026.10.10 = 2026.11.1): {"shared": [...], "agents": {agent id: [...]}},
    each {"id", "provider", "copy"}, no key value.

    copy "config": models.providers.<p>.apiKey of openclaw.json, into the shared store every agent inherits.
    copy "catalog": a provider of an agent's model catalog (models.json, generated plugin catalogs); the main agent's
    (agents/main/agent) go to the shared store, any other agent's to that agent's own store.
    catalogs: [(agent id, is the main agent dir, {provider key: apiKey value})]; store_ids_for(agent id, or None for
    the shared store) -> the ids of its stored profiles. The id is allocateProfileId's first choice,
    "<provider>:default"; one entry per provider and store (doctor stores a second key as "<provider>:models-json")."""
    cfg = cfg if isinstance(cfg, dict) else {}
    ids = store_ids_for or (lambda _aid: ())
    res = {"shared": [], "agents": {}}

    def add(dest, key, how):
        p = key.strip().lower()
        if not any(x["provider"] == p for x in dest):
            dest.append({"id": f"{p}:default", "provider": p, "copy": how})
    provs = _get(cfg, ["models", "providers"], None)
    shared_ids = set(ids(None))
    for k, entry in provs.items() if isinstance(provs, dict) else []:
        if isinstance(k, str) and k.strip() and isinstance(entry, dict) \
                and doctor_copies(entry.get("apiKey"), entry, shared_ids):
            add(res["shared"], k, "config")
    for aid, is_main, providers in catalogs or ():
        own = shared_ids if is_main else shared_ids | set(ids(aid))
        for k, value in providers.items() if isinstance(providers, dict) else []:
            if isinstance(k, str) and k.strip() and doctor_copies(value, _provider_cfg(cfg, k.strip().lower()), own):
                add(res["shared"] if is_main else res["agents"].setdefault(str(aid).lower(), []), k, "catalog")
    return res


def split_trailing_auth_profile(raw):
    """(model, profile or None) of a "provider/model@profile" ref: port of OpenClaw's splitTrailingAuthProfile
    (agents/model-ref-profile.ts, identical in 2026.10.4 and 2026.10.10). An 8-digit version or a quantization
    suffix after "@" is part of the model."""
    trimmed = raw.strip() if isinstance(raw, str) else ""
    if not trimmed:
        return "", None
    d = trimmed.find("@", trimmed.rfind("/") + 1)
    if d <= 0:
        return trimmed, None
    for suffix in _PROFILE_SUFFIX_NOT_PROFILE:
        if not suffix.match(trimmed, d + 1):
            continue
        nxt = trimmed.find("@", d + 1)
        if nxt < 0:
            return trimmed, None
        d = nxt
    model, profile = trimmed[:d].strip(), trimmed[d + 1:].strip()
    if not model or not profile:
        return trimmed, None
    return model, profile


_AGENT_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}", re.I | re.A)  # VALID_ID_RE (ASCII only, as in JS)


def normalize_agent_id(value):
    """OpenClaw's normalizeAgentId (packages/normalization-core/src/agent-id.ts, 2026.11.1): trimmed and lower-cased;
    an id that is not canonical has every run of other characters replaced by "-", leading and trailing "-" removed,
    and is cut to 64 characters; "main" when nothing is left. Cron jobs and the gateway's agent check use this form
    ("Haus Agent" -> "haus-agent")."""
    t = value.strip() if isinstance(value, str) else ""
    n = t.lower()
    if _AGENT_ID_RE.fullmatch(t):
        return n
    return re.sub(r"[^a-z0-9_-]+", "-", n).strip("-")[:64] or "main"


def _agent_cfg_entry(cfg, agent_id):
    """The agents.list / agents.entries object of `agent_id` (ids compared normalised, normalize_agent_id), or
    None."""
    agents = cfg.get("agents") if isinstance(cfg, dict) else None
    if not isinstance(agents, dict) or not isinstance(agent_id, str):
        return None
    want = normalize_agent_id(agent_id)
    for e in agents.get("list") if isinstance(agents.get("list"), list) else []:
        if isinstance(e, dict) and isinstance(e.get("id"), str) and normalize_agent_id(e["id"]) == want:
            return e
    ent = agents.get("entries")
    for k, e in ent.items() if isinstance(ent, dict) else []:
        if isinstance(k, str) and normalize_agent_id(k) == want and isinstance(e, dict):
            return e
    return None


def _model_primary(v):
    if isinstance(v, dict):
        v = v.get("primary")
    return v.strip() if isinstance(v, str) and v.strip() else None


def _agent_fallbacks_override(v):
    """OpenClaw's resolveSelectedModelFallbacksOverride (agents/agent-scope.ts): a primary of its own without
    fallbacks means none; an explicit list (also []) replaces the defaults; otherwise None (inherit)."""
    if isinstance(v, str):
        return [] if v.strip() else None
    if not isinstance(v, dict):
        return None
    if "fallbacks" not in v:
        return [] if _model_primary(v) else None
    return v["fallbacks"] if isinstance(v["fallbacks"], list) else None


def cron_job_agent(job, default_agent="main"):
    """The agent a cron job runs as (tryResolveCronJobEffectiveAgentId, cron/agent-id.ts): agentId, else the agent
    of its sessionKey ("agent:<id>:..."), else the default agent; normalised as OpenClaw does (normalize_agent_id)."""
    aid = job.get("agentId")
    if isinstance(aid, str) and aid.strip():
        return normalize_agent_id(aid)
    sk = job.get("sessionKey")
    if isinstance(sk, str):
        parts = sk.strip().split(":")
        if len(parts) >= 3 and parts[0].lower() == "agent" and parts[1].strip():
            return normalize_agent_id(parts[1])
    return normalize_agent_id(default_agent or "main")


def _subagent_model_selection(cfg, entry):
    """OpenClaw's resolveSubagentModelConfigSelectionResult (agents/agent-scope.ts): (model config, source) of the
    first of the agent's subagents.model ("subagent"), agents.defaults.subagents.model ("default-subagent") and
    the agent's model ("agent") that has a primary; None without one."""
    sub = entry.get("subagents") if entry else None
    for raw, src in ((sub.get("model") if isinstance(sub, dict) else None, "subagent"),
                     (_get(cfg, ["agents", "defaults", "subagents", "model"], None), "default-subagent"),
                     (entry.get("model") if entry else None, "agent")):
        if _model_primary(raw):
            return raw, src
    return None


def _subagent_fallbacks_override(cfg, entry):
    """OpenClaw's resolveSubagentModelFallbacksOverride (agents/agent-scope.ts): the override of the agent's
    subagents.model, else that of a selected default-subagent or agent model; None (inherit) otherwise."""
    sub = entry.get("subagents") if entry else None
    ov = _agent_fallbacks_override(sub.get("model") if isinstance(sub, dict) else None)
    if ov is not None:
        return ov
    sel = _subagent_model_selection(cfg, entry)
    return _agent_fallbacks_override(sel[0]) if sel and sel[1] in ("agent", "default-subagent") else None


def cron_model_chain(job, cfg, agent_id):
    """(primary ref or None, [fallback refs], fallbacks source) of a cron agent turn, as OpenClaw 2026.10.10 and
    2026.11.1 resolve it (cron/isolated-agent/model-selection.ts, run-fallback-policy.ts).

    Primary: payload.model, else the agent's subagents.model, else agents.defaults.subagents.model, else the
    agent's model, else the defaults' primary (cron follows the sub-agent spawn rules). Fallbacks: payload.fallbacks
    when it is a list (also []) -> "job"; for a subagents.model primary its override -> "subagent"; for an agent
    whose model is a string equal to the defaults' primary, the defaults' fallbacks when there are any ->
    "defaults"; else the agent's override -> "agent", else the defaults' -> "defaults". Not modelled: the model
    allowlist, hooks.gmail.model and a session's model override (a "session:<key>" target), an ACP agent runtime."""
    payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
    defaults = _get(cfg, ["agents", "defaults", "model"], None)
    dfbs = defaults.get("fallbacks") if isinstance(defaults, dict) else None
    dfbs = dfbs if isinstance(dfbs, list) else []
    entry = _agent_cfg_entry(cfg, agent_id)
    amodel = entry.get("model") if entry else None
    pm = payload.get("model")
    pm = pm.strip() if isinstance(pm, str) and pm.strip() else None
    sel = None if pm else _subagent_model_selection(cfg, entry)
    if pm:
        primary, msrc = pm, "payload"
    elif sel:
        primary, msrc = _model_primary(sel[0]), "agent" if sel[1] == "agent" else "subagent"
    else:
        primary, msrc = _model_primary(defaults), "default"
    fbs = None
    if isinstance(payload.get("fallbacks"), list):
        fbs, src = payload["fallbacks"], "job"
    if fbs is None and msrc == "subagent":
        fbs, src = _subagent_fallbacks_override(cfg, entry), "subagent"
    # run-prepare.ts inheritDefaultFallbacksForAgentStringModel: an agent model "provider/model" that repeats the
    # defaults' primary keeps the defaults' fallbacks (resolveSelectedModelFallbacksOverride would give none)
    if fbs is None and msrc in ("agent", "default") and dfbs and isinstance(amodel, str) \
            and _model_primary(amodel) == _model_primary(defaults):
        fbs, src = dfbs, "defaults"
    if fbs is None:
        fbs, src = _agent_fallbacks_override(amodel), "agent"
    if fbs is None:
        fbs, src = dfbs, "defaults"
    return primary, [f.strip() for f in fbs if isinstance(f, str) and f.strip()], src


def _model_alias_target(cfg, alias):
    models = _get(cfg, ["agents", "defaults", "models"], None)
    want = alias.strip().casefold()
    for ref, v in models.items() if isinstance(models, dict) else []:
        if isinstance(ref, str) and isinstance(v, dict) and isinstance(v.get("alias"), str) \
                and v["alias"].strip().casefold() == want:
            return ref
    return None


def cron_model_ref(cfg, raw):
    """(provider lower-cased, model id, explicit profile or None) of a cron candidate ref; a bare id is looked
    up as an alias of agents.defaults.models. None when it cannot be resolved."""
    model, profile = split_trailing_auth_profile(raw)
    if not model:
        return None
    prov, mid = _split_ref(model)
    if prov is None:
        target = _model_alias_target(cfg, model)
        if target is None:
            return None
        target, tprof = split_trailing_auth_profile(target)
        prov, mid = _split_ref(target)
        profile = profile or tprof
    if not prov or not mid:
        return None
    return prov, mid, profile


def _provider_cfg(cfg, provider):
    provs = _get(cfg, ["models", "providers"], None)
    for k, v in provs.items() if isinstance(provs, dict) else []:
        if isinstance(k, str) and k.strip().lower() == provider and isinstance(v, dict):
            return v
    return None


def cron_ref_refusal(cfg, provider, explicit_profile, profiles):
    """Why OpenClaw 2026.10.10 and 2026.11.1 refuse this candidate of a cron job without a recorded inference account
    (prepare-auth.ts, auth-plan.ts): "profile" when it would run on a stored auth profile, "aws-sdk" when on AWS SDK
    credentials (models.providers.<p>.auth "aws-sdk": no configured key, and no stored account that model@profile
    could record either), None when it is not refused.

    profiles: [{"id", "provider"}] the job's agent can use (its own store, the shared store, auth.profiles of
    openclaw.json, and in a precheck forecast the copies doctor_key_copies predicts). A model@profile ref names a
    stored account. models.providers.<p>.auth "aws-sdk" runs on AWS credentials, which are no configured key: refused.
    models.providers.<p>.apiKey: a SecretRef (also "${VAR}"/"$VAR") is a configured key that suppresses the profiles;
    a marker does only while usable (a known env-var name while its variable is set, which is assumed here; another
    marker only on a local base URL with api "openai-completions" or "ollama"); a value that names a stored profile
    pins it; a literal key (also an ALL_CAPS value OpenClaw does not know as a marker, such as "EMPTY") suppresses
    them only with auth "api-key", otherwise the profiles come first. A provider without stored profiles
    (configured key, environment, local or synthetic route) is not affected."""
    if explicit_profile:
        return "profile"
    pcfg = _provider_cfg(cfg, provider) or {}
    if pcfg.get("auth") == "aws-sdk":  # prepare-auth.ts: direct source with evidence "aws-sdk"
        return "aws-sdk"
    key = pcfg.get("apiKey")
    if isinstance(key, dict) or is_secret_ref(key):
        return None
    if isinstance(key, str) and key.strip():
        k = key.strip()
        if is_key_marker(k):
            if k in _KNOWN_ENV_KEY_MARKERS or (pcfg.get("api") in ("openai-completions", "ollama")
                                               and _local_base_url(pcfg.get("baseUrl"))):
                return None
        elif any(p.get("id") == k for p in profiles):
            return "profile"
        elif pcfg.get("auth") == "api-key":
            return None
    return "profile" if any(str(p.get("provider") or "").strip().lower() == provider for p in profiles) else None


def cron_ref_uses_stored_profile(cfg, provider, explicit_profile, profiles):
    """True when OpenClaw 2026.10.10 refuses this candidate of a cron job without a recorded inference account,
    on a stored auth profile or on AWS SDK credentials (cron_ref_refusal)."""
    return cron_ref_refusal(cfg, provider, explicit_profile, profiles) is not None


def cron_account_forecast(jobs, cfg, profiles_for, default_agent="main", copies_for=None, copies_pending=False,
                          configured=None):
    """Report-only forecast for openclaw/openclaw#192195 (no I/O).

    jobs: [{"id", "name", "enabled", "runtime_authority", "job"}] in store order, "job" the parsed job_json
    without its prompt (None when unparsable); profiles_for(agent_id) -> [{"id", "provider"}] (no secrets).
    copies_for(agent_id) -> the profiles OpenClaw's doctor creates from the literal provider keys that agent's runs
    see (doctor_key_copies); copies_pending: they are not in the stores yet (precheck, doctor has not run), so they
    are added to profiles_for's; otherwise they only tell which refusals a key fix lifts.
    Covers enabled agentTurn jobs with no recorded inference account (inferenceBinding), no scheduled runtime
    authority and a session target other than "main". A job is affected when its primary or any fallback would
    run on a stored auth profile or on AWS SDK credentials (cron_ref_refusal); a ref that names a profile
    ("model@profile") does, also when its bare model id is no alias (OpenClaw gives it the default provider).
    Returns {"checked": n, "bound": n, "affected": [{"id", "name", "agent", "primary", "primary_affected", "refs"}],
    "key_fix": [...]}; primary and refs ("provider/model", or the bare model id) never carry the @profile; refs are
    the affected ones in chain order. An entry with refs on AWS SDK credentials also has "aws_sdk": those refs (no
    account can be recorded for them); one with refs refused only because of doctor's pending copy has "key_copy".
    key_fix: one {"provider", "path", "auth", "where", "pending"} per provider whose refused refs (without an
    explicit @profile) run on a literal key doctor copies or copied, so that auth "api-key" or a SecretRef lifts the
    refusal: where "config" (models.providers.<p>.apiKey of openclaw.json holds the key) or "catalog" (only an agent's
    model catalog does), path "models.providers.<p>" as OpenClaw writes it, auth the configured mode or None,
    pending: the stored login is doctor's copy during this migration. No key value anywhere.
    configured: the agent ids openclaw.json configures (normalize_agent_id), or None for no check. OpenClaw cancels every run
    of a job whose agent is not configured ("cron job agent is unavailable", the gateway's isAgentAvailable), so such
    a job is not checked; it is listed in "unconfigured": [{"id", "name", "agent"}]."""
    cfg = cfg if isinstance(cfg, dict) else {}
    res = {"checked": 0, "bound": 0, "affected": [], "key_fix": [], "unconfigured": []}
    keyed = {}
    for row in jobs or []:
        job = row.get("job")
        if not row.get("enabled") or not isinstance(job, dict) or row.get("runtime_authority"):
            continue
        payload = job.get("payload") if isinstance(job.get("payload"), dict) else {}
        if payload.get("kind") != "agentTurn" or job.get("sessionTarget") == "main":
            continue
        agent = cron_job_agent(job, default_agent)
        if configured is not None and agent not in configured:
            res["unconfigured"].append({"id": row.get("id"), "name": row.get("name"), "agent": agent})
            continue
        if job.get("inferenceBinding") or job.get("authProfileBinding"):
            res["bound"] += 1
            continue
        res["checked"] += 1
        primary, fallbacks, _src = cron_model_chain(job, cfg, agent)
        profiles = list(profiles_for(agent))
        copies = list(copies_for(agent)) if copies_for else []
        refs, aws, copied, primary_affected = [], [], [], False
        for i, raw in enumerate([primary] + fallbacks):
            r = cron_model_ref(cfg, raw) if raw else None
            if r is None and raw:  # a bare id that is no alias: an explicit profile is still a stored login
                m_, prof_ = split_trailing_auth_profile(raw)
                r = (None, m_, prof_) if m_ and prof_ else None
            if r is None:
                continue
            now = cron_ref_refusal(cfg, r[0], r[2], profiles)
            why = cron_ref_refusal(cfg, r[0], r[2], profiles + copies) if copies_pending and copies else now
            if why is None:
                continue
            ref = f"{r[0]}/{r[1]}" if r[0] else r[1]
            primary_affected = primary_affected or i == 0
            # the refusal is on a literal key doctor copies (or copied): auth "api-key" or a SecretRef lifts it
            if why == "profile" and r[0] and not r[2] and cron_ref_refusal(cfg, r[0], None, copies) == "profile":
                keyed[r[0]] = keyed.get(r[0], False) or now is None
            if ref not in refs:
                refs.append(ref)
                if why == "aws-sdk":
                    aws.append(ref)
                elif now is None:
                    copied.append(ref)
        if refs:
            p = cron_model_ref(cfg, primary) if primary else None
            shown = f"{p[0]}/{p[1]}" if p else split_trailing_auth_profile(primary)[0] if primary else primary
            res["affected"].append(dict({"id": row.get("id"), "name": row.get("name"), "agent": agent,
                                         "primary": shown, "primary_affected": primary_affected, "refs": refs},
                                        **({"aws_sdk": aws} if aws else {}),
                                        **({"key_copy": copied} if copied else {})))
    provs = _get(cfg, ["models", "providers"], None)
    provs = provs if isinstance(provs, dict) else {}
    for prov in sorted(keyed):
        key = next((k for k, v in provs.items() if isinstance(k, str) and k.strip().lower() == prov
                    and isinstance(v, dict)), None)
        pcfg = _provider_cfg(cfg, prov) or {}
        auth = pcfg.get("auth") if pcfg.get("auth") in ("api-key", "aws-sdk", "oauth", "token") else None
        res["key_fix"].append({"provider": prov, "path": config_path(key.strip() if key else prov), "auth": auth,
                               "where": "config" if doctor_copies(pcfg.get("apiKey"), pcfg) else "catalog",
                               "pending": keyed[prov]})
    return res


# The automatic config fixup for openclaw/openclaw#192195 (decisions.md, addendum 2026-11-05): a literal key with
# models.providers.<p>.auth "api-key" makes OpenClaw 2026.10.10 and 2026.11.1 run <p> on the configured key, with
# evidence "provider-config", so a cron run without a recorded inference account is not refused even after doctor
# copied the key into its auth store (prepare-auth.ts providerBindingSuppressesProfiles; rehearsal logs/85).
# The value is in the provider schema of 2026.10.4, 2026.10.10 and 2026.11.1 (config/zod-schema.core.ts
# ModelProviderSchema.auth); on 2026.10.4 the configured key is what such a provider runs on anyway.
CRON_FIXUP_AUTH = "api-key"


def cron_key_autofix(cfg, key_fix, own_logins=None, done=()):
    """The providers the gate sets models.providers.<p>.auth "api-key" for before doctor pass 1 (pure): (fix, kept).

    key_fix: the "key_fix" entries of cron_account_forecast (providers whose literal key, as doctor's copy, is what a
    refused cron ref runs on). A provider is fixed when its literal key is in openclaw.json (where "config"; also
    when doctor copied it already), its models.providers entry (the first whose key matches case-insensitively, the
    one OpenClaw reads) has no "auth" key, it has no stored login of its own and this run did not set it before.
    own_logins(candidates) -> the providers (lower case) with a stored login that is not an api_key profile holding
    exactly that literal key; candidates: {provider: the literal apiKey} (values only for that comparison).
    fix: [{"provider", "entry" (the models.providers key as written), "path" ("models.providers.<entry>.auth" as
    OpenClaw writes it)}]; kept: [{"provider", "path", "why"}], why "auth" (set to another value), "catalog" (the key
    is only in a model catalog: no entry is created), "login" (auth "api-key" would set that login aside for every
    run) or "done" (set by this run already; a resume never repeats it). No key value in the result."""
    provs = _get(cfg, ["models", "providers"], None)
    provs = provs if isinstance(provs, dict) else {}
    cand, kept = [], []
    for k in key_fix or []:
        if not isinstance(k, dict) or not isinstance(k.get("provider"), str) or not k["provider"]:
            continue
        p = k["provider"]
        entry = next((x for x, v in provs.items() if isinstance(x, str) and x.strip().lower() == p
                      and isinstance(v, dict)), None)
        pcfg = provs[entry] if entry is not None else None
        path = (config_path(entry) if entry is not None else str(k.get("path") or config_path(p))) + ".auth"
        if p in done:
            why = "done"
        elif k.get("where") != "config" or pcfg is None or not doctor_copies(pcfg.get("apiKey"), pcfg):
            why = "catalog"
        elif "auth" in pcfg:
            why = "auth"
        else:
            cand.append({"provider": p, "entry": entry, "path": path})
            continue
        kept.append({"provider": p, "path": path, "why": why})
    own = set(own_logins({c["provider"]: provs[c["entry"]]["apiKey"] for c in cand})) if cand and own_logins else set()
    kept += [{"provider": c["provider"], "path": c["path"], "why": "login"} for c in cand if c["provider"] in own]
    return [c for c in cand if c["provider"] not in own], kept


def set_provider_auth(cfg, fix):
    """(new config, ledger) with models.providers.<entry>.auth = "api-key" for each cron_key_autofix entry that still
    has no auth (pure; the input is not changed). Ledger entries: step C1, path, before None (absent), after."""
    new = copy.deepcopy(cfg)
    provs = _get(new, ["models", "providers"], None)
    ledger = []
    for f in fix or []:
        entry = provs.get(f.get("entry")) if isinstance(provs, dict) else None
        if isinstance(entry, dict) and "auth" not in entry:
            entry["auth"] = CRON_FIXUP_AUTH
            ledger.append({"step": "C1", "path": fmt_path(["models", "providers", f["entry"], "auth"]),
                           "before": None, "after": CRON_FIXUP_AUTH})
    return new, ledger


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
                    add(rel, "sqlite-transient", "quarantine", "transient SQLite file (2026.9+ backup rules)")
                else:
                    add(rel, "sqlite-other", "leave", "transient name but not a regular file")
            elif e.name in _AGENT_DB_FAMILY:
                continue
            elif ".migrated" in e.name:
                add(rel, "migrated-archive", "leave", "archive of an imported file; 2026.9+ ignores it")
            elif ".sqlite" in e.name.lower():
                add(rel, "sqlite-other", "leave", "other SQLite file next to the agent DB")
    if not from7:
        return {"plan": plan, "findings": [], "info": info}

    tg_dict = isinstance(cfg.get("channels"), dict) and isinstance(cfg["channels"].get("telegram"), dict)
    bindings_ok = from_checkpoint == "2026.7.35" and tg_dict

    # Telegram retired JSON state.
    for e in _scandir_sorted(os.path.join(state_dir, "telegram")):
        rel = "telegram/" + e.name
        st = _lstat(os.path.join(state_dir, rel))
        if st is None:
            continue
        regular_or_link = stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)
        if TELEGRAM_CACHE_RE.match(e.name) and regular_or_link:
            if e.name.startswith("thread-bindings-"):
                if _verified_empty_bindings(os.path.join(state_dir, rel)):
                    add(rel, "telegram-cache", "leave", "verified-empty thread bindings; 2026.10 ignores it")
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
                add(rel, "telegram-cache", "quarantine", "retired Telegram cache (2026.9 refused it, 2026.10 ignores it)")
        elif ".migrated" in e.name:
            add(rel, "migrated-archive", "leave", "archive of an imported file; 2026.9+ ignores it")
    # telegram/ingress-spool-*: classify_retired_state() (2026.10 doctor imports the spool)

    # Telegram session caches next to every session store.
    store_dirs = ["sessions"] + ["agents/%s/sessions" % n for n in agent_names]
    for sdir in store_dirs:
        for suf in TELEGRAM_SESSION_SUFFIXES:
            rel = "%s/sessions.json.%s.json" % (sdir, suf)
            st = _lstat(os.path.join(state_dir, rel))
            if st is not None and (stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                add(rel, "telegram-session-cache", "quarantine",
                    "retired Telegram session cache (2026.9 refused it, 2026.10 ignores it)")
        for e in _scandir_sorted(os.path.join(state_dir, sdir)):
            if e.name.startswith("sessions.json.telegram-message-dispatch-") and e.name.endswith(".json"):
                add(sdir + "/" + e.name, "telegram-dispatch", "leave", "dispatch file; 2026.9+ ignores it")
            elif e.name.startswith("sessions.json.telegram-") and ".migrated" in e.name:
                add(sdir + "/" + e.name, "migrated-archive", "leave", "archive of an imported file; 2026.9+ ignores it")

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
                "no disabled entries; 2026.10 ignores the file" if ok
                else "unreadable or invalid JSON; 2026.10 ignores the file")

    # credentials/oauth.json (2026.9+ never reads it; startup may fence on it).
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

    # Pre-June legacy databases 2026.9+ never imports.
    for dbrel in LEGACY_DATABASES:
        path = os.path.join(state_dir, dbrel)
        if _lstat(path) is not None:
            rows = _legacy_db_rows(path, q)
            if rows is None or rows > 0:
                flag("legacy-db-unimported", "%s (%s)" % (dbrel, "unreadable" if rows is None else "%d rows" % rows))
                add(dbrel, "legacy-db", "leave", "not imported; 2026.9+ ignores it")
            else:
                add(dbrel, "legacy-db", "leave", "empty")
        ddir = os.path.dirname(dbrel)
        base = os.path.basename(dbrel)
        for e in _scandir_sorted(os.path.join(state_dir, ddir)):
            if e.name.startswith(base) and ".migrated" in e.name:
                add(ddir + "/" + e.name, "migrated-archive", "leave", "archive of an imported file; 2026.9+ ignores it")

    # Legacy memory sidecars (memory/<agentId>.sqlite): 2026.10 doctor imports them but refuses the
    # pre-July index format inside (memory-schema-BA04oCjG.mjs:822-841); the index is derived data.
    for e in _scandir_sorted(os.path.join(state_dir, "memory")):
        if e.name.endswith(".sqlite"):
            flag("legacy-memory-sidecar", "memory/" + e.name)
            if "legacy-memory-sidecar" in accepted:
                add("memory/" + e.name, "legacy-memory-sidecar", "quarantine", "accepted: legacy-memory-sidecar")
            else:
                add("memory/" + e.name, "legacy-memory-sidecar", "leave", "legacy memory sidecar")

    messages = {
        "telegram-bindings-nonempty": ("non-empty Telegram thread-bindings file(s) without a clean 2026.7.35 "
                                       "checkpoint and a configured channels.telegram: %s; accepting moves them "
                                       "to quarantine (bindings are not imported)"),
        "active-memory-optouts": ("Active Memory per-session opt-outs would be lost (2026.10 no longer imports them): %s; "
                                  "accepting re-enables recall for those sessions"),
        "oauth-json-only": ("credentials/oauth.json exists but the main agent auth store has no profiles: %s; "
                            "the credentials may exist only there and 2026.9+ never reads it"),
        "legacy-db-unimported": ("pre-June database(s) with data 2026.9+ never imports: %s; upgrade through 2026.9.5 "
                                 "first or accept losing these records"),
        "legacy-memory-sidecar": ("legacy memory sidecar database(s) %s: 2026.10 doctor imports them into the agent "
                                  "database and stops when it cannot (unknown schema, vector rows without sqlite-vec); "
                                  "accepting moves them to quarantine (the memory index is rebuilt from the memory "
                                  "files, which re-embeds them)"),
    }
    findings = [_finding(code, "acceptable", messages[code] % _brief(items), "precheck")
                for code, items in by_code.items()]
    return {"plan": plan, "findings": findings, "info": info}


# --- OpenClaw 2026.10: retired pre-July-2026 formats --------------------------------------------
# 2026.9.9 still imported these; 2026.10.2 doctor refuses them ("Upgrade through OpenClaw 2026.9.7" /
# "Install OpenClaw 2026.9.5") after the gate's first write, and a retry cannot help. 2026.7.35 writes
# none of them, but a long-lived install can carry leftovers from 2026.2.x-2026.6.x. The gate mirrors
# the 10.2 checks before the first write: files whose content 7.x already holds in SQLite (or that are
# disposable) go to quarantine, everything else HOLDs with an explicit code.
# v102 sources: retired-config-formats-yKg5AICE.mjs:5-125 (config keys; visitors in
# legacy-config-record-shared-C4da1YWQ.mjs:13-58), state-migrations.retired-files-Dlsbs5FH.mjs:14-26,
# state-migrations.retired-cron-files-BfwwvNnu.mjs:6-22, state-migrations.retired-delivery-files-
# BgPaIG3K.mjs:7-25 (+ state-migrations.source-path-Dt78NFQz.mjs:3-5), doctor-auth-legacy-paths-
# BtYQLXx6.mjs:96-110, installed-plugin-index-store-path-vGDuKHrq.mjs:32-40, extensions/device-pair/
# doctor-contract-api.js, memory-schema-BA04oCjG.mjs:822-841, openclaw-agent-db-schema-helpers-
# Dtb5qs6q.mjs:50-60, openclaw-state-db-fast-path-CgrBDAvP.mjs:2106-2110,
# telegram-ingress-spool-migration-BabmmEJC.mjs:12-75 (+ state-account-id-CdS1ON70.mjs).
RETIRED_FORMAT_BRIDGE = "2026.9.7"
RETIRED_QUARANTINE_KINDS = ("cron-json", "cron-json-state", "cron-run-log", "delivery-queue-json",
                            "oauth-sidecar", "plugin-install-index", "device-pair-notify",
                            "voice-call-log", "telegram-spool-invalid", "dreaming-json",
                            # OpenClaw 2026.10.5+ (oc_common.runtime_caps runtime_files_retired /
                            # sandbox_registry_retired): runtime files 2026.10.4 still imported
                            "acp-replay-ledger", "voicewake-json", "conversation-bindings-json",
                            "plugin-approvals-json", "restart-sentinel-json", "sandbox-registry")
# Retired runtime files of OpenClaw 2026.10.5+ (#165402, #164669; 2026.10.10 state-migrations.retired-runtime-
# files.ts, .restart-sentinel.ts, doctor-sandbox.ts). The proofs mirror the 2026.10.4 importers
# (state-migrations.runtime-state.ts, .acp-replay.ts, .restart-sentinel*.ts, doctor-sandbox-legacy-registry.ts).
_RESTART_SENTINEL_KIND = "legacy-restart-sentinel-json"
_RESTART_DECISIONS = ("canonical-preserved", "canonical-advanced", "legacy-update-finalized",
                      "invalid-canonical-repaired", "legacy-imported", "malformed-legacy-discarded",
                      "receipt-authoritative")
_RESTART_SENTINEL_MAX = 4 * 1024 * 1024  # MAX_LEGACY_RESTART_SENTINEL_BYTES
_VOICEWAKE_DEFAULT_TRIGGERS = ["openclaw", "claude", "computer"]
_CODEX_RESPONSES_API = "openai-codex-responses"  # renamed by 2026.10.4 doctor, refused from 2026.10.5
_CHATGPT_RESPONSES_API = "openai-chatgpt-responses"
# JavaScript String.prototype.trim(): WhiteSpace and LineTerminator (incl. U+FEFF)
_JS_WS = ("\t\n\v\f\r              "
          "    　﻿")
# Memory Core dreaming JSON in <workspace>/memory/.dreams/ (label, file, plugin-state namespaces, meta key):
# 2026.10 doctor stops on a file unless memory-core plugin state already holds that workspace's rows
# (extensions/memory-core/doctor-contract-api.js:159-226; 7.35 uses the same keys, dreaming-state-DLMGVRgZ.js).
_DREAMING_SOURCES = (
    ("daily ingestion", "daily-ingestion.json", ("dreaming-daily-ingestion",), None),
    ("session ingestion", "session-ingestion.json",
     ("dreaming-session-ingestion-files", "dreaming-session-ingestion-seen"), None),
    ("short-term recall", "short-term-recall.json", ("short-term-recall",), "recall"),
    ("phase signals", "phase-signals.json", ("short-term-phase-signals",), "phase"),
)
_OAUTH_SIDECAR_RE = re.compile(r"\A[a-f0-9]{32}\.json\Z")
_DOCTOR_CLAIM_SUFFIX_RE = re.compile(
    r"\.doctor-importing(?:-\d+-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?\Z")
_TELEGRAM_SPOOL_FILE_RE = re.compile(r"\A(\d{16})\.json(?:\.(processing|failed))?\Z")
_TELEGRAM_ACCOUNT_BAD_RE = re.compile(r"[^a-z0-9._-]+", re.I)
_RETIRED_QUEUE_MODES = ("queue", "steer-backlog", "steer+backlog")
_BLOCKED_IDS = ("__proto__", "prototype", "constructor")
# Memory tuning and other keys 2026.9+ doctor deletes without a message (v102 legacy-87xJ1JJq.mjs:2380-2475
# RETIRED_MEMORY_SEARCH_PATHS / RETIRED_TUNING_PATHS; 9.9 has the same memory list). Values are fixed now.
RETIRED_MEMORY_TUNING = (
    ("chunking",), ("sync", "watchDebounceMs"), ("sync", "intervalMinutes"),
    ("query", "hybrid", "vectorWeight"), ("query", "hybrid", "textWeight"),
    ("query", "hybrid", "candidateMultiplier"), ("query", "hybrid", "mmr", "lambda"),
    ("query", "hybrid", "temporalDecay", "halfLifeDays"), ("cache", "maxEntries"),
)


def _rec(v):
    return isinstance(v, dict)


def _cap(caps, name):
    """True when the bundled OpenClaw has capability `name` (oc_common.runtime_caps; None: 2026.10.4)."""
    return bool(isinstance(caps, dict) and caps.get(name))


def _js_trim(s):
    return s.strip(_JS_WS)


def _visit_agent_scopes(cfg, visitor):
    """visitAgentConfigScopes: agents.defaults, then agents.entries.<id> (or agents.list[i] without entries)."""
    agents = cfg.get("agents") if _rec(cfg.get("agents")) else None
    if agents is None:
        return
    if _rec(agents.get("defaults")):
        visitor(agents["defaults"], "agents.defaults")
    if _rec(agents.get("entries")):
        for aid, entry in agents["entries"].items():
            if aid not in _BLOCKED_IDS and _rec(entry):
                visitor(entry, "agents.entries.%s" % aid)
        return
    if isinstance(agents.get("list"), list):
        for i, entry in enumerate(agents["list"]):
            if _rec(entry) and not (isinstance(entry.get("id"), str) and entry["id"] in _BLOCKED_IDS):
                visitor(entry, "agents.list[%d]" % i)


def _visit_channel(cfg, channel_id, visitor):
    """visitChannelEntries: channels.<id> and every record under channels.<id>.accounts."""
    ch = cfg.get("channels") if _rec(cfg.get("channels")) else None
    ch = ch.get(channel_id) if ch is not None else None
    if not _rec(ch):
        return
    visitor(ch, "channels.%s" % channel_id)
    if _rec(ch.get("accounts")):
        for acc_id, acc in ch["accounts"].items():
            if _rec(acc):
                visitor(acc, "channels.%s.accounts.%s" % (channel_id, acc_id))


def retired_config_keys(cfg, caps=None):
    """Port of 10.2 findRetiredConfigUpgradeRequirement: ([paths], bridge version).

    caps: oc_common.runtime_caps of the bundled OpenClaw (None: 2026.10.4). empty_installs_tolerated (2026.10.6+):
    an empty plugins.installs object is not refused (doctor removes it); config_api_cdpurl_retired (2026.10.5+):
    the "openai-codex-responses" API ids and the extension driver's cdpUrl are refused too (10.10
    retired-config-formats.ts:34-70)."""
    if not _rec(cfg):
        return [], "2026.9.5"
    out = []

    def check(scope, path, keys):
        if _rec(scope):
            out.extend(("%s.%s" % (path, k) if path else k) for k in keys if k in scope)

    def sub(obj, *keys):
        for k in keys:
            if not _rec(obj):
                return None
            obj = obj.get(k)
        return obj

    def memory_store(scope, prefix):
        check(sub(scope, "memorySearch", "store"), prefix + "memorySearch.store", ["path"])
        check(sub(scope, "memory", "search", "store"), prefix + "memory.search.store", ["path"])

    check(cfg, "", ["heartbeat"])
    check(cfg.get("routing"), "routing", ["allowFrom", "groupChat"])
    installs = sub(cfg, "plugins", "installs")
    if not (_cap(caps, "empty_installs_tolerated") and installs == {}):
        check(cfg.get("plugins"), "plugins", ["installs"])
    if _cap(caps, "config_api_cdpurl_retired"):
        out.extend(fmt_path(e["parts"]) for e in _retired_api_cdpurl(cfg))
    check(cfg.get("browser"), "browser", ["relayBindHost"])
    check(sub(cfg, "browser", "ssrfPolicy"), "browser.ssrfPolicy", ["allowPrivateNetwork"])
    memory_store(cfg, "")

    def agent(scope, p):
        check(scope, p, ["systemPromptOverride", "silentReplyRewrite", "embeddedPi", "embeddedHarness", "agentRuntime"])
        check(scope.get("sandbox"), p + ".sandbox", ["perSession"])
        check(scope.get("silentReply"), p + ".silentReply", ["direct"])
        check(scope.get("model"), p + ".model", ["timeoutMs"])
        check(sub(scope, "subagents", "model"), p + ".subagents.model", ["timeoutMs"])
        memory_store(scope, p + ".")

    _visit_agent_scopes(cfg, agent)
    if _rec(cfg.get("surfaces")):
        for sid, surface in cfg["surfaces"].items():
            check(surface, "surfaces.%s" % sid, ["silentReplyRewrite"])
            check(sub(surface, "silentReply"), "surfaces.%s.silentReply" % sid, ["direct"])
    queue = sub(cfg, "messages", "queue")
    if _rec(queue):
        if isinstance(queue.get("mode"), str) and queue["mode"] in _RETIRED_QUEUE_MODES:
            out.append("messages.queue.mode")
        if _rec(queue.get("byChannel")):
            out.extend("messages.queue.byChannel.%s" % c for c, m in queue["byChannel"].items()
                       if isinstance(m, str) and m in _RETIRED_QUEUE_MODES)
    check(cfg.get("talk"), "talk", ["mode", "transport", "brain", "model", "voice"])
    check(cfg.get("gateway"), "gateway", ["webchat"])
    check(cfg.get("channels"), "channels", ["webchat"])
    check(sub(cfg, "channels", "telegram"), "channels.telegram", ["requireMention", "groupMentionsOnly"])
    _visit_channel(cfg, "whatsapp", lambda s, p: check(s, p, ["exposeErrorText"]))
    before_discord = len(out)

    def discord(s, p):
        check(sub(s, "voice", "tts"), p + ".voice.tts", ["openai", "elevenlabs", "microsoft", "edge"])
        for gid, guild in (s["guilds"].items() if _rec(s.get("guilds")) else ()):
            for cid, chan in (guild["channels"].items() if _rec(guild) and _rec(guild.get("channels")) else ()):
                check(chan, "%s.guilds.%s.channels.%s" % (p, gid, cid), ["allow", "agentId"])

    _visit_channel(cfg, "discord", discord)
    bridge = "2026.9.7" if len(out) > before_discord else "2026.9.5"

    def telegram(s, p):
        check(s, p, ["streamMode", "chunkMode", "blockStreaming", "blockStreamingCoalesce", "draftChunk"])
        if _rec(s.get("dm")):
            out.append(p + ".dm")
        if isinstance(s.get("streaming"), (bool, str)):
            out.append(p + ".streaming")
        check(sub(s, "streaming", "preview"), p + ".streaming.preview",
              ["nativeToolProgress", "nativeToolProgressAllowFrom"])
        for chat, direct in (s["direct"].items() if _rec(s.get("direct")) else ()):
            check(direct, "%s.direct.%s" % (p, chat), ["threadReplies"])

    _visit_channel(cfg, "telegram", telegram)
    _visit_channel(cfg, "nextcloud-talk", lambda s, p: check(s, p, ["allowPrivateNetwork"]))

    def matrix(s, p):
        check(s, p, ["allowPrivateNetwork"])
        if _rec(s.get("dm")) and s["dm"].get("policy") == "trusted":
            out.append(p + ".dm.policy")
        for section in ("groups", "rooms"):
            for rid, room in (s[section].items() if _rec(s.get(section)) else ()):
                check(room, "%s.%s.%s" % (p, section, rid), ["allow"])

    _visit_channel(cfg, "matrix", matrix)
    _visit_channel(cfg, "slack", lambda s, p: [check(c, "%s.channels.%s" % (p, cid), ["allow"])
                                               for cid, c in (s["channels"].items() if _rec(s.get("channels")) else ())])
    for cid in ("discord", "line", "matrix", "telegram"):
        _visit_channel(cfg, cid, lambda s, p: check(s.get("threadBindings"), p + ".threadBindings", ["ttlHours"]))
    _visit_channel(cfg, "feishu", lambda s, p: check(s, p, ["botName"]) if p != "channels.feishu" else None)
    check(cfg.get("session"), "session", ["parentForkMaxTokens"])
    check(sub(cfg, "session", "threadBindings"), "session.threadBindings", ["ttlHours"])
    check(sub(cfg, "agents", "defaults"), "agents.defaults", ["llm"])
    return out, bridge


def _retired_api_cdpurl(cfg):
    """The 2026.10.5+ refusals 2026.10.4 doctor still fixed itself, as rewrite entries (see retired_config_rewrites):
    models.providers.<id>.api / .models[i].api exactly "openai-codex-responses", and a non-blank string cdpUrl on a
    browser profile whose driver trims to "extension" (10.10 retired-config-formats.ts:38-70)."""
    out = []
    providers = _get(cfg, ["models", "providers"], None)
    for pid, prov in (providers.items() if _rec(providers) else ()):
        if not _rec(prov):
            continue
        if prov.get("api") == _CODEX_RESPONSES_API:
            out.append({"parts": ["models", "providers", pid, "api"], "op": "set", "from": _CODEX_RESPONSES_API,
                        "value": _CHATGPT_RESPONSES_API})
        for i, model in enumerate(prov["models"] if isinstance(prov.get("models"), list) else ()):
            if _rec(model) and model.get("api") == _CODEX_RESPONSES_API:
                out.append({"parts": ["models", "providers", pid, "models", i, "api"], "op": "set",
                            "from": _CODEX_RESPONSES_API, "value": _CHATGPT_RESPONSES_API})
    profiles = _get(cfg, ["browser", "profiles"], None)
    for name, prof in (profiles.items() if _rec(profiles) else ()):
        if _rec(prof) and isinstance(prof.get("driver"), str) and _js_trim(prof["driver"]) == "extension" \
                and isinstance(prof.get("cdpUrl"), str) and _js_trim(prof["cdpUrl"]):
            out.append({"parts": ["browser", "profiles", name, "cdpUrl"], "op": "delete"})
    return out


def retired_config_rewrites(cfg, caps=None):
    """Config fixes for the settings OpenClaw 2026.10.5+ refuses but 2026.10.4 doctor still migrated itself (pure).

    [] unless caps has config_api_cdpurl_retired. Entries: {"parts", "op": "set", "from", "value"} (the API id
    becomes "openai-chatgpt-responses") or {"parts", "op": "delete"} (the extension profile's cdpUrl), exactly
    what 2026.10.4 doctor did (legacy-config-migrations.runtime.models.codex.ts:56-92, legacy-config-core-
    normalizers.ts:35-70). The from-7x pre-migrate step applies them (premigrate_config rewrites=)."""
    if not _cap(caps, "config_api_cdpurl_retired") or not _rec(cfg):
        return []
    return _retired_api_cdpurl(cfg)


def _sql_str(s):
    return "'" + str(s).replace("'", "''") + "'"


def _table_cols(query, db, table):
    try:
        return {str(_cell(r, 1)) for r in query(db, "PRAGMA table_info(%s)" % _sql_str(table))}
    except Exception:  # unreadable: treated as "no such table"
        return set()


def _json_file(path, limit=64 * 1024 * 1024):
    raw = _read_regular_text(path, limit)
    if raw is None:
        return _MISSING
    try:
        return json.loads(raw)
    except ValueError:
        return _MISSING


def _installed_plugin_index_ids(state_dir, query):
    db = os.path.join(state_dir, "state", "openclaw.sqlite")
    if _lstat(db) is None:
        return set()
    try:
        rows = query(db, "SELECT install_records_json FROM installed_plugin_index "
                         "WHERE index_key='installed-plugin-index'")
        data = json.loads(_cell(rows[0])) if rows else {}
    except Exception:  # missing table or unreadable: nothing indexed
        return set()
    return set(data) if isinstance(data, dict) else set()


def _legacy_plugin_index_ids(doc):
    """ids of a retired plugins/installs.json (7.35 readLegacyInstalledPluginIndex, state-migrations-D4BL2s8k.js:
    665-704: installRecords ?? records, else plugins[] with a pluginId and an object installRecord); None when
    7.35 could not read it either."""
    if not _rec(doc):
        return None
    recs = doc.get("installRecords")
    if recs is None:
        recs = doc.get("records")
    if recs is not None:
        return set(recs) if _rec(recs) else None
    if isinstance(doc.get("plugins"), list):
        ids = {p["pluginId"] for p in doc["plugins"] if _rec(p) and isinstance(p.get("pluginId"), str)
               and p["pluginId"].strip() and _rec(p.get("installRecord"))}
        return ids or None
    return None


def _auth_store_blobs(state_dir, query, cfg=None, home="/config"):
    """Text of every auth store an OAuth sidecar could be referenced from, or True when one cannot be read
    (the caller then treats every sidecar as referenced: never quarantine a credential silently)."""
    blobs = []
    sdb = os.path.join(state_dir, "state", "openclaw.sqlite")
    dirs = [os.path.join(state_dir, "agents", e.name, "agent")
            for e in _scandir_sorted(os.path.join(state_dir, "agents"))]
    if _lstat(sdb) is not None:
        try:
            for r in query(sdb, "SELECT path FROM agent_databases"):
                p = str(_cell(r))
                dirs.append(os.path.dirname(p if os.path.isabs(p) else os.path.join(state_dir, p)))
        except Exception as exc:  # noqa: BLE001 - no registry on a fresh state
            if "no such table" not in str(exc):
                return True
    agents = cfg.get("agents") if _rec(cfg) and _rec(cfg.get("agents")) else {}
    entries = list(agents["list"]) if isinstance(agents.get("list"), list) else []
    entries += list(agents["entries"].values()) if _rec(agents.get("entries")) else []
    for e in entries:
        if _rec(e) and isinstance(e.get("agentDir"), str) and e["agentDir"].strip():
            dirs.append(_expand_home(e["agentDir"], home))
    seen = set()
    for adir in dirs:
        adir = os.path.abspath(adir)
        if adir in seen:
            continue
        seen.add(adir)
        for f in _scandir_sorted(adir):
            if f.name.endswith(".json"):
                t = _read_regular_text(os.path.join(adir, f.name))
                if t:
                    blobs.append(t)
        db = os.path.join(adir, "openclaw-agent.sqlite")
        if _lstat(db) is not None:
            try:
                blobs += [str(_cell(r)) for r in query(db, "SELECT store_json FROM auth_profile_store")]
            except Exception as exc:  # noqa: BLE001
                if "no such table" not in str(exc):
                    return True
    if _lstat(sdb) is not None:
        try:
            blobs += [str(_cell(r)) for r in query(sdb, "SELECT store_json FROM auth_profile_stores")]
        except Exception as exc:  # noqa: BLE001 - table absent on 7.x
            if "no such table" not in str(exc):
                return True
    return "\n".join(blobs)


def _within(state_dir, path):
    rel = os.path.relpath(os.path.abspath(path), os.path.abspath(state_dir))
    return None if rel == ".." or rel.startswith(".." + os.sep) else rel.replace(os.sep, "/")


def _expand_home(p, home):
    p = p.strip()
    if p == "~" or p.startswith("~/"):
        p = home + p[1:]
    return os.path.abspath(p)


def _memory_core_workspace_rows(state_db, query, workspace):
    """{namespace: [value dicts]} of memory-core plugin-state rows for one workspace (read-only)."""
    import hashlib
    wk = hashlib.sha256(os.path.abspath(workspace).encode("utf-8")).hexdigest()
    names = {"legacy-dreaming-source-acknowledgements", "short-term-meta"}
    for src in _DREAMING_SOURCES:
        names.update(src[2])
    out = {}
    if _lstat(state_db) is None:
        return out
    try:
        rows = query(state_db, "SELECT namespace, value_json FROM plugin_state_entries WHERE plugin_id='memory-core' "
                               "AND namespace IN (%s) AND entry_key LIKE %s"
                     % (", ".join(_sql_str(n) for n in sorted(names)), _sql_str(wk + ":%")))
    except Exception:  # noqa: BLE001 - no plugin state table: nothing migrated
        return out
    for r in rows:
        try:
            v = json.loads(_cell(r, 1))
        except (TypeError, ValueError):
            continue
        if _rec(v) and v.get("workspaceKey") == wk:
            out.setdefault(str(_cell(r, 0)), []).append(v)
    return out


def _spool_entry_problem(path, file_id, failed):
    """Mirror of 10.2 parseSource for one 7.x Telegram spool file; None when 10.2 imports it."""
    raw = _read_regular_text(path)
    if raw is None:
        return "unreadable or not a regular UTF-8 file"
    try:
        v = json.loads(raw)
    except ValueError:
        return "invalid JSON"
    ok_int = lambda x: isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 2 ** 53 - 1  # noqa: E731
    if not _rec(v) or v.get("version") != 1 or not ok_int(v.get("updateId")) \
            or str(v["updateId"]).rjust(16, "0") != file_id or not ok_int(v.get("receivedAt")):
        return "invalid version, update ID, or receipt timestamp"
    if failed:
        f = v.get("failure")
        if not _rec(f) or not isinstance(f.get("reason"), str) or not f["reason"] \
                or not isinstance(f.get("message"), str) or not ok_int(f.get("failedAt")):
            return "invalid failure tombstone"
        return None
    if not _rec(v.get("update")) or v["update"].get("update_id") != v["updateId"]:
        return "update payload does not match its spool ID"
    return None


# --- retired runtime files of OpenClaw 2026.10.5+: proof that 2026.10.4 already imported them -------------------
# Each proof returns (status, detail): "imported" (the content is in SQLite), "empty" (2026.10.4 would import
# nothing) or "unproven". Read-only; a symlink is never followed and any query error means "unproven".
_IMPORTED, _EMPTY, _UNPROVEN = "imported", "empty", "unproven"
_NOTHING = "nothing to import"


def _lstat_checked(path):
    """(stat, None) when `path` exists (a broken link too), (None, None) when it does not, (None, error text) when
    it cannot be inspected: 2026.10.10 refuses then ("Cannot inspect potentially retired state")."""
    try:
        return os.lstat(path), None
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, exc.strerror or type(exc).__name__


def _read_regular_bytes(path, limit):
    """Bytes of a regular file of at most `limit` bytes (O_NOFOLLOW, never a socket/FIFO); None otherwise."""
    st = _lstat(path)
    if st is None or not stat.S_ISREG(st.st_mode) or st.st_size > limit:
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        with os.fdopen(fd, "rb") as f:
            data = f.read(limit + 1)
    except OSError:
        return None
    return data if len(data) <= limit else None


def _sha256_hex(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _json_strict(data):
    """JSON.parse of UTF-8 bytes (NaN/Infinity rejected like JavaScript); _MISSING when it does not parse."""
    def no_const(name):
        raise ValueError(name)
    try:
        return json.loads(data.decode("utf-8"), parse_constant=no_const)
    except (UnicodeDecodeError, ValueError, RecursionError):
        return _MISSING


def _js_num(v):
    import math
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def _js_int(v, minimum=None):
    return _js_num(v) and float(v).is_integer() and (minimum is None or v >= minimum)


def _same_json(a, b):
    """node:util isDeepStrictEqual for JSON values (true is not 1, key order does not matter)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _js_num(a) or _js_num(b):
        return _js_num(a) and _js_num(b) and a == b
    if isinstance(a, dict):
        return isinstance(b, dict) and a.keys() == b.keys() and all(_same_json(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return isinstance(b, list) and len(a) == len(b) and all(_same_json(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def _opt_str(v):
    """normalizeOptionalString: a trimmed non-blank string, else None."""
    if not isinstance(v, str):
        return None
    v = _js_trim(v)
    return v or None


def _archive_twin(path, sha, limit):
    """Name of an identical `.migrated` copy 2026.10.4 left after importing `path` (it archives only after the SQLite
    commit, and deletes a source whose twin is identical): .migrated, .migrated.2, ... until one is absent
    (state-migrations.storage.ts:18-33)."""
    for i in range(1, 1000):
        twin = path + ".migrated" if i == 1 else "%s.migrated.%d" % (path, i)
        if not os.path.exists(twin):
            return None
        data = _read_regular_bytes(twin, limit)
        if data is not None and _sha256_hex(data) == sha:
            return os.path.basename(twin)
    return None


def _openclaw_home(env, home):
    """resolveRequiredHomeDir: OPENCLAW_HOME (a leading ~ is the OS home), else HOME/USERPROFILE, else `home`;
    path.resolve semantics (absolute, normalized, symlinks not resolved)."""
    def norm(v):
        v = _js_trim(v) if isinstance(v, str) else ""
        return v if v and v not in ("undefined", "null") else None
    os_home = norm(env.get("HOME")) or norm(env.get("USERPROFILE")) or home
    explicit = norm(env.get("OPENCLAW_HOME"))
    if explicit and (explicit == "~" or explicit.startswith("~/")):
        return os.path.abspath(os_home + explicit[1:])
    return os.path.abspath(explicit or os_home)


def _rows(q, db, sql):
    """Rows of a read-only query, or None when it fails (no such table/column, unreadable database)."""
    if _lstat(db) is None:
        return None
    try:
        return list(q(db, sql))
    except Exception:  # noqa: BLE001 - every failure leaves the file unproven
        return None


def _in_list(values):
    return ", ".join(_sql_str(v) for v in values)


def _acp_ledger_sessions(doc):
    """The sessions of a version-1 ACP replay ledger by the 2026.10.4 parse rules (acp-replay.ts:40-146), or a
    reason why 2026.10.4 could not import it."""
    if not _rec(doc) or isinstance(doc.get("version"), bool) or doc.get("version") != 1 \
            or not _rec(doc.get("sessions")):
        return "not a version 1 ledger"
    out = []
    for sid, s in doc["sessions"].items():
        if not _rec(s) or s.get("sessionId") != sid or not isinstance(s.get("sessionKey"), str) \
                or not isinstance(s.get("cwd"), str) or not isinstance(s.get("complete"), bool) \
                or not _js_num(s.get("createdAt")) or not _js_num(s.get("updatedAt")) \
                or not _js_int(s.get("nextSeq"), 1) or not isinstance(s.get("events"), list):
            return "invalid session"
        events = []
        for ev in s["events"]:
            if not _rec(ev) or not _js_int(ev.get("seq"), 1) or not _js_num(ev.get("at")) \
                    or ev.get("sessionId") != sid or not isinstance(ev.get("sessionKey"), str) \
                    or not _rec(ev.get("update")) or not isinstance(ev["update"].get("sessionUpdate"), str):
                return "invalid event"
            if "runId" in ev and not (isinstance(ev["runId"], str) and ev["runId"]):
                return "invalid run id"
            events.append(ev)
        seqs = [ev["seq"] for ev in events]
        if len(set(seqs)) != len(seqs) or s["nextSeq"] <= max(seqs or [0]):
            return "invalid sequencing"
        out.append((sid, s, sorted(events, key=lambda e: e["seq"])))
    return out


def _acp_ledger_proof(path, state_db, q):
    data = _read_regular_bytes(path, 64 * 1024 * 1024)
    if data is None:
        return _UNPROVEN, "not a regular file"
    doc = _json_strict(data)
    if doc is _MISSING:
        return _UNPROVEN, "invalid JSON"
    sessions = _acp_ledger_sessions(doc)
    if isinstance(sessions, str):
        return _UNPROVEN, sessions
    if not sessions:
        return _EMPTY, _NOTHING
    by_id, evs = {}, {}
    ids = [sid for sid, _s, _e in sessions]
    for i in range(0, len(ids), 500):
        chunk = _in_list(ids[i:i + 500])
        srows = _rows(q, state_db, "SELECT session_id, session_key, cwd, complete, created_at, updated_at, next_seq "
                                   "FROM acp_replay_sessions WHERE session_id IN (%s)" % chunk)
        erows = _rows(q, state_db, "SELECT session_id, seq, at, session_key, run_id, update_json FROM "
                                   "acp_replay_events WHERE session_id IN (%s) ORDER BY session_id, seq" % chunk)
        if srows is None or erows is None:
            return _UNPROVEN, "acp_replay_* tables not readable"
        for r in srows:
            by_id[_cell(r, 0)] = [_cell(r, k) for k in range(1, 7)]
        for r in erows:
            evs.setdefault(_cell(r, 0), []).append([_cell(r, k) for k in range(1, 6)])
    def same_event(ev, stored):
        seq, at, skey, run_id, upd = stored
        upd = _json_strict(upd.encode("utf-8")) if isinstance(upd, str) else _MISSING
        return _same_json(seq, ev["seq"]) and _same_json(at, ev["at"]) and skey == ev["sessionKey"] \
            and run_id == ev.get("runId") and _same_json(upd, ev["update"])

    missing, n_events = 0, 0
    for sid, s, events in sessions:  # reconcileCanonicalSession (acp-replay.ts:158-216)
        n_events += len(events)
        row, stored = by_id.get(sid), evs.get(sid, [])
        ok = row is not None and row[0] == s["sessionKey"] and row[1] == s["cwd"] \
            and _same_json(row[2], 1 if s["complete"] else 0) and _same_json(row[3], s["createdAt"]) \
            and _same_json(row[4], s["updatedAt"]) and _same_json(row[5], s["nextSeq"]) \
            and len(stored) == len(events) and all(same_event(e, r) for e, r in zip(events, stored))
        missing += not ok
    if missing:
        return _UNPROVEN, "%d of %d session(s) not in SQLite" % (missing, len(sessions))
    return _IMPORTED, "%d session(s), %d event(s) in acp_replay_*" % (len(sessions), n_events)


def _voicewake_proof(path, key, state_db, q):
    data = _read_regular_bytes(path, 64 * 1024 * 1024)
    if data is None:
        return _UNPROVEN, "not a regular file"
    twin = _archive_twin(path, _sha256_hex(data), 64 * 1024 * 1024)
    if twin:
        return _IMPORTED, "identical archived copy " + twin
    doc = _json_strict(data)
    if doc is _MISSING:
        return _UNPROVEN, "invalid JSON"
    rows = _rows(q, state_db, "SELECT value_json FROM config_machine_state WHERE state_key=%s" % _sql_str(key))
    if rows is None:
        return _UNPROVEN, "config_machine_state not readable"
    stored = _json_strict(str(_cell(rows[0])).encode("utf-8")) if rows else _MISSING
    if key == "voicewake.triggers":
        # normalizeLegacyVoiceWakeTriggers: trimmed non-blank strings, else the defaults
        raw = doc.get("triggers") if _rec(doc) else None
        triggers = [_opt_str(t) for t in raw if _opt_str(t)] if isinstance(raw, list) else []
        triggers = triggers or list(_VOICEWAKE_DEFAULT_TRIGGERS)
        if stored is not _MISSING and _same_json(stored, triggers):
            return _IMPORTED, "%s in SQLite" % key
        if stored is _MISSING and triggers == _VOICEWAKE_DEFAULT_TRIGGERS:
            return _EMPTY, _NOTHING + " (the default trigger words)"
        return _UNPROVEN, "SQLite holds other trigger words" if stored is not _MISSING else "not in SQLite"
    # voicewake.routing: compared with the raw file (stricter than 2026.10.4's normalized compare)
    if _rec(stored) and _rec(doc) and _same_json(stored.get("defaultTarget"), doc.get("defaultTarget")) \
            and _same_json(stored.get("routes"), doc.get("routes")):
        return _IMPORTED, "%s in SQLite" % key
    default = not _rec(doc) or (doc.get("defaultTarget") in (None, {"mode": "current"})
                                and doc.get("routes") in (None, []))
    if stored is _MISSING and default:
        return _EMPTY, _NOTHING + " (the default routing)"
    return _UNPROVEN, "SQLite holds other routing" if stored is not _MISSING else "not in SQLite"


def _conversation_bindings_proof(path, state_db, q):
    data = _read_regular_bytes(path, 64 * 1024 * 1024)
    if data is None:
        return _UNPROVEN, "not a regular file"
    twin = _archive_twin(path, _sha256_hex(data), 64 * 1024 * 1024)
    if twin:
        return _IMPORTED, "identical archived copy " + twin
    doc = _json_strict(data)
    if doc is _MISSING:
        return _UNPROVEN, "invalid JSON"
    if not _rec(doc) or isinstance(doc.get("version"), bool) or doc.get("version") != 1 \
            or not isinstance(doc.get("bindings"), list):
        return _EMPTY, _NOTHING + " (no version 1 bindings)"
    want = {}
    for rec in doc["bindings"]:
        conv = rec.get("conversation") if _rec(rec) else None
        if not _rec(conv) or not conv.get("conversationId") or not _opt_str(rec.get("targetSessionKey")):
            continue
        acc = conv.get("accountId")
        if acc is not None and not isinstance(acc, str):
            return _UNPROVEN, "invalid account id"  # 2026.10.4 fails on it and leaves the file
        cid = _opt_str(conv.get("conversationId")) or ""
        parent = _opt_str(conv.get("parentConversationId"))
        channel = (_opt_str(conv.get("channel")) or "").lower()
        account = (_opt_str(acc) or "default").lower()  # approximates normalizeAccountId: a mismatch only HOLDs
        k = (channel, account, parent if parent and parent != cid else "", cid)
        want[k] = _opt_str(rec.get("targetSessionKey"))
    if not want:
        return _EMPTY, _NOTHING + " (no binding with a conversation and a target session)"
    rows = _rows(q, state_db, "SELECT channel, account_id, COALESCE(parent_conversation_id, ''), conversation_id, "
                              "target_session_key FROM current_conversation_bindings")
    if rows is None:
        return _UNPROVEN, "current_conversation_bindings not readable"
    have = {tuple(_cell(r, k) for k in range(5)) for r in rows}
    missing = sum(1 for k, target in want.items() if k + (target,) not in have)
    if missing:
        return _UNPROVEN, "%d of %d binding(s) not in SQLite" % (missing, len(want))
    return _IMPORTED, "%d binding(s) in current_conversation_bindings" % len(want)


def _plugin_approvals_proof(path, state_db, q):
    data = _read_regular_bytes(path, 64 * 1024 * 1024)
    if data is None:
        return _UNPROVEN, "not a regular file"
    twin = _archive_twin(path, _sha256_hex(data), 64 * 1024 * 1024)
    if twin:
        return _IMPORTED, "identical archived copy " + twin
    doc = _json_strict(data)
    if doc is _MISSING:
        return _UNPROVEN, "invalid JSON"
    if not _rec(doc) or isinstance(doc.get("version"), bool) or doc.get("version") != 1 \
            or not isinstance(doc.get("approvals"), list):
        return _EMPTY, _NOTHING + " (no version 1 approvals)"
    want = {}
    for item in doc["approvals"]:
        e = item if _rec(item) else {}
        root, pid = _opt_str(e.get("pluginRoot")), _opt_str(e.get("pluginId"))
        channel = (_opt_str(e.get("channel")) or "").lower()
        if root and pid and channel:
            want[(root, channel, _opt_str(e.get("accountId")) or "default")] = pid
    if not want:
        return _EMPTY, _NOTHING + " (no complete approval)"
    rows = _rows(q, state_db, "SELECT plugin_root, channel, account_id, plugin_id FROM plugin_binding_approvals")
    if rows is None:
        return _UNPROVEN, "plugin_binding_approvals not readable"
    have = {tuple(_cell(r, k) for k in range(4)) for r in rows}
    missing = sum(1 for k, pid in want.items() if k + (pid,) not in have)
    if missing:
        return _UNPROVEN, "%d of %d approval(s) not in SQLite" % (missing, len(want))
    return _IMPORTED, "%d approval(s) in plugin_binding_approvals" % len(want)


def _restart_receipt_decision(report_json, sha):
    """The decision of a valid restart-sentinel migration report for exactly `sha` (readReceiptReport,
    restart-sentinel-receipts.ts:29-50), else None."""
    r = _json_strict(report_json.encode("utf-8")) if isinstance(report_json, str) else _MISSING
    if not _rec(r) or r.get("source") != _RESTART_SENTINEL_KIND or r.get("target") != "gateway_restart_sentinel" \
            or r.get("sourceSha256") != sha or not isinstance(r.get("sourceValid"), bool) \
            or not all(_same_json(r.get(k), 0) or _same_json(r.get(k), 1)
                       for k in ("importedRecordCount", "preservedSqliteRecordCount")) \
            or r.get("decision") not in _RESTART_DECISIONS:
        return None
    return r["decision"]


def _restart_sentinel_proof(path, state_db, q):
    """Any recorded 2026.10.4 decision for exactly these bytes is proof (the receipt keys hash the absolute path;
    matching on kind and sha256 alone also covers a copy of the state at another path)."""
    data = _read_regular_bytes(path, _RESTART_SENTINEL_MAX)
    if data is None:
        st = _lstat(path)
        return _UNPROVEN, ("larger than 4 MiB" if st is not None and stat.S_ISREG(st.st_mode)
                           and st.st_size > _RESTART_SENTINEL_MAX else "not a regular file")
    sha = _sha256_hex(data)
    for sql in ("SELECT report_json FROM migration_sources WHERE migration_kind=%s AND source_sha256=%s"
                % (_sql_str(_RESTART_SENTINEL_KIND), _sql_str(sha)),
                "SELECT report_json FROM migration_runs WHERE id LIKE %s AND status='completed'"
                % _sql_str("restart-sentinel-json:%:" + sha[:16])):
        for r in _rows(q, state_db, sql) or ():
            decision = _restart_receipt_decision(_cell(r), sha)
            if decision:
                return _IMPORTED, "receipt " + decision
    return _UNPROVEN, "no receipt for sha256 %s..." % sha[:12]


def _sandbox_registry_proof(path, registry_kind, sharded, state_db, q):
    """Monolithic sandbox/<kind>s.json ({entries: [{containerName}]}) or sharded sandbox/<kind>s/*.json; strict:
    an unreadable or invalid registry is unproven (2026.10.4 renamed it to .invalid-<time> without importing)."""
    st = _lstat(path)
    names = []
    if not sharded:
        if st is None or not stat.S_ISREG(st.st_mode):
            return _UNPROVEN, "not a regular file"
        data = _read_regular_bytes(path, 64 * 1024 * 1024)
        doc = _json_strict(data) if data is not None else _MISSING
        if not _rec(doc) or not isinstance(doc.get("entries"), list) \
                or not all(_rec(e) and isinstance(e.get("containerName"), str) for e in doc["entries"]):
            return _UNPROVEN, "not a valid registry file"
        names = [e["containerName"] for e in doc["entries"]]
    else:
        if st is None or not stat.S_ISDIR(st.st_mode):
            return _UNPROVEN, "not a directory"
        try:
            with os.scandir(path) as it:
                shards = sorted(e.name for e in it if e.name.endswith(".json"))
        except OSError:
            return _UNPROVEN, "directory not readable"
        for name in shards:
            data = _read_regular_bytes(os.path.join(path, name), 64 * 1024 * 1024)
            doc = _json_strict(data) if data is not None else _MISSING
            if not _rec(doc) or not isinstance(doc.get("containerName"), str):
                return _UNPROVEN, "invalid shard " + name
            names.append(doc["containerName"])
    if not names:
        return _EMPTY, _NOTHING
    rows = _rows(q, state_db, "SELECT container_name FROM sandbox_registry_entries WHERE registry_kind=%s"
                 % _sql_str(registry_kind))
    if rows is None:
        return _UNPROVEN, "sandbox_registry_entries not readable"
    have = {_cell(r) for r in rows}
    missing = len({n for n in names if n not in have})
    if missing:
        return _UNPROVEN, "%d of %d entr(ies) not in SQLite" % (missing, len(set(names)))
    return _IMPORTED, "%d entr(ies) in sandbox_registry_entries" % len(set(names))


# (relative path(s), plan kind, HOLD code, label, proof(path, state_db, q)); fixed order, every 2026.10.5+ refusal
_RUNTIME_FILE_FAMILIES = (
    (("acp/event-ledger.json", "acp/event-ledger.json.doctor-import"), "acp-replay-ledger", "acp-ledger-unimported",
     "ACP replay ledger", _acp_ledger_proof),
    (("settings/voicewake.json",), "voicewake-json", "voicewake-unimported", "Voice Wake trigger words",
     lambda p, db, q: _voicewake_proof(p, "voicewake.triggers", db, q)),
    (("settings/voicewake-routing.json",), "voicewake-json", "voicewake-unimported", "Voice Wake routing",
     lambda p, db, q: _voicewake_proof(p, "voicewake.routing", db, q)),
    (("bindings/current-conversations.json",), "conversation-bindings-json", "conversation-bindings-unimported",
     "conversation bindings", _conversation_bindings_proof),
    (("plugin-binding-approvals.json",), "plugin-approvals-json", "plugin-approvals-unimported",
     "plugin binding approvals", _plugin_approvals_proof),
    (("restart-sentinel.json", "restart-sentinel.json.doctor-importing"), "restart-sentinel-json",
     "restart-sentinel-unimported", "restart sentinel", _restart_sentinel_proof),
)
_SANDBOX_REGISTRIES = (("sandbox/containers.json", "container", False), ("sandbox/containers", "container", True),
                       ("sandbox/browsers.json", "browser", False), ("sandbox/browsers", "browser", True))


def classify_retired_state(state_dir, cfg, *, accepted, query=None, home="/config", env=None, mode="from-7x",
                           workspaces=(), config_root=None, caps=None):
    """Retired pre-July-2026 files and config keys that 10.2 doctor refuses (every gate mode).

    workspaces: absolute agent workspace dirs (dreaming JSON); config_root: the directory workspace files are
    quarantined relative to (plan entries then carry "root": "config"). env: the environment OpenClaw runs with
    (OPENCLAW_OAUTH_DIR; HOME/OPENCLAW_HOME for the default-home plugin-binding-approvals.json).
    caps: oc_common.runtime_caps of the bundled OpenClaw (None: 2026.10.4). With runtime_files_retired /
    sandbox_registry_retired (2026.10.5+) the runtime files 2026.10.4 still imported are checked too: quarantined
    with proof that OpenClaw imported them (plan entry "proof") or when 2026.10.4 would import nothing, otherwise
    an acceptable HOLD per file type.
    Returns {"plan": [{rel, kind, action, reason, size[, root][, proof]}], "findings": [...], "info": [...],
    "config_removals": [path parts], "config_rewrites": [...]} -- config_removals and config_rewrites
    (retired_config_rewrites, from-7x only) are applied by the from-7x pre-migrate step.
    """
    q = query or _query_ro_local
    accepted = set(accepted or ())
    env = os.environ if env is None else env
    cfg = cfg if _rec(cfg) else {}
    plan, info, removals = [], [], []
    by_code = {}

    def add(abs_path, kind, action, reason, root="state", proof=None):
        rel = _within(config_root if root == "config" else state_dir, abs_path) \
            if root == "state" or config_root else None
        if rel is None:
            flag("retired-state-outside", abs_path)
            return
        st = _lstat(abs_path)
        e = {"rel": rel, "kind": kind, "action": action, "reason": reason, "size": st.st_size if st is not None else 0}
        if root == "config":
            e["root"] = "config"
        if proof:
            e["proof"] = proof
        plan.append(e)

    def flag(code, item):
        by_code.setdefault(code, []).append(item)

    def acceptable(code, abs_path, kind, reason_ok, reason_leave, item, root="state"):
        flag(code, item)
        if code in accepted:
            add(abs_path, kind, "quarantine", reason_ok, root)
        else:
            add(abs_path, kind, "leave", reason_leave, root)

    def must_be_dir(path, label):
        """True when `path` is a directory to scan. 10.2 lists these with readdir, which follows a symlink to
        a directory; anything else that exists makes 10.2 refuse ("Cannot inspect potentially retired state")."""
        st = _lstat(path)
        if st is None:
            return False
        if stat.S_ISDIR(st.st_mode):
            return True
        if stat.S_ISLNK(st.st_mode) and os.path.isdir(path):
            return True
        flag("retired-state-uninspectable", "%s (%s exists but is not a directory)" % (path, label))
        return False

    state_db = os.path.join(state_dir, "state", "openclaw.sqlite")
    index_ids = _installed_plugin_index_ids(state_dir, q)

    # Cron state: <store>, <store>-state.json, <store dir>/runs/*.jsonl
    store = _get(cfg, ["cron", "store"], None)
    store = _expand_home(store, home) if isinstance(store, str) and store.strip() \
        else os.path.join(state_dir, "cron", "jobs.json")
    if _lstat(store) is not None:
        raw = None
        st = _lstat(store)
        if st is not None and stat.S_ISREG(st.st_mode):
            try:
                with open(store, "rb") as fh:
                    raw = fh.read()
            except OSError:
                raw = None
        imported = False
        if raw is not None:
            import hashlib
            sha = hashlib.sha256(raw).hexdigest()
            try:
                imported = bool(q(state_db, "SELECT 1 FROM migration_sources WHERE migration_kind='legacy-cron-json' "
                                            "AND source_path=%s AND source_sha256=%s" % (_sql_str(store), _sql_str(sha))))
            except Exception:  # noqa: BLE001 - no receipts table
                imported = False
            if not imported:
                try:
                    doc = json.loads(raw.decode("utf-8"))
                    jobs = doc.get("jobs") if _rec(doc) else None
                    ids = {str(j.get("id") or j.get("jobId")) for j in jobs if _rec(j)} if isinstance(jobs, list) else None
                    have = {str(_cell(r)) for r in q(state_db, "SELECT job_id FROM cron_jobs WHERE store_key=%s"
                                                     % _sql_str(store))}
                    imported = ids is not None and ids <= have
                except Exception:  # noqa: BLE001 - unparseable store or no cron_jobs table
                    imported = False
        if imported:
            add(store, "cron-json", "quarantine", "retired cron JSON store; its jobs are in SQLite")
        else:
            acceptable("cron-json-unimported", store, "cron-json", "accepted: cron-json-unimported",
                       "retired cron JSON store with jobs that are not in SQLite", store)
    sstore = store[:-5] + "-state.json" if store.endswith(".json") else store + "-state.json"
    if _lstat(sstore) is not None:
        add(sstore, "cron-json-state", "quarantine", "retired cron run state (next/last run times only)")
    runs = os.path.join(os.path.dirname(store), "runs")
    if must_be_dir(runs, "cron runs"):
        for e in _scandir_sorted(runs):
            if e.name.endswith(".jsonl"):
                add(os.path.join(runs, e.name), "cron-run-log", "quarantine", "retired cron run log (history only)")

    # JSON delivery queues (pre-July outbound messages; 7.x imports and removes them).
    nq = 0
    for qname in ("delivery-queue", "session-delivery-queue"):
        for d in (os.path.join(state_dir, qname), os.path.join(state_dir, qname, "failed")):
            if not must_be_dir(d, "delivery queue"):
                continue
            for e in _scandir_sorted(d):
                st = _lstat(os.path.join(d, e.name))
                if st is None or stat.S_ISDIR(st.st_mode):
                    continue
                src = _DOCTOR_CLAIM_SUFFIX_RE.sub("", e.name)
                if src.endswith(".json") or src.endswith(".delivered"):
                    add(os.path.join(d, e.name), "delivery-queue-json", "quarantine",
                        "retired JSON delivery queue entry (older than July 2026; never replayed)")
                    nq += 1
    if nq:
        info.append("%d retired JSON delivery queue file(s) from before July 2026 go to quarantine "
                    "(OpenClaw 2026.9+ would not replay them either)" % nq)

    # OAuth credential sidecars (credentials/auth-profiles/<32 hex>.json). 10.2 resolves OPENCLAW_OAUTH_DIR from the
    # process env, then the config env (env.vars / env; config-env-vars-DjPHKieF.mjs:45-60): check every candidate.
    oauth_dirs = []
    for v in (env.get("OPENCLAW_OAUTH_DIR"), _get(cfg, ["env", "vars", "OPENCLAW_OAUTH_DIR"], None),
              _get(cfg, ["env", "OPENCLAW_OAUTH_DIR"], None)):
        if isinstance(v, str) and v.strip() and "${" not in v:
            d = _expand_home(v, home)
            if d not in oauth_dirs:
                oauth_dirs.append(d)
    d = os.path.join(state_dir, "credentials")  # the default; also checked when an override is set (harmless)
    if d not in oauth_dirs:
        oauth_dirs.append(d)
    blobs = None
    for oauth_dir in oauth_dirs:
        sdir = os.path.join(oauth_dir, "auth-profiles")
        if not must_be_dir(sdir, "OAuth sidecars"):
            continue
        side = [e.name for e in _scandir_sorted(sdir) if _OAUTH_SIDECAR_RE.match(e.name)]
        if side and blobs is None:
            blobs = _auth_store_blobs(state_dir, q, cfg, home)
        for name in side:
            path = os.path.join(sdir, name)
            if blobs is True or name[:32] in blobs:
                acceptable("oauth-sidecar-referenced", path, "oauth-sidecar",
                           "accepted: oauth-sidecar-referenced (the profile needs a new login)",
                           "an auth profile still references it", path)
            else:
                add(path, "oauth-sidecar", "quarantine", "unreferenced pre-June OAuth sidecar")

    # Plugin install index file and the plugins.installs config key.
    pidx = os.path.join(state_dir, "plugins", "installs.json")
    if os.path.isfile(pidx):
        ids = _legacy_plugin_index_ids(_json_file(pidx))
        missing = sorted(str(x) for x in (ids or set()) - index_ids)
        if not missing:
            add(pidx, "plugin-install-index", "quarantine", "retired plugin install index; records are in SQLite")
        else:
            acceptable("plugin-index-unimported", pidx, "plugin-install-index", "accepted: plugin-index-unimported",
                       "install records missing from the SQLite index", "%s (%s)" % (pidx, _brief(missing)))
    installs = _get(cfg, ["plugins", "installs"], _MISSING)
    if installs is not _MISSING:
        missing = sorted(str(x) for x in set(installs if _rec(installs) else ()) - index_ids)
        if mode != "from-7x":
            if installs == {} and _cap(caps, "empty_installs_tolerated"):
                info.append("openclaw.json plugins.installs is an empty object; OpenClaw doctor removes it "
                            "(install records stay in SQLite)")
            # otherwise reported by retired_config_findings as a hard config key
        elif not missing or "plugins-installs-unindexed" in accepted:
            removals.append(["plugins", "installs"])
            if missing:
                flag("plugins-installs-unindexed", "plugins.installs (%s)" % _brief(missing))
        else:
            flag("plugins-installs-unindexed", "plugins.installs (%s)" % _brief(missing))

    # Device Pair notify state (7.35 imports subscribers and archives the file; an empty file stays).
    dpn = os.path.join(state_dir, "device-pair-notify.json")
    if _lstat(dpn) is not None:
        doc = _json_file(dpn)
        subs = doc.get("subscribers") if _rec(doc) else None
        if isinstance(subs, list) and subs:
            acceptable("device-pair-subscribers", dpn, "device-pair-notify", "accepted: device-pair-subscribers",
                       "Device Pair notify subscribers not imported", "%s (%d subscriber(s))" % (dpn, len(subs)))
        else:
            add(dpn, "device-pair-notify", "quarantine", "retired Device Pair notify state without subscribers")

    # Voice Call JSONL call log (refused when the voice-call plugin runs its migrations).
    vc_store = _get(cfg, ["plugins", "entries", "voice-call", "config", "store"], None)
    if not (isinstance(vc_store, str) and vc_store.strip()):
        vc_store = _get(cfg, ["plugins", "entries", "@openclaw/voice-call", "config", "store"], None)
    vc_dir = _expand_home(vc_store, home) if isinstance(vc_store, str) and vc_store.strip() \
        else os.path.join(state_dir, "voice-calls")
    vcl = os.path.join(vc_dir, "calls.jsonl")
    if _lstat(vcl) is not None:
        acceptable("voice-call-log", vcl, "voice-call-log", "accepted: voice-call-log",
                   "retired Voice Call JSONL call log", vcl)

    # Memory Core dreaming JSON per agent workspace (dreaming is per workspace).
    for ws in sorted({os.path.abspath(str(w)) for w in workspaces or ()}):
        found = [src for src in _DREAMING_SOURCES if os.path.isfile(os.path.join(ws, "memory", ".dreams", src[1]))]
        if not found:
            continue
        rows = _memory_core_workspace_rows(state_db, q, ws)
        for label, fname, namespaces, meta in found:
            if any(v.get("key") == "legacy-source:" + label for v in rows.get("legacy-dreaming-source-acknowledgements", [])) \
                    or (meta and any(v.get("key") == meta for v in rows.get("short-term-meta", []))) \
                    or any(rows.get(n) for n in namespaces):
                continue  # 2026.10 skips it: the dreaming state is already in SQLite
            path = os.path.join(ws, "memory", ".dreams", fname)
            acceptable("dreaming-json-unmigrated", path, "dreaming-json", "accepted: dreaming-json-unmigrated",
                       "pre-July dreaming JSON without SQLite state", path, root="config")

    # Telegram ingress spool: 10.2 doctor imports valid 7.x spool files into SQLite and throws on
    # unsupported directory names; malformed files leave doctor with a refusal.
    tdir = os.path.join(state_dir, "telegram")
    tst = _lstat(tdir)
    if tst is not None and not stat.S_ISDIR(tst.st_mode):
        flag("telegram-spool-unsupported", "%s is not a directory" % tdir)
    elif tst is not None:
        spool_ok = 0
        for e in _scandir_sorted(tdir):
            if not e.name.startswith("ingress-spool-"):
                continue
            acc = e.name[len("ingress-spool-"):]
            norm = _TELEGRAM_ACCOUNT_BAD_RE.sub("_", acc.strip()) if acc.strip() else "default"
            est = _lstat(os.path.join(tdir, e.name))
            if est is None or not stat.S_ISDIR(est.st_mode) or norm != acc:
                flag("telegram-spool-unsupported", "telegram/" + e.name)
                continue
            for f in _scandir_sorted(os.path.join(tdir, e.name)):
                m = _TELEGRAM_SPOOL_FILE_RE.match(_DOCTOR_CLAIM_SUFFIX_RE.sub("", f.name))
                if not m:
                    continue
                path = os.path.join(tdir, e.name, f.name)
                prob = _spool_entry_problem(path, m.group(1), m.group(2) == "failed")
                if prob:
                    acceptable("telegram-spool-invalid", path, "telegram-spool-invalid",
                               "accepted: telegram-spool-invalid", "spool file 10.2 cannot import",
                               "telegram/%s/%s (%s)" % (e.name, f.name, prob))
                else:
                    spool_ok += 1
        if spool_ok:
            info.append("telegram ingress spool: %d legacy Telegram update file(s); doctor imports them into the "
                        "SQLite ingress queue" % spool_ok)

    # Runtime files OpenClaw 2026.10.5+ refuses (lstat existence like OpenClaw; 2026.10.4 still imported them):
    # doctor's admission check (runtime JSON sidecars, restart sentinel) and its doctor:sandbox step.
    families = list(_RUNTIME_FILE_FAMILIES) if _cap(caps, "runtime_files_retired") else []
    # the retired approvals writer always used the default home (path.resolve compare, no symlink resolution)
    if os.path.abspath(state_dir) != os.path.join(_openclaw_home(env, home), ".openclaw"):
        families = [f for f in families if f[1] != "plugin-approvals-json"]
    if _cap(caps, "sandbox_registry_retired"):
        families += [((rel,), "sandbox-registry", "sandbox-registry-unimported", "sandbox registry",
                      lambda p, db, qq, k=kind, s=sharded: _sandbox_registry_proof(p, k, s, db, qq))
                     for rel, kind, sharded in _SANDBOX_REGISTRIES]
    for rels, kind, code, label, proof in families:
        for rel in rels:
            path = os.path.join(state_dir, rel)
            st, err = _lstat_checked(path)
            if err:
                flag("retired-state-uninspectable", "%s (%s)" % (path, err))
                continue
            if st is None:
                continue
            status, detail = proof(path, state_db, q)
            if status == _IMPORTED:
                add(path, kind, "quarantine", "retired pre-July-2026 %s; OpenClaw already imported it" % label,
                    proof=detail)
            elif status == _EMPTY:
                add(path, kind, "quarantine", "retired pre-July-2026 %s with nothing OpenClaw 2026.10.4 would import"
                    % label, proof=detail)
            else:
                acceptable(code, path, kind, "accepted: " + code, "retired pre-July-2026 %s (%s)" % (label, detail),
                           "%s (%s)" % (rel, detail))

    messages = {
        "retired-state-outside": ("retired pre-July-2026 file(s) outside the state directory: %s; OpenClaw 2026.10 "
                                  "refuses them: move them away by hand (after a backup)"),
        "retired-state-uninspectable": ("%s; OpenClaw 2026.10 refuses to migrate while it cannot inspect these "
                                        "paths: fix or remove them"),
        "cron-json-unimported": ("retired cron JSON store %s holds jobs that are not in the SQLite cron table; "
                                 "OpenClaw 2026.10 refuses it. 2026.7.35 does not run these jobs either; "
                                 "accepting moves the file to quarantine"),
        "oauth-sidecar-referenced": ("pre-June OAuth credential sidecar(s) still referenced by an auth profile: %s; "
                                     "OpenClaw 2026.10 refuses them and those profiles are already unusable on "
                                     "2026.7.35; accepting moves them to quarantine (log in again afterwards)"),
        "plugin-index-unimported": ("retired plugins/installs.json with install records missing from the SQLite "
                                    "index: %s; accepting moves it to quarantine (the plugins stay installed, only "
                                    "their install provenance is lost)"),
        "plugins-installs-unindexed": ("openclaw.json plugins.installs holds install records missing from the SQLite "
                                       "index: %s; OpenClaw 2026.10 refuses the key; accepting removes it (only the "
                                       "install provenance of those plugins is lost)"),
        "device-pair-subscribers": ("retired device-pair-notify.json with Device Pair subscribers: %s; accepting "
                                    "moves it to quarantine (re-subscribe afterwards)"),
        "voice-call-log": ("retired Voice Call JSONL call log %s; OpenClaw 2026.10 refuses it; accepting moves it to "
                           "quarantine (old call history only)"),
        "telegram-spool-unsupported": ("Telegram ingress spool entry OpenClaw 2026.10 cannot import: %s; doctor "
                                       "stops on it: rename it to telegram/ingress-spool-<account id> "
                                       "(letters, digits, . _ -) or move it away"),
        "telegram-spool-invalid": ("Telegram spool file(s) OpenClaw 2026.10 cannot import: %s; accepting moves them "
                                   "to quarantine (those old updates are not processed)"),
        "dreaming-json-unmigrated": ("pre-July-2026 dreaming file(s) whose state is not in SQLite: %s; OpenClaw 2026.10 "
                                     "stops on them. Accepting moves them to quarantine: dreaming starts its ingestion "
                                     "and short-term recall history afresh (MEMORY.md and memory notes are untouched)"),
        # OpenClaw 2026.10.5+ (caps runtime_files_retired / sandbox_registry_retired)
        "acp-ledger-unimported": ("pre-July-2026 ACP replay ledger(s) whose sessions are not in SQLite: %s; OpenClaw "
                                  "2026.10.5 and later refuse them (doctor: \"Upgrade through OpenClaw 2026.9.7\"). "
                                  "Accepting moves them to quarantine: ACP clients (IDE integrations) can no longer "
                                  "replay those old sessions; nothing else uses the file"),
        "voicewake-unimported": ("pre-July-2026 Voice Wake setting file(s) whose values are not in SQLite: %s; OpenClaw "
                                 "2026.10.5 and later refuse them. Accepting moves them to quarantine: the Voice Wake "
                                 "trigger words and routing of the macOS/iOS apps stay as SQLite holds them (default: "
                                 "openclaw, claude, computer)"),
        "conversation-bindings-unimported": ("pre-July-2026 bindings/current-conversations.json with bindings that are "
                                             "not in SQLite: %s; OpenClaw 2026.10.5 and later refuse it. Accepting "
                                             "moves it to quarantine: those chats lose their binding to a specific "
                                             "session and use normal routing again"),
        "plugin-approvals-unimported": ("pre-July-2026 plugin-binding-approvals.json with approvals that are not in "
                                        "SQLite: %s; OpenClaw 2026.10.5 and later refuse it. Accepting moves it to "
                                        "quarantine: those plugins ask again before binding a conversation"),
        "restart-sentinel-unimported": ("pre-July-2026 restart-sentinel.json without an OpenClaw migration receipt for "
                                        "its content: %s; OpenClaw 2026.10.5 and later refuse it. Accepting moves it "
                                        "to quarantine: only the one-time restart/update notice of that old restart "
                                        "is lost"),
        "sandbox-registry-unimported": ("pre-July-2026 sandbox registry entries that are not in SQLite (or unreadable): "
                                        "%s; OpenClaw 2026.10.5 and later refuse them (doctor reports its sandbox step "
                                        "as failed on every run). Accepting moves them to quarantine: OpenClaw forgets "
                                        "those Docker sandbox containers (they are recreated on demand; remove old "
                                        "containers by hand if any exist)"),
    }
    hard = {"retired-state-outside", "retired-state-uninspectable", "telegram-spool-unsupported"}
    findings = [_finding(code, "hard" if code in hard else "acceptable", messages[code] % _brief(items), "precheck")
                for code, items in by_code.items()]
    return {"plan": plan, "findings": findings, "info": info, "config_removals": removals,
            "config_rewrites": retired_config_rewrites(cfg, caps) if mode == "from-7x" else []}


def retired_config_findings(cfg, mode="from-7x", caps=None, runtime=None):
    """Hard finding for retired config keys 10.2 doctor refuses (plugins.installs: see classify_retired_state).

    caps: oc_common.runtime_caps (None: 2026.10.4); runtime: the bundled OpenClaw version for the message. In from-7x
    mode the keys the pre-migrate step rewrites (retired_config_rewrites) are left out; otherwise the message names
    the exact fix for them."""
    paths, bridge = retired_config_keys(cfg, caps)
    fixes = {fmt_path(e["parts"]): e for e in retired_config_rewrites(cfg, caps)}
    if mode == "from-7x":
        paths = [p for p in paths if p != "plugins.installs" and p not in fixes]
    if not paths:
        return []
    hints = [('set %s to "%s"' % (p, fixes[p]["value"])) if fixes[p]["op"] == "set" else
             "delete %s (extension profiles find their relay themselves)" % p for p in paths if p in fixes]
    if hints:  # bump/maintenance with a 2026.10.5+ runtime: name the exact fix
        fix = "; ".join(hints[:10]) + (" (+%d more)" % (len(hints) - 10) if len(hints) > 10 else "")
        if any(p not in fixes for p in paths):
            fix += "; remove the others (or migrate them with OpenClaw %s)" % bridge
        return [_finding("config-retired-keys", "hard",
                         "openclaw.json contains settings OpenClaw %s refuses (retired before July 2026): %s. Fix: %s; "
                         "then oc-upgrade retry" % (runtime or "2026.10", _brief(paths, 10), fix), "precheck")]
    return [_finding(
        "config-retired-keys", "hard",
        ("openclaw.json contains settings OpenClaw 2026.10 refuses (retired before July 2026): %s. OpenClaw "
         "2026.7.35 does not accept them either; remove them on 0.5.93 (or migrate them with OpenClaw %s), then "
         "oc-upgrade retry" if mode == "from-7x" else
         "openclaw.json contains settings OpenClaw 2026.10 refuses (retired before July 2026): %s; remove them "
         "(or migrate them with OpenClaw %s), then oc-upgrade retry") % (_brief(paths, 10), bridge), "precheck")]


# heartbeat.activeHours (2026.11.1 HeartbeatSchema, zod-schema.agent-runtime.ts:41-103): a strict object of optional
# strings start/end/timezone; a non-empty start/end must be HH:MM 24h, 24:00 only as end. JS \d is ASCII and $ (no m
# flag) is the end of the string: [0-9] and fullmatch.
_HB_TIME_RE = re.compile(r"([01][0-9]|2[0-3]|24):([0-5][0-9])")
_HB_ACTIVE_KEYS = ("start", "end", "timezone")


def config_env_for_substitution(cfg, env):
    """The variables OpenClaw substitutes ${NAME} with when it reads openclaw.json (io.read-helpers.ts
    resolveConfigForRead: applyConfigEnvVars, then resolveConfigEnvVars): `env` (the process environment), where a
    variable is unset or blank the config's own env.vars / env.<NAME> string values (collectConfigRuntimeEnvVars)."""
    out = {}
    block = cfg.get("env") if _rec(cfg) else None
    if _rec(block):
        cands = list(block["vars"].items()) if _rec(block.get("vars")) else []
        cands += [(k, v) for k, v in block.items() if k not in ("shellEnv", "vars")]
        out.update((k, v) for k, v in cands if isinstance(k, str) and isinstance(v, str))
    out.update((k, v) for k, v in (env or {}).items() if isinstance(v, str) and v.strip())
    return out


def _heartbeat_hours_problems(heartbeat, parts, env=None):
    """[(path, value, why)] for heartbeat.activeHours at `parts` (doctor: HeartbeatSchema.safeParse({activeHours})).

    OpenClaw validates the config after its ${NAME} / ${NAME:-default} substitution (readConfigFileSnapshot ->
    resolveConfigForRead; final config validation gates on that), so start/end are checked as substituted with `env`
    (config_env_for_substitution): a template that yields a valid time passes, an unset variable without a default
    stays as written and fails like OpenClaw's. The finding shows the value as written."""
    if not _rec(heartbeat) or "activeHours" not in heartbeat:
        return []
    active, base = heartbeat["activeHours"], parts + ["activeHours"]
    if not _rec(active):
        return [(fmt_path(base), active, "expected an object with start/end (HH:MM) and optional timezone")]
    out = [(fmt_path(base + [k]), active[k], "unknown key") for k in active if k not in _HB_ACTIVE_KEYS]
    out += [(fmt_path(base + [k]), active[k], "expected a string") for k in _HB_ACTIVE_KEYS
            if k in active and not isinstance(active[k], str)]
    for k in ("start", "end"):
        raw = active.get(k)
        value = env_substituted(raw, env) if isinstance(raw, str) else raw
        if not isinstance(value, str) or not value:
            continue
        m = _HB_TIME_RE.fullmatch(value)
        if not m:
            why = 'invalid time (use "HH:MM" 24h format)'
        elif m.group(1) == "24" and m.group(2) != "00":
            why = "invalid time (24:00 is the only allowed 24:xx value)"
        elif m.group(1) == "24" and k == "start":
            why = "invalid time (start cannot be 24:00)"
        else:
            continue
        if value != raw or "${" in raw:
            why += ", after OpenClaw's ${VAR} substitution"
        out.append((fmt_path(base + [k]), raw, why))
    return out


def heartbeat_hours_findings(cfg, caps=None, runtime=None, env=None):
    """Hard `config-heartbeat-hours` for invalid heartbeat.activeHours windows (caps heartbeat_hours_kept, 2026.11.1+).

    OpenClaw 2026.10.4 and 2026.10.10 doctor removed an invalid window (unrestricted hours afterwards); from 2026.11.1
    it keeps it and reports it (openclaw/openclaw#186305, legacy-config-core-migrate.ts:55-73), so the final config
    stays invalid and `doctor --fix` exits 1 with "Doctor blocked" (#187192) after it has started migrating. Port of
    reportInvalidHeartbeatActiveHours: agents.defaults.heartbeat, then every record of the agent roster
    (readAgentRosterProperty: agents.entries if present, else agents.list). env: the environment OpenClaw's doctor
    gets (None: os.environ), for its ${VAR} substitution (_heartbeat_hours_problems). Read-only; [] without the
    capability."""
    if not _cap(caps, "heartbeat_hours_kept") or not _rec(cfg) or not _rec(cfg.get("agents")):
        return []
    agents = cfg["agents"]
    env = config_env_for_substitution(cfg, os.environ if env is None else env)
    probs = _heartbeat_hours_problems(_get(agents, ["defaults", "heartbeat"], None),
                                      ["agents", "defaults", "heartbeat"], env)
    kind = "entries" if "entries" in agents else "list" if "list" in agents else None
    roster = agents.get(kind) if kind else None
    if kind == "entries" and _rec(roster):
        for key, agent in roster.items():
            if _rec(agent):
                probs += _heartbeat_hours_problems(agent.get("heartbeat"), ["agents", "entries", key, "heartbeat"],
                                                   env)
    elif kind == "list" and isinstance(roster, list):
        for i, agent in enumerate(roster):
            if _rec(agent):
                probs += _heartbeat_hours_problems(agent.get("heartbeat"), ["agents", "list", i, "heartbeat"], env)
    if not probs:
        return []

    def show(value):
        text = json.dumps(value, ensure_ascii=False)
        return text if len(text) <= 60 else text[:57] + "..."

    items = ["%s=%s (%s)" % (path, show(value), why) for path, value, why in probs]
    return [_finding(
        "config-heartbeat-hours", "hard",
        "openclaw.json has heartbeat windows that OpenClaw %s refuses: %s. Its doctor no longer removes them "
        "(openclaw/openclaw#186305) and would stop with \"Doctor blocked\" after the migration has started. Fix: "
        "set each to HH:MM (00:00-23:59, 24:00 only as end) or remove that activeHours (an agent then uses "
        "agents.defaults.heartbeat.activeHours; without one, heartbeats run at any hour), then oc-upgrade retry"
        % (runtime or "2026.11.1+", _brief(items, 6)), "precheck")]


def _exact_cols(cols, expected):
    return len(cols) == len(expected) and set(expected) <= cols


def retired_db_findings(agent_dbs, state_db, query=None):
    """Pre-July-2026 SQLite shapes 10.2 refuses (9.9 converted or dropped them).

    agent_dbs: [(agent_id, path, user_version, target_version)] for the configured/registered agents.
    """
    q = query or _query_ro_local
    mem, shape = [], []
    for aid, path, uv, target in agent_dbs:
        if _lstat(path) is None:
            continue

        def cols(t):
            return _table_cols(q, path, t)
        try:
            names = {str(_cell(r)) for r in q(path, "SELECT name FROM sqlite_master WHERE type='table'")}
        except Exception:  # unreadable DBs are reported by quick_check
            continue
        if {"meta", "files", "chunks"} <= names \
                and _exact_cols(cols("meta"), ["key", "value"]) \
                and _exact_cols(cols("files"), ["path", "source", "hash", "mtime", "size"]) \
                and _exact_cols(cols("chunks"), ["id", "path", "source", "start_line", "end_line", "hash", "model",
                                                 "text", "embedding", "updated_at"]):
            mem.append(aid)
        if isinstance(uv, int) and isinstance(target, int) and uv >= target:
            continue
        bad = ((isinstance(uv, int) and uv < 8 and bool(names & {"sessions", "session_entries", "transcript_events"}))
               or "session_transcript_files" in names
               or ("session_transcript_fts" in names and "session_key" in cols("session_transcript_fts"))
               or ("acp_parent_stream_events" in names and "session_id" not in cols("acp_parent_stream_events"))
               or ("trajectory_runtime_events" in names and "event_id" in cols("trajectory_runtime_events"))
               or ("memory_index_sources" in names and "source_kind" in cols("memory_index_sources")))
        if bad:
            shape.append("%s (agent DB schema %s)" % (aid, uv))
    if _lstat(state_db) is not None:
        try:
            rows = q(state_db, "PRAGMA table_info('agent_databases')")
            pk = [str(_cell(r, 1)) for r in sorted((r for r in rows if int(_cell(r, 5) or 0) > 0),
                                                   key=lambda r: int(_cell(r, 5)))]
            if rows and pk != ["agent_id", "path"]:
                shape.append("state DB agent_databases primary key %s" % (pk or "missing"))
        except Exception:  # noqa: BLE001 - reported by quick_check
            pass
    out = []
    if mem:
        out.append(_finding(
            "retired-memory-index", "hard",
            "agent database(s) still hold the pre-July memory index tables (meta/files/chunks): %s; OpenClaw "
            "2026.10 refuses them. On 0.5.93 run `openclaw memory index --agent <id>` for each (2026.7.35 converts "
            "the index when it opens it; memory search must be enabled for that agent), then oc-upgrade retry"
            % _brief(mem), "precheck"))
    if shape:
        out.append(_finding(
            "pre-july-schema", "hard",
            "database shape(s) OpenClaw 2026.10 no longer migrates (pre-July 2026): %s; restore a backup made by "
            "0.5.93 after a clean start, or migrate with OpenClaw %s first" % (_brief(shape), RETIRED_FORMAT_BRIDGE),
            "precheck"))
    return out


def _memory_scopes(cfg):
    """(label, memory search dict) for every scope that can carry memory search tuning."""
    out = []
    if _rec(cfg.get("memory")) and _rec(cfg["memory"].get("search")):
        out.append(("memory.search", cfg["memory"]["search"]))

    def agent(scope, p):
        if _rec(scope.get("memorySearch")):
            out.append((p + ".memorySearch", scope["memorySearch"]))
        if _rec(scope.get("memory")) and _rec(scope["memory"].get("search")):
            out.append((p + ".memory.search", scope["memory"]["search"]))
    if _rec(cfg):
        _visit_agent_scopes(cfg, agent)
    return out


def retired_tuning_dropped(cfg_before, cfg_after):
    """Memory search tuning set before doctor that 2026.9+ no longer supports and doctor removed.

    Doctor also moves memorySearch to memory.search, so a value counts as kept when the same tuning key
    holds the same value in any scope afterwards. Returns ["<path>=<value>", ...] (numbers/short strings;
    tuning keys hold no secrets)."""
    after = {(parts, json.dumps(v, sort_keys=True)) for _l, parts, v in _memory_tuning_values(cfg_after)}
    return ["%s.%s=%s" % (label, ".".join(parts), json.dumps(v)[:40])
            for label, parts, v in _memory_tuning_values(cfg_before)
            if (parts, json.dumps(v, sort_keys=True)) not in after]


def _memory_tuning_values(cfg):
    vals = []
    if not _rec(cfg):
        return vals
    for label, scope in _memory_scopes(cfg):
        for parts in RETIRED_MEMORY_TUNING:
            v = _get(scope, list(parts), _MISSING)
            if v is not _MISSING:
                vals.append((label, parts, v))
    return vals


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


def include_paths(cfg, raw_text=None):
    """fmt_path of each $include key of openclaw.json; ["(raw text)"] when only its text has one."""
    inc = [fmt_path(p) for p in _find_key_paths(cfg, "$include")] if isinstance(cfg, (dict, list)) else []
    if not inc and isinstance(raw_text, str) and re.search(r'"\$include"\s*:', raw_text):
        inc = ["(raw text)"]
    return inc


def config_precheck(cfg, raw_text):
    """Hard config findings: config-unreadable (not an object), config-includes ($include, B14),
    custom-session-store (non-empty session.store)."""
    phase = "precheck"
    if not isinstance(cfg, dict):
        return [_finding("config-unreadable", "hard",
                         "openclaw.json must be a strict JSON object (JSON5 comments are unsupported)", phase)]
    findings = []
    inc = include_paths(cfg, raw_text)
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
