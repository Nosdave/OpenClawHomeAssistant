#!/usr/bin/env python3
"""
oc-upgrade — upgrade checks, the migration gate and its helpers for the add-on.

Commands:
  check          Read-only inventory of the persistent OpenClaw state: versions,
                 database schemas, legacy (pre-June 2026) leftovers, model
                 wildcards, free space and (when a migration is pending) the
                 migration-gate readiness. Prints file names, sizes and versions
                 only — never tokens or other secret values.
                 Exit codes: 0 nothing to note, 4 notes (cleanup items the
                 upgrade handles), 2 possible bridge case (legacy database with
                 data that was never imported), 3 state written by a newer
                 OpenClaw than this image ships, 1 error.
  status         Show the add-on's upgrade bookkeeping (hold reason, migration
                 gate run, checked Home Assistant backup, quarantine, marker,
                 pending retry, gate options).
  retry [--doctor] [--accept CODE[,CODE]] [--cancel]
                 Ask the migration gate to continue on the next add-on start
                 (after fixing the cause of a HOLD). --accept continues past
                 acceptable HOLD codes; --doctor re-runs doctor (also allowed
                 after a successful migration, as a maintenance run).
  log [--pass N] [--lines N]
                 Tail of the current gate run's doctor log (redacted).
  cleanup [--apply]
                 List when OpenClaw's doctor captures of finished gate runs,
                 the gate archives and rehearsal exports of earlier add-on
                 versions and the 2026.7 plaintext pre-upgrade archives are
                 deleted (gate_cleanup_hours after the run, the export or the
                 migration; the add-on does it by itself), or delete what is
                 due now.
  gate --dry-run [--network]
                 Read-only preview of what the migration gate would do.
  state-guard    Used by run.sh at startup. Exit 3 (with reasons on stdout) when
                 the persistent state was written by a newer OpenClaw than the
                 bundled runtime, 0 otherwise.
  gate --plan | gate | gate --hold-exit78 | gate --hold-crash-loop <rc>
                 Used by run.sh (internal).
  plugins-sync   Used by run.sh after the migration gate, with the gateway
                 down (internal): updates the enabled official npm plugins
                 (@openclaw/codex, @openclaw/acpx, ...; not Brave, which run.sh
                 installs itself) to the bundled OpenClaw version, once per
                 version (marker /config/.openclaw/.plugin_cohort_<version>).
                 Never downgrades, leaves disabled plugins alone, always exits 0.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
from datetime import datetime, timezone

_PYLIB = os.environ.get("OC_ADDON_PYLIB", "/usr/local/lib/oc-addon/python")
_HERE = os.path.dirname(os.path.realpath(__file__))
for _p in (_HERE, _PYLIB):
    if _p in sys.path:
        sys.path.remove(_p)
    sys.path.insert(0, _p)

import oc_common as C  # noqa: E402

# Every OpenClaw release through the 2026.7.x line stamps schema version 1 into
# state/openclaw.sqlite and agents/*/agent/openclaw-agent.sqlite (PRAGMA
# user_version). Later lines migrate these databases one-way to higher schema
# versions that a 2026.7.x runtime cannot open.
JULY_LINE_SCHEMA = 1
FIRST_MIGRATING_LINE = (2026, 8, 0)

LEGACY_DATABASES = ("tasks/runs.sqlite", "flows/registry.sqlite", "plugin-state/state.sqlite")

RC_OK, RC_ERROR, RC_BRIDGE, RC_NEWER, RC_NOTES = 0, 1, 2, 3, 4

# Kept for callers of the Stage A helpers.
version_tuple = C.version_tuple
fmt_version = C.fmt_version
header_user_version = C.header_user_version
SchemaUnknown = C.SchemaUnknown
user_version = C.user_version
_query_ro = C.query_ro
human = C.human
gate_options = C.gate_options


def P():
    return C.paths()


def rel(path):
    return C.rel(path, P()["STATE"])


def _gate():
    import oc_gate  # noqa: PLC0415
    return oc_gate


def _mig():
    import oc_migrate  # noqa: PLC0415
    return oc_migrate


# --- helpers -----------------------------------------------------------------

def runtime_version():
    raw = os.environ.get("OPENCLAW_RUNTIME_VERSION", "")
    if version_tuple(raw):
        return version_tuple(raw)
    try:
        out = subprocess.run(["openclaw", "--version"], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return version_tuple(out)


def read_config():
    try:
        return json.loads(P()["CONFIG_PATH"].read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def core_databases():
    state = P()["STATE"]
    dbs = []
    state_db = state / "state" / "openclaw.sqlite"
    if state_db.exists():
        dbs.append(state_db)
    dbs.extend(sorted(state.glob("agents/*/agent/openclaw-agent.sqlite")))
    return dbs


def du_bytes(path):
    try:
        out = subprocess.run(["du", "-sb", str(path)], capture_output=True, text=True, timeout=300).stdout
        return int(out.split()[0])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return None


def migrated_for(runtime_str):
    """True when the gate's marker says this state was migrated for `runtime_str`."""
    m = C.load_json_or_none(P()["UPG_DIR"] / "gate" / "migrated.json")
    return bool(isinstance(m, dict) and runtime_str and version_tuple(m.get("runtime")) == version_tuple(runtime_str))


# --- state guard ---------------------------------------------------------------

def newer_state_reasons(runtime):
    """Reasons why the persistent state is newer than `runtime` (empty = fine).

    2026.7.x runtimes: lastTouchedVersion and the schema-1 constant (Stage A).
    2026.8+ runtimes: the gate predicate with the package's schema targets (§6.4);
    raises (fail closed) when the targets are unknown.
    """
    reasons = []
    cfg = read_config()
    if runtime and runtime >= FIRST_MIGRATING_LINE + (0,):
        G = _gate()
        pkg = C.runtime_package()
        try:
            cls = G.classify(P()["STATE"], cfg if isinstance(cfg, dict) else {}, pkg["schema_state"],
                             pkg["schema_agent"], fmt_version(runtime))
        except C.SchemaUnknown as exc:
            return [f"could not determine the schema version safely: {exc}"]
        return list(cls["newer"])
    meta = cfg.get("meta") if isinstance(cfg, dict) else None
    if isinstance(meta, dict):
        touched = version_tuple(meta.get("lastTouchedVersion"))
        if runtime and touched and touched > runtime:
            reasons.append(
                f"openclaw.json was last written by OpenClaw {fmt_version(touched)}, "
                f"but this image ships {fmt_version(runtime)}"
            )
    if runtime and runtime < FIRST_MIGRATING_LINE + (0,):
        for db in core_databases():
            try:
                uv = user_version(db)
            except SchemaUnknown as exc:
                reasons.append(f"could not determine the schema version safely: {exc}")
                continue
            if uv is not None and uv > JULY_LINE_SCHEMA:
                reasons.append(
                    f"{rel(db)} has schema version {uv}; OpenClaw {fmt_version(runtime)} only understands {JULY_LINE_SCHEMA}"
                )
    return reasons


def cmd_state_guard(_args):
    runtime = runtime_version()
    if runtime is None:
        print("WARN: could not determine the bundled OpenClaw version; state guard skipped")
        return RC_OK
    try:
        reasons = newer_state_reasons(runtime)
    except Exception as exc:  # fail closed: a guard that crashes must not let OpenClaw start
        print(f"state guard could not complete ({type(exc).__name__}: {exc}); holding to be safe — run 'oc-upgrade check'")
        return RC_NEWER
    for r in reasons:
        print(r)
    return RC_NEWER if reasons else RC_OK


# --- check ---------------------------------------------------------------------

def legacy_db_rows(path):
    """Total rows in user tables of a legacy database (None = unreadable)."""
    import sqlite3
    try:
        tables = [r[0] for r in _query_ro(path, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        total = 0
        for t in tables:
            total += int(_query_ro(path, f'SELECT COUNT(*) FROM "{t}"')[0][0])
        return total
    except (OSError, sqlite3.Error):
        return None


_LEGACY_WILDCARD_RE = re.compile(r"\A\s*openai-codex\s*/\s*\*\s*\Z", re.I)


def _scan_model_wildcards(agents):
    wildcards = []
    defaults = agents.get("defaults")
    models = defaults.get("models") if isinstance(defaults, dict) else None
    for key in (models if isinstance(models, dict) else {}):
        if str(key).endswith("*"):
            wildcards.append(str(key))
    entries = agents.get("list")
    for entry in (entries if isinstance(entries, list) else []):
        if isinstance(entry, dict):
            entry_models = entry.get("models")
            for key in (entry_models if isinstance(entry_models, dict) else {}):
                if str(key).endswith("*"):
                    wildcards.append(f"{entry.get('id', '?')}: {key}")
    ent = agents.get("entries")
    for aid, entry in (ent.items() if isinstance(ent, dict) else []):
        if isinstance(entry, dict):
            entry_models = entry.get("models")
            for key in (entry_models if isinstance(entry_models, dict) else {}):
                if str(key).endswith("*"):
                    wildcards.append(f"{aid}: {key}")
    return wildcards


def cmd_check(_args):
    import sqlite3
    rc = RC_OK
    notes = []
    p = P()
    state = p["STATE"]

    def bump(new, informational=False):
        nonlocal rc
        if informational:
            return
        order = {RC_OK: 0, RC_NOTES: 1, RC_BRIDGE: 2, RC_NEWER: 3}
        if order.get(new, 0) > order.get(rc, 0):
            rc = new

    print(f"oc-upgrade check — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} (read-only)")
    if not state.exists():
        print(f"No OpenClaw state at {state}.")
        return RC_OK

    runtime = runtime_version()
    cfg = read_config()
    pkg = None
    try:
        pkg = C.runtime_package()
    except C.RuntimePackageError as exc:
        pkg_err = str(exc)
    else:
        pkg_err = None
    G = None
    if runtime and runtime >= FIRST_MIGRATING_LINE + (0,):
        try:
            G = _gate()
        except Exception as exc:  # noqa: BLE001
            print(f"  NOTE: migration gate module unavailable ({type(exc).__name__}: {exc})")
    migrated = bool(pkg and migrated_for(pkg["version"]))
    info_only = migrated  # after a migration, leftovers 2026.9+ ignores are informational only

    print("\n== A Versions")
    print(f"  bundled OpenClaw:      {fmt_version(runtime)}")
    if pkg:
        print(f"  bundled OpenClaw schema targets: state {pkg['schema_state']}, agent {pkg['schema_agent']}")
    elif runtime and runtime >= FIRST_MIGRATING_LINE + (0,):
        print(f"  bundled OpenClaw schema targets: unknown ({pkg_err})")
    meta = cfg.get("meta") if isinstance(cfg, dict) else None
    touched = meta.get("lastTouchedVersion") if isinstance(meta, dict) else None
    print(f"  openclaw.json written by: {touched or 'unknown'}")
    if cfg is None and p["CONFIG_PATH"].exists():
        print("  NOTE: openclaw.json is not valid JSON")
        notes.append("openclaw.json unreadable")
        bump(RC_NOTES)
    for db in core_databases():
        try:
            print(f"  schema {rel(db)}: {user_version(db)}")
        except SchemaUnknown as exc:
            print(f"  schema {rel(db)}: UNKNOWN ({exc})")
    state_db = state / "state" / "openclaw.sqlite"
    if state_db.exists():
        try:
            row = _query_ro(state_db, "SELECT app_version FROM schema_meta WHERE meta_key='startup-migrations'")
            print(f"  startup-migrations checkpoint: {row[0][0] if row else 'none'}")
        except (OSError, sqlite3.Error):
            print("  startup-migrations checkpoint: n/a")
    cls = None
    if G is not None and pkg is not None:
        try:
            # full5: the stores OpenClaw holds back (deletion journal, this runtime's marker), as the gate plans
            cls = G.classify(state, cfg if isinstance(cfg, dict) else {}, pkg["schema_state"], pkg["schema_agent"],
                             pkg["version"], held=G.planning_held(state, G.load_marker(), pkg))
            why = cls["newer"] or cls["gate"] or cls["files"]
            print(f"  predicate: {cls['verdict']}" + (f" ({'; '.join(why[:4])})" if why else ""))
            orphans = [o for o in cls["orphans"] if not o.get("held")]
            if orphans:
                print("  agent databases of no configured or registered agent (doctor may migrate them one-way; "
                      "the gateway does not open them): "
                      + ", ".join(f"{o['path']} (schema {o['uv']})" for o in orphans))
            held = [o for o in cls["orphans"] if o.get("held")] + list(cls.get("held") or [])
            if held:
                print("  held agent databases (kept from deleted agents; not migrated, not opened): "
                      + ", ".join(f"{h['path']} (agent {h['id']}, schema {h['uv']}: {G.held_reason_text(h['reason'])})"
                                  for h in held))
            for h in cls.get("held_configured") or []:
                print(f"  NOTE: agent {h['id']} is configured, but OpenClaw holds its database {h['path']} back "
                      f"({G.held_reason_text(h['reason'])}); the gate holds (agent-db-held)")
        except Exception as exc:  # noqa: BLE001
            print(f"  predicate: n/a ({type(exc).__name__}: {exc})")
        try:
            j = G.load_journal()
        except (OSError, ValueError) as exc:
            j = None
            print(f"  gate: journal unreadable ({exc})")
        if j:
            print(f"  gate: run {j.get('run_id')} status {j.get('status')} phase {j.get('phase')}")
        m = G.load_marker()
        print(f"  migrated: {m.get('runtime')} ({m.get('mode')})" if m else "  migrated: no marker")
    try:
        reasons = newer_state_reasons(runtime)
    except Exception as exc:  # noqa: BLE001
        reasons = [f"state guard could not complete ({type(exc).__name__}: {exc})"]
    for r in reasons:
        print(f"  NEWER STATE: {r}")
    if reasons:
        bump(RC_NEWER)

    print("\n== B Legacy databases (pre-June 2026)" + ("  [informational: migrated]" if info_only else ""))
    found = False
    for name in LEGACY_DATABASES:
        path = state / name
        migrated_copies = sorted(str(x.name) for x in path.parent.glob(path.name + ".migrated*")) if path.parent.exists() else []
        if path.exists():
            found = True
            rows = legacy_db_rows(path)
            print(f"  PRESENT {name} ({human(path.stat().st_size)}, rows: {rows if rows is not None else 'unreadable'})")
            if migrated_copies:
                print(f"    imported before: {', '.join(migrated_copies)}")
            elif rows is None or rows > 0:
                print("    not imported -> possible bridge case (upgrade through 2026.9.5 first)")
                bump(RC_BRIDGE, info_only)
        elif migrated_copies:
            found = True
            print(f"  imported: {name} ({', '.join(migrated_copies)})")
    if not found:
        print("  none")

    M = None
    try:
        M = _mig()
    except Exception as exc:  # noqa: BLE001
        print(f"\n  NOTE: oc_migrate unavailable ({type(exc).__name__}: {exc}); sections C/E/F use basic rules")

    print("\n== C Legacy Telegram / Active Memory files (2026.9+ rules)" + ("  [informational: migrated]" if info_only else ""))
    shown = 0
    if M is not None:
        try:
            checkpoint = None
            if state_db.exists():
                try:
                    row = _query_ro(state_db, "SELECT app_version FROM schema_meta WHERE meta_key='startup-migrations'")
                    checkpoint = row[0][0] if row else None
                except (OSError, sqlite3.Error):
                    checkpoint = None
            sf = M.classify_state_files(str(state), cfg if isinstance(cfg, dict) else {}, from_checkpoint=checkpoint,
                                        accepted=set(), mode="from-7x")
            for e in sf.get("plan", []):
                if e.get("kind") == "sqlite-transient":
                    continue
                shown += 1
                print(f"  {e.get('rel')} ({e.get('size', 0)} B) {e.get('kind')}: {e.get('action')}"
                      + (f" — {e['reason']}" if e.get("reason") else ""))
                if e.get("action") == "quarantine":
                    bump(RC_NOTES, info_only)
            for f in sf.get("findings", []):
                print(f"  {f.get('cls', '').upper()} {f.get('code')}: {f.get('message')}")
                bump(RC_NOTES, info_only)
            if shown:
                notes.append("legacy Telegram/Active Memory files are set aside by the migration gate (quarantine)")
        except Exception as exc:  # noqa: BLE001
            print(f"  n/a ({type(exc).__name__}: {exc})")
    if not shown:
        print("  none")

    print("\n== C2 Pre-July-2026 files and settings (OpenClaw 2026.10 refuses them)"
          + ("  [informational: migrated]" if info_only else ""))
    shown = 0
    if M is not None:
        try:
            ccfg = cfg if isinstance(cfg, dict) else {}
            try:  # the checks of the bundled OpenClaw (2026.10.5+: runtime files, API ids, cdpUrl)
                caps = C.runtime_caps(C.runtime_package())
            except Exception:  # noqa: BLE001 - unknown runtime: the 2026.10.4 checks
                caps = None
            keys, _bridge = M.retired_config_keys(ccfg, caps)
            for k in keys:
                shown += 1
                print(f"  openclaw.json {k}: retired setting"
                      + (" (removed by the gate when its records are in SQLite)" if k == "plugins.installs" else ""))
                bump(RC_NOTES, info_only)
            rs = M.classify_retired_state(str(state), ccfg, accepted=set(), home=str(p["CONFIG_ROOT"]), caps=caps,
                                          env=dict(os.environ, HOME=str(p["CONFIG_ROOT"])))
            for e in rs.get("plan", []):
                shown += 1
                print(f"  {e.get('rel')} ({e.get('size', 0)} B) {e.get('kind')}: {e.get('action')}"
                      + (f" — {e['reason']}" if e.get("reason") else "")
                      + (f" (proof: {e['proof']})" if e.get("proof") else ""))
                bump(RC_NOTES, info_only)
            for f in rs.get("findings", []):
                shown += 1
                print(f"  {f.get('cls', '').upper()} {f.get('code')}: {f.get('message')}")
                bump(RC_NOTES, info_only)
            for i in rs.get("info", []):
                print(f"  info: {i}")
            if shown:
                notes.append("pre-July-2026 leftovers: the migration gate quarantines what is safe and holds on the rest")
        except Exception as exc:  # noqa: BLE001
            print(f"  n/a ({type(exc).__name__}: {exc})")
    if not shown:
        print("  none")

    print("\n== D credentials/oauth.json (provider names only)")
    oauth = state / "credentials" / "oauth.json"
    if oauth.exists():
        try:
            data = json.loads(oauth.read_text(encoding="utf-8"))
            names = sorted(data.keys()) if isinstance(data, dict) else []
            print(f"  present: {names}")
        except (OSError, ValueError):
            print("  present (unreadable)")
        notes.append("credentials/oauth.json is no longer imported by current OpenClaw (informational)")
        bump(RC_NOTES, info_only)
    else:
        print("  none")

    print("\n== E Agent database directories")
    any_agent = False
    transient = M.TRANSIENT_SQLITE_RE if M is not None else None
    for agent_dir in sorted(state.glob("agents/*/agent")):
        any_agent = True
        for x in sorted(agent_dir.glob("*.sqlite*")):
            is_t = bool(transient.fullmatch(x.name)) if transient is not None else False
            flag = "  <- transient memory sidecar (quarantined by the migration gate)" if is_t else ""
            print(f"  {rel(x)} ({human(x.lstat().st_size)}){flag}")
            if flag:
                bump(RC_NOTES, info_only)
    if not any_agent:
        print("  none")

    print("\n== F Model wildcards and model preflight")
    agents = cfg.get("agents") if isinstance(cfg, dict) else None
    if agents is not None and not isinstance(agents, dict):
        print("  NOTE: 'agents' is not an object in openclaw.json")
        notes.append("openclaw.json has an unexpected 'agents' section")
        bump(RC_NOTES)
        agents = None
    wildcards = _scan_model_wildcards(agents) if isinstance(agents, dict) else []
    print(f"  wildcards: {wildcards if wildcards else 'none'}")
    legacy_wildcards = [w for w in wildcards if _LEGACY_WILDCARD_RE.match(w.rsplit(": ", 1)[-1])]
    if legacy_wildcards and not info_only:
        notes.append("openai-codex/* wildcards are expanded into explicit entries by the migration gate")
        bump(RC_NOTES)
    if M is not None and isinstance(cfg, dict):
        try:
            for f in M.models_preflight(cfg):
                print(f"  {f.get('cls', '').upper()} {f.get('code')}: {f.get('message')}")
                bump(RC_NOTES, info_only or f.get("cls") == "info")
            # informational; G1 runs at the next gate run (update, or retry --doctor + restart)
            for ln in M.glm_thinking_preview(cfg, C.glm_thinking_option()):
                print("  " + ln)
        except Exception as exc:  # noqa: BLE001
            print(f"  preflight n/a ({type(exc).__name__}: {exc})")

    print("\n== G Already imported legacy files")
    migrated_count = sum(1 for _ in state.rglob("*.migrated*"))
    print(f"  {migrated_count}")
    qdir = p["UPG_DIR"] / "gate" / "quarantine"
    if qdir.exists():
        qn = sum(1 for x in qdir.rglob("*") if x.is_file() and x.name != "MANIFEST.json")
        print(f"  quarantined by the migration gate: {qn} file(s) in {qdir} (informational)")

    print("\n== H Space")
    state_size = du_bytes(state)
    ws = p["WORKSPACE"]
    ws_size = du_bytes(ws) if ws.exists() else 0
    for label, path in (("/config", p["CONFIG_ROOT"]), ("/share", p["SHARE"])):
        try:
            usage = shutil.disk_usage(path)
            print(f"  {label}: {human(usage.free)} free of {human(usage.total)}")
        except OSError:
            print(f"  {label}: n/a")
    print(f"  state {state}: {human(state_size) if state_size is not None else 'n/a'}; "
          f"workspace {ws}: {human(ws_size) if ws_size is not None else 'n/a'}")

    if cls is not None and G is not None and cls["verdict"] == "gate" and not migrated:
        print("\n== I Migration gate readiness (dry run, no network check)")
        g = G.Gate(dry_run=True, network=False, emit=print)
        try:
            mode = G.infer_mode(cls, cfg if isinstance(cfg, dict) else {})
            print(f"  mode: {mode}")
            lines, findings = G.readiness(g, mode)
            for ln in lines:
                print("  " + ln.replace("[gate]   ", "", 1).replace("[gate] ", "", 1))
            block = [f["code"] for f in findings if f.get("cls") in ("hard", "acceptable")]
            print(f"  a gate would HOLD with: {', '.join(dict.fromkeys(block))}" if block else
                  "  the gate precheck would pass")
        except Exception as exc:  # noqa: BLE001
            print(f"  n/a ({type(exc).__name__}: {exc})")
        finally:
            g.cleanup_tmp()

    print("\n== Result")
    meaning = {
        RC_OK: "OK — nothing to note.",
        RC_NOTES: "Notes only — items to handle as part of the 2026.10 upgrade; nothing blocks the current version.",
        RC_BRIDGE: "POSSIBLE BRIDGE CASE — a legacy database with data was never imported. Do not upgrade; send this output.",
        RC_NEWER: "STATE IS NEWER THAN THIS IMAGE — restore the matching backup; do not start OpenClaw on it.",
    }
    print(f"  rc={rc}: {meaning[rc]}")
    for n in notes:
        print(f"  - {n}")
    return rc


# --- status --------------------------------------------------------------------

def cmd_status(_args):
    p = P()
    upg = p["UPG_DIR"]
    hold = upg / "hold.txt"
    print(f"Upgrade bookkeeping in {upg}")
    if hold.exists():
        print("HOLD (OpenClaw not started):")
        print("  " + hold.read_text(encoding="utf-8", errors="replace").strip().replace("\n", "\n  "))
    else:
        print("No hold.")
    archives = [(a, st) for a, st in C.safe_children(p["STATE"] / "upgrade-backups")
                if stat.S_ISREG(st.st_mode) and a.name.startswith("openclaw-state-") and a.name.endswith(".tar.gz")]
    hours = gate_options()["cleanup_hours"]
    print("Pre-upgrade archives (local, Stage A, 7.x only):")
    for a, st in archives:
        when = "deleted automatically after the 2026.8+ migration, see oc-upgrade cleanup" if hours else \
            _gate().leftover_note(hours)
        print(f"  {_gate().printable(a)} ({human(st.st_size)}, PLAINTEXT; {when})")
    if not archives:
        print("  none")
    rehearsal = C.safe_files_below(p["SHARE"] / "openclaw-rehearsal",
                                   lambda n: n.startswith("openclaw-rehearsal.tar.gz"))
    print("Rehearsal exports (earlier add-on versions):")
    for a, st in rehearsal:
        kind = "encrypted" if a.name.endswith(".age") else "PLAINTEXT"
        print(f"  {_gate().printable(a)} ({human(st.st_size)}, {kind}; {_gate().leftover_note(hours)})")
    if not rehearsal:
        print("  none")
    print("Migration gate:")
    try:
        for line in _gate().status_lines():
            print(f"  {line}")
    except Exception as exc:  # noqa: BLE001
        print(f"  n/a ({type(exc).__name__}: {exc})")
    return RC_OK


# --- gate / retry / log --------------------------------------------------------

def _plan_without_gate_module(exc):
    """B11 when oc_gate itself cannot be imported: trust a marker for this runtime, else fail closed."""
    try:
        pkg = C.runtime_package()
    except C.RuntimePackageError:
        pkg = None
    if pkg and migrated_for(pkg["version"]):
        print(f"WARN [gate] migration gate unavailable ({type(exc).__name__}: {exc}); marker for {pkg['version']} present")
        print(f"[gate] plan: runtime={pkg['version']} gate module error ignored (migrated) -> no gate")
        return 0
    print(f"[gate] plan: error: migration gate unavailable ({type(exc).__name__}: {exc})")
    return 1


def cmd_gate(args):
    known = {"--plan", "--dry-run", "--network", "--hold-exit78", "--hold-crash-loop"}
    rest = [a for a in args if a not in known]
    if "--hold-crash-loop" in args:
        idx = args.index("--hold-crash-loop")
        last_rc = args[idx + 1] if idx + 1 < len(args) else None
        rest = [a for a in rest if a != last_rc]
    if rest:
        print(f"oc-upgrade gate: unknown argument(s): {' '.join(rest)}")
        return 2
    if "--hold-exit78" in args or "--hold-crash-loop" in args:
        code = "exit78" if "--hold-exit78" in args else "crash-loop"
        last = None
        if code == "crash-loop":
            try:
                last = int(last_rc) if last_rc is not None else None
            except ValueError:
                last = None
        try:
            return _gate().hold_after_start(code, last)
        except Exception as exc:  # noqa: BLE001 - always rc 0 (spec §5.2)
            print(f"WARN [gate] could not record the {code} hold: {type(exc).__name__}: {exc}")
            try:
                upg = P()["UPG_DIR"]
                upg.mkdir(parents=True, exist_ok=True)
                C.atomic_write_text(upg / "hold.txt", f"OpenClaw is held — migration gate run n/a, phase gateway\n"
                                                      f"Reason [{code}]: the gateway refused to start\n"
                                                      "Next: oc-upgrade retry\nDetails: oc-upgrade status\n")
            except OSError:
                pass
            return 0
    if "--plan" in args:
        try:
            G = _gate()
        except Exception as exc:  # noqa: BLE001
            return _plan_without_gate_module(exc)
        return G.plan(apply=False)["rc"]
    if "--dry-run" in args:
        try:
            G = _gate()
        except Exception as exc:  # noqa: BLE001
            print(f"[gate] dry-run: error: {type(exc).__name__}: {exc}")
            return 1
        return G.dry_run(network="--network" in args)
    if os.environ.get("OC_GATE_FROM_RUNSH") != "1":
        print("oc-upgrade gate is internal (run by the add-on at startup). After fixing a HOLD use: "
              "oc-upgrade retry   (then restart the add-on). Preview: oc-upgrade gate --dry-run")
        return 2
    try:
        G = _gate()
    except Exception as exc:  # noqa: BLE001
        print(f"[gate] HOLD internal-error in precheck: migration gate unavailable ({type(exc).__name__}: {exc})")
        try:
            upg = P()["UPG_DIR"]
            upg.mkdir(parents=True, exist_ok=True)
            C.atomic_write_text(upg / "hold.txt", "OpenClaw is held — migration gate run n/a, phase precheck\n"
                                                  f"Reason [internal-error]: {type(exc).__name__}: {exc}\n"
                                                  "Next: reinstall the add-on\nDetails: oc-upgrade status\n")
        except OSError:
            pass
        return 1
    return G.run_gate()


def cmd_retry(args):
    return _gate().retry_cmd(args)


def cmd_log(args):
    return _gate().log_cmd(args)


def cmd_cleanup(args):
    return _gate().cleanup_cmd(args)


# --- official plugins (full5) -------------------------------------------------------------
# OpenClaw's doctor never brings the official npm plugins to the core version (only `openclaw update` does, in its
# post-core pass, which the add-on cannot run): the add-on does it after the gate, before the gateway starts.
PLUGIN_LIST_TIMEOUT = 180
PLUGIN_UPDATE_TIMEOUT = 300
_RUNTIME_VERSION_RE = re.compile(r"^\d{4}\.\d+\.\d+(?:-\d+)?$")
# OpenClaw keeps loading a version-bound plugin from this release on (official-runtime-plugins.ts)
PLUGIN_MIN_COMPATIBLE = {"@openclaw/codex": "2026.9.7"}


def _sync_runtime_version():
    """The version run.sh checks the marker for (its validated OPENCLAW_RUNTIME_VERSION), else the package's."""
    env = os.environ.get("OPENCLAW_RUNTIME_VERSION", "").strip()
    if _RUNTIME_VERSION_RE.match(env):
        return env
    try:
        return C.runtime_package()["version"]
    except C.RuntimePackageError:
        return None


def _oc_capture(args, timeout, tmp, tag):
    """Run the bundled OpenClaw CLI (never through the wrapper); (rc, stdout text, redacted tail)."""
    out_p, err_p = os.path.join(tmp, f"{tag}.out"), os.path.join(tmp, f"{tag}.err")
    res = C.run_oc(args, timeout=timeout, log_path=err_p, stdout_path=out_p)
    texts = []
    for f in (out_p, err_p):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                texts.append(fh.read())
        except OSError:
            texts.append("")
    lines = [x.strip() for x in (texts[1] + "\n" + texts[0]).splitlines() if x.strip()]
    tail = C.redact_text(" | ".join(lines[-2:]))[:300]
    rc = "timeout" if res.timed_out else res.rc
    return rc, texts[0], tail


def _official_enabled(data):
    """{package: version} of the enabled official npm plugins in `openclaw plugins list --json` (not Brave, not
    bundled ones, CalVer versions only); None when the output has no plugin list."""
    plugins = data.get("plugins") if isinstance(data, dict) else None
    if not isinstance(plugins, list):
        return None
    found = {}
    for x in plugins:
        if not isinstance(x, dict) or x.get("enabled") is not True or x.get("origin") == "bundled":
            continue
        pkg = x.get("packageName")
        ver = x.get("version") or x.get("packageVersion")
        if not isinstance(pkg, str) or not pkg.startswith("@openclaw/") or pkg == "@openclaw/brave-plugin":
            continue
        if not re.fullmatch(r"@openclaw/[a-z0-9][a-z0-9._-]{0,100}", pkg):
            continue
        if isinstance(ver, str) and version_tuple(ver):
            found.setdefault(pkg, ver)
    return found


def cmd_plugins_sync(args):
    """`oc-upgrade plugins-sync` (internal; run.sh after the gate, gateway down). Always returns 0."""
    if args:
        print("usage: oc-upgrade plugins-sync")
        return RC_OK
    try:
        return _plugins_sync()
    except Exception as exc:  # noqa: BLE001 - best effort: never stops the add-on start
        print(f"WARN: Official plugins not updated ({type(exc).__name__}: {C.redact_text(str(exc))[:200]}); the add-on "
              "tries again at the next start.")
        return RC_OK


def _plugins_sync():
    p = P()
    rt = _sync_runtime_version()
    if not rt:
        print("WARN: Official plugins not updated: the OpenClaw version is unknown (non-fatal).")
        return RC_OK
    if (p["UPG_DIR"] / "hold.txt").exists():
        print("INFO: Official plugins not updated: OpenClaw is held (oc-upgrade status).")
        return RC_OK
    marker = p["STATE"] / f".plugin_cohort_{rt}"
    if marker.exists():
        return RC_OK
    import tempfile  # noqa: PLC0415
    with tempfile.TemporaryDirectory(prefix="oc-plugins-sync-") as tmp:
        rc, text, tail = _oc_capture(["plugins", "list", "--json"], PLUGIN_LIST_TIMEOUT, tmp, "list")
        found = _official_enabled(C.parse_json_output(text)) if rc == 0 else None
        if found is None:
            print(f"WARN: Official plugins not updated: openclaw plugins list failed (rc {rc}"
                  + (f": {tail}" if tail else "") + "); the add-on tries again at the next start.")
            return RC_OK
        rtv = version_tuple(rt)
        todo = []
        for pkg, ver in sorted(found.items()):
            if ver == rt:
                continue
            if version_tuple(ver) > rtv:
                print(f"WARN: {pkg} {ver} is newer than OpenClaw {rt}; left as is (no downgrade)")
                continue
            todo.append((pkg, ver))
        failed = []
        for pkg, ver in todo:
            print(f"INFO: Official plugins: updating {pkg} {ver} -> {rt} (OpenClaw {rt})...", flush=True)
            urc, _text, utail = _oc_capture(["plugins", "update", f"{pkg}@{rt}"], PLUGIN_UPDATE_TIMEOUT, tmp,
                                            f"update-{len(failed)}-{pkg.rsplit('/', 1)[-1]}")
            if urc != 0:
                failed.append((pkg, ver, f"openclaw plugins update failed, rc {urc}" + (f": {utail}" if utail else "")))
        if todo:
            rc, text, tail = _oc_capture(["plugins", "list", "--json"], PLUGIN_LIST_TIMEOUT, tmp, "relist")
            now = _official_enabled(C.parse_json_output(text)) if rc == 0 else None
            for pkg, ver in todo:
                if any(f[0] == pkg for f in failed):
                    continue
                got = (now or {}).get(pkg)
                if now is None:
                    failed.append((pkg, ver, f"openclaw plugins list failed after the update, rc {rc}"))
                elif got != rt:
                    failed.append((pkg, got or ver, f"openclaw plugins update left version {got or 'unknown'}"))
        for pkg, ver, why in failed:
            floor = PLUGIN_MIN_COMPATIBLE.get(pkg)
            loads = (f"; OpenClaw {rt} still loads it (minimum {floor})" if floor and version_tuple(ver)
                     and version_tuple(ver) >= version_tuple(floor) else "")
            print(f"WARN: {pkg} stays at {ver} ({why}){loads}. The add-on tries again at the next start; by hand: "
                  f"openclaw plugins update {pkg}@{rt}")
        if failed:
            return RC_OK
    try:
        C.atomic_write_text(marker, f"{rt}\n")
    except OSError as exc:
        print(f"WARN: could not record the official plugin update for OpenClaw {rt} ({exc}); it runs again at the "
              "next start")
    print(f"INFO: Official plugins match OpenClaw {rt}." if found else
          f"INFO: Official plugins: none enabled besides Brave; nothing to update for OpenClaw {rt}.")
    return RC_OK


COMMANDS = {
    "check": cmd_check,
    "status": cmd_status,
    "state-guard": cmd_state_guard,
    "gate": cmd_gate,
    "retry": cmd_retry,
    "log": cmd_log,
    "cleanup": cmd_cleanup,
    "plugins-sync": cmd_plugins_sync,
}


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help") or argv[1] not in COMMANDS:
        print(__doc__.strip())
        return RC_OK if len(argv) >= 2 and argv[1] in ("-h", "--help", "help") else RC_ERROR
    try:
        return COMMANDS[argv[1]](argv[2:])
    except KeyboardInterrupt:
        return RC_ERROR


if __name__ == "__main__":
    sys.exit(main(sys.argv))
