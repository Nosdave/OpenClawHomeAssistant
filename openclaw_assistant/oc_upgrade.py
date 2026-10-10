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
                 gate run, archives, quarantine, marker, pending retry).
  retry [--doctor] [--accept CODE[,CODE]] [--cancel]
                 Ask the migration gate to continue on the next add-on start
                 (after fixing the cause of a HOLD). --accept continues past
                 acceptable HOLD codes; --doctor re-runs doctor (also allowed
                 after a successful migration, as a maintenance run).
  log [--pass N] [--lines N]
                 Tail of the current gate run's doctor log (redacted).
  gate --dry-run [--network]
                 Read-only preview of what the migration gate would do.
  export         Request a cold copy of the state for an offline upgrade
                 rehearsal. The copy is written on the NEXT add-on start, before
                 the gateway starts, to /share/openclaw-rehearsal/<timestamp>/.
                 `export --cancel` withdraws the request.
  state-guard    Used by run.sh at startup. Exit 3 (with reasons on stdout) when
                 the persistent state was written by a newer OpenClaw than the
                 bundled runtime, 0 otherwise.
  gate --plan | gate | gate --hold-exit78 | gate --hold-crash-loop <rc>
                 Used by run.sh (internal).
"""

import json
import os
import re
import shutil
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
    info_only = migrated  # after a migration, leftovers 9.x ignores are informational only

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
            cls = G.classify(state, cfg if isinstance(cfg, dict) else {}, pkg["schema_state"], pkg["schema_agent"],
                             pkg["version"])
            why = cls["newer"] or cls["gate"] or cls["files"]
            print(f"  predicate: {cls['verdict']}" + (f" ({'; '.join(why[:4])})" if why else ""))
            if cls["orphans"]:
                print("  unconfigured agent databases (not migrated): "
                      + ", ".join(f"{o['path']} (schema {o['uv']})" for o in cls["orphans"]))
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

    print("\n== C Legacy Telegram / Active Memory files (9.9 rules)" + ("  [informational: migrated]" if info_only else ""))
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
        RC_NOTES: "Notes only — items to handle as part of the 2026.9 upgrade; nothing blocks the current version.",
        RC_BRIDGE: "POSSIBLE BRIDGE CASE — a legacy database with data was never imported. Do not upgrade; send this output.",
        RC_NEWER: "STATE IS NEWER THAN THIS IMAGE — restore the matching backup; do not start OpenClaw on it.",
    }
    print(f"  rc={rc}: {meaning[rc]}")
    for n in notes:
        print(f"  - {n}")
    return rc


# --- status / export -----------------------------------------------------------

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
    print(f"Export requested: {'yes (runs on next add-on start)' if (upg / 'export-request').exists() else 'no'}")
    archives = sorted((p["STATE"] / "upgrade-backups").glob("openclaw-state-*.tar.gz"))
    print("Pre-upgrade archives (local, Stage A):")
    for a in archives or []:
        print(f"  {a} ({human(a.stat().st_size)})")
    if not archives:
        print("  none")
    rehearsal = sorted((p["SHARE"] / "openclaw-rehearsal").glob("*/openclaw-rehearsal.tar.gz"))
    print("Rehearsal exports:")
    for a in rehearsal or []:
        print(f"  {a} ({human(a.stat().st_size)})")
    if not rehearsal:
        print("  none")
    print("Migration gate:")
    try:
        for line in _gate().status_lines():
            print(f"  {line}")
    except Exception as exc:  # noqa: BLE001
        print(f"  n/a ({type(exc).__name__}: {exc})")
    return RC_OK


def cmd_export(args):
    p = P()
    upg = p["UPG_DIR"]
    req = upg / "export-request"
    if "--cancel" in args:
        if req.exists():
            req.unlink()
            print("Export request withdrawn.")
        else:
            print("No export request pending.")
        return RC_OK
    upg.mkdir(parents=True, exist_ok=True)
    os.chmod(upg, 0o700)
    req.write_text(datetime.now(timezone.utc).isoformat() + "\n", encoding="utf-8")
    state_size = du_bytes(p["STATE"])
    print("Export requested. Restart the add-on to create it:")
    print("  - it runs on the next start, BEFORE the gateway starts (Telegram is offline for a few minutes);")
    print("  - the copy goes to /share/openclaw-rehearsal/<timestamp>/ (state incl. installed plugins + workspace,")
    print("    without logs, media, caches, earlier archives and workspace node_modules);")
    if state_size is not None:
        print(f"  - current state size: {human(state_size)} before compression;")
    print("  - THE COPY CONTAINS SECRETS (tokens, OAuth logins). Move it only to a machine you trust and")
    print("    delete it after the rehearsal. Withdraw with: oc-upgrade export --cancel")
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


COMMANDS = {
    "check": cmd_check,
    "status": cmd_status,
    "export": cmd_export,
    "state-guard": cmd_state_guard,
    "gate": cmd_gate,
    "retry": cmd_retry,
    "log": cmd_log,
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
