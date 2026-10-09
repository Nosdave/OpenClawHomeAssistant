#!/usr/bin/env python3
"""
oc-upgrade — read-only upgrade checks and upgrade helpers for the add-on.

Commands:
  check          Read-only inventory of the persistent OpenClaw state: versions,
                 database schemas, legacy (pre-June 2026) leftovers, model
                 wildcards and free space. Prints file names, sizes and versions
                 only — never tokens or other secret values.
                 Exit codes: 0 nothing to note, 4 notes (cleanup items the
                 upgrade handles), 2 possible bridge case (legacy database with
                 data that was never imported), 3 state written by a newer
                 OpenClaw than this image ships, 1 error.
  status         Show the add-on's upgrade bookkeeping (hold reason, archives,
                 pending export request).
  export         Request a cold copy of the state for an offline upgrade
                 rehearsal. The copy is written on the NEXT add-on start, before
                 the gateway starts, to /share/openclaw-rehearsal/<timestamp>/.
                 `export --cancel` withdraws the request.
  state-guard    Used by run.sh at startup. Exit 3 (with reasons on stdout) when
                 the persistent state was written by a newer OpenClaw than the
                 bundled runtime, 0 otherwise.
"""

import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path(os.environ.get("OPENCLAW_STATE_DIR", "/config/.openclaw"))
CONFIG_PATH = Path(os.environ.get("OPENCLAW_CONFIG_PATH", str(STATE_DIR / "openclaw.json")))
WORKSPACE_DIR = Path(os.environ.get("OPENCLAW_WORKSPACE_DIR", "/config/clawd"))
UPG_DIR = Path(os.environ.get("OC_UPGRADE_DIR", "/config/.openclaw-upgrade"))
SHARE_DIR = Path(os.environ.get("OC_UPGRADE_SHARE_DIR", "/share"))
EXPORT_REQUEST = UPG_DIR / "export-request"
HOLD_FILE = UPG_DIR / "hold.txt"

# Every OpenClaw release through the 2026.7.x line stamps schema version 1 into
# state/openclaw.sqlite and agents/*/agent/openclaw-agent.sqlite (PRAGMA
# user_version). Later lines migrate these databases one-way to higher schema
# versions that a 2026.7.x runtime cannot open.
JULY_LINE_SCHEMA = 1
FIRST_MIGRATING_LINE = (2026, 8, 0)

LEGACY_DATABASES = ("tasks/runs.sqlite", "flows/registry.sqlite", "plugin-state/state.sqlite")
SIDECAR_PATTERN = re.compile(r"\.sqlite\.(?:reindex-lock|generation-(?:lock|writer))\.sqlite$|\.sqlite\.generation-")

RC_OK, RC_ERROR, RC_BRIDGE, RC_NEWER, RC_NOTES = 0, 1, 2, 3, 4


# --- helpers -----------------------------------------------------------------

def version_tuple(text):
    """Parse `2026.7.35`, `2026.7.1-2` or `OpenClaw 2026.9.9 (abc)` into a comparable tuple."""
    if not isinstance(text, str):
        return None
    m = re.search(r"(\d{4})\.(\d{1,2})\.(\d{1,3})(?:-(\d{1,3})(?![\w.]))?", text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4) or 0))


def fmt_version(v):
    if not v:
        return "unknown"
    base = f"{v[0]}.{v[1]}.{v[2]}"
    return f"{base}-{v[3]}" if v[3] else base


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
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def header_user_version(path):
    """PRAGMA user_version straight from the database header (offset 60)."""
    try:
        with open(path, "rb") as f:
            head = f.read(100)
    except OSError:
        return None
    if len(head) < 64 or not head.startswith(b"SQLite format 3\x00"):
        return None
    return int.from_bytes(head[60:64], "big")


def _query_ro(path, sql):
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def user_version(path):
    """Schema version of a SQLite file without writing to it.

    The header is authoritative unless a non-empty WAL may carry a newer page 1;
    then ask SQLite read-only, and if that is not possible (no -shm), read a
    private copy of the database + WAL.
    """
    header = header_user_version(path)
    wal = Path(f"{path}-wal")
    if not (wal.exists() and wal.stat().st_size > 0):
        return header
    try:
        return int(_query_ro(path, "PRAGMA user_version")[0][0])
    except sqlite3.Error:
        pass
    try:
        with tempfile.TemporaryDirectory(prefix="oc-upgrade-") as tmp:
            copy = Path(tmp) / "db.sqlite"
            shutil.copyfile(path, copy)
            shutil.copyfile(wal, Path(f"{copy}-wal"))
            con = sqlite3.connect(str(copy), timeout=2)
            try:
                return int(con.execute("PRAGMA user_version").fetchone()[0])
            finally:
                con.close()
    except (OSError, sqlite3.Error):
        return header


def core_databases():
    dbs = []
    state_db = STATE_DIR / "state" / "openclaw.sqlite"
    if state_db.exists():
        dbs.append(state_db)
    dbs.extend(sorted(STATE_DIR.glob("agents/*/agent/openclaw-agent.sqlite")))
    return dbs


def rel(path):
    try:
        return str(Path(path).relative_to(STATE_DIR))
    except ValueError:
        return str(path)


def human(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def du_bytes(path):
    try:
        out = subprocess.run(["du", "-sb", str(path)], capture_output=True, text=True, timeout=300).stdout
        return int(out.split()[0])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return None


# --- state guard ---------------------------------------------------------------

def newer_state_reasons(runtime):
    """Reasons why the persistent state is newer than `runtime` (empty = fine)."""
    reasons = []
    cfg = read_config()
    if isinstance(cfg, dict):
        touched = version_tuple((cfg.get("meta") or {}).get("lastTouchedVersion"))
        if runtime and touched and touched > runtime:
            reasons.append(
                f"openclaw.json was last written by OpenClaw {fmt_version(touched)}, "
                f"but this image ships {fmt_version(runtime)}"
            )
    if runtime and runtime < FIRST_MIGRATING_LINE:
        for db in core_databases():
            uv = user_version(db)
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
    reasons = newer_state_reasons(runtime)
    for r in reasons:
        print(r)
    return RC_NEWER if reasons else RC_OK


# --- check ---------------------------------------------------------------------

def legacy_db_rows(path):
    """Total rows in user tables of a legacy database (None = unreadable)."""
    try:
        tables = [r[0] for r in _query_ro(path, "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        total = 0
        for t in tables:
            total += int(_query_ro(path, f'SELECT COUNT(*) FROM "{t}"')[0][0])
        return total
    except sqlite3.Error:
        return None


def cmd_check(_args):
    rc = RC_OK
    notes = []

    def bump(new):
        nonlocal rc
        order = {RC_OK: 0, RC_NOTES: 1, RC_BRIDGE: 2, RC_NEWER: 3}
        if order.get(new, 0) > order.get(rc, 0):
            rc = new

    print(f"oc-upgrade check — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} (read-only)")
    if not STATE_DIR.exists():
        print(f"No OpenClaw state at {STATE_DIR}.")
        return RC_OK

    runtime = runtime_version()
    cfg = read_config()
    print("\n== A Versions")
    print(f"  bundled OpenClaw:      {fmt_version(runtime)}")
    touched = (cfg or {}).get("meta", {}).get("lastTouchedVersion") if isinstance(cfg, dict) else None
    print(f"  openclaw.json written by: {touched or 'unknown'}")
    if cfg is None and CONFIG_PATH.exists():
        print("  NOTE: openclaw.json is not valid JSON")
        notes.append("openclaw.json unreadable")
        bump(RC_NOTES)
    for db in core_databases():
        print(f"  schema {rel(db)}: {user_version(db)}")
    state_db = STATE_DIR / "state" / "openclaw.sqlite"
    if state_db.exists():
        try:
            row = _query_ro(state_db, "SELECT app_version FROM schema_meta WHERE meta_key='startup-migrations'")
            print(f"  startup-migrations checkpoint: {row[0][0] if row else 'none'}")
        except sqlite3.Error:
            print("  startup-migrations checkpoint: n/a")
    reasons = newer_state_reasons(runtime)
    for r in reasons:
        print(f"  NEWER STATE: {r}")
    if reasons:
        bump(RC_NEWER)

    print("\n== B Legacy databases (pre-June 2026)")
    found = False
    for name in LEGACY_DATABASES:
        path = STATE_DIR / name
        migrated = sorted(str(p.name) for p in path.parent.glob(path.name + ".migrated*")) if path.parent.exists() else []
        if path.exists():
            found = True
            rows = legacy_db_rows(path)
            print(f"  PRESENT {name} ({human(path.stat().st_size)}, rows: {rows if rows is not None else 'unreadable'})")
            if migrated:
                print(f"    imported before: {', '.join(migrated)}")
            elif rows is None or rows > 0:
                print("    not imported -> possible bridge case (upgrade through 2026.9.5 first)")
                bump(RC_BRIDGE)
        elif migrated:
            found = True
            print(f"  imported: {name} ({', '.join(migrated)})")
    if not found:
        print("  none")

    print("\n== C Legacy Telegram / Active Memory files")
    patterns = ["telegram/*.json", "sessions/sessions.json.telegram-*.json",
                "agents/*/sessions/sessions.json.telegram-*.json", "plugins/active-memory/session-toggles.json"]
    legacy_files = [p for pat in patterns for p in sorted(STATE_DIR.glob(pat)) if p.is_file()]
    if legacy_files:
        for p in legacy_files:
            size = p.stat().st_size
            trivial = p.name.startswith("thread-bindings-") and size <= 64
            print(f"  {rel(p)} ({size} B){'  (empty binding list)' if trivial else ''}")
            if not trivial:
                bump(RC_NOTES)
        notes.append("legacy Telegram/Active Memory files must be handled (set aside or confirmed) before the 2026.9 upgrade")
    else:
        print("  none")

    print("\n== D credentials/oauth.json (provider names only)")
    oauth = STATE_DIR / "credentials" / "oauth.json"
    if oauth.exists():
        try:
            data = json.loads(oauth.read_text(encoding="utf-8"))
            names = sorted(data.keys()) if isinstance(data, dict) else []
            print(f"  present: {names}")
        except (OSError, ValueError):
            print("  present (unreadable)")
        notes.append("credentials/oauth.json is no longer imported by current OpenClaw (informational)")
        bump(RC_NOTES)
    else:
        print("  none")

    print("\n== E Agent database directories")
    any_agent = False
    for agent_dir in sorted(STATE_DIR.glob("agents/*/agent")):
        any_agent = True
        for p in sorted(agent_dir.glob("*.sqlite*")):
            flag = "  <- memory sidecar, must be set aside before the 2026.9 migration" if SIDECAR_PATTERN.search(p.name) else ""
            print(f"  {rel(p)} ({human(p.stat().st_size)}){flag}")
            if flag:
                bump(RC_NOTES)
    if not any_agent:
        print("  none")

    print("\n== F Model wildcards")
    wildcards = []
    if isinstance(cfg, dict):
        agents = cfg.get("agents") or {}
        for key in ((agents.get("defaults") or {}).get("models") or {}):
            if str(key).endswith("*"):
                wildcards.append(str(key))
        for entry in agents.get("list") or []:
            if isinstance(entry, dict):
                for key in (entry.get("models") or {}):
                    if str(key).endswith("*"):
                        wildcards.append(f"{entry.get('id', '?')}: {key}")
    print(f"  {wildcards if wildcards else 'none'}")
    if wildcards:
        notes.append("model wildcards must be replaced by explicit entries before the 2026.9 migration")
        bump(RC_NOTES)

    print("\n== G Already imported legacy files")
    migrated_count = sum(1 for _ in STATE_DIR.rglob("*.migrated*"))
    print(f"  {migrated_count}")

    print("\n== H Space")
    state_size = du_bytes(STATE_DIR)
    ws_size = du_bytes(WORKSPACE_DIR) if WORKSPACE_DIR.exists() else 0
    for label, path in (("/config", Path("/config")), ("/share", SHARE_DIR)):
        try:
            usage = shutil.disk_usage(path)
            print(f"  {label}: {human(usage.free)} free of {human(usage.total)}")
        except OSError:
            print(f"  {label}: n/a")
    print(f"  state {STATE_DIR}: {human(state_size) if state_size is not None else 'n/a'}; "
          f"workspace {WORKSPACE_DIR}: {human(ws_size) if ws_size is not None else 'n/a'}")

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
    print(f"Upgrade bookkeeping in {UPG_DIR}")
    if HOLD_FILE.exists():
        print("HOLD (OpenClaw not started):")
        print("  " + HOLD_FILE.read_text(encoding="utf-8", errors="replace").strip().replace("\n", "\n  "))
    else:
        print("No hold.")
    print(f"Export requested: {'yes (runs on next add-on start)' if EXPORT_REQUEST.exists() else 'no'}")
    archives = sorted((STATE_DIR / "upgrade-backups").glob("openclaw-state-*.tar.gz"))
    print("Pre-upgrade archives:")
    for a in archives or []:
        print(f"  {a} ({human(a.stat().st_size)})")
    if not archives:
        print("  none")
    rehearsal = sorted((SHARE_DIR / "openclaw-rehearsal").glob("*/openclaw-rehearsal.tar.gz"))
    print("Rehearsal exports:")
    for a in rehearsal or []:
        print(f"  {a} ({human(a.stat().st_size)})")
    if not rehearsal:
        print("  none")
    return RC_OK


def cmd_export(args):
    if "--cancel" in args:
        if EXPORT_REQUEST.exists():
            EXPORT_REQUEST.unlink()
            print("Export request withdrawn.")
        else:
            print("No export request pending.")
        return RC_OK
    UPG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(UPG_DIR, 0o700)
    EXPORT_REQUEST.write_text(datetime.now(timezone.utc).isoformat() + "\n", encoding="utf-8")
    state_size = du_bytes(STATE_DIR)
    print("Export requested. Restart the add-on to create it:")
    print("  - it runs on the next start, BEFORE the gateway starts (Telegram is offline for a few minutes);")
    print("  - the copy goes to /share/openclaw-rehearsal/<timestamp>/ (state + workspace, without logs, media,")
    print("    caches and earlier archives);")
    if state_size is not None:
        print(f"  - current state size: {human(state_size)} before compression;")
    print("  - THE COPY CONTAINS SECRETS (tokens, OAuth logins). Move it only to a machine you trust and")
    print("    delete it after the rehearsal. Withdraw with: oc-upgrade export --cancel")
    return RC_OK


COMMANDS = {
    "check": cmd_check,
    "status": cmd_status,
    "export": cmd_export,
    "state-guard": cmd_state_guard,
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
