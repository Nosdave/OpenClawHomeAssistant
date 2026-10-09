"""
Shared helpers for oc-upgrade and the migration gate (stdlib only, Python 3.11).

Everything here is side-effect free except the explicit writers
(atomic_write_*) and the subprocess runners (run_process / run_oc / node_query).
Paths are resolved at call time from the environment, so tests can point the
whole module at a temporary tree:

  OPENCLAW_STATE_DIR     default /config/.openclaw
  OPENCLAW_CONFIG_PATH   default $OPENCLAW_STATE_DIR/openclaw.json
  OPENCLAW_WORKSPACE_DIR default $OC_CONFIG_ROOT/clawd
  OC_UPGRADE_DIR         default /config/.openclaw-upgrade
  OC_UPGRADE_SHARE_DIR   default /share
  OC_CONFIG_ROOT         default /config   (HOME of every OpenClaw subprocess)
  OC_ADDON_ENTRY_FILE    default /usr/local/libexec/oc-addon/openclaw-entry
"""

import hashlib
import json
import os
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ENTRY_FILE = "/usr/local/libexec/oc-addon/openclaw-entry"
GIB = 1 << 30
MIB = 1 << 20


class SchemaUnknown(Exception):
    """The schema version of a database could not be determined safely."""


class ConfigReadError(Exception):
    """openclaw.json is missing, unreadable, not strict JSON or not an object."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind  # "missing" | "unreadable" | "not-object"


class RuntimePackageError(Exception):
    """The bundled OpenClaw package (entry, version, schema targets) is unknown."""


class NodeQueryError(Exception):
    """The node:sqlite fallback reader failed."""


class Stopped(Exception):
    """A long-running helper noticed the stop flag and aborted."""


# --- paths / time / formatting ---------------------------------------------------

def paths():
    """Resolved locations (Path objects); env-overridable for tests."""
    state = Path(os.environ.get("OPENCLAW_STATE_DIR") or "/config/.openclaw")
    config_root = Path(os.environ.get("OC_CONFIG_ROOT") or "/config")
    return {
        "STATE": state,
        "CONFIG_PATH": Path(os.environ.get("OPENCLAW_CONFIG_PATH") or str(state / "openclaw.json")),
        "UPG_DIR": Path(os.environ.get("OC_UPGRADE_DIR") or "/config/.openclaw-upgrade"),
        "SHARE": Path(os.environ.get("OC_UPGRADE_SHARE_DIR") or "/share"),
        "CONFIG_ROOT": config_root,
        "WORKSPACE": Path(os.environ.get("OPENCLAW_WORKSPACE_DIR") or str(config_root / "clawd")),
    }


def utc_now():
    return datetime.now(timezone.utc)


def utc_iso(dt=None):
    return (dt or utc_now()).strftime("%Y-%m-%dT%H:%M:%SZ")


def human(n):
    if n is None:
        return "n/a"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def fmt_duration(seconds):
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def rel(path, base=None):
    base = Path(base) if base is not None else paths()["STATE"]
    try:
        return str(Path(path).relative_to(base))
    except ValueError:
        return str(path)


# --- versions ----------------------------------------------------------------------

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


# --- SQLite (read-only) -------------------------------------------------------------

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


def _execute(con, sql, params, progress_handler, progress_n):
    if progress_handler is not None:
        con.set_progress_handler(progress_handler, progress_n)
    return con.execute(sql, tuple(params)).fetchall()


def _query_private_copy(path, sql, params=(), progress_handler=None, progress_n=10000):
    """Query a private copy of the database (+ its WAL, if any)."""
    wal = Path(f"{path}-wal")
    with tempfile.TemporaryDirectory(prefix="oc-upgrade-") as tmp:
        copy = Path(tmp) / "db.sqlite"
        shutil.copyfile(path, copy)
        if wal.exists():
            shutil.copyfile(wal, Path(f"{copy}-wal"))
        con = sqlite3.connect(str(copy), timeout=2)
        try:
            return _execute(con, sql, params, progress_handler, progress_n)
        finally:
            con.close()


def query_ro(path, sql, params=(), progress_handler=None, progress_n=10000):
    """Run a read-only query without creating or modifying any file next to the database.

    - No WAL content: everything is in the main file; open it with immutable=1,
      so SQLite neither creates nor touches -wal/-shm companions.
    - WAL content and an -shm index (normally: the gateway is running): read
      through the existing index with readonly_shm=1, so the index is not
      rewritten; fall back to a private copy if SQLite cannot use it read-only.
    - WAL content without -shm: query a private copy of database + WAL.
    `progress_handler` (optional) is installed with sqlite3's set_progress_handler;
    returning non-zero aborts the statement (sqlite3.OperationalError "interrupted").
    """
    wal, shm = Path(f"{path}-wal"), Path(f"{path}-shm")
    wal_has_data = wal.exists() and wal.stat().st_size > 0
    if not wal_has_data:
        uri = f"file:{path}?mode=ro&immutable=1"
    elif shm.exists():
        uri = f"file:{path}?mode=ro&readonly_shm=1"
    else:
        return _query_private_copy(path, sql, params, progress_handler, progress_n)
    try:
        con = sqlite3.connect(uri, uri=True, timeout=2)
        try:
            return _execute(con, sql, params, progress_handler, progress_n)
        finally:
            con.close()
    except sqlite3.Error:
        if not wal_has_data:
            raise
        return _query_private_copy(path, sql, params, progress_handler, progress_n)


def user_version(path):
    """Schema version of a SQLite file without writing to it.

    The header is authoritative unless a non-empty WAL may carry a newer page 1;
    then ask SQLite read-only (see query_ro; never creates or changes files).
    Raises SchemaUnknown if that WAL cannot be read.
    """
    header = header_user_version(path)
    wal = Path(f"{path}-wal")
    if not (wal.exists() and wal.stat().st_size > 0):
        return header
    try:
        return int(query_ro(path, "PRAGMA user_version")[0][0])
    except (OSError, sqlite3.Error) as exc:
        # The newer schema may live only in the WAL: never fall back to the
        # (possibly stale) header here.
        raise SchemaUnknown(f"{rel(path)}: WAL present but unreadable ({type(exc).__name__}: {exc})") from exc


NODE_QUERY_JS = (
    "import {DatabaseSync} from 'node:sqlite';"
    "const db=new DatabaseSync(process.env.OCQ_PATH,{readOnly:true});"
    "const p=JSON.parse(process.env.OCQ_PARAMS||'[]');"
    "process.stdout.write(JSON.stringify(db.prepare(process.env.OCQ_SQL).all(...p)));"
    "db.close()"
)


def node_query(path, sql, timeout=120, params=()):
    """Read-only query through node:sqlite (fallback when Python's SQLite cannot read a DB).

    Returns a list of dicts (column -> value). Raises NodeQueryError.
    """
    node = shutil.which("node")
    if not node:
        raise NodeQueryError("node not found")
    env = dict(os.environ)
    env.update(OCQ_PATH=str(path), OCQ_SQL=sql, OCQ_PARAMS=json.dumps(list(params)))
    with tempfile.TemporaryDirectory(prefix="oc-nodeq-") as tmp:
        out_p, err_p = Path(tmp) / "out.json", Path(tmp) / "err.txt"
        with open(out_p, "wb") as out, open(err_p, "wb") as err:
            try:
                proc = subprocess.run([node, "--input-type=module", "-e", NODE_QUERY_JS], stdin=subprocess.DEVNULL,
                                      stdout=out, stderr=err, env=env, timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                raise NodeQueryError(f"node:sqlite query timed out after {timeout}s") from exc
            except OSError as exc:
                raise NodeQueryError(f"node:sqlite query failed to start: {exc}") from exc
        if proc.returncode != 0:
            tail = err_p.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-3:]
            raise NodeQueryError(f"node:sqlite query failed (rc {proc.returncode}): {' | '.join(tail)}")
        try:
            data = json.loads(out_p.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise NodeQueryError(f"node:sqlite returned unparseable output: {exc}") from exc
    if not isinstance(data, list):
        raise NodeQueryError("node:sqlite returned a non-list result")
    return data


# --- files ------------------------------------------------------------------------------

def _fsync_dir(d):
    try:
        fd = os.open(str(d), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def atomic_write_bytes(path, data, default_mode=0o600):
    """Write via temp file + fsync + rename. Keeps the mode/owner of an existing file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    mode, owner = default_mode, None
    try:
        st = os.stat(path)
        mode, owner = stat.S_IMODE(st.st_mode), (st.st_uid, st.st_gid)
    except FileNotFoundError:
        pass
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        if owner is not None and hasattr(os, "fchown"):
            try:
                os.fchown(fd, owner[0], owner[1])
            except OSError:
                pass
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    _fsync_dir(path.parent)


def atomic_write_text(path, text, default_mode=0o600):
    atomic_write_bytes(path, text.encode("utf-8"), default_mode)


def atomic_write_json(path, obj, mode=0o600):
    atomic_write_text(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n", mode)


def _reject_constant(name):
    raise ValueError(f"non-standard JSON constant {name}")


def read_json_strict(path, with_text=False):
    """Parse a JSON object file strictly (no JSON5, no NaN). Raises ConfigReadError."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigReadError("missing", f"{path} does not exist") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigReadError("unreadable", f"{path} cannot be read ({type(exc).__name__}: {exc})") from exc
    try:
        obj = json.loads(text, parse_constant=_reject_constant)
    except ValueError as exc:
        raise ConfigReadError(
            "unreadable", f"{path} is not valid JSON ({exc}); strict JSON required (JSON5 comments are unsupported)"
        ) from exc
    if not isinstance(obj, dict):
        raise ConfigReadError("not-object", f"{path} does not contain a JSON object")
    return (obj, text) if with_text else obj


def load_json_or_none(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def sha256_file(path, stop_event=None, chunk=MIB):
    """sha256 of a regular file without following a final symlink. Polls stop_event (B17)."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    h = hashlib.sha256()
    fd = os.open(str(path), flags)
    with os.fdopen(fd, "rb") as f:
        while True:
            if stop_event is not None and stop_event.is_set():
                raise Stopped("stop requested")
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def walk_lstat(root, skip_dir=None, stop_event=None):
    """Yield (path, lstat) for everything below root; never follows symlinks.

    `skip_dir(path)` -> True prunes a directory (it is not yielded either).
    """
    stack = [Path(root)]
    n = 0
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                n += 1
                if stop_event is not None and n % 512 == 0 and stop_event.is_set():
                    raise Stopped("stop requested")
                p = Path(e.path)
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode):
                    if skip_dir is not None and skip_dir(p):
                        continue
                    stack.append(p)
                yield p, st


# --- runtime package / environment ---------------------------------------------------

def runtime_package():
    """{"version","entry","pkg_dir","node","schema_state","schema_agent"} of the bundled OpenClaw.

    Raises RuntimePackageError when the entry, version or schema targets are unknown.
    """
    entry_file = os.environ.get("OC_ADDON_ENTRY_FILE") or DEFAULT_ENTRY_FILE
    try:
        with open(entry_file, encoding="utf-8") as f:
            entry = f.readline().strip()
    except OSError as exc:
        raise RuntimePackageError(f"the add-on's record of the OpenClaw entry ({entry_file}) is missing") from exc
    if not entry:
        raise RuntimePackageError(f"{entry_file} is empty")
    pkg_dir = os.path.dirname(entry)
    try:
        with open(os.path.join(pkg_dir, "package.json"), encoding="utf-8") as f:
            pkg = json.load(f)
    except (OSError, ValueError) as exc:
        raise RuntimePackageError(f"cannot read {pkg_dir}/package.json ({type(exc).__name__})") from exc
    version = pkg.get("version") if isinstance(pkg, dict) else None
    if not isinstance(version, str) or not version_tuple(version):
        raise RuntimePackageError(f"{pkg_dir}/package.json has no usable version")
    oc = pkg.get("openclaw") if isinstance(pkg.get("openclaw"), dict) else {}
    sv = oc.get("schemaVersions") if isinstance(oc.get("schemaVersions"), dict) else {}
    s, a = sv.get("state"), sv.get("agent")
    if not (isinstance(s, int) and not isinstance(s, bool) and isinstance(a, int) and not isinstance(a, bool)):
        raise RuntimePackageError(f"{pkg_dir}/package.json lacks openclaw.schemaVersions.state/agent")
    return {"version": version, "entry": entry, "pkg_dir": pkg_dir, "node": shutil.which("node"),
            "schema_state": s, "schema_agent": a}


ENV_REMOVE = {
    "OPENCLAW_COMPATIBILITY_HOST_VERSION", "OPENCLAW_CONTAINER", "INVOCATION_ID", "JOURNAL_STREAM",
    "SYSTEMD_EXEC_PID", "OPENCLAW_SYSTEMD_UNIT", "OPENCLAW_SERVICE_MARKER", "OPENCLAW_SERVICE_KIND",
    "OPENCLAW_LAUNCHD_LABEL", "NODE_COMPILE_CACHE",
}
_HEAP_CAP_RE = re.compile(r"(?:^|\s)--max[-_]old[-_]space[-_]size(?:=\S*|\s+\d+)")


def strip_heap_cap(node_options):
    return " ".join(_HEAP_CAP_RE.sub(" ", node_options or "").split())


def openclaw_env():
    """Environment for every OpenClaw subprocess (spec §5.3 + B8: no heap cap for doctor/CLI)."""
    p = paths()
    env = {k: v for k, v in os.environ.items()
           if k not in ENV_REMOVE and not k.startswith("OPENCLAW_UPDATE_") and not k.startswith("OPENCLAW_SKIP_")}
    env.update({
        "HOME": str(p["CONFIG_ROOT"]),
        "OPENCLAW_CONFIG_PATH": str(p["CONFIG_PATH"]),
        "OPENCLAW_WORKSPACE_DIR": str(p["WORKSPACE"]),
        "OPENCLAW_NO_RESPAWN": "1",
        "OPENCLAW_NO_AUTO_UPDATE": "1",
        "OPENCLAW_SUPERVISOR_MODE": "external",
        "OPENCLAW_SERVICE_REPAIR_POLICY": "external",
        "NO_COLOR": "1",
        "FORCE_COLOR": "0",
    })
    opts = strip_heap_cap(env.get("NODE_OPTIONS", ""))
    if opts:
        env["NODE_OPTIONS"] = opts
    else:
        env.pop("NODE_OPTIONS", None)
    return env


# --- redaction --------------------------------------------------------------------------

_SECRET_KEY = r"[A-Za-z0-9_.-]*(?:token|secret|password|apikey|api_key|bottoken)[A-Za-z0-9_.-]*|[A-Za-z0-9_.-]*key"
_REDACT_RES = [
    (re.compile(r'("(?:' + _SECRET_KEY + r')"\s*:\s*)"(?:[^"\\]|\\.)*"', re.I), r'\1"***"'),
    (re.compile(r"\b((?:" + _SECRET_KEY + r")=)[^\s&\"']+", re.I), r"\1***"),
    (re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 ***"),
    (re.compile(r"sk-[A-Za-z0-9_-]{10,}"), "***"),
    (re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"), "***"),
    (re.compile(r"\b[A-Za-z0-9_-]{40,}\b"), "***"),
]


def redact_text(s):
    if not s:
        return s
    for rx, rep in _REDACT_RES:
        s = rx.sub(rep, s)
    return s


# --- subprocess runner -------------------------------------------------------------------

class RunResult(tuple):
    """(rc, duration_s) plus attributes timed_out / stopped / error."""

    def __new__(cls, rc, duration, timed_out=False, stopped=False, error=None):
        self = super().__new__(cls, (rc, duration))
        self.timed_out = timed_out
        self.stopped = stopped
        self.error = error
        return self

    @property
    def rc(self):
        return self[0]

    @property
    def duration(self):
        return self[1]


def _killpg(pgid, sig):
    try:
        os.killpg(pgid, sig)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _group_alive(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def run_process(argv, *, timeout, log_path, stop_event=None, kill_grace=30, stop_grace=None, env=None,
                cwd=None, stdout_path=None, on_tick=None, tick=1.0):
    """Run argv in its own session; stdout/stderr appended to files (never a pipe).

    - timeout (s, None = unlimited): SIGTERM to the process group, `kill_grace` s, SIGKILL.
    - stop_event set: SIGTERM, `stop_grace` s (default kill_grace), SIGKILL.
    - on_tick(elapsed_s) is called about every `tick` seconds while the process runs.
    Returns RunResult(rc, duration_s); rc < 0 means killed by a signal; rc 127 = could not start.
    """
    stop_grace = kill_grace if stop_grace is None else stop_grace
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if cwd is None:
        root = paths()["CONFIG_ROOT"]
        cwd = str(root) if root.is_dir() else None
    start = time.monotonic()
    with open(log_path, "ab") as log:
        out = open(stdout_path, "ab") if stdout_path else log
        try:
            try:
                proc = subprocess.Popen([str(a) for a in argv], stdin=subprocess.DEVNULL, stdout=out, stderr=log,
                                        cwd=cwd, env=env, start_new_session=True)
            except OSError as exc:
                log.write(f"[oc] could not start {argv[0]}: {exc}\n".encode())
                return RunResult(127, 0.0, error=str(exc))
            pgid = proc.pid
            timed_out = stopped = False
            kill_at = None
            try:
                while True:
                    try:
                        rc = proc.wait(timeout=tick)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    now = time.monotonic()
                    if on_tick is not None:
                        on_tick(now - start)
                    if stop_event is not None and stop_event.is_set() and not stopped:
                        stopped = True
                        _killpg(pgid, signal.SIGTERM)
                        deadline = now + stop_grace
                        kill_at = deadline if kill_at is None else min(kill_at, deadline)
                    elif kill_at is None and timeout is not None and now - start >= timeout:
                        timed_out = True
                        _killpg(pgid, signal.SIGTERM)
                        kill_at = now + kill_grace
                    if kill_at is not None and now >= kill_at:
                        _killpg(pgid, signal.SIGKILL)
                        kill_at = float("inf")
            except BaseException:
                _killpg(pgid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _killpg(pgid, signal.SIGKILL)
                    proc.wait()
                raise
            # Leftover group members (e.g. npm children) must not keep writing state.
            if _group_alive(pgid):
                _killpg(pgid, signal.SIGTERM)
                for _ in range(50):
                    if not _group_alive(pgid):
                        break
                    time.sleep(0.1)
                _killpg(pgid, signal.SIGKILL)
            return RunResult(rc, time.monotonic() - start, timed_out, stopped)
        finally:
            if out is not log:
                out.close()


def run_oc(args, *, timeout, log_path, stop_event=None, kill_grace=30, env=None, stdout_path=None, cwd=None,
           on_tick=None, stop_grace=None):
    """Run the bundled OpenClaw CLI as [node, ENTRY, *args] (never through the wrapper)."""
    pkg = runtime_package()
    argv = [pkg["node"] or "node", pkg["entry"], *args]
    return run_process(argv, timeout=timeout, log_path=log_path, stop_event=stop_event, kill_grace=kill_grace,
                       stop_grace=stop_grace, env=env if env is not None else openclaw_env(), cwd=cwd,
                       stdout_path=stdout_path, on_tick=on_tick)


def parse_json_output(text):
    """json.loads the whole text; else the last line starting with '{' (spec §5.4). None on failure."""
    if text is None:
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    for line in reversed(text.splitlines()):
        if line.lstrip().startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                return None
    return None


def new_stop_event():
    return threading.Event()
