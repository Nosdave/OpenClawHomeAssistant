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
                         (the image's Node binary is recorded next to it in openclaw-node)
  OC_ADDON_OPTIONS_FILE  default /data/options.json (add-on options)
"""

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote as _urlquote

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


def node_query(path, sql, timeout=120, params=(), stop_event=None):
    """Read-only query through node:sqlite (fallback when Python's SQLite cannot read a DB).

    Like query_ro, a database without WAL content is opened as an immutable URI, so SQLite creates
    no -wal/-shm file next to it. A set stop_event stops the query (raises Stopped).
    Returns a list of dicts (column -> value). Raises NodeQueryError.
    """
    node = image_node()
    if not node:
        raise NodeQueryError("node not found")
    location = str(path)
    try:
        wal_has_data = os.path.exists(f"{path}-wal") and os.stat(f"{path}-wal").st_size > 0
    except OSError:
        wal_has_data = True
    if not wal_has_data:
        location = f"file:{_urlquote(os.path.abspath(path))}?mode=ro&immutable=1"
    env = dict(os.environ)
    env.update(OCQ_PATH=location, OCQ_SQL=sql, OCQ_PARAMS=json.dumps(list(params)))
    with tempfile.TemporaryDirectory(prefix="oc-nodeq-") as tmp:
        out_p, err_p = Path(tmp) / "out.json", Path(tmp) / "err.txt"
        res = run_process([node, "--input-type=module", "-e", NODE_QUERY_JS], timeout=timeout, log_path=err_p,
                          stdout_path=out_p, stop_event=stop_event, kill_grace=5, env=env)
        if res.stopped:
            raise Stopped("stop requested")
        if res.timed_out:
            raise NodeQueryError(f"node:sqlite query timed out after {timeout}s")
        if res.error is not None:
            raise NodeQueryError(f"node:sqlite query failed to start: {res.error}")
        if res.rc != 0:
            tail = err_p.read_text(encoding="utf-8", errors="replace").strip().splitlines()[-3:]
            raise NodeQueryError(f"node:sqlite query failed (rc {res.rc}): {' | '.join(tail)}")
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


def json_dumps(obj, indent=2):
    """JSON text plus a newline that always encodes to UTF-8.

    Non-ASCII characters are kept as they are, unless the data holds a lone UTF-16 surrogate
    (Node's JSON.stringify writes "\\ud83d" for a label truncated mid-emoji, which json.loads
    accepts but UTF-8 cannot encode): then everything non-ASCII is written as \\u escapes.
    """
    text = json.dumps(obj, indent=indent, ensure_ascii=False) + "\n"
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = json.dumps(obj, indent=indent, ensure_ascii=True) + "\n"
    return text


def atomic_write_json(path, obj, mode=0o600):
    atomic_write_text(path, json_dumps(obj), mode)


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


def addon_options():
    """The add-on options the Supervisor rendered (/data/options.json; env OC_ADDON_OPTIONS_FILE for
    tests); {} when the file is missing or unreadable."""
    data = load_json_or_none(os.environ.get("OC_ADDON_OPTIONS_FILE") or "/data/options.json")
    return data if isinstance(data, dict) else {}


def glm_thinking_option():
    """Add-on option glm_thinking_levels (gate step G1). Default true, as in config.yaml: the Supervisor
    writes the default into options.json for an option the user never saved."""
    return addon_options().get("glm_thinking_levels", True) is True


# --- gate backup / cleanup options ---------------------------------------------------------

GATE_OPTION_DEFAULTS = {"gate_cleanup_hours": 48, "gate_backup_max_age_hours": 24}
_GATE_INT_RANGES = {"gate_cleanup_hours": (0, 720), "gate_backup_max_age_hours": (1, 168)}


def gate_options():
    """The migration gate's backup/cleanup options from /data/options.json (no environment needed, so this
    works under s6's cleared environment). A missing file means the config.yaml defaults."""
    o = addon_options()
    problems = []
    ints = {}
    for key, (lo, hi) in _GATE_INT_RANGES.items():
        default = GATE_OPTION_DEFAULTS[key]
        v = o.get(key, default)
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            problems.append(f"{key} is not an integer in {lo}..{hi}; using {default}")
            v = default
        ints[key] = v
    return {"cleanup_hours": ints["gate_cleanup_hours"],
            "backup_max_age_hours": ints["gate_backup_max_age_hours"],
            "problems": problems}


def safe_children(root):
    """[(path, lstat)] of a directory's entries, sorted, never following a link (root included) and never raising:
    other add-ons can write /share, and one odd entry (a link with an over-long target) must not break a listing."""
    try:
        if not stat.S_ISDIR(os.lstat(root).st_mode):
            return []
        out = []
        with os.scandir(root) as it:
            for e in it:
                try:
                    out.append((Path(e.path), e.stat(follow_symlinks=False)))
                except OSError:
                    continue
        return sorted(out, key=lambda x: str(x[0]))
    except OSError:
        return []


def safe_files_below(root, name_pred):
    """Regular files <root>/<dir>/<file> with name_pred(file name), through real directories only."""
    return [(f, fst) for d, dst in safe_children(root) if stat.S_ISDIR(dst.st_mode)
            for f, fst in safe_children(d) if stat.S_ISREG(fst.st_mode) and name_pred(f.name)]



# --- Supervisor API (read-only backup check) -------------------------------------------------

S6_TOKEN_FILE = "/run/s6/container_environment/SUPERVISOR_TOKEN"
# The Supervisor's fixed address (supervisor const DOCKER_IPV4_NETWORK_MASK[2]). Connecting to it directly
# keeps the bearer token away from whatever a host_network add-on's resolver answers for "supervisor".
SUPERVISOR_ADDR = ("172.30.32.2", 80)


class SupervisorError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status  # HTTP status, 0 = no connection / timeout / invalid response
        self.message = message


def supervisor_token(path=None):
    """The add-on's Supervisor token. Under s6-overlay run.sh and its children run with a reset environment,
    so the token is read from s6's container environment first; the process environment is the fallback
    (images without s6). None when neither has one."""
    p = path or S6_TOKEN_FILE
    try:
        with open(p, encoding="utf-8") as f:
            t = f.read(4096).strip()
        if _token_ok(t):
            return t
    except (OSError, UnicodeDecodeError):  # unreadable file: fall back to the environment
        pass
    t = (os.environ.get("SUPERVISOR_TOKEN") or "").strip()
    return t if _token_ok(t) else None


def _token_ok(t):
    """A usable bearer token: printable ASCII without whitespace (anything else would break the header)."""
    return bool(t) and len(t) <= 1024 and all(33 <= ord(c) <= 126 for c in t)


def supervisor_get(path, token, base=None, timeout=10, max_bytes=4 * MIB):
    """GET <path> on the Supervisor API and return its `data`. http.client on purpose: no proxy environment,
    no redirects. `base` ("http://host:port", test hook) overrides the fixed address. Errors never carry the
    token or the response body."""
    import http.client
    if base:
        m = re.fullmatch(r"http://([^/:]+)(?::(\d+))?/?", base)
        if not m:
            raise SupervisorError(0, "invalid Supervisor base URL")
        host, port = m.group(1), int(m.group(2) or 80)
    else:
        host, port = SUPERVISOR_ADDR
    if not _token_ok(token or ""):
        raise SupervisorError(0, "invalid Supervisor token")
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    deadline = time.monotonic() + 3 * timeout  # overall limit: a slow drip never keeps the precheck waiting

    held = {}

    def cut_off():  # a read blocked on a dripping socket returns once the socket is shut down
        sock = held.get("sock")  # kept here: http.client drops conn.sock after a "Connection: close" reply
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
    timer = threading.Timer(3 * timeout, cut_off)
    timer.daemon = True
    timer.start()
    try:
        if hasattr(conn, "connect"):
            conn.connect()
        held["sock"] = getattr(conn, "sock", None)
        conn.request("GET", path, headers={"Authorization": f"Bearer {token}", "Host": "supervisor",
                                           "Accept": "application/json"})
        resp = conn.getresponse()
        chunks, n = [], 0
        while n <= max_bytes:
            if time.monotonic() > deadline:
                raise TimeoutError("response not complete in time")
            b = resp.read(min(64 * 1024, max_bytes + 1 - n))
            if not b:
                break
            chunks.append(b)
            n += len(b)
        body = b"".join(chunks)
        status = resp.status
    except (OSError, http.client.HTTPException) as exc:
        raise SupervisorError(0, f"{type(exc).__name__}: {redact_text(str(exc))[:120]}") from None
    except (ValueError, UnicodeError):  # e.g. an invalid header value; the text could carry the token
        raise SupervisorError(0, "invalid request") from None
    finally:
        timer.cancel()
        conn.close()
    if time.monotonic() > deadline:
        raise SupervisorError(0, "TimeoutError: response not complete in time")
    if status != 200:
        raise SupervisorError(status, f"HTTP {status}")
    if len(body) > max_bytes:
        raise SupervisorError(0, "response too large")
    try:
        obj = json.loads(body)
    except (ValueError, RecursionError):
        raise SupervisorError(0, "invalid JSON response") from None
    if not isinstance(obj, dict) or obj.get("result") != "ok" or not isinstance(obj.get("data"), dict):
        raise SupervisorError(0, "unexpected response")
    return obj["data"]


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

def image_node():
    """The image's Node binary, recorded at build time in openclaw-node next to the entry file.

    A Homebrew `node` may come first on PATH; OpenClaw must still run on the Node the image
    checked. Falls back to PATH when the record is missing or not executable.
    """
    entry_file = os.environ.get("OC_ADDON_ENTRY_FILE") or DEFAULT_ENTRY_FILE
    try:
        with open(os.path.join(os.path.dirname(entry_file), "openclaw-node"), encoding="utf-8") as f:
            node = f.readline().strip()
    except OSError:
        node = ""
    if node and os.path.isfile(node) and os.access(node, os.X_OK):
        return node
    return shutil.which("node")


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
    return {"version": version, "entry": entry, "pkg_dir": pkg_dir, "node": image_node(),
            "schema_state": s, "schema_agent": a}


# What the bundled OpenClaw does, by the first release with that behaviour. Every gate check for OpenClaw
# 2026.10.5 and later asks runtime_caps() instead of comparing versions itself; on 2026.10.4 every capability is
# off and the gate behaves as in 0.5.94-full4. Entries: (name, first runtime with the behaviour above it).
RUNTIME_CAPS = (
    # doctor refuses retired runtime JSON files it has not imported (openclaw/openclaw#165402)
    ("runtime_files_retired", (2026, 10, 5, 0)),
    # the sandbox container/browser registries are retired files too (#164669)
    ("sandbox_registry_retired", (2026, 10, 5, 0)),
    # config validation refuses api "openai-codex-responses" and the extension driver's cdpUrl (d7f9ebd8de66)
    ("config_api_cdpurl_retired", (2026, 10, 5, 0)),
    # an empty plugins.installs {} is no longer refused; doctor removes it (#173851, 10.6-10.9; main line 10.10)
    ("empty_installs_tolerated", (2026, 10, 6, 0)),
    # doctor retires the Skill Workshop proposal tables (keeps only pending/quarantined drafts as files)
    ("retires_skill_proposals", (2026, 10, 10, 0)),
    # a cron agent turn without a recorded inference account stops at a stored-profile fallback (#192195)
    ("cron_refusal", (2026, 10, 10, 0)),
    # the gateway skips held stores of agents that are not configured instead of failing on them
    ("held_store_skip", (2026, 10, 10, 0)),
    # open issue openclaw/openclaw#191847: the 512 MB SQLite worker runs out of memory on large sessions
    # (precheck information only: largest agent database, biggest session)
    ("large_session_oom_issue", (2026, 10, 10, 0)),
    # doctor keeps an invalid heartbeat.activeHours window instead of removing it (#186305) and, with #187192,
    # then exits 1 ("Doctor blocked; required repairs remain incomplete."): the precheck holds on it first
    ("heartbeat_hours_kept", (2026, 11, 1, 0)),
    # doctor records the cron inference accounts itself (#172792; 2026.11.5-beta.1 parses as 2026.11.5)
    ("cron_doctor_migration", (2026, 11, 5, 0)),
)
CAP_NAMES = tuple(n for n, _v in RUNTIME_CAPS)
# Build-time record (Dockerfile): {"openclaw_version": ..., <cap>: true|false} for capabilities the image can
# prove by a dist grep (e.g. a backported doctor step the version table cannot know).
FEATURES_FILE = "/usr/local/lib/oc-addon/openclaw-features.json"


def runtime_features(version):
    """The build-time capability record, only when it was written for exactly this OpenClaw `version`."""
    data = load_json_or_none(os.environ.get("OC_ADDON_FEATURES_FILE") or FEATURES_FILE)
    if not isinstance(data, dict) or not isinstance(version, str) or data.get("openclaw_version") != version:
        return {}
    return {k: v for k, v in data.items() if k in CAP_NAMES and isinstance(v, bool)}


def runtime_caps(pkg):
    """{capability: bool} of the bundled OpenClaw (`pkg`: runtime_package() or a version string).

    The version table RUNTIME_CAPS is the floor; the image's record (runtime_features) can only switch a
    capability on, so a reworded dist string never turns a check off. Unknown versions give all False.
    Never raises."""
    version = pkg.get("version") if isinstance(pkg, dict) else pkg
    v = version_tuple(version)
    caps = {name: bool(v and v >= since) for name, since in RUNTIME_CAPS}
    for name, on in runtime_features(version).items():
        caps[name] = caps[name] or on
    return caps


ENV_REMOVE = {
    "OPENCLAW_COMPATIBILITY_HOST_VERSION", "OPENCLAW_CONTAINER", "INVOCATION_ID", "JOURNAL_STREAM",
    "SYSTEMD_EXEC_PID", "OPENCLAW_SYSTEMD_UNIT", "OPENCLAW_SERVICE_MARKER", "OPENCLAW_SERVICE_KIND",
    "OPENCLAW_LAUNCHD_LABEL", "NODE_COMPILE_CACHE",
    # 2026.10: a host lifeline on stdin would stop a background gateway at once. The NOCOW switch only gates
    # doctor's SQLite NOCOW rewrite during `openclaw update`; a standalone doctor --fix rewrites stores on btrfs
    # without NOCOW whatever it says (doctor-health in 2026.10.2 to 10.4).
    "OPENCLAW_GATEWAY_HOST_LIFELINE", "OPENCLAW_DOCTOR_SQLITE_NOCOW_REPAIR",
    # the add-on's Supervisor credentials are for the gate's read-only backup check only
    "SUPERVISOR_TOKEN", "HASSIO_TOKEN",
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

# Every key pattern starts at the beginning of a run of word characters, "." and "-" (a lookbehind, not \b) and
# reads the run once: with \b each "-" or "." of a long run (base64url, a dashed id) started a new scan of the rest
# of the run, quadratic (15 kB took seconds; a 16 MiB Skill Workshop file never finished).
# _SECRET_KEY: a key containing token/secret/password/apikey anywhere, or ending in "key" (JSON and key=value forms)
_SECRET_KEY = (r"(?<![A-Za-z0-9_.-])(?=[A-Za-z0-9_.-]*?(?:token|secret|password|apikey|api_key)"
               r"|[A-Za-z0-9_.-]*?key(?![A-Za-z0-9_.-]))[A-Za-z0-9_.-]*+")
# A key that names a secret, for the "key: value" / "key = value" rule below. It ends in one of:
# - token, secret, password, passwd, passphrase, passcode, "API key" (also api-key, x-api-key, botToken,
#   db_password), Passwort, Kennwort, API-Schlüssel, wachtwoord, contraseña, and private, secret, access, signing,
#   encryption, master or client key (AWS_SECRET_ACCESS_KEY, secret_key, PrivateKey), after any prefix
#   (WLAN-Passwort, Routerkennwort);
# - pwd, senha, hasło, парола, пароль, "mot de passe" as a word of their own, after "_", "." or "-" (MYSQL_PWD) or
#   in camelCase (dbPwd); never inside a word (OLDPWD, resenha);
# - pass the same way (SMTP_PASS, smtp.pass, smtpPass, "pass: x", "user: a, pass: b", "smtp pass: x", "user=bob
#   pass=x"), but not after the words of OpenClaw's own "<word> pass:" texts ("first pass: ...", "one more pass:
#   ...", "convergence pass: ..."; _PASS_NOT_AFTER), and not in bypass or compass.
# The keyword must end the key: maxTokens, passed, password_hint, pinned are no secret names.
_LONG_SECRET_WORDS = (r"token|secret|password|passwd|passwort|kennwort|pass[ _-]?phrase|pass[ _-]?code|wachtwoord"
                      r"|contrase(?:ñ|n)a|api[ _-]?key|api[ _-]?schl(?:ü|ue)ssel"
                      r"|(?:private|secret|access|signing|encryption|master|client)[ _-]?key")
_IN_KEY = r"(?<=[_.-])|(?<=(?-i:[a-z0-9]))(?=(?-i:P))"  # after a separator, or camelCase (dbPwd, simPin)
_WORD_START = r"(?:" + _IN_KEY + r"|(?<![\w.-]))"
# the words before "pass" in OpenClaw's own texts (2026.10.4 to 2026.11.1: "one more pass:", "would pass:",
# "convergence pass:", "held pass:") and in the gate's ("doctor pass"), plus ordinals
_PASS_NOT_AFTER = ("first", "second", "third", "fourth", "next", "last", "final", "more", "another", "would", "held",
                   "convergence", "doctor", "deletion", "cleanup")
_SECRET_WORD = (r"[\w.-]*?(?:" + _LONG_SECRET_WORDS
                + r"|" + _WORD_START + r"(?:pwd|senha|has[łl]o|парола(?:та)?|пароль|mot[ _-]de[ _-]passe)"
                + r"|(?:" + _IN_KEY + r"|(?<![\w.-])" + "".join(f"(?<!{w} )" for w in _PASS_NOT_AFTER) + r")pass)")
# a PIN (pin, PIN-Code, SIM-PIN, wifi_pin, simPin, PUK): only a value of 3 to 12 digits counts as one; OpenClaw's
# logs use "pin" for version and TLS pins ("dependency pin: name@1.2.3", "pin=true")
_PIN_WORD = r"[\w.-]*?" + _WORD_START + r"(?:pin(?:[ _-]?(?:code|nummer|number))?|puk)"
# between key and value: ":" or "=" (not "==", "::"), blanks, a quote or Markdown emphasis that closes the key
# (**Passwort:** x, `token`: x, "apiKey": x), and at most one line break (YAML "password:" + indented value)
_KV_SEP = (r"(?:\*\*?|__?|`)?[\"']?[^\S\r\n]*+[:=](?![:=])[^\S\r\n]*+(?:(?:\*\*?|__?)(?=\s)[^\S\r\n]*+)?"
           r"(?:\r?\n[^\S\r\n]*+)?")
# The value of a secret key, hidden whole (before, only its first word: "*** horse battery"):
# - a value in "double", 'single' or `back` quotes up to its closing quote (the quotes stay; YAML's '' inside
#   'single' quotes is part of the value);
# - else up to the end of the line, but not past: a comma or semicolon before a blank or a quote, a ")", "]" or "}"
#   that closes a bracket opened before the value, a sentence-final "." (also before a blank, a closing bracket or
#   a quote), a blank before "#" (comment) or "|" (table cell), "&name=" (next query parameter) or a blank before
#   "name=", "Name: " or "--flag" (next field: "password=x reason=y", "Passwort: 4711 Benutzer: admin"); a bracket
#   pair inside the value, also nested once, is part of it (abc(1), {{ ref }});
# - the value of a command-line flag (--token=x, --passwort=x) is one word: a blank ends it;
# - a bare true, false, null, undefined or none is no secret ("pass": true, apiKey: undefined stay readable).
_KV_VALUE = (r"(?P<v>(?=\S)(?!(?:true|false|null|undefined|none)[^\S\r\n]*+(?:[,;)\]}#|\r\n]|\Z))"
             r"(?:\"(?:[^\"\\\n]|\\.)++\"(?!\w)|'(?:[^'\\\n]|\\.|'')++'(?!\w)|`[^`\n]++`(?!\w)"
             r"|(?:[^\s()\[\]{}.,;&\"']"
             r"|(?:\.|[,;](?![\"'])|[\"'])++(?=[^\s.,;\"')\]}])"
             r"|&(?![\w.-]++=)"
             r"|\((?:(?:[^()\n]|\([^()\n]*+\))*+\))?|\[(?:(?:[^\[\]\n]|\[[^\[\]\n]*+\])*+\])?"
             r"|\{(?:(?:[^{}\n]|\{[^{}\n]*+\})*+\})?"
             r"|(?(flag)(?!)|[^\S\r\n]++(?![#|]|--\w|[\w.-]++(?:=|:\s|:\Z))))++))")
# "Passwort ist 4711", "the password is 'correct horse'", "set the password to hunter2": a password word, a verb,
# then a value in quotes, or one word that contains a digit ("password is configured", "password is required" stay
# readable); with a colon after the verb ("Das Passwort lautet: Sommer 2024") the whole value (_KV_VALUE)
_PROSE_WORD = (r"[\w.-]*?(?:password|passwd|passwort|kennwort|pass[ _-]?phrase|pass[ _-]?code|wachtwoord"
               r"|contrase(?:ñ|n)a)|(?<![\w.-])(?:senha|has[łl]o|парола(?:та)?|пароль|mot de passe)")
_PROSE_VERB = r"(?:is|was|ist|war|lautet|heißt|heisst|to|auf|est|es|é|jest|е)"
_PROSE_VALUE = (r"(?P<v>\"[^\"\n]*\"|'[^'\n]*'|`[^`\n]*`|„[^“”\n]*[“”]|“[^”\n]*”|«[^»\n]*»"
                r"|(?=[^\s,;()\[\]{}\"'`]*?\d)(?:[^\s,;()\[\]{}\"'`.!?:]|[.!?:]++(?=[^\s,;()\[\]{}\"'`.!?:]))++"
                r"(?=[.!?:]*+(?:[\s,;)\]}\"'`]|\Z)))")


def _pem_redact(m):
    return f"-----BEGIN {m.group(1)}-----***" + (f"-----END {m.group(1)}-----" if m.group(2) else "")


def _kv_redact(m):
    """key + separator + *** in place of the value; quotes around it and blanks after it stay."""
    v = m.group("v")
    core = v.rstrip()
    q = core[0] if len(core) > 1 and core[0] in "\"'`„“«" else ""
    end = core[-1] if q and core[-1] in "\"'`“”»" else ""
    return m.group("k") + m.group("s") + q + "***" + end + v[len(core):]


# Long standalone tokens. A run next to "/" or "." (path segment, file name such as
# openclaw.sqlite.<uuid>.bak or npm/projects/<hash>/) is not a token; a sentence-final "." is.
_LONG_TOKEN_RULE = (re.compile(r"(?<![A-Za-z0-9_/.-])[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_/-])(?!\.[A-Za-z0-9_-])"), "***")
_REDACT_RES = [
    (re.compile(r"AGE-SECRET-KEY-1[0-9A-Za-z]{20,}"), "AGE-SECRET-KEY-***"),
    # the formats of OpenClaw's own literal-secret check (LITERAL_SECRET_PATTERN, skills/security/scan-evidence.ts),
    # before the rules below cut them apart: PEM private keys (the whole body, also of a block without its END
    # line; "+" and "/" split the base64 into runs too short for the long-token rule), Google API keys, Slack and
    # GitHub tokens
    # (the body up to the matching END line, but never past the next BEGIN line: each BEGIN without its END reads
    # only up to the next one, linear; before, each read to the end of the text, quadratic)
    (re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----"
                r"(?:(?:(?!-----(?:BEGIN |END \1-----)).)*+(-----END \1-----)|[A-Za-z0-9+/=\s\\]*)", re.S),
     _pem_redact),
    (re.compile(r"\b(?:AIza[0-9A-Za-z_-]{35}|xox[baprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}"
                r"|github_pat_[A-Za-z0-9_]{20,})(?![A-Za-z0-9_-])"), "***"),
    (re.compile(r'("' + _SECRET_KEY + r'"\s*:\s*)"(?:[^"\\]|\\.)*"', re.I), r'\1"***"'),
    # key=value (URL query, env, logfmt): one word, not past "&", a quote, a closing bracket or a final "." or ","
    (re.compile(r"(" + _SECRET_KEY + r"=)(?:[^\s()\[\]{}.,;&\"']|[.,;]++(?=[^\s()\[\]{}.,;&\"'])"
                r"|\((?:[^()\s]*+\))?|\[(?:[^\[\]\s]*+\])?|\{(?:[^{}\s]*+\})?)++", re.I), r"\1***"),
    # YAML block scalar under a secret key ("password: |", "private_key: >-" and the lines below it indented deeper
    # than the key): the indicator and those lines become one "***" (before the next rule hides the indicator alone)
    (re.compile(r"(?m)^(?P<h>(?P<i>[^\S\r\n]*+)(?:-[^\S\r\n]++)?[\"']?(?<![\w.-])" + _SECRET_WORD
                + r"[\"']?[^\S\r\n]*+:[^\S\r\n]++)[|>][1-9+-]{0,2}+[^\S\r\n]*+(?:#[^\r\n]*+)?"
                r"(?:\r?\n(?:(?P=i)[^\S\r\n]++\S[^\r\n]*+|[^\S\r\n]*+(?=\r?\n)))++", re.I),
     lambda m: m.group("h") + "***"),
    # token: value / apiKey: 'value' / x-api-key: value / Passwort: value (YAML, .env, JS object inspection, HTTP
    # headers, Markdown, prose): the whole value (_KV_VALUE)
    (re.compile(r"(?<![\w.-])(?P<k>(?P<flag>-)?" + _SECRET_WORD + r")(?P<s>" + _KV_SEP + r")" + _KV_VALUE, re.I),
     _kv_redact),
    # PIN: 1234, SIM-PIN = '0000', **PIN-Code:** 4711 (digits only)
    (re.compile(r"(?<![\w.-])(?P<k>" + _PIN_WORD + r")(?P<s>" + _KV_SEP + r")"
                r"(?P<v>(?P<q>[\"'`]?)\d{3,12}(?P=q)(?![.,:/@-]?\w))", re.I), _kv_redact),
    # Das Passwort lautet: Sommer 2024 / the password is: correct horse (verb and colon): the whole value; the group
    # "flag" never takes part (_KV_VALUE asks for it)
    (re.compile(r"(?<![\w.-])(?P<flag>(?!))?(?P<k>" + _PROSE_WORD + r")(?P<s>[^\S\r\n]++" + _PROSE_VERB
                + r":[^\S\r\n]*+)" + _KV_VALUE, re.I), _kv_redact),
    # Das Passwort ist 4711 / the password is "correct horse" / set the password to hunter2
    (re.compile(r"(?<![\w.-])(?P<k>" + _PROSE_WORD + r")(?P<s>[^\S\r\n]++" + _PROSE_VERB + r":?[^\S\r\n]++)"
                + _PROSE_VALUE, re.I), _kv_redact),
    # --token <value>, --password <value>, --api-key <value>
    (re.compile(r"(?i)(--(?:token|password|secret|api[-_]?key)\s+)(?!-)\S+"), r"\1***"),
    # URL userinfo: scheme://user:password@host, also with an empty user (redis://:password@host)
    (re.compile(r"://[^/\s:@]*:[^@\s/]+@"), "://***@"),
    (re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 ***"),
    # Authorization: <any other scheme> <credentials> (Token, Bot, Digest, ...; also Proxy-Authorization, "quoted")
    (re.compile(r"(?i)(\bAuthorization[\"']?:[^\S\r\n]*+[\"']?[A-Za-z][\w-]*+)[^\S\r\n]++[^\s\"'`,;]{8,}"),
     r"\1 ***"),
    (re.compile(r"sk-[A-Za-z0-9_-]{10,}"), "***"),
    (re.compile(r"(?i)\bbot\d{6,12}:[A-Za-z0-9_-]{30,}"), "bot***"),  # Telegram Bot API URL form
    (re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"), "***"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "***"),  # JWT
    _LONG_TOKEN_RULE,
]


# the key names of the "key: value" and PIN rules, for a redaction per JSON value (the Skill Workshop export hides
# the value under such a key whole: a fullmatch of SECRET_NAME_RE, or of PIN_NAME_RE with a value of 3 to 12 digits)
SECRET_NAME_RE = re.compile(_SECRET_WORD, re.I)
PIN_NAME_RE = re.compile(_PIN_WORD, re.I)
PIN_VALUE_RE = re.compile(r"\d{3,12}")


def redact_text(s):
    if not s:
        return s
    for rx, rep in _REDACT_RES:
        s = rx.sub(rep, s)
    return s


def redact_text_counted(s, long_tokens=True):
    """(redact_text(s), number of replacements): the same rules, for exports that report what they hid.
    long_tokens=False leaves out the rule for long standalone tokens (an identifier such as a 121-character
    Skill Workshop proposal id); every other rule still applies."""
    if not s:
        return s, 0
    total = 0
    for rule in _REDACT_RES:
        if not long_tokens and rule is _LONG_TOKEN_RULE:
            continue
        s, n = rule[0].subn(rule[1], s)
        total += n
    return s, total


_PEM_BEGIN_RE = re.compile(r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?)-----")
_PEM_MAX_LINES = 200  # a PEM key of 16384 bits has about 200 lines; a BEGIN without END hides no more than that
# a line that ends in a separator or a flag/scheme whose value may stand alone on the next line
_OPEN_END_RE = re.compile(r"(?:[:=]|--[\w-]+|\b(?:Bearer|Basic))[\"'`*_]*+[^\S\r\n]*+$", re.I)
_BLOCK_HEAD_RE = re.compile(r"^(?P<i>[^\S\r\n]*+)(?:-[^\S\r\n]++)?[\"']?(?<![\w.-])" + _SECRET_WORD
                            + r"[\"']?[^\S\r\n]*+:[^\S\r\n]++[|>][1-9+-]{0,2}+[^\S\r\n]*+(?:#.*)?$", re.I)


class LineRedactor:
    """redact_text for a text read line by line (the [doctor] lines of the add-on log, `oc-upgrade log`), with the
    rules that span lines: a PEM private key block (every line from BEGIN up to the matching END, at most
    _PEM_MAX_LINES), a YAML block scalar under a secret key (the lines indented deeper than its key), and a value
    alone on the line after its key ("password:" and the value below). Feed the lines in order to one instance."""

    def __init__(self):
        self.prev = None  # the previous line when it ends open (_OPEN_END_RE)
        self.pem_end = None  # the END line of an open PEM block
        self.pem_left = 0
        self.block = None  # the indentation of an open block scalar's key

    def line(self, s):
        """One line (no line break), redacted."""
        if self.pem_end is not None:
            i = s.find(self.pem_end)
            if i >= 0:
                end, self.pem_end = self.pem_end, None
                return ("***" if s[:i].strip() else s[:i]) + end + self._plain(s[i + len(end):])
            self.pem_left -= 1
            if self.pem_left >= 0:
                return "***" if s.strip() else s
            self.pem_end = None
        if self.block is not None:
            if not s.strip():
                return s
            ind = len(s) - len(s.lstrip())
            if ind > self.block:
                return s[:ind] + "***"
            self.block = None
        return self._plain(s)

    def _plain(self, s):
        if self.prev is not None and s.strip():
            r = redact_text(self.prev + "\n" + s)
            out = r.split("\n", 1)[1] if r.count("\n") == 1 else "***"
        else:
            out = redact_text(s)
        self.prev = s if _OPEN_END_RE.search(s) else None
        m = _BLOCK_HEAD_RE.match(s)
        if m:
            self.block, self.prev = len(m.group("i")), None
        begins = list(_PEM_BEGIN_RE.finditer(s))
        if begins and s.find(f"-----END {begins[-1].group(1)}-----", begins[-1].end()) < 0:
            self.pem_end, self.pem_left, self.prev = f"-----END {begins[-1].group(1)}-----", _PEM_MAX_LINES, None
        return out


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


def _proc_stat(pid):
    """(state, ppid, pgrp, session, starttime) from /proc/<pid>/stat, or None (gone, or no /proc)."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
    except OSError:
        return None
    try:
        rest = data[data.rindex(b")") + 2:].split()  # the command name may hold spaces and parentheses
        return rest[0].decode("ascii", "replace"), int(rest[1]), int(rest[2]), int(rest[3]), int(rest[19])
    except (ValueError, IndexError):
        return None


def _proc_table():
    """{pid: _proc_stat} of every process /proc shows ({} without /proc)."""
    out = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return out
    for n in names:
        if n.isdigit():
            st = _proc_stat(int(n))
            if st is not None:
                out[int(n)] = st
    return out


def _proc_live(st):
    return st is not None and st[0] not in ("Z", "X")


def _descendants(root, table):
    """{pid: starttime} of the live descendants of `root` in a _proc_table, by parent-pid lineage."""
    kids = {}
    for pid, st in table.items():
        kids.setdefault(st[1], []).append(pid)
    out, todo = {}, list(kids.get(root, []))
    while todo:
        pid = todo.pop()
        if pid in out or not _proc_live(table.get(pid)):
            continue
        out[pid] = table[pid][4]
        todo.extend(kids.get(pid, []))
    return out


def _track_descendants(tracked, root):
    """Add the live descendants of `root` to tracked {pid: starttime} (D10: a child in its own session, such as the
    npm process OpenClaw's doctor starts detached, is reparented away when its parent dies, so the lineage is
    recorded while the parent runs)."""
    for pid, start in _descendants(root, _proc_table()).items():
        tracked.setdefault(pid, start)


def _kill_strays(tracked, grace=5.0):
    """D10: SIGTERM, then after `grace` s SIGKILL, every tracked descendant that still runs (the same start time:
    a reused pid is left alone) and its own descendants; killpg of the child's group does not reach a descendant
    that changed its session or group. Returns the pids signalled."""
    if not tracked:
        return []
    table = _proc_table()
    strays = {pid: start for pid, start in tracked.items()
              if _proc_live(table.get(pid)) and table[pid][4] == start}
    for pid in list(strays):
        for d, start in _descendants(pid, table).items():
            strays.setdefault(d, start)
    if not strays:
        return []

    def alive(pid, start):
        st = _proc_stat(pid)
        return _proc_live(st) and st[4] == start

    def signal_all(sig):
        for pid, start in strays.items():
            if alive(pid, start):
                try:
                    os.kill(pid, sig)
                except (ProcessLookupError, PermissionError):
                    pass
    signal_all(signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and any(alive(p, s) for p, s in strays.items()):
        time.sleep(0.1)
    signal_all(signal.SIGKILL)
    return sorted(strays)


def run_process(argv, *, timeout, log_path, stop_event=None, kill_grace=30, stop_grace=None, env=None,
                cwd=None, stdout_path=None, on_tick=None, tick=1.0):
    """Run argv in its own session; stdout/stderr appended to files (never a pipe).

    - timeout (s, None = unlimited): SIGTERM to the process group, `kill_grace` s, SIGKILL.
    - stop_event set: SIGTERM, `stop_grace` s (default kill_grace), SIGKILL.
    - on_tick(elapsed_s) is called about every `tick` seconds while the process runs.
    - When it has ended (or was killed), whatever is left of its process group is killed, and so are the descendants
      that left the group (another session, e.g. a detached npm child; seen in /proc while argv ran) (D10).
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
            tracked = {}  # D10: {pid: starttime} of its descendants, seen while it runs
            try:
                while True:
                    try:
                        rc = proc.wait(timeout=tick)
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    _track_descendants(tracked, proc.pid)
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
                        _track_descendants(tracked, proc.pid)
                        _killpg(pgid, signal.SIGKILL)
                        kill_at = float("inf")
            except BaseException:
                _track_descendants(tracked, proc.pid)
                _killpg(pgid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    _killpg(pgid, signal.SIGKILL)
                    proc.wait()
                _kill_strays(tracked)
                raise
            # Leftover group members (e.g. npm children) must not keep writing state.
            if _group_alive(pgid):
                _killpg(pgid, signal.SIGTERM)
                for _ in range(50):
                    if not _group_alive(pgid):
                        break
                    time.sleep(0.1)
                _killpg(pgid, signal.SIGKILL)
            # ... nor descendants that left the group (D10: OpenClaw starts npm detached, in its own session)
            strays = _kill_strays(tracked)
            if strays:
                log.write(f"[oc] stopped {len(strays)} leftover descendant process(es) outside its process group "
                          f"(pids {', '.join(map(str, strays[:10]))})\n".encode())
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
