#!/usr/bin/env python3
"""
Apply the add-on's patches to the installed OpenClaw dist (image build only; stdlib, Python 3.11).

usage: oc_dist_patch.py [--no-node-check] PKG_DIR PATCH_DIR

PATCH_DIR/manifest.json names the OpenClaw version the patches are for and, per patch, the dist
file, its sha256 before and after, and a unified diff (one file per diff, paths a/<file> b/<file>):

  {"openclaw_version": "2026.10.4",
   "patches": [{"name": "...", "file": "dist/x-HASH.mjs", "region": "//#region src/....ts",
                "stock_sha256": "...", "patched_sha256": "...", "diff": "x.patch"}]}

Every check fails the build instead of skipping a patch: another OpenClaw version, a missing or
re-packed file, a region that is not in exactly that one file, a hunk whose context is not at the
stated line (no offset, no fuzz), or a result that is not byte-identical to patched_sha256.
OpenClaw's content inventory (dist/postinstall-content-inventory.json) is updated for the patched
files and then re-checked as a whole, the way OpenClaw compares it (path, sha256, size, exec bit).
"""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys

INVENTORY = "dist/postinstall-content-inventory.json"
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class PatchError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_rel(rel):
    """A package-relative path below dist/, without .. or absolute parts."""
    if not isinstance(rel, str) or not rel.startswith("dist/") or rel.startswith("/") \
            or any(p in ("", ".", "..") for p in rel.split("/")):
        raise PatchError(f"unsafe dist path {rel!r}")
    return rel


def read_regular(path):
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise PatchError(f"{path} is not a regular file")
    with open(path, "rb") as f:
        return f.read(), st


def parse_diff(text, rel):
    """The hunks of a single-file unified diff for a/<rel> -> b/<rel>."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    heads = [i for i, ln in enumerate(lines) if ln.startswith("--- ")]
    if len(heads) != 1 or heads[0] + 1 >= len(lines) or not lines[heads[0] + 1].startswith("+++ "):
        raise PatchError(f"diff for {rel} must hold exactly one file")
    old_name = lines[heads[0]][4:].split("\t")[0]
    new_name = lines[heads[0] + 1][4:].split("\t")[0]
    if old_name != f"a/{rel}" or new_name != f"b/{rel}":
        raise PatchError(f"diff names {old_name} -> {new_name}, expected a/{rel} -> b/{rel}")
    hunks, i = [], heads[0] + 2
    while i < len(lines):
        m = HUNK_RE.match(lines[i])
        if not m:
            raise PatchError(f"unexpected diff line {i + 1}: {lines[i][:60]!r}")
        old_start, old_len = int(m.group(1)), int(m.group(2) or "1")
        new_len = int(m.group(4) or "1")
        old, new, i = [], [], i + 1
        while i < len(lines) and not lines[i].startswith("@@"):
            ln = lines[i]
            if ln.startswith("\\"):
                raise PatchError(f"diff for {rel}: missing final newlines are not supported")
            tag, body = ln[:1], ln[1:]
            if tag == " ":
                old.append(body)
                new.append(body)
            elif tag == "-":
                old.append(body)
            elif tag == "+":
                new.append(body)
            else:
                raise PatchError(f"unexpected diff line {i + 1}: {ln[:60]!r}")
            i += 1
        if len(old) != old_len or len(new) != new_len:
            raise PatchError(f"diff for {rel}: hunk at -{old_start} has wrong line counts")
        hunks.append((old_start, old, new))
    if not hunks:
        raise PatchError(f"diff for {rel} has no hunks")
    return hunks


def apply_hunks(data, hunks, rel):
    """Apply hunks exactly at their stated lines (no offset, no fuzz)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PatchError(f"{rel} is not UTF-8") from exc
    if not text.endswith("\n"):
        raise PatchError(f"{rel} does not end with a newline")
    src = text[:-1].split("\n")
    out, pos = [], 0
    for old_start, old, new in hunks:
        at = old_start - 1 if old else old_start
        if at < pos:
            raise PatchError(f"{rel}: hunks overlap or are out of order at line {old_start}")
        if src[at:at + len(old)] != old:
            raise PatchError(f"{rel}: hunk context does not match at line {old_start}")
        out.extend(src[pos:at])
        out.extend(new)
        pos = at + len(old)
    out.extend(src[pos:])
    return ("\n".join(out) + "\n").encode("utf-8")


def write_like(path, data, mode):
    tmp = path + ".oc-dist-patch.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_manifest(patch_dir):
    with open(os.path.join(patch_dir, "manifest.json"), encoding="utf-8") as f:
        man = json.load(f)
    entries = man.get("patches")
    if not isinstance(man.get("openclaw_version"), str) or not isinstance(entries, list) or not entries:
        raise PatchError("manifest needs openclaw_version and a non-empty patches list")
    seen = set()
    for e in entries:
        for key in ("name", "file", "stock_sha256", "patched_sha256", "diff"):
            if not isinstance(e.get(key), str) or not e[key]:
                raise PatchError(f"manifest entry {e.get('name')!r} lacks {key}")
        safe_rel(e["file"])
        if e["file"] in seen:
            raise PatchError(f"{e['file']} is patched twice")
        seen.add(e["file"])
        if os.path.basename(e["diff"]) != e["diff"]:
            raise PatchError(f"diff name {e['diff']!r} must be a plain file name")
    return man


def region_files(pkg, regions):
    """{region marker line: [dist/*.mjs files containing it]} in one pass over dist/."""
    wanted = {r.encode(): r for r in regions}
    hits = {r: [] for r in regions}
    if not wanted:
        return hits
    dist = os.path.join(pkg, "dist")
    for name in sorted(os.listdir(dist)):
        if not name.endswith(".mjs"):
            continue
        p = os.path.join(dist, name)
        if not stat.S_ISREG(os.lstat(p).st_mode):
            continue
        with open(p, "rb") as f:
            found = {wanted[ln.rstrip(b"\n")] for ln in f if ln.rstrip(b"\n") in wanted}
        for r in found:
            hits[r].append("dist/" + name)
    return hits


def update_inventory(pkg, changed):
    """changed: {rel: (stock_sha, patched_sha, size)}. Rewrite the entries, then re-check all."""
    inv = os.path.join(pkg, INVENTORY)
    raw, st = read_regular(inv)
    data = json.loads(raw)
    if (json.dumps(data, indent=2) + "\n").encode() != raw:
        raise PatchError("content inventory format changed")
    for rel, (stock, patched, size) in changed.items():
        hits = [e for e in data if e.get("path") == rel]
        if len(hits) != 1 or hits[0].get("sha256") != stock:
            raise PatchError(f"unexpected content inventory entry for {rel}")
        hits[0]["sha256"], hits[0]["size"] = patched, size
    write_like(inv, (json.dumps(data, indent=2) + "\n").encode(), stat.S_IMODE(st.st_mode))
    bad = []
    for e in data:
        p = os.path.join(pkg, e["path"])
        try:
            body, est = read_regular(p)
        except (OSError, PatchError):
            bad.append(e["path"])
            continue
        if sha256(body) != e["sha256"] or len(body) != e["size"] \
                or (est.st_mode & 0o111) != (e["mode"] & 0o111):
            bad.append(e["path"])
    if bad:
        raise PatchError("content inventory mismatch: " + ", ".join(bad[:10]))
    return len(data)


def apply_all(pkg, patch_dir, node_check=True, log=print):
    man = load_manifest(patch_dir)
    with open(os.path.join(pkg, "package.json"), encoding="utf-8") as f:
        version = json.load(f).get("version")
    if version != man["openclaw_version"]:
        raise PatchError(f"patches are for OpenClaw {man['openclaw_version']}, installed is {version}: "
                         "re-derive them for this version")
    regions = region_files(pkg, [e["region"] for e in man["patches"] if e.get("region")])
    staged = []
    for e in man["patches"]:
        rel = e["file"]
        path = os.path.join(pkg, rel)
        if e.get("region"):
            hits = regions[e["region"]]
            if hits != [rel]:
                raise PatchError(f"{e['name']}: region {e['region']!r} is in {hits or 'no file'}, expected {rel}")
        data, st = read_regular(path)
        if sha256(data) != e["stock_sha256"]:
            raise PatchError(f"{e['name']}: {rel} is not the stock file (sha256 {sha256(data)})")
        with open(os.path.join(patch_dir, e["diff"]), encoding="utf-8") as f:
            hunks = parse_diff(f.read(), rel)
        new = apply_hunks(data, hunks, rel)
        if sha256(new) != e["patched_sha256"]:
            raise PatchError(f"{e['name']}: patched {rel} has sha256 {sha256(new)}, expected {e['patched_sha256']}")
        staged.append((e, path, new, stat.S_IMODE(st.st_mode)))
    for e, path, new, mode in staged:
        write_like(path, new, mode)
        if node_check:
            subprocess.run(["node", "--check", path], check=True)
        log(f"[oc-dist-patch] {e['name']}: {e['file']} patched")
    n = update_inventory(pkg, {e["file"]: (e["stock_sha256"], e["patched_sha256"], len(new))
                               for e, _p, new, _m in staged})
    log(f"[oc-dist-patch] {len(staged)} file(s) patched for OpenClaw {version}; content inventory updated, "
        f"{n} entries re-checked")


def main(argv):
    node_check = True
    if argv and argv[0] == "--no-node-check":
        node_check, argv = False, argv[1:]
    if len(argv) != 2:
        print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
        return 2
    try:
        apply_all(argv[0], argv[1], node_check=node_check)
    except (PatchError, OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"[oc-dist-patch] FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
