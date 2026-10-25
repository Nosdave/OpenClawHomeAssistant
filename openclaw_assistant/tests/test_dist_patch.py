"""Unit tests for oc_dist_patch (stdlib unittest, Python 3.11)."""

import difflib
import hashlib
import io
import json
import os
import shutil
import sys
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

ADDON = Path(__file__).resolve().parent.parent
if str(ADDON) not in sys.path:
    sys.path.insert(0, str(ADDON))

import oc_dist_patch as P  # noqa: E402

REGION = "//#region src/agents/thing.ts"
STOCK = "\n".join(["import { x } from \"./x-AAAAAAAA.mjs\";", REGION, "const a = {",
                   "\tenabled: true,", "\thalfLifeDays: 30", "};", "function f() {", "\treturn 1;", "}",
                   "//#endregion", "export { a, f };"]) + "\n"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def nl_lines(s):
    """Lines split on "\\n" only (the patcher's line model; str.splitlines also splits on \\x85 etc.)."""
    parts = s.split("\n")
    return [p + "\n" for p in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def udiff(rel, old, new, n=3):
    return "".join(difflib.unified_diff(nl_lines(old), nl_lines(new), f"a/{rel}", f"b/{rel}", n=n))


class DistPatchCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="oc-dist-patch-test-"))
        self.pkg = self.tmp / "pkg"
        (self.pkg / "dist").mkdir(parents=True)
        (self.pkg / "package.json").write_text(json.dumps({"version": "2026.10.4"}))
        self.write("dist/thing-BBBBBBBB.mjs", STOCK)
        self.write("dist/other-CCCCCCCC.mjs", "export const o = 1;\n")
        self.write("dist/tool.js", "#!/usr/bin/env node\n", mode=0o755)
        self.write_ownership()
        self.patches = self.tmp / "patches"
        self.patches.mkdir()
        self.write_inventory()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, text, mode=0o644):
        p = self.pkg / rel
        p.write_text(text)
        os.chmod(p, mode)

    def write_ownership(self, fmt=lambda d: json.dumps(d, separators=(",", ":")) + "\n", stock=None):
        chunks = {"thing-BBBBBBBB.mjs": {"sha256": stock or sha(STOCK.encode()), "extensions": ["x"]},
                  "unrelated-DDDDDDDD.mjs": {"sha256": "3" * 64, "extensions": ["y"]}}
        (self.pkg / P.OWNERSHIP).write_text(fmt({"chunks": chunks}))

    def ownership(self):
        return json.loads((self.pkg / P.OWNERSHIP).read_text())["chunks"]

    def write_inventory(self, fmt=lambda d: json.dumps(d, indent=2) + "\n"):
        entries = []
        for p in sorted((self.pkg / "dist").iterdir()):
            if p.name == "postinstall-content-inventory.json":
                continue
            b = p.read_bytes()
            entries.append({"path": f"dist/{p.name}", "sha256": sha(b), "mode": os.stat(p).st_mode & 0o777,
                            "size": len(b)})
        (self.pkg / P.INVENTORY).write_text(fmt(entries))

    def inventory(self):
        return {e["path"]: e for e in json.loads((self.pkg / P.INVENTORY).read_text())}

    def add_patch(self, new_text, rel="dist/thing-BBBBBBBB.mjs", name="thing", region=REGION, diff=None,
                  patched=None, stock=None, version="2026.10.4", extra=()):
        old = (self.pkg / rel).read_bytes().decode()
        (self.patches / f"{name}.patch").write_text(diff if diff is not None else udiff(rel, old, new_text))
        entry = {"name": name, "file": rel, "stock_sha256": stock or sha(old.encode()),
                 "patched_sha256": patched or sha(new_text.encode()), "diff": f"{name}.patch"}
        if region:
            entry["region"] = region
        man = {"openclaw_version": version, "patches": [entry, *extra]}
        (self.patches / "manifest.json").write_text(json.dumps(man))
        return entry

    def run_patch(self):
        logs = []
        P.apply_all(str(self.pkg), str(self.patches), node_check=False, log=logs.append)
        return logs

    def assert_untouched(self):
        self.assertEqual((self.pkg / "dist/thing-BBBBBBBB.mjs").read_text(), STOCK)
        inv = self.inventory()
        self.assertEqual(inv["dist/thing-BBBBBBBB.mjs"]["sha256"], sha(STOCK.encode()))
        self.assertEqual(self.ownership()["thing-BBBBBBBB.mjs"]["sha256"], sha(STOCK.encode()))
        self.assertEqual(list(self.pkg.glob("dist/*.tmp")), [])


class ApplyTests(DistPatchCase):
    def test_patches_file_and_updates_inventory(self):
        new = STOCK.replace("halfLifeDays: 30", "halfLifeDays: 365")
        self.add_patch(new)
        logs = self.run_patch()
        body = (self.pkg / "dist/thing-BBBBBBBB.mjs").read_bytes()
        self.assertEqual(body, new.encode())
        inv = self.inventory()
        self.assertEqual(inv["dist/thing-BBBBBBBB.mjs"]["sha256"], sha(body))
        self.assertEqual(inv["dist/thing-BBBBBBBB.mjs"]["size"], len(body))
        self.assertEqual(oct(os.stat(self.pkg / "dist/thing-BBBBBBBB.mjs").st_mode & 0o777), "0o644")
        self.assertIn("thing: dist/thing-BBBBBBBB.mjs patched", logs[0])
        self.assertIn("1 file(s) patched for OpenClaw 2026.10.4", logs[-1])
        self.assertEqual(list(self.pkg.glob("dist/*.tmp")), [])
        own = self.ownership()
        self.assertEqual(own["thing-BBBBBBBB.mjs"]["sha256"], sha(body))
        self.assertEqual(own["unrelated-DDDDDDDD.mjs"]["sha256"], "3" * 64)
        own_bytes = (self.pkg / P.OWNERSHIP).read_bytes()
        self.assertEqual(inv[P.OWNERSHIP]["sha256"], sha(own_bytes))

    def test_multi_hunk_and_pure_insertion(self):
        new = STOCK.replace("\tenabled: true,\n", "\tenabled: true,\n\tnote: 1,\n").replace(
            "\treturn 1;", "\treturn 2;")
        self.add_patch(new, diff=udiff("dist/thing-BBBBBBBB.mjs", STOCK, new, n=0))
        self.run_patch()
        self.assertEqual((self.pkg / "dist/thing-BBBBBBBB.mjs").read_text(), new)

    def test_two_files_patched_together(self):
        new = STOCK.replace("halfLifeDays: 30", "halfLifeDays: 365")
        other_new = "export const o = 2;\n"
        (self.patches / "other.patch").write_text(udiff("dist/other-CCCCCCCC.mjs", "export const o = 1;\n", other_new))
        extra = {"name": "other", "file": "dist/other-CCCCCCCC.mjs", "stock_sha256": sha(b"export const o = 1;\n"),
                 "patched_sha256": sha(other_new.encode()), "diff": "other.patch"}
        self.add_patch(new, extra=[extra])
        self.run_patch()
        inv = self.inventory()
        self.assertEqual(inv["dist/other-CCCCCCCC.mjs"]["sha256"], sha(other_new.encode()))
        self.assertEqual(inv["dist/thing-BBBBBBBB.mjs"]["sha256"], sha(new.encode()))
        # other-CCCCCCCC.mjs has no ownership entry: only thing's entry changes
        self.assertEqual(set(self.ownership()), {"thing-BBBBBBBB.mjs", "unrelated-DDDDDDDD.mjs"})

    def test_removed_line_that_looks_like_a_header(self):
        self.write("dist/thing-BBBBBBBB.mjs", STOCK.replace("\treturn 1;", "-- not a header"))
        self.write_ownership(stock=sha((self.pkg / "dist/thing-BBBBBBBB.mjs").read_bytes()))
        self.write_inventory()
        old = (self.pkg / "dist/thing-BBBBBBBB.mjs").read_text()
        new = old.replace("-- not a header", "\treturn 2;")
        self.add_patch(new)
        self.assertIn("\n--- not a header\n", (self.patches / "thing.patch").read_text())
        self.run_patch()
        self.assertEqual((self.pkg / "dist/thing-BBBBBBBB.mjs").read_text(), new)

    def test_lines_with_cr_and_nel_are_ordinary_characters(self):
        old = STOCK.replace("\thalfLifeDays: 30", "\thalfLifeDays: 30 // a\rb\x85c")
        self.write("dist/thing-BBBBBBBB.mjs", old)
        self.write_ownership(stock=sha(old.encode()))
        self.write_inventory()
        new = old.replace("30 //", "365 //")
        self.add_patch(new)
        self.run_patch()
        self.assertEqual((self.pkg / "dist/thing-BBBBBBBB.mjs").read_bytes(), new.encode())

    def test_delete_every_line(self):
        self.add_patch("")
        self.run_patch()
        self.assertEqual((self.pkg / "dist/thing-BBBBBBBB.mjs").read_bytes(), b"")

    def test_empty_patch_list_checks_without_writing(self):
        (self.patches / "manifest.json").write_text(json.dumps({"openclaw_version": "2026.10.4", "patches": []}))
        logs = self.run_patch()
        self.assert_untouched()
        self.assertIn("0 file(s) patched", logs[-1])
        self.write("dist/other-CCCCCCCC.mjs", "drift\n")
        with self.assertRaises(P.PatchError):
            self.run_patch()


class RefusalTests(DistPatchCase):
    def assert_refused(self, fragment):
        with self.assertRaises(P.PatchError) as cm:
            self.run_patch()
        self.assertIn(fragment, str(cm.exception))
        self.assert_untouched()

    def test_other_openclaw_version(self):
        self.add_patch(STOCK.replace("30", "365"), version="2026.10.7")
        self.assert_refused("re-derive")

    def test_repacked_stock_file(self):
        self.add_patch(STOCK.replace("30", "365"), stock="0" * 64)
        self.assert_refused("is not the stock file")

    def test_result_differs_from_patched_hash(self):
        self.add_patch(STOCK.replace("30", "365"), patched="1" * 64)
        self.assert_refused("expected " + "1" * 64)

    def test_context_not_at_stated_line(self):
        new = STOCK.replace("halfLifeDays: 30", "halfLifeDays: 365")
        d = udiff("dist/thing-BBBBBBBB.mjs", STOCK, new).replace("@@ -2,7 +2,7 @@", "@@ -3,7 +3,7 @@")
        self.assertIn("@@ -3,7 +3,7 @@", d)
        self.add_patch(new, diff=d)
        self.assert_refused("hunk context does not match at line 3")

    def test_insertion_past_end_of_file(self):
        new = STOCK + "tail\n"
        n = len(STOCK.split("\n")) - 1
        d = "--- a/dist/thing-BBBBBBBB.mjs\n+++ b/dist/thing-BBBBBBBB.mjs\n@@ -50,0 +51 @@\n+tail\n"
        self.add_patch(new, diff=d)
        self.assert_refused("hunk context does not match at line 50")
        self.add_patch(new, diff=d.replace("-50,0 +51", f"-{n},0 +{n + 1}"))
        self.run_patch()
        self.assertEqual((self.pkg / "dist/thing-BBBBBBBB.mjs").read_text(), new)

    def test_new_side_start_must_agree(self):
        new = STOCK.replace("halfLifeDays: 30", "halfLifeDays: 365")
        d = udiff("dist/thing-BBBBBBBB.mjs", STOCK, new).replace("@@ -2,7 +2,7 @@", "@@ -2,7 +9,7 @@")
        self.add_patch(new, diff=d)
        self.assert_refused("expected +2")

    def test_text_before_header_or_after_last_hunk(self):
        new = STOCK.replace("halfLifeDays: 30", "halfLifeDays: 365")
        d = udiff("dist/thing-BBBBBBBB.mjs", STOCK, new)
        self.add_patch(new, diff="@@ -1 +1 @@\n-x\n+y\n" + d)
        self.assert_refused("must start with")
        self.add_patch(new, diff=d + "trailing junk\n")
        self.assert_refused("unexpected diff line")

    def test_wrong_hunk_counts(self):
        new = STOCK.replace("halfLifeDays: 30", "halfLifeDays: 365")
        d = udiff("dist/thing-BBBBBBBB.mjs", STOCK, new).replace("@@ -2,7 +2,7 @@", "@@ -2,6 +2,7 @@")
        self.add_patch(new, diff=d)
        self.assert_refused("wrong line counts")

    def test_region_in_two_files_or_none(self):
        self.write("dist/other-CCCCCCCC.mjs", REGION + "\n")
        self.write_inventory()
        self.add_patch(STOCK.replace("30", "365"))
        self.assert_refused("expected dist/thing-BBBBBBBB.mjs")
        self.add_patch(STOCK.replace("30", "365"), region="//#region src/nowhere.ts")
        self.assert_refused("no file")

    def test_diff_names_must_match_file(self):
        new = STOCK.replace("30", "365")
        self.add_patch(new, diff=udiff("dist/other-CCCCCCCC.mjs", STOCK, new))
        self.assert_refused("expected a/dist/thing-BBBBBBBB.mjs")

    def test_diff_with_two_files(self):
        new = STOCK.replace("30", "365")
        d = udiff("dist/thing-BBBBBBBB.mjs", STOCK, new) + udiff("dist/thing-BBBBBBBB.mjs", STOCK, new)
        self.add_patch(new, diff=d)
        self.assert_refused("a second file")

    def test_missing_final_newline_marker(self):
        new = STOCK.replace("30", "365")
        self.add_patch(new, diff=udiff("dist/thing-BBBBBBBB.mjs", STOCK, new) + "\\ No newline at end of file\n")
        self.assert_refused("missing final newlines")

    def test_unsafe_paths(self):
        for rel in ("../x.mjs", "/etc/passwd", "dist/../package.json", "dist//x.mjs", "lib/x.mjs"):
            with self.subTest(rel=rel):
                (self.patches / "manifest.json").write_text(json.dumps({"openclaw_version": "2026.10.4", "patches": [
                    {"name": "x", "file": rel, "stock_sha256": "0" * 64, "patched_sha256": "0" * 64,
                     "diff": "x.patch"}]}))
                self.assert_refused("unsafe dist path")

    def test_diff_name_with_directory(self):
        (self.patches / "manifest.json").write_text(json.dumps({"openclaw_version": "2026.10.4", "patches": [
            {"name": "x", "file": "dist/thing-BBBBBBBB.mjs", "stock_sha256": "0" * 64, "patched_sha256": "0" * 64,
             "diff": "../x.patch"}]}))
        self.assert_refused("plain file name")

    def test_same_file_twice(self):
        e = {"name": "x", "file": "dist/thing-BBBBBBBB.mjs", "stock_sha256": "0" * 64, "patched_sha256": "0" * 64,
             "diff": "x.patch"}
        (self.patches / "manifest.json").write_text(json.dumps({"openclaw_version": "2026.10.4", "patches": [e, e]}))
        self.assert_refused("patched twice")

    def test_symlinked_target(self):
        real = self.pkg / "dist/thing-BBBBBBBB.mjs"
        moved = self.tmp / "elsewhere.mjs"
        shutil.move(real, moved)
        os.symlink(moved, real)
        new = STOCK.replace("30", "365")
        (self.patches / "thing.patch").write_text(udiff("dist/thing-BBBBBBBB.mjs", STOCK, new))
        (self.patches / "manifest.json").write_text(json.dumps({"openclaw_version": "2026.10.4", "patches": [
            {"name": "thing", "file": "dist/thing-BBBBBBBB.mjs", "stock_sha256": sha(STOCK.encode()),
             "patched_sha256": sha(new.encode()), "diff": "thing.patch"}]}))
        with self.assertRaises(P.PatchError) as cm:
            self.run_patch()
        self.assertIn("not a regular file", str(cm.exception))
        self.assertEqual(moved.read_text(), STOCK)

    def test_inventory_format_changed(self):
        self.write_inventory(fmt=lambda d: json.dumps(d))
        self.add_patch(STOCK.replace("30", "365"))
        self.assert_refused("postinstall-content-inventory.json format changed")

    def test_inventory_entry_not_stock(self):
        inv = json.loads((self.pkg / P.INVENTORY).read_text())
        for e in inv:
            if e["path"] == "dist/thing-BBBBBBBB.mjs":
                e["sha256"] = "2" * 64
        (self.pkg / P.INVENTORY).write_text(json.dumps(inv, indent=2) + "\n")
        self.add_patch(STOCK.replace("30", "365"))
        with self.assertRaises(P.PatchError) as cm:
            self.run_patch()
        self.assertIn("unexpected content inventory entry", str(cm.exception))
        self.assertEqual((self.pkg / "dist/thing-BBBBBBBB.mjs").read_text(), STOCK)
        self.assertEqual(self.ownership()["thing-BBBBBBBB.mjs"]["sha256"], sha(STOCK.encode()))

    def test_ownership_entry_not_stock(self):
        self.write_ownership(stock="4" * 64)
        self.write_inventory()
        self.add_patch(STOCK.replace("30", "365"))
        with self.assertRaises(P.PatchError) as cm:
            self.run_patch()
        self.assertIn("unexpected dist/runtime-dependency-ownership.json entry", str(cm.exception))
        self.assertEqual((self.pkg / "dist/thing-BBBBBBBB.mjs").read_text(), STOCK)

    def test_ownership_format_changed(self):
        self.write_ownership(fmt=lambda d: json.dumps(d, indent=1))
        self.write_inventory()
        self.add_patch(STOCK.replace("30", "365"))
        with self.assertRaises(P.PatchError) as cm:
            self.run_patch()
        self.assertIn("runtime-dependency-ownership.json format changed", str(cm.exception))
        self.assertEqual((self.pkg / "dist/thing-BBBBBBBB.mjs").read_text(), STOCK)

    def test_node_check_failure_writes_nothing(self):
        self.add_patch(STOCK.replace("30", "365"))
        failed = subprocess.CompletedProcess(["node"], 1, "", "SyntaxError: boom")
        with mock.patch.object(P.subprocess, "run", return_value=failed) as run:
            with self.assertRaises(P.PatchError) as cm:
                P.apply_all(str(self.pkg), str(self.patches), node_check=True, log=lambda _m: None)
        self.assertIn("node --check failed: SyntaxError: boom", str(cm.exception))
        checked = run.call_args[0][0][-1]
        self.assertFalse(checked.startswith(str(self.pkg)), checked)
        self.assert_untouched()

    def test_inventory_recheck_catches_other_drift(self):
        self.write("dist/other-CCCCCCCC.mjs", "export const o = 'changed';\n")
        self.add_patch(STOCK.replace("30", "365"))
        with self.assertRaises(P.PatchError) as cm:
            self.run_patch()
        self.assertIn("content inventory mismatch: dist/other-CCCCCCCC.mjs", str(cm.exception))

    def test_inventory_recheck_catches_exec_bit(self):
        os.chmod(self.pkg / "dist/tool.js", 0o644)
        self.add_patch(STOCK.replace("30", "365"))
        with self.assertRaises(P.PatchError) as cm:
            self.run_patch()
        self.assertIn("dist/tool.js", str(cm.exception))


class MainTests(DistPatchCase):
    def test_exit_codes(self):
        self.add_patch(STOCK.replace("30", "365"), version="2026.10.7")
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(P.main(["--no-node-check", str(self.pkg), str(self.patches)]), 1)
            self.assertEqual(P.main([str(self.pkg)]), 2)
        self.assertIn("FAILED: patches are for OpenClaw 2026.10.7", err.getvalue())
        self.add_patch(STOCK.replace("30", "365"))
        with redirect_stderr(io.StringIO()):
            self.assertEqual(P.main(["--no-node-check", str(self.pkg), str(self.patches)]), 0)


class RepoPatchSetTests(unittest.TestCase):
    """The patch sets shipped in oc-patches/ are well-formed (no OpenClaw package needed)."""

    def test_manifests_and_diffs_parse(self):
        root = ADDON / "oc-patches"
        dirs = sorted(d for d in root.iterdir() if d.is_dir())
        self.assertTrue(dirs)
        for d in dirs:
            with self.subTest(version=d.name):
                man = P.load_manifest(str(d))
                self.assertEqual(man["openclaw_version"], d.name)
                for e in man["patches"]:
                    hunks = P.parse_diff((d / e["diff"]).read_text(), e["file"])
                    self.assertTrue(hunks)
                    for key in ("stock_sha256", "patched_sha256"):
                        self.assertRegex(e[key], r"^[0-9a-f]{64}$")
                listed = {e["diff"] for e in man["patches"]} | {"manifest.json"}
                self.assertEqual({p.name for p in d.iterdir()} - listed, set(), "unlisted files in " + d.name)

    @unittest.skipUnless(os.environ.get("OC_DIST_PATCH_REAL_PKG"), "set OC_DIST_PATCH_REAL_PKG to an unpacked "
                         "openclaw package to apply the shipped patch set to a copy")
    def test_real_package(self):
        src = Path(os.environ["OC_DIST_PATCH_REAL_PKG"])
        version = json.loads((src / "package.json").read_text())["version"]
        tmp = Path(tempfile.mkdtemp(prefix="oc-dist-patch-real-"))
        try:
            shutil.copytree(src, tmp / "pkg", symlinks=True)
            P.apply_all(str(tmp / "pkg"), str(ADDON / "oc-patches" / version), node_check=True, log=lambda _m: None)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
