"""Unit tests for oc_dist_patch (stdlib unittest, Python 3.11)."""

import difflib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

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


def udiff(rel, old, new, n=3):
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        f"a/{rel}", f"b/{rel}", n=n))


class DistPatchCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="oc-dist-patch-test-"))
        self.pkg = self.tmp / "pkg"
        (self.pkg / "dist").mkdir(parents=True)
        (self.pkg / "package.json").write_text(json.dumps({"version": "2026.10.4"}))
        self.write("dist/thing-BBBBBBBB.mjs", STOCK)
        self.write("dist/other-CCCCCCCC.mjs", "export const o = 1;\n")
        self.write("dist/tool.js", "#!/usr/bin/env node\n", mode=0o755)
        self.patches = self.tmp / "patches"
        self.patches.mkdir()
        self.write_inventory()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, rel, text, mode=0o644):
        p = self.pkg / rel
        p.write_text(text)
        os.chmod(p, mode)

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
        old = (self.pkg / rel).read_text()
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
        self.assert_refused("exactly one file")

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
        with self.assertRaises(P.PatchError) as cm:
            self.run_patch()
        self.assertIn("content inventory format changed", str(cm.exception))

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
