"""Release guard (11.1 host rehearsal A6): config.yaml `version` and the CHANGELOG's release label move together.

The gate's backup check (ha-backup-missing) accepts only an encrypted Home Assistant backup that holds the add-on
version from before the update. An image released with the previous version string (here 0.5.94-full4) therefore
holds every update from that version. While the top CHANGELOG section is "[Unreleased]" the version stays the last
released label; once the section is labelled, config.yaml must carry that label, which must differ from the one
below it (DOCS "Release checklist (maintainers)").
"""

import re
import unittest
from pathlib import Path

ADDON = Path(__file__).resolve().parent.parent
HEADING_RE = re.compile(r"^## \[([^\]]+)\]", re.M)
VERSION_RE = re.compile(r'^version:\s*"([^"]+)"\s*$', re.M)


class ReleaseVersionTests(unittest.TestCase):
    def labels(self):
        text = (ADDON / "CHANGELOG.md").read_text(encoding="utf-8")
        return HEADING_RE.findall(text)

    def version(self):
        m = VERSION_RE.search((ADDON / "config.yaml").read_text(encoding="utf-8"))
        self.assertIsNotNone(m, "config.yaml has no quoted version")
        return m.group(1)

    def test_version_follows_the_release_label(self):
        labels, version = self.labels(), self.version()
        released = [x for x in labels if x != "Unreleased"]
        self.assertGreaterEqual(len(released), 2, labels)
        self.assertNotIn("Unreleased", labels[1:], "only the top section may be unreleased")
        if labels[0] == "Unreleased":
            # not released yet: the version is still the last shipped one, and the release must change it
            self.assertEqual(version, released[0])
        else:
            self.assertEqual(version, labels[0], "config.yaml version must be the new release label")
            self.assertNotEqual(labels[0], released[1], "a release needs a new version (ha-backup-missing)")

    def test_docs_name_the_release_step(self):
        docs = (ADDON.parent / "DOCS.md").read_text(encoding="utf-8")
        self.assertIn("**Release checklist (maintainers).**", docs)
        self.assertIn("tests/test_release_version.py", docs)


if __name__ == "__main__":
    unittest.main()
