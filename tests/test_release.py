"""Release boundaries: no accidental evidence inclusion or missing resources."""

import hashlib
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("build_release", ROOT / "tools/build_release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
SKILL = ROOT / ".dsh/skills/cybersecurity-ops"


class TestRelease(unittest.TestCase):
    def test_archive_is_allowlisted_reproducible_and_checksummed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "skill"
            shutil.copytree(SKILL, source)
            (source / "evidence.txt").write_text("synthetic private evidence", encoding="utf-8")
            (source / ".env").write_text("synthetic credential", encoding="utf-8")
            first = release.build(source, root / "one")
            second = release.build(source, root / "two")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with ZipFile(first) as archive:
                self.assertEqual(set(archive.namelist()), {"cybersecurity-ops/" + name for name in release.PACKAGED_FILES})
                self.assertIsNone(archive.testzip())
            expected = hashlib.sha256(first.read_bytes()).hexdigest()
            self.assertEqual(first.with_suffix(".zip.sha256").read_text().split()[0], expected)

    def test_missing_resource_blocks_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "skill"
            shutil.copytree(SKILL, source)
            (source / "references/00-scope-and-rules.md").unlink()
            with self.assertRaises(ValueError):
                release.build(source, Path(tmp) / "dist")


if __name__ == "__main__":
    unittest.main()
