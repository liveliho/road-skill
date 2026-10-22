"""Regression checks for untrusted document content and publication boundaries."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import build_site


class SiteTests(unittest.TestCase):
    def test_untrusted_markup_is_text(self):
        rendered, _ = build_site.render_markdown(
            '# Title\n<script>alert(1)</script>\n\n[x](javascript:alert(1))\n\n'
            '```html\n<img src=x onerror=alert(1)>\n```', 'SKILL.md')
        self.assertNotIn('<script', rendered)
        self.assertNotIn('<img', rendered)
        self.assertNotIn('href="javascript:', rendered)
        self.assertIn('&lt;script&gt;', rendered)

    def test_link_boundary_and_internal_routing(self):
        self.assertEqual(build_site.safe_link('references/02-web-api.md', 'SKILL.md'), '#/docs/web')
        self.assertEqual(build_site.safe_link('../README.md', 'references/sources.md'), '#/docs/cli')
        for target in ('javascript:alert(1)', 'data:text/html,a', '//evil.example', '../../../secret', 'file:///etc/passwd', 'https://bad.example/\n'):
            with self.subTest(target=target):
                self.assertIsNone(build_site.safe_link(target, 'SKILL.md'))

    def test_build_has_allowlisted_docs_and_downloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'site'
            build_site.build_site(output)
            self.assertEqual(len(build_site.DOCS), 18)
            content = (output / 'content.js').read_text(encoding='utf-8')
            self.assertIn('window.ROAD_DOCS', content)
            self.assertNotIn('</script>', content.lower())
            self.assertTrue((output / 'downloads/cybersecurity-ops-1.1.0.zip').is_file())
            self.assertTrue((output / 'downloads/cybersecurity-ops-1.1.0.zip.sha256').is_file())
            self.assertEqual(len(list((output / 'downloads').glob('*-template.md'))), 3)
            self.assertFalse((output / '.git').exists())
            self.assertFalse((output / 'evidence').exists())


if __name__ == '__main__':
    unittest.main()
