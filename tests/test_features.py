import json
import unittest

from cspforge import (
    parse, audit, harden, render_policy, diff, render, render_sarif,
)


class TestHarden(unittest.TestCase):

    def test_harden_adds_baselines(self):
        h = harden(parse("script-src 'self' 'unsafe-inline'"))
        names = h.directive_names()
        for n in ["default-src", "object-src", "base-uri", "frame-ancestors", "form-action"]:
            self.assertIn(n, names)
        vals = h.get("script-src").source_values()
        self.assertNotIn("'unsafe-inline'", vals)

    def test_harden_deterministic(self):
        a = render_policy(harden(parse("script-src * 'unsafe-eval'")))
        b = render_policy(harden(parse("script-src * 'unsafe-eval'")))
        self.assertEqual(a, b)


class TestDiff(unittest.TestCase):

    def test_diff_sources(self):
        d = diff(
            parse("script-src 'self'"),
            parse("script-src 'self' https://cdn.example.com; object-src 'none'"),
        )
        self.assertIn("object-src", d["added_directives"])
        ch = {c["directive"]: c for c in d["changed_directives"]}
        self.assertIn("https://cdn.example.com", ch["script-src"]["added_sources"])

    def test_no_diff(self):
        d = diff(parse("default-src 'self'"), parse("default-src 'self'"))
        self.assertEqual(d["changed_directives"], [])
        self.assertEqual(d["added_directives"], [])


class TestReporter(unittest.TestCase):

    def test_formats(self):
        r = audit("default-src 'self'; script-src 'unsafe-inline'")
        for fmt in ["text", "json", "markdown", "sarif"]:
            with self.subTest(fmt=fmt):
                out = render(r, fmt)
                self.assertTrue(out.strip())
        data = json.loads(render(r, "json"))
        self.assertIn("findings", data)

    def test_sarif_schema(self):
        r = audit("script-src 'unsafe-inline'")
        doc = json.loads(render_sarif(r))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(doc["runs"][0]["tool"]["driver"]["name"], "CSPForge")
        self.assertTrue(doc["runs"][0]["results"])


if __name__ == "__main__":
    unittest.main()
