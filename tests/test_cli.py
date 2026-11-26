import unittest

from cspforge.cli import main


class TestCLI(unittest.TestCase):

    def test_audit_text(self):
        code = main(["audit", "default-src 'self'; script-src 'unsafe-inline'"])
        self.assertEqual(code, 0)

    def test_audit_json(self):
        code = main(["audit", "default-src 'self'", "--format", "json"])
        self.assertEqual(code, 0)

    def test_fail_on_gate(self):
        code = main(["audit", "script-src 'unsafe-inline'", "--fail-on", "high"])
        self.assertEqual(code, 2)

    def test_rules(self):
        self.assertEqual(main(["rules"]), 0)

    def test_parse_and_harden_and_diff(self):
        self.assertEqual(main(["parse", "default-src 'self'"]), 0)
        self.assertEqual(main(["harden", "script-src 'unsafe-inline'"]), 0)
        self.assertEqual(main(["diff", "default-src 'self'", "default-src 'none'"]), 0)


if __name__ == "__main__":
    unittest.main()
