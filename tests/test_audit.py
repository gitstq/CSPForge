import unittest

from cspforge import audit, compute_score, passes_gate, rule_ids, RULES
from cspforge.models import Severity, Finding


class TestAudit(unittest.TestCase):

    def test_unsafe_inline_detected(self):
        r = audit("default-src 'self'; script-src 'self' 'unsafe-inline'")
        ids = [f.rule_id for f in r.findings]
        self.assertIn("CSP002", ids)

    def test_safe_policy_has_fewer_findings(self):
        weak = audit("script-src * 'unsafe-inline' 'unsafe-eval'")
        strong = audit(
            "default-src 'self'; script-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        self.assertGreater(len(weak.findings), len(strong.findings))
        self.assertGreater(strong.score.value, weak.score.value)

    def test_score_bounds_and_grade(self):
        s = compute_score([])
        self.assertEqual(s.value, 100)
        self.assertEqual(s.grade, "A")
        self.assertEqual(s.verdict, "PASS")
        many = [Finding("X", "t", Severity.CRITICAL, "d", "m", "r") for _ in range(10)]
        s2 = compute_score(many)
        self.assertGreaterEqual(s2.value, 0)
        self.assertLessEqual(s2.value, 100)

    def test_critical_verdict_fail(self):
        r = audit("script-src 'unsafe-inline'")
        self.assertEqual(r.score.verdict, "FAIL")

    def test_gate(self):
        r = audit("default-src 'self'; script-src 'self' 'unsafe-inline'")
        self.assertFalse(passes_gate(r, "high"))
        self.assertTrue(passes_gate(r, "never"))

    def test_all_rules_deterministic(self):
        csp = "default-src 'self'; script-src 'self' 'unsafe-inline' https: data: 'sha1-abc'"
        a = audit(csp).to_json()
        b = audit(csp).to_json()
        self.assertEqual(a, b)

    def test_rule_ids_stable(self):
        ids = rule_ids()
        self.assertEqual(len(ids), len(set(ids)))
        self.assertIn("CSP001", ids)
        self.assertIn("CSP022", ids)
        self.assertEqual(len(ids), len(RULES))

    def test_nonce_weak(self):
        r = audit("default-src 'self'; script-src 'nonce-abc'")
        self.assertTrue(any(f.rule_id == "CSP009" for f in r.findings))

    def test_strict_dynamic_needs_anchor(self):
        r = audit("default-src 'self'; script-src 'self' 'strict-dynamic'")
        self.assertTrue(any(f.rule_id == "CSP011" for f in r.findings))


if __name__ == "__main__":
    unittest.main()
