import unittest

from cspforge import parse, classify_source
from cspforge.models import SourceKind


class TestParser(unittest.TestCase):

    def test_basic(self):
        p = parse("default-src 'self'; script-src 'self' https://cdn.example.com")
        self.assertEqual(len(p.directives), 2)
        self.assertEqual(p.get("default-src").source_values(), ["'self'"])
        self.assertEqual(
            p.get("script-src").source_values(),
            ["'self'", "https://cdn.example.com"],
        )

    def test_case_insensitive_names(self):
        p = parse("Default-Src 'SELF'")
        self.assertTrue(p.has("default-src"))
        self.assertEqual(p.get("DEFAULT-SRC").normalized_name, "default-src")

    def test_newline_separator(self):
        p = parse("default-src 'self'\nscript-src 'none'")
        self.assertEqual(len(p.directives), 2)

    def test_classify_sources(self):
        cases = {
            "'self'": SourceKind.KEYWORD,
            "'unsafe-inline'": SourceKind.KEYWORD,
            "'nonce-abc123DEF456=='": SourceKind.NONCE,
            "'sha256-abc'": SourceKind.HASH,
            "*": SourceKind.WILDCARD,
            "https:": SourceKind.SCHEME,
            "data:": SourceKind.SCHEME,
            "example.com": SourceKind.HOST,
            "*.example.com": SourceKind.HOST,
        }
        for token, kind in cases.items():
            with self.subTest(token=token):
                self.assertEqual(classify_source(token), kind)

    def test_empty_and_whitespace(self):
        p = parse("   ;  ;  ")
        self.assertEqual(p.directives, [])
        p2 = parse("")
        self.assertEqual(p2.directives, [])

    def test_strict_warnings(self):
        p = parse("default-src 'self'; default-src 'none'", strict=True)
        self.assertTrue(any("重复指令" in w for w in p.parse_warnings))

    def test_deterministic_json(self):
        a = parse("default-src 'self'; img-src https:").to_json()
        b = parse("default-src 'self'; img-src https:").to_json()
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
