<div align="center">

# 🛡️ CSPForge

**Zero-dependency, offline-first Content Security Policy parser, auditor & hardening engine — library + CLI.**

[简体中文](README.zh-CN.md) · [繁體中文](README.zh-TW.md) · **English**

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](pyproject.toml)

</div>

---

## 🎉 Introduction

Content Security Policy (CSP) is one of the most effective browser defenses against XSS and data injection — but a single misplaced `'unsafe-inline'` can silently invalidate the entire policy. **CSPForge** gives you a deterministic microscope for your CSP: parse any header into a structured model, audit it against 22 evidence-based rules, score it, and generate a hardened candidate — entirely offline, with no third-party packages and no network calls.

It is built for people who need **reproducible** security checks: CI gates that behave identically on your laptop and in the pipeline, reports that diff cleanly between runs, and findings you can actually act on.

> **Design promise:** same input → same output, always. No clock, no randomness, no network. Safe to run in air-gapped environments.

---

## ✨ Features

| Feature | Description |
| --- | --- |
| 🧩 **Deterministic parser** | Tolerant CSP3 parsing into directives and typed sources (keyword, nonce, hash, scheme, host, wildcard). |
| 🔬 **22 audit rules** | From `'unsafe-inline'` in `script-src` to weak nonces, SHA-1 hashes, missing `object-src 'none'`, frame-ancestors, and sandbox pitfalls. |
| 🎯 **Scoring & grading** | 0–100 score, A–F grade, and PASS/WARN/FAIL verdict derived from a transparent penalty table. |
| 🛠️ **Hardening suggestions** | Generate a stricter candidate policy by dropping dangerous sources and adding missing baselines. |
| 📊 **Four report formats** | Human-readable text, JSON, Markdown, and **SARIF 2.1.0** for GitHub Code Scanning. |
| 🚦 **CI gate** | `--fail-on` returns a non-zero exit code above a chosen severity threshold. |
| 🔀 **Policy diff** | See exactly which directives or sources were added/removed between two policies. |
| 🪶 **Zero dependencies** | Python 3.8+ standard library only. No pip install required to run from source. |

---

## 🚀 Quick Start

No installation needed — grab the source and run:

```bash
git clone https://github.com/gitstq/CSPForge.git
cd CSPForge

# Audit a policy
python3 -m cspforge audit "default-src 'self'; script-src 'self' 'unsafe-inline'"

# See the machine-readable result
python3 -m cspforge audit "default-src 'self'" --format sarif
```

Optional install for a global `cspforge` command:

```bash
pip install .
cspforge --help
```

---

## 📖 Usage Guide

### CLI

```bash
# Audit with a chosen output format and write to a file
cspforge audit "default-src 'self'; img-src https:" --format markdown -o report.md

# Read the policy from a file or stdin
cspforge audit -f header.txt
echo "default-src 'self'" | cspforge audit --stdin

# CI gate: fail the build if any HIGH or CRITICAL finding exists
cspforge audit "$CSP" --fail-on high

# Structured parse
cspforge parse "default-src 'self'; script-src 'nonce-abcDEF123456=='"

# Generate a hardened candidate
cspforge harden "script-src * 'unsafe-eval'"

# Compare two policies
cspforge diff "default-src 'self'" "default-src 'none'; object-src 'none'"

# List all rule IDs (handy for suppression allowlists)
cspforge rules
```

`--format` accepts `text` (default), `json`, `markdown`, `sarif`. Exit codes: `0` success, `1` input/IO error, `2` CI gate tripped.

### Library

```python
from cspforge import audit, parse, harden, render, render_policy, diff

report = audit("default-src 'self'; script-src 'self' 'unsafe-inline'")
print(report.score.value, report.score.grade)   # e.g. 75 C
for f in report.sorted_findings():
    print(f.rule_id, f.severity.value, f.title)

# SARIF for CI
sarif = render(report, "sarif")

# Parse, harden, compare
policy = parse("script-src * 'unsafe-inline'")
safer = harden(policy)
print(render_policy(safer))

delta = diff(policy, safer)
print(delta["changed_directives"])
```

Full public API is exported from the `cspforge` package; see `cspforge/__init__.py`.

### Rule IDs

Run `cspforge rules` for the authoritative list. Categories include: missing baseline directives (`CSP001`, `CSP005`–`CSP008`), unsafe script/style sources (`CSP002`–`CSP004`, `CSP015`, `CSP018`, `CSP021`), weak crypto (`CSP009`, `CSP010`), structural mistakes (`CSP011`–`CSP014`), transport (`CSP016`, `CSP017`), and sandbox/XSS edge cases (`CSP019`, `CSP020`, `CSP022`).

---

## 💡 Design & Iteration

**Why another CSP tool?** Most CSP analyzers are online services or depend on heavy frameworks. CSPForge is deliberately the opposite: a single deterministic core you can vendor into any pipeline.

**Key design decisions:**

1. **Determinism first.** Findings are sorted by severity then rule ID; report JSON uses fixed key order. Identical inputs produce byte-identical outputs.
2. **Tolerant parsing.** Real-world headers are messy — duplicated directives, stray whitespace, newline separators. The parser never throws on content; it records warnings instead.
3. **Rules as pure functions.** Each rule is an isolated, testable function returning `Finding` objects. Adding a rule means adding one function plus one list entry.
4. **Actionable remediation.** Every finding carries a concrete fix and, where relevant, a CWE reference.
5. **CI-native.** SARIF output and threshold-based exit codes make it drop-in for GitHub Actions, GitLab CI, and pre-commit.

**Iteration path:** v1.0.0 establishes the parser, 22 rules, scoring, hardening, diff, and four report formats. Future work (community-driven): additional CSP3 directives, a policy linter for `strict-dynamic` migrations, and localized SARIF messages.

---

## 📦 Packaging & Deployment

```bash
# Build a source archive with checksums (zero dependencies)
python3 scripts/package.py

# Outputs:
#   release/cspforge-1.0.0.zip
#   release/CHECKSUMS.sha256
```

Run the generated archive anywhere Python 3.8+ is available — unpack and execute `python3 -m cspforge`. Because there are no dependencies and no network calls, CSPForge is suitable for air-gapped CI runners and container images. This is a **library**, so no binary Release is published; integration examples are provided above.

Verify an archive:

```bash
sha256sum -c CHECKSUMS.sha256
```

---

## 🤝 Contributing

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md). Keep the project zero-dependency and deterministic, add tests for new rules, and use Angular-style commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`). Update all three README variants when behavior changes.

---

## 📄 License

Released under the [MIT License](LICENSE). © 2026 CSPForge contributors.
