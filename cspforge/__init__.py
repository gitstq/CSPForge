"""CSPForge — 零依赖·离线优先的 Content Security Policy 引擎。

公共 API::

    from cspforge import parse, audit, harden, diff, render

设计目标：确定性、可复现、无网络、无第三方依赖。
"""

from .models import (
    AuditReport, Directive, Finding, Policy, Score, Severity, Source, SourceKind,
)
from .parser import parse, parse_many, classify_source
from .rules import RULES, rule_ids
from .auditor import audit, audit_policy, compute_score, passes_gate
from .hardener import harden, render as render_policy
from .differ import diff, render_diff_text
from .reporter import render, render_sarif, render_text, render_markdown

__version__ = "1.0.0"
__all__ = [
    "parse", "parse_many", "classify_source",
    "audit", "audit_policy", "compute_score", "passes_gate",
    "harden", "render_policy", "diff", "render_diff_text",
    "render", "render_sarif", "render_text", "render_markdown",
    "RULES", "rule_ids",
    "Policy", "Directive", "Source", "SourceKind", "Finding", "Score",
    "AuditReport", "Severity", "__version__",
]
