"""审计引擎与评分。

组合解析器与规则集，产出 :class:`~cspforge.models.AuditReport`。
评分算法完全确定性：100 分起，按严重度扣分，下限 0。
"""

from __future__ import annotations

from typing import Iterable, Optional

from .models import AuditReport, Finding, Policy, Score, Severity, SEVERITY_PENALTY
from .parser import parse
from .rules import RULES, RuleFunc


def compute_score(
    findings: Iterable[Finding],
    *,
    penalties: Optional[dict] = None,
    base: int = 100,
) -> Score:
    """根据发现计算评分。

    - 从 100 分开始，逐条按严重度扣分。
    - grade: >=90 A, >=80 B, >=70 C, >=60 D, 其余 F。
    - verdict: 无 CRITICAL/HIGH -> PASS；有 MEDIUM -> WARN；否则 FAIL。
    """
    pmap = dict(SEVERITY_PENALTY)
    if penalties:
        pmap.update(penalties)
    penalty = 0
    has_high = False
    has_medium = False
    for f in findings:
        penalty += int(pmap.get(f.severity, 0))
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            has_high = True
        elif f.severity == Severity.MEDIUM:
            has_medium = True
    value = max(0, min(100, base - penalty))
    if value >= 90:
        grade = "A"
    elif value >= 80:
        grade = "B"
    elif value >= 70:
        grade = "C"
    elif value >= 60:
        grade = "D"
    else:
        grade = "F"
    if has_high:
        verdict = "FAIL"
    elif has_medium:
        verdict = "WARN"
    else:
        verdict = "PASS"
    return Score(value=value, grade=grade, verdict=verdict, penalty=penalty)


def audit_policy(
    policy: Policy,
    *,
    rules: Optional[list[RuleFunc]] = None,
    penalties: Optional[dict] = None,
) -> AuditReport:
    """对已解析的 Policy 执行审计。"""
    active = rules if rules is not None else RULES
    findings: list[Finding] = []
    for rule in active:
        findings.extend(rule(policy))
    # 确定性排序，避免规则内部顺序影响输出。
    findings.sort(key=lambda f: (-f.rank, f.rule_id))
    score = compute_score(findings, penalties=penalties)
    return AuditReport(policy=policy, findings=findings, score=score)


def audit(csp: str, **kwargs) -> AuditReport:
    """便捷入口：解析字符串并审计。"""
    return audit_policy(parse(csp), **kwargs)


def passes_gate(report: AuditReport, fail_on: str = "high") -> bool:
    """CI 门禁判定：是否存在严重度 >= fail_on 的发现。

    fail_on 取值: critical / high / medium / low / info / never。
    """
    order = {
        "critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "never": 99,
    }
    threshold = order.get(fail_on.lower(), 4)
    if fail_on.lower() == "never":
        return True
    return not any(f.rank >= threshold for f in report.findings)
