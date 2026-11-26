"""多格式报告渲染：text / json / markdown / sarif。

SARIF 2.1.0 输出遵循规范最小可用子集，可直接用于 GitHub Code Scanning 等 CI 门禁。
"""

from __future__ import annotations

import json
from typing import Any, Dict

from .models import AuditReport, Finding, Severity

# 严重度到 SARIF level 的映射
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _severity_tag(sev: Severity) -> str:
    return {
        Severity.CRITICAL: "[CRITICAL]",
        Severity.HIGH: "[HIGH]   ",
        Severity.MEDIUM: "[MEDIUM] ",
        Severity.LOW: "[LOW]    ",
        Severity.INFO: "[INFO]   ",
    }[sev]


def render_text(report: AuditReport, *, color: bool = False) -> str:
    lines: list[str] = []
    sc = report.score
    if sc:
        lines.append("=" * 64)
        lines.append("CSPForge · Content Security Policy Audit")
        lines.append("=" * 64)
        lines.append(f"Score: {sc.value}/100  Grade: {sc.grade}  Verdict: {sc.verdict}")
    counts = report.counts()
    lines.append(
        "Findings: " + ", ".join(f"{k}={counts[k]}" for k in
                                ["critical", "high", "medium", "low", "info"])
    )
    lines.append("-" * 64)
    findings = report.sorted_findings()
    if not findings:
        lines.append("No findings. Policy looks healthy.")
    for f in findings:
        lines.append(f"{_severity_tag(f.severity)} {f.rule_id}  {f.title}")
        lines.append(f"           directive : {f.directive}")
        lines.append(f"           detail    : {f.detail}")
        if f.evidence:
            lines.append(f"           evidence  : {f.evidence}")
        lines.append(f"           fix       : {f.remediation}")
        if f.cwe:
            lines.append(f"           ref       : {f.cwe}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(report: AuditReport) -> str:
    lines = ["# CSPForge 审计报告", ""]
    sc = report.score
    if sc:
        lines += [
            f"- **评分**：{sc.value}/100（{sc.grade}）",
            f"- **结论**：{sc.verdict}",
            "",
        ]
    lines += ["| 规则 | 严重度 | 指令 | 说明 |", "| --- | --- | --- | --- |"]
    for f in report.sorted_findings():
        lines.append(
            f"| {f.rule_id} | {f.severity.value} | `{f.directive}` | {f.detail.replace('|', '/')} |"
        )
    if not report.findings:
        lines.append("| — | — | — | 未发现问题 |")
    return "\n".join(lines) + "\n"


def render_sarif(report: AuditReport) -> str:
    """生成 SARIF 2.1.0 文档（确定性输出）。"""
    results = []
    for f in report.sorted_findings():
        result: Dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.detail}"},
        }
        if f.directive:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "Content-Security-Policy"},
                    "region": {"startLine": 1, "startColumn": 1},
                },
                "logicalLocations": [{"name": f.directive, "kind": "directive"}],
            }]
        if f.remediation:
            result["fixes"] = [{"description": {"text": f.remediation}}]
        if f.cwe:
            result.setdefault("taxa", []).append({"id": f.cwe})
        results.append(result)

    # 规则元数据（去重、稳定排序）
    seen = set()
    rules = []
    for f in report.sorted_findings():
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        rules.append({
            "id": f.rule_id,
            "shortDescription": {"text": f.title},
            "fullDescription": {"text": f.detail},
            "defaultConfiguration": {"level": _SARIF_LEVEL[f.severity]},
            "help": {"text": f.remediation},
        })

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CSPForge",
                    "semanticVersion": "1.0.0",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"


def render(report: AuditReport, fmt: str = "text", *, color: bool = False) -> str:
    fmt = fmt.lower()
    if fmt == "text":
        return render_text(report, color=color)
    if fmt == "json":
        return report.to_json() + "\n"
    if fmt == "markdown":
        return render_markdown(report)
    if fmt == "sarif":
        return render_sarif(report)
    raise ValueError(f"不支持的格式: {fmt}（可选 text/json/markdown/sarif）")
