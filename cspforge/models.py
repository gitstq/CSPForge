"""CSPForge 核心数据模型。

所有模型均为标准库 dataclass，不依赖任何第三方包。
字段顺序固定，序列化结果具备确定性（可复现、可比对）。
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
import json
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """审计发现的严重级别。"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


#: 严重级别权重，用于评分与排序（数值越大越严重）。
SEVERITY_RANK: Dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

#: 每个级别在评分中默认扣除的分数。
SEVERITY_PENALTY: Dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


class SourceKind(str, Enum):
    """源表达式的分类。"""

    KEYWORD = "keyword"        # 'self' 'none' 'unsafe-inline' 等
    NONCE = "nonce"            # 'nonce-xxx'
    HASH = "hash"              # 'sha256-xxx'
    SCHEME = "scheme"          # https: data: blob:
    HOST = "host"              # example.com *.example.com
    WILDCARD = "wildcard"      # *
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Source:
    """单条源表达式（source-expression）。"""

    raw: str
    kind: SourceKind
    normalized: str = ""

    def __post_init__(self) -> None:
        if not self.normalized:
            object.__setattr__(self, "normalized", self.raw.strip().lower())

    def to_dict(self) -> Dict[str, Any]:
        return {"raw": self.raw, "kind": self.kind.value, "normalized": self.normalized}


@dataclass
class Directive:
    """单条 CSP 指令（directive），如 ``script-src 'self' https:``。"""

    name: str
    sources: List[Source] = field(default_factory=list)

    @property
    def normalized_name(self) -> str:
        return self.name.strip().lower()

    def source_values(self) -> List[str]:
        return [s.normalized for s in self.sources]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "sources": [s.to_dict() for s in self.sources],
        }


@dataclass
class Policy:
    """解析后的完整 CSP 策略。"""

    directives: List[Directive] = field(default_factory=list)
    raw: str = ""
    #: 解析期间产生的警告（例如空指令、重复指令），供审计与交互式使用。
    parse_warnings: List[str] = field(default_factory=list)

    def get(self, name: str) -> Optional[Directive]:
        """按指令名查找（大小写不敏感），返回首个匹配。"""
        target = name.strip().lower()
        for d in self.directives:
            if d.normalized_name == target:
                return d
        return None

    def has(self, name: str) -> bool:
        return self.get(name) is not None

    def directive_names(self) -> List[str]:
        return sorted({d.normalized_name for d in self.directives})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw": self.raw,
            "directives": [d.to_dict() for d in self.directives],
            "parse_warnings": list(self.parse_warnings),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent, sort_keys=False)


@dataclass
class Finding:
    """一条审计发现。"""

    rule_id: str
    title: str
    severity: Severity
    directive: str
    detail: str
    remediation: str
    evidence: str = ""
    cwe: str = ""
    references: List[str] = field(default_factory=list)

    @property
    def rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "directive": self.directive,
            "detail": self.detail,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "cwe": self.cwe,
            "references": list(self.references),
        }


@dataclass
class Score:
    """策略安全评分结果。"""

    value: int                      # 0-100
    grade: str                      # A/B/C/D/F
    verdict: str                    # PASS / WARN / FAIL
    penalty: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "grade": self.grade,
            "verdict": self.verdict,
            "penalty": self.penalty,
        }


@dataclass
class AuditReport:
    """一次审计的完整结果。"""

    policy: Policy
    findings: List[Finding] = field(default_factory=list)
    score: Optional[Score] = None

    def sorted_findings(self) -> List[Finding]:
        """按严重度降序、规则 ID 升序稳定排序。"""
        return sorted(self.findings, key=lambda f: (-f.rank, f.rule_id))

    def counts(self) -> Dict[str, int]:
        result = {s.value: 0 for s in Severity}
        for f in self.findings:
            result[f.severity.value] += 1
        return result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy": self.policy.to_dict(),
            "score": self.score.to_dict() if self.score else None,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
