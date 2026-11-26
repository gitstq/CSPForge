"""加固建议生成器。

基于审计发现，对策略做「最小惊讶」的确定性改写，给出更安全的候选 CSP。
注意：加固是建议性质，不能替代对具体应用的回归测试。
"""

from __future__ import annotations

from typing import Dict, List

from .models import Policy, Source

# 需要移除的危险源（规范化小写）
_DROP_SOURCES = {
    "'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "*", "data:", "http:",
}


def harden(policy: Policy) -> Policy:
    """生成加固后的策略（不改变原对象）。"""
    new = Policy(raw=policy.raw)
    existing: Dict[str, List[Source]] = {}
    for d in policy.directives:
        name = d.normalized_name
        kept: List[Source] = []
        for s in d.sources:
            n = s.normalized
            if n in _DROP_SOURCES:
                continue
            # nonce/hash 中的弱 sha1 直接丢弃
            if n.startswith("'sha1-"):
                continue
            kept.append(s)
        # strict-dynamic 无锚点则移除（避免误配置）
        names = {s.normalized for s in kept}
        if name in {"script-src", "script-src-elem"} and "'strict-dynamic'" in names:
            has_anchor = any(s.kind.value in {"nonce", "hash"} for s in kept)
            if not has_anchor:
                kept = [s for s in kept if s.normalized != "'strict-dynamic'"]
        existing[name] = kept
        new.directives.append(type(d)(name=d.name, sources=kept))

    def ensure(name: str, sources: List[str]) -> None:
        if name not in existing:
            from .parser import parse_sources
            new.directives.append(
                type(new.directives[0])(name=name, sources=parse_sources(sources))
                if new.directives else _make_directive(name, sources)
            )
            existing[name] = []

    if "default-src" not in existing:
        ensure("default-src", ["'self'"])
    if "object-src" not in existing:
        ensure("object-src", ["'none'"])
    if "base-uri" not in existing:
        ensure("base-uri", ["'self'"])
    if "frame-ancestors" not in existing:
        ensure("frame-ancestors", ["'none'"])
    if "form-action" not in existing:
        ensure("form-action", ["'self'"])

    # 按指令名稳定排序，输出可读且可复现。
    new.directives.sort(key=lambda d: d.normalized_name)
    new.raw = render(new)
    return new


def _make_directive(name: str, sources: List[str]):
    from .models import Directive
    from .parser import parse_sources
    return Directive(name=name, sources=parse_sources(sources))


def render(policy: Policy) -> str:
    """把 Policy 渲染为规范化的 CSP 字符串。"""
    parts = []
    for d in policy.directives:
        tokens = [d.name] + [s.raw for s in d.sources]
        parts.append(" ".join(tokens))
    return "; ".join(parts)
