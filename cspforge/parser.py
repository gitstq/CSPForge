"""CSP 解析器（纯标准库实现）。

将 Content-Security-Policy 头字符串解析为 :class:`~cspforge.models.Policy`。
解析器是容错的：不会因非法输入抛异常，而是把问题记录到 parse_warnings 中，
以保证审计流程在任意真实世界头部上都可用（离线、确定性）。
"""

from __future__ import annotations

import re
from typing import List, Optional

from .models import Directive, Policy, Source, SourceKind

# 关键字源（带单引号）
_KEYWORDS = {
    "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'",
    "'unsafe-hashes'", "'strict-dynamic'", "'report-sample'",
    "'unsafe-allow-redirects'", "'wasm-unsafe-eval'",
}
# scheme 源，形如 https: data: blob: filesystem:
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*:$", re.IGNORECASE)
# nonce / hash 源
_NONCE_RE = re.compile(r"^'nonce-[A-Za-z0-9+/=_\-]+'$", re.IGNORECASE)
_HASH_RE = re.compile(r"^'(sha256|sha384|sha512)-[A-Za-z0-9+/=_\-]+'$", re.IGNORECASE)


def classify_source(token: str) -> SourceKind:
    """对单条源表达式进行分类。"""
    low = token.strip().lower()
    if low in _KEYWORDS:
        return SourceKind.KEYWORD
    if _NONCE_RE.match(token):
        return SourceKind.NONCE
    if _HASH_RE.match(token):
        return SourceKind.HASH
    if low == "*":
        return SourceKind.WILDCARD
    if _SCHEME_RE.match(token):
        return SourceKind.SCHEME
    # 主机源：允许 *. 前缀、端口、路径；简单判断为“不含引号且非空”
    if token and "'" not in token and not any(c.isspace() for c in token):
        return SourceKind.HOST
    return SourceKind.UNKNOWN


def parse_sources(tokens: List[str]) -> List[Source]:
    """把源 token 列表转换为 :class:`Source` 对象列表。"""
    return [Source(raw=t, kind=classify_source(t)) for t in tokens if t]


def parse(csp: str, *, strict: bool = False) -> Policy:
    """解析 CSP 字符串。

    参数
    ----
    csp:
        Content-Security-Policy 头的值（不含头名称）。
    strict:
        为 True 时，遇到空指令或明显畸形片段会写入 parse_warnings；
        为 False 时保持安静。行为始终是确定性的。
    """
    if csp is None:
        csp = ""
    if not isinstance(csp, str):
        raise TypeError("csp 必须是字符串")

    policy = Policy(raw=csp)
    seen = set()
    # CSP 以分号分隔指令；同时兼容换行（部分配置以换行分隔）。
    segments = re.split(r"[;\n]", csp)
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        # 指令名与源以空白分隔；不要误伤引号内的空白（CSP 关键字不含空格）。
        parts = seg.split()
        if not parts:
            continue
        name = parts[0].strip()
        sources = parts[1:]
        if not name:
            if strict:
                policy.parse_warnings.append("遇到无名指令片段，已忽略")
            continue
        key = name.lower()
        if key in seen:
            if strict:
                policy.parse_warnings.append(f"检测到重复指令: {name}")
        seen.add(key)
        policy.directives.append(
            Directive(name=name, sources=parse_sources(sources))
        )

    if not policy.directives and csp.strip() and strict:
        policy.parse_warnings.append("未解析到任何有效指令")
    return policy


def parse_many(csp_values: List[str]) -> List[Policy]:
    """批量解析多个 CSP 值，保持输入顺序。"""
    return [parse(v) for v in csp_values]
