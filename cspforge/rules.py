"""确定性 CSP 审计规则集。

每条规则是一个纯函数：接收 Policy，产出 0..N 条 Finding。
规则不依赖网络、不依赖时间、不依赖随机源——相同输入永远得到相同输出，
这是「CI 门禁可复现」的前提。

规则覆盖：CSP Level 3 常见误配置、XSS 缓解失效、点击劫持、数据泄露、
过时指令、弱 nonce/hash、可维护性问题等。
"""

from __future__ import annotations

from typing import Callable, List, Sequence

from .models import Finding, Policy, Severity, Source

# 规则函数类型
RuleFunc = Callable[[Policy], List[Finding]]

# 已知/标准指令（CSP3）
FETCH_DIRECTIVES = {
    "default-src", "script-src", "script-src-elem", "script-src-attr",
    "style-src", "style-src-elem", "style-src-attr", "img-src",
    "font-src", "connect-src", "media-src", "object-src", "frame-src",
    "child-src", "worker-src", "manifest-src", "prefetch-src",
}
DOCUMENT_DIRECTIVES = {
    "base-uri", "sandbox", "form-action", "frame-ancestors",
    "navigate-to", "require-trusted-types-for", "trusted-types",
}
REPORTING_DIRECTIVES = {"report-uri", "report-to"}
OTHER_DIRECTIVES = {"upgrade-insecure-requests", "block-all-mixed-content"}
KNOWN_DIRECTIVES = (
    FETCH_DIRECTIVES | DOCUMENT_DIRECTIVES | REPORTING_DIRECTIVES | OTHER_DIRECTIVES
)

DEPRECATED_DIRECTIVES = {
    "child-src": "优先使用 frame-src / worker-src",
    "report-uri": "已废弃，改用 Reporting API 的 report-to",
    "plugin-types": "已废弃，插件不再受支持",
    "referrer": "已废弃，改用 Referrer-Policy 响应头",
    "require-sri-for": "已从规范中移除",
}


def _mk(
    rule_id: str,
    title: str,
    severity: Severity,
    directive: str,
    detail: str,
    remediation: str,
    evidence: str = "",
    cwe: str = "",
    references: Sequence[str] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id, title=title, severity=severity, directive=directive,
        detail=detail, remediation=remediation, evidence=evidence,
        cwe=cwe, references=list(references),
    )


def _vals(policy: Policy, name: str) -> List[str]:
    d = policy.get(name)
    return d.source_values() if d else []


def _effective(policy: Policy, name: str) -> List[str]:
    """取得指令的有效源：优先具体指令，否则回退 default-src。"""
    d = policy.get(name)
    if d and d.sources:
        return d.source_values()
    return _vals(policy, "default-src")


# ---------------------------------------------------------------------------
# 规则实现
# ---------------------------------------------------------------------------

def csp001_missing_default_src(p: Policy) -> List[Finding]:
    if not p.has("default-src"):
        return [_mk(
            "CSP001", "缺少 default-src 兜底指令", Severity.HIGH, "default-src",
            "未设置 default-src，未显式声明的获取指令将没有任何回退限制，"
            "新资源类型可能默认不受约束。",
            "添加合适的 default-src（通常从 'self' 开始）作为所有 fetch 指令的兜底。",
            cwe="CWE-1021",
        )]
    return []


def csp002_script_unsafe_inline(p: Policy) -> List[Finding]:
    vals = _effective(p, "script-src")
    if "unsafe-inline" in [v.strip("'") for v in vals] or "'unsafe-inline'" in vals:
        return [_mk(
            "CSP002", "script-src 允许 'unsafe-inline'", Severity.CRITICAL, "script-src",
            "允许内联脚本会直接抵消 CSP 对 XSS 的核心防护能力。",
            "移除 'unsafe-inline'；改用 nonce、hash 或外部脚本文件。",
            evidence="'unsafe-inline' in script-src", cwe="CWE-79",
        )]
    return []


def csp003_script_unsafe_eval(p: Policy) -> List[Finding]:
    vals = _effective(p, "script-src")
    norm = [v.strip("'") for v in vals]
    if "unsafe-eval" in norm or "'unsafe-eval'" in vals:
        return [_mk(
            "CSP003", "script-src 允许 'unsafe-eval'", Severity.HIGH, "script-src",
            "'unsafe-eval' 允许 eval() 等动态代码执行，扩大 XSS 攻击面。",
            "移除 'unsafe-eval'，重构代码以避免动态求值；必要时使用 wasm-unsafe-eval 缩小范围。",
            cwe="CWE-95",
        )]
    return []


def csp004_script_wildcard(p: Policy) -> List[Finding]:
    vals = _effective(p, "script-src")
    if "*" in vals or "https:" in [v for v in vals] and "'self'" not in vals:
        evidence = "*" if "*" in vals else "https:"
        return [_mk(
            "CSP004", "script-src 存在过宽的源", Severity.HIGH, "script-src",
            "通配符或宽泛的 scheme 源允许从任意主机加载脚本，等同于放弃脚本来源约束。",
            "改为精确的主机白名单，或使用 nonce/hash 配合 'strict-dynamic'。",
            evidence=evidence, cwe="CWE-1021",
        )]
    return []


def csp005_object_src(p: Policy) -> List[Finding]:
    d = p.get("object-src")
    if d is None:
        return [_mk(
            "CSP005", "未显式设置 object-src 'none'", Severity.MEDIUM, "object-src",
            "未将 object-src 设为 'none' 时，插件类内容（如 Flash、旧式对象）可能成为注入载体。",
            "添加 object-src 'none'（现代浏览器/WebAssembly 场景通常无需插件）。",
            cwe="CWE-1021",
        )]
    vals = d.source_values()
    if "none" in [v.strip("'") for v in vals] or "'none'" in vals:
        return []
    return [_mk(
        "CSP005", "object-src 未禁止插件内容", Severity.MEDIUM, "object-src",
        "object-src 允许加载插件对象，存在历史漏洞利用风险。",
        "将 object-src 设为 'none'。", evidence=", ".join(vals), cwe="CWE-1021",
    )]


def csp006_missing_base_uri(p: Policy) -> List[Finding]:
    if not p.has("base-uri"):
        return [_mk(
            "CSP006", "缺少 base-uri 限制", Severity.MEDIUM, "base-uri",
            "未限制 <base> 标签时，攻击者可注入 base 标签劫持相对 URL 的解析基准。",
            "添加 base-uri 'self'（或 'none'）。", cwe="CWE-1021",
        )]
    return []


def csp007_frame_ancestors(p: Policy) -> List[Finding]:
    if not p.has("frame-ancestors"):
        return [_mk(
            "CSP007", "缺少 frame-ancestors（点击劫持防护）", Severity.MEDIUM,
            "frame-ancestors",
            "未设置 frame-ancestors 时页面可被任意站点嵌入，存在点击劫持风险。",
            "添加 frame-ancestors 'none' 或 'self' 以替代/补充 X-Frame-Options。",
            cwe="CWE-1021",
        )]
    vals = p.get("frame-ancestors").source_values()  # type: ignore[union-attr]
    if "*" in vals:
        return [_mk(
            "CSP007", "frame-ancestors 允许任意来源嵌入", Severity.MEDIUM, "frame-ancestors",
            "通配符允许任意站点嵌入本页面，点击劫持防护失效。",
            "使用 'none'、'self' 或明确的可信来源列表。", evidence="*", cwe="CWE-1021",
        )]
    return []


def csp008_missing_form_action(p: Policy) -> List[Finding]:
    if not p.has("form-action"):
        return [_mk(
            "CSP008", "缺少 form-action 限制", Severity.LOW, "form-action",
            "未限制表单提交目标，注入的表单可将数据提交到攻击者服务器。",
            "添加 form-action 'self'。", cwe="CWE-1021",
        )]
    return []


def csp009_weak_nonce(p: Policy) -> List[Finding]:
    out: List[Finding] = []
    nonces = []
    for d in p.directives:
        for s in d.sources:
            if s.kind.value == "nonce":
                nonces.append((d.name, s))
    for name, s in nonces:
        # 提取 nonce 值并计算长度（base64 编码后至少 16 字符 / 约 12 字节熵）。
        raw = s.raw.strip().strip("'")
        value = raw[len("nonce-"):] if raw.lower().startswith("nonce-") else raw
        if len(value) < 16:
            out.append(_mk(
                "CSP009", "nonce 长度不足", Severity.MEDIUM, name,
                f"nonce 值长度仅 {len(value)} 字符，熵不足，可能被暴力猜测。",
                "为每个响应生成至少 128 位随机 nonce（base64 通常 ≥22 字符），且一次一变。",
                evidence=f"nonce 长度={len(value)}", cwe="CWE-330",
            ))
    # 复用检测：不同指令使用相同 nonce 值属于正常；这里检测同一指令内重复 nonce。
    for d in p.directives:
        seen = set()
        for s in d.sources:
            if s.kind.value == "nonce":
                if s.normalized in seen:
                    out.append(_mk(
                        "CSP009", "同一指令内重复 nonce", Severity.LOW, d.name,
                        "同一指令中重复出现相同 nonce，通常是配置错误。",
                        "去重 nonce，保证每个来源唯一。", evidence=s.raw,
                    ))
                seen.add(s.normalized)
    return out


def csp010_weak_hash(p: Policy) -> List[Finding]:
    out: List[Finding] = []
    for d in p.directives:
        for s in d.sources:
            if s.kind.value == "hash" and s.normalized.startswith("'sha1-"):
                out.append(_mk(
                    "CSP010", "使用弱哈希算法 SHA-1", Severity.LOW, d.name,
                    "SHA-1 已不再被视为安全哈希，存在碰撞风险。",
                    "改用 sha256 / sha384 / sha512。", evidence=s.raw, cwe="CWE-328",
                ))
    return out


def csp011_strict_dynamic_without_nonce(p: Policy) -> List[Finding]:
    out: List[Finding] = []
    for d in p.directives:
        if d.normalized_name not in {"script-src", "script-src-elem"}:
            continue
        vals = d.source_values()
        has_strict = "'strict-dynamic'" in vals or "strict-dynamic" in [v.strip("'") for v in vals]
        if not has_strict:
            continue
        has_anchor = any(s.kind.value in {"nonce", "hash"} for s in d.sources)
        if not has_anchor:
            out.append(_mk(
                "CSP011", "'strict-dynamic' 缺少 nonce/hash 锚点", Severity.HIGH, d.name,
                "'strict-dynamic' 只有在存在 nonce 或 hash 信任锚点时才会生效；"
                "否则浏览器会忽略它并回退到宽松白名单。",
                "为可信脚本添加 nonce 或 hash，再配合 'strict-dynamic'。",
                cwe="CWE-1021",
            ))
    return out


def csp012_deprecated_directive(p: Policy) -> List[Finding]:
    out: List[Finding] = []
    for d in p.directives:
        name = d.normalized_name
        if name in DEPRECATED_DIRECTIVES:
            out.append(_mk(
                "CSP012", f"使用了过时指令 {name}", Severity.LOW, d.name,
                f"指令 {name} 已过时：{DEPRECATED_DIRECTIVES[name]}",
                "按现代 CSP3 规范替换该指令。", cwe="CWE-1021",
            ))
    return []


def csp013_unknown_directive(p: Policy) -> List[Finding]:
    out: List[Finding] = []
    for d in p.directives:
        if d.normalized_name not in KNOWN_DIRECTIVES:
            out.append(_mk(
                "CSP013", f"未知指令 {d.name}", Severity.INFO, d.name,
                f"指令 {d.name} 不在已知 CSP 指令集中，可能被浏览器忽略，或为拼写错误。",
                "核对该指令名称；标准指令请参照 CSP3 规范。", evidence=d.name,
            ))
    return []


def csp014_duplicate_directive(p: Policy) -> List[Finding]:
    counts: dict[str, int] = {}
    for d in p.directives:
        counts[d.normalized_name] = counts.get(d.normalized_name, 0) + 1
    out = []
    for name, c in sorted(counts.items()):
        if c > 1:
            out.append(_mk(
                "CSP014", f"重复指令 {name}", Severity.LOW, name,
                f"指令 {name} 出现了 {c} 次，只有第一个会被浏览器采用。",
                "合并重复指令，保留单一定义。", evidence=f"count={c}",
            ))
    return out


def csp015_data_uri_scripts(p: Policy) -> List[Finding]:
    vals = _effective(p, "script-src")
    if "data:" in vals:
        return [_mk(
            "CSP015", "script-src 允许 data: URI", Severity.MEDIUM, "script-src",
            "允许 data: URI 执行脚本可能被用于绕过过滤器投递 payload。",
            "从 script-src 移除 data:。", evidence="data:", cwe="CWE-79",
        )]
    return []


def csp016_insecure_scheme(p: Policy) -> List[Finding]:
    out = []
    for d in p.directives:
        if d.normalized_name not in FETCH_DIRECTIVES:
            continue
        insecure = [s.raw for s in d.sources if s.kind.value == "scheme" and s.normalized == "http:"]
        if insecure:
            out.append(_mk(
                "CSP016", f"{d.name} 使用明文 http: 源", Severity.LOW, d.name,
                "通过 http: 加载资源可能遭受中间人篡改。",
                "改用 https:，或启用 upgrade-insecure-requests。",
                evidence="http:", cwe="CWE-319",
            ))
    return out


def csp017_missing_upgrade_insecure(p: Policy) -> List[Finding]:
    if not p.has("upgrade-insecure-requests"):
        return [_mk(
            "CSP017", "缺少 upgrade-insecure-requests", Severity.INFO,
            "upgrade-insecure-requests",
            "未声明该指令时，页面中的 http:// 子资源不会自动升级为 https://。",
            "全站 HTTPS 时可添加 upgrade-insecure-requests。",
        )]
    return []


def csp018_style_unsafe_inline(p: Policy) -> List[Finding]:
    vals = _effective(p, "style-src")
    norm = [v.strip("'") for v in vals]
    if "unsafe-inline" in norm or "'unsafe-inline'" in vals:
        return [_mk(
            "CSP018", "style-src 允许 'unsafe-inline'", Severity.LOW, "style-src",
            "允许内联样式会弱化对基于样式的注入攻击的防护。",
            "移除 'unsafe-inline'，改用 nonce/hash 或外部样式表。",
            cwe="CWE-79",
        )]
    return []


def csp019_blanket_wildcard_default(p: Policy) -> List[Finding]:
    d = p.get("default-src")
    if d and "*" in d.source_values():
        return [_mk(
            "CSP019", "default-src 使用通配符 *", Severity.MEDIUM, "default-src",
            "default-src 中的 * 让所有未显式声明的资源类型都缺乏来源约束。",
            "收敛为明确的主机白名单，并为敏感类型单独设置更严格的指令。",
            evidence="*", cwe="CWE-1021",
        )]
    return []


def csp020_no_script_src(p: Policy) -> List[Finding]:
    if not p.has("script-src") and not p.has("script-src-elem") and not p.has("default-src"):
        return [_mk(
            "CSP020", "完全没有脚本来源约束", Severity.CRITICAL, "script-src",
            "既没有 script-src / script-src-elem，也没有 default-src，脚本来源完全不受限。",
            "至少添加 default-src 或 script-src（推荐 script-src 'self'）。",
            cwe="CWE-79",
        )]
    return []


def csp021_unsafe_hashes(p: Policy) -> List[Finding]:
    out = []
    for d in p.directives:
        vals = d.source_values()
        if "'unsafe-hashes'" in vals or "unsafe-hashes" in [v.strip("'") for v in vals]:
            out.append(_mk(
                "CSP021", "使用 'unsafe-hashes'", Severity.MEDIUM, d.name,
                "'unsafe-hashes' 允许对内联事件处理器等使用 hash，削弱防护边界。",
                "重构为外部脚本/nonce，移除 'unsafe-hashes'。",
                cwe="CWE-79",
            ))
    return out


def csp022_missing_sandbox_boundary(p: Policy) -> List[Finding]:
    """informational: 使用 sandbox 时若同时 allow-scripts + allow-same-origin 会失效。"""
    d = p.get("sandbox")
    if not d:
        return []
    vals = {v.lower() for v in d.source_values()}
    if "allow-scripts" in vals and "allow-same-origin" in vals:
        return [_mk(
            "CSP022", "sandbox 中 allow-scripts + allow-same-origin 组合", Severity.MEDIUM,
            "sandbox",
            "同时允许脚本与同源访问时，页面可移除自身的 sandbox 属性，隔离形同虚设。",
            "避免同时授予这两项；如需脚本，考虑移除 allow-same-origin。",
            evidence="allow-scripts allow-same-origin", cwe="CWE-693",
        )]
    return []


#: 规则注册表（ID 稳定，便于 CI 白名单/抑制）。
RULES: List[RuleFunc] = [
    csp001_missing_default_src,
    csp002_script_unsafe_inline,
    csp003_script_unsafe_eval,
    csp004_script_wildcard,
    csp005_object_src,
    csp006_missing_base_uri,
    csp007_frame_ancestors,
    csp008_missing_form_action,
    csp009_weak_nonce,
    csp010_weak_hash,
    csp011_strict_dynamic_without_nonce,
    csp012_deprecated_directive,
    csp013_unknown_directive,
    csp014_duplicate_directive,
    csp015_data_uri_scripts,
    csp016_insecure_scheme,
    csp017_missing_upgrade_insecure,
    csp018_style_unsafe_inline,
    csp019_blanket_wildcard_default,
    csp020_no_script_src,
    csp021_unsafe_hashes,
    csp022_missing_sandbox_boundary,
]


def rule_ids() -> List[str]:
    """返回全部规则 ID（依据函数文档字符串中的 ID 顺序，稳定）。"""
    ids = []
    for fn in RULES:
        doc = fn.__doc__ or ""
        # 从实现中约定：函数名即 cspNNN_xxx
        name = fn.__name__
        if name.startswith("csp") and "_" in name:
            ids.append(name.split("_", 1)[0].upper())
        else:
            ids.append(name.upper())
    return sorted(set(ids))
