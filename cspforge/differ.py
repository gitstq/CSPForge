"""策略差异对比（确定性）。

用于比较两份 CSP 的指令/源变化，回答「这次改动是收紧还是放宽了？」
"""

from __future__ import annotations

from typing import Any, Dict, List

from .models import Policy


def diff(a: Policy, b: Policy) -> Dict[str, Any]:
    """对比 a（旧）与 b（新），返回结构化差异。"""
    names = sorted(set(a.directive_names()) | set(b.directive_names()))
    added_directives: List[str] = []
    removed_directives: List[str] = []
    changes: List[Dict[str, Any]] = []

    for name in names:
        da = a.get(name)
        db = b.get(name)
        if da is None and db is not None:
            added_directives.append(name)
            continue
        if da is not None and db is None:
            removed_directives.append(name)
            continue
        sa = set(da.source_values())  # type: ignore[union-attr]
        sb = set(db.source_values())  # type: ignore[union-attr]
        added = sorted(sb - sa)
        removed = sorted(sa - sb)
        if added or removed:
            changes.append({
                "directive": name,
                "added_sources": added,
                "removed_sources": removed,
            })

    return {
        "added_directives": added_directives,
        "removed_directives": removed_directives,
        "changed_directives": changes,
    }


def render_diff_text(d: Dict[str, Any]) -> str:
    lines = ["CSP Diff", "-" * 40]
    if d["added_directives"]:
        lines.append("新增指令: " + ", ".join(d["added_directives"]))
    if d["removed_directives"]:
        lines.append("移除指令: " + ", ".join(d["removed_directives"]))
    for c in d["changed_directives"]:
        lines.append(f"[{c['directive']}]")
        if c["added_sources"]:
            lines.append("  + " + ", ".join(c["added_sources"]))
        if c["removed_sources"]:
            lines.append("  - " + ", ".join(c["removed_sources"]))
    if not d["added_directives"] and not d["removed_directives"] and not d["changed_directives"]:
        lines.append("无差异")
    return "\n".join(lines) + "\n"
