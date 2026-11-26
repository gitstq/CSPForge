"""CSPForge 命令行界面（零依赖，基于 argparse）。

子命令：
  audit    审计一个 CSP 字符串 / 文件 / stdin
  parse    解析并输出结构化 JSON
  harden   生成加固后的 CSP
  diff     对比两份 CSP
  rules    列出全部规则 ID
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .auditor import audit, audit_policy, passes_gate
from .differ import diff, render_diff_text
from .hardener import harden, render as render_policy
from .models import AuditReport
from .parser import parse
from .reporter import render
from .rules import RULES


def _read_input(value: Optional[str], file: Optional[str], stdin: bool) -> str:
    """统一读取输入：参数字符串 > 文件 > stdin。"""
    if value is not None:
        return value
    if file:
        with open(file, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    if stdin or not sys.stdin.isatty():
        data = sys.stdin.read()
        if data:
            return data.strip()
    raise ValueError("请提供 CSP：位置参数、-f/--file 或 stdin")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cspforge",
        description="零依赖·离线优先的 Content Security Policy 解析、审计与加固引擎",
    )
    p.add_argument("--version", action="version", version=f"cspforge {__version__}")
    sub = p.add_subparsers(dest="command")

    # audit
    a = sub.add_parser("audit", help="审计 CSP 并输出报告")
    a.add_argument("csp", nargs="?", help="CSP 字符串（也可通过 -f 或 stdin 提供）")
    a.add_argument("-f", "--file", help="从文件读取 CSP")
    a.add_argument("--stdin", action="store_true", help="强制从标准输入读取")
    a.add_argument("--format", default="text",
                   choices=["text", "json", "markdown", "sarif"], help="输出格式")
    a.add_argument("-o", "--output", help="写入文件（默认 stdout）")
    a.add_argument("--fail-on", default="never",
                   choices=["never", "info", "low", "medium", "high", "critical"],
                   help="出现 >= 该严重度的发现时以非零码退出（CI 门禁）")

    # parse
    ps = sub.add_parser("parse", help="解析 CSP 为结构化 JSON")
    ps.add_argument("csp", nargs="?")
    ps.add_argument("-f", "--file")
    ps.add_argument("--stdin", action="store_true")

    # harden
    h = sub.add_parser("harden", help="生成加固后的 CSP")
    h.add_argument("csp", nargs="?")
    h.add_argument("-f", "--file")
    h.add_argument("--stdin", action="store_true")
    h.add_argument("-o", "--output")

    # diff
    d = sub.add_parser("diff", help="对比两份 CSP")
    d.add_argument("old", nargs="?", help="旧 CSP 字符串")
    d.add_argument("new", nargs="?", help="新 CSP 字符串")
    d.add_argument("--old-file")
    d.add_argument("--new-file")
    d.add_argument("--format", default="text", choices=["text", "json"])

    # rules
    sub.add_parser("rules", help="列出全部审计规则 ID")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cmd = args.command
    if cmd is None:
        parser.print_help()
        return 0

    try:
        if cmd == "rules":
            ids = []
            for fn in RULES:
                name = fn.__name__
                ids.append(name.split("_", 1)[0].upper() if name.startswith("csp") else name.upper())
            for rid in sorted(set(ids)):
                print(rid)
            return 0

        if cmd == "audit":
            raw = _read_input(getattr(args, "csp", None), getattr(args, "file", None),
                              getattr(args, "stdin", False))
            report = audit(raw)
            out = render(report, args.format)
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(out)
            else:
                sys.stdout.write(out)
            return 0 if passes_gate(report, args.fail_on) else 2

        if cmd == "parse":
            raw = _read_input(args.csp, args.file, args.stdin)
            sys.stdout.write(parse(raw).to_json() + "\n")
            return 0

        if cmd == "harden":
            raw = _read_input(args.csp, args.file, args.stdin)
            hardened = render_policy(harden(parse(raw)))
            if args.output:
                with open(args.output, "w", encoding="utf-8") as fh:
                    fh.write(hardened + "\n")
            else:
                print(hardened)
            return 0

        if cmd == "diff":
            if args.old_file:
                with open(args.old_file, encoding="utf-8") as fh:
                    old_raw = fh.read().strip()
            else:
                old_raw = args.old or ""
            if args.new_file:
                with open(args.new_file, encoding="utf-8") as fh:
                    new_raw = fh.read().strip()
            else:
                new_raw = args.new or ""
            d = diff(parse(old_raw), parse(new_raw))
            if args.format == "json":
                import json
                sys.stdout.write(json.dumps(d, ensure_ascii=False, indent=2) + "\n")
            else:
                sys.stdout.write(render_diff_text(d))
            return 0

        parser.print_help()
        return 0
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"cspforge: error: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
