#!/usr/bin/env python3
"""一键打包脚本（零依赖）。

产出：
  - release/cspforge-<version>.zip  源码归档
  - release/README.txt              快速说明
  - release/CHECKSUMS.sha256        校验和

用法：python3 scripts/package.py [--version 1.0.0]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCLUDE = [
    "cspforge", "tests", "scripts",
    "README.md", "README.zh-CN.md", "README.zh-TW.md",
    "LICENSE", "CONTRIBUTING.md", "pyproject.toml", ".gitignore",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="1.0.0")
    args = ap.parse_args()

    release = ROOT / "release"
    release.mkdir(exist_ok=True)
    archive = release / f"cspforge-{args.version}.zip"

    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        base = f"cspforge-{args.version}"
        for item in INCLUDE:
            src = ROOT / item
            if src.is_dir():
                for f in sorted(src.rglob("*")):
                    if f.is_file() and "__pycache__" not in f.parts:
                        zf.write(f, f"{base}/{f.relative_to(ROOT)}")
            elif src.exists():
                zf.write(src, f"{base}/{item}")

    (release / "README.txt").write_text(
        "CSPForge — Zero-dependency CSP audit engine\n"
        f"Version: {args.version}\n"
        "Run: python3 -m cspforge audit \"default-src 'self'\"\n"
        "Docs: README.md / README.zh-CN.md / README.zh-TW.md\n",
        encoding="utf-8",
    )

    checksums = release / "CHECKSUMS.sha256"
    lines = []
    for path in sorted(release.glob("*")):
        if path.name == "CHECKSUMS.sha256" or path.is_dir():
            continue
        lines.append(f"{sha256(path)}  {path.name}")
    checksums.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"打包完成: {archive}")
    print(f"校验和: {checksums}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
