<div align="center">

# 🛡️ CSPForge

**零依赖 · 离线优先的 Content Security Policy 解析、审计与加固引擎 —— 库 + 命令行双形态。**

[English](README.md) · [繁體中文](README.zh-TW.md) · **简体中文**

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](pyproject.toml)

</div>

---

## 🎉 介绍

内容安全策略（CSP）是浏览器抵御 XSS 与数据注入最有效的防线之一，但一个放错位置的 `'unsafe-inline'` 就可能让整条策略形同虚设。**CSPForge** 为你的 CSP 提供一台「确定性显微镜」：把任意响应头解析成结构化模型，用 22 条有据可依的规则逐项审计、打分，并生成加固后的候选策略 —— 全程离线，不依赖任何第三方包，也不发起任何网络请求。

它专为需要**可复现**安全检查的人而设计：CI 门禁在笔记本和流水线里表现完全一致，报告在多次运行之间能干净地做差异比对，每一条发现都附带可以直接落地的修复建议。

> **设计承诺：** 相同输入永远得到相同输出。没有时钟、没有随机数、没有网络，可在隔离网络环境中放心运行。

---

## ✨ 特性

| 特性 | 说明 |
| --- | --- |
| 🧩 **确定性解析器** | 容错式 CSP3 解析，拆分为指令与带类型的源（关键字、nonce、hash、scheme、主机、通配符）。 |
| 🔬 **22 条审计规则** | 从 `script-src` 中的 `'unsafe-inline'`，到弱 nonce、SHA-1 哈希、缺失 `object-src 'none'`、frame-ancestors 以及 sandbox 陷阱。 |
| 🎯 **评分与分级** | 透明的扣分表得出 0–100 分、A–F 等级和 PASS/WARN/FAIL 结论。 |
| 🛠️ **加固建议** | 剔除危险源、补齐缺失基线，自动生成更严格的候选策略。 |
| 📊 **四种报告格式** | 易读文本、JSON、Markdown，以及可用于 GitHub Code Scanning 的 **SARIF 2.1.0**。 |
| 🚦 **CI 门禁** | `--fail-on` 在严重级别达到阈值时返回非零退出码。 |
| 🔀 **策略对比** | 精确查看两份策略之间新增/移除了哪些指令或源。 |
| 🪶 **零依赖** | 仅用 Python 3.8+ 标准库，从源码运行无需 pip 安装。 |

---

## 🚀 快速开始

无需安装，拉取源码即可运行：

```bash
git clone https://github.com/gitstq/CSPForge.git
cd CSPForge

# 审计一条策略
python3 -m cspforge audit "default-src 'self'; script-src 'self' 'unsafe-inline'"

# 查看机器可读的结果
python3 -m cspforge audit "default-src 'self'" --format sarif
```

如需全局 `cspforge` 命令，可选安装：

```bash
pip install .
cspforge --help
```

---

## 📖 使用指南

### 命令行

```bash
# 指定输出格式审计并写入文件
cspforge audit "default-src 'self'; img-src https:" --format markdown -o report.md

# 从文件或标准输入读取策略
cspforge audit -f header.txt
echo "default-src 'self'" | cspforge audit --stdin

# CI 门禁：出现任意 HIGH 或 CRITICAL 发现即让构建失败
cspforge audit "$CSP" --fail-on high

# 结构化解析
cspforge parse "default-src 'self'; script-src 'nonce-abcDEF123456=='"

# 生成加固候选策略
cspforge harden "script-src * 'unsafe-eval'"

# 对比两份策略
cspforge diff "default-src 'self'" "default-src 'none'; object-src 'none'"

# 列出全部规则 ID（便于配置抑制白名单）
cspforge rules
```

`--format` 支持 `text`（默认）、`json`、`markdown`、`sarif`。退出码：`0` 成功，`1` 输入/IO 错误，`2` 触发 CI 门禁。

### 作为库调用

```python
from cspforge import audit, parse, harden, render, render_policy, diff

report = audit("default-src 'self'; script-src 'self' 'unsafe-inline'")
print(report.score.value, report.score.grade)   # 例如 75 C
for f in report.sorted_findings():
    print(f.rule_id, f.severity.value, f.title)

# 供 CI 使用的 SARIF
sarif = render(report, "sarif")

# 解析、加固、对比
policy = parse("script-src * 'unsafe-inline'")
safer = harden(policy)
print(render_policy(safer))

delta = diff(policy, safer)
print(delta["changed_directives"])
```

全部公共 API 均从 `cspforge` 包导出，详见 `cspforge/__init__.py`。

### 规则编号一览

运行 `cspforge rules` 获取权威列表。规则涵盖：基线指令缺失（`CSP001`、`CSP005`–`CSP008`）、不安全的脚本/样式源（`CSP002`–`CSP004`、`CSP015`、`CSP018`、`CSP021`）、弱密码学（`CSP009`、`CSP010`）、结构性错误（`CSP011`–`CSP014`）、传输安全（`CSP016`、`CSP017`），以及 sandbox/XSS 边缘场景（`CSP019`、`CSP020`、`CSP022`）。

---

## 💡 设计迭代

**为什么再造一个 CSP 工具？** 大多数 CSP 分析器要么是在线服务，要么依赖沉重的框架。CSPForge 刻意反其道而行：提供一个可以嵌进任何流水线的轻量确定性内核。

**关键设计决策：**

1. **确定性优先。** 发现按严重度再按规则 ID 排序；报告 JSON 使用固定键顺序，相同输入产生逐字节相同的输出。
2. **容错解析。** 真实世界的响应头往往很脏 —— 重复指令、多余空白、换行分隔。解析器不会因内容抛异常，而是记录警告。
3. **规则即纯函数。** 每条规则都是隔离、可测试的独立函数，返回 `Finding` 对象。新增规则只需加一个函数和一个注册项。
4. **可落地的修复。** 每条发现都带具体修复方式，相关时还附上 CWE 参考。
5. **原生适配 CI。** SARIF 输出与基于阈值的退出码，让它能直接嵌入 GitHub Actions、GitLab CI 与 pre-commit。

**迭代路径：** v1.0.0 奠定解析器、22 条规则、评分、加固、对比与四种报告格式。后续方向（社区驱动）：补充 CSP3 指令、`strict-dynamic` 迁移检查器、SARIF 消息本地化。

---

## 📦 打包部署

```bash
# 构建带校验和的源码归档（零依赖）
python3 scripts/package.py

# 产出：
#   release/cspforge-1.0.0.zip
#   release/CHECKSUMS.sha256
```

在任意装有 Python 3.8+ 的环境解压归档即可运行 `python3 -m cspforge`。由于没有依赖、没有网络调用，CSPForge 非常适合隔离网 CI 执行器与容器镜像。本项目是**库**，因此不发布二进制 Release，集成示例已在上方给出。

校验归档：

```bash
sha256sum -c CHECKSUMS.sha256
```

---

## 🤝 贡献

欢迎贡献，请先阅读 [CONTRIBUTING.md](CONTRIBUTING.md)。请保持项目零依赖、确定性，为新规则补充测试，并使用 Angular 风格提交（`feat:`、`fix:`、`docs:`、`refactor:`、`test:`）。行为变更时请同步更新三个 README 版本。

---

## 📄 协议

以 [MIT 协议](LICENSE) 发布。© 2026 CSPForge 贡献者。
