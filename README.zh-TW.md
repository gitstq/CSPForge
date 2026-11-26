<div align="center">

# 🛡️ CSPForge

**零依賴、離線優先的 Content Security Policy 解析、稽核與強化引擎 —— 函式庫 + 命令列雙形態。**

[English](README.md) · [简体中文](README.zh-CN.md) · **繁體中文**

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](pyproject.toml)

</div>

---

## 🎉 介紹

Content Security Policy（CSP）是瀏覽器抵禦 XSS 與資料注入最有效的防線之一，但一個放錯位置的 `'unsafe-inline'` 就可能讓整條政策形同虛設。**CSPForge** 為你的 CSP 提供一台「決定性顯微鏡」：把任意回應標頭解析成結構化模型，用 22 條有憑有據的規則逐項稽核、評分，並產生強化後的候選政策 —— 全程離線，不依賴任何第三方套件，也不發出任何網路請求。

它專為需要**可重現**安全檢查的人而設計：CI 關卡在筆電與流水線中行為完全一致，報告在不同執行之間能乾淨地做差異比對，每一項發現都附上可以直接落地的修復建議。

> **設計承諾：** 相同輸入永遠得到相同輸出。沒有時鐘、沒有隨機數、沒有網路，可在隔離網路環境中安心執行。

---

## ✨ 特性

| 特性 | 說明 |
| --- | --- |
| 🧩 **決定性解析器** | 容錯式 CSP3 解析，拆成指令與帶類型的來源（關鍵字、nonce、hash、scheme、主機、萬用字元）。 |
| 🔬 **22 條稽核規則** | 從 `script-src` 中的 `'unsafe-inline'`，到弱 nonce、SHA-1 雜湊、缺少 `object-src 'none'`、frame-ancestors 以及 sandbox 陷阱。 |
| 🎯 **評分與分級** | 透過透明的扣分表得出 0–100 分、A–F 等級與 PASS/WARN/FAIL 結論。 |
| 🛠️ **強化建議** | 剔除危險來源、補齊缺少的基底，自動產生更嚴格的候選政策。 |
| 📊 **四種報告格式** | 易讀文字、JSON、Markdown，以及可供 GitHub Code Scanning 使用的 **SARIF 2.1.0**。 |
| 🚦 **CI 關卡** | `--fail-on` 在嚴重程度達到閾值時回傳非零結束碼。 |
| 🔀 **政策比對** | 精確查看兩份政策之間新增／移除了哪些指令或來源。 |
| 🪶 **零依賴** | 僅用 Python 3.8+ 標準函式庫，從原始碼執行無須 pip 安裝。 |

---

## 🚀 快速開始

無需安裝，抓取原始碼即可執行：

```bash
git clone https://github.com/gitstq/CSPForge.git
cd CSPForge

# 稽核一條政策
python3 -m cspforge audit "default-src 'self'; script-src 'self' 'unsafe-inline'"

# 查看機器可讀的結果
python3 -m cspforge audit "default-src 'self'" --format sarif
```

如需全域 `cspforge` 指令，可選擇安裝：

```bash
pip install .
cspforge --help
```

---

## 📖 使用指南

### 命令列

```bash
# 指定輸出格式稽核並寫入檔案
cspforge audit "default-src 'self'; img-src https:" --format markdown -o report.md

# 從檔案或標準輸入讀取政策
cspforge audit -f header.txt
echo "default-src 'self'" | cspforge audit --stdin

# CI 關卡：出現任意 HIGH 或 CRITICAL 發現就讓建置失敗
cspforge audit "$CSP" --fail-on high

# 結構化解析
cspforge parse "default-src 'self'; script-src 'nonce-abcDEF123456=='"

# 產生強化候選政策
cspforge harden "script-src * 'unsafe-eval'"

# 比對兩份政策
cspforge diff "default-src 'self'" "default-src 'none'; object-src 'none'"

# 列出全部規則 ID（便於設定抑制白名單）
cspforge rules
```

`--format` 支援 `text`（預設）、`json`、`markdown`、`sarif`。結束碼：`0` 成功、`1` 輸入／IO 錯誤、`2` 觸發 CI 關卡。

### 作為函式庫呼叫

```python
from cspforge import audit, parse, harden, render, render_policy, diff

report = audit("default-src 'self'; script-src 'self' 'unsafe-inline'")
print(report.score.value, report.score.grade)   # 例如 75 C
for f in report.sorted_findings():
    print(f.rule_id, f.severity.value, f.title)

# 供 CI 使用的 SARIF
sarif = render(report, "sarif")

# 解析、強化、比對
policy = parse("script-src * 'unsafe-inline'")
safer = harden(policy)
print(render_policy(safer))

delta = diff(policy, safer)
print(delta["changed_directives"])
```

全部公用 API 都從 `cspforge` 套件匯出，詳見 `cspforge/__init__.py`。

### 規則編號一覽

執行 `cspforge rules` 取得權威清單。規則涵蓋：基底指令缺少（`CSP001`、`CSP005`–`CSP008`）、不安全的腳本／樣式來源（`CSP002`–`CSP004`、`CSP015`、`CSP018`、`CSP021`）、弱密碼學（`CSP009`、`CSP010`）、結構性錯誤（`CSP011`–`CSP014`）、傳輸安全（`CSP016`、`CSP017`），以及 sandbox／XSS 邊緣情境（`CSP019`、`CSP020`、`CSP022`）。

---

## 💡 設計迭代

**為什麼再造一個 CSP 工具？** 大多數 CSP 分析器不是線上服務，就是依賴沉重的框架。CSPForge 刻意反其道而行：提供一個可以嵌進任何流水線的輕量決定性核心。

**關鍵設計決策：**

1. **決定性優先。** 發現先按嚴重程度、再按規則 ID 排序；報告 JSON 使用固定鍵順序，相同輸入產生逐位元組相同的輸出。
2. **容錯解析。** 真實世界的標頭往往很髒 —— 重複指令、多餘空白、換行分隔。解析器不會因內容擲出例外，而是記錄警告。
3. **規則即純函式。** 每條規則都是隔離、可測試的獨立函式，回傳 `Finding` 物件。新增規則只需加一個函式與一個註冊項目。
4. **可落地的修復。** 每項發現都附帶具體修復方式，相關時並附上 CWE 參考。
5. **原生相容 CI。** SARIF 輸出與以閾值為基礎的結束碼，讓它能直接嵌入 GitHub Actions、GitLab CI 與 pre-commit。

**迭代路徑：** v1.0.0 奠定解析器、22 條規則、評分、強化、比對與四種報告格式。後續方向（社群驅動）：補充 CSP3 指令、`strict-dynamic` 遷移檢查器、SARIF 訊息本地化。

---

## 📦 封裝部署

```bash
# 建置附校驗和的原始碼封存檔（零依賴）
python3 scripts/package.py

# 產出：
#   release/cspforge-1.0.0.zip
#   release/CHECKSUMS.sha256
```

在任意裝有 Python 3.8+ 的環境解開封存檔即可執行 `python3 -m cspforge`。由於沒有依賴、沒有網路呼叫，CSPForge 非常適合隔離網 CI 執行器與容器映像。本專案是**函式庫**，因此不發布二進位 Release，整合範例已於上方提供。

驗證封存檔：

```bash
sha256sum -c CHECKSUMS.sha256
```

---

## 🤝 貢獻

歡迎貢獻，請先閱讀 [CONTRIBUTING.md](CONTRIBUTING.md)。請保持專案零依賴、決定性，為新規則補上測試，並使用 Angular 風格提交（`feat:`、`fix:`、`docs:`、`refactor:`、`test:`）。行為變更時請同步更新三個 README 版本。

---

## 📄 授權

以 [MIT 授權](LICENSE) 發布。© 2026 CSPForge 貢獻者。
