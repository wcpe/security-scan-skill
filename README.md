# security-scan

一个「分层代码安全扫描与修复闭环」AI 编码技能：先用内置规则引擎预筛 source·sink·sanitizer 候选点，再由模型逐条验证「输入是否真的攻击者可控、调用链是否真的抵达危险汇聚点、路径上的净化函数是否真的防得住」，只输出带完整传播路径与可核验证据的 findings（Severity / CWE·OWASP / Location），产出 Markdown 与自包含 HTML 报告，并在用户确认后落地修复、跑原有测试、复扫确认同路径风险消失。

**未经用户明确确认不得改动代码。**

## 定位：与 privacy-guard 互补

| 技能 | 管什么 |
|---|---|
| **security-scan**（本仓） | 可被利用的漏洞与污点链路：SQL/命令注入、SSRF、路径穿越、反序列化、XSS/XXE、越权等 |
| [privacy-guard](https://github.com/wcpe/privacy-guard-skill) | 硬编码密钥与 PII 泄露：凭证、身份证/银行卡/手机号、内网地址、环境元数据、敏感文件 |

两者同属同一技能族，互不替代：security-scan 的 SKILL.md 明确把「只找硬编码密钥与 PII 泄露」划给 privacy-guard。

## 四种扫描模式

| 模式 | 扫描范围 | 分析强度 | 典型时机 |
|---|---|---|---|
| **L1 静态快检** | 本轮刚生成 / 刚改动的代码片段 | 高危模式匹配，秒级 | 写完代码随手一扫；或装成 git hook 常开 |
| **L2 轻量扫描** | 工作区未提交的增量变更 | 语义理解单变更的可控性与汇聚点 | 单个编码任务收尾时 |
| **L3 深度扫描** | 已提交但未审查的变更 + 跨文件调用链 | 跨文件跨函数完整污点数据流追踪 | 提交后、推送 / 发 PR / 发布 / 部署前 |
| **全量扫描** | 整仓，或指定目录 / 文件 | 同 L3，按模块分治 | 整仓审计、接手陌生项目、安全专项 |

## 安装

### Claude Code 插件

仓库根带 `.claude-plugin/plugin.json` manifest，`skills/` + `commands/` 沿用 Claude Code 插件布局：

```bash
# 作为 marketplace/local 插件安装
claude plugin add /path/to/security-scan-skill
# 或拷入项目/用户插件目录后启用
```

斜杠命令：`/security-scan`（默认 L2）、`/security-scan-l1`、`/security-scan-l3`、`/security-scan-full`。

### Codex 插件

仓库带 `.codex-plugin/plugin.json`（`skills` 指向 `./skills/`），按 Codex 插件目录装入即可。

### Devin 插件

仓库带 `.devin-plugin/plugin.json` manifest + `skills/security-scan/SKILL.md`（Devin 的插件加载约定）。在 Devin 侧用仓库 URL 安装插件后，`security-scan` 技能即被模型按触发词自动调用；引擎脚本（`scripts/*.py`）由会话内的 exec 工具直接执行，仅需 `python3`（可选 `ripgrep` 加速预筛）。

### 任何只认技能目录的 agent

把 `skills/security-scan/` 整个目录拷进 agent 的技能目录即可（opencode、Cursor、Gemini CLI 等通用）。

## 引擎脚本（也可脱离技能直接跑）

```bash
# L1 快检指定文件
python skills/security-scan/scripts/l1_check.py --file src/foo.py --file src/bar.py

# 收集扫描范围 → 规则预筛出候选点
python skills/security-scan/scripts/collect_scope.py --mode l3 --base origin/main --out .tmp/scope.json
python skills/security-scan/scripts/prefilter.py --scope .tmp/scope.json --out .tmp/candidates.json

# 模型逐条验证后渲染报告（findings.json 由验证环节产出）
python skills/security-scan/scripts/render_report.py --findings .tmp/findings.json --out-dir .tmp/security-scan

# 装 L1 git 拦截钩子（可选）
python skills/security-scan/scripts/install_l1_hook.py
```

语言专项规则见 `references/lang/`（java-kotlin / js-ts / python / go / rust / php / csharp / ruby），污点分析方法论见 `references/taint-analysis.md`，报告结构见 `references/report-format.md`。

## 目录结构

```
.claude-plugin/plugin.json   # Claude Code 插件 manifest
.codex-plugin/plugin.json    # Codex 插件 manifest
.devin-plugin/plugin.json    # Devin 插件 manifest
commands/                    # Claude Code 斜杠命令（4 个模式入口）
skills/security-scan/
  SKILL.md                   # 技能正文：模式路由、验证纪律、报告与修复闭环
  scripts/                   # 检测引擎：collect_scope / prefilter / l1_check / render_report / install_l1_hook + rules.json
  references/                # taint-analysis 方法论、报告格式、8 种语言专项规则
```

## 边界

- 纯性能问题（N+1、慢查询）、纯代码风格 / 可读性 review、纯重构、从零写新功能、license 合规——不是本技能目标。
- 与人工代码审查、渗透测试、SAST/SCA、组织现有安全流程是互补关系，不替代它们。
