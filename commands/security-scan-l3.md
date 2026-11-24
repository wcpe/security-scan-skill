---
description: L3 跨文件污点数据流深度扫描（推送 / 发 PR / 发布前，走 security-scan）
---

对已提交但未审查的变更及其跨文件调用链做 **L3 深度扫描**，用 **security-scan** 技能的 L3 模式：完整污点数据流追踪（source → 中间跳 → sink → sanitizer）。可用 `--base <ref>` 指定比较基线（如 `origin/main`、`HEAD~3`）。**未经用户明确确认不得改动代码**。
