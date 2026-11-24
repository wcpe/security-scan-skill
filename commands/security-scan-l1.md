---
description: L1 高危模式快检（刚写完的代码片段秒级预扫，走 security-scan）
---

对本轮刚生成 / 刚改动的代码做 **L1 静态快检**，用 **security-scan** 技能的 L1 模式：高危模式匹配、秒级出结果。直接引擎：`python skills/security-scan/scripts/l1_check.py --file <文件>`。**只检测不改动**。
