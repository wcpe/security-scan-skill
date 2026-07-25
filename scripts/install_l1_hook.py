#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security-scan · L1 常开快检钩子安装器

把 l1_check.py 挂到 Claude Code 的 PostToolUse 事件上，在每次 Edit / Write /
MultiEdit 之后自动对刚写入的内容做高危模式快检。

**本脚本会修改 settings.json，属于配置文件改动，只应在用户明确要求时执行。**
建议先跑 --dry-run 把将要写入的内容给用户过目。

用法：
  python install_l1_hook.py --scope project --dry-run   # 只看不写
  python install_l1_hook.py --scope project             # 写入项目级配置
  python install_l1_hook.py --scope user                # 写入用户级配置
  python install_l1_hook.py --scope project --uninstall # 卸载

写入前会自动备份原文件；重复安装不会产生重复条目。
"""

import argparse
import json
import os
import shutil
import sys
from datetime import datetime

# Windows 控制台默认用本地码页，强制 UTF-8 以免中文输出乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK_SCRIPT = os.path.join(HERE, "l1_check.py").replace("\\", "/")
MATCHER = "Edit|Write|MultiEdit"
MARKER = "l1_check.py"  # 用于识别本技能安装的条目


def settings_path(scope, override):
    if override:
        return os.path.abspath(override)
    if scope == "user":
        return os.path.join(os.path.expanduser("~"), ".claude", "settings.json")
    return os.path.join(os.getcwd(), ".claude", "settings.json")


def hook_command():
    """构造调用命令，路径统一用正斜杠以免 JSON 里出现转义反斜杠。"""
    python = sys.executable.replace("\\", "/") if sys.executable else "python"
    return '"%s" "%s"' % (python, HOOK_SCRIPT)


def load_settings(path):
    if not os.path.isfile(path):
        return {}, False
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read().strip()
        return (json.loads(text) if text else {}), True
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit("读取 %s 失败：%s\n请先修正该文件再重试。" % (path, exc))


def find_existing(post_hooks):
    """返回已安装条目的 (组索引, 钩子索引) 列表。"""
    found = []
    for gi, group in enumerate(post_hooks):
        for hi, hook in enumerate(group.get("hooks", [])):
            if MARKER in str(hook.get("command", "")):
                found.append((gi, hi))
    return found


def apply_install(settings):
    """返回 (新配置, 变更说明)。"""
    hooks = settings.setdefault("hooks", {})
    post_hooks = hooks.setdefault("PostToolUse", [])
    command = hook_command()

    existing = find_existing(post_hooks)
    if existing:
        changed = False
        for gi, hi in existing:
            if post_hooks[gi]["hooks"][hi].get("command") != command:
                post_hooks[gi]["hooks"][hi]["command"] = command
                changed = True
            if post_hooks[gi].get("matcher") != MATCHER:
                post_hooks[gi]["matcher"] = MATCHER
                changed = True
        return settings, ("已安装过，本次更新了命令路径" if changed else "已安装且配置一致，无需改动")

    post_hooks.append({
        "matcher": MATCHER,
        "hooks": [{"type": "command", "command": command}],
    })
    return settings, "新增 PostToolUse 钩子"


def apply_uninstall(settings):
    hooks = settings.get("hooks") or {}
    post_hooks = hooks.get("PostToolUse") or []
    if not find_existing(post_hooks):
        return settings, "未找到本技能安装的钩子，无需卸载"

    remaining_groups = []
    for group in post_hooks:
        kept = [h for h in group.get("hooks", []) if MARKER not in str(h.get("command", ""))]
        if kept:
            group["hooks"] = kept
            remaining_groups.append(group)
    if remaining_groups:
        hooks["PostToolUse"] = remaining_groups
    else:
        hooks.pop("PostToolUse", None)
    if not hooks:
        settings.pop("hooks", None)
    return settings, "已移除本技能的 PostToolUse 钩子"


def main():
    parser = argparse.ArgumentParser(description="security-scan L1 钩子安装器")
    parser.add_argument("--scope", choices=["project", "user"], default="project",
                        help="project 写入 <当前目录>/.claude/settings.json，user 写入 ~/.claude/settings.json")
    parser.add_argument("--settings", help="直接指定 settings.json 路径，覆盖 --scope")
    parser.add_argument("--dry-run", action="store_true", help="只打印将要写入的内容，不落盘")
    parser.add_argument("--uninstall", action="store_true", help="移除本技能安装的钩子")
    args = parser.parse_args()

    if not os.path.isfile(HOOK_SCRIPT):
        raise SystemExit("找不到 %s，无法安装。" % HOOK_SCRIPT)

    target = settings_path(args.scope, args.settings)
    settings, existed = load_settings(target)
    settings, action = (apply_uninstall(settings) if args.uninstall
                        else apply_install(settings))
    text = json.dumps(settings, ensure_ascii=False, indent=2)

    print("目标配置文件：%s%s" % (target, "" if existed else "（当前不存在，将新建）"))
    print("操作：%s" % action)
    print("---- 写入后的完整内容 ----")
    print(text)
    print("--------------------------")

    if args.dry_run:
        print("这是 --dry-run，未写入任何文件。确认无误后去掉该参数再执行一次。")
        return 0

    if existed:
        backup = "%s.bak-%s" % (target, datetime.now().strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(target, backup)
        print("原文件已备份到：%s" % backup)

    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(text + "\n")
    print("已写入 %s。" % target)
    if not args.uninstall:
        print("钩子在下次启动 Claude Code 会话时生效；命中时会在会话中给出 L1 提示。")
        print("卸载：python install_l1_hook.py --scope %s --uninstall" % args.scope)
    return 0


if __name__ == "__main__":
    sys.exit(main())
