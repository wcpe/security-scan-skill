#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security-scan · L1 静态快检

只跑 rules.json 里 l1=true 的高置信规则，面向「刚写入的这段代码」，秒级返回。
两种用法：

  1) 手动检查单个文件
     python l1_check.py --file src/foo.py

  2) 作为 Claude Code 的 PostToolUse 钩子（从标准输入读取钩子负载）
     python l1_check.py
     命中时以退出码 2 + stderr 把提示回流给模型，在下一轮改动里处理；
     未命中则静默退出 0。安装方式见 install_l1_hook.py。

设计约束：钩子在每次写文件后都会跑，任何异常都必须静默退出 0，绝不能打断会话。
"""

import argparse
import json
import os
import re
import sys

sys.dont_write_bytecode = True  # 钩子每次写文件都会跑，不要在技能目录里落 __pycache__

# Windows 控制台默认用本地码页，强制 UTF-8，否则回流给模型的中文提示会乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

MAX_REPORTED = 10
# 测试与样例路径里的「凭据」多数是假数据，只在这些路径下跳过 secret 类规则
TEST_PATH_RE = re.compile(
    r"(?:^|[/\\])(?:tests?|spec|__tests__|fixtures?|examples?|mocks?|testdata)[/\\]"
    r"|(?:_test|\.test|\.spec|Test|Tests)\.[A-Za-z0-9]+$"
)


def load_l1_rules():
    from prefilter import load_rules  # 复用同一套规则加载与编译逻辑
    rules, _broken = load_rules(os.path.join(HERE, "rules.json"), l1_only=True)
    return rules


def scan_text(rules, language, text, is_test_path):
    """对文本逐行套用 L1 规则，返回 (行号, 规则, 该行内容) 列表。"""
    from prefilter import rules_for_language
    applicable = rules_for_language(rules, language)
    hits = []
    for idx, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        for rule in applicable:
            if is_test_path and rule["kind"] == "secret":
                continue
            if not rule["_re"].search(raw):
                continue
            if rule["_exclude_re"] and rule["_exclude_re"].search(raw):
                continue
            hits.append((idx, rule, line))
    return hits


def format_hit(path, line_no, rule, line_text, mask):
    from prefilter import mask_secret
    shown = line_text
    if rule["kind"] == "secret" and mask:
        match = rule["_re"].search(line_text)
        if match:
            shown = mask_secret(line_text, (match.start(), match.end()))
    if len(shown) > 160:
        shown = shown[:160] + " …"
    tag = rule.get("category") or rule["kind"]
    cwe = (" · " + rule["cwe"]) if rule.get("cwe") else ""
    return "  %s:%d [%s%s] %s\n      %s" % (path, line_no, tag, cwe, rule.get("note", ""), shown)


def new_text_from_hook(tool_input, tool_name):
    """取出本轮实际写入的文本，用于把命中限定在新代码上。"""
    if tool_name == "Write":
        return tool_input.get("content", "")
    if tool_name == "MultiEdit":
        return "\n".join(e.get("new_string", "") for e in tool_input.get("edits", []))
    if tool_name == "NotebookEdit":
        return tool_input.get("new_source", "")
    return tool_input.get("new_string", "")


def run_hook():
    """钩子模式：读 stdin 负载，只检查本轮写入的内容。"""
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    tool_input = payload.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if not file_path or not os.path.isfile(file_path):
        return 0

    from collect_scope import detect_language, SKIP_DIRS
    rel_parts = os.path.abspath(file_path).replace("\\", "/").split("/")
    if any(part in SKIP_DIRS for part in rel_parts[:-1]):
        return 0

    language = detect_language(file_path)
    new_text = new_text_from_hook(tool_input, payload.get("tool_name", ""))
    if not new_text.strip():
        return 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return 0

    # 只保留出现在本轮写入内容里的行，行号仍以磁盘文件为准
    new_lines = {ln.strip() for ln in new_text.splitlines() if ln.strip()}
    is_test = bool(TEST_PATH_RE.search(file_path.replace("\\", "/")))
    hits = [h for h in scan_text(load_l1_rules(), language, content, is_test)
            if h[2] in new_lines]
    if not hits:
        return 0

    cwd = payload.get("cwd") or os.getcwd()
    try:
        shown_path = os.path.relpath(file_path, cwd).replace("\\", "/")
    except ValueError:
        shown_path = file_path.replace("\\", "/")

    lines = ["[security-scan · L1] 本轮写入的代码命中 %d 处高危模式，请在下一轮改动中处理："
             % len(hits)]
    for line_no, rule, text in hits[:MAX_REPORTED]:
        lines.append(format_hit(shown_path, line_no, rule, text, mask=True))
    if len(hits) > MAX_REPORTED:
        lines.append("  …另有 %d 处未列出。" % (len(hits) - MAX_REPORTED))
    lines.append("L1 只做模式匹配，命中不等于漏洞：确认输入是否可控、调用是否真的抵达汇聚点后再决定改不改。")
    lines.append("需要完整的语义与数据流分析时，改用 security-scan 技能的 L2 / L3 模式。")
    print("\n".join(lines), file=sys.stderr)
    return 2  # 退出码 2：把提示回流给模型


def run_manual(paths):
    """手动模式：整份文件跑 L1 规则，输出给人看。"""
    from collect_scope import detect_language
    rules = load_l1_rules()
    total = 0
    for path in paths:
        if not os.path.isfile(path):
            print("文件不存在：%s" % path)
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        is_test = bool(TEST_PATH_RE.search(path.replace("\\", "/")))
        hits = scan_text(rules, detect_language(path), content, is_test)
        total += len(hits)
        if not hits:
            print("%s：未命中 L1 高危模式。" % path)
            continue
        print("%s：命中 %d 处" % (path, len(hits)))
        for line_no, rule, text in hits:
            print(format_hit(path.replace("\\", "/"), line_no, rule, text, mask=True))
    if total:
        print("\nL1 只做模式匹配，命中不等于漏洞。需要语义与数据流判定请走 L2 / L3。")
    return 0


def main():
    parser = argparse.ArgumentParser(description="security-scan L1 静态快检")
    parser.add_argument("--file", action="append", default=[], help="手动检查的文件，可重复")
    args = parser.parse_args()

    if args.file:
        return run_manual(args.file)
    return run_hook()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:  # 钩子里的任何意外都不应打断会话
        sys.exit(0)
