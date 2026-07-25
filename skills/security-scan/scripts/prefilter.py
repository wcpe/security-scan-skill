#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security-scan · 规则预筛

在给定范围内用 rules.json 定位 source / sink / sanitizer / secret / config 候选点。
输出的是**待查线索**，不是结论——命中与否都不构成漏洞判定，判定由主 Agent 读代码完成。

用法：
  python prefilter.py --scope scope.json --out candidates.json
  python prefilter.py --path src/a.py --path src/b.js
  可选：--repo <目录> --l1-only --max-candidates 2000
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime

sys.dont_write_bytecode = True  # 不在技能目录里落 __pycache__

# Windows 控制台默认用本地码页，强制 UTF-8 以免中文输出乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RULES = os.path.join(HERE, "rules.json")
SNIPPET_MAX = 200
DEFAULT_MAX_CANDIDATES = 2000

# 与 collect_scope.py 保持一致的扩展名映射，供 --path 直接传文件时使用
sys.path.insert(0, HERE)
try:
    from collect_scope import detect_language, count_lines  # noqa: E402
except ImportError:  # 脚本被单独拷走时的降级路径
    def detect_language(_path):
        return "other"

    def count_lines(_path):
        return 0


def load_rules(rules_path, l1_only):
    """加载并编译规则；正则非法的规则跳过并记录。"""
    with open(rules_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    compiled, broken = [], []
    for rule in data.get("rules", []):
        if l1_only and not rule.get("l1"):
            continue
        try:
            rule = dict(rule)
            rule["_re"] = re.compile(rule["pattern"])
            rule["_exclude_re"] = re.compile(rule["exclude"]) if rule.get("exclude") else None
        except (re.error, KeyError) as exc:
            broken.append({"id": rule.get("id", "?"), "error": str(exc)})
            continue
        compiled.append(rule)
    return compiled, broken


def rules_for_language(rules, language):
    """挑出适用于该语言的规则：语言精确匹配或标注为 any。"""
    return [r for r in rules if "any" in r["lang"] or language in r["lang"]]


def mask_secret(text, span):
    """凭据类命中做脱敏，避免把完整密钥写进报告与日志。"""
    start, end = span
    matched = text[start:end]
    if len(matched) <= 8:
        keep = matched[:2]
    else:
        keep = matched[:6]
    return text[:start] + keep + "***[已脱敏 %d 字符]" % (len(matched) - len(keep)) + text[end:]


def in_changed_range(line_no, ranges):
    """行号是否落在本次改动范围内；无改动信息时返回 None 表示不适用。"""
    if not ranges:
        return None
    return any(start <= line_no <= end for start, end in ranges)


def scan_file(abs_path, rel_path, language, changed_lines, rules_cache, rules):
    """逐行套用规则，返回该文件的候选点列表。"""
    if language not in rules_cache:
        rules_cache[language] = rules_for_language(rules, language)
    applicable = rules_cache[language]
    if not applicable:
        return []

    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    found = []
    for idx, raw in enumerate(lines, start=1):
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        for rule in applicable:
            match = rule["_re"].search(line)
            if not match:
                continue
            if rule["_exclude_re"] and rule["_exclude_re"].search(line):
                continue
            snippet = line.strip()
            if rule["kind"] == "secret":
                offset = len(line) - len(line.lstrip())
                snippet = mask_secret(
                    snippet, (max(match.start() - offset, 0), max(match.end() - offset, 0)))
            if len(snippet) > SNIPPET_MAX:
                snippet = snippet[:SNIPPET_MAX] + " …"
            found.append({
                "file": rel_path,
                "line": idx,
                "kind": rule["kind"],
                "rule_id": rule["id"],
                "category": rule.get("category", ""),
                "cwe": rule.get("cwe", ""),
                "severity_hint": rule.get("severity_hint", "info"),
                "in_change": in_changed_range(idx, changed_lines),
                "snippet": snippet,
                "note": rule.get("note", ""),
            })
    return found


def targets_from_scope(scope_path):
    """从 scope.json 读出文件清单。"""
    with open(scope_path, "r", encoding="utf-8") as fh:
        scope = json.load(fh)
    repo = scope.get("repo", ".")
    targets = [
        (entry["path"], entry.get("language", "other"), entry.get("changed_lines", []))
        for entry in scope.get("files", [])
    ]
    return repo, targets


def targets_from_paths(repo, paths):
    """从 --path 参数直接构造文件清单。"""
    targets = []
    for path in paths:
        abs_path = path if os.path.isabs(path) else os.path.join(repo, path)
        if not os.path.isfile(abs_path):
            continue
        rel = os.path.relpath(abs_path, repo).replace("\\", "/")
        targets.append((rel, detect_language(rel), []))
    return targets


def main():
    parser = argparse.ArgumentParser(description="security-scan 规则预筛")
    parser.add_argument("--scope", help="collect_scope.py 产出的 scope.json")
    parser.add_argument("--path", action="append", default=[], help="直接指定文件，可重复")
    parser.add_argument("--repo", default=".", help="仓库根目录，--path 模式下用于计算相对路径")
    parser.add_argument("--rules", default=DEFAULT_RULES, help="规则文件路径")
    parser.add_argument("--l1-only", action="store_true", help="只用 L1 快检规则集")
    parser.add_argument("--max-candidates", type=int, default=DEFAULT_MAX_CANDIDATES)
    parser.add_argument("--out", help="输出 JSON 路径；不给则打印到标准输出")
    args = parser.parse_args()

    if not args.scope and not args.path:
        parser.error("需要 --scope 或至少一个 --path")

    if args.scope:
        repo, targets = targets_from_scope(args.scope)
    else:
        repo = os.path.abspath(args.repo)
        targets = targets_from_paths(repo, args.path)

    rules, broken = load_rules(args.rules, args.l1_only)
    rules_cache = {}
    candidates = []
    scanned = 0
    truncated = False

    for rel_path, language, changed_lines in targets:
        abs_path = os.path.join(repo, rel_path)
        scanned += 1
        candidates.extend(
            scan_file(abs_path, rel_path, language, changed_lines, rules_cache, rules))
        if len(candidates) >= args.max_candidates:
            truncated = True
            candidates = candidates[:args.max_candidates]
            break

    # 优先看落在改动行内的、以及严重级别提示更高的候选点
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    candidates.sort(key=lambda c: (
        0 if c["in_change"] else 1,
        severity_order.get(c["severity_hint"], 9),
        c["file"], c["line"],
    ))

    by_kind, by_category = {}, {}
    for item in candidates:
        by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
        if item["category"]:
            by_category[item["category"]] = by_category.get(item["category"], 0) + 1

    result = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "repo": repo.replace("\\", "/"),
        "rules_loaded": len(rules),
        "scanned_files": scanned,
        "total_candidates": len(candidates),
        "truncated": truncated,
        "in_change_note": "in_change 为 null 表示该文件按整份扫描，没有增量行的概念",
        "by_kind": dict(sorted(by_kind.items(), key=lambda kv: -kv[1])),
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "broken_rules": broken,
        "candidates": candidates,
    }

    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print("候选点已写入 %s：扫描 %d 个文件，命中 %d 处%s" % (
            args.out, scanned, len(candidates), "（已截断）" if truncated else ""))
        if result["by_category"]:
            print("  按类别：" + "、".join(
                "%s(%d)" % (k, v) for k, v in result["by_category"].items()))
        print("  提醒：候选点是待查线索，不是漏洞判定。")
    else:
        print(text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
