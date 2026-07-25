#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security-scan · 扫描范围解析

按扫描模式确定要分析的文件清单、改动行范围、行数与语言分布，输出 JSON
供 prefilter.py 与主 Agent 使用。只读，不修改任何文件。

用法：
  python collect_scope.py --mode l2                      # 工作区未提交的变更（含未跟踪文件）
  python collect_scope.py --mode l3 [--base <ref>]       # 已提交但尚未审查的变更
  python collect_scope.py --mode paths --path src/auth --path src/export
  python collect_scope.py --mode repo                    # 整仓
  python collect_scope.py --mode l1 --path a.py --path b.py   # 指定文件（paths 的别名）

  可选：--repo <目录> --limit 10000 --out scope.json
"""

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime

# Windows 控制台默认用本地码页，强制 UTF-8 以免中文输出乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

# 扩展名 → 语言。未列出的归为 other，仅参与 any 规则。
LANG_BY_EXT = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
    ".vue": "javascript", ".svelte": "javascript",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".go": "go",
    ".php": "php", ".phtml": "php",
    ".rb": "ruby", ".rake": "ruby", ".erb": "ruby",
    ".rs": "rust",
    ".cs": "csharp", ".cshtml": "csharp", ".razor": "csharp",
    ".xml": "xml",
    ".sql": "sql", ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
    ".yml": "config", ".yaml": "config", ".json": "config", ".toml": "config",
    ".properties": "config", ".ini": "config", ".env": "config",
    ".html": "html", ".htm": "html", ".jsp": "java",
}

# 无需扫描的目录：依赖、构建产物、版本控制、IDE、过程性目录
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "bower_components",
    "dist", "build", "out", "target", "bin", "obj", ".next", ".nuxt", ".output",
    "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
    ".gradle", ".idea", ".vscode", "coverage", "htmlcov", ".terraform",
    "third_party", "thirdparty", "Pods", ".tmp", ".cache",
}

# 无需扫描的文件：压缩产物、锁文件、映射文件
SKIP_FILE_RE = re.compile(
    r"(?:\.min\.(?:js|css)|\.bundle\.js|\.map|-lock\.json|\.lock|\.sum)$", re.I
)

MAX_FILE_BYTES = 1_500_000  # 单文件超过此大小视为非人写代码，跳过
DEFAULT_LIMIT = 10000       # 单次扫描建议行数上限


def run_git(repo, args):
    """执行 git 命令，返回 (是否成功, 标准输出)。"""
    try:
        proc = subprocess.run(
            ["git", "-c", "core.quotepath=false", "-C", repo] + args,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
    except (OSError, ValueError) as exc:
        return False, str(exc)
    if proc.returncode != 0:
        return False, (proc.stderr or "").strip()
    return True, proc.stdout


def detect_language(rel_path):
    """按扩展名与文件名判定语言。"""
    name = os.path.basename(rel_path)
    _, ext = os.path.splitext(name)
    if name in ("Gemfile", "Rakefile", "Guardfile"):
        return "ruby"
    if name in ("Dockerfile", "Makefile"):
        return "config"
    return LANG_BY_EXT.get(ext.lower(), "other")


def is_skipped(rel_path):
    """判断路径是否落在跳过名单内。"""
    parts = rel_path.replace("\\", "/").split("/")
    if any(part in SKIP_DIRS for part in parts[:-1]):
        return True
    return bool(SKIP_FILE_RE.search(parts[-1]))


def count_lines(abs_path):
    """统计文本行数；二进制或超大文件返回 None 表示不参与扫描。"""
    try:
        if os.path.getsize(abs_path) > MAX_FILE_BYTES:
            return None
        with open(abs_path, "rb") as fh:
            head = fh.read(8192)
            if b"\0" in head:
                return None
            rest = fh.read()
    except OSError:
        return None
    return (head + rest).count(b"\n") + 1


def parse_diff_ranges(diff_text):
    """从 unified=0 的 diff 中解析出每个文件的新增/修改行范围。"""
    ranges = {}
    current = None
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            if target == "/dev/null":
                current = None
            else:
                current = target[2:] if target.startswith(("a/", "b/")) else target
                ranges.setdefault(current, [])
            continue
        if current and line.startswith("@@"):
            match = re.search(r"\+(\d+)(?:,(\d+))?", line)
            if not match:
                continue
            start = int(match.group(1))
            count = int(match.group(2)) if match.group(2) is not None else 1
            if count > 0:  # count 为 0 表示纯删除，新文件里没有对应内容
                ranges[current].append([start, start + count - 1])
    return ranges


def has_commits_since(repo, base):
    """base..HEAD 之间是否真的有提交。基线等于 HEAD 时（例如当前就在主干分支上）为假。"""
    ok, out = run_git(repo, ["rev-list", "--count", "%s..HEAD" % base])
    return ok and out.strip().isdigit() and int(out.strip()) > 0


def resolve_l3_base(repo, explicit_base):
    """确定 L3 的比较基线：显式指定 > 上游分支 > origin/HEAD > 主干分叉点 > HEAD~1。

    候选基线必须与 HEAD 之间确实存在提交才采用，否则继续往下试——
    直接在主干分支上开发时，与主干的分叉点就是 HEAD 本身，取它会得到空区间。
    """
    if explicit_base:
        return explicit_base, "使用显式指定的基线"

    candidates = []
    ok, out = run_git(repo, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
    if ok and out.strip():
        candidates.append((out.strip(), "使用当前分支的上游分支作为基线"))

    ok, out = run_git(repo, ["rev-parse", "--verify", "--quiet", "origin/HEAD"])
    if ok and out.strip():
        candidates.append(("origin/HEAD", "使用 origin/HEAD 作为基线"))

    for branch in ("origin/main", "origin/master", "main", "master"):
        ok, _ = run_git(repo, ["rev-parse", "--verify", "--quiet", branch])
        if not ok:
            continue
        ok, merge_base = run_git(repo, ["merge-base", branch, "HEAD"])
        if ok and merge_base.strip():
            candidates.append((merge_base.strip(), "退回与 %s 的分叉点作为基线" % branch))

    for base, reason in candidates:
        if has_commits_since(repo, base):
            return base, reason

    ok, _ = run_git(repo, ["rev-parse", "--verify", "--quiet", "HEAD~1"])
    if ok:
        return "HEAD~1", "候选基线与 HEAD 之间没有新提交，退回仅比较最后一个提交"
    return None, "仓库只有一个提交，无法确定 L3 基线；请改用 --mode l2 或 --mode paths"


def make_entry(repo, rel_path, changed_lines):
    """构造单个文件条目；不可扫描的文件返回 None。"""
    abs_path = os.path.join(repo, rel_path)
    if not os.path.isfile(abs_path):
        return None
    lines = count_lines(abs_path)
    if lines is None:
        return None
    return {
        "path": rel_path.replace("\\", "/"),
        "language": detect_language(rel_path),
        "lines": lines,
        "changed_lines": changed_lines,
    }


def collect_from_git_diff(repo, diff_args, notes):
    """按 git diff 结果收集文件与改动行范围。"""
    ok, diff_text = run_git(repo, ["diff", "--unified=0", "--no-color"] + diff_args)
    if not ok:
        notes.append("git diff 执行失败：%s" % diff_text)
        return []
    entries = []
    for rel_path, ranges in parse_diff_ranges(diff_text).items():
        if is_skipped(rel_path):
            continue
        entry = make_entry(repo, rel_path, ranges)
        if entry:
            entries.append(entry)
    return entries


def collect_untracked(repo, notes):
    """收集未跟踪的新文件，整份视为改动。"""
    ok, out = run_git(repo, ["ls-files", "--others", "--exclude-standard"])
    if not ok:
        notes.append("列出未跟踪文件失败：%s" % out)
        return []
    entries = []
    for rel_path in out.splitlines():
        rel_path = rel_path.strip()
        if not rel_path or is_skipped(rel_path):
            continue
        entry = make_entry(repo, rel_path, [])
        if entry:
            entry["changed_lines"] = [[1, entry["lines"]]]
            entry["untracked"] = True
            entries.append(entry)
    return entries


def walk_paths(repo, targets, notes):
    """遍历指定路径（文件或目录）下的全部可扫描文件。"""
    entries = []
    for target in targets:
        abs_target = target if os.path.isabs(target) else os.path.join(repo, target)
        if os.path.isfile(abs_target):
            rel = os.path.relpath(abs_target, repo)
            entry = make_entry(repo, rel, [])
            if entry:
                entries.append(entry)
            continue
        if not os.path.isdir(abs_target):
            notes.append("路径不存在，已跳过：%s" % target)
            continue
        for root, dirs, files in os.walk(abs_target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                rel = os.path.relpath(os.path.join(root, name), repo)
                if is_skipped(rel):
                    continue
                entry = make_entry(repo, rel, [])
                if entry:
                    entries.append(entry)
    return entries


def build_scope(args):
    repo = os.path.abspath(args.repo)
    notes = []
    mode = "paths" if args.mode == "l1" else args.mode
    base = None

    ok, _ = run_git(repo, ["rev-parse", "--is-inside-work-tree"])
    is_git = ok
    if not is_git and mode in ("l2", "l3"):
        notes.append("目标目录不是 git 仓库，%s 模式不可用；请改用 --mode paths 或 --mode repo。" % mode.upper())
        entries = []
    elif mode == "l2":
        entries = collect_from_git_diff(repo, ["HEAD"], notes)
        entries += collect_untracked(repo, notes)
        if not entries:
            notes.append("工作区没有可扫描的变更。若要扫已提交的改动请用 --mode l3，扫指定范围请用 --mode paths。")
    elif mode == "l3":
        base, reason = resolve_l3_base(repo, args.base)
        if base is None:
            notes.append(reason)
            entries = []
        else:
            notes.append(reason + "：%s..HEAD" % base)
            entries = collect_from_git_diff(repo, ["%s..HEAD" % base], notes)
            if not entries:
                notes.append("该区间没有已提交的变更。若改动都还在工作区，应退回 --mode l2。")
    elif mode == "repo":
        entries = walk_paths(repo, [repo], notes)
    else:
        if not args.path:
            notes.append("paths 模式需要至少一个 --path 参数。")
            entries = []
        else:
            entries = walk_paths(repo, args.path, notes)

    # 同一文件可能被多个来源收集到，按路径去重并合并改动行
    merged = {}
    for entry in entries:
        existing = merged.get(entry["path"])
        if existing:
            existing["changed_lines"].extend(entry["changed_lines"])
        else:
            merged[entry["path"]] = entry
    entries = sorted(merged.values(), key=lambda e: e["path"])

    languages = {}
    for entry in entries:
        languages[entry["language"]] = languages.get(entry["language"], 0) + 1

    total_lines = sum(e["lines"] for e in entries)
    changed_total = sum(
        end - start + 1 for e in entries for start, end in e["changed_lines"]
    )
    over_limit = total_lines > args.limit
    if over_limit:
        notes.append(
            "扫描范围 %d 行已超过单次建议上限 %d 行：请按目录或提交区间拆成多轮，每轮单独出报告。"
            % (total_lines, args.limit)
        )

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "mode": args.mode.upper(),
        "repo": repo.replace("\\", "/"),
        "is_git_repo": is_git,
        "base": base,
        "files": entries,
        "total_files": len(entries),
        "total_lines": total_lines,
        "changed_lines_total": changed_total,
        "languages": dict(sorted(languages.items(), key=lambda kv: -kv[1])),
        "limit": args.limit,
        "over_limit": over_limit,
        "notes": notes,
    }


def main():
    parser = argparse.ArgumentParser(description="security-scan 扫描范围解析")
    parser.add_argument("--mode", required=True,
                        choices=["l1", "l2", "l3", "paths", "repo"])
    parser.add_argument("--repo", default=".", help="目标仓库根目录，默认当前目录")
    parser.add_argument("--path", action="append", default=[],
                        help="paths / l1 模式下的目标文件或目录，可重复")
    parser.add_argument("--base", help="L3 模式的比较基线，例如 origin/main 或 HEAD~3")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                        help="单次扫描建议行数上限，默认 %d" % DEFAULT_LIMIT)
    parser.add_argument("--out", help="输出 JSON 文件路径；不给则打印到标准输出")
    args = parser.parse_args()

    scope = build_scope(args)
    text = json.dumps(scope, ensure_ascii=False, indent=2)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        summary = "范围已写入 %s：%d 个文件 / %d 行" % (
            args.out, scope["total_files"], scope["total_lines"])
        if scope["languages"]:
            summary += "，语言：" + "、".join(
                "%s(%d)" % (k, v) for k, v in scope["languages"].items())
        print(summary)
        for note in scope["notes"]:
            print("  提示：" + note)
    else:
        print(text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
