#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""security-scan · 报告渲染

把 findings.json 渲染成 Markdown 与自包含 HTML 两份报告。
字段规范见 references/report-format.md；本脚本只做渲染，不做任何安全判定。

用法：
  python render_report.py --findings findings.json --out-dir .tmp/security-scan/20260725-101500/
  可选：--md-name report.md --html-name report.html
"""

import argparse
import html
import json
import os
import sys

# Windows 控制台默认用本地码页，强制 UTF-8 以免中文输出乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {
    "critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示",
}
CONFIDENCE_LABEL = {
    "confirmed": "已确认", "likely": "较可能", "needs-review": "待人工确认",
}
STATUS_LABEL = {
    "open": "待修复", "fixed": "已修复", "accepted-risk": "已接受风险",
    "false-positive": "误报已撤回",
}
VERDICT_LABEL = {
    "block": "存在阻断级问题，不建议提交 / 推送",
    "caution": "有需要处理的问题，可评估后再决定是否放行",
    "pass": "本次范围内未发现需要阻断的问题",
}
ROLE_LABEL = {
    "source": "入口", "propagation": "传播", "sanitizer": "净化", "sink": "汇聚点",
}


def load_findings(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data.get("findings"), list):
        raise ValueError("findings.json 缺少 findings 数组")
    problems = []
    for idx, item in enumerate(data["findings"]):
        for field in ("id", "severity", "title"):
            if not item.get(field):
                problems.append("第 %d 条 finding 缺少必填字段 %s" % (idx + 1, field))
        if item.get("severity") not in SEVERITY_ORDER:
            problems.append("第 %d 条 finding 的 severity 非法：%r" % (idx + 1, item.get("severity")))
    if problems:
        raise ValueError("findings.json 校验未通过：\n  - " + "\n  - ".join(problems))
    return data


def sort_findings(findings):
    return sorted(findings, key=lambda f: (
        SEVERITY_ORDER.index(f["severity"]), str(f.get("id", ""))))


def count_by_severity(findings):
    counts = {level: 0 for level in SEVERITY_ORDER}
    for item in findings:
        counts[item["severity"]] += 1
    return counts


def location_text(finding):
    loc = finding.get("location") or {}
    text = "%s:%s" % (loc.get("file", "?"), loc.get("line", "?"))
    if loc.get("symbol"):
        text += " (%s)" % loc["symbol"]
    return text


def cwe_owasp_text(finding):
    parts = [p for p in (finding.get("cwe"), finding.get("owasp")) if p]
    return " · ".join(parts) if parts else "—"


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------

def render_markdown(data):
    findings = sort_findings(data["findings"])
    counts = count_by_severity(findings)
    lines = []
    add = lines.append

    add("# 代码安全扫描报告")
    add("")
    add("| 项 | 内容 |")
    add("| --- | --- |")
    add("| 扫描目标 | %s |" % data.get("target", "—"))
    add("| 扫描模式 | %s |" % data.get("mode", "—"))
    add("| 仓库 | %s |" % data.get("repo", "—"))
    scanned = data.get("scanned") or {}
    add("| 扫描范围 | %s 个文件 / %s 行，预筛候选点 %s 处 |" % (
        scanned.get("files", "—"), scanned.get("lines", "—"), scanned.get("candidates", "—")))
    add("| 完成时间 | %s |" % data.get("scan_finished_at", "—"))
    add("| 总体结论 | %s |" % VERDICT_LABEL.get(data.get("verdict", ""), data.get("verdict", "—")))
    add("")
    add("**问题分布**：" + "，".join(
        "%s %d" % (SEVERITY_LABEL[level], counts[level]) for level in SEVERITY_ORDER))
    add("")
    if data.get("summary"):
        add(data["summary"])
        add("")

    add("## 问题清单")
    add("")
    if not findings:
        add("本次扫描范围内未发现成立的安全问题。已核查的候选点见下方「已核查但未上报」。")
        add("")
    else:
        add("| # | 严重级别 | 问题 | CWE · OWASP | 位置 | 置信度 | 状态 |")
        add("| --- | --- | --- | --- | --- | --- | --- |")
        for item in findings:
            add("| %s | %s | %s | %s | `%s` | %s | %s |" % (
                item["id"],
                SEVERITY_LABEL[item["severity"]],
                item["title"],
                cwe_owasp_text(item),
                location_text(item),
                CONFIDENCE_LABEL.get(item.get("confidence", ""), item.get("confidence", "—")),
                STATUS_LABEL.get(item.get("fix_status", "open"), item.get("fix_status", "—")),
            ))
        add("")

        add("## 问题详情")
        add("")
        for item in findings:
            add("### %s · [%s] %s" % (item["id"], SEVERITY_LABEL[item["severity"]], item["title"]))
            add("")
            add("- **位置**：`%s`" % location_text(item))
            add("- **分类**：%s（%s）" % (item.get("category", "—"), cwe_owasp_text(item)))
            add("- **置信度**：%s ｜ **状态**：%s" % (
                CONFIDENCE_LABEL.get(item.get("confidence", ""), item.get("confidence", "—")),
                STATUS_LABEL.get(item.get("fix_status", "open"), item.get("fix_status", "—"))))
            add("")
            if item.get("summary"):
                add(item["summary"])
                add("")
            if item.get("flow"):
                add("**数据传播路径**")
                add("")
                for step in item["flow"]:
                    add("%s. `%s:%s` **%s** — %s" % (
                        step.get("step", "-"), step.get("file", "?"), step.get("line", "?"),
                        ROLE_LABEL.get(step.get("role", ""), step.get("role", "")),
                        step.get("desc", "")))
                add("")
            if item.get("trigger_condition"):
                add("**触发条件**：%s" % item["trigger_condition"])
                add("")
            if item.get("sanitizer_analysis"):
                add("**路径上的校验为什么不足**：%s" % item["sanitizer_analysis"])
                add("")
            if item.get("impact"):
                add("**影响**：%s" % item["impact"])
                add("")
            for block in item.get("code", []):
                add("**涉及代码** `%s:%s`" % (block.get("file", "?"), block.get("start_line", "?")))
                add("")
                add("```" + block.get("language", ""))
                add(block.get("content", "").rstrip("\n"))
                add("```")
                add("")
            if item.get("remediation"):
                add("**修复建议**")
                add("")
                add(item["remediation"])
                add("")
            if item.get("references"):
                add("**参考**：" + "、".join(item["references"]))
                add("")

    not_reported = data.get("not_reported") or []
    add("## 已核查但未上报")
    add("")
    if not_reported:
        add("以下候选点已逐个核查，判定不构成安全问题：")
        add("")
        add("| 位置 | 命中规则 | 未上报原因 |")
        add("| --- | --- | --- |")
        for item in not_reported:
            add("| `%s:%s` | %s | %s |" % (
                item.get("file", "?"), item.get("line", "?"),
                item.get("rule_id", "—"), item.get("reason", "—")))
    else:
        add("无。")
    add("")

    add("## 能力边界")
    add("")
    for note in data.get("limitations") or [
        "本次扫描面向指定范围的静态分析，不是完整安全审计，不保证发现所有漏洞。",
        "结论取决于可读到的代码上下文；跨服务调用、运行时动态加载、闭源依赖内部逻辑可能超出分析范围。",
        "未构造攻击载荷，未对任何运行中的系统发起实际攻击。",
        "关键业务代码仍需人工安全评审、依赖扫描与组织既有安全流程配合。",
    ]:
        add("- " + note)
    add("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# HTML
# --------------------------------------------------------------------------

CSS = """
:root{--bg:#fbfbfd;--fg:#1a1a1f;--muted:#61616b;--card:#fff;--border:#e3e3ea;
--code-bg:#f4f4f8;--accent:#3b5bdb;
--critical:#b3261e;--high:#c0480a;--medium:#8a6100;--low:#1663a8;--info:#5c636a;}
@media (prefers-color-scheme:dark){:root{--bg:#131318;--fg:#e8e8ee;--muted:#9a9aa6;
--card:#1c1c23;--border:#2e2e38;--code-bg:#16161c;--accent:#8ea3ff;
--critical:#ff7a70;--high:#ffa14d;--medium:#ffd150;--low:#7bb8ff;--info:#a8b0b8;}}
*{box-sizing:border-box}
body{margin:0;padding:0;background:var(--bg);color:var(--fg);
font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:32px 20px 72px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:19px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--border)}
h3{font-size:16px;margin:0 0 10px}
a{color:var(--accent)}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px;margin:18px 0}
.meta div{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:10px 12px}
.meta dt{font-size:12px;color:var(--muted);margin:0 0 2px}
.meta dd{margin:0;font-size:14px;word-break:break-all}
.verdict{display:inline-block;padding:6px 14px;border-radius:999px;font-weight:600;font-size:14px;
border:1px solid var(--border);background:var(--card)}
.verdict.block{color:var(--critical);border-color:var(--critical)}
.verdict.caution{color:var(--medium);border-color:var(--medium)}
.verdict.pass{color:var(--low);border-color:var(--low)}
.counts{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}
.pill{border:1px solid var(--border);border-radius:6px;padding:5px 11px;font-size:13px;background:var(--card)}
.pill b{font-size:15px}
.sev{font-weight:700}
.sev-critical{color:var(--critical)}.sev-high{color:var(--high)}
.sev-medium{color:var(--medium)}.sev-low{color:var(--low)}.sev-info{color:var(--info)}
.tablewrap{overflow-x:auto;border:1px solid var(--border);border-radius:8px;background:var(--card)}
table{border-collapse:collapse;width:100%;min-width:720px;font-size:14px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
.card{background:var(--card);border:1px solid var(--border);border-left-width:4px;
border-radius:8px;padding:16px 18px;margin:14px 0}
.card.critical{border-left-color:var(--critical)}.card.high{border-left-color:var(--high)}
.card.medium{border-left-color:var(--medium)}.card.low{border-left-color:var(--low)}
.card.info{border-left-color:var(--info)}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 10px}
.tag{font-size:12px;border:1px solid var(--border);border-radius:5px;padding:2px 8px;color:var(--muted)}
.field{margin:10px 0}
.field .k{font-size:12px;color:var(--muted);margin-bottom:3px}
ol.flow{margin:6px 0;padding-left:20px}
ol.flow li{margin:5px 0}
.role{font-size:11px;border-radius:4px;padding:1px 6px;margin-right:6px;
border:1px solid var(--border);color:var(--muted)}
code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,"Cascadia Code",monospace}
code{background:var(--code-bg);padding:1px 5px;border-radius:4px;font-size:13px}
pre{background:var(--code-bg);border:1px solid var(--border);border-radius:6px;
padding:12px;overflow-x:auto;font-size:13px;margin:6px 0}
pre code{background:none;padding:0}
details{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin:10px 0}
summary{cursor:pointer;font-weight:600}
.muted{color:var(--muted);font-size:13px}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--border);color:var(--muted);font-size:13px}
"""


def esc(value):
    return html.escape(str(value if value is not None else ""))


def render_html(data):
    findings = sort_findings(data["findings"])
    counts = count_by_severity(findings)
    scanned = data.get("scanned") or {}
    verdict = data.get("verdict", "")
    out = []
    add = out.append

    add("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">")
    add("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
    add("<title>代码安全扫描报告 · %s</title>" % esc(data.get("target", "")))
    add("<style>%s</style></head><body><div class=\"wrap\">" % CSS)

    add("<h1>代码安全扫描报告</h1>")
    add("<p class=\"muted\">%s ｜ 模式 %s ｜ 完成于 %s</p>" % (
        esc(data.get("target", "—")), esc(data.get("mode", "—")),
        esc(data.get("scan_finished_at", "—"))))
    add("<p><span class=\"verdict %s\">%s</span></p>" % (
        esc(verdict), esc(VERDICT_LABEL.get(verdict, verdict or "—"))))

    add("<div class=\"meta\">")
    for key, value in (
        ("仓库", data.get("repo", "—")),
        ("扫描文件数", scanned.get("files", "—")),
        ("扫描行数", scanned.get("lines", "—")),
        ("预筛候选点", scanned.get("candidates", "—")),
    ):
        add("<div><dt>%s</dt><dd>%s</dd></div>" % (esc(key), esc(value)))
    add("</div>")

    add("<div class=\"counts\">")
    for level in SEVERITY_ORDER:
        add("<span class=\"pill\"><b class=\"sev sev-%s\">%d</b> %s</span>" % (
            level, counts[level], SEVERITY_LABEL[level]))
    add("</div>")

    if data.get("summary"):
        add("<p>%s</p>" % esc(data["summary"]))

    add("<h2>问题清单</h2>")
    if not findings:
        add("<p>本次扫描范围内未发现成立的安全问题。已核查的候选点见下方「已核查但未上报」。</p>")
    else:
        add("<div class=\"tablewrap\"><table><thead><tr>"
            "<th>#</th><th>严重级别</th><th>问题</th><th>CWE · OWASP</th>"
            "<th>位置</th><th>置信度</th><th>状态</th></tr></thead><tbody>")
        for item in findings:
            add("<tr><td><a href=\"#%s\">%s</a></td>"
                "<td class=\"sev sev-%s\">%s</td><td>%s</td><td>%s</td>"
                "<td><code>%s</code></td><td>%s</td><td>%s</td></tr>" % (
                    esc(item["id"]), esc(item["id"]),
                    esc(item["severity"]), SEVERITY_LABEL[item["severity"]],
                    esc(item["title"]), esc(cwe_owasp_text(item)), esc(location_text(item)),
                    esc(CONFIDENCE_LABEL.get(item.get("confidence", ""), item.get("confidence", "—"))),
                    esc(STATUS_LABEL.get(item.get("fix_status", "open"), item.get("fix_status", "—")))))
        add("</tbody></table></div>")

        add("<h2>问题详情</h2>")
        for item in findings:
            add("<div class=\"card %s\" id=\"%s\">" % (esc(item["severity"]), esc(item["id"])))
            add("<h3><span class=\"sev sev-%s\">[%s]</span> %s · %s</h3>" % (
                esc(item["severity"]), SEVERITY_LABEL[item["severity"]],
                esc(item["id"]), esc(item["title"])))
            add("<div class=\"tags\">")
            for tag in (
                location_text(item), item.get("category"), item.get("cwe"), item.get("owasp"),
                CONFIDENCE_LABEL.get(item.get("confidence", ""), item.get("confidence")),
                STATUS_LABEL.get(item.get("fix_status", "open"), item.get("fix_status")),
            ):
                if tag:
                    add("<span class=\"tag\">%s</span>" % esc(tag))
            add("</div>")

            if item.get("summary"):
                add("<p>%s</p>" % esc(item["summary"]))
            if item.get("flow"):
                add("<div class=\"field\"><div class=\"k\">数据传播路径</div><ol class=\"flow\">")
                for step in item["flow"]:
                    add("<li><span class=\"role\">%s</span><code>%s:%s</code> — %s</li>" % (
                        esc(ROLE_LABEL.get(step.get("role", ""), step.get("role", ""))),
                        esc(step.get("file", "?")), esc(step.get("line", "?")),
                        esc(step.get("desc", ""))))
                add("</ol></div>")
            for key, label in (
                ("trigger_condition", "触发条件"),
                ("sanitizer_analysis", "路径上的校验为什么不足"),
                ("impact", "影响"),
            ):
                if item.get(key):
                    add("<div class=\"field\"><div class=\"k\">%s</div><div>%s</div></div>" % (
                        label, esc(item[key])))
            for block in item.get("code", []):
                add("<div class=\"field\"><div class=\"k\">涉及代码 %s:%s</div>"
                    "<pre><code>%s</code></pre></div>" % (
                        esc(block.get("file", "?")), esc(block.get("start_line", "?")),
                        esc(block.get("content", ""))))
            if item.get("remediation"):
                add("<div class=\"field\"><div class=\"k\">修复建议</div><div>%s</div></div>"
                    % esc(item["remediation"]))
            if item.get("references"):
                add("<div class=\"field\"><div class=\"k\">参考</div><div class=\"muted\">%s</div></div>"
                    % esc("、".join(item["references"])))
            add("</div>")

    not_reported = data.get("not_reported") or []
    add("<h2>已核查但未上报</h2>")
    if not_reported:
        add("<details open><summary>%d 处候选点已核查，判定不构成安全问题</summary>"
            "<div class=\"tablewrap\" style=\"margin-top:10px\"><table><thead><tr>"
            "<th>位置</th><th>命中规则</th><th>未上报原因</th></tr></thead><tbody>"
            % len(not_reported))
        for item in not_reported:
            add("<tr><td><code>%s:%s</code></td><td>%s</td><td>%s</td></tr>" % (
                esc(item.get("file", "?")), esc(item.get("line", "?")),
                esc(item.get("rule_id", "—")), esc(item.get("reason", "—"))))
        add("</tbody></table></div></details>")
    else:
        add("<p class=\"muted\">无。</p>")

    add("<footer><strong>能力边界</strong><ul>")
    for note in data.get("limitations") or [
        "本次扫描面向指定范围的静态分析，不是完整安全审计，不保证发现所有漏洞。",
        "结论取决于可读到的代码上下文；跨服务调用、运行时动态加载、闭源依赖内部逻辑可能超出分析范围。",
        "未构造攻击载荷，未对任何运行中的系统发起实际攻击。",
        "关键业务代码仍需人工安全评审、依赖扫描与组织既有安全流程配合。",
    ]:
        add("<li>%s</li>" % esc(note))
    add("</ul></footer></div></body></html>")
    return "".join(out)


def main():
    parser = argparse.ArgumentParser(description="security-scan 报告渲染")
    parser.add_argument("--findings", required=True, help="findings.json 路径")
    parser.add_argument("--out-dir", required=True, help="报告输出目录")
    parser.add_argument("--md-name", default="report.md")
    parser.add_argument("--html-name", default="report.html")
    args = parser.parse_args()

    try:
        data = load_findings(args.findings)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("读取 findings.json 失败：%s" % exc, file=sys.stderr)
        return 1

    os.makedirs(args.out_dir, exist_ok=True)
    md_path = os.path.join(args.out_dir, args.md_name)
    html_path = os.path.join(args.out_dir, args.html_name)

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(data))
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(render_html(data))

    counts = count_by_severity(data["findings"])
    print("报告已生成：")
    print("  Markdown：%s" % md_path)
    print("  HTML：%s" % html_path)
    print("  问题分布：" + "，".join(
        "%s %d" % (SEVERITY_LABEL[level], counts[level]) for level in SEVERITY_ORDER))
    return 0


if __name__ == "__main__":
    sys.exit(main())
