# findings.json 字段规范与报告写法

`render_report.py` 只做渲染，报告的全部质量都取决于这份 JSON。写完先自查文末的清单再渲染。

## 顶层结构

```json
{
  "target": "工作区变更（L2）",
  "mode": "L2",
  "repo": "D:/proj/demo",
  "scanned": { "files": 12, "lines": 3412, "candidates": 57 },
  "scan_started_at": "2026-07-25 10:12:03",
  "scan_finished_at": "2026-07-25 10:19:41",
  "verdict": "block",
  "summary": "本次变更新增的封面导入接口把用户提交的 URL 直接交给服务端下载，构成 SSRF；其余 3 处候选点确认不成立。建议修复后再提交。",
  "findings": [ ... ],
  "not_reported": [ ... ],
  "limitations": [ ... ]
}
```

| 字段 | 必填 | 说明 |
|---|---|---|
| `target` | 是 | 人话描述扫了什么，例如「工作区变更（L2）」「src/auth 与 src/export 目录」「origin/main..HEAD 共 7 个提交」 |
| `mode` | 是 | `L1` / `L2` / `L3` / `FULL` |
| `repo` | 是 | 仓库根目录 |
| `scanned` | 是 | `files` / `lines` 取自 scope.json，`candidates` 取自 candidates.json |
| `scan_started_at`、`scan_finished_at` | 是 | `YYYY-MM-DD HH:MM:SS` |
| `verdict` | 是 | `block`（有阻断级问题，不建议提交/推送）/ `caution`（有问题但可评估后放行）/ `pass`（本次范围内无需阻断） |
| `summary` | 是 | 2–4 句总体判断。说清楚发现了什么、最要紧的是哪条、建议下一步做什么 |
| `findings` | 是 | 数组，可以为空 |
| `not_reported` | 是 | 查过但判定不成立的候选点，**不要留空数组糊弄过去** |
| `limitations` | 否 | 不填则渲染默认的四条能力边界；范围被拆分、有文件读不到等情况要显式补充 |

## finding 结构

```json
{
  "id": "SEC-001",
  "severity": "high",
  "confidence": "confirmed",
  "title": "封面导入接口未限制目标地址，可访问内网服务（SSRF）",
  "category": "ssrf",
  "cwe": "CWE-918",
  "owasp": "A10:2021 服务端请求伪造",
  "location": { "file": "API/Controllers/UploadController.cs", "line": 214, "symbol": "UploadByUrl" },
  "summary": "管理员接口 upload-by-url 接收调用方提交的 URL，未校验协议与目标网段即由服务端发起下载，且跟随重定向，可用于探测和访问内网服务。",
  "flow": [
    { "step": 1, "role": "source",      "file": "API/Controllers/UploadController.cs", "line": 198, "desc": "DTO 的 Url 字段来自请求体，调用方完全可控" },
    { "step": 2, "role": "propagation", "file": "API/Controllers/UploadController.cs", "line": 207, "desc": "仅去掉 query 参数用于推导扩展名，未对地址本身做任何校验" },
    { "step": 3, "role": "sink",        "file": "API/Services/ImageService.cs",        "line": 88,  "desc": "HttpClient 直接 GET 该地址并写入临时目录，默认跟随重定向" }
  ],
  "trigger_condition": "需要管理员身份；无需其他前置条件。",
  "sanitizer_analysis": "路径上只有 SanitizeExtension()，它只处理扩展名字符串，与目标地址无关；没有任何协议或网段限制。",
  "impact": "可探测内网存活主机与端口、读取云厂商元数据接口、以服务端身份访问仅内网可达的管理接口。",
  "code": [
    { "file": "API/Services/ImageService.cs", "start_line": 86, "language": "csharp",
      "content": "var client = _httpClientFactory.CreateClient();\nvar bytes = await client.GetByteArrayAsync(url);\nawait File.WriteAllBytesAsync(tempPath, bytes);" }
  ],
  "remediation": "限定协议为 http/https；解析域名后校验目标 IP 不在回环、私网、链路本地（含 169.254.169.254）网段；禁用自动重定向或对每一跳重新校验；保留原有「从 URL 导入封面」能力不变。",
  "fix_status": "open",
  "references": ["https://cwe.mitre.org/data/definitions/918.html"]
}
```

### 各字段的写法要求

| 字段 | 必填 | 要求 |
|---|---|---|
| `id` | 是 | `SEC-001` 递增，全报告唯一 |
| `severity` | 是 | `critical` / `high` / `medium` / `low` / `info`，判据见 `taint-analysis.md` 第八节 |
| `confidence` | 是 | `confirmed` / `likely` / `needs-review` |
| `title` | 是 | 一句话说清「哪里的什么问题」。写「SQL 注入」不合格，写「导出接口的排序字段直接拼进 ORDER BY，构成 SQL 标识符注入」才合格 |
| `category` | 是 | 与 rules.json 的 category 取值一致，便于聚合 |
| `cwe` | 是 | `CWE-89` 形式 |
| `owasp` | 建议 | OWASP Top 10 2021 条目，见下表 |
| `location` | 是 | 最能代表该问题的位置，通常是 sink。**行号必须核对过** |
| `summary` | 是 | 2–3 句：数据从哪来、怎么到的、会造成什么 |
| `flow` | 是 | 至少 source 与 sink 两步，中间跳能给就给。`role` 取 `source` / `propagation` / `sanitizer` / `sink` |
| `trigger_condition` | 是 | 需要什么身份、什么前置配置、什么时序。无条件就写「无需认证即可触发」 |
| `sanitizer_analysis` | 是 | 路径上有校验时，说明**读了实现后**为什么不足；确实没有任何校验就写「路径上没有任何校验」 |
| `impact` | 是 | 具体后果，不要写「可能造成安全风险」这种空话 |
| `code` | 建议 | 关键片段，3–15 行为宜。`content` 用真实代码，别改写 |
| `remediation` | 是 | 可直接照做的方案，优先结构化传参 / 允许列表；**明确说明如何保住原有业务能力** |
| `fix_status` | 是 | `open` / `fixed` / `accepted-risk` / `false-positive` |
| `references` | 否 | CWE、OWASP、框架安全文档链接 |

## not_reported 结构

```json
{ "file": "src/util/exec.py", "line": 33, "rule_id": "py-sink-shell-true", "reason": "命令模板固定在代码常量里，唯一变量已用 shlex.quote 转义，且调用方全部传枚举值" }
```

每条都要给出**具体**的排除理由。「不可控」三个字不够，要说清楚为什么不可控。

## CWE 与 OWASP Top 10 2021 对照

| 类别 | CWE | OWASP 2021 |
|---|---|---|
| SQL 注入 | CWE-89 | A03 注入 |
| 命令注入 | CWE-78 | A03 注入 |
| 代码注入 / 动态求值 | CWE-94 | A03 注入 |
| 模板注入 SSTI | CWE-1336 / CWE-917 | A03 注入 |
| XSS | CWE-79 | A03 注入 |
| NoSQL 注入 | CWE-943 | A03 注入 |
| LDAP 注入 | CWE-90 | A03 注入 |
| 路径穿越 / Zip Slip | CWE-22 | A01 访问控制失效 |
| 越权访问对象 | CWE-639 | A01 访问控制失效 |
| 缺少权限校验 | CWE-862 / CWE-863 | A01 访问控制失效 |
| 开放重定向 | CWE-601 | A01 访问控制失效 |
| 不安全反序列化 | CWE-502 | A08 软件与数据完整性失效 |
| 不可信来源加载代码 | CWE-829 | A08 软件与数据完整性失效 |
| SSRF | CWE-918 | A10 服务端请求伪造 |
| XXE | CWE-611 | A05 安全配置错误 |
| CORS 配置错误 | CWE-942 | A05 安全配置错误 |
| 关闭 TLS 校验 | CWE-295 | A02 加密机制失效 |
| 弱算法 / 弱模式 | CWE-327 | A02 加密机制失效 |
| 弱随机数 | CWE-338 / CWE-330 | A02 加密机制失效 |
| 硬编码凭据 | CWE-798 | A07 身份识别与认证失效 |
| 会话固定 / 失效缺陷 | CWE-384 / CWE-613 | A07 身份识别与认证失效 |
| 认证绕过 | CWE-287 | A07 身份识别与认证失效 |
| 批量赋值 | CWE-915 | A08 软件与数据完整性失效 |
| 原型链污染 | CWE-1321 | A08 软件与数据完整性失效 |
| 竞态 / TOCTOU | CWE-367 / CWE-362 | A04 不安全设计 |
| 敏感信息写入日志 | CWE-532 | A09 日志与监控失效 |

## 渲染前自查

1. 每条 finding 的 `flow` 里，source 与 sink 的 `file:line` 都实际打开核对过吗？
2. `sanitizer_analysis` 是读了净化函数实现之后写的，还是照着函数名猜的？
3. `severity` 与 `trigger_condition` 是否自洽？（需要管理员却标 critical，要有额外理由）
4. `remediation` 照做之后，原有功能还在吗？
5. `not_reported` 是不是空的？空的通常意味着候选点没有逐条核查。
6. 有没有同一条链路被拆成多条上报？
7. 报告里有没有出现完整的密钥、口令、令牌或个人敏感信息？必须脱敏。
8. `verdict` 与最高严重级别是否匹配？
