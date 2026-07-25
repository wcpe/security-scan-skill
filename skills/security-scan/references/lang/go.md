# Go 判定要点

只收录容易判错的部分；通用方法见 `../taint-analysis.md`。

## 命令执行：默认不经 shell

`exec.Command("git", "log", userArg)` **不走 shell**，`;` `|` `$()` 都只是普通字符。仅凭「拼进 exec.Command」判命令注入是误报。

真正的问题形态：

- 显式起 shell：`exec.Command("sh", "-c", cmd)` / `exec.Command("cmd", "/c", cmd)`。
- **程序名可控**：`exec.Command(userInput, ...)`。
- **选项注入**：可控参数以 `-` 开头，被目标程序当成选项（例如 `git` 的 `--upload-pack`、`tar` 的 `--to-command`）。防法是加 `--` 分隔或校验不以 `-` 开头。
- `exec.LookPath` 受 `PATH` 影响；Windows 上旧版本 Go 会先查当前目录。

## 路径

- `filepath.Join` 会 `Clean` 结果，所以 `filepath.Join("/base", "../etc/passwd")` 得到 `/etc/passwd` —— **拼接后直接跑出基准目录**，这是最常见的穿越形态。
- `filepath.Clean` 只做词法规范化，**不解析符号链接、不做归属约束**，单独用它当防护无效。
- 可用的防护：`filepath.IsLocal`（Go 1.20+，拒绝绝对路径与逃逸出当前目录的路径）、`os.Root`（Go 1.24+，把文件操作限制在目录内）、或 `filepath.EvalSymlinks` 后做带分隔符的前缀校验。
- `http.ServeFile` 会拒绝含 `..` 的请求路径，但如果你把路径从 query 参数里取出来自己拼，就绕过了这层保护。`http.FileServer` + `http.Dir` 是相对安全的组合。

## SQL

- `db.Query("... where id = ?", id)` 是绑定；`fmt.Sprintf` 拼出来的 SQL 就是注入。
- 标识符（表名、列名、排序字段）无法绑定，只能白名单。
- `database/sql` 的部分驱动默认不允许多语句，但不要依赖这一点。

## 模板与 XSS

- `html/template` 做**上下文相关**的自动转义（HTML / 属性 / JS / URL / CSS 各不相同），是安全默认。
- `text/template` **完全不转义**，用它渲染 HTML 就是 XSS。看 import 的是哪个包。
- `template.HTML(x)` / `template.JS(x)` / `template.URL(x)` 是显式声明「这段已安全」，把可控值转成这些类型即绕过转义。

## 类型与边界

- 整数转换静默截断：`int64` → `int32`、`int` → `int8`，以及 `len()` 的结果参与减法可能变负。文件大小、数量、偏移量的校验要注意溢出。
- `strconv.Atoi` 不做范围限制；负数常被忽略（分页 offset、数量字段）。
- `[]byte` 与 `string` 的转换会复制，但 `unsafe` 转换不会——`unsafe` 出现的地方要单独看。

## 并发

- Go 项目里竞态是高频问题：共享 map 无锁写、`sync.WaitGroup` 用错、闭包捕获循环变量（Go 1.22 前）。安全相关的形态是「先检查后使用」：先查配额 / 余额 / 是否已使用，再执行操作，中间无锁。
- `context` 超时缺失导致的资源耗尽属于可用性问题，视场景决定要不要报。

## 其他

- `tls.Config{InsecureSkipVerify: true}` 关闭证书校验。
- `math/rand` 不是密码学随机（Go 1.20+ 自动播种但依然可预测），令牌 / 密钥用 `crypto/rand`。
- `md5` / `sha1` 用于口令或签名不可接受。
- 比较密钥用 `crypto/subtle.ConstantTimeCompare`。
- `http.Server` 不设 `ReadTimeout` / `WriteTimeout` 会被慢连接拖垮（可用性问题，通常 low）。
- `json.Unmarshal` 到结构体时字段是显式的，过度提交风险低；但 `map[string]interface{}` 后再动态赋值就回到了批量赋值问题。
- 错误被忽略（`_ = doAuth()`）会让安全校验静默失效——Go 里这是链路成立的常见原因。
- SSRF：`http.Client` 默认跟随重定向，需要自定义 `CheckRedirect` 逐跳校验。
