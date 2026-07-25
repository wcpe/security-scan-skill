# C# / .NET 判定要点

只收录容易判错的部分；通用方法见 `../taint-analysis.md`。

## FromSqlRaw 与 FromSqlInterpolated 只差一个词

```csharp
db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}")  // 安全：插值被转成参数
db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name = {name}")           // 注入：字符串先被拼好
```

`FromSqlRaw` / `ExecuteSqlRaw` 接收的是已经拼好的字符串；`FromSqlInterpolated` / `ExecuteSqlInterpolated` 接收 `FormattableString` 并参数化。看到 `Raw` + `$"..."` 组合直接判注入。

其余 SQL 要点：`new SqlCommand($"...")` 与 `CommandText = $"..."` 是拼接；`SqlParameter` / `Parameters.AddWithValue` 是绑定（`AddWithValue` 会推断类型，可能引起隐式转换与索引失效，属性能问题不是安全问题）。标识符仍需白名单。

## 路径：Path.Combine 的绝对路径覆盖

```csharp
Path.Combine(@"C:\data", @"C:\Windows\System32\x")  // -> @"C:\Windows\System32\x"
Path.Combine("/var/data", "/etc/passwd")            // -> "/etc/passwd"
```

第二段是绝对路径（或以分隔符开头）时，第一段被整个丢弃。这是 .NET 路径穿越最常见的形态，比 `../` 更容易被漏。

正确写法是 `Path.GetFullPath` 后做带分隔符的前缀比较；只取文件名时用 `Path.GetFileName`（会剥掉目录成分）。注意 Windows 的保留设备名（`CON`、`NUL`、`COM1`）与 ADS（`file.txt:stream`）。

## 进程

- `Process.Start(new ProcessStartInfo { FileName = "x", Arguments = userInput })` 的 `Arguments` 是**单个字符串**，由目标程序自行拆词——不经 shell，但存在选项注入与引号逃逸。
- `UseShellExecute = true` 时交给操作系统 shell 处理，`FileName` 可控可执行任意已注册协议 / 文档。
- .NET Core 2.1+ 提供 `ArgumentList`，逐个添加参数不需要自己处理引号，是推荐写法。

## 反序列化

- `BinaryFormatter` 处理不可信数据即 RCE；.NET 5 起标记过时，.NET 9 已移除。同类还有 `NetDataContractSerializer`、`LosFormatter`、`ObjectStateFormatter`、`SoapFormatter`、`JavaScriptSerializer` + 自定义 `SimpleTypeResolver`。
- Json.NET：`TypeNameHandling` 设为 `All` / `Objects` / `Auto` / `Arrays` 时报文可指定类型，需配 `SerializationBinder` 白名单。`System.Text.Json` 默认不支持多态，相对安全。
- ViewState：`enableViewStateMac="false"` 或机器密钥泄露会导致反序列化 RCE（老 WebForms 项目）。

## XML

- **默认值随框架版本变化**：.NET Framework 4.5.2 之前 `XmlDocument` / `XmlTextReader` 默认解析外部实体；4.5.2 之后与 .NET Core 默认 `XmlResolver = null`（安全）。判定前先确认目标框架。
- 显式写了 `XmlResolver = new XmlUrlResolver()` 或 `DtdProcessing = DtdProcessing.Parse` 就是主动打开。
- `XmlSerializer` 本身不解析外部实体，但读取时用的 reader 可能会。

## Web 与认证

- Razor 默认 HTML 编码；开口是 `@Html.Raw(...)`、`new HtmlString(...)`、`Response.Write`、`MvcHtmlString`。
- 过度提交：直接把 EF 实体当 action 参数绑定，用户可赋值 `IsAdmin`、`Role`。用 DTO 或 `[Bind(Include=...)]`。
- `[Authorize]` 漏加在某个 controller / action 上是最常见的越权来源；`[AllowAnonymous]` 会覆盖控制器级的 `[Authorize]`。
- `[ValidateAntiForgeryToken]` 缺失 + Cookie 认证 = CSRF。
- 中间件顺序：`UseAuthentication` / `UseAuthorization` 必须在 `UseEndpoints` 之前且在静态文件之后，顺序错等于不生效。
- `ServerCertificateValidationCallback = (a,b,c,d) => true` 关闭证书校验。

## 加密与随机

- `new Random()` 不是密码学随机（且短时间内多次 new 可能产生相同序列）；令牌用 `RandomNumberGenerator.GetBytes`。
- `MD5.Create()` / `SHA1.Create()` 用于口令或签名不可接受；口令用 `Rfc2898DeriveBytes`（PBKDF2，迭代次数要够）或 ASP.NET Identity 的默认实现。
- 比较密钥用 `CryptographicOperations.FixedTimeEquals`。
- `AesManaged` 默认 CBC；写死 IV 或用零 IV 是问题。

## 其他

- `string.Format` / 插值字符串本身不是漏洞，但它们出现在 SQL / 命令 / 路径 / HTML 的构造处就是信号。
- LINQ 到内存的 `Where(x => x.Owner == user)` 若忘了写，就是越权——.NET 项目里越权多发于仓储层缺少归属过滤。
- `HttpClient` 默认跟随重定向：SSRF 校验需 `AllowAutoRedirect = false` 或逐跳校验。
- 异常信息：`UseDeveloperExceptionPage` 在生产开启会泄露堆栈与连接串。
