# JavaScript / TypeScript / Node 判定要点

只收录容易判错的部分；通用方法见 `../taint-analysis.md`。

## TypeScript 的类型不是运行时校验

`req.body` 被声明成 `{ id: string }` 不代表运行时真的是字符串——攻击者可以传数组、对象、`null`。这一点是好几类漏洞的起点：

- `{"password": {"$ne": null}}` 传进 Mongo 查询 → NoSQL 认证绕过。
- 声明为 `string` 的字段实际是数组，导致 `startsWith` 等校验静默失败或抛错。
- `id` 传对象绕过 `id !== currentUser.id` 这类比较。

**只有 zod / joi / yup / class-validator 这类运行时校验才算数。** 判定时不要把 TS 类型标注当成 sanitizer。

## 命令执行

- `child_process.exec` / `execSync` **走 shell**，元字符全部危险。
- `execFile` / `spawn` 传数组参数**不走 shell**，是安全写法——除非显式写了 `{ shell: true }`（等于退回 exec）。
- 不走 shell 时仍要看程序名是否可控、参数是否会被目标程序当选项解析。

## 路径

- `path.join('/base', userInput)` 会 normalize，但 `../` 照样能跑出 `/base`。它**不做归属约束**。
- `path.resolve('/base', '/etc/passwd')` → `/etc/passwd`，绝对路径直接覆盖前缀。
- 正确写法是 `const p = path.resolve(base, input); if (!p.startsWith(base + path.sep)) reject();` —— **`+ path.sep` 不能省**，否则 `/base-evil` 会通过。
- `res.sendFile(p)` 需要传 `{ root }` 才有内置约束；`express.static` 的 `dotfiles`、`index` 选项影响暴露面。
- `decodeURIComponent` 多解一次码会让「解码前校验」失效。

## 注入

- 模板字符串进 SQL：`` db.query(`select * from t where id = ${id}`) `` 与拼接等价。参数化写法是 `db.query('... where id = ?', [id])` 或 Prisma / Drizzle 的类型安全 API。`$queryRaw` 标签模板是参数化的，`$queryRawUnsafe` 不是——两者只差一个词。
- NoSQL：把 `req.body` 整个对象塞进 `find()` / `findOne()` 允许注入 `$ne` / `$gt` / `$regex` / `$where` 操作符。这类问题**正则完全看不出来**，要看有没有对字段做类型收敛。
- `eval` / `new Function` / `vm.runInNewContext` / `setTimeout("字符串")` 都是求值 sink。`vm` 模块**不是安全沙箱**。
- `require(userInput)` / 动态 `import()` 可加载任意本地模块。

## XSS

- 服务端渲染：模板引擎的转义默认值各不相同（EJS 的 `<%= %>` 转义、`<%- %>` 不转义；Handlebars 的 `{{ }}` 转义、`{{{ }}}` 不转义）。
- 前端框架默认转义，开口在 `dangerouslySetInnerHTML`、`v-html`、`[innerHTML]`、`$sce.trustAsHtml`。
- DOM 型 sink：`innerHTML`、`outerHTML`、`insertAdjacentHTML`、`document.write`、`el.setAttribute('href', x)`（`javascript:` 协议）、`location.href = x`、`window.open(x)`。
- 自研的「过滤 `<script>`」一律视为无效；富文本要用 DOMPurify。

## 原型链污染

`_.merge` / `_.defaultsDeep` / `Object.assign(sharedObj, userObj)` / 自写的递归合并，若不过滤 `__proto__`、`constructor`、`prototype`，可污染 `Object.prototype`，进而影响全应用逻辑（常见后果是绕过权限判断或触发 RCE 的 gadget）。同类的还有 `JSON.parse` 结果直接作为路径写入（`obj[a][b] = c`）。

## 认证与会话

- `jwt.decode()` **不验签**，只有 `jwt.verify()` 验。
- `jwt.verify` 必须显式传 `algorithms: ['RS256']` 之类，否则存在算法混淆（用公钥当 HMAC 密钥）；`alg: none` 同理。
- Cookie：`httpOnly` / `secure` / `sameSite` 被关掉要看会话是否依赖它。
- CORS：`origin: true` 与「回显请求 Origin」等价，配合 `credentials: true` 就是任意站点可带凭据读接口。

## 其他

- 用户输入构造正则 → ReDoS；嵌套量词的固定正则遇上超长输入同样会卡死。
- `rejectUnauthorized: false`、`NODE_TLS_REJECT_UNAUTHORIZED=0` 关闭 TLS 校验。
- `Math.random()` 不是密码学随机，令牌 / 重置码要用 `crypto.randomBytes` / `crypto.randomUUID`。
- `crypto.createHash('md5'|'sha1')` 用于口令不可接受。
- 比较令牌用 `crypto.timingSafeEqual`。
- 上传：只校验 `file.mimetype` 或扩展名不够，两者都由客户端提供。
- SSRF：服务端的 `fetch` / `axios` 默认跟随重定向，校验必须逐跳做。浏览器侧的 `fetch` 不算 SSRF。
