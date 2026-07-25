# Java / Kotlin 判定要点

只收录容易判错的部分；通用方法见 `../taint-analysis.md`。

## 命令执行：先分清走不走 shell

- `Runtime.exec(String)` **不经过 shell**，它用 `StringTokenizer` 按空白拆词。所以 `ls; rm -rf /` 里的 `;` 不会被解释，而是变成 `ls` 的一个参数。仅凭「拼了字符串进 exec」判命令注入是常见误报。
- 真正的注入形态是显式起 shell：`Runtime.exec(new String[]{"sh", "-c", cmd})`、`ProcessBuilder("cmd.exe", "/c", cmd)`。
- 不走 shell 时风险转移到两处：**程序名可控**（能换成任意可执行文件），以及**参数被目标程序当选项解析**（可控值以 `-` 开头，例如注入 `--output=`）。
- 拆词本身也可能被利用：可控值里的空格会被拆成多个参数，改变命令语义。

## SQL

- `PreparedStatement` 只能绑定**值**。表名、列名、`ORDER BY` / `GROUP BY` 字段、`ASC/DESC` 都绑不了——这些位置只能用「映射到代码里写死的白名单常量」。看到「已经用了 PreparedStatement」不要直接放行，看这个具体位置拼的是什么。
- MyBatis：`#{}` 是绑定，`${}` 是字符串替换。XML 映射文件和注解里的 `${}` 都要当拼接看。动态 `<if>` 里拼 `${orderBy}` 是高频问题。
- JPA/Hibernate：`createQuery("... where name = '" + n + "'")` 是注入；`createNativeQuery` 同理。`@Query` 里用 SpEL `?#{}` 要额外小心。
- `Statement` 没有绑定能力，出现即意味着 SQL 是拼出来的。

## 路径

- **`new File(parent, child)` 与 `Path.resolve(child)` 行为不同**：`new File("/base", "/etc/passwd")` 得到 `/base/etc/passwd`（child 当相对路径处理），而 `Paths.get("/base").resolve("/etc/passwd")` 直接得到 `/etc/passwd`（绝对路径覆盖）。后者是真陷阱。
- 两者都挡不住 `../`。
- `getAbsolutePath()` **不**解析 `..` 和符号链接；`getCanonicalPath()` / `toRealPath()` 才解析。校验必须基于后者，且比较时前缀要带上分隔符（`/data/user` 与 `/data/user-evil` 的问题）。
- Zip Slip：`ZipEntry.getName()` 完全由压缩包内容决定，解压前必须对每个条目做规范化 + 前缀校验。`ZipInputStream` 不会替你做。

## 反序列化

- `ObjectInputStream.readObject()` 处理不可信数据即 RCE 级（gadget 链），除非配了 `ObjectInputFilter`。
- Jackson：`enableDefaultTyping()` / `activateDefaultTyping()` / `@JsonTypeInfo(use = Id.CLASS)` 让报文能指定类名。必须配 `PolymorphicTypeValidator` 白名单。
- SnakeYAML：`new Yaml()` 默认可实例化任意类；安全写法是 `new Yaml(new SafeConstructor())`（1.x）或 SnakeYAML Engine 的安全 API。
- `XMLDecoder`、`XStream` 默认同样危险。

## XML

`DocumentBuilderFactory` / `SAXParserFactory` / `XMLInputFactory` / `TransformerFactory` / dom4j 的 `SAXReader` **默认允许外部实体**。安全的代码里必须能找到显式关闭：

```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// 或
factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
```

找不到就判成立。

## 表达式与日志

- SpEL（`SpelExpressionParser.parseExpression`）、OGNL、MVEL、`ScriptEngineManager`、`GroovyShell` 都是求值 sink，表达式内容可控即 RCE。
- 日志：用可控内容做日志时，若项目仍在受影响版本的 Log4j2 上，`${jndi:...}` 会被解析（Log4Shell）。看 `pom.xml` / `build.gradle` 里的版本。
- 反向的问题同样要看：把口令、令牌、完整身份证写进日志属于敏感信息泄露。

## Spring 特有

- `.csrf().disable()` 对纯 Token 认证的无状态 API 通常可接受；对使用 Cookie 会话的端点就是问题。要看认证方式再判。
- `permitAll()` 的匹配范围是否误放行了敏感路径；`antMatchers` 顺序错误会导致后面的规则永不生效。
- `@PreAuthorize` 写在接口上但实现类未被代理（同类内部调用）时不生效。
- 参数绑定的过度提交：直接把实体类当 `@RequestBody` 接，用户可赋值 `role`、`isAdmin` 等字段。

## Kotlin

- 字符串模板 `"select * from t where id = $id"` 等价于拼接，与 Java 的 `+` 同等对待。
- `ProcessBuilder(listOf("git", "log", userArg))` 不过 shell；`ProcessBuilder("sh", "-c", cmd)` 过。
- `!!` 与 `runCatching {}` 吞异常会掩盖失败的安全校验——校验失败后仍继续执行是链路成立的常见原因。

## 加密与随机

- `MessageDigest.getInstance("MD5"/"SHA-1")` 用于口令或签名不可接受；用作文件校验和无碍。
- `Cipher.getInstance("AES")` 在多数 JDK 上默认是 `AES/ECB/PKCS5Padding` —— 只写算法名不写模式就是 ECB。
- 口令存储要用 BCrypt / SCrypt / Argon2，不是「MD5 加盐」。
- 令牌、会话 ID、重置码必须 `SecureRandom`，`new Random()` 与 `Math.random()` 可预测。
- 比较密钥 / 令牌用 `MessageDigest.isEqual`，`String.equals` 有时序侧信道（低危，但值得提）。

## Minecraft 插件（Bukkit / Spigot / Paper / TabooLib）

这类项目的信任边界常被忽略——**玩家输入就是不可信输入**：

- source：指令参数 `args[i]`、聊天消息、牌子文本、书本内容、物品显示名与 lore、容器名、皮肤 / 材质 URL、玩家自定义的 NBT。
- 高危 sink：`Bukkit.dispatchCommand(Bukkit.getConsoleSender(), "give " + args[0] + " ...")` —— 玩家可控内容拼进控制台指令，等于任意控制台命令执行（直接提权到 OP）。
- 配置读写：用玩家输入作 YAML 路径键（`config.set(playerInput, ...)`）可覆盖任意配置项；用作文件名可穿越出插件目录。
- 数据库：玩家名 / UUID 拼进 SQL；离线服的玩家名完全可伪造。
- 权限：`hasPermission` 检查在异步任务里做、或只在 GUI 层做而不在实际执行处做，等于没做。
- 反序列化：`BukkitObjectInputStream` 读玩家提交的物品数据、`ConfigurationSerializable` 从不可信来源加载，同 Java 原生反序列化风险。
