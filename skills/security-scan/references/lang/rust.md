# Rust 判定要点

只收录容易判错的部分；通用方法见 `../taint-analysis.md`。

Rust 消除了内存安全类问题的大部分，但注入、穿越、越权这些逻辑层漏洞一个都不少。别因为「是 Rust」就降低警惕。

## 路径：join 的绝对路径覆盖

```rust
Path::new("/var/data").join("/etc/passwd")   // -> "/etc/passwd"
Path::new("/var/data").join("../../etc/passwd")  // -> "/var/data/../../etc/passwd"
```

第一种是最容易漏的形态。Windows 下还要注意盘符（`C:\...`）和 UNC 路径同样会覆盖。

好消息是 `Path::starts_with` 是**按路径组件**比较的，不存在 `/base` 匹配到 `/base-evil` 的问题。正确写法：

```rust
let full = base.join(name).canonicalize()?;   // canonicalize 会解析 .. 与符号链接
if !full.starts_with(&base_canonical) { return Err(...); }
```

注意 `canonicalize` 要求路径已存在——创建新文件时得先校验父目录。

## 命令执行

`Command::new("git").arg("log").arg(user_arg)` **不经 shell**，元字符无效。真正的问题是：

- 显式起 shell：`Command::new("sh").arg("-c").arg(cmd)`；
- 程序名可控；
- 选项注入：可控参数以 `-` 开头。

## SQL

- `sqlx::query!` / `query_as!` 宏在编译期校验且参数化，是安全路径；`sqlx::query(&format!("..."))` 是拼接。
- `.bind()` 绑定的是值，标识符仍需白名单。
- diesel 的 DSL 安全；`sql_query` + `format!` 不安全。

## 整数与转换

- **release 构建下整数溢出默认回绕不 panic**（debug 下 panic）。涉及金额、配额、长度、偏移量的算术要看有没有用 `checked_*` / `saturating_*`。
- `as` 转换静默截断：`u64 as u32`、`usize as u8`。
- `unwrap()` / `expect()` 在服务端 handler 里 panic 会中断该请求（axum/actix 会捕获），大量触发即可用性问题。

## unsafe

`unsafe` 块、`transmute`、`from_utf8_unchecked`、`get_unchecked`、裸指针解引用、`static mut`、手写 `Send`/`Sync` 实现——这些地方编译器不再兜底，需要人工核对不变量。FFI 边界（`extern "C"`）的长度与生命周期假设是重点。

## 反序列化与输入

- serde 本身不会实例化任意类型（没有 Java/Python 那种反序列化 RCE），但：
  - `#[serde(deny_unknown_fields)]` 缺失时多余字段被静默忽略——这是**批量赋值的反面**，通常安全，但会掩盖客户端传错字段的问题；
  - 直接把请求体反序列化进包含 `role` / `is_admin` 字段的实体，仍是过度提交；
  - `typetag` 之类的多态反序列化会恢复「按名字找类型」的语义，要按不安全反序列化对待。
- 解压：`zip` / `tar` crate 不会自动阻止 `../` 条目，需自行校验（`tar` 的 `Archive::unpack` 有部分保护，`zip` 基本没有）。

## Web 框架

- axum / actix 的提取器（`Query<T>`、`Path<T>`、`Json<T>`、`Multipart`）都是 source。
- 静态文件服务（`tower-http` 的 `ServeDir`）默认有路径约束；自己拼路径读文件就没有。
- 中间件顺序决定鉴权是否覆盖某条路由——路由注册在鉴权层外面等于没鉴权。
- 模板引擎：askama 默认按扩展名转义，`|safe` 关闭；tera 默认对 `.html` 转义，`| safe` 关闭。

## 加密与随机

- `rand::thread_rng()` 不保证密码学安全用途的强度；密钥 / 令牌用 `rand::rngs::OsRng`、`getrandom` 或 `ring`。
- 口令用 `argon2` / `bcrypt` crate。
- 比较密钥用 `subtle::ConstantTimeEq`，不用 `==`。
- 自己实现加密协议（拼 nonce、复用 IV、自造 MAC）一律标为问题。
