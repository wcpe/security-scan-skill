# Ruby / Rails 判定要点

只收录容易判错的部分；通用方法见 `../taint-analysis.md`。

## 正则的 ^ 和 $ 匹配的是「行」不是「串」

这是 Ruby 校验被绕过的头号原因：

```ruby
# 看着像「只允许字母数字」，实际只要求「存在一行是字母数字」
raise unless name =~ /^[a-z0-9]+$/
# "safe\n; rm -rf /" 通过校验
```

必须用 `\A` 和 `\z`（`\Z` 允许结尾一个换行，也不够严）。看到用 `^...$` 做安全校验一律判为不足，并检查该值最终去了哪个 sink。

## Kernel#open 与管道

`open(path)` 在路径以 `|` 开头时**执行命令**。`open(params[:url])`、`IO.read(userInput)` 因此同时是路径穿越和命令执行 sink。Ruby 3.0+ 移除了 `open-uri` 对 `open` 的重载，但 `Kernel#open` 的管道行为仍在。安全替代是 `File.open` / `File.read`。

## 命令执行

- 插值即注入：`system("convert #{path}")`、`` `git log #{ref}` ``、`%x{...}` 都过 shell。
- 多参数形式不过 shell：`system("convert", path)`、`Open3.capture3("git", "log", ref)`。
- 需要拼接时用 `Shellwords.escape`。
- 单参数的 `system("cmd")` 若字符串含 shell 元字符也会走 shell。

## 反序列化

- `Marshal.load` 处理不可信数据即 RCE，无安全用法。
- `YAML.load`：Psych 4（Ruby 3.1+ / Rails 7+ 捆绑）起默认行为等同 `safe_load`；更早版本可实例化任意类。**判定前先确认项目的 Ruby / Psych 版本**，不要一律判高危，也不要一律放行。
- `JSON.load`（大写 load）会创建对象，`JSON.parse` 才是纯解析。

## ActiveRecord

- `where("name = '#{params[:n]}'")` 是注入；`where("name = ?", params[:n])` / `where(name: params[:n])` 是绑定。
- **无法绑定的位置**：`order`、`group`、`having`、`joins`、`pluck`、`select` 的字段名。`order(params[:sort])` 是标识符注入的高频形态（Rails 6+ 对 `order` 加了部分校验，但仍可被 SQL 函数绕过）。这些位置只能白名单。
- `find_by_sql` / `connection.execute` / `select_all` 全靠自己保证。
- `where(params[:filter])` 传哈希时，用户可控的键值可查询任意列。

## 批量赋值与反射

- `params.permit!` 放行全部字段，等于取消强参数保护；`params.require(:x).permit(:a, :b)` 才是白名单。
- `update_attributes(params[:user])` 未过滤时用户可写 `admin` 等字段。
- `send(params[:action])` / `public_send` 方法名可控 = 任意方法调用；`constantize` / `safe_constantize` 类名可控 = 任意类加载。

## XSS

- ERB / Rails 视图默认转义；开口是 `.html_safe`、`raw(...)`、`<%== %>`、`sanitize` 的自定义白名单过宽。
- `link_to name, user_url` 里 `user_url` 可控时可注入 `javascript:` 协议。
- `content_tag` 的属性值同样需要转义。

## 其他

- `File.expand_path(input, base)` 解析 `..`，但 input 是绝对路径时会覆盖 base —— 之后仍需前缀校验。
- `send_file` / `send_data` 的路径可控即穿越。
- `redirect_to params[:url]` 是开放重定向；Rails 7+ 默认 `allow_other_host: false` 会拦下跨主机跳转，旧版本不会。
- `protect_from_forgery with: :null_session` 让 CSRF 攻击下会话变空而不是报错，对只读接口尚可，对写接口要看是否另有认证。
- `OpenSSL::SSL::VERIFY_NONE` 关闭证书校验。
- 口令用 `has_secure_password`（BCrypt）；令牌用 `SecureRandom`，不用 `rand`。
- 比较令牌用 `ActiveSupport::SecurityUtils.secure_compare`。
- `Timeout.timeout` 中断位置不确定，可能让安全校验只跑了一半（少见但真实）。
