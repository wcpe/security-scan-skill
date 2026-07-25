# PHP 判定要点

只收录容易判错的部分；通用方法见 `../taint-analysis.md`。

## 命令执行：escapeshellcmd 不等于 escapeshellarg

- `escapeshellarg($x)` 把整个值包成单个参数，是正确的转义。
- `escapeshellcmd($x)` 只转义元字符，**不会阻止参数注入**：`escapeshellcmd("file -o /etc/cron.d/x")` 原样通过，可控值仍能加选项。看到它被当成防护要判为不足。
- sink 全家：`system` / `exec` / `shell_exec` / `passthru` / `popen` / `proc_open` / `pcntl_exec` / 反引号。

## 文件包含（PHP 独有的高危面）

`include` / `require` 的路径可控就是 LFI；若 `allow_url_include` 开启则是 RFI（直接 RCE）。即便只可控一部分：

- `include "pages/$page.php"` 可用 `../` 穿越到任意 `.php`；
- 配合上传（图片马）、日志投毒、`php://filter` / `data://` / `phar://` 包装器，LFI 往往能升级为 RCE；
- `phar://` 反序列化：任何接受路径的文件函数（`file_exists`、`is_file`、`filesize`…）遇到 `phar://` 都会触发反序列化。

## 反序列化

`unserialize($userInput)` → POP 链，通过 `__wakeup` / `__destruct` / `__toString` 触发已加载类的危险逻辑。`unserialize($x, ['allowed_classes' => false])` 才有限制。JSON 是安全替代。

## SQL

- PDO 预编译 + `bindParam` / `bindValue` / `execute([...])` 是绑定；把变量插进 SQL 字符串（`"... where id = $id"`、`. $id .`）是拼接。
- `PDO::ATTR_EMULATE_PREPARES` 为 true（多数驱动的默认值）时，绑定由 PHP 侧做字符串替换。配合非 UTF-8 的 charset 曾有编码绕过；正确做法是在 DSN 里指定 `charset=utf8mb4` 并关闭模拟。
- `mysqli_real_escape_string` 只对值有效，且必须在正确的连接字符集下使用；标识符仍然只能白名单。

## 类型混淆（PHP 特有，正则完全看不见）

- `==` 松散比较：`"0e12345" == "0e54321"` 为真（magic hash），`0 == "abc"` 在 PHP 7 及以前为真。**口令 / 令牌 / 签名比较必须用 `===` 或 `hash_equals`。**
- `strcmp($password, $_POST['p'])` 传数组时返回 `null`，`null == 0` 为真 → 认证绕过。
- `in_array($x, $arr)` 不传第三个参数 `true` 时用松散比较。
- `switch` 的分支比较也是松散的。

## 输入与上传

- `$_FILES['x']['type']` 与文件名扩展名都由客户端提供，不能当校验依据；要用 `finfo` 检测真实类型，并用生成的文件名保存。
- `$_SERVER['HTTP_HOST']`、`HTTP_X_FORWARDED_FOR`、`HTTP_REFERER` 都可伪造。
- `extract($_GET)` / `import_request_variables` 直接覆盖局部变量。
- `basename()` 会剥掉目录成分，可用于取文件名；但它不解析 `..`，不能单独当路径防护。

## XSS

- `htmlspecialchars($x)` 默认不转义单引号（PHP 8.1 前），属性值用单引号包裹时会被绕过。正确写法：`htmlspecialchars($x, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`。
- Blade 的 `{{ }}` 转义、`{!! !!}` 不转义；Twig 默认 `autoescape` 开启，`|raw` 关闭。

## 加密与随机

- 口令必须 `password_hash` / `password_verify`，不是 `md5($p . $salt)`。
- 令牌用 `random_bytes` / `random_int`；`rand` / `mt_rand` / `uniqid` 可预测（`uniqid` 基于时间戳）。
- `hash_equals` 做定时安全比较。

## 配置

- `CURLOPT_SSL_VERIFYPEER => 0` / `CURLOPT_SSL_VERIFYHOST => 0` 关闭证书校验。
- `CURLOPT_FOLLOWLOCATION` 开启时 SSRF 需逐跳校验；`CURLOPT_PROTOCOLS` 应限定 http/https（否则 `file://`、`gopher://` 可用）。
- `display_errors` 在生产开启会泄露路径与 SQL。
- `libxml_disable_entity_loader(false)` 或未设置时，`simplexml_load_string` / `DOMDocument::loadXML` 可能解析外部实体（PHP 8.0+ 默认已安全，看版本）。
